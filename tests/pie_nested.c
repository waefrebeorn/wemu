/* pie_nested.c — differential fixture for WEMU's bounded nested signal
 * delivery.  Built as a static PIE and run BOTH natively (real host kernel,
 * the independent oracle) and through wemu_um_run_elf(); the two byte streams
 * must be identical in the deterministic modes.
 *
 * All signals are queued with kill(getpid, sig) (process-directed, SI_USER)
 * and no wall-clock timing — so both the host kernel and WEMU deliver at a
 * deterministic syscall checkpoint.  Only siginfo fields the two agree on are
 * printed (si_signo / si_code=SI_USER=0); si_pid/si_uid are process-specific and
 * are deliberately NOT in the byte stream.
 *
 * mode "oracle"  : SIGSEGV handler running, sends itself SIGILL -> the SIGILL
 *                  handler runs NESTED inside it, sigreturns back into the
 *                  SIGSEGV handler, which sigreturns to main.  Byte-exact vs
 *                  the real host kernel (a real signal nesting).
 * mode "masked"  : same, but SIGILL is blocked while the first handler runs;
 *                  the nested signal stays pending and is delivered only
 *                  after main unblocks it.  Also byte-exact vs host.
 * mode "depth"   : WEMU-only fail-closed probe — the handler re-sends the same
 *                  signal repeatedly; WEMU (which does not auto-block a
 *                  delivered signal) nests up to its bounded depth and then
 *                  refuses with WEMU_UM_REFUSE_NEST_DEPTH.  No host oracle:
 *                  a real kernel auto-blocks SIGSEGV in its own handler, so
 *                  this shape is deliberately outside the oracle.
 *
 * Raw syscalls only (no glibc errno/TLS writes, no canary) so the fixture is
 * safe under the emulator-provided %fs.
 * License: WaefreBeorn Umbrella License v3.0. */
#define _GNU_SOURCE
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SYS_write_         1
#define SYS_rt_sigaction_ 13
#define SYS_rt_sigreturn_ 15
#define SYS_sched_yield_  24
#define SYS_getpid_       39
#define SYS_getuid_       102
#define SYS_gettid_       186
#define SYS_kill_         62
#define SYS_rt_sigprocmask_ 14
#define SYS_exit_         60

#define SIGILL_           4
#define SIGSEGV_          11
#define SA_SIGINFO_       0x00000004u
#define SA_RESTORER_      0x04000000u
#define SI_USER_          0
#define WEMU_NEST_PROBES  8    /* depth-mode sends; exceeds WEMU's max nest */

struct local_sigaction {
    uint64_t handler, flags, restorer, mask;
};

static long rsys(long n, long a0, long a1, long a2, long a3, long a4, long a5) {
    register long r10 __asm__("r10") = a3;
    register long r8  __asm__("r8")  = a4;
    register long r9  __asm__("r9")  = a5;
    long ret;
    __asm__ volatile("syscall"
        : "=a"(ret)
        : "a"(n), "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return ret;
}

static void emit(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    (void)rsys(SYS_write_, 1, (long)s, (long)n, 0, 0, 0);
}
static void emit_num(const char *tag, long v) {
    char b[96];
    size_t i = 0;
    while (tag[i]) { b[i] = tag[i]; i++; }
    if (v < 0) { b[i++] = '-'; v = -v; }
    if (v == 0) b[i++] = '0';
    else {
        char t[32]; size_t j = 0;
        while (v > 0) { t[j++] = (char)('0' + (v % 10)); v /= 10; }
        while (j > 0) b[i++] = t[--j];
    }
    b[i++] = '\n';
    (void)rsys(SYS_write_, 1, (long)b, (long)i, 0, 0, 0);
}

/* SA_RESTORER trampoline: both the host kernel and WEMU return through it. */
static void sig_restorer(void) {
    __asm__ volatile("mov $15, %%rax\n\tsyscall"
                     ::: "rax", "rcx", "r11", "memory");
}

static long raw_sigaction(int sig, const struct local_sigaction *act,
                          struct local_sigaction *old, unsigned long ssz) {
    return rsys(SYS_rt_sigaction_, sig, (long)act, (long)old, ssz, 0, 0);
}

static volatile sig_atomic_t depth;      /* live handler nesting depth */
static volatile sig_atomic_t sends;      /* self-sends issued (depth mode) */
static int g_mode;                       /* 0 oracle, 1 depth, 2 masked */

static void send_self(int sig) {
    long pid = rsys(SYS_getpid_, 0, 0, 0, 0, 0, 0);
    (void)rsys(SYS_kill_, pid, sig, 0, 0, 0, 0);
    /* Both the host kernel and WEMU deliver at the return from a syscall:
     * kill itself may already have delivered, but this checkpoint makes the
     * observation point explicit and deterministic on both. */
    (void)rsys(SYS_sched_yield_, 0, 0, 0, 0, 0, 0);
}

static void handler_segv(int sig, siginfo_t *si, void *ucontext) {
    (void)ucontext;
    int d = ++depth;
    if (g_mode == 1) {                  /* depth fail-closed probe */
        emit_num("D=", d);
        if (sends < WEMU_NEST_PROBES) {
            sends++;
            send_self(SIGSEGV_);        /* re-send: WEMU nests, host auto-blocks */
        }
        emit_num("U=", d);
    } else {                            /* oracle / masked */
        emit_num("A-SIG=", sig);
        emit_num("A-CODE=", si->si_code);
        emit_num("A-DEPTH=", d);
        send_self(SIGILL_);             /* nested SIGILL handler runs here */
        emit("A-DONE\n");
    }
    depth--;
}

static void handler_ill(int sig, siginfo_t *si, void *ucontext) {
    (void)ucontext;
    int d = ++depth;
    emit_num("B-SIG=", sig);
    emit_num("B-CODE=", si->si_code);
    emit_num("B-DEPTH=", d);
    emit("B-DONE\n");
    depth--;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "oracle";
    if (!strcmp(mode, "depth")) g_mode = 1;
    else if (!strcmp(mode, "masked")) g_mode = 2;
    else g_mode = 0;

    struct local_sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.flags    = SA_SIGINFO_ | SA_RESTORER_;
    sa.restorer = (uint64_t)(uintptr_t)&sig_restorer;
    sa.mask     = 0;
    sa.handler  = (uint64_t)(uintptr_t)&handler_segv;
    (void)raw_sigaction(SIGSEGV_, &sa, 0, 8);
    if (g_mode != 1) {
        sa.handler = (uint64_t)(uintptr_t)&handler_ill;
        (void)raw_sigaction(SIGILL_, &sa, 0, 8);
    }

    if (g_mode == 2) {
        /* Block SIGILL with a virtual per-thread mask (bit signo-1 = bit 3). */
        uint64_t set = (uint64_t)1u << (SIGILL_ - 1);
        (void)rsys(SYS_rt_sigprocmask_, 0 /* SIG_BLOCK */, (long)&set, 0, 8, 0, 0);
        emit("MASK-BLOCK\n");
    } else if (g_mode == 1) {
        emit("DEPTH-START\n");
    } else {
        emit("START\n");
    }

    send_self(SIGSEGV_);                /* first (flat) delivery */

    if (g_mode == 2) {
        uint64_t set = (uint64_t)1u << (SIGILL_ - 1);
        (void)rsys(SYS_rt_sigprocmask_, 1 /* SIG_UNBLOCK */, (long)&set, 0, 8, 0, 0);
        emit("MASK-UNBLOCK\n");
        emit("MASK-END\n");
    } else if (g_mode == 1) {
        emit("DEPTH-END\n");
    } else {
        emit("AFTER-A\n");
        emit("END\n");
    }
    (void)rsys(SYS_exit_, 0, 0, 0, 0, 0, 0);
    return 0;
}
