/* clone3_thread.c — differential fixture for WEMU's bounded clone3 thread
 * path and its fail-closed pidfd / signal-mask edges.  Built as a static PIE
 * and run natively (host execve, the independent oracle) and through
 * wemu_um_run_elf(); the byte streams must be exact where the host and the
 * bounded model agree.
 *
 * mode "ok" (default): spawn ONE bounded shared-VM thread through clone3's
 * struct clone_args (VM + THREAD + SIGHAND + SETTLS + CHILD_SETTID/CLEARTID,
 * stack + stack_size, TLS value, child_tid).  The child reads its own TLS
 * value, records it in shared VM and exits just itself; main prints a verdict.
 * A refused clone3 prints a fixed line and exits 7 (the old-path control).
 *
 * mode "refuse": submit the unmodeled knobs and print each raw return code:
 * a pidfd field, a CLONE_PIDFD flag, CLONE_CLEAR_SIGHAND, an oversized struct
 * (a future per-thread sigmask), and rt_sigprocmask blocking SIGSYS.  On a
 * real kernel most of these succeed; WEMU refuses each with -EINVAL/-E2BIG
 * and records the exact reason in WemuUmResult.refuses[].  Every child that
 * a real clone3 creates exits immediately, so the parent's output is stable.
 *
 * All syscalls are raw inline asm (no glibc errno/TLS writes, no canary) so
 * the fixture is safe under the emulator-provided %fs.
 * License: WaefreBeorn Umbrella License v3.0. */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>

#define SYS_write_          1
#define SYS_rt_sigprocmask_ 14
#define SYS_clone3_         435
#define SYS_exit_           60
#define SYS_exit_group_     231

#define CLONE_VM_             0x00000100u
#define CLONE_SIGHAND_        0x00000800u
#define CLONE_PIDFD_          0x00001000u
#define CLONE_THREAD_         0x00010000u
#define CLONE_SETTLS_         0x00080000u
#define CLONE_CHILD_CLEARTID_ 0x00200000u
#define CLONE_CHILD_SETTID_   0x01000000u
#define CLONE_CLEAR_SIGHAND_  0x100000000ull

#define SIG_SETMASK_ 2
#define SIGSYS_      31

struct local_clone_args {
    uint64_t flags, pidfd, child_tid, parent_tid, exit_signal,
             stack, stack_size, tls, set_tid, set_tid_size, cgroup;
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

static void emit(const char *s, unsigned long n) {
    (void)rsys(SYS_write_, 1, (long)s, n, 0, 0, 0);
}

/* Decimal return-code line, no libc (raw write only). */
static void emit_num(const char *tag, long rc) {
    char b[80];
    size_t i = 0;
    while (tag[i]) { b[i] = tag[i]; i++; }
    if (rc < 0) { b[i++] = '-'; rc = -rc; }
    if (rc == 0) b[i++] = '0';
    else {
        char t[24]; size_t j = 0;
        while (rc > 0) { t[j++] = (char)('0' + (rc % 10)); rc /= 10; }
        while (j > 0) b[i++] = t[--j];
    }
    b[i++] = '\n';
    emit(b, i);
}

static char stack[16384] __attribute__((aligned(16)));
static char tls_area[4096] __attribute__((aligned(16)));
static int  ctid;
static volatile int done;
static volatile int tls_seen;

static const char good[]    = "C3-TLS-OK\n";
static const char bad[]     = "C3-TLS-BAD\n";
static const char mainok[]  = "MAIN-OK\n";
static const char refused[] = "CLONE3-REFUSED\n";

static void base_args(struct local_clone_args *ca) {
    for (size_t i = 0; i < sizeof *ca; i++) ((unsigned char *)ca)[i] = 0;
    ca->flags = CLONE_VM_ | CLONE_SIGHAND_ | CLONE_THREAD_ | CLONE_SETTLS_ |
                CLONE_CHILD_SETTID_ | CLONE_CHILD_CLEARTID_;
    ca->stack = (uint64_t)stack;
    ca->stack_size = sizeof stack;
    ca->tls = (uint64_t)&tls_area[0];
    ca->child_tid = (uint64_t)&ctid;
    ca->exit_signal = 0;
}

/* Every clone3 below may create a host child on the oracle; make sure such a
 * child leaves the fixture immediately with a stable, silent status. */
static long spawn(struct local_clone_args *ca, unsigned long size) {
    long t = rsys(SYS_clone3_, (long)ca, (long)size, 0, 0, 0, 0);
    if (t == 0) (void)rsys(SYS_exit_, 0, 0, 0, 0, 0, 0);
    return t;
}

static int run_ok(void) {
    struct local_clone_args ca;
    base_args(&ca);
    *(volatile int *)&tls_area[0] = 7;        /* child's TLS index at fs:0 */
    long t = rsys(SYS_clone3_, (long)&ca, sizeof ca, 0, 0, 0, 0);
    if (t == 0) {
        int idx;
        __asm__ volatile("mov %%fs:0, %0" : "=r"(idx));
        __atomic_store_n(&tls_seen, idx, __ATOMIC_RELAXED);
        __atomic_store_n(&done, 1, __ATOMIC_RELEASE);
        (void)rsys(SYS_exit_, 0, 0, 0, 0, 0, 0);
        __builtin_unreachable();
    }
    if (t < 0) {
        emit(refused, sizeof refused - 1);
        return 7;
    }
    /* Wait for the child to record its own TLS value in shared VM. */
    while (!__atomic_load_n(&done, __ATOMIC_ACQUIRE)) { }
    int ok = (__atomic_load_n(&tls_seen, __ATOMIC_RELAXED) == 7);
    emit(ok ? good : bad, ok ? sizeof good - 1 : sizeof bad - 1);
    emit(mainok, sizeof mainok - 1);
    return 0;
}

static int run_refuse(void) {
    struct local_clone_args ca;

    /* A. pidfd FIELD set without the flag: the kernel ignores it and spawns;
     *    WEMU refuses with an exact CLONE3_PIDFD reason. */
    base_args(&ca);
    ca.pidfd = (uint64_t)&ctid;
    emit_num("PIDFD-FIELD-RC=", spawn(&ca, sizeof ca));

    /* B. CLONE_PIDFD flag + field: the real kernel returns a pidfd; WEMU must
     *    refuse before the thread or fd exists. */
    base_args(&ca);
    ca.flags |= CLONE_PIDFD_;
    ca.pidfd = (uint64_t)&ctid;
    emit_num("PIDFD-FLAG-RC=", spawn(&ca, sizeof ca));

    /* C. CLONE_CLEAR_SIGHAND (an unmodeled signal-handler reset): both the
     *    kernel and WEMU refuse (the flag conflicts with CLONE_SIGHAND). */
    base_args(&ca);
    ca.flags |= CLONE_CLEAR_SIGHAND_;
    emit_num("CLEARSIGHAND-RC=", spawn(&ca, sizeof ca));

    /* D. struct larger than v0 (a possible per-thread sigmask extension):
     *    the kernel returns -E2BIG, WEMU refuses with an exact SIGMASK_SIZE. */
    base_args(&ca);
    emit_num("SIZE-RC=", spawn(&ca, sizeof ca + 8));

    /* E. per-thread mask blocking SIGSYS: the kernel accepts it, WEMU refuses
     *    because masking its trap signal would break syscall dispatch. */
    uint64_t mask = 1ull << (SIGSYS_ - 1);
    emit_num("SIGPROCMASK-RC=",
             rsys(SYS_rt_sigprocmask_, SIG_SETMASK_, (long)&mask, 0, 8, 0, 0));

    return 0;
}

int main(int argc, char **argv) {
    int refuse = argc >= 2 && argv[1][0] == 'r';
    int rc = refuse ? run_refuse() : run_ok();
    (void)rsys(SYS_exit_group_, rc, 0, 0, 0, 0, 0);
    return rc;
}
