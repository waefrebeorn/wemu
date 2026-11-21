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
#include <string.h>

#define SYS_write_          1
#define SYS_rt_sigprocmask_ 14
#define SYS_getpid_         39
#define SYS_clone_          56
#define SYS_wait4_          61
#define SYS_clone3_         435
#define SYS_exit_           60
#define SYS_exit_group_     231
#define SYS_pidfd_send_signal_ 424
#define SYS_pidfd_open_     434
#define SYS_pidfd_getfd_    438

#define SIG_BLOCK_   0
#define SIG_UNBLOCK_ 1
#define SIG_SETMASK_ 2
#define SIGUSR1_     10
#define SIGTERM_     15

#define CLONE_VM_             0x00000100u
#define CLONE_SIGHAND_        0x00000800u
#define CLONE_PIDFD_          0x00001000u
#define CLONE_THREAD_         0x00010000u
#define CLONE_SETTLS_         0x00080000u
#define CLONE_CHILD_CLEARTID_ 0x00200000u
#define CLONE_CHILD_SETTID_   0x01000000u
#define CLONE_CLEAR_SIGHAND_  0x100000000ull
#define CLONE_INTO_CGROUP_    0x200000000ull

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

/* ---- virtual per-thread signal-mask differential --------------------
 * Both the real kernel and WEMU must present identical guest-visible mask
 * semantics: the root blocks SIGUSR1, a bounded clone3 thread inherits it,
 * that thread blocks SIGTERM / unblocks SIGUSR1, and the root keeps its own
 * mask.  WEMU additionally proves it never touched the host thread mask. */
static uint64_t vmask_buf, vmask_old;
static volatile int vmask_done;
static volatile long vmask_child_usr1, vmask_child_term, vmask_child_after;

static long mask_bit(uint64_t m, unsigned sig) {
    return (long)((m >> (sig - 1)) & 1u);
}

static int run_vmask(void) {
    const uint64_t usr1 = 1ull << (SIGUSR1_ - 1);
    const uint64_t term = 1ull << (SIGTERM_ - 1);

    vmask_buf = usr1;
    emit_num("VMASK-BLOCK-RC=",
             rsys(SYS_rt_sigprocmask_, SIG_BLOCK_, (long)&vmask_buf,
                  (long)&vmask_old, 8, 0, 0));
    emit_num("VMASK-BLOCK-OLD-USR1=", mask_bit(vmask_old, SIGUSR1_));

    vmask_old = 0;
    emit_num("VMASK-QUERY-RC=",
             rsys(SYS_rt_sigprocmask_, SIG_SETMASK_, 0, (long)&vmask_old, 8, 0, 0));
    emit_num("VMASK-ROOT-USR1=", mask_bit(vmask_old, SIGUSR1_));

    struct local_clone_args ca;
    base_args(&ca);
    long t = rsys(SYS_clone3_, (long)&ca, sizeof ca, 0, 0, 0, 0);
    if (t == 0) {
        uint64_t m = 0;
        (void)rsys(SYS_rt_sigprocmask_, SIG_SETMASK_, 0, (long)&m, 8, 0, 0);
        __atomic_store_n(&vmask_child_usr1, mask_bit(m, SIGUSR1_), __ATOMIC_RELAXED);
        uint64_t s = term;
        (void)rsys(SYS_rt_sigprocmask_, SIG_BLOCK_, (long)&s, 0, 8, 0, 0);
        m = 0;
        (void)rsys(SYS_rt_sigprocmask_, SIG_SETMASK_, 0, (long)&m, 8, 0, 0);
        __atomic_store_n(&vmask_child_term, mask_bit(m, SIGTERM_), __ATOMIC_RELAXED);
        s = usr1;
        (void)rsys(SYS_rt_sigprocmask_, SIG_UNBLOCK_, (long)&s, 0, 8, 0, 0);
        m = 0;
        (void)rsys(SYS_rt_sigprocmask_, SIG_SETMASK_, 0, (long)&m, 8, 0, 0);
        __atomic_store_n(&vmask_child_after, mask_bit(m, SIGUSR1_), __ATOMIC_RELAXED);
        __atomic_store_n(&vmask_done, 1, __ATOMIC_RELEASE);
        (void)rsys(SYS_exit_, 0, 0, 0, 0, 0, 0);
        __builtin_unreachable();
    }
    if (t < 0) { emit(refused, sizeof refused - 1); return 7; }
    while (!__atomic_load_n(&vmask_done, __ATOMIC_ACQUIRE)) { }
    emit_num("VMASK-CHILD-USR1=", __atomic_load_n(&vmask_child_usr1, __ATOMIC_RELAXED));
    emit_num("VMASK-CHILD-TERM=", __atomic_load_n(&vmask_child_term, __ATOMIC_RELAXED));
    emit_num("VMASK-CHILD-AFTER=", __atomic_load_n(&vmask_child_after, __ATOMIC_RELAXED));
    vmask_old = 0;
    (void)rsys(SYS_rt_sigprocmask_, SIG_SETMASK_, 0, (long)&vmask_old, 8, 0, 0);
    emit_num("VMASK-PARENT-USR1=", mask_bit(vmask_old, SIGUSR1_));
    return 0;
}

/* ---- exact fail-closed diagnostics for the remaining extras ----------
 * The host oracle proves every shape is a real kernel feature (none returns
 * -ENOSYS); WEMU refuses all of them with dedicated reasons. */
static int want_tid;

static int run_refuse2(void) {
    struct local_clone_args ca;

    /* pidfd_send_signal on a bad fd: host -EBADF, WEMU -EINVAL + exact reason. */
    emit_num("PIDSIG-RC=", rsys(SYS_pidfd_send_signal_, -1, 0, 0, 0, 0, 0));

    /* clone_args.set_tid / set_tid_size on a fork shape. */
    want_tid = 12345;
    memset(&ca, 0, sizeof ca);
    ca.set_tid = (uint64_t)&want_tid;
    ca.set_tid_size = 1;
    emit_num("SETTID-RC=", spawn(&ca, sizeof ca));

    /* clone_args.cgroup with CLONE_INTO_CGROUP on a fork shape: the kernel
     * validates the fd; WEMU refuses before any process exists. */
    memset(&ca, 0, sizeof ca);
    ca.flags = CLONE_INTO_CGROUP_;
    ca.cgroup = 1234;
    emit_num("CGROUP-RC=", spawn(&ca, sizeof ca));

    /* A structurally valid clone3 fork shape outside the bounded form:
     * CLONE_VM without THREAD/SIGHAND would hand the child our address space. */
    memset(&ca, 0, sizeof ca);
    ca.flags = CLONE_VM_;
    ca.exit_signal = 17;                 /* SIGCHLD */
    emit_num("FORKSHAPE-RC=", spawn(&ca, sizeof ca));

    return 0;
}

/* ---- exact fail-closed diagnostics: pidfd_open / pidfd_getfd / CLEAR_SIGHAND ----
 * The host oracle proves each is a real kernel feature (pidfd_open on self
 * succeeds, pidfd_getfd on a bad fd is -EBADF, CLEAR_SIGHAND|SIGHAND is
 * -EINVAL); WEMU refuses all three with dedicated exact reasons. */
static int run_refuse3(void) {
    long me = rsys(SYS_getpid_, 0, 0, 0, 0, 0, 0);
    emit_num("PIDFDOPEN-RC=", rsys(SYS_pidfd_open_, me, 0, 0, 0, 0, 0));
    emit_num("PIDFDGETFD-RC=", rsys(SYS_pidfd_getfd_, -1, -1, 0, 0, 0, 0));
    emit_num("CLRCLEAR-RC=",
             rsys(SYS_clone_, (long)(CLONE_CLEAR_SIGHAND_ | CLONE_SIGHAND_),
                  0, 0, 0, 0, 0));
    return 0;
}

/* ---- positive byte-exact differential: bounded fork-shaped clone3 -----
 * A v0 clone_args with flags==0, exit_signal=SIGCHLD and NO knobs is WEMU's
 * bounded COW fork form.  The child writes then exits 0; the parent wait4()s
 * and reports only boolean invariants (never a pid or raw status word), so
 * the byte stream is identical on the host kernel and under WEMU. */
static int run_fork(void) {
    struct local_clone_args ca;
    memset(&ca, 0, sizeof ca);
    ca.exit_signal = 17;                 /* SIGCHLD */

    long pid = rsys(SYS_clone3_, (long)&ca, sizeof ca, 0, 0, 0, 0);
    if (pid == 0) {
        emit("C3FORK-CHILD\n", sizeof "C3FORK-CHILD\n" - 1);
        (void)rsys(SYS_exit_, 0, 0, 0, 0, 0, 0);
        __builtin_unreachable();
    }
    if (pid < 0) { emit(refused, sizeof refused - 1); return 7; }

    int st = 0;
    long w = rsys(SYS_wait4_, pid, (long)&st, 0, 0, 0, 0);
    int exited0 = (w == pid) && ((st & 0x7f) == 0) && (((st >> 8) & 0xff) == 0);
    emit_num("C3FORK-WAIT-OK=", exited0);
    emit("C3FORK-PARENT\n", sizeof "C3FORK-PARENT\n" - 1);
    return 0;
}

int main(int argc, char **argv) {
    char mode = (argc >= 2 && argv[1][0]) ? argv[1][0] : 'o';
    int rc;
    if (mode == 'v')      rc = run_vmask();
    else if (mode == '2') rc = run_refuse2();
    else if (mode == '3') rc = run_refuse3();
    else if (mode == 'f') rc = run_fork();
    else if (mode == 'r') rc = run_refuse();
    else                  rc = run_ok();
    (void)rsys(SYS_exit_group_, rc, 0, 0, 0, 0, 0);
    return rc;
}
