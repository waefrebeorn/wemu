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
#include <signal.h>
#include <ucontext.h>

#define SYS_write_          1
#define SYS_rt_sigprocmask_ 14
#define SYS_getpid_         39
#define SYS_clone_          56
#define SYS_wait4_          61
#define SYS_clone3_         435
#define SYS_exit_           60
#define SYS_exit_group_     231
#define SYS_rt_sigaction_   13
#define SYS_rt_sigprocmask_ 14
#define SYS_sched_yield_    24
#define SYS_mmap_           9
#define SYS_mprotect_       10
#define SYS_getuid_         102
#define SYS_tgkill_         234
#define SYS_kill_           62
#define SYS_pidfd_send_signal_ 424
#define SYS_pidfd_open_     434
#define SYS_pidfd_getfd_    438
#define SYS_openat_         257

#define PIDFD_NONBLOCK_     0x800u
#define SIGCONT_            18
#define SIGWINCH_           28

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
#define SIGILL_      4
#define SIGFPE_      8
#define SIGSEGV_     11
#define SA_RESTORER_ 0x04000000u
#define SA_SIGINFO_  0x00000004u
#define SI_TKILL_    (-6)
#define PROT_READ_   1
#define PROT_WRITE_  2
#define MAP_PRIVATE_ANON_ 0x22

/* Kernel x86-64 rt_sigaction layout: handler@0, flags@8, restorer@16,
 * mask@24.  Only the synchronous-fault signals are modeled by WEMU. */
struct local_sigaction {
    uint64_t handler, flags, restorer, mask;
};

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

static long raw_sigaction(int sig, const struct local_sigaction *act,
                          struct local_sigaction *old, unsigned long ssz) {
    return rsys(SYS_rt_sigaction_, sig, (long)act, (long)old, ssz, 0, 0);
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

/* ---- out-of-scope pidfd shapes stay refused with an exact reason ------
 * The host oracle proves each shape is a REAL kernel feature (pidfd_open on
 * self with PIDFD_NONBLOCK succeeds, pidfd_getfd on a bad pidfd is -EBADF);
 * WEMU refuses both with dedicated exact reasons.  This is the SAME structural
 * test as the original refuse3, but the pidfd_open now uses an unsupported
 * FLAG (the plain flags==0 form is an admitted in-scope shape, tested in mode
 * "p" below). */
static int run_refuse3(void) {
    long me = rsys(SYS_getpid_, 0, 0, 0, 0, 0, 0);
    emit_num("PIDFDOPEN-RC=",
             rsys(SYS_pidfd_open_, me, PIDFD_NONBLOCK_, 0, 0, 0, 0));
    emit_num("PIDFDGETFD-RC=", rsys(SYS_pidfd_getfd_, -1, -1, 0, 0, 0, 0));
    emit_num("CLRCLEAR-RC=",
             rsys(SYS_clone_, (long)(CLONE_CLEAR_SIGHAND_ | CLONE_SIGHAND_),
                  0, 0, 0, 0, 0));
    return 0;
}

/* ---- bounded pidfd authority: positive byte-exact differential -------
 * Every call below is an IN-SCOPE shape under WEMU's bounded authority:
 *   pidfd_open(getpid(), 0)      -> the root TID is an admitted guest TID;
 *   pidfd_getfd(pfd, fd, 0)      -> pfd was minted by WEMU and fd was obtained
 *                                   by the guest's own openat;
 *   pidfd_send_signal(pfd, SIGCONT, NULL, 0)
 *                                -> SIGCONT is the whitelisted benign signal.
 * WEMU dispatches each to the real host syscall, so the guest-visible booleans
 * are byte-exact with the native kernel oracle.  Only booleans are emitted
 * (never raw fd numbers or pids), so the two byte streams are identical. */
static const char pa_path[] = "/etc/hostname";

static int run_pidfd_authority(void) {
    long me = rsys(SYS_getpid_, 0, 0, 0, 0, 0, 0);
    long fd = rsys(SYS_openat_, -100 /* AT_FDCWD */, (long)pa_path,
                   0 /* O_RDONLY */, 0, 0, 0);
    emit_num("PA-OPEN-FD-OK=", fd > 0);
    long pfd = rsys(SYS_pidfd_open_, me, 0, 0, 0, 0, 0);
    emit_num("PA-PIDFD-OK=", pfd > 0);
    long gfd = rsys(SYS_pidfd_getfd_, pfd, fd, 0, 0, 0, 0);
    emit_num("PA-GETFD-OK=", gfd > 0);
    long sr = rsys(SYS_pidfd_send_signal_, pfd, SIGCONT_, 0, 0, 0, 0);
    emit_num("PA-SIGNAL-OK=", sr == 0);
    return 0;
}

/* ---- bounded pidfd authority: out-of-scope fail-closed edge ----------
 * Two shapes the authority must REFUSE even with a valid minted pidfd:
 *   pidfd_getfd(pfd, 2, 0)          -> fd 2 (stderr) was never admitted by a
 *                                      guest openat (the supervisor wired it);
 *   pidfd_send_signal(pfd, SIGWINCH, NULL, 0)
 *                                   -> SIGWINCH is not the whitelisted signal.
 * The host oracle proves both are real kernel features (getfd duplicates fd 2
 * and returns a positive fd; SIGWINCH is ignored with rc 0), while WEMU must
 * refuse each with an exact reason and NO host dispatch.  The leading
 * pidfd_open(getpid(),0) is an admitted shape and is byte-exact on both legs. */
static int run_pidfd_refuse(void) {
    long me = rsys(SYS_getpid_, 0, 0, 0, 0, 0, 0);
    long pfd = rsys(SYS_pidfd_open_, me, 0, 0, 0, 0, 0);
    emit_num("PQ-PIDFD-OK=", pfd > 0);
    emit_num("PQ-GETFD-UNADMITTED-RC=",
             rsys(SYS_pidfd_getfd_, pfd, 2, 0, 0, 0, 0));
    emit_num("PQ-SIGNAL-NONWL-RC=",
             rsys(SYS_pidfd_send_signal_, pfd, SIGWINCH_, 0, 0, 0, 0));
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

/* ---- per-thread signal dispositions -----------------------------------
 * Each modeled CLONE_THREAD guest owns a private rt_sigaction table: a new
 * thread inherits a COPY of its parent's table and a synchronous fault is
 * delivered from the FAULTING thread's table.  Mode "d" registers DISTINCT
 * signals in root (SIGFPE) and child (SIGILL) so a real kernel (which shares
 * dispositions under CLONE_SIGHAND) and WEMU's per-thread model are byte-exact
 * identical: query-only readback sees the inherited handler and each fault
 * runs its owner's handler.  Mode "x" registers the SAME signal with different
 * handlers in both threads: WEMU's per-thread tables keep them separate while
 * the OLD process-wide path clobbers one with the other (negative control).
 * Handlers terminate from inside the signal frame — the synthetic delivery
 * does not repair the faulting instruction, so there is no retry. */
static volatile int disp_done;

/* SA_RESTORER trampoline.  A real kernel needs a valid restorer to build the
 * signal frame; WEMU's bounded delivery records but never uses it because the
 * handlers below terminate from inside the frame. */
static void disp_restorer(void) {
    __asm__ volatile("mov $15, %%rax\n\tsyscall"   /* SYS_rt_sigreturn */
                     ::: "rax", "rcx", "r11", "memory");
}

static const char d_child_h[] = "D-CHILD-HANDLER\n";
static const char d_root_h[]  = "D-ROOT-HANDLER\n";
static const char x_child_h[] = "X-CHILD-HANDLER\n";
static const char x_root_h[]  = "X-ROOT-HANDLER\n";

static void d_child_sigill(int sig) {
    (void)sig;
    emit(d_child_h, sizeof d_child_h - 1);
    __atomic_store_n(&disp_done, 1, __ATOMIC_RELEASE);
    (void)rsys(SYS_exit_, 0, 0, 0, 0, 0, 0);   /* end only this thread */
    __builtin_unreachable();
}
static void d_root_sigfpe(int sig) {
    (void)sig;
    emit(d_root_h, sizeof d_root_h - 1);
    (void)rsys(SYS_exit_group_, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
static void x_child_sigill(int sig) {
    (void)sig;
    emit(x_child_h, sizeof x_child_h - 1);
    __atomic_store_n(&disp_done, 1, __ATOMIC_RELEASE);
    (void)rsys(SYS_exit_, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
static void x_root_sigill(int sig) {
    (void)sig;
    emit(x_root_h, sizeof x_root_h - 1);
    (void)rsys(SYS_exit_group_, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

__attribute__((noinline)) static void do_ud2(void) { __asm__ volatile("ud2"); }
__attribute__((noinline)) static void do_div0(void) {
    volatile unsigned z = 0;
    unsigned out;
    __asm__ volatile("xor %%edx,%%edx\n\tmov $1,%%eax\n\tdivl %1"
                     : "=a"(out) : "m"(z) : "edx", "cc");
    (void)out;
}

static long set_handler(int sig, uint64_t h) {
    struct local_sigaction sa;
    sa.handler = h;
    sa.flags = SA_RESTORER_;
    sa.restorer = (uint64_t)(uintptr_t)&disp_restorer;
    sa.mask = 0;
    return raw_sigaction(sig, &sa, 0, 8);
}

static int run_disp(void) {
    struct local_sigaction old;
    uint64_t rh = (uint64_t)(uintptr_t)&d_root_sigfpe;
    emit_num("D-ROOT-SET-RC=", set_handler(SIGFPE_, rh));

    struct local_clone_args ca;
    base_args(&ca);
    __atomic_store_n(&disp_done, 0, __ATOMIC_RELAXED);
    long t = rsys(SYS_clone3_, (long)&ca, sizeof ca, 0, 0, 0, 0);
    if (t == 0) {
        memset(&old, 0, sizeof old);
        emit_num("D-QUERY-RC=", raw_sigaction(SIGFPE_, 0, &old, 8));
        emit_num("D-INHERIT=", old.handler == rh);
        emit_num("D-CHILD-SET-RC=",
                 set_handler(SIGILL_, (uint64_t)(uintptr_t)&d_child_sigill));
        do_ud2();                       /* SIGILL -> d_child_sigill */
        (void)rsys(SYS_exit_, 4, 0, 0, 0, 0, 0); /* unreachable */
        __builtin_unreachable();
    }
    if (t < 0) { emit(refused, sizeof refused - 1); return 7; }
    while (!__atomic_load_n(&disp_done, __ATOMIC_ACQUIRE)) { }
    do_div0();                          /* SIGFPE -> d_root_sigfpe */
    return 0;                           /* unreachable: handler exit_group */
}

static int run_disp_collide(void) {
    uint64_t rh = (uint64_t)(uintptr_t)&x_root_sigill;
    emit_num("X-ROOT-SET-RC=", set_handler(SIGILL_, rh));
    struct local_clone_args ca;
    base_args(&ca);
    __atomic_store_n(&disp_done, 0, __ATOMIC_RELAXED);
    long t = rsys(SYS_clone3_, (long)&ca, sizeof ca, 0, 0, 0, 0);
    if (t == 0) {
        emit_num("X-CHILD-SET-RC=",
                 set_handler(SIGILL_, (uint64_t)(uintptr_t)&x_child_sigill));
        do_ud2();                       /* per-thread: x_child_sigill */
        (void)rsys(SYS_exit_, 4, 0, 0, 0, 0, 0); /* unreachable */
        __builtin_unreachable();
    }
    if (t < 0) { emit(refused, sizeof refused - 1); return 7; }
    while (!__atomic_load_n(&disp_done, __ATOMIC_ACQUIRE)) { }
    do_ud2();       /* per-thread -> x_root_sigill; shared -> x_child_sigill */
    return 0;
}

static int run_disp_refuse(void) {
    struct local_sigaction sa;
    sa.handler = (uint64_t)(uintptr_t)&d_root_sigfpe;
    sa.flags = 0; sa.restorer = 0; sa.mask = 0;
    emit_num("SA-USR1-RC=", raw_sigaction(SIGUSR1_, &sa, 0, 8));
    emit_num("SA-SIZE-RC=", raw_sigaction(SIGFPE_, &sa, 0, 16));
    sa.handler = 0x1000;               /* handler outside the guest image */
    emit_num("SA-ADDR-RC=", raw_sigaction(SIGFPE_, &sa, 0, 8));
    return 0;
}

/* ---- bounded tgkill + SA_SIGINFO delivery ----------------------------
 * Mode "g": root registers an SA_SIGINFO SIGFPE handler, spawns ONE bounded
 * clone3 thread, tgkills THAT tid, and the handler in the target prints the
 * deterministic siginfo/ucontext fields.  Host and WEMU must be byte-exact.
 * Mode "m": the target inherits a blocked SIGFPE, ignores the queued signal
 * while masked, then unblocks and receives it (per-thread mask respected).
 * Mode "k"/"u": fail-closed shapes (bad tgid/tid/signal); "k" matches the
 * host's errno exactly, "u" is a signal-0 existence check the host accepts
 * and WEMU refuses (documented bounded divergence).  Mode "a": SA_SIGINFO
 * SIGSEGV fault — si_code/si_addr/ucontext are byte-exact and sigreturn
 * resumes the faulting store.  All handler writes are raw syscalls. */
static volatile int tg_ready, tg_done;
static uintptr_t tga_page;

static void emit_num_t(const char *pre, const char *suf, long v) {
    char tag[64]; size_t i = 0;
    while (*pre && i < 56) tag[i++] = *pre++;
    while (*suf && i < 56) tag[i++] = *suf++;
    tag[i] = 0;
    emit_num(tag, v);
}

static void emit_tg_fields(const char *pre, siginfo_t *si, void *ucv) {
    ucontext_t *uc = (ucontext_t *)ucv;
    emit_num_t(pre, "SIGNO=", si->si_signo);
    emit_num_t(pre, "CODE=", si->si_code);
    emit_num_t(pre, "ERRNO=", si->si_errno);
    emit_num_t(pre, "PID-EQ=",
               si->si_pid == rsys(SYS_getpid_, 0, 0, 0, 0, 0, 0));
    emit_num_t(pre, "UID-EQ=",
               si->si_uid == rsys(SYS_getuid_, 0, 0, 0, 0, 0, 0));
    emit_num_t(pre, "UC-MASK=", sigismember(&uc->uc_sigmask, SIGFPE_));
    emit_num_t(pre, "UC-RIP=", uc->uc_mcontext.gregs[REG_RIP] != 0);
}

static long set_siginfo_handler(int sig, uint64_t h) {
    struct local_sigaction sa;
    sa.handler = h;
    sa.flags = SA_RESTORER_ | SA_SIGINFO_;
    sa.restorer = (uint64_t)(uintptr_t)&disp_restorer;
    sa.mask = 0;
    return raw_sigaction(sig, &sa, 0, 8);
}

static void tg_handler(int s, siginfo_t *si, void *u) {
    (void)s;
    emit("TG-HANDLER\n", sizeof "TG-HANDLER\n" - 1);
    emit_tg_fields("TG-", si, u);
    __atomic_store_n(&tg_done, 1, __ATOMIC_RELEASE);
    (void)rsys(SYS_exit_, 0, 0, 0, 0, 0, 0);   /* end only this thread */
    __builtin_unreachable();
}

static void tgm_handler(int s, siginfo_t *si, void *u) {
    (void)s;
    emit("TGM-HANDLER\n", sizeof "TGM-HANDLER\n" - 1);
    emit_tg_fields("TGM-", si, u);
    __atomic_store_n(&tg_done, 1, __ATOMIC_RELEASE);
    (void)rsys(SYS_exit_, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

static int run_tgkill(int masked) {
    const char *pre = masked ? "TGM-" : "TG-";
    long me = rsys(SYS_getpid_, 0, 0, 0, 0, 0, 0);
    emit_num_t(pre, "SET-RC=",
               set_siginfo_handler(SIGFPE_,
                   (uint64_t)(uintptr_t)(masked ? &tgm_handler : &tg_handler)));
    if (masked) {
        uint64_t blk = 1ull << (SIGFPE_ - 1);
        emit_num("TGM-BLOCK-RC=",
                 rsys(SYS_rt_sigprocmask_, SIG_BLOCK_, (long)&blk, 0, 8, 0, 0));
    }
    struct local_clone_args ca;
    base_args(&ca);
    __atomic_store_n(&tg_ready, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&tg_done, 0, __ATOMIC_RELAXED);
    long t = rsys(SYS_clone3_, (long)&ca, sizeof ca, 0, 0, 0, 0);
    if (t == 0) {
        if (masked) {
            uint64_t m = 0;
            (void)rsys(SYS_rt_sigprocmask_, SIG_SETMASK_, 0, (long)&m, 8, 0, 0);
            emit_num("TGM-CHILD-MASK=", (m >> (SIGFPE_ - 1)) & 1ull);
        }
        __atomic_store_n(&tg_ready, 1, __ATOMIC_RELEASE);
        if (masked) {
            for (int i = 0; i < 64; i++)
                (void)rsys(SYS_sched_yield_, 0, 0, 0, 0, 0, 0);
            emit("TGM-NO-DELIVERY\n", sizeof "TGM-NO-DELIVERY\n" - 1);
            uint64_t un = 1ull << (SIGFPE_ - 1);
            (void)rsys(SYS_rt_sigprocmask_, SIG_UNBLOCK_, (long)&un, 0, 8, 0, 0);
        }
        while (!__atomic_load_n(&tg_done, __ATOMIC_ACQUIRE))
            (void)rsys(SYS_sched_yield_, 0, 0, 0, 0, 0, 0);
        (void)rsys(SYS_exit_, 0, 0, 0, 0, 0, 0);
        __builtin_unreachable();
    }
    if (t < 0) { emit(refused, sizeof refused - 1); return 7; }
    while (!__atomic_load_n(&tg_ready, __ATOMIC_ACQUIRE)) { }
    long rc = rsys(SYS_tgkill_, (int)me, (int)t, SIGFPE_, 0, 0, 0);
    while (!__atomic_load_n(&tg_done, __ATOMIC_ACQUIRE)) { }
    emit_num_t(pre, "KILL-RC=", rc);
    return 0;
}

static int run_tgkill_refuse(void) {
    long me = rsys(SYS_getpid_, 0, 0, 0, 0, 0, 0);
    emit_num("TGK-TGID-RC=", rsys(SYS_tgkill_, me + 12345, me, SIGFPE_, 0, 0, 0));
    emit_num("TGK-TID-RC=", rsys(SYS_tgkill_, me, 0x7fffffffL, SIGFPE_, 0, 0, 0));
    emit_num("TGK-TGID0-RC=", rsys(SYS_tgkill_, 0, me, SIGFPE_, 0, 0, 0));
    emit_num("TGK-SIGNEG-RC=", rsys(SYS_tgkill_, me, me, -1, 0, 0, 0));
    return 0;
}

static int run_tgkill_unmodeled(void) {
    long me = rsys(SYS_getpid_, 0, 0, 0, 0, 0, 0);
    emit_num("TGU-SIG0-RC=", rsys(SYS_tgkill_, me, me, 0, 0, 0, 0));
    return 0;
}

/* ---- bounded process-directed kill + SA_SIGINFO delivery -------------
 * Mode "l": the root registers an SA_SIGINFO SIGFPE handler, BLOCKS SIGFPE,
 * sends kill(getpid(), SIGFPE) to itself and prints the syscall result, then
 * unblocks and reaches a syscall checkpoint.  The host delivers on unblock;
 * WEMU queues the bounded event to the calling thread and delivers it at its
 * next checkpoint.  Both print the same deterministic siginfo/ucontext fields
 * (si_code=SI_USER=0, distinct from SI_TKILL=-6), by a byte-exact oracle.
 * Mode "j": fail-closed shapes where host and WEMU agree (-ESRCH unknown pid,
 * -EINVAL negative signal).
 * Mode "w": two signal-0 existence checks the host accepts and WEMU refuses
 * (process-group pid form, unmodeled signal) — a documented divergence. */
static volatile int kl_done;

static void kl_handler(int s, siginfo_t *si, void *u) {
    (void)s;
    emit("KL-HANDLER\n", sizeof "KL-HANDLER\n" - 1);
    emit_tg_fields("KL-", si, u);
    __atomic_store_n(&kl_done, 1, __ATOMIC_RELEASE);
    /* Normal return through SA_RESTORER -> rt_sigreturn: WEMU restores the
     * saved GPRs and resumes after the checkpoint syscall. */
}

static int run_kill(void) {
    long me = rsys(SYS_getpid_, 0, 0, 0, 0, 0, 0);
    uint64_t blk = 1ull << (SIGFPE_ - 1);
    __atomic_store_n(&kl_done, 0, __ATOMIC_RELAXED);
    emit_num("KL-SET-RC=",
             set_siginfo_handler(SIGFPE_, (uint64_t)(uintptr_t)&kl_handler));
    (void)rsys(SYS_rt_sigprocmask_, SIG_BLOCK_, (long)&blk, 0, 8, 0, 0);
    long rc = rsys(SYS_kill_, (int)me, SIGFPE_, 0, 0, 0, 0);
    emit_num("KL-KILL-RC=", rc);
    (void)rsys(SYS_rt_sigprocmask_, SIG_UNBLOCK_, (long)&blk, 0, 8, 0, 0);
    /* Bounded wait: with the kill path disabled (negative control) no handler
     * ever runs, so this must not spin into WEMU's syscall budget. */
    for (int i = 0; i < 64 && !__atomic_load_n(&kl_done, __ATOMIC_ACQUIRE); i++)
        (void)rsys(SYS_sched_yield_, 0, 0, 0, 0, 0, 0);
    emit("KL-DONE\n", sizeof "KL-DONE\n" - 1);
    return 0;
}

static int run_kill_refuse(void) {
    long me = rsys(SYS_getpid_, 0, 0, 0, 0, 0, 0);
    emit_num("KLJ-PID-RC=", rsys(SYS_kill_, (int)(me + 12345), SIGFPE_, 0, 0, 0, 0));
    emit_num("KLJ-SIG-RC=", rsys(SYS_kill_, (int)me, -1, 0, 0, 0, 0));
    return 0;
}

static int run_kill_unmodeled(void) {
    long me = rsys(SYS_getpid_, 0, 0, 0, 0, 0, 0);
    emit_num("KLW-GROUP-RC=", rsys(SYS_kill_, 0, 0, 0, 0, 0, 0));
    emit_num("KLW-SIG0-RC=", rsys(SYS_kill_, (int)me, 0, 0, 0, 0, 0));
    return 0;
}

static void tga_handler(int s, siginfo_t *si, void *u) {
    (void)s;
    ucontext_t *uc = (ucontext_t *)u;
    emit_num_t("TGA-", "SIGNO=", si->si_signo);
    emit_num_t("TGA-", "CODE=", si->si_code);
    emit_num_t("TGA-", "ERRNO=", si->si_errno);
    emit_num_t("TGA-", "ADDR-EQ=", si->si_addr == (void *)tga_page);
    emit_num_t("TGA-", "UC-MASK=", sigismember(&uc->uc_sigmask, SIGSEGV_));
    emit_num_t("TGA-", "UC-RIP=", uc->uc_mcontext.gregs[REG_RIP] != 0);
    (void)rsys(SYS_mprotect_, (long)tga_page, 4096, PROT_READ_ | PROT_WRITE_,
               0, 0, 0);
    /* normal return -> SA_RESTORER -> rt_sigreturn -> faulting store retried */
}

static int run_sainfo_fault(void) {
    long p = rsys(SYS_mmap_, 0, 4096, PROT_READ_, MAP_PRIVATE_ANON_, -1, 0);
    if (p < 0) return 90;
    tga_page = (uintptr_t)p;
    emit_num("TGA-SET-RC=",
             set_siginfo_handler(SIGSEGV_, (uint64_t)(uintptr_t)&tga_handler));
    *(volatile int *)p = 0x12345678;       /* fault -> handler -> sigreturn */
    emit_num("TGA-VALUE=", *(volatile int *)p);
    return 0;
}

/* ---- bounded FP/XMM/x87 preservation in signal frames ----------------
 * Mode "F": load four known XMM patterns and x87 ST0=1.0, fault on a read-only
 * page with an SA_SIGINFO SIGSEGV handler.  The handler reads the kernel-saved
 * fpregs (cwd/mxcsr/XMM0-3/ST0), edits xmm0 IN THE FRAME and clobbers the LIVE
 * xmm1 + x87 ST0, then mprotects and returns normally.  A real kernel's
 * rt_sigreturn restores from the frame, so the interrupted code must see the
 * frame edit in xmm0 and the original values everywhere else — byte-exact
 * against the host.  WEMU must match, proving the whole blob was preserved. */
typedef unsigned char xmm_bytes[16] __attribute__((aligned(16)));

static const xmm_bytes fp_pat0 = {
    0x04,0x03,0x02,0x01, 0x08,0x07,0x06,0x05,
    0x0c,0x0b,0x0a,0x09, 0x10,0x0f,0x0e,0x0d };
static const xmm_bytes fp_pat1 = {
    0x14,0x13,0x12,0x11, 0x18,0x17,0x16,0x15,
    0x1c,0x1b,0x1a,0x19, 0x20,0x1f,0x1e,0x1d };
static const xmm_bytes fp_pat2 = {
    0x24,0x23,0x22,0x21, 0x28,0x27,0x26,0x25,
    0x2c,0x2b,0x2a,0x29, 0x30,0x2f,0x2e,0x2d };
static const xmm_bytes fp_pat3 = {
    0x34,0x33,0x32,0x31, 0x38,0x37,0x36,0x35,
    0x3c,0x3b,0x3a,0x39, 0x40,0x3f,0x3e,0x3d };

static void fp_load(int i, const xmm_bytes *p) {
    switch (i) {
    case 0: __asm__ volatile("movdqu %0, %%xmm0"::"m"(*p):"memory"); break;
    case 1: __asm__ volatile("movdqu %0, %%xmm1"::"m"(*p):"memory"); break;
    case 2: __asm__ volatile("movdqu %0, %%xmm2"::"m"(*p):"memory"); break;
    default:__asm__ volatile("movdqu %0, %%xmm3"::"m"(*p):"memory"); break;
    }
}
static void fp_store(int i, xmm_bytes *p) {
    switch (i) {
    case 0: __asm__ volatile("movdqu %%xmm0, %0":"=m"(*p)::"memory"); break;
    case 1: __asm__ volatile("movdqu %%xmm1, %0":"=m"(*p)::"memory"); break;
    case 2: __asm__ volatile("movdqu %%xmm2, %0":"=m"(*p)::"memory"); break;
    default:__asm__ volatile("movdqu %%xmm3, %0":"=m"(*p)::"memory"); break;
    }
}
static unsigned long fp_dword(const xmm_bytes *p, int idx) {
    uint32_t v; memcpy(&v, *p + 4 * idx, 4); return (unsigned long)v;
}
static void fp_st0(unsigned long *exp, unsigned long *hi) {
    unsigned char b[10] __attribute__((aligned(16)));
    uint16_t e, h;
    __asm__ volatile("fstpt %0":"=m"(b)::"memory");   /* store+pop ST0 */
    memcpy(&e, b + 8, 2); memcpy(&h, b + 6, 2);
    *exp = (unsigned long)(e & 0x7fffu);
    *hi  = (unsigned long)h;
}

static uintptr_t fp_page;
static void fp_handler(int s, siginfo_t *si, void *u) {
    (void)s; (void)si;
    ucontext_t *uc = (ucontext_t *)u;
    emit("F-HANDLER\n", sizeof "F-HANDLER\n" - 1);
    fpregset_t fp = uc->uc_mcontext.fpregs;
    emit_num("F-UC-FPREGS=", (long)(fp != 0));
    if (fp) {
        emit_num("F-UC-CWD=", (long)fp->cwd);
        emit_num("F-UC-MXCSR=", (long)fp->mxcsr);
        static const char *const xn[4] = {
            "F-UC-X0-", "F-UC-X1-", "F-UC-X2-", "F-UC-X3-" };
        for (int i = 0; i < 4; i++) {
            emit_num_t(xn[i], "LO=", (long)fp->_xmm[i].element[0]);
            emit_num_t(xn[i], "HI=", (long)fp->_xmm[i].element[3]);
        }
        emit_num("F-UC-ST0-EXP=", (long)fp->_st[0].exponent);
        emit_num("F-UC-ST0-HI=", (long)fp->_st[0].significand[3]);
        /* Edit the FRAME (not the live register): a real sigreturn applies
         * this edit, so WEMU must read it back from the synthetic frame. */
        fp->_xmm[0].element[0] = 0x00c0ffeeu;
    }
    __asm__ volatile("pxor %%xmm1, %%xmm1" ::: "memory");   /* clobber live */
    __asm__ volatile("fstp %%st(0)\n\tfldz" ::: "memory");
    (void)rsys(SYS_mprotect_, (long)fp_page, 4096, PROT_READ_ | PROT_WRITE_,
               0, 0, 0);
    /* normal return -> SA_RESTORER -> rt_sigreturn -> faulting store retried */
}

static int run_fp_frame(void) {
    long p = rsys(SYS_mmap_, 0, 4096, PROT_READ_, MAP_PRIVATE_ANON_, -1, 0);
    if (p < 0) return 90;
    fp_page = (uintptr_t)p;
    emit_num("F-SET-RC=",
             set_siginfo_handler(SIGSEGV_, (uint64_t)(uintptr_t)&fp_handler));
    fp_load(0, &fp_pat0); fp_load(1, &fp_pat1);
    fp_load(2, &fp_pat2); fp_load(3, &fp_pat3);
    __asm__ volatile("fld1" ::: "memory");              /* ST0 = 1.0 */
    *(volatile int *)p = 0x5eedface;                    /* fault -> handler */
    /* rt_sigreturn resumed here with the frame's FP state restored.  Save
     * all four XMMs before any libc/emit call can clobber them. */
    xmm_bytes b0, b1, b2, b3;
    fp_store(0, &b0); fp_store(1, &b1);
    fp_store(2, &b2); fp_store(3, &b3);
    emit_num("F-BACK-X0-LO=", (long)fp_dword(&b0, 0));
    emit_num("F-BACK-X0-HI=", (long)fp_dword(&b0, 3));
    emit_num("F-BACK-X1-LO=", (long)fp_dword(&b1, 0));
    emit_num("F-BACK-X2-LO=", (long)fp_dword(&b2, 0));
    emit_num("F-BACK-X3-LO=", (long)fp_dword(&b3, 0));
    unsigned long ex, hi;
    fp_st0(&ex, &hi);
    emit_num("F-BACK-ST0-EXP=", (long)ex);
    emit_num("F-BACK-ST0-HI=", (long)hi);
    emit_num("F-VALUE=", *(volatile int *)p);
    emit("F-DONE\n", sizeof "F-DONE\n" - 1);
    return 0;
}

int main(int argc, char **argv) {
    char mode = (argc >= 2 && argv[1][0]) ? argv[1][0] : 'o';
    int rc;
    if (mode == 'v')      rc = run_vmask();
    else if (mode == '2') rc = run_refuse2();
    else if (mode == '3') rc = run_refuse3();
    else if (mode == 'p') rc = run_pidfd_authority();
    else if (mode == 'q') rc = run_pidfd_refuse();
    else if (mode == 'f') rc = run_fork();
    else if (mode == 'r') rc = run_refuse();
    else if (mode == 'd') rc = run_disp();
    else if (mode == 'x') rc = run_disp_collide();
    else if (mode == 's') rc = run_disp_refuse();
    else if (mode == 'g') rc = run_tgkill(0);
    else if (mode == 'm') rc = run_tgkill(1);
    else if (mode == 'k') rc = run_tgkill_refuse();
    else if (mode == 'u') rc = run_tgkill_unmodeled();
    else if (mode == 'l') rc = run_kill();
    else if (mode == 'j') rc = run_kill_refuse();
    else if (mode == 'w') rc = run_kill_unmodeled();
    else if (mode == 'a') rc = run_sainfo_fault();
    else if (mode == 'F') rc = run_fp_frame();
    else                  rc = run_ok();
    (void)rsys(SYS_exit_group_, rc, 0, 0, 0, 0, 0);
    return rc;
}
