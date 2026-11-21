/* pie_timer.c — differential fixture for WEMU's bounded virtual ITIMER_REAL
 * timer.  Built as a static PIE and run BOTH natively (real host setitimer,
 * the independent oracle) and through wemu_um_run_elf(); the two byte streams
 * must be identical.
 *
 * mode "oracle" (default): register an SA_SIGINFO SIGALRM handler, arm a
 * one-shot ITIMER_REAL for 1 microsecond, then spin on sched_yield() until the handler
 * fires.  The handler records ONLY fields a real kernel and the bounded model
 * agree on (si_signo/si_code/si_errno/si_pid/si_uid) and the fixture prints
 * them.  Host oracle observation: setitimer -> si_signo=14, si_code=SI_KERNEL
 * (128), si_errno=si_pid=si_uid=0.  WEMU's checkpoint-delivery model produces
 * the same siginfo when the virtual clock expires; wall-clock timing is never
 * printed, so the comparison is byte-exact.
 *
 * mode "refuse": submit only unmodeled shapes (wrong which, periodic interval,
 * over-long delay, alarm(>1), bad pointer) and print each raw return code.
 * On a real kernel most of these succeed, so this mode is WEMU-only; the gate
 * checks the exact -EINVAL/-EFAULT and WemuUmResult.refuses[].
 *
 * All syscalls are raw inline asm (no glibc errno/TLS writes, no canary) so
 * the fixture is safe under the emulator-provided %fs.
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
#define SYS_setitimer_    38
#define SYS_getitimer_    36
#define SYS_alarm_        37
#define SYS_exit_         60

#define SIGALRM_          14
#define ITIMER_REAL_      0
#define SA_SIGINFO_       0x00000004u
#define SA_RESTORER_      0x04000000u

struct local_sigaction {
    uint64_t handler, flags, restorer, mask;
};
/* x86-64 kernel struct itimerval: two struct timevals of two longs each. */
struct local_itimerval {
    int64_t isec, iusec, vsec, vusec;
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
static void emit_num(const char *tag, long rc) {
    char b[80]; size_t i = 0;
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

static void zero_itimerval(struct local_itimerval *v) {
    v->isec = v->iusec = v->vsec = v->vusec = 0;
}

/* SA_RESTORER trampoline.  The handler returns normally, so both the host
 * kernel and WEMU use it to resume after the signal frame. */
static void timer_restorer(void) {
    __asm__ volatile("mov $15, %%rax\n\tsyscall"
                     ::: "rax", "rcx", "r11", "memory");
}

static volatile sig_atomic_t got;
static volatile long t_signo, t_code, t_errno, t_pid, t_uid;

static void timer_handler(int sig, siginfo_t *si, void *ucontext) {
    (void)ucontext;
    t_signo = sig;
    t_code  = si->si_code;
    t_errno = si->si_errno;
    t_pid   = si->si_pid;
    t_uid   = si->si_uid;
    __atomic_store_n(&got, 1, __ATOMIC_RELEASE);
}

/* Kernel x86-64 rt_sigaction layout (declared above). */
static long raw_sigaction(int sig, const struct local_sigaction *act,
                          struct local_sigaction *old, unsigned long ssz) {
    return rsys(SYS_rt_sigaction_, sig, (long)act, (long)old, ssz, 0, 0);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "oracle";
    if (!strcmp(mode, "refuse")) {
        struct local_itimerval v;
        zero_itimerval(&v); v.vusec = 1000;
        emit_num("WHICH=", rsys(SYS_setitimer_, 1 /* ITIMER_PROF */,
                                (long)&v, 0, 0, 0, 0));
        zero_itimerval(&v); v.iusec = 1000; v.vusec = 1000;
        emit_num("INTERVAL=", rsys(SYS_setitimer_, ITIMER_REAL_,
                                   (long)&v, 0, 0, 0, 0));
        zero_itimerval(&v); v.vsec = 2;
        emit_num("VALUE=", rsys(SYS_setitimer_, ITIMER_REAL_,
                                (long)&v, 0, 0, 0, 0));
        emit_num("ALARM=", rsys(SYS_alarm_, 2, 0, 0, 0, 0, 0));
        zero_itimerval(&v);
        emit_num("GETWHICH=", rsys(SYS_getitimer_, 1, (long)&v, 0, 0, 0, 0));
        emit_num("BADPTR=", rsys(SYS_setitimer_, ITIMER_REAL_,
                                 0x1000L, 0, 0, 0, 0));
        return 0;
    }

    struct local_sigaction sa;
    sa.handler  = (uint64_t)(uintptr_t)&timer_handler;
    sa.flags    = SA_SIGINFO_ | SA_RESTORER_;
    sa.restorer = (uint64_t)(uintptr_t)&timer_restorer;
    sa.mask     = 0;
    emit_num("SET-RC=", raw_sigaction(SIGALRM_, &sa, 0, 8));

    struct local_itimerval v;
    zero_itimerval(&v); v.vusec = 1;          /* 1 us => one virtual tick */
    emit_num("ITIMER-RC=", rsys(SYS_setitimer_, ITIMER_REAL_,
                                (long)&v, 0, 0, 0, 0));
    for (int i = 0; i < 2048 &&
                    !__atomic_load_n(&got, __ATOMIC_ACQUIRE); i++)
        (void)rsys(SYS_sched_yield_, 0, 0, 0, 0, 0, 0);

    emit_num("SIG=", t_signo);
    emit_num("CODE=", t_code);
    emit_num("ERRNO=", t_errno);
    emit_num("PID=", t_pid);
    emit_num("UID=", t_uid);
    emit_num("GOT=", got);
    return 0;
}
