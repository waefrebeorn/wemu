/* threaded_guest.c — differential fixture for WEMU's bounded shared-VM
 * CLONE_THREAD path.  Built as a static PIE and run both natively (host
 * execve, the independent oracle) and through wemu_um_run_elf(); the two
 * stdout streams must be byte-exact.
 *
 * All syscalls are raw inline-asm (no glibc errno/TLS writes), and the child
 * threads get an emulator-visible TLS value via CLONE_SETTLS.  Each thread
 * records a value derived from its OWN TLS index; main prints a fixed verdict
 * in a fixed order, so stdout is deterministic regardless of scheduling.
 * License: WaefreBeorn Umbrella License v3.0. */
#define _GNU_SOURCE
#include <stdint.h>

#define SYS_write_      1
#define SYS_clone_      56
#define SYS_exit_       60
#define SYS_exit_group_ 231

#define CLONE_VM_          0x00000100u
#define CLONE_SIGHAND_     0x00000800u
#define CLONE_THREAD_      0x00010000u
#define CLONE_SETTLS_      0x00080000u
#define CLONE_CHILD_SETTID_ 0x01000000u
#define CLONE_CHILD_CLEARTID_ 0x00200000u
#define CLONE_NEWUSER_     0x10000000u

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
    (void)rsys(SYS_write_, 1, (long)s, (long)n, 0, 0, 0);
}

static char stacks[2][16384] __attribute__((aligned(16)));
static char tls_area[2][4096] __attribute__((aligned(16)));
static int  ctids[2];
static volatile int done[2];
static volatile int results[2];

/* Each thread's index lives at offset 0 of its own TLS block; the kernel
 * applies it from the clone TLS argument (CLONE_SETTLS).  Reading it back is
 * the differential check that the guest's TLS was honoured. */
static inline int my_idx(void) {
    int v;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(v));
    return v;
}

static const char good[] = "TLS-VALUES-OK\n";
static const char bad[]  = "TLS-VALUES-BAD\n";
static const char neg[]  = "THREAD-FLAGS-RC=-22\n";
static const char mh[]   = "MAIN-OK\n";

static void thread_body(int idx) {
    results[idx] = 100 + idx;                 /* per-thread, shared VM */
    __atomic_store_n(&done[idx], 1, __ATOMIC_RELEASE);
    (void)rsys(SYS_exit_, 0, 0, 0, 0, 0, 0);   /* exit THIS thread only */
    __builtin_unreachable();
}

int main(void) {
    const unsigned long tf = CLONE_VM_ | CLONE_SIGHAND_ | CLONE_THREAD_ |
                             CLONE_SETTLS_ | CLONE_CHILD_SETTID_ |
                             CLONE_CHILD_CLEARTID_;
    for (int i = 0; i < 2; i++) {
        *(int *)&tls_area[i][0] = i;
        long t = rsys(SYS_clone_, (long)tf,
                      (long)(stacks[i] + sizeof stacks[i]), /* top, 16-aligned */
                      0, (long)&ctids[i], (long)&tls_area[i][0], 0);
        if (t == 0) thread_body(my_idx());   /* child: never returns */
    }

    while (!__atomic_load_n(&done[0], __ATOMIC_ACQUIRE) ||
           !__atomic_load_n(&done[1], __ATOMIC_ACQUIRE)) { }

    int tls_ok = results[0] == 100 && results[1] == 101;
    emit(tls_ok ? good : bad, tls_ok ? sizeof good - 1 : sizeof bad - 1);

    /* Negative control: real kernel refuses CLONE_NEWUSER here too. */
    long bad_rc = rsys(SYS_clone_,
                       (long)(tf | CLONE_NEWUSER_),
                       (long)(stacks[0] + sizeof stacks[0]),
                       0, (long)&ctids[0], (long)&tls_area[0][0], 0);
    if (bad_rc == -22) emit(neg, sizeof neg - 1);

    emit(mh, sizeof mh - 1);
    (void)rsys(SYS_exit_group_, 0, 0, 0, 0, 0, 0);
    return 0;
}
