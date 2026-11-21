/* thread_exec — differential fixture for bounded execve from a non-main
 * CLONE_THREAD guest.  Built as a static PIE and run both natively (host
 * execve, the independent oracle) and through wemu_um_run_elf(); the two
 * stdout byte streams and exit codes must be byte-exact.
 *
 * stage1: main spawns ONE modeled shared-VM thread (CLONE_VM | CLONE_THREAD |
 * CLONE_SIGHAND | CLONE_SETTLS | CLONE_CHILD_SETTID, TLS value set), then
 * spins.  That NON-MAIN thread calls execve() of this same binary with fresh
 * argv.  On the host the kernel replaces the whole thread group and runs
 * stage2 on the caller; under WEMU the bounded thread-exec path quiesces the
 * peer and does the same.  stage2 prints a fixed line and exit_group(42).
 *
 * If the exec is refused (negative control: thread-exec disabled), the guest
 * thread prints a fixed refusal line and exits 7 — no image replacement.
 *
 * All syscalls are raw inline-asm (no glibc errno/TLS writes, no canary) so
 * the fixture is safe under the emulator-provided %fs.
 * License: WaefreBeorn Umbrella License v3.0. */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>

#define SYS_write_      1
#define SYS_clone_      56
#define SYS_execve_     59
#define SYS_exit_       60
#define SYS_exit_group_ 231

#define CLONE_VM_             0x00000100u
#define CLONE_SIGHAND_        0x00000800u
#define CLONE_THREAD_         0x00010000u
#define CLONE_SETTLS_         0x00080000u
#define CLONE_CHILD_SETTID_   0x01000000u

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

static char stack[16384] __attribute__((aligned(16)));
static char tls_area[4096] __attribute__((aligned(16)));
static int  ctid;
static volatile int ready;

/* Static (not stack-local): the CLONE_THREAD child resumes on its own stack,
 * so the execve argument vectors must live at addresses independent of the
 * parent's frame. */
static char *nargv[] = { (char *)"tests/thread_exec", (char *)"2", NULL };
static char *nenv[]  = { (char *)"THREADEXEC=1", NULL };

static const char stage2[]  = "STAGE2: [alpha] [beta (two)]\n";
static const char refused[] = "THREADEXEC-REFUSED\n";

int main(int argc, char **argv) {
    if (argc >= 2 && argv[1][0] == '2') { /* stage2: exec target */
        emit(stage2, sizeof stage2 - 1);
        (void)rsys(SYS_exit_group_, 42, 0, 0, 0, 0, 0);
        return 42;
    }

    /* stage1.  Per-thread TLS index lives at offset 0 of this thread's block;
     * CLONE_SETTLS makes the kernel (or WEMU) apply it to the new thread. */
    *(volatile int *)&tls_area[0] = 7;

    const unsigned long tf = CLONE_VM_ | CLONE_SIGHAND_ | CLONE_THREAD_ |
                             CLONE_SETTLS_ | CLONE_CHILD_SETTID_;
    long t = rsys(SYS_clone_, (long)tf,
                  (long)(stack + sizeof stack), 0, (long)&ctid,
                  (long)&tls_area[0], 0);
    if (t == 0) {
        __atomic_store_n(&ready, 1, __ATOMIC_RELEASE);
        /* Read back our TLS index: proves the guest TLS was honoured before
         * the exec resets register/TLS state to the new image. */
        int idx;
        __asm__ volatile("mov %%fs:0, %0" : "=r"(idx));
        (void)rsys(SYS_execve_, (long)nargv[0], (long)nargv, (long)nenv,
                   0, 0, 0);
        /* Only reached when the exec was refused (negative control). */
        emit(refused, sizeof refused - 1);
        (void)rsys(SYS_exit_group_, (idx == 7) ? 7 : 8, 0, 0, 0, 0, 0);
        return 7;
    }

    /* Parent main spins until the whole image is replaced (host) or until
     * WEMU quiesces this peer thread (emulated).  It never emits output. */
    for (;;) __atomic_load_n(&ready, __ATOMIC_ACQUIRE);
    return 0;
}
