/* test_usermode_threadexec — differential gate for BOUNDED execve from a
 * non-main shared-VM CLONE_THREAD guest in the native user-mode executor.
 *
 * 1. Shape policy: only the modeled CLONE_THREAD form (VM + THREAD + SIGHAND
 *    + SETTLS/TID bits) is eligible; namespace/exit-signal/pidfd/no-VM and
 *    plain (non-thread) shapes fail closed.
 * 2. Positive differential: a static-PIE fixture whose NON-MAIN thread calls
 *    execve() of a fresh stage-2 image runs under the real host kernel and
 *    under WEMU.  stdout bytes + exit code + exec count are byte-exact
 *    (execs==1, exec_thread==1).
 * 3. Negative control ("old path must refuse"): with thread-exec disabled,
 *    the same fixture is refused exactly as in the OLD path (-EBUSY, guest
 *    prints THREADEXEC-REFUSED, execs==0, denied>0, no replacement).
 * License: WaefreBeorn Umbrella License v3.0. */
#define _GNU_SOURCE
#include "wemu_usermode.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define FAIL(...) do { fprintf(stderr, "FAIL: " __VA_ARGS__); exit(1); } while (0)

#define GUEST_BIN "tests/thread_exec"
static char *const GUEST_ENV[] = { (char *)"PATH=/usr/bin:/bin", NULL };
static const char *const WANT = "STAGE2: [alpha] [beta (two)]\n";

typedef struct { char b[WEMU_UM_OUT_MAX]; size_t n; } Cap;

static void check_exact(const char *tag, const char *got, size_t gn,
                        const char *want, size_t wn) {
    if (gn != wn || memcmp(got, want, wn) != 0)
        FAIL("%s: output mismatch (%zu bytes) got=[%s] want=[%s]\n",
             tag, gn, got, want);
}

/* Independent oracle: the REAL host kernel runs the same fixture/argv. */
static int host_exec(char *const argv[], Cap *cap) {
    memset(cap, 0, sizeof *cap);
    int p[2];
    if (pipe(p) != 0) FAIL("oracle pipe\n");
    pid_t pid = fork();
    if (pid == 0) {
        close(p[0]);
        if (dup2(p[1], 1) < 0) _exit(126);
        close(p[1]);
        execve(GUEST_BIN, argv, GUEST_ENV);
        _exit(127);
    }
    close(p[1]);
    for (;;) {
        ssize_t k = read(p[0], cap->b + cap->n, sizeof cap->b - 1 - cap->n);
        if (k > 0) cap->n += (size_t)k;
        else if (k == 0) break;
        else if (errno == EINTR) continue;
        else break;
    }
    close(p[0]);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) { }
    cap->b[cap->n] = '\0';
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* Raw x86-64 clone flags (no libc dependency in the gate's policy check). */
#define F_VM       0x00000100ull
#define F_SIGHAND  0x00000800ull
#define F_THREAD   0x00010000ull
#define F_SETTLS   0x00080000ull
#define F_SETTID   0x01000000ull
#define F_NEWUSER  0x10000000ull
#define F_PIDFD    0x00001000ull
#define F_SIGCHLD  0x00000011ull

static void test_policy(void) {
    const uint64_t good = F_VM | F_SIGHAND | F_THREAD | F_SETTLS | F_SETTID;
    if (wemu_um_thread_exec_modeled(good) != 1)
        FAIL("modeled CLONE_THREAD shape must be admitted for exec\n");
    if (wemu_um_thread_exec_modeled(good | F_NEWUSER) ||
        wemu_um_thread_exec_modeled(good | F_PIDFD) ||
        wemu_um_thread_exec_modeled(good | F_SIGCHLD) ||
        wemu_um_thread_exec_modeled(good & ~F_VM) ||
        wemu_um_thread_exec_modeled(good & ~F_THREAD) ||
        wemu_um_thread_exec_modeled(0))
        FAIL("unsupported thread shapes must fail closed\n");
    if (wemu_um_set_thread_exec_enabled(2) != -1 ||
        wemu_um_set_thread_exec_enabled(1) != 0)
        FAIL("thread-exec negative-control switch validation\n");
    printf("ok: FAIL-CLOSED exec-from-thread shape — modeled CLONE_THREAD only; "
           "namespace/pidfd/exit-signal/no-VM/non-thread refused\n");
}

static void test_positive(void) {
    char prog[] = GUEST_BIN;
    char *argv[] = { prog, (char *)"stage1", NULL };

    Cap oracle;
    int he = host_exec(argv, &oracle);
    if (he != 42) FAIL("host oracle exit=%d want 42\n", he);
    check_exact("host", oracle.b, oracle.n, WANT, strlen(WANT));

    WemuUmResult r;
    int rc = wemu_um_run_elf(GUEST_BIN, argv, GUEST_ENV, &r);
    if (rc != WEMU_UM_OK)
        FAIL("thread-exec status=%s out=[%s]\n", wemu_um_status_name(rc), r.out);
    if (r.exit_code != 42 || r.execs != 1 || r.exec_thread != 1 || r.denied != 0)
        FAIL("thread-exec exit=%d execs=%u exec_thread=%u denied=%llu "
             "want 42/1/1/0\n", r.exit_code, r.execs, r.exec_thread,
             (unsigned long long)r.denied);
    check_exact("wemu", r.out, r.out_len, oracle.b, oracle.n);
    printf("        (exit=%d, execs=%u, exec_thread=%u; == host execve)\n",
           r.exit_code, r.execs, r.exec_thread);
    printf("ok: BOUNDED execve from non-main CLONE_THREAD — byte-exact vs host, "
           "register/TLS state reset on image swap\n");
}

static void test_negative_old_path(void) {
    char prog[] = GUEST_BIN;
    char *argv[] = { prog, (char *)"stage1", NULL };

    if (wemu_um_set_thread_exec_enabled(0) != 0) FAIL("disable thread-exec\n");
    WemuUmResult r;
    int rc = wemu_um_run_elf(GUEST_BIN, argv, GUEST_ENV, &r);
    (void)wemu_um_set_thread_exec_enabled(1);   /* restore default */
    if (rc != WEMU_UM_OK || r.exit_code != 7 || r.execs != 0 ||
        r.exec_thread != 0 || r.denied == 0 ||
        strcmp(r.out, "THREADEXEC-REFUSED\n") != 0)
        FAIL("old-path negative control: status=%s exit=%d execs=%u "
             "exec_thread=%u denied=%llu out=[%s]\n",
             wemu_um_status_name(rc), r.exit_code, r.execs, r.exec_thread,
             (unsigned long long)r.denied, r.out);
    printf("ok: NEGATIVE CONTROL (old path) thread-exec disabled -> -EBUSY, "
           "denied=%llu, no replacement\n", (unsigned long long)r.denied);
}

int main(void) {
    test_policy();
    test_positive();
    test_negative_old_path();
    printf("WEMU BOUNDED THREAD-EXEC GATE PASS (non-main CLONE_THREAD execve "
           "byte-exact vs host; old path refuses)\n");
    return 0;
}
