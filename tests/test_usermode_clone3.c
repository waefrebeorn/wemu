/* test_usermode_clone3 — differential gate for WEMU's bounded clone3 thread
 * path, its exact fail-closed diagnostics, and the old-path negative control.
 *
 * 1. Shape policy: a v0 clone_args describing the bounded shared-VM
 *    CLONE_THREAD form is admitted; pidfd (flag or field), CLONE_CLEAR_SIGHAND,
 *    a larger struct (future per-thread sigmask), namespace/exit-signal/bad
 *    stack/TLS/TID knobs all fail closed.  The same predicate the handler uses
 *    is audited off-line here.
 * 2. Positive differential: a static-PIE fixture creates ONE bounded clone3
 *    thread; the real host kernel and WEMU must produce byte-identical stdout
 *    and exit 0, with clone3_threads==1/threads_created==1/denied==0.
 * 3. Fail closed: the fixture submits the unmodeled pidfd / signal-mask knobs.
 *    The HOST oracle accepts most of them (proving they are real host
 *    features); WEMU refuses each and records an exact WemuUmResult.refuses[]
 *    reason, creating no thread.
 * 4. Negative control (old path): with the bounded clone3 thread path
 *    disabled, the same fixture is refused exactly as before (-EINVAL, no
 *    host thread, denied>0, reason CLONE3_DISABLED).
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

#define GUEST_BIN "tests/clone3_thread"
static char *const GUEST_ENV[] = { (char *)"PATH=/usr/bin:/bin", NULL };

static const char WANT_OK[] =
    "C3-TLS-OK\nMAIN-OK\n";
static const char WANT_REFUSE[] =
    "PIDFD-FIELD-RC=-22\n"
    "PIDFD-FLAG-RC=-22\n"
    "CLEARSIGHAND-RC=-22\n"
    "SIZE-RC=-7\n"
    "SIGPROCMASK-RC=-22\n";

/* Virtual mask: SIGUSR1 (10) / SIGTERM (15) are ordinary signals; the root
 * blocks USR1, a bounded clone3 thread inherits it, blocks TERM and unblocks
 * USR1, and the root keeps its own mask.  Host and WEMU must be byte-exact. */
static const char WANT_VMASK[] =
    "VMASK-BLOCK-RC=0\n"
    "VMASK-BLOCK-OLD-USR1=0\n"
    "VMASK-QUERY-RC=0\n"
    "VMASK-ROOT-USR1=1\n"
    "VMASK-CHILD-USR1=1\n"
    "VMASK-CHILD-TERM=1\n"
    "VMASK-CHILD-AFTER=0\n"
    "VMASK-PARENT-USR1=1\n";

/* Four remaining extras: pidfd_send_signal, set_tid, cgroup and an unmodeled
 * fork shape.  Host proves they are real kernel features; WEMU refuses each.
 * With exact diagnostics OFF, pidfd_send_signal falls back to -ENOSYS. */
static const char WANT_REFUSE2[] =
    "PIDSIG-RC=-22\n"
    "SETTID-RC=-22\n"
    "CGROUP-RC=-22\n"
    "FORKSHAPE-RC=-22\n";
static const char WANT_REFUSE2_OLD[] =
    "PIDSIG-RC=-38\n"
    "SETTID-RC=-22\n"
    "CGROUP-RC=-22\n"
    "FORKSHAPE-RC=-22\n";

typedef struct { char b[WEMU_UM_OUT_MAX]; size_t n; } Cap;

/* Independent oracle: the REAL host kernel runs the same fixture/argv. */
static int host_exec(const char *mode, Cap *cap) {
    memset(cap, 0, sizeof *cap);
    int p[2];
    if (pipe(p) != 0) FAIL("oracle pipe\n");
    pid_t pid = fork();
    if (pid == 0) {
        close(p[0]);
        if (dup2(p[1], 1) < 0) _exit(126);
        close(p[1]);
        char prog[] = GUEST_BIN;
        char *argv[] = { prog, (char *)mode, NULL };
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

static int wemu_exec(const char *mode, WemuUmResult *r) {
    char prog[] = GUEST_BIN;
    char *argv[] = { prog, (char *)mode, NULL };
    return wemu_um_run_elf(GUEST_BIN, argv, GUEST_ENV, r);
}

static void check_exact(const char *tag, const char *got, size_t gn,
                        const char *want, size_t wn) {
    if (gn != wn || memcmp(got, want, wn) != 0)
        FAIL("%s: output mismatch (%zu bytes) got=[%s] want=[%s]\n",
             tag, gn, got, want);
}

/* Mirror of the kernel's struct clone_args (x86-64, v0 = 88 bytes). */
struct local_clone_args {
    uint64_t flags, pidfd, child_tid, parent_tid, exit_signal,
             stack, stack_size, tls, set_tid, set_tid_size, cgroup;
};

#define F_VM       0x00000100ull
#define F_SIGHAND  0x00000800ull
#define F_PIDFD    0x00001000ull
#define F_THREAD   0x00010000ull
#define F_NEWUSER  0x10000000ull
#define F_SETTLS   0x00080000ull
#define F_SETTID   0x01000000ull
#define F_CLEARTID 0x00200000ull

static void good_args(struct local_clone_args *ca) {
    memset(ca, 0, sizeof *ca);
    ca->flags = F_VM | F_SIGHAND | F_THREAD | F_SETTLS | F_SETTID | F_CLEARTID;
    ca->stack = 0x100000ull;
    ca->stack_size = 16384;
    ca->tls = 0x200000ull;
    ca->child_tid = 0x300000ull;
}

static void test_policy(void) {
    struct local_clone_args ca;
    good_args(&ca);
    if (!wemu_um_clone3_thread_modeled(&ca, sizeof ca))
        FAIL("bounded clone3 CLONE_THREAD shape must be admitted\n");

    good_args(&ca); ca.pidfd = 0x400000ull;
    if (wemu_um_clone3_thread_modeled(&ca, sizeof ca))
        FAIL("clone_args.pidfd must fail closed\n");
    good_args(&ca); ca.flags |= F_PIDFD;
    if (wemu_um_clone3_thread_modeled(&ca, sizeof ca))
        FAIL("CLONE_PIDFD flag must fail closed\n");
    good_args(&ca); ca.flags |= 0x100000000ull;   /* CLONE_CLEAR_SIGHAND */
    if (wemu_um_clone3_thread_modeled(&ca, sizeof ca))
        FAIL("CLONE_CLEAR_SIGHAND must fail closed\n");
    good_args(&ca);
    if (wemu_um_clone3_thread_modeled(&ca, sizeof ca + 8))
        FAIL("struct larger than v0 (future sigmask) must fail closed\n");
    good_args(&ca); ca.flags |= F_NEWUSER;
    if (wemu_um_clone3_thread_modeled(&ca, sizeof ca))
        FAIL("namespace flag must fail closed\n");
    good_args(&ca); ca.exit_signal = 17;
    if (wemu_um_clone3_thread_modeled(&ca, sizeof ca))
        FAIL("exit signal on a thread must fail closed\n");
    good_args(&ca); ca.flags &= ~F_SETTLS;        /* TLS knob with no flag */
    if (wemu_um_clone3_thread_modeled(&ca, sizeof ca))
        FAIL("TLS knob without CLONE_SETTLS must fail closed\n");
    good_args(&ca); ca.stack_size = 8;            /* too small to be a stack */
    if (wemu_um_clone3_thread_modeled(&ca, sizeof ca))
        FAIL("undersized stack must fail closed\n");
    good_args(&ca); ca.stack = UINT64_MAX - 8;    /* stack + size wraps */
    if (wemu_um_clone3_thread_modeled(&ca, sizeof ca))
        FAIL("wrapping stack must fail closed\n");
    memset(&ca, 0, sizeof ca);                   /* fork shape is not a thread */
    if (wemu_um_clone3_thread_modeled(&ca, sizeof ca))
        FAIL("fork-shaped clone3 is not the bounded thread shape\n");

    if (wemu_um_set_clone3_thread_enabled(2) != -1 ||
        wemu_um_set_clone3_thread_enabled(1) != 0)
        FAIL("clone3-thread negative-control switch validation\n");

    /* Bounded fork predicate: only a knob-free fork shape; set_tid / cgroup /
     * shared VM and a thread shape are not the bounded fork form. */
    memset(&ca, 0, sizeof ca);
    if (!wemu_um_clone3_fork_modeled(&ca, sizeof ca))
        FAIL("knob-free fork clone3 must be admitted by the fork predicate\n");
    ca.set_tid = 0x1000;
    if (wemu_um_clone3_fork_modeled(&ca, sizeof ca))
        FAIL("set_tid must fail closed in the fork predicate\n");
    memset(&ca, 0, sizeof ca); ca.cgroup = 0x1000;
    if (wemu_um_clone3_fork_modeled(&ca, sizeof ca))
        FAIL("cgroup must fail closed in the fork predicate\n");
    memset(&ca, 0, sizeof ca); ca.flags = F_VM;
    if (wemu_um_clone3_fork_modeled(&ca, sizeof ca))
        FAIL("shared VM must fail closed in the fork predicate\n");
    good_args(&ca);
    if (wemu_um_clone3_fork_modeled(&ca, sizeof ca))
        FAIL("thread shape is not the bounded fork form\n");

    /* Pure sigprocmask form predicate: ordinary signals are virtualizable,
     * WEMU control signals (SIGSYS=31, SIGALRM=14, SIGUSR2=12) are not. */
    if (!wemu_um_sigprocmask_modeled(0 /* BLOCK */, 1ull << 9 /* SIGUSR1 */) ||
        !wemu_um_sigprocmask_modeled(1 /* UNBLOCK */, 1ull << 14 /* SIGTERM */) ||
        wemu_um_sigprocmask_modeled(0, 1ull << 30 /* SIGSYS */) ||
        wemu_um_sigprocmask_modeled(0, 1ull << 13 /* SIGALRM */) ||
        wemu_um_sigprocmask_modeled(0, 1ull << 11 /* SIGUSR2 */) ||
        wemu_um_sigprocmask_modeled(99, 0))
        FAIL("sigprocmask virtualization predicate edges\n");

    if (wemu_um_set_sigmask_virtual_enabled(2) != -1 ||
        wemu_um_set_sigmask_virtual_enabled(1) != 0 ||
        wemu_um_set_exact_refuse_enabled(2) != -1 ||
        wemu_um_set_exact_refuse_enabled(1) != 0)
        FAIL("new negative-control switch validation\n");

    printf("ok: FAIL-CLOSED clone3 shape — bounded CLONE_THREAD only; pidfd/"
           "sigmask/namespace/exit-signal/bad-knob refused\n");
    printf("ok: PURE POLICY — bounded fork, virtualizable mask, and both new "
           "negative-control switches audited\n");
}

static void test_positive(void) {
    Cap oracle;
    int he = host_exec("ok", &oracle);
    if (he != 0) FAIL("host oracle exit=%d want 0\n", he);
    check_exact("host", oracle.b, oracle.n, WANT_OK, sizeof WANT_OK - 1);

    WemuUmResult r;
    int rc = wemu_exec("ok", &r);
    if (rc != WEMU_UM_OK)
        FAIL("clone3 thread status=%s out=[%s]\n", wemu_um_status_name(rc), r.out);
    if (r.exit_code != 0) FAIL("clone3 thread exit=%d want 0\n", r.exit_code);
    if (r.clone3_threads != 1 || r.threads_created != 1 || r.forks != 0 ||
        r.denied != 0 || r.execs != 0)
        FAIL("clone3 thread counts: clone3=%u threads=%u forks=%u denied=%llu "
             "execs=%u want 1/1/0/0/0\n", r.clone3_threads, r.threads_created,
             r.forks, (unsigned long long)r.denied, r.execs);
    for (unsigned i = 0; i < WEMU_UM_N_REFUSE; i++)
        if (r.refuses[i]) FAIL("positive run recorded refuse[%u]=%u\n", i, r.refuses[i]);
    check_exact("wemu", r.out, r.out_len, oracle.b, oracle.n);
    printf("        (exit=%d, clone3_threads=%u, threads=%u; == host execve)\n",
           r.exit_code, r.clone3_threads, r.threads_created);
    printf("ok: BOUNDED clone3 CLONE_THREAD — byte-exact vs host, TLS "
           "honoured, real host thread created\n");
}

static void test_fail_closed(void) {
    /* The host oracle PROVES these are real host features: pidfd creation
     * succeeds and blocking SIGSYS succeeds.  WEMU refuses all of them. */
    Cap oracle;
    int he = host_exec("refuse", &oracle);
    if (he != 0) FAIL("host refuse-mode exit=%d want 0\n", he);
    long hp, hf, hc, hs, hm;
    if (sscanf(oracle.b,
               "PIDFD-FIELD-RC=%ld\nPIDFD-FLAG-RC=%ld\nCLEARSIGHAND-RC=%ld\n"
               "SIZE-RC=%ld\nSIGPROCMASK-RC=%ld\n",
               &hp, &hf, &hc, &hs, &hm) != 5)
        FAIL("host oracle refuse output unparsable: [%s]\n", oracle.b);
    if (hp <= 0 || hf <= 0 || hc != -22 || hs != -7 || hm != 0)
        FAIL("host oracle changed: pidfd=%ld/%ld clear=%ld size=%ld "
             "sigprocmask=%ld\n", hp, hf, hc, hs, hm);

    WemuUmResult r;
    int rc = wemu_exec("refuse", &r);
    if (rc != WEMU_UM_OK)
        FAIL("refuse-mode status=%s out=[%s]\n", wemu_um_status_name(rc), r.out);
    if (r.exit_code != 0) FAIL("refuse-mode exit=%d want 0\n", r.exit_code);
    check_exact("wemu refuse", r.out, r.out_len, WANT_REFUSE, sizeof WANT_REFUSE - 1);
    if (r.clone3_threads != 0 || r.threads_created != 0 || r.forks != 0)
        FAIL("refused shapes created threads: clone3=%u threads=%u forks=%u\n",
             r.clone3_threads, r.threads_created, r.forks);
    if (r.denied != 5)
        FAIL("refuse-mode denied=%llu want 5\n", (unsigned long long)r.denied);
    /* Exact diagnostics: two pidfd shapes, CLONE_CLEAR_SIGHAND, the oversized
     * (future-sigmask) struct, and one unmodeled rt_sigprocmask. */
    if (r.refuses[WEMU_UM_REFUSE_CLONE3_PIDFD] != 2 ||
        r.refuses[WEMU_UM_REFUSE_CLONE3_SIGMASK] != 1 ||
        r.refuses[WEMU_UM_REFUSE_SIGPROCMASK] != 1 ||
        r.refuses[WEMU_UM_REFUSE_CLONE3_SIGMASK_SIZE] != 1)
        FAIL("exact refusal reasons: pidfd=%u sigmask=%u procmask=%u size=%u\n",
             r.refuses[WEMU_UM_REFUSE_CLONE3_PIDFD],
             r.refuses[WEMU_UM_REFUSE_CLONE3_SIGMASK],
             r.refuses[WEMU_UM_REFUSE_SIGPROCMASK],
             r.refuses[WEMU_UM_REFUSE_CLONE3_SIGMASK_SIZE]);
    printf("        (host accepts pidfd+SIGPROCMASK; WEMU refuses with exact "
           "reasons pidfd=2 sigmask=1 procmask=1 size=1)\n");
    printf("ok: FAIL-CLOSED pidfd/sigmask — no thread, exact refusal "
           "diagnostics, no host dispatch\n");
}

static void test_negative_old_path(void) {
    if (wemu_um_set_clone3_thread_enabled(0) != 0)
        FAIL("disable clone3 thread path\n");
    WemuUmResult r;
    int rc = wemu_exec("ok", &r);
    (void)wemu_um_set_clone3_thread_enabled(1);   /* restore default */
    if (rc != WEMU_UM_OK || r.exit_code != 7)
        FAIL("old-path negative control: status=%s exit=%d want OK/7\n",
             wemu_um_status_name(rc), r.exit_code);
    if (strcmp(r.out, "CLONE3-REFUSED\n") != 0)
        FAIL("old-path negative control output=[%s]\n", r.out);
    if (r.clone3_threads != 0 || r.threads_created != 0 || r.forks != 0 ||
        r.denied == 0 ||
        r.refuses[WEMU_UM_REFUSE_CLONE3_DISABLED] != 1)
        FAIL("old-path control: clone3=%u threads=%u forks=%u denied=%llu "
             "disabled=%u\n", r.clone3_threads, r.threads_created, r.forks,
             (unsigned long long)r.denied,
             r.refuses[WEMU_UM_REFUSE_CLONE3_DISABLED]);
    printf("ok: NEGATIVE CONTROL (old path) clone3 thread disabled -> -EINVAL, "
           "denied=%llu, no thread\n", (unsigned long long)r.denied);
}

static void test_sigmask_virtual(void) {
    Cap oracle;
    int he = host_exec("vmask", &oracle);
    if (he != 0) FAIL("host vmask exit=%d want 0\n", he);
    check_exact("host vmask", oracle.b, oracle.n, WANT_VMASK, sizeof WANT_VMASK - 1);

    WemuUmResult r;
    int rc = wemu_exec("vmask", &r);
    if (rc != WEMU_UM_OK)
        FAIL("vmask status=%s out=[%s]\n", wemu_um_status_name(rc), r.out);
    if (r.exit_code != 0) FAIL("vmask exit=%d want 0\n", r.exit_code);
    if (r.clone3_threads != 1 || r.threads_created != 1 || r.forks != 0 ||
        r.denied != 0 || r.execs != 0)
        FAIL("vmask counts: c3=%u threads=%u forks=%u denied=%llu execs=%u\n",
             r.clone3_threads, r.threads_created, r.forks,
             (unsigned long long)r.denied, r.execs);
    if (r.refuses[WEMU_UM_REFUSE_SIGPROCMASK] != 0)
        FAIL("vmask refused an ordinary signal mask: %u\n",
             r.refuses[WEMU_UM_REFUSE_SIGPROCMASK]);
    /* Eight rt_sigprocmask calls in the fixture (block/query root, four in
     * the child, final parent query) must all be served from thread state. */
    if (r.sigmask_virtualized < 8)
        FAIL("vmask virtualized=%u want >=8\n", r.sigmask_virtualized);
    const uint64_t usr1_bit = 1ull << (10 - 1);   /* kernel sigset: bit N-1 */
    if (r.host_sigmask_end & usr1_bit)
        FAIL("guest SIGUSR1 leaked to the real host mask: %llx\n",
             (unsigned long long)r.host_sigmask_end);
    check_exact("wemu vmask", r.out, r.out_len, oracle.b, oracle.n);
    printf("        (virtualized=%u, host_sigmask_end=%llx; == host)\n",
           r.sigmask_virtualized, (unsigned long long)r.host_sigmask_end);
    printf("ok: VIRTUAL per-thread signal masks — byte-exact vs host, inherit "
           "across CLONE_THREAD, host mask untouched\n");

    /* NEGATIVE CONTROL (old path): with virtualization off, rt_sigprocmask is
     * passed to the host from inside the SIGSYS handler; the handler's
     * sigreturn restores the pre-syscall mask, so the guest's block never
     * persists and the byte stream no longer matches the kernel oracle. */
    if (wemu_um_set_sigmask_virtual_enabled(0) != 0)
        FAIL("disable per-thread mask virtualization\n");
    WemuUmResult old;
    rc = wemu_exec("vmask", &old);
    (void)wemu_um_set_sigmask_virtual_enabled(1);   /* restore default */
    if (rc != WEMU_UM_OK || old.exit_code != 0)
        FAIL("old-path vmask: status=%s exit=%d\n",
             wemu_um_status_name(rc), old.exit_code);
    if (old.sigmask_virtualized != 0)
        FAIL("old path still used the virtual mask: %u\n", old.sigmask_virtualized);
    if (strstr(old.out, "VMASK-ROOT-USR1=0\n") == NULL)
        FAIL("old path unexpectedly persisted the guest mask: [%s]\n", old.out);
    printf("ok: NEGATIVE CONTROL (mask pass-through) — virtualized=0, guest "
           "mask lost at sigreturn, bytes differ from host\n");
}

static void test_fail_closed2(void) {
    /* The host oracle proves every shape is a REAL kernel feature: none
     * returns -ENOSYS, pidfd_send_signal with a bad fd is -EBADF, set_tid
     * without privilege is -EPERM, and the unmodeled fork shape spawns. */
    Cap oracle;
    int he = host_exec("2", &oracle);
    if (he != 0) FAIL("host refuse2 exit=%d want 0\n", he);
    long hp, hst, hc, hf;
    if (sscanf(oracle.b,
               "PIDSIG-RC=%ld\nSETTID-RC=%ld\nCGROUP-RC=%ld\nFORKSHAPE-RC=%ld\n",
               &hp, &hst, &hc, &hf) != 4)
        FAIL("host refuse2 output unparsable: [%s]\n", oracle.b);
    if (hp == -38 || hst == -38 || hc == -38 || hf == -38)
        FAIL("host oracle returned ENOSYS for a real feature: %ld/%ld/%ld/%ld\n",
             hp, hst, hc, hf);
    if (hp != -9 || hf <= 0)
        FAIL("host oracle changed: pidsig=%ld forkbad=%ld\n", hp, hf);

    WemuUmResult r;
    int rc = wemu_exec("2", &r);
    if (rc != WEMU_UM_OK)
        FAIL("refuse2 status=%s out=[%s]\n", wemu_um_status_name(rc), r.out);
    if (r.exit_code != 0) FAIL("refuse2 exit=%d want 0\n", r.exit_code);
    check_exact("wemu refuse2", r.out, r.out_len, WANT_REFUSE2, sizeof WANT_REFUSE2 - 1);
    if (r.clone3_threads != 0 || r.threads_created != 0 || r.forks != 0)
        FAIL("refuse2 created processes: c3=%u threads=%u forks=%u\n",
             r.clone3_threads, r.threads_created, r.forks);
    if (r.denied != 4)
        FAIL("refuse2 denied=%llu want 4\n", (unsigned long long)r.denied);
    if (r.refuses[WEMU_UM_REFUSE_PIDFD_SEND_SIGNAL] != 1 ||
        r.refuses[WEMU_UM_REFUSE_CLONE3_SET_TID] != 1 ||
        r.refuses[WEMU_UM_REFUSE_CLONE3_CGROUP] != 1 ||
        r.refuses[WEMU_UM_REFUSE_CLONE3_FORK_SHAPE] != 1)
        FAIL("refuse2 exact reasons: pidsig=%u settid=%u cgroup=%u fork=%u\n",
             r.refuses[WEMU_UM_REFUSE_PIDFD_SEND_SIGNAL],
             r.refuses[WEMU_UM_REFUSE_CLONE3_SET_TID],
             r.refuses[WEMU_UM_REFUSE_CLONE3_CGROUP],
             r.refuses[WEMU_UM_REFUSE_CLONE3_FORK_SHAPE]);
    printf("        (host pidsig=%ld settid=%ld cgroup=%ld forkbad=%ld; WEMU "
           "refuses with exact reasons 1/1/1/1)\n", hp, hst, hc, hf);
    printf("ok: FAIL-CLOSED extras — pidfd_send_signal/set_tid/cgroup/"
           "unmodeled-fork-shape refused with exact diagnostics\n");

    /* NEGATIVE CONTROL (coarse diagnostics): with exact reasons off, the old
     * path returns generic -ENOSYS for pidfd_send_signal and folds all three
     * clone3 extras into CLONE3_SHAPE. */
    if (wemu_um_set_exact_refuse_enabled(0) != 0)
        FAIL("disable exact refuse diagnostics\n");
    WemuUmResult old;
    rc = wemu_exec("2", &old);
    (void)wemu_um_set_exact_refuse_enabled(1);      /* restore default */
    if (rc != WEMU_UM_OK || old.exit_code != 0)
        FAIL("old-path refuse2: status=%s exit=%d\n",
             wemu_um_status_name(rc), old.exit_code);
    check_exact("wemu refuse2 old", old.out, old.out_len,
                WANT_REFUSE2_OLD, sizeof WANT_REFUSE2_OLD - 1);
    if (r.refuses[WEMU_UM_REFUSE_PIDFD_SEND_SIGNAL] != 1 ||
        old.refuses[WEMU_UM_REFUSE_PIDFD_SEND_SIGNAL] != 0 ||
        old.refuses[WEMU_UM_REFUSE_CLONE3_SET_TID] != 0 ||
        old.refuses[WEMU_UM_REFUSE_CLONE3_CGROUP] != 0 ||
        old.refuses[WEMU_UM_REFUSE_CLONE3_FORK_SHAPE] != 0 ||
        old.refuses[WEMU_UM_REFUSE_CLONE3_SHAPE] != 3)
        FAIL("old-path coarse diagnostics: pidsig=%u settid=%u cgroup=%u "
             "fork=%u shape=%u\n",
             old.refuses[WEMU_UM_REFUSE_PIDFD_SEND_SIGNAL],
             old.refuses[WEMU_UM_REFUSE_CLONE3_SET_TID],
             old.refuses[WEMU_UM_REFUSE_CLONE3_CGROUP],
             old.refuses[WEMU_UM_REFUSE_CLONE3_FORK_SHAPE],
             old.refuses[WEMU_UM_REFUSE_CLONE3_SHAPE]);
    printf("ok: NEGATIVE CONTROL (coarse diagnostics) — -ENOSYS + generic "
           "CLONE3_SHAPE=3 instead of four exact reasons\n");
}

int main(void) {
    wemu_um_reset_isolation();
    test_policy();
    test_positive();
    test_fail_closed();
    test_sigmask_virtual();
    test_fail_closed2();
    test_negative_old_path();
    printf("WEMU BOUNDED CLONE3-THREAD GATE PASS (host-byte-exact bounded "
           "thread + virtual per-thread masks; pidfd/tid/cgroup/fork fail "
           "closed; old paths refuse)\n");
    return 0;
}
