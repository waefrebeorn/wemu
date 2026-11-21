/* test_usermode_timer.c — gate for WEMU's bounded virtual ITIMER_REAL timer.
 *
 * Positive: the SAME static-PIE fixture is run by the REAL host kernel (real
 * setitimer/SIGALRM, independent oracle) and by wemu_um_run_elf() (bounded
 * checkpoint clock).  The captured bytes must be identical: si_signo/si_code
 * (SI_KERNEL)/si_errno/si_pid/si_uid of a setitimer alarm are stable on both.
 *
 * Fail-closed: unmodeled which, periodic interval, over-long delay, alarm(>1)
 * and a guest pointer outside the mapped ranges each return an exact errno and
 * a distinct WEMU_UM_REFUSE_TIMER_* count; no timer is armed and no host
 * signal is sent.  Pure shape predicates are audited before any run.
 *
 * Negative controls: (1) timer path OFF -> setitimer is an unlisted syscall
 * (-ENOSYS), the handler never runs and the byte stream diverges from the
 * host oracle; (2) exact diagnostics OFF -> the named refusals fold back to
 * generic -ENOSYS with no exact reasons.  License: WaefreBeorn Umbrella v3.0. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "wemu_usermode.h"

#define FAIL(...) do { fprintf(stderr, "FAIL: " __VA_ARGS__); exit(1); } while (0)
#define GUEST_BIN "tests/pie_timer"
static char *const GUEST_ENV[] = { NULL };

typedef struct { char b[WEMU_UM_OUT_MAX]; size_t n; } Cap;

/* Independent oracle: the real host kernel runs the same fixture/argv. */
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

static const char WANT_ORACLE[] =
    "SET-RC=0\n"
    "ITIMER-RC=0\n"
    "SIG=14\n"
    "CODE=128\n"
    "ERRNO=0\n"
    "PID=0\n"
    "UID=0\n"
    "GOT=1\n";
static const char WANT_REFUSE[] =
    "WHICH=-22\n"
    "INTERVAL=-22\n"
    "VALUE=-22\n"
    "ALARM=-22\n"
    "GETWHICH=-22\n"
    "BADPTR=-14\n";
static const char WANT_DISABLED[] =
    "SET-RC=0\n"
    "ITIMER-RC=-38\n"
    "SIG=0\n"
    "CODE=0\n"
    "ERRNO=0\n"
    "PID=0\n"
    "UID=0\n"
    "GOT=0\n";
static const char WANT_COARSE[] =
    "WHICH=-38\n"
    "INTERVAL=-38\n"
    "VALUE=-38\n"
    "ALARM=-38\n"
    "GETWHICH=-38\n"
    "BADPTR=-38\n";

static void check_refuse_zero(const WemuUmResult *r) {
    if (r->refuses[WEMU_UM_REFUSE_TIMER_WHICH] ||
        r->refuses[WEMU_UM_REFUSE_TIMER_VALUE] ||
        r->refuses[WEMU_UM_REFUSE_TIMER_INTERVAL] ||
        r->refuses[WEMU_UM_REFUSE_TIMER_PTR] ||
        r->refuses[WEMU_UM_REFUSE_TIMER_BUSY] ||
        r->refuses[WEMU_UM_REFUSE_TIMER_TARGET])
        FAIL("timer refuses present where none expected\n");
}

int main(void) {
    /* Pure shape predicates: audited before any guest runs. */
    if (!wemu_um_timer_signal_modeled(SIGALRM) ||
        wemu_um_timer_signal_modeled(SIGUSR1) ||
        wemu_um_timer_signal_modeled(0) ||
        wemu_um_timer_signal_modeled(-1))
        FAIL("timer signal predicate edges\n");
    if (!wemu_um_timer_modeled(0, 0, 1) ||
        !wemu_um_timer_modeled(0, 0, WEMU_UM_TIMER_MAX_USEC) ||
        wemu_um_timer_modeled(1, 0, 1) ||            /* wrong which */
        wemu_um_timer_modeled(0, 1, 1) ||            /* periodic interval */
        wemu_um_timer_modeled(0, 0, 0) ||            /* disarm is not arming */
        wemu_um_timer_modeled(0, 0, WEMU_UM_TIMER_MAX_USEC + 1ull) ||
        wemu_um_timer_modeled(0, 0, ~0ull))
        FAIL("timer shape predicate edges\n");
    if (!wemu_um_sigaction_modeled(SIGALRM, 8) ||
        wemu_um_sigaction_modeled(SIGALRM, 16) ||
        !wemu_um_sigaction_modeled(SIGSEGV, 8) ||
        wemu_um_sigaction_modeled(SIGUSR1, 8))
        FAIL("timer sigaction predicate edges\n");
    if (WEMU_UM_N_REFUSE <= WEMU_UM_REFUSE_TIMER_DISABLED ||
        WEMU_UM_TIMER_MAX_TICKS !=
            WEMU_UM_TIMER_MAX_USEC / WEMU_UM_TIMER_TICK_USEC)
        FAIL("timer constants/refuse table\n");

    wemu_um_reset_isolation();          /* all switches default ON */

    /* Positive byte-exact host differential. */
    Cap host;
    int hrc = host_exec("oracle", &host);
    if (hrc != 0 || host.n != sizeof(WANT_ORACLE) - 1 ||
        memcmp(host.b, WANT_ORACLE, host.n) != 0)
        FAIL("host oracle unstable: rc=%d bytes=%zu out=[%s]\n",
             hrc, host.n, host.b);

    WemuUmResult r;
    int wrc = wemu_exec("oracle", &r);
    if (wrc != WEMU_UM_OK || strcmp(r.out, WANT_ORACLE) != 0)
        FAIL("wemu timer oracle diverges: rc=%d out=[%s]\n", wrc, r.out);
    if (r.timer_armed < 1 || r.timer_ticks < 1 || r.timer_signals < 1 ||
        r.signals_delivered < 1 || r.timer_dropped != 0 ||
        r.host_sigmask_end != 0)
        FAIL("timer evidence missing: armed=%u ticks=%u sig=%u del=%u "
             "drop=%u hostmask=%llx\n",
             r.timer_armed, r.timer_ticks, r.timer_signals,
             r.signals_delivered, r.timer_dropped,
             (unsigned long long)r.host_sigmask_end);
    check_refuse_zero(&r);
    printf("ok: BOUNDED TIMER -> per-thread pending slot, SA_SIGINFO "
           "byte-exact vs host (si_code=SI_KERNEL=128, pid/uid=0), "
           "one-shot checkpoint delivery\n");

    /* Fail-closed shapes: named errnos, named refusal counters, no signal. */
    wrc = wemu_exec("refuse", &r);
    if (wrc != WEMU_UM_OK || strcmp(r.out, WANT_REFUSE) != 0)
        FAIL("refuse stream: rc=%d out=[%s]\n", wrc, r.out);
    if (r.refuses[WEMU_UM_REFUSE_TIMER_WHICH] != 2 ||
        r.refuses[WEMU_UM_REFUSE_TIMER_VALUE] != 2 ||
        r.refuses[WEMU_UM_REFUSE_TIMER_INTERVAL] != 1 ||
        r.refuses[WEMU_UM_REFUSE_TIMER_PTR] != 1 ||
        r.refuses[WEMU_UM_REFUSE_TIMER_BUSY] ||
        r.refuses[WEMU_UM_REFUSE_TIMER_TARGET] ||
        r.timer_armed || r.timer_signals || r.bad_ptrs != 1)
        FAIL("refuse counters: which=%u value=%u interval=%u ptr=%u "
             "busy=%u target=%u armed=%u sig=%u badptr=%u\n",
             r.refuses[WEMU_UM_REFUSE_TIMER_WHICH],
             r.refuses[WEMU_UM_REFUSE_TIMER_VALUE],
             r.refuses[WEMU_UM_REFUSE_TIMER_INTERVAL],
             r.refuses[WEMU_UM_REFUSE_TIMER_PTR],
             r.refuses[WEMU_UM_REFUSE_TIMER_BUSY],
             r.refuses[WEMU_UM_REFUSE_TIMER_TARGET],
             r.timer_armed, r.timer_signals, r.bad_ptrs);
    printf("ok: FAIL-CLOSED timer — wrong which / periodic interval / "
           "over-long delay / alarm(>1) / bad pointer refused exactly, "
           "no host timer armed\n");

    /* Negative control 1: old path — timer syscalls are unlisted, the byte
     * stream loses the handler and diverges from the host oracle. */
    if (wemu_um_set_timer_enabled(0) != 0) FAIL("set_timer_enabled(0)\n");
    wrc = wemu_exec("oracle", &r);
    if (wrc != WEMU_UM_OK || strcmp(r.out, WANT_DISABLED) != 0 ||
        strcmp(r.out, host.b) == 0)
        FAIL("disabled timer did not change the byte stream: out=[%s]\n", r.out);
    if (r.refuses[WEMU_UM_REFUSE_TIMER_DISABLED] < 1 ||
        r.timer_armed || r.timer_signals || r.timer_ticks)
        FAIL("disabled timer evidence: refuses=%u armed=%u sig=%u ticks=%u\n",
             r.refuses[WEMU_UM_REFUSE_TIMER_DISABLED],
             r.timer_armed, r.timer_signals, r.timer_ticks);
    printf("ok: NEGATIVE CONTROL (timer off) — -ENOSYS, no handler, "
           "byte stream differs from the host oracle\n");
    if (wemu_um_set_timer_enabled(1) != 0) FAIL("set_timer_enabled(1)\n");

    /* Negative control 2: coarse diagnostics fold named refusals back into
     * generic -ENOSYS with no exact reasons — proves the reasons are real. */
    if (wemu_um_set_exact_refuse_enabled(0) != 0) FAIL("set_exact(0)\n");
    wrc = wemu_exec("refuse", &r);
    if (wrc != WEMU_UM_OK || strcmp(r.out, WANT_COARSE) != 0)
        FAIL("coarse refuse stream: rc=%d out=[%s]\n", wrc, r.out);
    check_refuse_zero(&r);
    if (r.denied < 6 || r.bad_ptrs != 1)
        FAIL("coarse refusals not counted as denials: denied=%llu badptr=%u\n",
             (unsigned long long)r.denied, r.bad_ptrs);
    printf("ok: NEGATIVE CONTROL (coarse diagnostics) — named timer refusals "
           "fold to -ENOSYS, exact counters zero\n");
    wemu_um_set_exact_refuse_enabled(1);

    printf("WEMU BOUNDED TIMER GATE PASS (host-byte-exact setitimer siginfo; "
           "one-shot checkpoint delivery into the per-thread pending slot; "
           "exact fail-closed intervals/signals/pointers; old-path and coarse "
           "negative controls)\n");
    return 0;
}
