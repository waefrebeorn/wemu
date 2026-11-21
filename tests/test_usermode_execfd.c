/* test_usermode_execfd — differential gate for BOUNDED fd-relative execveat
 * in the native user-mode executor.
 *
 * 1. Policy predicate: only AT_FDCWD/no-flags, fd-relative/no-flags and
 *    fd/AT_EMPTY_PATH shapes are eligible; other flag bits, AT_FDCWD with
 *    AT_EMPTY_PATH and unknown/negative dirfd all fail closed.
 * 2. AT_EMPTY_PATH on a guest-opened fd: the SAME static-PIE fixture runs
 *    under a real host execveat and under WEMU.  stdout bytes, exit code and
 *    exec count must be byte-exact (execs==1).
 * 3. fd-relative execveat(dfd, "base", ..., 0) with an admitted directory fd:
 *    byte-exact vs host execveat, execs==1.
 * 4. Negative controls ("old path must refuse"): an fd the guest never opened
 *    (guest-visible -EBADF, byte-exact vs host), an unsupported flag bit
 *    (-EINVAL, byte-exact vs host), and the AT_FDCWD+AT_EMPTY_PATH old form
 *    (-EINVAL) all leave the image intact (execs==0, denied>0).
 * 5. fail-closed dev/ino fallback when kcmp is unavailable (forced off for the
 *    gate): an unchanged admitted fd still execs byte-exact; a close+reopen
 *    onto a different inode still refuses (wrong OFD).
 * 6. bounded fexecve parity for FD_CLOEXEC admitted fds: NEW path honours the
 *    internal dup (byte-exact, exit 42) and a guest fd census proves the dup
 *    does not leak; the OLD all-refuse path is kept as a negative control.
 * License: WaefreBeorn Umbrella License v3.0. */
#define _GNU_SOURCE
#include "wemu_usermode.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define FAIL(...) do { fprintf(stderr, "FAIL: " __VA_ARGS__); exit(1); } while (0)

#define GUEST_BIN "tests/exec_chain"
static char *const GUEST_ENV[] = { (char *)"PATH=/usr/bin:/bin", NULL };
static const char *const WANT = "STAGE2: [alpha] [beta (two)]\n";

typedef struct { char b[WEMU_UM_OUT_MAX]; size_t n; } Cap;

static void print_exact(const char *tag, const char *p, size_t n) {
    printf("  %-9s exact stdout (%zu bytes): \"", tag, n);
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)p[i];
        if (c == '\n') fputs("\\n", stdout);
        else if (c >= 0x20 && c < 0x7f) putchar(c);
        else printf("\\x%02x", c);
    }
    printf("\"\n");
}

static void check_exact(const char *tag, const char *got, size_t gn,
                        const char *want, size_t wn) {
    if (gn != wn || memcmp(got, want, wn) != 0)
        FAIL("%s: output mismatch (%zu bytes) got=[%s] want=[%s]\n",
             tag, gn, got, want);
    print_exact(tag, got, gn);
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

static void test_policy(void) {
    if (wemu_um_execveat_modeled(AT_FDCWD, 0) != 1 ||
        wemu_um_execveat_modeled(AT_FDCWD, AT_EMPTY_PATH) != 0 ||
        wemu_um_execveat_modeled(3, 0) != 1 ||
        wemu_um_execveat_modeled(3, AT_EMPTY_PATH) != 1 ||
        wemu_um_execveat_modeled(3, AT_EMPTY_PATH | 0x2000u) != 0 ||
        wemu_um_execveat_modeled(3, 0x2000u) != 0 ||
        wemu_um_execveat_modeled(-1, 0) != 0 ||
        wemu_um_execveat_modeled(-5, AT_EMPTY_PATH) != 0)
        FAIL("execveat shape policy: CWD/fd-relative/fd-exec only; "
             "other flags and unknown dirfd refused\n");
    printf("ok: FAIL-CLOSED execveat shape — CWD/fd-relative/AT_EMPTY_PATH, "
           "unsupported flags + unknown dirfd refused\n");
}

/* Positive differential: an admitted fd describes the new image. */
static void test_differential(const char *tag, char *const argv[],
                              int want_exit) {
    Cap oracle;
    int he = host_exec(argv, &oracle);
    if (he != want_exit)
        FAIL("%s: host oracle exit=%d want %d\n", tag, he, want_exit);
    check_exact("host", oracle.b, oracle.n, WANT, strlen(WANT));

    WemuUmResult r;
    int rc = wemu_um_run_elf(GUEST_BIN, argv, GUEST_ENV, &r);
    if (rc != WEMU_UM_OK)
        FAIL("%s: status=%s out=[%s]\n", tag, wemu_um_status_name(rc), r.out);
    if (r.exit_code != want_exit || r.execs != 1 || r.denied != 0)
        FAIL("%s: exit=%d execs=%u denied=%llu want %d/1/0\n", tag,
             r.exit_code, r.execs, (unsigned long long)r.denied, want_exit);
    check_exact(tag, r.out, r.out_len, oracle.b, oracle.n);
    printf("        (exit=%d, execs=%u; == host execveat)\n", r.exit_code,
           r.execs);
}

/* Negative control whose errno is also the host's: byte-exact.stdout. */
static void test_negative_host_exact(const char *tag, char *const argv[],
                                     const char *want, int want_exit) {
    Cap oracle;
    int he = host_exec(argv, &oracle);
    if (he != want_exit)
        FAIL("%s: host oracle exit=%d want %d\n", tag, he, want_exit);
    check_exact("host", oracle.b, oracle.n, want, strlen(want));

    WemuUmResult r;
    int rc = wemu_um_run_elf(GUEST_BIN, argv, GUEST_ENV, &r);
    if (rc != WEMU_UM_OK)
        FAIL("%s: status=%s out=[%s]\n", tag, wemu_um_status_name(rc), r.out);
    if (r.exit_code != want_exit || r.execs != 0 || r.denied == 0)
        FAIL("%s: exit=%d execs=%u denied=%llu want %d/0/>0\n", tag,
             r.exit_code, r.execs, (unsigned long long)r.denied, want_exit);
    check_exact(tag, r.out, r.out_len, oracle.b, oracle.n);
    printf("ok: NEGATIVE CONTROL %-14s -> %s, denied=%llu, no replacement\n",
           tag, wemu_um_status_name(rc), (unsigned long long)r.denied);
}

/* Strong admission-control proof: the supervisor opens a valid ELF fd and
 * hands its number to the guest, which never opened it.  The real host
 * execveat succeeds (byte-exact STAGE2 output), but WEMU must refuse with
 * -EBADF and no replacement — proving the fd table is actually enforced. */
static void test_negative_unadmitted_real_fd(void) {
    int fd = open(GUEST_BIN, O_RDONLY);
    if (fd < 0) FAIL("open supervisor fd\n");
    char fds[16];
    snprintf(fds, sizeof fds, "%d", fd);
    char a0[] = GUEST_BIN;
    char *av[] = { a0, (char *)"fdarg", fds, NULL };

    Cap oracle;
    int he = host_exec(av, &oracle);
    if (he != 42 || oracle.n != strlen(WANT) ||
        memcmp(oracle.b, WANT, oracle.n) != 0)
        FAIL("fdarg host oracle: exit=%d out=[%s] (fd was not valid)\n",
             he, oracle.b);

    WemuUmResult r;
    int rc = wemu_um_run_elf(GUEST_BIN, av, GUEST_ENV, &r);
    close(fd);
    if (rc != WEMU_UM_OK || r.exit_code != 13 || r.execs != 0 ||
        r.denied == 0 || strcmp(r.out, "FDARG-RC=-9\n") != 0)
        FAIL("fdarg: status=%s exit=%d execs=%u denied=%llu out=[%s]\n",
             wemu_um_status_name(rc), r.exit_code, r.execs,
             (unsigned long long)r.denied, r.out);
    printf("ok: NEGATIVE CONTROL supervisor fd (host would exec) -> -EBADF, "
           "denied=%llu, no replacement\n", (unsigned long long)r.denied);
}

/* Close+reopen fd-NUMBER reuse.  The host executes the reopened file
 * (PIE-LOAD-BIAS-OK, exit 0).  The OLD number-only path (OFD check disabled)
 * matches the host byte-exact; the DEFAULT path detects the changed OFD and
 * refuses with -EBADF, leaving the image intact.  This proves the hardening
 * actually changes behaviour rather than merely refusing everything. */
static void test_fd_reuse(void) {
    char a0[] = GUEST_BIN;
    char *av[] = { a0, (char *)"reuse", (char *)GUEST_BIN,
                   (char *)"tests/pie_hello", NULL };
    const char *want = "PIE-LOAD-BIAS-OK\n";

    Cap oracle;
    int he = host_exec(av, &oracle);
    if (he != 0) FAIL("fd-reuse: host oracle exit=%d want 0\n", he);
    check_exact("host", oracle.b, oracle.n, want, strlen(want));

    /* OLD path: number-only admission still execs the reopened fd. */
    if (wemu_um_set_fd_ofd_check_enabled(0) != 0)
        FAIL("fd-reuse: set_fd_ofd_check_enabled(0)\n");
    WemuUmResult oldr;
    int rc = wemu_um_run_elf(GUEST_BIN, av, GUEST_ENV, &oldr);
    if (rc != WEMU_UM_OK || oldr.exit_code != 0 || oldr.execs != 1 ||
        oldr.denied != 0 || strcmp(oldr.out, want) != 0)
        FAIL("fd-reuse OLD path: status=%s exit=%d execs=%u denied=%llu out=[%s]\n",
             wemu_um_status_name(rc), oldr.exit_code, oldr.execs,
             (unsigned long long)oldr.denied, oldr.out);
    check_exact("old-reuse", oldr.out, oldr.out_len, oracle.b, oracle.n);

    /* NEW path (default): reused number is refused, no image replacement. */
    if (wemu_um_set_fd_ofd_check_enabled(1) != 0)
        FAIL("fd-reuse: set_fd_ofd_check_enabled(1)\n");
    WemuUmResult r;
    rc = wemu_um_run_elf(GUEST_BIN, av, GUEST_ENV, &r);
    if (rc != WEMU_UM_OK || r.exit_code != 16 || r.execs != 0 ||
        r.denied == 0 || strcmp(r.out, "REUSE-RC=-9\n") != 0)
        FAIL("fd-reuse NEW path: status=%s exit=%d execs=%u denied=%llu out=[%s]\n",
             wemu_um_status_name(rc), r.exit_code, r.execs,
             (unsigned long long)r.denied, r.out);
    printf("ok: NEGATIVE CONTROL reused-number fd -> -EBADF, denied=%llu, "
           "no replacement (OLD path execs byte-exact)\n",
           (unsigned long long)r.denied);
}

/* O_CLOEXEC fd on fexecve: the host honours it via an internal dup.  The NEW
 * bounded path now does too (a private high fd, closed before guest code runs)
 * — byte-exact vs host.  The fd_cloexec_refuse switch reproduces the OLD
 * all-refuse path as a negative control (-EBADF, no replacement). */
static void test_cloexec(void) {
    char a0[] = GUEST_BIN;
    char *av[] = { a0, (char *)"cloexec", (char *)GUEST_BIN, NULL };

    Cap oracle;
    int he = host_exec(av, &oracle);
    if (he != 42 || oracle.n != strlen(WANT) ||
        memcmp(oracle.b, WANT, oracle.n) != 0)
        FAIL("cloexec: host oracle exit=%d out=[%s]\n", he, oracle.b);

    /* Number-only OLD path still admits it (byte-exact). */
    if (wemu_um_set_fd_ofd_check_enabled(0) != 0)
        FAIL("cloexec: set_fd_ofd_check_enabled(0)\n");
    WemuUmResult oldr;
    int rc = wemu_um_run_elf(GUEST_BIN, av, GUEST_ENV, &oldr);
    if (rc != WEMU_UM_OK || oldr.exit_code != 42 || oldr.execs != 1 ||
        oldr.denied != 0 || strcmp(oldr.out, WANT) != 0)
        FAIL("cloexec number-only path: status=%s exit=%d execs=%u out=[%s]\n",
             wemu_um_status_name(rc), oldr.exit_code, oldr.execs, oldr.out);

    /* NEW hardened path: OFD check on, fexecve internal-dup honoured. */
    if (wemu_um_set_fd_ofd_check_enabled(1) != 0 ||
        wemu_um_set_fd_cloexec_refuse(0) != 0)
        FAIL("cloexec: enable hardened fexecve path\n");
    WemuUmResult r;
    rc = wemu_um_run_elf(GUEST_BIN, av, GUEST_ENV, &r);
    if (rc != WEMU_UM_OK || r.exit_code != 42 || r.execs != 1 ||
        r.denied != 0 || strcmp(r.out, WANT) != 0)
        FAIL("cloexec NEW path: status=%s exit=%d execs=%u denied=%llu "
             "out=[%s]\n", wemu_um_status_name(rc), r.exit_code, r.execs,
             (unsigned long long)r.denied, r.out);
    check_exact("cloexec", r.out, r.out_len, oracle.b, oracle.n);

    /* NEGATIVE CONTROL: OLD all-refuse path reproduces the prior -EBADF. */
    if (wemu_um_set_fd_cloexec_refuse(1) != 0)
        FAIL("cloexec: set_fd_cloexec_refuse(1)\n");
    WemuUmResult rejr;
    rc = wemu_um_run_elf(GUEST_BIN, av, GUEST_ENV, &rejr);
    if (rc != WEMU_UM_OK || rejr.exit_code != 18 || rejr.execs != 0 ||
        rejr.denied == 0 || strcmp(rejr.out, "CLOEXEC-RC=-9\n") != 0)
        FAIL("cloexec OLD all-refuse: status=%s exit=%d execs=%u denied=%llu "
             "out=[%s]\n", wemu_um_status_name(rc), rejr.exit_code,
             rejr.execs, (unsigned long long)rejr.denied, rejr.out);
    if (wemu_um_set_fd_cloexec_refuse(0) != 0)
        FAIL("cloexec: restore fd_cloexec_refuse(0)\n");
    printf("ok: O_CLOEXEC admitted fd — NEW fexecve dup byte-exact (exit 42); "
           "OLD all-refuse -> -EBADF, no replacement\n");
}

/* dev/ino fallback when kcmp is unavailable.  Forcing kcmp off (-ENOSYS)
 * exercises the fallback deterministically: an admitted fd whose identity is
 * UNCHANGED still execs byte-exact, while a close+reopen that reuses the fd
 * NUMBER onto a DIFFERENT inode (wrong OFD) is still refused. */
static void test_kcmp_fallback(void) {
    char a0[] = GUEST_BIN;
    char *av_empty[] = { a0, (char *)"empty", (char *)GUEST_BIN, NULL };

    Cap oracle;
    int he = host_exec(av_empty, &oracle);
    if (he != 42 || oracle.n != strlen(WANT) ||
        memcmp(oracle.b, WANT, oracle.n) != 0)
        FAIL("kcmp-fallback: host oracle exit=%d out=[%s]\n", he, oracle.b);

    if (wemu_um_set_fd_kcmp_forced_off(1) != 0)
        FAIL("kcmp-fallback: set_fd_kcmp_forced_off(1)\n");

    /* Same admitted fd: dev/ino matches the captured identity -> exec. */
    WemuUmResult r;
    int rc = wemu_um_run_elf(GUEST_BIN, av_empty, GUEST_ENV, &r);
    if (rc != WEMU_UM_OK || r.exit_code != 42 || r.execs != 1 ||
        r.denied != 0 || strcmp(r.out, WANT) != 0)
        FAIL("kcmp-fallback same fd: status=%s exit=%d execs=%u denied=%llu "
             "out=[%s]\n", wemu_um_status_name(rc), r.exit_code, r.execs,
             (unsigned long long)r.denied, r.out);
    check_exact("fb-same", r.out, r.out_len, oracle.b, oracle.n);

    /* Wrong OFD (different inode via close+reuse): must still refuse. */
    char *av_reuse[] = { a0, (char *)"reuse", (char *)GUEST_BIN,
                         (char *)"tests/pie_hello", NULL };
    rc = wemu_um_run_elf(GUEST_BIN, av_reuse, GUEST_ENV, &r);
    if (rc != WEMU_UM_OK || r.exit_code != 16 || r.execs != 0 ||
        r.denied == 0 || strcmp(r.out, "REUSE-RC=-9\n") != 0)
        FAIL("kcmp-fallback wrong OFD: status=%s exit=%d execs=%u denied=%llu "
             "out=[%s]\n", wemu_um_status_name(rc), r.exit_code, r.execs,
             (unsigned long long)r.denied, r.out);

    if (wemu_um_set_fd_kcmp_forced_off(0) != 0)
        FAIL("kcmp-fallback: restore fd_kcmp_forced_off(0)\n");
    printf("ok: kcmp-forced-off dev/ino fallback — same-fd exec byte-exact; "
           "wrong-OFD (different inode) refused\n");
}

/* Extract the FDCOUNT=N line printed by the env-gated guest fd census. */
static int fd_census(const char *out, size_t n) {
    const char *p = out;
    size_t left = n;
    while (left >= 8 && memcmp(p, "FDCOUNT=", 8) != 0) { p++; left--; }
    if (left < 8) return -1;
    int v = 0;
    for (const char *q = p + 8; *q >= '0' && *q <= '9'; q++) v = v * 10 + (*q - '0');
    return v;
}

/* Non-leak control: the bounded fexecve internal dup must be private.  With
 * an fd census enabled in the new image, a plain admitted-fd exec and a
 * CLOEXEC admitted-fd exec must expose the SAME number of open fds.  A dup
 * left open by the CLOEXEC path would add one and fail this comparison. */
static void test_cloexec_no_leak(void) {
    char a0[] = GUEST_BIN;
    char *env[] = { (char *)"PATH=/usr/bin:/bin",
                    (char *)"WEMU_FD_CENSUS=1", NULL };
    char *av_empty[] = { a0, (char *)"empty", (char *)GUEST_BIN, NULL };
    char *av_clo[]   = { a0, (char *)"cloexec", (char *)GUEST_BIN, NULL };
    WemuUmResult plain, clo;
    int rc = wemu_um_run_elf(GUEST_BIN, av_empty, env, &plain);
    if (rc != WEMU_UM_OK || plain.exit_code != 42 || plain.execs != 1)
        FAIL("fd-census plain: status=%s exit=%d execs=%u out=[%s]\n",
             wemu_um_status_name(rc), plain.exit_code, plain.execs, plain.out);
    rc = wemu_um_run_elf(GUEST_BIN, av_clo, env, &clo);
    if (rc != WEMU_UM_OK || clo.exit_code != 42 || clo.execs != 1)
        FAIL("fd-census cloexec: status=%s exit=%d execs=%u out=[%s]\n",
             wemu_um_status_name(rc), clo.exit_code, clo.execs, clo.out);
    int cp = fd_census(plain.out, plain.out_len);
    int cc = fd_census(clo.out, clo.out_len);
    if (cp < 0 || cc < 0 || cp != cc)
        FAIL("fexecve internal dup leaks into guest: plain=%d cloexec=%d\n", cp, cc);
    printf("ok: fexecve CLOEXEC internal dup does not leak into guest "
           "(fd census %d == %d)\n", cp, cc);
}

int main(void) {
    test_policy();

    /* AT_EMPTY_PATH on a fd opened via openat -> admitted fd exec. */
    char empty[] = GUEST_BIN;
    char *av_empty[] = { empty, (char *)"empty", (char *)GUEST_BIN, NULL };
    test_differential("AT_EMPTY_PATH", av_empty, 42);
    printf("ok: AT_EMPTY_PATH execveat on an admitted fd — byte-exact vs host\n");

    /* dirfd-relative path on an admitted directory fd. */
    char *av_rel[] = { empty, (char *)"rel", (char *)"tests",
                       (char *)"exec_chain", NULL };
    test_differential("dirfd-relative", av_rel, 42);
    printf("ok: fd-relative execveat on an admitted dirfd — byte-exact vs host\n");

    /* Old/fail-closed forms. */
    char *av_ufd[] = { empty, (char *)"unknownfd", NULL };
    test_negative_host_exact("unknownfd", av_ufd, "UNKNOWNFD-RC=-9\n", 10);

    /* A real, valid fd the guest never opened: host execs, WEMU refuses. */
    test_negative_unadmitted_real_fd();

    /* close+reopen that reuses an admitted fd NUMBER: refused with the new
     * OFD check, byte-exact vs host with the old number-only path. */
    test_fd_reuse();

    /* O_CLOEXEC fd on fexecve: NEW path honours the bounded internal dup. */
    test_cloexec();
    test_cloexec_no_leak();

    /* kcmp forced off: dev/ino fallback admits the same fd, still refuses a
     * wrong OFD (close+reopen onto a different inode). */
    test_kcmp_fallback();

    char *av_bf[] = { empty, (char *)"badflags", (char *)GUEST_BIN, NULL };
    test_negative_host_exact("badflags", av_bf, "BADFLAGS-RC=-22\n", 11);

    /* AT_FDCWD + AT_EMPTY_PATH (no fd) is refused by POLICY (host would exec
     * the path) — assert WEMU's fail-closed result, not host-exact output. */
    char *av_flags[] = { empty, (char *)"flags", (char *)GUEST_BIN, NULL };
    WemuUmResult r;
    int rc = wemu_um_run_elf(GUEST_BIN, av_flags, GUEST_ENV, &r);
    if (rc != WEMU_UM_OK || r.exit_code != 3 || r.execs != 0 ||
        r.denied == 0 || strcmp(r.out, "FLAGS-RC=-22\n") != 0)
        FAIL("old-path flags: status=%s exit=%d execs=%u denied=%llu out=[%s]\n",
             wemu_um_status_name(rc), r.exit_code, r.execs,
             (unsigned long long)r.denied, r.out);
    printf("ok: NEGATIVE CONTROL (old path) AT_FDCWD+AT_EMPTY_PATH -> "
           "-EINVAL, denied=%llu, no replacement\n",
           (unsigned long long)r.denied);

    printf("WEMU BOUNDED EXECVEAT-FD GATE PASS (admitted-fd fd-exec + "
           "dirfd-relative byte-exact vs host; dev/ino fallback on kcmp-off; "
           "fexecve CLOEXEC internal-dup parity; fail-closed unknown fd/flags)\n");
    return 0;
}
