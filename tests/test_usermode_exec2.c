/* test_usermode_exec2 — differential gate for BOUNDED #! script dispatch and
 * exec from a FORKED CHILD in the native user-mode executor.
 *
 * 1. Policy predicate: bounded #! parsing accepts only a terminated line with
 *    a non-empty interpreter; empty/unterminated/overlong forms fail closed.
 * 2. Real #! script fixtures (with and without an optional interpreter arg):
 *    the SAME static-PIE interpreter runs under a real host execve and under
 *    WEMU.  stdout bytes, exit code, exec count must be byte-exact.
 * 3. Real fork+child-exec fixture: a COW child replaces its image; the guest
 *    parent's wait4 must still see the child's real exit code.  Byte-exact vs
 *    the host oracle, execs==1, forks==1.
 * 4. Negative controls ("old path must refuse"): a PT_INTERP interpreter, an
 *    unterminated #! line, a self-referential script (recursion bound), and
 *    AT_EMPTY_PATH execveat all refuse with no image replacement.
 * License: WaefreBeorn Umbrella License v3.0. */
#define _GNU_SOURCE
#include "wemu_usermode.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define FAIL(...) do { fprintf(stderr, "FAIL: " __VA_ARGS__); exit(1); } while (0)

#define INTERP_BIN "tests/script_interp"
#define DRIVER_BIN "tests/exec_script"
#define FORK_BIN   "tests/exec_fork"
#define SCRIPT_A   "tests/wemu_script_a.scr"
#define SCRIPT_B   "tests/wemu_script_b.scr"
#define SCRIPT_BAD "tests/wemu_script_bad.scr"
#define SCRIPT_LOOP "tests/wemu_script_loop.scr"
static char *const GUEST_ENV[] = { (char *)"PATH=/usr/bin:/bin", NULL };

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

/* Independent oracle: the REAL host kernel execve()s the fixture. */
static int host_exec(const char *path, char *const argv[], Cap *cap) {
    memset(cap, 0, sizeof *cap);
    int p[2];
    if (pipe(p) != 0) FAIL("oracle pipe\n");
    pid_t pid = fork();
    if (pid == 0) {
        close(p[0]);
        if (dup2(p[1], 1) < 0) _exit(126);
        close(p[1]);
        execve(path, argv, GUEST_ENV);
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

static void write_script(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    if (!f) FAIL("create %s\n", path);
    fputs(text, f);
    fclose(f);
    /* The real host kernel requires the execute bit on a #! target; WEMU's
     * bounded loader does not, but the differential oracle does. */
    if (chmod(path, 0755) != 0) FAIL("chmod %s\n", path);
}

static void abs_path(const char *rel, char *out, size_t cap) {
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd)) FAIL("getcwd\n");
    int n = snprintf(out, cap, "%s/%s", cwd, rel);
    if (n < 0 || (size_t)n >= cap) FAIL("abs path too long\n");
}

static void test_policy(void) {
    char good_opt[512];
    abs_path(INTERP_BIN, good_opt, sizeof good_opt);
    char line[600];
    int n = snprintf(line, sizeof line, "#!%s OPT\nbody\n", good_opt);
    if (n < 0 || (size_t)n >= sizeof line) FAIL("policy line\n");
    if (wemu_um_exec_script_modeled(line, strlen(line)) != 1)
        FAIL("policy: valid #! with optional arg must be modeled\n");

    int n2 = snprintf(line, sizeof line, "#!%s\nbody\n", good_opt);
    if (n2 < 0 || (size_t)n2 >= sizeof line) FAIL("policy line2\n");
    if (wemu_um_exec_script_modeled(line, strlen(line)) != 1)
        FAIL("policy: valid #! without optional arg must be modeled\n");

    const char *bad[] = {
        "#!\nbody\n",                    /* empty interpreter */
        "#!/bin/sh",                     /* unterminated line */
        "#!   \nbody\n",                 /* only whitespace */
        "#!",                            /* too short */
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
        if (wemu_um_exec_script_modeled(bad[i], strlen(bad[i])) != 0)
            FAIL("policy: malformed #! [%s] must fail closed\n", bad[i]);

    char over[400];
    memset(over, 'x', sizeof over);
    over[0] = '#'; over[1] = '!'; over[sizeof over - 1] = '\n';
    if (wemu_um_exec_script_modeled(over, sizeof over) != 0)
        FAIL("policy: overlong #! line must fail closed\n");

    const char elf[] = { '\177', 'E', 'L', 'F', '\n', '\0' };
    if (wemu_um_exec_script_modeled(elf, 4) != 0)
        FAIL("policy: ELF header is not a script\n");

    printf("ok: FAIL-CLOSED #! policy — bounded line only; empty/unterminated/"
           "overlong/ELF refused\n");
}

static void test_script(const char *script, const char *tag,
                        const char *want, int want_exit, int want_opt) {
    /* The top-level run starts from the driver ELF; its execve targets the
     * script, on both the host oracle and WEMU. */
    char d0[512], d1[512];
    char *argv[] = { d0, d1, NULL };
    snprintf(d0, sizeof d0, "%s", DRIVER_BIN);
    snprintf(d1, sizeof d1, "%s", script);

    Cap oracle;
    int he = host_exec(DRIVER_BIN, argv, &oracle);
    if (he != want_exit)
        FAIL("%s: host oracle exit=%d want %d\n", tag, he, want_exit);
    check_exact("host", oracle.b, oracle.n, want, strlen(want));

    WemuUmResult r;
    int rc = wemu_um_run_elf(DRIVER_BIN, argv, GUEST_ENV, &r);
    if (rc != WEMU_UM_OK)
        FAIL("%s: status=%s out=[%s]\n", tag, wemu_um_status_name(rc), r.out);
    if (r.exit_code != want_exit || r.execs != 1)
        FAIL("%s: exit=%d execs=%u want %d/1\n", tag, r.exit_code, r.execs,
             want_exit);
    check_exact(tag, r.out, r.out_len, oracle.b, oracle.n);
    printf("        (exit=%d, execs=%u, optional_arg=%d; == host execve)\n",
           r.exit_code, r.execs, want_opt);
}

static void test_script_differential(void) {
    char interp[4096];
    abs_path(INTERP_BIN, interp, sizeof interp);

    char text[8192];
    int n = snprintf(text, sizeof text,
                     "#!%s SCRIPT_OPT\nbody line (ignored by interpreter)\n",
                     interp);
    if (n < 0 || (size_t)n >= sizeof text) FAIL("script text\n");
    write_script(SCRIPT_A, text);

    char expected[8192];
    snprintf(expected, sizeof expected,
             "INTERP: [%s] [SCRIPT_OPT] [%s] [u1] [u2]\n", interp, SCRIPT_A);
    test_script(SCRIPT_A, "script", expected, 23, 1);
    printf("ok: BOUNDED #! script (with optional arg) byte-exact vs host\n");

    n = snprintf(text, sizeof text, "#!%s\nbody (no optional arg)\n", interp);
    if (n < 0 || (size_t)n >= sizeof text) FAIL("script text B\n");
    write_script(SCRIPT_B, text);
    snprintf(expected, sizeof expected,
             "INTERP: [%s] [%s] [u1] [u2]\n", interp, SCRIPT_B);
    test_script(SCRIPT_B, "script2", expected, 23, 0);
    printf("ok: BOUNDED #! script (no optional arg) byte-exact vs host\n");
}

static void test_child_exec(void) {
    static char b0[512], b1[512];
    char *argv[] = { b0, b1, NULL };
    snprintf(b0, sizeof b0, "%s", FORK_BIN);
    snprintf(b1, sizeof b1, "root");

    const char *want = "PRE-EXEC: child before replacement\n"
                       "CHILD-EXEC: image replaced\n"
                       "PARENT: child exit=37\n";
    Cap oracle;
    int he = host_exec(FORK_BIN, argv, &oracle);
    if (he != 0) FAIL("child-exec host oracle exit=%d want 0\n", he);
    check_exact("host", oracle.b, oracle.n, want, strlen(want));

    WemuUmResult r;
    int rc = wemu_um_run_elf(FORK_BIN, argv, GUEST_ENV, &r);
    if (rc != WEMU_UM_OK)
        FAIL("child-exec status=%s out=[%s]\n", wemu_um_status_name(rc), r.out);
    if (r.exit_code != 0 || r.execs != 1 || r.forks != 1)
        FAIL("child-exec exit=%d execs=%u forks=%u want 0/1/1\n",
             r.exit_code, r.execs, r.forks);
    check_exact("child", r.out, r.out_len, oracle.b, oracle.n);
    printf("        (exit=0, execs=%u, forks=%u; == host fork+execve)\n",
           r.execs, r.forks);
    printf("ok: FORKED-CHILD exec byte-exact vs host; wait4 sees child exit 37\n");
}

static void expect_refusal(const char *tag, const char *script,
                           int want_status) {
    static char p[512], d[512];
    char *argv[] = { d, p, NULL };
    snprintf(d, sizeof d, "%s", DRIVER_BIN);
    snprintf(p, sizeof p, "%s", script);
    WemuUmResult r;
    int rc = wemu_um_run_elf(DRIVER_BIN, argv, GUEST_ENV, &r);
    if (rc != want_status || r.execs != 0)
        FAIL("%s: status=%s execs=%u want %s/0 (out=[%s])\n", tag,
             wemu_um_status_name(rc), r.execs,
             wemu_um_status_name(want_status), r.out);
    printf("ok: NEGATIVE CONTROL %-22s -> %s, no replacement\n",
           tag, wemu_um_status_name(rc));
}

static void test_negative(void) {
    /* PT_INTERP interpreter: the host would run /bin/sh, WEMU refuses. */
    write_script(SCRIPT_BAD, "#!/bin/sh\necho SHOULD-NOT-RUN\n");
    expect_refusal("PT_INTERP interpreter", SCRIPT_BAD, WEMU_UM_ERR_INTERP);

    /* Unterminated #! line: no interpreter is entered. */
    char interp[4096];
    abs_path(INTERP_BIN, interp, sizeof interp);
    char text[8192];
    int n = snprintf(text, sizeof text, "#!%s", interp);
    if (n < 0 || (size_t)n >= sizeof text) FAIL("bad script text\n");
    write_script(SCRIPT_BAD, text);
    expect_refusal("unterminated #! line", SCRIPT_BAD, WEMU_UM_ERR_SCRIPT);

    /* Self-referential script: recursion bound refuses (host returns ELOOP). */
    n = snprintf(text, sizeof text, "#!%s\nloop\n", SCRIPT_LOOP);
    if (n < 0 || (size_t)n >= sizeof text) FAIL("loop script text\n");
    write_script(SCRIPT_LOOP, text);
    expect_refusal("script recursion bound", SCRIPT_LOOP, WEMU_UM_ERR_SCRIPT);

    /* Old fd-relative form still refused: AT_EMPTY_PATH -> -EINVAL, denied. */
    char *fv[] = { (char *)"tests/exec_chain", (char *)"flags",
                   (char *)"tests/exec_chain", NULL };
    WemuUmResult r;
    int rc = wemu_um_run_elf("tests/exec_chain", fv, GUEST_ENV, &r);
    if (rc != WEMU_UM_OK || r.execs != 0 || r.denied == 0 ||
        strcmp(r.out, "FLAGS-RC=-22\n") != 0)
        FAIL("AT_EMPTY_PATH: status=%s execs=%u denied=%llu out=[%s]\n",
             wemu_um_status_name(rc), r.execs,
             (unsigned long long)r.denied, r.out);
    printf("ok: NEGATIVE CONTROL (old path) AT_EMPTY_PATH/fd-relative -> "
           "-EINVAL, denied=%llu, no replacement\n",
           (unsigned long long)r.denied);
}

int main(void) {
    test_policy();
    test_script_differential();
    test_child_exec();
    test_negative();
    printf("WEMU BOUNDED SCRIPT/FORK-EXEC GATE PASS (host-byte-exact #! "
           "dispatch + child exec, fail-closed old path)\n");
    return 0;
}
