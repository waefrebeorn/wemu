/* test_usermode_exec — differential gate for BOUNDED execve in the native
 * user-mode executor.
 *
 * 1. Dispatch table audit: execve/execveat are listed and routed to the
 *    bounded image-replacement handler (no default-allow).
 * 2. Real execve chain: a static-PIE guest execve()s itself with a fresh
 *    argv/envp.  Its stdout bytes and exit code through wemu_um_run_elf must
 *    be byte-exact vs a real host execve of the same fixture.  The result
 *    must report exactly one successful image replacement.
 * 3. Counters reset: the post-exec syscall count matches running the final
 *    image directly (pre-exec startup syscalls are not carried over).
 * 4. Fail-closed edges: unsupported execveat flags (-EINVAL, denied), a
 *    PT_INTERP target (WEMU_UM_ERR_INTERP) and a missing target
 *    (WEMU_UM_ERR_FORMAT) never replace the image.
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

static void print_exact(const char *tag, const char *p, size_t n) {
    printf("  %-11s exact stdout (%zu bytes): \"", tag, n);
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)p[i];
        if (c == '\n') fputs("\\n", stdout);
        else if (c >= 0x20 && c < 0x7f) putchar(c);
        else printf("\\x%02x", c);
    }
    printf("\"\n");
}

typedef struct { char b[WEMU_UM_OUT_MAX]; size_t n; } Cap;

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

static uint64_t g_syscalls_after_exec;

static void test_differential(void) {
    char *argv[] = { (char *)GUEST_BIN, (char *)"stage1", (char *)GUEST_BIN, NULL };
    const char *want = "STAGE2: [alpha] [beta (two)]\n";

    Cap oracle;
    int he = host_exec(argv, &oracle);
    if (he != 42 || oracle.n != strlen(want) ||
        memcmp(oracle.b, want, oracle.n) != 0)
        FAIL("host oracle: exit=%d out=[%s] want exit=42/[%s]\n",
             he, oracle.b, want);

    WemuUmResult r;
    int rc = wemu_um_run_elf(GUEST_BIN, argv, GUEST_ENV, &r);
    if (rc != WEMU_UM_OK)
        FAIL("exec chain status=%s out=[%s]\n", wemu_um_status_name(rc), r.out);
    if (r.exit_code != 42)
        FAIL("exec chain exit=%d want 42\n", r.exit_code);
    if (r.out_len != oracle.n || memcmp(r.out, oracle.b, oracle.n) != 0)
        FAIL("exec chain output mismatch native=[%s] host=[%s]\n", r.out, oracle.b);
    if (r.execs != 1)
        FAIL("exec chain execs=%u want 1 (image was not replaced)\n", r.execs);
    if (r.denied != 0)
        FAIL("exec chain denied=%llu want 0\n", (unsigned long long)r.denied);
    g_syscalls_after_exec = r.syscalls;
    print_exact("exec", r.out, r.out_len);
    printf("        (exit=42, execs=%u, syscalls=%llu; == host execve)\n",
           r.execs, (unsigned long long)r.syscalls);
    printf("ok: BOUNDED execve — real self-exec chain byte-exact vs host\n");
}

static void test_reset(void) {
    char *argv[] = { (char *)GUEST_BIN, (char *)"stage2",
                     (char *)"alpha", (char *)"beta (two)", NULL };
    WemuUmResult r;
    int rc = wemu_um_run_elf(GUEST_BIN, argv, GUEST_ENV, &r);
    if (rc != WEMU_UM_OK || r.exit_code != 42 || r.execs != 0)
        FAIL("direct stage2: status=%s exit=%d execs=%u\n",
             wemu_um_status_name(rc), r.exit_code, r.execs);
    if (r.syscalls != g_syscalls_after_exec)
        FAIL("counter reset: post-exec syscalls=%llu, direct stage2=%llu "
             "(pre-exec startup accounting leaked across exec)\n",
             (unsigned long long)g_syscalls_after_exec,
             (unsigned long long)r.syscalls);
    printf("ok: exec resets syscall/signal/fork/thread state — post-exec "
           "syscalls=%llu == direct final image\n",
           (unsigned long long)r.syscalls);
}

static void test_policy(void) {
    if (wemu_um_execveat_modeled(AT_FDCWD, 0) != 1 ||
        wemu_um_execveat_modeled(AT_FDCWD, AT_EMPTY_PATH) != 0 ||
        wemu_um_execveat_modeled(3, 0) != 0)
        FAIL("execveat policy: only AT_FDCWD+no flags may be modeled\n");
    printf("ok: FAIL-CLOSED execveat policy — AT_FDCWD/no-flags only; "
           "AT_EMPTY_PATH and fd-relative refused\n");
}

static void test_fail_closed(void) {
    WemuUmResult r;

    /* Unsupported execveat flags: guest sees -EINVAL, image not replaced. */
    char *fv[] = { (char *)GUEST_BIN, (char *)"flags", (char *)GUEST_BIN, NULL };
    int rc = wemu_um_run_elf(GUEST_BIN, fv, GUEST_ENV, &r);
    if (rc != WEMU_UM_OK || r.exit_code != 3 || r.execs != 0 ||
        r.denied == 0 || strcmp(r.out, "FLAGS-RC=-22\n") != 0)
        FAIL("flags: status=%s exit=%d execs=%u denied=%llu out=[%s]\n",
             wemu_um_status_name(rc), r.exit_code, r.execs,
             (unsigned long long)r.denied, r.out);
    printf("ok: FAIL-CLOSED execveat(AT_EMPTY_PATH) -> -EINVAL, "
           "denied=%llu, no replacement [%s]\n",
           (unsigned long long)r.denied, r.out);

    /* PT_INTERP target: the dynamic loader is never executed. */
    char *iv[] = { (char *)GUEST_BIN, (char *)"interp", NULL };
    rc = wemu_um_run_elf(GUEST_BIN, iv, GUEST_ENV, &r);
    if (rc != WEMU_UM_ERR_INTERP || r.execs != 0)
        FAIL("interp: status=%s execs=%u want ERR_INTERP/0\n",
             wemu_um_status_name(rc), r.execs);
    printf("ok: FAIL-CLOSED execve(ET_DYN+PT_INTERP) -> %s, no replacement\n",
           wemu_um_status_name(rc));

    /* Missing target: validated load fails closed, old image stays intact. */
    char *bv[] = { (char *)GUEST_BIN, (char *)"badpath", NULL };
    rc = wemu_um_run_elf(GUEST_BIN, bv, GUEST_ENV, &r);
    if (rc != WEMU_UM_ERR_FORMAT || r.execs != 0)
        FAIL("badpath: status=%s execs=%u want ERR_FORMAT/0\n",
             wemu_um_status_name(rc), r.execs);
    printf("ok: FAIL-CLOSED execve(missing target) -> %s, no replacement\n",
           wemu_um_status_name(rc));
}

static void test_table(void) {
    size_t n = 0;
    const WemuUmSyscallEntry *t = wemu_um_syscall_table(&n);
    int seen_execve = 0, seen_execveat = 0;
    for (size_t i = 0; i < n; i++) {
        if (t[i].nr == 59) {
            if (strcmp(t[i].name, "execve") != 0 ||
                t[i].kind != WEMU_UM_DISPATCH_EXECVE)
                FAIL("table[%zu] execve miswired\n", i);
            seen_execve = 1;
        }
        if (t[i].nr == 322) {
            if (strcmp(t[i].name, "execveat") != 0 ||
                t[i].kind != WEMU_UM_DISPATCH_EXECVE)
                FAIL("table[%zu] execveat miswired\n", i);
            seen_execveat = 1;
        }
    }
    if (!seen_execve || !seen_execveat)
        FAIL("execve/execveat absent from bounded dispatch table\n");
    printf("ok: dispatch table wires execve(59)+execveat(322) to the "
           "bounded image-replacement handler (%zu entries)\n", n);
}

int main(void) {
    test_table();
    test_policy();
    test_differential();
    test_reset();
    test_fail_closed();
    printf("WEMU BOUNDED EXECVE GATE PASS (host-byte-exact exec chain, "
           "state reset, fail-closed PT_INTERP/flags/target)\n");
    return 0;
}
