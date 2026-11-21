/* test_usermode_isolate — differential gate for process-per-guest
 * address-space isolation in the WEMU native user-mode executor.
 *
 * Supervisor (this process) creates two mappings before forking the guest:
 *   - a MAP_SHARED guest ARENA holding a known marker; the forked guest builds
 *     its SysV stack in this region, and every host-syscall pointer is checked
 *     against the registered guest region before dispatch.
 *   - a host-only SECRET page that the supervisor keeps but the guest child
 *     unmaps before it begins executing.
 *
 * Cases (all driven by the freestanding tests/isolate_probe guest):
 *   1. valid : legal in-image pointer; WEMU output must be byte-exact vs a
 *              real host execve oracle of the same probe.
 *   2. arena : pointer into the MAP_SHARED arena; must be admitted and return
 *              the supervisor's marker byte-exact (shared region + validation).
 *   3. oob   : out-of-region host pointer; WEMU must refuse (ERR_BADPTR) with
 *              zero bytes — the host secret is never read.
 *   4. load  : a DIRECT load of the host secret (invisible to any syscall
 *              validator).  With isolation ON the guest faults and emits no
 *              bytes; with isolation OFF (negative control, old behaviour)
 *              the guest observes and prints the secret bytes.
 *
 * License: WaefreBeorn Umbrella License v3.0. */
#define _GNU_SOURCE
#include "wemu_usermode.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define FAIL(...) do { fprintf(stderr, "FAIL: " __VA_ARGS__); exit(1); } while (0)
#define GUEST_BIN "tests/isolate_probe"
static char *const GUEST_ENV[] = { (char *)"PATH=/usr/bin:/bin", NULL };
static const char SECRET[17] = "H0ST-SECRET-DO-N";   /* 16 bytes + NUL */
static const char MARKER[17] = "SHARED-ARENA-OK!";   /* 16 bytes + NUL */

typedef struct { char b[WEMU_UM_OUT_MAX]; size_t n; } Cap;

static void print_exact(const char *tag, const char *p, size_t n) {
    printf("  %-9s exact bytes (%zu): \"", tag, n);
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)p[i];
        if (c == '\n') fputs("\\n", stdout);
        else if (c >= 0x20 && c < 0x7f) putchar(c);
        else printf("\\x%02x", c);
    }
    printf("\"\n");
}

/* Real native exec of the probe = independent host oracle. */
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

static int run_guest(const char *mode, uint64_t target, WemuUmResult *r) {
    char hex[32];
    snprintf(hex, sizeof hex, "%llx", (unsigned long long)target);
    char *argv[] = { (char *)GUEST_BIN, (char *)mode, hex, NULL };
    return wemu_um_run_elf(GUEST_BIN, argv, GUEST_ENV, r);
}

static int contains(const char *hay, size_t n, const char *needle) {
    return memmem(hay, n, needle, strlen(needle)) != NULL;
}

int main(void) {
    /* Supervisor-owned host SECRET (kept) and MAP_SHARED guest ARENA. */
    uint8_t *secret = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (secret == MAP_FAILED) FAIL("secret mmap\n");
    memcpy(secret, SECRET, 16);
    uint8_t *arena = mmap(NULL, 2u << 20, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (arena == MAP_FAILED) FAIL("arena mmap\n");
    memcpy(arena + (1u << 20), MARKER, 16);   /* supervisor writes the marker */

    uint64_t sec_va = (uint64_t)(uintptr_t)secret;
    uint64_t arena_va = (uint64_t)(uintptr_t)arena;
    if (wemu_um_set_guest_arena(arena, 2u << 20) != 0)
        FAIL("set_guest_arena rejected a valid MAP_SHARED region\n");
    if (wemu_um_isolate_host_pages(secret, 4096) != 0)
        FAIL("isolate_host_pages rejected a valid region\n");

    WemuUmResult r;

    /* 1. valid pointer — byte-exact vs native host oracle. */
    {
        char *ov[] = { (char *)GUEST_BIN, (char *)"valid", (char *)"0", NULL };
        Cap oracle;
        int he = host_exec(ov, &oracle);
        if (he != 0 || oracle.n != 16 || memcmp(oracle.b, "GUEST-VALID-ABC!", 16))
            FAIL("host oracle(valid): exit=%d out=[%s]\n", he, oracle.b);
        int rc = run_guest("valid", 0, &r);
        if (rc != WEMU_UM_OK || r.exit_code != 0 || r.out_len != 16 ||
            r.out_len != oracle.n || memcmp(r.out, oracle.b, oracle.n) != 0)
            FAIL("valid: status=%s out=[%s] want-byte-exact=[%s]\n",
                 wemu_um_status_name(rc), r.out, oracle.b);
        if (r.arena_lo != arena_va || r.arena_hi != arena_va + (2u << 20))
            FAIL("arena not reported: lo=0x%llx hi=0x%llx\n",
                 (unsigned long long)r.arena_lo, (unsigned long long)r.arena_hi);
        print_exact("valid", r.out, r.out_len);
        printf("ok: VALID guest pointer byte-exact vs host oracle "
               "(arena 0x%llx..0x%llx, hidden=%u)\n",
               (unsigned long long)r.arena_lo, (unsigned long long)r.arena_hi,
               r.host_pages_hidden);
    }

    /* 2. arena pointer — in-region MAP_SHARED read admitted, marker verified. */
    {
        int rc = run_guest("arena", arena_va + (1u << 20), &r);
        if (rc != WEMU_UM_OK || r.exit_code != 0 || r.out_len != 16 ||
            memcmp(r.out, MARKER, 16) != 0)
            FAIL("arena: status=%s out=[%s] want marker=[%s]\n",
                 wemu_um_status_name(rc), r.out, MARKER);
        print_exact("arena", r.out, r.out_len);
        printf("ok: MAP_SHARED ARENA pointer admitted — supervisor marker "
               "byte-exact, guest stack lives in the shared region\n");
    }

    /* 3. out-of-region syscall pointer — refused, no host bytes. */
    {
        int rc = run_guest("oob", sec_va, &r);
        if (rc != WEMU_UM_ERR_BADPTR || r.bad_ptrs != 1 ||
            r.bad_ptr_nr != 1 || r.bad_ptr_va != sec_va || r.out_len != 0 ||
            contains(r.out, r.out_len, SECRET))
            FAIL("oob: status=%s bad=%u/%u/0x%llx out=[%s]\n",
                 wemu_um_status_name(rc), r.bad_ptrs, r.bad_ptr_nr,
                 (unsigned long long)r.bad_ptr_va, r.out);
        printf("ok: OOB syscall pointer refused (%s, bad_ptr_va=0x%llx), "
               "zero host bytes (oracle secret=[%s] absent)\n",
               wemu_um_status_name(rc), (unsigned long long)r.bad_ptr_va, SECRET);
    }

    /* 4a. direct load, isolation ON — guest cannot observe host bytes. */
    {
        int rc = run_guest("load", sec_va, &r);
        if (r.host_pages_hidden != 1)
            FAIL("load: host_pages_hidden=%u want 1\n", r.host_pages_hidden);
        if (rc != WEMU_UM_ERR_FAULT || contains(r.out, r.out_len, SECRET))
            FAIL("isolated load LEAKED: status=%s out=[%s]\n",
                 wemu_um_status_name(rc), r.out);
        printf("ok: DIRECT load of host secret with isolation ON -> %s, "
               "host page unmapped (hidden=%u), secret absent\n",
               wemu_um_status_name(rc), r.host_pages_hidden);
    }

    /* 4b. NEGATIVE CONTROL — isolation OFF reproduces the old shared-address-
     *     space behaviour: the same direct load observes and prints the host
     *     secret.  This is the observable difference the gate detects. */
    {
        if (wemu_um_set_isolation_enabled(0) != 0) FAIL("disable switch\n");
        int rc = run_guest("load", sec_va, &r);
        if (r.host_pages_hidden != 0)
            FAIL("negctl: host_pages_hidden=%u want 0\n", r.host_pages_hidden);
        if (rc != WEMU_UM_OK || !contains(r.out, r.out_len, SECRET))
            FAIL("negctl: no leak (status=%s out=[%s]) — gate cannot "
                 "distinguish isolated from old path\n",
                 wemu_um_status_name(rc), r.out);
        print_exact("negctl", r.out, r.out_len);
        printf("ok: NEGATIVE CONTROL (isolation OFF) — guest OBSERVED host "
               "secret [%s], status=%s; old path differs\n",
               SECRET, wemu_um_status_name(rc));
        wemu_um_set_isolation_enabled(1);
    }

    wemu_um_reset_isolation();
    munmap(arena, 2u << 20);
    munmap(secret, 4096);
    printf("WEMU PROCESS-PER-GUEST ISOLATION GATE PASS (shared arena, "
           "pointer validation, host bytes unobservable)\n");
    return 0;
}
