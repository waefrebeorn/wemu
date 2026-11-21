/* test_usermode_mpk — differential gate for CPU-enforced guest memory
 * protection with x86-64 protection keys (MPK/pkeys) in WEMU native user-mode.
 *
 * The supervisor maps a host-only SECRET page and a MAP_SHARED guest ARENA,
 * registers both, and runs the freestanding tests/isolate_probe guest:
 *
 *   1. valid/arena : legal guest pointers stay byte-exact vs a real host
 *                    execve oracle / the supervisor's shared marker.
 *   2. load (AUTO) : a DIRECT load of the host secret is blocked by HARDWARE.
 *                    With PKU the run faults with SEGV_PKUERR and si_pkey ==
 *                    r.pkey_host (not a plain unmapped-page #PF); the secret
 *                    is never emitted.  The guest arena reads fine (its own
 *                    key is enabled), so this is a key violation, not a
 *                    general memory failure.
 *   3. load (FORCE_FALLBACK) : simulate a host without pkeys.  The run FAILS
 *                    CLOSED to the munmap hide path: still no leak, but the
 *                    fault is an unmapped-page #PF, not SEGV_PKUERR.
 *   4. load (isolation OFF) : NEGATIVE CONTROL reproducing the old shared-
 *                    address-space path — the guest observes and prints the
 *                    secret.  This is the observable difference the gate
 *                    detects; the protected paths cannot produce it.
 *
 * License: WaefreBeorn Umbrella License v3.0. */
#define _GNU_SOURCE
#include "wemu_usermode.h"

#include <errno.h>
#include <signal.h>
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
static const char SECRET[17] = "H0ST-SECRET-DO-N";
static const char MARKER[17] = "SHARED-ARENA-OK!";
#ifndef SEGV_PKUERR
#define SEGV_PKUERR 4
#endif

typedef struct { char b[WEMU_UM_OUT_MAX]; size_t n; } Cap;

static int contains(const char *hay, size_t n, const char *needle) {
    return memmem(hay, n, needle, strlen(needle)) != NULL;
}

/* Real native exec of the probe = independent byte-exact host oracle. */
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

int main(void) {
    uint8_t *secret = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (secret == MAP_FAILED) FAIL("secret mmap\n");
    memcpy(secret, SECRET, 16);
    uint8_t *arena = mmap(NULL, 2u << 20, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (arena == MAP_FAILED) FAIL("arena mmap\n");
    memcpy(arena + (1u << 20), MARKER, 16);
    uint64_t sec_va = (uint64_t)(uintptr_t)secret;
    uint64_t arena_va = (uint64_t)(uintptr_t)arena;

    if (wemu_um_set_guest_arena(arena, 2u << 20) != 0) FAIL("set_guest_arena\n");
    if (wemu_um_isolate_host_pages(secret, 4096) != 0) FAIL("isolate_host_pages\n");

    WemuUmResult r;

    /* 1. Legal guest pointers stay byte-exact under the pkey regime. */
    {
        char *ov[] = { (char *)GUEST_BIN, (char *)"valid", (char *)"0", NULL };
        Cap oracle;
        int he = host_exec(ov, &oracle);
        if (he != 0 || oracle.n != 16 || memcmp(oracle.b, "GUEST-VALID-ABC!", 16))
            FAIL("host oracle(valid)\n");
        int rc = run_guest("valid", 0, &r);
        if (rc != WEMU_UM_OK || r.exit_code != 0 || r.out_len != 16 ||
            r.out_len != oracle.n || memcmp(r.out, oracle.b, oracle.n) != 0)
            FAIL("valid: status=%s out=[%s]\n", wemu_um_status_name(rc), r.out);
        int rc2 = run_guest("arena", arena_va + (1u << 20), &r);
        if (rc2 != WEMU_UM_OK || r.out_len != 16 || memcmp(r.out, MARKER, 16))
            FAIL("arena: status=%s out=[%s]\n", wemu_um_status_name(rc2), r.out);
        printf("ok: VALID in-image pointer byte-exact vs host oracle; "
               "ARENA pointer byte-exact (guest key accessible)\n");
    }

    /* 2. AUTO mode: direct host-page load blocked by hardware. */
    if (wemu_um_set_pkey_mode(WEMU_UM_PKEY_AUTO) != 0) FAIL("pkey mode AUTO\n");
    {
        int rc = run_guest("load", sec_va, &r);
        if (rc != WEMU_UM_ERR_FAULT || r.out_len != 0 ||
            contains(r.out, r.out_len, SECRET))
            FAIL("AUTO load leaked: status=%s out=[%s]\n",
                 wemu_um_status_name(rc), r.out);
        if (r.host_pages_hidden != 1) FAIL("AUTO: host_pages_hidden=%u want 1\n",
                                           r.host_pages_hidden);
        if (r.pkey_active) {
            /* PKU path: hardware key violation with the exact host key. */
            if (r.pkey_guest < 0 || r.pkey_host < 0 ||
                r.pkey_guest == r.pkey_host)
                FAIL("AUTO: bad keys guest=%d host=%d\n", r.pkey_guest, r.pkey_host);
            if (r.fault_code != SEGV_PKUERR || r.fault_pkey != r.pkey_host)
                FAIL("AUTO: no PKU evidence (fault_code=%d want %d, "
                     "fault_pkey=%d want host key %d)\n",
                     r.fault_code, SEGV_PKUERR, r.fault_pkey, r.pkey_host);
            printf("ok: MPK ACTIVE — direct host-page load -> %s, "
                   "SEGV_PKUERR (code=%d) on pkey=%d (guest=%d), secret absent\n",
                   wemu_um_status_name(rc), r.fault_code, r.fault_pkey,
                   r.pkey_guest);
        } else {
            /* Host lacks PKU: the fail-closed munmap path must still hold. */
            if (!r.pkey_fallback || r.fault_code == SEGV_PKUERR)
                FAIL("AUTO fallback: pkey_fallback=%u fault_code=%d\n",
                     r.pkey_fallback, r.fault_code);
            printf("ok: host lacks PKU — AUTO fell back to munmap (%s), "
                   "no PKU fault, secret absent (fail-closed)\n",
                   wemu_um_status_name(rc));
        }
        /* Supervisor keeps its own mapping and secret regardless of mode. */
        if (memcmp(secret, SECRET, 16) != 0) FAIL("supervisor secret changed\n");
    }

    /* 3. Fail-closed fallback (forced): simulate no pkey support. */
    if (wemu_um_set_pkey_mode(WEMU_UM_PKEY_FORCE_FALLBACK) != 0)
        FAIL("pkey mode FORCE_FALLBACK\n");
    {
        int rc = run_guest("load", sec_va, &r);
        if (rc != WEMU_UM_ERR_FAULT || r.out_len != 0 ||
            contains(r.out, r.out_len, SECRET))
            FAIL("fallback load leaked: status=%s out=[%s]\n",
                 wemu_um_status_name(rc), r.out);
        if (r.pkey_active || !r.pkey_fallback)
            FAIL("fallback: pkey_active=%u pkey_fallback=%u\n",
                 r.pkey_active, r.pkey_fallback);
        if (r.fault_code == SEGV_PKUERR)
            FAIL("fallback: unexpected SEGV_PKUERR (code=%d)\n", r.fault_code);
        printf("ok: FAIL-CLOSED FALLBACK (pkeys forced off) — load -> %s, "
               "fault_code=%d (not PKU), secret absent\n",
               wemu_um_status_name(rc), r.fault_code);
    }

    /* 4. NEGATIVE CONTROL — isolation OFF reproduces the old shared-address-
     *    space path: the same direct load observes and prints the secret. */
    if (wemu_um_set_isolation_enabled(0) != 0) FAIL("disable switch\n");
    {
        int rc = run_guest("load", sec_va, &r);
        if (r.pkey_active || r.pkey_fallback || r.host_pages_hidden != 0)
            FAIL("negctl: unexpected protection flags\n");
        if (rc != WEMU_UM_OK || !contains(r.out, r.out_len, SECRET))
            FAIL("negctl: no leak (status=%s out=[%s]) — old path cannot be "
                 "distinguished\n", wemu_um_status_name(rc), r.out);
        printf("  negctl exact bytes (%u): \"%s\"\n", r.out_len, r.out);
        printf("ok: NEGATIVE CONTROL (isolation OFF) — guest OBSERVED host "
               "secret [%s], status=%s; protected paths differ\n",
               SECRET, wemu_um_status_name(rc));
    }

    wemu_um_set_isolation_enabled(1);
    wemu_um_set_pkey_mode(WEMU_UM_PKEY_AUTO);
    wemu_um_reset_isolation();
    munmap(arena, 2u << 20);
    munmap(secret, 4096);
    printf("WEMU MPK GATE PASS (hardware pkey fault, byte-exact guest, "
           "fail-closed fallback, old path differs)\n");
    return 0;
}
