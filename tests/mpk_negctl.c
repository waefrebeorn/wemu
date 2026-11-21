/* mpk_negctl.c — negative-control driver built against the UNMODIFIED
 * 1b09ea3 executor by tools/mpk_negctl.sh.  Uses only the pre-MPK public API
 * so it links against the old libwemu.  It maps a host-only secret, runs the
 * same freestanding isolate_probe in "load" mode, and shows:
 *   - isolation ON  : the old munmap path blocks the read (no bytes), but the
 *                     old result has NO pkey evidence fields at all;
 *   - isolation OFF : the old shared-address-space path observes and prints
 *                     the host secret — the observable difference that a
 *                     CPU-enforced pkey gate must detect.
 * The MPK gate (test_usermode_mpk) instead reports SEGV_PKUERR + si_pkey. */
#define _GNU_SOURCE
#include "wemu_usermode.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static const char SECRET[17] = "H0ST-SECRET-DO-N";

static int run_load(uint8_t *sec, int isolate_on, WemuUmResult *r) {
    char hex[32];
    snprintf(hex, sizeof hex, "%llx", (unsigned long long)(uintptr_t)sec);
    char *argv[] = { (char *)"isolate_probe", (char *)"load", hex, NULL };
    char *env[] = { NULL };
    wemu_um_set_isolation_enabled(isolate_on);
    return wemu_um_run_elf("tests/isolate_probe", argv, env, r);
}

int main(void) {
    uint8_t *secret = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (secret == MAP_FAILED) return 2;
    memcpy(secret, SECRET, 16);
    uint8_t *arena = mmap(NULL, 2u << 20, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (arena == MAP_FAILED) return 2;
    wemu_um_set_guest_arena(arena, 2u << 20);
    wemu_um_isolate_host_pages(secret, 4096);

    WemuUmResult r;
    int rc_on = run_load(secret, 1, &r);
    int blocked_on = (rc_on == WEMU_UM_ERR_FAULT) &&
                     !memmem(r.out, r.out_len, SECRET, 16);
    printf("OLD-EXECUTOR isolation ON : status=%s host_pages_hidden=%u "
           "secret_leaked=%d (munmap path; NO pkey fields in old API)\n",
           wemu_um_status_name(rc_on), r.host_pages_hidden,
           memmem(r.out, r.out_len, SECRET, 16) != NULL);

    int rc_off = run_load(secret, 0, &r);
    int leaked_off = memmem(r.out, r.out_len, SECRET, 16) != NULL;
    printf("OLD-EXECUTOR isolation OFF: status=%s out_len=%u out=[%s] "
           "secret_leaked=%d\n",
           wemu_um_status_name(rc_off), r.out_len, r.out, leaked_off);

    munmap(arena, 2u << 20);
    munmap(secret, 4096);
    /* Expect the old path to block when isolated and leak when switched off:
     * that is the differential the new hardware-enforced gate improves on. */
    return (blocked_on && leaked_off) ? 0 : 1;
}
