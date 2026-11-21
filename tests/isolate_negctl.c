/* isolate_negctl.c — negative-control driver built against the UNMODIFIED
 * c2399ed executor by tools/isolate_negctl.sh.  Uses only the pre-isolation
 * public API so it links against the old libwemu.  It maps a host-only secret,
 * runs the same isolate_probe in "load" mode, and reports whether the guest
 * observed the host bytes.  The old shared-address-space path must leak;
 * the isolated path must not. */
#define _GNU_SOURCE
#include "wemu_usermode.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static const char SECRET[17] = "H0ST-SECRET-DO-N";

int main(void) {
    uint8_t *sec = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (sec == MAP_FAILED) return 2;
    memcpy(sec, SECRET, 16);
    char hex[32];
    snprintf(hex, sizeof hex, "%llx", (unsigned long long)(uintptr_t)sec);
    char *argv[] = { (char *)"isolate_probe", (char *)"load", hex, NULL };
    char *env[] = { NULL };
    WemuUmResult r;
    int rc = wemu_um_run_elf("tests/isolate_probe", argv, env, &r);
    int leaked = memmem(r.out, r.out_len, SECRET, 16) != NULL;
    printf("OLD-EXECUTOR negctl: status=%s out_len=%u out=[%s] secret_leaked=%d\n",
           wemu_um_status_name(rc), r.out_len, r.out, leaked);
    munmap(sec, 4096);
    return leaked ? 0 : 1;                 /* script expects the old path to leak */
}
