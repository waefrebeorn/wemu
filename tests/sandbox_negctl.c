/* sandbox_negctl.c — ABI-compatible runner for the pre-change and hardened
 * WEMU libraries.  Uses only fields present in BOTH wemu_usermode.h versions
 * so the same source builds against either, proving the differential is in
 * the executor and not in the gate. */
#define _GNU_SOURCE
#include "wemu_usermode.h"
#include <stdio.h>

int main(int argc, char **argv) {
    WemuUmResult r;
    const char *mode = argc > 2 ? argv[2] : "exec";
    char *av[] = { (char *)"probe", (char *)mode, NULL };
    char *ev[] = { (char *)"PATH=/usr/bin:/bin", NULL };
    int rc = wemu_um_run_elf(argv[1], av, ev, &r);
    printf("mode=%-8s status=%-12s(%d) out_len=%u out=[%s]\n",
           mode, wemu_um_status_name(rc), rc, r.out_len, r.out);
    return 0;
}
