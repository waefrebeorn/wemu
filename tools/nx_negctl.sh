#!/bin/sh
# Negative control for the guest page-table XD/NX fault-enforcement increment.
# Compiles the SAME "fetch from an XD-marked page" probe twice:
#   (a) against the current libwemu.a  -> must fault  (#PF, P|I/D = 0x11)
#   (b) against libwemu.a whose src/wemu_mem.o is replaced by the base
#       1b09b1e5 version (bit 63 only bookkept, never enforced) -> must leak
#       (fetch succeeds, fault=0).
# If the differential disappears the script exits non-zero.  No isolation is
# claimed beyond this reproducible differential.
set -eu
cd "$(dirname "$0")/.."
BASE=1b09b1e5
command -v gcc >/dev/null 2>&1 || { echo "gcc required" >&2; exit 2; }
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

cat > "$TMP/nx_probe.c" <<'PROBE'
#include "wemu.h"
#include "wemu_internal.h"
#include <stdio.h>
#include <stdint.h>
int main(void) {
    WemuCpu *c = wemu_cpu_create(8u << 20);
    uint64_t e;
    wemu_cpu_enable_paging(c, 0);
    e = 0x11003ull; wemu_mem_write(c, 0x10000, &e, 8);         /* PML4[0] */
    e = 0x12003ull; wemu_mem_write(c, 0x11000, &e, 8);         /* PDPT[0] */
    e = 0x13003ull; wemu_mem_write(c, 0x12000 + 16, &e, 8);    /* PD[2] */
    e = 0x2003ull | (1ull << 63);                              /* PT[0] XD */
    wemu_mem_write(c, 0x13000, &e, 8);
    wemu_cpu_set_cr3(c, 0x10000);
    wemu_cpu_enable_paging(c, 1);
    uint8_t buf[16];
    c->fault = 0; c->cr2 = 0; c->fault_error = 0;
    int r = wemu_mem_fetch(c, 0x400000, buf, 1);
    printf("NX_FETCH ret=%d fault=%d cr2=%llx err=%llx\n", r, c->fault,
           (unsigned long long)c->cr2, (unsigned long long)c->fault_error);
    wemu_cpu_destroy(c);
    return 0;
}
PROBE

# (a) current tree (fixed)
gcc -std=c11 -O0 -Iinclude -Isrc -o "$TMP/probe_fixed" "$TMP/nx_probe.c" libwemu.a -lm
FIXED=$("$TMP/probe_fixed")

# (b) same library, but wemu_mem.o from the unmodified base commit
mkdir -p "$TMP/base"
git show "$BASE:src/wemu_mem.c" > "$TMP/base/wemu_mem.c"
gcc -std=c11 -O0 -Iinclude -Isrc -c "$TMP/base/wemu_mem.c" -o "$TMP/base/wemu_mem.o"
cp libwemu.a "$TMP/libwemu_base.a"
( cd "$TMP/base" && ar r "$TMP/libwemu_base.a" wemu_mem.o )
gcc -std=c11 -O0 -Iinclude -Isrc -o "$TMP/probe_base" "$TMP/nx_probe.c" \
    "$TMP/libwemu_base.a" -lm
BASEOUT=$("$TMP/probe_base")

echo "base  $BASE: $BASEOUT"
echo "fixed HEAD:   $FIXED"

case "$BASEOUT" in *"ret=0 fault=0"*) ;; *)
    echo "nx_negctl: FAIL - base did not leak the XD fetch" >&2; exit 1;; esac
case "$FIXED" in *"fault=14"*"err=11"*) ;; *)
    echo "nx_negctl: FAIL - fixed tree did not fault #PF P|I/D" >&2; exit 1;; esac
echo "nx_negctl: PASS (base leaks XD fetch; fixed faults P|I/D)"
