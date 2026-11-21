#!/bin/sh
# tools/mpk_negctl.sh — prove the MPK gate's old path really differs.
# Build libwemu from the UNMODIFIED 1b09ea3 executor (the parent of this leg),
# link the same isolate_probe + a minimal pre-MPK driver against it, and show
# that the old path has no pkey evidence (munmap / leak) while the new gate
# reports a hardware SEGV_PKUERR with si_pkey.
set -e
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM
mkdir -p "$TMP/src" "$TMP/include"
cp "$ROOT"/src/*.c "$TMP/src/"
cp "$ROOT"/src/*.h "$TMP/src/"
cp "$ROOT"/include/*.h "$TMP/include/"
git -C "$ROOT" show 1b09ea3:src/wemu_usermode.c > "$TMP/src/wemu_usermode.c"
git -C "$ROOT" show 1b09ea3:include/wemu_usermode.h > "$TMP/include/wemu_usermode.h"

CF="-std=c11 -O2 -g -w -I$TMP/include -I$TMP/src -fno-stack-protector"
for f in "$TMP"/src/*.c; do
    cc $CF -c "$f" -o "${f%.c}.o"
done
ar rcs "$TMP/libwemu_old.a" "$TMP"/src/*.o
cc $CF -o "$TMP/mpk_negctl" "$ROOT/tests/mpk_negctl.c" "$TMP/libwemu_old.a" -lm

echo "=== NEGATIVE CONTROL: unmodified 1b09ea3 executor (no MPK) ==="
cd "$ROOT"
"$TMP/mpk_negctl"
echo "=== old path: munmap (no PKU fault / no pkey evidence) or leak when off ==="
echo "=== new path: hardware SEGV_PKUERR, si_pkey == pkey_host (see test_usermode_mpk) ==="
