#!/bin/sh
# tools/isolate_negctl.sh — prove the isolation gate's old path really differs.
# Build libwemu from the UNMODIFIED c2399ed executor (the parent of this leg),
# link the same isolate_probe + a minimal driver against it, and show that a
# direct guest load observes host bytes that the isolated executor blocks.
set -e
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM
mkdir -p "$TMP/src" "$TMP/include"
cp "$ROOT"/src/*.c "$TMP/src/"
cp "$ROOT"/src/*.h "$TMP/src/"
cp "$ROOT"/include/*.h "$TMP/include/"
git -C "$ROOT" show c2399ed:src/wemu_usermode.c > "$TMP/src/wemu_usermode.c"
git -C "$ROOT" show c2399ed:include/wemu_usermode.h > "$TMP/include/wemu_usermode.h"

CF="-std=c11 -O2 -g -w -I$TMP/include -I$TMP/src -fno-stack-protector"
for f in "$TMP"/src/*.c; do
    cc $CF -c "$f" -o "${f%.c}.o"
done
ar rcs "$TMP/libwemu_old.a" "$TMP"/src/*.o
cc $CF -o "$TMP/isolate_negctl" "$ROOT/tests/isolate_negctl.c" "$TMP/libwemu_old.a" -lm

echo "=== NEGATIVE CONTROL: unmodified c2399ed executor ==="
cd "$ROOT"
"$TMP/isolate_negctl"
echo "=== old path leaked host bytes (isolated path: ERR_FAULT, no bytes) ==="
