#!/bin/sh
# sandbox_negctl.sh — differential negative control for the WEMU native
# user-mode sandbox hardening.  Builds a PRISTINE pre-change libwemu.a from
# the pinned base commit and runs the SAME guest probe + SAME runner against
# both libraries.  The hardened library must refuse what the old one admitted.
set -eu
BASE=${1:-e484379}
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

make -C "$ROOT" -s libwemu.a tests/sandbox_probe
git -C "$ROOT" archive "$BASE" | tar -x -C "$TMP"
make -C "$TMP" -s libwemu.a

cc -O2 -I"$TMP/include" -o "$TMP/negctl_old" \
   "$ROOT/tests/sandbox_negctl.c" "$TMP/libwemu.a" -lm
cc -O2 -I"$ROOT/include" -o "$TMP/negctl_new" \
   "$ROOT/tests/sandbox_negctl.c" "$ROOT/libwemu.a" -lm

PROBE="$ROOT/tests/sandbox_probe"
echo "--- PRE-CHANGE WEMU ($BASE) ---"
for m in exec mprotect ptr brk; do "$TMP/negctl_old" "$PROBE" "$m"; done
echo "--- HARDENED WEMU (this tree) ---"
for m in exec mprotect ptr brk; do "$TMP/negctl_new" "$PROBE" "$m"; done
