# WEMU -- the x86-64 emulator

Runs x86-64 guest code in-process. It is the instrument the compiler back ends are
verified with, and the guest leg for programs that cannot run natively.

## Build

`make`

## Verify

`make test` -- plus the parent's `test_isa_exec` and `test_wemu_kernel`, which run
emitted code and a guest kernel through it.

## Docs

No local docs yet; the parent's `docs/compendium/04-roadmap/` carries the loop and
back-edge findings this emulator produced.
