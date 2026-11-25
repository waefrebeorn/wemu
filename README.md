# WEMU — the WuBu Emulator

A clean-room C11 x86-64 emulator: the sovereign guest-execution layer for
[WuBuOS](https://github.com/waefrebeorn/WuBuOS). WuBuOS is a lightweight OS
that *contains* other operating systems as guests; WEMU is how their code
runs when no host Linux is underneath — on the bare metal, under our own
kernel, on our own terms.

## Founding story

On 2026-11-19 the WuBuOS multi-host boot gate caught a real bug: Ubuntu
26.04's gcc14 defaults to x86-64-v3, so the kernel's `memset` was vectorized
with `vmovd` / `vpbroadcastb` (AVX2). QEMU's `qemu64` TCG CPU cannot decode
those instructions — `#UD` → triple fault before the IDT exists. The kernel
fix was to pin `-march=x86-64`. The deeper lesson: **the emulator is a
dependency we do not own.** WEMU exists so that the instruction sets WuBuOS
needs are ours to implement, gate, and extend — starting with the exact two
instructions that broke the boot.

## What works today (behavior-gated, `make test`)

- **Long-mode x86-64 interpreter**: REX/VEX decode, ModRM/SIB/RIP-relative
  addressing, the integer core (mov/add/sub/logic/cmp/test, push/pop,
  call/ret/jmp/jcc/loop, lea, shifts/rotates, imul/mul/div/idiv,
  movzx/movsx/movsxd, bswap, bt/bts/btr/btc, bsf/bsr, cmovcc/setcc,
  inc/dec/neg/not, cdq/cqo, cpuid/rdtsc), correct CF/PF/AF/ZF/SF/OF.
- **SSE2 + AVX/AVX2 seed**: movd/movq/movdqa(u)/pxor/pand/por/pandn/
  padd{b,w,d,q}/psub{b,w,d,q}/pshufd/psllq/psrldq/pslldq, and the VEX forms
  including **vmovd + vpbroadcastb/w/d/q** at 128 and 256 bits with correct
  upper-half zeroing.
- **4-level paging**: 4KiB and 2MiB leaves, #PF with CR2, canonical checks.
- **Machine layer**: guest RAM + COM1 UART (port I/O and syscall `write`
  both emit real serial bytes), syscall hook, honest `#UD` on anything not
  yet implemented — never a fake success.

Gates: `test_isa` (hand-assembled sequences + 400 differential cases against
an independent C model), `test_avx` (the CI-gap instructions, including the
full gcc14 memset vector body compared to native `memset`), `test_paging`,
`test_machine`.

## Roadmap

1. **ISA completion** — remaining integer ops, full SSE2/AVX2, then AVX-512
   subsets as the compiler emits them; every addition lands with a
   differential gate.
2. **JIT** — translate hot blocks to native x86-64 using the WuBuNOS
   encoder (the tree already has a self-hosted JIT stack); interpreter
   stays as the correctness oracle.
3. **VMM leg** — VT-x/AMD-V capability probe + EPT guest execution for
   native-speed guests on WuBuOS bare metal (the "load their system" path).
4. **Devices** — virtio-blk/net/console, PIT/APIC, then the machine types
   WuBuOS guests need.
5. **Integration** — WuBuOS consumes WEMU as a submodule; the guest manager
   boots Linux kernels + rootfs through it; 9P shares files both ways.

## Provenance (slerm)

WEMU is a **slerm**: a ground-up clean-room reimplementation. QEMU's
machine-model ambition and device taxonomy inspired the architecture; the
Intel SDM and AMD APM define the instruction semantics. **No QEMU source
was copied, linked, or derived.** Every line here is original C11.

License: **WaefreBeorn Umbrella License v3.0** (see LICENSE).

## Build

```
make          # libwemu.a
make test     # all four behavior gates
```

C11, no external dependencies, `-Werror` clean.

## Standard

- **Layer:** x86-64 emulator (WEMU)
- **Build:** `make`
- **Verify:** `make test`
- **Docs:** no `docs/` yet -- the parent's `docs/compendium/04-roadmap/submodule-standard.md` is the front door
- **Provenance:** own C11; no vendored third-party source without a note

Part of the ~WuBu~ tree: this repository is held to the same conventions as
the parent. See the parent's `docs/compendium/04-roadmap/submodule-standard.md`
for the checklist and why each item exists.
