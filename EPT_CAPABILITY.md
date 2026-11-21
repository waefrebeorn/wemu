# EPT / cross-process isolation — capability probe and bounded increment

Branch `leg/ept-capability` from base `1b09b1e5` (clean-room WEMU repo clone;
canonical repos/submodules untouched, no push, DISPLAY untouched).

## 1. Local capability probe (reproducible: `tools/capability_probe.sh`)

Exact output captured on this host:

```
Linux wubu1 7.0.0-42-generic ... x86_64
crw-rw----+ 1 root kvm 10, 232 /dev/kvm        (readable+writable by this user)
CPU flags: vmx, ept                            (VT-x + EPT available in silicon)
/usr/src/linux-headers-7.0.0-42-generic, /usr/include/linux/kvm.h present
KVM_GET_API_VERSION=12
KVM_GET_VCPU_MMAP_SIZE=12288
KVM_CREATE_VM=4 (errno=0)                      (VM creation succeeds)
cap NR_VCPUS=24, MAX_VCPUS=4096, SET_TSS_ADDR=1, NR_MEMSLOTS=32764
```

**Finding:** the host is *not* missing VT-x/EPT hardware or KVM userspace
access. So a `VERIFIED_NEGATIVE` of the form "no EPT capability" would be
false. The missing capability is architectural/in-scope, not a host facility:
WEMU is a **user-mode interpreter** with a software 4-level page walk; it has
no VMM/vmxon/EPT context, no VMCS, no SMC invalidation, and no guest page-table
ownership distinct from the interpreter's `cpu->ram`. Building a real VT-x/EPT
VMM is an entire new leg (see README roadmap: JIT -> VT-x/EPT VMM -> devices),
not a bounded increment, and would not be honest to claim as done here.

## 2. Existing paging model (`src/wemu_mem.c`)

Long-mode 4-level walk, MAXPHYADDR=52, `efer=0xd00` (LME|LMA|NXE). Enforced
before this change: present (P), reserved bits 62:52 (RSVD), U/S, W/R (with
CR0.WP for supervisor writes), non-canonical #GP, and I/D error-bit tagging on
instruction fetch (`wemu_mem_fetch` routes through `wemu_translate_ex(...,
is_fetch=1)`). PK (bit 5) and SGX (bit 6) remain clear and are explicitly out
of scope (CR4.PKE / ENCLS not implemented).

**Gap found:** bit 63 (XD/NX) was *parsed* — deliberately excluded from
`PT_RESERVED_MASK` and documented as "allowed (EFER.NXE=1)" — but **never
enforced**. With NXE=1 an instruction fetch from an XD leaf succeeded; with
NXE=0 the reserved bit-63 case was likewise not faulted. This is exactly the
"guest page-table fault enforcement beyond current bookkeeping" increment:
execute-permission enforcement, i.e. the software analogue of EPT's XD bit.

## 3. Bounded increment implemented

`src/wemu_mem.c`:
- EFER.NXE=1: leaf bit 63 set + `is_fetch` -> #PF with error `P|I/D = 0x11`
  (applied to 4KiB and 2MiB/1GiB leaves via the shared `leaf_prot_fault`).
- EFER.NXE=0: bit 63 added to the reserved mask -> #PF `P|RSVD = 0x9`.
- Data reads/writes from an XD page remain legal (XD gates execute only).

`tests/test_paging.c`: gate covering 4KiB XD fetch fault + CR2 + exact error,
data-read-allowed, executable-page control, NXE=0 RSVD error, and 2MiB XD leaf.

`tools/nx_negctl.sh`: reproducible negative control — same probe linked against
current HEAD (faults `P|I/D`) and against `1b09b1e5`'s `wemu_mem.o` (leaks,
fetch succeeds). Differential is asserted; no isolation is claimed beyond it.

## 4. Remaining gaps (honest scope)

- This is **guest page-table execute-permission enforcement in the interpreter**,
  not VT-x/EPT, not cross-process isolation. No VMCS/VMXON/EPT paging structure
  is created or owned.
- WEMU still runs guests in-process via `fork` with a MAP_SHARED arena; host-page
  hiding uses pkeys/munmap plus syscall pointer-range validation (one address
  space), not separate hardware address spaces.
- NX fault attribution stays at the walk; no CR4.PKE protection-key (error bit
  5) or SGX (bit 6) modelling. A guest that never enables paging (PG=0) still
  gets identity translation with no execute check.
- Full EPT VMM, nested paging, INVVPID/INVEPT, and SMC invalidation remain open.
