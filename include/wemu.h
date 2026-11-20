/* wemu.h — WEMU public API. WuBu Emulator: a clean-room C11 x86-64
 * interpreter + machine skeleton, the sovereign guest-execution layer
 * for WuBuOS ("load their system"). Opaque handles; one owner per
 * concern; no function bodies in headers.
 *
 * Provenance: behaviour inspired by QEMU's machine-model ambition;
 * every line here is original, written from the Intel SDM / AMD APM
 * instruction semantics. No QEMU source was copied, linked, or derived.
 * License: WaefreBeorn Umbrella License v3.0. */
#ifndef WEMU_H
#define WEMU_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct WemuCpu WemuCpu;
typedef struct WemuMachine WemuMachine;

/* CPU lifecycle. ram_size bytes of guest-physical memory at GPA 0. */
WemuCpu *wemu_cpu_create(uint64_t ram_size);
void wemu_cpu_destroy(WemuCpu *cpu);

/* Load flat code at a guest address; set entry RIP. */
int wemu_cpu_load(WemuCpu *cpu, uint64_t gpa, const uint8_t *code, size_t len);
void wemu_cpu_set_rip(WemuCpu *cpu, uint64_t rip);
void wemu_cpu_set_rsp(WemuCpu *cpu, uint64_t rsp);

/* Register access by index (0=RAX .. 15=R15). */
uint64_t wemu_cpu_reg(const WemuCpu *cpu, int idx);
void wemu_cpu_set_reg(WemuCpu *cpu, int idx, uint64_t val);
uint64_t wemu_cpu_rip(const WemuCpu *cpu);
uint64_t wemu_cpu_rflags(const WemuCpu *cpu);

/* Guest memory (translation-aware when paging is enabled). */
int wemu_mem_read(WemuCpu *cpu, uint64_t va, void *dst, size_t len);
int wemu_mem_write(WemuCpu *cpu, uint64_t va, const void *src, size_t len);

/* Paging control: cr3 + CR0.PG. Without it, VA == GPA. */
void wemu_cpu_set_cr3(WemuCpu *cpu, uint64_t cr3);
void wemu_cpu_enable_paging(WemuCpu *cpu, int on);

/* Syscall hook: return the value to place in RAX. nr=60/231 (exit/
 * exit_group) halt the CPU by default; the hook may override. */
typedef int64_t (*WemuSyscallFn)(WemuCpu *cpu, uint64_t nr,
                                 const uint64_t args[6], void *ud);
void wemu_cpu_set_syscall_hook(WemuCpu *cpu, WemuSyscallFn fn, void *ud);

/* Execution. step = one instruction; run = until halt or max_insns.
 * Returns instructions executed, or -1 on a decode/exec fault (the
 * fault vector is readable via wemu_cpu_fault). */
int64_t wemu_cpu_step(WemuCpu *cpu);
int64_t wemu_cpu_run(WemuCpu *cpu, uint64_t max_insns);
int wemu_cpu_halted(const WemuCpu *cpu);
/* Halt from outside the guest (a syscall hook finishing exit/exit_group
 * uses this; the guest itself halts via HLT or the default hook). */
void wemu_cpu_halt(WemuCpu *cpu);
int wemu_cpu_fault(const WemuCpu *cpu);      /* 0 = none, else x86 vector */
/* Clear a pending fault (a syscall hook that translated a bad guest
 * pointer to -EFAULT uses this: the guest gets the errno, not a CPU
 * exception it never architecturally took). */
void wemu_cpu_clear_fault(WemuCpu *cpu);
uint64_t wemu_cpu_fault_addr(const WemuCpu *cpu); /* CR2 for #PF */

/* XMM register read (16 bytes). */
void wemu_cpu_xmm(const WemuCpu *cpu, int idx, uint8_t out[16]);

/* User-mode ELF execution (wemu_elf.c): load a static ET_EXEC x86-64
 * ELF into guest RAM at its p_vaddr, zero .bss, build the SysV initial
 * stack (argc/argv/envp/auxv) at RAM top, set RIP=e_entry. Exactly one
 * of path / bytes is used: path!=NULL reads the file, else bytes[0..len).
 * argv is NULL-terminated (may be NULL for argc=0). Paging stays OFF:
 * flat identity memory is user mode. Returns 0 or -1. */
int wemu_cpu_load_elf(WemuCpu *cpu, const char *path,
                      const uint8_t *bytes, size_t len,
                      char *const argv[]);
/* Page-aligned end of the loaded ELF image (initial program break). */
uint64_t wemu_cpu_elf_brk(const WemuCpu *cpu);

/* Segment bases for user-mode TLS (%fs / %gs overrides). The CPU adds
 * these to effective addresses; arch_prctl-style guests set them via
 * the syscall hook. Default 0 (flat). */
void wemu_cpu_set_fs_base(WemuCpu *cpu, uint64_t base);
void wemu_cpu_set_gs_base(WemuCpu *cpu, uint64_t base);
uint64_t wemu_cpu_fs_base(const WemuCpu *cpu);
uint64_t wemu_cpu_gs_base(const WemuCpu *cpu);

/* ---- LOCK-prefix atomics -------------------------------------------
 * WEMU executes one instruction at a time, so a plain read-modify-write
 * (RMW) never interleaves with another guest agent in the step model.
 * Real x86 LOCK makes an RMW one indivisible bus transaction; without
 * LOCK the read and the write are separate bus cycles and a competing
 * agent can land between them (the classic lost update).  To make that
 * distinction observable and testable, an optional observer hook models
 * a second hardware agent competing for the same address.  The emulator
 * calls it at the read->write boundary of a NON-LOCK memory RMW (PRE:
 * its write is clobbered by our stale writeback), and only AFTER a LOCK
 * RMW completes (POST: serialized after the indivisible RMW, so both
 * updates survive).  With no hook installed execution is unchanged. */
#define WEMU_HAS_LOCK_ATOMICS 1

typedef enum {
    WEMU_ATOMIC_PRE_WRITE = 0,  /* non-LOCK RMW: between its read and write */
    WEMU_ATOMIC_POST_WRITE = 1  /* LOCK RMW: after its indivisible writeback */
} WemuAtomicPhase;

typedef void (*WemuAtomicObserver)(WemuCpu *cpu, uint64_t va, int bytes,
                                  WemuAtomicPhase phase, void *ud);
void wemu_cpu_set_atomic_observer(WemuCpu *cpu, WemuAtomicObserver fn, void *ud);

/* ---- CMPXCHG8B/16B + memory-ordering / PAUSE hints --------------------
 * 0F C7 /1 (REX.W selects CMPXCHG16B) is a real atomic compare-and-swap:
 * EDX:EAX / RDX:RAX is compared with an 8/16-byte memory operand. On
 * equal the memory receives ECX:EBX / RCX:RBX; on mismatch the accumulator
 * receives memory. ZF is the only architecturally defined flag (WEMU
 * preserves the others). Like XCHG, both forms are implicitly bus-locked.
 *
 * LFENCE (0F AE /5), MFENCE (0F AE /6), SFENCE (0F AE /7) and PAUSE
 * (F3 90) are fetched, decoded and EXECUTED as no-op hints. WEMU is a
 * single-threaded interpreter with no speculative/reordering engine, no
 * store buffer and no other hardware agent by default, so there is
 * nothing for a fence to drain and nothing for PAUSE to yield to. They
 * are therefore honest no-ops and NEVER #UD. Execution counts are exposed
 * so a host or gate can observe that a hint actually executed rather
 * than being skipped or discarded as an unknown prefix/opcode. */
#define WEMU_HAS_CX8_FENCE_PAUSE 1

typedef enum {
    WEMU_HINT_LFENCE = 0,
    WEMU_HINT_MFENCE = 1,
    WEMU_HINT_SFENCE = 2,
    WEMU_HINT_PAUSE  = 3,
    WEMU_HINT_KINDS  = 4
} WemuHintKind;
uint64_t wemu_cpu_hint_count(const WemuCpu *cpu, WemuHintKind kind);

/* ---- Guest exception delivery (minimal IDT) --------------------------
 * Before this, a fault (wemu_cpu_fault) only stopped the run loop: WEMU
 * latched the vector but never DELIVERED it to the guest.  A guest IDT now
 * maps vector -> registered guest handler RIP.  On a fault,
 * wemu_cpu_deliver_exception pushes a real x86-64 interrupt frame on the
 * guest stack and transfers RIP to that handler (fault cleared so the run
 * resumes there).  Vectors with no registered handler keep the legacy
 * behaviour: the fault stays latched and wemu_cpu_step returns -1.
 * Decoder (fault origin), executor and memory (frame push) stay separate
 * owners; wemu_exception.c owns delivery. */
#define WEMU_HAS_EXCEPTION_DELIVERY 1

/* Install a guest handler RIP for a vector (0..255). 0 = ok, -1 = bad vector. */
int  wemu_cpu_register_exception_handler(WemuCpu *cpu, unsigned vector,
                                         uint64_t guest_rip);
/* Query a registration: 0 = present (writes *out_rip), -1 = none/bad vector. */
int  wemu_cpu_exception_handler(const WemuCpu *cpu, unsigned vector,
                                uint64_t *out_rip);
/* Deliver a vector now: push error frame + transfer to handler.
 * Returns 0 when delivered, -1 when no handler is registered (the fault
 * remains latched — the pre-change semantics). */
int  wemu_cpu_deliver_exception(WemuCpu *cpu, unsigned vector);
/* Host-side raise, e.g. the VSL mprotect write hook: latch vector, error
 * code and CR2; delivered at the next step boundary. cr2=0 leaves CR2 as-is. */
void wemu_cpu_raise_exception(WemuCpu *cpu, unsigned vector,
                              uint64_t error, uint64_t cr2);
/* Metadata of the last DELIVERED exception (0/0/0 before any delivery). */
unsigned wemu_cpu_exception_vector(const WemuCpu *cpu);
uint64_t wemu_cpu_exception_error(const WemuCpu *cpu);
uint64_t wemu_cpu_exception_cr2(const WemuCpu *cpu);

/* ---- Architectural IDT descriptors + real #PF error codes ------------
 * The registered-RIP IDT above is kept for backwards compatibility.  In
 * addition, a guest may install a REAL long-mode IDT in memory and point
 * the CPU at it with wemu_cpu_idt_load(base, limit).  When an IDTR is
 * loaded, exception delivery READS the 16-byte gate from guest physical
 * memory and validates it (limit, gate type, present, DPL) before using
 * its 64-bit offset as the handler RIP.  Frame pushing stays in the
 * exception owner; no CS/RPL/IST stack switch is performed.
 *
 * Gate validation follows the SDM interrupt-delivery pseudocode:
 *   index outside IDT limit, or not an interrupt/trap gate  -> #GP(code)
 *   software vector with gate DPL < CPL                     -> #GP(code)
 *   gate not present                                        -> #NP(code)
 * code = (vector << 3) | 2  (IDT bit set, EXT=0, TI=0).
 *
 * #PF error codes are now computed by the page-walk owner: bit0 P
 * (0=not-present, 1=protection), bit1 W/R, bit2 U/S.  RSVD, I/D and PK
 * remain 0 (those checks are not modelled).  U/S is driven by the
 * modelled CPL: a data access with CPL=3 is a user access. */
#define WEMU_HAS_ARCH_IDT 1

typedef struct {
    uint64_t offset;   /* 64-bit handler offset encoded in the gate */
    uint16_t selector; /* target code selector (not used for a switch) */
    uint8_t  ist;      /* IST index (no IST stack switch is modelled) */
    uint8_t  type;     /* low nibble: 0xE interrupt gate, 0xF trap gate */
    uint8_t  dpl;      /* descriptor privilege level (0..3) */
    uint8_t  present;  /* P bit */
} WemuIdtGate;

/* Install an IDTR (guest-physical base, byte limit = base+limit-1).
 * Bounded: base+limit must fit in guest RAM. Returns 0 or -1. */
int  wemu_cpu_idt_load(WemuCpu *cpu, uint64_t base, uint16_t limit);
/* Read one 16-byte gate from the loaded IDT without side effects.
 * Bounded: vector<256 and the whole gate must fit inside the IDT limit.
 * Returns 0 on success, -1 on bad vector/out-of-limit/read failure. */
int  wemu_cpu_idt_gate(const WemuCpu *cpu, unsigned vector, WemuIdtGate *out);
/* Modelled current privilege level (0..3, reset 0). Used for the #PF U/S
 * bit and for the software-vector DPL gate check. */
void wemu_cpu_set_cpl(WemuCpu *cpu, int cpl);
int  wemu_cpu_cpl(const WemuCpu *cpu);
/* Error code of the currently latched fault (0 if none). */
uint64_t wemu_cpu_fault_error(const WemuCpu *cpu);
/* Deliver a SOFTWARE vector (INT n semantics): same gate validation as an
 * exception, plus the CPL<=DPL check. Returns 0 delivered, -1 rejected
 * (the resulting #GP/#NP is latched — see wemu_cpu_fault/_fault_error). */
int  wemu_cpu_deliver_int(WemuCpu *cpu, unsigned vector);

/* Machine: CPU + COM1 serial. Output bytes go to the callback. */
typedef void (*WemuSerialFn)(uint8_t byte, void *ud);
WemuMachine *wemu_machine_create(uint64_t ram_size, WemuSerialFn out, void *ud);
void wemu_machine_destroy(WemuMachine *m);
WemuCpu *wemu_machine_cpu(WemuMachine *m);

#ifdef __cplusplus
}
#endif
#endif /* WEMU_H */