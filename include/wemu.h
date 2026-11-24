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
 * its 64-bit offset as the handler RIP. Frame pushing stays in the
 * exception owner. See the privilege/IST section below for gate-privilege
 * checks, IF clearing, IST stack selection and the extra #PF error bits.
 *
 * Gate validation follows the SDM interrupt-delivery pseudocode:
 *   index outside IDT limit, or not an interrupt/trap gate  -> #GP(code)
 *   software vector with gate DPL < CPL                     -> #GP(code)
 *   gate not present                                        -> #NP(code)
 * code = (vector << 3) | 2  (IDT bit set, EXT=0, TI=0).
 *
 * #PF error codes: bit0 P (0=not-present, 1=protection), bit1 W/R, bit2
 * U/S. I/D (bit4) and RSVD (bit3) are now modelled — see below. PK bit5
 * and SGX bit6 stay 0 (PKE / enclaves not implemented). U/S is driven by
 * the modelled CPL: a data access with CPL=3 is a user access. */
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

/* ---- Privilege checks, IF clearing, IST stacks, extra #PF bits --------
 * Small architectural increments on top of the descriptor path above:
 *  - software INT gate access requires max(CPL, CS.RPL) <= gate.DPL;
 *    exceptions still ignore the gate privilege fields.
 *  - an interrupt gate (type 0xE) clears EFLAGS.IF on delivery; a trap
 *    gate (0xF) preserves it. The flag saved in the interrupt frame is the
 *    pre-clear value, as on real hardware.
 *  - a nonzero IST index in the gate selects a modelled TSS.IST[n] stack
 *    base for the frame; index 0 keeps the current RSP.
 *  - #PF error codes now include I/D (bit 4, set by instruction fetch) and
 *    RSVD (bit 3, set when a paging entry has a reserved bit). PK (bit 5)
 *    and SGX (bit 6) stay clear: CR4.PKE and enclave execution are not
 *    implemented, so there is no protection key / enclave to attribute. */
#define WEMU_HAS_PRIV_IST_PF 1

void wemu_cpu_set_cs_rpl(WemuCpu *cpu, int rpl);
int  wemu_cpu_cs_rpl(const WemuCpu *cpu);
void wemu_cpu_set_ist(WemuCpu *cpu, unsigned index, uint64_t base);
uint64_t wemu_cpu_ist(const WemuCpu *cpu, unsigned index);

/* ---- #GP/#SS/#NP delivery + double-fault (#DF) latching ---------------
 * Vectors 13 (#GP), 12 (#SS) and 11 (#NP) are delivered like #PF: they
 * push an error code and transfer to the gate offset.  #GP from a
 * non-canonical linear address carries error code 0 (SDM); #SS/#NP carry
 * the code supplied by their origin (a selector, or an IDT code for a
 * not-present gate).
 *
 * When an exception's own delivery faults (bad IDT gate: #NP for P=0, #GP
 * for an invalid type or an out-of-limit index) that secondary fault is a
 * #DF contributor.  WEMU now records the #DF condition and, when a usable
 * #DF gate is installed, delivers vector 8 with error code 0.  With no #DF
 * handler the legacy secondary latch is preserved, so existing guests see
 * the same wemu_cpu_fault() value as before.  A fault while delivering #DF
 * is a triple fault: the condition is recorded but never recursed. */
#define WEMU_HAS_FAULT_DELIVERY 1

unsigned wemu_cpu_double_faults(const WemuCpu *cpu);          /* count */
int      wemu_cpu_double_fault_latched(const WemuCpu *cpu);   /* sticky bit */
unsigned wemu_cpu_double_fault_source(const WemuCpu *cpu);    /* #NP/#GP */
uint64_t wemu_cpu_double_fault_source_error(const WemuCpu *cpu);

/* ---- Frame-push #DF + bounded GDT/TSS segment-origin faults -----------
 * Two fault-origin gaps are now covered:
 *  (1) An interrupt-frame push goes through wemu_gpa_write.  If that write
 *      fails (the guest stack lies outside RAM, so the secondary fault is
 *      #GP) the condition is a #DF contributor: it is fed into the #DF
 *      latch with the secondary vector/error preserved.  Delivery is NOT
 *      completed and RSP/RIP are left untouched — with no valid stack a
 *      #DF frame cannot be pushed either, so this is the triple-fault
 *      boundary.  Latches stay observable via wemu_cpu_double_fault_*.
 *  (2) A bounded GDT/TSS model checks the code and stack selectors of a
 *      privilege-changing SOFTWARE INT and generates:
 *        #NP(selector) - gate target code segment not present,
 *        #TS(selector) - TSS has no valid SS for the target CPL,
 *        #SS(selector) - SS segment not present / not writable data.
 *      Selector error codes follow the SDM: (selector & 0xFFFC), i.e.
 *      index + TI with IDT/EXT/RPL clear.  A passing check leaves the
 *      existing INT delivery unchanged.
 *
 * This increment generates FAULTS only; the CPL switch, RSP0/SS0 load and
 * CS/SS reload were added by WEMU_HAS_INT_CPL_SWITCH and WEMU_HAS_LTR_TSS
 * below.  Still not modelled: conforming-code checks, segment limit /
 * expand-down / DPL checks, 16-bit or VM86 stack switches, task gates
 * and #DF delivery on a bad stack.  Bounded LDT descriptors and TI=1
 * selector decode were added by WEMU_HAS_LDT below. */
#define WEMU_HAS_SEGMENTS 1

/* Load a bounded GDT (guest-physical base, byte limit). base+limit must
 * fit in guest RAM; the whole table is bounded at load time. Returns 0
 * or -1.  Descriptors are parsed lazily, 8 bytes each, from guest RAM. */
int  wemu_cpu_gdt_load(WemuCpu *cpu, uint64_t base, uint16_t limit);

/* The SS selector the TSS would supply for a switch to CPL 'cpl' (0..3).
 * Default 0 for every CPL (no stack available).  A valid stack selector
 * must have RPL == cpl and point at a present writable data segment. */
void    wemu_cpu_tss_set_ss(WemuCpu *cpu, int cpl, uint16_t selector);
uint16_t wemu_cpu_tss_ss(const WemuCpu *cpu, int cpl);

/* Target CPL requested for the next software INT.  Default 0.  Kept as a
 * compatibility observable: when a GDT is loaded, the architectural target
 * is instead derived from the gate's code-descriptor DPL
 * (see WEMU_HAS_INT_CPL_SWITCH).  With no GDT there is no segment model, so
 * the value has no effect. */
void wemu_cpu_set_int_target_cpl(WemuCpu *cpu, int cpl);
int  wemu_cpu_int_target_cpl(const WemuCpu *cpu);

/* ---- Guest-executed INT n + real CPL / TSS RSP0 / CS:SS reload --------
 * Two gaps closed here:
 *  (1) 0xCD imm8 (INT n) is EXECUTED by wemu_exec, not just callable from
 *      the host: the guest itself transfers through the loaded IDT via
 *      wemu_cpu_deliver_int (software-INT semantics, max(CPL,CS.RPL)<=DPL).
 *      For INT n the saved RIP is the address AFTER the instruction.
 *  (2) A privilege-changing software INT (target CPL from the gate's code
 *      descriptor DPL) now performs a REAL x86-64 stack switch: load the
 *      TSS RSP for the target CPL (RSP0 for ring 0), push the old SS/RSP
 *      ahead of RFLAGS/CS/RIP, and reload CS from the gate and SS from the
 *      TSS, updating the modelled CPL.  Same-level INTs keep the legacy
 *      frame (SS slot 0, no TSS RSP0 load, no CPL change).  Exceptions (host/
 *      fault raises) are unchanged.  The GDT/TSS table owner is the bounded one
 *      from WEMU_HAS_SEGMENTS — no second table is introduced. */
#define WEMU_HAS_INT_CPL_SWITCH 1

/* Current CS / SS selectors. Reset: CS=0x28, SS=0 (the legacy frame value).
 * Setting CS also updates CS.RPL used by the software-INT DPL check. */
void    wemu_cpu_set_cs(WemuCpu *cpu, uint16_t selector);
uint16_t wemu_cpu_cs(const WemuCpu *cpu);
void    wemu_cpu_set_ss(WemuCpu *cpu, uint16_t selector);
uint16_t wemu_cpu_ss(const WemuCpu *cpu);

/* TSS stack pointer for a switch to CPL 'cpl' (0=RSP0, 1/2=RSP1/2).
 * Default 0 for every CPL; 0 means "no base configured" — keep the
 * current RSP as the frame base (backward-compatible with descriptor-less
 * guests). A nonzero value is the new RSP the handler frame is built on. */
void    wemu_cpu_tss_set_rsp(WemuCpu *cpu, int cpl, uint64_t rsp);
uint64_t wemu_cpu_tss_rsp(const WemuCpu *cpu, int cpl);

/* ---- IRET (0xCF) + architectural same-level frames + exception CPL ----
 * Three gaps closed here:
 *  (1) 0xCF is EXECUTED by wemu_exec.  IRET pops RIP, CS and RFLAGS and,
 *      when the popped CS.RPL differs from the running CPL, also RSP and
 *      SS — restoring the pre-interrupt CPL/RIP/RSP.  The frame's CS is the
 *      interrupted procedure's selector (RPL = old CPL), so a ring-3 INT
 *      followed by IRET in the ring-0 handler returns exactly to ring 3.
 *  (2) A same-level SOFTWARE INT now pushes the architectural 3-qword
 *      frame (RIP, CS, RFLAGS [+ error]) instead of the legacy 5-qword
 *      one; a privilege switch keeps the 5-qword frame with old SS/RSP.
 *  (3) Host/fault-raised exceptions now use the SAME CPL-switch path as
 *      software INTs: when the gate's code descriptor in the bounded GDT
 *      has a DPL different from the current CPL, the stack switch, CS/SS
 *      reload and CPL update happen exactly as for INT n.  Descriptor-less
 *      guests and same-level exceptions keep their legacy frame layout.
 * An error code sits below the popped frame; as on hardware the handler
 * must adjust RSP past it before IRET. */
#define WEMU_HAS_IRET 1

/* Host-callable form of the same primitive the 0xCF opcode executes. */
int wemu_cpu_iret(WemuCpu *cpu);

/* ---- LTR: bounded 64-bit TSS descriptor parse + RSP0/SS0 load ---------
 * A guest TSS descriptor is a 16-byte system descriptor in the bounded
 * GDT (S=0, type 0x9 available / 0xB busy, P, 20-bit limit, 64-bit base).
 * wemu_cpu_ltr is the host side of LTR: it reads the descriptor from guest
 * RAM, validates it, bounds base+limit to guest RAM, then loads the stack
 * state from the TSS image and marks the descriptor busy (the SDM's locked
 * read-modify-write).  It does not itself change CPL or RSP.
 *
 * Faults are latched with a selector error code (selector & 0xfffc):
 *   #GP(0)   null selector, or CPL != 0 (LTR is ring-0 only);
 *   #GP(sel) TI=1 with no loaded LDT, outside the table, non-TSS type, busy
 *            TSS, or nonzero reserved dwords in the upper 8 descriptor bytes;
 *   #NP(sel) descriptor not present;
 *   #TS(sel) TSS limit too small for RSP0/SS0, or TSS outside guest RAM.
 *
 * WEMU TSS image at the descriptor base (guest physical):
 *   +0x04 RSP0 (u64)   +0x0c RSP1   +0x14 RSP2
 *   +0x1c SS0 (u16)    +0x1e SS1    +0x20 SS2
 * RSP0/1/2 are the architectural 64-bit TSS offsets.  A real 64-bit TSS
 * has NO SS fields, so WEMU keeps the SS selectors in the architecturally
 * reserved +0x1c..+0x21 bytes as an explicit documented extension: the
 * bounded GDT model needs an SS selector for a CPL switch and this makes it
 * guest-supplied rather than host-only.
 *
 * NOT modelled: hardware task switching (far JMP/CALL or a task gate to a
 * TSS selector), the back-link field, I/O-permission bitmap checks, and
 * non-canonical-address checks (guest RAM bounded by ram_size instead). */
#define WEMU_HAS_LTR_TSS 1

typedef struct {
    uint64_t base;      /* base from both halves of the 16-byte descriptor */
    uint32_t limit;     /* 20-bit limit */
    uint16_t selector;  /* selector used to load TR */
    uint8_t  type;      /* type as read (0x9 available) */
    uint8_t  dpl;
    uint8_t  present;
    uint8_t  busy;      /* 1 after a successful load (type became 0xB) */
} WemuTssDescriptor;

/* LTR-like load. Returns 0 on success (out may be NULL), -1 on a rejected
 * descriptor (fault vector/error readable via wemu_cpu_fault/_fault_error). */
int      wemu_cpu_ltr(WemuCpu *cpu, uint16_t selector, WemuTssDescriptor *out);
int      wemu_cpu_tr_loaded(const WemuCpu *cpu);
uint16_t wemu_cpu_tr(const WemuCpu *cpu);
uint64_t wemu_cpu_tr_base(const WemuCpu *cpu);
uint32_t wemu_cpu_tr_limit(const WemuCpu *cpu);

/* ---- Hardware task switching: far JMP/CALL through a TSS selector ------
 * A far JMP/CALL m16:64 (0xFF /5 or /3, memory operand) whose selector names
 * a 64-bit TSS descriptor in the bounded GDT performs a REAL task switch:
 * the suspended task's CS/SS/RIP/RSP/RFLAGS are saved into its TSS image,
 * the new task's back-link is set to the old task's TR selector (SDM), and
 * the new CS/SS/RIP/RSP/RFLAGS/CPL are loaded from the new TSS image.  The
 * new TSS descriptor is marked busy; a task entered by CALL sets NT so that
 * IRET (0xCF) returns through the back-link to the suspended task.
 *
 * Backed by the SAME bounded GDT/TSS owner as LTR — no second table.  Fault
 * origin is the descriptor, with a selector error code (sel & 0xfffc):
 *   #GP(0)   GDT not configured, null selector, or LDT selector;
 *   #GP(sel) outside GDT, non-TSS / busy TSS, nonzero reserved dwords,
 *            or CPL/RPL > TSS DPL;
 *   #NP(sel) TSS descriptor not present;
 *   #TS(sel) TSS limit too small for the switch state, TSS outside RAM,
 *            no current task to save into, or bad new CS/SS selectors.
 * A far pointer with a register operand is #UD (far pointers are memory).
 *
 * WEMU TSS image extension for task switching (within the descriptor limit):
 *   +0x00 backlink (u16, architectural)
 *   +0x28 task CS (u16)   +0x2a task SS (u16)
 *   +0x30 task RIP (u64)  +0x38 task RSP (u64)  +0x40 RFLAGS (u64)
 * The suspended task's state is written to these same offsets in its OWN
 * TSS; the entering task's initial state is read from them in its TSS.
 *
 * NOT modelled: non-canonical checks (RAM is bounded by ram_size).  Bounded
 * LDT selectors and full GPR save/restore were added by WEMU_HAS_LDT and
 * WEMU_HAS_TASK_GPR_STATE below. */
#define WEMU_HAS_TASK_SWITCH 1

/* ---- Bounded call/task gates + nested task returns --------------------
 * On top of far JMP/CALL through a TSS selector, WEMU now decodes the two
 * remaining descriptor forms used for controlled transfer, always bounded
 * by the latched GDT/IDT limits and guest RAM:
 *
 *   GDT 64-bit CALL GATE (S=0, type 0xC): a far CALL through its selector
 *     reads the target code selector (bytes 2-3) and 64-bit offset (bytes
 *     0-1,6-11) and performs a far call: return CS:RIP is pushed on the
 *     guest stack and control transfers to the gate's code:offset.  Bad
 *     gates latch #GP(selector); a not-present gate is #NP(selector).
 *
 *   TASK GATE (S=0, type 0x5) in the GDT or IDT: bytes 2-3 hold the selector
 *     of a 64-bit TSS.  Using the gate performs the same back-link task
 *     switch as a far CALL through the TSS directly.  For a software INT
 *     the gate's DPL is checked (max(CPL,CS.RPL) <= DPL) and gate faults use
 *     the IDT error code (vector<<3)|2; for a GDT far transfer they use the
 *     gate selector.
 *
 *   NESTED TASK RETURN: EFLAGS.NT (bit 14) is set on a task switch entered
 *     by CALL or an interrupt/task gate and cleared by JMP.  IRET with NT
 *     set follows the current TSS back-link and RESTORES NT from the
 *     suspended task's saved RFLAGS, so a chain A->B->C IRETs back through
 *     B to A (one back-link level per task, as the SDM defines).
 *
 * A far CALL/JMP dispatches by descriptor type: 0xC -> call gate, 0x5/0x9
 * -> task gate / TSS, anything else -> #GP(selector).  A register far
 * pointer is #UD.  Privilege-changing call gates (TSS stack switch, old
 * SS:RSP push and parameter copy) are modelled by WEMU_HAS_PRIV_CALL_GATE
 * below; same-level call gates and all task-gate forms are modelled here. */
#define WEMU_HAS_TASK_GATES 1

/* Far CALL dispatch: decode descriptor type and route to call gate or task
 * gate/TSS.  'return_rip' is the address after the far CALL. */
int      wemu_cpu_far_call(WemuCpu *cpu, uint16_t selector, uint64_t return_rip);
/* Decode a 64-bit GDT call gate and perform a same-level far call. */
int      wemu_cpu_call_gate(WemuCpu *cpu, uint16_t selector, uint64_t return_rip);

/* Guest-executed far JMP/CALL entry point.  'return_rip' is the address of
 * the instruction following the far transfer (saved in the old task's TSS);
 * 'nested' is 1 for CALL (NT set), 0 for JMP.  Accepts a TSS selector OR a
 * GDT task gate selector.  Returns 0 on success. */
int      wemu_cpu_task_switch(WemuCpu *cpu, uint16_t selector,
                              uint64_t return_rip, int nested);
/* IRET with NT set: follow the current TSS back-link to the suspended task. */
int      wemu_cpu_task_return(WemuCpu *cpu);
int      wemu_cpu_task_nested(const WemuCpu *cpu);
unsigned wemu_cpu_task_switches(const WemuCpu *cpu);

/* ---- Bounded LDT descriptors + TI=1 selector decode -------------------
 * The bounded GDT owner now routes EVERY descriptor read by the selector's
 * TI bit (selector bit 2): TI=0 selects the GDT, TI=1 selects the loaded
 * LDT.  The same table owner therefore decodes code/data descriptors, call
 * gates, task gates and TSS descriptors from either table; error codes keep
 * the TI bit ((selector & 0xfffc), SDM).  With no LDT loaded a TI=1 selector
 * is #GP(selector) — the old "LDT not modelled" rejection is now just the
 * "LDTR not loaded" case.
 *
 * wemu_cpu_ldt_load is the bounded host side of LLDT with an already-built
 * LDT image in guest RAM: base+limit must fit in RAM (the 20-bit descriptor
 * limit is capped at 0xfffff).  wemu_cpu_lldt is the real LLDT form: it
 * parses an 8-byte LDT system descriptor (S=0, type 0x2) from the
 * GDT, validates it and latches base/limit.  LLDT is ring-0 only.  Faults
 * (selector error code = selector & 0xfffc):
 *   #GP(0)   CPL != 0, or a null selector;
 *   #GP(sel) TI=1 (an LDT descriptor must live in the GDT), outside the GDT,
 *            S=1 or type != 0x2;
 *   #NP(sel) descriptor not present;
 *   #TS(sel) LDT image outside guest RAM.
 * A real LLDT instruction is not decoded (the host setter is the API). */
#define WEMU_HAS_LDT 1

typedef struct {
    uint64_t base;      /* LDT base from both descriptor halves */
    uint32_t limit;     /* 20-bit limit */
    uint16_t selector;  /* GDT selector used to load LDTR */
    uint8_t  type;      /* type as read (0x2 LDT) */
    uint8_t  dpl;
    uint8_t  present;
} WemuLdtDescriptor;

int      wemu_cpu_ldt_load(WemuCpu *cpu, uint64_t base, uint32_t limit);
int      wemu_cpu_lldt(WemuCpu *cpu, uint16_t selector,
                       WemuLdtDescriptor *out);
int      wemu_cpu_ldt_loaded(const WemuCpu *cpu);
uint64_t wemu_cpu_ldt_base(const WemuCpu *cpu);
uint32_t wemu_cpu_ldt_limit(const WemuCpu *cpu);

/* ---- Privilege-changing call gates ------------------------------------
 * A 64-bit GDT/LDT call gate whose target code descriptor DPL differs from
 * the running CPL performs an architectural stack switch instead of the
 * same-level call:
 *   - target CPL comes from the gate's code descriptor (RPL/DPL),
 *   - SS and RSP come from the TSS for that CPL (SS0/RSP0 for ring 0),
 *   - the OLD SS:RSP are pushed on the new stack (8 bytes each, SDM),
 *   - 'param_count' (gate bytes 4:0, count in 64-bit words) parameters are
 *     copied from the caller's stack to the new stack,
 *   - return CS:RIP are pushed last, so the handler resumes with RSP at the
 *     return RIP, parameters at RSP+8, old RSP/SS above them:
 *       [rsp+0]  return RIP   [rsp+8]  return CS
 *       [rsp+16] param[0] ... [rsp+16+8*(n-1)] param[n-1]
 *       [rsp+16+8*n] old RSP  [rsp+24+8*n] old SS
 *     (n = param_count; with n=0 this is the classic 32-byte frame).
 *   - CS/SS/CPL are reloaded from the gate and TSS; a same-level gate keeps
 *     the legacy 16-byte return-far-pointer frame.
 * Faults: #GP(gate) for a bad gate/target code, #TS(ss) for a missing or
 * bad TSS stack, #SS(0) when the new stack write leaves guest RAM, #NP(gate)
 * for a not-present gate.  Old WEMU #GPs every privilege-changing gate. */
#define WEMU_HAS_PRIV_CALL_GATE 1

/* ---- Full GPR state in the TSS on task switch --------------------------
 * A 64-bit hardware TSS has no general-register area, so WEMU extends its
 * TSS image (as it already does for the task CS/SS/RIP/RSP/RFLAGS state).
 * Task-state offsets (little-endian, guest physical):
 *   +0x48 RAX  +0x50 RCX  +0x58 RDX  +0x60 RBX  +0x68 RSP  +0x70 RBP
 *   +0x78 RSI  +0x80 RDI  +0x88 R8   ...        +0xC0 R15
 * A full task-state image needs a TSS limit >= 0xC8.  The save/restore is
 * bounded: a TSS with the smaller legacy limit (0x48..0xC7) keeps the old
 * CS/SS/RIP/RSP/RFLAGS-only behaviour, so existing guests/tasks are
 * unchanged.  RSP is architecturally reloaded from +0x38 (the slot at
 * +0x68 is still saved for a complete register snapshot).  The same area is
 * saved on task entry (far CALL/JMP/task gate) and restored on a back-link
 * IRET task return, so nested A->B->C->B->A chains preserve GPRs at each
 * level. */
#define WEMU_HAS_TASK_GPR_STATE 1
#define WEMU_TSS_TASK_GPR_BASE 0x48u
#define WEMU_TSS_TASK_GPR_END  0xc8u

/* Machine: CPU + COM1 serial. Output bytes go to the callback. */
typedef void (*WemuSerialFn)(uint8_t byte, void *ud);
WemuMachine *wemu_machine_create(uint64_t ram_size, WemuSerialFn out, void *ud);
void wemu_machine_destroy(WemuMachine *m);
WemuCpu *wemu_machine_cpu(WemuMachine *m);
/* Queue bytes for the guest's COM1 RX FIFO (0x3F8 data, 0x3FD LSR bit 0).
 * Returns the number of bytes accepted; drops new bytes when full. */
size_t wemu_machine_queue_input(WemuMachine *m, const void *data, size_t len);

/* COM2 (0x2F8) is the 9P link: guest TX bytes go to `out`, and the host
 * pushes RX bytes with wemu_machine_com2_push(). Kept separate from COM1 so
 * the debug log and the 9P wire never interleave. */
void   wemu_machine_set_com2(WemuMachine *m, WemuSerialFn out, void *ud);
/* Device window the MMIO hooks answer for (RAM accesses skip the hook). */
void   wemu_virtio_bar(uint64_t *base, uint64_t *len);
size_t wemu_machine_com2_push(WemuMachine *m, const void *data, size_t len);
size_t wemu_machine_queue_keyboard(WemuMachine *m, const char *text);

#ifdef __cplusplus
}
#endif
#endif /* WEMU_H */