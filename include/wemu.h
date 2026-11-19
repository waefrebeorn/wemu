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
int wemu_cpu_fault(const WemuCpu *cpu);      /* 0 = none, else x86 vector */
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

/* Machine: CPU + COM1 serial. Output bytes go to the callback. */
typedef void (*WemuSerialFn)(uint8_t byte, void *ud);
WemuMachine *wemu_machine_create(uint64_t ram_size, WemuSerialFn out, void *ud);
void wemu_machine_destroy(WemuMachine *m);
WemuCpu *wemu_machine_cpu(WemuMachine *m);

#ifdef __cplusplus
}
#endif
#endif /* WEMU_H */