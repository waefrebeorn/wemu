/* wemu_internal.h — shared internal state. Not a public surface. */
#ifndef WEMU_INTERNAL_H
#define WEMU_INTERNAL_H

#include "wemu.h"
#include <string.h>

#define WEMU_RAM_MAX (1ull << 32)

/* PC-histogram buckets for WEMU_PROFILE=1 (64-byte granularity). */
#define WEMU_PROFILE_BUCKETS 65536u

struct WemuCpu {
    uint64_t r[16];          /* RAX RCX RDX RBX RSP RBP RSI RDI R8..R15 */
    uint64_t rip;
    uint64_t rflags;
    uint8_t  xmm[16][16];
    uint8_t  ymm_hi[16][16];   /* upper 128 bits of YMM (VEX.256) */
    uint64_t cr0, cr2, cr3, cr4, efer;
    uint64_t fs_base, gs_base; /* user-mode TLS segment bases */
    /* x87 FPU (wemu_x87.c owns semantics); st(0) = x87_st[x87_top] */
    double   x87_st[8];
    int      x87_top;
    uint16_t x87_cw, x87_sw;
    uint64_t elf_brk;          /* page-aligned end of loaded ELF image */
    uint8_t *ram;
    uint64_t ram_size;
    int halted;
    void *machine_ud;        /* owning WemuMachine, for port-I/O devices */
    int (*mmio_read)(WemuCpu *cpu, uint64_t gpa, void *dst, size_t len);
    int (*mmio_write)(WemuCpu *cpu, uint64_t gpa, const void *src, size_t len);
    /* The device window the hooks cover. Every guest byte of RAM used to be
     * offered to the MMIO hook first (~11 calls per guest step, measured), so
     * one range test here keeps RAM accesses off the indirect call. */
    uint64_t mmio_lo, mmio_hi;
    /* PC histogram (WEMU_PROFILE=1): where the guest spends its steps. */
    int       profile;
    uint32_t  prof_bucket_shift;
    uint32_t *hist;
    uint64_t  prof_total;
    int fault;               /* x86 exception vector, 0 = none */
    uint64_t fault_error;    /* error code accompanying a pending fault */
    /* exception delivery (wemu_exception.c owns these): a minimal IDT of
     * vector -> guest handler RIP, plus metadata of the last delivery. */
    struct { uint64_t rip; uint8_t present; } idt[256];
    /* Optional architectural IDT (wemu_exception.c). When configured,
     * delivery reads/validates the 16-byte gate from guest RAM. */
    struct { uint64_t base; uint16_t limit; uint8_t configured; } idtr;
    int cpl;                 /* modelled CPL 0..3 (reset 0) */
    int cs_rpl;              /* RPL of the modelled current CS selector */
    uint16_t cs_selector;    /* modelled current CS selector (reset 0x28) */
    uint16_t ss_selector;    /* modelled current SS selector (reset 0) */
    uint16_t ds_selector, es_selector, fs_selector, gs_selector;
    uint64_t apic_base_msr;  /* IA32_APIC_BASE (0x1B) */
    uint64_t ist[8];         /* IST stack bases (1..7; 0 reserved) */
    unsigned exc_vector;     /* last delivered vector (0 = none yet) */
    uint64_t exc_error;      /* last delivered error code */
    uint64_t exc_cr2;        /* CR2 captured at last #PF delivery */
    /* double-fault bookkeeping (wemu_exception.c): a fault raised while
     * delivering another exception is a #DF condition.  Sticky so a host
     * or gate can observe it even when no #DF handler is installed. */
    unsigned df_count;       /* number of #DF conditions latched */
    uint8_t  df_latched;     /* 1 after the first #DF condition */
    uint8_t  df_src_vector;  /* secondary vector that caused it (#NP/#GP) */
    uint64_t df_src_error;   /* that secondary vector's error code */
    /* bounded GDT + TSS SS selectors (wemu_exception.c). GDT descriptors
     * stay in guest RAM; only base/limit are latched, like the IDTR. */
    struct { uint64_t base; uint16_t limit; uint8_t configured; } gdt;
    /* bounded LDT (wemu_exception.c). TI=1 selectors select descriptors in
     * this table; TI=0 keeps selecting the GDT above. base+limit is bounded
     * to guest RAM at load time, exactly like GDTR/IDTR. */
    struct { uint64_t base; uint32_t limit; uint8_t configured; } ldt;
    uint16_t tss_ss[4];      /* TSS-supplied SS selector per target CPL */
    uint64_t tss_rsp[4];     /* TSS-supplied RSP per target CPL (RSP0..RSP2) */
    /* task register, cached by wemu_cpu_ltr (wemu_exception.c) */
    struct {
        uint64_t base;
        uint32_t limit;
        uint16_t selector;
        uint8_t  loaded;
        uint8_t  busy;
    } tr;
    /* hardware task switching (wemu_exception.c): nested-task back-link.
     * The per-task saved execution state lives in the TSS image in guest
     * RAM; only the NT bit and observability counters live here. */
    int task_nested;         /* NT: current task entered via a task CALL */
    unsigned task_switches;  /* count of successful switches + returns */
    int int_target_cpl;      /* software-INT stack-switch target (0 = no switch) */
    WemuSyscallFn sys_fn;
    void *sys_ud;
    /* optional observer modelling a competing hardware agent (LOCK atomics) */
    WemuAtomicObserver atomic_observer;
    void *atomic_observer_ud;
    /* no-op hint execution counts (wemu_exec owns the increments) */
    uint64_t hint_count[WEMU_HINT_KINDS];
    /* serial (machine layer installs these) */
    WemuSerialFn serial_out;
    void *serial_ud;
};

int wemu_cpu_gdt_load(WemuCpu *cpu, uint64_t base, uint16_t limit);

/* flags bits */
#define WF_CF 0x001
#define WF_PF 0x004
#define WF_AF 0x010
#define WF_ZF 0x040
#define WF_SF 0x080
#define WF_OF 0x800
#define WF_IF 0x200 /* EFLAGS.IF: interrupt gate clears this on delivery */
#define WF_NT 0x4000 /* EFLAGS.NT: nested task, IRET follows the TSS back-link */

/* decoded instruction (wemu_decode.c fills, wemu_exec.c consumes) */
typedef struct {
    uint8_t len;             /* total bytes consumed */
    uint8_t rex;             /* 0 or 0x40..0x4F */
    uint8_t opsize;          /* operand bytes: 2/4/8 */
    uint8_t addrsize;        /* address bytes: 4/8 */
    uint8_t op;              /* primary opcode (after 0F escape: 0x100|b) */
    uint8_t modrm, sib;
    uint8_t has_modrm, has_sib;
    uint8_t rip_rel;         /* ModRM mod=0 rm=5: disp is RIP-relative */
    uint8_t vex_len;         /* 0 = legacy, 2/3 = VEX prefix bytes */
    uint8_t vex[3];
    uint8_t rep;             /* 0, 0xF2, 0xF3 */
    uint8_t lock;            /* 0xF0 LOCK prefix present */
    uint8_t seg;             /* segment override: 0 none, 0x64 FS, 0x65 GS */
    int64_t disp;
    uint64_t imm;
    uint8_t imm_len;
    uint8_t fault;           /* decode fault vector (6 = #UD) */
} WemuInsn;

/* decode one instruction at cpu->rip; returns 0 ok, -1 fault */
int wemu_decode(WemuCpu *cpu, WemuInsn *in);

/* execute a decoded instruction; returns 0 ok, -1 fault */
int wemu_exec(WemuCpu *cpu, const WemuInsn *in);

/* IRET (0xCF): pop an interrupt frame, restoring RIP/CS/RFLAGS and, on a
 * privilege return, RSP/SS/CPL (wemu_exception.c). */
int wemu_iret(WemuCpu *cpu);

/* SSE/AVX leaf: returns 1 if it handled the opcode, 0 if not, -1 fault */
int wemu_exec_sse(WemuCpu *cpu, const WemuInsn *in);

/* memory helpers (wemu_mem.c) */
int wemu_gpa_read(WemuCpu *cpu, uint64_t gpa, void *dst, size_t len);
int wemu_gpa_write(WemuCpu *cpu, uint64_t gpa, const void *src, size_t len);
/* 4-level walk; is_write/is_user drive the #PF W/R and U/S error bits,
 * is_fetch drives I/D. Sets *fault (#PF=14, #GP=13) and cpu->fault_error
 * on failure. RSVD is set when a paging entry has a reserved bit set. */
uint64_t wemu_translate_ex(WemuCpu *cpu, uint64_t va, int is_write,
                           int is_user, int is_fetch, int *fault);
uint64_t wemu_translate(WemuCpu *cpu, uint64_t va, int is_write, int is_user,
                        int *fault);
/* Instruction-fetch read (wemu_decode.c): same walk with is_fetch=1. */
int wemu_mem_fetch(WemuCpu *cpu, uint64_t va, void *dst, size_t len);

/* machine-attached MMIO regions: return 0 handled, 1 not ours, -1 fault */
void wemu_virtio_reset(void);
int wemu_virtio_mmio_read(WemuCpu *cpu, uint64_t gpa, void *dst, size_t len);
int wemu_virtio_mmio_write(WemuCpu *cpu, uint64_t gpa, const void *src, size_t len);

/* effective address for a ModRM memory operand (one owner: exec + sse) */
uint64_t wemu_eff_addr(WemuCpu *cpu, const WemuInsn *in);
int wemu_x87_exec(WemuCpu *cpu, const WemuInsn *in); /* 1 ok, 0 #UD, -1 mem */

/* port I/O (wemu_machine.c owns devices; bare CPU ignores/returns ~0) */
void wemu_port_out(WemuCpu *cpu, uint16_t port, uint32_t val, int bytes);
uint32_t wemu_port_in(WemuCpu *cpu, uint16_t port, int bytes);

/* register write with x86 width semantics (32-bit writes zero-extend) */
void wemu_reg_write(WemuCpu *c, int i, int bytes, uint64_t v);

/* string instructions (wemu_string.c): 1 handled, 0 not ours, -1 fault */
int wemu_exec_string(WemuCpu *c, const WemuInsn *in);

/* flags helpers (wemu_cpu.c) */
void wemu_set_logic_flags(WemuCpu *cpu, uint64_t res, int bytes);
void wemu_set_add_flags(WemuCpu *cpu, uint64_t a, uint64_t b, uint64_t res,
                        int bytes, int carry_in, int is_sub);
uint64_t wemu_mask(uint64_t v, int bytes);
int wemu_parity(uint64_t v);

#endif /* WEMU_INTERNAL_H */