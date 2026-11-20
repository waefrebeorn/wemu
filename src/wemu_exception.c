/* wemu_exception.c — guest exception delivery (minimal IDT).
 * One concern: turning a latched fault vector into a real transfer of
 * control to a registered guest handler, with an x86-64 interrupt frame
 * pushed on the guest stack.  Fault ORIGINS stay in their own owners
 * (decode sets WemuInsn.fault; exec/mem set cpu->fault); frame storage goes
 * through the memory owner (wemu_gpa_write).  No god headers, no inline
 * bodies in headers. */
#include "wemu_internal.h"

/* x86-64 vectors that push an error code with the interrupt frame.
 * #UD (6) is deliberately absent: no error code for an invalid opcode. */
static int exc_has_error_code(unsigned v) {
    switch (v) {
    case 8:  /* #DF  */
    case 10: /* #TS  */
    case 11: /* #SS  */
    case 12: /* #GP  */
    case 13: /* #GP  */
    case 14: /* #PF  */
    case 17: /* #AC  */
    case 21: /* #CP  */
    case 29: /* #VC  */
    case 30: /* #SX  */
    case 31: /* #VC  */
        return 1;
    default:
        return 0;
    }
}

/* SDM error_code(vector, IDT=1, EXT=0): bits 15:3 hold the vector, bit 1
 * is the IDT flag.  For vector 6 this is 0x32. */
static uint64_t exc_idt_code(unsigned vector) {
    return ((uint64_t)vector << 3) | 0x2ull;
}

/* Read a 16-byte long-mode gate from guest RAM at the loaded IDTR.  This
 * is a pure read: bounded by vector<256 and by the IDT byte limit, both
 * checked at load time against guest RAM, so no fault can be raised here.
 * The IDT base is a guest-physical address (no paging of the IDT itself). */
static int exc_idt_gate_read(const WemuCpu *cpu, unsigned vector,
                             WemuIdtGate *g) {
    if (!cpu || !cpu->idtr.configured || vector >= 256 || !g) return -1;
    uint64_t off = (uint64_t)vector * 16;
    if (off + 15 > cpu->idtr.limit) return -1;
    const uint8_t *raw = cpu->ram + cpu->idtr.base + off;
    g->offset = (uint64_t)raw[0] | ((uint64_t)raw[1] << 8) |
                ((uint64_t)raw[6] << 16) | ((uint64_t)raw[7] << 24) |
                ((uint64_t)raw[8] << 32) | ((uint64_t)raw[9] << 40) |
                ((uint64_t)raw[10] << 48) | ((uint64_t)raw[11] << 56);
    g->selector = (uint16_t)raw[2] | ((uint16_t)raw[3] << 8);
    g->ist      = raw[4] & 0x7;
    g->type     = raw[5] & 0xf;
    g->dpl      = (raw[5] >> 5) & 0x3;
    g->present  = (raw[5] >> 7) & 1;
    return 0;
}

/* Delivery target parsed from a gate (or synthesized for the legacy path).
 * Kept small so the legacy registered-RIP path need not fake a descriptor. */
typedef struct {
    uint64_t rip;             /* handler offset */
    uint8_t  ist;             /* IST index from gate byte 4 (0 = none) */
    uint8_t  type;            /* 0xE interrupt (clears IF), 0xF trap */
    uint16_t selector;        /* gate target code selector */
} ExcTarget;

/* SDM interrupt-delivery checks, in pseudocode order.  On rejection the
 * original vector is REPLACED by #GP/#NP with the IDT error code latched.
 * 'software' gates the CPL/RPL/DPL rule: exceptions ignore gate DPL.
 * For a software INT the gate is accessible only when the requesting
 * privilege max(CPL, CS.RPL) does not exceed the gate DPL -- the canonical
 * x86 protection rule.  RPL is modelled on the current CS selector. */
static int exc_idt_check(WemuCpu *cpu, unsigned vector, ExcTarget *t,
                         int software) {
    WemuIdtGate g;
    if (exc_idt_gate_read(cpu, vector, &g) != 0) {
        cpu->fault = 13; /* descriptor outside the IDT limit */
        cpu->fault_error = exc_idt_code(vector);
        return -1;
    }
    if (g.type != 0xE && g.type != 0xF) { /* long mode: intr/trap gate only */
        cpu->fault = 13;
        cpu->fault_error = exc_idt_code(vector);
        return -1;
    }
    if (software) {
        int req = cpu->cpl > cpu->cs_rpl ? cpu->cpl : cpu->cs_rpl;
        if ((int)g.dpl < req) {
            cpu->fault = 13; /* max(CPL,RPL) > DPL: software INT rejected */
            cpu->fault_error = exc_idt_code(vector);
            return -1;
        }
    }
    if (!g.present) {
        cpu->fault = 11; /* #NP, not #GP: SDM "gate not present" */
        cpu->fault_error = exc_idt_code(vector);
        return -1;
    }
    t->rip  = g.offset;
    t->ist  = g.ist;
    t->type = g.type;
    t->selector = g.selector;
    return 0;
}

int wemu_cpu_idt_load(WemuCpu *cpu, uint64_t base, uint16_t limit) {
    if (!cpu) return -1;
    /* Bounded descriptor table: the whole [base, base+limit] must fit in
     * guest RAM.  A 16-bit limit caps the table at 64KiB. */
    if (base > cpu->ram_size || (uint64_t)limit > cpu->ram_size - base)
        return -1;
    cpu->idtr.base = base;
    cpu->idtr.limit = limit;
    cpu->idtr.configured = 1;
    return 0;
}

int wemu_cpu_idt_gate(const WemuCpu *cpu, unsigned vector, WemuIdtGate *out) {
    if (!cpu || !out) return -1;
    WemuIdtGate g;
    if (exc_idt_gate_read(cpu, vector, &g) != 0) return -1;
    *out = g;
    return 0;
}

/* ---- bounded GDT/TSS segment-origin checks (software INT only) -------
 * Read the access byte of a GDT descriptor by selector.  Descriptors live
 * in guest RAM and are bounded by the limit latched at wemu_cpu_gdt_load.
 * TI=1 selects an LDT, which WEMU does not model: treated as invalid. */
static int exc_gdt_access(const WemuCpu *cpu, uint16_t sel, uint8_t *access) {
    if (!cpu || !cpu->gdt.configured || !access) return -1;
    if (sel & 0x4u) return -1;                 /* LDT not modelled */
    unsigned index = (unsigned)sel >> 3;
    if (index == 0) return -1;                 /* null selector */
    uint64_t off = (uint64_t)index * 8;
    if (off + 7 > cpu->gdt.limit) return -1;   /* outside the GDT */
    *access = cpu->ram[cpu->gdt.base + off + 5];
    return 0;
}

/* Architectural target CPL of a software INT: the DPL of the gate's code
 * descriptor (a non-conforming code segment loads that DPL into CPL; a
 * conforming one keeps the current CPL).  Derived from the SAME bounded
 * GDT owner, never a second table.  Returns -1 when the selector is outside
 * the GDT (the caller then lets the segment check latch #NP). */
static int exc_target_cpl(const WemuCpu *cpu, const ExcTarget *t, int *out) {
    if (!cpu->gdt.configured) { *out = cpu->cpl; return 0; }
    uint8_t access;
    if (exc_gdt_access(cpu, t->selector, &access) != 0) return -1;
    int conforming = (access & 0x1Cu) == 0x1Cu; /* S=1, code, conforming */
    *out = conforming ? cpu->cpl : ((access >> 5) & 3);
    return 0;
}

/* Bounded segment checks for a privilege-changing software INT.  Called
 * only after the gate itself validated, and only when the requested
 * target CPL differs from the current one.  On rejection the fault and
 * its selector error code are latched for the caller.  A pass generates
 * no state change — the privilege switch is performed by exc_deliver. */
static int exc_int_segment_check(WemuCpu *cpu, const ExcTarget *t, int target) {
    /* No GDT loaded: no segment model, so generate no faults at all. */
    if (!cpu->gdt.configured) return 0;
    if (target == cpu->cpl) return 0;          /* no stack switch */
    if (target < 0 || target > 3) return 0;    /* invalid request: no switch */

    /* Gate target code segment: a not-present descriptor is #NP(selector).
     * Skipped when no GDT is loaded, preserving the descriptor-less path. */
    if (cpu->gdt.configured) {
        uint8_t cs_access;
        uint16_t cs = t->selector;
        if (exc_gdt_access(cpu, cs, &cs_access) != 0 || !(cs_access & 0x80u)) {
            cpu->fault = 11; /* #NP */
            cpu->fault_error = (uint64_t)(cs & 0xFFFCu);
            return -1;
        }
    }

    /* The TSS must supply an SS selector for the target CPL.  A null
     * selector, a mismatched RPL, an LDT selector or a selector outside
     * the GDT is an invalid-TSS condition (#TS). */
    uint16_t ss = cpu->tss_ss[target];
    uint64_t ss_err = (uint64_t)(ss & 0xFFFCu);
    if (!cpu->gdt.configured || (ss & 0xFFFCu) == 0 ||
        (ss & 3u) != (unsigned)target || (ss & 4u)) {
        cpu->fault = 10; /* #TS */
        cpu->fault_error = ss_err;
        return -1;
    }
    uint8_t ss_access;
    if (exc_gdt_access(cpu, ss, &ss_access) != 0) {
        cpu->fault = 10; /* #TS: SS outside the GDT limit */
        cpu->fault_error = ss_err;
        return -1;
    }
    /* Stack must be a present writable data segment: P, S=1, W=1. */
    if (!(ss_access & 0x80u) || !(ss_access & 0x10u) ||
        !(ss_access & 0x02u)) {
        cpu->fault = 12; /* #SS */
        cpu->fault_error = ss_err;
        return -1;
    }
    return 0;
}

int wemu_cpu_gdt_load(WemuCpu *cpu, uint64_t base, uint16_t limit) {
    if (!cpu) return -1;
    if (base > cpu->ram_size || (uint64_t)limit > cpu->ram_size - base)
        return -1;
    cpu->gdt.base = base;
    cpu->gdt.limit = limit;
    cpu->gdt.configured = 1;
    return 0;
}

void wemu_cpu_tss_set_ss(WemuCpu *cpu, int cpl, uint16_t selector) {
    if (cpu && cpl >= 0 && cpl <= 3) cpu->tss_ss[cpl] = selector;
}
uint16_t wemu_cpu_tss_ss(const WemuCpu *cpu, int cpl) {
    return (cpu && cpl >= 0 && cpl <= 3) ? cpu->tss_ss[cpl] : 0;
}
void wemu_cpu_tss_set_rsp(WemuCpu *cpu, int cpl, uint64_t rsp) {
    if (cpu && cpl >= 0 && cpl <= 3) cpu->tss_rsp[cpl] = rsp;
}
uint64_t wemu_cpu_tss_rsp(const WemuCpu *cpu, int cpl) {
    return (cpu && cpl >= 0 && cpl <= 3) ? cpu->tss_rsp[cpl] : 0;
}

/* ---- LTR: bounded 64-bit TSS descriptor parse + stack load ------------
 * The descriptor is a 16-byte system segment in the bounded GDT (two GDT
 * slots).  TI=1 selects an LDT (not modelled).  A 64-bit TSS descriptor
 * must have S=0 and type 0x9 (available); LTR rejects a busy (0xB) TSS and
 * a nonzero reserved dword in the upper half, then marks the descriptor
 * busy with a locked write to the GDT (SDM LTR pseudocode). */
static int exc_gdt_tss_desc(const WemuCpu *cpu, uint16_t sel, uint8_t d[16]) {
    if (!cpu || !cpu->gdt.configured || !d) return -1;
    if (sel & 0x4u) return -1;                 /* LDT not modelled */
    unsigned index = (unsigned)sel >> 3;
    if (index == 0) return -1;                 /* null selector */
    uint64_t off = (uint64_t)index * 8;
    if (off + 15 > cpu->gdt.limit) return -1;  /* full 16-byte descriptor */
    memcpy(d, cpu->ram + cpu->gdt.base + off, 16);
    return 0;
}

/* Offsets in the 64-bit TSS image. RSP0/1/2 are the architectural offsets;
 * the SS slots are the documented WEMU extension (a real 64-bit TSS has no
 * SS fields). */
#define TSS_RSP0_OFF  0x04u
#define TSS_RSP1_OFF  0x0cu
#define TSS_RSP2_OFF  0x14u
#define TSS_SS0_OFF   0x1cu
#define TSS_SS1_OFF   0x1eu
#define TSS_SS2_OFF   0x20u
#define TSS_MIN_LIMIT (TSS_SS2_OFF + 2u)

int wemu_cpu_ltr(WemuCpu *cpu, uint16_t selector, WemuTssDescriptor *out) {
    if (!cpu) return -1;
    uint64_t sel_err = (uint64_t)(selector & 0xFFFCu);

    /* LTR is ring-0 only; a null selector is #GP(0). */
    if (cpu->cpl != 0 || sel_err == 0) {
        cpu->fault = 13; cpu->fault_error = 0; return -1;
    }

    uint8_t d[16];
    if (exc_gdt_tss_desc(cpu, selector, d) != 0) {
        cpu->fault = 13; cpu->fault_error = sel_err; return -1;
    }

    uint8_t access = d[5];
    uint8_t type = (uint8_t)(access & 0x0fu);
    int present = (access >> 7) & 1;
    /* S=1 (code/data) or any type other than an AVAILABLE TSS is #GP —
     * this also rejects a busy TSS (type 0xB) as the SDM requires. */
    if ((access & 0x10u) || type != 0x9u) {
        cpu->fault = 13; cpu->fault_error = sel_err; return -1;
    }
    /* In 64-bit mode the upper descriptor half holds base[63:32] in its
     * first dword and three reserved dwords that must be zero. */
    if (d[12] || d[13] || d[14] || d[15]) {
        cpu->fault = 13; cpu->fault_error = sel_err; return -1;
    }
    if (!present) {
        cpu->fault = 11; cpu->fault_error = sel_err; return -1; /* #NP */
    }

    uint64_t base = (uint64_t)d[2]  | ((uint64_t)d[3]  << 8) |
                    ((uint64_t)d[4] << 16) | ((uint64_t)d[7] << 24) |
                    ((uint64_t)d[8] << 32) | ((uint64_t)d[9] << 40) |
                    ((uint64_t)d[10] << 48) | ((uint64_t)d[11] << 56);
    uint32_t limit = (uint32_t)d[0] | ((uint32_t)d[1] << 8) |
                     ((uint32_t)(d[6] & 0x0fu) << 16);

    /* Bounded TSS: the limit must cover the fields loaded below and the
     * whole image must fit in guest RAM.  A bad TSS limit is #TS(selector). */
    if (limit < TSS_MIN_LIMIT || base > cpu->ram_size ||
        (uint64_t)limit > cpu->ram_size - base) {
        cpu->fault = 10; cpu->fault_error = sel_err; return -1;
    }

    uint64_t rsp0, rsp1, rsp2;
    uint16_t ss0, ss1, ss2;
    memcpy(&rsp0, cpu->ram + base + TSS_RSP0_OFF, 8);
    memcpy(&rsp1, cpu->ram + base + TSS_RSP1_OFF, 8);
    memcpy(&rsp2, cpu->ram + base + TSS_RSP2_OFF, 8);
    memcpy(&ss0,  cpu->ram + base + TSS_SS0_OFF, 2);
    memcpy(&ss1,  cpu->ram + base + TSS_SS1_OFF, 2);
    memcpy(&ss2,  cpu->ram + base + TSS_SS2_OFF, 2);
    cpu->tss_rsp[0] = rsp0; cpu->tss_rsp[1] = rsp1; cpu->tss_rsp[2] = rsp2;
    cpu->tss_ss[0]  = ss0;  cpu->tss_ss[1]  = ss1;  cpu->tss_ss[2]  = ss2;

    /* Mark the descriptor busy in guest GDT memory (locked RMW on hardware). */
    cpu->ram[cpu->gdt.base + (uint64_t)(selector >> 3) * 8 + 5] =
        (uint8_t)((access & ~0x0fu) | 0x0bu);

    cpu->tr.selector = selector;
    cpu->tr.base = base;
    cpu->tr.limit = limit;
    cpu->tr.loaded = 1;
    cpu->tr.busy = 1;

    if (out) {
        out->base = base; out->limit = limit; out->selector = selector;
        out->type = type; out->dpl = (uint8_t)((access >> 5) & 3);
        out->present = (uint8_t)present; out->busy = 1;
    }
    return 0;
}

int wemu_cpu_tr_loaded(const WemuCpu *cpu) { return cpu && cpu->tr.loaded; }
uint16_t wemu_cpu_tr(const WemuCpu *cpu) {
    return (cpu && cpu->tr.loaded) ? cpu->tr.selector : 0;
}
uint64_t wemu_cpu_tr_base(const WemuCpu *cpu) {
    return (cpu && cpu->tr.loaded) ? cpu->tr.base : 0;
}
uint32_t wemu_cpu_tr_limit(const WemuCpu *cpu) {
    return (cpu && cpu->tr.loaded) ? cpu->tr.limit : 0;
}

/* ---- Hardware task switching: far JMP/CALL through a TSS selector ------
 * The suspended task's execution state is saved into ITS TSS image and the
 * entering task's back-link (SDM: selector of the previous task) is written
 * into ITS TSS image.  Both images live in guest RAM; only the NT bit and
 * observability counters are CPU-side.  The owner is the bounded GDT/TSS
 * model above — no second descriptor table is introduced. */
#define TSS_BACKLINK_OFF   0x00u
#define TSS_TASK_CS_OFF    0x28u
#define TSS_TASK_SS_OFF    0x2au
#define TSS_TASK_RIP_OFF   0x30u
#define TSS_TASK_RSP_OFF   0x38u
#define TSS_TASK_FL_OFF    0x40u
#define TSS_TASK_MIN_LIMIT (TSS_TASK_FL_OFF + 8u) /* 0x48 */

/* Parse base/limit/access from an already-bounded 16-byte TSS descriptor. */
static void exc_tss_parse(const uint8_t d[16], uint64_t *base,
                          uint32_t *limit, uint8_t *access) {
    *access = d[5];
    *base = (uint64_t)d[2]  | ((uint64_t)d[3]  << 8) |
            ((uint64_t)d[4] << 16) | ((uint64_t)d[7] << 24) |
            ((uint64_t)d[8] << 32) | ((uint64_t)d[9] << 40) |
            ((uint64_t)d[10] << 48) | ((uint64_t)d[11] << 56);
    *limit = (uint32_t)d[0] | ((uint32_t)d[1] << 8) |
             ((uint32_t)(d[6] & 0x0fu) << 16);
}

/* The TSS image must cover every field we touch and fit in guest RAM. */
static int exc_tss_bounded(const WemuCpu *cpu, uint64_t base, uint32_t limit) {
    return limit >= TSS_TASK_MIN_LIMIT && base <= cpu->ram_size &&
           (uint64_t)limit <= cpu->ram_size - base;
}

int wemu_cpu_task_switch(WemuCpu *cpu, uint16_t selector, uint64_t return_rip,
                         int nested) {
    if (!cpu) return -1;
    uint64_t sel_err = (uint64_t)(selector & 0xFFFCu);

    /* Null / LDT / no GDT: #GP with a selector error code. */
    if (!cpu->gdt.configured || sel_err == 0 || (selector & 0x4u)) {
        cpu->fault = 13; cpu->fault_error = sel_err; return -1;
    }
    uint8_t d[16];
    if (exc_gdt_tss_desc(cpu, selector, d) != 0) {
        cpu->fault = 13; cpu->fault_error = sel_err; return -1;
    }
    uint64_t base; uint32_t limit; uint8_t access;
    exc_tss_parse(d, &base, &limit, &access);
    uint8_t type = (uint8_t)(access & 0x0fu);
    int dpl = (int)((access >> 5) & 3);
    int present = (access >> 7) & 1;

    /* A task switch requires an AVAILABLE 64-bit TSS (S=0, type 9).  A code
     * or data descriptor, a busy TSS (type B), or nonzero reserved dwords
     * in the upper descriptor half is #GP(selector). */
    if ((access & 0x10u) || type != 0x9u ||
        (d[12] | d[13] | d[14] | d[15]) != 0) {
        cpu->fault = 13; cpu->fault_error = sel_err; return -1;
    }
    /* For JMP/CALL the selector's CPL and RPL may not exceed the TSS DPL. */
    if (cpu->cpl > dpl || (int)(selector & 3u) > dpl) {
        cpu->fault = 13; cpu->fault_error = sel_err; return -1;
    }
    if (!present) {
        cpu->fault = 11; cpu->fault_error = sel_err; return -1; /* #NP */
    }
    if (!exc_tss_bounded(cpu, base, limit)) {
        cpu->fault = 10; cpu->fault_error = sel_err; return -1; /* #TS */
    }
    /* There must be a current task whose state can be saved. */
    if (!cpu->tr.loaded || !exc_tss_bounded(cpu, cpu->tr.base, cpu->tr.limit)) {
        cpu->fault = 10;
        cpu->fault_error = (uint64_t)(cpu->tr.selector & 0xFFFCu);
        return -1;
    }

    /* Validate the entering task's CS/SS selectors from its TSS image.
     * CS must be a present code segment, SS a present writable data one. */
    uint16_t new_cs, new_ss;
    memcpy(&new_cs, cpu->ram + base + TSS_TASK_CS_OFF, 2);
    memcpy(&new_ss, cpu->ram + base + TSS_TASK_SS_OFF, 2);
    uint8_t cs_acc = 0, ss_acc = 0;
    if ((new_cs & 0xFFFCu) == 0 || (new_ss & 0xFFFCu) == 0 ||
        exc_gdt_access(cpu, new_cs, &cs_acc) != 0 ||
        exc_gdt_access(cpu, new_ss, &ss_acc) != 0 ||
        !(cs_acc & 0x80u) || !(cs_acc & 0x10u) || !(cs_acc & 0x08u) ||
        !(ss_acc & 0x80u) || !(ss_acc & 0x10u) || !(ss_acc & 0x02u)) {
        cpu->fault = 10; cpu->fault_error = sel_err; return -1; /* #TS */
    }
    int new_cpl = (int)(new_cs & 3u);

    /* Save the suspended task into its OWN TSS image.  The saved RIP is the
     * instruction after the far transfer, so a back-link IRET resumes there. */
    uint64_t ob = cpu->tr.base;
    uint16_t old_sel = cpu->tr.selector, old_cs = cpu->cs_selector;
    uint16_t old_ss = cpu->ss_selector;
    uint64_t old_rsp = cpu->r[4], old_fl = cpu->rflags;
    memcpy(cpu->ram + ob + TSS_TASK_CS_OFF,  &old_cs,    2);
    memcpy(cpu->ram + ob + TSS_TASK_SS_OFF,  &old_ss,    2);
    memcpy(cpu->ram + ob + TSS_TASK_RIP_OFF, &return_rip, 8);
    memcpy(cpu->ram + ob + TSS_TASK_RSP_OFF, &old_rsp,   8);
    memcpy(cpu->ram + ob + TSS_TASK_FL_OFF,  &old_fl,    8);

    /* Back-link of the NEW task = selector of the OLD task (SDM). */
    memcpy(cpu->ram + base + TSS_BACKLINK_OFF, &old_sel, 2);

    /* Mark the new descriptor busy in guest GDT memory (locked RMW on HW). */
    cpu->ram[cpu->gdt.base + (uint64_t)(selector >> 3) * 8 + 5] =
        (uint8_t)((access & ~0x0fu) | 0x0bu);

    /* Load the entering task's state from its TSS image. */
    uint64_t n_rip, n_rsp, n_fl;
    memcpy(&n_rip, cpu->ram + base + TSS_TASK_RIP_OFF, 8);
    memcpy(&n_rsp, cpu->ram + base + TSS_TASK_RSP_OFF, 8);
    memcpy(&n_fl,  cpu->ram + base + TSS_TASK_FL_OFF,  8);
    cpu->rip = n_rip;
    cpu->r[4] = n_rsp;
    if (n_fl) cpu->rflags = n_fl | 2ull; /* bit 1 reserved, always set */
    cpu->cs_selector = new_cs; cpu->cs_rpl = new_cpl;
    cpu->ss_selector = new_ss; cpu->cpl = new_cpl;
    cpu->tr.selector = selector; cpu->tr.base = base; cpu->tr.limit = limit;
    cpu->tr.busy = 1;
    cpu->task_nested = nested ? 1 : 0;
    cpu->task_switches++;
    cpu->fault = 0; cpu->fault_error = 0;
    return 0;
}

int wemu_cpu_task_return(WemuCpu *cpu) {
    if (!cpu || !cpu->task_nested || !cpu->tr.loaded) return -1;
    uint16_t back;
    memcpy(&back, cpu->ram + cpu->tr.base + TSS_BACKLINK_OFF, 2);
    uint64_t back_err = (uint64_t)(back & 0xFFFCu);
    if (!cpu->gdt.configured || back_err == 0 || (back & 0x4u)) {
        cpu->fault = 10; cpu->fault_error = back_err; return -1; /* #TS */
    }
    uint8_t d[16];
    if (exc_gdt_tss_desc(cpu, back, d) != 0) {
        cpu->fault = 10; cpu->fault_error = back_err; return -1;
    }
    uint64_t base; uint32_t limit; uint8_t access;
    exc_tss_parse(d, &base, &limit, &access);
    /* The suspended task is BUSY (it was active when we left it). */
    if ((access & 0x10u) || (access & 0x0fu) != 0x0bu ||
        !exc_tss_bounded(cpu, base, limit)) {
        cpu->fault = 10; cpu->fault_error = back_err; return -1;
    }

    uint16_t cs, ss; uint64_t rip, rsp, fl;
    memcpy(&cs,  cpu->ram + base + TSS_TASK_CS_OFF,  2);
    memcpy(&ss,  cpu->ram + base + TSS_TASK_SS_OFF,  2);
    memcpy(&rip, cpu->ram + base + TSS_TASK_RIP_OFF, 8);
    memcpy(&rsp, cpu->ram + base + TSS_TASK_RSP_OFF, 8);
    memcpy(&fl,  cpu->ram + base + TSS_TASK_FL_OFF,  8);
    cpu->rip = rip;
    cpu->r[4] = rsp;
    cpu->rflags = fl | 2ull;
    cpu->cs_selector = cs; cpu->cs_rpl = (int)(cs & 3u);
    cpu->ss_selector = ss; cpu->cpl = (int)(cs & 3u);

    /* The task we are leaving is no longer active: mark its TSS available. */
    uint16_t cur = cpu->tr.selector;
    uint64_t coff = cpu->gdt.base + (uint64_t)(cur >> 3) * 8 + 5;
    if ((cur & 0xFFFCu) && !(cur & 0x4u) &&
        (uint64_t)((cur >> 3) * 8 + 5) <= cpu->gdt.limit &&
        coff < cpu->ram_size) {
        uint8_t a = cpu->ram[coff];
        if ((a & 0x0fu) == 0x0bu)
            cpu->ram[coff] = (uint8_t)((a & ~0x0fu) | 0x09u);
    }
    cpu->tr.selector = back; cpu->tr.base = base; cpu->tr.limit = limit;
    cpu->tr.busy = 1;
    cpu->task_nested = 0;
    cpu->task_switches++;
    cpu->fault = 0; cpu->fault_error = 0;
    return 0;
}

int wemu_cpu_task_nested(const WemuCpu *cpu) { return cpu && cpu->task_nested; }
unsigned wemu_cpu_task_switches(const WemuCpu *cpu) {
    return cpu ? cpu->task_switches : 0;
}

void wemu_cpu_set_int_target_cpl(WemuCpu *cpu, int cpl) {
    if (cpu) cpu->int_target_cpl = cpl < 0 ? 0 : (cpl > 3 ? 3 : cpl);
}
int wemu_cpu_int_target_cpl(const WemuCpu *cpu) {
    return cpu ? cpu->int_target_cpl : 0;
}

/* push a 64-bit slot; the guest stack grows down (address-space owner). */
static int exc_push(WemuCpu *cpu, uint64_t *sp, uint64_t v) {
    *sp -= 8;
    return wemu_gpa_write(cpu, *sp, &v, 8);
}

int wemu_cpu_register_exception_handler(WemuCpu *cpu, unsigned vector,
                                        uint64_t guest_rip) {
    if (!cpu || vector >= 256) return -1;
    cpu->idt[vector].rip = guest_rip;
    cpu->idt[vector].present = 1;
    return 0;
}

int wemu_cpu_exception_handler(const WemuCpu *cpu, unsigned vector,
                               uint64_t *out_rip) {
    if (!cpu || vector >= 256 || !cpu->idt[vector].present) return -1;
    if (out_rip) *out_rip = cpu->idt[vector].rip;
    return 0;
}

/* A usable #DF handler exists when a loaded IDT has a present long-mode
 * gate for vector 8, or (legacy path) a registered handler for it.  Used
 * to decide whether a double-fault condition can actually be delivered. */
static int exc_has_df_handler(const WemuCpu *cpu) {
    if (!cpu) return 0;
    if (cpu->idtr.configured) {
        WemuIdtGate g;
        if (exc_idt_gate_read(cpu, 8, &g) != 0) return 0;
        return g.present && (g.type == 0xE || g.type == 0xF);
    }
    return cpu->idt[8].present;
}

/* Record a double-fault condition.  The secondary vector (#NP for a
 * not-present gate, #GP for a bad gate type / out-of-limit index) and its
 * error code stay observable even when #DF itself cannot be delivered. */
static void exc_latch_df(WemuCpu *cpu, unsigned src, uint64_t src_error) {
    cpu->df_count++;
    cpu->df_latched = 1;
    cpu->df_src_vector = (uint8_t)src;
    cpu->df_src_error = src_error;
}

/* Real delivery.  Called from wemu_cpu_step at the fault boundary (and
 * available to a host bridge).  Returns 0 when the guest was transferred
 * to a handler, -1 when no handler is registered / the gate was rejected
 * (in which case #GP/#NP is latched for the caller). */
static int exc_deliver(WemuCpu *cpu, unsigned vector, int software) {
    if (!cpu || vector == 0 || vector >= 256) return -1;
    ExcTarget t;
    int target = cpu->cpl;     /* derived target CPL (software INT only) */
    int priv_switch = 0;       /* 1 when the INT changes privilege */
    if (cpu->idtr.configured) {
        /* Architectural path: parse and validate the gate from guest RAM. */
        if (exc_idt_check(cpu, vector, &t, software) != 0) {
            if (!software) {
                /* SDM: a fault raised while delivering an exception is a
                 * double-fault condition (#NP/#GP are #DF contributors).
                 * Record it.  When a usable #DF gate exists, replace the
                 * secondary #GP/#NP with #DF and transfer control to the
                 * #DF handler (error code 0, per SDM).  Without one, keep
                 * the legacy secondary latch so existing guests that read
                 * wemu_cpu_fault() observe the same value as before.  A
                 * fault while delivering #DF itself is a triple fault:
                 * latch #DF but never recurse. */
                unsigned src = (unsigned)cpu->fault;
                uint64_t src_err = cpu->fault_error;
                exc_latch_df(cpu, src, src_err);
                if (vector != 8 && exc_has_df_handler(cpu)) {
                    cpu->fault = 8;
                    cpu->fault_error = 0;
                    return exc_deliver(cpu, 8, 0);
                }
            }
            return -1;
        }
        /* The architectural target CPL is the DPL of the gate's code
         * descriptor in the SAME bounded GDT.  This applies to a software
         * INT AND to an exception whose gate targets a different ring —
         * both take the identical stack/CPL switch path below.  Segment
         * checks run only for a privilege change; on failure they have
         * already latched #TS/#SS/#NP for the caller.  With no GDT there
         * is no descriptor to derive a target from, so both paths keep the
         * current CPL (the legacy descriptor-less behaviour). */
        if (cpu->gdt.configured) {
            int derived;
            if (exc_target_cpl(cpu, &t, &derived) == 0) target = derived;
            /* A software INT with an out-of-GDT selector falls back to the
             * legacy requested target so the segment check latches #NP;
             * an exception has no such request and simply does not switch. */
            else target = software ? cpu->int_target_cpl : cpu->cpl;
            if (exc_int_segment_check(cpu, &t, target) != 0) return -1;
            priv_switch = (target != cpu->cpl);
        }
    } else {
        /* Legacy registered-RIP path (WEMU_HAS_EXCEPTION_DELIVERY).
         * No descriptor: no IST, trap-gate semantics (IF preserved). */
        if (!cpu->idt[vector].present) return -1;
        t.rip  = cpu->idt[vector].rip;
        t.ist  = 0;
        t.type = 0xF;
        t.selector = 0x28;
    }

    uint64_t fault_rip = cpu->rip;      /* saved RIP (INT n = next insn) */
    uint64_t old_rsp  = cpu->r[4];
    /* Stack base: on a privilege change the TSS supplies the new RSP
     * (RSP0 for CPL 0); a nonzero IST index still overrides it.  A zero
     * TSS RSP means "no base configured" and keeps the old RSP, preserving
     * descriptor-less / legacy guests. */
    uint64_t sp;
    if (priv_switch) {
        uint64_t tss_rsp = cpu->tss_rsp[target];
        /* An LTR-loaded TSS supplies the base even when RSP is 0; the
         * legacy host-setter convention treats 0 as "not configured". */
        int from_tss = cpu->tr.loaded && target >= 0 && target <= 2;
        uint64_t base = (from_tss || tss_rsp) ? tss_rsp : old_rsp;
        sp = t.ist ? cpu->ist[t.ist & 7] : base;
    } else {
        sp = t.ist ? cpu->ist[t.ist & 7] : old_rsp;
    }
    uint64_t error    = cpu->fault_error;
    uint64_t saved_fl = cpu->rflags;    /* flags as seen before delivery */
    /* x86-64 frame CS is the selector of the INTERRUPTED procedure: its
     * RPL is the pre-interrupt CPL, which is exactly what IRET consults to
     * decide whether the frame carries an old RSP/SS.  A privilege switch
     * reloads the LIVE CS from the gate and the LIVE SS from the TSS
     * below, but the frame keeps the old CS/SS.  Same-level deliveries
     * keep the legacy convention (SS slot 0, CS = current CS = 0x28 at
     * reset). */
    uint64_t saved_ss = priv_switch ? (uint64_t)cpu->ss_selector : 0ull;
    uint64_t saved_cs = (uint64_t)cpu->cs_selector;

    /* Push the saved RFLAGS BEFORE clearing IF: an interrupt gate clears
     * IF for the handler, but the flag saved on the stack retains it.
     * A failed push is a #DF contributor: the secondary fault (#GP for an
     * out-of-RAM stack) is fed into the latch below and delivery is NOT
     * completed — with no valid stack a #DF frame cannot be pushed either. */
    int push_fault = 0;
    unsigned push_vec = 13;
    uint64_t push_err = 0;
#define EXC_PUSH(v) do {                                                      \
        if (!push_fault && exc_push(cpu, &sp, (uint64_t)(v)) != 0) {          \
            push_fault = 1;                                                   \
            push_vec = (unsigned)cpu->fault;                                  \
            push_err = cpu->fault_error;                                      \
        }                                                                     \
    } while (0)
    /* A same-level SOFTWARE INT uses the architectural 3-qword frame
     * (RIP, CS, RFLAGS [+ error]): no old SS/RSP are pushed when CPL does
     * not change.  A privilege switch (INT or exception) and the legacy
     * exception path push the full 5-qword frame with the old SS/RSP. */
    int push_ss_rsp = priv_switch || !software;
    if (push_ss_rsp) {
        EXC_PUSH(saved_ss);   /* SS: old SS on a switch, 0 for same-level */
        EXC_PUSH(old_rsp);    /* old RSP (pre-switch) */
    }
    EXC_PUSH(saved_fl);       /* RFLAGS */
    EXC_PUSH(saved_cs);       /* CS: interrupted procedure's selector */
    EXC_PUSH(fault_rip);      /* RIP */
    if (exc_has_error_code(vector))
        EXC_PUSH(error);      /* error code (#PF etc.) */
#undef EXC_PUSH

    if (push_fault) {
        exc_latch_df(cpu, push_vec ? push_vec : 13u, push_err);
        /* Keep the secondary fault visible as the legacy latch and leave
         * RSP/RIP untouched: no frame was committed and no handler ran. */
        cpu->fault = push_vec ? (int)push_vec : 13;
        cpu->fault_error = push_err;
        return -1;
    }

    cpu->r[4] = sp;
    cpu->rip  = t.rip;
    if (priv_switch) {
        cpu->cpl = target;                    /* real privilege transition */
        cpu->cs_rpl = target;
        cpu->cs_selector = t.selector;        /* CS reloaded from the gate */
        cpu->ss_selector = cpu->tss_ss[target]; /* SS from the TSS */
    }
    if (t.type == 0xE) cpu->rflags &= ~(uint64_t)WF_IF; /* interrupt gate */
    cpu->exc_vector = vector;
    cpu->exc_error  = error;
    cpu->exc_cr2    = cpu->cr2;         /* CR2 is architecturally held */
    cpu->fault      = 0;                /* delivered: resume at handler */
    cpu->fault_error = 0;
    return 0;
}

int wemu_cpu_deliver_exception(WemuCpu *cpu, unsigned vector) {
    return exc_deliver(cpu, vector, 0); /* exceptions ignore gate DPL */
}

int wemu_cpu_deliver_int(WemuCpu *cpu, unsigned vector) {
    return exc_deliver(cpu, vector, 1); /* INT n: CPL<=DPL is enforced */
}

/* ---- IRET (0xCF) -----------------------------------------------------
 * Return from an interrupt/exception frame.  Long mode pops RIP, CS and
 * RFLAGS; when the popped CS.RPL differs from the current CPL the frame
 * also carries the old RSP and SS, which are restored together with CPL.
 * The frame's CS is the interrupted procedure's selector (RPL = old CPL),
 * so a ring-3 -> ring-0 INT followed by IRET in the handler lands exactly
 * back on ring 3 with the original RIP/RSP/SS/RFLAGS.  Frame reads go
 * through the memory owner; a short stack faults as #SS.  An error code,
 * when the original event pushed one, sits BELOW the 3/5-qword frame: the
 * handler is responsible for adjusting RSP before IRET (as on hardware). */
int wemu_iret(WemuCpu *cpu) {
    if (!cpu) return -1;
    /* NT set: this task was entered by a far CALL/task switch, so IRET is
     * a task return through the TSS back-link, not an interrupt-frame pop. */
    if (cpu->task_nested) return wemu_cpu_task_return(cpu);
    uint64_t sp = cpu->r[4];
    uint64_t rip = 0, cs = 0, fl = 0, rsp = 0, ss = 0;
    if (wemu_gpa_read(cpu, sp, &rip, 8) != 0 ||
        wemu_gpa_read(cpu, sp + 8, &cs, 8) != 0 ||
        wemu_gpa_read(cpu, sp + 16, &fl, 8) != 0) {
        cpu->fault = 12; /* #SS: stack fault reading the IRET frame */
        cpu->fault_error = 0;
        return -1;
    }
    int target_cpl = (int)(cs & 3u);
    int priv_return = (target_cpl != cpu->cpl);
    if (priv_return && target_cpl > cpu->cpl) {
        /* Return to a less-privileged level: restore old RSP and SS. */
        if (wemu_gpa_read(cpu, sp + 24, &rsp, 8) != 0 ||
            wemu_gpa_read(cpu, sp + 32, &ss, 8) != 0) {
            cpu->fault = 12;
            cpu->fault_error = 0;
            return -1;
        }
    } else if (priv_return) {
        /* IRET may not return to a more privileged level. */
        cpu->fault = 13; /* #GP */
        cpu->fault_error = 0;
        return -1;
    }
    /* Commit architectural state only after every frame read succeeded. */
    cpu->rip = rip;
    cpu->cs_selector = (uint16_t)cs;
    cpu->cs_rpl = target_cpl;
    cpu->rflags = fl | 2ull;   /* EFLAGS bit 1 is reserved, always set */
    if (priv_return) {
        cpu->cpl = target_cpl;
        cpu->ss_selector = (uint16_t)ss;
        cpu->r[4] = rsp;
    } else {
        cpu->r[4] = sp + 24;   /* same-level: 3-qword frame consumed */
    }
    return 0;
}

int wemu_cpu_iret(WemuCpu *cpu) { return wemu_iret(cpu); }

/* Host-side raise (VSL mprotect write hook, device, external event).
 * Latch for delivery at the next step boundary so RIP/stack state is
 * consistent (never mutate a frame mid-instruction). */
void wemu_cpu_raise_exception(WemuCpu *cpu, unsigned vector,
                              uint64_t error, uint64_t cr2) {
    if (!cpu || vector == 0 || vector >= 256) return;
    cpu->fault = (int)vector;
    cpu->fault_error = error;
    if (cr2) cpu->cr2 = cr2;
}

unsigned wemu_cpu_exception_vector(const WemuCpu *cpu) {
    return cpu ? cpu->exc_vector : 0;
}
uint64_t wemu_cpu_exception_error(const WemuCpu *cpu) {
    return cpu ? cpu->exc_error : 0;
}
uint64_t wemu_cpu_exception_cr2(const WemuCpu *cpu) {
    return cpu ? cpu->exc_cr2 : 0;
}

/* ---- Double-fault observables ---------------------------------------- */
unsigned wemu_cpu_double_faults(const WemuCpu *cpu) {
    return cpu ? cpu->df_count : 0;
}
int wemu_cpu_double_fault_latched(const WemuCpu *cpu) {
    return cpu && cpu->df_latched;
}
unsigned wemu_cpu_double_fault_source(const WemuCpu *cpu) {
    return cpu ? cpu->df_src_vector : 0;
}
uint64_t wemu_cpu_double_fault_source_error(const WemuCpu *cpu) {
    return cpu ? cpu->df_src_error : 0;
}
