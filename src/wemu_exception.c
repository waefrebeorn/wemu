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

/* Bounded segment checks for a privilege-changing software INT.  Called
 * only after the gate itself validated, and only when the requested
 * target CPL differs from the current one.  On rejection the fault and
 * its selector error code are latched for the caller.  A pass generates
 * no state change — the actual privilege switch is NOT modelled here. */
static int exc_int_segment_check(WemuCpu *cpu, const ExcTarget *t) {
    int target = cpu->int_target_cpl;
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
        /* Privilege-changing software INT: the bounded GDT/TSS segment
         * checks run after the gate itself validated.  A failure has
         * already latched #TS/#SS/#NP for the caller. */
        if (software && exc_int_segment_check(cpu, &t) != 0) return -1;
    } else {
        /* Legacy registered-RIP path (WEMU_HAS_EXCEPTION_DELIVERY).
         * No descriptor: no IST, trap-gate semantics (IF preserved). */
        if (!cpu->idt[vector].present) return -1;
        t.rip  = cpu->idt[vector].rip;
        t.ist  = 0;
        t.type = 0xF;
        t.selector = 0x28;
    }

    uint64_t fault_rip = cpu->rip;      /* saved RIP = faulting instruction */
    uint64_t old_rsp  = cpu->r[4];
    /* IST switch: a nonzero gate IST index selects TSS.IST[n] as the new
     * stack base.  WEMU models those bases directly (no TSS descriptor);
     * index 0 means "use the current RSP". */
    uint64_t sp = t.ist ? cpu->ist[t.ist & 7] : old_rsp;
    uint64_t error    = cpu->fault_error;
    uint64_t saved_fl = cpu->rflags;    /* flags as seen before delivery */

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
    EXC_PUSH(0x00ull);        /* SS */
    EXC_PUSH(old_rsp);        /* old RSP (pre-switch) */
    EXC_PUSH(saved_fl);       /* RFLAGS */
    EXC_PUSH(0x28ull);        /* CS: 64-bit code selector */
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
