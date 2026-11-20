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

/* push a 64-bit slot; the guest stack grows down (address-space owner). */
static void exc_push(WemuCpu *cpu, uint64_t *sp, uint64_t v) {
    *sp -= 8;
    (void)wemu_gpa_write(cpu, *sp, &v, 8);
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

/* Real delivery.  Called from wemu_cpu_step at the fault boundary (and
 * available to a host bridge).  Returns 0 when the guest was transferred
 * to a handler, -1 when no handler is registered — in which case the
 * legacy behaviour (fault left latched, step returns -1) is preserved. */
int wemu_cpu_deliver_exception(WemuCpu *cpu, unsigned vector) {
    if (!cpu || vector == 0 || vector >= 256) return -1;
    if (!cpu->idt[vector].present) return -1;

    uint64_t handler  = cpu->idt[vector].rip;
    uint64_t fault_rip = cpu->rip;      /* saved RIP = faulting instruction */
    uint64_t old_rsp  = cpu->r[4];
    uint64_t sp       = old_rsp;
    uint64_t error    = cpu->fault_error;

    /* Long-mode interrupt frame (ring0 -> ring0, no IST): SS, old RSP,
     * RFLAGS, CS, RIP, then the error code last for vectors that push one
     * (so RSP points at the error code on entry, per the SDM). */
    exc_push(cpu, &sp, 0x00ull);          /* SS */
    exc_push(cpu, &sp, old_rsp);          /* old RSP */
    exc_push(cpu, &sp, cpu->rflags);      /* RFLAGS */
    exc_push(cpu, &sp, 0x28ull);          /* CS: 64-bit code selector */
    exc_push(cpu, &sp, fault_rip);        /* RIP */
    if (exc_has_error_code(vector))
        exc_push(cpu, &sp, error);        /* error code (#PF etc.) */

    cpu->r[4] = sp;
    cpu->rip  = handler;
    cpu->exc_vector = vector;
    cpu->exc_error  = error;
    cpu->exc_cr2    = cpu->cr2;           /* CR2 is architecturally held */
    cpu->fault      = 0;                  /* delivered: resume at handler */
    cpu->fault_error = 0;
    return 0;
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
