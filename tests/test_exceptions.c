/* test_exceptions.c — real guest exception-delivery gate.
 *
 * Pre-change WEMU only LATCHED a fault vector and stopped; it never pushed
 * a frame or transferred control.  This gate installs guest IDT handlers
 * and proves two real deliveries:
 *   #UD (6)  from LOCK on a non-lockable instruction (exec fault origin),
 *   #PF (14) from a VSL-mprotect-style write hook (host raise: error 0x3,
 *            CR2 = protected VA).
 * It checks vector, error code, CR2, the pushed x86-64 frame and RIP
 * transfer.  A no-handler case proves the legacy latch is preserved.
 *
 * NEGATIVE CONTROL: this SAME source compiled against pre-change WEMU
 * (no WEMU_HAS_EXCEPTION_DELIVERY) prints FAIL and exits 1. */
#include "wemu.h"
#include <stdio.h>

static int fails;
#define CHECK(c, m) do { if (!(c)) { \
    printf("FAIL: %s (line %d)\n", m, __LINE__); fails++; } } while (0)

#define RAMSZ        (1u << 20)
#define CODE          0x1000u
#define UD_HANDLER    0x4000u
#define PF_HANDLER    0x4100u
#define STACK         0x80000u
#define PROTECTED_VA  0x90000u

static WemuCpu *boot(void) {
    WemuCpu *c = wemu_cpu_create(RAMSZ);
    wemu_cpu_set_rip(c, CODE);
    wemu_cpu_set_rsp(c, STACK);
    return c;
}

static uint64_t frame_qword(WemuCpu *c, uint64_t sp, int idx) {
    uint64_t v = 0;
    (void)wemu_mem_read(c, sp + (uint64_t)idx * 8, &v, 8);
    return v;
}

/* Runs against BOTH old and new WEMU: a latched fault with no registered
 * handler must behave exactly as before (step -1, fault set, RIP held). */
static void check_legacy_latch(void) {
    uint8_t ud[] = { 0xF0, 0x01, 0xD8, 0xF4 }; /* LOCK ADD EAX,EBX -> #UD */
    WemuCpu *c = boot();
    wemu_cpu_load(c, CODE, ud, sizeof ud);
    int64_t n = wemu_cpu_step(c);
    CHECK(n == -1 && wemu_cpu_fault(c) == 6,
          "no handler: #UD stays latched, step returns -1");
    CHECK(wemu_cpu_rip(c) == CODE, "no handler: RIP unchanged");
    wemu_cpu_destroy(c);
}

int main(void) {
    check_legacy_latch();

#ifndef WEMU_HAS_EXCEPTION_DELIVERY
    /* Pre-change code has no IDT/delivery API at all. */
    printf("FAIL: WEMU_HAS_EXCEPTION_DELIVERY absent — "
           "pre-change WEMU latches faults but never delivers them\n");
    return 1;
#else
    /* ---- #UD: LOCK on a non-lockable instruction, real exec fault ---- */
    {
        uint8_t ud[] = { 0xF0, 0x01, 0xD8, 0xF4 };
        WemuCpu *c = boot();
        wemu_cpu_load(c, CODE, ud, sizeof ud);
        CHECK(wemu_cpu_register_exception_handler(c, 6, UD_HANDLER) == 0,
              "install #UD handler");
        int64_t n = wemu_cpu_step(c);
        CHECK(n == 1, "#UD delivered: step returns 1 at handler");
        CHECK(wemu_cpu_fault(c) == 0, "#UD delivery clears the latched fault");
        CHECK(wemu_cpu_rip(c) == UD_HANDLER, "#UD transfers RIP to handler");
        CHECK(wemu_cpu_exception_vector(c) == 6, "delivered vector == 6");
        CHECK(wemu_cpu_exception_error(c) == 0, "#UD pushes no error code");
        /* frame without error code: RIP,CS,FLAGS,oldRSP,SS */
        uint64_t sp = wemu_cpu_reg(c, 4);
        CHECK(frame_qword(c, sp, 0) == CODE, "#UD frame saved RIP = faulting insn");
        CHECK(frame_qword(c, sp, 1) == 0x28, "#UD frame CS = 0x28");
        CHECK(frame_qword(c, sp, 2) == 2, "#UD frame RFLAGS = reset 2");
        CHECK(frame_qword(c, sp, 3) == STACK, "#UD frame old RSP");
        CHECK(frame_qword(c, sp, 4) == 0, "#UD frame SS = 0");
        CHECK(sp == STACK - 5 * 8, "#UD frame is 5 qwords");
        printf("delivery: #UD vec=%u err=%llu rip=0x%llx\n",
               wemu_cpu_exception_vector(c),
               (unsigned long long)wemu_cpu_exception_error(c),
               (unsigned long long)wemu_cpu_rip(c));
        wemu_cpu_destroy(c);
    }

    /* ---- #PF: VSL mprotect write hook raises #PF(P|W=3, CR2) --------- */
    {
        WemuCpu *c = boot();
        CHECK(wemu_cpu_register_exception_handler(c, 14, PF_HANDLER) == 0,
              "install #PF handler");
        /* mirror the overlay: write to a PROT_READ page -> #PF, error 3 */
        wemu_cpu_raise_exception(c, 14, 0x3, PROTECTED_VA);
        CHECK(wemu_cpu_fault(c) == 14, "mprotect hook latches #PF");
        int64_t n = wemu_cpu_step(c);
        CHECK(n == 1, "#PF delivered: step returns 1 at handler");
        CHECK(wemu_cpu_rip(c) == PF_HANDLER, "#PF transfers RIP to handler");
        CHECK(wemu_cpu_fault(c) == 0, "#PF delivery clears the fault");
        CHECK(wemu_cpu_exception_vector(c) == 14, "delivered vector == 14");
        CHECK(wemu_cpu_exception_error(c) == 0x3, "#PF error code = P|W = 3");
        CHECK(wemu_cpu_exception_cr2(c) == PROTECTED_VA,
              "#PF CR2 = protected VA");
        /* frame with error code: error,RIP,CS,FLAGS,oldRSP,SS */
        uint64_t sp = wemu_cpu_reg(c, 4);
        CHECK(frame_qword(c, sp, 0) == 0x3, "#PF frame slot0 = error 3");
        CHECK(frame_qword(c, sp, 1) == CODE, "#PF frame saved RIP");
        CHECK(frame_qword(c, sp, 2) == 0x28, "#PF frame CS");
        CHECK(frame_qword(c, sp, 3) == 2, "#PF frame RFLAGS");
        CHECK(frame_qword(c, sp, 4) == STACK, "#PF frame old RSP");
        CHECK(frame_qword(c, sp, 5) == 0, "#PF frame SS");
        CHECK(sp == STACK - 6 * 8, "#PF frame is 6 qwords");
        printf("delivery: #PF vec=%u err=%llu cr2=0x%llx rip=0x%llx\n",
               wemu_cpu_exception_vector(c),
               (unsigned long long)wemu_cpu_exception_error(c),
               (unsigned long long)wemu_cpu_exception_cr2(c),
               (unsigned long long)wemu_cpu_rip(c));
        wemu_cpu_destroy(c);
    }

    /* ---- differential: no handler -> no delivery (legacy preserved) - */
    {
        WemuCpu *c = boot();
        wemu_cpu_raise_exception(c, 14, 0x3, PROTECTED_VA);
        int64_t n = wemu_cpu_step(c); /* no #PF handler registered */
        CHECK(n == -1 && wemu_cpu_fault(c) == 14,
              "no #PF handler: fault stays latched (pre-change semantics)");
        CHECK(wemu_cpu_rip(c) == CODE, "no #PF handler: RIP unchanged");
        wemu_cpu_destroy(c);
    }

    if (fails) {
        printf("%d EXCEPTION-DELIVERY CHECK(S) FAILED\n", fails);
        return 1;
    }
    printf("ALL EXCEPTION-DELIVERY CHECKS PASS\n");
    return 0;
#endif
}
