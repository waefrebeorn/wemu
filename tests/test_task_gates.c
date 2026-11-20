/* test_task_gates.c — differential gate for bounded call/task gate decoding
 * and nested task-chain returns.
 *
 * A REAL guest program drives a nested chain using BOTH task-gate forms:
 *   A (ring 0): movabs rax,SENT_A; INT 0x40    -- IDT task gate -> TSS B
 *   B:          movabs rbx,SENT_B; far CALL [FAR_GATE_C]
 *                                       -- GDT task gate -> TSS C
 *              IRET                      -- back-link -> A
 *   C:          movabs rcx,SENT_C; IRET   -- back-link -> B
 *   A resumes, HLT.
 * Because B was entered with NT=1, C's IRET restores B's saved NT=1 and B's
 * own IRET follows ITS back-link to A.  If IRET cleared NT unconditionally
 * (old WEMU), B's IRET would pop a garbage interrupt frame and the chain
 * would fault instead of completing.
 *
 * Expectations (gate layout, back-links, saved state, fault codes) come from
 * the SDM, not from the implementation.  Negative controls check the exact
 * #GP/#NP vector and selector/IDT error code for rejected gates.
 *
 * NEGATIVE CONTROL: this SAME source compiled against the pre-change
 * library (1773858) prints FAIL and exits 1 — that WEMU rejects IDT/GDT
 * task gates and call gates (#GP) and clears NT on every IRET, so the
 * A->B->C->B->A chain cannot run.
 */
#include "wemu.h"
#include <stdio.h>
#include <string.h>

#ifndef WEMU_HAS_TASK_GATES
int main(void) {
    printf("FAIL: WEMU_HAS_TASK_GATES absent — pre-change WEMU #GPs IDT/GDT "
           "task gates (type 5) and GDT call gates (type 0xC), and IRET clears "
           "NT unconditionally, so the guest A->B->C chain cannot execute\n");
    return 1;
}
#else

static int fails, checks;
#define CHECK(c, m) do { checks++; if (!(c)) { \
    printf("FAIL: %s (line %d)\n", m, __LINE__); fails++; } } while (0)

#define RAMSZ       (1u << 20)
#define A_CODE      0x1000u
#define B_CODE      0x2000u
#define C_CODE      0x3000u
#define HANDLER     0x4000u
#define GDT_BASE    0x5000u
#define IDT_BASE    0x6000u
#define TSS_A_BASE  0x7000u
#define TSS_B_BASE  0x8000u
#define TSS_C_BASE  0x9000u
#define FAR_GATE_C  0xA000u
#define FAR_CALLG   0xA100u
#define GDT_LIMIT   0x0fffu
#define IDT_LIMIT   0x04ffu
#define TSS_LIMIT   0x67u
#define A_RSP       0xB0000u
#define B_RSP       0xC0000u
#define C_RSP       0xD0000u
#define H_RSP       0xE0000u

#define KCS             0x08u
#define KSS             0x10u
#define TSS_A_SEL       0x18u
#define TSS_B_SEL       0x28u
#define TSS_C_SEL       0x38u
#define TASK_GATE_C_SEL 0x48u
#define CALL_GATE_SEL   0x50u

#define VEC_A       0x40u

#define SENT_A 0xA5A5A5A5A5A5A5A5ull
#define SENT_B 0xB5B5B5B5B5B5B5B5ull
#define SENT_C 0xC5C5C5C5C5C5C5C5ull
#define SENT_H 0xD5D5D5D5D5D5D5D5ull

/* A: movabs rax (10) ; INT 0x40 (2) ; HLT (1) */
#define A_RESUME   (A_CODE + 12u)
/* B: movabs rbx (10) ; far CALL [FAR_GATE_C] (7) ; IRET (1) */
#define B_RESUME   (B_CODE + 17u)

#define TSS_AVAIL   0x89u
#define TSS_BUSY    0x8Bu
#define GATE_PRES   0x85u   /* P=1 DPL=0 S=0 type=5 (task gate) */
#define CALLGATE    0x8Cu   /* P=1 DPL=0 S=0 type=0xC (64-bit call gate) */

static void set_desc(WemuCpu *c, uint16_t sel, uint8_t access) {
    uint8_t d[8];
    memset(d, 0, sizeof d);
    d[5] = access;
    (void)wemu_mem_write(c, GDT_BASE + (uint64_t)(sel >> 3) * 8, d, 8);
}

/* 8-byte system gate (task gate): TSS selector in bytes 2-3. */
static void set_task_gate(WemuCpu *c, uint16_t sel, uint16_t tss,
                          uint8_t access) {
    uint8_t d[8];
    memset(d, 0, sizeof d);
    d[2] = (uint8_t)tss; d[3] = (uint8_t)(tss >> 8);
    d[5] = access;
    (void)wemu_mem_write(c, GDT_BASE + (uint64_t)(sel >> 3) * 8, d, 8);
}

/* 16-byte 64-bit call gate: code selector bytes 2-3, offset bytes 0-1,6-11. */
static void set_call_gate(WemuCpu *c, uint16_t sel, uint16_t cs,
                          uint64_t off, uint8_t access) {
    uint8_t d[16];
    memset(d, 0, sizeof d);
    d[0] = (uint8_t)off;        d[1] = (uint8_t)(off >> 8);
    d[2] = (uint8_t)cs;         d[3] = (uint8_t)(cs >> 8);
    d[5] = access;
    d[6] = (uint8_t)(off >> 16); d[7] = (uint8_t)(off >> 24);
    d[8] = (uint8_t)(off >> 32); d[9] = (uint8_t)(off >> 40);
    d[10] = (uint8_t)(off >> 48); d[11] = (uint8_t)(off >> 56);
    (void)wemu_mem_write(c, GDT_BASE + (uint64_t)(sel >> 3) * 8, d, sizeof d);
}

static void set_tss_desc(WemuCpu *c, uint16_t sel, uint8_t access,
                         uint64_t base, uint32_t limit) {
    uint8_t d[16];
    memset(d, 0, sizeof d);
    d[0] = (uint8_t)limit;         d[1] = (uint8_t)(limit >> 8);
    d[2] = (uint8_t)base;          d[3] = (uint8_t)(base >> 8);
    d[4] = (uint8_t)(base >> 16);  d[5] = access;
    d[6] = (uint8_t)((limit >> 16) & 0x0fu);
    d[7] = (uint8_t)(base >> 24);
    d[8] = (uint8_t)(base >> 32);  d[9] = (uint8_t)(base >> 40);
    d[10] = (uint8_t)(base >> 48); d[11] = (uint8_t)(base >> 56);
    (void)wemu_mem_write(c, GDT_BASE + (uint64_t)(sel >> 3) * 8, d, sizeof d);
}

/* IDT task gate: TSS selector bytes 2-3, access byte 5. */
static void set_idt_task_gate(WemuCpu *c, unsigned vec, uint16_t tss,
                              uint8_t access) {
    uint8_t d[16];
    memset(d, 0, sizeof d);
    d[2] = (uint8_t)tss; d[3] = (uint8_t)(tss >> 8);
    d[5] = access;
    (void)wemu_mem_write(c, IDT_BASE + (uint64_t)vec * 16, d, sizeof d);
}

static void set_tss_image(WemuCpu *c, uint64_t base, uint16_t cs, uint16_t ss,
                          uint64_t rip, uint64_t rsp, uint64_t fl) {
    uint8_t t[0x48];
    memset(t, 0, sizeof t);
    memcpy(t + 0x28, &cs, 2);
    memcpy(t + 0x2a, &ss, 2);
    memcpy(t + 0x30, &rip, 8);
    memcpy(t + 0x38, &rsp, 8);
    memcpy(t + 0x40, &fl, 8);
    (void)wemu_mem_write(c, base, t, sizeof t);
}

static void set_far_ptr(WemuCpu *c, uint64_t addr, uint16_t sel) {
    uint8_t fp[10];
    memset(fp, 0, sizeof fp);       /* offset ignored for gate/TSS transfers */
    fp[8] = (uint8_t)sel; fp[9] = (uint8_t)(sel >> 8);
    (void)wemu_mem_write(c, addr, fp, sizeof fp);
}

static uint16_t qword16(WemuCpu *c, uint64_t addr) {
    uint16_t v = 0; (void)wemu_mem_read(c, addr, &v, 2); return v;
}
static uint64_t qword64(WemuCpu *c, uint64_t addr) {
    uint64_t v = 0; (void)wemu_mem_read(c, addr, &v, 8); return v;
}

static const uint8_t a_code[] = {
    0x48, 0xB8, 0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5, /* movabs rax,SA */
    0xCD, VEC_A,                                          /* INT 0x40 */
    0xF4                                                  /* HLT */
};
static const uint8_t b_code[] = {
    0x48, 0xBB, 0xB5,0xB5,0xB5,0xB5,0xB5,0xB5,0xB5,0xB5, /* movabs rbx,SB */
    0xFF, 0x1C, 0x25,                                     /* far CALL m16:64 */
    (uint8_t)FAR_GATE_C, (uint8_t)(FAR_GATE_C >> 8),
    (uint8_t)(FAR_GATE_C >> 16), (uint8_t)(FAR_GATE_C >> 24),
    0xCF                                                  /* IRET */
};
static const uint8_t c_code[] = {
    0x48, 0xB9, 0xC5,0xC5,0xC5,0xC5,0xC5,0xC5,0xC5,0xC5, /* movabs rcx,SC */
    0xCF                                                  /* IRET */
};
static const uint8_t handler_code[] = {
    0x48, 0xBA, 0xD5,0xD5,0xD5,0xD5,0xD5,0xD5,0xD5,0xD5, /* movabs rdx,SH */
    0xF4                                                  /* HLT */
};

static WemuCpu *boot(void) {
    WemuCpu *c = wemu_cpu_create(RAMSZ);
    wemu_cpu_set_rip(c, A_CODE);
    set_desc(c, KCS, 0x9A); set_desc(c, KSS, 0x92);
    set_tss_desc(c, TSS_A_SEL, TSS_AVAIL, TSS_A_BASE, TSS_LIMIT);
    set_tss_desc(c, TSS_B_SEL, TSS_AVAIL, TSS_B_BASE, TSS_LIMIT);
    set_tss_desc(c, TSS_C_SEL, TSS_AVAIL, TSS_C_BASE, TSS_LIMIT);
    CHECK(wemu_cpu_gdt_load(c, GDT_BASE, GDT_LIMIT) == 0, "load GDTR");
    CHECK(wemu_cpu_idt_load(c, IDT_BASE, IDT_LIMIT) == 0, "load IDTR");
    set_idt_task_gate(c, VEC_A, TSS_B_SEL, GATE_PRES);
    set_task_gate(c, TASK_GATE_C_SEL, TSS_C_SEL, GATE_PRES);
    set_call_gate(c, CALL_GATE_SEL, KCS, HANDLER, CALLGATE);
    set_tss_image(c, TSS_A_BASE, 0, 0, 0, 0, 0);
    set_tss_image(c, TSS_B_BASE, KCS, KSS, B_CODE, B_RSP, 0x202);
    set_tss_image(c, TSS_C_BASE, KCS, KSS, C_CODE, C_RSP, 0x202);
    set_far_ptr(c, FAR_GATE_C, TASK_GATE_C_SEL);
    set_far_ptr(c, FAR_CALLG, CALL_GATE_SEL);
    (void)wemu_cpu_load(c, A_CODE, a_code, sizeof a_code);
    (void)wemu_cpu_load(c, B_CODE, b_code, sizeof b_code);
    (void)wemu_cpu_load(c, C_CODE, c_code, sizeof c_code);
    (void)wemu_cpu_load(c, HANDLER, handler_code, sizeof handler_code);
    CHECK(wemu_cpu_ltr(c, TSS_A_SEL, NULL) == 0, "LTR loads task A");
    wemu_cpu_set_cpl(c, 0);
    wemu_cpu_set_cs(c, KCS);
    wemu_cpu_set_ss(c, KSS);
    wemu_cpu_set_rsp(c, A_RSP);
    wemu_cpu_clear_fault(c);
    return c;
}

/* ---- main differential chain: A -> B -> C -> IRET -> B -> IRET -> A ----- */
static void test_chain(void) {
    WemuCpu *c = boot();
    int64_t n = wemu_cpu_run(c, 12);

    CHECK(n == 8, "8 guest instructions (mov/INT/mov/farCALL/mov/IRET/IRET/HLT)");
    CHECK(wemu_cpu_halted(c), "guest reached HLT after the nested return");
    CHECK(wemu_cpu_fault(c) == 0, "nested chain without fault");
    CHECK(wemu_cpu_reg(c, 0) == SENT_A, "task A RAX preserved");
    CHECK(wemu_cpu_reg(c, 3) == SENT_B, "task B actually executed (RBX)");
    CHECK(wemu_cpu_reg(c, 1) == SENT_C, "task C actually executed (RCX)");
    CHECK(wemu_cpu_rip(c) == A_RESUME + 1, "A resumed after the INT task gate");
    CHECK(wemu_cpu_cs(c) == KCS && wemu_cpu_ss(c) == KSS, "A's CS/SS restored");
    CHECK(wemu_cpu_cpl(c) == 0, "CPL restored to A");
    CHECK(wemu_cpu_reg(c, 4) == A_RSP, "RSP restored to A");
    CHECK(wemu_cpu_tr(c) == TSS_A_SEL, "TR back at task A");
    CHECK(wemu_cpu_task_switches(c) == 4, "2 task gates + 2 back-link returns");
    CHECK(!wemu_cpu_task_nested(c), "NT clear after returning all the way to A");

    /* TSS evidence: B's back-link names A, C's names B; both saved RIPs and
     * B's saved NT bit prove the interrupted tasks really nested. */
    CHECK(qword16(c, TSS_B_BASE + 0x00) == TSS_A_SEL, "B back-link = A");
    CHECK(qword16(c, TSS_C_BASE + 0x00) == TSS_B_SEL, "C back-link = B");
    CHECK(qword64(c, TSS_A_BASE + 0x30) == A_RESUME, "A saved RIP = after INT");
    CHECK(qword64(c, TSS_B_BASE + 0x30) == B_RESUME, "B saved RIP = after far CALL");
    CHECK((qword64(c, TSS_B_BASE + 0x40) & 0x4000ull) != 0,
          "B was nested (saved RFLAGS.NT set when C was entered)");
    CHECK((qword16(c, GDT_BASE + (TSS_B_SEL >> 3) * 8 + 5) & 0x0f) == 0x09,
          "B's TSS available again after C returned to it");
    CHECK((qword16(c, GDT_BASE + (TSS_C_SEL >> 3) * 8 + 5) & 0x0f) == 0x09,
          "C's TSS available again after final return");
    CHECK((qword16(c, GDT_BASE + (TSS_A_SEL >> 3) * 8 + 5) & 0x0f) == 0x0b,
          "A's TSS still busy");

    printf("task_gates: A->B->C->B->A rax=0x%llx rbx=0x%llx rcx=0x%llx "
           "rip=0x%llx switches=%u NT=%d\n",
           (unsigned long long)wemu_cpu_reg(c, 0),
           (unsigned long long)wemu_cpu_reg(c, 3),
           (unsigned long long)wemu_cpu_reg(c, 1),
           (unsigned long long)wemu_cpu_rip(c),
           wemu_cpu_task_switches(c), wemu_cpu_task_nested(c));
    wemu_cpu_destroy(c);
}

/* ---- bounded 64-bit call gate: host + guest-executed far CALL ---------- */
static void test_call_gate(void) {
    /* host entry: decode gate, push return far pointer, transfer to handler */
    WemuCpu *c = boot();
    uint64_t old_rsp = wemu_cpu_reg(c, 4);
    CHECK(wemu_cpu_call_gate(c, CALL_GATE_SEL, A_RESUME) == 0,
          "call gate transfer succeeds");
    CHECK(wemu_cpu_fault(c) == 0, "call gate no fault");
    CHECK(wemu_cpu_rip(c) == HANDLER, "call gate target RIP = gate offset");
    CHECK(wemu_cpu_cs(c) == KCS, "call gate target CS = gate selector");
    CHECK(wemu_cpu_task_switches(c) == 0, "call gate is not a task switch");
    CHECK(wemu_cpu_reg(c, 4) == old_rsp - 16, "far call pushes 16 bytes");
    CHECK(qword64(c, old_rsp - 16) == A_RESUME, "pushed return RIP");
    CHECK(qword16(c, old_rsp - 8) == KCS, "pushed return CS");
    CHECK(wemu_cpu_run(c, 4) == 2 && wemu_cpu_halted(c) &&
          wemu_cpu_reg(c, 2) == SENT_H, "handler executes to HLT (RDX sentinel)");
    wemu_cpu_destroy(c);

    /* guest-executed far CALL through a call-gate selector dispatches too */
    c = boot();
    {
        uint8_t g[17];
        memcpy(g, a_code, 10);
        g[10] = 0xFF; g[11] = 0x1C; g[12] = 0x25;
        g[13] = (uint8_t)FAR_CALLG; g[14] = (uint8_t)(FAR_CALLG >> 8);
        g[15] = (uint8_t)(FAR_CALLG >> 16); g[16] = (uint8_t)(FAR_CALLG >> 24);
        (void)wemu_cpu_load(c, A_CODE, g, sizeof g);
        CHECK(wemu_cpu_run(c, 6) == 4, "guest far CALL reaches handler + HLT");
        CHECK(wemu_cpu_fault(c) == 0 && wemu_cpu_halted(c),
              "guest call-gate transfer faultless");
        CHECK(wemu_cpu_reg(c, 2) == SENT_H, "call-gate handler ran (RDX)");
        CHECK(wemu_cpu_rip(c) == HANDLER + 11, "RIP at handler HLT+1");
        CHECK(qword64(c, A_RSP - 16) == A_CODE + 17, "guest return RIP pushed");
        CHECK(qword16(c, A_RSP - 8) == KCS, "guest return CS pushed");
    }
    wemu_cpu_destroy(c);
}

/* ---- negative controls: exact fault vector + error code --------------- */
static void test_negatives(void) {
    WemuCpu *c;

    /* IDT task gate not present -> #NP((vec<<3)|2), no task switch. */
    c = boot();
    set_idt_task_gate(c, VEC_A, TSS_B_SEL, GATE_PRES & ~0x80u);
    CHECK(wemu_cpu_deliver_int(c, VEC_A) == -1, "not-present IDT task gate");
    CHECK(wemu_cpu_fault(c) == 11 && wemu_cpu_fault_error(c) == 0x202ull,
          "IDT task gate P=0 -> #NP(idt code)");
    CHECK(wemu_cpu_task_switches(c) == 0, "no switch on bad IDT gate");
    wemu_cpu_destroy(c);

    /* Software INT through a DPL=0 task gate at CPL=3 -> #GP(idt code). */
    c = boot();
    wemu_cpu_set_cpl(c, 3);
    CHECK(wemu_cpu_deliver_int(c, VEC_A) == -1, "DPL0 task gate at CPL3");
    CHECK(wemu_cpu_fault(c) == 13 && wemu_cpu_fault_error(c) == 0x202ull,
          "task gate max(CPL,RPL)>DPL -> #GP(idt code)");
    wemu_cpu_destroy(c);

    /* GDT task gate with null TSS selector -> #GP(0). */
    c = boot();
    set_task_gate(c, TASK_GATE_C_SEL, 0x0000, GATE_PRES);
    CHECK(wemu_cpu_task_switch(c, TASK_GATE_C_SEL, A_RESUME, 1) == -1,
          "GDT task gate with null TSS");
    CHECK(wemu_cpu_fault(c) == 13 && wemu_cpu_fault_error(c) == 0,
          "null TSS in gate -> #GP(0)");
    wemu_cpu_destroy(c);

    /* GDT task gate to the already-busy TSS A -> #GP(TSS_A_SEL). */
    c = boot();
    set_task_gate(c, TASK_GATE_C_SEL, TSS_A_SEL, GATE_PRES);
    CHECK(wemu_cpu_task_switch(c, TASK_GATE_C_SEL, A_RESUME, 1) == -1,
          "GDT task gate to busy TSS");
    CHECK(wemu_cpu_fault(c) == 13 && wemu_cpu_fault_error(c) == TSS_A_SEL,
          "busy TSS via gate -> #GP(tss selector)");
    wemu_cpu_destroy(c);

    /* GDT task gate not present -> #NP(gate selector). */
    c = boot();
    set_task_gate(c, TASK_GATE_C_SEL, TSS_C_SEL, GATE_PRES & ~0x80u);
    CHECK(wemu_cpu_task_switch(c, TASK_GATE_C_SEL, A_RESUME, 1) == -1,
          "not-present GDT task gate");
    CHECK(wemu_cpu_fault(c) == 11 && wemu_cpu_fault_error(c) == TASK_GATE_C_SEL,
          "GDT task gate P=0 -> #NP(gate selector)");
    wemu_cpu_destroy(c);

    /* Call gate wrong type (a code descriptor) -> #GP(selector). */
    c = boot();
    CHECK(wemu_cpu_call_gate(c, KCS, A_RESUME) == -1, "call gate on code seg");
    CHECK(wemu_cpu_fault(c) == 13 && wemu_cpu_fault_error(c) == KCS,
          "non-call-gate descriptor -> #GP(selector)");
    wemu_cpu_destroy(c);

    /* Call gate not present -> #NP(selector). */
    c = boot();
    set_call_gate(c, CALL_GATE_SEL, KCS, HANDLER, CALLGATE & ~0x80u);
    CHECK(wemu_cpu_call_gate(c, CALL_GATE_SEL, A_RESUME) == -1,
          "not-present call gate");
    CHECK(wemu_cpu_fault(c) == 11 && wemu_cpu_fault_error(c) == CALL_GATE_SEL,
          "call gate P=0 -> #NP(selector)");
    wemu_cpu_destroy(c);

    /* Call gate with a null target code selector -> #GP(gate selector). */
    c = boot();
    set_call_gate(c, CALL_GATE_SEL, 0, HANDLER, CALLGATE);
    CHECK(wemu_cpu_call_gate(c, CALL_GATE_SEL, A_RESUME) == -1,
          "call gate with null CS");
    CHECK(wemu_cpu_fault(c) == 13 && wemu_cpu_fault_error(c) == CALL_GATE_SEL,
          "null target CS -> #GP(gate selector)");
    wemu_cpu_destroy(c);

    /* GDT task gate whose TSS limit is too small -> #TS(tss selector). */
    c = boot();
    set_tss_desc(c, TSS_C_SEL, TSS_AVAIL, TSS_C_BASE, 0x10);
    CHECK(wemu_cpu_task_switch(c, TASK_GATE_C_SEL, A_RESUME, 1) == -1,
          "GDT task gate -> short TSS");
    CHECK(wemu_cpu_fault(c) == 10 && wemu_cpu_fault_error(c) == TSS_C_SEL,
          "short TSS via gate -> #TS(tss selector)");
    wemu_cpu_destroy(c);

    /* Call-gate selector past the GDT limit -> #GP(selector): bounded. */
    c = boot();
    CHECK(wemu_cpu_call_gate(c, 0x2000u, A_RESUME) == -1,
          "call gate selector past GDT limit");
    CHECK(wemu_cpu_fault(c) == 13 && wemu_cpu_fault_error(c) == 0x2000u,
          "out-of-GDT call gate -> #GP(selector)");
    wemu_cpu_destroy(c);
}

int main(void) {
    test_chain();
    test_call_gate();
    test_negatives();
    if (fails) {
        printf("test_task_gates: %d/%d CHECK(S) FAILED\n", fails, checks);
        return 1;
    }
    printf("test_task_gates: PASS (%d checks; IDT+GDT task gates, nested "
           "A->B->C IRET chain, call gate, #GP/#NP/#TS negatives)\n", checks);
    return 0;
}
#endif
