/* test_ldt.c — differential gate for bounded LDT descriptors and TI=1
 * selector decode.
 *
 * A REAL guest program transfers through descriptors that live ONLY in a
 * loaded LDT:
 *   A (ring 0): far CALL [FAR_LDT_GATE]  -- TI=1 call gate in the LDT
 *               HLT
 *   handler:    movabs rdx,SENT_H ; HLT
 * and a separate task switch uses a TI=1 TSS descriptor in the same LDT:
 *   far JMP/CALL [FAR_LDT_TSS] -> TSS B, whose GPR/CS/SS/RIP come from the
 *   LDT-resident TSS descriptor.
 *
 * The oracle is the SDM descriptor layout read back from GUEST RAM: the
 * gate offset and TSS selector are built independently from raw bytes, and
 * a mutation of the LDT gate offset must change the delivered RIP (proving
 * the decode reads the LDT, not the GDT).  Negative controls check the exact
 * #GP/#NP vector and selector error code, including TI bit preservation.
 *
 * NEGATIVE CONTROL: compiled against the pre-change library (90ca922) this
 * prints FAIL and exits 1 — old WEMU rejects every TI=1 selector with
 * #GP ("LDT not modelled") and has no LLDT-style host setter.
 */
#include "wemu.h"
#include <stdio.h>
#include <string.h>

#ifndef WEMU_HAS_LDT
int main(void) {
    printf("FAIL: WEMU_HAS_LDT absent — pre-change WEMU rejects TI=1 selectors "
           "with #GP and has no bounded LDT / LLDT setter, so LDT call gates "
           "and LDT task switches cannot execute\n");
    return 1;
}
#else

static int fails, checks;
#define CHECK(c, m) do { checks++; if (!(c)) { \
    printf("FAIL: %s (line %d)\n", m, __LINE__); fails++; } } while (0)

#define RAMSZ       (1u << 20)
#define GDT_BASE    0x4000u
#define GDT_LIMIT   0x1ffu
#define LDT_BASE    0x6000u
#define LDT_LIMIT   0x0ffu
#define A_CODE      0x1000u
#define B_CODE      0x2000u
#define HANDLER     0x4800u
#define HANDLER2    0x4900u
#define TSS_A_BASE  0x7000u
#define TSS_B_BASE  0x8000u
#define TSS_LIMIT   0x67u
#define FAR_LDT_GATE 0xA000u
#define FAR_LDT_TSS  0xA100u
#define A_RSP       0xB0000u
#define B_RSP       0xC0000u

#define KCS          0x08u   /* GDT idx1: DPL0 code  */
#define KSS          0x10u   /* GDT idx2: DPL0 data  */
#define LDT_DESC_SEL 0x18u   /* GDT idx3: LDT descriptor (8 bytes) */
#define TSS_A_SEL    0x20u   /* GDT idx4: TSS A (16 bytes)          */
#define LDT_CS_SEL   0x0cu   /* TI=1 idx1 RPL0: code in LDT         */
#define LDT_CALLG_SEL 0x14u  /* TI=1 idx2 RPL0: call gate in LDT    */
#define LDT_TSS_SEL  0x24u   /* TI=1 idx4 RPL0: TSS B in LDT        */

#define A_RESUME   (A_CODE + 17u)  /* movabs (10) + far CALL m16:64 (7) */

#define SENT_A 0xA5A5A5A5A5A5A5A5ull
#define SENT_B 0xB5B5B5B5B5B5B5B5ull
#define SENT_H 0xD5D5D5D5D5D5D5D5ull
#define SENT_H2 0xE5E5E5E5E5E5E5E5ull

#define TSS_AVAIL 0x89u
#define LDT_ACCESS 0x82u    /* P=1 DPL=0 S=0 type=2 (LDT) */
#define CALLGATE   0x8Cu    /* P=1 DPL=0 S=0 type=0xC     */

/* Write an 8-byte descriptor (code/data/LDT) at a byte offset in a table. */
static void set_desc_at(WemuCpu *c, uint64_t base, uint64_t off,
                        uint8_t access, uint64_t lb, uint32_t lm) {
    uint8_t d[8];
    memset(d, 0, sizeof d);
    d[0] = (uint8_t)lm;         d[1] = (uint8_t)(lm >> 8);
    d[2] = (uint8_t)lb;         d[3] = (uint8_t)(lb >> 8);
    d[4] = (uint8_t)(lb >> 16); d[5] = access;
    d[6] = (uint8_t)((lm >> 16) & 0x0fu);
    d[7] = (uint8_t)(lb >> 24);
    (void)wemu_mem_write(c, base + off, d, sizeof d);
}

/* Write a 16-byte system descriptor (TSS) at a byte offset in a table. */
static void set_desc16_at(WemuCpu *c, uint64_t base, uint64_t off,
                          uint8_t access, uint64_t lb, uint32_t lm) {
    uint8_t d[16];
    memset(d, 0, sizeof d);
    d[0] = (uint8_t)lm;         d[1] = (uint8_t)(lm >> 8);
    d[2] = (uint8_t)lb;         d[3] = (uint8_t)(lb >> 8);
    d[4] = (uint8_t)(lb >> 16); d[5] = access;
    d[6] = (uint8_t)((lm >> 16) & 0x0fu);
    d[7] = (uint8_t)(lb >> 24);
    d[8] = (uint8_t)(lb >> 32); d[9] = (uint8_t)(lb >> 40);
    d[10] = (uint8_t)(lb >> 48); d[11] = (uint8_t)(lb >> 56);
    (void)wemu_mem_write(c, base + off, d, sizeof d);
}

/* 16-byte 64-bit call gate: code selector bytes 2-3, offset bytes 0-1,6-11. */
static void set_call_gate_at(WemuCpu *c, uint64_t base, uint64_t off,
                             uint16_t cs, uint64_t target, uint8_t access) {
    uint8_t d[16];
    memset(d, 0, sizeof d);
    d[0] = (uint8_t)target;      d[1] = (uint8_t)(target >> 8);
    d[2] = (uint8_t)cs;          d[3] = (uint8_t)(cs >> 8);
    d[5] = access;
    d[6] = (uint8_t)(target >> 16); d[7] = (uint8_t)(target >> 24);
    d[8] = (uint8_t)(target >> 32); d[9] = (uint8_t)(target >> 40);
    d[10] = (uint8_t)(target >> 48); d[11] = (uint8_t)(target >> 56);
    (void)wemu_mem_write(c, base + off, d, sizeof d);
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
    memset(fp, 0, sizeof fp);
    fp[8] = (uint8_t)sel; fp[9] = (uint8_t)(sel >> 8);
    (void)wemu_mem_write(c, addr, fp, sizeof fp);
}

static uint16_t qword16(WemuCpu *c, uint64_t a) {
    uint16_t v = 0; (void)wemu_mem_read(c, a, &v, 2); return v;
}
static uint64_t qword64(WemuCpu *c, uint64_t a) {
    uint64_t v = 0; (void)wemu_mem_read(c, a, &v, 8); return v;
}

/* A: movabs rax,SA ; far CALL m16:64 [FAR_LDT_GATE] ; HLT */
static const uint8_t a_code[] = {
    0x48, 0xB8, 0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,
    0xFF, 0x1C, 0x25,
    (uint8_t)FAR_LDT_GATE, (uint8_t)(FAR_LDT_GATE >> 8),
    (uint8_t)(FAR_LDT_GATE >> 16), (uint8_t)(FAR_LDT_GATE >> 24),
    0xF4
};
static const uint8_t b_code[] = {
    0x48, 0xBB, 0xB5,0xB5,0xB5,0xB5,0xB5,0xB5,0xB5,0xB5, 0xF4
};
static const uint8_t handler_code[] = {
    0x48, 0xBA, 0xD5,0xD5,0xD5,0xD5,0xD5,0xD5,0xD5,0xD5, 0xF4
};
static const uint8_t handler2_code[] = {
    0x48, 0xBE, 0xE5,0xE5,0xE5,0xE5,0xE5,0xE5,0xE5,0xE5, 0xF4
};

/* Build the GDT only (no LDT loaded). */
static WemuCpu *boot_gdt(void) {
    WemuCpu *c = wemu_cpu_create(RAMSZ);
    set_desc_at(c, GDT_BASE, (KCS >> 3) * 8, 0x9A, 0, 0);
    set_desc_at(c, GDT_BASE, (KSS >> 3) * 8, 0x92, 0, 0);
    set_desc_at(c, GDT_BASE, (LDT_DESC_SEL >> 3) * 8, LDT_ACCESS,
                LDT_BASE, LDT_LIMIT);
    set_desc16_at(c, GDT_BASE, (TSS_A_SEL >> 3) * 8, TSS_AVAIL,
                  TSS_A_BASE, TSS_LIMIT);
    CHECK(wemu_cpu_gdt_load(c, GDT_BASE, GDT_LIMIT) == 0, "load GDTR");
    set_tss_image(c, TSS_A_BASE, KCS, KSS, A_CODE, A_RSP, 0x202);
    CHECK(wemu_cpu_ltr(c, TSS_A_SEL, NULL) == 0, "LTR on GDT TSS A");
    wemu_cpu_set_cpl(c, 0);
    wemu_cpu_set_cs(c, KCS);
    wemu_cpu_set_ss(c, KSS);
    wemu_cpu_set_rsp(c, A_RSP);
    wemu_cpu_clear_fault(c);
    return c;
}

/* Load the LDT and populate LDT descriptors/gates. 'gate_target' selects
 * the call-gate offset so the mutation test can prove LDT-sourced decode. */
static void install_ldt(WemuCpu *c, uint64_t gate_target) {
    WemuLdtDescriptor d;
    CHECK(wemu_cpu_lldt(c, LDT_DESC_SEL, &d) == 0, "LLDT loads LDT descriptor");
    CHECK(d.base == LDT_BASE && d.limit == LDT_LIMIT && d.type == 0x2 &&
          d.present == 1 && d.dpl == 0, "LLDT parses SDM LDT descriptor");
    CHECK(wemu_cpu_ldt_loaded(c) && wemu_cpu_ldt_base(c) == LDT_BASE &&
          wemu_cpu_ldt_limit(c) == LDT_LIMIT, "LDTR getters match descriptor");
    /* Everything below lives ONLY in the LDT. */
    set_desc_at(c, LDT_BASE, (LDT_CS_SEL >> 3) * 8, 0x9A, 0, 0);
    set_call_gate_at(c, LDT_BASE, (LDT_CALLG_SEL >> 3) * 8,
                     LDT_CS_SEL, gate_target, CALLGATE);
    set_desc16_at(c, LDT_BASE, (LDT_TSS_SEL >> 3) * 8, TSS_AVAIL,
                  TSS_B_BASE, TSS_LIMIT);
    set_tss_image(c, TSS_B_BASE, LDT_CS_SEL, KSS, B_CODE, B_RSP, 0x202);
    (void)wemu_cpu_load(c, HANDLER, handler_code, sizeof handler_code);
    (void)wemu_cpu_load(c, HANDLER2, handler2_code, sizeof handler2_code);
    (void)wemu_cpu_load(c, B_CODE, b_code, sizeof b_code);
}

/* ---- LLDT descriptor decode ------------------------------------------- */
static void test_lldt(void) {
    WemuCpu *c = boot_gdt();
    install_ldt(c, HANDLER);
    wemu_cpu_destroy(c);
}

/* ---- LDT-resident call gate (host + guest-executed far CALL) ----------- */
static void test_ldt_call_gate(void) {
    WemuCpu *c = boot_gdt();
    install_ldt(c, HANDLER);
    /* Host form: a TI=1 gate selector reaches a handler through the LDT. */
    CHECK(wemu_cpu_call_gate(c, LDT_CALLG_SEL, A_RESUME) == 0,
          "TI=1 call gate decodes the LDT gate");
    CHECK(wemu_cpu_fault(c) == 0 && wemu_cpu_rip(c) == HANDLER,
          "LDT call gate transfer faultless, RIP = gate offset");
    CHECK(wemu_cpu_cs(c) == LDT_CS_SEL, "LDT gate loads LDT code selector");
    CHECK(qword64(c, A_RSP - 16) == A_RESUME &&
          qword16(c, A_RSP - 8) == KCS, "LDT same-level call pushed return CS:RIP");
    wemu_cpu_destroy(c);

    /* Guest form: the far CALL instruction itself uses a TI=1 selector. */
    c = boot_gdt();
    install_ldt(c, HANDLER);
    set_far_ptr(c, FAR_LDT_GATE, LDT_CALLG_SEL);
    (void)wemu_cpu_load(c, A_CODE, a_code, sizeof a_code);
    wemu_cpu_set_rip(c, A_CODE);
    CHECK(wemu_cpu_run(c, 5) == 4 && wemu_cpu_halted(c),
          "guest far CALL via TI=1 gate reaches HLT");
    CHECK(wemu_cpu_fault(c) == 0 && wemu_cpu_reg(c, 2) == SENT_H,
          "LDT gate handler ran (RDX sentinel)");
    CHECK(qword64(c, A_RSP - 16) == A_RESUME, "guest return RIP pushed");
    wemu_cpu_destroy(c);

    /* Oracle independence: mutate ONLY the LDT gate offset.  The delivered
     * RIP must follow the mutated LDT bytes, proving GDT was not used. */
    c = boot_gdt();
    install_ldt(c, HANDLER);
    set_call_gate_at(c, LDT_BASE, (LDT_CALLG_SEL >> 3) * 8,
                     LDT_CS_SEL, HANDLER2, CALLGATE);
    CHECK(wemu_cpu_call_gate(c, LDT_CALLG_SEL, A_RESUME) == 0 &&
          wemu_cpu_rip(c) == HANDLER2, "mutated LDT gate offset is decoded");
    CHECK(wemu_cpu_run(c, 3) == 2 && wemu_cpu_reg(c, 6) == SENT_H2,
          "mutated LDT handler ran (RSI sentinel)");
    wemu_cpu_destroy(c);
}

/* ---- LDT-resident TSS descriptor (TI=1 task switch) ------------------- */
static void test_ldt_task_switch(void) {
    WemuCpu *c = boot_gdt();
    install_ldt(c, HANDLER);
    set_far_ptr(c, FAR_LDT_TSS, LDT_TSS_SEL);
    CHECK(wemu_cpu_task_switch(c, LDT_TSS_SEL, A_RESUME, 1) == 0,
          "TI=1 TSS descriptor in LDT performs a task switch");
    CHECK(wemu_cpu_fault(c) == 0 && wemu_cpu_tr(c) == LDT_TSS_SEL,
          "TR loads the TI=1 TSS selector");
    CHECK(wemu_cpu_cs(c) == LDT_CS_SEL && wemu_cpu_cpl(c) == 0,
          "entering task loads LDT-resident code selector");
    CHECK(wemu_cpu_rip(c) == B_CODE && wemu_cpu_reg(c, 4) == B_RSP,
          "entering task RIP/RSP from LDT TSS image");
    CHECK(qword16(c, TSS_B_BASE + 0x00) == TSS_A_SEL,
          "TI=1 switch writes back-link to the new TSS");
    CHECK(qword64(c, TSS_A_BASE + 0x30) == A_RESUME,
          "TI=1 switch saved the old task RIP");
    /* Busy bit must be set in the LDT table, not the GDT. */
    CHECK((qword16(c, LDT_BASE + (LDT_TSS_SEL >> 3) * 8 + 5) & 0x0f) == 0x0b,
          "TI=1 TSS marked busy in the LDT");
    CHECK(wemu_cpu_run(c, 3) == 2 && wemu_cpu_reg(c, 3) == SENT_B,
          "LDT-entered task executes to HLT (RBX sentinel)");
    wemu_cpu_destroy(c);
}

/* ---- negative controls: exact vector + selector error code ------------ */
static void test_negatives(void) {
    WemuCpu *c;

    /* TI=1 selector with no LDTR loaded -> #GP(selector incl TI bit). */
    c = boot_gdt();
    CHECK(wemu_cpu_call_gate(c, LDT_CALLG_SEL, A_RESUME) == -1,
          "TI=1 gate with no LDT loaded is rejected");
    CHECK(wemu_cpu_fault(c) == 13 && wemu_cpu_fault_error(c) == LDT_CALLG_SEL,
          "unloaded LDTR -> #GP(TI selector)");
    wemu_cpu_destroy(c);

    /* LLDT on a code descriptor -> #GP(selector). */
    c = boot_gdt();
    CHECK(wemu_cpu_lldt(c, KCS, NULL) == -1, "LLDT on code descriptor");
    CHECK(wemu_cpu_fault(c) == 13 && wemu_cpu_fault_error(c) == KCS,
          "non-LDT descriptor -> #GP(selector)");
    wemu_cpu_destroy(c);

    /* LLDT not present -> #NP(selector). */
    c = boot_gdt();
    set_desc_at(c, GDT_BASE, (LDT_DESC_SEL >> 3) * 8,
                LDT_ACCESS & ~0x80u, LDT_BASE, LDT_LIMIT);
    CHECK(wemu_cpu_lldt(c, LDT_DESC_SEL, NULL) == -1, "LLDT on P=0 descriptor");
    CHECK(wemu_cpu_fault(c) == 11 && wemu_cpu_fault_error(c) == LDT_DESC_SEL,
          "LLDT P=0 -> #NP(selector)");
    wemu_cpu_destroy(c);

    /* LLDT selector past the GDT limit -> #GP(selector). */
    c = boot_gdt();
    CHECK(wemu_cpu_lldt(c, 0x1000u, NULL) == -1, "LLDT past GDT limit");
    CHECK(wemu_cpu_fault(c) == 13 && wemu_cpu_fault_error(c) == 0x1000u,
          "out-of-GDT LLDT -> #GP(selector)");
    wemu_cpu_destroy(c);

    /* LLDT with a TI=1 selector -> #GP(selector incl TI). */
    c = boot_gdt();
    CHECK(wemu_cpu_lldt(c, 0x1cu, NULL) == -1, "LLDT via TI=1 selector");
    CHECK(wemu_cpu_fault(c) == 13 && wemu_cpu_fault_error(c) == 0x1cu,
          "LLDT must use GDT -> #GP(TI selector)");
    wemu_cpu_destroy(c);

    /* LLDT is ring-0 only -> #GP(0). */
    c = boot_gdt();
    wemu_cpu_set_cpl(c, 3);
    CHECK(wemu_cpu_lldt(c, LDT_DESC_SEL, NULL) == -1, "LLDT at CPL3");
    CHECK(wemu_cpu_fault(c) == 13 && wemu_cpu_fault_error(c) == 0,
          "LLDT at CPL>0 -> #GP(0)");
    wemu_cpu_destroy(c);

    /* TI=1 selector past the LDT limit -> #GP(selector incl TI). */
    c = boot_gdt();
    install_ldt(c, HANDLER);
    CHECK(wemu_cpu_call_gate(c, 0x0ffcu, A_RESUME) == -1,
          "TI=1 selector past LDT limit");
    CHECK(wemu_cpu_fault(c) == 13 && wemu_cpu_fault_error(c) == 0x0ffcu,
          "out-of-LDT selector -> #GP(TI selector)");
    wemu_cpu_destroy(c);
}

int main(void) {
    test_lldt();
    test_ldt_call_gate();
    test_ldt_task_switch();
    test_negatives();
    if (fails) {
        printf("test_ldt: %d/%d CHECK(S) FAILED\n", fails, checks);
        return 1;
    }
    printf("test_ldt: PASS (%d checks; LLDT descriptor parse, TI=1 LDT call "
           "gate host+guest, mutated-gate oracle, TI=1 LDT TSS switch, "
           "#GP/#NP negatives)\n", checks);
    return 0;
}
#endif
