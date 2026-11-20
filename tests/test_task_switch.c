/* test_task_switch.c — differential gate for bounded hardware task switching.
 *
 * A REAL guest program performs task A -> B -> A:
 *   A (ring 0) loads RAX with a sentinel, executes far CALL m16:64 through
 *     a 64-bit TSS descriptor selector (0xFF /3, absolute SIB memory ref);
 *   WEMU saves A's CS/SS/RIP/RSP/RFLAGS into A's TSS image, writes A's TR
 *     selector into B's TSS back-link, and loads B's CS/SS/RIP/RSP from
 *     B's TSS image;
 *   B loads RBX with a second sentinel and executes IRET, which (NT set)
 *     follows the back-link and restores A's saved state;
 *   A resumes at the instruction after the far CALL and HLTs.
 *
 * Expectations (saved state, back-link, descriptor busy bits, result state)
 * come from the SDM / 64-bit TSS layout, not from the implementation.
 * Negative controls check the exact #GP/#NP/#TS/#UD vector and selector
 * error code for rejected descriptors and a bad far-pointer operand.
 *
 * NEGATIVE CONTROL: this SAME source compiled against the pre-change
 * library (0dece40, no WEMU_HAS_TASK_SWITCH) prints FAIL and exits 1 —
 * 0xFF /3 is #UD there, so the guest never reaches task B.
 */
#include "wemu.h"
#include <stdio.h>
#include <string.h>

#ifndef WEMU_HAS_TASK_SWITCH
int main(void) {
    printf("FAIL: WEMU_HAS_TASK_SWITCH absent — pre-change WEMU #UDs on far "
           "JMP/CALL (0xFF /3,/5), has no TSS back-link and no IRET task "
           "return; the guest A->B->A switch cannot execute\n");
    return 1;
}
#else

static int fails, checks;
#define CHECK(c, m) do { checks++; if (!(c)) { \
    printf("FAIL: %s (line %d)\n", m, __LINE__); fails++; } } while (0)

#define RAMSZ       (1u << 20)
#define A_CODE      0x1000u
#define B_CODE      0x2000u
#define GDT_BASE    0x3000u
#define TSS_A_BASE  0x4000u
#define TSS_B_BASE  0x5000u
#define FAR_B       0x6000u
#define GDT_LIMIT   0x0fffu
#define TSS_LIMIT   0x67u        /* full 103-byte 64-bit TSS */
#define A_RSP       0x80000u
#define B_RSP       0x90000u

#define KCS         0x08u        /* idx1: present code DPL0 */
#define KSS         0x10u        /* idx2: present RW data DPL0 */
#define TSS_A_SEL   0x18u        /* idx3+4: available 64-bit TSS A */
#define TSS_B_SEL   0x28u        /* idx5+6: available 64-bit TSS B */

#define SENT_A      0xA5A5A5A5A5A5A5A5ull
#define SENT_B      0xB5B5B5B5B5B5B5B5ull
/* A: movabs rax,SENT_A (10B); far CALL [FAR_B] (7B); HLT (1B) */
#define A_RESUME    (A_CODE + 10u + 7u)

#define TSS_AVAIL   0x89u
#define TSS_BUSY    0x8Bu

static void set_desc(WemuCpu *c, uint16_t sel, uint8_t access) {
    uint8_t d[8];
    memset(d, 0, sizeof d);
    d[5] = access;
    (void)wemu_mem_write(c, GDT_BASE + (uint64_t)(sel >> 3) * 8, d, 8);
}

/* 16-byte 64-bit TSS descriptor (two GDT slots). */
static void set_tss_desc(WemuCpu *c, uint16_t sel, uint8_t access,
                         uint64_t base, uint32_t limit, uint32_t reserved) {
    uint8_t d[16];
    memset(d, 0, sizeof d);
    d[0]  = (uint8_t)limit;         d[1] = (uint8_t)(limit >> 8);
    d[2]  = (uint8_t)base;          d[3] = (uint8_t)(base >> 8);
    d[4]  = (uint8_t)(base >> 16);  d[5] = access;
    d[6]  = (uint8_t)((limit >> 16) & 0x0fu);
    d[7]  = (uint8_t)(base >> 24);
    d[8]  = (uint8_t)(base >> 32);  d[9] = (uint8_t)(base >> 40);
    d[10] = (uint8_t)(base >> 48);  d[11] = (uint8_t)(base >> 56);
    d[12] = (uint8_t)reserved;      d[13] = (uint8_t)(reserved >> 8);
    d[14] = (uint8_t)(reserved >> 16); d[15] = (uint8_t)(reserved >> 24);
    (void)wemu_mem_write(c, GDT_BASE + (uint64_t)(sel >> 3) * 8, d, sizeof d);
}

/* TSS image.  WEMU task-switch state lives at +0x28/0x2a (CS/SS u16) and
 * +0x30/0x38/0x40 (RIP/RSP/RFLAGS u64), within the 103-byte TSS. */
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

static uint16_t qword16(WemuCpu *c, uint64_t addr) {
    uint16_t v = 0;
    (void)wemu_mem_read(c, addr, &v, 2);
    return v;
}
static uint64_t qword64(WemuCpu *c, uint64_t addr) {
    uint64_t v = 0;
    (void)wemu_mem_read(c, addr, &v, 8);
    return v;
}

static const uint8_t a_code[] = {
    0x48, 0xB8, 0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5, /* movabs rax,SENT_A */
    0xFF, 0x1C, 0x25,                                     /* far CALL m16:64 */
    (uint8_t)FAR_B, (uint8_t)(FAR_B >> 8),
    (uint8_t)(FAR_B >> 16), (uint8_t)(FAR_B >> 24),
    0xF4                                                  /* HLT */
};
static const uint8_t b_code[] = {
    0x48, 0xBB, 0xB5,0xB5,0xB5,0xB5,0xB5,0xB5,0xB5,0xB5, /* movabs rbx,SENT_B */
    0xCF                                                  /* IRET -> back-link */
};

static WemuCpu *boot(void) {
    WemuCpu *c = wemu_cpu_create(RAMSZ);
    uint8_t fp[10];
    wemu_cpu_set_rip(c, A_CODE);
    set_desc(c, KCS, 0x9A);                       /* present code DPL0 */
    set_desc(c, KSS, 0x92);                       /* present RW data DPL0 */
    set_tss_desc(c, TSS_A_SEL, TSS_AVAIL, TSS_A_BASE, TSS_LIMIT, 0);
    set_tss_desc(c, TSS_B_SEL, TSS_AVAIL, TSS_B_BASE, TSS_LIMIT, 0);
    CHECK(wemu_cpu_gdt_load(c, GDT_BASE, GDT_LIMIT) == 0, "load GDTR");
    set_tss_image(c, TSS_A_BASE, 0, 0, 0, 0, 0);  /* A's state saved on switch */
    set_tss_image(c, TSS_B_BASE, KCS, KSS, B_CODE, B_RSP, 0x202);
    memset(fp, 0, sizeof fp);                     /* offset ignored for TSS */
    fp[8] = (uint8_t)TSS_B_SEL; fp[9] = (uint8_t)(TSS_B_SEL >> 8);
    (void)wemu_mem_write(c, FAR_B, fp, sizeof fp);
    (void)wemu_cpu_load(c, A_CODE, a_code, sizeof a_code);
    (void)wemu_cpu_load(c, B_CODE, b_code, sizeof b_code);
    CHECK(wemu_cpu_ltr(c, TSS_A_SEL, NULL) == 0, "LTR loads task A");
    wemu_cpu_set_cpl(c, 0);
    wemu_cpu_set_cs(c, KCS);
    wemu_cpu_set_ss(c, KSS);
    wemu_cpu_set_rsp(c, A_RSP);
    wemu_cpu_clear_fault(c);
    return c;
}

/* ---- positive: A -> B -> A through TSS back-link --------------------- */
static void test_round_trip(void) {
    WemuCpu *c = boot();
    int64_t n = wemu_cpu_run(c, 12);

    CHECK(n == 5, "exactly 5 guest instructions (mov,CALL,mov,IRET,HLT)");
    CHECK(wemu_cpu_halted(c), "guest reached HLT after task return");
    CHECK(wemu_cpu_fault(c) == 0, "round trip without fault");
    CHECK(wemu_cpu_reg(c, 0) == SENT_A, "task A's RAX state preserved");
    CHECK(wemu_cpu_reg(c, 3) == SENT_B, "task B actually executed (RBX)");
    CHECK(wemu_cpu_rip(c) == A_RESUME + 1, "A resumed after the far CALL");
    CHECK(wemu_cpu_cs(c) == KCS && wemu_cpu_ss(c) == KSS,
          "CS/SS restored to task A");
    CHECK(wemu_cpu_cpl(c) == 0, "CPL restored to task A");
    CHECK(wemu_cpu_reg(c, 4) == A_RSP, "RSP restored to task A");
    CHECK(wemu_cpu_tr(c) == TSS_A_SEL, "TR points back at task A");
    CHECK(wemu_cpu_task_switches(c) == 2, "one switch + one back-link return");
    CHECK(!wemu_cpu_task_nested(c), "NT cleared on return");

    /* TSS evidence: B's back-link names A, A's TSS holds A's saved RIP. */
    CHECK(qword16(c, TSS_B_BASE + 0x00) == TSS_A_SEL,
          "B's back-link = A's TSS selector");
    CHECK(qword64(c, TSS_A_BASE + 0x30) == A_RESUME,
          "A's saved RIP = instruction after far CALL");
    CHECK(qword64(c, TSS_A_BASE + 0x38) == A_RSP, "A's saved RSP");
    CHECK((qword16(c, GDT_BASE + (TSS_B_SEL >> 3) * 8 + 5) & 0x0f) == 0x09,
          "B's TSS descriptor made available again after return");
    CHECK((qword16(c, GDT_BASE + (TSS_A_SEL >> 3) * 8 + 5) & 0x0f) == 0x0b,
          "A's TSS descriptor still busy");

    printf("task_switch: A->B->A rax=0x%llx rbx=0x%llx rip=0x%llx "
           "backlink=0x%x switches=%u\n",
           (unsigned long long)wemu_cpu_reg(c, 0),
           (unsigned long long)wemu_cpu_reg(c, 3),
           (unsigned long long)wemu_cpu_rip(c),
           (unsigned)qword16(c, TSS_B_BASE), wemu_cpu_task_switches(c));
    wemu_cpu_destroy(c);
}

/* ---- negative controls: exact fault vector + selector error ---------- */
static void expect_switch_fault(uint16_t sel, int vec, uint64_t err,
                                const char *name) {
    WemuCpu *c = boot();
    CHECK(wemu_cpu_task_switch(c, sel, A_RESUME, 1) == -1, name);
    CHECK(wemu_cpu_fault(c) == vec, "rejected task switch: fault vector");
    CHECK(wemu_cpu_fault_error(c) == err, "rejected task switch: error code");
    CHECK(wemu_cpu_tr(c) == TSS_A_SEL && wemu_cpu_task_switches(c) == 0,
          "rejected task switch: no state change");
    printf("  %-26s -> vec=%u err=0x%llx\n", name,
           (unsigned)wemu_cpu_fault(c),
           (unsigned long long)wemu_cpu_fault_error(c));
    wemu_cpu_destroy(c);
}

static void test_bad_switches(void) {
    WemuCpu *c;

    expect_switch_fault(0x0000, 13, 0x0000, "null TSS selector");
    expect_switch_fault(0x002C, 13, 0x002C, "LDT selector");
    expect_switch_fault(KCS,    13, KCS,    "code descriptor, not TSS");

    c = boot(); /* busy TSS (A itself is busy after LTR) */
    CHECK(wemu_cpu_task_switch(c, TSS_A_SEL, A_RESUME, 1) == -1, "busy TSS");
    CHECK(wemu_cpu_fault(c) == 13 && wemu_cpu_fault_error(c) == TSS_A_SEL,
          "busy TSS -> #GP(selector)");
    wemu_cpu_destroy(c);

    c = boot();
    set_tss_desc(c, TSS_B_SEL, 0x09, TSS_B_BASE, TSS_LIMIT, 0); /* P=0 */
    CHECK(wemu_cpu_task_switch(c, TSS_B_SEL, A_RESUME, 1) == -1,
          "not-present TSS");
    CHECK(wemu_cpu_fault(c) == 11 && wemu_cpu_fault_error(c) == TSS_B_SEL,
          "not-present TSS -> #NP(selector)");
    wemu_cpu_destroy(c);

    c = boot();
    set_tss_desc(c, TSS_B_SEL, TSS_AVAIL, TSS_B_BASE, 0x10, 0);
    CHECK(wemu_cpu_task_switch(c, TSS_B_SEL, A_RESUME, 1) == -1,
          "TSS limit too small");
    CHECK(wemu_cpu_fault(c) == 10 && wemu_cpu_fault_error(c) == TSS_B_SEL,
          "short TSS -> #TS(selector)");
    wemu_cpu_destroy(c);

    c = boot();
    set_tss_desc(c, TSS_B_SEL, TSS_AVAIL, TSS_B_BASE, TSS_LIMIT, 1);
    CHECK(wemu_cpu_task_switch(c, TSS_B_SEL, A_RESUME, 1) == -1,
          "upper reserved != 0");
    CHECK(wemu_cpu_fault(c) == 13 && wemu_cpu_fault_error(c) == TSS_B_SEL,
          "reserved dwords -> #GP(selector)");
    wemu_cpu_destroy(c);

    c = boot();
    wemu_cpu_set_cpl(c, 3); /* DPL0 TSS not callable from ring 3 */
    CHECK(wemu_cpu_task_switch(c, TSS_B_SEL, A_RESUME, 1) == -1,
          "CPL > TSS DPL");
    CHECK(wemu_cpu_fault(c) == 13 && wemu_cpu_fault_error(c) == TSS_B_SEL,
          "CPL > DPL -> #GP(selector)");
    wemu_cpu_destroy(c);

    c = boot();
    set_tss_image(c, TSS_B_BASE, 0, KSS, B_CODE, B_RSP, 0x202); /* null CS */
    CHECK(wemu_cpu_task_switch(c, TSS_B_SEL, A_RESUME, 1) == -1,
          "null CS in TSS image");
    CHECK(wemu_cpu_fault(c) == 10 && wemu_cpu_fault_error(c) == TSS_B_SEL,
          "bad target CS -> #TS(selector)");
    wemu_cpu_destroy(c);

    /* Guest-executed negative: far CALL with a register operand is #UD. */
    c = boot();
    {
        const uint8_t bad[] = { 0x48, 0xB8, 1,0,0,0,0,0,0,0,
                                0xFF, 0xDB, 0xF4 }; /* FF /3, mod=11 rm=3 */
        (void)wemu_cpu_load(c, A_CODE, bad, sizeof bad);
        CHECK(wemu_cpu_step(c) == 1 && wemu_cpu_step(c) == -1,
              "guest far CALL r/m with register operand #UDs");
        CHECK(wemu_cpu_fault(c) == 6, "#UD for far pointer in register");
        CHECK(wemu_cpu_rip(c) == A_CODE + 10, "no state change on #UD");
    }
    wemu_cpu_destroy(c);

    /* Guest-executed negative: busy target descriptor faults with #GP. */
    c = boot();
    set_tss_desc(c, TSS_B_SEL, TSS_BUSY, TSS_B_BASE, TSS_LIMIT, 0);
    CHECK(wemu_cpu_step(c) == 1 && wemu_cpu_step(c) == -1,
          "guest far CALL to busy TSS faults");
    CHECK(wemu_cpu_fault(c) == 13 && wemu_cpu_fault_error(c) == TSS_B_SEL,
          "guest busy TSS -> #GP(selector)");
    CHECK(wemu_cpu_rip(c) == A_CODE + 10, "guest stayed at the far CALL");
    wemu_cpu_destroy(c);
}

int main(void) {
    test_round_trip();
    test_bad_switches();
    if (fails) {
        printf("test_task_switch: %d/%d CHECK(S) FAILED\n", fails, checks);
        return 1;
    }
    printf("test_task_switch: PASS (%d checks; A->B->A TSS back-link + "
           "IRET task return + #GP/#NP/#TS/#UD negatives)\n", checks);
    return 0;
}
#endif
