/* test_iret.c — differential gate for IRET (0xCF), architectural
 * same-level interrupt frames, and exception-path CPL switching.
 *
 * Three independent SDM-derived expectations are checked against REAL
 * guest execution through wemu_cpu_step (no host-side shortcut):
 *
 *   A. ring-3 INT n followed by IRET in the ring-0 handler must land back
 *      on ring 3 with the ORIGINAL RIP/RSP/CS/SS/RFLAGS.  The privilege
 *      frame is 5 qwords: RIP, interrupted CS (RPL=old CPL), RFLAGS,
 *      old RSP, old SS — TSS RSP0 only supplies the NEW stack base.
 *   B. a same-level INT n pushes the architectural 3-qword frame
 *      (RIP, CS, RFLAGS), NOT the legacy 5-qword one; IRET consumes it
 *      and restores the pre-INT RSP exactly.
 *   C. a HOST-raised exception whose gate code descriptor targets a
 *      different DPL takes the same CPL-switch path as INT n: CPL, CS,
 *      SS and the stack switch all change, and the frame holds the old
 *      (not the gate) CS.
 *
 * NEGATIVE CONTROL: compiled against the pre-change library (e23e1ff,
 * no WEMU_HAS_IRET) this prints FAIL and exits 1: old WEMU #UDs on 0xCF,
 * pushes a 5-qword same-level frame, and never switches CPL on an
 * exception.  Executed against that library to confirm. */
#include "wemu.h"
#include <stdio.h>
#include <string.h>

#ifndef WEMU_HAS_IRET
int main(void) {
    printf("FAIL: WEMU_HAS_IRET absent — old WEMU #UDs on guest IRET (0xCF), "
           "uses a 5-qword same-level frame, and never switches CPL on an "
           "exception\n");
    return 1;
}
#else

static int fails, checks;
#define CHECK(c, m) do { checks++; if (!(c)) { \
    printf("FAIL: %s (line %d)\n", m, __LINE__); fails++; } } while (0)

#define RAMSZ     (1u << 20)
#define CODE      0x1000u
#define IDT_BASE  0x2000u
#define IDT_LIMIT 0x0fffu
#define GDT_BASE  0x3000u
#define GDT_LIMIT 0x0fffu
#define HANDLER   0x6000u
#define U_RSP     0x80000u
#define R0_RSP0   0x70000u
#define VEC       0x2Au      /* INT 42: no error code */

/* GDT selectors: KCS idx1 ring-0 code 0x9A, KSS idx2 ring-0 data 0x92,
 * UCS idx3 ring-3 code 0xFA, USS idx4 ring-3 data 0xF2. */
#define KCS  0x08u
#define KSS  0x10u
#define UCS  0x1Bu
#define USS  0x23u

static void set_gate(WemuCpu *c, unsigned v, uint64_t off, uint8_t type,
                     uint8_t dpl, uint16_t sel, int present) {
    uint8_t g[16];
    memset(g, 0, sizeof g);
    g[0] = (uint8_t)off;         g[1] = (uint8_t)(off >> 8);
    g[2] = (uint8_t)sel;         g[3] = (uint8_t)(sel >> 8);
    g[4] = 0;                    /* no IST */
    g[5] = (uint8_t)((present ? 0x80 : 0) | (dpl << 5) | (type & 0xf));
    g[6] = (uint8_t)(off >> 16); g[7] = (uint8_t)(off >> 24);
    g[8] = (uint8_t)(off >> 32); g[9] = (uint8_t)(off >> 40);
    g[10] = (uint8_t)(off >> 48); g[11] = (uint8_t)(off >> 56);
    (void)wemu_mem_write(c, IDT_BASE + (uint64_t)v * 16, g, sizeof g);
}

static void set_desc(WemuCpu *c, uint16_t sel, uint8_t access) {
    uint8_t d[8];
    memset(d, 0, sizeof d);
    d[5] = access;
    (void)wemu_mem_write(c, GDT_BASE + (uint64_t)(sel >> 3) * 8, d, 8);
}

static uint64_t frame_qword(WemuCpu *c, uint64_t sp, int idx) {
    uint64_t v = 0;
    (void)wemu_mem_read(c, sp + (uint64_t)idx * 8, &v, 8);
    return v;
}

static WemuCpu *boot(void) {
    WemuCpu *c = wemu_cpu_create(RAMSZ);
    wemu_cpu_set_rip(c, CODE);
    set_gate(c, VEC, HANDLER, 0xE, 3, KCS, 1);  /* DPL3: ring 3 may INT */
    set_gate(c, 6, HANDLER, 0xE, 0, KCS, 1);    /* #UD: ring-0 target */
    CHECK(wemu_cpu_idt_load(c, IDT_BASE, IDT_LIMIT) == 0, "load IDTR");
    set_desc(c, KCS, 0x9A);
    set_desc(c, KSS, 0x92);
    set_desc(c, UCS, 0xFA);
    set_desc(c, USS, 0xF2);
    CHECK(wemu_cpu_gdt_load(c, GDT_BASE, GDT_LIMIT) == 0, "load GDTR");
    return c;
}

/* ---- A. ring-3 INT n, IRET in the handler, exact ring-3 restoration -- */
static void test_priv_round_trip(void) {
    WemuCpu *c = boot();
    const uint8_t code[] = { 0xFB, 0xCD, VEC, 0xF4 }; /* STI; INT 42; HLT */
    const uint8_t iret[] = { 0xCF };                  /* handler: IRET */
    CHECK(wemu_cpu_load(c, CODE, code, sizeof code) == 0, "load guest");
    CHECK(wemu_cpu_load(c, HANDLER, iret, sizeof iret) == 0, "load IRET");
    wemu_cpu_set_rsp(c, U_RSP);
    wemu_cpu_set_cpl(c, 3);
    wemu_cpu_set_cs(c, UCS);
    wemu_cpu_set_ss(c, USS);
    wemu_cpu_tss_set_ss(c, 0, KSS);
    wemu_cpu_tss_set_rsp(c, 0, R0_RSP0);

    CHECK(wemu_cpu_step(c) == 1, "STI executed");
    uint64_t fl_before = wemu_cpu_rflags(c);
    CHECK((fl_before & 0x200u) != 0, "IF set before INT");

    CHECK(wemu_cpu_step(c) == 1, "guest INT n delivered");
    CHECK(wemu_cpu_fault(c) == 0, "INT delivered without fault");
    CHECK(wemu_cpu_rip(c) == HANDLER, "INT reaches handler");
    CHECK(wemu_cpu_cpl(c) == 0 && wemu_cpu_cs(c) == KCS &&
          wemu_cpu_ss(c) == KSS, "ring 3 -> 0: CPL/CS/SS reloaded");
    CHECK((wemu_cpu_rflags(c) & 0x200u) == 0, "interrupt gate cleared IF");

    uint64_t sp = wemu_cpu_reg(c, 4);
    CHECK(sp == R0_RSP0 - 5 * 8, "privilege frame is 5 qwords on RSP0");
    CHECK(frame_qword(c, sp, 0) == CODE + 3, "frame RIP = after INT");
    CHECK(frame_qword(c, sp, 1) == UCS, "frame CS = interrupted ring-3 CS");
    CHECK(frame_qword(c, sp, 2) == fl_before, "frame RFLAGS retains IF");
    CHECK(frame_qword(c, sp, 3) == U_RSP, "frame old RSP = ring-3 RSP");
    CHECK(frame_qword(c, sp, 4) == USS, "frame old SS = ring-3 SS");

    CHECK(wemu_cpu_step(c) == 1, "guest IRET executed");
    CHECK(wemu_cpu_fault(c) == 0, "IRET raised no fault");
    CHECK(wemu_cpu_rip(c) == CODE + 3, "IRET restored saved RIP");
    CHECK(wemu_cpu_cpl(c) == 3, "IRET restored CPL 3");
    CHECK(wemu_cpu_cs(c) == UCS && wemu_cpu_cs_rpl(c) == 3,
          "IRET restored ring-3 CS/RPL");
    CHECK(wemu_cpu_ss(c) == USS, "IRET restored ring-3 SS");
    CHECK(wemu_cpu_reg(c, 4) == U_RSP, "IRET restored ring-3 RSP");
    CHECK(wemu_cpu_rflags(c) == (fl_before | 2u),
          "IRET restored pre-INT RFLAGS (IF included)");
    printf("priv_round_trip: rip=0x%llx cpl=%d cs=0x%x ss=0x%x "
           "rsp=0x%llx fl=0x%llx\n",
           (unsigned long long)wemu_cpu_rip(c), wemu_cpu_cpl(c),
           (unsigned)wemu_cpu_cs(c), (unsigned)wemu_cpu_ss(c),
           (unsigned long long)wemu_cpu_reg(c, 4),
           (unsigned long long)wemu_cpu_rflags(c));
    wemu_cpu_destroy(c);
}

/* ---- B. same-level INT: architectural 3-qword frame + IRET ----------- */
static void test_same_level_frame(void) {
    WemuCpu *c = boot();
    const uint8_t code[] = { 0xCD, VEC, 0xF4 };       /* INT 42; HLT */
    const uint8_t iret[] = { 0xCF };
    CHECK(wemu_cpu_load(c, CODE, code, sizeof code) == 0, "load guest");
    CHECK(wemu_cpu_load(c, HANDLER, iret, sizeof iret) == 0, "load IRET");
    set_gate(c, VEC, HANDLER, 0xE, 0, KCS, 1);        /* DPL 0 for CPL 0 */
    wemu_cpu_set_rsp(c, U_RSP);
    wemu_cpu_set_cpl(c, 0);
    wemu_cpu_set_cs(c, KCS);
    wemu_cpu_set_ss(c, KSS);

    CHECK(wemu_cpu_step(c) == 1, "same-level INT delivered");
    CHECK(wemu_cpu_fault(c) == 0 && wemu_cpu_rip(c) == HANDLER,
          "same-level INT reaches handler");
    uint64_t sp = wemu_cpu_reg(c, 4);
    CHECK(sp == U_RSP - 3 * 8, "same-level frame is architectural 3 qwords");
    CHECK(frame_qword(c, sp, 0) == CODE + 2, "3q frame slot0 = saved RIP");
    CHECK(frame_qword(c, sp, 1) == KCS, "3q frame slot1 = current CS");
    CHECK(frame_qword(c, sp, 2) == 2, "3q frame slot2 = RFLAGS");
    CHECK(wemu_cpu_cpl(c) == 0, "same-level INT keeps CPL 0");

    CHECK(wemu_cpu_step(c) == 1, "same-level IRET executed");
    CHECK(wemu_cpu_rip(c) == CODE + 2, "same-level IRET restored RIP");
    CHECK(wemu_cpu_reg(c, 4) == U_RSP, "same-level IRET restored RSP");
    CHECK(wemu_cpu_cpl(c) == 0 && wemu_cpu_cs(c) == KCS &&
          wemu_cpu_ss(c) == KSS, "same-level IRET keeps CS/SS/CPL");
    printf("same_level_frame: sp=0x%llx (3 qwords) rip=0x%llx rsp=0x%llx\n",
           (unsigned long long)sp, (unsigned long long)wemu_cpu_rip(c),
           (unsigned long long)wemu_cpu_reg(c, 4));
    wemu_cpu_destroy(c);
}

/* ---- C. host-raised exception whose gate targets ring 0 switches CPL - */
static void test_fault_raised_cpl_switch(void) {
    WemuCpu *c = boot();
    const uint8_t iret[] = { 0xCF };
    CHECK(wemu_cpu_load(c, HANDLER, iret, sizeof iret) == 0, "load IRET");
    wemu_cpu_set_rip(c, CODE);
    wemu_cpu_set_rsp(c, U_RSP);
    wemu_cpu_set_cpl(c, 3);
    wemu_cpu_set_cs(c, UCS);
    wemu_cpu_set_ss(c, USS);
    wemu_cpu_tss_set_ss(c, 0, KSS);
    wemu_cpu_tss_set_rsp(c, 0, R0_RSP0);

    /* Host raises #UD (no error code); delivery happens at the step
     * boundary. Its gate selects KCS (DPL 0) -> target CPL 0 != CPL 3. */
    wemu_cpu_raise_exception(c, 6, 0, 0);
    CHECK(wemu_cpu_step(c) == 1, "host-raised exception delivered");
    CHECK(wemu_cpu_fault(c) == 0, "fault cleared on delivery");
    CHECK(wemu_cpu_exception_vector(c) == 6, "delivered vector == #UD");
    CHECK(wemu_cpu_rip(c) == HANDLER, "exception reaches ring-0 gate");
    CHECK(wemu_cpu_cpl(c) == 0, "exception switched CPL 3 -> 0");
    CHECK(wemu_cpu_cs(c) == KCS && wemu_cpu_ss(c) == KSS,
          "exception reloaded CS/SS from gate/TSS");

    uint64_t sp = wemu_cpu_reg(c, 4);
    CHECK(sp == R0_RSP0 - 5 * 8, "exception switch frame = 5 qwords");
    CHECK(frame_qword(c, sp, 0) == CODE, "exception frame RIP = old RIP");
    CHECK(frame_qword(c, sp, 1) == UCS,
          "exception frame CS = interrupted CS, not gate CS");
    CHECK(frame_qword(c, sp, 3) == U_RSP, "exception frame old RSP");
    CHECK(frame_qword(c, sp, 4) == USS, "exception frame old SS");

    CHECK(wemu_cpu_step(c) == 1, "IRET after exception delivered");
    CHECK(wemu_cpu_cpl(c) == 3 && wemu_cpu_rip(c) == CODE &&
          wemu_cpu_reg(c, 4) == U_RSP && wemu_cpu_cs(c) == UCS &&
          wemu_cpu_ss(c) == USS, "IRET undoes exception CPL switch");
    printf("fault_cpl_switch: vec=%u cpl 3->0->%d rip=0x%llx rsp=0x%llx\n",
           wemu_cpu_exception_vector(c), wemu_cpu_cpl(c),
           (unsigned long long)wemu_cpu_rip(c),
           (unsigned long long)wemu_cpu_reg(c, 4));
    wemu_cpu_destroy(c);
}

int main(void) {
    test_priv_round_trip();
    test_same_level_frame();
    test_fault_raised_cpl_switch();
    if (fails) {
        printf("test_iret: %d/%d CHECK(S) FAILED\n", fails, checks);
        return 1;
    }
    printf("test_iret: PASS (%d checks; IRET + 3q same-level + exc CPL)\n",
           checks);
    return 0;
}
#endif
