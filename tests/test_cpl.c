/* test_cpl.c — differential gate for GUEST-executed INT n (0xCD imm8) and
 * the real privilege transition it triggers.
 *
 * The guest program executes the instruction (STI; INT 42; HLT or INT 42;
 * HLT) through wemu_cpu_step — nothing is delivered by a host API call.
 * Every expected bit is computed independently from the SDM:
 *   target CPL   = DPL of the gate's non-conforming code descriptor
 *   new RSP      = TSS RSP[target] (RSP0 for CPL 0), IST overrides
 *   frame (switch) = old SS, old RSP, RFLAGS, gate CS, saved RIP
 *   saved RIP    = address AFTER the INT n instruction
 *   gate DPL     = max(CPL, CS.RPL) check; violations latch #GP(IDT code)
 *   IDT code     = (vector << 3) | 2
 *
 * NEGATIVE CONTROL: this same source compiled against the pre-change
 * library (78a8059, no WEMU_HAS_INT_CPL_SWITCH) prints FAIL and exits 1:
 * old WEMU decodes 0xCD but has no exec handler (#UD), and knows nothing
 * about TSS RSP0, CS/SS reload or the modelled CPL change. */
#include "wemu.h"
#include <stdio.h>
#include <string.h>

#ifndef WEMU_HAS_INT_CPL_SWITCH
int main(void) {
    printf("FAIL: WEMU_HAS_INT_CPL_SWITCH absent — old WEMU #UDs on guest "
           "INT n and models no CPL change / TSS RSP0 / CS:SS reload\n");
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
#define GP_HANDLER 0x6100u
#define U_RSP     0x80000u
#define R0_RSP0   0x70000u
#define VEC       0x2Au        /* INT 42: no error code */

/* GDT selectors (index = selector >> 3). */
#define KCS  0x08u             /* idx1: ring-0 code,  DPL 0, 0x9A */
#define KSS  0x10u             /* idx2: ring-0 RW data, DPL 0, 0x92 */
#define UCS  0x1Bu             /* idx3: ring-3 code,  DPL 3, 0xFA */
#define USS  0x23u             /* idx4: ring-3 RW data, DPL 3, 0xF2 */
#define IDT_CODE(v) ((uint64_t)(v) << 3 | 2ull)

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
    d[5] = access;               /* P|DPL|S|type in the access byte */
    (void)wemu_mem_write(c, GDT_BASE + (uint64_t)(sel >> 3) * 8, d, 8);
}

static uint64_t frame_qword(WemuCpu *c, uint64_t sp, int idx) {
    uint64_t v = 0;
    (void)wemu_mem_read(c, sp + (uint64_t)idx * 8, &v, 8);
    return v;
}

/* IDT + GDT in guest RAM, as a real system would have before INT n. */
static WemuCpu *boot(void) {
    WemuCpu *c = wemu_cpu_create(RAMSZ);
    wemu_cpu_set_rip(c, CODE);
    set_gate(c, VEC, HANDLER, 0xE, 3, KCS, 1);  /* DPL3: ring 3 may INT */
    set_gate(c, 13, GP_HANDLER, 0xE, 0, KCS, 1); /* #GP for the reject path */
    CHECK(wemu_cpu_idt_load(c, IDT_BASE, IDT_LIMIT) == 0, "load IDTR");
    set_desc(c, KCS, 0x9A);      /* present code, DPL 0 */
    set_desc(c, KSS, 0x92);      /* present RW data, DPL 0 */
    set_desc(c, UCS, 0xFA);      /* present code, DPL 3 */
    set_desc(c, USS, 0xF2);      /* present RW data, DPL 3 */
    CHECK(wemu_cpu_gdt_load(c, GDT_BASE, GDT_LIMIT) == 0, "load GDTR");
    return c;
}

/* ---- ring 3 -> ring 0: real stack switch, CPL change, CS/SS reload ---- */
static void test_privilege_switch(void) {
    WemuCpu *c = boot();
    const uint8_t code[] = { 0xFB, 0xCD, VEC, 0xF4 }; /* STI; INT 42; HLT */
    CHECK(wemu_cpu_load(c, CODE, code, sizeof code) == 0, "load INT guest");
    wemu_cpu_set_rsp(c, U_RSP);
    wemu_cpu_set_cpl(c, 3);
    wemu_cpu_set_cs(c, UCS);     /* also sets CS.RPL = 3 */
    wemu_cpu_set_ss(c, USS);
    wemu_cpu_tss_set_ss(c, 0, KSS);
    wemu_cpu_tss_set_rsp(c, 0, R0_RSP0);
    CHECK(wemu_cpu_tss_rsp(c, 0) == R0_RSP0, "TSS RSP0 readable");
    CHECK(wemu_cpu_cs_rpl(c) == 3, "CS.RPL from selector");

    CHECK(wemu_cpu_step(c) == 1, "STI executed (IF set before INT)");
    CHECK((wemu_cpu_rflags(c) & 0x200u) != 0, "IF is set before INT");
    CHECK(wemu_cpu_step(c) == 1, "guest executed INT n");
    CHECK(wemu_cpu_fault(c) == 0, "INT delivered without fault");
    CHECK(wemu_cpu_exception_vector(c) == VEC, "delivered vector == INT 42");
    CHECK(wemu_cpu_exception_error(c) == 0, "INT 42 pushes no error code");
    CHECK(wemu_cpu_rip(c) == HANDLER, "handler RIP from gate offset");
    CHECK(wemu_cpu_cpl(c) == 0, "privilege transition CPL 3 -> 0");
    CHECK(wemu_cpu_cs(c) == KCS, "CS reloaded from gate selector");
    CHECK(wemu_cpu_ss(c) == KSS, "SS reloaded from TSS SS[0]");
    CHECK(wemu_cpu_cs_rpl(c) == 0, "CS.RPL reloaded to target CPL");
    CHECK((wemu_cpu_rflags(c) & 0x200u) == 0, "interrupt gate cleared IF");

    uint64_t sp = wemu_cpu_reg(c, 4);
    CHECK(sp == R0_RSP0 - 5 * 8, "RSP0 load: 5-qword switch frame");
    CHECK(frame_qword(c, sp, 0) == CODE + 3, "saved RIP = instruction AFTER INT");
    CHECK(frame_qword(c, sp, 1) == UCS, "frame CS = interrupted (ring-3) CS");
    CHECK((frame_qword(c, sp, 2) & 0x200u) != 0, "saved RFLAGS retains IF");
    CHECK(frame_qword(c, sp, 3) == U_RSP, "frame old RSP = ring-3 RSP");
    CHECK(frame_qword(c, sp, 4) == USS, "frame old SS = ring-3 SS");
    printf("cpl_switch: cpl 3->0 vec=%u cs=0x%x ss=0x%x rsp=0x%llx "
           "(RSP0=0x%llx) rip=0x%llx\n",
           wemu_cpu_exception_vector(c), (unsigned)wemu_cpu_cs(c),
           (unsigned)wemu_cpu_ss(c), (unsigned long long)sp,
           (unsigned long long)wemu_cpu_tss_rsp(c, 0),
           (unsigned long long)frame_qword(c, sp, 0));
    wemu_cpu_destroy(c);
}

/* ---- ring 0 -> ring 0: no privilege change, no TSS RSP0 load ---------- */
static void test_same_level(void) {
    WemuCpu *c = boot();
    const uint8_t code[] = { 0xCD, VEC, 0xF4 }; /* INT 42; HLT */
    CHECK(wemu_cpu_load(c, CODE, code, sizeof code) == 0, "load INT guest");
    set_gate(c, VEC, HANDLER, 0xE, 0, KCS, 1);  /* DPL 0 for CPL 0 */
    wemu_cpu_set_rsp(c, U_RSP);
    wemu_cpu_set_cpl(c, 0);
    wemu_cpu_set_cs(c, KCS);
    wemu_cpu_set_ss(c, KSS);
    wemu_cpu_tss_set_ss(c, 0, KSS);
    wemu_cpu_tss_set_rsp(c, 0, R0_RSP0);        /* present but NOT used */

    CHECK(wemu_cpu_step(c) == 1, "guest executed same-level INT n");
    CHECK(wemu_cpu_exception_vector(c) == VEC, "same-level vector == 42");
    CHECK(wemu_cpu_rip(c) == HANDLER, "same-level reaches handler");
    CHECK(wemu_cpu_cpl(c) == 0, "CPL stays 0 (no transition)");
    CHECK(wemu_cpu_cs(c) == KCS, "CS unchanged at same level");
    uint64_t sp = wemu_cpu_reg(c, 4);
    CHECK(sp == U_RSP - 3 * 8, "same-level: architectural 3-qword frame");
    CHECK(frame_qword(c, sp, 0) == CODE + 2, "saved RIP = after INT");
    CHECK(frame_qword(c, sp, 1) == KCS, "frame CS = current CS");
    CHECK(frame_qword(c, sp, 2) == 2, "frame RFLAGS slot (no SS/RSP pushed)");
    printf("same_level: cpl=%d vec=%u rsp=0x%llx rip=0x%llx\n",
           wemu_cpu_cpl(c), wemu_cpu_exception_vector(c),
           (unsigned long long)sp, (unsigned long long)frame_qword(c, sp, 0));
    wemu_cpu_destroy(c);
}

/* ---- guest INT rejected by gate DPL: #GP(IDT code), saved RIP = INT --- */
static void test_rejected_int(void) {
    WemuCpu *c = boot();
    const uint8_t code[] = { 0xCD, VEC, 0xF4 }; /* INT 42; HLT */
    CHECK(wemu_cpu_load(c, CODE, code, sizeof code) == 0, "load INT guest");
    set_gate(c, VEC, HANDLER, 0xE, 0, KCS, 1);  /* DPL 0 < CPL 3 */
    wemu_cpu_set_rsp(c, U_RSP);
    wemu_cpu_set_cpl(c, 3);
    wemu_cpu_set_cs(c, UCS);
    wemu_cpu_set_ss(c, USS);
    /* The rejected INT's secondary #GP gate targets ring 0; the exception
     * now takes the same CPL-switch path, so arm TSS SS[0]/RSP0. */
    wemu_cpu_tss_set_ss(c, 0, KSS);
    wemu_cpu_tss_set_rsp(c, 0, R0_RSP0);

    CHECK(wemu_cpu_step(c) == 1, "rejected INT delivers #GP to guest");
    CHECK(wemu_cpu_exception_vector(c) == 13, "guest INT violation -> #GP");
    CHECK(wemu_cpu_exception_error(c) == IDT_CODE(VEC), "#GP error = IDT code");
    CHECK(wemu_cpu_rip(c) == GP_HANDLER, "#GP reaches its handler");
    uint64_t sp = wemu_cpu_reg(c, 4);
    /* #GP pushes an error code first: slot0=code, slot1=saved RIP. */
    CHECK(frame_qword(c, sp, 0) == IDT_CODE(VEC), "#GP frame error code");
    CHECK(frame_qword(c, sp, 1) == CODE, "fault saved RIP = the INT insn");
    printf("reject: vec=%u err=0x%llx rip=0x%llx saved_rip=0x%llx\n",
           wemu_cpu_exception_vector(c),
           (unsigned long long)wemu_cpu_exception_error(c),
           (unsigned long long)wemu_cpu_rip(c),
           (unsigned long long)frame_qword(c, sp, 1));
    wemu_cpu_destroy(c);
}

int main(void) {
    test_privilege_switch();
    test_same_level();
    test_rejected_int();
    if (fails) {
        printf("test_cpl: %d/%d CHECK(S) FAILED\n", fails, checks);
        return 1;
    }
    printf("test_cpl: PASS (%d checks; guest INT n + CPL/TSS RSP0/CS:SS)\n",
           checks);
    return 0;
}
#endif
