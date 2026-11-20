/* test_call_gate_priv.c — differential gate for privilege-changing 64-bit
 * call gates (TSS stack switch, old SS:RSP push, parameter copy).
 *
 * A ring-3 caller uses a DPL=3 call gate whose target code descriptor is
 * DPL=0.  Expected behaviour comes from the SDM CALL-gate pseudocode, not
 * from the implementation:
 *   - the TSS supplies SS0/RSP0 for the new stack;
 *   - old SS and old RSP are saved as 8-byte slots;
 *   - 'param_count' qwords are copied from the caller stack in order;
 *   - return CS:RIP are pushed last, so the ring-0 handler enters with RSP
 *     at the return RIP and its parameters at RSP+8;
 *   - CS/SS/CPL are reloaded from the gate and TSS.
 *
 * This source deliberately uses ONLY APIs that already exist in pre-change
 * WEMU, so it compiles and RUNS against the old library: old WEMU #GPs the
 * privilege-changing gate and the checks fail.  Feature-macro stubs are not
 * used — the negative control is behavioural, not a compile-time skip.
 */
#include "wemu.h"
#include <stdio.h>
#include <string.h>

static int fails, checks;
#define CHECK(c, m) do { checks++; if (!(c)) { \
    printf("FAIL: %s (line %d)\n", m, __LINE__); fails++; } } while (0)

#define RAMSZ     (1u << 20)
#define GDT_BASE  0x5000u
#define GDT_LIMIT 0x1ffu
#define TSS_BASE  0x10000u
#define TSS_LIMIT 0x67u
#define KCS       0x08u   /* GDT idx1: DPL0 code */
#define KSS       0x10u   /* GDT idx2: DPL0 data */
#define UCS       0x1bu   /* GDT idx3: DPL3 code */
#define USS       0x23u   /* GDT idx4: DPL3 data */
#define TSS_SEL   0x28u   /* GDT idx5: 16-byte TSS */
#define CGS       0x38u   /* GDT idx7: 16-byte call gate, DPL3 */
#define CGS0      0x48u   /* GDT idx9: 16-byte call gate, DPL0 */
#define HANDLER   0x4000u
#define U_CODE    0x1000u
#define FAR_GATE  0xa000u
#define U_RSP     0xc0000u
#define K_RSP     0xe0000u
#define RET_RIP   0x1234ull
#define U_RESUME  (U_CODE + 17u)
#define NPARAMS   3u
#define FINAL_RSP (K_RSP - 32u - 8u * NPARAMS)  /* 0xe0000 - 56 */

#define P0 0x1111111111111111ull
#define P1 0x2222222222222222ull
#define P2 0x3333333333333333ull
#define SENT_A 0xA5A5A5A5A5A5A5A5ull
#define SENT_H 0xD5D5D5D5D5D5D5D5ull

#define TSS_AVAIL 0x89u
#define CALLG_D3  0xECu  /* P=1 DPL=3 S=0 type=0xC */
#define CALLG_D0  0x8Cu  /* P=1 DPL=0 S=0 type=0xC */

static void set_desc(WemuCpu *c, uint16_t sel, uint8_t access) {
    uint8_t d[8];
    memset(d, 0, sizeof d);
    d[5] = access;
    (void)wemu_mem_write(c, GDT_BASE + (uint64_t)(sel >> 3) * 8, d, 8);
}

static void set_tss_desc(WemuCpu *c, uint16_t sel, uint64_t base,
                         uint32_t limit) {
    uint8_t d[16];
    memset(d, 0, sizeof d);
    d[0] = (uint8_t)limit;        d[1] = (uint8_t)(limit >> 8);
    d[2] = (uint8_t)base;         d[3] = (uint8_t)(base >> 8);
    d[4] = (uint8_t)(base >> 16); d[5] = TSS_AVAIL;
    d[6] = (uint8_t)((limit >> 16) & 0x0fu);
    d[7] = (uint8_t)(base >> 24);
    d[8] = (uint8_t)(base >> 32); d[9] = (uint8_t)(base >> 40);
    d[10] = (uint8_t)(base >> 48); d[11] = (uint8_t)(base >> 56);
    (void)wemu_mem_write(c, GDT_BASE + (uint64_t)(sel >> 3) * 8, d, 16);
}

/* 16-byte gate: selector bytes 2-3, offset bytes 0-1,6-11, param count byte 4. */
static void set_call_gate(WemuCpu *c, uint16_t sel, uint16_t cs,
                          uint64_t off, uint8_t access, unsigned np) {
    uint8_t d[16];
    memset(d, 0, sizeof d);
    d[0] = (uint8_t)off;        d[1] = (uint8_t)(off >> 8);
    d[2] = (uint8_t)cs;         d[3] = (uint8_t)(cs >> 8);
    d[4] = (uint8_t)(np & 0x1fu);
    d[5] = access;
    d[6] = (uint8_t)(off >> 16); d[7] = (uint8_t)(off >> 24);
    d[8] = (uint8_t)(off >> 32); d[9] = (uint8_t)(off >> 40);
    d[10] = (uint8_t)(off >> 48); d[11] = (uint8_t)(off >> 56);
    (void)wemu_mem_write(c, GDT_BASE + (uint64_t)(sel >> 3) * 8, d, 16);
}

static void set_tss_image(WemuCpu *c) {
    uint8_t t[0x48];
    memset(t, 0, sizeof t);
    memcpy(t + 0x04, &((uint64_t){K_RSP}), 8); /* RSP0 */
    uint16_t ss0 = KSS;
    memcpy(t + 0x1c, &ss0, 2);                 /* SS0 */
    (void)wemu_mem_write(c, TSS_BASE, t, sizeof t);
}

static void set_far_ptr(WemuCpu *c, uint64_t addr, uint16_t sel) {
    uint8_t fp[10];
    memset(fp, 0, sizeof fp);
    fp[8] = (uint8_t)sel; fp[9] = (uint8_t)(sel >> 8);
    (void)wemu_mem_write(c, addr, fp, sizeof fp);
}

static uint64_t qword64(WemuCpu *c, uint64_t a) {
    uint64_t v = 0; (void)wemu_mem_read(c, a, &v, 8); return v;
}

/* ring-0 handler: movabs rdx,SENT_H ; HLT */
static const uint8_t handler_code[] = {
    0x48, 0xBA, 0xD5,0xD5,0xD5,0xD5,0xD5,0xD5,0xD5,0xD5, 0xF4
};
/* ring-3 caller: movabs rax,SA ; far CALL m16:64 [FAR_GATE] ; HLT */
static const uint8_t u_code[] = {
    0x48, 0xB8, 0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,
    0xFF, 0x1C, 0x25,
    (uint8_t)FAR_GATE, (uint8_t)(FAR_GATE >> 8),
    (uint8_t)(FAR_GATE >> 16), (uint8_t)(FAR_GATE >> 24),
    0xF4
};

static WemuCpu *boot(void) {
    WemuCpu *c = wemu_cpu_create(RAMSZ);
    set_desc(c, KCS, 0x9A);  set_desc(c, KSS, 0x92);
    set_desc(c, UCS, 0xFA);  set_desc(c, USS, 0xF2);
    set_tss_desc(c, TSS_SEL, TSS_BASE, TSS_LIMIT);
    set_call_gate(c, CGS, KCS, HANDLER, CALLG_D3, NPARAMS);
    set_call_gate(c, CGS0, KCS, HANDLER, CALLG_D0, 0);
    CHECK(wemu_cpu_gdt_load(c, GDT_BASE, GDT_LIMIT) == 0, "load GDTR");
    set_tss_image(c);
    CHECK(wemu_cpu_ltr(c, TSS_SEL, NULL) == 0, "LTR loads the TSS");
    wemu_cpu_tss_set_ss(c, 0, KSS);
    wemu_cpu_tss_set_rsp(c, 0, K_RSP);
    wemu_cpu_set_cpl(c, 3);
    wemu_cpu_set_cs(c, UCS);
    wemu_cpu_set_ss(c, USS);
    wemu_cpu_set_rsp(c, U_RSP);
    (void)wemu_mem_write(c, U_RSP + 0,  &((uint64_t){P0}), 8);
    (void)wemu_mem_write(c, U_RSP + 8,  &((uint64_t){P1}), 8);
    (void)wemu_mem_write(c, U_RSP + 16, &((uint64_t){P2}), 8);
    (void)wemu_cpu_load(c, HANDLER, handler_code, sizeof handler_code);
    wemu_cpu_clear_fault(c);
    return c;
}

/* ---- host-call form: full architectural stack switch ----------------- */
static void test_host_call(void) {
    WemuCpu *c = boot();
    CHECK(wemu_cpu_call_gate(c, CGS, RET_RIP) == 0,
          "DPL3->DPL0 call gate succeeds");
    CHECK(wemu_cpu_fault(c) == 0, "privilege call gate has no fault");
    CHECK(wemu_cpu_cpl(c) == 0 && wemu_cpu_cs(c) == KCS &&
          wemu_cpu_ss(c) == KSS, "CS/SS/CPL reloaded from gate and TSS");
    CHECK(wemu_cpu_rip(c) == HANDLER, "RIP = call gate offset");
    CHECK(wemu_cpu_reg(c, 4) == FINAL_RSP, "RSP = TSS RSP0 minus full frame");
    /* SDM frame layout, byte-exact. */
    CHECK(qword64(c, FINAL_RSP) == RET_RIP, "[rsp+0] return RIP");
    CHECK(qword64(c, FINAL_RSP + 8) == UCS, "[rsp+8] return CS (old RPL)");
    CHECK(qword64(c, FINAL_RSP + 16) == P0, "[rsp+16] param[0] copied");
    CHECK(qword64(c, FINAL_RSP + 24) == P1, "[rsp+24] param[1] copied");
    CHECK(qword64(c, FINAL_RSP + 32) == P2, "[rsp+32] param[2] copied");
    CHECK(qword64(c, FINAL_RSP + 40) == U_RSP, "[rsp+40] old RSP pushed");
    CHECK(qword64(c, FINAL_RSP + 48) == USS, "[rsp+48] old SS pushed");
    CHECK(wemu_cpu_run(c, 4) == 2 && wemu_cpu_halted(c) &&
          wemu_cpu_reg(c, 2) == SENT_H, "ring-0 handler executes to HLT");
    wemu_cpu_destroy(c);
}

/* ---- guest-executed far CALL through the same gate -------------------- */
static void test_guest_call(void) {
    WemuCpu *c = boot();
    set_far_ptr(c, FAR_GATE, CGS);
    (void)wemu_cpu_load(c, U_CODE, u_code, sizeof u_code);
    wemu_cpu_set_rip(c, U_CODE);
    CHECK(wemu_cpu_run(c, 6) == 4 && wemu_cpu_halted(c),
          "guest far CALL via privilege gate reaches HLT");
    CHECK(wemu_cpu_fault(c) == 0 && wemu_cpu_cpl(c) == 0 &&
          wemu_cpu_cs(c) == KCS && wemu_cpu_ss(c) == KSS,
          "guest gate switches to ring 0 without fault");
    CHECK(wemu_cpu_reg(c, 2) == SENT_H, "ring-0 handler ran (RDX sentinel)");
    CHECK(wemu_cpu_reg(c, 0) == SENT_A, "ring-3 caller RAX survived switch");
    CHECK(qword64(c, FINAL_RSP) == U_RESUME, "guest return RIP pushed");
    CHECK(qword64(c, FINAL_RSP + 8) == UCS, "guest return CS pushed");
    CHECK(qword64(c, FINAL_RSP + 16) == P0, "guest param[0] copied");
    CHECK(qword64(c, FINAL_RSP + 40) == U_RSP, "guest old RSP pushed");
    CHECK(qword64(c, FINAL_RSP + 48) == USS, "guest old SS pushed");
    wemu_cpu_destroy(c);
}

/* ---- same-level gate keeps the legacy 16-byte frame ------------------- */
static void test_same_level(void) {
    WemuCpu *c = boot();
    wemu_cpu_set_cpl(c, 0);
    wemu_cpu_set_cs(c, KCS);
    wemu_cpu_set_ss(c, KSS);
    wemu_cpu_set_rsp(c, K_RSP);
    CHECK(wemu_cpu_call_gate(c, CGS0, RET_RIP) == 0,
          "same-level DPL0 call gate succeeds");
    CHECK(wemu_cpu_reg(c, 4) == K_RSP - 16, "same-level frame is 16 bytes");
    CHECK(qword64(c, K_RSP - 16) == RET_RIP &&
          qword64(c, K_RSP - 8) == KCS, "same-level return CS:RIP pushed");
    wemu_cpu_destroy(c);
}

/* ---- negative controls: exact vector + selector error code ------------ */
static void test_negatives(void) {
    WemuCpu *c;

    /* DPL0 gate used from CPL3 -> #GP(gate selector). */
    c = boot();
    set_call_gate(c, CGS, KCS, HANDLER, CALLG_D0, NPARAMS);
    CHECK(wemu_cpu_call_gate(c, CGS, RET_RIP) == -1, "DPL0 gate at CPL3");
    CHECK(wemu_cpu_fault(c) == 13 && wemu_cpu_fault_error(c) == CGS,
          "gate max(CPL,RPL)>DPL -> #GP(gate)");
    wemu_cpu_destroy(c);

    /* No TSS SS for target CPL -> #TS(0). */
    c = boot();
    wemu_cpu_tss_set_ss(c, 0, 0);
    CHECK(wemu_cpu_call_gate(c, CGS, RET_RIP) == -1, "missing TSS SS0");
    CHECK(wemu_cpu_fault(c) == 10 && wemu_cpu_fault_error(c) == 0,
          "no SS0 -> #TS(0)");
    wemu_cpu_destroy(c);

    /* TSS SS0 with wrong RPL -> #TS(ss & 0xfffc). */
    c = boot();
    wemu_cpu_tss_set_ss(c, 0, 0x11u);
    CHECK(wemu_cpu_call_gate(c, CGS, RET_RIP) == -1, "SS0 RPL != target");
    CHECK(wemu_cpu_fault(c) == 10 && wemu_cpu_fault_error(c) == 0x10u,
          "SS0 RPL mismatch -> #TS(SS0)");
    wemu_cpu_destroy(c);

    /* Target code descriptor not present -> #GP(gate selector). */
    c = boot();
    set_desc(c, KCS, 0x1Au);
    CHECK(wemu_cpu_call_gate(c, CGS, RET_RIP) == -1, "target code P=0");
    CHECK(wemu_cpu_fault(c) == 13 && wemu_cpu_fault_error(c) == CGS,
          "not-present target code -> #GP(gate)");
    wemu_cpu_destroy(c);

    /* TSS RSP0 that makes the frame underflow guest RAM -> #SS(SS0). */
    c = boot();
    wemu_cpu_tss_set_rsp(c, 0, 0);
    CHECK(wemu_cpu_call_gate(c, CGS, RET_RIP) == -1, "RSP0 underflow");
    CHECK(wemu_cpu_fault(c) == 12 && wemu_cpu_fault_error(c) == KSS,
          "out-of-RAM new stack -> #SS(SS0)");
    wemu_cpu_destroy(c);
}

int main(void) {
    test_host_call();
    test_guest_call();
    test_same_level();
    test_negatives();
    if (fails) {
        printf("test_call_gate_priv: %d/%d CHECK(S) FAILED\n", fails, checks);
        return 1;
    }
    printf("test_call_gate_priv: PASS (%d checks; DPL3->0 TSS stack switch, "
           "old SS:RSP, 3 copied params, guest far CALL, #GP/#TS/#SS "
           "negatives)\n", checks);
    return 0;
}
