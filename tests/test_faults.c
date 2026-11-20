/* test_faults.c — differential gate for #GP/#SS/#NP delivery and the
 * double-fault (#DF) latch.
 *
 * The guest supplies long-mode IDT gates in RAM; faults are triggered by
 * real guest state (a non-canonical linear address for #GP, an invalid
 * LOCK form whose #UD gate is unusable for #DF) or, where WEMU has no
 * segment model, by the same host-raise path the VSL bridge uses for #PF
 * (#SS/#NP).  Every observed bit — vector, error code, RIP and frame
 * slots — is compared with an independently written SDM expectation.
 *
 * NEGATIVE CONTROL: this SAME source compiled against the pre-change
 * library (b8c536b, no WEMU_HAS_FAULT_DELIVERY) prints FAIL and exits 1.
 *
 * DELIBERATELY NOT MODELLED (verified, not an oversight): #PF error bits 5
 * (PK) and 6 (SGX) stay 0.  'cr4' occurs only as a struct field in
 * src/wemu_internal.h and in comments in src/wemu_mem.c/include/wemu.h —
 * no code reads it, so CR4.PKE cannot gate a protection-key check.  There
 * is no PKRU state and ENCLS (0F 01 CF), WRPKRU (0F 01 EF) and RDPKRU
 * (0F 01 EE) all decode to an honest #UD (probe: step=-1, fault=6).  With
 * no key register and no enclave, there is no PK/SGX access to attribute;
 * fabricating those bits would be a lie. */
#include "wemu.h"
#include <stdio.h>
#include <string.h>

#ifndef WEMU_HAS_FAULT_DELIVERY
int main(void) {
    printf("FAIL: WEMU_HAS_FAULT_DELIVERY absent — pre-change WEMU delivers "
           "only #UD/#PF and never latches a double fault\n");
    return 1;
}
#else

static int fails, checks;
#define CHECK(c, m) do { checks++; if (!(c)) { \
    printf("FAIL: %s (line %d)\n", m, __LINE__); fails++; } } while (0)

#define RAMSZ       (1u << 20)
#define CODE        0x1000u
#define IDT_BASE    0x2000u
#define IDT_LIMIT   0x0fffu
#define GP_HANDLER  0x6100u
#define SS_HANDLER  0x6110u
#define NP_HANDLER  0x6120u
#define DF_HANDLER  0x6130u
#define STACK       0x80000u
#define NONCANON    0x0000800000000000ull /* bit47 set, bits63:48 clear */
#define IDT_CODE(v) (((uint64_t)(v) << 3) | 2u)

static void set_gate(WemuCpu *c, unsigned v, uint64_t off, uint8_t type,
                     int present) {
    uint8_t g[16];
    memset(g, 0, sizeof g);
    g[0] = (uint8_t)off;         g[1] = (uint8_t)(off >> 8);
    g[2] = 0x28; g[3] = 0x00;    /* 64-bit code selector */
    g[4] = 0x00;                 /* no IST */
    g[5] = (uint8_t)((present ? 0x80 : 0) | (type & 0xf));
    g[6] = (uint8_t)(off >> 16); g[7] = (uint8_t)(off >> 24);
    g[8] = (uint8_t)(off >> 32); g[9] = (uint8_t)(off >> 40);
    g[10] = (uint8_t)(off >> 48); g[11] = (uint8_t)(off >> 56);
    (void)wemu_mem_write(c, IDT_BASE + v * 16, g, sizeof g);
}

static WemuCpu *boot(int with_df) {
    WemuCpu *c = wemu_cpu_create(RAMSZ);
    wemu_cpu_set_rip(c, CODE);
    wemu_cpu_set_rsp(c, STACK);
    set_gate(c, 13, GP_HANDLER, 0xE, 1); /* #GP */
    set_gate(c, 12, SS_HANDLER, 0xE, 1); /* #SS */
    set_gate(c, 11, NP_HANDLER, 0xE, 1); /* #NP */
    set_gate(c, 8,  DF_HANDLER, 0xE, with_df); /* #DF */
    /* A present-looking but P=0 #UD gate: a real #UD then faults with
     * #NP during delivery (type is valid, present bit is clear). */
    set_gate(c, 6, GP_HANDLER, 0xE, 0);
    CHECK(wemu_cpu_idt_load(c, IDT_BASE, IDT_LIMIT) == 0, "load IDTR");
    return c;
}

static uint64_t frame_qword(WemuCpu *c, uint64_t sp, int idx) {
    uint64_t v = 0;
    (void)wemu_mem_read(c, sp + (uint64_t)idx * 8, &v, 8);
    return v;
}

/* ---- #GP from a real non-canonical guest access (error code 0) ------- */
static void test_gp_noncanonical(void) {
    /* REX.W A1 moffs64: MOV RAX, [0x0000800000000000] -> non-canonical #GP. */
    uint8_t rd[] = { 0x48, 0xA1,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00 };
    WemuCpu *c = boot(1);
    (void)wemu_cpu_load(c, CODE, rd, sizeof rd);

    CHECK(wemu_cpu_step(c) == 1, "non-canonical #GP delivered");
    CHECK(wemu_cpu_fault(c) == 0, "#GP fault cleared on delivery");
    CHECK(wemu_cpu_exception_vector(c) == 13, "delivered vector == #GP(13)");
    CHECK(wemu_cpu_exception_error(c) == 0, "#GP error code = 0 (non-canonical)");
    CHECK(wemu_cpu_rip(c) == GP_HANDLER, "#GP transfers to gate offset");
    uint64_t sp = wemu_cpu_reg(c, 4);
    CHECK(sp == STACK - 6 * 8, "#GP frame is 6 qwords (error code pushed)");
    CHECK(frame_qword(c, sp, 0) == 0, "#GP frame slot0 = error 0");
    CHECK(frame_qword(c, sp, 1) == CODE, "#GP frame saved RIP = faulting insn");
    CHECK(frame_qword(c, sp, 2) == 0x28, "#GP frame CS");
    CHECK(frame_qword(c, sp, 4) == STACK, "#GP frame old RSP");
    printf("gp: vec=%u err=%llu rip=0x%llx (expected 13/0/0x%x)\n",
           wemu_cpu_exception_vector(c),
           (unsigned long long)wemu_cpu_exception_error(c),
           (unsigned long long)wemu_cpu_rip(c), GP_HANDLER);
    wemu_cpu_destroy(c);
}

/* ---- #SS and #NP delivered with their origin error codes ------------- */
static void test_ss_np_delivery(void) {
    {
        WemuCpu *c = boot(1);
        wemu_cpu_raise_exception(c, 12, 0, 0); /* #SS, no selector -> error 0 */
        CHECK(wemu_cpu_step(c) == 1, "#SS delivered");
        CHECK(wemu_cpu_exception_vector(c) == 12, "delivered vector == #SS(12)");
        CHECK(wemu_cpu_exception_error(c) == 0, "#SS error code = 0");
        CHECK(wemu_cpu_rip(c) == SS_HANDLER, "#SS transfers to gate offset");
        uint64_t sp = wemu_cpu_reg(c, 4);
        CHECK(sp == STACK - 6 * 8, "#SS frame is 6 qwords");
        CHECK(frame_qword(c, sp, 0) == 0, "#SS frame slot0 = error 0");
        CHECK(frame_qword(c, sp, 1) == CODE, "#SS frame saved RIP");
        printf("ss: vec=%u err=%llu rip=0x%llx (expected 12/0/0x%x)\n",
               wemu_cpu_exception_vector(c),
               (unsigned long long)wemu_cpu_exception_error(c),
               (unsigned long long)wemu_cpu_rip(c), SS_HANDLER);
        wemu_cpu_destroy(c);
    }
    {
        WemuCpu *c = boot(1);
        uint64_t code = IDT_CODE(40); /* #NP with an IDT-code selector */
        wemu_cpu_raise_exception(c, 11, code, 0);
        CHECK(wemu_cpu_step(c) == 1, "#NP delivered");
        CHECK(wemu_cpu_exception_vector(c) == 11, "delivered vector == #NP(11)");
        CHECK(wemu_cpu_exception_error(c) == code, "#NP error = (40<<3)|2");
        CHECK(wemu_cpu_rip(c) == NP_HANDLER, "#NP transfers to gate offset");
        uint64_t sp = wemu_cpu_reg(c, 4);
        CHECK(frame_qword(c, sp, 0) == code, "#NP frame slot0 = IDT code");
        CHECK(frame_qword(c, sp, 1) == CODE, "#NP frame saved RIP");
        printf("np: vec=%u err=0x%llx rip=0x%llx (expected 11/0x%llx)\n",
               wemu_cpu_exception_vector(c),
               (unsigned long long)wemu_cpu_exception_error(c),
               (unsigned long long)wemu_cpu_rip(c),
               (unsigned long long)code);
        wemu_cpu_destroy(c);
    }
}

/* ---- #DF delivered when the #UD gate is not present ------------------ */
static void test_df_not_present(void) {
    uint8_t ud[] = { 0xF0, 0x01, 0xD8, 0xF4 }; /* LOCK ADD -> #UD */
    WemuCpu *c = boot(1);
    /* boot() installs a type-0xE, P=0 #UD gate -> the #UD delivery raises
     * #NP (11), a #DF contributor. */
    (void)wemu_cpu_load(c, CODE, ud, sizeof ud);
    CHECK(wemu_cpu_double_faults(c) == 0, "no #DF before the fault");
    CHECK(wemu_cpu_step(c) == 1, "#DF delivered after failed #UD delivery");
    CHECK(wemu_cpu_exception_vector(c) == 8, "delivered vector == #DF(8)");
    CHECK(wemu_cpu_exception_error(c) == 0, "#DF error code = 0 (SDM)");
    CHECK(wemu_cpu_rip(c) == DF_HANDLER, "#DF transfers to the #DF gate offset");
    CHECK(wemu_cpu_double_faults(c) == 1, "exactly one #DF condition latched");
    CHECK(wemu_cpu_double_fault_latched(c) != 0, "#DF latch is set");
    CHECK(wemu_cpu_double_fault_source(c) == 11, "#DF source = #NP (11)");
    CHECK(wemu_cpu_double_fault_source_error(c) == IDT_CODE(6),
          "#DF source error = (6<<3)|2 = 0x32");
    uint64_t sp = wemu_cpu_reg(c, 4);
    CHECK(sp == STACK - 6 * 8, "#DF frame is 6 qwords (zero error slot)");
    CHECK(frame_qword(c, sp, 0) == 0, "#DF frame slot0 = error 0");
    CHECK(frame_qword(c, sp, 1) == CODE, "#DF frame saved RIP = faulting insn");
    CHECK(frame_qword(c, sp, 2) == 0x28, "#DF frame CS");
    CHECK(frame_qword(c, sp, 4) == STACK, "#DF frame old RSP");
    CHECK(frame_qword(c, sp, 5) == 0, "#DF frame SS");
    printf("df_np: vec=%u err=%llu src=%u srcerr=0x%llx rip=0x%llx\n",
           wemu_cpu_exception_vector(c),
           (unsigned long long)wemu_cpu_exception_error(c),
           wemu_cpu_double_fault_source(c),
           (unsigned long long)wemu_cpu_double_fault_source_error(c),
           (unsigned long long)wemu_cpu_rip(c));
    wemu_cpu_destroy(c);
}

/* ---- #DF from a bad gate TYPE (secondary #GP contributor) ------------ */
static void test_df_bad_type(void) {
    uint8_t ud[] = { 0xF0, 0x01, 0xD8, 0xF4 };
    WemuCpu *c = boot(1);
    set_gate(c, 6, GP_HANDLER, 0x4, 1); /* task gate: invalid in long mode */
    (void)wemu_cpu_load(c, CODE, ud, sizeof ud);
    CHECK(wemu_cpu_step(c) == 1, "#DF delivered after invalid gate type");
    CHECK(wemu_cpu_exception_vector(c) == 8, "bad-type #DF vector == 8");
    CHECK(wemu_cpu_double_fault_source(c) == 13, "#DF source = #GP (13)");
    CHECK(wemu_cpu_double_fault_source_error(c) == IDT_CODE(6),
          "bad-type #DF source error = 0x32");
    printf("df_gp: vec=%u src=%u srcerr=0x%llx\n",
           wemu_cpu_exception_vector(c), wemu_cpu_double_fault_source(c),
           (unsigned long long)wemu_cpu_double_fault_source_error(c));
    wemu_cpu_destroy(c);
}

/* ---- no #DF handler: latch recorded, legacy #NP latch preserved ------ */
static void test_df_without_handler(void) {
    uint8_t ud[] = { 0xF0, 0x01, 0xD8, 0xF4 };
    WemuCpu *c = boot(0); /* gate 8 not present */
    (void)wemu_cpu_load(c, CODE, ud, sizeof ud);
    CHECK(wemu_cpu_step(c) == -1, "no #DF gate: delivery still stops");
    CHECK(wemu_cpu_fault(c) == 11, "legacy secondary #NP latch preserved");
    CHECK(wemu_cpu_fault_error(c) == IDT_CODE(6), "legacy #NP error = 0x32");
    CHECK(wemu_cpu_rip(c) == CODE, "RIP unchanged when nothing is delivered");
    CHECK(wemu_cpu_double_fault_latched(c) != 0, "#DF condition still recorded");
    CHECK(wemu_cpu_double_faults(c) == 1, "one #DF condition counted");
    CHECK(wemu_cpu_double_fault_source(c) == 11, "recorded source = #NP");
    printf("df_nohandler: fault=%d err=0x%llx df=%u src=%u (legacy latch)\n",
           wemu_cpu_fault(c), (unsigned long long)wemu_cpu_fault_error(c),
           wemu_cpu_double_faults(c), wemu_cpu_double_fault_source(c));
    wemu_cpu_destroy(c);
}

int main(void) {
    test_gp_noncanonical();
    test_ss_np_delivery();
    test_df_not_present();
    test_df_bad_type();
    test_df_without_handler();
    if (fails) {
        printf("test_faults: %d/%d CHECK(S) FAILED\n", fails, checks);
        return 1;
    }
    printf("test_faults: PASS (%d checks; #GP/#SS/#NP delivery + #DF latch)\n",
           checks);
    return 0;
}
#endif
