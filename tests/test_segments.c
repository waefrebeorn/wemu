/* test_segments.c — differential gate for frame-push #DF and the bounded
 * GDT/TSS segment-origin faults (#TS/#SS/#NP) on a software INT.
 *
 * Every observed bit — vector, error code, source, #DF latch, RIP and RSP —
 * is compared with an independently written SDM expectation.  Selector
 * error codes are (selector & 0xFFFC) (index + TI, IDT/EXT/RPL clear).
 *
 * NEGATIVE CONTROL: this SAME source compiled against the pre-change
 * library (ae21035, no WEMU_HAS_SEGMENTS) prints FAIL and exits 1: old
 * WEMU ignores a failed frame push (delivering "successfully" to the
 * handler) and knows nothing about GDT/TSS selectors.
 *
 * This increment generates FAULTS only; it does not perform a privilege
 * change (no RSP0 load, no CS/SS reload).  See WEMU_HAS_SEGMENTS in wemu.h
 * for the explicit list of what is not modelled. */
#include "wemu.h"
#include <stdio.h>
#include <string.h>

#ifndef WEMU_HAS_SEGMENTS
int main(void) {
    printf("FAIL: WEMU_HAS_SEGMENTS absent — pre-change WEMU ignores a failed "
           "frame push (no #GP -> #DF latch) and has no GDT/TSS segment-origin "
           "#TS/#SS/#NP faults\n");
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
#define GDT_BASE    0x3000u
#define GDT_LIMIT   0x0fffu
#define HANDLER     0x6000u
#define UD_HANDLER  0x6100u
#define DF_HANDLER  0x6130u
#define TS_HANDLER  0x6200u
#define SS_HANDLER  0x6210u
#define NP_HANDLER  0x6220u
#define STACK       0x80000u
#define BADSTACK    (RAMSZ + 16u)      /* first frame push lands past RAM */
#define CS_SEL      0x28u              /* GDT index 5: present code */
#define SS_SEL      0x30u              /* GDT index 6: RW data, RPL 0 */
#define NP_CS_SEL   0x38u              /* GDT index 7: no descriptor */

/* Access bytes: P|DPL|S|type. 0x9A = present code R/X, 0x92 = present RW
 * data, 0x12 = not-present RW data, 0x90 = present read-only data. */
#define ACC_CODE    0x9Au
#define ACC_RW      0x92u
#define ACC_NOTP    0x12u
#define ACC_RO      0x90u

static void set_gate(WemuCpu *c, unsigned v, uint64_t off, uint8_t type,
                     uint8_t dpl, uint16_t sel, int present) {
    uint8_t g[16];
    memset(g, 0, sizeof g);
    g[0] = (uint8_t)off;         g[1] = (uint8_t)(off >> 8);
    g[2] = (uint8_t)sel;         g[3] = (uint8_t)(sel >> 8);
    g[4] = 0x00;                 /* no IST */
    g[5] = (uint8_t)((present ? 0x80 : 0) | (dpl << 5) | (type & 0xf));
    g[6] = (uint8_t)(off >> 16); g[7] = (uint8_t)(off >> 24);
    g[8] = (uint8_t)(off >> 32); g[9] = (uint8_t)(off >> 40);
    g[10] = (uint8_t)(off >> 48); g[11] = (uint8_t)(off >> 56);
    (void)wemu_mem_write(c, IDT_BASE + v * 16, g, sizeof g);
}

static void set_desc(WemuCpu *c, uint16_t sel, uint8_t access) {
    uint8_t d[8];
    memset(d, 0, sizeof d);
    d[5] = access;
    (void)wemu_mem_write(c, GDT_BASE + ((uint64_t)(sel >> 3)) * 8, d, 8);
}

/* A CPU with a loaded IDT+GDT.  gate 40 is a DPL=3 software-INT gate so a
 * CPL=3 caller can request it; gates 10/11/12 deliver the generated faults
 * so the vector/error can be observed after wemu_cpu_step(). */
static WemuCpu *boot_seg(void) {
    WemuCpu *c = wemu_cpu_create(RAMSZ);
    wemu_cpu_set_rip(c, CODE);
    wemu_cpu_set_rsp(c, STACK);
    wemu_cpu_set_cpl(c, 0);
    wemu_cpu_set_cs_rpl(c, 0);
    set_gate(c, 40, HANDLER,    0xE, 3, CS_SEL, 1); /* software INT target */
    set_gate(c, 10, TS_HANDLER, 0xE, 0, CS_SEL, 1); /* #TS */
    set_gate(c, 12, SS_HANDLER, 0xE, 0, CS_SEL, 1); /* #SS */
    set_gate(c, 11, NP_HANDLER, 0xE, 0, CS_SEL, 1); /* #NP */
    CHECK(wemu_cpu_idt_load(c, IDT_BASE, IDT_LIMIT) == 0, "load IDTR");
    set_desc(c, CS_SEL, ACC_CODE);
    set_desc(c, SS_SEL, ACC_RW);
    CHECK(wemu_cpu_gdt_load(c, GDT_BASE, GDT_LIMIT) == 0, "load GDTR");
    return c;
}

typedef void (*SegSetup)(WemuCpu *c);

static void setup_ts(WemuCpu *c) {
    wemu_cpu_tss_set_ss(c, 0, 0x33);    /* RPL 3, target CPL 0 */
}
static void setup_ss_notp(WemuCpu *c) {
    set_desc(c, SS_SEL, ACC_NOTP);      /* P=0 */
    wemu_cpu_tss_set_ss(c, 0, SS_SEL);
}
static void setup_np(WemuCpu *c) {
    set_gate(c, 40, HANDLER, 0xE, 3, NP_CS_SEL, 1); /* CS index 7 absent */
    wemu_cpu_tss_set_ss(c, 0, SS_SEL);
}

/* Drive a rejected software INT through to its handler so vector/error are
 * observable via the delivery API as well as the raw fault latch. */
static void expect_swint_fault(SegSetup setup, unsigned want_vec,
                               uint64_t want_err) {
    WemuCpu *c = boot_seg();
    setup(c);
    wemu_cpu_set_cpl(c, 3);             /* CPL 3 -> target 0: stack switch */
    wemu_cpu_set_int_target_cpl(c, 0);
    CHECK(wemu_cpu_int_target_cpl(c) == 0, "target CPL readable");
    CHECK(wemu_cpu_deliver_int(c, 40) == -1, "software INT rejected");
    CHECK(wemu_cpu_fault(c) == (int)want_vec, "generated fault vector");
    CHECK(wemu_cpu_fault_error(c) == want_err, "generated fault error code");
    CHECK(wemu_cpu_rip(c) == CODE, "no handler transfer on segment fault");
    CHECK(wemu_cpu_step(c) == 1, "latched fault delivered to its handler");
    CHECK(wemu_cpu_exception_vector(c) == want_vec, "delivered vector matches");
    CHECK(wemu_cpu_exception_error(c) == want_err, "delivered error matches");
    printf("seg: vec=%u err=0x%llx (expected %u/0x%llx)\n",
           wemu_cpu_exception_vector(c),
           (unsigned long long)wemu_cpu_exception_error(c),
           want_vec, (unsigned long long)want_err);
    wemu_cpu_destroy(c);
}

/* ---- #TS: TSS SS selector has the wrong RPL for the target CPL -------- */
static void test_ts_bad_tss(void) {
    WemuCpu *c = boot_seg();
    wemu_cpu_set_cpl(c, 3);
    wemu_cpu_set_int_target_cpl(c, 0);
    wemu_cpu_tss_set_ss(c, 0, 0x33);    /* RPL 3, target CPL 0 */
    CHECK(wemu_cpu_tss_ss(c, 0) == 0x33, "TSS SS selector readable");
    CHECK(wemu_cpu_deliver_int(c, 40) == -1, "INT rejected: wrong-RPL TSS SS");
    CHECK(wemu_cpu_fault(c) == 10, "#TS latched for bad TSS SS");
    CHECK(wemu_cpu_fault_error(c) == 0x30, "#TS error = 0x33 & 0xfffc");
    wemu_cpu_destroy(c);
    expect_swint_fault(setup_ts, 10, 0x30);
}

/* ---- #SS: stack segment not present / not writable -------------------- */
static void test_ss_stack(void) {
    {
        WemuCpu *c = boot_seg();
        set_desc(c, SS_SEL, ACC_NOTP);   /* P=0 */
        wemu_cpu_set_cpl(c, 3);
        wemu_cpu_set_int_target_cpl(c, 0);
        wemu_cpu_tss_set_ss(c, 0, SS_SEL);
        CHECK(wemu_cpu_deliver_int(c, 40) == -1, "INT rejected: SS not present");
        CHECK(wemu_cpu_fault(c) == 12, "#SS latched (not present)");
        CHECK(wemu_cpu_fault_error(c) == SS_SEL, "#SS error = selector");
        wemu_cpu_destroy(c);
    }
    expect_swint_fault(setup_ss_notp, 12, SS_SEL);
    {
        WemuCpu *c = boot_seg();
        set_desc(c, SS_SEL, ACC_RO);     /* present but read-only */
        wemu_cpu_set_cpl(c, 3);
        wemu_cpu_set_int_target_cpl(c, 0);
        wemu_cpu_tss_set_ss(c, 0, SS_SEL);
        CHECK(wemu_cpu_deliver_int(c, 40) == -1, "INT rejected: SS read-only");
        CHECK(wemu_cpu_fault(c) == 12, "#SS latched (not writable)");
        wemu_cpu_destroy(c);
    }
}

/* ---- #NP: gate target code segment not present ------------------------ */
static void test_np_code(void) {
    {
        WemuCpu *c = boot_seg();
        setup_np(c);
        wemu_cpu_set_cpl(c, 3);
        wemu_cpu_set_int_target_cpl(c, 0);
        CHECK(wemu_cpu_deliver_int(c, 40) == -1, "INT rejected: gate CS absent");
        CHECK(wemu_cpu_fault(c) == 11, "#NP latched for absent code segment");
        CHECK(wemu_cpu_fault_error(c) == NP_CS_SEL, "#NP error = selector");
        wemu_cpu_destroy(c);
    }
    {
        WemuCpu *c = boot_seg();
        setup_np(c);
        wemu_cpu_set_cpl(c, 3);
        wemu_cpu_set_int_target_cpl(c, 0);
        CHECK(wemu_cpu_deliver_int(c, 40) == -1, "NP case: rejected");
        CHECK(wemu_cpu_step(c) == 1, "#NP delivered");
        CHECK(wemu_cpu_exception_vector(c) == 11, "delivered vector == #NP");
        CHECK(wemu_cpu_exception_error(c) == NP_CS_SEL, "#NP delivered error");
        CHECK(wemu_cpu_rip(c) == NP_HANDLER, "#NP reaches its handler");
        wemu_cpu_destroy(c);
    }
}

/* ---- valid GDT/TSS state does not block a software INT ---------------- */
static void test_valid_segments_pass(void) {
    WemuCpu *c = boot_seg();
    wemu_cpu_set_cpl(c, 3);
    wemu_cpu_set_int_target_cpl(c, 0);
    wemu_cpu_tss_set_ss(c, 0, SS_SEL);
    CHECK(wemu_cpu_deliver_int(c, 40) == 0, "valid segments: INT accepted");
    CHECK(wemu_cpu_rip(c) == HANDLER, "valid INT reaches handler");
    CHECK(wemu_cpu_fault(c) == 0, "valid INT latches no fault");
    wemu_cpu_destroy(c);
}

/* ---- frame-push failure feeds the #DF latch --------------------------- */
static void test_frame_push_df(void) {
    const uint8_t ud2[] = { 0x0F, 0x0B };
    WemuCpu *c = wemu_cpu_create(RAMSZ);
    wemu_cpu_set_rip(c, CODE);
    wemu_cpu_set_rsp(c, BADSTACK);     /* first push lands outside RAM */
    set_gate(c, 6, UD_HANDLER, 0xE, 0, CS_SEL, 1);  /* #UD: present */
    set_gate(c, 8, DF_HANDLER, 0xE, 0, CS_SEL, 1);  /* #DF: present */
    CHECK(wemu_cpu_idt_load(c, IDT_BASE, IDT_LIMIT) == 0, "load IDTR");
    (void)wemu_cpu_load(c, CODE, ud2, sizeof ud2);

    CHECK(wemu_cpu_double_faults(c) == 0, "no #DF before the fault");
    CHECK(wemu_cpu_step(c) == -1, "frame-push #GP stops delivery");
    CHECK(wemu_cpu_fault(c) == 13, "secondary #GP latched");
    CHECK(wemu_cpu_fault_error(c) == 0, "secondary #GP error 0");
    CHECK(wemu_cpu_rip(c) == CODE, "no handler transfer after push fault");
    CHECK(wemu_cpu_reg(c, 4) == BADSTACK, "RSP unchanged: no partial frame");
    CHECK(wemu_cpu_exception_vector(c) == 0, "no successful delivery");
    CHECK(wemu_cpu_double_fault_latched(c) != 0, "#DF latch set");
    CHECK(wemu_cpu_double_faults(c) == 1, "exactly one #DF latched");
    CHECK(wemu_cpu_double_fault_source(c) == 13, "#DF source = #GP (13)");
    CHECK(wemu_cpu_double_fault_source_error(c) == 0, "#DF source error 0");
    printf("framepush: fault=%d err=0x%llx df=%u src=%u "
           "srcerr=0x%llx rip=0x%llx\n",
           wemu_cpu_fault(c), (unsigned long long)wemu_cpu_fault_error(c),
           wemu_cpu_double_faults(c), wemu_cpu_double_fault_source(c),
           (unsigned long long)wemu_cpu_double_fault_source_error(c),
           (unsigned long long)wemu_cpu_rip(c));
    wemu_cpu_destroy(c);
}

int main(void) {
    test_ts_bad_tss();
    test_ss_stack();
    test_np_code();
    test_valid_segments_pass();
    test_frame_push_df();
    if (fails) {
        printf("test_segments: %d/%d CHECK(S) FAILED\n", fails, checks);
        return 1;
    }
    printf("test_segments: PASS (%d checks; frame-push #DF + "
           "GDT/TSS #TS/#SS/#NP)\n", checks);
    return 0;
}
#endif
