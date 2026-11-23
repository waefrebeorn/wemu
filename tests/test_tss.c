/* test_tss.c — differential gate for bounded 64-bit TSS descriptor parsing
 * (LTR-like load) and TSS-supplied RSP0/SS0 on a ring-3 -> ring-0 INT.
 *
 * Every expectation is written from the SDM / the 64-bit TSS layout, not
 * from the implementation:
 *   - LTR reads a 16-byte system descriptor from the bounded GDT and
 *     validates null / TI / GDT limit / type / busy / present / reserved;
 *   - base[63:0] and limit[19:0] are assembled from both descriptor halves;
 *   - RSP0/1/2 come from TSS +0x04/0x0c/0x14, WEMU's SS slots from +0x1c..;
 *   - bad descriptors latch #GP/#NP/#TS with a selector error code;
 *   - the descriptor is marked busy by the load.
 * The positive case drives a REAL guest INT 0x2a from CPL 3 through the
 * loaded IDT and checks the handler's CPL/CS/SS/RSP against the TSS image —
 * no host RSP0/SS0 setter is used to supply the winning values (stale,
 * deliberately wrong host values are set first and must be overwritten).
 *
 * NEGATIVE CONTROL: this SAME source compiled against the pre-change
 * library (d97508e, no WEMU_HAS_LTR_TSS) prints FAIL and exits 1.
 */
#include "wemu.h"
#include <stdio.h>
#include <string.h>

#ifndef WEMU_HAS_LTR_TSS
int main(void) {
    printf("FAIL: WEMU_HAS_LTR_TSS absent — pre-change WEMU has no LTR/TSS "
           "descriptor parse and only host-set RSP0/SS0; the guest INT could "
           "not take its stack from a guest TSS\n");
    return 1;
}
#else

static int fails, checks;
#define CHECK(c, m) do { checks++; if (!(c)) { \
    printf("FAIL: %s (line %d)\n", m, __LINE__); fails++; } } while (0)

#define RAMSZ      (1u << 20)
#define CODE       0x1000u
#define IDT_BASE   0x2000u
#define IDT_LIMIT  0x0fffu
#define GDT_BASE   0x3000u
#define GDT_LIMIT  0x0fffu
#define TSS_BASE   0x4000u
#define TSS_LIMIT  0x67u        /* full 103-byte 64-bit TSS */
#define HANDLER    0x6000u
#define U_RSP      0x80000u
#define TSS_RSP0   0x70000u
#define TSS_SS0    0x0010u      /* ring-0 data selector from the GDT */
#define VEC        0x2Au        /* INT 42: no error code */

#define KCS        0x08u        /* idx1: present code DPL0 */
#define KSS        0x10u        /* idx2: present RW data DPL0 */
#define UCS        0x1Bu        /* idx3: present code DPL3 */
#define USS        0x23u        /* idx4: present RW data DPL3 */
#define TSS_SEL    0x28u        /* idx5: 64-bit TSS descriptor (idx5+idx6) */
#define STALE_RSP  0x90000u
#define STALE_SS   0x0033u

/* P|DPL|S|type: 0x89 = available 64-bit TSS (type 9, S=0, P=1, DPL=0). */
#define TSS_AVAIL  0x89u
#define TSS_BUSY   0x8Bu

static void set_gate(WemuCpu *c, unsigned v, uint64_t off, uint8_t type,
                     uint8_t dpl, uint16_t sel, int present) {
    uint8_t g[16];
    memset(g, 0, sizeof g);
    g[0] = (uint8_t)off;         g[1] = (uint8_t)(off >> 8);
    g[2] = (uint8_t)sel;         g[3] = (uint8_t)(sel >> 8);
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

/* A 16-byte 64-bit TSS descriptor: lower half has limit15:0 / base15:0 /
 * base23:16 / access / limit19:16 / base31:24; upper half has base63:32
 * followed by three reserved dwords that LTR must check are zero. */
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

/* RSP0/1/2 at the architectural 64-bit TSS offsets; SS0/1/2 in WEMU's
 * documented reserved-area slots. */
static void set_tss_image(WemuCpu *c, uint64_t rsp0, uint16_t ss0) {
    uint8_t t[0x22];
    uint64_t rsp1 = 0, rsp2 = 0;
    uint16_t ss1 = 0, ss2 = 0;
    memset(t, 0, sizeof t);
    memcpy(t + 0x04, &rsp0, 8);
    memcpy(t + 0x0c, &rsp1, 8);
    memcpy(t + 0x14, &rsp2, 8);
    memcpy(t + 0x1c, &ss0, 2);
    memcpy(t + 0x1e, &ss1, 2);
    memcpy(t + 0x20, &ss2, 2);
    (void)wemu_mem_write(c, TSS_BASE, t, sizeof t);
}

static uint64_t frame_qword(WemuCpu *c, uint64_t sp, int idx) {
    uint64_t v = 0;
    (void)wemu_mem_read(c, sp + (uint64_t)idx * 8, &v, 8);
    return v;
}

static WemuCpu *boot(void) {
    WemuCpu *c = wemu_cpu_create(RAMSZ);
    wemu_cpu_set_rip(c, CODE);
    set_gate(c, VEC, HANDLER, 0xE, 3, KCS, 1); /* DPL3: ring 3 may INT */
    CHECK(wemu_cpu_idt_load(c, IDT_BASE, IDT_LIMIT) == 0, "load IDTR");
    set_desc(c, KCS, 0x9A);                     /* present code DPL0 */
    set_desc(c, KSS, 0x92);                     /* present RW data DPL0 */
    set_desc(c, UCS, 0xFA);                     /* present code DPL3 */
    set_desc(c, USS, 0xF2);                     /* present RW data DPL3 */
    set_tss_desc(c, TSS_SEL, TSS_AVAIL, TSS_BASE, TSS_LIMIT, 0);
    CHECK(wemu_cpu_gdt_load(c, GDT_BASE, GDT_LIMIT) == 0, "load GDTR");
    set_tss_image(c, TSS_RSP0, TSS_SS0);
    return c;
}

/* ---- positive: TSS descriptor drives the ring-3 -> ring-0 INT --------- */
static void test_tss_drives_ring0_switch(void) {
    WemuCpu *c = boot();
    const uint8_t code[] = { 0xCD, VEC, 0xF4 }; /* INT 42; HLT */
    const uint8_t iret[] = { 0xCF };
    WemuTssDescriptor d;
    uint8_t access = 0;

    /* Deliberately poison the legacy host setters.  A correct LTR must
     * overwrite them from guest TSS memory. */
    wemu_cpu_tss_set_rsp(c, 0, STALE_RSP);
    wemu_cpu_tss_set_ss(c, 0, STALE_SS);

    CHECK(!wemu_cpu_tr_loaded(c), "TR not loaded before LTR");
    CHECK(wemu_cpu_ltr(c, TSS_SEL, &d) == 0, "LTR accepts available TSS");
    CHECK(wemu_cpu_fault(c) == 0, "LTR latches no fault");
    CHECK(d.base == TSS_BASE && d.limit == TSS_LIMIT,
          "descriptor base/limit assembled from both halves");
    CHECK(d.selector == TSS_SEL && d.type == 0x9 && d.dpl == 0 &&
          d.present == 1 && d.busy == 1, "descriptor fields parsed");
    CHECK(wemu_cpu_tr_loaded(c) && wemu_cpu_tr(c) == TSS_SEL, "TR loaded");
    CHECK(wemu_cpu_tr_base(c) == TSS_BASE && wemu_cpu_tr_limit(c) == TSS_LIMIT,
          "TR caches descriptor base/limit");
    CHECK(wemu_mem_read(c, GDT_BASE + (TSS_SEL >> 3) * 8 + 5, &access, 1) == 0 &&
          access == TSS_BUSY, "descriptor marked busy in guest GDT");
    CHECK(wemu_cpu_tss_rsp(c, 0) == TSS_RSP0,
          "RSP0 loaded from TSS (overwrote stale host value)");
    CHECK(wemu_cpu_tss_ss(c, 0) == TSS_SS0,
          "SS0 loaded from TSS (overwrote stale host value)");

    /* Loading the same selector again faults: the descriptor is now busy. */
    CHECK(wemu_cpu_ltr(c, TSS_SEL, NULL) == -1, "second LTR on busy TSS fails");
    CHECK(wemu_cpu_fault(c) == 13 && wemu_cpu_fault_error(c) == TSS_SEL,
          "busy TSS -> #GP(selector)");
    wemu_cpu_clear_fault(c);

    /* Real guest execution: INT 42 from ring 3 through the loaded IDT. */
    CHECK(wemu_cpu_load(c, CODE, code, sizeof code) == 0, "load guest");
    CHECK(wemu_cpu_load(c, HANDLER, iret, sizeof iret) == 0, "load handler");
    wemu_cpu_set_cpl(c, 3);
    wemu_cpu_set_cs(c, UCS);
    wemu_cpu_set_ss(c, USS);
    wemu_cpu_set_rsp(c, U_RSP);

    CHECK(wemu_cpu_step(c) == 1, "guest INT n executed");
    CHECK(wemu_cpu_fault(c) == 0, "INT delivered without fault");
    CHECK(wemu_cpu_rip(c) == HANDLER, "INT reaches handler");
    CHECK(wemu_cpu_cpl(c) == 0, "ring 3 -> ring 0");
    CHECK(wemu_cpu_cs(c) == KCS, "CS reloaded from gate");
    CHECK(wemu_cpu_ss(c) == TSS_SS0, "SS came from TSS SS0, not stale host SS");
    uint64_t sp = wemu_cpu_reg(c, 4);
    CHECK(sp == TSS_RSP0 - 5 * 8, "handler stack based on TSS RSP0");
    CHECK(frame_qword(c, sp, 0) == CODE + 2, "frame RIP = after INT");
    CHECK(frame_qword(c, sp, 1) == UCS, "frame CS = interrupted ring-3 CS");
    CHECK(frame_qword(c, sp, 3) == U_RSP, "frame old RSP = ring-3 RSP");
    CHECK(frame_qword(c, sp, 4) == USS, "frame old SS = ring-3 SS");

    printf("tss_switch: base=0x%llx limit=0x%x rsp0=0x%llx ss0=0x%x "
           "cpl=%d cs=0x%x ss=0x%x rsp=0x%llx\n",
           (unsigned long long)d.base, (unsigned)d.limit,
           (unsigned long long)wemu_cpu_tss_rsp(c, 0),
           (unsigned)wemu_cpu_tss_ss(c, 0), wemu_cpu_cpl(c),
           (unsigned)wemu_cpu_cs(c), (unsigned)wemu_cpu_ss(c),
           (unsigned long long)sp);
    wemu_cpu_destroy(c);
}

/* ---- negative controls: rejected descriptors, exact vector + error --- */
static void expect_ltr_fault(WemuCpu *c, uint16_t sel, int vec,
                             uint64_t err, const char *name) {
    CHECK(wemu_cpu_ltr(c, sel, NULL) == -1, name);
    CHECK(wemu_cpu_fault(c) == vec, "rejected descriptor: fault vector");
    CHECK(wemu_cpu_fault_error(c) == err, "rejected descriptor: error code");
    CHECK(!wemu_cpu_tr_loaded(c), "rejected descriptor: TR stays unloaded");
    printf("  %-24s -> vec=%u err=0x%llx\n", name,
           (unsigned)wemu_cpu_fault(c),
           (unsigned long long)wemu_cpu_fault_error(c));
    wemu_cpu_destroy(c);
}

static void test_bad_descriptors(void) {
    WemuCpu *c;

    c = boot();
    expect_ltr_fault(c, 0x00, 13, 0x00, "null selector");

    c = boot();
    expect_ltr_fault(c, 0x2C, 13, 0x2C, "TI=1 (LDT selector)");

    c = boot();
    CHECK(wemu_cpu_gdt_load(c, GDT_BASE, 0x20) == 0, "shrink GDT limit");
    expect_ltr_fault(c, TSS_SEL, 13, TSS_SEL, "past GDT limit");

    c = boot();
    set_tss_desc(c, TSS_SEL, 0x9A, TSS_BASE, TSS_LIMIT, 0); /* code type */
    expect_ltr_fault(c, TSS_SEL, 13, TSS_SEL, "not a TSS (code)");

    c = boot();
    set_tss_desc(c, TSS_SEL, TSS_BUSY, TSS_BASE, TSS_LIMIT, 0);
    expect_ltr_fault(c, TSS_SEL, 13, TSS_SEL, "busy TSS");

    c = boot();
    set_tss_desc(c, TSS_SEL, 0x09, TSS_BASE, TSS_LIMIT, 0); /* P=0 */
    expect_ltr_fault(c, TSS_SEL, 11, TSS_SEL, "not present");

    c = boot();
    set_tss_desc(c, TSS_SEL, TSS_AVAIL, TSS_BASE, 0x10, 0); /* short limit */
    expect_ltr_fault(c, TSS_SEL, 10, TSS_SEL, "TSS limit too small");

    c = boot();
    set_tss_desc(c, TSS_SEL, TSS_AVAIL, RAMSZ, TSS_LIMIT, 0);
    expect_ltr_fault(c, TSS_SEL, 10, TSS_SEL, "TSS outside guest RAM");

    c = boot();
    set_tss_desc(c, TSS_SEL, TSS_AVAIL, TSS_BASE, TSS_LIMIT, 1);
    expect_ltr_fault(c, TSS_SEL, 13, TSS_SEL, "upper reserved != 0");

    c = boot();
    wemu_cpu_set_cpl(c, 3);
    expect_ltr_fault(c, TSS_SEL, 13, 0x00, "CPL != 0");
}

static void test_ltr_str_opcodes(void) {
    WemuCpu *c = boot();
    /* mov ax,TSS_SEL; ltr ax; str ax; hlt — exercises the actual 0F 00
     * /3 and /1 opcodes the kernel uses (host wemu_cpu_ltr is not enough). */
    uint8_t code[] = {
        0x66,0xB8,(uint8_t)TSS_SEL,(uint8_t)(TSS_SEL >> 8),
        0x0F,0x00,0xD8,             /* LTR AX */
        0x0F,0x00,0xC8,             /* STR AX */
        0xF4
    };
    wemu_cpu_load(c, CODE, code, sizeof code);
    wemu_cpu_run(c, 12);
    CHECK(wemu_cpu_fault(c) == 0, "LTR/STR opcodes faulted");
    CHECK((uint16_t)wemu_cpu_reg(c, 0) == TSS_SEL,
          "STR did not report the loaded TSS selector");
    wemu_cpu_destroy(c);
}

int main(void) {
    test_tss_drives_ring0_switch();
    test_bad_descriptors();
    test_ltr_str_opcodes();
    if (fails) {
        printf("test_tss: %d/%d CHECK(S) FAILED\n", fails, checks);
        return 1;
    }
    printf("test_tss: PASS (%d checks; LTR descriptor parse + TSS RSP0/SS0 "
           "ring-3 INT + #GP/#NP/#TS negatives)\n", checks);
    return 0;
}
#endif
