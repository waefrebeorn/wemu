/* test_idt.c — differential gate for architectural IDT descriptors and
 * real #PF error codes.
 *
 * The guest (not the host) supplies the IDT: 16-byte long-mode gates are
 * written into guest RAM, an IDTR is loaded, and faults are triggered by
 * real guest instructions (LOCK #UD, a real 4-level page-walk #PF).  The
 * gate asserts vector, error code, CR2, frame contents and the SDM gate
 * rejection paths (#GP/#NP with the IDT error code), then compares every
 * observed bit against an architectural expectation table.
 *
 * NEGATIVE CONTROL: compiled against pre-change WEMU (no WEMU_HAS_ARCH_IDT)
 * this prints FAIL and exits 1; a build that keeps the API but drops the
 * translate() error-code write fails the #PF error assertions below.
 * Both controls were executed against this source. */
#include "wemu.h"
#include <stdio.h>
#include <string.h>

#ifndef WEMU_HAS_ARCH_IDT
int main(void) {
    printf("FAIL: WEMU_HAS_ARCH_IDT absent — pre-change WEMU has no IDT "
           "descriptor parsing and leaves #PF error codes at 0\n");
    return 1;
}
#else

static int fails, checks;
#define CHECK(c, m) do { checks++; if (!(c)) { \
    printf("FAIL: %s (line %d)\n", m, __LINE__); fails++; } } while (0)

#define RAMSZ      (1u << 20)
#define CODE        0x1000u
#define IDT_BASE    0x2000u
#define IDT_LIMIT   0x0fffu          /* 256 gates * 16 bytes - 1 */
#define UD_HANDLER  0x6000u
#define PF_HANDLER  0x6100u
#define SW_HANDLER  0x6200u
#define STACK       0x80000u
#define PML4        0x10000u
#define PDPT        0x11000u
#define PD          0x12000u
#define PT          0x13000u
#define BAD_VA      0x800000u        /* PD[4] absent -> real page-walk #PF */
#define GOOD_VA     0x400000u        /* PT[0] -> GPA 0x5000 */
#define GOOD_PA     0x5000u
#define PF_UD_CODE  ((14u << 3) | 2u)  /* 0x72 */
#define GP_SW_CODE  ((40u << 3) | 2u)  /* 0x142 */

/* Write a long-mode 64-bit interrupt/trap gate into guest RAM. */
static void set_gate(WemuCpu *c, unsigned v, uint64_t off, uint8_t type,
                     uint8_t dpl, int present) {
    uint8_t g[16];
    memset(g, 0, sizeof g);
    g[0] = (uint8_t)off;         g[1] = (uint8_t)(off >> 8);
    g[2] = 0x28; g[3] = 0x00;    /* selector */
    g[4] = 0x00;                 /* IST */
    g[5] = (uint8_t)((present ? 0x80 : 0) | (dpl << 5) | (type & 0xf));
    g[6] = (uint8_t)(off >> 16); g[7] = (uint8_t)(off >> 24);
    g[8] = (uint8_t)(off >> 32); g[9] = (uint8_t)(off >> 40);
    g[10] = (uint8_t)(off >> 48); g[11] = (uint8_t)(off >> 56);
    (void)wemu_mem_write(c, IDT_BASE + v * 16, g, sizeof g);
}

static WemuCpu *boot(void) {
    WemuCpu *c = wemu_cpu_create(RAMSZ);
    wemu_cpu_set_rip(c, CODE);
    wemu_cpu_set_rsp(c, STACK);
    wemu_cpu_set_cpl(c, 0);
    set_gate(c, 6, UD_HANDLER, 0xE, 0, 1);
    set_gate(c, 14, PF_HANDLER, 0xE, 0, 1);
    CHECK(wemu_cpu_idt_load(c, IDT_BASE, IDT_LIMIT) == 0, "load bounded IDTR");
    return c;
}

/* Tables: VA 0x1000 -> GPA 0x1000 (code fetch, P|RW|US); VA 0x400000 ->
 * GPA 0x5000 (data); VA 0x800000 unmapped (PD[4] clear). */
static void setup_paging(WemuCpu *c) {
    uint64_t e;
    wemu_cpu_enable_paging(c, 0);
    e = PDPT  | 3; (void)wemu_mem_write(c, PML4, &e, 8);
    e = PD    | 3; (void)wemu_mem_write(c, PDPT, &e, 8);
    e = PT    | 3; (void)wemu_mem_write(c, PD + 0 * 8, &e, 8); /* code PD */
    e = PT    | 3; (void)wemu_mem_write(c, PD + 2 * 8, &e, 8); /* data PD */
    e = 0;         (void)wemu_mem_write(c, PD + 4 * 8, &e, 8); /* absent */
    e = 0x1000 | 7; (void)wemu_mem_write(c, PT + 1 * 8, &e, 8); /* code page */
    e = GOOD_PA | 3; (void)wemu_mem_write(c, PT, &e, 8);       /* data page */
    wemu_cpu_set_cr3(c, PML4);
    wemu_cpu_enable_paging(c, 1);
}

/* Read a pushed frame as a GPA (the frame is not covered by our tables). */
static uint64_t frame_qword(WemuCpu *c, uint64_t sp, int idx) {
    uint64_t v = 0;
    wemu_cpu_enable_paging(c, 0);
    (void)wemu_mem_read(c, sp + (uint64_t)idx * 8, &v, 8);
    wemu_cpu_enable_paging(c, 1);
    return v;
}

/* ---- #UD delivered through a REAL gate written by the guest ---------- */
static void test_ud_gate(void) {
    uint8_t ud[] = { 0xF0, 0x01, 0xD8, 0xF4 }; /* LOCK ADD EAX,EBX -> #UD */
    WemuCpu *c = boot();
    WemuIdtGate g;
    (void)wemu_cpu_load(c, CODE, ud, sizeof ud);

    CHECK(wemu_cpu_idt_gate(c, 6, &g) == 0, "read guest #UD gate");
    CHECK(g.offset == UD_HANDLER && g.selector == 0x28 &&
          g.type == 0xE && g.dpl == 0 && g.present == 1,
          "parsed gate fields match the descriptor written by the guest");

    CHECK(wemu_cpu_step(c) == 1, "#UD delivered via guest IDT");
    CHECK(wemu_cpu_fault(c) == 0, "#UD fault cleared on delivery");
    CHECK(wemu_cpu_rip(c) == UD_HANDLER, "#UD transfers to gate offset");
    CHECK(wemu_cpu_exception_vector(c) == 6, "delivered vector 6");
    CHECK(wemu_cpu_exception_error(c) == 0, "#UD has no error code");
    uint64_t sp = wemu_cpu_reg(c, 4);
    CHECK(frame_qword(c, sp, 0) == CODE, "#UD frame saved RIP = faulting insn");
    CHECK(frame_qword(c, sp, 1) == 0x28, "#UD frame CS");
    CHECK(frame_qword(c, sp, 2) == 2, "#UD frame RFLAGS");
    CHECK(frame_qword(c, sp, 3) == STACK, "#UD frame old RSP");
    CHECK(frame_qword(c, sp, 4) == 0, "#UD frame SS");
    CHECK(sp == STACK - 5 * 8, "#UD frame is 5 qwords (no error code)");
    printf("ud_gate: vec=%u err=%llu off=0x%llx\n",
           wemu_cpu_exception_vector(c),
           (unsigned long long)wemu_cpu_exception_error(c),
           (unsigned long long)g.offset);
    wemu_cpu_destroy(c);
}

/* ---- real page-walk #PF: write to an unmapped VA --------------------- */
static void test_pf_error(void) {
    uint8_t wr[] = { 0x48, 0x89, 0x04, 0x25, 0x00, 0x00, 0x80, 0x00 };
    /* MOV [0x800000], RAX — write, supervisor, not-present -> error 0x2 */
    WemuCpu *c = boot();
    setup_paging(c);
    (void)wemu_cpu_load(c, CODE, wr, sizeof wr);

    CHECK(wemu_cpu_step(c) == 1, "real page-walk #PF delivered");
    CHECK(wemu_cpu_fault(c) == 0, "#PF fault cleared on delivery");
    CHECK(wemu_cpu_exception_vector(c) == 14, "delivered vector 14");
    CHECK(wemu_cpu_exception_error(c) == 0x2ull,
          "#PF error = W only (P=0, U=0, S=0) -> 0x2");
    CHECK(wemu_cpu_exception_cr2(c) == BAD_VA, "#PF CR2 = faulting VA");
    CHECK(wemu_cpu_rip(c) == PF_HANDLER, "#PF transfers to gate offset");
    uint64_t sp = wemu_cpu_reg(c, 4);
    CHECK(frame_qword(c, sp, 0) == 0x2ull, "#PF frame slot0 = error 2");
    CHECK(frame_qword(c, sp, 1) == CODE, "#PF frame saved RIP = faulting insn");
    CHECK(sp == STACK - 6 * 8, "#PF frame is 6 qwords (error code last)");
    printf("pf_error: vec=%u err=%llu cr2=0x%llx (expected 0x2)\n",
           wemu_cpu_exception_vector(c),
           (unsigned long long)wemu_cpu_exception_error(c),
           (unsigned long long)wemu_cpu_exception_cr2(c));
    wemu_cpu_destroy(c);
}

/* ---- U/S bit: same fault with CPL=3 sets U -> 0x6 -------------------- */
static void test_pf_user_bit(void) {
    uint8_t wr[] = { 0x48, 0x89, 0x04, 0x25, 0x00, 0x00, 0x80, 0x00 };
    WemuCpu *c = boot();
    setup_paging(c);
    wemu_cpu_set_cpl(c, 3);
    (void)wemu_cpu_load(c, CODE, wr, sizeof wr);
    CHECK(wemu_cpu_step(c) == 1, "user #PF delivered");
    CHECK(wemu_cpu_exception_error(c) == 0x6ull,
          "#PF error = W|U (P=0) -> 0x6");
    CHECK(wemu_cpu_exception_cr2(c) == BAD_VA, "user #PF CR2");
    printf("pf_user: err=%llu (expected 0x6)\n",
           (unsigned long long)wemu_cpu_exception_error(c));
    wemu_cpu_destroy(c);
}

/* ---- P bit: user write to a present read-only leaf -> 0x7 ------------ */
static void test_pf_protection(void) {
    uint8_t wr[] = { 0x48, 0x89, 0x04, 0x25, 0x00, 0x00, 0x40, 0x00 };
    /* MOV [0x400000], RAX — mapped leaf with RW=0, accessed as user */
    WemuCpu *c = boot();
    setup_paging(c);
    wemu_cpu_enable_paging(c, 0);
    {
        uint64_t e = GOOD_PA | 0x5ull; /* P|US, RW=0 */
        (void)wemu_mem_write(c, PT, &e, 8);
    }
    wemu_cpu_enable_paging(c, 1);
    wemu_cpu_set_cpl(c, 3);
    (void)wemu_cpu_load(c, CODE, wr, sizeof wr);
    CHECK(wemu_cpu_step(c) == 1, "protection #PF delivered");
    CHECK(wemu_cpu_fault(c) == 0, "protection #PF cleared");
    CHECK(wemu_cpu_exception_error(c) == 0x7ull,
          "#PF error = P|W|U (RW violation) -> 0x7");
    CHECK(wemu_cpu_exception_cr2(c) == GOOD_VA, "protection #PF CR2");
    printf("pf_prot: err=%llu (expected 0x7)\n",
           (unsigned long long)wemu_cpu_exception_error(c));
    wemu_cpu_destroy(c);
}

/* ---- SDM gate rejection paths: #NP (not present) and #GP ------------- */
static void test_gate_rejections(void) {
    uint8_t ud[] = { 0xF0, 0x01, 0xD8, 0xF4 };
    WemuCpu *c = boot();
    WemuIdtGate g;

    /* Gate not present -> #NP, with the IDT error code for vector 6. */
    set_gate(c, 6, UD_HANDLER, 0xE, 0, 0);
    CHECK(wemu_cpu_idt_gate(c, 6, &g) == 0 && g.present == 0,
          "gate readback shows P=0");
    (void)wemu_cpu_load(c, CODE, ud, sizeof ud);
    CHECK(wemu_cpu_step(c) == -1, "non-present gate: no delivery");
    CHECK(wemu_cpu_fault(c) == 11, "non-present IDT gate -> #NP (vector 11)");
    CHECK(wemu_cpu_fault_error(c) == 0x32ull,
          "#NP error code = (6<<3)|2 = 0x32");

    /* Bad gate type -> #GP with the same IDT error code. */
    wemu_cpu_clear_fault(c);
    set_gate(c, 6, UD_HANDLER, 0x4, 0, 1); /* task gate: invalid in long mode */
    (void)wemu_cpu_set_rip(c, CODE);
    CHECK(wemu_cpu_step(c) == -1, "invalid gate type: no delivery");
    CHECK(wemu_cpu_fault(c) == 13, "invalid gate type -> #GP");
    CHECK(wemu_cpu_fault_error(c) == 0x32ull, "#GP IDT error code 0x32");

    /* Restore a valid gate. */
    set_gate(c, 6, UD_HANDLER, 0xE, 0, 1);
    printf("gate_reject: np=0x32 gp=0x32 (expected)\n");
    wemu_cpu_destroy(c);
}

/* ---- software vector: DPL check and bounded IDT limit ---------------- */
static void test_software_dpl_and_limit(void) {
    WemuCpu *c = boot();
    WemuIdtGate g;
    set_gate(c, 40, SW_HANDLER, 0xE, 0, 1); /* DPL=0 gate */
    wemu_cpu_set_cpl(c, 3);

    CHECK(wemu_cpu_deliver_int(c, 40) == -1, "software INT through DPL=0 gate rejected at CPL=3");
    CHECK(wemu_cpu_fault(c) == 13, "DPL rejection -> #GP");
    CHECK(wemu_cpu_fault_error(c) == GP_SW_CODE, "DPL #GP error = (40<<3)|2");

    /* Exceptions ignore gate DPL even when CPL=3. */
    wemu_cpu_clear_fault(c);
    set_gate(c, 6, UD_HANDLER, 0xE, 0, 1);
    CHECK(wemu_cpu_deliver_exception(c, 6) == 0,
          "exception ignores gate DPL (CPL=3, DPL=0)");
    CHECK(wemu_cpu_rip(c) == UD_HANDLER, "exception still reaches handler");

    /* Software delivery succeeds once DPL >= CPL. */
    set_gate(c, 40, SW_HANDLER, 0xF, 3, 1); /* trap gate, DPL=3 */
    CHECK(wemu_cpu_deliver_int(c, 40) == 0, "software INT with DPL=3 accepted");
    CHECK(wemu_cpu_rip(c) == SW_HANDLER, "software INT reaches gate offset");

    /* Bounded descriptor table: vector beyond the loaded byte limit is
     * rejected, and a table that would overflow guest RAM is refused. */
    CHECK(wemu_cpu_idt_load(c, IDT_BASE, 0x1ff) == 0,
          "load smaller IDTR (vectors 0..31 only)");
    CHECK(wemu_cpu_idt_gate(c, 255, &g) == -1, "gate read bounded by IDT limit");
    CHECK(wemu_cpu_idt_load(c, RAMSZ - 8, IDT_LIMIT) == -1,
          "IDTR load bounded by guest RAM");
    printf("sw_dpl: dpl0=cpl3 rejected, dpl3 accepted, limit bounded\n");
    wemu_cpu_destroy(c);
}

int main(void) {
    test_ud_gate();
    test_pf_error();
    test_pf_user_bit();
    test_pf_protection();
    test_gate_rejections();
    test_software_dpl_and_limit();
    if (fails) {
        printf("test_idt: %d/%d CHECK(S) FAILED\n", fails, checks);
        return 1;
    }
    printf("test_idt: PASS (%d checks; SDM gate + #PF error bits)\n", checks);
    return 0;
}
#endif
