/* test_task_gpr.c — differential gate for full GPR save/restore in the TSS
 * on hardware task switches.
 *
 * A nested A->B->C->B->A task chain runs through far task CALLs and back-link
 * IRETs.  Each task has a DISTINCT 16-register sentinel pattern in its full
 * TSS image (limit 0xc8).  The expected values are built independently from
 * the SDM-style WEMU TSS layout at +0x48..+0xc7, so the gate verifies both
 * directions: the suspended task's registers are written into its own TSS,
 * and the entering task's registers are loaded from its TSS.  A bounded
 * check confirms a legacy-size TSS (limit 0x67) is left untouched.
 *
 * Only APIs that already exist in pre-change WEMU are used, so this source
 * compiles and RUNS against the old library: old WEMU saves only
 * CS/SS/RIP/RSP/RFLAGS and leaves the GPR area zero, so the checks fail.
 */
#include "wemu.h"
#include <stdio.h>
#include <string.h>

static int fails, checks;
#define CHECK(c, m) do { checks++; if (!(c)) { \
    printf("FAIL: %s (line %d)\n", m, __LINE__); fails++; } } while (0)

#define RAMSZ     (1u << 20)
#define GDT_BASE  0x4000u
#define GDT_LIMIT 0x1ffu
#define TSS_A_BASE 0x10000u
#define TSS_B_BASE 0x20000u
#define TSS_C_BASE 0x30000u
#define TSS_LIMIT 0xc8u          /* full task-state image */
#define LEGACY_LIMIT 0x67u       /* old CS/SS/RIP/RSP/RFLAGS-only image */
#define KCS       0x08u
#define KSS       0x10u
#define TSS_A_SEL 0x18u
#define TSS_B_SEL 0x28u
#define TSS_C_SEL 0x38u
#define FAR_TSS_B 0xA000u
#define A_RSP     0xb0000u
#define B_RSP     0xc0000u
#define C_RSP     0xd0000u
#define GPR_BASE  0x48u
#define A_RESUME  0x1111u
#define B_RESUME  0x2222u

#define TSS_AVAIL 0x89u
#define TSS_BUSY  0x8bu
#define SENT_A 0xA5A5A5A5A5A5A5A5ull

static const uint64_t rsp_of[3] = { A_RSP, B_RSP, C_RSP };
static const uint64_t tss_base[3] = { TSS_A_BASE, TSS_B_BASE, TSS_C_BASE };
static const uint16_t tss_sel[3] = { TSS_A_SEL, TSS_B_SEL, TSS_C_SEL };

/* task t = 0(A)/1(B)/2(C), register i = 0(RAX)..15(R15).  RSP (i=4) is
 * loaded architecturally from TSS +0x38, so its sentinel is the stack base. */
static uint64_t sent(int t, int i) {
    static const uint64_t hi[3] = {
        0xA000000000000000ull, 0xB000000000000000ull, 0xC000000000000000ull
    };
    if (i == 4) return rsp_of[t];
    return hi[t] | ((uint64_t)(i + 1) << 8) | 0x5aull;
}

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

static void set_tss_image(WemuCpu *c, int t) {
    uint8_t img[0xc8];
    uint64_t gpr[16];
    uint16_t cs = KCS, ss = KSS;
    uint64_t rip = (t == 0) ? A_RESUME : ((t == 1) ? B_RESUME : 0x3333u);
    uint64_t rsp = rsp_of[t], fl = 0x202ull;
    for (int i = 0; i < 16; i++) gpr[i] = sent(t, i);
    memset(img, 0, sizeof img);
    memcpy(img + 0x28, &cs, 2);
    memcpy(img + 0x2a, &ss, 2);
    memcpy(img + 0x30, &rip, 8);
    memcpy(img + 0x38, &rsp, 8);
    memcpy(img + 0x40, &fl, 8);
    memcpy(img + GPR_BASE, gpr, sizeof gpr);
    /* RSP0/SS0 for LTR. */
    memcpy(img + 0x04, &rsp, 8);
    memcpy(img + 0x1c, &ss, 2);
    (void)wemu_mem_write(c, tss_base[t], img, sizeof img);
}

static uint16_t qword16(WemuCpu *c, uint64_t a) {
    uint16_t v = 0; (void)wemu_mem_read(c, a, &v, 2); return v;
}
static uint64_t qword64(WemuCpu *c, uint64_t a) {
    uint64_t v = 0; (void)wemu_mem_read(c, a, &v, 8); return v;
}

/* Check all 16 live GPRs against a task's expected snapshot. */
static void check_live_gprs(WemuCpu *c, int t, const char *where) {
    for (int i = 0; i < 16; i++) {
        if (wemu_cpu_reg(c, i) != sent(t, i)) {
            printf("FAIL: %s: R%d expected 0x%llx got 0x%llx (line %d)\n",
                   where, i, (unsigned long long)sent(t, i),
                   (unsigned long long)wemu_cpu_reg(c, i), __LINE__);
            fails++;
        }
        checks++;
    }
}

/* Check the GPR snapshot stored in a task's TSS image. */
static void check_saved_gprs(WemuCpu *c, int t, const char *where) {
    for (int i = 0; i < 16; i++) {
        uint64_t got = qword64(c, tss_base[t] + GPR_BASE + (uint64_t)i * 8);
        if (got != sent(t, i)) {
            printf("FAIL: %s: saved TSS%d R%d expected 0x%llx got 0x%llx "
                   "(line %d)\n", where, t, i, (unsigned long long)sent(t, i),
                   (unsigned long long)got, __LINE__);
            fails++;
        }
        checks++;
    }
}

static WemuCpu *boot(void) {
    WemuCpu *c = wemu_cpu_create(RAMSZ);
    set_desc(c, KCS, 0x9a);
    set_desc(c, KSS, 0x92);
    for (int t = 0; t < 3; t++) {
        set_tss_desc(c, tss_sel[t], tss_base[t], TSS_LIMIT);
        set_tss_image(c, t);
    }
    CHECK(wemu_cpu_gdt_load(c, GDT_BASE, GDT_LIMIT) == 0, "load GDTR");
    CHECK(wemu_cpu_ltr(c, TSS_A_SEL, NULL) == 0, "LTR on task A");
    wemu_cpu_set_cpl(c, 0);
    wemu_cpu_set_cs(c, KCS);
    wemu_cpu_set_ss(c, KSS);
    wemu_cpu_set_rip(c, A_RESUME + 1u);
    for (int i = 0; i < 16; i++) wemu_cpu_set_reg(c, i, sent(0, i));
    wemu_cpu_clear_fault(c);
    return c;
}

/* ---- nested chain A->B->C->B->A, GPRs at every level ------------------ */
static void test_chain(void) {
    WemuCpu *c = boot();

    CHECK(wemu_cpu_task_switch(c, TSS_B_SEL, A_RESUME, 1) == 0,
          "A->B task CALL succeeds");
    CHECK(wemu_cpu_fault(c) == 0 && wemu_cpu_tr(c) == TSS_B_SEL,
          "A->B faultless, TR = B");
    check_saved_gprs(c, 0, "A saved on A->B");
    check_live_gprs(c, 1, "B entered");
    CHECK(qword16(c, TSS_B_BASE + 0x00) == TSS_A_SEL, "B back-link = A");
    CHECK(qword64(c, TSS_A_BASE + 0x30) == A_RESUME, "A saved RIP = A_RESUME");

    CHECK(wemu_cpu_task_switch(c, TSS_C_SEL, B_RESUME, 1) == 0,
          "B->C task CALL succeeds");
    check_saved_gprs(c, 1, "B saved on B->C");
    check_live_gprs(c, 2, "C entered");
    CHECK(qword16(c, TSS_C_BASE + 0x00) == TSS_B_SEL, "C back-link = B");
    CHECK(qword64(c, TSS_B_BASE + 0x30) == B_RESUME, "B saved RIP = B_RESUME");

    CHECK(wemu_cpu_task_return(c) == 0, "C IRET returns to B");
    CHECK(wemu_cpu_task_nested(c), "B remains nested after C returned");
    CHECK(wemu_cpu_tr(c) == TSS_B_SEL, "TR back at B");
    check_saved_gprs(c, 2, "C saved on C->B");
    check_live_gprs(c, 1, "B restored");

    CHECK(wemu_cpu_task_return(c) == 0, "B IRET returns to A");
    CHECK(!wemu_cpu_task_nested(c), "NT clear back in A");
    CHECK(wemu_cpu_tr(c) == TSS_A_SEL, "TR back at A");
    CHECK(wemu_cpu_rip(c) == A_RESUME, "A RIP restored from TSS");
    check_saved_gprs(c, 1, "B saved on B->A");
    check_live_gprs(c, 0, "A final");
    CHECK(wemu_cpu_task_switches(c) == 4, "4 switches in the chain");

    printf("task_gpr: chain A->B->C->B->A rax=0x%llx rbx=0x%llx "
           "rcx=0x%llx switches=%u\n",
           (unsigned long long)wemu_cpu_reg(c, 0),
           (unsigned long long)wemu_cpu_reg(c, 3),
           (unsigned long long)wemu_cpu_reg(c, 1),
           wemu_cpu_task_switches(c));
    wemu_cpu_destroy(c);
}

/* ---- guest-executed far CALL through a TSS also snapshots GPRs -------- */
static void test_guest_far_call(void) {
    WemuCpu *c = boot();
    uint8_t fp[10];
    uint8_t b_code[] = { 0xF4 };  /* B: HLT */
    uint8_t a_code[] = {
        0x48, 0xB8, 0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5, /* movabs rax */
        0xFF, 0x1C, 0x25,
        (uint8_t)FAR_TSS_B, (uint8_t)(FAR_TSS_B >> 8),
        (uint8_t)(FAR_TSS_B >> 16), (uint8_t)(FAR_TSS_B >> 24)
    };
    memset(fp, 0, sizeof fp);
    fp[8] = (uint8_t)TSS_B_SEL; fp[9] = (uint8_t)(TSS_B_SEL >> 8);
    (void)wemu_mem_write(c, FAR_TSS_B, fp, sizeof fp);
    (void)wemu_cpu_load(c, B_RESUME, b_code, sizeof b_code);
    (void)wemu_cpu_load(c, A_RESUME, a_code, sizeof a_code);
    wemu_cpu_set_rip(c, A_RESUME);
    CHECK(wemu_cpu_run(c, 5) == 3 && wemu_cpu_halted(c),
          "guest far CALL to B reaches HLT");
    CHECK(wemu_cpu_fault(c) == 0 && wemu_cpu_tr(c) == TSS_B_SEL,
          "guest task CALL faultless");
    CHECK(wemu_cpu_reg(c, 0) == sent(1, 0) &&
          wemu_cpu_reg(c, 3) == sent(1, 3), "B GPRs loaded, A's RAX replaced");
    CHECK(qword64(c, TSS_A_BASE + GPR_BASE) == SENT_A,
          "guest far CALL saved A's RAX into A's TSS");
    wemu_cpu_destroy(c);
}

/* ---- bounded: legacy-size TSS keeps the old no-GPR behaviour ---------- */
static void test_bounded_legacy(void) {
    WemuCpu *c = boot();
    uint64_t before = qword64(c, TSS_A_BASE + GPR_BASE);
    set_tss_desc(c, TSS_B_SEL, TSS_B_BASE, LEGACY_LIMIT);
    CHECK(wemu_cpu_task_switch(c, TSS_B_SEL, A_RESUME, 0) == 0,
          "legacy-limit TSS switch still succeeds");
    CHECK(qword64(c, TSS_A_BASE + GPR_BASE) == before,
          "legacy TSS did not write a GPR snapshot into A");
    CHECK(wemu_cpu_reg(c, 0) == sent(0, 0) &&
          wemu_cpu_reg(c, 3) == sent(0, 3),
          "legacy TSS did not reload GPRs into B");
    wemu_cpu_destroy(c);
}

int main(void) {
    test_chain();
    test_guest_far_call();
    test_bounded_legacy();
    if (fails) {
        printf("test_task_gpr: %d/%d CHECK(S) FAILED\n", fails, checks);
        return 1;
    }
    printf("test_task_gpr: PASS (%d checks; full 16-GPR A->B->C->B->A chain, "
           "guest far CALL snapshot, bounded legacy TSS)\n", checks);
    return 0;
}
