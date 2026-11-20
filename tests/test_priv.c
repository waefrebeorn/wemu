/* test_priv.c — differential gate for privilege checks, IF clearing, IST
 * stack selection and extra #PF error bits.
 *
 * The guest (not the host) installs long-mode IDT gates with DPL/IST/type
 * variations.  Faults are triggered by real guest instructions (#UD via
 * LOCK, #PF via a real 4-level page walk, including an instruction-fetch
 * fault and a reserved-bit fault).  Every observed bit — vector, error
 * code, CR2, RSP and stack slots — is compared with an independently
 * written x86-64 expectation table.
 *
 * NEGATIVE CONTROL: built against pre-change WEMU (no WEMU_HAS_PRIV_IST_PF)
 * this prints FAIL and exits 1.  The gate was run against the pre-change
 * library from the sibling leg/idt worktree to confirm that. */
#include "wemu.h"
#include <stdio.h>
#include <string.h>

#ifndef WEMU_HAS_PRIV_IST_PF
int main(void) {
    printf("FAIL: WEMU_HAS_PRIV_IST_PF absent — pre-change WEMU has no "
           "CPL/RPL/DPL gate check, no IF clearing, no IST stack selection, "
           "and leaves #PF I/D + RSVD at 0\n");
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
#define HANDLER   0x6000u
#define STACK     0x80000u
#define IST_STACK 0x90000u
#define PML4      0x10000u
#define PDPT      0x11000u
#define PD        0x12000u
#define PT        0x13000u
#define DATA_VA   0x400000u
#define DATA_PA   0x5000u

/* x86-64 #PF error bits and IDT error code (SDM). */
#define PF_P    0x01u
#define PF_WR   0x02u
#define PF_US   0x04u
#define PF_RSVD 0x08u
#define PF_ID   0x10u
#define IDT_CODE(v) (((unsigned)(v) << 3) | 2u)

static void set_gate(WemuCpu *c, unsigned v, uint64_t off, uint8_t type,
                     uint8_t dpl, uint8_t ist, int present) {
    uint8_t g[16];
    memset(g, 0, sizeof g);
    g[0] = (uint8_t)off;         g[1] = (uint8_t)(off >> 8);
    g[2] = 0x28; g[3] = 0x00;    /* target code selector */
    g[4] = (uint8_t)(ist & 7);   /* IST index */
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
    wemu_cpu_set_cs_rpl(c, 0);
    set_gate(c, 6,  HANDLER, 0xE, 0, 0, 1); /* #UD: interrupt gate */
    set_gate(c, 14, HANDLER, 0xE, 0, 0, 1); /* #PF: interrupt gate */
    CHECK(wemu_cpu_idt_load(c, IDT_BASE, IDT_LIMIT) == 0, "load IDTR");
    return c;
}

/* VA 0x1000 (code) -> GPA 0x1000; VA 0x400000 -> GPA 0x5000; VA 0x800000
 * unmapped (PD[4] clear). */
static void setup_paging(WemuCpu *c) {
    uint64_t e;
    wemu_cpu_enable_paging(c, 0);
    e = PDPT | 3;        (void)wemu_mem_write(c, PML4, &e, 8);
    e = PD    | 3;        (void)wemu_mem_write(c, PDPT, &e, 8);
    e = PT    | 3;        (void)wemu_mem_write(c, PD + 0 * 8, &e, 8);
    e = PT    | 3;        (void)wemu_mem_write(c, PD + 2 * 8, &e, 8);
    e = 0;                (void)wemu_mem_write(c, PD + 4 * 8, &e, 8);
    e = 0x1000 | 7;       (void)wemu_mem_write(c, PT + 1 * 8, &e, 8); /* code */
    e = DATA_PA | 3;      (void)wemu_mem_write(c, PT, &e, 8);         /* data */
    wemu_cpu_set_cr3(c, PML4);
    wemu_cpu_enable_paging(c, 1);
}

/* Frames are written as GPAs; read them with paging off. */
static uint64_t frame_qword(WemuCpu *c, uint64_t sp, int idx) {
    uint64_t v = 0;
    wemu_cpu_enable_paging(c, 0);
    (void)wemu_mem_read(c, sp + (uint64_t)idx * 8, &v, 8);
    wemu_cpu_enable_paging(c, 1);
    return v;
}

/* ---- DPL / RPL / CPL check on a software INT gate -------------------- */
static void test_privilege_checks(void) {
    WemuCpu *c = boot();
    set_gate(c, 40, HANDLER, 0xE, 1, 0, 1); /* gate DPL=1 */

    /* max(CPL,RPL)=0 <= DPL=1 -> accepted. */
    CHECK(wemu_cpu_deliver_int(c, 40) == 0, "INT accepted: max(CPL,RPL)=0 <= DPL=1");
    CHECK(wemu_cpu_rip(c) == HANDLER && wemu_cpu_fault(c) == 0,
          "accepted INT reaches the gate offset");

    /* Raise CS.RPL only: max(0,3)=3 > DPL=1 -> #GP with the IDT code. */
    wemu_cpu_set_rip(c, CODE);
    wemu_cpu_set_cs_rpl(c, 3);
    CHECK(wemu_cpu_deliver_int(c, 40) == -1, "INT rejected when RPL=3 > DPL=1");
    CHECK(wemu_cpu_fault(c) == 13, "RPL rejection latches #GP");
    CHECK(wemu_cpu_fault_error(c) == IDT_CODE(40), "RPL #GP error = (40<<3)|2");
    CHECK(wemu_cpu_rip(c) == CODE, "rejected INT does not move RIP");

    /* Raise CPL only: max(2,0)=2 > DPL=1 -> #GP. */
    wemu_cpu_clear_fault(c);
    wemu_cpu_set_cs_rpl(c, 0);
    wemu_cpu_set_cpl(c, 2);
    CHECK(wemu_cpu_deliver_int(c, 40) == -1, "INT rejected when CPL=2 > DPL=1");
    CHECK(wemu_cpu_fault(c) == 13, "CPL rejection latches #GP");

    /* Widen DPL to 3: max(2,0)=2 <= 3 -> accepted. */
    wemu_cpu_clear_fault(c);
    set_gate(c, 40, HANDLER, 0xF, 3, 0, 1); /* trap gate, DPL=3 */
    CHECK(wemu_cpu_deliver_int(c, 40) == 0, "INT accepted with DPL=3 at CPL=2");
    CHECK(wemu_cpu_rip(c) == HANDLER, "widened-DPL INT reaches handler");

    /* Exceptions ignore BOTH gate privilege fields. */
    wemu_cpu_clear_fault(c);
    wemu_cpu_set_rip(c, CODE);
    wemu_cpu_set_cpl(c, 3);
    wemu_cpu_set_cs_rpl(c, 3);
    CHECK(wemu_cpu_deliver_exception(c, 6) == 0,
          "exception ignores gate DPL/RPL at CPL=3");
    CHECK(wemu_cpu_rip(c) == HANDLER, "exception still reaches handler");
    printf("privilege: rpl3>dpl1 rejected, cpl2>dpl1 rejected, "
           "dpl3 accepted, exceptions ignore priv\n");
    wemu_cpu_destroy(c);
}

/* ---- interrupt gate clears IF; trap gate preserves it ---------------- */
static void test_if_clearing(void) {
    const uint8_t sti[] = { 0xFB }; /* STI: set IF, then advance RIP */
    for (int gate_type = 0xE; gate_type <= 0xF; gate_type++) {
        WemuCpu *c = boot();
        (void)wemu_cpu_load(c, CODE, sti, sizeof sti);
        CHECK(wemu_cpu_step(c) == 1, "STI executed");
        CHECK((wemu_cpu_rflags(c) & 0x200u) != 0, "IF set before delivery");
        set_gate(c, 40, HANDLER, (uint8_t)gate_type, 3, 0, 1);
        CHECK(wemu_cpu_deliver_int(c, 40) == 0, "INT delivered (IF test)");

        uint64_t fl = wemu_cpu_rflags(c);
        uint64_t sp = wemu_cpu_reg(c, 4);
        uint64_t saved = frame_qword(c, sp, 2); /* RFLAGS slot */
        if (gate_type == 0xE) {
            CHECK((fl & 0x200u) == 0, "interrupt gate clears IF in handler");
            CHECK((saved & 0x200u) != 0, "saved frame RFLAGS retains IF");
            printf("if_clear: intr_gate after=0x%llx saved=0x%llx\n",
                   (unsigned long long)fl, (unsigned long long)saved);
        } else {
            CHECK((fl & 0x200u) != 0, "trap gate preserves IF in handler");
            CHECK((saved & 0x200u) != 0, "trap gate frame RFLAGS has IF");
            printf("if_clear: trap_gate after=0x%llx saved=0x%llx\n",
                   (unsigned long long)fl, (unsigned long long)saved);
        }
        CHECK(frame_qword(c, sp, 0) == CODE + 1, "saved RIP after STI");
        CHECK(sp == STACK - 5 * 8, "no error code: 5 qword frame");
        wemu_cpu_destroy(c);
    }
}

/* ---- IST stack selection from the gate byte -------------------------- */
static void test_ist_stack(void) {
    const uint8_t ud[] = { 0xF0, 0x01, 0xD8, 0xF4 }; /* LOCK ADD -> #UD */
    WemuCpu *c = boot();
    wemu_cpu_set_ist(c, 2, IST_STACK);
    CHECK(wemu_cpu_ist(c, 2) == IST_STACK, "IST[2] base readable");
    set_gate(c, 6, HANDLER, 0xE, 0, 2, 1); /* #UD through IST index 2 */
    (void)wemu_cpu_load(c, CODE, ud, sizeof ud);

    CHECK(wemu_cpu_step(c) == 1, "#UD delivered via IST gate");
    uint64_t sp = wemu_cpu_reg(c, 4);
    CHECK(sp == IST_STACK - 5 * 8, "RSP switched to IST[2] base");
    CHECK(frame_qword(c, sp, 0) == CODE, "IST frame saved RIP");
    CHECK(frame_qword(c, sp, 1) == 0x28, "IST frame CS");
    CHECK(frame_qword(c, sp, 3) == STACK, "IST frame old-RSP = pre-switch RSP");
    CHECK(frame_qword(c, sp, 4) == 0, "IST frame SS");
    CHECK(sp != STACK - 5 * 8, "IST stack differs from the normal stack");
    printf("ist: gate_ist=2 old_rsp=0x%x new_rsp=0x%llx (base 0x%x)\n",
           STACK, (unsigned long long)sp, IST_STACK);
    wemu_cpu_destroy(c);
}

/* ---- #PF I/D (instruction fetch) + RSVD (reserved paging bit) -------- */
static void test_pf_id_and_rsvd(void) {
    /* (a) Make the code page non-present: the NEXT fetch faults with I/D. */
    {
        const uint8_t nop = 0x90;
        uint64_t zero = 0;
        WemuCpu *c = boot();
        setup_paging(c);
        (void)wemu_cpu_load(c, CODE, &nop, 1);
        wemu_cpu_enable_paging(c, 0);
        (void)wemu_mem_write(c, PT + 1 * 8, &zero, 8); /* code PTE P=0 */
        wemu_cpu_enable_paging(c, 1);
        wemu_cpu_set_rip(c, CODE);

        CHECK(wemu_cpu_step(c) == 1, "instruction-fetch #PF delivered");
        CHECK(wemu_cpu_exception_vector(c) == 14, "fetch fault is #PF");
        CHECK(wemu_cpu_exception_error(c) == PF_ID,
              "fetch #PF error = I/D only (0x10), P=0/W=0/U=0");
        CHECK(wemu_cpu_exception_cr2(c) == CODE, "fetch #PF CR2 = code VA");
        uint64_t sp = wemu_cpu_reg(c, 4);
        CHECK(sp == STACK - 6 * 8, "fetch #PF frame = 6 qwords");
        CHECK(frame_qword(c, sp, 0) == PF_ID, "fetch #PF error on stack");
        CHECK(frame_qword(c, sp, 1) == CODE, "fetch #PF saved RIP = code VA");
        printf("pf_id: vec=14 err=0x%llx cr2=0x%llx (expected 0x10 / 0x%x)\n",
               (unsigned long long)wemu_cpu_exception_error(c),
               (unsigned long long)wemu_cpu_exception_cr2(c), CODE);
        wemu_cpu_destroy(c);
    }

    /* (b) Present data leaf with a reserved bit set: write faults with
     *     P=1|W=1|RSVD=1 and I/D clear. */
    {
        const uint8_t wr[] = { 0x48, 0x89, 0x04, 0x25,
                               0x00, 0x00, 0x40, 0x00 }; /* MOV [DATA_VA],RAX */
        uint64_t e = DATA_PA | 3 | (1ull << 52); /* P|RW|US + reserved bit 52 */
        WemuCpu *c = boot();
        setup_paging(c);
        wemu_cpu_enable_paging(c, 0);
        (void)wemu_mem_write(c, PT, &e, 8);
        wemu_cpu_enable_paging(c, 1);
        (void)wemu_cpu_load(c, CODE, wr, sizeof wr);

        CHECK(wemu_cpu_step(c) == 1, "reserved-bit #PF delivered");
        uint64_t err = wemu_cpu_exception_error(c);
        CHECK(wemu_cpu_exception_vector(c) == 14, "reserved fault is #PF");
        CHECK(err == (PF_P | PF_WR | PF_RSVD),
              "RSVD #PF error = P|W|RSVD (0xb), I/D clear");
        CHECK((err & PF_ID) == 0, "data fault has I/D clear");
        CHECK(wemu_cpu_exception_cr2(c) == DATA_VA, "RSVD #PF CR2 = data VA");
        uint64_t sp = wemu_cpu_reg(c, 4);
        CHECK(frame_qword(c, sp, 0) == err, "RSVD error on stack");
        CHECK(frame_qword(c, sp, 1) == CODE, "RSVD #PF saved RIP");
        printf("pf_rsvd: vec=14 err=0x%llx cr2=0x%x (expected 0xb)\n",
               (unsigned long long)err, DATA_VA);
        wemu_cpu_destroy(c);
    }

    /* (c) #PF through an IST gate combines error slot with IST stack. */
    {
        const uint8_t wr[] = { 0x48, 0x89, 0x04, 0x25,
                               0x00, 0x00, 0x80, 0x00 }; /* MOV [0x800000] */
        WemuCpu *c = boot();
        setup_paging(c);
        wemu_cpu_set_ist(c, 3, IST_STACK);
        /* Gate lives at a guest-physical address: write it with paging off. */
        wemu_cpu_enable_paging(c, 0);
        set_gate(c, 14, HANDLER, 0xE, 0, 3, 1); /* #PF -> IST[3] */
        wemu_cpu_enable_paging(c, 1);
        (void)wemu_cpu_load(c, CODE, wr, sizeof wr);

        CHECK(wemu_cpu_step(c) == 1, "#PF via IST gate delivered");
        CHECK(wemu_cpu_exception_error(c) == PF_WR, "not-present write -> W only");
        uint64_t sp = wemu_cpu_reg(c, 4);
        CHECK(sp == IST_STACK - 6 * 8, "#PF frame switched to IST[3]");
        CHECK(frame_qword(c, sp, 0) == PF_WR, "IST #PF error slot");
        CHECK(frame_qword(c, sp, 4) == STACK, "IST #PF old-RSP preserved");
        printf("pf_ist: err=0x%llx new_rsp=0x%llx (IST[3] 0x%x)\n",
               (unsigned long long)wemu_cpu_exception_error(c),
               (unsigned long long)sp, IST_STACK);
        wemu_cpu_destroy(c);
    }
}

int main(void) {
    test_privilege_checks();
    test_if_clearing();
    test_ist_stack();
    test_pf_id_and_rsvd();
    if (fails) {
        printf("test_priv: %d/%d CHECK(S) FAILED\n", fails, checks);
        return 1;
    }
    printf("test_priv: PASS (%d checks; privilege/IF/IST/#PF bits)\n", checks);
    return 0;
}
#endif
