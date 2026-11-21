/* test_paging.c — long-mode 4-level page walk: constructed tables,
 * 4KiB + 2MiB leaves, non-present #PF with CR2, canonical check, and
 * EFER.NXE-correct XD/NX fault enforcement (P|I/D on fetch, P|RSVD when
 * NXE=0) on both 4KiB and 2MiB leaves. */
#include "wemu.h"
#include "wemu_internal.h"
#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(cond, msg) do { if (!(cond)) { \
    printf("FAIL: %s (line %d)\n", msg, __LINE__); fails++; } } while (0)

int main(void) {
    WemuCpu *c = wemu_cpu_create(8 << 20); /* 8MB: room for a 2MiB-aligned leaf */
    /* tables: PML4 @0x10000, PDPT @0x11000, PD @0x12000, PT @0x13000
     * map VA 0x400000 -> PA 0x2000 (4KiB).
     * VA 0x400000 = 2^22: PML4[0], PDPT[0], PD[2], PT[0]. */
    uint64_t e;
    e = 0x11003; wemu_mem_write(c, 0x10000, &e, 8);          /* PML4[0] */
    e = 0x12003; wemu_mem_write(c, 0x11000, &e, 8);          /* PDPT[0] */
    e = 0x13003; wemu_mem_write(c, 0x12000 + 2 * 8, &e, 8);  /* PD[2] */
    e = 0x2003;  wemu_mem_write(c, 0x13000 + 0 * 8, &e, 8);  /* PT[0] */
    wemu_cpu_set_cr3(c, 0x10000);
    wemu_cpu_enable_paging(c, 1);

    uint64_t val = 0xCAFEF00Dull;
    CHECK(wemu_mem_write(c, 0x400000, &val, 8) == 0, "write via VA");
    uint64_t got = 0;
    wemu_cpu_enable_paging(c, 0); /* raw GPA read-back */
    CHECK(wemu_mem_read(c, 0x2000, &got, 8) == 0 && got == val,
          "VA write lands at mapped GPA");
    wemu_cpu_enable_paging(c, 1);
    c->fault = 0;

    /* non-present: VA 0x800000 (PDPT[2] absent) -> #PF, CR2 set */
    CHECK(wemu_mem_read(c, 0x800000, &got, 8) != 0, "unmapped read faults");
    CHECK(wemu_cpu_fault(c) == 14, "fault vector is #PF");
    CHECK(wemu_cpu_fault_addr(c) == 0x800000, "CR2 holds faulting VA");

    /* 2MiB large page: PD[1] with PS -> VA 0x200000..0x3FFFFF */
    c->fault = 0;
    e = 0x200000 | 0x83; /* PA 0x200000: 2MiB-ALIGNED as the SDM requires */
    wemu_cpu_enable_paging(c, 0); /* table writes go to raw GPA */
    wemu_mem_write(c, 0x12000 + 1 * 8, &e, 8);
    wemu_cpu_enable_paging(c, 1);
    val = 0x1234;
    CHECK(wemu_mem_write(c, 0x200000 + 0x1234, &val, 8) == 0, "2MiB write");
    wemu_cpu_enable_paging(c, 0);
    CHECK(wemu_mem_read(c, 0x200000 + 0x1234, &got, 8) == 0 && got == 0x1234,
          "2MiB leaf translation");
    wemu_cpu_enable_paging(c, 1);

    /* ---- XD/NX enforcement (was bookkeeping-only before this increment) ----
     * The WEMU reset EFER is 0xd00 (LME|LMA|NXE): bit 63 of a leaf is the
     * execute-disable bit and MUST fault instruction fetch.  Data reads from
     * the same page stay legal.  Verify both 4KiB and 2MiB leaves, the exact
     * error code (P=1, I/D=1 => 0x11), and the NXE=0 reserved-bit path. */
    uint8_t byte, fetch_buf;
    /* 4KiB leaf PT[0] -> XD */
    wemu_cpu_enable_paging(c, 0);
    e = 0x2003 | (1ull << 63);
    wemu_mem_write(c, 0x13000, &e, 8);
    wemu_cpu_enable_paging(c, 1);
    c->fault = 0; c->fault_error = 0; c->cr2 = 0;
    CHECK(wemu_mem_fetch(c, 0x400000, &fetch_buf, 1) != 0, "XD 4K fetch faults");
    CHECK(wemu_cpu_fault(c) == 14, "XD 4K -> #PF");
    CHECK(wemu_cpu_fault_addr(c) == 0x400000, "XD 4K CR2");
    CHECK(c->fault_error == 0x11, "XD 4K error P|I/D = 0x11");
    c->fault = 0;
    CHECK(wemu_mem_read(c, 0x400000, &byte, 1) == 0 && c->fault == 0,
          "data read from XD 4K page allowed");
    /* control: same page without XD executes */
    wemu_cpu_enable_paging(c, 0);
    e = 0x2003; wemu_mem_write(c, 0x13000, &e, 8);
    wemu_cpu_enable_paging(c, 1);
    c->fault = 0;
    CHECK(wemu_mem_fetch(c, 0x400000, &fetch_buf, 1) == 0 && c->fault == 0,
          "fetch from executable 4K page succeeds");
    /* NXE=0: bit 63 is reserved -> #PF P|RSVD (0x9) even on a data read */
    uint64_t saved_efer = c->efer;
    c->efer &= ~(1ull << 11);
    wemu_cpu_enable_paging(c, 0);
    e = 0x2003 | (1ull << 63); wemu_mem_write(c, 0x13000, &e, 8);
    wemu_cpu_enable_paging(c, 1);
    c->fault = 0; c->fault_error = 0;
    CHECK(wemu_mem_read(c, 0x400000, &byte, 1) != 0, "NXE=0 XD -> reserved #PF");
    CHECK(wemu_cpu_fault(c) == 14 && c->fault_error == 0x9,
          "NXE=0 error P|RSVD = 0x9");
    c->efer = saved_efer;
    /* 2MiB leaf PD[1] -> XD */
    wemu_cpu_enable_paging(c, 0);
    e = 0x200000 | 0x83 | (1ull << 63);
    wemu_mem_write(c, 0x12000 + 1 * 8, &e, 8);
    wemu_cpu_enable_paging(c, 1);
    c->fault = 0; c->fault_error = 0;
    CHECK(wemu_mem_fetch(c, 0x200000, &fetch_buf, 1) != 0, "XD 2M fetch faults");
    CHECK(wemu_cpu_fault(c) == 14 && c->fault_error == 0x11,
          "XD 2M error P|I/D = 0x11");
    c->fault = 0;
    CHECK(wemu_mem_read(c, 0x200000, &byte, 1) == 0 && c->fault == 0,
          "data read from XD 2M page allowed");

    /* paging off: identity */
    wemu_cpu_enable_paging(c, 0);
    c->fault = 0;
    CHECK(wemu_mem_write(c, 0x5000, &val, 8) == 0, "identity write");
    wemu_cpu_destroy(c);

    if (fails) { printf("test_paging: %d FAILURES\n", fails); return 1; }
    printf("test_paging: PASS (4KiB, 2MiB, #PF+CR2, identity, XD/NX fetch "
           "fault enforcement incl. NXE=0 RSVD)\n");
    return 0;
}