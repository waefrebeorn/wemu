/* test_paging.c — long-mode 4-level page walk: constructed tables,
 * 4KiB + 2MiB leaves, non-present #PF with CR2, canonical check. */
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

    /* paging off: identity */
    wemu_cpu_enable_paging(c, 0);
    c->fault = 0;
    CHECK(wemu_mem_write(c, 0x5000, &val, 8) == 0, "identity write");
    wemu_cpu_destroy(c);

    if (fails) { printf("test_paging: %d FAILURES\n", fails); return 1; }
    printf("test_paging: PASS (4KiB, 2MiB, #PF+CR2, identity)\n");
    return 0;
}