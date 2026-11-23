/* test_highhalf_paging.c — 48-bit canonical higher-half address gate.
 *
 * wemu_translate_ex() used `if (va >> 47)` as its non-canonical test, which
 * rejects EVERY canonical higher-half address (va >> 47 == 0x1ffff). That
 * blocks WEMU from running any higher-half OS kernel, including WuBuOS.
 * The 48-bit rule is: bits 63:47 must be all zero OR all one.
 */
#include "wemu.h"
#include <stdio.h>
#include <stdint.h>

#define PML4  0x100000ull
#define PDPT0 0x101000ull
#define PDPTH 0x102000ull
#define PD    0x103000ull
#define LOW   0x200000ull
#define HIGH  0xffffff8000200000ull
#define BAD   0x0000800000000000ull

static int fails;
#define CHECK(c, m) do { if (!(c)) { printf("FAIL: %s\n", m); fails++; } } while (0)

static void put64(WemuCpu *c, uint64_t a, uint64_t v) {
    if (wemu_mem_write(c, a, &v, 8) != 0) { printf("FAIL: table write %llx\n", (unsigned long long)a); fails++; }
}

int main(void) {
    WemuCpu *c = wemu_cpu_create(64u << 20);
    for (uint64_t a = PML4; a < PD + 0x1000; a += 8) put64(c, a, 0);
    put64(c, PML4, PDPT0 | 3);
    put64(c, PML4 + 511 * 8, PDPTH | 3);
    put64(c, PDPT0, PD | 3);
    put64(c, PDPTH, PD | 3);
    put64(c, PD + 1 * 8, 0x200000ull | 0x83); /* 2 MiB page at phys 2 MiB */

    wemu_cpu_set_cr3(c, PML4);
    wemu_cpu_enable_paging(c, 1);

    const uint64_t pattern = 0x1122334455667788ull;
    CHECK(wemu_mem_write(c, LOW, &pattern, 8) == 0, "write through low alias");
    CHECK(wemu_cpu_fault(c) == 0, "low alias faulted");
    wemu_cpu_clear_fault(c);

    uint64_t got = 0;
    CHECK(wemu_mem_read(c, HIGH, &got, 8) == 0, "read through higher-half alias");
    CHECK(wemu_cpu_fault(c) == 0, "canonical higher-half address faulted");
    CHECK(got == pattern, "higher-half alias read wrong value");
    wemu_cpu_clear_fault(c);

    got = 0;
    int rc = wemu_mem_read(c, BAD, &got, 8);
    CHECK(rc != 0, "non-canonical address succeeded");
    CHECK(wemu_cpu_fault(c) == 13, "non-canonical address did not raise #GP");
    wemu_cpu_clear_fault(c);

    printf("test_highhalf_paging: %s (low=%llx high=%llx bad=%llx)\n",
           fails ? "FAIL" : "PASS", (unsigned long long)LOW,
           (unsigned long long)HIGH, (unsigned long long)BAD);
    wemu_cpu_destroy(c);
    return fails ? 1 : 0;
}
