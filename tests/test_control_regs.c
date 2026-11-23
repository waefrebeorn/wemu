/* test_control_regs.c — MOV CRn <-> GPR, the minimum privileged instruction
 * pair a kernel needs to boot in WEMU. 0F 20/22 decoded with ModRM but had
 * no exec handlers, so the first kernel instruction after CLI (#UD'd). */
#include "wemu.h"
#include "wemu_internal.h"
#include <stdio.h>
#include <stdint.h>

static int fails;
#define CHECK(c, m) do { if (!(c)) { printf("FAIL: %s\n", m); fails++; } } while (0)

static void run(WemuCpu *c, const uint8_t *code, size_t n, const char *what) {
    wemu_cpu_load(c, 0x1000, code, n);
    wemu_cpu_set_rip(c, 0x1000);
    int64_t s = wemu_cpu_run(c, 1); /* one instruction, never HLT */
    CHECK(s >= 0 && wemu_cpu_fault(c) == 0, what);
    if (s < 0) wemu_cpu_clear_fault(c);
}

int main(void) {
    WemuCpu *c = wemu_cpu_create(1u << 20);

    c->cr0 = 0x11ull;
    wemu_cpu_set_reg(c, 0, 0);
    { const uint8_t code[] = { 0x48, 0x0f, 0x20, 0xc0 }; /* mov rax,cr0 */
      run(c, code, sizeof code, "mov rax,cr0 faulted"); }
    CHECK(wemu_cpu_reg(c, 0) == 0x11ull, "mov rax,cr0 wrong value");

    wemu_cpu_set_reg(c, 0, 0x12345000ull);
    { const uint8_t code[] = { 0x48, 0x0f, 0x22, 0xd8 }; /* mov cr3,rax */
      run(c, code, sizeof code, "mov cr3,rax faulted"); }
    CHECK(c->cr3 == 0x12345000ull, "mov cr3,rax wrong value");

    wemu_cpu_set_reg(c, 0, 0);
    { const uint8_t code[] = { 0x48, 0x0f, 0x20, 0xc3 }; /* mov rax,cr3 */
      run(c, code, sizeof code, "mov rax,cr3 faulted"); }
    CHECK(wemu_cpu_reg(c, 0) == 0x12345000ull, "mov rax,cr3 wrong value");

    /* LGDT [rax] reads the 16:64 descriptor and loads GDTR. */
    uint8_t desc[10] = { 0x17, 0x00 };
    uint64_t base = 0x2100ull;
    for (int i = 0; i < 8; i++) desc[2 + i] = (uint8_t)(base >> (8 * i));
    CHECK(wemu_mem_write(c, 0x2000, desc, sizeof desc) == 0, "write GDT descriptor");
    wemu_cpu_set_reg(c, 0, 0x2000);
    { const uint8_t code[] = { 0x48, 0x0f, 0x01, 0x08 };
      run(c, code, sizeof code, "lgdt faulted"); }
    CHECK(c->gdt.configured && c->gdt.limit == 0x17 && c->gdt.base == base,
          "lgdt loaded wrong descriptor");

    printf("test_control_regs: %s (CR0/CR3 round trip + LGDT)\n", fails ? "FAIL" : "PASS");
    wemu_cpu_destroy(c);
    return fails ? 1 : 0;
}
