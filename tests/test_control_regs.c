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
    { const uint8_t code[] = { 0x48, 0x0f, 0x20, 0xd8 }; /* CR3 -> RAX */
      run(c, code, sizeof code, "mov rax,cr3 faulted"); }
    CHECK(wemu_cpu_reg(c, 0) == 0x12345000ull, "mov rax,cr3 wrong value");
    wemu_cpu_set_reg(c, 1, 0);
    { const uint8_t code[] = { 0x48, 0x0f, 0x20, 0xd9 }; /* CR3 -> RBX */
      run(c, code, sizeof code, "mov rbx,cr3 faulted"); }
    CHECK(wemu_cpu_reg(c, 1) == 0x12345000ull, "mov rbx,cr3 wrong value");

    /* LGDT [rax] reads the 16:64 descriptor and loads GDTR. */
    uint8_t desc[10] = { 0x17, 0x00 };
    uint64_t base = 0x2100ull;
    for (int i = 0; i < 8; i++) desc[2 + i] = (uint8_t)(base >> (8 * i));
    CHECK(wemu_mem_write(c, 0x2000, desc, sizeof desc) == 0, "write GDT descriptor");
    wemu_cpu_set_reg(c, 0, 0x2000);
    { const uint8_t code[] = { 0x48, 0x0f, 0x01, 0x10 }; /* LGDT /2 */
      run(c, code, sizeof code, "lgdt faulted"); }
    CHECK(c->gdt.configured && c->gdt.limit == 0x17 && c->gdt.base == base,
          "lgdt loaded wrong descriptor");
    { const uint8_t code[] = { 0x48, 0x0f, 0x01, 0x18 }; /* LIDT /3 */
      run(c, code, sizeof code, "lidt faulted"); }
    CHECK(c->idtr.configured && c->idtr.limit == 0x17 && c->idtr.base == base,
          "lidt loaded wrong descriptor");

    /* MOV DS/SS, ax — the next 32-bit crt0 step after LGDT. */
    wemu_cpu_set_reg(c, 0, 0x10);
    { const uint8_t code[] = { 0x8e, 0xd8 }; /* mov ds,ax */
      run(c, code, sizeof code, "mov ds,ax faulted"); }
    CHECK(c->ds_selector == 0x10, "mov ds,ax wrong selector");
    wemu_cpu_set_reg(c, 0, 0x18);
    { const uint8_t code[] = { 0x8e, 0xd0 }; /* mov ss,ax */
      run(c, code, sizeof code, "mov ss,ax faulted"); }
    CHECK(c->ss_selector == 0x18, "mov ss,ax wrong selector");

    /* IA32_APIC_BASE MSR: apic_init reads and rewrites it. */
    wemu_cpu_set_reg(c, 1, 0x1B); /* RCX */
    { const uint8_t code[] = { 0x0f, 0x32 }; /* rdmsr */
      run(c, code, sizeof code, "rdmsr faulted"); }
    CHECK((uint32_t)wemu_cpu_reg(c, 0) == 0xfee00000u, "rdmsr APIC base low");
    CHECK((uint32_t)wemu_cpu_reg(c, 2) == 0, "rdmsr APIC base high");
    wemu_cpu_set_reg(c, 0, 0xfee00800ull);
    wemu_cpu_set_reg(c, 2, 0);
    { const uint8_t code[] = { 0x0f, 0x30 }; /* wrmsr */
      run(c, code, sizeof code, "wrmsr faulted"); }
    { const uint8_t code[] = { 0x0f, 0x32 };
      run(c, code, sizeof code, "rdmsr after wrmsr faulted"); }
    CHECK(wemu_cpu_reg(c, 0) == 0xfee00800ull, "msr round trip");

    printf("test_control_regs: %s (CR0/CR3, LGDT/LIDT, DS/SS, MSR)\n", fails ? "FAIL" : "PASS");
    wemu_cpu_destroy(c);
    return fails ? 1 : 0;
}
