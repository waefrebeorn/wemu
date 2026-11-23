/* test_invlpg — INVLPG (0F 01 /7) no-fault gate.
 *
 * wubu_vmm_map_page executes `invlpg (%r12)` after writing a PTE. WEMU has
 * no cached translations (every access walks the page tables), so INVLPG
 * is a no-op, but it must decode and advance RIP instead of #GP.
 */
#include "wemu.h"
#include <stdio.h>
#include <stdint.h>

#define CHECK(cond, ...) do { if (!(cond)) { \
    fprintf(stderr, "FAIL: " __VA_ARGS__); return 1; } } while (0)

int main(void) {
    uint8_t code[] = {
        0x41,0x0F,0x01,0x3C,0x24,   /* invlpg (%r12) */
        0xF4                        /* hlt */
    };
    WemuCpu *c = wemu_cpu_create(0x100000);
    if (!c) return 2;
    wemu_cpu_load(c, 0x1000, code, sizeof code);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_set_reg(c, 12, 0x2000);
    wemu_cpu_run(c, 8);
    CHECK(wemu_cpu_fault(c) == 0, "INVLPG faulted");
    CHECK(wemu_cpu_rip(c) == 0x1006, "INVLPG did not advance RIP");
    wemu_cpu_destroy(c);
    printf("test_invlpg: PASS (no fault, RIP advanced)\n");
    return 0;
}
