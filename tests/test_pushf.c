/* test_pushf — PUSHF/POPF round-trip gate.
 *
 * WEMU #GP'd on 0x9C in wubu_spin_lock (`pushf; pop %r13; cli`), stopping
 * the long guest boot right after TSS setup. FLAGS bit 1 is architecturally
 * set and must survive a push/pop round-trip.
 */
#include "wemu.h"
#include <stdio.h>
#include <stdint.h>

#define CHECK(cond, ...) do { if (!(cond)) { \
    fprintf(stderr, "FAIL: " __VA_ARGS__); return 1; } } while (0)

int main(void) {
    uint8_t code[] = {
        0xF9,       /* stc */
        0x9C,       /* pushfq */
        0x58,       /* pop rax */
        0x50,       /* push rax */
        0x9D,       /* popfq */
        0x9C,       /* pushfq */
        0x59,       /* pop rcx */
        0xF4        /* hlt */
    };
    WemuCpu *c = wemu_cpu_create(0x100000);
    if (!c) return 2;
    wemu_cpu_load(c, 0x1000, code, sizeof code);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_set_rsp(c, 0x80000);
    wemu_cpu_run(c, 20);
    CHECK(wemu_cpu_fault(c) == 0, "pushf/popf faulted");
    uint64_t a = wemu_cpu_reg(c, 0), cc = wemu_cpu_reg(c, 1);
    CHECK((a & 1u) != 0, "STC did not set CF in pushed flags");
    CHECK((a & 2u) != 0, "FLAGS bit 1 was not set");
    CHECK(cc == a, "pushf/popf round-trip changed flags");
    wemu_cpu_destroy(c);
    printf("test_pushf: PASS (push/pop flags round-trip, CF preserved)\n");
    return 0;
}
