/* test_pci_config — minimal PCI config-space gate.
 *
 * WuBuOS scans bus 0 by writing 0x80000000|dev<<11|off to 0xCF8 and reading
 * 0xCFC. WEMU previously dropped both ports, so the kernel saw 0 devices.
 * This gate proves a virtio-blk function is visible to real guest I/O.
 */
#include "wemu.h"
#include <stdio.h>
#include <stdint.h>

#define CHECK(cond, ...) do { if (!(cond)) { \
    fprintf(stderr, "FAIL: " __VA_ARGS__); return 1; } } while (0)

static uint32_t read_cfg(uint32_t addr) {
    uint8_t code[] = {
        0xB8, (uint8_t)addr, (uint8_t)(addr >> 8),
              (uint8_t)(addr >> 16), (uint8_t)(addr >> 24),
        0xBA,0xF8,0x0C,0x00,0x00, 0xEF, /* out dx,eax -> 0xCF8 */
        0xBA,0xFC,0x0C,0x00,0x00, 0xED, /* in eax,dx  <- 0xCFC */
        0xF4
    };
    WemuMachine *m = wemu_machine_create(0x100000, NULL, NULL);
    WemuCpu *c = wemu_machine_cpu(m);
    if (!c) return 0;
    wemu_cpu_load(c, 0x1000, code, sizeof code);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_run(c, 16);
    uint32_t v = (uint32_t)wemu_cpu_reg(c, 0);
    wemu_machine_destroy(m);
    return v;
}

int main(void) {
    CHECK(read_cfg(0x80000000u) == 0x10421af4u, "wrong vendor/device ID");
    CHECK(read_cfg(0x80000008u) == 0x01080000u, "wrong class code");
    CHECK((read_cfg(0x80000034u) & 0xffu) == 0x40u, "wrong capability pointer");
    CHECK(read_cfg(0x80000800u) == 0xffffffffu, "empty function not all-ones");
    printf("test_pci_config: PASS (1af4:1042, class 01:08, caps @40)\n");
    return 0;
}
