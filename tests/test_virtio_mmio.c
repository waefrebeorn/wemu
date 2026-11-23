/* test_virtio_mmio — BAR4 register-file gate for the modeled virtio-blk
 * function. GPA 0x0F000000 exposes common config, notify, ISR and device
 * config. This leg gates the handshake-visible registers, not virtqueue
 * data-plane processing.
 */
#include "wemu.h"
#include <stdio.h>
#include <stdint.h>

#define CHECK(cond, ...) do { if (!(cond)) { \
    fprintf(stderr, "FAIL: " __VA_ARGS__); return 1; } } while (0)

static uint32_t run(uint8_t *code, size_t n, int reg) {
    WemuMachine *m = wemu_machine_create(0x100000, NULL, NULL);
    WemuCpu *c = wemu_machine_cpu(m);
    if (!c) return 0;
    wemu_cpu_load(c, 0x1000, code, n);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_run(c, 24);
    if (wemu_cpu_fault(c)) fprintf(stderr, "FAULT %u\n", wemu_cpu_fault(c));
    uint32_t v = (uint32_t)wemu_cpu_reg(c, reg);
    wemu_machine_destroy(m);
    return v;
}

int main(void) {
    /* dev_feat_sel=0; read dev_feat into EBX */
    uint8_t feat[] = {
        0xB8,0,0,0,0, 0x67,0xA3,0x00,0x00,0x00,0x0F,
        0x67,0xA1,0x04,0x00,0x00,0x0F, 0x89,0xC3, 0xF4
    };
    uint32_t fv = run(feat, sizeof feat, 3);
    CHECK((fv & (1u << 9)) != 0,
          "VIRTIO_BLK_F_FLUSH not offered");

    uint8_t qsize[] = {
        0x31,0xC0, 0x67,0x66,0xA3,0x16,0x00,0x00,0x0F,
        0x67,0xA1,0x18,0x00,0x00,0x0F, 0x89,0xC1, 0xF4
    };
    uint32_t qv = run(qsize, sizeof qsize, 1);
    CHECK(qv == 256, "queue size not 256");

    uint8_t cap[] = {
        0x67,0xA1,0x00,0x30,0x00,0x0F, 0x89,0xC2, 0xF4
    };
    CHECK(run(cap, sizeof cap, 2) == 2048, "device capacity not 2048 sectors");

    uint8_t gen[] = {
        0x67,0xA1,0x15,0x00,0x00,0x0F, 0x89,0xC6, 0xF4
    };
    CHECK(run(gen, sizeof gen, 6) == 0, "config_generation not stable");
    printf("test_virtio_mmio: PASS (features, queue=256, capacity=2048)\n");
    return 0;
}
