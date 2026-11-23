/* test_virtio_mmio — BAR4 register-file gate for the modeled virtio-blk
 * function. GPA 0x0F000000 exposes common config, notify, ISR and device
 * config. This leg gates the handshake-visible registers, not virtqueue
 * data-plane processing.
 */
#define _POSIX_C_SOURCE 200809L
#include "wemu.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

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

static int data_plane(void) {
    WemuMachine *m = wemu_machine_create(0x100000, NULL, NULL);
    WemuCpu *c = wemu_machine_cpu(m);
    if (!c) return 1;
    const uint64_t desc = 0x3000, avail = 0x4000, used = 0x5000;
    const uint64_t hdr = 0x6000, data = 0x7000, status = 0x8000;
    uint8_t d[16];
    memset(d, 0, sizeof d);
    memcpy(d, &desc, 8); d[8] = 16; d[12] = 1; d[14] = 1;
    CHECK(wemu_mem_write(c, 0x0F000020, d, 8) == 0, "desc PFN write");
    memset(d, 0, sizeof d);
    memcpy(d, &avail, 8);
    CHECK(wemu_mem_write(c, 0x0F000028, d, 8) == 0, "avail PFN write");
    memset(d, 0, sizeof d);
    memcpy(d, &used, 8);
    CHECK(wemu_mem_write(c, 0x0F000030, d, 8) == 0, "used PFN write");
    uint16_t one = 1;
    CHECK(wemu_mem_write(c, 0x0F00001C, &one, 2) == 0, "queue enable");
    /* descriptor chain: header (next) -> data (write, next) -> status (write) */
    memset(d, 0, sizeof d); memcpy(d, &hdr, 8); d[8] = 16; d[12] = 1; d[14] = 1;
    CHECK(wemu_mem_write(c, desc, d, 16) == 0, "desc0");
    memset(d, 0, sizeof d); memcpy(d, &data, 8); d[8] = 0; d[9] = 2; d[12] = 3; d[14] = 2;
    CHECK(wemu_mem_write(c, desc + 16, d, 16) == 0, "desc1");
    memset(d, 0, sizeof d); memcpy(d, &status, 8); d[8] = 1; d[12] = 2;
    CHECK(wemu_mem_write(c, desc + 32, d, 16) == 0, "desc2");
    uint8_t av[8] = {0,0,1,0,0,0,0,0}; /* flags=0, idx=1, ring[0]=0 */
    CHECK(wemu_mem_write(c, avail, av, sizeof av) == 0, "avail ring");
    memset(d, 0, sizeof d); d[0] = 0; /* VIRTIO_BLK_T_IN */
    CHECK(wemu_mem_write(c, hdr, d, 16) == 0, "request header");
    uint8_t sentinel = 0xff;
    CHECK(wemu_mem_write(c, status, &sentinel, 1) == 0, "status sentinel");
    uint16_t kick = 0;
    CHECK(wemu_mem_write(c, 0x0F001000, &kick, 2) == 0, "notify");
    uint8_t used_idx[2] = {0};
    CHECK(wemu_mem_read(c, used + 2, used_idx, 2) == 0, "used idx read");
    uint8_t st = 0xff;
    CHECK(wemu_mem_read(c, status, &st, 1) == 0, "status read");
    CHECK(used_idx[0] == 1 && used_idx[1] == 0, "used.idx not advanced");
    CHECK(st == 0, "block status not VIRTIO_BLK_S_OK");
    wemu_machine_destroy(m);
    return 0;
}

static int host_backed_read(void) {
    char path[] = "/tmp/wemu-virtio-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0, "mkstemp failed");
    uint8_t pattern[512];
    for (size_t i = 0; i < sizeof pattern; i++) pattern[i] = (uint8_t)(i * 7u + 3u);
    CHECK(write(fd, pattern, sizeof pattern) == (ssize_t)sizeof pattern,
          "disk image write failed");
    close(fd);
    CHECK(setenv("WEMU_VIRTIO_DISK", path, 1) == 0, "setenv failed");

    WemuMachine *m = wemu_machine_create(0x100000, NULL, NULL);
    WemuCpu *c = wemu_machine_cpu(m);
    if (!c) return 1;
    const uint64_t desc = 0x3000, avail = 0x4000, used = 0x5000;
    const uint64_t hdr = 0x6000, data = 0x7000, status = 0x8000;
    uint8_t d[16];
    memset(d, 0, sizeof d); memcpy(d, &desc, 8); d[8] = 16; d[12] = 1; d[14] = 1;
    CHECK(wemu_mem_write(c, 0x0F000020, d, 8) == 0, "desc PFN");
    memset(d, 0, sizeof d); memcpy(d, &avail, 8);
    CHECK(wemu_mem_write(c, 0x0F000028, d, 8) == 0, "avail PFN");
    memset(d, 0, sizeof d); memcpy(d, &used, 8);
    CHECK(wemu_mem_write(c, 0x0F000030, d, 8) == 0, "used PFN");
    uint16_t one = 1;
    CHECK(wemu_mem_write(c, 0x0F00001C, &one, 2) == 0, "queue enable");
    memset(d, 0, sizeof d); memcpy(d, &hdr, 8); d[8] = 16; d[12] = 1; d[14] = 1;
    CHECK(wemu_mem_write(c, desc, d, 16) == 0, "desc0");
    memset(d, 0, sizeof d); memcpy(d, &data, 8); d[8] = 0; d[9] = 2; d[12] = 3; d[14] = 2;
    CHECK(wemu_mem_write(c, desc + 16, d, 16) == 0, "desc1");
    memset(d, 0, sizeof d); memcpy(d, &status, 8); d[8] = 1; d[12] = 2;
    CHECK(wemu_mem_write(c, desc + 32, d, 16) == 0, "desc2");
    uint8_t av[8] = {0,0,1,0,0,0,0,0};
    CHECK(wemu_mem_write(c, avail, av, sizeof av) == 0, "avail ring");
    memset(d, 0, sizeof d);
    CHECK(wemu_mem_write(c, hdr, d, 16) == 0, "IN header");
    uint16_t kick = 0;
    CHECK(wemu_mem_write(c, 0x0F001000, &kick, 2) == 0, "notify");
    uint8_t got[512] = {0};
    CHECK(wemu_mem_read(c, data, got, sizeof got) == 0, "data read");
    CHECK(memcmp(got, pattern, sizeof pattern) == 0, "host image bytes differ");
    wemu_machine_destroy(m);
    unsetenv("WEMU_VIRTIO_DISK");
    unlink(path);
    return 0;
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
    CHECK(data_plane() == 0, "data-plane request failed");
    CHECK(host_backed_read() == 0, "host-backed image read failed");
    printf("test_virtio_mmio: PASS (features, queue=256, capacity=2048, request + host image)\n");
    return 0;
}
