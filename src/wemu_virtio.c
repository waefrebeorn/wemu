/* wemu_virtio.c — the BAR4 register file for one modern virtio-blk
 * function. GPA 0x0F000000..0x0F003FFF is the device's MMIO BAR, laid out
 * by the PCI capability list: common cfg @0, notify @0x1000, ISR @0x2000,
 * device cfg @0x3000 (OASIS VIRTIO 1.0 4.1.4). Data-plane virtqueue
 * processing is NOT here yet; this leg makes the register handshake real.
 */
#include "wemu_internal.h"
#include <string.h>

#define VIRTIO_BAR_BASE 0x0F000000ull
#define VIRTIO_BAR_LEN  0x00004000ull
#define VQ_SIZE         256u
#define BLK_SECTORS     2048ull

static struct {
    uint32_t dev_feat_sel, drv_feat_sel;
    uint32_t dev_feat[2], drv_feat[2];
    uint8_t status;
    uint16_t queue_sel, queue_size, queue_enable, queue_notify;
    uint64_t desc, driver, device;
} v;

static uint8_t common_read8(unsigned off) {
    uint64_t v64 = 0;
    unsigned shift = 0;
    if (off < 4) { v64 = v.dev_feat_sel; shift = off; }
    else if (off < 8) { v64 = v.dev_feat[v.dev_feat_sel & 1u]; shift = off - 4u; }
    else if (off < 0x0c) { v64 = v.drv_feat_sel; shift = off - 8u; }
    else if (off < 0x10) { v64 = v.drv_feat[v.drv_feat_sel & 1u]; shift = off - 0x0cu; }
    else if (off == 0x14) { v64 = v.status; shift = 0; }
    else if (off == 0x15) { v64 = 0; shift = 0; } /* config_generation */
    else if (off >= 0x16 && off < 0x18) { v64 = v.queue_sel; shift = off - 0x16u; }
    else if (off >= 0x18 && off < 0x1a) { v64 = v.queue_size; shift = off - 0x18u; }
    else if (off >= 0x1c && off < 0x1e) { v64 = v.queue_enable; shift = off - 0x1cu; }
    else if (off >= 0x1e && off < 0x20) { v64 = v.queue_notify; shift = off - 0x1eu; }
    else if (off >= 0x20 && off < 0x28) { v64 = v.desc; shift = off - 0x20u; }
    else if (off >= 0x28 && off < 0x30) { v64 = v.driver; shift = off - 0x28u; }
    else if (off >= 0x30 && off < 0x38) { v64 = v.device; shift = off - 0x30u; }
    return (uint8_t)(v64 >> (8u * shift));
}

static void common_write8(unsigned off, uint8_t b) {
    unsigned idx;
    uint32_t *dst = NULL;
    if (off < 4) { dst = &v.dev_feat_sel; idx = off; }
    else if (off < 8) { dst = &v.dev_feat[v.dev_feat_sel & 1u]; idx = off - 4u; }
    else if (off < 0x0c) { dst = &v.drv_feat_sel; idx = off - 8u; }
    else if (off < 0x10) { dst = &v.drv_feat[v.drv_feat_sel & 1u]; idx = off - 0x0cu; }
    if (dst) {
        *dst = (uint32_t)((*dst & ~(0xffu << (8u * idx))) |
                          ((uint32_t)b << (8u * idx)));
        return;
    }
    if (off == 0x14) v.status = b;
    else if (off >= 0x16 && off < 0x18) {
        idx = off - 0x16u;
        v.queue_sel = (uint16_t)((v.queue_sel & ~(0xffu << (8u * idx))) |
                                 ((uint16_t)b << (8u * idx)));
    } else if (off >= 0x18 && off < 0x1a) {
        idx = off - 0x18u;
        v.queue_size = (uint16_t)((v.queue_size & ~(0xffu << (8u * idx))) |
                                  ((uint16_t)b << (8u * idx)));
    } else if (off >= 0x1c && off < 0x1e) {
        idx = off - 0x1cu;
        v.queue_enable = (uint16_t)((v.queue_enable & ~(0xffu << (8u * idx))) |
                                    ((uint16_t)b << (8u * idx)));
    } else if (off >= 0x1e && off < 0x20) {
        idx = off - 0x1eu;
        v.queue_notify = (uint16_t)((v.queue_notify & ~(0xffu << (8u * idx))) |
                                    ((uint16_t)b << (8u * idx)));
    } else if (off >= 0x20 && off < 0x38) {
        uint64_t *q = off < 0x28 ? &v.desc : off < 0x30 ? &v.driver : &v.device;
        idx = off < 0x28 ? off - 0x20u : off < 0x30 ? off - 0x28u : off - 0x30u;
        *q = (uint64_t)((*q & ~(0xffull << (8u * idx))) |
                        ((uint64_t)b << (8u * idx)));
    }
}
void wemu_virtio_reset(void) {
    memset(&v, 0, sizeof v);
    v.dev_feat[0] = 1u << 9; /* VIRTIO_BLK_F_FLUSH */
    v.dev_feat[1] = 1u;      /* VIRTIO_F_VERSION_1 */
    v.queue_size = VQ_SIZE;
    v.queue_notify = 0;
}

int wemu_virtio_mmio_read(WemuCpu *cpu, uint64_t gpa, void *dst, size_t len) {
    (void)cpu;
    if (gpa < VIRTIO_BAR_BASE || gpa >= VIRTIO_BAR_BASE + VIRTIO_BAR_LEN)
        return 1;
    if (len > VIRTIO_BAR_BASE + VIRTIO_BAR_LEN - gpa) return -1;
    uint8_t *out = dst;
    for (size_t i = 0; i < len; i++) {
        unsigned off = (unsigned)(gpa + i - VIRTIO_BAR_BASE);
        if (off < 0x40) out[i] = common_read8(off);
        else if (off >= 0x3000 && off < 0x3008)
            out[i] = (uint8_t)(BLK_SECTORS >> (8u * (off - 0x3000u)));
        else out[i] = 0; /* notify / ISR / reserved: zero until modeled */
    }
    return 0;
}

int wemu_virtio_mmio_write(WemuCpu *cpu, uint64_t gpa, const void *src, size_t len) {
    (void)cpu;
    if (gpa < VIRTIO_BAR_BASE || gpa >= VIRTIO_BAR_BASE + VIRTIO_BAR_LEN)
        return 1;
    if (len > VIRTIO_BAR_BASE + VIRTIO_BAR_LEN - gpa) return -1;
    const uint8_t *in = src;
    for (size_t i = 0; i < len; i++) {
        unsigned off = (unsigned)(gpa + i - VIRTIO_BAR_BASE);
        if (off < 0x40) common_write8(off, in[i]);
        /* notify writes are acknowledged but do not process virtqueues yet */
    }
    return 0;
}
