/* wemu_virtio.c — the BAR4 register file for one modern virtio-blk
 * function. GPA 0x0F000000..0x0F003FFF is the device's MMIO BAR, laid out
 * by the PCI capability list: common cfg @0, notify @0x1000, ISR @0x2000,
 * device cfg @0x3000 (OASIS VIRTIO 1.0 4.1.4). Data-plane virtqueue
 * processing is NOT here yet; this leg makes the register handshake real.
 */
#include "wemu_internal.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>

#define VIRTIO_BAR_BASE 0x0F000000ull
#define VIRTIO_BAR_LEN  0x00004000ull
#define VQ_SIZE         256u
#define BLK_SECTORS     2048ull
#define BLK_SECTOR_BYTES 512u
#define VIRTIO_BLK_T_IN  0u
#define VIRTIO_BLK_T_OUT 1u
#define VIRTIO_BLK_T_FLUSH 4u

static int trace_enabled(void) {
    static int cached = -1;
    if (cached < 0) cached = getenv("WEMU_VIRTIO_TRACE") != NULL;
    return cached;
}

static struct {
    uint32_t dev_feat_sel, drv_feat_sel;
    uint32_t dev_feat[2], drv_feat[2];
    uint8_t status;
    uint16_t queue_sel, queue_size, queue_enable, queue_notify;
    uint64_t desc, driver, device;
    uint16_t last_avail, used_idx;
    uint8_t *disk;
    FILE *disk_file;
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
    if (!v.disk) v.disk = calloc((size_t)BLK_SECTORS, BLK_SECTOR_BYTES);
    if (v.disk_file) { fclose(v.disk_file); v.disk_file = NULL; }
    const char *path = getenv("WEMU_VIRTIO_DISK");
    if (path && *path) {
        v.disk_file = fopen(path, "r+b");
        if (!v.disk_file) v.disk_file = fopen(path, "w+b");
        if (v.disk_file) {
            size_t got = fread(v.disk, BLK_SECTOR_BYTES, BLK_SECTORS, v.disk_file);
            (void)got;
            rewind(v.disk_file);
        }
    }
}

static uint16_t gpa_r16(WemuCpu *cpu, uint64_t gpa) {
    uint8_t b[2] = {0, 0};
    if (wemu_gpa_read(cpu, gpa, b, 2) != 0) return 0;
    return (uint16_t)(b[0] | ((uint16_t)b[1] << 8));
}

static void gpa_w16(WemuCpu *cpu, uint64_t gpa, uint16_t v16) {
    uint8_t b[2] = {(uint8_t)v16, (uint8_t)(v16 >> 8)};
    (void)wemu_gpa_write(cpu, gpa, b, 2);
}

static void process_queue(WemuCpu *cpu) {
    if (trace_enabled()) fprintf(stderr, "VTRACE kick en=%u avail=%u used=%u\n",
                                 v.queue_enable, gpa_r16(cpu, v.driver + 2), v.used_idx);
    if (!v.queue_enable || !v.desc || !v.driver || !v.device || !v.disk) return;
    uint16_t avail_idx = gpa_r16(cpu, v.driver + 2);
    uint32_t guard = 0;
    while (v.last_avail != avail_idx && guard++ < VQ_SIZE) {
        uint16_t slot = (uint16_t)(v.last_avail % v.queue_size);
        uint16_t head = gpa_r16(cpu, v.driver + 4 + (uint64_t)slot * 2);
        uint64_t hdr = 0, data = 0, status = 0;
        uint32_t data_len = 0;
        uint32_t type = 0;
        uint64_t sector = 0;
        uint16_t cur = head, next_guard = 0;
        while (cur < v.queue_size && next_guard++ < 8) {
            uint8_t d[16];
            if (wemu_gpa_read(cpu, v.desc + (uint64_t)cur * 16, d, 16) != 0) return;
            uint64_t addr; uint32_t len; uint16_t flags, next;
            memcpy(&addr, d, 8); memcpy(&len, d + 8, 4);
            memcpy(&flags, d + 12, 2); memcpy(&next, d + 14, 2);
            if (hdr == 0) {
                uint8_t h[16] = {0};
                if (wemu_gpa_read(cpu, addr, h, 16) != 0) return;
                memcpy(&type, h, 4); memcpy(&sector, h + 8, 8);
                hdr = addr;
            } else if (data == 0 && (flags & 2u)) {
                if (status == 0 && len == 1) { status = addr; }
                else { data = addr; data_len = len; }
            } else if (status == 0 && len == 1) status = addr;
            if (!(flags & 1u)) break;
            cur = next;
        }
        uint64_t off = sector * BLK_SECTOR_BYTES;
        if (type == VIRTIO_BLK_T_IN && data && data_len &&
            off <= (uint64_t)BLK_SECTORS * BLK_SECTOR_BYTES &&
            data_len <= (uint64_t)BLK_SECTORS * BLK_SECTOR_BYTES - off) {
            if (wemu_gpa_write(cpu, data, v.disk + off, data_len) != 0) return;
        } else if (type == VIRTIO_BLK_T_OUT && data && data_len &&
                   off <= (uint64_t)BLK_SECTORS * BLK_SECTOR_BYTES &&
                   data_len <= (uint64_t)BLK_SECTORS * BLK_SECTOR_BYTES - off) {
            if (wemu_gpa_read(cpu, data, v.disk + off, data_len) != 0) return;
            if (v.disk_file && fseek(v.disk_file, (long)off, SEEK_SET) == 0) {
                (void)fwrite(v.disk + off, 1, data_len, v.disk_file);
                fflush(v.disk_file);
            }
        }
        if (status) {
            uint8_t ok = 0;
            if (type != VIRTIO_BLK_T_IN && type != VIRTIO_BLK_T_OUT &&
                type != VIRTIO_BLK_T_FLUSH) ok = 1;
            (void)wemu_gpa_write(cpu, status, &ok, 1);
        }
        uint8_t ue[8] = {0};
        memcpy(ue, &head, 2); /* id = head (u32, low half) */
        (void)wemu_gpa_write(cpu,
                             v.device + 4 + (uint64_t)(v.used_idx % v.queue_size) * 8,
                             ue, 8);
        v.used_idx++;
        gpa_w16(cpu, v.device + 2, v.used_idx);
        v.last_avail++;
    }
}

int wemu_virtio_mmio_read(WemuCpu *cpu, uint64_t gpa, void *dst, size_t len) {
    (void)cpu;
    if (gpa < VIRTIO_BAR_BASE || gpa >= VIRTIO_BAR_BASE + VIRTIO_BAR_LEN)
        return 1;
    if (len > VIRTIO_BAR_BASE + VIRTIO_BAR_LEN - gpa) return -1;
    if (trace_enabled() && (gpa - VIRTIO_BAR_BASE) < 0x40)
        fprintf(stderr, "VTRACE rd off=%02x len=%zu\n",
                (unsigned)(gpa - VIRTIO_BAR_BASE), len);
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
    if (trace_enabled()) {
        unsigned off0 = (unsigned)(gpa - VIRTIO_BAR_BASE);
        if (off0 < 0x40 || (off0 >= 0x1000 && off0 < 0x1002))
            fprintf(stderr, "VTRACE wr off=%02x len=%zu val=%02x\n", off0, len, len ? in[0] : 0);
    }
    for (size_t i = 0; i < len; i++) {
        unsigned off = (unsigned)(gpa + i - VIRTIO_BAR_BASE);
        if (off < 0x40) common_write8(off, in[i]);
        else if (off >= 0x1000 && off < 0x1002 && i == 0) process_queue(cpu);
    }
    return 0;
}
