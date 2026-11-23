/* wemu_machine.c — the machine layer: CPU + COM1 UART. One concern:
 * devices and their port I/O. Bare CPUs (no machine) ignore port I/O. */
#include "wemu_internal.h"
#include <stdlib.h>
#include <stdio.h>

#define COM1_RX_SIZE 256u
#define PCI_CONFIG_ADDR 0xCF8u
#define PCI_CONFIG_DATA 0xCFCu
#define VIRTIO_VENDOR 0x1AF4u
#define VIRTIO_BLK_MODERN 0x1042u
struct WemuMachine {
    WemuCpu *cpu;
    uint8_t rx[COM1_RX_SIZE];
    size_t head, tail, count;
    uint32_t pci_addr;
    uint8_t pci_cfg[256];
};

/* WEMU_KBD_SEND feeds a minimal PS/2 scancode stream: port 0x64 reports
 * output-buffer-full, port 0x60 pops make/break pairs. No IRQ is faked;
 * the guest polls it via ps2_poll_keyboard(). */
static uint8_t kbd_q[64];
static unsigned kbd_head, kbd_count;

static int kbd_trace_enabled(void) {
    static int cached = -1;
    if (cached < 0) cached = getenv("WEMU_KBD_TRACE") != NULL;
    return cached;
}

static uint8_t ascii_scancode(unsigned char c) {
    switch (c) {
    case 'a': return 0x1e; case 'b': return 0x30; case 'c': return 0x2e;
    case 'd': return 0x20; case 'e': return 0x12; case 'f': return 0x21;
    case 'g': return 0x22; case 'h': return 0x23; case 'i': return 0x17;
    case 'j': return 0x24; case 'k': return 0x25; case 'l': return 0x26;
    case 'm': return 0x32; case 'n': return 0x31; case 'o': return 0x18;
    case 'p': return 0x19; case 'q': return 0x10; case 'r': return 0x13;
    case 's': return 0x1f; case 't': return 0x14; case 'u': return 0x1a;
    case 'v': return 0x2b; case 'w': return 0x11; case 'x': return 0x2d;
    case 'y': return 0x15; case 'z': return 0x2c;
    case '0': return 0x0b; case '1': return 0x02; case '2': return 0x03;
    case '3': return 0x04; case '4': return 0x05; case '5': return 0x06;
    case '6': return 0x07; case '7': return 0x08; case '8': return 0x09;
    case '9': return 0x0a;
    case ' ': return 0x39; case '\n': return 0x1c; case '\r': return 0x1c;
    default: return 0;
    }
}
static void kbd_push(uint8_t sc) {
    if (kbd_count >= sizeof kbd_q) return;
    kbd_q[(kbd_head + kbd_count) % sizeof kbd_q] = sc;
    kbd_count++;
}

size_t wemu_machine_queue_keyboard(WemuMachine *m, const char *text) {
    (void)m;
    if (!text || !*text) return 0;
    kbd_head = kbd_count = 0;
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        uint8_t sc = ascii_scancode(*p);
        if (sc) { kbd_push(sc); kbd_push((uint8_t)(sc | 0x80)); }
    }
    kbd_push(0x1c); kbd_push(0x9c);
    if (kbd_trace_enabled()) fprintf(stderr, "KBD queued=%u text=%s\n", kbd_count, text);
    return kbd_count;
}

static int rx_pop(WemuMachine *m, uint8_t *out) {
    if (!m || m->count == 0) return 0;
    *out = m->rx[m->tail];
    m->tail = (m->tail + 1) % COM1_RX_SIZE;
    m->count--;
    return 1;
}

/* i8042 PS/2 controller: no devices attached in WEMU. A status of 0
 * means output buffer empty and input buffer empty; returning 0xff here
 * made WuBuOS ps2_init spin forever waiting for phantom keyboard data. */
#define PS2_DATA 0x60
#define PS2_STATUS 0x64

/* COM1 registers */
#define COM1_DATA 0x3F8
#define COM1_IER  0x3F9
#define COM1_LSR  0x3FD

static void pci_cfg_put32(uint8_t *cfg, unsigned off, uint32_t v) {
    if (off > 252) return;
    for (int i = 0; i < 4; i++) cfg[off + (unsigned)i] = (uint8_t)(v >> (8 * i));
}

static uint32_t pci_cfg_get32(const uint8_t *cfg, unsigned off) {
    if (off > 252) return 0xffffffffu;
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v |= (uint32_t)cfg[off + (unsigned)i] << (8 * i);
    return v;
}

static void pci_cfg_init(uint8_t *cfg) {
    memset(cfg, 0xff, 256);              /* empty functions read all ones */
    memset(cfg, 0, 64);                  /* bus 0 dev 0 fn 0: our device */
    pci_cfg_put32(cfg, 0x00, ((uint32_t)VIRTIO_BLK_MODERN << 16) | VIRTIO_VENDOR);
    pci_cfg_put32(cfg, 0x04, 0x00100000u); /* CAPS bit expected by the driver */
    pci_cfg_put32(cfg, 0x08, 0x01800000u); /* mass-storage, subclass 0x80 (other) */
    cfg[0x0C] = 0x00;                    /* header type 0 */
    pci_cfg_put32(cfg, 0x20, 0x0F000000u); /* BAR4: 16 KiB MMIO at 0x0F000000 */
    pci_cfg_put32(cfg, 0x34, 0x40u);                    /* capability list head */
    /* virtio vendor caps: common @40 (16B), notify @50 (20B, so its
     * multiplier lives at 0x60 and the next cap is 0x70), ISR @70 (16B),
     * device config @80 (16B). cap_next values are ABSOLUTE offsets. */
    pci_cfg_put32(cfg, 0x40, 0x01105009u); /* 09 50 10 01 */
    pci_cfg_put32(cfg, 0x44, 4u);           /* bar 4 */
    pci_cfg_put32(cfg, 0x48, 0x00000000u);  /* common offset */
    pci_cfg_put32(cfg, 0x4C, 0x1000u);      /* common length */
    pci_cfg_put32(cfg, 0x50, 0x02147009u); /* 09 70 14 02 */
    pci_cfg_put32(cfg, 0x54, 4u);           /* bar 4 */
    pci_cfg_put32(cfg, 0x58, 0x00001000u);  /* notify offset */
    pci_cfg_put32(cfg, 0x5C, 0x1000u);      /* notify length */
    pci_cfg_put32(cfg, 0x60, 0u);           /* notify multiplier = 0 */
    pci_cfg_put32(cfg, 0x70, 0x03108009u); /* 09 80 10 03 */
    pci_cfg_put32(cfg, 0x74, 4u);
    pci_cfg_put32(cfg, 0x78, 0x00002000u);
    pci_cfg_put32(cfg, 0x7C, 0x1000u);
    pci_cfg_put32(cfg, 0x80, 0x04100009u); /* 09 00 10 04 */
    pci_cfg_put32(cfg, 0x84, 4u);
    pci_cfg_put32(cfg, 0x88, 0x00003000u);
    pci_cfg_put32(cfg, 0x8C, 0x1000u);
}

static int pci_trace(void) {
    static int cached = -1;
    if (cached < 0) cached = getenv("WEMU_PCI_TRACE") != NULL;
    return cached;
}

static int pci_selected(const WemuMachine *m) {
    return (m->pci_addr & 0x80000000u) &&
           ((m->pci_addr & 0x00FF0000u) == 0) &&
           ((m->pci_addr & 0x0000F800u) == 0) &&
           ((m->pci_addr & 0x00000700u) == 0);
}

void wemu_port_out(WemuCpu *cpu, uint16_t port, uint32_t val, int bytes) {
    WemuMachine *m = (WemuMachine *)cpu->machine_ud;
    (void)bytes;
    if (port == PCI_CONFIG_ADDR) {
        if (m) m->pci_addr = val;
        if (pci_trace()) fprintf(stderr, "PTRACE addr=%08x\n", val);
        return;
    }
    if (port == PCI_CONFIG_DATA && m && pci_selected(m)) {
        unsigned off = m->pci_addr & 0xFCu;
        if (pci_trace()) fprintf(stderr, "PTRACE wr off=%02x val=%08x\n", off, val);
        if (off == 0x20) val = (val & 0xFFFFC000u) | 0x4u; /* 16 KiB memory BAR */
        pci_cfg_put32(m->pci_cfg, off, val);
        return;
    }
    if (port == COM1_DATA && cpu->serial_out)
        cpu->serial_out((uint8_t)val, cpu->serial_ud);
    /* other ports: no device attached yet — writes are dropped honestly */
}

uint32_t wemu_port_in(WemuCpu *cpu, uint16_t port, int bytes) {
    WemuMachine *m = (WemuMachine *)cpu->machine_ud;
    if (port == COM1_LSR)
        return 0x60u | ((m && m->count) ? 1u : 0u); /* DR | THR empty | TSRE */
    if (port == COM1_DATA) {
        uint8_t b = 0;
        (void)rx_pop(m, &b);
        return b;
    }
    if (port == PCI_CONFIG_DATA) {
        if (!m || !pci_selected(m)) {
            if (pci_trace()) fprintf(stderr, "PTRACE rd EMPTY addr=%08x\n", m ? m->pci_addr : 0);
            return 0xffffffffu;
        }
        uint32_t v = pci_cfg_get32(m->pci_cfg, m->pci_addr & 0xFCu);
        if (pci_trace()) fprintf(stderr, "PTRACE rd off=%02x val=%08x\n",
                                 m->pci_addr & 0xFCu, v);
        return v;
    }
    if (port == PS2_STATUS) {
        if (kbd_trace_enabled()) fprintf(stderr, "KBD rd status=%u\n", kbd_count);
        return (uint8_t)(kbd_count ? 1u : 0u);
    }
    if (port == PS2_DATA) {
        if (kbd_trace_enabled()) fprintf(stderr, "KBD rd data count=%u\n", kbd_count);
        if (!kbd_count) return 0;
        uint8_t sc = kbd_q[kbd_head];
        kbd_head = (kbd_head + 1) % sizeof kbd_q;
        kbd_count--;
        return sc;
    }
    return bytes == 1 ? 0xff : bytes == 2 ? 0xffff : 0xffffffffu;
}

size_t wemu_machine_queue_input(WemuMachine *m, const void *data, size_t len) {
    if (!m || !data) return 0;
    const uint8_t *p = data;
    size_t accepted = 0;
    for (size_t i = 0; i < len && m->count < COM1_RX_SIZE; i++) {
        m->rx[m->head] = p[i];
        m->head = (m->head + 1) % COM1_RX_SIZE;
        m->count++;
        accepted++;
    }
    return accepted;
}

WemuMachine *wemu_machine_create(uint64_t ram_size, WemuSerialFn out, void *ud) {
    WemuMachine *m = calloc(1, sizeof *m);
    if (!m) return NULL;
    m->cpu = wemu_cpu_create(ram_size);
    if (!m->cpu) { free(m); return NULL; }
    m->cpu->serial_out = out;
    m->cpu->serial_ud = ud;
    m->cpu->machine_ud = m;
    m->cpu->mmio_read = wemu_virtio_mmio_read;
    m->cpu->mmio_write = wemu_virtio_mmio_write;
    pci_cfg_init(m->pci_cfg);
    wemu_virtio_reset();
    return m;
}

void wemu_machine_destroy(WemuMachine *m) {
    if (!m) return;
    wemu_cpu_destroy(m->cpu);
    free(m);
}

WemuCpu *wemu_machine_cpu(WemuMachine *m) { return m ? m->cpu : NULL; }