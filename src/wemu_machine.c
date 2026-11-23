/* wemu_machine.c — the machine layer: CPU + COM1 UART. One concern:
 * devices and their port I/O. Bare CPUs (no machine) ignore port I/O. */
#include "wemu_internal.h"
#include <stdlib.h>

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
    pci_cfg_put32(cfg, 0x08, 0x01080000u); /* mass-storage, 0x08, prog 0 */
    cfg[0x0C] = 0x00;                    /* header type 0 */
    pci_cfg_put32(cfg, 0x20, 0x0F000000u); /* BAR4: 16 KiB MMIO at 0x0F000000 */
    cfg[0x34] = 0x40;                    /* capability list head */
    /* virtio vendor caps: common, notify, isr, device configuration */
    pci_cfg_put32(cfg, 0x40, 0x01100909u); cfg[0x44] = 4;
    pci_cfg_put32(cfg, 0x48, 0x00001000u); pci_cfg_put32(cfg, 0x4C, 0x1000u);
    pci_cfg_put32(cfg, 0x50, 0x02141009u); cfg[0x54] = 4;
    pci_cfg_put32(cfg, 0x58, 0x00001000u); pci_cfg_put32(cfg, 0x5C, 0x1000u);
    pci_cfg_put32(cfg, 0x60, 0x03101009u); cfg[0x64] = 4;
    pci_cfg_put32(cfg, 0x68, 0x00002000u); pci_cfg_put32(cfg, 0x6C, 0x1000u);
    pci_cfg_put32(cfg, 0x70, 0x04101009u); cfg[0x74] = 4;
    pci_cfg_put32(cfg, 0x78, 0x00003000u); pci_cfg_put32(cfg, 0x7C, 0x1000u);
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
    if (port == PCI_CONFIG_ADDR) { if (m) m->pci_addr = val; return; }
    if (port == PCI_CONFIG_DATA && m && pci_selected(m)) {
        unsigned off = m->pci_addr & 0xFCu;
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
        if (!m || !pci_selected(m)) return 0xffffffffu;
        return pci_cfg_get32(m->pci_cfg, m->pci_addr & 0xFCu);
    }
    if (port == PS2_DATA || port == PS2_STATUS) return 0;
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
    pci_cfg_init(m->pci_cfg);
    return m;
}

void wemu_machine_destroy(WemuMachine *m) {
    if (!m) return;
    wemu_cpu_destroy(m->cpu);
    free(m);
}

WemuCpu *wemu_machine_cpu(WemuMachine *m) { return m ? m->cpu : NULL; }