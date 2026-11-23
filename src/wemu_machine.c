/* wemu_machine.c — the machine layer: CPU + COM1 UART. One concern:
 * devices and their port I/O. Bare CPUs (no machine) ignore port I/O. */
#include "wemu_internal.h"
#include <stdlib.h>

#define COM1_RX_SIZE 256u
struct WemuMachine {
    WemuCpu *cpu;
    uint8_t rx[COM1_RX_SIZE];
    size_t head, tail, count;
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

void wemu_port_out(WemuCpu *cpu, uint16_t port, uint32_t val, int bytes) {
    (void)bytes;
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
    return m;
}

void wemu_machine_destroy(WemuMachine *m) {
    if (!m) return;
    wemu_cpu_destroy(m->cpu);
    free(m);
}

WemuCpu *wemu_machine_cpu(WemuMachine *m) { return m ? m->cpu : NULL; }