/* wemu_machine.c — the machine layer: CPU + COM1 UART. One concern:
 * devices and their port I/O. Bare CPUs (no machine) ignore port I/O. */
#include "wemu_internal.h"
#include <stdlib.h>

struct WemuMachine {
    WemuCpu *cpu;
};

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
    (void)cpu;
    if (port == COM1_LSR) return 0x60; /* THR empty + transmitter idle */
    if (port == COM1_DATA || port == PS2_DATA || port == PS2_STATUS) return 0;
    return bytes == 1 ? 0xff : bytes == 2 ? 0xffff : 0xffffffffu;
}

WemuMachine *wemu_machine_create(uint64_t ram_size, WemuSerialFn out, void *ud) {
    WemuMachine *m = calloc(1, sizeof *m);
    if (!m) return NULL;
    m->cpu = wemu_cpu_create(ram_size);
    if (!m->cpu) { free(m); return NULL; }
    m->cpu->serial_out = out;
    m->cpu->serial_ud = ud;
    return m;
}

void wemu_machine_destroy(WemuMachine *m) {
    if (!m) return;
    wemu_cpu_destroy(m->cpu);
    free(m);
}

WemuCpu *wemu_machine_cpu(WemuMachine *m) { return m ? m->cpu : NULL; }