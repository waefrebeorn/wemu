/* test_ps2_ports — idle i8042 status gate.
 *
 * WEMU used to return 0xff for every unmapped port, so port 0x64 reported
 * OBF=1 forever and WuBuOS ps2_init spun in `in $0x64,%al; test $1,%al`.
 * With no PS/2 devices attached, both the data and status ports must read
 * as idle (OBF=0, IBF=0). Executes the real IN instructions, not just a
 * direct helper call, so the gate covers decode and the machine layer.
 */
#include "wemu.h"
#include <stdio.h>
#include <stdint.h>

#define CHECK(cond, ...) do { if (!(cond)) { \
    fprintf(stderr, "FAIL: " __VA_ARGS__); return 1; } } while (0)

static uint8_t read_port(uint16_t port) {
    uint8_t code[] = { 0xE4, (uint8_t)(port & 0xff), 0xF4 };
    WemuCpu *c = wemu_cpu_create(0x10000);
    if (!c) return 0xff;
    wemu_cpu_load(c, 0x1000, code, sizeof code);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_run(c, 8);
    uint8_t v = (uint8_t)wemu_cpu_reg(c, 0);
    wemu_cpu_destroy(c);
    return v;
}

int main(void) {
    uint8_t st = read_port(0x64);
    uint8_t data = read_port(0x60);
    CHECK(st == 0, "port 0x64 status = %02x, want 00 (no phantom OBF)\n", st);
    CHECK(data == 0, "port 0x60 data = %02x, want 00 (no devices)\n", data);
    printf("test_ps2_ports: PASS (0x64=00, 0x60=00, no spin)\n");
    return 0;
}
