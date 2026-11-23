/* test_serial_input — COM1 RX queue gate.
 *
 * WuBuOS's live console polls 0x3FD LSR bit 0 and reads bytes from 0x3F8.
 * WEMU previously returned a constant 0x60/0 for these ports, so the
 * console prompt could be displayed but never receive a command.
 */
#include "wemu.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define CHECK(cond, ...) do { if (!(cond)) { \
    fprintf(stderr, "FAIL: " __VA_ARGS__); return 1; } } while (0)

int main(void) {
    WemuMachine *m = wemu_machine_create(0x100000, NULL, NULL);
    WemuCpu *c = wemu_machine_cpu(m);
    if (!c) return 2;
    /* read LSR, then three data bytes into low memory */
    uint8_t code[] = {
        0xE5,0xFD,0x03,0x89,0xC3,   /* in eax,0x3fd; mov ebx,eax */
        0xE5,0xF8,0x03,0x89,0xC1,   /* in eax,0x3f8; mov ecx,eax */
        0xE5,0xF8,0x03,0x89,0xC2,   /* in eax,0x3f8; mov edx,eax */
        0xE5,0xF8,0x03,0x89,0xC6,   /* in eax,0x3f8; mov esi,eax */
        0xF4
    };
    wemu_cpu_load(c, 0x1000, code, sizeof code);
    wemu_cpu_set_rip(c, 0x1000);
    CHECK(wemu_machine_queue_input(m, "hi\n", 3) == 3, "queue accepted wrong count");
    wemu_cpu_run(c, 20);
    CHECK(wemu_cpu_fault(c) == 0, "serial input gate faulted");
    uint8_t lsr = (uint8_t)wemu_cpu_reg(c, 3);
    uint8_t data[3] = {(uint8_t)wemu_cpu_reg(c, 1),
                       (uint8_t)wemu_cpu_reg(c, 2),
                       (uint8_t)wemu_cpu_reg(c, 6)};
    CHECK((lsr & 1u) != 0, "LSR did not report data-ready");
    CHECK(memcmp(data, "hi\n", 3) == 0, "COM1 RX queue returned wrong bytes");
    CHECK(wemu_machine_queue_input(m, "x", 1) == 1, "second queue failed");
    wemu_machine_destroy(m);
    printf("test_serial_input: PASS (LSR DR + FIFO bytes)\n");
    return 0;
}
