/* test_machine.c — the machine gate: flat code writes COM1 via port
 * I/O and via the syscall path; serial bytes must arrive exactly. */
#include "wemu.h"
#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(cond, msg) do { if (!(cond)) { \
    printf("FAIL: %s (line %d)\n", msg, __LINE__); fails++; } } while (0)

static char cap[256];
static int capn;
static void ser(uint8_t b, void *ud) {
    (void)ud;
    if (capn < (int)sizeof cap - 1) cap[capn++] = (char)b;
}

int main(void) {
    /* port I/O: mov dx,0x3F8; mov al,'W'; out dx,al; ... 'u','B','u'; hlt */
    {
        uint8_t code[] = { 0x66,0xBA,0xF8,0x03,
                           0xB0,'W', 0xEE,
                           0xB0,'u', 0xEE,
                           0xB0,'B', 0xEE,
                           0xB0,'u', 0xEE,
                           0xF4 };
        capn = 0;
        WemuMachine *m = wemu_machine_create(1 << 20, ser, NULL);
        WemuCpu *c = wemu_machine_cpu(m);
        wemu_cpu_load(c, 0x1000, code, sizeof code);
        wemu_cpu_set_rip(c, 0x1000);
        wemu_cpu_run(c, 1000);
        cap[capn] = 0;
        CHECK(strcmp(cap, "WuBu") == 0, "COM1 port-I/O serial output");
        CHECK(wemu_cpu_halted(c), "hlt after out");
        wemu_machine_destroy(m);
    }
    /* syscall path: write(1, msg, 4); exit(7) */
    {
        uint8_t code[] = {
            0x48,0xB8,0x01,0,0,0,0,0,0,0,        /* mov rax,1 (write) */
            0x48,0xBF,0x01,0,0,0,0,0,0,0,        /* mov rdi,1 (fd) */
            0x48,0xBE,0x00,0x30,0,0,0,0,0,0,     /* mov rsi,0x3000 */
            0x48,0xBA,0x04,0,0,0,0,0,0,0,        /* mov rdx,4 */
            0x0F,0x05,                            /* syscall */
            0x48,0xB8,0x3C,0,0,0,0,0,0,0,        /* mov rax,60 (exit) */
            0x48,0xBF,0x07,0,0,0,0,0,0,0,        /* mov rdi,7 */
            0x0F,0x05,                            /* syscall */
            0xF4 };
        capn = 0;
        WemuMachine *m = wemu_machine_create(1 << 20, ser, NULL);
        WemuCpu *c = wemu_machine_cpu(m);
        wemu_cpu_load(c, 0x1000, code, sizeof code);
        wemu_cpu_load(c, 0x3000, (const uint8_t *)"WEMU", 4);
        wemu_cpu_set_rip(c, 0x1000);
        wemu_cpu_run(c, 1000);
        cap[capn] = 0;
        CHECK(strcmp(cap, "WEMU") == 0, "syscall write -> serial");
        CHECK(wemu_cpu_halted(c), "exit halts");
        wemu_machine_destroy(m);
    }
    /* LSR read: in al, 0x3FD must report THR-empty (0x60) */
    {
        uint8_t code[] = { 0x66,0xBA,0xFD,0x03, 0xEC, 0xF4 }; /* mov dx,3FD; in al,dx; hlt */
        WemuMachine *m = wemu_machine_create(1 << 20, ser, NULL);
        WemuCpu *c = wemu_machine_cpu(m);
        wemu_cpu_load(c, 0x1000, code, sizeof code);
        wemu_cpu_set_rip(c, 0x1000);
        wemu_cpu_run(c, 10);
        CHECK((wemu_cpu_reg(c, 0) & 0xff) == 0x60, "COM1 LSR status");
        wemu_machine_destroy(m);
    }
    if (fails) { printf("test_machine: %d FAILURES\n", fails); return 1; }
    printf("test_machine: PASS (port I/O + syscall serial + LSR)\n");
    return 0;
}