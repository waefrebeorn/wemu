/* test_string.c — the devil's-advocate gate: real compiled code uses
 * rep stosb/movsb for memset/memcpy. An emulator that only runs picked
 * integer ops cannot run real programs. Differential vs native libc. */
#include "wemu.h"
#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(cond, msg) do { if (!(cond)) { \
    printf("FAIL: %s (line %d)\n", msg, __LINE__); fails++; } } while (0)

int main(void) {
    /* rep stosb: memset(0x4000, 0x5A, 100) */
    {
        uint8_t code[] = {
            0x48,0xBF,0x00,0x40,0,0,0,0,0,0,   /* mov rdi, 0x4000 */
            0xB0,0x5A,                          /* mov al, 0x5A */
            0x48,0xB9,0x64,0,0,0,0,0,0,0,      /* mov rcx, 100 */
            0xFC,                               /* cld */
            0xF3,0xAA,                          /* rep stosb */
            0xF4 };
        WemuCpu *c = wemu_cpu_create(1 << 20);
        wemu_cpu_load(c, 0x1000, code, sizeof code);
        wemu_cpu_set_rip(c, 0x1000);
        wemu_cpu_run(c, 100);
        uint8_t got[100], want[100];
        memset(want, 0x5A, 100);
        wemu_mem_read(c, 0x4000, got, 100);
        CHECK(wemu_cpu_fault(c) == 0, "rep stosb faulted");
        CHECK(memcmp(got, want, 100) == 0, "rep stosb == native memset");
        CHECK(wemu_cpu_reg(c, 1) == 0, "rcx drained");
        CHECK(wemu_cpu_reg(c, 7) == 0x4064, "rdi advanced");
        wemu_cpu_destroy(c);
    }
    /* rep movsq: memcpy 80 bytes */
    {
        uint8_t code[] = {
            0x48,0xBE,0x00,0x50,0,0,0,0,0,0,   /* mov rsi, 0x5000 */
            0x48,0xBF,0x00,0x60,0,0,0,0,0,0,   /* mov rdi, 0x6000 */
            0x48,0xB9,0x0A,0,0,0,0,0,0,0,      /* mov rcx, 10 */
            0xFC,
            0xF3,0x48,0xA5,                     /* rep movsq */
            0xF4 };
        WemuCpu *c = wemu_cpu_create(1 << 20);
        uint8_t src[80];
        for (int i = 0; i < 80; i++) src[i] = (uint8_t)(i * 7 + 3);
        wemu_cpu_load(c, 0x5000, src, 80);
        wemu_cpu_load(c, 0x1000, code, sizeof code);
        wemu_cpu_set_rip(c, 0x1000);
        wemu_cpu_run(c, 100);
        uint8_t got[80];
        wemu_mem_read(c, 0x6000, got, 80);
        CHECK(memcmp(got, src, 80) == 0, "rep movsq == native memcpy");
        wemu_cpu_destroy(c);
    }
    /* std + rep stosb backwards (DF=1) */
    {
        uint8_t code[] = {
            0x48,0xBF,0x63,0x40,0,0,0,0,0,0,   /* mov rdi, 0x4063 (end) */
            0xB0,0x99,
            0x48,0xB9,0x64,0,0,0,0,0,0,0,
            0xFD,                               /* std */
            0xF3,0xAA,
            0xFC,                               /* cld restore */
            0xF4 };
        WemuCpu *c = wemu_cpu_create(1 << 20);
        wemu_cpu_load(c, 0x1000, code, sizeof code);
        wemu_cpu_set_rip(c, 0x1000);
        wemu_cpu_run(c, 100);
        uint8_t got[100], want[100];
        memset(want, 0x99, 100);
        wemu_mem_read(c, 0x4000, got, 100);
        CHECK(memcmp(got, want, 100) == 0, "backwards rep stosb (DF=1)");
        CHECK(wemu_cpu_reg(c, 7) == 0x4000 - 1, "rdi walked down");
        wemu_cpu_destroy(c);
    }
    /* repe scasb: find first mismatch (memcmp-like) */
    {
        uint8_t code[] = {
            0x48,0xBF,0x00,0x70,0,0,0,0,0,0,
            0xB0,0x41,                          /* mov al, 'A' */
            0x48,0xB9,0x08,0,0,0,0,0,0,0,
            0xFC,
            0xF3,0xAE,                          /* repe scasb */
            0xF4 };
        WemuCpu *c = wemu_cpu_create(1 << 20);
        wemu_cpu_load(c, 0x7000, (const uint8_t *)"AAAABAAA", 8);
        wemu_cpu_load(c, 0x1000, code, sizeof code);
        wemu_cpu_set_rip(c, 0x1000);
        wemu_cpu_run(c, 100);
        CHECK(wemu_cpu_reg(c, 1) == 3, "repe scasb: 5 compares incl mismatch (rcx=3)");
        CHECK(wemu_cpu_reg(c, 7) == 0x7005, "rdi past the 'B'");
        wemu_cpu_destroy(c);
    }
    if (fails) { printf("test_string: %d FAILURES\n", fails); return 1; }
    printf("test_string: PASS (rep stos/movs/scas vs native, DF both ways)\n");
    return 0;
}