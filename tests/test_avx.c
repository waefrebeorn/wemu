/* test_avx.c — the founding gate: vmovd + vpbroadcastb, the exact
 * instructions whose absence in qemu64 TCG triple-faulted the WuBuOS
 * CI boot. WEMU must execute the gcc14 memset vector body correctly.
 * Whitebox: reads ymm_hi via the internal struct. */
#include "wemu.h"
#include "wemu_internal.h"
#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(cond, msg) do { if (!(cond)) { \
    printf("FAIL: %s (line %d)\n", msg, __LINE__); fails++; } } while (0)

int main(void) {
    /* The CI sequence: vmovd xmm0, esi ; vpbroadcastb ymm0, xmm0
     * (c5 f9 6e c6)      (c4 e2 7d 78 c0) */
    {
        uint8_t code[] = { 0xC5,0xF9,0x6E,0xC6,
                           0xC4,0xE2,0x7D,0x78,0xC0, 0xF4 };
        WemuCpu *c = wemu_cpu_create(1 << 20);
        wemu_cpu_load(c, 0x1000, code, sizeof code);
        wemu_cpu_set_rip(c, 0x1000);
        wemu_cpu_set_reg(c, 6, 0x41); /* ESI = 'A' */
        wemu_cpu_run(c, 100);
        CHECK(wemu_cpu_fault(c) == 0, "vmovd/vpbroadcastb faulted");
        uint8_t lo[16], hi[16];
        wemu_cpu_xmm(c, 0, lo);
        memcpy(hi, c->ymm_hi[0], 16);
        int ok = 1;
        for (int i = 0; i < 16; i++) if (lo[i] != 0x41 || hi[i] != 0x41) ok = 0;
        CHECK(ok, "vpbroadcastb filled all 32 YMM bytes");
        wemu_cpu_destroy(c);
    }
    /* 128-bit form zeroes the upper half: vpbroadcastb xmm0, xmm0 */
    {
        uint8_t code[] = { 0xC5,0xF9,0x6E,0xC6,
                           0xC4,0xE2,0x79,0x78,0xC0, 0xF4 };
        WemuCpu *c = wemu_cpu_create(1 << 20);
        wemu_cpu_load(c, 0x1000, code, sizeof code);
        wemu_cpu_set_rip(c, 0x1000);
        wemu_cpu_set_reg(c, 6, 0x7F);
        memset(c->ymm_hi[0], 0xAA, 16);
        wemu_cpu_run(c, 100);
        uint8_t lo[16];
        wemu_cpu_xmm(c, 0, lo);
        int ok = 1;
        for (int i = 0; i < 16; i++) {
            if (lo[i] != 0x7F || c->ymm_hi[0][i] != 0) ok = 0;
        }
        CHECK(ok, "VEX.128 broadcast + upper-zero");
        wemu_cpu_destroy(c);
    }
    /* the full CI memset vector body against a real buffer:
     * vmovd xmm0,esi; vpbroadcastb ymm0,xmm0; vmovdqu [rdi],ymm0;
     * vmovdqu [rdi+0x20],ymm0; hlt  — compare with native memset. */
    {
        uint8_t code[] = { 0xC5,0xF9,0x6E,0xC6,
                           0xC4,0xE2,0x7D,0x78,0xC0,
                           0xC5,0xFE,0x7F,0x07,          /* vmovdqu [rdi],ymm0 */
                           0xC5,0xFE,0x7F,0x47,0x20,     /* vmovdqu [rdi+32],ymm0 */
                           0xF4 };
        WemuCpu *c = wemu_cpu_create(1 << 20);
        wemu_cpu_load(c, 0x1000, code, sizeof code);
        wemu_cpu_set_rip(c, 0x1000);
        wemu_cpu_set_reg(c, 6, 0x5A);
        wemu_cpu_set_reg(c, 7, 0x4000);
        wemu_cpu_run(c, 100);
        uint8_t got[64], want[64];
        memset(want, 0x5A, 64);
        wemu_mem_read(c, 0x4000, got, 64);
        CHECK(memcmp(got, want, 64) == 0, "CI memset body == native memset");
        wemu_cpu_destroy(c);
    }
    /* legacy SSE2: movd xmm0,eax; paddd xmm0,xmm1; pshufd; pxor */
    {
        uint8_t code[] = { 0x66,0x0F,0x6E,0xC0,        /* movd xmm0, eax */
                           0x66,0x0F,0x6E,0xCB,        /* movd xmm1, ebx */
                           0x66,0x0F,0xFE,0xC1,        /* paddd xmm0, xmm1 */
                           0x66,0x0F,0x70,0xC0,0x1B,   /* pshufd xmm0,xmm0,0x1B */
                           0xF4 };
        WemuCpu *c = wemu_cpu_create(1 << 20);
        wemu_cpu_load(c, 0x1000, code, sizeof code);
        wemu_cpu_set_rip(c, 0x1000);
        wemu_cpu_set_reg(c, 0, 100);
        wemu_cpu_set_reg(c, 3, 23);
        wemu_cpu_run(c, 100);
        uint8_t x[16];
        wemu_cpu_xmm(c, 0, x);
        uint32_t d[4];
        memcpy(d, x, 16);
        CHECK(d[3] == 123 && d[0] == 0 && d[1] == 0 && d[2] == 0,
              "movd+paddd+pshufd");
        wemu_cpu_destroy(c);
    }
    /* vpaddb ymm: 32 lanes of byte adds */
    {
        uint8_t code[] = { 0xC5,0xF9,0x6E,0xC0,        /* vmovd xmm0,eax */
                           0xC4,0xE2,0x7D,0x78,0xC0,   /* vpbroadcastb ymm0 */
                           0xC5,0xF9,0x6E,0xCB,        /* vmovd xmm1,ebx */
                           0xC4,0xE2,0x7D,0x78,0xC9,   /* vpbroadcastb ymm1 */
                           0xC5,0xF5,0xFC,0xC1,        /* vpaddb ymm0,ymm1,ymm1? */
                           0xF4 };
        /* vpaddb ymm0, ymm1, ymm1: vvvv=1 (vex[1]=~1<<3=0xF0|...), rm=1 */
        WemuCpu *c = wemu_cpu_create(1 << 20);
        wemu_cpu_load(c, 0x1000, code, sizeof code);
        wemu_cpu_set_rip(c, 0x1000);
        wemu_cpu_set_reg(c, 0, 200);
        wemu_cpu_set_reg(c, 3, 55);
        wemu_cpu_run(c, 100);
        uint8_t lo[16];
        wemu_cpu_xmm(c, 0, lo);
        int ok = 1;
        for (int i = 0; i < 16; i++)
            if (lo[i] != (uint8_t)(55 + 55) || c->ymm_hi[0][i] != 110) ok = 0;
        CHECK(ok, "vpaddb 256-bit lanes");
        wemu_cpu_destroy(c);
    }
    if (fails) { printf("test_avx: %d FAILURES\n", fails); return 1; }
    printf("test_avx: PASS (the CI-gap instructions execute correctly)\n");
    return 0;
}