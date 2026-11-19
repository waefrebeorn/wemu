/* test_cpuid.c — feature honesty: a guest probes CPUID/XGETBV before
 * emitting vector code. If we implement AVX2 but claim nothing, no real
 * guest will ever use it. Claim exactly what we execute. */
#include "wemu.h"
#include "wemu_internal.h"
#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(cond, msg) do { if (!(cond)) { \
    printf("FAIL: %s (line %d)\n", msg, __LINE__); fails++; } } while (0)

static WemuCpu *boot(const uint8_t *code, size_t len) {
    WemuCpu *c = wemu_cpu_create(1 << 20);
    wemu_cpu_load(c, 0x1000, code, len);
    wemu_cpu_set_rip(c, 0x1000);
    return c;
}

int main(void) {
    /* cpuid leaf 0: max leaf >= 7, vendor WuBuEmulator */
    {
        uint8_t code[] = { 0x48,0x31,0xC0, 0x0F,0xA2, 0xF4 }; /* xor eax; cpuid */
        WemuCpu *c = boot(code, sizeof code);
        wemu_cpu_run(c, 10);
        CHECK(wemu_cpu_reg(c, 0) >= 7, "max basic leaf >= 7");
        CHECK(wemu_cpu_reg(c, 3) == 0x75427557, "vendor WuBu (EBX)");
        wemu_cpu_destroy(c);
    }
    /* cpuid leaf 1: SSE2 (EDX26), AVX+OSXSAVE (ECX28/27) */
    {
        uint8_t code[] = { 0x48,0xB8,0x01,0,0,0,0,0,0,0, 0x0F,0xA2, 0xF4 };
        WemuCpu *c = boot(code, sizeof code);
        wemu_cpu_run(c, 10);
        CHECK((wemu_cpu_reg(c, 2) >> 26) & 1, "leaf1 EDX SSE2 claimed");
        CHECK((wemu_cpu_reg(c, 1) >> 28) & 1, "leaf1 ECX AVX claimed");
        CHECK((wemu_cpu_reg(c, 1) >> 27) & 1, "leaf1 ECX OSXSAVE claimed");
        wemu_cpu_destroy(c);
    }
    /* cpuid leaf 7: AVX2 (EBX5) — the founding instruction set */
    {
        uint8_t code[] = { 0x48,0xB8,0x07,0,0,0,0,0,0,0,
                           0x48,0x31,0xC9, 0x0F,0xA2, 0xF4 };
        WemuCpu *c = boot(code, sizeof code);
        wemu_cpu_run(c, 10);
        CHECK((wemu_cpu_reg(c, 3) >> 5) & 1, "leaf7 EBX AVX2 claimed");
        wemu_cpu_destroy(c);
    }
    /* xgetbv(0) = 7: x87+SSE+AVX state — guests enable AVX only if so */
    {
        uint8_t code[] = { 0x48,0x31,0xC9, 0x0F,0x01,0xD0, 0xF4 };
        WemuCpu *c = boot(code, sizeof code);
        wemu_cpu_run(c, 10);
        CHECK(wemu_cpu_fault(c) == 0, "xgetbv decoded");
        CHECK((wemu_cpu_reg(c, 0) & 0xffffffff) == 7, "XCR0 = x87|SSE|AVX");
        wemu_cpu_destroy(c);
    }
    /* vzeroupper clears upper halves after AVX use */
    {
        uint8_t code[] = { 0xC5,0xF9,0x6E,0xC6,        /* vmovd xmm0,esi */
                           0xC4,0xE2,0x7D,0x78,0xC0,   /* vpbroadcastb ymm0 */
                           0xC5,0xF8,0x77,             /* vzeroupper */
                           0xF4 };
        WemuCpu *c = boot(code, sizeof code);
        wemu_cpu_set_reg(c, 6, 0x42);
        wemu_cpu_run(c, 10);
        CHECK(wemu_cpu_fault(c) == 0, "vzeroupper decoded");
        int ok = 1;
        for (int i = 0; i < 16; i++) if (c->ymm_hi[0][i]) ok = 0;
        CHECK(ok, "vzeroupper cleared YMM upper");
        uint8_t lo[16];
        wemu_cpu_xmm(c, 0, lo);
        CHECK(lo[0] == 0x42, "low half preserved");
        wemu_cpu_destroy(c);
    }
    if (fails) { printf("test_cpuid: %d FAILURES\n", fails); return 1; }
    printf("test_cpuid: PASS (features claimed == features executed)\n");
    return 0;
}