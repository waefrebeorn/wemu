/* test_packuswb — host-differential gate for PACKUSWB (66 0F 67 /r).
 *
 * CI kernel artifact run caught 66 0F 67 C1 in gcc14-vectorized
 * interrupt_init after the SHUFPS gap was closed. Words from the low
 * destination half and the high source half are saturated independently
 * to unsigned bytes.
 */
#include "wemu.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <emmintrin.h>

#define CHECK(cond, ...) do { if (!(cond)) { \
    fprintf(stderr, "FAIL: " __VA_ARGS__); return 1; } } while (0)

static void host_pack(const uint8_t a[16], const uint8_t b[16], uint8_t out[16]) {
    __m128i va = _mm_loadu_si128((const __m128i *)a);
    __m128i vb = _mm_loadu_si128((const __m128i *)b);
    __m128i vr = _mm_packus_epi16(va, vb);
    _mm_storeu_si128((__m128i *)out, vr);
}

static int guest_pack(const uint8_t a[16], const uint8_t b[16], uint8_t out[16]) {
    uint8_t code[] = {
        0xF3,0x0F,0x6F,0x04,0x25,0x00,0x20,0x00,0x00,
        0xF3,0x0F,0x6F,0x0C,0x25,0x40,0x20,0x00,0x00,
        0x66,0x0F,0x67,0xC1,
        0xF3,0x0F,0x7F,0x04,0x25,0x80,0x20,0x00,0x00,
        0xF4
    };
    WemuCpu *c = wemu_cpu_create(0x10000);
    if (!c) return -1;
    wemu_mem_write(c, 0x2000, a, 16);
    wemu_mem_write(c, 0x2040, b, 16);
    wemu_cpu_load(c, 0x1000, code, sizeof code);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_run(c, 20);
    int fault = wemu_cpu_fault(c);
    if (!fault) wemu_mem_read(c, 0x2080, out, 16);
    wemu_cpu_destroy(c);
    return fault;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    uint64_t rng = 0xabcdef0123456789ull;
    int cases = 0;
    for (int i = 0; i < 256; i++) {
        uint8_t a[16], b[16], hout[16], gout[16];
        for (int k = 0; k < 16; k++) {
            rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
            a[k] = (uint8_t)rng;
            rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
            b[k] = (uint8_t)rng;
        }
        /* bias half the words to saturation boundaries */
        if (i & 1) { memset(a, 0x80, 4); memset(b + 8, 0x7F, 4); }
        host_pack(a, b, hout);
        int fault = guest_pack(a, b, gout);
        CHECK(fault == 0, "WEMU fault %d on packuswb case %d\n", fault, i);
        CHECK(memcmp(hout, gout, 16) == 0,
              "packuswb mismatch case %d\n  host %02x%02x%02x%02x%02x%02x%02x%02x\n"
              "  wemu %02x%02x%02x%02x%02x%02x%02x%02x\n", i,
              hout[0],hout[1],hout[2],hout[3],hout[4],hout[5],hout[6],hout[7],
              gout[0],gout[1],gout[2],gout[3],gout[4],gout[5],gout[6],gout[7]);
        cases++;
    }
    printf("test_packuswb: PASS (%d cases, host vs WEMU)\n", cases);
    return 0;
}
