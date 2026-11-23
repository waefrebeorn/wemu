/* test_pinsrw — WEMU gate for 66 41 0F C4 /r imm8 (PINSRW with REX.B).
 * gcc14-vectorized ring-0 GEMV emitted this and faulted in the guest. */
#include "wemu.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define CHECK(cond, ...) do { if (!(cond)) { \
    fprintf(stderr, "FAIL: " __VA_ARGS__); return 1; } } while (0)

static int guest_pinsrw(const uint8_t in[16], uint64_t src,
                        unsigned imm, uint8_t out[16])
{
    uint8_t code[] = {
        0xF3,0x0F,0x6F,0x04,0x25,0x00,0x20,0x00,0x00, /* movdqu xmm0,[0x2000] */
        0x66,0x41,0x0F,0xC4,0xC0,(uint8_t)imm,        /* pinsrw xmm0,r8w,imm */
        0xF3,0x0F,0x7F,0x04,0x25,0x80,0x20,0x00,0x00, /* movdqu [0x2080],xmm0 */
        0xF4
    };
    WemuCpu *c = wemu_cpu_create(0x10000);
    if (!c) return -1;
    wemu_mem_write(c, 0x2000, in, 16);
    wemu_cpu_set_reg(c, 8, src);
    wemu_cpu_load(c, 0x1000, code, sizeof code);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_run(c, 20);
    int fault = wemu_cpu_fault(c);
    if (!fault) wemu_mem_read(c, 0x2080, out, 16);
    wemu_cpu_destroy(c);
    return fault;
}

int main(void)
{
    uint64_t rng = 0x13579bdf2468acefull;
    for (unsigned imm = 0; imm < 8; imm++) {
        uint8_t in[16], got[16], want[16];
        for (int i = 0; i < 16; i++) {
            rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
            in[i] = (uint8_t)rng;
        }
        uint64_t src = 0x123456789abcdef0ull ^ (rng & 0xffffu);
        memcpy(want, in, 16);
        uint16_t word = (uint16_t)src;
        memcpy(want + 2 * imm, &word, 2);
        int fault = guest_pinsrw(in, src, imm, got);
        CHECK(fault == 0, "WEMU fault %d on pinsrw imm=%u\n", fault, imm);
        CHECK(memcmp(got, want, 16) == 0,
              "pinsrw imm=%u mismatch (word=%04x)\n", imm, word);
    }
    printf("test_pinsrw: PASS (8 imm cases, REX.B source)\n");
    return 0;
}
