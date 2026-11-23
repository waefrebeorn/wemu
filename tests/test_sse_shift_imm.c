/* test_sse_shift_imm — host-differential gate for SSE2 immediate shifts.
 *
 * CI run #148 caught the real kernel #UD'ing on 66 0F 71 /2 (PSRLW) in a
 * gcc14-vectorized memset. WEMU previously modeled only 0F 73 and treated
 * its /2 and /6 as WORD shifts; the SDM assigns word shifts to 0F 71,
 * dword shifts to 0F 72 and qword shifts to 0F 73. Every group is compared
 * here against the host CPU with the same bytes and the same input.
 */
#include "wemu.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define CHECK(cond, ...) do { if (!(cond)) { \
    fprintf(stderr, "FAIL: " __VA_ARGS__); return 1; } } while (0)

typedef void (*HostShiftFn)(const uint8_t *, uint8_t *);

/* Build a tiny native stub so both immediates are baked into the opcode
 * stream; inline-asm "r" constraints cannot feed .byte immediates. */
static void host_shift(uint8_t op, uint8_t reg, uint8_t imm,
                       const uint8_t in[16], uint8_t out[16]) {
    long ps = sysconf(_SC_PAGESIZE);
    void *page = mmap(NULL, (size_t)ps, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { perror("mmap"); exit(2); }
    uint8_t code[] = {
        0xF3, 0x0F, 0x6F, 0x07,             /* movdqu xmm0,[rdi] */
        0x66, 0x0F, op, (uint8_t)(0xC0 | (reg << 3)), imm,
        0xF3, 0x0F, 0x7F, 0x06,             /* movdqu [rsi],xmm0 */
        0xC3
    };
    memcpy(page, code, sizeof code);
    if (mprotect(page, (size_t)ps, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect"); exit(2);
    }
    HostShiftFn fn;
    memcpy(&fn, &page, sizeof fn);
    fn(in, out);
    munmap(page, (size_t)ps);
}

static int guest_shift(uint8_t op, uint8_t reg, uint8_t imm,
                       const uint8_t in[16], uint8_t out[16]) {
    uint8_t code[] = {
        0xF3, 0x0F, 0x6F, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00,
        0x66, 0x0F, op, (uint8_t)(0xC0 | (reg << 3)), imm,
        0xF3, 0x0F, 0x7F, 0x04, 0x25, 0x80, 0x20, 0x00, 0x00,
        0xF4
    };
    WemuCpu *c = wemu_cpu_create(0x10000);
    if (!c) return -1;
    wemu_mem_write(c, 0x2000, in, 16);
    wemu_cpu_load(c, 0x1000, code, sizeof code);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_run(c, 20);
    int fault = wemu_cpu_fault(c);
    if (!fault) wemu_mem_read(c, 0x2080, out, 16);
    wemu_cpu_destroy(c);
    return fault;
}

int main(void) {
    uint64_t rng = 0x5eed123456789abcull;
    static const uint8_t counts[] = {0, 1, 7, 15, 16, 31, 32, 63, 64, 255};
    struct { uint8_t op; uint8_t regs[5]; int n; } groups[] = {
        { 0x71, {2, 4, 6, 0, 0}, 3 },
        { 0x72, {2, 4, 6, 0, 0}, 3 },
        { 0x73, {2, 3, 6, 7, 0}, 4 },
    };
    int cases = 0;
    for (unsigned g = 0; g < 3; g++) {
        for (int r = 0; r < groups[g].n; r++) {
            uint8_t reg = groups[g].regs[r];
            for (unsigned k = 0; k < sizeof counts; k++) {
                uint8_t in[16], hout[16], gout[16];
                for (int i = 0; i < 16; i++) {
                    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
                    in[i] = (uint8_t)rng;
                }
                host_shift(groups[g].op, reg, counts[k], in, hout);
                int fault = guest_shift(groups[g].op, reg, counts[k], in, gout);
                CHECK(fault == 0, "WEMU fault %d on 66 0F %02X /%u imm=%u\n",
                      fault, groups[g].op, reg, counts[k]);
                CHECK(memcmp(hout, gout, 16) == 0,
                      "mismatch 66 0F %02X /%u imm=%u\n  host %02x%02x%02x%02x%02x%02x%02x%02x\n  wemu %02x%02x%02x%02x%02x%02x%02x%02x\n",
                      groups[g].op, reg, counts[k],
                      hout[0],hout[1],hout[2],hout[3],hout[4],hout[5],hout[6],hout[7],
                      gout[0],gout[1],gout[2],gout[3],gout[4],gout[5],gout[6],gout[7]);
                cases++;
            }
        }
    }
    printf("test_sse_shift_imm: PASS (%d cases, host vs WEMU)\n", cases);
    return 0;
}
