/* test_pextrw — host-differential gate for PEXTRW (66 0F C5 /r imm8).
 *
 * CI kernel artifact run caught 66 0F C5 D7 01 in gcc14-vectorized
 * interrupt_init. The imm selects one of eight words; the result is a
 * zero-extended 32-bit GPR value.
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

typedef void (*HostFn)(const uint8_t *, uint32_t *);

static void host_pextr(uint8_t imm, const uint8_t in[16], uint32_t *out) {
    long ps = sysconf(_SC_PAGESIZE);
    void *page = mmap(NULL, (size_t)ps, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { perror("mmap"); exit(2); }
    uint8_t code[] = {
        0xF3,0x0F,0x6F,0x07,           /* movdqu xmm0,[rdi] */
        0x66,0x0F,0xC5,0xC0,imm,       /* pextrw eax,xmm0,imm */
        0x89,0x06,                     /* mov [rsi],eax */
        0xC3
    };
    memcpy(page, code, sizeof code);
    if (mprotect(page, (size_t)ps, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect"); exit(2);
    }
    HostFn fn;
    memcpy(&fn, &page, sizeof fn);
    fn(in, out);
    munmap(page, (size_t)ps);
}

static int guest_pextr(uint8_t imm, const uint8_t in[16], uint32_t *out) {
    uint8_t code[] = {
        0xF3,0x0F,0x6F,0x04,0x25,0x00,0x20,0x00,0x00,
        0x66,0x0F,0xC5,0xC0,imm,
        0x89,0x04,0x25,0x80,0x20,0x00,0x00, /* mov [0x2080],eax */
        0xF4
    };
    WemuCpu *c = wemu_cpu_create(0x10000);
    if (!c) return -1;
    wemu_mem_write(c, 0x2000, in, 16);
    wemu_cpu_load(c, 0x1000, code, sizeof code);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_run(c, 20);
    int fault = wemu_cpu_fault(c);
    if (!fault) wemu_mem_read(c, 0x2080, out, 4);
    wemu_cpu_destroy(c);
    return fault;
}

int main(void) {
    uint64_t rng = 0x13579bdf2468acefull;
    int cases = 0;
    for (unsigned imm = 0; imm < 8; imm++) {
        for (int i = 0; i < 32; i++) {
            uint8_t in[16];
            uint32_t hout = 0, gout = 0;
            for (int k = 0; k < 16; k++) {
                rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
                in[k] = (uint8_t)rng;
            }
            host_pextr((uint8_t)imm, in, &hout);
            int fault = guest_pextr((uint8_t)imm, in, &gout);
            CHECK(fault == 0, "WEMU fault %d on pextrw imm=%u\n", fault, imm);
            CHECK(hout == gout, "pextrw imm=%u mismatch host=%08x wemu=%08x\n",
                  imm, hout, gout);
            cases++;
        }
    }
    printf("test_pextrw: PASS (%d cases, host vs WEMU)\n", cases);
    return 0;
}
