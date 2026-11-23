/* test_shufps — host-differential gate for SHUFPS/SHUFPD (0F C6 /r imm8).
 *
 * CI #150 RED: gcc14-vectorized interrupt_init used
 * `shufps $0x88,-0x50(%rcx),%xmm13` (44 0F C6 69 B0 88) and WEMU #UD'd.
 * The selector mapping is: low two outputs come from DEST, high two from
 * r/m; each 2-bit field selects a dword (or a qword with the 66 prefix).
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

typedef void (*HostShufFn)(const uint8_t *, const uint8_t *, uint8_t *);

static void host_shuf(int pd, uint8_t imm, const uint8_t a[16],
                      const uint8_t b[16], uint8_t out[16]) {
    long ps = sysconf(_SC_PAGESIZE);
    void *page = mmap(NULL, (size_t)ps, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { perror("mmap"); exit(2); }
    int n = 0;
    uint8_t code[32];
    uint8_t l0[] = {0xF3,0x0F,0x6F,0x07}; memcpy(code+n,l0,sizeof l0); n+=4;
    uint8_t l1[] = {0xF3,0x0F,0x6F,0x0E}; memcpy(code+n,l1,sizeof l1); n+=4;
    if (pd) code[n++] = 0x66;
    uint8_t sh[] = {0x0F,0xC6,0xC1,imm}; memcpy(code+n,sh,sizeof sh); n+=4;
    uint8_t st[] = {0xF3,0x0F,0x7F,0x02}; /* [rdx], xmm0 */ memcpy(code+n,st,sizeof st); n+=4;
    code[n++] = 0xC3;
    memcpy(page, code, (size_t)n);
    if (mprotect(page, (size_t)ps, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect"); exit(2);
    }
    HostShufFn fn;
    memcpy(&fn, &page, sizeof fn);
    fn(a, b, out);
    munmap(page, (size_t)ps);
}

static int guest_shuf(int pd, uint8_t imm, const uint8_t a[16],
                      const uint8_t b[16], uint8_t out[16]) {
    int n = 0;
    uint8_t code[64];
    uint8_t l0[] = {0xF3,0x0F,0x6F,0x04,0x25,0x00,0x20,0x00,0x00};
    uint8_t l1[] = {0xF3,0x0F,0x6F,0x0C,0x25,0x40,0x20,0x00,0x00};
    uint8_t st[] = {0xF3,0x0F,0x7F,0x04,0x25,0x80,0x20,0x00,0x00};
    memcpy(code+n,l0,sizeof l0); n+=9;
    memcpy(code+n,l1,sizeof l1); n+=9;
    if (pd) code[n++] = 0x66;
    uint8_t sh[] = {0x0F,0xC6,0xC1,imm}; memcpy(code+n,sh,sizeof sh); n+=4;
    memcpy(code+n,st,sizeof st); n+=9;
    code[n++] = 0xF4;
    WemuCpu *c = wemu_cpu_create(0x10000);
    if (!c) return -1;
    wemu_mem_write(c, 0x2000, a, 16);
    wemu_mem_write(c, 0x2040, b, 16);
    wemu_cpu_load(c, 0x1000, code, (size_t)n);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_run(c, 20);
    int fault = wemu_cpu_fault(c);
    if (!fault) wemu_mem_read(c, 0x2080, out, 16);
    wemu_cpu_destroy(c);
    return fault;
}

int main(void) {
    uint64_t rng = 0x1234abcd5678ef01ull;
    int cases = 0;
    for (int pd = 0; pd < 2; pd++) {
        for (unsigned imm = 0; imm < 256; imm++) {
            uint8_t a[16], b[16], hout[16], gout[16];
            for (int i = 0; i < 16; i++) {
                rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
                a[i] = (uint8_t)rng;
                rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
                b[i] = (uint8_t)rng;
            }
            host_shuf(pd, (uint8_t)imm, a, b, hout);
            int fault = guest_shuf(pd, (uint8_t)imm, a, b, gout);
            CHECK(fault == 0, "WEMU fault %d on %s imm=%02x\n", fault,
                  pd ? "shufpd" : "shufps", imm);
            CHECK(memcmp(hout, gout, 16) == 0,
                  "%s imm=%02x mismatch\n  host %02x%02x%02x%02x%02x%02x%02x%02x\n"
                  "  wemu %02x%02x%02x%02x%02x%02x%02x%02x\n",
                  pd ? "shufpd" : "shufps", imm,
                  hout[0],hout[1],hout[2],hout[3],hout[4],hout[5],hout[6],hout[7],
                  gout[0],gout[1],gout[2],gout[3],gout[4],gout[5],gout[6],gout[7]);
            cases++;
        }
    }
    printf("test_shufps: PASS (%d cases, host vs WEMU)\n", cases);
    return 0;
}
