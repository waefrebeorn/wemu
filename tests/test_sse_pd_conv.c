/* test_sse_pd_conv — host-differential gate for UNPCKLPD and CVTPD2DQ.
 *
 * Long guest boot reached wubu_gaad_add_spirals and #GP'd on
 * 66 0F 14 (UNPCKLPD) followed by 66 0F E6 (CVTTPD2DQ). WEMU had no
 * handlers for either. Expectations come from real host instructions via an executable stub.
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

typedef void (*HostFn)(const uint8_t *, const uint8_t *, uint8_t *, uint8_t *);

static void host_ops(int round, const uint8_t a[16], const uint8_t b[16],
                     uint8_t unp[16], uint8_t cvt[16]) {
    long ps = sysconf(_SC_PAGESIZE);
    void *page = mmap(NULL, (size_t)ps, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { perror("mmap"); exit(2); }
    uint8_t code[] = {
        0xF3,0x0F,0x6F,0x07,                  /* movdqu xmm0,[rdi] */
        0xF3,0x0F,0x6F,0x0E,                  /* movdqu xmm1,[rsi] */
        0x66,0x0F,0x14,0xC1,                  /* unpcklpd xmm0,xmm1 */
        0xF3,0x0F,0x7F,0x02,                  /* movdqu [rdx],xmm0 */
        (uint8_t)(round ? 0xF2 : 0x66),0x0F,0xE6,0xC1, /* cvt(cvt)tpd2dq */
        0xF3,0x0F,0x7F,0x01,                  /* movdqu [rcx],xmm0 */
        0xC3
    };
    memcpy(page, code, sizeof code);
    if (mprotect(page, (size_t)ps, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect"); exit(2);
    }
    HostFn fn;
    memcpy(&fn, &page, sizeof fn);
    fn(a, b, unp, cvt);
    munmap(page, (size_t)ps);
}

static int guest_ops(int round, const uint8_t a[16], const uint8_t b[16],
                     uint8_t unp[16], uint8_t cvt[16]) {
    uint8_t code[] = {
        0xF3,0x0F,0x6F,0x04,0x25,0x00,0x20,0x00,0x00,
        0xF3,0x0F,0x6F,0x0C,0x25,0x40,0x20,0x00,0x00,
        0x66,0x0F,0x14,0xC1,             /* unpcklpd xmm0,xmm1 */
        0xF3,0x0F,0x7F,0x04,0x25,0x80,0x20,0x00,0x00,
        (uint8_t)(round ? 0xF2 : 0x66),0x0F,0xE6,0xC1, /* cvt(cvt)tpd2dq */
        0xF3,0x0F,0x7F,0x04,0x25,0xC0,0x20,0x00,0x00,
        0xF4
    };
    WemuCpu *c = wemu_cpu_create(0x10000);
    if (!c) return -1;
    wemu_mem_write(c, 0x2000, a, 16);
    wemu_mem_write(c, 0x2040, b, 16);
    wemu_cpu_load(c, 0x1000, code, sizeof code);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_run(c, 24);
    int fault = wemu_cpu_fault(c);
    if (!fault) {
        wemu_mem_read(c, 0x2080, unp, 16);
        wemu_mem_read(c, 0x20C0, cvt, 16);
    }
    wemu_cpu_destroy(c);
    return fault;
}

int main(void) {
    const double vals[] = {0.0, -0.0, 1.9, -2.9, 2147483647.0,
                           -2147483648.0, 1e300, -1e300};
    int cases = 0;
    for (int round = 0; round < 2; round++) {
    for (unsigned ia = 0; ia < 8; ia++) {
        for (unsigned ib = 0; ib < 8; ib++) {
            uint8_t a[16], b[16], hup[16], hcv[16], gup[16], gcv[16];
            double av[2] = {vals[ia], vals[(ia + 1) & 7]};
            double bv[2] = {vals[ib], vals[(ib + 1) & 7]};
            memcpy(a, av, 16);
            memcpy(b, bv, 16);
            host_ops(round, a, b, hup, hcv);
            int fault = guest_ops(round, a, b, gup, gcv);
            CHECK(fault == 0, "WEMU fault %d on pd-conv", fault);
            CHECK(memcmp(hup, gup, 16) == 0, "UNPCKLPD mismatch");
            CHECK(memcmp(hcv, gcv, 16) == 0, "CVTPD2DQ mismatch");
            cases++;
        }
    }
    }
    printf("test_sse_pd_conv: PASS (%d cases, host vs WEMU)\n", cases);
    return 0;
}
