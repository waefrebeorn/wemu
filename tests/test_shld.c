/* test_shld.c — SHLD/SHRD differential gate. The oracle is the HOST
 * CPU itself (inline asm) — hardware, not a shared C abstraction.
 * busybox seq faulted #UD on shld %cl,%r9,%rax (glibc memmove tail);
 * this gate keeps the double-precision shifts honest across widths,
 * count sources (imm8/CL), and edge counts. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "wemu.h"
#include "wemu_internal.h"

#define FAIL(...) do { fprintf(stderr, "FAIL: " __VA_ARGS__); exit(1); } while (0)

static uint64_t rnd(void) {
    static uint64_t s = 0x9e3779b97f4a7c15ull;
    s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s;
}

static uint64_t nat_shld64(uint64_t d, uint64_t s, uint8_t c) {
    uint64_t r = d;
    __asm__ volatile("shld %%cl, %1, %0" : "+r"(r) : "r"(s), "c"(c) : "cc");
    return r;
}
static uint64_t nat_shrd64(uint64_t d, uint64_t s, uint8_t c) {
    uint64_t r = d;
    __asm__ volatile("shrd %%cl, %1, %0" : "+r"(r) : "r"(s), "c"(c) : "cc");
    return r;
}
static uint32_t nat_shld32(uint32_t d, uint32_t s, uint8_t c) {
    uint32_t r = d;
    __asm__ volatile("shld %%cl, %1, %0" : "+r"(r) : "r"(s), "c"(c) : "cc");
    return r;
}
static uint32_t nat_shrd32(uint32_t d, uint32_t s, uint8_t c) {
    uint32_t r = d;
    __asm__ volatile("shrd %%cl, %1, %0" : "+r"(r) : "r"(s), "c"(c) : "cc");
    return r;
}
static uint16_t nat_shld16(uint16_t d, uint16_t s, uint8_t c) {
    uint16_t r = d;
    __asm__ volatile("shld %%cl, %1, %0" : "+r"(r) : "r"(s), "c"(c) : "cc");
    return r;
}
static uint16_t nat_shrd16(uint16_t d, uint16_t s, uint8_t c) {
    uint16_t r = d;
    __asm__ volatile("shrd %%cl, %1, %0" : "+r"(r) : "r"(s), "c"(c) : "cc");
    return r;
}

/* run one shld/shrd under WEMU: dest=rax(rm), src=rdx(reg), count=CL or imm */
static uint64_t emu(int left, int os, int use_imm, uint64_t d, uint64_t s,
                    uint8_t cnt, uint64_t *flags_out) {
    WemuCpu *c = wemu_cpu_create(0x10000);
    uint8_t code[16]; int n = 0;
    if (os == 2) code[n++] = 0x66;
    if (os == 8) code[n++] = 0x48;
    code[n++] = 0x0F;
    code[n++] = (uint8_t)(left ? (use_imm ? 0xA4 : 0xA5)
                               : (use_imm ? 0xAC : 0xAD));
    code[n++] = 0xD0; /* modrm: reg=2 (rdx=src), rm=0 (rax=dest) */
    if (use_imm) code[n++] = cnt;
    code[n++] = 0xF4;
    wemu_mem_write(c, 0x1000, code, (size_t)n);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_set_reg(c, 0, d);
    wemu_cpu_set_reg(c, 2, s);
    wemu_cpu_set_reg(c, 1, cnt);
    wemu_cpu_run(c, 4);
    if (wemu_cpu_fault(c)) FAIL("shld/shrd fault %d os=%d cnt=%d\n",
                                wemu_cpu_fault(c), os, cnt);
    uint64_t r = wemu_cpu_reg(c, 0);
    *flags_out = wemu_cpu_rflags(c);
    wemu_cpu_destroy(c);
    return r;
}

int main(void) {
    long rounds = 0;
    const int OS[3] = { 2, 4, 8 };
    for (int iter = 0; iter < 500; iter++) {
        uint64_t d = rnd(), s = rnd();
        uint8_t cnt = (uint8_t)(rnd() & 0xff);
        for (int w = 0; w < 3; w++) {
            int os = OS[w];
            uint64_t mask = os == 8 ? ~0ull : ((1ull << (os * 8)) - 1);
            uint64_t dm = d & mask, sm = s & mask;
            for (int left = 0; left < 2; left++) {
                for (int ui = 0; ui < 2; ui++) {
                    uint64_t f;
                    uint64_t got = emu(left, os, ui, dm, sm, cnt, &f);
                    unsigned bits = (unsigned)os * 8;
                    unsigned mc = cnt & (bits == 64 ? 63 : 31);
                    /* SDM: count > operand size leaves result/flags
                     * UNDEFINED (only 16-bit ops can reach it: mask 31).
                     * We implement QEMU semantics there; hardware quirks
                     * are not a contract. Gate the defined range only —
                     * emu() already asserted no fault for every case. */
                    if (os == 2 && mc >= 16) { rounds++; continue; }
                    uint64_t want;
                    if (os == 8) want = left ? nat_shld64(dm, sm, cnt)
                                             : nat_shrd64(dm, sm, cnt);
                    else if (os == 4) want = left ? nat_shld32((uint32_t)dm, (uint32_t)sm, cnt)
                                                  : nat_shrd32((uint32_t)dm, (uint32_t)sm, cnt);
                    else want = left ? nat_shld16((uint16_t)dm, (uint16_t)sm, cnt)
                                     : nat_shrd16((uint16_t)dm, (uint16_t)sm, cnt);
                    if (got != want)
                        FAIL("sh%s os=%d imm=%d d=%llx s=%llx cnt=%d: got %llx want %llx\n",
                             left ? "ld" : "rd", os, ui,
                             (unsigned long long)dm, (unsigned long long)sm,
                             cnt, (unsigned long long)got, (unsigned long long)want);
                    /* CF must match hardware for nonzero masked counts */
                    if (mc) {
                        uint64_t r = dm;
                        unsigned hwcf;
                        uint8_t cfbyte = 0;
                        /* explicit =a output + hardcoded setc %%al: no
                         * constraint-allocation ambiguity (the "rm" form
                         * miscompiled under register pressure). */
                        if (left) {
                            if (os == 8) __asm__ volatile("shld %%cl, %2, %0; setc %%al"
                                : "+r"(r), "=a"(cfbyte) : "r"(sm), "c"(cnt) : "cc");
                            else if (os == 4) { uint32_t r32 = (uint32_t)dm;
                                __asm__ volatile("shld %%cl, %2, %0; setc %%al"
                                    : "+r"(r32), "=a"(cfbyte) : "r"((uint32_t)sm), "c"(cnt) : "cc"); }
                            else { uint16_t r16 = (uint16_t)dm;
                                __asm__ volatile("shld %%cl, %2, %0; setc %%al"
                                    : "+r"(r16), "=a"(cfbyte) : "r"((uint16_t)sm), "c"(cnt) : "cc"); }
                        } else {
                            if (os == 8) __asm__ volatile("shrd %%cl, %2, %0; setc %%al"
                                : "+r"(r), "=a"(cfbyte) : "r"(sm), "c"(cnt) : "cc");
                            else if (os == 4) { uint32_t r32 = (uint32_t)dm;
                                __asm__ volatile("shrd %%cl, %2, %0; setc %%al"
                                    : "+r"(r32), "=a"(cfbyte) : "r"((uint32_t)sm), "c"(cnt) : "cc"); }
                            else { uint16_t r16 = (uint16_t)dm;
                                __asm__ volatile("shrd %%cl, %2, %0; setc %%al"
                                    : "+r"(r16), "=a"(cfbyte) : "r"((uint16_t)sm), "c"(cnt) : "cc"); }
                        }
                        hwcf = cfbyte;
                        if (((f & 1) != 0) != (hwcf != 0))
                            FAIL("CF mismatch sh%s os=%d cnt=%d d=%llx s=%llx: emu=%d hw=%d\n",
                                 left ? "ld" : "rd", os, cnt,
                                 (unsigned long long)dm, (unsigned long long)sm,
                                 (int)(f & 1), hwcf);
                    }
                    rounds++;
                }
            }
        }
    }
    /* the exact busybox seq instruction: shld %cl,%r9,%rax (REX.WR) */
    {
        WemuCpu *c = wemu_cpu_create(0x10000);
        uint8_t code[] = { 0x4C,0x0F,0xA5,0xC8, 0xF4 };
        wemu_mem_write(c, 0x1000, code, sizeof code);
        wemu_cpu_set_rip(c, 0x1000);
        wemu_cpu_set_reg(c, 0, 0x0123456789abcdefull);
        wemu_cpu_set_reg(c, 9, 0xfedcba9876543210ull);
        wemu_cpu_set_reg(c, 1, 12);
        wemu_cpu_run(c, 4);
        if (wemu_cpu_fault(c)) FAIL("seq-form shld fault %d\n", wemu_cpu_fault(c));
        uint64_t want = nat_shld64(0x0123456789abcdefull, 0xfedcba9876543210ull, 12);
        if (wemu_cpu_reg(c, 0) != want)
            FAIL("seq-form shld: got %llx want %llx\n",
                 (unsigned long long)wemu_cpu_reg(c, 0), (unsigned long long)want);
        wemu_cpu_destroy(c);
    }
    printf("SHLD/SHRD GATE PASS (%ld differential rounds vs host CPU + seq-form)\n", rounds);
    return 0;
}
