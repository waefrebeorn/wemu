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

/* Host oracle for the zero-count flag rule: preset RFLAGS with POPFQ,
 * execute the real width-specific shift, capture RFLAGS with PUSHFQ.
 * Width-typed operands matter — passing uint64_t would emit a 64-bit
 * SHLD and make the 16/32-bit cases look like emulator bugs. */
static uint64_t nat_flags(int left, int bytes, uint64_t d, uint64_t s,
                          uint8_t cnt, uint64_t preset, uint64_t *fl) {
    uint64_t r = d, f = preset;
    if (bytes == 2) {
        uint16_t r16 = (uint16_t)d, s16 = (uint16_t)s;
        if (left) __asm__ volatile("pushq %1\n\tpopfq\n\t"
                                   "shld %%cl,%w2,%w0\n\t"
                                   "pushfq\n\tpopq %1"
                                   : "+r"(r16), "+r"(f) : "r"(s16), "c"(cnt)
                                   : "cc", "memory");
        else      __asm__ volatile("pushq %1\n\tpopfq\n\t"
                                   "shrd %%cl,%w2,%w0\n\t"
                                   "pushfq\n\tpopq %1"
                                   : "+r"(r16), "+r"(f) : "r"(s16), "c"(cnt)
                                   : "cc", "memory");
        r = r16;
    } else if (bytes == 4) {
        uint32_t r32 = (uint32_t)d, s32 = (uint32_t)s;
        if (left) __asm__ volatile("pushq %1\n\tpopfq\n\t"
                                   "shld %%cl,%k2,%k0\n\t"
                                   "pushfq\n\tpopq %1"
                                   : "+r"(r32), "+r"(f) : "r"(s32), "c"(cnt)
                                   : "cc", "memory");
        else      __asm__ volatile("pushq %1\n\tpopfq\n\t"
                                   "shrd %%cl,%k2,%k0\n\t"
                                   "pushfq\n\tpopq %1"
                                   : "+r"(r32), "+r"(f) : "r"(s32), "c"(cnt)
                                   : "cc", "memory");
        r = r32;
    } else {
        if (left) __asm__ volatile("pushq %1\n\tpopfq\n\t"
                                   "shld %%cl,%2,%0\n\t"
                                   "pushfq\n\tpopq %1"
                                   : "+r"(r), "+r"(f) : "r"(s), "c"(cnt)
                                   : "cc", "memory");
        else      __asm__ volatile("pushq %1\n\tpopfq\n\t"
                                   "shrd %%cl,%2,%0\n\t"
                                   "pushfq\n\tpopq %1"
                                   : "+r"(r), "+r"(f) : "r"(s), "c"(cnt)
                                   : "cc", "memory");
    }
    *fl = f;
    return r;
}

/* Emulator side of the same probe: inject a known RFLAGS pattern
 * directly (the test already includes wemu_internal.h). */
static uint64_t emu_flags(int left, int os, int use_imm, uint64_t d, uint64_t s,
                          uint8_t cnt, uint64_t preset, uint64_t *fl) {
    WemuCpu *c = wemu_cpu_create(0x10000);
    uint8_t code[16]; int n = 0;
    if (os == 2) code[n++] = 0x66;
    if (os == 8) code[n++] = 0x48;
    code[n++] = 0x0F;
    code[n++] = (uint8_t)(left ? (use_imm ? 0xA4 : 0xA5)
                               : (use_imm ? 0xAC : 0xAD));
    code[n++] = 0xD0;                     /* reg=RDX(src), rm=RAX(dest) */
    if (use_imm) code[n++] = cnt;
    code[n++] = 0xF4;
    wemu_mem_write(c, 0x1000, code, (size_t)n);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_set_reg(c, 0, d);
    wemu_cpu_set_reg(c, 2, s);
    wemu_cpu_set_reg(c, 1, cnt);
    ((WemuCpu *)c)->rflags = preset;
    wemu_cpu_run(c, 4);
    if (wemu_cpu_fault(c)) FAIL("zero-count flags probe fault %d\n",
                                wemu_cpu_fault(c));
    uint64_t r = wemu_cpu_reg(c, 0);
    *fl = wemu_cpu_rflags(c);
    wemu_cpu_destroy(c);
    return r;
}

/* Named regression — SDM Vol.2B SHLD/SHRD "Flags Affected":
 *   "If the count operand is 0, the flags are not affected."
 * The Operation pseudocode masks COUNT first (MOD 32 / MOD 64) and then
 * takes the "COUNT = 0 -> No operation" branch, so a count that masks to
 * zero is the same case.  The old executor unconditionally rebuilt RFLAGS
 * with CF/OF/ZF/SF/PF cleared, turning STC; SHLD $0,%rdx,%rax into CLC. */
static long zero_count_flags(void) {
    static const int OS[3] = { 2, 4, 8 };
    static const uint64_t PRESET[2] = { 0x8d5, 0x2 }; /* all status flags set/clear */
    long cases = 0;
    for (int w = 0; w < 3; w++) {
        int bytes = OS[w];
        uint64_t mask = bytes == 8 ? ~0ull : ((1ull << (bytes * 8)) - 1);
        uint64_t d = 0x0123456789abcdefull & mask;
        uint64_t s = 0xfedcba9876543210ull & mask;
        uint8_t zero_counts[2] = { 0, (uint8_t)(bytes == 2 ? 32 : 64) };
        for (int left = 0; left < 2; left++) {
            for (int ui = 0; ui < 2; ui++) {
                for (unsigned pi = 0; pi < 2; pi++) {
                    for (int ci = 0; ci < 2; ci++) {
                        uint8_t cnt = zero_counts[ci];
                        uint64_t hf, ef, hr, er;
                        hr = nat_flags(left, bytes, d, s, cnt, PRESET[pi], &hf);
                        er = emu_flags(left, bytes, ui, d, s, cnt, PRESET[pi], &ef);
                        cases++;
                        if (er == hr && (ef & 0x8d5) == (hf & 0x8d5)) continue;
                        FAIL("zero-count flags sh%s r/m%d %s cnt=%d preset=%03llx:"
                             " r got %llx want %llx | flags got %03llx want %03llx\n",
                             left ? "ld" : "rd", bytes * 8, ui ? "imm" : "cl", cnt,
                             (unsigned long long)PRESET[pi],
                             (unsigned long long)er, (unsigned long long)hr,
                             (unsigned long long)(ef & 0x8d5),
                             (unsigned long long)(hf & 0x8d5));
                    }
                }
            }
        }
    }
    return cases;
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
    long zc = zero_count_flags();
    printf("SHLD/SHRD GATE PASS (%ld differential rounds vs host CPU + seq-form"
           " + %ld zero-count flag cases)\n", rounds, zc);
    return 0;
}
