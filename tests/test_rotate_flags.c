/* test_rotate_flags.c -- host-CPU differential gate for RCL/RCR with CL
 * and for the count==0 no-flag-change rule across the shift/rotate group.
 *
 * Oracle: the HOST x86-64 CPU via inline asm (pushfq/popfq), never a C
 * model. Intel SDM Vol.2B: RCL/RCR rotate a bits+1 ring that includes CF;
 * the count is masked to 5 bits (6 for REX.W), then reduced modulo the
 * ring width; a zero count changes no flag. OF is defined only for a
 * count of 1. https://www.felixcloutier.com/x86/rcl:rcr:rol:ror
 */
#include "wemu.h"
#include "wemu_internal.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define F_CF 0x1ull
#define F_PF 0x4ull
#define F_AF 0x10ull
#define F_ZF 0x40ull
#define F_SF 0x80ull
#define F_OF 0x800ull
#define F_MASK (F_CF | F_PF | F_AF | F_ZF | F_SF | F_OF)
#define POISON 0xA5A5A5A5A5A5A5A5ull

static long cases;
static int fails, shown;

static uint64_t rnd(void) {
    static uint64_t s = 0x243f6a8885a308d3ull;
    s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s;
}

/* Return the full RAX after the host rotate, publishing hardware flags. */
static uint64_t host_rot(int op, int bytes, uint64_t val, unsigned cnt,
                         uint64_t fi, uint64_t *fl) {
    uint64_t r = val, f = 0;
    if (bytes == 1 && op == 2) {
        uint64_t c = cnt & 31;
        __asm__ volatile("push %3\n\tpopfq\n\trclb %%cl,%b0\n\tpushfq\n\tpop %1"
            : "+a"(r), "=&r"(f) : "c"(c), "r"(fi) : "cc", "memory");
    } else if (bytes == 1) {
        uint64_t c = cnt & 31;
        __asm__ volatile("push %3\n\tpopfq\n\trcrb %%cl,%b0\n\tpushfq\n\tpop %1"
            : "+a"(r), "=&r"(f) : "c"(c), "r"(fi) : "cc", "memory");
    } else if (bytes == 2 && op == 2) {
        uint64_t c = cnt & 31;
        __asm__ volatile("push %3\n\tpopfq\n\trclw %%cl,%w0\n\tpushfq\n\tpop %1"
            : "+a"(r), "=&r"(f) : "c"(c), "r"(fi) : "cc", "memory");
    } else if (bytes == 2) {
        uint64_t c = cnt & 31;
        __asm__ volatile("push %3\n\tpopfq\n\trcrw %%cl,%w0\n\tpushfq\n\tpop %1"
            : "+a"(r), "=&r"(f) : "c"(c), "r"(fi) : "cc", "memory");
    } else if (bytes == 4 && op == 2) {
        uint64_t c = cnt & 31;
        __asm__ volatile("push %3\n\tpopfq\n\trcll %%cl,%k0\n\tpushfq\n\tpop %1"
            : "+a"(r), "=&r"(f) : "c"(c), "r"(fi) : "cc", "memory");
    } else if (bytes == 4) {
        uint64_t c = cnt & 31;
        __asm__ volatile("push %3\n\tpopfq\n\trcrl %%cl,%k0\n\tpushfq\n\tpop %1"
            : "+a"(r), "=&r"(f) : "c"(c), "r"(fi) : "cc", "memory");
    } else if (op == 2) {
        __asm__ volatile("push %3\n\tpopfq\n\trclq %%cl,%0\n\tpushfq\n\tpop %1"
            : "+a"(r), "=&r"(f) : "c"((uint64_t)(cnt & 63)), "r"(fi) : "cc", "memory");
    } else {
        __asm__ volatile("push %3\n\tpopfq\n\trcrq %%cl,%0\n\tpushfq\n\tpop %1"
            : "+a"(r), "=&r"(f) : "c"((uint64_t)(cnt & 63)), "r"(fi) : "cc", "memory");
    }
    *fl = f;
    return r;
}

static uint64_t emu_rot(int op, int bytes, uint64_t val, unsigned cnt,
                        uint64_t fi, uint64_t *fl) {
    WemuCpu *c = wemu_cpu_create(1 << 20);
    uint64_t mask = bytes == 8 ? ~0ull : ((1ull << (bytes * 8)) - 1);
    uint64_t dst = (POISON & ~mask) | (val & mask);
    uint8_t code[96]; int n = 0;
    code[n++] = 0x48; code[n++] = 0xB8; /* mov rax, dst */
    for (int i = 0; i < 8; i++) code[n++] = (uint8_t)(dst >> (8 * i));
    uint64_t cntv = bytes == 8 ? (cnt & 63) : (cnt & 31);
    code[n++] = 0x48; code[n++] = 0xB9; /* mov rcx, count */
    for (int i = 0; i < 8; i++) code[n++] = (uint8_t)(cntv >> (8 * i));
    if (bytes == 2) code[n++] = 0x66;
    if (bytes == 8) code[n++] = 0x48;
    if (bytes == 1) code[n++] = 0xD2;
    else code[n++] = 0xD3;
    code[n++] = (uint8_t)(0xC0 | (op << 3)); /* /2 RCL, /3 RCR, rm=RAX */
    code[n++] = 0xF4;
    wemu_cpu_load(c, 0x1000, code, (size_t)n);
    c->rflags = fi | 2ull; /* popfq-equivalent: bit 1 is reserved-set */
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_set_rsp(c, 0x80000);
    int64_t steps = wemu_cpu_run(c, 32);
    if (steps < 0 || wemu_cpu_fault(c)) {
        printf("FAIL: emu fault %d steps %lld (op=%d bytes=%d)\n",
               wemu_cpu_fault(c), (long long)steps, op, bytes);
        wemu_cpu_destroy(c); exit(1);
    }
    uint64_t r = wemu_cpu_reg(c, 0), f = wemu_cpu_rflags(c);
    wemu_cpu_destroy(c);
    *fl = f;
    return r;
}

static void one(int op, int bytes, uint64_t val, unsigned cnt, uint64_t fi) {
    uint64_t mask = bytes == 8 ? ~0ull : ((1ull << (bytes * 8)) - 1);
    uint64_t a = (POISON & ~mask) | (val & mask);
    uint64_t hf, ef, hr = host_rot(op, bytes, a, cnt, fi, &hf);
    uint64_t er = emu_rot(op, bytes, a, cnt, fi, &ef);
    cases++;
    /* OF is architecturally defined only when the effective count is 1;
     * for larger rotates hardware may leave it however it likes. A zero
     * count must change no flag at all, so all bits remain comparable. */
    uint64_t fm = F_MASK;
    unsigned eff = (cnt & (bytes == 8 ? 63u : 31u));
    if (cnt != 0 && eff != 1) fm &= ~F_OF;
    if (er == hr && (ef & fm) == (hf & fm)) return;
    fails++;
    if (shown++ < 30)
        printf("FAIL: %s/%d val=%llx cnt=%u fi=%llx | rax got %llx want %llx"
               " | flags got %llx want %llx\n",
               op == 2 ? "rcl" : "rcr", bytes * 8,
               (unsigned long long)val, cnt, (unsigned long long)fi,
               (unsigned long long)er, (unsigned long long)hr,
               (unsigned long long)(ef & F_MASK), (unsigned long long)(hf & F_MASK));
}

int main(void) {
    const int widths[3] = { 1, 2, 4 };
    const unsigned counts[] = { 0, 1, 2, 8, 15, 16, 17, 31, 32, 33, 63 };
    for (int w = 0; w < 3; w++)
        for (int op = 2; op <= 3; op++)
            for (unsigned ci = 0; ci < 2; ci++) {
                uint64_t fi = 0x8d5ull | ci; /* AF/ZF/SF/OF set, CF=ci */
                for (unsigned j = 0; j < sizeof counts / sizeof counts[0]; j++) {
                    one(op, widths[w], 0x0123456789abcdefull, counts[j], fi);
                    one(op, widths[w], 0x8000000000000001ull, counts[j], fi);
                }
                for (int t = 0; t < 200; t++)
                    one(op, widths[w], rnd(), (unsigned)(rnd() & 63), fi);
            }
    for (unsigned ci = 0; ci < 2; ci++) {
        uint64_t fi = 0x8d5ull | ci;
        for (unsigned j = 0; j < sizeof counts / sizeof counts[0]; j++) {
            one(2, 8, 0x0123456789abcdefull, counts[j], fi);
            one(3, 8, 0x8000000000000001ull, counts[j], fi);
        }
        for (int t = 0; t < 200; t++) {
            one(2, 8, rnd(), (unsigned)(rnd() & 63), fi);
            one(3, 8, rnd(), (unsigned)(rnd() & 63), fi);
        }
    }
    printf("test_rotate_flags: %s (%ld cases, %d failures; rcl/rcr 8/16/32/64,"
           " count 0, ring wrap, CF-in, OF count=1)\n",
           fails ? "FAIL" : "PASS", cases, fails);
    return fails ? 1 : 0;
}
