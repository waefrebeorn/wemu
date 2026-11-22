/* test_flag_diff.c — host-CPU differential gate for ADC/SBB/CMP/NEG flags.
 *
 * The oracle is the HOST x86-64 CPU (inline asm, result + pushfq/popfq),
 * never a shared C model.  All six architecturally-defined status flags
 * (CF/PF/AF/ZF/SF/OF) plus the full 64-bit destination GPR are compared
 * across 8/16/32/64-bit operands, both carry-in values, boundary operands
 * and random operands.
 *
 * SDM Vol.2B "SBB—Integer Subtraction with Borrow" (Vol. 2B 4-589):
 *     DEST <- (DEST - (SRC + CF)); OF, SF, ZF, AF, PF, CF set per result.
 *     https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf
 * SDM Vol.1 3-16: AF is set on a carry OR a borrow out of bit 3.
 *     https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-1-manual.pdf
 */
#include "wemu.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define F_CF 0x1ull
#define F_PF 0x4ull
#define F_AF 0x10ull
#define F_ZF 0x40ull
#define F_SF 0x80ull
#define F_OF 0x800ull
#define F_MASK (F_CF | F_PF | F_AF | F_ZF | F_SF | F_OF)

enum { OP_ADC, OP_SBB, OP_CMP, OP_NEG, NOPS };
static const char *opname[NOPS] = { "adc", "sbb", "cmp", "neg" };

static uint64_t rnd(void) {
    static uint64_t s = 0x9e3779b97f4a7c15ull;
    s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s;
}

/* Host oracle.  RAX starts as 'a' so the unchanged upper bits of 8/16-bit
 * operations are observable; BT sets CF from the carry-in; pushfq/popfq
 * capture the exact hardware flags after the instruction. */
static uint64_t host(int op, int bytes, uint64_t a, uint64_t b,
                     uint64_t cin, uint64_t *fl) {
    uint64_t r = a, f = 0;
    switch (op) {
    case OP_ADC:
        switch (bytes) {
        case 1: __asm__ volatile("bt $0,%2\n\tadc %b3,%b0\n\tpushfq\n\tpop %1"
                    : "+a"(r), "=&r"(f) : "r"(cin), "r"(b) : "cc", "memory"); break;
        case 2: __asm__ volatile("bt $0,%2\n\tadc %w3,%w0\n\tpushfq\n\tpop %1"
                    : "+a"(r), "=&r"(f) : "r"(cin), "r"(b) : "cc", "memory"); break;
        case 4: __asm__ volatile("bt $0,%2\n\tadc %k3,%k0\n\tpushfq\n\tpop %1"
                    : "+a"(r), "=&r"(f) : "r"(cin), "r"(b) : "cc", "memory"); break;
        default: __asm__ volatile("bt $0,%2\n\tadc %3,%0\n\tpushfq\n\tpop %1"
                    : "+a"(r), "=&r"(f) : "r"(cin), "r"(b) : "cc", "memory"); break;
        }
        break;
    case OP_SBB:
        switch (bytes) {
        case 1: __asm__ volatile("bt $0,%2\n\tsbb %b3,%b0\n\tpushfq\n\tpop %1"
                    : "+a"(r), "=&r"(f) : "r"(cin), "r"(b) : "cc", "memory"); break;
        case 2: __asm__ volatile("bt $0,%2\n\tsbb %w3,%w0\n\tpushfq\n\tpop %1"
                    : "+a"(r), "=&r"(f) : "r"(cin), "r"(b) : "cc", "memory"); break;
        case 4: __asm__ volatile("bt $0,%2\n\tsbb %k3,%k0\n\tpushfq\n\tpop %1"
                    : "+a"(r), "=&r"(f) : "r"(cin), "r"(b) : "cc", "memory"); break;
        default: __asm__ volatile("bt $0,%2\n\tsbb %3,%0\n\tpushfq\n\tpop %1"
                    : "+a"(r), "=&r"(f) : "r"(cin), "r"(b) : "cc", "memory"); break;
        }
        break;
    case OP_CMP:
        switch (bytes) {
        case 1: __asm__ volatile("bt $0,%2\n\tcmp %b3,%b0\n\tpushfq\n\tpop %1"
                    : "+a"(r), "=&r"(f) : "r"(cin), "r"(b) : "cc", "memory"); break;
        case 2: __asm__ volatile("bt $0,%2\n\tcmp %w3,%w0\n\tpushfq\n\tpop %1"
                    : "+a"(r), "=&r"(f) : "r"(cin), "r"(b) : "cc", "memory"); break;
        case 4: __asm__ volatile("bt $0,%2\n\tcmp %k3,%k0\n\tpushfq\n\tpop %1"
                    : "+a"(r), "=&r"(f) : "r"(cin), "r"(b) : "cc", "memory"); break;
        default: __asm__ volatile("bt $0,%2\n\tcmp %3,%0\n\tpushfq\n\tpop %1"
                    : "+a"(r), "=&r"(f) : "r"(cin), "r"(b) : "cc", "memory"); break;
        }
        break;
    case OP_NEG:
        switch (bytes) {
        case 1: __asm__ volatile("neg %b0\n\tpushfq\n\tpop %1"
                    : "+a"(r), "=&r"(f) : : "cc", "memory"); break;
        case 2: __asm__ volatile("neg %w0\n\tpushfq\n\tpop %1"
                    : "+a"(r), "=&r"(f) : : "cc", "memory"); break;
        case 4: __asm__ volatile("neg %k0\n\tpushfq\n\tpop %1"
                    : "+a"(r), "=&r"(f) : : "cc", "memory"); break;
        default: __asm__ volatile("neg %0\n\tpushfq\n\tpop %1"
                    : "+a"(r), "=&r"(f) : : "cc", "memory"); break;
        }
        break;
    default: abort();
    }
    *fl = f;
    return r;
}

/* Emit mov rax,a; mov rbx,b; stc/clc; <op rax,rbx or neg rax>; hlt. */
static uint64_t emu(int op, int bytes, uint64_t a, uint64_t b,
                    uint64_t cin, uint64_t *fl) {
    WemuCpu *c = wemu_cpu_create(1 << 20);
    uint8_t code[64]; int n = 0;
    code[n++] = 0x48; code[n++] = 0xB8;
    for (int i = 0; i < 8; i++) code[n++] = (uint8_t)(a >> (8 * i));
    code[n++] = 0x48; code[n++] = 0xBB;
    for (int i = 0; i < 8; i++) code[n++] = (uint8_t)(b >> (8 * i));
    code[n++] = cin ? 0xF9 : 0xF8;                    /* stc / clc */
    if (bytes == 2) code[n++] = 0x66;
    if (bytes == 8) code[n++] = 0x48;
    if (op == OP_NEG) {
        code[n++] = bytes == 1 ? 0xF6 : 0xF7;
        code[n++] = 0xD8;                              /* neg r/m, /3 (al/ax/eax/rax) */
    } else {
        static const uint8_t base[3] = { 0x10, 0x18, 0x38 }; /* adc/sbb/cmp */
        code[n++] = (uint8_t)(base[op] + (bytes == 1 ? 0 : 1));
        code[n++] = 0xD8;                              /* reg=rbx, rm=rax */
    }
    code[n++] = 0xF4;
    wemu_cpu_load(c, 0x1000, code, (size_t)n);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_set_rsp(c, 0x80000);
    int64_t steps = wemu_cpu_run(c, 32);
    if (steps < 0 || wemu_cpu_fault(c)) {
        printf("FAIL: %s bytes=%d a=%llx b=%llx cin=%llu: emu fault %d steps %lld\n",
               opname[op], bytes, (unsigned long long)a, (unsigned long long)b,
               (unsigned long long)cin, wemu_cpu_fault(c), (long long)steps);
        wemu_cpu_destroy(c);
        exit(1);
    }
    uint64_t r = wemu_cpu_reg(c, 0), f = wemu_cpu_rflags(c);
    wemu_cpu_destroy(c);
    *fl = f;
    return r;
}

static int fails, shown;
static long cases;

static void one(int op, int bytes, uint64_t a, uint64_t b, uint64_t cin) {
    uint64_t hf, ef, hr, er;
    uint64_t mask = bytes == 8 ? ~0ull : ((1ull << (bytes * 8)) - 1);
    a &= mask; b &= mask;
    /* 64-bit poison above the operand width; x86-64 leaves those bits
     * alone for 8/16-bit writes and zeroes them for 32-bit writes. */
    uint64_t poison = bytes == 8 ? a : (0xA5A5A5A5A5A5A5A5ull & ~mask) | a;
    hr = host(op, bytes, poison, b, cin, &hf);
    er = emu(op, bytes, poison, b, cin, &ef);
    cases++;
    if (er == hr && (ef & F_MASK) == (hf & F_MASK)) return;
    fails++;
    if (shown++ < 100) {
        printf("FAIL: %s r/m%d a=%llx b=%llx CF=%llu | rax got %llx want %llx"
               " | flags got %04x want %04x (CF%d/%d PF%d/%d AF%d/%d"
               " ZF%d/%d SF%d/%d OF%d/%d)\n",
               opname[op], bytes * 8, (unsigned long long)poison,
               (unsigned long long)b, (unsigned long long)cin,
               (unsigned long long)er, (unsigned long long)hr,
               (unsigned)(ef & F_MASK), (unsigned)(hf & F_MASK),
               !!(ef&F_CF), !!(hf&F_CF), !!(ef&F_PF), !!(hf&F_PF),
               !!(ef&F_AF), !!(hf&F_AF), !!(ef&F_ZF), !!(hf&F_ZF),
               !!(ef&F_SF), !!(hf&F_SF), !!(ef&F_OF), !!(hf&F_OF));
    }
}

int main(void) {
    /* Named regression — SBB r/m64 with SRC=~0 and CF=1.  SDM Vol.2B 4-589:
     * DEST <- DEST - (SRC + CF) = DEST - 2^64; the borrow must set CF for
     * every DEST.  The old `mb + carry_in` test wrapped to 0 and cleared
     * CF.  Hardware (Core i7-14650HX) reports CF=1, result unchanged. */
    one(OP_SBB, 8, 0x0123456789abcdefull, 0xffffffffffffffffull, 1);
    static const uint64_t edge[] = {
        0, 1, 2, 7, 8, 0x0f, 0x10, 0x11, 0x7f, 0x80, 0xff, 0x100,
        0x7fff, 0x8000, 0xffff, 0x1234, 0xaaaa, 0x5555,
        0x7fffffff, 0x80000000, 0xffffffff,
        0x7fffffffffffffffull, 0x8000000000000000ull,
        0xfffffffffffffff0ull, 0xffffffffffffffffull,
        0x0123456789abcdefull, 0xfedcba9876543210ull
    };
    const int widths[4] = { 1, 2, 4, 8 };
    /* Exhaustive-ish boundary cross product + random rounds. */
    for (int w = 0; w < 4; w++) {
        int bytes = widths[w];
        uint64_t mask = bytes == 8 ? ~0ull : ((1ull << (bytes * 8)) - 1);
        for (unsigned i = 0; i < sizeof edge / sizeof edge[0]; i++) {
            uint64_t a = edge[i] & mask;
            for (unsigned j = 0; j < sizeof edge / sizeof edge[0]; j++) {
                uint64_t b = edge[j] & mask;
                for (int cin = 0; cin < 2; cin++)
                    for (int op = 0; op < NOPS; op++)
                        one(op, bytes, a, b, (uint64_t)cin);
            }
        }
        for (int t = 0; t < 500; t++) {
            uint64_t a = rnd(), b = rnd();
            /* seed each round with boundary values often */
            if (t % 3 == 0) a = edge[rnd() % (sizeof edge / sizeof edge[0])];
            if (t % 5 == 0) b = edge[rnd() % (sizeof edge / sizeof edge[0])];
            a &= mask; b &= mask;
            for (int cin = 0; cin < 2; cin++)
                for (int op = 0; op < NOPS; op++)
                    one(op, bytes, a, b, (uint64_t)cin);
        }
    }
    if (fails) {
        printf("test_flag_diff: %d FAILURES / %ld cases\n", fails, cases);
        return 1;
    }
    printf("test_flag_diff: PASS (%ld cases vs host CPU, 4 widths x 4 ops,"
           " CF/PF/AF/ZF/SF/OF + full GPR)\n", cases);
    return 0;
}
