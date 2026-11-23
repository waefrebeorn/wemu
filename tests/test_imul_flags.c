/* test_imul_flags.c — host-CPU differential gate for 3-operand IMUL.
 *
 * WEMU bug under test: the 0x69 / 0x6B handler reads the r/m source with
 * (int64_t)read_rm(c, in, os).  read_rm returns the operand ZERO-extended to
 * 64 bits, so with os=2/4 a negative source (e.g. 0xffffffff == -1) is
 * treated as a large POSITIVE value.  The truncated product in the
 * destination register happens to be correct modulo 2^(os*8), but the
 * CF/OF overflow test compares the wrongly-signed full product against the
 * sign-extended truncation and sets CF=OF=1 where hardware clears them.
 *
 * SDM Vol.2B "IMUL — Signed Multiply" (3-operand form): DEST <- SRC * imm
 * with both operands SIGN-extended; CF=OF=1 iff the signed product does not
 * fit in the destination operand width.  The 2-operand form has the
 * identical result and CF/OF definition (product is commutative), so an
 * inline-asm `imul r/m, r` on the host CPU is an independent oracle that
 * computes the exact architecturally-defined product and flags.
 */
#include "wemu.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define F_CF 0x1ull
#define F_OF 0x800ull
#define F_MASK (F_CF | F_OF)

static uint64_t rnd(void) {
    static uint64_t s = 0x9e3779b97f4a7c15ull;
    s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s;
}

/* Host oracle: signed multiply of the two already-width-correct values.
 * Returns the truncated result; *fl receives hardware RFLAGS. */
static uint64_t host_imul(int bytes, uint64_t src, uint64_t mul, uint64_t *fl) {
    uint64_t f = 0, r;
    switch (bytes) {
    case 2: {
        /* 16-bit writes preserve bits 63:16 of the destination register. */
        uint64_t s = (0xA5A5A5A5A5A5A5A5ull & ~0xffffull) | (src & 0xffff);
        __asm__ volatile("imulw %w2, %w0\n\tpushfq\n\tpop %1"
                         : "+a"(s), "=&r"(f) : "r"((uint16_t)mul)
                         : "cc", "memory");
        r = s; break;
    }
    case 4: {
        /* 32-bit writes zero-extend bits 63:32 on x86-64. */
        uint64_t s = src;
        __asm__ volatile("imull %k2, %k0\n\tpushfq\n\tpop %1"
                         : "+a"(s), "=&r"(f) : "r"((uint32_t)mul)
                         : "cc", "memory");
        r = s; break;
    }
    case 8: {
        uint64_t s = src, m = mul;
        __asm__ volatile("imulq %2, %0\n\tpushfq\n\tpop %1"
                         : "+a"(s), "=&r"(f) : "r"(m) : "cc", "memory");
        r = s; break;
    }
    default: abort();
    }
    *fl = f;
    return r;
}

/* Emit: mov rax,src; mov rcx,poison; <prefix> 69/6B C8 <imm>; hlt.
 * 69/6B modrm C8 = mod=11, reg=1 (RCX dest), rm=0 (RAX source). */
static uint64_t emu_imul(int bytes, int op, uint64_t src, uint64_t imm,
                         uint64_t *fl) {
    WemuCpu *c = wemu_cpu_create(1 << 20);
    uint8_t code[96]; int n = 0;
    code[n++] = 0x48; code[n++] = 0xB8; /* mov rax, src */
    for (int i = 0; i < 8; i++) code[n++] = (uint8_t)(src >> (8 * i));
    code[n++] = 0x48; code[n++] = 0xB9; /* mov rcx, poison */
    for (int i = 0; i < 8; i++) code[n++] = (uint8_t)(0xA5A5A5A5A5A5A5A5ull >> (8 * i));
    if (bytes == 2) code[n++] = 0x66;
    if (bytes == 8) code[n++] = 0x48;
    code[n++] = (uint8_t)op;
    code[n++] = 0xC8;
    if (op == 0x6B) {
        code[n++] = (uint8_t)imm;
    } else if (bytes == 2) {
        code[n++] = (uint8_t)imm; code[n++] = (uint8_t)(imm >> 8);
    } else {
        for (int i = 0; i < 4; i++) code[n++] = (uint8_t)(imm >> (8 * i));
    }
    code[n++] = 0xF4;
    wemu_cpu_load(c, 0x1000, code, (size_t)n);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_set_rsp(c, 0x80000);
    int64_t steps = wemu_cpu_run(c, 32);
    if (steps < 0 || wemu_cpu_fault(c)) {
        printf("FAIL: emu fault %d steps %lld (op=%02x bytes=%d)\n",
               wemu_cpu_fault(c), (long long)steps, op, bytes);
        wemu_cpu_destroy(c);
        exit(1);
    }
    uint64_t r = wemu_cpu_reg(c, 1), f = wemu_cpu_rflags(c);
    wemu_cpu_destroy(c);
    *fl = f;
    return r;
}

static int fails, shown;
static long cases;

static void record(const char *tag, uint64_t src, uint64_t imm,
                   uint64_t hr, uint64_t er, uint64_t hf, uint64_t ef) {
    cases++;
    if (er == hr && (ef & F_MASK) == (hf & F_MASK)) return;
    fails++;
    if (shown++ < 40) {
        printf("FAIL: %s src=%llx imm=%llx | got %llx want %llx | "
               "CF got %d want %d, OF got %d want %d\n",
               tag, (unsigned long long)src, (unsigned long long)imm,
               (unsigned long long)er, (unsigned long long)hr,
               !!(ef & F_CF), !!(hf & F_CF), !!(ef & F_OF), !!(hf & F_OF));
    }
}

static void one(int bytes, int op, uint64_t src, uint64_t imm_raw) {
    uint64_t mask = bytes == 8 ? ~0ull : ((1ull << (bytes * 8)) - 1);
    src &= mask;
    /* Architecturally the multiplier is sign-extended from its encoding. */
    uint64_t mul = (op == 0x6B) ? (uint64_t)(int64_t)(int8_t)imm_raw
                 : (bytes == 8) ? (uint64_t)(int64_t)(int32_t)imm_raw
                                : (imm_raw & mask);
    imm_raw &= mask;

    uint64_t hf, ef, hr, er;
    hr = host_imul(bytes, src, mul, &hf);
    er = emu_imul(bytes, op, src, imm_raw, &ef);
    char tag[64];
    snprintf(tag, sizeof tag, "imul%s r%d,rax,imm",
             op == 0x6B ? "8" : (bytes == 8 ? "64" : (bytes == 4 ? "32" : "16")),
             bytes * 8);
    record(tag, src, imm_raw, hr, er, hf, ef);
}

/* 2-operand form: 0F AF /r.  modrm C1 = dest RAX, src RCX. */
static uint64_t emu_imul2(int bytes, uint64_t src, uint64_t mul, uint64_t *fl) {
    WemuCpu *c = wemu_cpu_create(1 << 20);
    uint64_t mask = bytes == 8 ? ~0ull : ((1ull << (bytes * 8)) - 1);
    uint64_t poison = 0xA5A5A5A5A5A5A5A5ull;
    uint64_t dst = (poison & ~mask) | (src & mask);
    uint8_t code[96]; int n = 0;
    code[n++] = 0x48; code[n++] = 0xB8; /* mov rax, dst */
    for (int i = 0; i < 8; i++) code[n++] = (uint8_t)(dst >> (8 * i));
    code[n++] = 0x48; code[n++] = 0xB9; /* mov rcx, mul */
    for (int i = 0; i < 8; i++) code[n++] = (uint8_t)(mul >> (8 * i));
    if (bytes == 2) code[n++] = 0x66;
    if (bytes == 8) code[n++] = 0x48;
    code[n++] = 0x0F; code[n++] = 0xAF; code[n++] = 0xC1;
    code[n++] = 0xF4;
    wemu_cpu_load(c, 0x1000, code, (size_t)n);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_set_rsp(c, 0x80000);
    int64_t steps = wemu_cpu_run(c, 32);
    if (steps < 0 || wemu_cpu_fault(c)) {
        printf("FAIL: emu fault %d steps %lld (imul2 bytes=%d)\n",
               wemu_cpu_fault(c), (long long)steps, bytes);
        wemu_cpu_destroy(c);
        exit(1);
    }
    uint64_t r = wemu_cpu_reg(c, 0), f = wemu_cpu_rflags(c);
    wemu_cpu_destroy(c);
    *fl = f;
    return r;
}

static void one2(int bytes, uint64_t src, uint64_t mul) {
    uint64_t mask = bytes == 8 ? ~0ull : ((1ull << (bytes * 8)) - 1);
    src &= mask; mul &= mask;
    uint64_t hf, ef, hr = host_imul(bytes, src, mul, &hf);
    uint64_t er = emu_imul2(bytes, src, mul, &ef);
    char tag[64];
    snprintf(tag, sizeof tag, "imul2 r%d,rax,rcx", bytes * 8);
    record(tag, src, mul, hr, er, hf, ef);
}

int main(void) {
    /* Full width coverage: 16/32-bit sign extension plus REX.W 64-bit
     * overflow detection, which needs a product wider than 64 bits. */
    one(4, 0x69, 0xffffffffull, 2);
    one(2, 0x69, 0xffffull, 2);
    one(8, 0x69, 0xffffffffffffffffull, 2);
    one(8, 0x6B, 0x8000000000000000ull, 0x7f);

    static const uint64_t srcs[] = {
        0, 1, 2, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff,
        0x7fffffff, 0x80000000, 0xffffffff, 0x7fffffffffffffffull,
        0x8000000000000000ull, 0xffffffffffffffffull,
        0x0123456789abcdefull, 0xfedcba9876543210ull
    };
    static const uint64_t imms[] = {
        0, 1, 2, 3, 7, 0x7f, 0x80, 0xff, 0x7fff, 0x8000,
        0xffff, 0x7fffffff, 0x80000000, 0xffffffff
    };
    const int widths[3] = { 2, 4, 8 };
    const int ops[2] = { 0x69, 0x6B };
    for (int w = 0; w < 3; w++) {
        int bytes = widths[w];
        uint64_t mask = bytes == 8 ? ~0ull : ((1ull << (bytes * 8)) - 1);
        for (unsigned i = 0; i < sizeof srcs / sizeof srcs[0]; i++)
            for (unsigned j = 0; j < sizeof imms / sizeof imms[0]; j++) {
                for (int k = 0; k < 2; k++)
                    one(bytes, ops[k], srcs[i] & mask, imms[j] & 0xff);
                one2(bytes, srcs[i] & mask, imms[j] & mask);
            }
        for (int t = 0; t < 300; t++) {
            uint64_t s = rnd() & mask, m = rnd() & 0xff;
            if (t % 3 == 0) s = srcs[rnd() % (sizeof srcs / sizeof srcs[0])] & mask;
            for (int k = 0; k < 2; k++) one(bytes, ops[k], s, m);
            one2(bytes, s, m);
        }
    }
    if (fails) {
        printf("test_imul_flags: %d FAILURES / %ld cases\n", fails, cases);
        return 1;
    }
    printf("test_imul_flags: PASS (%ld cases vs host CPU; 16/32/64-bit,"
           " 69/6B/AF; CF/OF + full dest GPR)\n", cases);
    return 0;
}
