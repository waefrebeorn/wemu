/* test_isa.c — integer core gates: hand-assembled sequences with known
 * answers + a differential block (expected values/flags computed by an
 * INDEPENDENT C implementation, compared against the interpreter). */
#include "wemu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;
#define CHECK(cond, msg) do { if (!(cond)) { \
    printf("FAIL: %s (line %d)\n", msg, __LINE__); fails++; } } while (0)

static WemuCpu *boot(const uint8_t *code, size_t len) {
    WemuCpu *c = wemu_cpu_create(1 << 20);
    wemu_cpu_load(c, 0x1000, code, len);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_set_rsp(c, 0x80000);
    return c;
}

static void run(WemuCpu *c) {
    int64_t n = wemu_cpu_run(c, 100000);
    CHECK(n >= 0 && wemu_cpu_fault(c) == 0, "run faulted");
}

int main(void) {
    /* mov rax, 0x1122334455667788; mov rbx, 0x10; add rax, rbx; hlt */
    {
        uint8_t code[] = { 0x48,0xB8,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,
                           0x48,0xBB,0x10,0,0,0,0,0,0,0,
                           0x48,0x01,0xD8, 0xF4 };
        WemuCpu *c = boot(code, sizeof code); run(c);
        CHECK(wemu_cpu_reg(c, 0) == 0x1122334455667798ull, "mov64+add");
        CHECK(wemu_cpu_halted(c), "hlt");
        wemu_cpu_destroy(c);
    }
    /* push/pop + call/ret: call fwd; hlt; fwd: pop rax; ret */
    {
        uint8_t code[] = { 0x48,0xB8,0x42,0,0,0,0,0,0,0,   /* mov rax,42 */
                           0x50,                            /* push rax */
                           0xE8,0x02,0,0,0,                 /* call ret (+2) */
                           0x58,                            /* pop rax */
                           0xF4,                            /* hlt */
                           0xC3 };                          /* ret */
        WemuCpu *c = boot(code, sizeof code); run(c);
        CHECK(wemu_cpu_reg(c, 0) == 0x42, "call/ret/push/pop");
        CHECK(wemu_cpu_reg(c, 4) == 0x80000, "stack balanced");
        wemu_cpu_destroy(c);
    }
    /* loop: rcx=10; rax=0; body: add rax,rcx; dec rcx; jnz body; hlt */
    {
        uint8_t code[] = { 0x48,0xB9,0x0A,0,0,0,0,0,0,0,
                           0x48,0x31,0xC0,
                           0x48,0x01,0xC8,       /* add rax,rcx */
                           0x48,0xFF,0xC9,       /* dec rcx */
                           0x75,0xF8,            /* jnz -8 */
                           0xF4 };
        WemuCpu *c = boot(code, sizeof code); run(c);
        CHECK(wemu_cpu_reg(c, 0) == 55, "loop sum 1..10");
        wemu_cpu_destroy(c);
    }
    /* lea + SIB: rbx=0x2000; rcx=4; lea rax,[rbx+rcx*8+0x10] */
    {
        uint8_t code[] = { 0x48,0xBB,0x00,0x20,0,0,0,0,0,0,
                           0x48,0xB9,0x04,0,0,0,0,0,0,0,
                           0x48,0x8D,0x44,0xCB,0x10, 0xF4 };
        WemuCpu *c = boot(code, sizeof code); run(c);
        CHECK(wemu_cpu_reg(c, 0) == 0x2030, "lea sib disp");
        wemu_cpu_destroy(c);
    }
    /* memory: mov [0x3000], rax; mov rbx, [0x3000] */
    {
        uint8_t code[] = { 0x48,0xB8,0xEF,0xBE,0xAD,0xDE,0,0,0,0,
                           0x48,0xA3,0x00,0x30,0,0,0,0,0,0, /* mov [moffs],rax */
                           0x48,0x8B,0x1C,0x25,0x00,0x30,0,0, /* mov rbx,[0x3000] */
                           0xF4 };
        WemuCpu *c = boot(code, sizeof code); run(c);
        CHECK(wemu_cpu_reg(c, 3) == 0xDEADBEEFull, "mem roundtrip");
        wemu_cpu_destroy(c);
    }
    /* movzx/movsx + bswap */
    {
        uint8_t code[] = { 0x48,0xB8,0x80,0xFF,0,0,0,0,0,0,
                           0x48,0x0F,0xB6,0xC0,   /* movzx rax, al */
                           0x48,0x0F,0xBE,0xD8,   /* movsx rbx, al */
                           0x48,0x0F,0xC8,        /* bswap rax */
                           0xF4 };
        WemuCpu *c = boot(code, sizeof code); run(c);
        CHECK(wemu_cpu_reg(c, 0) == 0x8000000000000000ull, "bswap(movzx)");
        CHECK(wemu_cpu_reg(c, 3) == 0xFFFFFFFFFFFFFF80ull, "movsx negative");
        wemu_cpu_destroy(c);
    }
    /* shifts: mov rax, 0xFF00; shr rax, 4; shl rax, 2 */
    {
        uint8_t code[] = { 0x48,0xB8,0x00,0xFF,0,0,0,0,0,0,
                           0x48,0xC1,0xE8,0x04,
                           0x48,0xC1,0xE0,0x02, 0xF4 };
        WemuCpu *c = boot(code, sizeof code); run(c);
        CHECK(wemu_cpu_reg(c, 0) == 0x3FC0, "shr/shl");
        wemu_cpu_destroy(c);
    }
    /* differential: 8 ops x 4 widths x carry-in, vs independent C model.
     * The devil's-advocate expansion: the first gate only covered 6 ops
     * at 2 widths — survivorship bias. Real code uses 8/16-bit + adc/sbb. */
    {
        srand(1234);
        for (int t = 0; t < 800; t++) {
            uint64_t a = ((uint64_t)rand() << 32) | (unsigned)rand();
            uint64_t b = ((uint64_t)rand() << 32) | (unsigned)rand();
            static const int bitsof[4] = { 64, 32, 16, 8 };
            int bits = bitsof[t % 4];
            uint64_t mask = bits == 64 ? ~0ull : (1ull << bits) - 1;
            a &= mask; b &= mask;
            int op = (t / 4) % 8; /* add or adc sbb and sub xor cmp */
            static const uint8_t ops[8] = { 0x01,0x09,0x11,0x19,0x21,0x29,0x31,0x39 };
            int cin = (t / 32) & 1;
            uint8_t code[32]; int n = 0;
            if (bits == 8) {
                code[n++] = 0xB0; code[n++] = (uint8_t)a;
                code[n++] = 0xB3; code[n++] = (uint8_t)b;
                code[n++] = cin ? 0xF9 : 0xF8; /* stc/clc */
                code[n++] = ops[op] & ~1; code[n++] = 0xD8;
            } else {
                uint8_t pfx = bits == 16 ? 0x66 : 0x48;
                int immbytes = bits == 16 ? 2 : bits == 32 ? 4 : 8;
                if (bits == 32) { code[n++] = 0xB8; }
                else { code[n++] = pfx; code[n++] = 0xB8; }
                for (int i = 0; i < immbytes; i++) code[n++] = (uint8_t)(a >> (8*i));
                if (bits == 32) { code[n++] = 0xBB; }
                else { code[n++] = pfx; code[n++] = 0xBB; }
                for (int i = 0; i < immbytes; i++) code[n++] = (uint8_t)(b >> (8*i));
                code[n++] = cin ? 0xF9 : 0xF8;
                if (bits != 32) code[n++] = pfx;
                code[n++] = ops[op]; code[n++] = 0xD8;
            }
            code[n++] = 0xF4;
            WemuCpu *c = boot(code, (size_t)n); run(c);
            uint64_t exp;
            switch (op) {
            case 0: exp = (a + b) & mask; break;
            case 1: exp = a | b; break;
            case 2: exp = (a + b + (uint64_t)cin) & mask; break;
            case 3: exp = (a - b - (uint64_t)cin) & mask; break;
            case 4: exp = a & b; break;
            case 5: exp = (a - b) & mask; break;
            case 6: exp = a ^ b; break;
            default: exp = a; break;
            }
            CHECK(wemu_cpu_reg(c, 0) == exp, "differential value");
            if (op == 0 || op == 2 || op == 3 || op == 5) {
                int is_sub = op == 3 || op == 5;
                int c_in = (op == 2 || op == 3) ? cin : 0;
                __uint128_t ua = a, ub = b;
                int cf = is_sub ? (ua < ub + (unsigned)c_in)
                                : (((ua + ub + (unsigned)c_in) >> bits) & 1);
                int64_t sa = (int64_t)(a << (64 - bits)) >> (64 - bits);
                int64_t sb = (int64_t)(b << (64 - bits)) >> (64 - bits);
                __int128 sr = is_sub ? (__int128)sa - sb - c_in
                                     : (__int128)sa + sb + c_in;
                __int128 lim = (__int128)1 << (bits - 1);
                int of = sr >= lim || sr < -lim;
                uint64_t f = wemu_cpu_rflags(c);
                CHECK(((f & 1) != 0) == cf, "differential CF");
                CHECK(((f & 0x800) != 0) == of, "differential OF");
                CHECK(((f & 0x40) != 0) == (exp == 0), "differential ZF");
                CHECK(((f & 0x80) != 0) == ((exp >> (bits - 1)) & 1), "differential SF");
            }
            wemu_cpu_destroy(c);
        }
    }
    if (fails) { printf("test_isa: %d FAILURES\n", fails); return 1; }
    printf("test_isa: PASS (sequences + 800 differential cases, 8 ops x 4 widths x CF)\n");
    return 0;
}