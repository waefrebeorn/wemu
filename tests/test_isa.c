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

/* flags expected by independent C semantics */
static uint64_t exp_flags_add(uint64_t a, uint64_t b, int bits) {
    uint64_t mask = bits == 64 ? ~0ull : (1ull << bits) - 1;
    uint64_t r = (a + b) & mask;
    uint64_t f = 2;
    if (!r) f |= 0x40;
    if (r >> (bits - 1)) f |= 0x80;
    if (bits < 64 ? (a + b) > mask : r < a) f |= 1;
    uint64_t sa = a >> (bits - 1), sb = b >> (bits - 1), sr = r >> (bits - 1);
    if (sa == sb && sr != sa) f |= 0x800;
    int p = 1; for (int i = 0; i < 8; i++) p ^= (r >> i) & 1;
    if (p) f |= 4;
    return f;
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
    /* differential: add/sub/and/or/xor/cmp at 64 and 32 bits */
    {
        srand(1234);
        for (int t = 0; t < 400; t++) {
            uint64_t a = ((uint64_t)rand() << 32) | (unsigned)rand();
            uint64_t b = ((uint64_t)rand() << 32) | (unsigned)rand();
            int bits = (t & 1) ? 64 : 32;
            uint64_t mask = bits == 64 ? ~0ull : 0xffffffffull;
            a &= mask; b &= mask;
            int op = t % 6; /* add or and sub xor cmp */
            static const uint8_t ops[6] = { 0x01, 0x09, 0x21, 0x29, 0x31, 0x39 };
            uint8_t rex = bits == 64 ? 0x48 : 0x40;
            int immbytes = bits == 64 ? 8 : 4;
            uint8_t code[24]; int n = 0;
            code[n++] = rex; code[n++] = 0xB8;
            for (int i = 0; i < immbytes; i++) code[n++] = (uint8_t)(a >> (8 * i));
            code[n++] = rex; code[n++] = 0xBB;
            for (int i = 0; i < immbytes; i++) code[n++] = (uint8_t)(b >> (8 * i));
            code[n++] = rex; code[n++] = ops[op]; code[n++] = 0xD8; /* op rax,rbx */
            code[n++] = 0xF4;
            WemuCpu *c = boot(code, (size_t)n); run(c);
            uint64_t exp;
            switch (op) {
            case 0: exp = (a + b) & mask; break;
            case 1: exp = a | b; break;
            case 2: exp = a & b; break;
            case 3: exp = (a - b) & mask; break;
            case 4: exp = a ^ b; break;
            default: exp = a; break; /* cmp leaves rax */
            }
            CHECK(wemu_cpu_reg(c, 0) == exp, "differential value");
            if (op == 0) {
                uint64_t ef = exp_flags_add(a, b, bits);
                uint64_t gf = wemu_cpu_rflags(c) & 0x8C5;
                CHECK(gf == (ef & 0x8C5), "differential add flags");
            }
            if (op == 3) { /* sub: ZF/SF/CF check */
                uint64_t f = wemu_cpu_rflags(c);
                CHECK(((f & 0x40) != 0) == (exp == 0), "sub ZF");
                CHECK(((f & 1) != 0) == (a < b), "sub CF");
            }
            wemu_cpu_destroy(c);
        }
    }
    if (fails) { printf("test_isa: %d FAILURES\n", fails); return 1; }
    printf("test_isa: PASS (sequences + 400 differential cases)\n");
    return 0;
}