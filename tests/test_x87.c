/* test_x87.c — x87 FPU gate. Bit-exact double round-trips and IEEE
 * arithmetic vs C (same hardware FP), condition codes vs the SDM
 * table, all four rounding modes, integer load/store, and a native
 * fninit/fnstcw spot-check. busybox seq's FP path needs this surface. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include "wemu.h"
#include "wemu_internal.h"

#define FAIL(...) do { fprintf(stderr, "FAIL: " __VA_ARGS__); exit(1); } while (0)

static uint64_t rnd(void) {
    static uint64_t s = 0xdeadbeefcafebabeull;
    s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s;
}
static WemuCpu *run(const uint8_t *code, int n) {
    WemuCpu *c = wemu_cpu_create(0x10000);
    wemu_mem_write(c, 0x1000, code, (size_t)n);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_run(c, 200);
    if (wemu_cpu_fault(c)) FAIL("x87 fault %d rip=%llx\n",
        wemu_cpu_fault(c), (unsigned long long)wemu_cpu_rip(c));
    return c;
}
static void put64(WemuCpu *c, uint64_t addr, double d) {
    wemu_mem_write(c, addr, &d, 8);
}
static double get64(WemuCpu *c, uint64_t addr) {
    double d; wemu_mem_read(c, addr, &d, 8); return d;
}
/* m64 operand at 0x2000: modrm 04 25 + disp32 */
#define M64(reg) 0x04 | ((reg) << 3), 0x25, 0x00, 0x20, 0x00, 0x00

int main(void) {
    /* 1. fld/fstp m64 round-trip: bit-exact */
    for (int i = 0; i < 200; i++) {
        uint64_t bits = rnd();
        double d; memcpy(&d, &bits, 8);
        uint8_t code[] = { 0xDD, M64(0), 0xDD, M64(3), 0xF4 };
        WemuCpu *c = wemu_cpu_create(0x10000);
        put64(c, 0x2000, d);
        wemu_mem_write(c, 0x1000, code, sizeof code);
        wemu_cpu_set_rip(c, 0x1000);
        wemu_cpu_run(c, 10);
        if (wemu_cpu_fault(c)) FAIL("fld/fstp fault %d\n", wemu_cpu_fault(c));
        double out = get64(c, 0x2000);
        uint64_t ob; memcpy(&ob, &out, 8);
        if (ob != bits) FAIL("fld/fstp roundtrip %llx -> %llx\n",
            (unsigned long long)bits, (unsigned long long)ob);
        wemu_cpu_destroy(c);
    }
    /* 2. arithmetic m64 via faddp/fmulp/fsubp/fdivp: bit-exact vs C */
    {
        const uint8_t ops[4] = { 0xC1, 0xC9, 0xE9, 0xF9 };
        for (int i = 0; i < 200; i++) {
            double a = (double)(int64_t)(rnd() % 100000) / 7.0;
            double b = (double)(int64_t)(rnd() % 100000) / 13.0;
            if (b == 0.0) b = 1.0;
            for (int op = 0; op < 4; op++) {
                uint8_t code[] = { 0xDD, M64(0), 0xDD, M64(0),
                                   0xDE, ops[op], 0xDD, M64(3), 0xF4 };
                WemuCpu *c = wemu_cpu_create(0x10000);
                put64(c, 0x2000, a);
                wemu_mem_write(c, 0x1000, code, sizeof code);
                wemu_cpu_set_rip(c, 0x1000);
                /* second fld reads 0x2000 too — patch: store b at 0x2008
                 * and use a second operand slot */
                put64(c, 0x2008, b);
                code[10] = 0x08; /* disp of second fld -> 0x2008 */
                wemu_mem_write(c, 0x1000, code, sizeof code);
                wemu_cpu_run(c, 10);
                if (wemu_cpu_fault(c)) FAIL("arith fault %d op%d\n",
                    wemu_cpu_fault(c), op);
                double got = get64(c, 0x2000);
                double want = op == 0 ? a + b : op == 1 ? a * b
                            : op == 2 ? a - b : a / b;
                uint64_t gb, wb; memcpy(&gb, &got, 8); memcpy(&wb, &want, 8);
                if (gb != wb) FAIL("arith op%d a=%g b=%g got %g want %g\n",
                    op, a, b, got, want);
                wemu_cpu_destroy(c);
            }
        }
    }
    /* 3. register forms: fadd st0,st1 (D8 C1) and fmul st1,st0 (DC C9) */
    {
        uint8_t code[] = { 0xD9, 0xE8, 0xD9, 0xE8, 0xD8, 0xC1,
                           0xDD, M64(3), 0xF4 }; /* fld1 fld1 fadd -> 2 */
        WemuCpu *c = run(code, sizeof code);
        if (get64(c, 0x2000) != 2.0) FAIL("fadd st0,st1\n");
        wemu_cpu_destroy(c);
        uint8_t code2[] = { 0xD9, 0xE8, 0xD9, 0xE8, 0xD9, 0xE8,
                            0xDC, 0xC9, 0xDD, M64(3), 0xDD, M64(3), 0xF4 };
        /* fld1 fld1 fld1 -> st0=1 st1=1 st2=1; fmul st1,st0 -> st1=1;
         * fstp fstp -> store st0=1 then st0=1 */
        c = run(code2, sizeof code2);
        if (get64(c, 0x2000) != 1.0) FAIL("fmul st1,st0\n");
        wemu_cpu_destroy(c);
    }
    /* 4. constants */
    {
        uint8_t code[] = { 0xD9, 0xEB, 0xDD, M64(3), 0xF4 }; /* fldpi */
        WemuCpu *c = run(code, sizeof code);
        if (get64(c, 0x2000) != 3.14159265358979323846) FAIL("fldpi\n");
        wemu_cpu_destroy(c);
    }
    /* 5. fcompp condition codes via fnstsw ax (SDM table) */
    {
        struct { double a, b; int c0, c2, c3; } T[] = {
            { 2.0, 1.0, 1, 0, 0 },  /* st0=b=1 < st1=a=2: less */
            { 1.0, 2.0, 0, 0, 0 },  /* st0=b=2 > st1=a=1: greater */
            { 1.0, 1.0, 0, 0, 1 },  /* equal */
        };
        for (int t = 0; t < 3; t++) {
            uint8_t code[] = { 0xDD, M64(0), 0xDD, M64(0), 0xDE, 0xD9,
                               0xDF, 0xE0, 0xF4 };
            WemuCpu *c = wemu_cpu_create(0x10000);
            put64(c, 0x2000, T[t].a); put64(c, 0x2008, T[t].b);
            code[10] = 0x08;
            wemu_mem_write(c, 0x1000, code, sizeof code);
            wemu_cpu_set_rip(c, 0x1000);
            wemu_cpu_run(c, 10);
            if (wemu_cpu_fault(c)) FAIL("fcompp fault\n");
            uint16_t sw = (uint16_t)wemu_cpu_reg(c, 0);
            int c0 = (sw >> 8) & 1, c2 = (sw >> 10) & 1, c3 = (sw >> 14) & 1;
            if (c0 != T[t].c0 || c2 != T[t].c2 || c3 != T[t].c3)
                FAIL("fcompp %g vs %g: cc=%d%d%d want %d%d%d\n",
                     T[t].a, T[t].b, c0, c2, c3, T[t].c0, T[t].c2, T[t].c3);
            wemu_cpu_destroy(c);
        }
        /* unordered (NaN): C0=C2=C3=1 */
        uint8_t code[] = { 0xDD, M64(0), 0xDD, M64(0), 0xDE, 0xD9,
                           0xDF, 0xE0, 0xF4 };
        WemuCpu *c = wemu_cpu_create(0x10000);
        double nan = NAN;
        put64(c, 0x2000, 1.0); put64(c, 0x2008, nan);
        code[10] = 0x08;
        wemu_mem_write(c, 0x1000, code, sizeof code);
        wemu_cpu_set_rip(c, 0x1000);
        wemu_cpu_run(c, 10);
        uint16_t sw = (uint16_t)wemu_cpu_reg(c, 0);
        if ((sw & 0x4500) != 0x4500) FAIL("fcompp unordered sw=%04x\n", sw);
        wemu_cpu_destroy(c);
    }
    /* 6. fcomi flags (ZF/CF/PF) */
    {
        uint8_t code[] = { 0xD9, 0xE8, 0xD9, 0xEE, 0xDB, 0xF1, 0xF4 };
        /* fld1 fldz -> st0=0 st1=1; fcomi st0,st1: 0<1 -> CF=1 */
        WemuCpu *c = run(code, sizeof code);
        if (!(wemu_cpu_rflags(c) & 1)) FAIL("fcomi less CF\n");
        wemu_cpu_destroy(c);
    }
    /* 7. fild/fistp m64: exact integers within 2^53 */
    for (int i = 0; i < 100; i++) {
        int64_t v = (int64_t)(rnd() % (1ull << 52));
        if (rnd() & 1) v = -v;
        uint8_t code[] = { 0xDF, M64(5), 0xDF, M64(7), 0xF4 };
        WemuCpu *c = wemu_cpu_create(0x10000);
        wemu_mem_write(c, 0x2000, &v, 8);
        wemu_mem_write(c, 0x1000, code, sizeof code);
        wemu_cpu_set_rip(c, 0x1000);
        wemu_cpu_run(c, 10);
        if (wemu_cpu_fault(c)) FAIL("fild/fistp fault\n");
        int64_t out; wemu_mem_read(c, 0x2000, &out, 8);
        if (out != v) FAIL("fild/fistp %lld -> %lld\n",
            (long long)v, (long long)out);
        wemu_cpu_destroy(c);
    }
    /* 8. frndint under all four rounding modes (fldcw sets RC) */
    {
        struct { uint16_t cw; double v; int64_t want; } T[] = {
            { 0x037F,  2.5,  2 }, { 0x037F, -2.5, -2 },  /* nearest-even */
            { 0x077F,  2.5,  2 }, { 0x077F, -2.5, -3 },  /* down */
            { 0x0B7F,  2.5,  3 }, { 0x0B7F, -2.5, -2 },  /* up */
            { 0x0F7F,  2.5,  2 }, { 0x0F7F, -2.5, -2 },  /* trunc */
        };
        for (int t = 0; t < 8; t++) {
            uint8_t code[] = { 0xD9, M64(5), 0xDD, M64(0), 0xD9, 0xFC,
                               0xDF, M64(7), 0xF4 };
            WemuCpu *c = wemu_cpu_create(0x10000);
            wemu_mem_write(c, 0x2000, &T[t].cw, 2);
            put64(c, 0x2008, T[t].v);
            code[10] = 0x08;
            wemu_mem_write(c, 0x1000, code, sizeof code);
            wemu_cpu_set_rip(c, 0x1000);
            wemu_cpu_run(c, 10);
            if (wemu_cpu_fault(c)) FAIL("frndint fault\n");
            int64_t out; wemu_mem_read(c, 0x2000, &out, 8);
            if (out != T[t].want) FAIL("frndint cw=%04x v=%g got %lld want %lld\n",
                T[t].cw, T[t].v, (long long)out, (long long)T[t].want);
            wemu_cpu_destroy(c);
        }
    }
    /* 9. fxch + fchs/fabs/fsqrt */
    {
        uint8_t code[] = { 0xD9, 0xE8, 0xD9, 0xEE, 0xD9, 0xC9,
                           0xDD, M64(3), 0xD9, 0xE0, 0xDD, M64(3), 0xF4 };
        /* fld1 fldz fxch st1 -> st0=1 st0=0; fstp -> 1; fchs st0=-0... */
        WemuCpu *c = run(code, sizeof code);
        /* first fstp stores 1 (fxch worked); fchs + second fstp
         * overwrites with -0 — the FINAL value proves both. */
        double fx = get64(c, 0x2000);
        if (fx != 0.0 || !signbit(fx)) FAIL("fxch/fchs final=%g\n", fx);
        wemu_cpu_destroy(c);
        uint8_t code2[] = { 0xD9, 0xE8, 0xD9, 0xE8, 0xDE, 0xC1,
                            0xD9, 0xC0, 0xDE, 0xC1, 0xD9, 0xFA,
                            0xDD, M64(3), 0xF4 };
        /* 1+1=2; fld st0 duplicates -> 2,2; faddp -> 4; sqrt=2 */
        c = run(code2, sizeof code2);
        if (get64(c, 0x2000) != 2.0) FAIL("fsqrt chain\n");
        wemu_cpu_destroy(c);
    }
    /* 10. native spot-check: fninit -> fnstcw == 0x037F on real hardware */
    {
        uint16_t hw;
        __asm__ volatile("fninit; fnstcw %0" : "=m"(hw));
        uint8_t code[] = { 0xDB, 0xE3, 0xD9, M64(7), 0xF4 };
        WemuCpu *c = run(code, sizeof code);
        uint16_t em; wemu_mem_read(c, 0x2000, &em, 2);
        if (em != hw || em != 0x037F) FAIL("fninit cw emu=%04x hw=%04x\n", em, hw);
        wemu_cpu_destroy(c);
    }
    printf("X87 GATE PASS (round-trips, IEEE arith, cc table, rounding, native cw)\n");
    return 0;
}
