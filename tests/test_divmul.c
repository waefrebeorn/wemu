/* test_divmul.c — one-operand MUL/DIV/IDIV differential gate.
 *
 * The oracle is the HOST CPU itself (inline asm), not a shared C model:
 * hardware, not an abstraction that could be wrong together with WEMU.
 *
 * Intel SDM Vol.2B (F6 /4 /6 /7): for an 8-bit divisor the implicit
 * dividend/result pair is AX, with AH as the HIGH half:
 *   MUL  r/m8 -> AX   = AL * r/m8          (AH = upper half of product)
 *   DIV  r/m8 -> AX/r/m8: AL = quotient, AH = remainder
 *   IDIV r/m8 -> AX/r/m8: AL = quotient, AH = remainder (trunc toward 0)
 * DX/EDX/RDX is the high half ONLY for 16/32/64-bit operands.
 *
 * The old executor used r[2] (RDX/DL) as the 8-bit high half, so it both
 * wrote the product's upper byte / remainder into DL and read a bogus
 * dividend (DL:AL) for DIV/IDIV.  This gate catches both classes. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "wemu.h"

#define FAIL(...) do { fprintf(stderr, "FAIL: " __VA_ARGS__); exit(1); } while (0)

static uint64_t rnd(void) {
    static uint64_t s = 0x243f6a8885a308d3ull;
    s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s;
}

/* ---- host oracle: width-typed inline asm, real DIV/IDIV/MUL ---- */
static uint16_t nat_mul8(uint8_t al, uint8_t src) {
    uint16_t ax = al;
    __asm__ volatile("mulb %1" : "+a"(ax) : "r"(src) : "cc");
    return ax;
}
static uint16_t nat_div8(uint16_t ax, uint8_t src) {
    uint16_t r = ax;
    __asm__ volatile("divb %1" : "+a"(r) : "r"(src) : "cc");
    return r;
}
static uint16_t nat_idiv8(int16_t ax, int8_t src) {
    uint16_t r = (uint16_t)ax;
    __asm__ volatile("idivb %1" : "+a"(r) : "r"(src) : "cc");
    return r;
}

/* ---- emulator side: F6 /4=/E2 mul dl, /6=F2 div dl, /7=FA idiv dl ---- */
static uint16_t emu8(uint8_t modrm, uint16_t ax, uint64_t rdx,
                     uint64_t *rdx_out, int *fault) {
    WemuCpu *c = wemu_cpu_create(0x10000);
    uint8_t code[] = { 0xF6, modrm, 0xF4 };
    wemu_mem_write(c, 0x1000, code, sizeof code);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_set_reg(c, 0, ax);
    wemu_cpu_set_reg(c, 2, rdx);
    wemu_cpu_run(c, 4);
    *fault = wemu_cpu_fault(c);
    uint16_t rax = (uint16_t)wemu_cpu_reg(c, 0);
    *rdx_out = wemu_cpu_reg(c, 2);
    wemu_cpu_destroy(c);
    return rax;
}

/* Check one 8-bit case against hardware, including RDX preservation:
 * SDM lists only AX as an implicit operand for the byte forms. */
static void check(const char *tag, uint8_t modrm, uint16_t ax, uint64_t rdx,
                  uint16_t want) {
    uint64_t rdx_out; int fault;
    uint16_t got = emu8(modrm, ax, rdx, &rdx_out, &fault);
    if (fault)
        FAIL("%s: ax=%04x dl=%02x unexpected fault %d\n", tag, ax,
             (unsigned)(rdx & 0xff), fault);
    if (got != want || rdx_out != rdx)
        FAIL("%s: ax=%04x dl=%02x RAX got %04x want %04x | RDX got %llx want %llx\n",
             tag, ax, (unsigned)(rdx & 0xff), got, want,
             (unsigned long long)rdx_out, (unsigned long long)rdx);
}

/* Deterministic named regressions — also the exact scratch reproducer.
 * These run FIRST so the RED line is stable and grep-able. */
static void named_regressions(void) {
    struct { const char *tag; uint8_t modrm; uint16_t ax; uint8_t dl; uint16_t want; } t[] = {
        { "mul  F6 /4 AH-upper", 0xE2, 0xaa10, 0x10, 0x0100 }, /* AL*DL=0x0100 */
        { "div  F6 /6 AH-rem",   0xF2, 0x0100, 0x02, 0x0080 }, /* 0x100/2=0x80 rem 0 */
        { "idiv F6 /7 AH-rem",   0xFA, 0x0180, 0x04, 0x0060 }, /* 384/4=96 rem 0 */
    };
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++)
        check(t[i].tag, t[i].modrm, t[i].ax, 0xdeadbeef00000000ull | t[i].dl,
              t[i].want);
}

int main(void) {
    named_regressions();
    long rounds = 0;

    /* MUL: AL * src, with random stale AH preset. Hardware writes AX. */
    for (int i = 0; i < 2000; i++) {
        uint8_t al = (uint8_t)rnd(), src = (uint8_t)rnd(), ah = (uint8_t)rnd();
        uint16_t ax = (uint16_t)((ah << 8) | al);
        uint64_t rdx = 0x1234567800000000ull | src;
        check("mul", 0xE2, ax, rdx, nat_mul8(al, src));
        rounds++;
    }
    /* DIV: build AX = q*src + rem so the quotient always fits in AL. */
    for (int i = 0; i < 2000; i++) {
        uint8_t src = (uint8_t)(rnd() % 255 + 1);
        uint8_t q = (uint8_t)rnd();
        uint8_t rem = (uint8_t)(rnd() % src);
        uint16_t ax = (uint16_t)(q * src + rem);
        uint64_t rdx = 0x1234567800000000ull | src;
        check("div", 0xF2, ax, rdx, nat_div8(ax, src));
        rounds++;
    }
    /* IDIV: signed AX = q*src + rem, quotient in [-128,127], |rem|<|src|. */
    for (int i = 0; i < 2000; i++) {
        int mag = (int)(rnd() % 127 + 1);   /* 1..127: exact as int8_t */
        int src = (rnd() & 1) ? -mag : mag;
        int q = (int)(rnd() % 256) - 128;
        int rem = (int)(rnd() % (unsigned)(src > 0 ? src : -src));
        int16_t ax = (int16_t)(q * src + rem);
        uint64_t rdx = 0x1234567800000000ull | (uint8_t)src;
        check("idiv", 0xFA, (uint16_t)ax, rdx,
              nat_idiv8(ax, (int8_t)src));
        rounds++;
    }

    printf("DIV/MUL GATE PASS (3 named regressions + %ld differential rounds vs host CPU)\n",
           rounds);
    return 0;
}
