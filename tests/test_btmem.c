/* test_btmem.c — memory bit-base BT/BTS/BTR/BTC offset gate.
 *
 * Intel SDM Vol.2A, "BT—Bit Test" (and BTS/BTR/BTC): a REGISTER bit base
 * takes BitOffset modulo the operand size, but a MEMORY bit base addresses
 * the unit containing the bit at
 *
 *     EffectiveAddress + OperandSize * (BitOffset DIV (OperandSize*8))
 *
 * (the SDM gives EA + 4*(BitOffset DIV 32) for r/m32 and EA +
 * 2*(BitOffset DIV 16) for r/m16).  WEMU masked the offset and always
 * read/wrote the qword/dword at the unmodified EA, so bit offsets >= the
 * operand size hit the wrong address.  Expected values here are host-CPU
 * measurements of the exact encoded bytes (Intel Core i7-14650HX). */
#include "wemu.h"
#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(cond, msg) do { if (!(cond)) { \
    printf("FAIL: %s (line %d)\n", msg, __LINE__); fails++; } } while (0)

#define BITBASE 0x2000u
#define NBYTES  32u

/* Run one instruction with the memory bit base at [rax], bit offset in
 * rbx.  Returns RFLAGS; *out receives NBYTES of memory after execution. */
static uint64_t run_sequence(const uint8_t *code, size_t len, uint64_t idx,
                             const uint8_t *mem, uint8_t *out) {
    WemuCpu *c = wemu_cpu_create(1 << 20);
    uint8_t prog[32];
    memset(prog, 0, sizeof prog);
    memcpy(prog, code, len);
    prog[len] = 0xF4;                       /* hlt */
    wemu_mem_write(c, 0x1000, prog, len + 1);
    wemu_mem_write(c, BITBASE, mem, NBYTES);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_set_reg(c, 0, BITBASE);        /* rax = bit base address */
    wemu_cpu_set_reg(c, 3, idx);            /* rbx = bit offset */
    int64_t n = wemu_cpu_run(c, 16);
    CHECK(n >= 0 && wemu_cpu_fault(c) == 0, "btmem run faulted");
    uint64_t f = wemu_cpu_rflags(c);
    wemu_mem_read(c, BITBASE, out, NBYTES);
    wemu_cpu_destroy(c);
    return f;
}

static void clear(uint8_t *m) { memset(m, 0, NBYTES); }

int main(void) {
    uint8_t mem[NBYTES], out[NBYTES];
    uint64_t f;

    /* BT qword [rax], rbx, offset 64 -> EA+8, bit 0; byte8=1 so CF=1.
     * Buggy WEMU reads bit 0 of [rax] (byte0=0) -> CF=0. */
    clear(mem); mem[8] = 0x01;
    f = run_sequence((const uint8_t[]){0x48,0x0F,0xA3,0x18}, 4, 64, mem, out);
    CHECK((f & 1) == 1, "BT m64 offset64 CF (SDM EA+8)");
    CHECK(out[8] == 0x01 && out[0] == 0x00, "BT must not write memory");

    /* BTS qword [rax], rbx, offset 64 -> set bit 0 of qword at EA+8.
     * Byte0 is preset so the buggy CF reads 1 and byte8 stays 0. */
    clear(mem); mem[0] = 0x01;
    f = run_sequence((const uint8_t[]){0x48,0x0F,0xAB,0x18}, 4, 64, mem, out);
    CHECK((f & 1) == 0, "BTS m64 offset64 CF (old bit at EA+8)");
    CHECK(out[8] == 0x01, "BTS m64 offset64 sets byte8 (SDM)");
    CHECK(out[0] == 0x01, "BTS m64 offset64 leaves byte0 alone");

    /* BTR dword [rax], rbx, offset 64 -> EA + 4*(64/32) = EA+8, bit 0.
     * Byte8 preset; hardware clears it and CF=1. */
    clear(mem); mem[8] = 0x01;
    f = run_sequence((const uint8_t[]){0x0F,0xB3,0x18}, 3, 64, mem, out);
    CHECK((f & 1) == 1, "BTR m32 offset64 CF (SDM EA+8)");
    CHECK(out[8] == 0x00, "BTR m32 offset64 clears byte8");

    /* BTC dword [rax], rbx, offset 64 -> complement bit 0 at EA+8. */
    clear(mem); mem[8] = 0x01;
    f = run_sequence((const uint8_t[]){0x0F,0xBB,0x18}, 3, 64, mem, out);
    CHECK((f & 1) == 1, "BTC m32 offset64 CF");
    CHECK(out[8] == 0x00, "BTC m32 offset64 complements byte8");

    /* Control: offset < operand size must stay at EA (no regression). */
    clear(mem); mem[0] = 0x01;
    f = run_sequence((const uint8_t[]){0x48,0x0F,0xAB,0x18}, 4, 1, mem, out);
    CHECK((f & 1) == 0 && out[0] == 0x03, "BTS m64 offset1 control");

    if (fails) { printf("test_btmem: %d FAILURES\n", fails); return 1; }
    printf("test_btmem: PASS (memory bit-base offsets, SDM EA+N*(off DIV N*8))\n");
    return 0;
}
