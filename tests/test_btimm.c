/* test_btimm.c — 0F BA /5 (BTS) host-CPU differential gate with repeated
 * REX prefixes, where the LAST REX selects the operand size (and therefore
 * the width used to mask the imm8 bit index).
 *
 * Intel SDM Vol.2A, "BT—Bit Test" / "BTS—Bit Test and Set":
 *   a REGISTER bit base takes BitOffset modulo the operand size; CF gets
 *   the selected bit and BTS writes it back.  A 64-bit operand therefore
 *   masks imm8 with 63, a 32-bit operand with 31.
 *   https://cdrdv2-public.intel.com/835751/253666-sdm-vol-2a.pdf
 * SDM Vol.2A 2.2.1 "REX Prefixes": only one REX prefix is allowed; real
 * hardware (the oracle here) applies the LAST REX before the opcode and
 * ignores earlier ones.  WEMU consumed only the first REX and treated the
 * second as an opcode, so these encodings #UD instead of executing BTS.
 *
 * The host oracle executes the EXACT encoded bytes (inline .byte), not an
 * assembler mnemonic that could fold the bit index into a displacement. */
#include "wemu.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int fails;
#define CHECK(cond, msg) do { if (!(cond)) { \
    printf("FAIL: %s (line %d)\n", msg, __LINE__); fails++; } } while (0)

enum { C_REXR_REXW_OFF0, C_REXW_REXR_OFF0, C_REXR_REXW_OFF32,
       C_REXW_OFF0, C_66_OFF0, NCASES };

static void host(int id, uint64_t rax, uint64_t *out, uint8_t *cf) {
    uint8_t c = 0;
    switch (id) {
    case C_REXR_REXW_OFF0: /* 44 48 0F BA E8 00: BTS rax,0 (REX.W from last) */
        __asm__ volatile(".byte 0x44,0x48,0x0f,0xba,0xe8,0x00\n\tsetc %0"
                         : "=qm"(c), "+a"(rax) : : "cc", "memory"); break;
    case C_REXW_REXR_OFF0: /* 48 44 ...: last REX has W=0 -> BTS eax,0 */
        __asm__ volatile(".byte 0x48,0x44,0x0f,0xba,0xe8,0x00\n\tsetc %0"
                         : "=qm"(c), "+a"(rax) : : "cc", "memory"); break;
    case C_REXR_REXW_OFF32: /* imm8=0x20: r/m64 bit32, r/m32 bit0 */
        __asm__ volatile(".byte 0x48,0x44,0x0f,0xba,0xe8,0x20\n\tsetc %0"
                         : "=qm"(c), "+a"(rax) : : "cc", "memory"); break;
    case C_REXW_OFF0:
        __asm__ volatile(".byte 0x48,0x0f,0xba,0xe8,0x00\n\tsetc %0"
                         : "=qm"(c), "+a"(rax) : : "cc", "memory"); break;
    case C_66_OFF0:
        __asm__ volatile(".byte 0x66,0x0f,0xba,0xe8,0x00\n\tsetc %0"
                         : "=qm"(c), "+a"(rax) : : "cc", "memory"); break;
    default: abort();
    }
    *out = rax; *cf = c;
}

static void emu(const uint8_t *code, size_t n, uint64_t rax,
                uint64_t *out, uint8_t *cf, int *fault) {
    WemuCpu *c = wemu_cpu_create(1 << 20);
    uint8_t prog[32];
    memset(prog, 0, sizeof prog);
    memcpy(prog, code, n);
    prog[n] = 0xF4;                        /* hlt */
    wemu_cpu_load(c, 0x1000, prog, n + 1);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_set_reg(c, 0, rax);
    int64_t steps = wemu_cpu_run(c, 8);
    *fault = (int)wemu_cpu_fault(c);
    if (steps < 0 && !*fault) *fault = 99;
    *out = wemu_cpu_reg(c, 0);
    *cf = (uint8_t)(wemu_cpu_rflags(c) & 1);
    wemu_cpu_destroy(c);
}

static const struct {
    const char *name;
    uint8_t code[8];
    size_t len;
    uint64_t rax;
    uint64_t host_result;
    uint8_t host_cf;
} cases[NCASES] = {
    { "REX.R,REX.W BTS rax,0",   {0x44,0x48,0x0f,0xba,0xe8,0x00}, 6,
      0x100000000ull, 0x100000001ull, 0 },
    { "REX.W,REX.R BTS eax,0",   {0x48,0x44,0x0f,0xba,0xe8,0x00}, 6,
      0x100000000ull, 0x1ull, 0 },
    { "REX.W,REX.R BTS eax,0x20",{0x48,0x44,0x0f,0xba,0xe8,0x20}, 6,
      0x100000000ull, 0x1ull, 0 },
    { "control BTS rax,0",       {0x48,0x0f,0xba,0xe8,0x00}, 5,
      0x100000000ull, 0x100000001ull, 0 },
    { "control BTS ax,0",        {0x66,0x0f,0xba,0xe8,0x00}, 5,
      0x100000000ull, 0x100000001ull, 0 },
};

int main(void) {
    for (int i = 0; i < NCASES; i++) {
        uint64_t hr = 0, er = 0;
        uint8_t hcf = 0, ecf = 0;
        int fault = 0;
        host(i, cases[i].rax, &hr, &hcf);
        CHECK(hr == cases[i].host_result && hcf == cases[i].host_cf,
              "host oracle disagrees with itself");
        emu(cases[i].code, cases[i].len, cases[i].rax, &er, &ecf, &fault);
        printf("%-26s host rax=%llx cf=%u | wemu fault=%d rax=%llx cf=%u\n",
               cases[i].name, (unsigned long long)hr, hcf, fault,
               (unsigned long long)er, ecf);
        CHECK(!fault, "WEMU faulted on a host-valid BTS encoding");
        CHECK(er == hr, "BTS result differs from host CPU");
        CHECK(ecf == hcf, "BTS CF differs from host CPU");
    }
    if (fails) { printf("test_btimm: %d FAILURES\n", fails); return 1; }
    printf("test_btimm: PASS (0F BA /5 REX operand size selects bit-index width)\n");
    return 0;
}
