/* test_fcomi_flags.c — x87 FCOMI/FCOMIP/FUCOMI/FUCOMIP -> EFLAGS.
 * Host-differential gate: the oracle is the HOST CPU (inline asm).
 * Preset OF/SF/ZF/AF/PF/CF, compare st(0) vs st(1) with each of the
 * four x87 compare-and-set-EFLAGS forms, then compare the resulting
 * status flags against WEMU.
 *
 * SDM Vol 2A, FCOMI/FCOMIP/FUCOMI/FUCOMIP "Flags Affected":
 *   "The FCOMI/FCOMIP and FUCOMI/FUCOMIP instructions set the OF,
 *    SF and AF flags to zero in the EFLAGS register (regardless of
 *    whether an invalid-operation exception is detected)."
 * https://shell-storm.org/x86doc/FCOMI_FCOMIP_FUCOMI_FUCOMIP.html
 *
 * WEMU's x87_comi_flags() only rebuilt ZF/PF/CF and left OF/SF/AF
 * untouched, so STC-style presets leaked stale OF/SF/AF into the guest.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include "wemu.h"
#include "wemu_internal.h"

#define FAIL(...) do { fprintf(stderr, "FAIL: " __VA_ARGS__); exit(1); } while (0)

/* OF, SF, ZF, AF, PF, CF — every flag FCOMI defines */
#define CMPFLAGS (WF_OF | WF_SF | WF_ZF | WF_AF | WF_PF | WF_CF)

#define NOPS 4
static const char *const vname[NOPS] = {
    "fcomi", "fcomip", "fucomi", "fucomip"
};
/* DB F0+i = fcomi, DF F0+i = fcomip, DB E8+i = fucomi,
 * DF E8+i = fucomip ; i=1 (st(1)) -> F1 / E9 */
static const uint8_t vbytes[NOPS][2] = {
    { 0xDB, 0xF1 }, { 0xDF, 0xF1 }, { 0xDB, 0xE9 }, { 0xDF, 0xE9 }
};

/* host oracle: preset flags via push/popfq, load st0=a st1=b, compare,
   capture flags with pushfq. The compare bytes are a compile-time
   string literal so the SDM encoding is written once and used as-is. */
#define HOST_FCOMI(BYTES) __asm__ volatile(                         \
    "fninit\n\t"                                                    \
    "fldl %[b]\n\t"          /* st0 = b */                          \
    "fldl %[a]\n\t"          /* st0 = a, st1 = b */                 \
    "pushq %0\n\t popfq\n\t" /* preset status flags */              \
    BYTES                                                           \
    "pushfq\n\t popq %0\n\t" /* capture result flags */             \
    : "+r"(f)                                                       \
    : [a] "m"(a), [b] "m"(b)                                        \
    : "cc", "memory", "st", "st(1)")

static uint64_t host_fcomi_flags(int op, double a, double b, uint64_t preset) {
    uint64_t f = preset;
    switch (op) {
    case 0: HOST_FCOMI(".byte 0xDB, 0xF1\n\t"); break; /* fcomi   */
    case 1: HOST_FCOMI(".byte 0xDF, 0xF1\n\t"); break; /* fcomip  */
    case 2: HOST_FCOMI(".byte 0xDB, 0xE9\n\t"); break; /* fucomi  */
    case 3: HOST_FCOMI(".byte 0xDF, 0xE9\n\t"); break; /* fucomip */
    default: FAIL("bad op %d\n", op);
    }
    return f;
}

/* emulator side: identical byte sequence, preset RFLAGS directly
   (test includes wemu_internal.h), read back after HLT. */
static uint64_t emu_fcomi_flags(int op, double a, double b, uint64_t preset) {
    WemuCpu *c = wemu_cpu_create(0x10000);
    uint8_t code[] = {
        0xDB, 0xE3,                                       /* fninit */
        0xDD, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00,          /* fld m64 [0x2008] = b */
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00,          /* fld m64 [0x2000] = a */
        vbytes[op][0], vbytes[op][1],                     /* fcomi st0,st1 */
        0xF4                                              /* hlt */
    };
    wemu_mem_write(c, 0x2000, &a, 8);
    wemu_mem_write(c, 0x2008, &b, 8);
    wemu_mem_write(c, 0x1000, code, sizeof code);
    wemu_cpu_set_rip(c, 0x1000);
    ((WemuCpu *)c)->rflags = preset;
    wemu_cpu_run(c, 8);
    if (wemu_cpu_fault(c)) FAIL("%s emu fault %d rip=%llx\n", vname[op],
        wemu_cpu_fault(c), (unsigned long long)wemu_cpu_rip(c));
    uint64_t f = wemu_cpu_rflags(c);
    wemu_cpu_destroy(c);
    return f;
}

int main(void) {
    struct { const char *name; double a, b; } C[] = {
        { "less",      1.0,  2.0 },
        { "greater",   2.0,  1.0 },
        { "equal",     1.0,  1.0 },
        { "unordered", NAN,  1.0 },
    };
    /* preset with all six status flags SET (exposes the OF/SF/AF leak)
     * and all CLEAR (positive control). */
    static const uint64_t PRESET[2] = { 0x8d5, 0x002 };
    long cases = 0;
    for (int op = 0; op < NOPS; op++) {
        for (unsigned ci = 0; ci < sizeof C / sizeof C[0]; ci++) {
            for (int pi = 0; pi < 2; pi++) {
                uint64_t preset = PRESET[pi];
                uint64_t hf = host_fcomi_flags(op, C[ci].a, C[ci].b, preset);
                uint64_t ef = emu_fcomi_flags(op, C[ci].a, C[ci].b, preset);
                if ((hf & CMPFLAGS) != (ef & CMPFLAGS))
                    FAIL("%s %s preset=%llx: host=%03llx emu=%03llx "
                         "diff=%03llx (OF=%d SF=%d AF=%d)\n",
                         vname[op], C[ci].name, (unsigned long long)preset,
                         (unsigned long long)(hf & CMPFLAGS),
                         (unsigned long long)(ef & CMPFLAGS),
                         (unsigned long long)((hf ^ ef) & CMPFLAGS),
                         !!(ef & WF_OF), !!(ef & WF_SF), !!(ef & WF_AF));
                cases++;
            }
        }
    }
    printf("FCOMI FLAGS GATE PASS (%ld cases: host-CPU differential OF/SF/AF/ZF/PF/CF)\n",
           cases);
    return 0;
}
