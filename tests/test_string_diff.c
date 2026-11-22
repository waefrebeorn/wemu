/* test_string_diff.c — host-CPU differential gate for the REP string family.
 *
 * Oracle: the HOST x86-64 CPU executes the SAME instruction (inline asm,
 * real RAX/RCX/RSI/RDI/RFLAGS and real memory). WEMU executes guest bytes
 * with the same starting GPRs, flags and memory image. GPRs (RAX/RCX/RSI/
 * RDI), all architecturally defined flags (CF/PF/AF/ZF/SF/OF/DF), and every
 * byte of both memory buffers are compared after execution.
 *
 * SDM (Intel combined Vol 1/2, order 325462):
 *   Vol. 2A 3-195..3-198, CMPS: "The CF, OF, SF, ZF, AF, and PF flags are
 *   set according to the temporary result of the comparison", temp :=
 *   SRC1 - SRC2.
 *   Vol. 1 3-16 (section 3.4.3.1): AF "Set if an arithmetic operation
 *   generates a carry or a borrow out of bit 3 of the result; cleared
 *   otherwise."
 *   https://cdrdv2-public.intel.com/825743/325462-sdm-vol-1-2abcd-3abcd-4.pdf
 */
#include "wemu.h"
#include "wemu_internal.h"
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define FLAG_MASK (WF_CF | WF_PF | WF_AF | WF_ZF | WF_SF | WF_OF | 0x400u)
#define NB 64
#define G_SI_BASE 0x20000ull
#define G_DI_BASE 0x30000ull
#define G_CODE    0x1000ull

struct str_state {
    uint64_t rax, rcx, rsi, rdi, rflags;
    uint8_t src[NB], dst[NB];
};

/* One host function per (op, width, prefix). The instruction is executed
 * with the flags loaded from the state; DF is part of those flags. DF is
 * cleared again before returning to the C ABI. */
#define DEFINE_HOST(name, op, suf, pre)                                      \
static void name(struct str_state *s) {                                      \
    register uint64_t h_rax __asm__("rax") = s->rax;                         \
    register uint64_t h_rcx __asm__("rcx") = s->rcx;                         \
    register uint64_t h_rsi __asm__("rsi") = s->rsi;                         \
    register uint64_t h_rdi __asm__("rdi") = s->rdi;                         \
    uint64_t f_in = (s->rflags & FLAG_MASK) | 2u, f_out;                     \
    __asm__ volatile(                                                        \
        "push %[fi]\n\t"                                                     \
        "popfq\n\t"                                                          \
        pre " " op suf "\n\t"                                                \
        "pushfq\n\t"                                                         \
        "pop %[fo]\n\t"                                                      \
        "cld\n\t"                                                            \
        : [fo] "=r"(f_out), [a] "+r"(h_rax), [c] "+r"(h_rcx),                \
          [si] "+r"(h_rsi), [di] "+r"(h_rdi)                                 \
        : [fi] "r"(f_in)                                                     \
        : "cc", "memory");                                                   \
    s->rax = h_rax; s->rcx = h_rcx; s->rsi = h_rsi; s->rdi = h_rdi;         \
    s->rflags = f_out;                                                       \
}

#define HOST_GROUP(op)                                                       \
    DEFINE_HOST(host_##op##_b_0,   #op, "b", "")                             \
    DEFINE_HOST(host_##op##_b_f3,  #op, "b", "rep")                          \
    DEFINE_HOST(host_##op##_b_f2,  #op, "b", "repne")                        \
    DEFINE_HOST(host_##op##_w_0,   #op, "w", "")                             \
    DEFINE_HOST(host_##op##_w_f3,  #op, "w", "rep")                          \
    DEFINE_HOST(host_##op##_w_f2,  #op, "w", "repne")                        \
    DEFINE_HOST(host_##op##_d_0,   #op, "l", "")                             \
    DEFINE_HOST(host_##op##_d_f3,  #op, "l", "rep")                          \
    DEFINE_HOST(host_##op##_d_f2,  #op, "l", "repne")                        \
    DEFINE_HOST(host_##op##_q_0,   #op, "q", "")                             \
    DEFINE_HOST(host_##op##_q_f3,  #op, "q", "rep")                          \
    DEFINE_HOST(host_##op##_q_f2,  #op, "q", "repne")

HOST_GROUP(movs)
HOST_GROUP(cmps)
HOST_GROUP(stos)
HOST_GROUP(lods)
HOST_GROUP(scas)

typedef void (*host_fn)(struct str_state *);
static const host_fn hosts[5][4][3] = {
    { { host_movs_b_0, host_movs_b_f3, host_movs_b_f2 },
      { host_movs_w_0, host_movs_w_f3, host_movs_w_f2 },
      { host_movs_d_0, host_movs_d_f3, host_movs_d_f2 },
      { host_movs_q_0, host_movs_q_f3, host_movs_q_f2 } },
    { { host_cmps_b_0, host_cmps_b_f3, host_cmps_b_f2 },
      { host_cmps_w_0, host_cmps_w_f3, host_cmps_w_f2 },
      { host_cmps_d_0, host_cmps_d_f3, host_cmps_d_f2 },
      { host_cmps_q_0, host_cmps_q_f3, host_cmps_q_f2 } },
    { { host_stos_b_0, host_stos_b_f3, host_stos_b_f2 },
      { host_stos_w_0, host_stos_w_f3, host_stos_w_f2 },
      { host_stos_d_0, host_stos_d_f3, host_stos_d_f2 },
      { host_stos_q_0, host_stos_q_f3, host_stos_q_f2 } },
    { { host_lods_b_0, host_lods_b_f3, host_lods_b_f2 },
      { host_lods_w_0, host_lods_w_f3, host_lods_w_f2 },
      { host_lods_d_0, host_lods_d_f3, host_lods_d_f2 },
      { host_lods_q_0, host_lods_q_f3, host_lods_q_f2 } },
    { { host_scas_b_0, host_scas_b_f3, host_scas_b_f2 },
      { host_scas_w_0, host_scas_w_f3, host_scas_w_f2 },
      { host_scas_d_0, host_scas_d_f3, host_scas_d_f2 },
      { host_scas_q_0, host_scas_q_f3, host_scas_q_f2 } },
};
static const char *knames[5] = { "movs", "cmps", "stos", "lods", "scas" };
static const char *pnames[3] = { "none", "F3", "F2" };
static const uint8_t opcodes[5] = { 0xA4, 0xA6, 0xAA, 0xAC, 0xAE };

static uint64_t rnd(void) {
    static uint64_t s = 0x9e3779b97f4a7c15ull;
    s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s;
}

static int fails;
static void fail(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap); va_end(ap);
    fails++;
}

static void one(int kind, int wi, int pi, uint64_t fl0, uint64_t count,
                uint64_t rax0, int df) {
    static const int widths[4] = { 1, 2, 4, 8 };
    static const uint8_t prefixes[3] = { 0, 0xF3, 0xF2 };
    int bytes = widths[wi];
    /* DF=0 walks up from offset 8 (max last byte 8+6*8=63); DF=1 walks
     * down from offset 8+(count-1)*bytes to 8. Both stay inside NB. */
    uint64_t off = df ? 8 + (count ? (count - 1) * (uint64_t)bytes : 0) : 8;

    struct str_state h = { 0 };
    for (int i = 0; i < NB; i++) { h.src[i] = (uint8_t)rnd(); h.dst[i] = (uint8_t)rnd(); }
    h.rax = rax0; h.rcx = count;
    h.rflags = (fl0 & FLAG_MASK) | 2u;
    if (df) h.rflags |= 0x400u; else h.rflags &= ~0x400u;
    h.rsi = (uint64_t)(uintptr_t)(h.src + off);
    h.rdi = (uint64_t)(uintptr_t)(h.dst + off);
    hosts[kind][wi][pi](&h);

    WemuCpu *c = wemu_cpu_create(0x80000);
    uint8_t code[8]; int n = 0;
    if (prefixes[pi]) code[n++] = prefixes[pi];
    if (bytes == 2) code[n++] = 0x66;
    if (bytes == 8) code[n++] = 0x48;
    code[n++] = (uint8_t)(opcodes[kind] | (bytes > 1 ? 1 : 0));
    code[n++] = 0xF4;
    if (wemu_cpu_load(c, G_CODE, code, (size_t)n) ||
        wemu_mem_write(c, G_SI_BASE, h.src, NB) ||
        wemu_mem_write(c, G_DI_BASE, h.dst, NB)) {
        fail("setup failed\n"); wemu_cpu_destroy(c); return;
    }
    c->rflags = h.rflags;
    wemu_cpu_set_rip(c, G_CODE);
    wemu_cpu_set_reg(c, 0, rax0);
    wemu_cpu_set_reg(c, 1, count);
    wemu_cpu_set_reg(c, 6, G_SI_BASE + off);
    wemu_cpu_set_reg(c, 7, G_DI_BASE + off);
    for (int r = 2; r < 16; r++) {
        if (r == 6 || r == 7) continue;
        uint64_t sentinel = 0x1122334455667788ull + (uint64_t)r;
        wemu_cpu_set_reg(c, r, sentinel);
    }
    wemu_cpu_run(c, 64);
    if (wemu_cpu_fault(c)) {
        fail("fault %d: %s w=%d %s df=%d cnt=%" PRIu64 "\n",
             wemu_cpu_fault(c), knames[kind], bytes, pnames[pi], df, count);
        wemu_cpu_destroy(c); return;
    }

    uint8_t gsrc[NB], gdst[NB];
    wemu_mem_read(c, G_SI_BASE, gsrc, NB);
    wemu_mem_read(c, G_DI_BASE, gdst, NB);
    uint64_t esi = wemu_cpu_reg(c, 6) - G_SI_BASE;
    uint64_t edi = wemu_cpu_reg(c, 7) - G_DI_BASE;
    uint64_t hsi = h.rsi - (uint64_t)(uintptr_t)h.src;
    uint64_t hdi = h.rdi - (uint64_t)(uintptr_t)h.dst;
    uint64_t ef = wemu_cpu_rflags(c) & FLAG_MASK;
    uint64_t hf = h.rflags & FLAG_MASK;
    if (wemu_cpu_reg(c, 0) != h.rax || wemu_cpu_reg(c, 1) != h.rcx ||
        esi != hsi || edi != hdi || ef != hf ||
        memcmp(gsrc, h.src, NB) || memcmp(gdst, h.dst, NB)) {
        fail("MISMATCH %s w=%d %s df=%d cnt=%" PRIu64
             " fl0=%04" PRIx64 " rax0=%016" PRIx64 "\n"
             "  GPR  emu rax=%016" PRIx64 " rcx=%016" PRIx64
             " rsi+%llx rdi+%llx | host rax=%016" PRIx64 " rcx=%016" PRIx64
             " rsi+%llx rdi+%llx\n"
             "  FLAG emu=%04" PRIx64 " host=%04" PRIx64
             " (AF emu=%d host=%d CF emu=%d host=%d)\n",
             knames[kind], bytes, pnames[pi], df, count, fl0, rax0,
             wemu_cpu_reg(c, 0), wemu_cpu_reg(c, 1),
             (unsigned long long)esi, (unsigned long long)edi,
             h.rax, h.rcx, (unsigned long long)hsi, (unsigned long long)hdi,
             ef, hf, (int)((ef & WF_AF) != 0), (int)((hf & WF_AF) != 0),
             (int)((ef & WF_CF) != 0), (int)((hf & WF_CF) != 0));
    }
    for (int r = 2; r < 16; r++) {
        if (r == 6 || r == 7) continue;
        uint64_t sentinel = 0x1122334455667788ull + (uint64_t)r;
        if (wemu_cpu_reg(c, r) != sentinel) {
            fail("GPR r%d clobbered by %s\n", r, knames[kind]);
            break;
        }
    }
    wemu_cpu_destroy(c);
}

int main(void) {
    uint64_t rounds = 0;
    static const uint64_t counts[] = { 0, 1, 2, 3, 4, 7 };
    for (int r = 0; r < 12; r++) {
        uint64_t fl0 = rnd(), rax0 = rnd();
        for (int df = 0; df < 2; df++)
          for (int k = 0; k < 5; k++)
           for (int wi = 0; wi < 4; wi++)
            for (int pi = 0; pi < 3; pi++)
             for (unsigned ci = 0; ci < sizeof counts / sizeof counts[0]; ci++) {
                one(k, wi, pi, fl0, counts[ci], rax0, df);
                rounds++;
             }
    }
    /* Named minimal control: 0x10 - 0x01 borrows out of bit 3, so the
     * SDM says AF=1. Encoded as a plain CMPSB (F3 prefix does not change
     * flag computation). This is the exact host-vs-emu failure that the
     * shared subtraction flag helper used to produce wrong. */
    {
        struct str_state h = { 0 };
        h.src[0] = 0x10; h.dst[0] = 0x01;
        h.rax = h.rcx = 0; h.rflags = 2;
        h.rsi = (uint64_t)(uintptr_t)h.src;
        h.rdi = (uint64_t)(uintptr_t)h.dst;
        host_cmps_b_0(&h);
        WemuCpu *c = wemu_cpu_create(0x80000);
        uint8_t code[] = { 0xA6, 0xF4 };
        wemu_cpu_load(c, G_CODE, code, sizeof code);
        wemu_mem_write(c, G_SI_BASE, h.src, NB);
        wemu_mem_write(c, G_DI_BASE, h.dst, NB);
        c->rflags = 2;
        wemu_cpu_set_rip(c, G_CODE);
        wemu_cpu_set_reg(c, 6, G_SI_BASE);
        wemu_cpu_set_reg(c, 7, G_DI_BASE);
        wemu_cpu_run(c, 4);
        uint64_t ef = wemu_cpu_rflags(c) & FLAG_MASK;
        uint64_t hf = h.rflags & FLAG_MASK;
        if (ef != hf)
            fail("NAMED cmpsb 0x10-0x01: AF emu=%d host=%d (flags emu=%04" PRIx64
                 " host=%04" PRIx64 ")\n",
                 (int)((ef & WF_AF) != 0), (int)((hf & WF_AF) != 0), ef, hf);
        rounds++;
        wemu_cpu_destroy(c);
    }
    if (fails) {
        fprintf(stderr, "test_string_diff: %d FAILURES of %" PRIu64 " rounds\n",
                fails, rounds);
        return 1;
    }
    printf("test_string_diff: PASS (%" PRIu64 " host-CPU differential rounds, "
           "movs/cmps/stos/lods/scas, DF both ways, all defined flags)\n", rounds);
    return 0;
}
