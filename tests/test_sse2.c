/* test_sse2 — differential gate for the SSE2/SSSE3/AVX2 growth set:
 * every new vector opcode executes against an independent C oracle,
 * 128- and 256-bit, random inputs (fixed seed). Same survivorship-bias
 * rule as test_isa: the oracle is written from the SDM semantics, not
 * from the implementation. */
#include "wemu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define FAIL(...) do { fprintf(stderr, "FAIL: " __VA_ARGS__); exit(1); } while (0)

static uint64_t rng = 0x123456789ABCDEFull;
static uint64_t rnd(void) {
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return rng;
}

/* code harness: inputs at 0x2000 (xmm0) / 0x2040 (xmm1), result to 0x2080.
 * For 256-bit ops the loads/stores are vmovdqu ymm. */
static void run_vec(const uint8_t *insn, int ilen, int is256,
                    const uint8_t a[32], const uint8_t b[32],
                    uint8_t out[32], uint64_t *rax) {
    WemuCpu *cpu = wemu_cpu_create(0x10000);
    uint8_t code[64];
    int n = 0;
    /* vmovdqu ymm0,[0x2000] : C5 FE 6F 04 25 00 20 00 00 (VEX2 pp=F3? no:
     * vmovdqu is VEX.128/256.F3.0F 6F) — use explicit bytes */
    if (is256) {
        uint8_t l0[] = { 0xC5, 0xFE, 0x6F, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00 };
        uint8_t l1[] = { 0xC5, 0xFE, 0x6F, 0x0C, 0x25, 0x40, 0x20, 0x00, 0x00 };
        memcpy(code + n, l0, sizeof l0); n += (int)sizeof l0;
        memcpy(code + n, l1, sizeof l1); n += (int)sizeof l1;
    } else {
        uint8_t l0[] = { 0xF3, 0x0F, 0x6F, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00 };
        uint8_t l1[] = { 0xF3, 0x0F, 0x6F, 0x0C, 0x25, 0x40, 0x20, 0x00, 0x00 };
        memcpy(code + n, l0, sizeof l0); n += (int)sizeof l0;
        memcpy(code + n, l1, sizeof l1); n += (int)sizeof l1;
    }
    memcpy(code + n, insn, (size_t)ilen); n += ilen;
    if (is256) {
        uint8_t s0[] = { 0xC5, 0xFE, 0x7F, 0x04, 0x25, 0x80, 0x20, 0x00, 0x00 };
        memcpy(code + n, s0, sizeof s0); n += (int)sizeof s0;
    } else {
        uint8_t s0[] = { 0xF3, 0x0F, 0x7F, 0x04, 0x25, 0x80, 0x20, 0x00, 0x00 };
        memcpy(code + n, s0, sizeof s0); n += (int)sizeof s0;
    }
    code[n++] = 0xF4;
    wemu_mem_write(cpu, 0x2000, a, 32);
    wemu_mem_write(cpu, 0x2040, b, 32);
    wemu_cpu_load(cpu, 0x1000, code, (size_t)n);
    wemu_cpu_set_rip(cpu, 0x1000);
    wemu_cpu_run(cpu, 20);
    if (wemu_cpu_fault(cpu)) FAIL("vec fault %d (insn %02x %02x)\n",
        wemu_cpu_fault(cpu), insn[0], insn[1]);
    wemu_mem_read(cpu, 0x2080, out, 32);
    if (rax) *rax = wemu_cpu_reg(cpu, 0);
    wemu_cpu_destroy(cpu);
}

/* encoders: dst=xmm0/ymm0, src1=xmm0 (legacy) or vvvv, src2=xmm1/ymm1 */
static int enc_legacy(uint8_t *p, uint8_t op, int dst, int src) {
    p[0] = 0x66; p[1] = 0x0F; p[2] = op;
    p[3] = (uint8_t)(0xC0 | (dst << 3) | src);
    return 4;
}
static int enc_vex(uint8_t *p, uint8_t op, int dst, int src1, int src2,
                   int L, int pp, int map) {
    int n = 0;
    if (map == 1) {
        p[n++] = 0xC5;
        p[n++] = (uint8_t)((dst < 8 ? 0x80 : 0) | ((~src1 & 15) << 3) |
                           (L ? 4 : 0) | pp);
    } else {
        p[n++] = 0xC4;
        p[n++] = (uint8_t)((dst < 8 ? 0x80 : 0) | 0x60 | map);
        p[n++] = (uint8_t)(((~src1 & 15) << 3) | (L ? 4 : 0) | pp);
    }
    p[n++] = op;
    p[n++] = (uint8_t)(0xC0 | ((dst & 7) << 3) | (src2 & 7));
    return n;
}

/* ---- C oracles (SDM semantics, independent of wemu_sse.c) ---- */
static void o_binop(int op, int es, uint8_t *d, const uint8_t *a,
                    const uint8_t *b, int nb) {
    for (int i = 0; i < nb; i += es) {
        uint64_t av = 0, bv = 0;
        for (int k = 0; k < es; k++) {
            av |= (uint64_t)a[i+k] << (8*k);
            bv |= (uint64_t)b[i+k] << (8*k);
        }
        uint64_t r = 0;
        int64_t sa = (int64_t)(av << (64-es*8)) >> (64-es*8);
        int64_t sb = (int64_t)(bv << (64-es*8)) >> (64-es*8);
        switch (op) {
        case 0: r = av ^ bv; break;
        case 1: r = av & bv; break;
        case 2: r = ~av & bv; break;
        case 3: r = av | bv; break;
        case 4: r = av + bv; break;
        case 5: r = av - bv; break;
        case 6: r = av == bv ? ~0ull : 0; break;
        case 7: r = sa > sb ? ~0ull : 0; break;
        case 8: r = av < bv ? av : bv; break;
        case 9: r = av > bv ? av : bv; break;
        case 10: r = av > bv ? av - bv : 0; break;
        case 11: { uint64_t mx = es>=8 ? ~0ull : (1ull<<(es*8))-1;
                   r = av+bv > mx ? mx : av+bv; break; }
        }
        for (int k = 0; k < es; k++) d[i+k] = (uint8_t)(r >> (8*k));
    }
}
static void o_unpck(uint8_t *d, const uint8_t *a, const uint8_t *b,
                    int nb, int es, int hi) {
    for (int lane = 0; lane < nb; lane += 16)
        for (int i = 0; i < 8/es; i++) {
            int so = hi ? 8 : 0;
            memcpy(d+lane+2*i*es, a+lane+so+i*es, (size_t)es);
            memcpy(d+lane+(2*i+1)*es, b+lane+so+i*es, (size_t)es);
        }
}

static void check(const char *name, const uint8_t *got, const uint8_t *want,
                  int nb) {
    for (int i = 0; i < nb; i++)
        if (got[i] != want[i])
            FAIL("%s byte %d: got %02x want %02x\n", name, i, got[i], want[i]);
}

int main(void) {
    uint8_t a[32], b[32], out[32], want[32], insn[16];
    const int NB[2] = { 16, 32 };
    for (int iter = 0; iter < 100; iter++) {
        for (int i = 0; i < 32; i++) { a[i] = (uint8_t)rnd(); b[i] = (uint8_t)rnd(); }
        for (int w = 0; w < 2; w++) {
            int nb = NB[w], L = w;
            /* binary ops: {op byte, oracle op, es} */
            struct { uint8_t o; int op; int es; } B[] = {
                {0xEF,0,16},{0xDB,1,16},{0xDF,2,16},{0xEB,3,16},
                {0xFC,4,1},{0xFD,4,2},{0xFE,4,4},{0xD4,4,8},
                {0xF8,5,1},{0xF9,5,2},{0xFA,5,4},{0xFB,5,8},
                {0x74,6,1},{0x75,6,2},{0x76,6,4},
                {0x64,7,1},{0x65,7,2},{0x66,7,4},
                {0xDA,8,1},{0xDE,9,1},{0xD8,10,1},{0xDC,11,1},
            };
            for (size_t k = 0; k < sizeof B / sizeof B[0]; k++) {
                int n = enc_legacy(insn, B[k].o, 0, 1);
                run_vec(insn, n, 0, a, b, out, NULL);
                o_binop(B[k].op, B[k].es, want, a, b, 16);
                check("legacy-binop", out, want, 16);
                n = enc_vex(insn, B[k].o, 0, 0, 1, L, 1, 1);
                run_vec(insn, n, L, a, b, out, NULL);
                o_binop(B[k].op, B[k].es, want, a, b, nb);
                check("vex-binop", out, want, nb);
            }
            /* unpacks */
            struct { uint8_t o; int es; int hi; } U[] = {
                {0x60,1,0},{0x61,2,0},{0x62,4,0},{0x6C,8,0},
                {0x68,1,1},{0x69,2,1},{0x6A,4,1},{0x6D,8,1},
            };
            for (size_t k = 0; k < sizeof U / sizeof U[0]; k++) {
                int n = enc_legacy(insn, U[k].o, 0, 1);
                run_vec(insn, n, 0, a, b, out, NULL);
                o_unpck(want, a, b, 16, U[k].es, U[k].hi);
                check("legacy-unpck", out, want, 16);
                n = enc_vex(insn, U[k].o, 0, 0, 1, L, 1, 1);
                run_vec(insn, n, L, a, b, out, NULL);
                o_unpck(want, a, b, nb, U[k].es, U[k].hi);
                check("vex-unpck", out, want, nb);
            }
            /* pmovmskb: result in RAX */
            {
                int n = enc_legacy(insn, 0xD7, 0, 1); /* 66 0F D7 C1 */
                uint64_t rax = 0;
                run_vec(insn, n, 0, a, b, out, &rax);
                uint32_t m = 0;
                for (int i = 0; i < 16; i++) if (b[i] & 0x80) m |= 1u << i;
                if ((uint32_t)rax != m) FAIL("pmovmskb: %llx want %x\n",
                    (unsigned long long)rax, m);
                n = enc_vex(insn, 0xD7, 0, 0, 1, L, 1, 1);
                run_vec(insn, n, L, a, b, out, &rax);
                m = 0;
                for (int i = 0; i < nb; i++) if (b[i] & 0x80) m |= 1u << i;
                if ((uint32_t)rax != m) FAIL("vpmovmskb: %llx want %x\n",
                    (unsigned long long)rax, m);
            }
            /* palignr imm8 (0F 3A 0F) */
            {
                int imms[] = { 0, 1, 7, 15, 16, 31 };
                for (size_t k = 0; k < sizeof imms / sizeof imms[0]; k++) {
                    int imm = imms[k];
                    insn[0]=0x66; insn[1]=0x0F; insn[2]=0x3A; insn[3]=0x0F;
                    insn[4]=0xC1; insn[5]=(uint8_t)imm;
                    run_vec(insn, 6, 0, a, b, out, NULL);
                    for (int lane = 0; lane < 16; lane += 16) {
                        uint8_t cat[32];
                        memcpy(cat, a+lane, 16); memcpy(cat+16, b+lane, 16);
                        for (int i = 0; i < 16; i++)
                            want[lane+i] = imm+i < 32 ? cat[imm+i] : 0;
                    }
                    check("palignr", out, want, 16);
                    int n = enc_vex(insn, 0x0F, 0, 0, 1, L, 1, 3);
                    insn[n++] = (uint8_t)imm;
                    run_vec(insn, n, L, a, b, out, NULL);
                    for (int lane = 0; lane < nb; lane += 16) {
                        uint8_t cat[32];
                        memcpy(cat, a+lane, 16); memcpy(cat+16, b+lane, 16);
                        for (int i = 0; i < 16; i++)
                            want[lane+i] = imm+i < 32 ? cat[imm+i] : 0;
                    }
                    check("vpalignr", out, want, nb);
                }
            }
            /* pshufb (0F 38 00) */
            {
                insn[0]=0x66; insn[1]=0x0F; insn[2]=0x38; insn[3]=0x00; insn[4]=0xC1;
                run_vec(insn, 5, 0, a, b, out, NULL);
                for (int i = 0; i < 16; i++)
                    want[i] = (b[i] & 0x80) ? 0 : a[b[i] & 15];
                check("pshufb", out, want, 16);
                int n = enc_vex(insn, 0x00, 0, 0, 1, L, 1, 2);
                run_vec(insn, n, L, a, b, out, NULL);
                for (int lane = 0; lane < nb; lane += 16)
                    for (int i = 0; i < 16; i++)
                        want[lane+i] = (b[lane+i] & 0x80) ? 0
                                       : a[lane + (b[lane+i] & 15)];
                check("vpshufb", out, want, nb);
            }
            /* pshufd imm8 (0F 70) */
            {
                int imm = (int)(rnd() & 0xff);
                insn[0]=0x66; insn[1]=0x0F; insn[2]=0x70; insn[3]=0xC1; insn[4]=(uint8_t)imm;
                run_vec(insn, 5, 0, a, b, out, NULL);
                for (int i = 0; i < 4; i++)
                    memcpy(want+4*i, b+4*((imm>>(2*i))&3), 4);
                check("pshufd", out, want, 16);
                int n = enc_vex(insn, 0x70, 0, 0, 1, L, 1, 1);
                insn[n++] = (uint8_t)imm;
                run_vec(insn, n, L, a, b, out, NULL);
                for (int lane = 0; lane < nb; lane += 16)
                    for (int i = 0; i < 4; i++)
                        memcpy(want+lane+4*i, b+lane+4*((imm>>(2*i))&3), 4);
                check("vpshufd", out, want, nb);
            }
            /* psrldq/pslldq imm8 (0F 73 /3 /6), legacy + VEX */
            for (int which = 0; which < 2; which++) {
                int imm = (int)(rnd() & 31);
                int reg = which ? 6 : 3;
                insn[0]=0x66; insn[1]=0x0F; insn[2]=0x73;
                insn[3]=(uint8_t)(0xC0|(reg<<3)|0); insn[4]=(uint8_t)imm;
                run_vec(insn, 5, 0, a, b, out, NULL);
                for (int i = 0; i < 16; i++)
                    want[i] = which ? ((i >= imm) ? a[i-imm] : 0)
                                    : ((imm+i < 16) ? a[imm+i] : 0);
                check("psXldq", out, want, 16);
                int n = enc_vex(insn, 0x73, 0, 0, 0, L, 1, 1);
                insn[3] = (uint8_t)(0xC0 | (reg << 3) | 0); /* rm=xmm0 */
                insn[n++] = (uint8_t)imm;
                run_vec(insn, n, L, a, b, out, NULL);
                for (int lane = 0; lane < nb; lane += 16)
                    for (int i = 0; i < 16; i++)
                        want[lane+i] = which ? ((i >= imm) ? a[lane+i-imm] : 0)
                                             : ((imm+i < 16) ? a[lane+imm+i] : 0);
                check("vpsXldq", out, want, nb);
            }
        }
    }
    /* movhps/movlps/movlhps/movhlps + movaps roundtrip: one directed pass */
    {
        uint8_t code[128];
        int n = 0;
        uint8_t l0[] = { 0xF3,0x0F,0x6F,0x04,0x25,0x00,0x20,0x00,0x00 };
        uint8_t l1[] = { 0xF3,0x0F,0x6F,0x0C,0x25,0x40,0x20,0x00,0x00 };
        memcpy(code+n,l0,sizeof l0); n+=(int)sizeof l0;
        memcpy(code+n,l1,sizeof l1); n+=(int)sizeof l1;
        /* movlhps xmm0,xmm1 (0F 16 C1): xmm0.hi = xmm1.lo */
        code[n++]=0x0F; code[n++]=0x16; code[n++]=0xC1;
        /* movhlps xmm2,xmm0 (0F 12 D0): xmm2.lo = xmm0.hi */
        code[n++]=0x0F; code[n++]=0x12; code[n++]=0xD0;
        /* movhps [0x2080],xmm0 ; movlps [0x2090],xmm2 */
        uint8_t s0[] = { 0x0F,0x17,0x04,0x25,0x80,0x20,0x00,0x00 };
        uint8_t s1[] = { 0x0F,0x13,0x14,0x25,0x90,0x20,0x00,0x00 };
        memcpy(code+n,s0,sizeof s0); n+=(int)sizeof s0;
        memcpy(code+n,s1,sizeof s1); n+=(int)sizeof s1;
        code[n++]=0xF4;
        WemuCpu *cpu = wemu_cpu_create(0x10000);
        for (int i = 0; i < 32; i++) { a[i]=(uint8_t)rnd(); b[i]=(uint8_t)rnd(); }
        wemu_mem_write(cpu,0x2000,a,32); wemu_mem_write(cpu,0x2040,b,32);
        wemu_cpu_load(cpu,0x1000,code,(size_t)n);
        wemu_cpu_set_rip(cpu,0x1000);
        wemu_cpu_run(cpu,20);
        if (wemu_cpu_fault(cpu)) FAIL("movh/lps fault %d\n", wemu_cpu_fault(cpu));
        uint8_t hi[8], lo[8];
        wemu_mem_read(cpu,0x2080,hi,8);
        wemu_mem_read(cpu,0x2090,lo,8);
        if (memcmp(hi,b,8)) FAIL("movlhps/movhps\n");
        if (memcmp(lo,b,8)) FAIL("movhlps/movlps\n");
        wemu_cpu_destroy(cpu);
    }
    printf("SSE2 GATE PASS (100 random rounds x 128/256 vs C oracle)\n");
    return 0;
}