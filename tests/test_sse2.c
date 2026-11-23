/* test_sse2 — differential gate for the SSE2/SSSE3/AVX2 growth set:
 * every new vector opcode executes against an independent C oracle,
 * 128- and 256-bit, random inputs (fixed seed). Same survivorship-bias
 * rule as test_isa: the oracle is written from the SDM semantics, not
 * from the implementation. */
#include "wemu.h"
#include "wemu_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
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
    if (es == 16) {
        /* BYTE-wise logical oracle — deliberately NOT the emulator's
         * element-accumulator shape: that shared abstraction hid the
         * >=64-bit-shift fold bug in both (100 random rounds passed
         * while glibc strcmp_avx2 miscompared "false" vs "fdisk"). */
        for (int i = 0; i < nb; i++)
            d[i] = op == 0 ? (uint8_t)(a[i] ^ b[i])
                 : op == 1 ? (uint8_t)(a[i] & b[i])
                 : op == 2 ? (uint8_t)((uint8_t)~a[i] & b[i])
                 :           (uint8_t)(a[i] | b[i]);
        return;
    }
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
            /* movmskps / movmskpd: sign-bit extraction */
            {
                int n = enc_legacy(insn, 0x50, 0, 1);
                insn[0] = 0x66; /* pd: 2 qword sign bits */
                uint64_t rax = 0;
                run_vec(insn, n, 0, a, b, out, &rax);
                uint32_t m = 0;
                for (int i = 0; i < 2; i++) if (b[8*i+7] & 0x80) m |= 1u << i;
                if ((uint32_t)rax != m) FAIL("movmskpd: %llx want %x\n",
                    (unsigned long long)rax, m);
                uint8_t raw[3] = { 0x0F, 0x50, 0xC1 }; /* ps: no prefix */
                run_vec(raw, 3, 0, a, b, out, &rax);
                m = 0;
                for (int i = 0; i < 4; i++) if (b[4*i+3] & 0x80) m |= 1u << i;
                if ((uint32_t)rax != m) FAIL("movmskps: %llx want %x\n",
                    (unsigned long long)rax, m);
                n = enc_vex(insn, 0x50, 0, 0, 1, L, 0, 1); /* vmovmskps */
                run_vec(insn, n, L, a, b, out, &rax);
                m = 0;
                for (int i = 0; i < nb/4; i++) if (b[4*i+3] & 0x80) m |= 1u << i;
                if ((uint32_t)rax != m) FAIL("vmovmskps: %llx want %x\n",
                    (unsigned long long)rax, m);
                n = enc_vex(insn, 0x50, 0, 0, 1, L, 1, 1); /* vmovmskpd */
                run_vec(insn, n, L, a, b, out, &rax);
                m = 0;
                for (int i = 0; i < nb/8; i++) if (b[8*i+7] & 0x80) m |= 1u << i;
                if ((uint32_t)rax != m) FAIL("vmovmskpd: %llx want %x\n",
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
            /* psrldq/pslldq imm8 (0F 73 /3 /7 per SDM), legacy + VEX */
            for (int which = 0; which < 2; which++) {
                int imm = (int)(rnd() & 31);
                int reg = which ? 7 : 3;
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
    /* Named regression: the glibc strcmp_avx2 vpandn zero-mask clear.
     * "false" vs "fdisk": a = zero-byte mask (00x5, ff x27), b = equal
     * mask (ff 00 00 ff 00, ff x27). ~a & b must keep ONLY byte 0.
     * The es=16 accumulator fold bug zeroed everything -> busybox's
     * binary applet search concluded "false" == "fdisk" -> applet not
     * found. Both legacy SSE2 and VEX.128/256 forms are gated. */
    {
        uint8_t a[32], b[32], want[32], out[32], insn[16];
        memset(a, 0xff, 32); memset(a, 0x00, 5);
        memset(b, 0xff, 32); b[1] = b[2] = b[4] = 0;
        memset(want, 0x00, 32); want[0] = 0xff; want[3] = 0xff;
        int n = enc_legacy(insn, 0xDF, 0, 1);
        run_vec(insn, n, 0, a, b, out, NULL);
        check("strcmp-pandn-legacy", out, want, 16);
        for (int L = 0; L < 2; L++) {
            n = enc_vex(insn, 0xDF, 0, 0, 1, L, 1, 1);
            run_vec(insn, n, L, a, b, out, NULL);
            check("strcmp-pandn-vex", out, want, L ? 32 : 16);
        }
    }
    /* Named regression: immediate shift groups. SDM: 0F 71 is WORD
     * (/2 psrlw, /4 psraw, /6 psllw), 0F 72 is DWORD, 0F 73 is QWORD
     * (/2 psrlq, /6 psllq) plus /3 psrldq and /7 pslldq (BYTE shifts).
     * An earlier gate encoded the word ops on 0F 73 and hid the bug that
     #UD'd gcc14-vectorized kernel memset in boot-verify #148. */
    {
        uint8_t a[32], out[32], want[32], insn[16];
        for (int i = 0; i < 32; i++) a[i] = (uint8_t)(i * 7 + 3);
        const int cnts[] = { 0, 1, 7, 15, 16, 31, 32, 63, 64, 255 };
        for (int L = 0; L < 2; L++) {
            int nb = L ? 32 : 16;
            for (size_t ci = 0; ci < sizeof cnts / sizeof cnts[0]; ci++) {
                int cnt = cnts[ci];
                /* pslldq /7 and psrldq /3, byte-wise oracle */
                for (int digit = 3; digit <= 7; digit += 4) {
                    for (int i = 0; i < nb; i++) {
                        int lane = i & ~15, j = i & 15;
                        if (digit == 7)
                            want[i] = j >= cnt ? a[lane + j - cnt] : 0;
                        else
                            want[i] = cnt + j < 16 ? a[lane + cnt + j] : 0;
                    }
                    insn[0]=0x66; insn[1]=0x0F; insn[2]=0x73;
                    insn[3]=(uint8_t)(0xC0 | (digit << 3)); insn[4]=(uint8_t)cnt;
                    run_vec(insn, 5, 0, a, a, out, NULL);
                    check("shiftgrp-psdq-legacy", out, want, 16);
                    /* VEX: C5 (F9|FD) 73 /digit, vvvv=0 (dest xmm0) */
                    insn[0]=0xC5; insn[1]=L?0xFD:0xF9; insn[2]=0x73;
                    insn[3]=(uint8_t)(0xC0 | (digit << 3)); insn[4]=(uint8_t)cnt;
                    run_vec(insn, 5, L, a, a, out, NULL);
                    check("shiftgrp-psdq-vex", out, want, nb);
                }
                /* psllw /6, psrlw /2, psraw /4 — 0F 71 WORD group */
                for (int digit = 2; digit <= 6; digit += 2) {
                    for (int w = 0; w < nb / 2; w++) {
                        uint16_t v = (uint16_t)(a[2*w] | (a[2*w+1] << 8));
                        uint16_t r;
                        if (digit == 6) r = cnt >= 16 ? 0 : (uint16_t)(v << cnt);
                        else if (digit == 2) r = cnt >= 16 ? 0 : (uint16_t)(v >> cnt);
                        else { int16_t s = (int16_t)v;
                               r = cnt >= 16 ? (uint16_t)(s >> 15) : (uint16_t)(s >> cnt); }
                        want[2*w] = (uint8_t)r; want[2*w+1] = (uint8_t)(r >> 8);
                    }
                    insn[0]=0x66; insn[1]=0x0F; insn[2]=0x71;
                    insn[3]=(uint8_t)(0xC0 | (digit << 3)); insn[4]=(uint8_t)cnt;
                    run_vec(insn, 5, 0, a, a, out, NULL);
                    check("shiftgrp-psw-legacy", out, want, 16);
                }
                /* psllq /6, psrlq /2 — 0F 73 QWORD group (not word) */
                for (int digit = 2; digit <= 6; digit += 4) {
                    for (int q = 0; q < 2; q++) {
                        uint64_t v = (uint64_t)a[8*q] | ((uint64_t)a[8*q+1]<<8) |
                            ((uint64_t)a[8*q+2]<<16) | ((uint64_t)a[8*q+3]<<24) |
                            ((uint64_t)a[8*q+4]<<32) | ((uint64_t)a[8*q+5]<<40) |
                            ((uint64_t)a[8*q+6]<<48) | ((uint64_t)a[8*q+7]<<56);
                        uint64_t r = digit == 6 ? (cnt >= 64 ? 0 : v << cnt)
                                                : (cnt >= 64 ? 0 : v >> cnt);
                        for (int k = 0; k < 8; k++)
                            want[8*q+k] = (uint8_t)(r >> (8*k));
                    }
                    insn[0]=0x66; insn[1]=0x0F; insn[2]=0x73;
                    insn[3]=(uint8_t)(0xC0 | (digit << 3)); insn[4]=(uint8_t)cnt;
                    run_vec(insn, 5, 0, a, a, out, NULL);
                    check("shiftgrp-psq-legacy", out, want, 16);
                }
            }
        }
    }
    /* Named regression: (v)comisd/(v)ucomisd scalar compare -> EFLAGS.
     * busybox seq faulted #UD on comisd %xmm1,%xmm5. Gate the four
     * outcomes (less/greater/equal/unordered) for double + single,
     * reg and memory forms, legacy and VEX. */
    {
        struct { double a, b; uint64_t want; } T[] = {
            { 1.0, 2.0, WF_CF },
            { 2.0, 1.0, 0 },
            { 1.0, 1.0, WF_ZF },
        };
        for (int t = 0; t < 3; t++) {
            for (int form = 0; form < 4; form++) {
                WemuCpu *c = wemu_cpu_create(0x10000);
                uint8_t code[16]; int n = 0;
                int vexf = form >= 2, memf = form & 1;
                if (vexf) { code[n++]=0xC5; code[n++]=0xF9; } /* pp=1: double */
                else { code[n++]=0x66; code[n++]=0x0F; }
                code[n++]=0x2F; /* VEX C5 already implies the 0F map */
                if (memf) {
                    /* absolute [0x2000] needs SIB (modrm 04, SIB 25):
                     * modrm 05 alone is RIP-relative in 64-bit mode */
                    code[n++]=0x04; code[n++]=0x25; code[n++]=0x00;
                    code[n++]=0x20; code[n++]=0x00; code[n++]=0x00;
                    wemu_mem_write(c, 0x2000, &T[t].b, 8);
                } else {
                    code[n++]=0xC1; /* xmm0, xmm1 */
                    memcpy(c->xmm[1], &T[t].b, 8);
                }
                code[n++]=0xF4;
                memcpy(c->xmm[0], &T[t].a, 8);
                wemu_mem_write(c, 0x1000, code, (size_t)n);
                wemu_cpu_set_rip(c, 0x1000);
                wemu_cpu_run(c, 4);
                if (wemu_cpu_fault(c)) FAIL("comisd form%d fault %d\n", form, wemu_cpu_fault(c));
                uint64_t f = wemu_cpu_rflags(c) & (WF_ZF|WF_PF|WF_CF|WF_OF|WF_SF|WF_AF);
                if (f != T[t].want)
                    FAIL("comisd form%d %g vs %g flags=%llx want %llx\n",
                         form, T[t].a, T[t].b,
                         (unsigned long long)f, (unsigned long long)T[t].want);
                wemu_cpu_destroy(c);
            }
        }
        /* unordered (NaN): ZF=PF=CF=1 */
        {
            WemuCpu *c = wemu_cpu_create(0x10000);
            uint8_t code[] = { 0x66,0x0F,0x2F,0xC1, 0xF4 };
            double one = 1.0, nan = NAN;
            memcpy(c->xmm[0], &one, 8); memcpy(c->xmm[1], &nan, 8);
            wemu_mem_write(c, 0x1000, code, sizeof code);
            wemu_cpu_set_rip(c, 0x1000);
            wemu_cpu_run(c, 4);
            uint64_t f = wemu_cpu_rflags(c) & (WF_ZF|WF_PF|WF_CF);
            if (f != (WF_ZF|WF_PF|WF_CF)) FAIL("comisd unordered flags=%llx\n", (unsigned long long)f);
            wemu_cpu_destroy(c);
        }
        /* single-precision comiss (no 66) */
        {
            WemuCpu *c = wemu_cpu_create(0x10000);
            uint8_t code[] = { 0x0F,0x2F,0xC1, 0xF4 };
            float fa = 1.0f, fb = 2.0f;
            memcpy(c->xmm[0], &fa, 4); memcpy(c->xmm[1], &fb, 4);
            wemu_mem_write(c, 0x1000, code, sizeof code);
            wemu_cpu_set_rip(c, 0x1000);
            wemu_cpu_run(c, 4);
            if (wemu_cpu_fault(c)) FAIL("comiss fault %d\n", wemu_cpu_fault(c));
            if (!(wemu_cpu_rflags(c) & WF_CF)) FAIL("comiss less CF\n");
            wemu_cpu_destroy(c);
        }
    }
    /* Named regression: scalar SSE2 arithmetic + conversions — the
     * busybox seq FP-printf surface (cvtsi2sd/mulsd/addsd faulted #UD).
     * Bit-exact vs C double; cvttsd2si truncation + overflow indefinite;
     * minsd/maxsd NaN returns SRC per SDM. */
    {
        /* addsd/mulsd/subsd/divsd xmm0, xmm1 (F2 0F 58/59/5C/5E C1) */
        const uint8_t ops[4] = { 0x58, 0x59, 0x5C, 0x5E };
        for (int i = 0; i < 100; i++) {
            double a = (double)(int64_t)(rnd() % 1000000) / 11.0;
            double b = (double)(int64_t)(rnd() % 1000000) / 17.0;
            if (b == 0.0) b = 1.0;
            for (int op = 0; op < 4; op++) {
                WemuCpu *c = wemu_cpu_create(0x10000);
                uint8_t code[] = { 0xF2,0x0F,ops[op],0xC1, 0xF4 };
                memcpy(c->xmm[0], &a, 8); memcpy(c->xmm[1], &b, 8);
                wemu_mem_write(c, 0x1000, code, sizeof code);
                wemu_cpu_set_rip(c, 0x1000);
                wemu_cpu_run(c, 4);
                if (wemu_cpu_fault(c)) FAIL("scalar op%d fault %d\n", op, wemu_cpu_fault(c));
                double got; memcpy(&got, c->xmm[0], 8);
                double want = op==0 ? a+b : op==1 ? a*b : op==2 ? a-b : a/b;
                uint64_t gb, wb; memcpy(&gb,&got,8); memcpy(&wb,&want,8);
                if (gb != wb) FAIL("scalar op%d a=%g b=%g got %g want %g\n", op, a, b, got, want);
                wemu_cpu_destroy(c);
            }
        }
        /* cvtsi2sd rax -> xmm0 (F2 REX.W 0F 2A C0) */
        {
            WemuCpu *c = wemu_cpu_create(0x10000);
            uint8_t code[] = { 0xF2,0x48,0x0F,0x2A,0xC0, 0xF4 };
            wemu_cpu_set_reg(c, 0, (uint64_t)(int64_t)-1234567);
            wemu_mem_write(c, 0x1000, code, sizeof code);
            wemu_cpu_set_rip(c, 0x1000);
            wemu_cpu_run(c, 4);
            double got; memcpy(&got, c->xmm[0], 8);
            if (got != -1234567.0) FAIL("cvtsi2sd got %g\n", got);
            wemu_cpu_destroy(c);
        }
        /* cvttsd2si xmm0 -> eax: truncation + overflow indefinite */
        {
            struct { double v; int32_t want; } T[] = {
                { 2.9, 2 }, { -2.9, -2 }, { 1e18, (int32_t)0x80000000 },
            };
            for (int t = 0; t < 3; t++) {
                WemuCpu *c = wemu_cpu_create(0x10000);
                uint8_t code[] = { 0xF2,0x0F,0x2C,0xC0, 0xF4 };
                memcpy(c->xmm[0], &T[t].v, 8);
                wemu_mem_write(c, 0x1000, code, sizeof code);
                wemu_cpu_set_rip(c, 0x1000);
                wemu_cpu_run(c, 4);
                if ((int32_t)wemu_cpu_reg(c,0) != T[t].want)
                    FAIL("cvttsd2si %g got %d want %d\n", T[t].v,
                         (int32_t)wemu_cpu_reg(c,0), T[t].want);
                wemu_cpu_destroy(c);
            }
        }
        /* cvtsd2ss (F2 0F 5A) + cvtss2sd (F3 0F 5A) round-trip */
        {
            WemuCpu *c = wemu_cpu_create(0x10000);
            uint8_t code[] = { 0xF2,0x0F,0x5A,0xC0, 0xF3,0x0F,0x5A,0xC0, 0xF4 };
            double v = 1.5; /* exactly representable in float */
            memcpy(c->xmm[0], &v, 8);
            wemu_mem_write(c, 0x1000, code, sizeof code);
            wemu_cpu_set_rip(c, 0x1000);
            wemu_cpu_run(c, 6);
            double got; memcpy(&got, c->xmm[0], 8);
            if (got != 1.5) FAIL("cvt sd<->ss roundtrip got %g\n", got);
            wemu_cpu_destroy(c);
        }
        /* minsd/maxsd: NaN returns SRC (xmm1) per SDM */
        {
            WemuCpu *c = wemu_cpu_create(0x10000);
            uint8_t code[] = { 0xF2,0x0F,0x5D,0xC1, 0xF4 };
            double nan = NAN, two = 2.0;
            memcpy(c->xmm[0], &nan, 8); memcpy(c->xmm[1], &two, 8);
            wemu_mem_write(c, 0x1000, code, sizeof code);
            wemu_cpu_set_rip(c, 0x1000);
            wemu_cpu_run(c, 4);
            double got; memcpy(&got, c->xmm[0], 8);
            if (got != 2.0) FAIL("minsd NaN semantics got %g\n", got);
            wemu_cpu_destroy(c);
        }
    }
    /* Named regression: movq xmm -> r64 (66 REX.W 0F 7E) must move all
     * 64 bits. glibc __printf_fp extracts doubles with movq; the old
     * 32-bit-only handler printed every integer-valued double as 0
     * (busybox seq 1 5 -> five zeros, awk 2+3 -> 0). Also movd 32-bit
     * merge semantics + the r64 -> xmm direction (0F 6E REX.W). */
    {
        WemuCpu *c = wemu_cpu_create(0x10000);
        uint8_t code[] = { 0x66,0x48,0x0F,0x7E,0xC0, 0xF4 }; /* movq xmm0,rax */
        double d = 5.0; /* 0x4014000000000000: low half is ZERO */
        memcpy(c->xmm[0], &d, 8);
        wemu_mem_write(c, 0x1000, code, sizeof code);
        wemu_cpu_set_rip(c, 0x1000);
        wemu_cpu_run(c, 4);
        if (wemu_cpu_fault(c)) FAIL("movq fault %d\n", wemu_cpu_fault(c));
        uint64_t bits = wemu_cpu_reg(c, 0), want;
        memcpy(&want, &d, 8);
        if (bits != want) FAIL("movq xmm0,rax: got %llx want %llx\n",
            (unsigned long long)bits, (unsigned long long)want);
        wemu_cpu_destroy(c);
        /* round-trip r64 -> xmm0 (66 REX.W 0F 6E) */
        c = wemu_cpu_create(0x10000);
        uint8_t code2[] = { 0x66,0x48,0x0F,0x6E,0xC0,
                            0x66,0x48,0x0F,0x7E,0xC1, 0xF4 };
        wemu_cpu_set_reg(c, 0, want);
        wemu_mem_write(c, 0x1000, code2, sizeof code2);
        wemu_cpu_set_rip(c, 0x1000);
        wemu_cpu_run(c, 6);
        if (wemu_cpu_reg(c, 1) != want) FAIL("movq roundtrip\n");
        wemu_cpu_destroy(c);
        /* movd (no REX.W): 32-bit merge keeps upper GPR bits */
        c = wemu_cpu_create(0x10000);
        uint8_t code3[] = { 0x66,0x0F,0x7E,0xC0, 0xF4 };
        uint32_t lo = 0xdeadbeef;
        memcpy(c->xmm[0], &lo, 4);
        wemu_cpu_set_reg(c, 0, 0x1122334400000000ull);
        wemu_mem_write(c, 0x1000, code3, sizeof code3);
        wemu_cpu_set_rip(c, 0x1000);
        wemu_cpu_run(c, 4);
        if (wemu_cpu_reg(c, 0) != 0x11223344deadbeefull) FAIL("movd merge\n");
        wemu_cpu_destroy(c);
    }
    /* Named regression: cvt operand ORDER. cvttsd2si r32, xmm:
     * ModRM.reg = GPR dest (REX.R extends it), ModRM.rm = XMM source.
     * Reading xmm[reg] read the wrong register — awk $N became $0.
     * Gate the REX.R form (r9d <- xmm0) + cvtsd2ss with DISTINCT
     * src/dest (the same-reg round-trip hid the bug). */
    {
        WemuCpu *c = wemu_cpu_create(0x10000);
        uint8_t code[] = { 0xF2,0x44,0x0F,0x2C,0xC8, 0xF4 };
        double one = 1.0;
        memcpy(c->xmm[0], &one, 8);
        wemu_mem_write(c, 0x1000, code, sizeof code);
        wemu_cpu_set_rip(c, 0x1000);
        wemu_cpu_run(c, 4);
        if (wemu_cpu_fault(c)) FAIL("cvttsd2si r9d fault %d\n", wemu_cpu_fault(c));
        if ((int32_t)wemu_cpu_reg(c, 9) != 1)
            FAIL("cvttsd2si xmm0,r9d: got %d want 1\n", (int32_t)wemu_cpu_reg(c,9));
        wemu_cpu_destroy(c);
        /* cvtsd2ss xmm1, xmm0 (F2 0F 5A C8): dest xmm1, src xmm0 */
        c = wemu_cpu_create(0x10000);
        uint8_t code2[] = { 0xF2,0x0F,0x5A,0xC8, 0xF4 };
        double v = 1.5;
        memcpy(c->xmm[0], &v, 8);
        wemu_mem_write(c, 0x1000, code2, sizeof code2);
        wemu_cpu_set_rip(c, 0x1000);
        wemu_cpu_run(c, 4);
        float got; memcpy(&got, c->xmm[1], 4);
        if (got != 1.5f) FAIL("cvtsd2ss distinct regs got %g\n", got);
        wemu_cpu_destroy(c);
    }
    printf("SSE2 GATE PASS (100 random rounds x 128/256 vs C oracle)\n");
    return 0;
}