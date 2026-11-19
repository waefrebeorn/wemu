/* wemu_sse.c — SSE2 + AVX/AVX2 seed set. The founding instructions:
 * vmovd + vpbroadcastb are the exact ops whose absence in qemu64 TCG
 * triple-faulted the WuBuOS CI boot (gcc14 vectorized memset). WEMU
 * executes them instead of dying. One concern: vector register ops. */
#include "wemu_internal.h"
#include <math.h>

#define REX_R(in) (((in)->rex >> 2) & 1)
#define REX_B(in) ((in)->rex & 1)
#define REG(in)   (((in)->modrm >> 3) & 7)

static int vex_vvvv(const WemuInsn *in) {
    /* 3-byte VEX: vvvv lives in byte 2; 2-byte: byte 1 (both inverted) */
    uint8_t b = in->vex_len == 3 ? in->vex[2] : in->vex[1];
    return (~b >> 3) & 15;
}
static int vex_l(const WemuInsn *in) {
    return in->vex_len == 3 ? (in->vex[2] & 4) != 0 : (in->vex[1] & 4) != 0;
}

/* read the r/m operand as a vector (mod==3: xmm; else memory) */
static int rm_vec(WemuCpu *c, const WemuInsn *in, uint8_t *lo, uint8_t *hi,
                  int nbytes) {
    if ((in->modrm >> 6) == 3) {
        int rm = (in->modrm & 7) | (REX_B(in) << 3);
        memcpy(lo, c->xmm[rm], 16);
        memcpy(hi, c->ymm_hi[rm], 16);
        return 0;
    }
    /* effective address: shared owner (SIB, RIP-relative, disp) */
    uint64_t addr = wemu_eff_addr(c, in);
    if (wemu_mem_read(c, addr, lo, (size_t)nbytes) != 0) return -1;
    if (nbytes == 32 && wemu_mem_read(c, addr + 16, hi, 16) != 0) return -1;
    return 0;
}

static void store_vec(WemuCpu *c, const WemuInsn *in, const uint8_t *lo,
                      const uint8_t *hi, int nbytes) {
    if ((in->modrm >> 6) == 3) {
        int rm = (in->modrm & 7) | (REX_B(in) << 3);
        memcpy(c->xmm[rm], lo, 16);
        if (nbytes == 32) memcpy(c->ymm_hi[rm], hi, 16);
        return;
    }
    uint64_t addr = wemu_eff_addr(c, in);
    wemu_mem_write(c, addr, lo, 16);
    if (nbytes == 32) wemu_mem_write(c, addr + 16, hi, 16);
}

/* element-wise binary op; es = element bytes (1/2/4/8) */
static void binop(int op, uint8_t *d, const uint8_t *a, const uint8_t *b,
                  int nbytes, int es) {
    if (es == 16) {
        /* Logical ops (pxor/pand/pandn/por) are BYTE-wise. The element
         * loop below accumulates into uint64_t with shifts 8*k — for
         * es=16 those shifts are >=64 (UB; x86 masks to 63) and fold
         * upper-lane bytes into lower ones. glibc strcmp_avx2's vpandn
         * zero-mask clearing hit exactly this: "false" vs "fdisk"
         * compared equal because the terminator bit was never cleared. */
        for (int i = 0; i < nbytes; i++) {
            uint8_t av = a[i], bv = b[i];
            d[i] = op == 0 ? (uint8_t)(av ^ bv)
                 : op == 1 ? (uint8_t)(av & bv)
                 : op == 2 ? (uint8_t)(~av & bv)
                 :           (uint8_t)(av | bv);
        }
        return;
    }
    for (int i = 0; i < nbytes; i += es) {
        uint64_t av = 0, bv = 0;
        for (int k = 0; k < es; k++) {
            av |= (uint64_t)a[i + k] << (8 * k);
            bv |= (uint64_t)b[i + k] << (8 * k);
        }
        uint64_t r = 0;
        switch (op) {
        case 0: r = av ^ bv; break;             /* pxor */
        case 1: r = av & bv; break;             /* pand */
        case 2: r = ~av & bv; break;            /* pandn */
        case 3: r = av | bv; break;             /* por */
        case 4: r = av + bv; break;             /* padd */
        case 5: r = av - bv; break;             /* psub */
        case 6: r = av == bv ? ~0ull : 0; break;   /* pcmpeq */
        case 7: {                               /* pcmpgt (signed) */
            int bits = es * 8;
            int64_t sa = (int64_t)(av << (64 - bits)) >> (64 - bits);
            int64_t sb = (int64_t)(bv << (64 - bits)) >> (64 - bits);
            r = sa > sb ? ~0ull : 0;
            break;
        }
        case 8: r = av < bv ? av : bv; break;   /* pminu */
        case 9: r = av > bv ? av : bv; break;   /* pmaxu */
        case 10: r = av > bv ? av - bv : 0; break; /* psubusb */
        case 11: {                              /* paddusb */
            uint64_t s = av + bv;
            uint64_t max = es >= 8 ? ~0ull : ((1ull << (es * 8)) - 1);
            r = s > max ? max : s;
            break;
        }
        }
        for (int k = 0; k < es; k++) d[i + k] = (uint8_t)(r >> (8 * k));
    }
}

static int es_for(uint8_t o) {
    switch (o) {
    case 0xFC: case 0xF8: return 1;
    case 0xFD: case 0xF9: return 2;
    case 0xFE: case 0xFA: return 4;
    case 0xD4: case 0xFB: return 8;
    case 0x74: case 0x64: case 0xDA: case 0xDE:
    case 0xD8: case 0xDC: return 1;
    case 0x75: case 0x65: return 2;
    case 0x76: case 0x66: return 4;
    }
    return 16; /* logical ops: whole lane */
}

int wemu_exec_sse(WemuCpu *c, const WemuInsn *in) {
    uint32_t full = in->op | ((uint32_t)(in->vex[0] >> 4) << 8);
    uint8_t o = in->op;
    int vex = in->vex_len != 0;
    int L = vex ? vex_l(in) : 0;
    int nb = L ? 32 : 16;
    int dst = REG(in) | (REX_R(in) << 3);
    uint8_t a[32] = {0}, b[32] = {0}, d[32] = {0};
    int sse66 = !vex && in->opsize == 2;

    if (full == 0x177) { /* (v)zeroupper / emms: clear upper YMM state.
        * Neither form carries a ModRM byte (0x77 is the opcode). */
        for (int i = 0; i < 16; i++) memset(c->ymm_hi[i], 0, 16);
        return 1;
    }
    if (full == 0x16E || (vex && full == 0x16E)) { /* (v)movd xmm, r/m32 */
        uint64_t v = 0;
        if ((in->modrm >> 6) == 3) {
            int rm = (in->modrm & 7) | (REX_B(in) << 3);
            v = c->r[rm] & ((in->rex & 8) ? ~0ull : 0xffffffffull);
        } else {
            uint64_t addr = wemu_eff_addr(c, in);
            if (wemu_mem_read(c, addr, &v, (in->rex & 8) ? 8 : 4) != 0) return -1;
        }
        memset(c->xmm[dst], 0, 16);
        memcpy(c->xmm[dst], &v, (in->rex & 8) ? 8 : 4);
        if (vex) memset(c->ymm_hi[dst], 0, 16);
        return 1;
    }
    if (full == 0x17E) { /* movd r/m32, xmm (66) / movq xmm, r/m64 (F3) */
        if (in->rep == 0xF3) {
            uint64_t v = 0;
            int rm = (in->modrm & 7) | (REX_B(in) << 3);
            if ((in->modrm >> 6) == 3) v = c->r[rm];
            else if (wemu_mem_read(c, wemu_eff_addr(c, in), &v, 8) != 0)
                return -1;
            memset(c->xmm[dst], 0, 16);
            memcpy(c->xmm[dst], &v, 8);
            return 1;
        }
        uint32_t v;
        memcpy(&v, c->xmm[dst], 4);
        if ((in->modrm >> 6) == 3) {
            int rm = (in->modrm & 7) | (REX_B(in) << 3);
            c->r[rm] = (c->r[rm] & ~0xffffffffull) | v;
        } else {
            wemu_mem_write(c, wemu_eff_addr(c, in), &v, 4);
        }
        return 1;
    }
    if (vex && full == 0x17E) { /* vmovd/vmovq r/m, xmm */
        int bytes = (in->rex & 8) ? 8 : 4;
        uint64_t v = 0;
        memcpy(&v, c->xmm[dst], (size_t)bytes);
        if ((in->modrm >> 6) == 3) {
            int rm = (in->modrm & 7) | (REX_B(in) << 3);
            if (bytes == 4) c->r[rm] = (c->r[rm] & ~0xffffffffull) | (uint32_t)v;
            else c->r[rm] = v;
        } else {
            wemu_mem_write(c, wemu_eff_addr(c, in), &v, (size_t)bytes);
        }
        return 1;
    }
    if (full == 0x16F || full == 0x17F) { /* (v)movdqa(u) load/store */
        if (!vex && !sse66 && in->rep != 0xF3) return 0;
        if (full == 0x16F) {
            if (rm_vec(c, in, c->xmm[dst], c->ymm_hi[dst], nb) != 0) return -1;
            if (vex && !L) memset(c->ymm_hi[dst], 0, 16);
        } else {
            store_vec(c, in, c->xmm[dst], c->ymm_hi[dst], nb);
        }
        return 1;
    }
    if (full == 0x1D6) { /* (v)movq xmm/m64, xmm */
        uint64_t v;
        memcpy(&v, c->xmm[dst], 8);
        if ((in->modrm >> 6) == 3) {
            int rm = (in->modrm & 7) | (REX_B(in) << 3);
            memset(c->xmm[rm], 0, 16);
            memcpy(c->xmm[rm], &v, 8);
            if (vex) memset(c->ymm_hi[rm], 0, 16);
        } else {
            wemu_mem_write(c, wemu_eff_addr(c, in), &v, 8);
        }
        return 1;
    }
    if (vex && full >= 0x200 &&
        (o == 0x78 || o == 0x79 || o == 0x7C || o == 0x59)) {
        /* vpbroadcastb/w/d/q: the CI-gap instructions */
        int es = o == 0x78 ? 1 : o == 0x79 ? 2 : o == 0x7C ? 4 : 8;
        uint8_t seed[8] = {0};
        if ((in->modrm >> 6) == 3) {
            int rm = (in->modrm & 7) | (REX_B(in) << 3);
            memcpy(seed, c->xmm[rm], (size_t)es);
        } else {
            if (wemu_mem_read(c, wemu_eff_addr(c, in), seed, (size_t)es) != 0)
                return -1;
        }
        for (int i = 0; i < nb; i += es) memcpy(d + i, seed, (size_t)es);
        memcpy(c->xmm[dst], d, 16);
        if (L) memcpy(c->ymm_hi[dst], d + 16, 16);
        else memset(c->ymm_hi[dst], 0, 16);
        return 1;
    }
    /* binary vector ops: legacy (66 required) and VEX */
    int op = -1;
    if (o == 0xEF) op = 0;
    else if (o == 0xDB) op = 1;
    else if (o == 0xDF) op = 2;
    else if (o == 0xEB) op = 3;
    else if (o == 0xFC || o == 0xFD || o == 0xFE || o == 0xD4) op = 4;
    else if (o == 0xF8 || o == 0xF9 || o == 0xFA || o == 0xFB) op = 5;
    else if (o == 0x74 || o == 0x75 || o == 0x76) op = 6;  /* pcmpeq */
    else if (o == 0x64 || o == 0x65 || o == 0x66) op = 7;  /* pcmpgt */
    else if (o == 0xDA) op = 8;                            /* pminub */
    else if (o == 0xDE) op = 9;                            /* pmaxub */
    else if (o == 0xD8) op = 10;                           /* psubusb */
    else if (o == 0xDC) op = 11;                           /* paddusb */
    if (op >= 0 && full >= 0x100 && full < 0x200 && (vex || sse66)) {
        int es = es_for(o);
        if (rm_vec(c, in, b, b + 16, nb) != 0) return -1;
        if (vex) {
            int src = vex_vvvv(in);
            memcpy(a, c->xmm[src], 16);
            memcpy(a + 16, c->ymm_hi[src], 16);
        } else {
            memcpy(a, c->xmm[dst], 16);
            memcpy(a + 16, c->ymm_hi[dst], 16);
        }
        binop(op, d, a, b, nb, es);
        memcpy(c->xmm[dst], d, 16);
        if (L) memcpy(c->ymm_hi[dst], d + 16, 16);
        else if (vex) memset(c->ymm_hi[dst], 0, 16);
        return 1;
    }
    if (!vex && sse66 && full == 0x170) { /* pshufd xmm, xmm/m128, imm8 */
        if (rm_vec(c, in, b, b + 16, 16) != 0) return -1;
        for (int i = 0; i < 4; i++)
            memcpy(d + 4 * i, b + 4 * ((in->imm >> (2 * i)) & 3), 4);
        memcpy(c->xmm[dst], d, 16);
        return 1;
    }
    if (!vex && sse66 && full == 0x173) { /* shift-count group 66 0F 73 */
        int reg = REG(in);
        /* the shift-count group selects the op via reg; the OPERAND is
         * the r/m register, not the reg field. SDM group table:
         * /2 psrlw, /3 psrldq, /4 psraw, /6 psllw, /7 pslldq.
         * (The old code had /7 as per-qword psllq and /6 as pslldq —
         * glibc __strcmp_sse2's pslldq $7/$15 alignment shifts executed
         * as BIT shifts, miscomparing "false" vs "fdflush"/"fdformat".) */
        int xr = (in->modrm & 7) | (REX_B(in) << 3);
        memcpy(a, c->xmm[xr], 16);
        uint64_t cnt = in->imm & 0xff;
        if (reg == 7) { /* pslldq: whole-lane BYTE shift left */
            for (int i = 15; i >= 0; i--)
                d[i] = ((uint64_t)i >= cnt) ? a[i - cnt] : 0;
        } else if (reg == 3) { /* psrldq: whole-lane BYTE shift right */
            for (int i = 0; i < 16; i++)
                d[i] = (cnt + (uint64_t)i < 16) ? a[cnt + i] : 0;
        } else if (reg == 6 || reg == 2 || reg == 4) { /* psllw/psrlw/psraw */
            for (int w = 0; w < 8; w++) {
                uint16_t v;
                memcpy(&v, a + 2 * w, 2);
                uint16_t r;
                if (reg == 6) r = cnt >= 16 ? 0 : (uint16_t)(v << cnt);
                else if (reg == 2) r = cnt >= 16 ? 0 : (uint16_t)(v >> cnt);
                else { int16_t s = (int16_t)v;
                       r = cnt >= 16 ? (uint16_t)(s >> 15)
                                     : (uint16_t)(s >> cnt); }
                memcpy(d + 2 * w, &r, 2);
            }
        } else return 0;
        memcpy(c->xmm[xr], d, 16);
        return 1;
    }
    /* ---- SSE2/SSSE3/AVX2 growth: the glibc-string-function surface ---- */
    if (full >= 0x100 && full < 0x200 && (vex || sse66) &&
        (o == 0x60 || o == 0x61 || o == 0x62 || o == 0x6C ||
         o == 0x68 || o == 0x69 || o == 0x6A || o == 0x6D)) {
        /* punpckl/h bw/wd/dq/qdq: interleave elements per 128-bit lane */
        int es = (o == 0x60 || o == 0x68) ? 1 : (o == 0x61 || o == 0x69) ? 2
               : (o == 0x62 || o == 0x6A) ? 4 : 8;
        int hi = o == 0x68 || o == 0x69 || o == 0x6A || o == 0x6D;
        if (rm_vec(c, in, b, b + 16, nb) != 0) return -1;
        if (vex) {
            int src = vex_vvvv(in);
            memcpy(a, c->xmm[src], 16);
            memcpy(a + 16, c->ymm_hi[src], 16);
        } else {
            memcpy(a, c->xmm[dst], 16);
            memcpy(a + 16, c->ymm_hi[dst], 16);
        }
        int per_lane = 8 / es;             /* elements interleaved per lane */
        for (int lane = 0; lane < nb; lane += 16) {
            for (int i = 0; i < per_lane; i++) {
                int so = hi ? 8 : 0;
                memcpy(d + lane + 2 * i * es, a + lane + so + i * es, (size_t)es);
                memcpy(d + lane + (2 * i + 1) * es, b + lane + so + i * es, (size_t)es);
            }
        }
        memcpy(c->xmm[dst], d, 16);
        if (L) memcpy(c->ymm_hi[dst], d + 16, 16);
        else if (vex) memset(c->ymm_hi[dst], 0, 16);
        return 1;
    }
    if (full == 0x150 && (vex || in->rep == 0)) {
        /* (v)movmskps r32, xmm/ymm (no prefix): bit31 of each dword;
         * (v)movmskpd (66): bit63 of each qword */
        if ((in->modrm >> 6) != 3) return 0;
        int rm = (in->modrm & 7) | (REX_B(in) << 3);
        uint8_t src[32];
        memcpy(src, c->xmm[rm], 16);
        memcpy(src + 16, c->ymm_hi[rm], 16);
        uint32_t mask = 0;
        if (in->opsize == 2) { /* 66 / VEX.pp=1: pd (qword sign bits) */
            for (int i = 0; i < nb / 8; i++)
                if (src[8 * i + 7] & 0x80) mask |= 1u << i;
        } else {
            for (int i = 0; i < nb / 4; i++)
                if (src[4 * i + 3] & 0x80) mask |= 1u << i;
        }
        int gr = REG(in) | (REX_R(in) << 3);
        c->r[gr] = mask;
        return 1;
    }
    if (full == 0x1D7 && (vex || sse66)) { /* (v)pmovmskb r32, xmm/ymm */
        if ((in->modrm >> 6) != 3) return 0;
        int rm = (in->modrm & 7) | (REX_B(in) << 3);
        uint8_t src[32];
        memcpy(src, c->xmm[rm], 16);
        memcpy(src + 16, c->ymm_hi[rm], 16);
        uint32_t mask = 0;
        for (int i = 0; i < nb; i++)
            if (src[i] & 0x80) mask |= 1u << i;
        int gr = REG(in) | (REX_R(in) << 3);
        c->r[gr] = mask;                   /* 32-bit write zero-extends */
        return 1;
    }
    if (full == 0x30F && (vex || sse66)) { /* (v)palignr xmm, xmm/m, imm8 */
        if (rm_vec(c, in, b, b + 16, nb) != 0) return -1;
        if (vex) {
            int src = vex_vvvv(in);
            memcpy(a, c->xmm[src], 16);
            memcpy(a + 16, c->ymm_hi[src], 16);
        } else {
            memcpy(a, c->xmm[dst], 16);
            memcpy(a + 16, c->ymm_hi[dst], 16);
        }
        uint64_t cnt = in->imm & 0xff;
        for (int lane = 0; lane < nb; lane += 16) {
            uint8_t cat[32];
            memcpy(cat, a + lane, 16);
            memcpy(cat + 16, b + lane, 16);
            for (int i = 0; i < 16; i++)
                d[lane + i] = cnt + (uint64_t)i < 32 ? cat[cnt + i] : 0;
        }
        memcpy(c->xmm[dst], d, 16);
        if (L) memcpy(c->ymm_hi[dst], d + 16, 16);
        else if (vex) memset(c->ymm_hi[dst], 0, 16);
        return 1;
    }
    if (full == 0x200 && (vex || sse66)) { /* (v)pshufb (SSSE3) */
        if (rm_vec(c, in, b, b + 16, nb) != 0) return -1;
        if (vex) {
            int src = vex_vvvv(in);
            memcpy(a, c->xmm[src], 16);
            memcpy(a + 16, c->ymm_hi[src], 16);
        } else {
            memcpy(a, c->xmm[dst], 16);
            memcpy(a + 16, c->ymm_hi[dst], 16);
        }
        for (int lane = 0; lane < nb; lane += 16)
            for (int i = 0; i < 16; i++)
                d[lane + i] = (b[lane + i] & 0x80) ? 0
                              : a[lane + (b[lane + i] & 15)];
        memcpy(c->xmm[dst], d, 16);
        if (L) memcpy(c->ymm_hi[dst], d + 16, 16);
        else if (vex) memset(c->ymm_hi[dst], 0, 16);
        return 1;
    }
    if (vex && full == 0x170) { /* vpshufd ymm/xmm, xmm/m, imm8 */
        if (rm_vec(c, in, b, b + 16, nb) != 0) return -1;
        for (int lane = 0; lane < nb; lane += 16)
            for (int i = 0; i < 4; i++)
                memcpy(d + lane + 4 * i,
                       b + lane + 4 * ((in->imm >> (2 * i)) & 3), 4);
        memcpy(c->xmm[dst], d, 16);
        if (L) memcpy(c->ymm_hi[dst], d + 16, 16);
        else memset(c->ymm_hi[dst], 0, 16);
        return 1;
    }
    if (vex && full == 0x173 && (REG(in) == 3 || REG(in) == 7)) {
        /* vpsrldq (/3) / vpslldq (/7): ModRM.reg is the op digit, rm is
         * the source, and the DESTINATION lives in VEX.vvvv */
        int dstv = vex_vvvv(in);
        if (rm_vec(c, in, a, a + 16, nb) != 0) return -1;
        uint64_t cnt = in->imm & 0xff;
        for (int lane = 0; lane < nb; lane += 16) {
            if (REG(in) == 3)
                for (int i = 0; i < 16; i++)
                    d[lane + i] = cnt + (uint64_t)i < 16 ? a[lane + cnt + i] : 0;
            else
                for (int i = 15; i >= 0; i--)
                    d[lane + i] = (uint64_t)i >= cnt ? a[lane + i - cnt] : 0;
        }
        memcpy(c->xmm[dstv], d, 16);
        if (L) memcpy(c->ymm_hi[dstv], d + 16, 16);
        else memset(c->ymm_hi[dstv], 0, 16);
        return 1;
    }
    if ((full == 0x110 || full == 0x111) && !vex &&
        (in->rep == 0xF3 || in->rep == 0xF2)) {
        /* movss (F3) / movsd (F2): scalar 4/8-byte move */
        int bytes = in->rep == 0xF3 ? 4 : 8;
        if (full == 0x110) {
            uint8_t v[8] = {0};
            if ((in->modrm >> 6) == 3) {
                int rm = (in->modrm & 7) | (REX_B(in) << 3);
                memcpy(v, c->xmm[rm], (size_t)bytes);
                /* reg<-reg keeps dst upper bytes (legacy merge) */
                memcpy(c->xmm[dst], v, (size_t)bytes);
            } else {
                if (wemu_mem_read(c, wemu_eff_addr(c, in), v, (size_t)bytes) != 0)
                    return -1;
                memset(c->xmm[dst], 0, 16);
                memcpy(c->xmm[dst], v, (size_t)bytes);
            }
        } else {
            uint8_t v[8];
            memcpy(v, c->xmm[dst], (size_t)bytes);
            if ((in->modrm >> 6) == 3) {
                int rm = (in->modrm & 7) | (REX_B(in) << 3);
                memcpy(c->xmm[rm], v, (size_t)bytes);
            } else if (wemu_mem_write(c, wemu_eff_addr(c, in), v, (size_t)bytes) != 0)
                return -1;
        }
        return 1;
    }
    if (full == 0x12E || full == 0x12F) {
        /* (v)ucomisd/(v)comisd (66) and (v)ucomiss/(v)comiss (none):
         * scalar compare -> EFLAGS (ZF/PF/CF; OF/SF/AF cleared).
         * busybox seq's FP formatting path compares with comisd. */
        int pp = vex ? ((in->vex_len == 3 ? in->vex[2] : in->vex[1]) & 3)
                     : (sse66 ? 1 : 0);
        int dbl = pp == 1;
        if (vex && L) return 0; /* VEX.L=1 is #UD for scalar compares */
        double a, b;
        if (dbl) {
            memcpy(&a, c->xmm[dst], 8);
            if ((in->modrm >> 6) == 3) {
                int rm = (in->modrm & 7) | (REX_B(in) << 3);
                memcpy(&b, c->xmm[rm], 8);
            } else if (wemu_mem_read(c, wemu_eff_addr(c, in), &b, 8) != 0)
                return -1;
        } else {
            float fa, fb;
            memcpy(&fa, c->xmm[dst], 4);
            if ((in->modrm >> 6) == 3) {
                int rm = (in->modrm & 7) | (REX_B(in) << 3);
                memcpy(&fb, c->xmm[rm], 4);
            } else if (wemu_mem_read(c, wemu_eff_addr(c, in), &fb, 4) != 0)
                return -1;
            a = (double)fa; b = (double)fb;
        }
        uint64_t f = c->rflags & ~(WF_ZF | WF_PF | WF_CF | WF_OF | WF_SF | WF_AF);
        if (isnan(a) || isnan(b)) f |= WF_ZF | WF_PF | WF_CF;
        else if (a < b) f |= WF_CF;
        else if (a == b) f |= WF_ZF;
        c->rflags = f;
        return 1;
    }
    if ((full == 0x128 || full == 0x129 || full == 0x110 || full == 0x111) &&
        (vex || in->rep == 0)) {
        /* (v)movaps/movups (no prefix) and (v)movapd/movupd (66):
         * whole-lane moves, byte-identical to movdqa(u) */
        if (full == 0x128 || full == 0x110) {
            if (rm_vec(c, in, c->xmm[dst], c->ymm_hi[dst], nb) != 0) return -1;
            if (vex && !L) memset(c->ymm_hi[dst], 0, 16);
        } else {
            store_vec(c, in, c->xmm[dst], c->ymm_hi[dst], nb);
        }
        return 1;
    }
    if ((full == 0x112 || full == 0x113 || full == 0x116 || full == 0x117) &&
        !vex && in->rep == 0) {
        /* movlps/movhps (and 66 pd forms): 8-byte half-lane moves.
         * reg<-reg forms are movhlps (0F12) / movlhps (0F16). */
        int hi = full == 0x116 || full == 0x117;
        int load = full == 0x112 || full == 0x116;
        uint8_t v[8];
        if (load) {
            if ((in->modrm >> 6) == 3) {
                int rm = (in->modrm & 7) | (REX_B(in) << 3);
                /* movhlps: dst.low <- src.high ; movlhps: dst.high <- src.low */
                memcpy(v, c->xmm[rm] + (hi ? 0 : 8), 8);
            } else if (wemu_mem_read(c, wemu_eff_addr(c, in), v, 8) != 0)
                return -1;
            memcpy(c->xmm[dst] + (hi ? 8 : 0), v, 8);
        } else {
            memcpy(v, c->xmm[dst] + (hi ? 8 : 0), 8);
            if ((in->modrm >> 6) == 3) {
                int rm = (in->modrm & 7) | (REX_B(in) << 3);
                memcpy(c->xmm[rm], v, 8);
            } else if (wemu_mem_write(c, wemu_eff_addr(c, in), v, 8) != 0)
                return -1;
        }
        return 1;
    }
    if (full >= 0x154 && full <= 0x157) {
        /* and/andn/or/xor ps (no prefix) / pd (66): lane-wise logic */
        int lop = full == 0x154 ? 1 : full == 0x155 ? 2
                : full == 0x156 ? 3 : 0;
        if (rm_vec(c, in, b, b + 16, nb) != 0) return -1;
        if (vex) {
            int src = vex_vvvv(in);
            memcpy(a, c->xmm[src], 16);
            memcpy(a + 16, c->ymm_hi[src], 16);
        } else {
            memcpy(a, c->xmm[dst], 16);
            memcpy(a + 16, c->ymm_hi[dst], 16);
        }
        binop(lop, d, a, b, nb, 16);
        memcpy(c->xmm[dst], d, 16);
        if (L) memcpy(c->ymm_hi[dst], d + 16, 16);
        else if (vex) memset(c->ymm_hi[dst], 0, 16);
        return 1;
    }
    return 0; /* not ours */
}