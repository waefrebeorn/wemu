/* wemu_sse.c — SSE2 + AVX/AVX2 seed set. The founding instructions:
 * vmovd + vpbroadcastb are the exact ops whose absence in qemu64 TCG
 * triple-faulted the WuBuOS CI boot (gcc14 vectorized memset). WEMU
 * executes them instead of dying. One concern: vector register ops. */
#include "wemu_internal.h"

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
    if (!vex && sse66 && full == 0x173) { /* psllq/psrldq/pslldq imm8 */
        int reg = REG(in);
        memcpy(a, c->xmm[dst], 16);
        uint64_t cnt = in->imm & 0xff;
        if (reg == 7) { /* psllq per qword */
            for (int q = 0; q < 2; q++) {
                uint64_t v;
                memcpy(&v, a + 8 * q, 8);
                v = cnt >= 64 ? 0 : v << cnt;
                memcpy(d + 8 * q, &v, 8);
            }
        } else if (reg == 3) { /* psrldq whole lane bytes */
            for (int i = 0; i < 16; i++)
                d[i] = (cnt + (uint64_t)i < 16) ? a[cnt + i] : 0;
        } else if (reg == 6) { /* pslldq */
            for (int i = 15; i >= 0; i--)
                d[i] = ((uint64_t)i >= cnt) ? a[i - cnt] : 0;
        } else return 0;
        memcpy(c->xmm[dst], d, 16);
        return 1;
    }
    return 0; /* not ours */
}