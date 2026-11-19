/* wemu_x87.c — x87 FPU: the double-precision escape opcodes D8-DF.
 * One concern: x87 state + semantics. busybox seq's FP formatting path
 * faulted #UD on fnstcw before this existed; glibc's FP printf/scanf
 * surface needs the same subset. Internal precision is IEEE double
 * (m80 converts via host long double) — documented limitation; the
 * common subset is complete, rare opcodes stay honest #UD.
 * License: WaefreBeorn Umbrella License v3.0. */
#include "wemu_internal.h"
#include <math.h>
#include <fenv.h>
#include <string.h>

#define X87_SW_C0 0x0100
#define X87_SW_C1 0x0200
#define X87_SW_C2 0x0400
#define X87_SW_C3 0x4000

static double *st(WemuCpu *c, int i) {
    return &c->x87_st[(c->x87_top + i) & 7];
}
static void x87_push(WemuCpu *c, double v) {
    c->x87_top = (c->x87_top - 1) & 7;
    c->x87_st[c->x87_top] = v;
    c->x87_sw = (uint16_t)((c->x87_sw & ~0x3800) | (c->x87_top << 11));
}
static void x87_pop(WemuCpu *c) {
    c->x87_top = (c->x87_top + 1) & 7;
    c->x87_sw = (uint16_t)((c->x87_sw & ~0x3800) | (c->x87_top << 11));
}
static void set_cc(WemuCpu *c, int c0, int c2, int c3) {
    uint16_t sw = c->x87_sw & ~(X87_SW_C0 | X87_SW_C2 | X87_SW_C3);
    if (c0) sw |= X87_SW_C0;
    if (c2) sw |= X87_SW_C2;
    if (c3) sw |= X87_SW_C3;
    c->x87_sw = sw;
}
/* compare -> condition codes (unordered: C0=C2=C3=1) */
static void x87_compare(WemuCpu *c, double a, double b) {
    if (isnan(a) || isnan(b)) set_cc(c, 1, 1, 1);
    else if (a > b) set_cc(c, 0, 0, 0);
    else if (a < b) set_cc(c, 1, 0, 0);
    else set_cc(c, 0, 0, 1);
}
static void x87_comi_flags(WemuCpu *c, double a, double b) {
    uint64_t f = c->rflags & ~(WF_ZF | WF_PF | WF_CF);
    if (isnan(a) || isnan(b)) f |= WF_ZF | WF_PF | WF_CF;
    else if (a < b) f |= WF_CF;
    else if (a == b) f |= WF_ZF;
    c->rflags = f;
}
static int host_round_mode(uint16_t cw) {
    switch ((cw >> 10) & 3) {
    case 1: return FE_DOWNWARD;
    case 2: return FE_UPWARD;
    case 3: return FE_TOWARDZERO;
    default: return FE_TONEAREST;
    }
}
static double x87_round(WemuCpu *c, double v) {
    int old = fegetround();
    fesetround(host_round_mode(c->x87_cw));
    double r = nearbyint(v);
    fesetround(old);
    return r;
}
static uint64_t x87_to_int(WemuCpu *c, double v, int bytes) {
    double r = x87_round(c, v);
    uint64_t indef = bytes == 2 ? 0x8000u : bytes == 4 ? 0x80000000u
                                                        : 0x8000000000000000ull;
    if (isnan(r)) return indef;
    if (bytes == 2) {
        if (r < -32768.0 || r > 32767.0) return indef;
        return (uint16_t)(int16_t)r;
    }
    if (bytes == 4) {
        if (r < -2147483648.0 || r > 2147483647.0) return indef;
        return (uint32_t)(int32_t)r;
    }
    if (r < -9223372036854775808.0 || r >= 9223372036854775808.0) return indef;
    return (uint64_t)(int64_t)r;
}

/* memory operand helpers (x87 never uses the reg field as a GPR) */
static int rd_mem(WemuCpu *c, const WemuInsn *in, void *dst, int bytes) {
    return wemu_mem_read(c, wemu_eff_addr(c, in), dst, (size_t)bytes);
}
static int wr_mem(WemuCpu *c, const WemuInsn *in, const void *src, int bytes) {
    return wemu_mem_write(c, wemu_eff_addr(c, in), src, (size_t)bytes);
}
static double ld_m32(WemuCpu *c, const WemuInsn *in, int *err) {
    float f; *err = rd_mem(c, in, &f, 4); return (double)f;
}
static double ld_m64(WemuCpu *c, const WemuInsn *in, int *err) {
    double d; *err = rd_mem(c, in, &d, 8); return d;
}
static double ld_m80(WemuCpu *c, const WemuInsn *in, int *err) {
    long double ld; *err = rd_mem(c, in, &ld, 10); return (double)ld;
}
static int st_m32(WemuCpu *c, const WemuInsn *in, double v) {
    float f = (float)v; return wr_mem(c, in, &f, 4);
}
static int st_m64(WemuCpu *c, const WemuInsn *in, double v) {
    return wr_mem(c, in, &v, 8);
}
static int st_m80(WemuCpu *c, const WemuInsn *in, double v) {
    long double ld = (long double)v; return wr_mem(c, in, &ld, 10);
}
static double ld_int(WemuCpu *c, const WemuInsn *in, int bytes, int *err) {
    if (bytes == 2) { int16_t v; *err = rd_mem(c, in, &v, 2); return (double)v; }
    if (bytes == 4) { int32_t v; *err = rd_mem(c, in, &v, 4); return (double)v; }
    int64_t v; *err = rd_mem(c, in, &v, 8); return (double)v;
}

/* returns 1 handled, 0 unknown (#UD), -1 memory fault */
int wemu_x87_exec(WemuCpu *c, const WemuInsn *in) {
    uint32_t full = in->op | ((in->vex[0] >> 4) << 8);
    int o = full & 0xFF;
    int reg = (in->modrm >> 3) & 7;
    int isreg = (in->modrm >> 6) == 3;
    int i = in->modrm & 7;
    int err = 0;
    double a;

    if (o == 0xD8 || o == 0xDC) {
        int m64 = (o == 0xDC);
        if (isreg) {
            /* D8: op st(0),st(i) ; DC: op st(i),st(0) */
            int dst = m64 ? i : 0, src = m64 ? 0 : i;
            double x = *st(c, dst), y = *st(c, src);
            switch (reg) {
            case 0: *st(c, dst) = x + y; break;
            case 1: *st(c, dst) = x * y; break;
            case 4: *st(c, dst) = m64 ? y - x : x - y; break; /* DC fsubr / D8 fsub */
            case 5: *st(c, dst) = m64 ? x - y : y - x; break; /* DC fsub  / D8 fsubr */
            case 6: *st(c, dst) = m64 ? y / x : x / y; break; /* DC fdivr / D8 fdiv */
            case 7: *st(c, dst) = m64 ? x / y : y / x; break; /* DC fdiv  / D8 fdivr */
            case 2: x87_compare(c, x, y); break;              /* fcom */
            case 3: x87_compare(c, x, y); x87_pop(c); break;  /* fcomp */
            default: return 0;
            }
            return 1;
        }
        a = m64 ? ld_m64(c, in, &err) : ld_m32(c, in, &err);
        if (err) return -1;
        switch (reg) {
        case 0: *st(c, 0) = *st(c, 0) + a; break;
        case 1: *st(c, 0) = *st(c, 0) * a; break;
        case 2: x87_compare(c, *st(c, 0), a); break;
        case 3: x87_compare(c, *st(c, 0), a); x87_pop(c); break;
        case 4: *st(c, 0) = *st(c, 0) - a; break;
        case 5: *st(c, 0) = a - *st(c, 0); break;
        case 6: *st(c, 0) = *st(c, 0) / a; break;
        case 7: *st(c, 0) = a / *st(c, 0); break;
        }
        return 1;
    }
    if (o == 0xD9) {
        if (isreg) {
            if ((in->modrm & 0xF8) == 0xC0) { double v = *st(c, i); x87_push(c, v); return 1; } /* fld st(i) */
            if ((in->modrm & 0xF8) == 0xC8) { double t = *st(c, 0); *st(c, 0) = *st(c, i); *st(c, i) = t; return 1; } /* fxch */
            if (in->modrm == 0xD0) return 1; /* fnop */
            switch (in->modrm) {
            case 0xE0: *st(c, 0) = -*st(c, 0); return 1;      /* fchs */
            case 0xE1: *st(c, 0) = fabs(*st(c, 0)); return 1; /* fabs */
            case 0xE4: x87_compare(c, *st(c, 0), 0.0); return 1; /* ftst */
            case 0xE5: { /* fxam: SDM class table C3 C2 C0 (+C1=sign):
                * unsupported 000, NaN 001, normal 010, inf 011,
                * zero 100, empty 101, denormal 110. glibc __printf_fp
                * classifies with fxam — a wrong class prints 0. */
                double v = *st(c, 0);
                int c0, c2, c3;
                if (isnan(v)) { c0 = 1; c2 = 0; c3 = 0; }
                else if (isinf(v)) { c0 = 1; c2 = 1; c3 = 0; }
                else if (v == 0.0) { c0 = (signbit(v) != 0); c2 = 0; c3 = 1; }
                else if (isnormal(v)) { c0 = (signbit(v) != 0); c2 = 1; c3 = 0; }
                else { c0 = (signbit(v) != 0); c2 = 1; c3 = 1; } /* denormal */
                set_cc(c, c0, c2, c3);
                uint16_t sw = c->x87_sw & ~X87_SW_C1;
                if (signbit(v)) sw |= X87_SW_C1;
                c->x87_sw = sw;
                return 1;
            }
            case 0xE8: x87_push(c, 1.0); return 1;
            case 0xE9: x87_push(c, 3.32192809488736234787); return 1; /* fldl2t */
            case 0xEA: x87_push(c, 1.44269504088896340736); return 1; /* fldl2e */
            case 0xEB: x87_push(c, 3.14159265358979323846); return 1; /* fldpi */
            case 0xEC: x87_push(c, 0.30102999566398119521); return 1; /* fldlg2 */
            case 0xED: x87_push(c, 0.69314718055994530942); return 1; /* fldln2 */
            case 0xEE: x87_push(c, 0.0); return 1;
            case 0xF0: *st(c, 0) = exp2(*st(c, 0)) - 1.0; return 1; /* f2xm1 */
            case 0xF1: *st(c, 1) = *st(c, 1) * log2(*st(c, 0)); x87_pop(c); return 1; /* fyl2x */
            case 0xF2: { double t = tan(*st(c, 0)); *st(c, 0) = t; x87_push(c, 1.0); return 1; } /* fptan */
            case 0xF3: { double r = atan2(*st(c, 1), *st(c, 0)); x87_pop(c); *st(c, 0) = r; return 1; } /* fpatan */
            case 0xF5: *st(c, 0) = remainder(*st(c, 0), *st(c, 1)); return 1; /* fprem1 (IEEE) */
            case 0xF6: c->x87_top = (c->x87_top - 1) & 7; return 1; /* fdecstp */
            case 0xF7: c->x87_top = (c->x87_top + 1) & 7; return 1; /* fincstp */
            case 0xF8: *st(c, 0) = fmod(*st(c, 0), *st(c, 1)); return 1; /* fprem */
            case 0xF9: *st(c, 1) = *st(c, 1) * log2(*st(c, 0) + 1.0); x87_pop(c); return 1; /* fyl2xp1 */
            case 0xFA: *st(c, 0) = sqrt(*st(c, 0)); return 1;
            case 0xFB: { double s = sin(*st(c, 0)), co = cos(*st(c, 0)); *st(c, 0) = s; x87_push(c, co); return 1; } /* fsincos */
            case 0xFC: *st(c, 0) = x87_round(c, *st(c, 0)); return 1; /* frndint */
            case 0xFD: *st(c, 0) = ldexp(*st(c, 0), (int)x87_round(c, *st(c, 1))); return 1; /* fscale */
            case 0xFE: *st(c, 0) = sin(*st(c, 0)); return 1;
            case 0xFF: *st(c, 0) = cos(*st(c, 0)); return 1;
            }
            return 0;
        }
        switch (reg) {
        case 0: a = ld_m32(c, in, &err); if (err) return -1; x87_push(c, a); return 1;
        case 2: if (st_m32(c, in, *st(c, 0))) return -1; return 1;
        case 3: if (st_m32(c, in, *st(c, 0))) return -1; x87_pop(c); return 1;
        case 5: { uint16_t cw; if (rd_mem(c, in, &cw, 2)) return -1; c->x87_cw = cw; return 1; } /* fldcw */
        case 7: if (wr_mem(c, in, &c->x87_cw, 2)) return -1; return 1; /* fnstcw */
        }
        return 0;
    }
    if (o == 0xDA || o == 0xDB) {
        if (isreg) {
            uint64_t f = c->rflags;
            int take = 0;
            if (o == 0xDA) {
                switch (reg) {
                case 0: take = (f & WF_CF) != 0; break;
                case 1: take = (f & WF_ZF) != 0; break;
                case 2: take = (f & (WF_CF | WF_ZF)) != 0; break;
                case 3: take = (f & WF_PF) != 0; break;
                }
                if (reg <= 3) { if (take) *st(c, 0) = *st(c, i); return 1; }
                if (o == 0xDA && in->modrm == 0xE9) { /* fucompp */
                    x87_compare(c, *st(c, 0), *st(c, 1)); x87_pop(c); x87_pop(c); return 1;
                }
            } else {
                switch (reg) {
                case 0: take = (f & WF_CF) == 0; break;
                case 1: take = (f & WF_ZF) == 0; break;
                case 2: take = (f & (WF_CF | WF_ZF)) == 0; break;
                case 3: take = (f & WF_PF) == 0; break;
                }
                if (reg <= 3) { if (take) *st(c, 0) = *st(c, i); return 1; }
                if (in->modrm == 0xE2) { c->x87_sw &= 0x7F00; return 1; } /* fclex */
                if (in->modrm == 0xE3) { c->x87_cw = 0x037F; c->x87_sw = 0; c->x87_top = 0; return 1; } /* fninit */
                if (reg == 5) { x87_comi_flags(c, *st(c, 0), *st(c, i)); return 1; } /* fucomi */
                if (reg == 6) { x87_comi_flags(c, *st(c, 0), *st(c, i)); return 1; } /* fcomi */
            }
            return 0;
        }
        if (o == 0xDA) { /* integer m32 arithmetic */
            a = ld_int(c, in, 4, &err); if (err) return -1;
            switch (reg) {
            case 0: *st(c, 0) += a; break;
            case 1: *st(c, 0) *= a; break;
            case 2: x87_compare(c, *st(c, 0), a); break;
            case 3: x87_compare(c, *st(c, 0), a); x87_pop(c); break;
            case 4: *st(c, 0) -= a; break;
            case 5: *st(c, 0) = a - *st(c, 0); break;
            case 6: *st(c, 0) /= a; break;
            case 7: *st(c, 0) = a / *st(c, 0); break;
            }
            return 1;
        }
        switch (reg) { /* DB memory */
        case 0: a = ld_int(c, in, 4, &err); if (err) return -1; x87_push(c, a); return 1; /* fild m32 */
        case 2: { uint32_t v = (uint32_t)x87_to_int(c, *st(c, 0), 4); if (wr_mem(c, in, &v, 4)) return -1; return 1; } /* fist */
        case 3: { uint32_t v = (uint32_t)x87_to_int(c, *st(c, 0), 4); if (wr_mem(c, in, &v, 4)) return -1; x87_pop(c); return 1; } /* fistp */
        case 5: a = ld_m80(c, in, &err); if (err) return -1; x87_push(c, a); return 1; /* fld m80 */
        case 7: if (st_m80(c, in, *st(c, 0))) return -1; x87_pop(c); return 1; /* fstp m80 */
        }
        return 0;
    }
    if (o == 0xDD) {
        if (isreg) {
            switch (reg) {
            case 0: return 1;                                   /* ffree */
            case 2: *st(c, i) = *st(c, 0); return 1;            /* fst */
            case 3: *st(c, i) = *st(c, 0); x87_pop(c); return 1; /* fstp */
            case 4: x87_compare(c, *st(c, 0), *st(c, i)); return 1; /* fucom */
            case 5: x87_compare(c, *st(c, 0), *st(c, i)); x87_pop(c); return 1; /* fucomp */
            }
            return 0;
        }
        switch (reg) {
        case 0: a = ld_m64(c, in, &err); if (err) return -1; x87_push(c, a); return 1;
        case 2: if (st_m64(c, in, *st(c, 0))) return -1; return 1;
        case 3: if (st_m64(c, in, *st(c, 0))) return -1; x87_pop(c); return 1;
        case 7: if (wr_mem(c, in, &c->x87_sw, 2)) return -1; return 1; /* fnstsw m16 */
        }
        return 0;
    }
    if (o == 0xDE) {
        if (isreg) {
            if (in->modrm == 0xD9) { x87_compare(c, *st(c, 0), *st(c, 1)); x87_pop(c); x87_pop(c); return 1; } /* fcompp */
            double x = *st(c, i), y = *st(c, 0);
            switch (reg) {
            case 0: *st(c, i) = x + y; break;
            case 1: *st(c, i) = x * y; break;
            case 4: *st(c, i) = y - x; break; /* fsubrp */
            case 5: *st(c, i) = x - y; break; /* fsubp */
            case 6: *st(c, i) = y / x; break; /* fdivrp */
            case 7: *st(c, i) = x / y; break; /* fdivp */
            default: return 0;
            }
            x87_pop(c);
            return 1;
        }
        a = ld_int(c, in, 2, &err); if (err) return -1; /* integer m16 */
        switch (reg) {
        case 0: *st(c, 0) += a; break;
        case 1: *st(c, 0) *= a; break;
        case 2: x87_compare(c, *st(c, 0), a); break;
        case 3: x87_compare(c, *st(c, 0), a); x87_pop(c); break;
        case 4: *st(c, 0) -= a; break;
        case 5: *st(c, 0) = a - *st(c, 0); break;
        case 6: *st(c, 0) /= a; break;
        case 7: *st(c, 0) = a / *st(c, 0); break;
        }
        return 1;
    }
    if (o == 0xDF) {
        if (isreg) {
            if (in->modrm == 0xE0) { /* fnstsw ax */
                c->r[0] = (c->r[0] & ~0xFFFFull) | c->x87_sw;
                return 1;
            }
            if (reg == 5) { x87_comi_flags(c, *st(c, 0), *st(c, i)); x87_pop(c); return 1; } /* fucomip */
            if (reg == 6) { x87_comi_flags(c, *st(c, 0), *st(c, i)); x87_pop(c); return 1; } /* fcomip */
            return 0;
        }
        switch (reg) {
        case 0: a = ld_int(c, in, 2, &err); if (err) return -1; x87_push(c, a); return 1; /* fild m16 */
        case 2: { uint16_t v = (uint16_t)x87_to_int(c, *st(c, 0), 2); if (wr_mem(c, in, &v, 2)) return -1; return 1; } /* fist m16 */
        case 3: { uint16_t v = (uint16_t)x87_to_int(c, *st(c, 0), 2); if (wr_mem(c, in, &v, 2)) return -1; x87_pop(c); return 1; } /* fistp m16 */
        case 5: a = ld_int(c, in, 8, &err); if (err) return -1; x87_push(c, a); return 1; /* fild m64 */
        case 7: { uint64_t v = x87_to_int(c, *st(c, 0), 8); if (wr_mem(c, in, &v, 8)) return -1; x87_pop(c); return 1; } /* fistp m64 */
        }
        return 0;
    }
    return 0;
}
