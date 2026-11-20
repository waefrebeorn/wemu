/* wemu_exec.c — integer instruction execution. One concern: decoded
 * integer ops -> architectural state. SSE/AVX live in wemu_sse.c. */
#include "wemu_internal.h"

#define REX_R(in) (((in)->rex >> 2) & 1)
#define REX_X(in) (((in)->rex >> 1) & 1)
#define REX_B(in) ((in)->rex & 1)
#define REG(in)   (((in)->modrm >> 3) & 7)

static uint64_t read_reg(WemuCpu *c, int i, int bytes) {
    uint64_t v = c->r[i & 15];
    return wemu_mask(v, bytes);
}

/* 8-bit register read: AH/CH/DH/BH only without any REX prefix */
static uint64_t read_reg8(WemuCpu *c, int i, int has_rex) {
    if (!has_rex && i >= 4 && i <= 7)
        return (c->r[i - 4] >> 8) & 0xff;
    return c->r[i & 15] & 0xff;
}

static void write_reg(WemuCpu *c, int i, int bytes, uint64_t v) {
    if (bytes == 4) { c->r[i & 15] = v & 0xffffffffull; return; } /* zero-ext */
    if (bytes == 8) { c->r[i & 15] = v; return; }
    if (bytes == 2) {
        c->r[i & 15] = (c->r[i & 15] & ~0xffffull) | (v & 0xffff);
        return;
    }
    c->r[i & 15] = (c->r[i & 15] & ~0xffull) | (v & 0xff);
}

static void write_reg8(WemuCpu *c, int i, int has_rex, uint64_t v) {
    if (!has_rex && i >= 4 && i <= 7) {
        c->r[i - 4] = (c->r[i - 4] & ~0xff00ull) | ((v & 0xff) << 8);
        return;
    }
    write_reg(c, i, 1, v);
}

/* effective address for mod!=3 — shared owner in wemu_mem.c */
static uint64_t eff_addr(WemuCpu *c, const WemuInsn *in) {
    return wemu_eff_addr(c, in);
}

static uint64_t read_rm(WemuCpu *c, const WemuInsn *in, int bytes) {
    if ((in->modrm >> 6) == 3) {
        int rm = (in->modrm & 7) | (REX_B(in) << 3);
        return bytes == 1 ? read_reg8(c, rm, in->rex)
                          : read_reg(c, rm, bytes);
    }
    uint64_t v = 0;
    wemu_mem_read(c, eff_addr(c, in), &v, (size_t)bytes);
    return v;
}

static void write_rm(WemuCpu *c, const WemuInsn *in, int bytes, uint64_t v) {
    if ((in->modrm >> 6) == 3) {
        int rm = (in->modrm & 7) | (REX_B(in) << 3);
        if (bytes == 1) write_reg8(c, rm, in->rex, v);
        else write_reg(c, rm, bytes, v);
        return;
    }
    uint64_t m = wemu_mask(v, bytes);
    wemu_mem_write(c, eff_addr(c, in), &m, (size_t)bytes);
}

static uint64_t read_regop(WemuCpu *c, const WemuInsn *in, int bytes) {
    int r = REG(in) | (REX_R(in) << 3);
    return bytes == 1 ? read_reg8(c, r, in->rex) : read_reg(c, r, bytes);
}

static void write_regop(WemuCpu *c, const WemuInsn *in, int bytes, uint64_t v) {
    int r = REG(in) | (REX_R(in) << 3);
    if (bytes == 1) write_reg8(c, r, in->rex, v);
    else write_reg(c, r, bytes, v);
}

/* ---- LOCK-prefix atomic RMW support --------------------------------
 * Intel SDM: LOCK is legal ONLY on the listed read-modify-write forms
 * with a MEMORY destination; every other use is #UD.  The same predicate
 * tells us which instructions are interruptible RMWs in our step model. */
static int rmw_classify(const WemuInsn *in, int *implicit_lock) {
    *implicit_lock = 0;
    if ((in->modrm >> 6) == 3) return 0;      /* register destination */
    uint32_t full = in->op | ((uint32_t)(in->vex[0] >> 4) << 8);
    int reg = REG(in);
    if (full < 0x100) {
        uint8_t o = in->op;
        if (o <= 0x3D && (o & 7) <= 5 && (o & 0xC0) == 0) {
            int form = o & 7, grp = (o >> 3) & 7;
            if ((form == 0 || form == 1) && grp != 7) return 1; /* not CMP */
        }
        if (o >= 0x80 && o <= 0x83) return reg != 7;  /* grp1, not CMP */
        if (o == 0x86 || o == 0x87) {                 /* XCHG: implicit lock */
            *implicit_lock = 1; return 1;
        }
        if ((o == 0xF6 || o == 0xF7) && (reg == 2 || reg == 3)) return 1;
        if (o == 0xFE && (reg == 0 || reg == 1)) return 1; /* inc/dec */
        if (o == 0xFF && (reg == 0 || reg == 1)) return 1; /* inc/dec */
        return 0;
    }
    if (full == 0x1B0 || full == 0x1B1) return 1;     /* cmpxchg */
    if (full == 0x1C0 || full == 0x1C1) return 1;     /* xadd */
    if (full == 0x1C7) { *implicit_lock = 1; return reg == 1; } /* cmpxchg8b/16b */
    if (full == 0x1BA) return reg == 5 || reg == 6 || reg == 7; /* bts/btr/btc */
    if (full == 0x1AB || full == 0x1B3 || full == 0x1BB) return 1;
    return 0;
}

/* Interleaving point for a tracked memory RMW.  A competing hardware
 * agent (the observer hook) may interleave between our read and write
 * ONLY when the RMW is not bus-locked: its write is then clobbered by our
 * stale writeback = lost update.  Under LOCK the agent is serialized
 * after our indivisible writeback = both updates survive. */
static void rmw_interleave(WemuCpu *c, const WemuInsn *in, int locked,
                           int bytes, int after_write) {
    if (!c->atomic_observer || (in->modrm >> 6) == 3) return;
    if (locked != after_write) return;
    c->atomic_observer(c, eff_addr(c, in), bytes,
                       locked ? WEMU_ATOMIC_POST_WRITE : WEMU_ATOMIC_PRE_WRITE,
                       c->atomic_observer_ud);
}
static uint64_t rmw_read(WemuCpu *c, const WemuInsn *in, int bytes, int locked) {
    uint64_t v = read_rm(c, in, bytes);
    rmw_interleave(c, in, locked, bytes, 0);
    return v;
}
static void rmw_write(WemuCpu *c, const WemuInsn *in, int bytes, int locked,
                      uint64_t v) {
    write_rm(c, in, bytes, v);
    rmw_interleave(c, in, locked, bytes, 1);
}

/* ---- CMPXCHG8B / CMPXCHG16B (0F C7 /1) -------------------------------
 * SDM: 0F C7 /1 compares EDX:EAX with an m64; REX.W 0F C7 /1 compares
 * RDX:RAX with an m128 (CMPXCHG16B). Equal -> memory <- ECX:EBX
 * (RCX:RBX) and ZF=1; unequal -> accumulator <- memory and ZF=0.
 * ZF is the ONLY defined flag here, so the others are preserved. Both
 * forms use an implicitly locked bus cycle (no LOCK prefix required),
 * so the competing-agent observer fires POST only. */
static int exec_cmpxchg8b_16b(WemuCpu *c, const WemuInsn *in) {
    if ((in->modrm >> 6) == 3 || REG(in) != 1) { c->fault = 6; return -1; }
    int wide = (in->rex & 8) != 0;
    int bytes = wide ? 16 : 8;
    uint64_t addr = eff_addr(c, in);
    uint8_t mem[16] = {0}, out[16] = {0};
    if (wemu_mem_read(c, addr, mem, (size_t)bytes) != 0) {
        c->fault = 14; return -1;
    }
    uint64_t mlo, mhi;
    if (wide) {
        memcpy(&mlo, mem, 8);
        memcpy(&mhi, mem + 8, 8);
    } else {
        /* m64: EAX compares bytes 0..3, EDX compares bytes 4..7. */
        uint32_t l32, h32;
        memcpy(&l32, mem, 4); memcpy(&h32, mem + 4, 4);
        mlo = l32; mhi = h32;
    }
    uint64_t expected_lo = c->r[0], expected_hi = c->r[2];
    if (!wide) {
        expected_lo = (uint32_t)expected_lo; expected_hi = (uint32_t)expected_hi;
    }
    uint64_t flags = c->rflags & ~WF_ZF;
    if (expected_lo == mlo && expected_hi == mhi) {
        uint64_t b = c->r[3], cc = c->r[1];
        if (wide) {
            memcpy(out, &b, 8); memcpy(out + 8, &cc, 8);
        } else {
            uint32_t b32 = (uint32_t)b, c32 = (uint32_t)cc;
            memcpy(out, &b32, 4); memcpy(out + 4, &c32, 4);
        }
        if (wemu_mem_write(c, addr, out, (size_t)bytes) != 0) {
            c->fault = 14; return -1;
        }
        flags |= WF_ZF;
    } else {
        c->r[0] = mlo;   /* 32-bit value written to RAX zero-extends */
        c->r[2] = mhi;
    }
    c->rflags = flags;
    if (c->atomic_observer)
        c->atomic_observer(c, addr, bytes, WEMU_ATOMIC_POST_WRITE,
                           c->atomic_observer_ud);
    return 0;
}

static int cc_true(WemuCpu *c, int cc) {
    uint64_t f = c->rflags;
    switch (cc >> 1) {
    case 0: return (f & WF_OF) != 0;
    case 1: return (f & WF_CF) != 0;
    case 2: return (f & WF_ZF) != 0;
    case 3: return (f & (WF_CF | WF_ZF)) != 0;
    case 4: return (f & WF_SF) != 0;
    case 5: return (f & WF_PF) != 0;
    case 6: return ((f & WF_SF) != 0) != ((f & WF_OF) != 0);
    case 7: return (f & WF_ZF) ||
                   (((f & WF_SF) != 0) != ((f & WF_OF) != 0));
    }
    return 0;
}

static void do_add(WemuCpu *c, uint64_t a, uint64_t b, int bytes, int cin,
                   uint64_t *out) {
    uint64_t r = wemu_mask(a + b + (uint64_t)cin, bytes);
    wemu_set_add_flags(c, a, b, r, bytes, cin, 0);
    *out = r;
}

static void do_sub(WemuCpu *c, uint64_t a, uint64_t b, int bytes, int cin,
                   uint64_t *out) {
    uint64_t r = wemu_mask(a - b - (uint64_t)cin, bytes);
    wemu_set_add_flags(c, a, b, r, bytes, cin, 1);
    *out = r;
}

/* grp1 op by reg field: 0 add 1 or 2 adc 3 sbb 4 and 5 sub 6 xor 7 cmp */
static void grp1(WemuCpu *c, int op, uint64_t a, uint64_t b, int bytes,
                 uint64_t *out, int *writeback) {
    uint64_t r = 0;
    int cin = (c->rflags & WF_CF) ? 1 : 0;
    *writeback = 1;
    switch (op) {
    case 0: do_add(c, a, b, bytes, 0, &r); break;
    case 1: r = wemu_mask(a | b, bytes); wemu_set_logic_flags(c, r, bytes); break;
    case 2: do_add(c, a, b, bytes, cin, &r); break;
    case 3: do_sub(c, a, b, bytes, cin, &r); break;
    case 4: r = wemu_mask(a & b, bytes); wemu_set_logic_flags(c, r, bytes); break;
    case 5: do_sub(c, a, b, bytes, 0, &r); break;
    case 6: r = wemu_mask(a ^ b, bytes); wemu_set_logic_flags(c, r, bytes); break;
    case 7: do_sub(c, a, b, bytes, 0, &r); *writeback = 0; break;
    }
    *out = r;
}

static void do_shift(WemuCpu *c, int op, uint64_t val, uint64_t cnt,
                     int bytes, uint64_t *out) {
    int bits = bytes * 8;
    cnt &= (bits == 64) ? 63 : 31;
    uint64_t r = val;
    uint64_t f = c->rflags & ~(WF_CF | WF_OF | WF_ZF | WF_SF | WF_PF);
    if (cnt) {
        uint64_t cf = 0, of = 0;
        switch (op) {
        case 0: case 1: /* rol/ror: CF only, flags otherwise untouched */
            cnt %= (uint64_t)bits;
            if (cnt) {
                r = op == 0 ? (val << cnt) | (val >> (bits - cnt))
                            : (val >> cnt) | (val << (bits - cnt));
                r = wemu_mask(r, bytes);
                cf = op == 0 ? (r & 1) : (r >> (bits - 1));
                if (cf) f |= WF_CF;
                if (cnt == 1) {
                    of = op == 0 ? ((r >> (bits - 1)) ^ cf)
                                 : ((r >> (bits - 1)) ^ ((r >> (bits - 2)) & 1));
                    if (of) f |= WF_OF;
                }
            }
            c->rflags = f; *out = r; return;
        case 4: case 6: /* shl/sal */
            cf = (val >> (bits - cnt)) & 1;
            r = wemu_mask(val << cnt, bytes);
            if (cnt == 1) of = (r >> (bits - 1)) ^ cf;
            break;
        case 5: /* shr */
            cf = (val >> (cnt - 1)) & 1;
            r = val >> cnt;
            if (cnt == 1) of = val >> (bits - 1);
            break;
        case 7: /* sar */
            cf = (val >> (cnt - 1)) & 1;
            r = (uint64_t)((int64_t)(val << (64 - bits)) >> (64 - bits) >> cnt);
            r = wemu_mask(r, bytes);
            of = 0;
            break;
        }
        if (cf) f |= WF_CF;
        if (of) f |= WF_OF;
        if (!r) f |= WF_ZF;
        if (r >> (bits - 1)) f |= WF_SF;
        if (wemu_parity(r)) f |= WF_PF;
    }
    c->rflags = f;
    *out = r;
}

static void push64(WemuCpu *c, uint64_t v) {
    c->r[4] -= 8;
    wemu_mem_write(c, c->r[4], &v, 8);
}

static uint64_t pop64(WemuCpu *c) {
    uint64_t v = 0;
    wemu_mem_read(c, c->r[4], &v, 8);
    c->r[4] += 8;
    return v;
}

int wemu_exec(WemuCpu *c, const WemuInsn *in) {
    uint32_t full = in->op | ((uint32_t)(in->vex[0] >> 4) << 8);
    int os = in->opsize;
    uint8_t o = in->op;
    uint64_t r = 0, a, b;
    int wb;

    /* LOCK prefix validation: legal only on a tracked memory RMW.
     * LOCK on a register destination, on CMP, on a non-RMW opcode, or
     * on a VEX instruction (rejected in decode) is #UD. */
    int implicit_lk = 0;
    int is_rmw = rmw_classify(in, &implicit_lk);
    int eff_locked = implicit_lk || in->lock;
    if (in->lock && !is_rmw) { c->fault = 6; return -1; }

    /* SSE/AVX maps and legacy SSE opcodes go to the vector leaf;
     * unhandled two-byte ops fall through to the integer switch below
     * (cmovcc/setcc/movzx/imul/bswap live there). VEX must be handled. */
    if (in->vex_len || full >= 0x100) {
        int h = wemu_exec_sse(c, in);
        if (h == 1) { c->rip += in->len; return 0; }
        if (h < 0) return -1;
        if (in->vex_len) goto ud;
    }

    /* CMPXCHG8B/16B and the no-op hints: before this change every one of
     * these opcodes reached the honest #UD tail at the bottom of exec. */
    if (full == 0x1C7) {
        if (exec_cmpxchg8b_16b(c, in) != 0) return -1;
        c->rip += in->len;
        return 0;
    }
    if (full == 0x1AE && (in->modrm >> 6) == 3) {
        int freg = REG(in);
        if (freg == 5) c->hint_count[WEMU_HINT_LFENCE]++;
        else if (freg == 6) c->hint_count[WEMU_HINT_MFENCE]++;
        else if (freg == 7) c->hint_count[WEMU_HINT_SFENCE]++;
        else goto ud; /* other 0F AE /digits are not implemented */
        c->rip += in->len;
        return 0;
    }
    if (!in->vex_len && o == 0x90 && in->rep == 0xF3 && !REX_B(in)) {
        c->hint_count[WEMU_HINT_PAUSE]++; /* F3 90 PAUSE: no-op hint */
        c->rip += in->len;
        return 0;
    }

    /* string family (movs/stos/scas/cmps/lods + cld/std): real compiled
     * memset/memcpy live here — delegate to the one owner */
    {
        int sh = wemu_exec_string(c, in);
        if (sh == 1) { c->rip += in->len; return 0; }
        if (sh < 0) return -1;
    }

    /* x87 FPU: PRIMARY-map escapes D8-DF (no 0F prefix) — one leaf */
    if (!in->vex_len && o >= 0xD8 && o <= 0xDF) {
        int xr = wemu_x87_exec(c, in);
        if (xr == 1) { c->rip += in->len; return 0; }
        if (xr < 0) { c->fault = 14; return -1; }
        goto ud;
    }

    if (full < 0x100 && o <= 0x3D && (o & 7) <= 5 && (o & 0xC0) == 0) {
        int op = (o >> 3) & 7;
        int form = o & 7;
        if (form == 4) { a = read_reg(c, 0, 1); b = in->imm & 0xff;
            grp1(c, op, a, b, 1, &r, &wb);
            if (wb) write_reg(c, 0, 1, r);
        } else if (form == 5) { a = read_reg(c, 0, os);
            b = os == 2 ? (uint16_t)in->imm : (int32_t)in->imm;
            grp1(c, op, a, b, os, &r, &wb);
            if (wb) write_reg(c, 0, os, r);
        } else if (form <= 1) { int bytes = form == 0 ? 1 : os;
            a = is_rmw ? rmw_read(c, in, bytes, eff_locked)
                       : read_rm(c, in, bytes);
            b = read_regop(c, in, bytes);
            grp1(c, op, a, b, bytes, &r, &wb);
            if (wb) { if (is_rmw) rmw_write(c, in, bytes, eff_locked, r);
                      else write_rm(c, in, bytes, r); }
        } else { int bytes = form == 2 ? 1 : os;
            a = read_regop(c, in, bytes); b = read_rm(c, in, bytes);
            grp1(c, op, a, b, bytes, &r, &wb);
            if (wb) write_regop(c, in, bytes, r);
        }
        c->rip += in->len;
        return 0;
    }

    switch (full) {
    case 0x50: case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57:
        push64(c, c->r[(o - 0x50) | (REX_B(in) << 3)]);
        break;
    case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        write_reg(c, (o - 0x58) | (REX_B(in) << 3), 8, pop64(c));
        break;
    case 0x63: { /* movsxd */
        int32_t v = (int32_t)read_rm(c, in, 4);
        write_regop(c, in, os, (uint64_t)(int64_t)v);
        break;
    }
    case 0x68: push64(c, (uint64_t)(int64_t)(int32_t)in->imm); break;
    case 0x6A: push64(c, (uint64_t)(int64_t)(int8_t)in->imm); break;
    case 0x69: case 0x6B: {
        int64_t sv = full == 0x69 ? (int64_t)(int32_t)in->imm
                                  : (int64_t)(int8_t)in->imm;
        int64_t av = (int64_t)read_rm(c, in, os);
        uint64_t res = wemu_mask((uint64_t)(av * sv), os);
        int64_t full_res = av * sv;
        uint64_t f = c->rflags & ~(WF_CF | WF_OF);
        if (full_res != (int64_t)(res << (64 - os * 8)) >> (64 - os * 8))
            f |= WF_CF | WF_OF;
        c->rflags = f;
        write_regop(c, in, os, res);
        break;
    }
    case 0x80: case 0x81: case 0x83: {
        int bytes = full == 0x80 ? 1 : os;
        a = is_rmw ? rmw_read(c, in, bytes, eff_locked) : read_rm(c, in, bytes);
        b = full == 0x83 ? (uint64_t)(int64_t)(int8_t)in->imm
            : bytes == 2 ? (uint64_t)(uint16_t)in->imm
            : bytes == 1 ? in->imm & 0xff : (uint64_t)(int64_t)(int32_t)in->imm;
        grp1(c, REG(in), a, b, bytes, &r, &wb);
        if (wb) { if (is_rmw) rmw_write(c, in, bytes, eff_locked, r);
                  else write_rm(c, in, bytes, r); }
        break;
    }
    case 0x84: case 0x85: {
        int bytes = full == 0x84 ? 1 : os;
        r = wemu_mask(read_rm(c, in, bytes) & read_regop(c, in, bytes), bytes);
        wemu_set_logic_flags(c, r, bytes);
        break;
    }
    case 0x86: case 0x87: {
        int bytes = full == 0x86 ? 1 : os;
        /* memory XCHG is implicitly atomic even without the LOCK prefix */
        a = is_rmw ? rmw_read(c, in, bytes, eff_locked) : read_rm(c, in, bytes);
        b = read_regop(c, in, bytes);
        if (is_rmw) rmw_write(c, in, bytes, eff_locked, b);
        else write_rm(c, in, bytes, b);
        write_regop(c, in, bytes, a);
        break;
    }
    case 0x88: write_rm(c, in, 1, read_regop(c, in, 1)); break;
    case 0x89: write_rm(c, in, os, read_regop(c, in, os)); break;
    case 0x8A: write_regop(c, in, 1, read_rm(c, in, 1)); break;
    case 0x8B: write_regop(c, in, os, read_rm(c, in, os)); break;
    case 0x8D: { /* lea: address arithmetic, NO segment base applied */
        WemuInsn noseg = *in;
        noseg.seg = 0;
        write_regop(c, in, os, eff_addr(c, &noseg));
        break;
    }
    case 0x90: case 0x91: case 0x92: case 0x93:
    case 0x94: case 0x95: case 0x96: case 0x97: {
        int rr = (o - 0x90) | (REX_B(in) << 3);
        if (o == 0x90 && !REX_B(in)) break; /* plain nop (incl. pause) */
        /* xchg rAX, r: 32-bit form zero-extends both operands */
        a = read_reg(c, 0, os);
        b = read_reg(c, rr, os);
        write_reg(c, 0, os, b);
        write_reg(c, rr, os, a);
        break;
    }
    case 0x98: /* cwde/cdqe */
        if (os == 8) c->r[0] = (uint64_t)(int64_t)(int32_t)c->r[0];
        else if (os == 4) c->r[0] = (uint32_t)(int32_t)(int16_t)c->r[0];
        else c->r[0] = (c->r[0] & ~0xffffull) | (uint16_t)(int16_t)(int8_t)c->r[0];
        break;
    case 0x99: /* cdq/cqo */
        if (os == 8) c->r[2] = (int64_t)c->r[0] < 0 ? ~0ull : 0;
        else if (os == 4) c->r[2] = (int32_t)c->r[0] < 0 ? 0xffffffffull : 0;
        else c->r[2] = (c->r[2] & ~0xffffull) | ((int16_t)c->r[0] < 0 ? 0xffff : 0);
        break;
    case 0xA0: { uint8_t v = 0; wemu_mem_read(c, in->imm, &v, 1);
        write_reg(c, 0, 1, v); break; }
    case 0xA1: { uint64_t v = 0; wemu_mem_read(c, in->imm, &v, (size_t)os);
        write_reg(c, 0, os, v); break; }
    case 0xA2: { uint8_t v = (uint8_t)c->r[0];
        wemu_mem_write(c, in->imm, &v, 1); break; }
    case 0xA3: { uint64_t v = wemu_mask(c->r[0], os);
        wemu_mem_write(c, in->imm, &v, (size_t)os); break; }
    case 0xA8:
        r = (c->r[0] & 0xff) & (in->imm & 0xff);
        wemu_set_logic_flags(c, r, 1);
        break;
    case 0xA9:
        r = wemu_mask(read_reg(c, 0, os) & (os == 2 ? (uint64_t)(uint16_t)in->imm : (uint64_t)(int64_t)(int32_t)in->imm), os);
        wemu_set_logic_flags(c, r, os);
        break;
    case 0xC0: case 0xC1: case 0xD0: case 0xD1: case 0xD2: case 0xD3: {
        int bytes = (full == 0xC0 || full == 0xD0 || full == 0xD2) ? 1 : os;
        uint64_t cnt = (full == 0xC0 || full == 0xC1) ? in->imm & 63
                     : (full == 0xD0 || full == 0xD1) ? 1ull : c->r[1] & 63;
        a = read_rm(c, in, bytes);
        do_shift(c, REG(in), a, cnt, bytes, &r);
        write_rm(c, in, bytes, r);
        break;
    }
    case 0xC2: c->rip = pop64(c); c->r[4] += in->imm & 0xffff;
        return 0;
    case 0xC3: c->rip = pop64(c); return 0;
    case 0xC6: write_rm(c, in, 1, in->imm & 0xff); break;
    case 0xC7: write_rm(c, in, os, os == 2 ? (uint64_t)(uint16_t)in->imm : (uint64_t)(int64_t)(int32_t)in->imm); break;
    case 0xC9: /* leave */
        c->r[4] = c->r[5];
        c->r[5] = pop64(c);
        break;
    case 0xCC: c->fault = 3; return -1; /* int3 */
    case 0xE8: push64(c, c->rip + in->len);
        c->rip += in->len + (uint64_t)(int64_t)(int32_t)in->imm;
        return 0;
    case 0xE9:
        c->rip += in->len + (uint64_t)(int64_t)(int32_t)in->imm;
        return 0;
    case 0xEB:
        c->rip += in->len + (uint64_t)(int64_t)(int8_t)in->imm;
        return 0;
    case 0xF4: c->halted = 1; break;
    case 0xF5: c->rflags ^= WF_CF; break;            /* cmc */
    case 0xF8: c->rflags &= ~WF_CF; break;           /* clc */
    case 0xF9: c->rflags |= WF_CF; break;            /* stc */
    case 0xFA: c->rflags &= ~0x200ull; break;        /* cli */
    case 0xFB: c->rflags |= 0x200ull; break;         /* sti */
    case 0xE6: wemu_port_out(c, (uint16_t)(in->imm & 0xff), (uint32_t)c->r[0], 1); break;
    case 0xE7: wemu_port_out(c, (uint16_t)(in->imm & 0xff), (uint32_t)c->r[0], os); break;
    case 0xEE: wemu_port_out(c, (uint16_t)c->r[2], (uint32_t)c->r[0], 1); break;
    case 0xEF: wemu_port_out(c, (uint16_t)c->r[2], (uint32_t)c->r[0], os); break;
    case 0xE4: write_reg(c, 0, 1, wemu_port_in(c, (uint16_t)(in->imm & 0xff), 1)); break;
    case 0xE5: write_reg(c, 0, os, wemu_port_in(c, (uint16_t)(in->imm & 0xff), os)); break;
    case 0xEC: write_reg(c, 0, 1, wemu_port_in(c, (uint16_t)c->r[2], 1)); break;
    case 0xED: write_reg(c, 0, os, wemu_port_in(c, (uint16_t)c->r[2], os)); break;
    case 0xF6: case 0xF7: {
        int bytes = full == 0xF6 ? 1 : os;
        int op = REG(in);
        a = is_rmw ? rmw_read(c, in, bytes, eff_locked) : read_rm(c, in, bytes);
        if (op <= 1) { /* test */
            b = bytes == 1 ? in->imm & 0xff
                : bytes == 2 ? (uint64_t)(uint16_t)in->imm
                : (uint64_t)(int64_t)(int32_t)in->imm;
            r = wemu_mask(a & b, bytes);
            wemu_set_logic_flags(c, r, bytes);
        } else if (op == 2) { /* not */
            uint64_t v = wemu_mask(~a, bytes);
            if (is_rmw) rmw_write(c, in, bytes, eff_locked, v);
            else write_rm(c, in, bytes, v);
        } else if (op == 3) { /* neg */
            r = wemu_mask(0 - a, bytes);
            wemu_set_add_flags(c, 0, a, r, bytes, 0, 1);
            if (is_rmw) rmw_write(c, in, bytes, eff_locked, r);
            else write_rm(c, in, bytes, r);
        } else if (op == 4) { /* mul */
            uint64_t hi, lo;
            if (bytes == 8) {
                __uint128_t p = (__uint128_t)c->r[0] * a;
                lo = (uint64_t)p; hi = (uint64_t)(p >> 64);
            } else {
                uint64_t p = wemu_mask(c->r[0], bytes) * a;
                lo = wemu_mask(p, bytes); hi = p >> (bytes * 8);
            }
            write_reg(c, 0, bytes, lo); write_reg(c, 2, bytes, hi);
            uint64_t f = c->rflags & ~(WF_CF | WF_OF);
            if (hi) f |= WF_CF | WF_OF;
            c->rflags = f;
        } else if (op == 5) { /* imul */
            if (bytes == 8) {
                __int128 p = (__int128)(int64_t)c->r[0] * (int64_t)a;
                write_reg(c, 0, 8, (uint64_t)p);
                write_reg(c, 2, 8, (uint64_t)(p >> 64));
                uint64_t f = c->rflags & ~(WF_CF | WF_OF);
                if (p != (__int128)(int64_t)(uint64_t)p) f |= WF_CF | WF_OF;
                c->rflags = f;
            } else {
                int64_t p = (int64_t)(wemu_mask(c->r[0], bytes) << (64 - bytes * 8)) >> (64 - bytes * 8);
                int64_t av = (int64_t)(a << (64 - bytes * 8)) >> (64 - bytes * 8);
                int64_t pr = p * av;
                write_reg(c, 0, bytes, wemu_mask((uint64_t)pr, bytes));
                write_reg(c, 2, bytes, wemu_mask((uint64_t)(pr >> (bytes * 8)), bytes));
                uint64_t f = c->rflags & ~(WF_CF | WF_OF);
                int64_t trunc = (int64_t)(wemu_mask((uint64_t)pr, bytes) << (64 - bytes * 8)) >> (64 - bytes * 8);
                if (pr != trunc) f |= WF_CF | WF_OF;
                c->rflags = f;
            }
        } else if (op == 6) { /* div */
            if (!a) { c->fault = 0; return -1; }
            if (bytes == 8) {
                __uint128_t n = ((__uint128_t)c->r[2] << 64) | c->r[0];
                uint64_t q = (uint64_t)(n / a), rem = (uint64_t)(n % a);
                if (n / a > 0xffffffffffffffffull) { c->fault = 0; return -1; }
                write_reg(c, 0, 8, q); write_reg(c, 2, 8, rem);
            } else {
                uint64_t n = (wemu_mask(c->r[2], bytes) << (bytes * 8)) |
                             wemu_mask(c->r[0], bytes);
                uint64_t q = n / a;
                if (q >> (bytes * 8)) { c->fault = 0; return -1; }
                write_reg(c, 0, bytes, q); write_reg(c, 2, bytes, n % a);
            }
        } else { /* idiv */
            if (!a) { c->fault = 0; return -1; }
            if (bytes == 8) {
                __int128 n = ((__int128)(int64_t)c->r[2] << 64) |
                             (uint64_t)c->r[0];
                int64_t q = (int64_t)(n / (int64_t)a);
                write_reg(c, 0, 8, (uint64_t)q);
                write_reg(c, 2, 8, (uint64_t)(n % (int64_t)a));
            } else {
                int bits = bytes * 8;
                int64_t n = (int64_t)((wemu_mask(c->r[2], bytes) << bits) |
                                      wemu_mask(c->r[0], bytes));
                n = (n << (64 - bits * 2)) >> (64 - bits * 2);
                int64_t av = (int64_t)(a << (64 - bits)) >> (64 - bits);
                int64_t q = n / av;
                if (q != (int64_t)(wemu_mask((uint64_t)q, bytes) << (64 - bits)) >> (64 - bits)) {
                    c->fault = 0; return -1;
                }
                write_reg(c, 0, bytes, wemu_mask((uint64_t)q, bytes));
                write_reg(c, 2, bytes, wemu_mask((uint64_t)(n % av), bytes));
            }
        }
        break;
    }
    case 0xFE: {
        a = is_rmw ? rmw_read(c, in, 1, eff_locked) : read_rm(c, in, 1);
        r = wemu_mask(a + (REG(in) == 0 ? 1 : -1), 1);
        uint64_t cf = c->rflags & WF_CF;
        wemu_set_add_flags(c, a, 1, r, 1, 0, REG(in) != 0);
        c->rflags = (c->rflags & ~WF_CF) | cf;
        if (is_rmw) rmw_write(c, in, 1, eff_locked, r);
        else write_rm(c, in, 1, r);
        break;
    }
    case 0xFF: {
        int op = REG(in);
        if (op == 0 || op == 1) { /* inc/dec rm */
            a = is_rmw ? rmw_read(c, in, os, eff_locked) : read_rm(c, in, os);
            r = wemu_mask(a + (op == 0 ? 1 : -1), os);
            uint64_t cf = c->rflags & WF_CF;
            wemu_set_add_flags(c, a, 1, r, os, 0, op != 0);
            c->rflags = (c->rflags & ~WF_CF) | cf;
            if (is_rmw) rmw_write(c, in, os, eff_locked, r);
            else write_rm(c, in, os, r);
        } else if (op == 2) { /* call rm */
            a = read_rm(c, in, 8);
            push64(c, c->rip + in->len);
            c->rip = a;
            return 0;
        } else if (op == 4) { /* jmp rm */
            c->rip = read_rm(c, in, 8);
            return 0;
        } else if (op == 6) { /* push rm */
            push64(c, read_rm(c, in, 8));
        } else goto ud;
        break;
    }
    default:
        if (full < 0x100 && o >= 0xB0 && o <= 0xB7) {
            write_reg8(c, (o - 0xB0) | (REX_B(in) << 3), in->rex, in->imm & 0xff);
        } else if (full < 0x100 && o >= 0xB8 && o <= 0xBF) {
            write_reg(c, (o - 0xB8) | (REX_B(in) << 3), os, in->imm);
        } else if (full < 0x100 && o >= 0x70 && o <= 0x7F) {
            int cc = o - 0x70;
            int taken = cc_true(c, cc);
            if (cc & 1) taken = !taken;
            if (taken) c->rip += (uint64_t)(int64_t)(int8_t)in->imm;
            c->rip += in->len;
            return 0;
        } else if (full >= 0x180 && full <= 0x18F) {
            int cc = full - 0x180;
            int taken = cc_true(c, cc);
            if (cc & 1) taken = !taken;
            if (taken) c->rip += (uint64_t)(int64_t)(int32_t)in->imm;
            c->rip += in->len;
            return 0;
        } else if (full >= 0x140 && full <= 0x14F) { /* cmovcc */
            int cc = full - 0x140;
            int taken = cc_true(c, cc);
            if (cc & 1) taken = !taken;
            a = read_rm(c, in, os);
            if (taken) write_regop(c, in, os, a);
        } else if (full >= 0x190 && full <= 0x19F) { /* setcc */
            int cc = full - 0x190;
            int taken = cc_true(c, cc);
            if (cc & 1) taken = !taken;
            write_rm(c, in, 1, taken ? 1 : 0);
        } else if (full == 0x1AF) { /* imul r, rm */
            int64_t av = (int64_t)(read_regop(c, in, os) << (64 - os * 8)) >> (64 - os * 8);
            int64_t bv = (int64_t)(read_rm(c, in, os) << (64 - os * 8)) >> (64 - os * 8);
            int64_t pr = av * bv;
            uint64_t f = c->rflags & ~(WF_CF | WF_OF);
            int64_t trunc = (int64_t)(wemu_mask((uint64_t)pr, os) << (64 - os * 8)) >> (64 - os * 8);
            if (pr != trunc) f |= WF_CF | WF_OF;
            c->rflags = f;
            write_regop(c, in, os, wemu_mask((uint64_t)pr, os));
        } else if (full == 0x1B6 || full == 0x1BE) { /* movzx/movsx r, rm8 */
            a = read_rm(c, in, 1);
            write_regop(c, in, os, full == 0x1B6 ? a : (uint64_t)(int64_t)(int8_t)a);
        } else if (full == 0x1A4 || full == 0x1A5 ||
                   full == 0x1AC || full == 0x1AD) {
            /* shld/shrd r/m, r, imm8/CL — double-precision shifts.
             * glibc memmove tails use shld; busybox seq faulted here
             * (#UD) before this existed. dest = r/m, src = reg. */
            int left = (full == 0x1A4 || full == 0x1A5);
            uint64_t dest = read_rm(c, in, os);
            uint64_t src = read_regop(c, in, os);
            uint64_t cnt = (full == 0x1A4 || full == 0x1AC)
                               ? (in->imm & 0xff) : (c->r[1] & 0xff);
            int bits = os * 8;
            cnt &= (bits == 64) ? 63 : 31;
            uint64_t r = dest, cf = 0, of = 0;
            uint64_t f = c->rflags & ~(WF_CF | WF_OF | WF_ZF | WF_SF | WF_PF);
            if (cnt) {
                if (cnt < (uint64_t)bits) {
                    if (left) {
                        cf = (dest >> (bits - cnt)) & 1;
                        r = (dest << cnt) | (src >> (bits - cnt));
                    } else {
                        cf = (dest >> (cnt - 1)) & 1;
                        r = (dest >> cnt) | (src << (bits - cnt));
                    }
                } else { /* count >= width: SDM undefined; QEMU semantics */
                    cf = (src >> (cnt - bits)) & 1;
                    r = left ? (src << (cnt - bits)) : (src >> (cnt - bits));
                }
                r = wemu_mask(r, os);
                if (cnt == 1)
                    of = left ? ((r >> (bits - 1)) ^ cf)
                              : (((r ^ dest) >> (bits - 1)) & 1);
                if (cf) f |= WF_CF;
                if (of) f |= WF_OF;
                if (!r) f |= WF_ZF;
                if (r >> (bits - 1)) f |= WF_SF;
                if (wemu_parity(r)) f |= WF_PF;
            }
            c->rflags = f;
            write_rm(c, in, os, r);
        } else if (full == 0x1B7 || full == 0x1BF) { /* movzx/movsx r, rm16 */
            a = read_rm(c, in, 2);
            write_regop(c, in, os, full == 0x1B7 ? a : (uint64_t)(int64_t)(int16_t)a);
        } else if (full >= 0x1C8 && full <= 0x1CF) { /* bswap */
            int rr = (o - 0xC8) | (REX_B(in) << 3);
            uint64_t v = c->r[rr], out = 0;
            for (int i = 0; i < os; i++)
                out |= ((v >> (8 * i)) & 0xff) << (8 * (os - 1 - i));
            write_reg(c, rr, os, out);
        } else if (full == 0x11E || full == 0x11F) {
            /* endbr64/endbr32 (F3 0F 1E FA/FB) and multi-byte NOP
             * (0F 1F /0): architectural NOPs; ModRM/disp already consumed
             * by the decoder. CET landing pads must not fault guests. */
        } else if (full == 0x1BC || full == 0x1BD) { /* bsf/bsr, tzcnt/lzcnt */
            a = read_rm(c, in, os);
            int bits = os * 8;
            if (in->rep == 0xF3) { /* tzcnt/lzcnt: defined for src==0 */
                uint64_t f = c->rflags & ~(WF_ZF | WF_CF);
                if (!a) {
                    r = (uint64_t)bits;
                    f |= WF_CF;             /* CF=1: source was zero */
                } else {
                    int bit = full == 0x1BC ? 0 : bits - 1;
                    if (full == 0x1BC) while (!((a >> bit) & 1)) bit++;
                    else while (!((a >> bit) & 1)) bit--;
                    r = full == 0x1BC ? (uint64_t)bit
                                      : (uint64_t)(bits - 1 - bit);
                }
                if (!r) f |= WF_ZF;         /* ZF per the result */
                c->rflags = f;
                write_regop(c, in, os, r);
            } else {
                uint64_t f = c->rflags & ~WF_ZF;
                if (!a) { f |= WF_ZF; c->rflags = f; }
                else {
                    int bit = full == 0x1BC ? 0 : bits - 1;
                    if (full == 0x1BC) while (!((a >> bit) & 1)) bit++;
                    else while (!((a >> bit) & 1)) bit--;
                    write_regop(c, in, os, (uint64_t)bit);
                    c->rflags = f;
                }
            }
        } else if (full == 0x1C0 || full == 0x1C1) { /* xadd r/m, r */
            /* xadd is an atomic RMW: r/m <- r/m + r; r <- old r/m */
            int bytes = full == 0x1C0 ? 1 : os;
            a = rmw_read(c, in, bytes, eff_locked);
            b = read_regop(c, in, bytes);
            do_add(c, a, b, bytes, 0, &r);
            rmw_write(c, in, bytes, eff_locked, r);
            write_regop(c, in, bytes, a);
        } else if (full == 0x1B0 || full == 0x1B1) { /* cmpxchg r/m, r */
            /* compare accumulator (AL/EAX/RAX) with r/m.  Equal:
             * ZF=1, r/m <- reg; else ZF=0, accumulator <- r/m. */
            int bytes = full == 0x1B0 ? 1 : os;
            a = bytes == 1 ? read_reg(c, 0, 1) : read_reg(c, 0, bytes);
            b = rmw_read(c, in, bytes, eff_locked);
            do_sub(c, a, b, bytes, 0, &r);
            if (a == b) {
                rmw_write(c, in, bytes, eff_locked, read_regop(c, in, bytes));
            } else {
                if (bytes == 1) write_reg(c, 0, 1, b);
                else write_reg(c, 0, bytes, b);
            }
        } else if (full == 0x1BA) { /* bt/bts/btr/btc imm8 */
            int op = REG(in);
            a = is_rmw ? rmw_read(c, in, os, eff_locked) : read_rm(c, in, os);
            uint64_t bit = in->imm & (os * 8 - 1);
            uint64_t f = c->rflags & ~WF_CF;
            if ((a >> bit) & 1) f |= WF_CF;
            c->rflags = f;
            if (op == 5) { if (is_rmw) rmw_write(c, in, os, eff_locked, a | (1ull << bit));
                           else write_rm(c, in, os, a | (1ull << bit)); }
            else if (op == 6) { if (is_rmw) rmw_write(c, in, os, eff_locked, a & ~(1ull << bit));
                                else write_rm(c, in, os, a & ~(1ull << bit)); }
            else if (op == 7) { if (is_rmw) rmw_write(c, in, os, eff_locked, a ^ (1ull << bit));
                                else write_rm(c, in, os, a ^ (1ull << bit)); }
        } else if (full == 0x1A3 || full == 0x1AB || full == 0x1B3 || full == 0x1BB) {
            a = is_rmw ? rmw_read(c, in, os, eff_locked) : read_rm(c, in, os);
            uint64_t bit = read_regop(c, in, os) & (os * 8 - 1);
            uint64_t f = c->rflags & ~WF_CF;
            if ((a >> bit) & 1) f |= WF_CF;
            c->rflags = f;
            if (full == 0x1AB) { if (is_rmw) rmw_write(c, in, os, eff_locked, a | (1ull << bit));
                                 else write_rm(c, in, os, a | (1ull << bit)); }
            else if (full == 0x1B3) { if (is_rmw) rmw_write(c, in, os, eff_locked, a & ~(1ull << bit));
                                      else write_rm(c, in, os, a & ~(1ull << bit)); }
            else if (full == 0x1BB) { if (is_rmw) rmw_write(c, in, os, eff_locked, a ^ (1ull << bit));
                                      else write_rm(c, in, os, a ^ (1ull << bit)); }
        } else if (full == 0x1A2) { /* cpuid: claim ONLY what we execute.
            * CPUID outputs: EAX->r0 EBX->r3 ECX->r1 EDX->r2 */
            uint64_t leaf = c->r[0];
            if (leaf == 0) {
                c->r[0] = 7; /* max basic leaf */
                c->r[3] = 0x75427557; /* EBX "WuBu" */
                c->r[1] = 0x6c756d45; /* ECX "Emul" */
                c->r[2] = 0x726f7461; /* EDX "ator" */
            } else if (leaf == 1) {
                c->r[0] = 0x000906E9; /* family/model/stepping (consistent) */
                c->r[3] = 0;          /* EBX */
                /* EDX: TSC MSR PAE CX8 CMOV FXSR MMX SSE SSE2 */
                c->r[2] = (1ull<<4)|(1ull<<5)|(1ull<<6)|(1ull<<8)|(1ull<<15)|
                          (1ull<<24)|(1ull<<23)|(1ull<<25)|(1ull<<26);
                /* ECX: SSE3 SSSE3 XSAVE OSXSAVE POPCNT SSE4.1 SSE4.2 AVX */
                c->r[1] = (1ull<<0)|(1ull<<9)|(1ull<<26)|(1ull<<27)|(1ull<<23)|
                          (1ull<<19)|(1ull<<20)|(1ull<<28);
            } else if (leaf == 7) {
                c->r[0] = 0; /* max subleaf */
                c->r[3] = (1ull<<5); /* EBX: AVX2 — the founding gap, owned */
                c->r[1] = 0;
                c->r[2] = 0;
            } else { c->r[0] = c->r[1] = c->r[2] = c->r[3] = 0; }
        } else if (full == 0x101 && in->modrm == 0xD0) { /* xgetbv */
            if ((c->r[1] & 0xffffffff) == 0) {
                c->r[0] = 0x7; /* XCR0: x87+SSE+AVX state enabled */
                c->r[2] = 0;
            } else { c->r[0] = 0; c->r[2] = 0; }
        } else if (full == 0x131) { /* rdtsc */
            static uint64_t tsc;
            tsc += 100;
            c->r[0] = tsc & 0xffffffff; c->r[2] = tsc >> 32;
        } else if (full == 0x10B) { c->fault = 6; return -1; } /* ud2 */
        else goto ud;
    }
    c->rip += in->len;
    return 0;
ud:
    c->fault = 6; /* #UD: unimplemented opcode — honest, never fake */
    return -1;
}