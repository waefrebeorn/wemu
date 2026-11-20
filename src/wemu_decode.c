/* wemu_decode.c — x86-64 instruction decoder: legacy prefixes, REX,
 * VEX (2/3-byte), opcode maps (1-byte / 0F / 0F38 / 0F3A), ModRM, SIB,
 * displacements, immediates. One concern: bytes -> WemuInsn. */
#include "wemu_internal.h"

typedef struct {
    WemuCpu *cpu;
    uint64_t va;
    uint8_t buf[16];
    int n;                   /* bytes fetched */
    int pos;
} Fetch;

static int fetch(Fetch *f, int need) {
    if (f->n - f->pos >= need) return 0;
    int have = f->n - f->pos;
    if (wemu_mem_read(f->cpu, f->va + f->pos, f->buf + f->pos,
                      (size_t)(need - have)) != 0)
        return -1;
    f->n = f->pos + need;
    return 0;
}

static uint8_t peek(Fetch *f) {
    if (fetch(f, f->pos + 1) != 0) return 0;
    return f->buf[f->pos];
}

static uint8_t take(Fetch *f) {
    uint8_t b = peek(f);
    f->pos++;
    return b;
}

static uint64_t take_imm(Fetch *f, int len) {
    uint64_t v = 0;
    for (int i = 0; i < len; i++)
        v |= (uint64_t)take(f) << (8 * i);
    return v;
}

/* immediate length for opcodes that carry one (primary map) */
static int imm_len_for(uint32_t op, int opsize, uint8_t modrm_reg,
                       int addrsize) {
    if (op >= 0xB8 && op <= 0xBF) return opsize; /* mov r, imm (66/REX.W aware) */
    if (op >= 0xB0 && op <= 0xB7) return 1;
    if (op >= 0xA0 && op <= 0xA3) return addrsize; /* mov moffs */
    if (op == 0xE4 || op == 0xE6) return 1;        /* in/out imm8 */
    if (op == 0xE5 || op == 0xE7) return opsize == 2 ? 2 : 4;
    switch (op) {
    case 0x04: case 0x0C: case 0x14: case 0x1C:
    case 0x24: case 0x2C: case 0x34: case 0x3C:
        return 1;                             /* AL, imm8 (grp1 form 4) */
    case 0x05: case 0x0D: case 0x15: case 0x1D:
    case 0x25: case 0x2D: case 0x35: case 0x3D:
    case 0x68: case 0xA9: case 0xE8: case 0xE9:
        return opsize == 2 ? 2 : 4;
    case 0x80: return 1;                     /* grp1 imm8 */
    case 0x81: return opsize == 2 ? 2 : 4;   /* grp1 imm */
    case 0x69: return opsize == 2 ? 2 : 4;   /* imul r,rm,imm */
    case 0x6B: return 1;                     /* imul r,rm,imm8 */
    case 0xF6: return (modrm_reg <= 1) ? 1 : 0;  /* test imm8 */
    case 0xF7: return (modrm_reg <= 1) ? (opsize == 2 ? 2 : 4) : 0;
    case 0x83: case 0x6A: case 0xA8: case 0xEB:
    case 0xCD: case 0xC2: case 0xCA:
        return (op == 0xC2 || op == 0xCA) ? 2 : 1;
    case 0xC7: return opsize == 2 ? 2 : 4;   /* mov r/m, imm */
    case 0xC6: return 1;
    case 0xC0: case 0xC1: return 1;          /* grp2 shift imm8 */
    case 0x0F: return 0;
    default:
        if (op >= 0x70 && op <= 0x7F) return 1;      /* jcc rel8 */
        if (op >= 0x180 && op <= 0x18F) return 4;    /* 0F 8x jcc rel32 */
        if (op == 0x1BA) return 1;                   /* 0F BA grp8 imm8 */
        if (op == 0x1A4 || op == 0x1AC) return 1;    /* shld/shrd imm8 */
        if (op >= 0x170 && op <= 0x173) return 1;    /* pshufd/psrlw/pslld/psllq imm8 */
        if (op >= 0x300 && op <= 0x3FF) return 1;    /* 0F 3A map: all imm8 */
        if (op == 0x1C7) return 0;   /* 0F C7 /1 cmpxchg8b/16b: no immediate */
        /* 0F AE /5,/6,/7 fences need ModRM but no immediate; F3 90 PAUSE
         * is a plain 0x90 with a REP prefix. Neither needs decode work. */
        return 0;
    }
}

int wemu_decode(WemuCpu *cpu, WemuInsn *in) {
    Fetch f = { cpu, cpu->rip, {0}, 0, 0 };
    in->opsize = 4;
    in->addrsize = 8;
    uint8_t rex = 0;
    int op;

    /* legacy prefixes */
    for (;;) {
        uint8_t b = peek(&f);
        if (b == 0x66) { in->opsize = 2; take(&f); }
        else if (b == 0x67) { in->addrsize = 4; take(&f); }
        else if (b == 0xF2 || b == 0xF3) { in->rep = b; take(&f); }
        else if (b == 0x64 || b == 0x65) { in->seg = b; take(&f); }
        else if (b == 0xF0) { in->lock = 1; take(&f); }
        else if (b == 0x2E || b == 0x36 || b == 0x3E ||
                 b == 0x26 || b == 0x9B) { take(&f); } /* 9B = fwait: x87
                 sync prefix, no-op for the interpreter (no async FP) */
        else break;
        rex = 0; /* REX must be last prefix */
    }
    uint8_t b = peek(&f);
    if (b >= 0x40 && b <= 0x4F) { rex = take(&f); b = peek(&f); }
    in->rex = rex;
    if (rex & 8) in->opsize = 8;

    /* VEX prefixes */
    if (b == 0xC4 || b == 0xC5) {
        if (in->lock) { in->fault = 6; return -1; } /* LOCK + VEX: #UD */
        uint8_t p0 = take(&f);
        uint8_t p1 = take(&f);
        if (p0 == 0xC4) {
            uint8_t p2 = take(&f);
            in->vex_len = 3;
            in->vex[0] = p0; in->vex[1] = p1; in->vex[2] = p2;
            int mmmmm = p1 & 0x1f;
            int pp = p2 & 3;
            in->opsize = (p2 & 0x80) ? 8 : ((pp == 1) ? 2 : 4);
            /* synthesize REX from inverted VEX R/X/B (all in p1 bits 7:5) */
            in->rex = (uint8_t)(0x40 | ((~p1 >> 5) & 7) |
                                ((p2 & 0x80) ? 8 : 0));
            in->rep = (uint8_t)(pp == 2 ? 0xF3 : pp == 3 ? 0xF2 : 0);
            op = (mmmmm == 1) ? 0x100 : (mmmmm == 2) ? 0x200 :
                 (mmmmm == 3) ? 0x300 : -1;
            if (op < 0) { in->fault = 6; return -1; }
            op |= take(&f);
        } else {
            in->vex_len = 2;
            in->vex[0] = p0; in->vex[1] = p1;
            int pp = p1 & 3;
            in->opsize = (pp == 1) ? 2 : 4;
            in->rex = (uint8_t)(0x40 | ((~p1 >> 5) & 4));
            in->rep = (uint8_t)(pp == 2 ? 0xF3 : pp == 3 ? 0xF2 : 0);
            op = 0x100 | take(&f);
        }
        in->op = (uint8_t)(op & 0xff);
        /* store full map in len-adjacent field via op trick: keep map in
         * vex[0] high nibble for the SSE leaf */
        in->vex[0] = (uint8_t)((op >> 8) << 4);
        goto modrm;
    }

    op = take(&f);
    if (op == 0x0F) {
        uint8_t b2 = take(&f);
        if (b2 == 0x38) op = 0x200 | take(&f);
        else if (b2 == 0x3A) op = 0x300 | take(&f);
        else op = 0x100 | b2;
    }
    in->op = (uint8_t)(op & 0xff);
    if (op >= 0x100) in->vex[0] = (uint8_t)((op >> 8) << 4); /* map marker */

modrm:;
    /* which opcodes need ModRM */
    int need_modrm = 0;
    uint32_t full = op;
    uint8_t o = in->op;
    if (full < 0x100) {
        if ((o & 0xC0) == 0x00 && (o & 7) <= 3 && o != 0x0F) need_modrm = 1;
        if (o >= 0x80 && o <= 0x8F) need_modrm = 1;
        if (o == 0x63 || o == 0x69 || o == 0x6B || o == 0x8D) need_modrm = 1;
        if (o >= 0xC0 && o <= 0xC1) need_modrm = 1;
        if (o == 0xC6 || o == 0xC7) need_modrm = 1;
        if (o == 0xD0 || o == 0xD1 || o == 0xD2 || o == 0xD3) need_modrm = 1;
        if (o >= 0xD8 && o <= 0xDF) need_modrm = 1; /* x87 escapes */
        if (o == 0xF6 || o == 0xF7) need_modrm = 1;
        if (o == 0xFE || o == 0xFF) need_modrm = 1;
        if (o == 0x8F) need_modrm = 1;
    } else {
        need_modrm = 1; /* two/three-byte opcodes in our subset all use it */
        if (full == 0x105 || full == 0x10B || full == 0x1A2 ||
            full == 0x131 || full == 0x177 || full == 0x10E ||
            (full >= 0x180 && full <= 0x18F) ||
            (full >= 0x1C8 && full <= 0x1CF))
            need_modrm = 0; /* syscall/sysret/cpuid/rdtsc/emms/bswap/jcc rel32 */
    }
    if (need_modrm) {
        in->has_modrm = 1;
        in->modrm = take(&f);
        int mod = in->modrm >> 6, rm = in->modrm & 7;
        if (mod != 3 && rm == 4) {
            in->has_sib = 1;
            in->sib = take(&f);
            int base = in->sib & 7;
            if (mod == 0 && base == 5) {
                in->disp = (int32_t)take_imm(&f, 4);
            } else if (mod == 1) in->disp = (int8_t)take(&f);
            else if (mod == 2) in->disp = (int32_t)take_imm(&f, 4);
        } else if (mod == 0 && rm == 5) {
            in->rip_rel = 1;
            in->disp = (int32_t)take_imm(&f, 4);
        } else if (mod == 1) in->disp = (int8_t)take(&f);
        else if (mod == 2) in->disp = (int32_t)take_imm(&f, 4);
    }
    in->imm_len = (uint8_t)imm_len_for(full, in->opsize,
                                       in->modrm >> 3 & 7, in->addrsize);
    if (in->imm_len) in->imm = take_imm(&f, in->imm_len);
    in->len = (uint8_t)f.pos;
    if (f.pos > 15) { in->fault = 6; return -1; } /* x86 max insn length */
    return 0;
}