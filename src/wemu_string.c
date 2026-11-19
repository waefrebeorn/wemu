/* wemu_string.c — string instructions (movs/stos/scas/cmps) with rep
 * prefixes and DF direction. One concern: the block-move family that
 * real memset/memcpy/memcmp compile to (rep stosb/movsb). Without these
 * an emulator cannot run actual compiled code, only hand-picked ops. */
#include "wemu_internal.h"

#define WF_DF 0x400

/* returns 1 handled, 0 not a string op, -1 fault */
int wemu_exec_string(WemuCpu *c, const WemuInsn *in) {
    uint8_t o = in->op;
    /* PRIMARY map only: vex[0] carries the map marker for legacy 0F
     * too. Without this guard 0F AF (imul r,rm) executes as SCAS,
     * 0F AB (bts) as STOS — silent state corruption (found by glibc
     * strtol summing digits under the busybox gate). */
    if (in->vex_len || in->vex[0]) return 0;
    if (o == 0xFC) { c->rflags &= ~WF_DF; return 1; } /* cld */
    if (o == 0xFD) { c->rflags |= WF_DF; return 1; }  /* std */
    int kind;
    switch (o) {
    case 0xA4: case 0xA5: kind = 0; break; /* movs */
    case 0xA6: case 0xA7: kind = 1; break; /* cmps */
    case 0xAA: case 0xAB: kind = 2; break; /* stos */
    case 0xAC: case 0xAD: kind = 4; break; /* lods */
    case 0xAE: case 0xAF: kind = 3; break; /* scas */
    default: return 0;
    }
    int bytes = (o & 1) ? in->opsize : 1;
    int64_t step = (c->rflags & WF_DF) ? -bytes : bytes;
    uint64_t count = 1;
    int rep = in->rep != 0;
    if (rep) count = c->r[1] & (in->addrsize == 4 ? 0xffffffffull : ~0ull);
    uint64_t done = 0;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t di = c->r[7];
        uint64_t si = c->r[6];
        uint64_t a = 0, b = 0;
        switch (kind) {
        case 0: /* movs [rdi], [rsi] */
            if (wemu_mem_read(c, si, &a, (size_t)bytes) != 0) return -1;
            if (wemu_mem_write(c, di, &a, (size_t)bytes) != 0) return -1;
            c->r[7] += (uint64_t)step;
            c->r[6] += (uint64_t)step;
            break;
        case 1: /* cmps [rsi], [rdi] -> flags */
            if (wemu_mem_read(c, si, &a, (size_t)bytes) != 0) return -1;
            if (wemu_mem_read(c, di, &b, (size_t)bytes) != 0) return -1;
            wemu_set_add_flags(c, a, b, wemu_mask(a - b, bytes), bytes, 0, 1);
            c->r[6] += (uint64_t)step;
            c->r[7] += (uint64_t)step;
            break;
        case 2: /* stos [rdi], al/eax */
            a = wemu_mask(c->r[0], bytes);
            if (wemu_mem_write(c, di, &a, (size_t)bytes) != 0) return -1;
            c->r[7] += (uint64_t)step;
            break;
        case 3: /* scas al/eax, [rdi] -> flags */
            a = wemu_mask(c->r[0], bytes);
            if (wemu_mem_read(c, di, &b, (size_t)bytes) != 0) return -1;
            wemu_set_add_flags(c, a, b, wemu_mask(a - b, bytes), bytes, 0, 1);
            c->r[7] += (uint64_t)step;
            break;
        case 4: /* lods al/eax, [rsi] */
            if (wemu_mem_read(c, si, &a, (size_t)bytes) != 0) return -1;
            wemu_reg_write(c, 0, bytes, a);
            c->r[6] += (uint64_t)step;
            break;
        }
        done++;
        if (rep && (kind == 1 || kind == 3)) {
            int zf = (c->rflags & WF_ZF) != 0;
            if (in->rep == 0xF3 && !zf) break;  /* repe: stop on mismatch */
            if (in->rep == 0xF2 && zf) break;   /* repne: stop on match */
        }
    }
    if (rep) c->r[1] -= done;
    return 1;
}