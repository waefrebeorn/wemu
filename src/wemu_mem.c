/* wemu_mem.c — guest physical memory + long-mode 4-level page walk.
 * One concern: address translation and checked memory access. */
#include "wemu_internal.h"
#include <stdlib.h>

int wemu_gpa_read(WemuCpu *cpu, uint64_t gpa, void *dst, size_t len) {
    if (gpa > cpu->ram_size || len > cpu->ram_size - gpa) {
        cpu->fault = 13; /* #GP: outside guest RAM */
        return -1;
    }
    memcpy(dst, cpu->ram + gpa, len);
    return 0;
}

int wemu_gpa_write(WemuCpu *cpu, uint64_t gpa, const void *src, size_t len) {
    if (gpa > cpu->ram_size || len > cpu->ram_size - gpa) {
        cpu->fault = 13;
        return -1;
    }
    memcpy(cpu->ram + gpa, src, len);
    return 0;
}

/* 4-level walk (4KiB pages; 2MiB/1GiB leaves honored via PS bit).
 * Returns translated GPA, sets *fault (#PF=14) on failure. */
uint64_t wemu_translate(WemuCpu *cpu, uint64_t va, int *fault) {
    *fault = 0;
    if (!(cpu->cr0 & 0x80000000ull)) /* PG clear: identity */
        return va;
    if (va >> 47) { /* non-canonical */
        *fault = 13;
        return 0;
    }
    uint64_t table = cpu->cr3 & 0x000ffffffffff000ull;
    int shift = 39;
    for (int level = 0; level < 4; level++) {
        uint64_t idx = (va >> shift) & 0x1ff;
        uint64_t ent;
        if (wemu_gpa_read(cpu, table + idx * 8, &ent, 8) != 0) {
            *fault = 14;
            return 0;
        }
        if (!(ent & 1)) { /* not present */
            *fault = 14;
            cpu->cr2 = va;
            return 0;
        }
        if ((ent & 0x80) && level < 3) { /* large page (2MiB/1GiB) */
            uint64_t mask = (1ull << shift) - 1;
            return (ent & 0x000ffffffffff000ull & ~mask) | (va & mask);
        }
        if (level == 3)
            return (ent & 0x000ffffffffff000ull) | (va & 0xfff);
        table = ent & 0x000ffffffffff000ull;
        shift -= 9;
    }
    *fault = 14;
    return 0;
}

int wemu_mem_read(WemuCpu *cpu, uint64_t va, void *dst, size_t len) {
    uint8_t *d = dst;
    while (len) {
        int f;
        uint64_t gpa = wemu_translate(cpu, va, &f);
        if (f) { cpu->fault = f; return -1; }
        uint64_t chunk = 0x1000 - (va & 0xfff);
        if (chunk > len) chunk = len;
        if (wemu_gpa_read(cpu, gpa, d, (size_t)chunk) != 0) return -1;
        va += chunk; d += chunk; len -= (size_t)chunk;
    }
    return 0;
}

int wemu_mem_write(WemuCpu *cpu, uint64_t va, const void *src, size_t len) {
    const uint8_t *s = src;
    while (len) {
        int f;
        uint64_t gpa = wemu_translate(cpu, va, &f);
        if (f) { cpu->fault = f; return -1; }
        uint64_t chunk = 0x1000 - (va & 0xfff);
        if (chunk > len) chunk = len;
        if (wemu_gpa_write(cpu, gpa, s, (size_t)chunk) != 0) return -1;
        va += chunk; s += chunk; len -= (size_t)chunk;
    }
    return 0;
}

uint64_t wemu_eff_addr(WemuCpu *c, const WemuInsn *in) {
    int rex_b = in->rex & 1, rex_x = (in->rex >> 1) & 1;
    int rm = (in->modrm & 7) | (rex_b << 3);
    if (in->rip_rel)
        return c->rip + in->len + (uint64_t)in->disp;
    uint64_t addr;
    if (in->has_sib) {
        int scale = 1 << (in->sib >> 6);
        int idx = ((in->sib >> 3) & 7) | (rex_x << 3);
        int base = (in->sib & 7) | (rex_b << 3);
        addr = (in->modrm >> 6) == 0 && (in->sib & 7) == 5
                   ? 0 /* disp32 is the base; added once below */
                   : c->r[base];
        if (idx != 4) addr += c->r[idx] * (uint64_t)scale;
    } else {
        addr = c->r[rm];
    }
    if (in->addrsize == 4) addr &= 0xffffffffull;
    addr += (uint64_t)in->disp;
    /* user-mode TLS: FS/GS overrides add the segment base (flat DS/ES/
     * SS/CS contribute 0). LEA excludes the base at its call site. */
    if (in->seg == 0x64) addr += c->fs_base;
    else if (in->seg == 0x65) addr += c->gs_base;
    return addr;
}