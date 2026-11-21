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

/* x86 #PF error code bits (SDM 4.7): P(0), W/R(1), U/S(2), RSVD(3),
 * I/D(4), PK(5).  WEMU models P, W/R, U/S, RSVD and I/D.  PK (protection
 * key) and SGX (bit 6) stay clear: CR4.PKE / ENCLS are not implemented, so
 * there is no protection-key or enclave access to attribute a fault to. */
#define PF_P     0x01ull
#define PF_WR    0x02ull
#define PF_US    0x04ull
#define PF_RSVD  0x08ull
#define PF_ID    0x10ull

/* 4-level paging, MAXPHYADDR=52, CR4.PKE=0 (WEMU does not implement PKE):
 * bits 62:52 of a paging-structure entry are reserved; bit 63 is XD/NX.
 * With EFER.NXE=1 (WEMU's reset value) bit 63 is the execute-disable bit
 * and is ENFORCED on instruction fetch (#PF, error P=1 + I/D=1); it is no
 * longer merely parsed.  With NXE=0 bit 63 is reserved and faults with
 * RSVD.  Other reserved bits fault with P=1 (the entry is present) and the
 * RSVD error bit set. */
#define PT_RESERVED_MASK 0x7FF0000000000000ull
#define PT_XD           (1ull << 63)
#define EFER_NXE        (1ull << 11) /* 0x800 */

static uint64_t pf_code(int present, int write, int user, int fetch,
                        int reserved) {
    return (present ? PF_P : 0) | (write ? PF_WR : 0) | (user ? PF_US : 0) |
           (fetch ? PF_ID : 0) | (reserved ? PF_RSVD : 0);
}

/* Leaf permission check.  U/S: a user access needs U=1 on the leaf.
 * W/R: a write needs RW=1; supervisor writes are checked only when
 * CR0.WP is set (SDM), user writes are always checked.  XD: with EFER.NXE=1
 * an instruction fetch from a leaf with bit 63 set faults (no dedicated
 * error-code bit: P=1 + I/D=1); with NXE=0 bit 63 is reserved and is caught
 * by the walk's reserved-bit check, so it is not a protection fault here. */
static int leaf_prot_fault(const WemuCpu *cpu, uint64_t ent,
                           int is_write, int is_user, int is_fetch) {
    if (is_user && !(ent & 0x4)) return 1;
    if (is_write && !(ent & 0x2) && (is_user || (cpu->cr0 & 0x10000ull)))
        return 1;
    if (is_fetch && (cpu->efer & EFER_NXE) && (ent & PT_XD)) return 1;
    return 0;
}

/* 4-level walk (4KiB pages; 2MiB/1GiB leaves honored via PS bit).
 * is_fetch marks instruction fetches for the #PF I/D bit.  Sets *fault
 * (#PF=14, #GP=13) and the architectural error code in cpu->fault_error
 * on failure. */
uint64_t wemu_translate_ex(WemuCpu *cpu, uint64_t va, int is_write,
                           int is_user, int is_fetch, int *fault) {
    *fault = 0;
    if (!(cpu->cr0 & 0x80000000ull)) /* PG clear: identity */
        return va;
    if (va >> 47) { /* non-canonical: #GP, no selector error code */
        cpu->fault_error = 0;
        *fault = 13;
        return 0;
    }
    uint64_t table = cpu->cr3 & 0x000ffffffffff000ull;
    uint64_t rsvd_mask = PT_RESERVED_MASK;
    if (!(cpu->efer & EFER_NXE)) rsvd_mask |= PT_XD; /* NXE=0: XD bit reserved */
    int shift = 39;
    for (int level = 0; level < 4; level++) {
        uint64_t idx = (va >> shift) & 0x1ff;
        uint64_t ent;
        if (wemu_gpa_read(cpu, table + idx * 8, &ent, 8) != 0) {
            *fault = 14;
            cpu->cr2 = va;
            cpu->fault_error = pf_code(0, is_write, is_user, is_fetch, 0);
            return 0;
        }
        if (!(ent & 1)) { /* not present */
            *fault = 14;
            cpu->cr2 = va;
            cpu->fault_error = pf_code(0, is_write, is_user, is_fetch, 0);
            return 0;
        }
        if (ent & rsvd_mask) { /* reserved bit set in a present entry */
            *fault = 14;
            cpu->cr2 = va;
            cpu->fault_error = pf_code(1, is_write, is_user, is_fetch, 1);
            return 0;
        }
        if ((ent & 0x80) && level < 3) { /* large page (2MiB/1GiB) */
            if (leaf_prot_fault(cpu, ent, is_write, is_user, is_fetch)) {
                *fault = 14;
                cpu->cr2 = va;
                cpu->fault_error = pf_code(1, is_write, is_user, is_fetch, 0);
                return 0;
            }
            uint64_t mask = (1ull << shift) - 1;
            return (ent & 0x000ffffffffff000ull & ~mask) | (va & mask);
        }
        if (level == 3) {
            if (leaf_prot_fault(cpu, ent, is_write, is_user, is_fetch)) {
                *fault = 14;
                cpu->cr2 = va;
                cpu->fault_error = pf_code(1, is_write, is_user, is_fetch, 0);
                return 0;
            }
            return (ent & 0x000ffffffffff000ull) | (va & 0xfff);
        }
        table = ent & 0x000ffffffffff000ull;
        shift -= 9;
    }
    *fault = 14;
    cpu->cr2 = va;
    cpu->fault_error = pf_code(0, is_write, is_user, is_fetch, 0);
    return 0;
}

/* Data access: I/D clear. */
uint64_t wemu_translate(WemuCpu *cpu, uint64_t va, int is_write, int is_user,
                        int *fault) {
    return wemu_translate_ex(cpu, va, is_write, is_user, 0, fault);
}

int wemu_mem_read(WemuCpu *cpu, uint64_t va, void *dst, size_t len) {
    uint8_t *d = dst;
    while (len) {
        int f;
        uint64_t gpa = wemu_translate(cpu, va, 0, cpu->cpl == 3, &f);
        if (f) { cpu->fault = f; return -1; }
        uint64_t chunk = 0x1000 - (va & 0xfff);
        if (chunk > len) chunk = len;
        if (wemu_gpa_read(cpu, gpa, d, (size_t)chunk) != 0) return -1;
        va += chunk; d += chunk; len -= (size_t)chunk;
    }
    return 0;
}

/* Instruction fetch: the only reader that sets the #PF I/D error bit. */
int wemu_mem_fetch(WemuCpu *cpu, uint64_t va, void *dst, size_t len) {
    uint8_t *d = dst;
    while (len) {
        int f;
        uint64_t gpa = wemu_translate_ex(cpu, va, 0, cpu->cpl == 3, 1, &f);
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
        uint64_t gpa = wemu_translate(cpu, va, 1, cpu->cpl == 3, &f);
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