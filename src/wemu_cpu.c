/* wemu_cpu.c — CPU state, flags arithmetic, lifecycle, step/run loop,
 * syscall dispatch. One concern: the architectural state machine. */
#include "wemu_internal.h"
#include <stdlib.h>

uint64_t wemu_mask(uint64_t v, int bytes) {
    if (bytes >= 8) return v;
    return v & ((1ull << (bytes * 8)) - 1);
}

int wemu_parity(uint64_t v) {
    uint8_t b = (uint8_t)v;
    int p = 1;
    for (int i = 0; i < 8; i++) p ^= (b >> i) & 1;
    return p; /* PF=1 when low byte has even parity */
}

void wemu_set_logic_flags(WemuCpu *cpu, uint64_t res, int bytes) {
    uint64_t m = wemu_mask(res, bytes);
    uint64_t f = cpu->rflags & ~(WF_CF | WF_OF | WF_ZF | WF_SF | WF_PF | WF_AF);
    if (!m) f |= WF_ZF;
    if (m >> (bytes * 8 - 1)) f |= WF_SF;
    if (wemu_parity(m)) f |= WF_PF;
    cpu->rflags = f;
}

void wemu_set_add_flags(WemuCpu *cpu, uint64_t a, uint64_t b, uint64_t res,
                        int bytes, int carry_in, int is_sub) {
    int bits = bytes * 8;
    uint64_t m = wemu_mask(res, bytes);
    uint64_t ma = wemu_mask(a, bytes), mb = wemu_mask(b, bytes);
    uint64_t f = cpu->rflags & ~(WF_CF | WF_OF | WF_ZF | WF_SF | WF_PF | WF_AF);
    if (!m) f |= WF_ZF;
    if (m >> (bits - 1)) f |= WF_SF;
    if (wemu_parity(m)) f |= WF_PF;
    /* AF: carry out of bit 3 */
    if (((ma & 0xf) + (mb & 0xf) + carry_in) & 0x10) f |= WF_AF;
    if (is_sub) {
        /* CF = borrow: a < b + carry_in (unsigned, masked) */
        if (ma < mb + (uint64_t)carry_in) f |= WF_CF;
        /* OF: sign(a) != sign(b) && sign(res) != sign(a) */
        uint64_t sa = ma >> (bits - 1), sb = mb >> (bits - 1),
                 sr = m >> (bits - 1);
        if (sa != sb && sr != sa) f |= WF_OF;
    } else {
        /* CF: result wrapped below either operand */
        if (m < ma || (carry_in && m == ma)) f |= WF_CF;
        uint64_t sa = ma >> (bits - 1), sb = mb >> (bits - 1),
                 sr = m >> (bits - 1);
        if (sa == sb && sr != sa) f |= WF_OF;
    }
    cpu->rflags = f;
}

WemuCpu *wemu_cpu_create(uint64_t ram_size) {
    if (!ram_size || ram_size > WEMU_RAM_MAX) return NULL;
    WemuCpu *cpu = calloc(1, sizeof *cpu);
    if (!cpu) return NULL;
    cpu->ram = calloc(1, (size_t)ram_size);
    if (!cpu->ram) { free(cpu); return NULL; }
    cpu->ram_size = ram_size;
    cpu->rflags = 2;
    cpu->cr0 = 0x11; /* PE|MP: long mode ready, paging OFF until enabled */
    cpu->efer = 0xd00;        /* LME|LMA|NXE */
    cpu->x87_cw = 0x037F;     /* x87 reset: all exceptions masked, round-nearest */
    cpu->r[4] = ram_size - 0x1000; /* default stack near RAM top */
    return cpu;
}

void wemu_cpu_destroy(WemuCpu *cpu) {
    if (!cpu) return;
    free(cpu->ram);
    free(cpu);
}

int wemu_cpu_load(WemuCpu *cpu, uint64_t gpa, const uint8_t *code, size_t len) {
    return wemu_gpa_write(cpu, gpa, code, len);
}

void wemu_cpu_set_rip(WemuCpu *cpu, uint64_t rip) { cpu->rip = rip; }
void wemu_cpu_set_rsp(WemuCpu *cpu, uint64_t rsp) { cpu->r[4] = rsp; }
uint64_t wemu_cpu_reg(const WemuCpu *cpu, int idx) {
    return (idx >= 0 && idx < 16) ? cpu->r[idx] : 0;
}
void wemu_cpu_set_reg(WemuCpu *cpu, int idx, uint64_t val) {
    if (idx >= 0 && idx < 16) cpu->r[idx] = val;
}
uint64_t wemu_cpu_rip(const WemuCpu *cpu) { return cpu->rip; }
uint64_t wemu_cpu_rflags(const WemuCpu *cpu) { return cpu->rflags; }
void wemu_cpu_set_cr3(WemuCpu *cpu, uint64_t cr3) { cpu->cr3 = cr3; }
void wemu_cpu_enable_paging(WemuCpu *cpu, int on) {
    if (on) cpu->cr0 |= 0x80000000ull;
    else cpu->cr0 &= ~0x80000000ull;
}
void wemu_cpu_set_fs_base(WemuCpu *cpu, uint64_t base) { cpu->fs_base = base; }
void wemu_cpu_set_gs_base(WemuCpu *cpu, uint64_t base) { cpu->gs_base = base; }
uint64_t wemu_cpu_fs_base(const WemuCpu *cpu) { return cpu->fs_base; }
uint64_t wemu_cpu_gs_base(const WemuCpu *cpu) { return cpu->gs_base; }
void wemu_cpu_set_syscall_hook(WemuCpu *cpu, WemuSyscallFn fn, void *ud) {
    cpu->sys_fn = fn; cpu->sys_ud = ud;
}
void wemu_cpu_set_atomic_observer(WemuCpu *cpu, WemuAtomicObserver fn,
                                  void *ud) {
    cpu->atomic_observer = fn; cpu->atomic_observer_ud = ud;
}
uint64_t wemu_cpu_hint_count(const WemuCpu *cpu, WemuHintKind kind) {
    return ((unsigned)kind < (unsigned)WEMU_HINT_KINDS) ? cpu->hint_count[kind] : 0;
}
int wemu_cpu_halted(const WemuCpu *cpu) { return cpu->halted; }
void wemu_cpu_halt(WemuCpu *cpu) { cpu->halted = 1; }
int wemu_cpu_fault(const WemuCpu *cpu) { return cpu->fault; }
void wemu_cpu_clear_fault(WemuCpu *cpu) { cpu->fault = 0; }
uint64_t wemu_cpu_fault_addr(const WemuCpu *cpu) { return cpu->cr2; }
uint64_t wemu_cpu_fault_error(const WemuCpu *cpu) {
    return cpu ? cpu->fault_error : 0;
}
void wemu_cpu_set_cpl(WemuCpu *cpu, int cpl) {
    if (cpu) cpu->cpl = cpl < 0 ? 0 : (cpl > 3 ? 3 : cpl);
}
int wemu_cpu_cpl(const WemuCpu *cpu) { return cpu ? cpu->cpl : 0; }
void wemu_cpu_xmm(const WemuCpu *cpu, int idx, uint8_t out[16]) {
    if (idx >= 0 && idx < 16) memcpy(out, cpu->xmm[idx], 16);
    else memset(out, 0, 16);
}

void wemu_reg_write(WemuCpu *c, int i, int bytes, uint64_t v) {
    if (i < 0 || i > 15) return;
    if (bytes == 4) { c->r[i] = v & 0xffffffffull; return; }
    if (bytes == 8) { c->r[i] = v; return; }
    if (bytes == 2) {
        c->r[i] = (c->r[i] & ~0xffffull) | (v & 0xffff);
        return;
    }
    c->r[i] = (c->r[i] & ~0xffull) | (v & 0xff);
}

/* default syscall semantics: exit halts; write goes to serial if wired */
static int64_t default_syscall(WemuCpu *cpu, uint64_t nr,
                               const uint64_t args[6]) {
    if (nr == 60 || nr == 231) { /* exit / exit_group */
        cpu->halted = 1;
        return (int64_t)(args[0] & 0xff);
    }
    if (nr == 1 && cpu->serial_out) { /* write(fd, buf, len) -> serial */
        uint8_t b;
        for (uint64_t i = 0; i < args[2]; i++) {
            if (wemu_mem_read(cpu, args[1] + i, &b, 1) != 0)
                return -14;
            cpu->serial_out(b, cpu->serial_ud);
        }
        return (int64_t)args[2];
    }
    return -38; /* -ENOSYS */
}

int64_t wemu_cpu_step(WemuCpu *cpu) {
    if (cpu->halted) return -1;
    /* A fault latched before this instruction (host raise) keeps its error
     * code; otherwise a fresh instruction boundary clears stale metadata. */
    if (!cpu->fault) cpu->fault_error = 0;
    /* A fault already latched (host raise, or a previous hook) is delivered
     * here at the instruction boundary.  No handler -> legacy -1. */
    if (cpu->fault) {
        int v = cpu->fault;
        if (wemu_cpu_deliver_exception(cpu, (unsigned)v) == 0) return 1;
        return -1;
    }
    WemuInsn in;
    memset(&in, 0, sizeof in);
    if (wemu_decode(cpu, &in) != 0) {
        int v = in.fault ? in.fault : cpu->fault;
        if (v) cpu->fault = v;            /* latch decode faults too */
        if (v && wemu_cpu_deliver_exception(cpu, (unsigned)v) == 0) return 1;
        return -1;
    }
    /* syscall is handled here so the hook sees architectural state */
    uint32_t full = in.op | ((uint32_t)(in.vex[0] >> 4) << 8);
    if (full == 0x105 && !in.vex_len) {
        uint64_t args[6] = { cpu->r[7], cpu->r[6], cpu->r[2],
                             cpu->r[10], cpu->r[8], cpu->r[9] };
        int64_t rv = cpu->sys_fn ? cpu->sys_fn(cpu, cpu->r[0], args, cpu->sys_ud)
                               : default_syscall(cpu, cpu->r[0], args);
        cpu->r[0] = (uint64_t)rv;
        cpu->rip += in.len;
        return 1;
    }
    uint64_t insn_rip = cpu->rip;
    int er = wemu_exec(cpu, &in);
    /* Memory faults latched inside exec (read_rm/write_rm ignore the
     * helper's return) must still reach delivery, and must save the
     * faulting instruction's RIP — not the advanced RIP of a completed
     * instruction. */
    if (cpu->fault) {
        cpu->rip = insn_rip;
        if (wemu_cpu_deliver_exception(cpu, (unsigned)cpu->fault) == 0)
            return 1;
        return -1;
    }
    if (er != 0) return -1;
    return 1;
}

int64_t wemu_cpu_run(WemuCpu *cpu, uint64_t max_insns) {
    int64_t n = 0;
    /* Don't pre-gate on cpu->fault: a host-raised fault must reach step()
     * so it can be delivered to a registered handler.  With no handler
     * step() returns -1 and the loop breaks — the old stopping behaviour. */
    while ((uint64_t)n < max_insns && !cpu->halted) {
        if (wemu_cpu_step(cpu) < 0) break;
        n++;
    }
    return n;
}