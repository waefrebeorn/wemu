/* test_rep_fault_restart.c — host-CPU differential gate for REP string
 * instructions interrupted by a fault mid-count.
 *
 * The SDM requires a faulting REP string instruction to be restartable:
 * the count and index registers must reflect the iterations that COMPLETED
 * before the fault, so re-execution after the fault is resolved resumes at
 * the right element instead of replaying the whole count.  Intel SDM Vol 2B
 * 4-562, "REP—Repeat String Operation (Prefix)" (verbatim):
 *   "A repeating string operation can be suspended by an exception or
 *    interrupt. ... The source and destination registers point to the next
 *    string elements to be operated on, the EIP register points to the
 *    string instruction, and the ECX register has the value it held
 *    following the last successful iteration of the instruction."
 * Its Operation pseudocode decrements CountReg AFTER executing the
 * associated string instruction, so the faulting iteration is not counted.
 * Primary SDM PDF:
 *   https://cdrdv2-public.intel.com/825743/325462-sdm-vol-1-2abcd-3abcd-4.pdf
 *
 * Oracle: the HOST x86-64 CPU runs the real instruction against a guard
 * page; a SA_SIGINFO handler reads the precise fault-state GPRs out of
 * ucontext.  WEMU runs the same guest bytes against the end of its guest
 * RAM buffer.  RCX, RSI, RDI, RAX, RFLAGS and the touched bytes are compared.
 */
#define _GNU_SOURCE
#include "wemu.h"
#include "wemu_internal.h"
#include <inttypes.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

#define G_CODE 0x500ull
#define G_RAM  0x2000ull       /* guest RAM ends here: the "guard page" */
#define FLAG_MASK (WF_CF | WF_PF | WF_AF | WF_ZF | WF_SF | WF_OF | 0x400u)

static sigjmp_buf jb;
static struct cap {
    uint64_t rcx, rsi, rdi, rax, rflags, fault_addr, rip;
    int sig;
} cap;

static void on_segv(int sig, siginfo_t *si, void *uc_) {
    ucontext_t *uc = (ucontext_t *)uc_;
    cap.sig = sig;
    cap.rcx = (uint64_t)uc->uc_mcontext.gregs[REG_RCX];
    cap.rsi = (uint64_t)uc->uc_mcontext.gregs[REG_RSI];
    cap.rdi = (uint64_t)uc->uc_mcontext.gregs[REG_RDI];
    cap.rax = (uint64_t)uc->uc_mcontext.gregs[REG_RAX];
    cap.rflags = (uint64_t)uc->uc_mcontext.gregs[REG_EFL];
    cap.rip = (uint64_t)uc->uc_mcontext.gregs[REG_RIP];
    cap.fault_addr = (uint64_t)(uintptr_t)si->si_addr;
    siglongjmp(jb, 1);
}

/* One host runner per string instruction; the instruction is fixed at
 * compile time so the oracle never executes a different opcode than the
 * guest bytes under test.  Registers are loaded INSIDE the asm because the
 * fault state is read from ucontext, not from C variables. */
#define HOST_REP(name, insn)                                                  \
static void name(int df, uint64_t rsi, uint64_t rdi, uint64_t rcx,            \
                 uint64_t rax, int *faulted) {                                \
    memset(&cap, 0, sizeof cap);                                              \
    if (sigsetjmp(jb, 1) == 0) {                                              \
        __asm__ volatile(                                                     \
            "mov %[a], %%rax\n\t"                                             \
            "mov %[c], %%rcx\n\t"                                             \
            "mov %[si], %%rsi\n\t"                                            \
            "mov %[di], %%rdi\n\t"                                            \
            "push %[fi]\n\t popfq\n\t"                                        \
            "rep " insn "\n\t"                                               \
            "cld\n\t"                                                         \
            :                                                                 \
            : [a] "r"(rax), [c] "r"(rcx), [si] "r"(rsi), [di] "r"(rdi),       \
              [fi] "r"((uint64_t)2 | (df ? 0x400u : 0u))                      \
            : "rax", "rcx", "rsi", "rdi", "cc", "memory");                    \
        *faulted = 0;                                                         \
    } else {                                                                  \
        *faulted = 1;                                                         \
    }                                                                         \
}

HOST_REP(h_stosb, "stosb")
HOST_REP(h_stosw, "stosw")
HOST_REP(h_stosd, "stosl")
HOST_REP(h_stosq, "stosq")
HOST_REP(h_movsb, "movsb")
HOST_REP(h_movsq, "movsq")

typedef void (*host_fn)(int, uint64_t, uint64_t, uint64_t, uint64_t, int *);
static const host_fn hosts[6] = {
    h_stosb, h_stosw, h_stosd, h_stosq, h_movsb, h_movsq
};
static const char *names[6] = {
    "stosb", "stosw", "stosd", "stosq", "movsb", "movsq"
};
static const int widths[6] = { 1, 2, 4, 8, 1, 8 };
/* AA is ALWAYS byte STOS; AB is the opsize-sensitive STOS (66=word,
 * default=dword, REX.W=qword); A5 is the matching opsize-sensitive MOVS. */
static const uint8_t codes[6][4] = {
    { 0xF3, 0xAA, 0, 0 },       /* stosb     */
    { 0xF3, 0x66, 0xAB, 0 },    /* stosw     */
    { 0xF3, 0xAB, 0, 0 },       /* stosd     */
    { 0xF3, 0x48, 0xAB, 0 },    /* stosq     */
    { 0xF3, 0xA4, 0, 0 },       /* movsb     */
    { 0xF3, 0x48, 0xA5, 0 },    /* movsq     */
};
static const int codelens[6] = { 2, 3, 2, 3, 2, 3 };

static int fails;
static void fail(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap); va_end(ap);
    fails++;
}

static void one(int k, int df, uint8_t *hdata, uint64_t ps) {
    int bytes = widths[k];
    uint64_t count = 8, rax = 0x5a5a5a5a5a5a5a5aull;
    /* Both sides: two full elements before a guard page.  DF=0 faults on
     * the write past the high boundary; DF=1 on the write below the low
     * boundary.  Host: 3-page guard/data/guard mapping.  WEMU: guest RAM
     * [0,G_RAM), data page at its high end (DF=0) or low end (DF=1). */
    uint64_t gbase = df ? 0 : G_RAM - ps;
    uint64_t h_start = df ? (uint64_t)(uintptr_t)(hdata + bytes)
                          : (uint64_t)(uintptr_t)(hdata + ps - 2 * (uint64_t)bytes);
    uint64_t g_start = gbase + (df ? (uint64_t)bytes : ps - 2 * (uint64_t)bytes);
    /* MOVS destination stays inside the data page, far from both guards. */
    uint64_t h_rsi = h_start, h_rdi = (k >= 4) ? (uint64_t)(uintptr_t)(hdata + 0x400) : h_start;
    uint64_t g_rsi = g_start, g_rdi = (k >= 4) ? gbase + 0x400 : g_start;

    int faulted;
    hosts[k](df, h_rsi, h_rdi, count, rax, &faulted);
    if (!faulted || cap.sig != SIGSEGV) {
        fail("HOST %s df=%d: expected SIGSEGV mid-REP, got faulted=%d sig=%d\n",
             names[k], df, faulted, cap.sig);
        return;
    }
    uint64_t hsnap_addr = df ? (uint64_t)(uintptr_t)hdata
                             : (uint64_t)(uintptr_t)(hdata + ps - 32);
    uint8_t hsnap[32];
    memcpy(hsnap, (const void *)(uintptr_t)hsnap_addr, 32);

    WemuCpu *c = wemu_cpu_create(G_RAM);
    /* Same byte pattern on both sides (slot i holds i*7+11), so untouched
     * bytes compare exactly and only REP-written bytes may differ. */
    for (uint64_t i = 0; i < ps; i++) {
        uint8_t pat = (uint8_t)(i * 7 + 11);
        uint64_t dst = df ? i : G_RAM - ps + i;
        if (wemu_mem_write(c, dst, &pat, 1)) {
            fail("guest data load\n"); wemu_cpu_destroy(c); return;
        }
    }
    uint8_t code[8];
    memcpy(code, codes[k], (size_t)codelens[k]);
    code[codelens[k]] = 0xF4;
    if (wemu_cpu_load(c, G_CODE, code, (size_t)codelens[k] + 1)) {
        fail("guest code load failed\n"); wemu_cpu_destroy(c); return;
    }
    c->rflags = 2 | (df ? 0x400u : 0u);
    wemu_cpu_set_rip(c, G_CODE);
    wemu_cpu_set_reg(c, 0, rax);
    wemu_cpu_set_reg(c, 1, count);
    wemu_cpu_set_reg(c, 6, g_rsi);
    wemu_cpu_set_reg(c, 7, g_rdi);
    wemu_cpu_run(c, 8);

    uint8_t gsnap[32];
    uint64_t gsnap_addr = df ? 0 : G_RAM - 32;
    wemu_mem_read(c, gsnap_addr, gsnap, 32);

    uint64_t e_rcx = wemu_cpu_reg(c, 1);
    uint64_t e_rsi = wemu_cpu_reg(c, 6);
    uint64_t e_rdi = wemu_cpu_reg(c, 7);
    uint64_t e_rax = wemu_cpu_reg(c, 0);
    uint64_t e_fl = wemu_cpu_rflags(c) & FLAG_MASK;
    uint64_t h_fl = cap.rflags & FLAG_MASK;
    if (e_rcx != cap.rcx)
        fail("RCX %s df=%d: emu=%" PRIu64 " host=%" PRIu64 "\n",
             names[k], df, e_rcx, cap.rcx);
    if (e_rsi - g_rsi != cap.rsi - h_rsi)
        fail("RSI %s df=%d: emu delta=%" PRId64 " host delta=%" PRId64 "\n",
             names[k], df, (int64_t)(e_rsi - g_rsi),
             (int64_t)(cap.rsi - h_rsi));
    if (e_rdi - g_rdi != cap.rdi - h_rdi)
        fail("RDI %s df=%d: emu delta=%" PRId64 " host delta=%" PRId64 "\n",
             names[k], df, (int64_t)(e_rdi - g_rdi),
             (int64_t)(cap.rdi - h_rdi));
    if (e_rax != cap.rax)
        fail("RAX %s df=%d: emu=%016" PRIx64 " host=%016" PRIx64 "\n",
             names[k], df, e_rax, cap.rax);
    if (e_fl != h_fl)
        fail("FLAGS %s df=%d: emu=%04" PRIx64 " host=%04" PRIx64 "\n",
             names[k], df, e_fl, h_fl);
    if (memcmp(gsnap, hsnap, 32)) {
        size_t i;
        for (i = 0; i < 32; i++) if (gsnap[i] != hsnap[i]) break;
        fail("MEM %s df=%d: byte %zu emu=%02x host=%02x\n",
             names[k], df, i, gsnap[i], hsnap[i]);
    }
    wemu_cpu_destroy(c);
}

int main(void) {
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) { fprintf(stderr, "sysconf(_SC_PAGESIZE) failed\n"); return 1; }
    /* guard | data | guard: one page of mapped bytes with faults on both
     * ends, so DF=0 and DF=1 are both real guard-page faults on the host. */
    uint8_t *base = mmap(NULL, (size_t)ps * 3, PROT_NONE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) { perror("mmap"); return 1; }
    uint8_t *data = base + ps;
    if (mprotect(data, (size_t)ps, PROT_READ | PROT_WRITE)) {
        perror("mprotect"); return 1;
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGSEGV, &sa, NULL)) { perror("sigaction"); return 1; }

    unsigned rounds = 0;
    for (int df = 0; df < 2; df++)
        for (int k = 0; k < 6; k++) {
            /* fresh, deterministic data bytes before every case */
            for (long i = 0; i < ps; i++) data[i] = (uint8_t)(i * 7 + 11);
            one(k, df, data, (uint64_t)ps);
            rounds++;
        }
    if (fails) {
        fprintf(stderr, "test_rep_fault_restart: %d FAILURES of %u rounds\n",
                fails, rounds);
        return 1;
    }
    printf("test_rep_fault_restart: PASS (%u host-fault differential rounds, "
           "REP STOS/MOVS 8/16/32/64, DF both ways)\n", rounds);
    return 0;
}
