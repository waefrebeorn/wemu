/* test_lock_atomics.c — LOCK-prefix gate. Two parts:
 *
 *  (1) API-stable probe: LOCK on a non-lockable instruction must raise #UD.
 *      This part compiles and runs against the PRE-FIX emulator too, where
 *      it FAILS (the old decoder silently discarded 0xF0): it is the
 *      negative control for the whole gate.
 *
 *  (2) With WEMU_HAS_LOCK_ATOMICS: functional LOCK XCHG / CMPXCHG /
 *      ADD / AND / OR / XADD results, plus a differential atomicity check
 *      driven by a competing-agent observer. A non-LOCK RMW loses the
 *      agent's update (PRE interleave); a LOCK RMW keeps it (POST,
 *      serialized after the indivisible RMW). */
#include "wemu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;
#define CHECK(cond, msg) do { if (!(cond)) { \
    printf("FAIL: %s (line %d)\n", msg, __LINE__); fails++; } } while (0)

#define RAMSZ  (1u << 20)
#define CODE   0x1000u
#define DATA   0x2000u
#define CNT    0x3000u

static WemuCpu *boot(void) {
    WemuCpu *c = wemu_cpu_create(RAMSZ);
    wemu_cpu_set_rip(c, CODE);
    wemu_cpu_set_rsp(c, 0x80000);
    return c;
}

#ifdef WEMU_HAS_LOCK_ATOMICS
typedef struct { uint8_t b[128]; int n; } Code;
static void e(Code *k, uint8_t x) { if (k->n < 128) k->b[k->n++] = x; }
static void e32(Code *k, uint64_t v) {
    for (int i = 0; i < 4; i++) e(k, (uint8_t)(v >> (8 * i)));
}
/* absolute [addr] in 64-bit mode: mod=00, rm=100(SIB), SIB base=101 */
static void absrm(Code *k, uint8_t reg, uint64_t addr) {
    e(k, (uint8_t)(0x04 | ((reg & 7) << 3)));
    e(k, 0x25);
    e32(k, addr);
}
static void load(WemuCpu *c, const Code *k) {
    wemu_cpu_load(c, CODE, k->b, (size_t)k->n);
}
static uint64_t mem64(WemuCpu *c, uint64_t addr) {
    uint64_t v = 0;
    wemu_mem_read(c, addr, &v, 8);
    return v;
}
static void setmem64(WemuCpu *c, uint64_t addr, uint64_t v) {
    wemu_mem_write(c, addr, &v, 8);
}
#endif /* WEMU_HAS_LOCK_ATOMICS */

/* ---------------- (1) API-stable negative-control probe ---------------- */
static void check_lock_rejection(void) {
    /* F0 01 D8 : LOCK ADD EAX, EBX — register destination, LOCK illegal. */
    {
        uint8_t code[] = { 0xF0, 0x01, 0xD8, 0xF4 };
        WemuCpu *c = boot();
        wemu_cpu_load(c, CODE, code, sizeof code);
        int64_t n = wemu_cpu_step(c);
        CHECK(n == -1 && wemu_cpu_fault(c) == 6,
              "LOCK ADD reg,reg must raise #UD");
        wemu_cpu_destroy(c);
    }
    /* F0 89 D8 : LOCK MOV EAX, EBX — not an RMW, LOCK illegal. */
    {
        uint8_t code[] = { 0xF0, 0x89, 0xD8, 0xF4 };
        WemuCpu *c = boot();
        wemu_cpu_load(c, CODE, code, sizeof code);
        int64_t n = wemu_cpu_step(c);
        CHECK(n == -1 && wemu_cpu_fault(c) == 6,
              "LOCK MOV must raise #UD");
        wemu_cpu_destroy(c);
    }
    /* F0 38 D8 : LOCK CMP EAX, EBX — CMP is never lockable. */
    {
        uint8_t code[] = { 0xF0, 0x38, 0xD8, 0xF4 };
        WemuCpu *c = boot();
        wemu_cpu_load(c, CODE, code, sizeof code);
        int64_t n = wemu_cpu_step(c);
        CHECK(n == -1 && wemu_cpu_fault(c) == 6,
              "LOCK CMP must raise #UD");
        wemu_cpu_destroy(c);
    }
    /* control: the same ops WITHOUT LOCK execute cleanly. */
    {
        /* 01 D8: EAX += EBX -> 7; 89 C3: EBX = EAX (leaves EAX=7) */
        uint8_t code[] = { 0x01, 0xD8, 0x89, 0xC3, 0xF4 };
        WemuCpu *c = boot();
        wemu_cpu_load(c, CODE, code, sizeof code);
        wemu_cpu_set_reg(c, 0, 3);
        wemu_cpu_set_reg(c, 3, 4);
        int64_t n = wemu_cpu_run(c, 10);
        CHECK(n >= 0 && wemu_cpu_fault(c) == 0, "plain ADD/MOV must not fault");
        CHECK(wemu_cpu_reg(c, 0) == 7, "plain ADD result");
        wemu_cpu_destroy(c);
    }
}

#ifdef WEMU_HAS_LOCK_ATOMICS
/* ---------------- (2a) functional LOCK RMW semantics ------------------- */
static void check_functional(void) {
    /* LOCK XCHG [DATA], RAX : mem=0x11, RAX=0x22 -> mem=0x22, RAX=0x11 */
    {
        Code k = {0};
        e(&k, 0xF0); e(&k, 0x48); e(&k, 0x87); absrm(&k, 0, DATA);
        WemuCpu *c = boot(); load(c, &k);
        setmem64(c, DATA, 0x11); wemu_cpu_set_reg(c, 0, 0x22);
        int64_t n = wemu_cpu_step(c);
        CHECK(n == 1 && wemu_cpu_fault(c) == 0, "LOCK XCHG executes");
        CHECK(mem64(c, DATA) == 0x22 && wemu_cpu_reg(c, 0) == 0x11,
              "LOCK XCHG swaps memory and register");
        wemu_cpu_destroy(c);
    }
    /* implicit XCHG: no F0, still atomic (model marks it locked) */
    {
        Code k = {0};
        e(&k, 0x48); e(&k, 0x87); absrm(&k, 0, DATA);
        WemuCpu *c = boot(); load(c, &k);
        setmem64(c, DATA, 0x11); wemu_cpu_set_reg(c, 0, 0x22);
        wemu_cpu_step(c);
        CHECK(mem64(c, DATA) == 0x22 && wemu_cpu_reg(c, 0) == 0x11,
              "memory XCHG without F0 still swaps");
        wemu_cpu_destroy(c);
    }
    /* LOCK CMPXCHG [DATA], RCX : RAX==mem -> write RCX, ZF=1 */
    {
        Code k = {0};
        e(&k, 0xF0); e(&k, 0x48); e(&k, 0x0F); e(&k, 0xB1);
        absrm(&k, 1, DATA); /* reg=RCX */
        WemuCpu *c = boot(); load(c, &k);
        setmem64(c, DATA, 0x33);
        wemu_cpu_set_reg(c, 0, 0x33); wemu_cpu_set_reg(c, 1, 0x99);
        int64_t n = wemu_cpu_step(c);
        CHECK(n == 1 && wemu_cpu_fault(c) == 0, "LOCK CMPXCHG executes");
        CHECK(mem64(c, DATA) == 0x99, "LOCK CMPXCHG equal writes reg");
        CHECK((wemu_cpu_rflags(c) & 0x40) != 0, "LOCK CMPXCHG equal sets ZF");
        wemu_cpu_destroy(c);
    }
    /* LOCK CMPXCHG mismatch : RAX != mem -> RAX=mem, ZF=0, mem unchanged */
    {
        Code k = {0};
        e(&k, 0xF0); e(&k, 0x48); e(&k, 0x0F); e(&k, 0xB1);
        absrm(&k, 1, DATA);
        WemuCpu *c = boot(); load(c, &k);
        setmem64(c, DATA, 0x44);
        wemu_cpu_set_reg(c, 0, 0x33); wemu_cpu_set_reg(c, 1, 0x99);
        wemu_cpu_step(c);
        CHECK(mem64(c, DATA) == 0x44 && wemu_cpu_reg(c, 0) == 0x44,
              "LOCK CMPXCHG mismatch loads accumulator");
        CHECK((wemu_cpu_rflags(c) & 0x40) == 0, "LOCK CMPXCHG mismatch clears ZF");
        wemu_cpu_destroy(c);
    }
    /* LOCK ADD / AND / OR [DATA], RAX */
    {
        struct { uint8_t op; uint64_t m, r, want; const char *name; } t[] = {
            { 0x01, 3,       5,       8,        "ADD" },
            { 0x21, 0xF0ull, 0x3Cull, 0x30ull,  "AND" },
            { 0x09, 0x30ull, 0x0Full, 0x3Full,  "OR"  }
        };
        for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
            Code k = {0};
            e(&k, 0xF0); e(&k, 0x48); e(&k, t[i].op); absrm(&k, 0, DATA);
            WemuCpu *c = boot(); load(c, &k);
            setmem64(c, DATA, t[i].m); wemu_cpu_set_reg(c, 0, t[i].r);
            int64_t n = wemu_cpu_step(c);
            CHECK(n == 1 && wemu_cpu_fault(c) == 0, "LOCK grp1 executes");
            if (mem64(c, DATA) != t[i].want) {
                printf("FAIL: LOCK %s got %llx want %llx\n", t[i].name,
                       (unsigned long long)mem64(c, DATA),
                       (unsigned long long)t[i].want);
                fails++;
            }
            wemu_cpu_destroy(c);
        }
    }
    /* LOCK XADD [DATA], RAX : mem=7, RAX=5 -> mem=12, RAX=7 */
    {
        Code k = {0};
        e(&k, 0xF0); e(&k, 0x48); e(&k, 0x0F); e(&k, 0xC1);
        absrm(&k, 0, DATA);
        WemuCpu *c = boot(); load(c, &k);
        setmem64(c, DATA, 7); wemu_cpu_set_reg(c, 0, 5);
        wemu_cpu_step(c);
        CHECK(mem64(c, DATA) == 12 && wemu_cpu_reg(c, 0) == 7,
              "LOCK XADD result");
        wemu_cpu_destroy(c);
    }
}

/* ---------------- (2b) differential atomicity -------------------------- */
typedef struct { int calls; int phases[2]; } Obs;

/* A second hardware agent that increments the same counter once. */
static void competing_agent(WemuCpu *cpu, uint64_t va, int bytes,
                            WemuAtomicPhase phase, void *ud) {
    Obs *o = (Obs *)ud;
    o->calls++;
    o->phases[phase]++;
    uint64_t v = 0;
    if (wemu_mem_read(cpu, va, &v, (size_t)bytes) != 0) return;
    v += 1;
    wemu_mem_write(cpu, va, &v, (size_t)bytes);
}

static uint64_t counter_rmw(int locked, Obs *o) {
    Code k = {0};
    if (locked) e(&k, 0xF0);
    e(&k, 0x48); e(&k, 0x01);          /* REX.W ADD r/m64, r64 */
    absrm(&k, 0, CNT);                 /* [CNT], RAX */
    WemuCpu *c = boot(); load(c, &k);
    wemu_cpu_set_reg(c, 0, 1);         /* RAX = 1: our increment */
    setmem64(c, CNT, 0);
    wemu_cpu_set_atomic_observer(c, competing_agent, o);
    int64_t n = wemu_cpu_step(c);
    CHECK(n == 1 && wemu_cpu_fault(c) == 0, "counter RMW step");
    uint64_t v = mem64(c, CNT);
    wemu_cpu_destroy(c);
    return v;
}

static void check_differential(void) {
    Obs a = {0}, b = {0};
    uint64_t nonatomic = counter_rmw(0, &a);
    uint64_t atomic    = counter_rmw(1, &b);

    printf("differential: plain ADD=%llu (agent calls=%d), "
           "LOCK ADD=%llu (agent calls=%d)\n",
           (unsigned long long)nonatomic, a.calls,
           (unsigned long long)atomic, b.calls);

    CHECK(a.calls == 1 && a.phases[WEMU_ATOMIC_PRE_WRITE] == 1,
          "non-LOCK RMW interleaves agent at PRE_WRITE");
    CHECK(b.calls == 1 && b.phases[WEMU_ATOMIC_POST_WRITE] == 1,
          "LOCK RMW serializes agent at POST_WRITE");
    CHECK(nonatomic == 1, "non-atomic RMW loses the agent's update (lost update)");
    CHECK(atomic == 2, "LOCK RMW retains both increments");
    CHECK(atomic != nonatomic, "LOCK and non-LOCK are observably different");
}
#endif /* WEMU_HAS_LOCK_ATOMICS */

int main(void) {
    check_lock_rejection();            /* runs against old + new emulator */
#ifdef WEMU_HAS_LOCK_ATOMICS
    check_functional();
    check_differential();
#else
    printf("note: legacy build, new LOCK checks compiled out\n");
#endif
    if (fails) {
        printf("%d LOCK-ATOMICS CHECK(S) FAILED\n", fails);
        return 1;
    }
    printf("ALL LOCK-ATOMICS CHECKS PASS\n");
    return 0;
}
