/* test_isa_atomic_fence.c — differential gate for the CMPXCHG8B/16B and
 * fence/PAUSE increments.
 *
 *  (1) API-stable probe runs against the PRE-CHANGE emulator too: 0F C7 /1
 *      in both widths and LFENCE/MFENCE/SFENCE/PAUSE must execute without
 *      #UD. It FAILS on the old build (all reached the #UD tail) and is
 *      the negative control for the whole gate.
 *
 *  (2) With WEMU_HAS_CX8_FENCE_PAUSE: randomized differential of both CAS
 *      widths against a byte-wise C oracle written from the SDM, itself
 *      cross-checked against the HOST CPU via inline asm; plus execution
 *      counts proving the hints really executed and mis-encoding #UDs. */
#include "wemu.h"
#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(cond, msg) do { if (!(cond)) { \
    printf("FAIL: %s (line %d)\n", msg, __LINE__); fails++; } } while (0)

#define RAMSZ (1u << 20)
#define CODE  0x1000u
#define DATA  0x2000u
#define ZF_BIT 0x40ull

static WemuCpu *boot(void) {
    WemuCpu *c = wemu_cpu_create(RAMSZ);
    wemu_cpu_set_rip(c, CODE);
    wemu_cpu_set_rsp(c, 0x80000);
    return c;
}
typedef struct { uint8_t b[64]; int n; } Code;
static void e(Code *k, uint8_t x) { if (k->n < 64) k->b[k->n++] = x; }
static void e32(Code *k, uint64_t v) {
    for (int i = 0; i < 4; i++) e(k, (uint8_t)(v >> (8 * i)));
}
static void emit_bytes(Code *k, const uint8_t *p, int n) {
    for (int i = 0; i < n; i++) e(k, p[i]);
}
/* 0F C7 /1, absolute memory operand: mod=00 reg=001 rm=100(SIB),
 * SIB=0x25 (no index, base=101) -> disp32 is the address in 64-bit mode. */
static void emit_cx(Code *k, int wide, int lock) {
    if (lock) e(k, 0xF0);
    if (wide) e(k, 0x48);   /* REX.W: 64-bit -> CMPXCHG16B */
    e(k, 0x0F); e(k, 0xC7);
    e(k, 0x0C); e(k, 0x25);
    e32(k, DATA);
}
static void setmem(WemuCpu *c, const uint8_t *src, int n) {
    wemu_mem_write(c, DATA, src, (size_t)n);
}

/* ---------------- (1) API-stable negative-control probe -------------- */
static void check_probe(void) {
    static const char *names[4] = { "LFENCE", "MFENCE", "SFENCE", "PAUSE" };
    /* Independent encoding check: host `as` emits 0F AE E8/F0/F8 and F3 90. */
    static const uint8_t hint[4][3] = {
        { 0x0F, 0xAE, 0xE8 }, { 0x0F, 0xAE, 0xF0 },
        { 0x0F, 0xAE, 0xF8 }, { 0xF3, 0x90 }
    };
    static const int hlen[4] = { 3, 3, 3, 2 };
    for (int i = 0; i < 4; i++) {
        Code k = {0};
        emit_bytes(&k, hint[i], hlen[i]); e(&k, 0xF4);
        WemuCpu *c = boot();
        wemu_cpu_load(c, CODE, k.b, (size_t)k.n);
        int64_t s = wemu_cpu_step(c);
        CHECK(s == 1 && wemu_cpu_fault(c) == 0, names[i]);
        wemu_cpu_destroy(c);
    }
    for (int wide = 0; wide < 2; wide++) {
        Code k = {0};
        emit_cx(&k, wide, 0); e(&k, 0xF4);
        WemuCpu *c = boot();
        wemu_cpu_load(c, CODE, k.b, (size_t)k.n);
        uint8_t zero[16] = {0};
        setmem(c, zero, 16);
        int64_t s = wemu_cpu_step(c);
        CHECK(s == 1 && wemu_cpu_fault(c) == 0,
              wide ? "CMPXCHG16B executes" : "CMPXCHG8B executes");
        wemu_cpu_destroy(c);
    }
}

#ifdef WEMU_HAS_CX8_FENCE_PAUSE
static void getmem(WemuCpu *c, uint8_t *dst, int n) {
    wemu_mem_read(c, DATA, dst, (size_t)n);
}

/* ---------------- (2a) byte-wise C oracle from the SDM ---------------- */
typedef struct {
    uint8_t mem[16];
    uint64_t rax, rdx, rbx, rcx;
    uint8_t zf;
} Oracle;

static Oracle oracle_cx(const uint8_t mem[16], uint64_t rax, uint64_t rdx,
                        uint64_t rbx, uint64_t rcx, int wide) {
    Oracle o;
    memset(&o, 0, sizeof o);
    /* Model the whole 16-byte buffer: bytes outside the operand must stay
     * untouched (the gate compares all 16 to catch an 8/16-byte overrun). */
    memcpy(o.mem, mem, 16);
    o.rax = rax; o.rdx = rdx; o.rbx = rbx; o.rcx = rcx;
    uint64_t lo, hi;
    if (wide) {
        memcpy(&lo, mem, 8); memcpy(&hi, mem + 8, 8);
    } else {
        /* m64 halves are at offsets 0 and 4, NOT 0 and 8. */
        uint32_t l32, h32;
        memcpy(&l32, mem, 4); memcpy(&h32, mem + 4, 4);
        lo = l32; hi = h32;
        rax &= 0xffffffffu; rdx &= 0xffffffffu;
    }
    int eq = (rax == lo) && (rdx == hi);
    o.zf = (uint8_t)eq;
    if (eq) {
        if (wide) {
            memcpy(o.mem, &rbx, 8); memcpy(o.mem + 8, &rcx, 8);
        } else {
            uint32_t b32 = (uint32_t)rbx, c32 = (uint32_t)rcx;
            memcpy(o.mem, &b32, 4); memcpy(o.mem + 4, &c32, 4);
        }
    } else {
        o.rax = lo; o.rdx = hi;
    }
    return o;               /* RBX/RCX untouched; other flags not modelled */
}

/* The C oracle is validated against a second, non-C abstraction: the real
 * host CPU. setz goes to MEMORY so the compiler cannot overlap the ZF
 * output with the explicit RAX/RDX/RCX/RBX operands. */
typedef struct { uint64_t lo, hi; } __attribute__((aligned(16))) U128;

static uint8_t native_cx16(U128 *m, uint64_t *a, uint64_t *d,
                           uint64_t b, uint64_t c) {
    uint8_t zf;
    uint64_t aa = *a, dd = *d;
    __asm__ volatile("cmpxchg16b %0\n\tsetz %3"
                     : "+m"(*m), "+a"(aa), "+d"(dd), "=m"(zf)
                     : "b"(b), "c"(c) : "cc");
    *a = aa; *d = dd;
    return zf;
}
static uint8_t native_cx8(uint64_t *m, uint32_t *a, uint32_t *d,
                          uint32_t b, uint32_t c) {
    uint8_t zf;
    uint32_t aa = *a, dd = *d;
    __asm__ volatile("cmpxchg8b %0\n\tsetz %3"
                     : "+m"(*m), "+a"(aa), "+d"(dd), "=m"(zf)
                     : "b"(b), "c"(c) : "cc");
    *a = aa; *d = dd;
    return zf;
}
static int host_has_cx(void) {
    uint32_t a, b, c, d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                     : "a"(1u), "c"(0u));
    return (int)(((c >> 13) & 1u) && ((d >> 8) & 1u)); /* CX16 + CX8 */
}
static uint64_t rng(uint64_t *s) {
    uint64_t x = *s;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    *s = x;
    return x * 0x2545F4914F6CDD1Dull;
}

static void check_differential(int native_ok) {
    uint64_t seed = 0x9E3779B97F4A7C15ull;
    int cases = 0, cross = 0, oracle_bad = 0;
    for (int r = 0; r < 200; r++) {
        for (int wide = 0; wide < 2; wide++) {
            uint8_t mem[16];
            for (int i = 0; i < 16; i++) mem[i] = (uint8_t)rng(&seed);
            uint64_t rbx = rng(&seed), rcx = rng(&seed);
            uint64_t rax, rdx;
            if (r & 1) {                  /* force the equal path half the time */
                if (wide) {
                    memcpy(&rax, mem, 8); memcpy(&rdx, mem + 8, 8);
                } else {
                    uint32_t l32, h32;
                    memcpy(&l32, mem, 4); memcpy(&h32, mem + 4, 4);
                    rax = l32; rdx = h32;
                }
            } else { rax = rng(&seed); rdx = rng(&seed); }
            Oracle want = oracle_cx(mem, rax, rdx, rbx, rcx, wide);
            cases++;

            if (native_ok) {
                uint8_t nm[16]; memcpy(nm, mem, 16);
                uint8_t zf; uint64_t a = rax, d = rdx;
                if (wide) {
                    U128 u; memcpy(&u, nm, 16);
                    zf = native_cx16(&u, &a, &d, rbx, rcx);
                    memcpy(nm, &u, 16);
                } else {
                    uint64_t m; memcpy(&m, nm, 8);
                    uint32_t a32 = (uint32_t)rax, d32 = (uint32_t)rdx;
                    zf = native_cx8(&m, &a32, &d32,
                                    (uint32_t)rbx, (uint32_t)rcx);
                    memcpy(nm, &m, 8);
                    a = a32; d = d32;
                }
                if (memcmp(nm, want.mem, (size_t)(wide ? 16 : 8)) != 0 ||
                    a != want.rax || d != want.rdx || zf != want.zf) {
                    if (oracle_bad++ < 3)
                        printf("FAIL: host CPU != C oracle (wide=%d r=%d)\n",
                               wide, r);
                    fails++;
                }
                cross++;
            }

            /* STC first: CF=1 is our sentinel for "undefined flags kept". */
            Code k = {0};
            e(&k, 0xF9);
            emit_cx(&k, wide, (r & 4) != 0);
            e(&k, 0xF4);
            WemuCpu *c = boot();
            wemu_cpu_load(c, CODE, k.b, (size_t)k.n);
            setmem(c, mem, 16);
            wemu_cpu_set_reg(c, 0, rax);
            wemu_cpu_set_reg(c, 1, rcx);
            wemu_cpu_set_reg(c, 2, rdx);
            wemu_cpu_set_reg(c, 3, rbx);
            wemu_cpu_set_reg(c, 6, 0x123456789abcdef0ull);
            int64_t n = wemu_cpu_run(c, 2);   /* STC, then the CAS */
            if (n != 2 || wemu_cpu_fault(c) != 0) {
                if (fails < 6)
                    printf("FAIL: CAS step wide=%d r=%d n=%lld fault=%d\n",
                           wide, r, (long long)n, wemu_cpu_fault(c));
                fails++;
                wemu_cpu_destroy(c);
                continue;
            }
            uint8_t got[16]; getmem(c, got, 16);
            uint64_t fl = wemu_cpu_rflags(c);
            if (memcmp(got, want.mem, 16) != 0 ||
                wemu_cpu_reg(c, 0) != want.rax ||
                wemu_cpu_reg(c, 2) != want.rdx ||
                wemu_cpu_reg(c, 1) != rcx || wemu_cpu_reg(c, 3) != rbx ||
                ((fl & ZF_BIT) != 0) != (want.zf != 0) ||
                (fl & ~ZF_BIT) != 3ull ||      /* CF + reserved bit 1 kept */
                wemu_cpu_reg(c, 6) != 0x123456789abcdef0ull ||
                wemu_cpu_rip(c) != CODE + (uint64_t)k.n - 1) {
                if (fails < 6)
                    printf("FAIL: emulator != oracle (wide=%d r=%d "
                           "mem=%02x%02x rax=%llx rdx=%llx zf=%d)\n",
                           wide, r, got[0], got[1],
                           (unsigned long long)wemu_cpu_reg(c, 0),
                           (unsigned long long)wemu_cpu_reg(c, 2),
                           (int)((fl & ZF_BIT) != 0));
                fails++;
            }
            wemu_cpu_destroy(c);
        }
    }
    printf("differential: %d CMPXCHG8B/16B cases vs byte-wise C oracle; "
           "host-CPU cross-check=%d; mismatches=%d\n",
           cases, cross, fails);
}

/* ---- hints really executed (counts), not silently skipped ----------- */
static void check_hints(void) {
    struct H {
        const char *name; uint8_t b[3]; int len; WemuHintKind kind;
    } h[4] = {
        { "LFENCE", { 0x0F, 0xAE, 0xE8 }, 3, WEMU_HINT_LFENCE },
        { "MFENCE", { 0x0F, 0xAE, 0xF0 }, 3, WEMU_HINT_MFENCE },
        { "SFENCE", { 0x0F, 0xAE, 0xF8 }, 3, WEMU_HINT_SFENCE },
        { "PAUSE",  { 0xF3, 0x90, 0x00 }, 2, WEMU_HINT_PAUSE  }
    };
    Code k = {0};
    int total = 0;
    for (int i = 0; i < 4; i++) {
        emit_bytes(&k, h[i].b, h[i].len);
        total += h[i].len;
    }
    e(&k, 0xF4);                 /* HLT after the four hints */
    WemuCpu *c = boot();
    wemu_cpu_load(c, CODE, k.b, (size_t)k.n);
    wemu_cpu_set_reg(c, 0, 0x1111111111111111ull);
    wemu_cpu_set_reg(c, 1, 0x2222222222222222ull);
    wemu_cpu_set_reg(c, 2, 0x3333333333333333ull);
    wemu_cpu_set_reg(c, 3, 0x4444444444444444ull);
    uint64_t fl0 = wemu_cpu_rflags(c);
    for (int i = 0; i < WEMU_HINT_KINDS; i++)
        CHECK(wemu_cpu_hint_count(c, (WemuHintKind)i) == 0, "fresh hint count");

    int64_t n = wemu_cpu_run(c, 4);
    CHECK(n == 4 && wemu_cpu_fault(c) == 0, "four hints execute without #UD");
    CHECK(wemu_cpu_rip(c) == CODE + (uint64_t)total, "hints advance RIP exactly");
    for (int i = 0; i < 4; i++)
        CHECK(wemu_cpu_hint_count(c, h[i].kind) == 1, h[i].name);
    CHECK(wemu_cpu_reg(c, 0) == 0x1111111111111111ull &&
          wemu_cpu_reg(c, 1) == 0x2222222222222222ull &&
          wemu_cpu_reg(c, 2) == 0x3333333333333333ull &&
          wemu_cpu_reg(c, 3) == 0x4444444444444444ull &&
          wemu_cpu_rflags(c) == fl0, "hints are no-ops on guest state");
    CHECK(!wemu_cpu_halted(c) && wemu_cpu_step(c) == 1 &&
          wemu_cpu_halted(c), "HLT still reached after hints");
    printf("hints: LFENCE/MFENCE/SFENCE/PAUSE counts = %llu/%llu/%llu/%llu\n",
           (unsigned long long)wemu_cpu_hint_count(c, WEMU_HINT_LFENCE),
           (unsigned long long)wemu_cpu_hint_count(c, WEMU_HINT_MFENCE),
           (unsigned long long)wemu_cpu_hint_count(c, WEMU_HINT_SFENCE),
           (unsigned long long)wemu_cpu_hint_count(c, WEMU_HINT_PAUSE));
    wemu_cpu_destroy(c);
}

/* ---- CMPXCHG8B/16B are implicitly bus-locked ------------------------- */
typedef struct { int pre, post; } Obs;
static void observer(WemuCpu *cpu, uint64_t va, int bytes,
                     WemuAtomicPhase phase, void *ud) {
    (void)cpu; (void)va; (void)bytes;
    Obs *o = (Obs *)ud;
    if (phase == WEMU_ATOMIC_PRE_WRITE) o->pre++; else o->post++;
}
static void check_implicit_lock(void) {
    for (int wide = 0; wide < 2; wide++) {
        Code k = {0}; emit_cx(&k, wide, 0); e(&k, 0xF4);
        WemuCpu *c = boot();
        wemu_cpu_load(c, CODE, k.b, (size_t)k.n);
        uint8_t z[16] = {0}; setmem(c, z, 16);
        Obs o = {0, 0};
        wemu_cpu_set_atomic_observer(c, observer, &o);
        CHECK(wemu_cpu_step(c) == 1 && wemu_cpu_fault(c) == 0,
              "implicit-lock CAS executes");
        CHECK(o.post == 1 && o.pre == 0,
              "CAS observer serialized POST (implicit LOCK), never PRE");
        wemu_cpu_destroy(c);
    }
}

/* ---- malformed encodings stay honest #UD ---------------------------- */
static void check_reject(void) {
    struct { const char *name; uint8_t b[9]; int n; } t[] = {
        { "LOCK MFENCE #UD",     { 0xF0,0x0F,0xAE,0xF0,0xF4 }, 5 },
        { "register CX8 #UD",    { 0x0F,0xC7,0xC8,0xF4 }, 4 },
        { "0F AE /4 #UD",        { 0x0F,0xAE,0xE4,0xF4 }, 4 }
    };
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
        WemuCpu *c = boot();
        wemu_cpu_load(c, CODE, t[i].b, (size_t)t[i].n);
        CHECK(wemu_cpu_step(c) == -1 && wemu_cpu_fault(c) == 6, t[i].name);
        wemu_cpu_destroy(c);
    }
    /* 0F C7 /0 with a memory operand is not CMPXCHG8B -> #UD */
    Code k = {0};
    e(&k, 0x0F); e(&k, 0xC7); e(&k, 0x04); e(&k, 0x25); e32(&k, DATA);
    e(&k, 0xF4);
    WemuCpu *c = boot();
    wemu_cpu_load(c, CODE, k.b, (size_t)k.n);
    CHECK(wemu_cpu_step(c) == -1 && wemu_cpu_fault(c) == 6,
          "CMPXCHG8B wrong /digit #UD");
    wemu_cpu_destroy(c);
}
#endif /* WEMU_HAS_CX8_FENCE_PAUSE */

int main(void) {
    int native = 0;
#ifdef WEMU_HAS_CX8_FENCE_PAUSE
    native = host_has_cx();
#endif
    check_probe();                        /* old + new: negative control */
#ifdef WEMU_HAS_CX8_FENCE_PAUSE
    check_differential(native);
    check_hints();
    check_implicit_lock();
    check_reject();
#else
    printf("note: legacy build, new CAS/fence checks compiled out\n");
#endif
    if (fails) {
        printf("%d ISA ATOMIC/FENCE CHECK(S) FAILED\n", fails);
        return 1;
    }
    printf("ALL ISA ATOMIC/FENCE CHECKS PASS (native CX oracle: %s)\n",
           native ? "yes" : "no");
    return 0;
}
