/* test_usermode — WEMU user-mode ELF gate.
 * 1. A hand-built static freestanding ELF (raw write+exit syscalls)
 *    loads, runs, writes the exact bytes to serial, exits 42.
 * 2. .bss zeroing + SysV stack layout (argc/argv/auxv) are asserted.
 * 3. FS/GS segment bases: TLS loads add the base, LEA does not.
 * 4. endbr64 / multi-byte NOP / tzcnt / lzcnt behave (C oracle).
 * 5. REAL static busybox parses and runs to its first syscall with a
 *    plausible Linux nr — proof the loader handles a real-world ELF.
 *    (Full applet output is the wubuos bridge gate, L14 phase 2.) */
#include "wemu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define FAIL(...) do { fprintf(stderr, "FAIL: " __VA_ARGS__); exit(1); } while (0)

/* ---- serial capture ---- */
static char ser[4096];
static size_t ser_n;
static void ser_out(uint8_t b, void *ud) {
    (void)ud;
    if (ser_n < sizeof ser - 1) ser[ser_n++] = (char)b;
}

/* ---- tiny static ELF builder ----
 * layout: [ehdr][1 phdr R: headers @0x400000][pad to 0x1000]
 *         [code+msg @0x401000, R E][bss segment @0x402000 RW, mem>file]
 * code: write(1, msg, 11); exit(42) via raw syscalls. */
static size_t build_tiny_elf(uint8_t *img, size_t cap) {
    const uint64_t base = 0x400000, code_va = 0x401000, bss_va = 0x402000;
    const char msg[] = "hello-wemu\n";
    uint8_t code[64];
    size_t n = 0;
    /* mov eax,1 ; mov edi,1 ; lea rsi,[rip+msg] ; mov edx,11 ; syscall */
    code[n++] = 0xB8; code[n++] = 1; code[n++] = 0; code[n++] = 0; code[n++] = 0;
    code[n++] = 0xBF; code[n++] = 1; code[n++] = 0; code[n++] = 0; code[n++] = 0;
    code[n++] = 0x48; code[n++] = 0x8D; code[n++] = 0x35; /* lea rsi,[rip+d] */
    size_t disp_at = n; n += 4;
    code[n++] = 0xBA; code[n++] = 11; code[n++] = 0; code[n++] = 0; code[n++] = 0;
    code[n++] = 0x0F; code[n++] = 0x05;
    /* mov eax,60 ; mov edi,42 ; syscall */
    code[n++] = 0xB8; code[n++] = 60; code[n++] = 0; code[n++] = 0; code[n++] = 0;
    code[n++] = 0xBF; code[n++] = 42; code[n++] = 0; code[n++] = 0; code[n++] = 0;
    code[n++] = 0x0F; code[n++] = 0x05;
    size_t msg_off = n;
    int32_t disp = (int32_t)(msg_off - (disp_at + 4));
    memcpy(code + disp_at, &disp, 4);
    memcpy(code + n, msg, sizeof msg - 1);
    n += sizeof msg - 1;

    memset(img, 0, cap);
    /* Elf64_Ehdr */
    img[0] = 0x7F; img[1] = 'E'; img[2] = 'L'; img[3] = 'F';
    img[4] = 2; img[5] = 1; img[6] = 1;             /* class64, LSB, ver */
    uint16_t type = 2, mach = 62, phentsz = 56;
    uint32_t ver = 1, flags = 0;
    uint64_t entry = code_va, phoff = 64;
    uint16_t ehsize = 64, phnum = 3;
    memcpy(img + 16, &type, 2); memcpy(img + 18, &mach, 2);
    memcpy(img + 20, &ver, 4); memcpy(img + 24, &entry, 8);
    memcpy(img + 32, &phoff, 8); memcpy(img + 40, &flags, 4);
    memcpy(img + 52, &ehsize, 2); memcpy(img + 54, &phentsz, 2);
    memcpy(img + 56, &phnum, 2);
    /* phdr 0: R, headers themselves at base */
    size_t p = 64;
    uint32_t t = 1, fl = 4; uint64_t off = 0, va = base, fsz = 120, msz = 120, al = 0x1000;
    memcpy(img + p, &t, 4); memcpy(img + p + 4, &fl, 4);
    memcpy(img + p + 8, &off, 8); memcpy(img + p + 16, &va, 8);
    memcpy(img + p + 24, &va, 8); memcpy(img + p + 32, &fsz, 8);
    memcpy(img + p + 40, &msz, 8); memcpy(img + p + 48, &al, 8);
    /* phdr 1: R E, code at 0x401000 (file offset 0x1000) */
    p += 56; fl = 5; off = 0x1000; va = code_va; fsz = msz = n;
    memcpy(img + p, &t, 4); memcpy(img + p + 4, &fl, 4);
    memcpy(img + p + 8, &off, 8); memcpy(img + p + 16, &va, 8);
    memcpy(img + p + 24, &va, 8); memcpy(img + p + 32, &fsz, 8);
    memcpy(img + p + 40, &msz, 8); memcpy(img + p + 48, &al, 8);
    /* phdr 2: RW at 0x402000, filesz 8, memsz 0x100 (.bss tail) */
    p += 56; fl = 6; off = 0x2000; va = bss_va; fsz = 8; msz = 0x100;
    memcpy(img + p, &t, 4); memcpy(img + p + 4, &fl, 4);
    memcpy(img + p + 8, &off, 8); memcpy(img + p + 16, &va, 8);
    memcpy(img + p + 24, &va, 8); memcpy(img + p + 32, &fsz, 8);
    memcpy(img + p + 40, &msz, 8); memcpy(img + p + 48, &al, 8);
    memcpy(img + 0x1000, code, n);
    memset(img + 0x2000, 0xA5, 8);   /* .data seed; .bss tail must be 0 */
    return 0x2100;
}

static void test_tiny_elf(void) {
    uint8_t img[0x3000];
    size_t len = build_tiny_elf(img, sizeof img);
    WemuMachine *m = wemu_machine_create(0x1000000, ser_out, NULL);
    if (!m) FAIL("machine create\n");
    WemuCpu *cpu = wemu_machine_cpu(m);
    char *argv[] = { "tiny", "arg1", NULL };
    if (wemu_cpu_load_elf(cpu, NULL, img, len, argv) != 0)
        FAIL("load_elf tiny\n");
    /* .bss zeroed, .data kept */
    uint8_t b = 0;
    wemu_mem_read(cpu, 0x402000, &b, 1);
    if (b != 0xA5) FAIL("data seed: %02x\n", b);
    wemu_mem_read(cpu, 0x402008, &b, 1);
    if (b != 0) FAIL("bss not zero: %02x\n", b);
    wemu_mem_read(cpu, 0x4020FF, &b, 1);
    if (b != 0) FAIL("bss tail not zero: %02x\n", b);
    /* SysV stack: argc, argv[0] -> "tiny", auxv has AT_PAGESZ=4096 */
    uint64_t rsp = wemu_cpu_reg(cpu, 4), v = 0;
    if (rsp & 0xF) FAIL("rsp not 16-aligned: %llx\n", (unsigned long long)rsp);
    wemu_mem_read(cpu, rsp, &v, 8);
    if (v != 2) FAIL("argc=%llu\n", (unsigned long long)v);
    wemu_mem_read(cpu, rsp + 8, &v, 8);
    char s[16] = {0};
    wemu_mem_read(cpu, v, s, 4);
    if (strcmp(s, "tiny") != 0) FAIL("argv[0]=%s\n", s);
    int found_pagesz = 0;
    uint64_t auxv_at = rsp + 8 + (2 + 1) * 8 + 8; /* argc,argv+NULL,envp NULL */
    for (uint64_t a = auxv_at; a < auxv_at + 512; a += 16) {
        uint64_t kv[2];
        wemu_mem_read(cpu, a, kv, 16);
        if (kv[0] == 0) break;
        if (kv[0] == 6 && kv[1] == 4096) found_pagesz = 1;
    }
    if (!found_pagesz) FAIL("no AT_PAGESZ=4096 in auxv\n");
    /* run: default hook routes write->serial, exit halts */
    ser_n = 0;
    int64_t n = wemu_cpu_run(cpu, 100000);
    if (n < 0 || !wemu_cpu_halted(cpu) || wemu_cpu_fault(cpu))
        FAIL("tiny run: n=%lld fault=%d\n", (long long)n, wemu_cpu_fault(cpu));
    ser[ser_n] = 0;
    if (strcmp(ser, "hello-wemu\n") != 0) FAIL("serial=%s\n", ser);
    if (wemu_cpu_reg(cpu, 0) != 42) FAIL("exit code %llu\n",
        (unsigned long long)wemu_cpu_reg(cpu, 0));
    if (wemu_cpu_elf_brk(cpu) != 0x403000) FAIL("elf_brk=%llx\n",
        (unsigned long long)wemu_cpu_elf_brk(cpu));
    wemu_machine_destroy(m);
    printf("ok: tiny static ELF write+exit(42), bss, SysV stack\n");
}

static void test_segments(void) {
    WemuCpu *cpu = wemu_cpu_create(0x100000);
    wemu_cpu_set_fs_base(cpu, 0x80000);
    wemu_cpu_set_gs_base(cpu, 0x90000);
    uint64_t v = 0x1122334455667788ull;
    wemu_mem_write(cpu, 0x80000 + 0x28, &v, 8);
    v = 0x99;
    wemu_mem_write(cpu, 0x90000 + 0x10, &v, 8);
    /* mov rax, fs:[0x28] ; mov rbx, gs:[0x10] ; lea rcx, fs:[0x28] */
    uint8_t code[] = {
        0x64, 0x48, 0x8B, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00,
        0x65, 0x48, 0x8B, 0x1C, 0x25, 0x10, 0x00, 0x00, 0x00,
        0x64, 0x48, 0x8D, 0x0C, 0x25, 0x28, 0x00, 0x00, 0x00,
        0xF4,
    };
    wemu_cpu_load(cpu, 0x1000, code, sizeof code);
    wemu_cpu_set_rip(cpu, 0x1000);
    wemu_cpu_run(cpu, 100);
    if (wemu_cpu_fault(cpu)) FAIL("seg fault %d\n", wemu_cpu_fault(cpu));
    if (wemu_cpu_reg(cpu, 0) != 0x1122334455667788ull) FAIL("fs load\n");
    if (wemu_cpu_reg(cpu, 3) != 0x99) FAIL("gs load\n");
    if (wemu_cpu_reg(cpu, 1) != 0x28) FAIL("lea must ignore fs base\n");
    if (wemu_cpu_fs_base(cpu) != 0x80000 || wemu_cpu_gs_base(cpu) != 0x90000)
        FAIL("base getters\n");
    wemu_cpu_destroy(cpu);
    printf("ok: FS/GS TLS bases (load adds base, LEA does not)\n");
}

static void test_cet_nop_bmi(void) {
    WemuCpu *cpu = wemu_cpu_create(0x10000);
    /* endbr64 ; nopl 0x0(%rax,%rax,1) ; tzcnt rax,rcx ; lzcnt rdx,rcx ; hlt */
    uint8_t code[] = {
        0xF3, 0x0F, 0x1E, 0xFA,
        0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xF3, 0x48, 0x0F, 0xBC, 0xC1,
        0xF3, 0x48, 0x0F, 0xBD, 0xD1,
        0xF4,
    };
    wemu_cpu_load(cpu, 0x1000, code, sizeof code);
    wemu_cpu_set_rip(cpu, 0x1000);
    /* differential over several inputs vs C oracle */
    uint64_t inputs[] = { 0, 1, 0x8000000000000000ull, 0x1234567890ABCDEFull, 0x100 };
    for (size_t i = 0; i < sizeof inputs / sizeof inputs[0]; i++) {
        uint64_t x = inputs[i];
        wemu_cpu_set_reg(cpu, 1, x);
        wemu_cpu_set_rip(cpu, 0x1000);
        /* 4 instructions: endbr64, nopl, tzcnt, lzcnt (no hlt: the cpu
         * stays runnable for the next differential input) */
        for (int k = 0; k < 4; k++) {
            if (wemu_cpu_step(cpu) < 0) FAIL("cet/bmi fault %d\n",
                wemu_cpu_fault(cpu));
        }
        uint64_t tz = 64, lz = 64;
        if (x) {
            tz = 0; while (!((x >> tz) & 1)) tz++;
            lz = 0; while (!((x >> (63 - lz)) & 1)) lz++;
        }
        if (wemu_cpu_reg(cpu, 0) != tz) FAIL("tzcnt(%llx)=%llu want %llu\n",
            (unsigned long long)x, (unsigned long long)wemu_cpu_reg(cpu, 0),
            (unsigned long long)tz);
        if (wemu_cpu_reg(cpu, 2) != lz) FAIL("lzcnt(%llx)=%llu want %llu\n",
            (unsigned long long)x, (unsigned long long)wemu_cpu_reg(cpu, 2),
            (unsigned long long)lz);
        uint64_t f = wemu_cpu_rflags(cpu);
        if ((f & 1) != (x == 0 ? 1 : 0)) FAIL("tzcnt CF for %llx\n",
            (unsigned long long)x);
    }
    wemu_cpu_destroy(cpu);
    printf("ok: endbr64/multi-byte NOP/tzcnt/lzcnt vs C oracle\n");
}

static void test_near_jcc_rel32(void) {
    /* the busybox-found decoder bug: 0F 8x jcc rel32 has NO ModRM.
     * Differential: taken and not-taken must land on exact bytes. */
    WemuCpu *cpu = wemu_cpu_create(0x10000);
    /* 0x1000: xor eax,eax (ZF=1) ; je rel32 -> 0x1020 ; mov eax,1 ; hlt
     * 0x1020: mov eax,7 ; hlt */
    uint8_t code[] = {
        0x31, 0xC0,
        0x0F, 0x84, 0x14, 0x00, 0x00, 0x00,   /* je +0x14 -> 0x1020 */
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xF4,
    };
    wemu_cpu_load(cpu, 0x1000, code, sizeof code);
    uint8_t tgt[] = { 0xB8, 0x07, 0x00, 0x00, 0x00, 0xF4 };
    wemu_cpu_load(cpu, 0x1020, tgt, sizeof tgt);
    wemu_cpu_set_rip(cpu, 0x1000);
    wemu_cpu_run(cpu, 10);
    if (wemu_cpu_reg(cpu, 0) != 7) FAIL("jcc rel32 taken: eax=%llu\n",
        (unsigned long long)wemu_cpu_reg(cpu, 0));
    /* not taken: cmp eax,1 (ZF=0) then je over the mov (fresh cpu: the
     * first one halted) */
    wemu_cpu_destroy(cpu);
    cpu = wemu_cpu_create(0x10000);
    uint8_t code2[] = {
        0x83, 0xF8, 0x01,                     /* cmp eax,1 */
        0x0F, 0x84, 0x05, 0x00, 0x00, 0x00,   /* je +5 -> skip mov */
        0xB8, 0x09, 0x00, 0x00, 0x00,         /* mov eax,9 */
        0xF4,
    };
    wemu_cpu_load(cpu, 0x1100, code2, sizeof code2);
    wemu_cpu_set_reg(cpu, 0, 0);
    wemu_cpu_set_rip(cpu, 0x1100);
    wemu_cpu_run(cpu, 10);
    if (wemu_cpu_reg(cpu, 0) != 9) FAIL("jcc rel32 not-taken: eax=%llu\n",
        (unsigned long long)wemu_cpu_reg(cpu, 0));
    wemu_cpu_destroy(cpu);
    printf("ok: near jcc rel32 taken/not-taken (no ModRM)\n");
}

static void test_grp1_imm8(void) {
    /* the busybox-found gap: 80 /r ib (grp1 imm8) must consume its imm.
     * and $0x80,%ch with two CH values, vs C oracle. */
    WemuCpu *cpu = wemu_cpu_create(0x10000);
    uint8_t code[] = { 0x80, 0xE5, 0x80, 0xF4 }; /* and ch,0x80 ; hlt */
    wemu_cpu_load(cpu, 0x1000, code, sizeof code);
    uint64_t inputs[] = { 0x0000, 0x8000, 0x1280, 0xFF00 };
    for (size_t i = 0; i < sizeof inputs / sizeof inputs[0]; i++) {
        WemuCpu *c2 = wemu_cpu_create(0x10000);
        wemu_cpu_load(c2, 0x1000, code, sizeof code);
        wemu_cpu_set_rip(c2, 0x1000);
        wemu_cpu_set_reg(c2, 1, inputs[i]);
        wemu_cpu_run(c2, 4);
        if (wemu_cpu_fault(c2)) FAIL("grp1 imm8 fault %d\n",
            wemu_cpu_fault(c2));
        uint64_t ch = (inputs[i] >> 8) & 0xff;
        uint64_t want = ch & 0x80;
        uint64_t got = (wemu_cpu_reg(c2, 1) >> 8) & 0xff;
        if (got != want) FAIL("and ch,0x80: %llx -> %llx want %llx\n",
            (unsigned long long)inputs[i], (unsigned long long)got,
            (unsigned long long)want);
        if (((wemu_cpu_rflags(c2) & 0x40) != 0) != (want == 0))
            FAIL("grp1 imm8 ZF\n");
        wemu_cpu_destroy(c2);
    }
    wemu_cpu_destroy(cpu);
    printf("ok: grp1 imm8 (80 /r ib) length + CH semantics\n");
}

static void test_alu_imm8(void) {
    /* the busybox-found gap: accumulator imm8 forms (04/0C/.../3C)
     * must consume their immediate. cmp al,2 with AL=2 -> ZF=1, and
     * the following mov must execute intact (length differential). */
    WemuCpu *cpu = wemu_cpu_create(0x10000);
    uint8_t code[] = { 0x3C, 0x02, 0xB8, 0x07, 0x00, 0x00, 0x00, 0xF4 };
    wemu_cpu_load(cpu, 0x1000, code, sizeof code);
    wemu_cpu_set_rip(cpu, 0x1000);
    wemu_cpu_set_reg(cpu, 0, 2);
    wemu_cpu_run(cpu, 6);
    if (wemu_cpu_fault(cpu)) FAIL("cmp al,imm8 fault %d\n",
        wemu_cpu_fault(cpu));
    if (wemu_cpu_reg(cpu, 0) != 7) FAIL("cmp al,imm8 length: eax=%llu\n",
        (unsigned long long)wemu_cpu_reg(cpu, 0));
    if (!(wemu_cpu_rflags(cpu) & 0x40)) FAIL("cmp al,2 with al=2: ZF=0\n");
    wemu_cpu_destroy(cpu);
    printf("ok: accumulator imm8 (cmp al,ib) length + flags\n");
}

static void test_two_byte_not_string(void) {
    /* the strtol root cause: the string leaf matched low opcode bytes
     * and ate 0F AF (imul) as SCAS, 0F AB (bts) as STOS. Regression:
     * imul r,rm multiplies; bts sets a bit without storing AL. */
    WemuCpu *cpu = wemu_cpu_create(0x10000);
    uint8_t code[] = {
        0xBF, 0x0A, 0x00, 0x00, 0x00,             /* mov edi,10 */
        0x4C, 0x63, 0xFF,                         /* movslq edi,r15 */
        0xBE, 0x07, 0x00, 0x00, 0x00,             /* mov esi,7 */
        0x49, 0x0F, 0xAF, 0xF7,                   /* imul r15,rsi -> 70 */
        0x48, 0x0F, 0xAB, 0xFE,                   /* bts rsi,rdi (bit10) */
        0xF4,
    };
    wemu_cpu_load(cpu, 0x1000, code, sizeof code);
    wemu_cpu_set_rip(cpu, 0x1000);
    wemu_cpu_run(cpu, 10);
    if (wemu_cpu_fault(cpu)) FAIL("two-byte/string fault %d\n",
        wemu_cpu_fault(cpu));
    if (wemu_cpu_reg(cpu, 6) != (70 | (1ull << 10)))
        FAIL("imul r,rm / bts: rsi=%llx want %llx\n",
             (unsigned long long)wemu_cpu_reg(cpu, 6),
             (unsigned long long)(70 | (1ull << 10)));
    wemu_cpu_destroy(cpu);
    printf("ok: 0F AF imul / 0F AB bts not eaten by string leaf\n");
}

static void test_xchg_rax(void) {
    /* busybox-found gap: 90+r is xchg rAX,r (only 90 without REX.B is
     * nop). 64- and 32-bit forms, vs C oracle. */
    WemuCpu *cpu = wemu_cpu_create(0x10000);
    uint8_t code64[] = { 0x48, 0x93, 0xF4 };       /* xchg rax,rbx */
    wemu_cpu_load(cpu, 0x1000, code64, sizeof code64);
    wemu_cpu_set_rip(cpu, 0x1000);
    wemu_cpu_set_reg(cpu, 0, 0x1111222233334444ull);
    wemu_cpu_set_reg(cpu, 3, 0xAAAA5555AAAA5555ull);
    wemu_cpu_run(cpu, 4);
    if (wemu_cpu_reg(cpu, 0) != 0xAAAA5555AAAA5555ull ||
        wemu_cpu_reg(cpu, 3) != 0x1111222233334444ull)
        FAIL("xchg rax,rbx 64\n");
    wemu_cpu_destroy(cpu);
    cpu = wemu_cpu_create(0x10000);
    uint8_t code32[] = { 0x93, 0xF4 };             /* xchg eax,ebx */
    wemu_cpu_load(cpu, 0x1000, code32, sizeof code32);
    wemu_cpu_set_rip(cpu, 0x1000);
    wemu_cpu_set_reg(cpu, 0, 0xFFFFFFFF00000001ull);
    wemu_cpu_set_reg(cpu, 3, 0xFFFFFFFF00000002ull);
    wemu_cpu_run(cpu, 4);
    if (wemu_cpu_reg(cpu, 0) != 2 || wemu_cpu_reg(cpu, 3) != 1)
        FAIL("xchg eax,ebx 32 zero-extend: rax=%llx rbx=%llx\n",
             (unsigned long long)wemu_cpu_reg(cpu, 0),
             (unsigned long long)wemu_cpu_reg(cpu, 3));
    wemu_cpu_destroy(cpu);
    printf("ok: xchg rAX,r 64/32 (90+r, nop only for plain 90)\n");
}

static void test_xadd(void) {
    /* lock xadd %eax,(%rbx): memory += reg, reg <- old memory.
     * Differential vs C oracle incl. wrap (CF) and sign overflow. */
    struct { uint64_t rm, reg; int bytes; } cases[] = {
        { 5, 3, 4 }, { 0xFFFFFFFF, 1, 4 }, { 0x7FFFFFFF, 1, 4 },
        { 5, 3, 8 }, { ~0ull, 1, 8 }, { 0x7FFFFFFFFFFFFFFFull, 1, 8 },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        WemuCpu *cpu = wemu_cpu_create(0x10000);
        uint64_t v = cases[i].rm;
        wemu_mem_write(cpu, 0x2000, &v, 8);
        uint8_t code[40];
        int n = 0;
        if (cases[i].bytes == 4) {
            code[n++]=0xB8; uint32_t g32=(uint32_t)cases[i].reg;
            memcpy(code+n,&g32,4); n+=4;
            code[n++]=0xF0; code[n++]=0x0F; code[n++]=0xC1; code[n++]=0x05;
        } else {
            code[n++]=0x48; code[n++]=0xB8; uint64_t g64=cases[i].reg;
            memcpy(code+n,&g64,8); n+=8;
            code[n++]=0xF0; code[n++]=0x48; code[n++]=0x0F; code[n++]=0xC1; code[n++]=0x05;
        }
        int32_t d = (int32_t)(0x2000 - (0x1000 + n + 4));
        memcpy(code+n,&d,4); n+=4;
        code[n++]=0xF4;
        wemu_cpu_load(cpu, 0x1000, code, (size_t)n);
        wemu_cpu_set_rip(cpu, 0x1000);
        wemu_cpu_run(cpu, 6);
        if (wemu_cpu_fault(cpu)) FAIL("xadd fault %d case %zu\n",
            wemu_cpu_fault(cpu), i);
        int bits = cases[i].bytes * 8;
        uint64_t mask = bits >= 64 ? ~0ull : ((1ull << bits) - 1);
        uint64_t want_mem = (cases[i].rm + cases[i].reg) & mask;
        uint64_t got_mem = 0;
        wemu_mem_read(cpu, 0x2000, &got_mem, 8);
        got_mem &= mask;
        if (got_mem != want_mem) FAIL("xadd mem case %zu: %llx want %llx\n",
            i, (unsigned long long)got_mem, (unsigned long long)want_mem);
        if ((wemu_cpu_reg(cpu, 0) & mask) != (cases[i].rm & mask))
            FAIL("xadd reg case %zu\n", i);
        int cf = (wemu_cpu_rflags(cpu) & 1) != 0;
        int want_cf = bits >= 64
            ? (cases[i].rm + cases[i].reg < cases[i].rm)
            : ((cases[i].rm & mask) + (cases[i].reg & mask) > mask);
        if (cf != want_cf) FAIL("xadd CF case %zu\n", i);
        wemu_cpu_destroy(cpu);
    }
    printf("ok: (lock) xadd 32/64 wrap/overflow vs C oracle\n");
}

static void test_cmpxchg(void) {
    /* glibc malloc's lll_lock: lock cmpxchg %edx,(%rbx). Differential
     * vs C oracle: equal and unequal, 32/64-bit, reg and memory. */
    struct { uint64_t rax, rm, reg; int bytes; } cases[] = {
        { 5, 5, 9, 4 }, { 5, 7, 9, 4 }, { 5, 5, 9, 8 }, { 5, 7, 9, 8 },
        { 0xFFFFFFFF00000000ull, 0xFFFFFFFF00000000ull, 1, 4 },
        { 0x123456789ABCDEFull, 0x123456789ABCDEF0ull, 0x11, 8 },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        WemuCpu *cpu = wemu_cpu_create(0x10000);
        /* mov [0x2000], rm-init via store: use mov rax,imm; mov [rip],rax
         * simpler: write guest RAM directly, then cmpxchg [0x2000], reg */
        uint64_t v = cases[i].rm;
        wemu_mem_write(cpu, 0x2000, &v, 8);
        uint8_t code[40];
        int n = 0;
        if (cases[i].bytes == 4) {
            /* mov eax, imm32 ; mov edx, imm32 ; lock cmpxchg [rip+d], edx */
            code[n++]=0xB8; uint32_t a32=(uint32_t)cases[i].rax;
            memcpy(code+n,&a32,4); n+=4;
            code[n++]=0xBA; uint32_t g32=(uint32_t)cases[i].reg;
            memcpy(code+n,&g32,4); n+=4;
            code[n++]=0xF0; code[n++]=0x0F; code[n++]=0xB1; code[n++]=0x15;
            int32_t d = (int32_t)(0x2000 - (0x1000 + n + 4));
            memcpy(code+n,&d,4); n+=4;
        } else {
            code[n++]=0x48; code[n++]=0xB8; uint64_t a64=cases[i].rax;
            memcpy(code+n,&a64,8); n+=8;
            code[n++]=0x48; code[n++]=0xBA; uint64_t g64=cases[i].reg;
            memcpy(code+n,&g64,8); n+=8;
            code[n++]=0xF0; code[n++]=0x48; code[n++]=0x0F; code[n++]=0xB1; code[n++]=0x15;
            int32_t d = (int32_t)(0x2000 - (0x1000 + n + 4));
            memcpy(code+n,&d,4); n+=4;
        }
        code[n++]=0xF4;
        wemu_cpu_load(cpu, 0x1000, code, (size_t)n);
        wemu_cpu_set_rip(cpu, 0x1000);
        wemu_cpu_run(cpu, 10);
        if (wemu_cpu_fault(cpu)) FAIL("cmpxchg fault %d case %zu\n",
            wemu_cpu_fault(cpu), i);
        uint64_t want_mem = cases[i].rax == cases[i].rm
                          ? cases[i].reg : cases[i].rm;
        uint64_t want_rax = cases[i].rax == cases[i].rm
                          ? cases[i].rax : cases[i].rm;
        if (cases[i].bytes == 4) {
            want_mem &= 0xffffffffull;
            want_rax &= 0xffffffffull;
        }
        uint64_t got_mem = 0;
        wemu_mem_read(cpu, 0x2000, &got_mem, 8);
        if (cases[i].bytes == 4) got_mem &= 0xffffffffull;
        if (got_mem != want_mem) FAIL("cmpxchg mem case %zu: %llx want %llx\n",
            i, (unsigned long long)got_mem, (unsigned long long)want_mem);
        if (wemu_cpu_reg(cpu, 0) != want_rax)
            FAIL("cmpxchg rax case %zu: %llx want %llx\n", i,
                 (unsigned long long)wemu_cpu_reg(cpu, 0),
                 (unsigned long long)want_rax);
        int zf = (wemu_cpu_rflags(cpu) & 0x40) != 0;
        if (zf != (cases[i].rax == cases[i].rm))
            FAIL("cmpxchg ZF case %zu\n", i);
        wemu_cpu_destroy(cpu);
    }
    printf("ok: (lock) cmpxchg 32/64 equal/unequal vs C oracle\n");
}

/* ---- real busybox: run to first syscall ---- */
static uint64_t first_nr = ~0ull;
static int64_t probe_hook(WemuCpu *cpu, uint64_t nr,
                          const uint64_t args[6], void *ud) {
    (void)cpu; (void)args; (void)ud;
    first_nr = nr;
    return 0;
}

static void test_real_busybox(void) {
    const char *path = getenv("WEMU_BUSYBOX");
    if (!path) path = "/home/wubu/opt/busybox-static/usr/bin/busybox";
    WemuCpu *cpu = wemu_cpu_create(64ull << 20);
    if (!cpu) FAIL("cpu create 64MB\n");
    char *argv[] = { "busybox", "echo", "gate", NULL };
    if (wemu_cpu_load_elf(cpu, path, NULL, 0, argv) != 0)
        FAIL("load real busybox %s\n", path);
    wemu_cpu_set_syscall_hook(cpu, probe_hook, NULL);
    int64_t n = 0;
    while (first_nr == ~0ull && n < 20000000) {
        if (wemu_cpu_step(cpu) < 0) break;
        n++;
    }
    if (wemu_cpu_fault(cpu))
        FAIL("busybox fault vec=%d rip=%llx after %lld insns\n",
             wemu_cpu_fault(cpu), (unsigned long long)wemu_cpu_rip(cpu),
             (long long)n);
    if (first_nr == ~0ull) FAIL("busybox: no syscall in %lld insns\n",
        (long long)n);
    /* glibc static startup opens with brk(0) (malloc init); other
     * plausible openers across glibc versions: arch_prctl,
     * set_tid_address, set_robust_list, rseq, mmap, getrandom. */
    int plausible = first_nr == 12 || first_nr == 158 || first_nr == 218 ||
                    first_nr == 273 || first_nr == 334 || first_nr == 9 ||
                    first_nr == 318;
    if (!plausible) FAIL("implausible first syscall nr=%llu\n",
        (unsigned long long)first_nr);
    printf("ok: real busybox loaded, first syscall nr=%llu after %lld insns\n",
           (unsigned long long)first_nr, (long long)n);
    wemu_cpu_destroy(cpu);
}

int main(void) {
    test_tiny_elf();
    test_segments();
    test_cet_nop_bmi();
    test_near_jcc_rel32();
    test_grp1_imm8();
    test_alu_imm8();
    test_two_byte_not_string();
    test_xchg_rax();
    test_xadd();
    test_cmpxchg();
    test_real_busybox();
    printf("USERMODE GATE PASS\n");
    return 0;
}