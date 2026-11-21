/* sandbox_probe.c — freestanding static ET_EXEC guest for the WEMU native
 * user-mode sandbox differential gate.  No libc: a custom _start reads the
 * mode from argv[1] and issues raw syscalls so the gate controls every
 * argument exactly.
 *
 *   exec     : mmap(PROT_EXEC) with an IN-WINDOW hint but no MAP_FIXED.
 *              Pre-change WEMU admitted it (the hint looked in-window) and
 *              the kernel returned an executable page OUTSIDE the seccomp
 *              trap window; this probe then ran shellcode there.  Hardened
 *              WEMU refuses it and the shellcode never runs.
 *   mprotect : mprotect a page outside the image window to RWX.  Refused in
 *              both versions (regression guard, not the differential).
 *   ptr      : write(1, 0xDEAD0000, 4) — an out-of-range guest pointer.
 *              Hardened WEMU fails closed with WEMU_UM_ERR_BADPTR and no
 *              host write; pre-change WEMU handed it to the host kernel.
 *   brk      : ask for 1 GiB of heap growth above the initial break.
 *              Hardened WEMU bounds brk and returns the current break.
 *
 * License: WaefreBeorn Umbrella License v3.0. */
#include <stddef.h>
#include <stdint.h>

#define SYS_WRITE  1
#define SYS_BRK    12
#define SYS_MMAP   9
#define SYS_MPROTECT 10
#define SYS_EXIT_GROUP 231

#define PROT_READ  1
#define PROT_WRITE 2
#define PROT_EXEC  4
#define MAP_PRIVATE   0x02
#define MAP_ANONYMOUS 0x20
#define MAP_FIXED     0x10

static inline long sc6(long n, long a1, long a2, long a3,
                       long a4, long a5, long a6) {
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    register long r9  __asm__("r9")  = a6;
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a1), "S"(a2), "d"(a3),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
}

static size_t slen(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static void out(const char *s) {
    (void)sc6(SYS_WRITE, 1, (long)s, (long)slen(s), 0, 0, 0);
}

/* Print a 64-bit value in hex without libc. */
static void out_hex(uint64_t v) {
    char b[19];
    static const char d[] = "0123456789abcdef";
    b[0] = '0'; b[1] = 'x';
    for (int i = 0; i < 16; i++) b[2 + i] = d[(v >> (60 - 4 * i)) & 15];
    b[18] = '\n';
    (void)sc6(SYS_WRITE, 1, (long)b, 18, 0, 0, 0);
}

static void out_dec(long v) {
    char b[24];
    int n = 0;
    unsigned long u = v < 0 ? (unsigned long)(-(v + 1)) + 1 : (unsigned long)v;
    if (v < 0) b[n++] = '-';
    char tmp[20];
    int k = 0;
    do { tmp[k++] = (char)('0' + (u % 10)); u /= 10; } while (u);
    while (k) b[n++] = tmp[--k];
    b[n++] = '\n';
    (void)sc6(SYS_WRITE, 1, (long)b, n, 0, 0, 0);
}

static void bye(int code) {
    (void)sc6(SYS_EXIT_GROUP, code, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

/* Written into by the shellcode below; proves it actually ran. */
static volatile uint64_t shellcode_ran;

/* Build and invoke a tiny stub at an arbitrary executable address.  The
 * stub writes 0xC0FFEE to shellcode_ran (absolute address, no relocations)
 * and returns, so the gate can distinguish "shellcode ran" from "refused". */
typedef void (*fn)(void);
static void run_stub(uint64_t p) {
    uint8_t code[32];
    int n = 0;
    code[n++] = 0x48; code[n++] = 0xb8;              /* movabs rax,imm64 */
    for (int i = 0; i < 8; i++) code[n++] = (uint8_t)(0xC0FFEEull >> (8 * i));
    code[n++] = 0x48; code[n++] = 0xba;              /* movabs rdx,addr64 */
    for (int i = 0; i < 8; i++) code[n++] = (uint8_t)((uint64_t)&shellcode_ran >> (8 * i));
    code[n++] = 0x48; code[n++] = 0x89; code[n++] = 0x02; /* mov [rdx],rax */
    code[n++] = 0xc3;                                /* ret */
    uint8_t *dst = (uint8_t *)(uintptr_t)p;
    for (int i = 0; i < n; i++) dst[i] = code[i];
    ((fn)(uintptr_t)p)();
}

/* Initial stack pointer captured before any C prologue touches RSP. */
extern const char _start[];             /* defined by the asm stub below */
uintptr_t *wemu_sp;
__asm__(".globl _start\n"
        "_start:\n"
        "  mov %rsp, wemu_sp(%rip)\n"
        "  and $-16, %rsp\n"
        "  call guest_main\n"
        "  mov %eax, %edi\n"
        "  mov $231, %eax\n"          /* exit_group(return value) */
        "  syscall\n");

void guest_main(void) {   /* called by the asm _start; must keep this name */
    uint64_t argc = wemu_sp[0];
    char **argv = (char **)(wemu_sp + 1);
    const char *mode = (argc > 1 && argv[1]) ? argv[1] : "exec";

    if (mode[0] == 'e') {                 /* exec: mmap RWX, in-window hint */
        uint64_t hint = (uint64_t)(uintptr_t)&_start & ~0xfffull;
        long p = sc6(SYS_MMAP, (long)hint, 0x1000,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p < 0) {
            out("MMAP-REFUSED\n");
            out_dec(p);
            bye(0);
        }
        out("MMAP-ADMITTED\n");
        out_hex((uint64_t)p);
        run_stub((uint64_t)p);
        if (shellcode_ran == 0xC0FFEEull) out("SHELLCODE-RAN\n");
        else out("SHELLCODE-BLOCKED\n");
        bye(0);
    }
    if (mode[0] == 'm') {                 /* mprotect RWX outside the image */
        uint64_t page = 0x600000ull;
        long r = sc6(SYS_MMAP, (long)page, 0x1000, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (r < 0) { out("MPROTECT-SETUP-FAIL\n"); out_dec(r); bye(2); }
        long rc = sc6(SYS_MPROTECT, (long)page, 0x1000,
                      PROT_READ | PROT_WRITE | PROT_EXEC, 0, 0, 0);
        if (rc < 0) out("MPROTECT-REFUSED\n");
        else out("MPROTECT-ADMITTED\n");
        bye(0);
    }
    if (mode[0] == 'p') {                 /* out-of-range write buffer */
        (void)sc6(SYS_WRITE, 1, 0xDEAD0000ull, 4, 0, 0, 0);
        out("PTR-WRITE-RETURNED\n");       /* only reachable if not refused */
        bye(0);
    }
    if (mode[0] == 'b') {                 /* unbounded brk growth */
        long cur = sc6(SYS_BRK, 0, 0, 0, 0, 0, 0);
        out("BRK-CUR="); out_hex((uint64_t)cur);
        long rc = sc6(SYS_BRK, cur + 0x40000000ull, 0, 0, 0, 0, 0);
        out("BRK-RC="); out_hex((uint64_t)rc);
        if (rc == cur) out("BRK-BOUNDED\n");
        else out("BRK-GREW\n");
        bye(0);
    }
    out("UNKNOWN-MODE\n");
    bye(3);
}
