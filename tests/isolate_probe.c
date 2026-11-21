/* isolate_probe.c — freestanding static ET_EXEC guest for the WEMU
 * process-per-guest address-space-isolation differential gate.  No libc: a
 * custom _start reads mode + a hex address from argv and issues raw syscalls
 * so the gate controls every argument exactly.
 *
 *   valid : write(1, in-image buffer, 16)  — legal guest pointer, must pass.
 *   arena : write(1, argv[2], 16)          — pointer into the supervisor's
 *           MAP_SHARED guest arena; must pass (region validation accepts it),
 *           and the bytes are a marker the supervisor wrote before the run.
 *   oob   : write(1, argv[2], 16)          — out-of-region host pointer; the
 *           syscall pointer validator must refuse it (no host bytes).
 *   load  : two volatile 64-bit loads from argv[2] followed by a write of the
 *           loaded bytes.  A syscall validator CANNOT see this; the only way
 *           to stop it is to remove the host page from the guest process.
 *           Isolated guest faults (no bytes); a shared-address-space guest
 *           observes and prints the host bytes.
 *
 * License: WaefreBeorn Umbrella License v3.0. */
#include <stddef.h>
#include <stdint.h>

#define SYS_WRITE  1
#define SYS_EXIT_GROUP 231

static inline long sc3(long n, long a1, long a2, long a3) {
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a1), "S"(a2), "d"(a3)
                     : "rcx", "r11", "memory");
    return ret;
}

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

static void out(const void *buf, size_t n) {
    (void)sc3(SYS_WRITE, 1, (long)buf, (long)n);
}

static void bye(int code) {
    (void)sc3(SYS_EXIT_GROUP, code, 0, 0);
    __builtin_unreachable();
}

static uint64_t hexval(char c) {
    if (c >= '0' && c <= '9') return (uint64_t)(c - '0');
    if (c >= 'a' && c <= 'f') return (uint64_t)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (uint64_t)(c - 'A' + 10);
    return 0;
}

static uint64_t parse_hex(const char *s) {
    uint64_t v = 0;
    while (*s == '0' && s[1]) s++;
    while (*s) { v = (v << 4) | hexval(*s); s++; }
    return v;
}

/* Known 16-byte legal buffer, lives in the guest image (a registered range). */
static const char g_valid[16] = "GUEST-VALID-ABC!";

/* Initial stack pointer captured before any C prologue touches RSP. */
extern const char _start[];
uintptr_t *wemu_sp;
__asm__(".globl _start\n"
        "_start:\n"
        "  mov %rsp, wemu_sp(%rip)\n"
        "  and $-16, %rsp\n"
        "  call guest_main\n"
        "  mov %eax, %edi\n"
        "  mov $231, %eax\n"          /* exit_group(return value) */
        "  syscall\n");

void guest_main(void) {
    uint64_t argc = wemu_sp[0];
    char **argv = (char **)(wemu_sp + 1);
    const char *mode = (argc > 1 && argv[1]) ? argv[1] : "valid";
    uint64_t target = (argc > 2 && argv[2]) ? parse_hex(argv[2]) : 0;

    if (mode[0] == 'v') {                 /* valid in-image pointer */
        out(g_valid, 16);
        bye(0);
    }
    if (mode[0] == 'a') {                 /* MAP_SHARED arena pointer */
        out((const void *)(uintptr_t)target, 16);
        bye(0);
    }
    if (mode[0] == 'o') {                 /* out-of-region syscall pointer */
        (void)sc6(SYS_WRITE, 1, (long)target, 16, 0, 0, 0);
        bye(0);
    }
    if (mode[0] == 'l') {                 /* direct load of host bytes */
        volatile uint64_t *p = (volatile uint64_t *)(uintptr_t)target;
        uint64_t word0 = p[0];
        uint64_t word1 = p[1];
        uint64_t pair[2] = { word0, word1 };
        out(pair, 16);
        bye(0);
    }
    bye(3);
}
