/* wemu_usermode.c — bounded host-mode ELF executor with VSL syscall dispatch.
 *
 * Ownership: this file owns the trap scope, the dispatch table, the guest
 * ABI boundary and the bounded run; VSL owns the numbering (the VSL_SYS_*
 * header is reused verbatim).  The interpreter in wemu_cpu.c is untouched.
 *
 * Mechanism: fork a child, map the static ET_EXEC at its link addresses,
 * build a SysV stack, install an IP-scoped seccomp-BPF filter that TRAPs
 * syscalls issued from the guest image, and setcontext() to e_entry.  The
 * SIGSYS handler reads RDI/RSI/RDX/R10/R8/R9 (siginfo carries no args),
 * looks the number up in a fail-closed table, and either runs the real host
 * syscall (same ABI, no marshalling), unwinds on exit, or refuses with
 * -ENOSYS.  Host-handler syscalls are outside the filter's IP window, so
 * they run for real without re-trapping.
 * License: WaefreBeorn Umbrella License v3.0. */
#define _GNU_SOURCE
#include "wemu_usermode.h"
#include "vsl_syscall_numbers.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS SECCOMP_RET_KILL
#endif

/* Four Linux x86-64 numbers absent from the VSL table.  The gate audits
 * these against the kernel header too; keep the WEMU_UM_SYS_ prefix so a
 * future VSL addition is visible instead of silently duplicated. */
#define WEMU_UM_SYS_SENDFILE     40
#define WEMU_UM_SYS_PRCTL       157
#define WEMU_UM_SYS_ARCH_PRCTL  158
#define WEMU_UM_SYS_RSEQ        334
#define WEMU_UM_SYS_TIME        201   /* busybox ls timestamp path */

/* ---- the one dispatch table (no implicit allow) --------------------- */
static const WemuUmSyscallEntry um_table[] = {
    { VSL_SYS_READ,            "read",            WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_WRITE,           "write",           WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_CLOSE,           "close",           WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_FSTAT,           "fstat",           WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_LSEEK,           "lseek",           WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_MMAP,            "mmap",            WEMU_UM_DISPATCH_EXEC_GUARD },
    { VSL_SYS_MPROTECT,        "mprotect",        WEMU_UM_DISPATCH_EXEC_GUARD },
    { VSL_SYS_MUNMAP,          "munmap",          WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_BRK,             "brk",             WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_RT_SIGACTION,    "rt_sigaction",    WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_RT_SIGPROCMASK,  "rt_sigprocmask",  WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_IOCTL,           "ioctl",           WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_WRITEV,          "writev",          WEMU_UM_DISPATCH_HOST },
    { WEMU_UM_SYS_SENDFILE,    "sendfile",        WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_GETPID,          "getpid",          WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_UNAME,           "uname",           WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_FCNTL,           "fcntl",           WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_GETCWD,          "getcwd",          WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_READLINK,        "readlink",        WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_GETUID,          "getuid",          WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_GETGID,          "getgid",          WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_SETUID,          "setuid",          WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_SETGID,          "setgid",          WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_GETEUID,         "geteuid",         WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_GETEGID,         "getegid",         WEMU_UM_DISPATCH_HOST },
    { WEMU_UM_SYS_PRCTL,       "prctl",           WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_FUTEX,           "futex",           WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_GETDENTS64,      "getdents64",      WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_SET_TID_ADDRESS, "set_tid_address", WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_SET_ROBUST_LIST, "set_robust_list", WEMU_UM_DISPATCH_HOST },
    { WEMU_UM_SYS_RSEQ,        "rseq",            WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_CLOCK_GETTIME,   "clock_gettime",   WEMU_UM_DISPATCH_HOST },
    { WEMU_UM_SYS_TIME,        "time",            WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_GETRANDOM,       "getrandom",       WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_PRLIMIT64,       "prlimit64",       WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_OPENAT,          "openat",          WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_NEWFSTATAT,      "newfstatat",      WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_READLINKAT,      "readlinkat",      WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_FACCESSAT,       "faccessat",       WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_STATX,           "statx",           WEMU_UM_DISPATCH_HOST },
    { WEMU_UM_SYS_ARCH_PRCTL,  "arch_prctl",      WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_EXIT,            "exit",            WEMU_UM_DISPATCH_EXIT },
    { VSL_SYS_EXIT_GROUP,      "exit_group",      WEMU_UM_DISPATCH_EXIT },
};

const WemuUmSyscallEntry *wemu_um_syscall_table(size_t *count) {
    if (count) *count = sizeof um_table / sizeof um_table[0];
    return um_table;
}

const char *wemu_um_status_name(int s) {
    switch (s) {
    case WEMU_UM_OK:           return "OK";
    case WEMU_UM_ERR_ARGS:     return "ERR_ARGS";
    case WEMU_UM_ERR_LOAD:     return "ERR_LOAD";
    case WEMU_UM_ERR_FORMAT:   return "ERR_FORMAT";
    case WEMU_UM_ERR_RANGE:    return "ERR_RANGE";
    case WEMU_UM_ERR_TRAP:     return "ERR_TRAP";
    case WEMU_UM_ERR_FAULT:    return "ERR_FAULT";
    case WEMU_UM_ERR_BUDGET:   return "ERR_BUDGET";
    case WEMU_UM_ERR_DENIED:   return "ERR_DENIED";
    case WEMU_UM_ERR_INTERNAL: return "ERR_INTERNAL";
    default:                   return "ERR_UNKNOWN";
    }
}

/* ---- per-child run state -------------------------------------------- */
enum { UM_WHY_EXIT = 1, UM_WHY_FAULT, UM_WHY_BUDGET, UM_WHY_ALARM };

static struct {
    volatile sig_atomic_t active;
    greg_t child_rsp;                /* original (non-guest) stack */
    volatile int why;
    volatile int exit_code;
    volatile uint64_t syscalls;
    volatile uint64_t denied;
    uint64_t win_lo, win_hi;
    WemuUmResult *result;
} g_um;

static void um_finish(void) __attribute__((noreturn));

/* Redirect sigreturn to our own stack.  siglongjmp from a signal delivered
 * on the guest stack is rejected by glibc's fortified ____longjmp_chk and
 * is needlessly dangerous anyway: rewriting REG_RIP/REG_RSP and returning
 * from the handler makes the kernel restore the ORIGINAL stack for us. */
static void um_abort_to_finish(ucontext_t *uc, int why) {
    g_um.why = why;
    uc->uc_mcontext.gregs[REG_RIP] = (greg_t)(uintptr_t)um_finish;
    uc->uc_mcontext.gregs[REG_RSP] = (g_um.child_rsp - 16) & ~(greg_t)15;
}

static const WemuUmSyscallEntry *um_lookup(uint64_t nr) {
    for (size_t i = 0; i < sizeof um_table / sizeof um_table[0]; i++)
        if (um_table[i].nr == (uint32_t)nr) return &um_table[i];
    return NULL;
}

static int64_t um_host(uint64_t nr, uint64_t a[6]) {
    return (int64_t)syscall((long)nr, a[0], a[1], a[2], a[3], a[4], a[5]);
}

/* On this kernel SIGSYS arrives with RIP already past the 2-byte syscall;
 * older kernels leave RIP on it.  Advance only when the bytes are 0F 05. */
static void um_skip_syscall(greg_t *r) {
    const uint8_t *p = (const uint8_t *)(uintptr_t)r[REG_RIP];
    if (p[0] == 0x0f && p[1] == 0x05)
        r[REG_RIP] = (greg_t)((uint64_t)r[REG_RIP] + 2);
}

static void um_sigsys(int sig, siginfo_t *si, void *ucv) {
    (void)sig;
    if (!g_um.active) _exit(200);            /* never dispatch outside a run */
    ucontext_t *uc = (ucontext_t *)ucv;
    greg_t *r = uc->uc_mcontext.gregs;
    uint64_t nr = (uint64_t)si->si_syscall;
    uint64_t a[6] = {
        (uint64_t)r[REG_RDI], (uint64_t)r[REG_RSI], (uint64_t)r[REG_RDX],
        (uint64_t)r[REG_R10], (uint64_t)r[REG_R8],  (uint64_t)r[REG_R9],
    };
    const WemuUmSyscallEntry *e = um_lookup(nr);
    g_um.syscalls++;

    if (!e) {                                /* FAIL CLOSED: no default-allow */
        g_um.denied++;
        r[REG_RAX] = (greg_t)-ENOSYS;
        um_skip_syscall(r);
        if (g_um.denied > 8) { um_abort_to_finish(uc, UM_WHY_BUDGET); return; }
        return;
    }
    if (e->kind == WEMU_UM_DISPATCH_EXIT) {
        g_um.exit_code = (int)(int32_t)a[0];
        um_abort_to_finish(uc, UM_WHY_EXIT);
        return;
    }

    int64_t ret = -EPERM;
    if (e->kind == WEMU_UM_DISPATCH_EXEC_GUARD) {
        /* mmap(addr,len,prot,..) / mprotect(addr,len,prot): a guest may only
         * make executable memory inside the registered image window.  No
         * W^X escape into host text/heap via a dispatched syscall. */
        int wants_exec = (int)(a[2] & PROT_EXEC) != 0;
        int in_window = a[0] >= g_um.win_lo &&
                        a[0] < g_um.win_hi &&
                        a[1] <= g_um.win_hi - a[0];
        if (!wants_exec || in_window) ret = um_host(nr, a);
    } else if ((nr == VSL_SYS_WRITE || nr == VSL_SYS_WRITEV ||
                WEMU_UM_SYS_SENDFILE == nr) && (a[0] == 1 || a[0] == 2)) {
        /* Bound output bookkeeping; the pipe read in the parent is the
         * authoritative capture. */
        uint64_t room = WEMU_UM_OUT_MAX - 1u - g_um.result->out_len;
        if (nr == VSL_SYS_WRITE && a[2] > room) a[2] = room;
        ret = um_host(nr, a);
        if (ret > 0) {
            uint64_t n = (uint64_t)ret;
            if (n > room) n = room;
            g_um.result->out_len += (uint32_t)n;
        }
    } else {
        ret = um_host(nr, a);
    }

    r[REG_RAX] = (greg_t)ret;
    um_skip_syscall(r);
    if (g_um.syscalls >= WEMU_UM_MAX_SYSCALLS ||
        g_um.result->out_len >= WEMU_UM_OUT_MAX - 1u) {
        um_abort_to_finish(uc, UM_WHY_BUDGET);
    }
}

static void um_fault(int sig, siginfo_t *si, void *ucv) {
    (void)sig; (void)si;
    if (!g_um.active) _exit(201);
    um_abort_to_finish((ucontext_t *)ucv, UM_WHY_FAULT);
}

static void um_alarm(int sig, siginfo_t *si, void *ucv) {
    (void)sig; (void)si;
    if (!g_um.active) return;
    um_abort_to_finish((ucontext_t *)ucv, UM_WHY_ALARM);
}

/* ---- ELF loading ---------------------------------------------------- */
typedef struct {
    uint8_t  *file;
    size_t    len;
    uint64_t  entry;
    uint64_t  phdr_va;
    uint16_t  phnum;
    uint64_t  lo, hi;            /* page-aligned guest image window */
} UmImage;

static uint8_t *um_read_file(const char *path, size_t *len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0 ||
        (uint64_t)st.st_size > (1u << 28)) { close(fd); return NULL; }
    size_t n = (size_t)st.st_size;
    uint8_t *buf = malloc(n);
    if (!buf) { close(fd); return NULL; }
    size_t got = 0;
    while (got < n) {
        ssize_t k = read(fd, buf + got, n - got);
        if (k <= 0) { free(buf); close(fd); return NULL; }
        got += (size_t)k;
    }
    close(fd);
    *len = n;
    return buf;
}

/* Fail if the link-address window overlaps anything already mapped in the
 * child: MAP_FIXED would otherwise silently overwrite host text/libc. */
static int um_range_free(uint64_t lo, uint64_t hi) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    int free_ = 1;
    while (fgets(line, sizeof line, f)) {
        unsigned long a, b;
        if (sscanf(line, "%lx-%lx", &a, &b) == 2 &&
            (uint64_t)a < hi && (uint64_t)b > lo) { free_ = 0; break; }
    }
    fclose(f);
    return free_;
}

#define UM_IMAGE_LIMIT 0x7fff0000ull     /* stay below the host stack/vDSO */

static int um_load(const char *path, UmImage *im) {
    memset(im, 0, sizeof *im);
    im->file = um_read_file(path, &im->len);
    if (!im->file || im->len < sizeof(Elf64_Ehdr)) return -1;
    Elf64_Ehdr eh;
    memcpy(&eh, im->file, sizeof eh);
    if (eh.e_ident[EI_MAG0] != ELFMAG0 || eh.e_ident[EI_MAG1] != ELFMAG1 ||
        eh.e_ident[EI_MAG2] != ELFMAG2 || eh.e_ident[EI_MAG3] != ELFMAG3 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_ident[EI_DATA] != ELFDATA2LSB ||
        eh.e_ident[EI_VERSION] != EV_CURRENT ||
        eh.e_type != ET_EXEC || eh.e_machine != EM_X86_64 ||
        eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phnum == 0 ||
        (uint64_t)eh.e_phoff + (uint64_t)eh.e_phnum * eh.e_phentsize > im->len) {
        return -1;
    }
    im->entry = eh.e_entry;
    im->phnum = eh.e_phnum;

    uint64_t lo = UINT64_MAX, hi = 0;
    for (unsigned i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr ph;
        memcpy(&ph, im->file + eh.e_phoff + (uint64_t)i * sizeof ph, sizeof ph);
        if (ph.p_type != PT_LOAD) {
            if (ph.p_type == PT_PHDR) im->phdr_va = ph.p_vaddr;
            continue;
        }
        if (ph.p_memsz < ph.p_filesz ||
            ph.p_offset + ph.p_filesz > im->len ||
            ph.p_vaddr + ph.p_memsz < ph.p_vaddr ||
            ph.p_vaddr + ph.p_memsz > UM_IMAGE_LIMIT) return -1;
        uint64_t ps = ph.p_vaddr & ~0xfffull;
        uint64_t pe = (ph.p_vaddr + ph.p_memsz + 0xfffull) & ~0xfffull;
        if (ps < 0x1000) return -1;
        if (ps < lo) lo = ps;
        if (pe > hi) hi = pe;
        if (ph.p_offset == 0 && !im->phdr_va) im->phdr_va = ph.p_vaddr + eh.e_phoff;
    }
    if (hi <= lo || hi - lo > (256u << 20)) return -1;
    im->lo = lo; im->hi = hi;
    if (hi >= (1ull << 32) || !um_range_free(lo, hi)) return -2;

    /* Pass 1: reserve every page range writable, then copy, then apply the
     * final protections (handles adjacent segments sharing a page). */
    for (unsigned i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr ph;
        memcpy(&ph, im->file + eh.e_phoff + (uint64_t)i * sizeof ph, sizeof ph);
        if (ph.p_type != PT_LOAD || !ph.p_memsz) continue;
        uint64_t ps = ph.p_vaddr & ~0xfffull;
        uint64_t pe = (ph.p_vaddr + ph.p_memsz + 0xfffull) & ~0xfffull;
        void *p = mmap((void *)(uintptr_t)ps, (size_t)(pe - ps),
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (p == MAP_FAILED) return -1;
    }
    for (unsigned i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr ph;
        memcpy(&ph, im->file + eh.e_phoff + (uint64_t)i * sizeof ph, sizeof ph);
        if (ph.p_type != PT_LOAD || !ph.p_memsz) continue;
        uint8_t *dst = (uint8_t *)(uintptr_t)ph.p_vaddr;
        memcpy(dst, im->file + ph.p_offset, (size_t)ph.p_filesz);
        memset(dst + ph.p_filesz, 0, (size_t)(ph.p_memsz - ph.p_filesz));
    }
    for (unsigned i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr ph;
        memcpy(&ph, im->file + eh.e_phoff + (uint64_t)i * sizeof ph, sizeof ph);
        if (ph.p_type != PT_LOAD || !ph.p_memsz) continue;
        uint64_t ps = ph.p_vaddr & ~0xfffull;
        uint64_t pe = (ph.p_vaddr + ph.p_memsz + 0xfffull) & ~0xfffull;
        int prot = 0;
        if (ph.p_flags & PF_R) prot |= PROT_READ;
        if (ph.p_flags & PF_W) prot |= PROT_WRITE;
        if (ph.p_flags & PF_X) prot |= PROT_EXEC;
        if (mprotect((void *)(uintptr_t)ps, (size_t)(pe - ps), prot) != 0)
            return -1;
    }
    return 0;
}

/* ---- SysV initial stack --------------------------------------------- */
#define AT_NULL_   0
#define AT_PHDR_   3
#define AT_PHENT_  4
#define AT_PHNUM_  5
#define AT_PAGESZ_ 6
#define AT_BASE_   7
#define AT_ENTRY_  9
#define AT_CLKTCK_ 17
#define AT_SECURE_ 23
#define AT_RANDOM_ 25

static uint64_t um_build_stack(char *const argv[], char *const envp[],
                               const UmImage *im, uint8_t **mem_out) {
    size_t argc = 0, envc = 0, strsz = 0;
    while (argv && argv[argc]) strsz += strlen(argv[argc++]) + 1;
    while (envp && envp[envc]) strsz += strlen(envp[envc++]) + 1;
#define UM_NAUX 9
    size_t vecsz = 8 + (argc + 1) * 8 + (envc + 1) * 8 + UM_NAUX * 16 + 16;
    size_t stacksz = 1u << 20;
    uint8_t *mem = mmap(NULL, stacksz, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return 0;
    uint64_t base = (uint64_t)(uintptr_t)mem, top = base + stacksz;
    uint64_t strp = top - strsz;
    uint64_t randp = strp - 16;
    uint64_t p = (randp - vecsz) & ~0xfull;
    uint8_t *w = mem + (size_t)(p - base);

#define PUT64(v) do { uint64_t vv_ = (uint64_t)(v); memcpy(w, &vv_, 8); w += 8; } while (0)
    PUT64(argc);
    for (size_t i = 0; i < argc; i++) {
        PUT64(strp);
        size_t n = strlen(argv[i]) + 1;
        memcpy(mem + (size_t)(strp - base), argv[i], n);
        strp += n;
    }
    PUT64(0);
    for (size_t i = 0; i < envc; i++) {
        PUT64(strp);
        size_t n = strlen(envp[i]) + 1;
        memcpy(mem + (size_t)(strp - base), envp[i], n);
        strp += n;
    }
    PUT64(0);
    uint64_t aux[UM_NAUX][2] = {
        { AT_PHDR_, im->phdr_va }, { AT_PHENT_, sizeof(Elf64_Phdr) },
        { AT_PHNUM_, im->phnum },  { AT_PAGESZ_, 4096 },
        { AT_BASE_, 0 },           { AT_ENTRY_, im->entry },
        { AT_CLKTCK_, 100 },       { AT_SECURE_, 0 },
        { AT_RANDOM_, randp },
    };
    for (size_t i = 0; i < UM_NAUX; i++) { PUT64(aux[i][0]); PUT64(aux[i][1]); }
    PUT64(AT_NULL_); PUT64(0);
#undef PUT64
    uint64_t seed = im->entry ^ 0x9E3779B97F4A7C15ull;
    for (int i = 0; i < 16; i++) {
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        mem[randp - base + (size_t)i] = (uint8_t)seed;
    }
    *mem_out = mem;
    return p;                                /* 16-byte aligned at entry */
}

/* ---- seccomp trap scope: guest image only --------------------------- */
static int um_install_filter(uint64_t lo, uint64_t hi) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4),                 /* arch */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 12),                /* ip hi */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 8),                 /* ip lo */
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, (uint32_t)lo, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, (uint32_t)hi, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof f / sizeof f[0]), .filter = f,
    };
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) == 0 ? 0 : -1;
}

/* Entered by SIGRT sigreturn with REG_RIP rewritten by the handlers, so it
 * runs on the child's ORIGINAL stack, never the guest's.  No return: the
 * result is published through the MAP_SHARED page and the child _exit()s. */
static void um_finish(void) {
    WemuUmResult *shared = g_um.result;
    g_um.active = 0;
    alarm(0);
    shared->syscalls = g_um.syscalls;
    shared->denied = g_um.denied;
    shared->exit_code = g_um.exit_code;
    switch (g_um.why) {
    case UM_WHY_EXIT:  shared->status = WEMU_UM_OK;          break;
    case UM_WHY_FAULT: shared->status = WEMU_UM_ERR_FAULT;    break;
    case UM_WHY_ALARM: shared->status = WEMU_UM_ERR_BUDGET;   break;
    case UM_WHY_BUDGET:
        shared->status = g_um.denied > 8 ? WEMU_UM_ERR_DENIED
                                         : WEMU_UM_ERR_BUDGET;
        break;
    default:           shared->status = WEMU_UM_ERR_INTERNAL; break;
    }
    _exit(0);
}

static void um_child_fail(WemuUmResult *shared, int code) {
    shared->status = code;
    _exit(0);
}

static void um_child_run(const char *path, char *const argv[], char *const envp[],
                         WemuUmResult *shared, int out_fd) {
    close(0);                                /* guest must not read our stdin */
    if (dup2(out_fd, STDOUT_FILENO) < 0 || dup2(out_fd, STDERR_FILENO) < 0)
        um_child_fail(shared, WEMU_UM_ERR_INTERNAL);
    close(out_fd);

    UmImage im;
    int rc = um_load(path, &im);
    if (rc == -2) um_child_fail(shared, WEMU_UM_ERR_RANGE);
    if (rc != 0) um_child_fail(shared, WEMU_UM_ERR_FORMAT);
    uint8_t *stack_mem;
    uint64_t rsp = um_build_stack(argv, envp, &im, &stack_mem);
    if (!rsp) um_child_fail(shared, WEMU_UM_ERR_INTERNAL);
    free(im.file);

    memset(&g_um, 0, sizeof g_um);
    g_um.result = shared;
    g_um.win_lo = im.lo;
    g_um.win_hi = im.hi;

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = um_sigsys;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGALRM);          /* no nested unwind from handler */
    if (sigaction(SIGSYS, &sa, NULL) != 0) um_child_fail(shared, WEMU_UM_ERR_TRAP);
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = um_fault;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGSYS);
    if (sigaction(SIGSEGV, &sa, NULL) != 0 || sigaction(SIGBUS, &sa, NULL) != 0)
        um_child_fail(shared, WEMU_UM_ERR_TRAP);
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = um_alarm;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGSYS);
    if (sigaction(SIGALRM, &sa, NULL) != 0) um_child_fail(shared, WEMU_UM_ERR_TRAP);
    if (um_install_filter(im.lo, im.hi) != 0)
        um_child_fail(shared, WEMU_UM_ERR_TRAP);

    ucontext_t uc;
    if (getcontext(&uc) != 0) um_child_fail(shared, WEMU_UM_ERR_TRAP);
    uc.uc_mcontext.gregs[REG_RSP] = (greg_t)rsp;
    uc.uc_mcontext.gregs[REG_RIP] = (greg_t)im.entry;
    uc.uc_mcontext.gregs[REG_EFL] = 0x202;    /* IF=1, reserved bit 1 */
    uc.uc_mcontext.gregs[REG_RDX] = 0;        /* rtld_fini */
    sigemptyset(&uc.uc_sigmask);             /* all signals live in the guest */

    uintptr_t sp;
    __asm__ volatile ("mov %%rsp, %0" : "=r"(sp));
    g_um.child_rsp = (greg_t)sp;
    g_um.why = 0;
    g_um.active = 1;
    alarm(WEMU_UM_TIMEOUT_SEC);
    (void)setcontext(&uc);                   /* transfers to e_entry */
    um_finish();                             /* only on setcontext failure */
}

int wemu_um_run_elf(const char *path, char *const argv[],
                    char *const envp[], WemuUmResult *out) {
    if (!path || !out) return WEMU_UM_ERR_ARGS;
    memset(out, 0, sizeof *out);
    WemuUmResult *shared = mmap(NULL, sizeof *shared, PROT_READ | PROT_WRITE,
                                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED) return WEMU_UM_ERR_INTERNAL;
    memset(shared, 0, sizeof *shared);

    int pfd[2];
    if (pipe(pfd) != 0) {
        munmap(shared, sizeof *shared);
        return WEMU_UM_ERR_INTERNAL;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]); close(pfd[1]); munmap(shared, sizeof *shared);
        return WEMU_UM_ERR_INTERNAL;
    }
    if (pid == 0) um_child_run(path, argv, envp, shared, pfd[1]);

    close(pfd[1]);
    size_t n = 0;
    for (;;) {
        ssize_t k = read(pfd[0], out->out + n, WEMU_UM_OUT_MAX - 1u - n);
        if (k > 0) { n += (size_t)k; if (n >= WEMU_UM_OUT_MAX - 1u) break; }
        else if (k == 0) break;
        else if (errno == EINTR) continue;
        else break;
    }
    close(pfd[0]);
    int wst = 0;
    while (waitpid(pid, &wst, 0) < 0 && errno == EINTR) { }

    WemuUmResult final = *shared;              /* keep the pipe capture */
    memcpy(final.out, out->out, WEMU_UM_OUT_MAX);
    final.out_len = (uint32_t)n;
    final.out[n] = '\0';
    if (!WIFEXITED(wst) && final.status == WEMU_UM_OK)
        final.status = WEMU_UM_ERR_INTERNAL;
    *out = final;
    munmap(shared, sizeof *shared);
    return final.status;
}
