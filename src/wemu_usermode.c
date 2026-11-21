/* wemu_usermode.c — bounded host-mode ELF executor with VSL syscall dispatch.
 *
 * Ownership: this file owns the trap scope, the dispatch table, the guest
 * ABI boundary and the bounded run; VSL owns the numbering (the VSL_SYS_*
 * header is reused verbatim).  The interpreter in wemu_cpu.c is untouched.
 *
 * Mechanism: fork a child, map the ELF's PT_LOAD segments at their link
 * addresses (ET_EXEC) or at a chosen load bias (ET_DYN / static PIE), build a
 * SysV stack, install an IP-scoped seccomp-BPF filter that TRAPs syscalls
 * issued from the guest image, and setcontext() to e_entry.  The SIGSYS
 * handler reads RDI/RSI/RDX/R10/R8/R9 (siginfo carries no args), looks the
 * number up in a fail-closed table, and either runs the real host syscall
 * (same ABI, no marshalling), unwinds on exit, or refuses with -ENOSYS.
 * Host-handler syscalls are outside the filter's IP window, so they run for
 * real without re-trapping.
 *
 * Bounded guest signal delivery: rt_sigaction is intercepted into a small
 * (WEMU_UM_SIG_NSIG) guest signal table instead of being passed to the host.
 * A synchronous fault (SIGSEGV/SIGBUS/SIGILL/SIGFPE) raised from guest RIP is
 * delivered to a registered guest handler by rewriting the ucontext; the
 * handler's return address is the guest's own SA_RESTORER, so a normal
 * sigreturn comes back through rt_sigreturn and restores the saved context.
 * Delivery is bounded (WEMU_UM_MAX_SIGNALS, no nesting) and fails closed for
 * unknown signals, unregistered handlers and faults outside the guest image.
 *
 * Bounded fork/clone: fork/vfork, clone and clone3 are dispatched in-process.
 * A fork-shaped request (CSIGNAL 0/SIGCHLD, optionally the two glibc TID
 * bookkeeping bits) becomes a raw SYS_fork from the SIGSYS handler: the guest
 * child gets a PRIVATE copy-on-write address
 * space (guest image, stack and TLS) and continues at the instruction after
 * the syscall with RAX=0; the parent gets the child pid.  CLONE_VM/THREAD/
 * SIGHAND/NEWPID/... are refused with -EINVAL (no shared address space, no
 * host threads, no nested dispatch state).  The fork budget lives in the
 * MAP_SHARED page so it bounds the whole guest process tree.
 *
 * TLS rule: the guest owns %fs while our handlers run (it sets it with
 * arch_prctl).  Every syscall/invocation from a handler is therefore a RAW
 * syscall or a TLS-free helper — glibc's syscall() wrapper would write errno
 * into the GUEST's TLS slot and silently corrupt it (ENOENT=2 became a
 * pointer, crashing head/seq/expr/awk/... before main did any work).
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
#define WEMU_UM_SYS_RT_SIGRETURN 15   /* not in the VSL table */
#define WEMU_UM_SYS_SCHED_GETAFFINITY 204 /* not in the VSL table */
#define WEMU_UM_SYS_DUP3         292 /* not in the VSL table */
#define SIG_DFL_ 0
#define SIG_IGN_ 1

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
    { VSL_SYS_BRK,             "brk",              WEMU_UM_DISPATCH_BRK },
    { VSL_SYS_RT_SIGACTION,    "rt_sigaction",    WEMU_UM_DISPATCH_SIGACTION },
    { WEMU_UM_SYS_RT_SIGRETURN,"rt_sigreturn",    WEMU_UM_DISPATCH_SIGRETURN },
    { VSL_SYS_RT_SIGPROCMASK,  "rt_sigprocmask",  WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_IOCTL,           "ioctl",           WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_WRITEV,          "writev",          WEMU_UM_DISPATCH_HOST },
    { WEMU_UM_SYS_SENDFILE,    "sendfile",        WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_GETPID,          "getpid",          WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_UNAME,           "uname",           WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_FCNTL,           "fcntl",           WEMU_UM_DISPATCH_HOST },
    { WEMU_UM_SYS_DUP3,        "dup3",            WEMU_UM_DISPATCH_HOST },
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
    { VSL_SYS_GETGROUPS,      "getgroups",       WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_ACCESS,         "access",          WEMU_UM_DISPATCH_HOST },
    { VSL_SYS_GETPPID,        "getppid",         WEMU_UM_DISPATCH_HOST },
    { WEMU_UM_SYS_SCHED_GETAFFINITY,"sched_getaffinity", WEMU_UM_DISPATCH_HOST },
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
    { VSL_SYS_FORK,            "fork",            WEMU_UM_DISPATCH_FORK },
    { VSL_SYS_VFORK,           "vfork",           WEMU_UM_DISPATCH_FORK },
    { VSL_SYS_CLONE,           "clone",           WEMU_UM_DISPATCH_CLONE },
    { VSL_SYS_CLONE3,          "clone3",          WEMU_UM_DISPATCH_CLONE3 },
    { VSL_SYS_WAIT4,           "wait4",           WEMU_UM_DISPATCH_HOST },
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
    case WEMU_UM_ERR_INTERP:   return "ERR_INTERP";
    case WEMU_UM_ERR_BADPTR:   return "ERR_BADPTR";
    default:                   return "ERR_UNKNOWN";
    }
}

/* ---- per-child run state -------------------------------------------- */
enum { UM_WHY_EXIT = 1, UM_WHY_FAULT, UM_WHY_BUDGET, UM_WHY_ALARM, UM_WHY_BADPTR };

/* Bounded guest address-space bookkeeping.  The native path shares the host
 * address space with the guest, so "mapped guest ranges" are the ELF image
 * window, the SysV stack, the bounded brk heap and guest mmap results.  A
 * pointer outside ALL of them is refused before any host syscall sees it. */
#define UM_MAX_MMAPS  16u
#define UM_HEAP_MAX   (16u << 20)   /* max brk growth above the initial break */

/* Number of general registers in mcontext_t (compile-time, no magic 23). */
#define UM_NGREG \
    (sizeof(((ucontext_t *)0)->uc_mcontext.gregs) / sizeof(greg_t))

static struct {
    volatile sig_atomic_t active;
    int is_root;                     /* only the first child owns the result */
    greg_t child_rsp;                /* original (non-guest) stack */
    volatile int why;
    volatile int exit_code;
    volatile uint64_t syscalls;
    volatile uint64_t denied;
    uint64_t win_lo, win_hi;       /* guest ELF image window (PT_LOAD) */
    uint64_t stack_lo, stack_hi;   /* SysV initial stack mapping */
    uint64_t heap_lo, heap_hi;     /* bounded brk heap [initial break, current] */
    uint64_t mmap_lo[UM_MAX_MMAPS], mmap_hi[UM_MAX_MMAPS];
    uint32_t n_mmaps;
    volatile uint32_t bad_ptrs;    /* pointers refused before host dispatch */
    volatile uint32_t bad_ptr_nr;
    volatile uint64_t bad_ptr_va;
    WemuUmResult *result;
    /* bounded guest signal model (all touched only inside signal handlers) */
    uint64_t sig_handler[WEMU_UM_SIG_NSIG];  /* guest handler RIP */
    uint64_t sig_restorer[WEMU_UM_SIG_NSIG]; /* guest SA_RESTORER (sigreturn) */
    uint32_t sig_flags[WEMU_UM_SIG_NSIG];
    uint8_t  sig_valid[WEMU_UM_SIG_NSIG];
    volatile uint32_t sig_deliveries;
    volatile uint32_t sig_denied;
    volatile int in_handler;         /* no nested delivery while one is live */
    int saved_valid;                 /* a context is stashed for sigreturn */
    greg_t saved_gregs[UM_NGREG];    /* register context at the delivered fault */
} g_um;

/* Only these synchronous-fault signals are ever registered or delivered.
 * Everything else is refused by rt_sigaction and would unwind on fault. */
static int um_sig_sync(int sig) {
    return sig == SIGSEGV || sig == SIGBUS || sig == SIGILL || sig == SIGFPE;
}

int wemu_um_signal_modeled(int sig) { return um_sig_sync(sig); }

static int um_sig_registered(int sig) {
    return sig > 0 && sig < WEMU_UM_SIG_NSIG && g_um.sig_valid[sig];
}

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

static void um_note_denied(uint64_t nr) {
    g_um.denied++;
    for (uint32_t k = 0; k < 8; k++)
        if (g_um.result->denied_nrs[k] == 0) {
            g_um.result->denied_nrs[k] = (uint32_t)nr; break;
        }
}

static const WemuUmSyscallEntry *um_lookup(uint64_t nr) {
    for (size_t i = 0; i < sizeof um_table / sizeof um_table[0]; i++)
        if (um_table[i].nr == (uint32_t)nr) return &um_table[i];
    return NULL;
}

static int64_t um_host(uint64_t nr, uint64_t a[6]) {
    register long r10 __asm__("r10") = (long)a[3];
    register long r8  __asm__("r8")  = (long)a[4];
    register long r9  __asm__("r9")  = (long)a[5];
    long ret;
    __asm__ volatile("syscall"
        : "=a"(ret)
        : "a"((long)nr), "D"((long)a[0]), "S"((long)a[1]), "d"((long)a[2]),
          "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return (int64_t)ret;             /* raw kernel return: -errno, no TLS */
}

/* Same rule for the run's own housekeeping syscalls (alarm, fork). */
static int64_t um_raw0(long nr) {
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(nr)
                     : "rcx", "r11", "memory");
    return (int64_t)ret;
}

static int64_t um_raw1(long nr, long a0) {
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(nr), "D"(a0)
                     : "rcx", "r11", "memory");
    return (int64_t)ret;
}

/* ---- mapped-range guest pointer validation -------------------------- */
/* The native path shares the host address space with the guest, so a guest
 * pointer is a host pointer.  Before a host syscall may see one it must lie
 * wholly inside a range the executor registered as guest-mapped: the ELF
 * image, the SysV stack, the bounded brk heap, or an admitted guest mmap.
 * Anything else fails closed with NO host syscall dispatched. */
static int um_range_has(uint64_t lo, uint64_t hi, uint64_t ptr, uint64_t len) {
    if (hi <= lo || ptr < lo || ptr >= hi) return 0;
    if (len == 0) return 1;
    return len <= hi - ptr;                 /* no wrap */
}

static int um_ptr_ok(uint64_t ptr, uint64_t len) {
    if (ptr == 0) return 1;                 /* NULL: absent/optional buffer */
    if (um_range_has(g_um.win_lo, g_um.win_hi, ptr, len)) return 1;
    if (um_range_has(g_um.stack_lo, g_um.stack_hi, ptr, len)) return 1;
    if (um_range_has(g_um.heap_lo, g_um.heap_hi, ptr, len)) return 1;
    for (uint32_t i = 0; i < g_um.n_mmaps; i++)
        if (um_range_has(g_um.mmap_lo[i], g_um.mmap_hi[i], ptr, len)) return 1;
    return 0;
}

/* Path pointer: first byte must be mapped and the NUL must be found inside
 * the SAME registered range (bounded to 4096 bytes). */
static int um_str_ok(uint64_t ptr) {
    if (ptr == 0) return 1;
    uint64_t end = 0;
    if (ptr >= g_um.win_lo && ptr < g_um.win_hi) end = g_um.win_hi;
    else if (ptr >= g_um.stack_lo && ptr < g_um.stack_hi) end = g_um.stack_hi;
    else if (ptr >= g_um.heap_lo && ptr < g_um.heap_hi) end = g_um.heap_hi;
    else for (uint32_t i = 0; i < g_um.n_mmaps; i++)
        if (ptr >= g_um.mmap_lo[i] && ptr < g_um.mmap_hi[i]) {
            end = g_um.mmap_hi[i]; break;
        }
    if (!end) return 0;
    uint64_t span = end - ptr;
    uint64_t limit = span < 4096 ? span : 4096;
    const uint8_t *s = (const uint8_t *)(uintptr_t)ptr;
    for (uint64_t i = 0; i < limit; i++) if (s[i] == 0) return 1;
    return 0;
}

static int um_bad(uint64_t nr, uint64_t va) {
    g_um.bad_ptrs++;
    g_um.bad_ptr_nr = (uint32_t)nr;
    g_um.bad_ptr_va = va;
    return 0;
}

static int um_chk(uint64_t nr, uint64_t ptr, uint64_t len) {
    return um_ptr_ok(ptr, len) ? 1 : um_bad(nr, ptr);
}

static int um_chk_str(uint64_t nr, uint64_t ptr) {
    return um_str_ok(ptr) ? 1 : um_bad(nr, ptr);
}

/* Every syscall in um_table that makes the HOST kernel dereference a guest
 * pointer is listed here.  Scalar-only calls (exit, getpid, lseek, ...), the
 * exec guard (mmap/mprotect addr is a hint/value, not dereferenced) and
 * pointer-STORE calls (set_tid_address / set_robust_list: the kernel stores
 * the value, it never follows it) are intentionally absent — validating
 * their scalar args would break the guest ABI. */
static int um_ptr_args_ok(uint64_t nr, const uint64_t a[6]) {
    switch (nr) {
    case VSL_SYS_READ: case VSL_SYS_WRITE: case 17: case 18: /* pread/pwrite */
        return um_chk(nr, a[1], a[2]);
    case VSL_SYS_WRITEV:
        if (a[2] > 1024) return um_bad(nr, a[1]);
        return um_chk(nr, a[1], a[2] * 16ull);
    case VSL_SYS_IOCTL:
        if (a[2] && a[2] < 0x1000) return 1;  /* request-encoded scalar */
        return um_chk(nr, a[2], 8);
    case VSL_SYS_GETCWD:
        return um_chk(nr, a[0], a[1]);
    case VSL_SYS_READLINK:
        return um_chk_str(nr, a[0]) && um_chk(nr, a[1], a[2]);
    case VSL_SYS_READLINKAT:
        return um_chk_str(nr, a[1]) && um_chk(nr, a[2], a[3]);
    case VSL_SYS_FSTAT:
        return um_chk(nr, a[1], 144);
    case VSL_SYS_NEWFSTATAT:
        return um_chk_str(nr, a[1]) && um_chk(nr, a[2], 144);
    case VSL_SYS_STATX:
        return um_chk_str(nr, a[1]) && um_chk(nr, a[4], 256);
    case VSL_SYS_GETDENTS64:
        return um_chk(nr, a[1], a[2]);
    case VSL_SYS_UNAME:
        return um_chk(nr, a[0], 512);
    case VSL_SYS_GETRANDOM:
        return um_chk(nr, a[0], a[1]);
    case VSL_SYS_CLOCK_GETTIME:
        return um_chk(nr, a[1], 16);
    case VSL_SYS_FUTEX:
        return um_chk(nr, a[0], 4);
    case VSL_SYS_RT_SIGACTION:
        return um_chk(nr, a[1], 32) && um_chk(nr, a[2], 32);
    case VSL_SYS_RT_SIGPROCMASK:
        return um_chk(nr, a[1], 8) && um_chk(nr, a[2], 8);
    case VSL_SYS_PRLIMIT64:
        return um_chk(nr, a[2], 16) && um_chk(nr, a[3], 16);
    case WEMU_UM_SYS_SENDFILE:
        return um_chk(nr, a[2], 8);           /* optional loff_t *offset */
    case WEMU_UM_SYS_ARCH_PRCTL:
        if (a[0] == 0x1003 || a[0] == 0x1004) return um_chk(nr, a[1], 8);
        return 1;                              /* SET_FS/SET_GS take a value */
    case VSL_SYS_OPENAT: case VSL_SYS_FACCESSAT:
        return um_chk_str(nr, a[1]);
    default:
        return 1;                              /* no host-dereferenced pointer */
    }
}

/* On this kernel SIGSYS arrives with RIP already past the 2-byte syscall;
 * older kernels leave RIP on it.  Advance only when the bytes are 0F 05. */
static void um_skip_syscall(greg_t *r) {
    const uint8_t *p = (const uint8_t *)(uintptr_t)r[REG_RIP];
    if (p[0] == 0x0f && p[1] == 0x05)
        r[REG_RIP] = (greg_t)((uint64_t)r[REG_RIP] + 2);
}

/* Kernel x86-64 rt_sigaction layout (glibc translates its own struct to
 * this before the syscall): handler@0, flags@8, restorer@16, mask@24. */
typedef struct {
    uint64_t handler, flags, restorer, mask;
} UmKernelSigaction;

/* Guest rt_sigaction: record only a bounded set of synchronous signals in
 * our own table; never install a host handler.  Unknown signals, bad sizes
 * and out-of-image handlers are refused — there is no implied default. */
static int64_t um_sigaction(const uint64_t a[6]) {
    int sig = (int)a[0];
    uint64_t act = a[1], oldact = a[2], ssz = a[3];
    if (sig <= 0 || sig >= WEMU_UM_SIG_NSIG || ssz != 8 || !um_sig_sync(sig)) {
        g_um.sig_denied++;
        return -EINVAL;
    }
    UmKernelSigaction ksa;
    if (act) memcpy(&ksa, (const void *)(uintptr_t)act, sizeof ksa);
    else     memset(&ksa, 0, sizeof ksa);
    if (oldact) {
        UmKernelSigaction old = { g_um.sig_handler[sig], g_um.sig_flags[sig],
                                  g_um.sig_restorer[sig], 0 };
        memcpy((void *)(uintptr_t)oldact, &old, sizeof old);
    }
    if (ksa.handler == SIG_DFL_ || ksa.handler == SIG_IGN_) {
        g_um.sig_valid[sig] = 0;             /* unregister */
        return 0;
    }
    if (ksa.handler < g_um.win_lo || ksa.handler >= g_um.win_hi) {
        g_um.sig_denied++;                    /* handler outside the image */
        return -EINVAL;
    }
    g_um.sig_handler[sig]  = ksa.handler;
    g_um.sig_restorer[sig] = ksa.restorer;
    g_um.sig_flags[sig]    = (uint32_t)ksa.flags;
    g_um.sig_valid[sig]    = 1;
    return 0;
}

/* Guest rt_sigreturn: put the fault-time registers back.  The ucontext we
 * are returning from is the SIGSYS one raised by this very syscall, so the
 * kernel resumes at the restored RIP (the faulting instruction) on sigreturn. */
static void um_sigreturn(greg_t *r) {
    if (!g_um.in_handler || !g_um.saved_valid) {
        g_um.sig_denied++;
        r[REG_RAX] = (greg_t)-EINVAL;
        um_skip_syscall(r);
        return;
    }
    memcpy(r, g_um.saved_gregs, sizeof g_um.saved_gregs);
    g_um.saved_valid = 0;
    g_um.in_handler = 0;
    /* Deliberately no um_skip_syscall: RIP is now the faulting instruction. */
}

/* ---- bounded fork/clone -------------------------------------------- */
/* Only a fork-shaped clone is modelled: CSIGNAL 0/SIGCHLD and optionally
 * the two glibc-fork TID bookkeeping bits (CLONE_CHILD_SETTID/CLEARTID).
 * Those two are accepted but not applied: the COW child has a private TLS
 * copy and no host thread to futex-wake, so the pointers are ignored.
 * Sharing VM / SIGHAND / THREAD / namespaces would hand a host thread or a
 * second dispatcher to the guest, so those flags are refused before any
 * kernel call. */
#define UM_CLONE_TID_BITS (0x00200000ull | 0x01000000ull)
int wemu_um_clone_flags_modeled(uint64_t flags) {
    uint64_t extra = flags & ~0xffull;
    if (extra & ~UM_CLONE_TID_BITS) return 0;
    return (flags & 0xffu) == 0 || (flags & 0xffu) == SIGCHLD;
}

/* Kernel struct clone_args (linux/sched.h), little-endian x86-64. */
typedef struct {
    uint64_t flags, pidfd, child_tid, parent_tid, exit_signal,
             stack, stack_size, tls, set_tid, set_tid_size, cgroup;
} UmCloneArgs;

static int um_clone3_modeled(const uint64_t a[6]) {
    UmCloneArgs ca;
    if (a[1] < sizeof ca || !a[0]) return 0;
    memcpy(&ca, (const void *)(uintptr_t)a[0], sizeof ca);
    /* No pidfd/tid/tls/stack knobs: all of them imply either shared state
     * or a child starting on a different stack, which we do not model. */
    if (ca.pidfd || ca.child_tid || ca.parent_tid || ca.stack ||
        ca.stack_size || ca.tls || ca.set_tid || ca.set_tid_size || ca.cgroup)
        return 0;
    if (ca.flags != 0) return 0;
    return ca.exit_signal == 0 || ca.exit_signal == SIGCHLD;
}

/* One shared counter bounds the whole process tree, not just this process. */
static int64_t um_do_fork(void) {
    if (g_um.in_handler) { g_um.denied++; return -EPERM; }
    uint32_t used = __atomic_fetch_add(&g_um.result->forks, 1, __ATOMIC_SEQ_CST);
    if (used >= WEMU_UM_MAX_FORKS) {
        __atomic_fetch_sub(&g_um.result->forks, 1, __ATOMIC_SEQ_CST);
        g_um.denied++;
        return -EAGAIN;
    }
    int64_t pid = um_raw0(57 /* SYS_fork */);
    if (pid < 0) {
        __atomic_fetch_sub(&g_um.result->forks, 1, __ATOMIC_SEQ_CST);
        return pid;
    }
    if (pid == 0) {
        /* Private COW address space; inherited g_um is our own copy.  Only
         * the root publishes results; children report status via wait4. */
        g_um.is_root = 0;
        (void)um_raw1(37 /* SYS_alarm */, WEMU_UM_TIMEOUT_SEC);
        /* alarm timers are NOT inherited across fork */
    }
    return pid;
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
        um_note_denied(nr);
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
    if (e->kind == WEMU_UM_DISPATCH_SIGRETURN) {
        um_sigreturn(r);                     /* resumes at the saved fault RIP */
        return;
    }

    /* Fail closed BEFORE any host syscall: the guest shares our address
     * space, so an unvalidated pointer is a host pointer.  A bad one ends
     * the run with WEMU_UM_ERR_BADPTR; no host handler sees it. */
    if (!um_ptr_args_ok(nr, a)) {
        r[REG_RAX] = (greg_t)-EFAULT;
        um_abort_to_finish(uc, UM_WHY_BADPTR);
        return;
    }

    if (e->kind == WEMU_UM_DISPATCH_FORK ||
        e->kind == WEMU_UM_DISPATCH_CLONE ||
        e->kind == WEMU_UM_DISPATCH_CLONE3) {
        int64_t child;
        if (e->kind == WEMU_UM_DISPATCH_CLONE) {
            /* RDI=flags, RSI=child stack: a non-zero stack means the child
             * resumes on a different stack, which we do not model. */
            if (!wemu_um_clone_flags_modeled(a[0]) || a[1] != 0) {
                um_note_denied(nr); child = -EINVAL;
            } else child = um_do_fork();
        } else if (e->kind == WEMU_UM_DISPATCH_CLONE3) {
            if (!um_clone3_modeled(a)) {
                um_note_denied(nr); child = -EINVAL;
            } else child = um_do_fork();
        } else {
            /* fork(2)/vfork(2): the kernel fixes exit_signal=SIGCHLD.  Our
             * bounded COW model makes vfork's shared-stack rule moot. */
            child = um_do_fork();
        }
        r[REG_RAX] = (greg_t)child;
        um_skip_syscall(r);
        if (g_um.syscalls >= WEMU_UM_MAX_SYSCALLS || g_um.denied > 8)
            um_abort_to_finish(uc, UM_WHY_BUDGET);
        return;
    }

    int64_t ret = -EPERM;
    if (e->kind == WEMU_UM_DISPATCH_SIGACTION) {
        ret = um_sigaction(a);
    } else if (e->kind == WEMU_UM_DISPATCH_EXEC_GUARD) {
        /* mmap(addr,len,prot,flags,..) / mprotect(addr,len,prot): a guest may
         * only make executable memory inside the registered image window,
         * which is the ONLY range the seccomp filter traps.  No W^X escape
         * into host text/heap via a dispatched syscall. */
        int wants_exec = (a[2] & PROT_EXEC) != 0;
        int in_window = a[0] >= g_um.win_lo && a[0] < g_um.win_hi &&
                        a[1] <= g_um.win_hi - a[0];
        if (!wants_exec) {
            ret = um_host(nr, a);
            /* Remember admitted mappings so their buffers pass pointer
             * validation; bounded table, bounded size. */
            if (nr == VSL_SYS_MMAP && ret >= 0 && a[1] &&
                a[1] < (1ull << 40) && g_um.n_mmaps < UM_MAX_MMAPS) {
                uint64_t base = (uint64_t)ret;
                g_um.mmap_lo[g_um.n_mmaps] = base;
                g_um.mmap_hi[g_um.n_mmaps] = base + a[1];
                g_um.n_mmaps++;
            }
        } else if (nr == VSL_SYS_MMAP) {
            /* A non-MAP_FIXED mmap may land ANYWHERE — the addr argument is
             * only a hint, so an in-window hint does NOT admit the result.
             * Tighten: only a MAP_FIXED range wholly inside the trapped
             * image window is admitted; all other PROT_EXEC maps refused. */
            int fixed = (a[3] & MAP_FIXED) != 0;
            if (fixed && in_window) ret = um_host(nr, a);
        } else if (in_window) {
            ret = um_host(nr, a);            /* mprotect: already trapped */
        }
    } else if (e->kind == WEMU_UM_DISPATCH_BRK) {
        /* Bounded heap growth.  brk() failure semantics: return the current
         * break, never move it.  The heap range is tracked so legitimate
         * guest heap pointers pass validation. */
        uint64_t cur = g_um.heap_hi;
        if (a[0] == 0) {
            ret = (int64_t)cur;              /* query: current break */
        } else if (a[0] < g_um.heap_lo ||
                   a[0] > g_um.heap_lo + UM_HEAP_MAX) {
            ret = (int64_t)cur;              /* out of bounds: refuse */
        } else {
            ret = um_host(nr, a);
            if (ret > 0) g_um.heap_hi = (uint64_t)ret;
        }
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

/* A synchronous CPU fault inside the guest image is offered to a registered
 * guest handler.  Everything else fails closed: unknown signal, no handler,
 * a fault outside the guest window, a nested fault, or an exhausted budget. */
static void um_fault(int sig, siginfo_t *si, void *ucv) {
    if (!g_um.active) _exit(201);
    ucontext_t *uc = (ucontext_t *)ucv;
    greg_t *r = uc->uc_mcontext.gregs;
    int signo = si ? si->si_signo : sig;
    uint64_t rip = (uint64_t)r[REG_RIP];
    int in_guest = rip >= g_um.win_lo && rip < g_um.win_hi;

    if (!um_sig_sync(signo) || !in_guest || !um_sig_registered(signo) ||
        g_um.in_handler || g_um.sig_deliveries >= WEMU_UM_MAX_SIGNALS) {
        g_um.sig_denied++;                    /* fail closed, no delivery */
        um_abort_to_finish(uc, UM_WHY_FAULT);
        return;
    }

    /* Stash the fault-time registers (bounded: one live delivery at a time). */
    memcpy(g_um.saved_gregs, r, sizeof g_um.saved_gregs);
    g_um.saved_valid = 1;
    g_um.in_handler = 1;
    g_um.sig_deliveries++;

    /* Minimal delivery frame: put the guest's SA_RESTORER where a C handler's
     * epilogue will `ret`, with SysV stack alignment at handler entry.  We
     * only supply signo in RDI; siginfo/ucontext args are not populated. */
    greg_t sp = (r[REG_RSP] - 16) & ~(greg_t)15;
    *(uint64_t *)(uintptr_t)(sp + 8) = g_um.sig_restorer[signo];
    r[REG_RSP] = sp + 8;                        /* %16 == 8, [RSP]=restorer */
    r[REG_RDI] = (greg_t)signo;
    r[REG_RSI] = 0;
    r[REG_RDX] = 0;
    r[REG_RIP] = (greg_t)g_um.sig_handler[signo];
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
    uint64_t  entry;      /* runtime entry (link e_entry + bias) */
    uint64_t  phdr_va;    /* runtime AT_PHDR (link phdr vaddr + bias) */
    uint16_t  phnum;
    uint64_t  bias;       /* 0 for ET_EXEC, chosen base for ET_DYN */
    uint64_t  lo, hi;     /* page-aligned runtime guest image window */
    uint8_t   is_dyn;
    uint8_t   has_interp; /* PT_INTERP: needs ld.so — refused, not emulated */
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

/* Choose a collision-free load bias for an ET_DYN image whose link-time
 * page-extent is [vlo,vhi).  Deterministic 256 MiB candidates below the
 * host stack/vDSO ceiling; range-free is checked against /proc/self/maps. */
static int um_pick_bias(uint64_t vlo, uint64_t vhi, uint64_t *out) {
    for (uint64_t cand = 0x10000000ull; cand <= UM_IMAGE_LIMIT;
         cand += 0x10000000ull) {
        if (vhi > UM_IMAGE_LIMIT - cand) continue;   /* runtime window fits */
        uint64_t lo = cand + vlo, hi = cand + vhi;
        if (lo < 0x1000 || hi > UM_IMAGE_LIMIT) continue;
        if (um_range_free(lo, hi)) { *out = cand; return 0; }
    }
    return -1;                                /* no free window */
}

/* Map an ET_EXEC at its link addresses, or an ET_DYN (PIE) at a chosen load
 * bias.  A PT_INTERP image is flagged (not loaded) and refused by the caller:
 * running ld.so / shared objects is deliberately out of scope. */
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
        (eh.e_type != ET_EXEC && eh.e_type != ET_DYN) ||
        eh.e_machine != EM_X86_64 ||
        eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phnum == 0 ||
        (uint64_t)eh.e_phoff + (uint64_t)eh.e_phnum * eh.e_phentsize > im->len) {
        return -1;
    }
    im->is_dyn = (eh.e_type == ET_DYN);
    im->phnum = eh.e_phnum;

    uint64_t lo = UINT64_MAX, hi = 0;         /* link-time page extent */
    uint64_t link_phdr = 0;
    for (unsigned i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr ph;
        memcpy(&ph, im->file + eh.e_phoff + (uint64_t)i * sizeof ph, sizeof ph);
        if (ph.p_type == PT_INTERP) { im->has_interp = 1; continue; }
        if (ph.p_type == PT_PHDR) { link_phdr = ph.p_vaddr; continue; }
        if (ph.p_type != PT_LOAD) continue;
        if (ph.p_memsz < ph.p_filesz ||
            ph.p_offset + ph.p_filesz > im->len ||
            ph.p_vaddr + ph.p_memsz < ph.p_vaddr) return -1;
        uint64_t ps = ph.p_vaddr & ~0xfffull;
        uint64_t pe = (ph.p_vaddr + ph.p_memsz + 0xfffull) & ~0xfffull;
        if (!im->is_dyn && ps < 0x1000) return -1;
        if (ps < lo) lo = ps;
        if (pe > hi) hi = pe;
        if (ph.p_offset == 0 && !link_phdr) link_phdr = ph.p_vaddr + eh.e_phoff;
    }
    if (hi <= lo || hi - lo > (256u << 20)) return -1;

    uint64_t bias = 0;
    if (im->is_dyn) {
        if (um_pick_bias(lo, hi, &bias) != 0) return -2;
    } else {
        /* ET_EXEC keeps the original hard link-address rules. */
        if (hi >= (1ull << 32) || !um_range_free(lo, hi)) return -2;
    }
    if (eh.e_entry + bias < bias || eh.e_entry + bias > UM_IMAGE_LIMIT)
        return -1;
    im->bias = bias;
    im->lo = lo + bias;
    im->hi = hi + bias;
    im->entry = eh.e_entry + bias;
    im->phdr_va = link_phdr + bias;

    /* Pass 1: reserve every page range writable, then copy, then apply the
     * final protections (handles adjacent segments sharing a page). */
    for (unsigned i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr ph;
        memcpy(&ph, im->file + eh.e_phoff + (uint64_t)i * sizeof ph, sizeof ph);
        if (ph.p_type != PT_LOAD || !ph.p_memsz) continue;
        uint64_t ps = bias + (ph.p_vaddr & ~0xfffull);
        uint64_t pe = bias + ((ph.p_vaddr + ph.p_memsz + 0xfffull) & ~0xfffull);
        void *p = mmap((void *)(uintptr_t)ps, (size_t)(pe - ps),
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (p == MAP_FAILED) return -1;
    }
    for (unsigned i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr ph;
        memcpy(&ph, im->file + eh.e_phoff + (uint64_t)i * sizeof ph, sizeof ph);
        if (ph.p_type != PT_LOAD || !ph.p_memsz) continue;
        uint8_t *dst = (uint8_t *)(uintptr_t)(bias + ph.p_vaddr);
        memcpy(dst, im->file + ph.p_offset, (size_t)ph.p_filesz);
        memset(dst + ph.p_filesz, 0, (size_t)(ph.p_memsz - ph.p_filesz));
    }
    for (unsigned i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr ph;
        memcpy(&ph, im->file + eh.e_phoff + (uint64_t)i * sizeof ph, sizeof ph);
        if (ph.p_type != PT_LOAD || !ph.p_memsz) continue;
        uint64_t ps = bias + (ph.p_vaddr & ~0xfffull);
        uint64_t pe = bias + ((ph.p_vaddr + ph.p_memsz + 0xfffull) & ~0xfffull);
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
                               const UmImage *im, uint8_t **mem_out,
                               uint64_t *lo_out, uint64_t *hi_out) {
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
        { AT_BASE_, im->bias },    { AT_ENTRY_, im->entry },
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
    *lo_out = base;                          /* registered guest stack range */
    *hi_out = top;
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
    (void)um_raw1(37 /* SYS_alarm */, 0);
    if (!g_um.is_root) {
        /* A COW child is reaped by the guest parent's wait4: publish only a
         * real exit status there, never the run-wide shared result. */
        _exit(g_um.why == UM_WHY_EXIT ? (g_um.exit_code & 0xff) : 128);
    }
    shared->syscalls = g_um.syscalls;
    shared->denied = g_um.denied;
    shared->signals_delivered = g_um.sig_deliveries;
    shared->signals_denied = g_um.sig_denied;
    shared->bad_ptrs = g_um.bad_ptrs;
    shared->bad_ptr_nr = g_um.bad_ptr_nr;
    shared->bad_ptr_va = g_um.bad_ptr_va;
    shared->exit_code = g_um.exit_code;
    switch (g_um.why) {
    case UM_WHY_EXIT:  shared->status = WEMU_UM_OK;          break;
    case UM_WHY_FAULT: shared->status = WEMU_UM_ERR_FAULT;    break;
    case UM_WHY_ALARM: shared->status = WEMU_UM_ERR_BUDGET;   break;
    case UM_WHY_BADPTR: shared->status = WEMU_UM_ERR_BADPTR;  break;
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
    /* Guest must not read the harness's stdin, but fd 0 must stay VALID:
     * applets such as tr/od/expand probe it even with a file operand. */
    {
        int nullfd = open("/dev/null", O_RDONLY);
        if (nullfd >= 0) {
            if (dup2(nullfd, STDIN_FILENO) < 0)
                um_child_fail(shared, WEMU_UM_ERR_INTERNAL);
            close(nullfd);
        } else {
            close(STDIN_FILENO);
        }
    }
    if (dup2(out_fd, STDOUT_FILENO) < 0 || dup2(out_fd, STDERR_FILENO) < 0)
        um_child_fail(shared, WEMU_UM_ERR_INTERNAL);
    close(out_fd);

    UmImage im;
    int rc = um_load(path, &im);
    if (rc == -2) um_child_fail(shared, WEMU_UM_ERR_RANGE);
    if (rc != 0) um_child_fail(shared, WEMU_UM_ERR_FORMAT);
    if (im.has_interp) um_child_fail(shared, WEMU_UM_ERR_INTERP);
    uint8_t *stack_mem;
    uint64_t stack_lo = 0, stack_hi = 0;
    uint64_t rsp = um_build_stack(argv, envp, &im, &stack_mem,
                                  &stack_lo, &stack_hi);
    if (!rsp) um_child_fail(shared, WEMU_UM_ERR_INTERNAL);
    free(im.file);

    memset(&g_um, 0, sizeof g_um);
    g_um.is_root = 1;
    g_um.result = shared;
    g_um.win_lo = im.lo;
    g_um.win_hi = im.hi;
    g_um.stack_lo = stack_lo;
    g_um.stack_hi = stack_hi;
    /* The initial brk is the floor of the bounded guest heap; query it
     * BEFORE the trap filter is installed (host code, never trapped). */
    g_um.heap_lo = (uint64_t)(int64_t)syscall(SYS_brk, 0);
    g_um.heap_hi = g_um.heap_lo;

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
    if (sigaction(SIGSEGV, &sa, NULL) != 0 || sigaction(SIGBUS, &sa, NULL) != 0 ||
        sigaction(SIGILL, &sa, NULL) != 0 || sigaction(SIGFPE, &sa, NULL) != 0)
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
