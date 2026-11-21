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
 * SIGHAND/NEWPID/... are refused by the fork-only policy.
 *
 * Bounded shared-VM CLONE_THREAD: a clone whose flags are CLONE_VM +
 * CLONE_THREAD + CLONE_SIGHAND (plus whitelisted FS/FILES/SYSVSEM/TLS/TID
 * bits, no exit signal, no namespaces) is a REAL host thread created with
 * raw SYS_clone from the SIGSYS handler.  The guest's TLS value is passed
 * through to CLONE_SETTLS, so the kernel sets the new thread's fs base.  The
 * child resumes in the handler on the guest stack with no sigreturn frame;
 * it rebuilds a guest ucontext from the parent's SIGSYS frame and
 * setcontext()s into guest code with RAX=0 and the guest stack.  Per-thread
 * state is a bounded slot table selected by raw gettid() (the guest owns %fs,
 * so this cannot be __thread); dispatch is serialised by a spin lock that is dropped
 * around blocking host calls.  A bounded clone handshake stops a parent from
 * overwriting the bootstrap record before the child copies it.
 *
 * Bounded clone3 thread: the SAME thread shape submitted through clone3's
 * struct clone_args is admitted when args are exactly v0 (88 bytes), pidfd,
 * CLONE_PIDFD/CLONE_CLEAR_SIGHAND, namespaces, exit signal, set_tid and cgroup
 * are all absent, and the stack/TLS/TID knobs match the declared flags.  The
 * fields are translated to the equivalent raw SYS_clone arguments and the
 * bounded thread path above creates the host thread.  clone3 requests that
 * are not this shape or the bounded fork shape fail closed with an exact
 * reason code in WemuUmResult.refuses[].  set_tid/cgroup knobs, unmodeled fork
 * shapes and pidfd_send_signal carry their own exact refuse reasons.
 *
 * BOUNDED PIDFD AUTHORITY: pidfd_open/getfd/send_signal are no longer blanket
 * refusals.  pidfd_open admits ONLY a TID the guest actually created (the root
 * slot or an admitted CLONE_THREAD slot) with flags==0 and mints a real host
 * pidfd, tracked in a bounded table; pidfd_getfd admits ONLY a WEMU-minted
 * pidfd and a target fd in the guest's admitted fd table; pidfd_send_signal
 * admits ONLY a WEMU-minted pidfd and a whitelisted benign signal (SIGCONT).
 * In-scope shapes dispatch the real host syscall, so their guest-visible
 * result is byte-exact against the kernel oracle.  Every other shape fails
 * closed with an exact refuse reason and NO host syscall.  The per-thread
 * signal masks/dispositions and every out-of-scope pidfd refusal are kept.
 *
 * VIRTUAL PER-THREAD SIGNAL MASKS: rt_sigprocmask is never dispatched to the
 * host.  Each modeled thread owns a private 64-bit kernel sigset; SIG_BLOCK /
 * SIG_UNBLOCK / SIG_SETMASK and oldset are applied to that state, so a guest
 * can mask ordinary signals without ever changing the host thread's real mask
 * (which would silently block WEMU's SIGSYS trap, ALRM bound or USR2 quiesce).
 * A set touching a WEMU control signal still fails closed with an exact reason.
 * A new CLONE_THREAD inherits its parent's virtual mask.  The OLD pass-through
 * path and the coarse fail-closed diagnostics are kept behind negative-control
 * switches for the differential gates.
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
#define WEMU_UM_SYS_EXECVEAT     322 /* not in the VSL table */
#define WEMU_UM_SYS_KCMP         312 /* raw kcmp: open-file-description identity */
#define WEMU_UM_SYS_PIDFD_SEND_SIGNAL 424 /* pidfd_send_signal: bounded authority */
#define WEMU_UM_SYS_PIDFD_OPEN       434 /* pidfd_open: bounded authority */
#define WEMU_UM_SYS_PIDFD_GETFD      438 /* pidfd_getfd: bounded authority */
#define UM_PIDFD_NONBLOCK            0x800u /* fcntl.h PIDFD_NONBLOCK (x86-64) */
#define UM_SIGCONT                   18     /* x86-64 signal number (kernel) */
#define UM_KCMP_FILE             0    /* linux/kcmp.h KCMP_FILE */
#define UM_F_GETFD               1    /* fcntl(2) */
#define UM_F_DUPFD_CLOEXEC       1030 /* fcntl.h (x86-64) */
#define UM_FD_CLOEXEC            1    /* fcntl.h FD_CLOEXEC */
#define UM_ADMITTED_FD_MIN       512  /* held OFD dups stay above guest fd numbers */
#define UM_AT_FDCWD              (-100)
#define UM_AT_EMPTY_PATH         0x1000u /* fcntl.h AT_EMPTY_PATH (x86-64) */
#define UM_ARCH_GET_FS           0x1003
#define UM_ARCH_SET_FS           0x1002
#define SIG_DFL_ 0
#define SIG_IGN_ 1
/* Kernel sigset bit (signal N -> bit N-1).  A guest may never mask WEMU's
 * control signals: SIGSYS traps its syscalls, SIGALRM bounds the run and
 * SIGUSR2 quiesces peers during an exec from a thread. */
#define UM_WEMU_SIGMASK ((1ull << (SIGSYS - 1)) | (1ull << (SIGALRM - 1)) | \
                         (1ull << (SIGUSR2 - 1)))
/* x86-64 rt_sigprocmask `how` values. */
#define UM_SIG_BLOCK    0
#define UM_SIG_UNBLOCK  1
#define UM_SIG_SETMASK  2

/* x86-64 raw pkey syscalls (absent from some libc header sets).  Kept with
 * the WEMU_UM_SYS_ prefix so a future VSL addition is visible, not silently
 * duplicated.  Linux x86-64: pkey_mprotect=329, pkey_alloc=330, pkey_free=331. */
#define WEMU_UM_SYS_PKEY_MPROTECT 329
#define WEMU_UM_SYS_PKEY_ALLOC    330
#define WEMU_UM_SYS_PKEY_FREE     331
#define WEMU_PKU_CPUID_BIT        (1u << 3)   /* CPUID.(EAX=7,ECX=0).ECX.PKU */

/* PKRU is per-thread register state; rdpkru/wrpkru require ECX=EDX=0. */
static inline uint32_t um_rdpkru(void) {
    uint32_t v;
    __asm__ volatile("rdpkru" : "=a"(v) : "c"(0), "d"(0));
    return v;
}
static inline void um_wrpkru(uint32_t v) {
    __asm__ volatile("wrpkru" :: "a"(v), "c"(0), "d"(0) : "memory");
}
static int um_cpu_pkey_support(void) {
    unsigned eax, ebx, ecx, edx;
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "a"(7u), "c"(0u));
    return (ecx & WEMU_PKU_CPUID_BIT) != 0;
}

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
    { VSL_SYS_RT_SIGPROCMASK,  "rt_sigprocmask",  WEMU_UM_DISPATCH_SIGPROCMASK },
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
    { VSL_SYS_EXECVE,          "execve",          WEMU_UM_DISPATCH_EXECVE },
    { WEMU_UM_SYS_EXECVEAT,    "execveat",        WEMU_UM_DISPATCH_EXECVE },
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
    case WEMU_UM_ERR_SCRIPT:   return "ERR_SCRIPT";
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
#define UM_MAX_GUEST_FDS 32u          /* bounded admitted-fd table for execveat */
#define UM_MAX_PIDFDS 16u             /* bounded WEMU-minted pidfd table */
#define UM_HEAP_MAX   (16u << 20)   /* max brk growth above the initial break */

/* Number of general registers in mcontext_t (compile-time, no magic 23). */
#define UM_NGREG \
    (sizeof(((ucontext_t *)0)->uc_mcontext.gregs) / sizeof(greg_t))

/* x86-64 clone flags (linux/sched.h) used by the shared-VM thread model. */
#define UM_CLONE_VM           0x00000100ull
#define UM_CLONE_FS           0x00000200ull
#define UM_CLONE_FILES        0x00000400ull
#define UM_CLONE_SIGHAND      0x00000800ull
#define UM_CLONE_THREAD       0x00010000ull
#define UM_CLONE_SYSVSEM      0x00040000ull
#define UM_CLONE_SETTLS       0x00080000ull
#define UM_CLONE_PARENT_SETTID 0x00100000ull
#define UM_CLONE_CHILD_CLEARTID 0x00200000ull
#define UM_CLONE_CHILD_SETTID  0x01000000ull
#define UM_CLONE_PIDFD         0x00001000ull   /* CLONE_PIDFD: not modeled */
#define UM_CLONE_CLEAR_SIGHAND 0x100000000ull  /* CLONE_CLEAR_SIGHAND: not modeled */
#define UM_THREAD_FLAG_MASK  (UM_CLONE_VM | UM_CLONE_FS | UM_CLONE_FILES | \
                              UM_CLONE_SIGHAND | UM_CLONE_THREAD | UM_CLONE_SYSVSEM | \
                              UM_CLONE_SETTLS | UM_CLONE_PARENT_SETTID | \
                              UM_CLONE_CHILD_CLEARTID | UM_CLONE_CHILD_SETTID)

/* Bounded per-thread signal disposition table.  Only synchronous-fault
 * signals live here; a modeled CLONE_THREAD guest owns a private copy, a new
 * thread inherits a COPY of its parent's table, and a synchronous fault is
 * delivered from the FAULTING thread's table.  The legacy process-wide table
 * (used when the negative-control switch is off) is a separate UmSigDisp so
 * the two paths cannot alias. */
typedef struct {
    uint64_t handler[WEMU_UM_SIG_NSIG];
    uint64_t restorer[WEMU_UM_SIG_NSIG];
    uint32_t flags[WEMU_UM_SIG_NSIG];
    uint8_t  valid[WEMU_UM_SIG_NSIG];
} UmSigDisp;

/* Per-thread run state.  The guest owns %fs, so THIS cannot be __thread;
 * instead each bounded host thread owns a slot, selected by raw gettid().
 * Shared address-space state (ranges, counters, fd table, result page)
 * stays in g_um below and is guarded by the dispatch lock. */
typedef struct {
    volatile long tid;               /* 0 = free slot */
    volatile sig_atomic_t active;
    int is_root;
    volatile int why;
    volatile int exit_code;
    greg_t child_rsp;                /* stack for the abort/finish path */
    volatile int in_handler;         /* one live guest-signal delivery/thread */
    int saved_valid;
    greg_t saved_gregs[UM_NGREG];
    volatile uint32_t sig_deliveries;
    volatile uint32_t sig_denied;
    uint64_t clone_flags;            /* raw flags used to create this thread */
    uint8_t  modeled_thread;         /* 1 = admitted CLONE_THREAD shape */
    /* Private guest signal mask (kernel sigset, 64 bits).  Never applied to
     * the host thread: SIGSYS/ALRM/USR2 stay dispatchable while the guest
     * thinks it has blocked an ordinary signal. */
    uint64_t sig_mask;
    /* Private signal disposition table for this modeled thread.  Allocated
     * per slot (not __thread); a CLONE_THREAD child inherits a copy. */
    UmSigDisp disp;
} UmThread;

#define UM_SHAPE_THREAD 1u

static UmThread g_thr[WEMU_UM_MAX_THREADS];
static UmThread *g_boot_thr;         /* root slot, set before the guest runs */

/* Bounded slot allocator state, shared across the thread group (CLONE_VM). */
typedef struct {
    ucontext_t *uc;                  /* parent's SIGSYS ucontext (shared VM) */
    uint64_t child_stack;            /* guest-provided stack top */
    int slot;
    uint64_t child_sigmask;          /* inherited virtual signal mask */
} UmThreadBoot;
static UmThreadBoot g_boot;
static volatile int g_boot_ready;    /* parent waits until the child copied it */

/* An admitted guest fd is bound to the OPEN FILE DESCRIPTION that was live
 * when the guest obtained the number (openat/dup3).  `held` is a supervisor
 * CLOEXEC dup of that OFD, kept above the guest fd range; `fd` is the guest-
 * visible number.  kcmp(KCMP_FILE, fd, held)==0 at exec time proves the number
 * still describes the SAME OFD — a close+reopen (or dup2 onto the number)
 * yields a different struct file and is refused, even for the same inode. */
typedef struct {
    long    fd;        /* admitted guest fd number */
    long    held;      /* supervisor dup of the admitted OFD (CLOEXEC) */
    uint8_t cloexec;   /* guest fd had FD_CLOEXEC set at admission */
    /* Stable identity captured at admission for the fail-closed fallback
     * when kcmp(KCMP_FILE) is unavailable (-ENOSYS/-EPERM).  Raw kernel
     * stat layout puts st_dev at byte 0 and st_ino at byte 8. */
    uint64_t dev;
    uint64_t ino;
} UmAdmittedFd;

/* A pidfd WEMU minted on behalf of the guest via a bounded pidfd_open.  `pfd`
 * is the guest-visible (== host) fd number and `tid` is the admitted guest TID
 * it denotes.  Only a pidfd in this table may be used by pidfd_getfd /
 * pidfd_send_signal: a raw fd number the guest never obtained from WEMU's
 * pidfd_open is an out-of-scope shape and fails closed.  Process-wide like the
 * fd table (CLONE_FILES shares fds), guarded by the dispatch lock. */
typedef struct {
    long    pfd;
    long    tid;
    uint8_t valid;
} UmPidfd;

static struct {
    volatile uint64_t syscalls;
    volatile uint64_t denied;
    uint64_t win_lo, win_hi;       /* guest ELF image window (PT_LOAD) */
    uint64_t stack_lo, stack_hi;   /* SysV initial stack mapping */
    uint64_t heap_lo, heap_hi;     /* bounded brk heap [initial break, current] */
    uint64_t mmap_lo[UM_MAX_MMAPS], mmap_hi[UM_MAX_MMAPS];
    uint32_t n_mmaps;
    /* Bounded guest fd table: fd numbers the guest legitimately obtained
     * (openat/dup3), each bound to the open-file-description live at that
     * moment.  execveat with AT_EMPTY_PATH or a dirfd-relative path is admitted
     * ONLY for an fd in this table whose OFD is UNCHANGED (kcmp) — a guest
     * cannot execute a file described by a supervisor fd it never opened, nor
     * one whose number it closed and reopened.  fd state is process-wide
     * (CLONE_FILES shares it), so it lives here, guarded by the dispatch lock. */
    UmAdmittedFd guest_fds[UM_MAX_GUEST_FDS];
    uint32_t n_guest_fds;
    /* Bounded WEMU-minted pidfd table (see UmPidfd above). */
    UmPidfd pidfds[UM_MAX_PIDFDS];
    uint32_t n_pidfds;
    uint64_t arena_lo, arena_hi;   /* registered MAP_SHARED guest arena */
    volatile uint32_t bad_ptrs;    /* pointers refused before host dispatch */
    volatile uint32_t bad_ptr_nr;
    volatile uint64_t bad_ptr_va;
    int      fault_code;           /* si_code of last guest sync fault */
    int      fault_pkey;           /* si_pkey of a SEGV_PKUERR fault, -1 else */
    WemuUmResult *result;
    /* Legacy PROCESS-WIDE signal dispositions (CLONE_SIGHAND shared).  Used
     * only by the negative-control path (per-thread dispositions disabled);
     * the hardened path stores dispositions in each UmThread.disp instead. */
    UmSigDisp shared_disp;
} g_um;

/* Supervisor-side isolation configuration.  Set by the gate BEFORE
 * wemu_um_run_elf(), inherited by the forked guest child (COW), and read by
 * the child while it builds the guest address space.  Isolation is ON by
 * default; the disable switch exists only as a differential-test control. */
static struct {
    uint64_t arena_lo, arena_hi;   /* MAP_SHARED guest arena (0 = none) */
    uint64_t hide_lo[WEMU_UM_MAX_HOST_PAGES];
    uint64_t hide_hi[WEMU_UM_MAX_HOST_PAGES];
    uint32_t n_hide;
    int enabled;
    int pkey_mode;               /* WEMU_UM_PKEY_AUTO or FORCE_FALLBACK */
    int thread_exec_enabled;     /* bounded execve from a CLONE_THREAD guest */
    int clone3_thread_enabled;   /* bounded CLONE_THREAD via clone3 (old-path control) */
    int sigmask_virtual_enabled; /* guest masks stay in per-thread state */
    int thread_disp_enabled;     /* per-thread rt_sigaction disposition tables */
    int exact_refuse_enabled;    /* dedicated refuse codes instead of coarse */
    int fd_ofd_check_enabled;    /* bind admitted fds to their OFD (kcmp) */
    /* Negative-control knobs for the fd-identity differential gates.  Both
     * default to the hardened behaviour; the gate flips them to reproduce the
     * OLD refusal path and the kernel-without-kcmp fallback path. */
    int fd_kcmp_forced_off;      /* 1 = pretend kcmp is unavailable (-ENOSYS) */
    int fd_cloexec_refuse;       /* 1 = OLD path: refuse every CLOEXEC fd */
    int pidfd_authority_enabled; /* bounded pidfd authority (OLD path off) */
} g_cfg = { .enabled = 1, .pkey_mode = WEMU_UM_PKEY_AUTO,
            .thread_exec_enabled = 1, .clone3_thread_enabled = 1,
            .sigmask_virtual_enabled = 1, .thread_disp_enabled = 1,
            .exact_refuse_enabled = 1, .fd_ofd_check_enabled = 1,
            .fd_kcmp_forced_off = 0, .fd_cloexec_refuse = 0,
            .pidfd_authority_enabled = 1 };

/* CPU-enforced protection-key state, built in the forked guest child before
 * the first guest instruction.  PKRU is per-thread: the supervisor (parent)
 * keeps its own value and full access to its pages. */
static uint32_t g_host_pkru;      /* all guest/host keys enabled (handler state) */
static uint32_t g_guest_pkru;     /* guest state: guest key on, host key denied */
static int g_pkey_guest = -1;     /* pkey assigned to the guest arena */
static int g_pkey_host  = -1;     /* pkey assigned to registered host pages */
static uint32_t g_pkey_active;    /* 1 when hardware keys protect this run */
static uint32_t g_pkey_fallback;  /* 1 when the munmap hide path was used */
int wemu_um_set_guest_arena(void *base, size_t len) {
    uint64_t b = (uint64_t)(uintptr_t)base;
    if (!base || (b & 0xfffull) || len < (2u << 20) || b + len < b) return -1;
    g_cfg.arena_lo = b;
    g_cfg.arena_hi = b + len;
    return 0;
}

int wemu_um_isolate_host_pages(void *addr, size_t len) {
    uint64_t lo = (uint64_t)(uintptr_t)addr;
    if (!addr || !len || lo + len < lo) return -1;
    if (g_cfg.n_hide >= WEMU_UM_MAX_HOST_PAGES) return -1;
    g_cfg.hide_lo[g_cfg.n_hide] = lo;
    g_cfg.hide_hi[g_cfg.n_hide] = lo + len;
    g_cfg.n_hide++;
    return 0;
}

void wemu_um_reset_isolation(void) {
    g_cfg.arena_lo = g_cfg.arena_hi = 0;
    g_cfg.n_hide = 0;
    g_cfg.enabled = 1;
    g_cfg.pkey_mode = WEMU_UM_PKEY_AUTO;
    g_cfg.thread_exec_enabled = 1;
    g_cfg.clone3_thread_enabled = 1;
    g_cfg.sigmask_virtual_enabled = 1;
    g_cfg.thread_disp_enabled = 1;
    g_cfg.exact_refuse_enabled = 1;
    g_cfg.fd_ofd_check_enabled = 1;
    g_cfg.fd_kcmp_forced_off = 0;
    g_cfg.fd_cloexec_refuse = 0;
    g_cfg.pidfd_authority_enabled = 1;
    memset(&g_um.pidfds, 0, sizeof g_um.pidfds);
    g_um.n_pidfds = 0;
}

int wemu_um_set_isolation_enabled(int enabled) {
    if (enabled != 0 && enabled != 1) return -1;
    g_cfg.enabled = enabled;
    return 0;
}

int wemu_um_set_thread_exec_enabled(int enabled) {
    if (enabled != 0 && enabled != 1) return -1;
    g_cfg.thread_exec_enabled = enabled;
    return 0;
}

int wemu_um_set_clone3_thread_enabled(int enabled) {
    if (enabled != 0 && enabled != 1) return -1;
    g_cfg.clone3_thread_enabled = enabled;
    return 0;
}

int wemu_um_set_sigmask_virtual_enabled(int enabled) {
    if (enabled != 0 && enabled != 1) return -1;
    g_cfg.sigmask_virtual_enabled = enabled;
    return 0;
}

int wemu_um_set_thread_disp_enabled(int enabled) {
    if (enabled != 0 && enabled != 1) return -1;
    g_cfg.thread_disp_enabled = enabled;
    return 0;
}

/* The disposition table the caller must read/write: the faulting thread's
 * private table on the hardened path, the legacy process-wide table on the
 * negative-control path.  Both live in shared VM, so a CLONE_THREAD child may
 * copy its parent's via *um_disp(parent) before the raw clone. */
static UmSigDisp *um_disp(UmThread *th) {
    return g_cfg.thread_disp_enabled ? &th->disp : &g_um.shared_disp;
}

int wemu_um_set_exact_refuse_enabled(int enabled) {
    if (enabled != 0 && enabled != 1) return -1;
    g_cfg.exact_refuse_enabled = enabled;
    return 0;
}

int wemu_um_set_fd_ofd_check_enabled(int enabled) {
    if (enabled != 0 && enabled != 1) return -1;
    g_cfg.fd_ofd_check_enabled = enabled;
    return 0;
}

int wemu_um_set_fd_kcmp_forced_off(int forced_off) {
    if (forced_off != 0 && forced_off != 1) return -1;
    g_cfg.fd_kcmp_forced_off = forced_off;
    return 0;
}

int wemu_um_set_fd_cloexec_refuse(int refuse) {
    if (refuse != 0 && refuse != 1) return -1;
    g_cfg.fd_cloexec_refuse = refuse;
    return 0;
}

/* The exec-from-thread policy is exactly the modeled shared-VM CLONE_THREAD
 * shape; keeping it a single predicate makes the handler and the gate audit
 * the same rule.  A slot that reaches exec was admitted at clone time: raw
 * clone or the bounded clone3 shape both record these flags.  Requests with
 * pidfd / signal-mask knobs are refused before a slot is allocated, so they
 * never reach exec. */
int wemu_um_thread_exec_modeled(uint64_t flags) {
    return wemu_um_clone_thread_flags_modeled(flags);
}

int wemu_um_set_pkey_mode(int mode) {
    if (mode != WEMU_UM_PKEY_AUTO && mode != WEMU_UM_PKEY_FORCE_FALLBACK) return -1;
    g_cfg.pkey_mode = mode;
    return 0;
}

/* Raw pkey syscalls (host context, RIP outside the guest image: not trapped). */
/* Forward declarations: um_raw0/um_raw1 are defined with the other raw
 * syscall helpers later in this file. */
static int64_t um_raw0(long nr);
static int64_t um_raw1(long nr, long a0);
static uint32_t um_hide_host_pages(void);

static int64_t um_raw_pkey_alloc(void) {
    long ret;
    /* pkey_alloc(unsigned long flags, unsigned long init): both args must be
     * ZERO — um_raw0() leaves rdi/rsi undefined, which the kernel rejects. */
    __asm__ volatile("syscall" : "=a"(ret)
        : "a"((long)WEMU_UM_SYS_PKEY_ALLOC), "D"(0L), "S"(0L)
        : "rcx", "r11", "memory");
    return (int64_t)ret;
}
static int64_t um_raw_pkey_mprotect(uint64_t lo, uint64_t hi, int key) {
    register long r10 __asm__("r10") = (long)key;
    long ret;
    __asm__ volatile("syscall" : "=a"(ret)
        : "a"((long)WEMU_UM_SYS_PKEY_MPROTECT), "D"((long)lo),
          "S"((long)(hi - lo)), "d"((long)(PROT_READ | PROT_WRITE)), "r"(r10)
        : "rcx", "r11", "memory");
    return (int64_t)ret;
}
/* Set up CPU-enforced protection of the registered host pages in the forked
 * guest child, BEFORE its first guest instruction.  The guest arena gets one
 * key (always accessible); registered host pages get another key whose AD bit
 * is set in PKRU while the guest runs, so a direct guest load/store raises a
 * hardware SEGV_PKUERR instead of observing host bytes.  If the host lacks
 * PKU or a syscall fails, the run FAILS CLOSED to the munmap hide path — it
 * is never left unprotected.  Returns 0, or -1 if even the fallback fails. */
static int um_setup_pkeys(WemuUmResult *shared) {
    g_pkey_guest = g_pkey_host = -1;
    g_pkey_active = g_pkey_fallback = 0;
    g_um.fault_code = 0;
    g_um.fault_pkey = -1;
    shared->pkey_active = 0;
    shared->pkey_fallback = 0;
    shared->pkey_guest = shared->pkey_host = -1;
    shared->fault_code = 0;
    shared->fault_pkey = -1;

    /* No host pages registered: nothing to protect, nothing to hide. */
    if (!g_cfg.n_hide) { g_host_pkru = um_rdpkru(); return 0; }

    int try_pkey = (g_cfg.pkey_mode == WEMU_UM_PKEY_AUTO) &&
                   um_cpu_pkey_support();
    if (try_pkey) {
        int64_t kh = um_raw_pkey_alloc();
        if (kh >= 0) {
            /* The arena stays in the DEFAULT key (0), which is always
             * accessible.  A nonzero arena key would break every guest
             * syscall/signal: Linux resets PKRU on signal delivery, and our
             * handlers run on the guest stack inside the arena, so a keyed
             * arena would fault on the handler's first stack access. */
            g_pkey_host = (int)kh;
            g_pkey_guest = 0;
        }
    }

    if (g_pkey_host >= 0) {
        /* Key allocated: the kernel cleared AD/WD for it in this thread's
         * PKRU.  Stamp the arena with the default key and every host-only
         * region with the dedicated host key.  All ranges are page-aligned
         * by contract. */
        int ok = 1;
        if (g_cfg.arena_hi > g_cfg.arena_lo &&
            um_raw_pkey_mprotect(g_cfg.arena_lo, g_cfg.arena_hi, 0) != 0)
            ok = 0;
        for (uint32_t i = 0; ok && i < g_cfg.n_hide; i++)
            if (um_raw_pkey_mprotect(g_cfg.hide_lo[i], g_cfg.hide_hi[i],
                                     g_pkey_host) != 0) ok = 0;
        if (ok) {
            /* Keep the key allocated (do not free: freeing would re-disable
             * the stamped pages).  PKRU denies the host key only in the guest
             * child; the supervisor parent retains full access. */
            g_host_pkru = um_rdpkru();
            g_guest_pkru = g_host_pkru |
                           (1u << (2u * (unsigned)g_pkey_host));
            g_guest_pkru &= ~3u;               /* keep key 0 (arena) enabled */
            g_pkey_active = 1;
            shared->pkey_active = 1;
            shared->pkey_guest = g_pkey_guest;
            shared->pkey_host  = g_pkey_host;
            return 0;
        }
        /* mprotect failed after keys were stamped: fall through to munmap.
         * Do NOT free the keys (that would lock out the stamped arena); the
         * child exits shortly, reclaiming them with its mm. */
    }

    /* Fail-closed fallback: pkeys unsupported/unavailable/forced off.  Remove
     * host pages from the guest page table — a plain #PF still blocks the
     * read.  A short count fails the run closed. */
    g_pkey_fallback = 1;
    shared->pkey_fallback = 1;
    g_host_pkru = um_rdpkru();
    g_guest_pkru = g_host_pkru;
    return (um_hide_host_pages() == g_cfg.n_hide) ? 0 : -1;
}

/* Called in the FORKED GUEST CHILD, after all host-side setup is complete and
 * before setcontext() transfers control to the guest.  Removing the mapping
 * is what makes host bytes unobservable by ordinary guest loads/stores; the
 * syscall validator is the second, independent line of defence.  Returns the
 * number of regions actually removed (a short count fails the run closed). */
static uint32_t um_hide_host_pages(void) {
    uint32_t n = 0;
    for (uint32_t i = 0; i < g_cfg.n_hide; i++)
        if (munmap((void *)(uintptr_t)g_cfg.hide_lo[i],
                   (size_t)(g_cfg.hide_hi[i] - g_cfg.hide_lo[i])) == 0) n++;
    return n;
}

/* The guest owns %fs while our handlers run, so the image loader (malloc,
 * stdio) must be called only after %fs is put back on the HOST's value.
 * Captured in um_child_run before the guest first runs. */
static uint64_t g_host_fs;

/* Bounded, host-owned copy of a guest exec request.  The SIGSYS handler only
 * saves the three guest pointers; the strings are copied in host context
 * (host %fs restored) by um_exec_continue before the old image is touched. */
#define UM_EXEC_MAX_ARG   256u
#define UM_EXEC_MAX_NARG  64u
#define UM_EXEC_STORE     (16u << 10)
typedef struct {
    uint32_t nr;
    uint64_t pathp, argvp, envpp;
    long     dirfd;                  /* execveat dirfd (AT_FDCWD for execve) */
    uint64_t flags;                  /* execveat flags (0 for execve) */
    uint8_t  empty_path;             /* AT_EMPTY_PATH: path names an fd, not a path */
    uint8_t  from_thread;            /* caller was a non-root CLONE_THREAD guest */
    size_t   used;
    char     store[UM_EXEC_STORE];
    const char *path;
    char    *argv[UM_EXEC_MAX_NARG + 1];
    char    *envp[UM_EXEC_MAX_NARG + 1];
} UmExecReq;
static UmExecReq g_exec;

/* ---- bounded #! script dispatch -------------------------------------- */
/* Linux binfmt_script rebuilds argv as [interp, i_arg?, script, argv[1]...].
 * We parse only the first UM_SCRIPT_BUF bytes (the kernel's BINPRM_BUF_SIZE)
 * and refuse a line without a terminator, an empty/overlong interpreter or an
 * overlong optional argument — no partial or speculative dispatch. */
#define UM_SCRIPT_BUF 256u

typedef struct {
    char interp[UM_EXEC_MAX_ARG];
    char opt[UM_EXEC_MAX_ARG];
    int  has_opt;
} UmShebang;

/* Per-depth rebuilt argv slots: a script hop writes slot[depth] while reading
 * slot[depth-1] (or g_exec.argv at depth 0), so chains never alias. */
static char *g_script_argv[WEMU_UM_MAX_SCRIPT_DEPTH + 1][UM_EXEC_MAX_NARG + 1];

/* Pure parser over a bounded header buffer.  0 = not a script, 1 = a valid
 * bounded #! line, -1 = starts with #! but malformed (fail closed). */
static int um_parse_shebang(const char *buf, size_t n, UmShebang *sh) {
    if (n < 2 || buf[0] != '#' || buf[1] != '!') return 0;
    size_t cap = n < UM_SCRIPT_BUF ? n : (size_t)UM_SCRIPT_BUF;
    size_t i = 2;
    while (i < cap && (buf[i] == ' ' || buf[i] == '\t')) i++;
    size_t is = i;
    while (i < cap && buf[i] != ' ' && buf[i] != '\t' &&
           buf[i] != '\n' && buf[i] != '\r') i++;
    size_t il = i - is;
    if (il == 0 || il >= UM_EXEC_MAX_ARG) return -1;
    while (i < cap && (buf[i] == ' ' || buf[i] == '\t')) i++;
    if (i >= cap) return -1;                   /* no terminator in window */
    if (sh) {
        memcpy(sh->interp, buf + is, il); sh->interp[il] = 0;
        sh->opt[0] = 0; sh->has_opt = 0;
    }
    if (buf[i] == '\n' || buf[i] == '\r') return 1;
    size_t os = i;
    while (i < cap && buf[i] != '\n' && buf[i] != '\r') i++;
    if (i >= cap) return -1;                   /* optional arg unterminated */
    size_t ol = i - os;
    if (ol == 0 || ol >= UM_EXEC_MAX_ARG) return -1;
    if (sh) {
        memcpy(sh->opt, buf + os, ol); sh->opt[ol] = 0; sh->has_opt = 1;
    }
    return 1;
}

int wemu_um_exec_script_modeled(const char *hdr, size_t n) {
    if (!hdr) return 0;
    UmShebang sh;
    return um_parse_shebang(hdr, n, &sh) == 1;
}

/* Copy a host-side string (interpreter path / optional arg / script path)
 * into the bounded, host-owned exec store so it survives image teardown. */
static const char *um_exec_store_str(const char *s) {
    size_t n = strlen(s);
    if (n >= UM_EXEC_MAX_ARG || g_exec.used + n + 1 > UM_EXEC_STORE) return NULL;
    char *d = g_exec.store + g_exec.used;
    memcpy(d, s, n);
    d[n] = 0;
    g_exec.used += n + 1;
    return d;
}

/* Serialise dispatch state updates.  Released around blocking host calls so
 * a futex-waiting thread cannot freeze a peer that needs to wake it. */
static volatile int g_dispatch_lock;
static void um_lock(void) {
    while (__atomic_exchange_n(&g_dispatch_lock, 1, __ATOMIC_ACQUIRE)) { }
}
static void um_unlock(void) {
    __atomic_store_n(&g_dispatch_lock, 0, __ATOMIC_RELEASE);
}

/* Only these synchronous-fault signals are ever registered or delivered.
 * Everything else is refused by rt_sigaction and would unwind on fault. */
static int um_sig_sync(int sig) {
    return sig == SIGSEGV || sig == SIGBUS || sig == SIGILL || sig == SIGFPE;
}

int wemu_um_signal_modeled(int sig) { return um_sig_sync(sig); }

int wemu_um_sigaction_modeled(int sig, uint64_t sigsetsize) {
    return um_sig_sync(sig) && sigsetsize == 8;
}

/* ---- bounded pidfd authority: pure shape predicates ----------------- */
/* Runtime ownership state (admitted TID / minted pidfd / admitted fd) is
 * checked by the handler in addition to these pure form checks. */
int wemu_um_pidfd_open_modeled(uint64_t flags) {
    return flags == 0;                    /* PIDFD_NONBLOCK / unlisted bits: no */
}

int wemu_um_pidfd_getfd_modeled(uint64_t flags) {
    return flags == 0;                    /* pidfd_getfd flags must be zero */
}

int wemu_um_pidfd_signal_modeled(int sig) {
    /* SIGCONT's default action is a no-op for a running process, so signalling
     * a WEMU-minted pidfd with it is a bounded, byte-exact host differential. */
    return sig == UM_SIGCONT;
}

int wemu_um_set_pidfd_authority_enabled(int enabled) {
    if (enabled != 0 && enabled != 1) return -1;
    g_cfg.pidfd_authority_enabled = enabled;
    return 0;
}

/* Registered in the CALLING thread's disposition table (or the legacy shared
 * table on the negative-control path), never process-wide on the hardened
 * path.  A fault is delivered from the faulting thread's own table. */
static int um_sig_registered(int sig, UmThread *th) {
    return sig > 0 && sig < WEMU_UM_SIG_NSIG && um_disp(th)->valid[sig];
}

static void um_finish(void) __attribute__((noreturn));
/* Bounded image replacement: entered in HOST context (host %fs restored) on
 * the child's original stack after the SIGSYS handler rewrote RIP/RSP. */
static void um_exec_continue(void) __attribute__((noreturn));

/* Redirect sigreturn to our own stack.  siglongjmp from a signal delivered
 * on the guest stack is rejected by glibc's fortified ____longjmp_chk and
 * is needlessly dangerous anyway: rewriting REG_RIP/REG_RSP and returning
 * from the handler makes the kernel restore the ORIGINAL stack for us. */
static void um_abort_to_finish(ucontext_t *uc, UmThread *th, int why) {
    th->why = why;
    uc->uc_mcontext.gregs[REG_RIP] = (greg_t)(uintptr_t)um_finish;
    uc->uc_mcontext.gregs[REG_RSP] = (th->child_rsp - 16) & ~(greg_t)15;
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

/* Raw arch_prctl(ARCH_GET_FS/ARCH_SET_FS).  A glibc syscall() wrapper would
 * write errno through %fs (guest-owned inside a handler), so use raw asm.
 * ARCH_GET_FS takes a POINTER; ARCH_SET_FS takes a value. */
static uint64_t um_raw_get_fs(void) {
    uint64_t v = 0;
    register long rsi __asm__("rsi") = (long)&v;
    long ret;
    __asm__ volatile("syscall" : "=a"(ret), "+m"(v)
                     : "a"(158L /* SYS_arch_prctl */),
                       "D"(0x1003L /* ARCH_GET_FS */), "r"(rsi)
                     : "rcx", "r11", "memory");
    (void)ret;
    return v;
}

static int um_raw_set_fs(uint64_t v) {
    long ret;
    __asm__ volatile("syscall" : "=a"(ret)
                     : "a"(158L /* SYS_arch_prctl */),
                       "D"(0x1002L /* ARCH_SET_FS */), "S"((long)v)
                     : "rcx", "r11", "memory");
    return ret == 0 ? 0 : -1;
}

static void um_skip_syscall(greg_t *r);

/* TLS-free current-thread lookup: the guest owns %fs, so __thread is unsafe.
 * A raw gettid() plus a bounded slot table identifies the host thread. */
static long um_raw_gettid(void) { return (long)um_raw0(186 /* SYS_gettid */); }

static UmThread *um_thread_select(void) {
    long tid = um_raw_gettid();
    for (unsigned i = 0; i < WEMU_UM_MAX_THREADS; i++)
        if (g_thr[i].tid == tid) return &g_thr[i];
    return NULL;
}

/* ---- bounded exec-from-thread: quiesce peer host threads -------------- */
/* An execve from a shared-VM thread replaces the image for the WHOLE thread
 * group: the kernel kills every peer thread and continues on the caller with
 * fresh registers and a fresh TLS base.  WEMU's peer threads are real host
 * threads sharing the image window, so leaving one alive would run stale
 * guest code over a replaced image.  Before the swap we signal each active
 * peer with a reserved host signal; its handler marks the slot inactive and
 * exits only that thread with a raw SYS_exit (no glibc/TLS, %fs is the
 * guest's).  SIGUSR2 is outside the guest signal table (WEMU_UM_SIG_NSIG=32)
 * and outside WEMU's own SIGSYS/SIGSEGV/SIGALRM handlers. */
#define UM_EXEC_QUIESCE_SIG SIGUSR2

static void um_exec_peer_die(int sig, siginfo_t *si, void *ucv) {
    (void)sig; (void)si; (void)ucv;
    UmThread *th = um_thread_select();       /* raw gettid: TLS-free */
    if (th) __atomic_store_n(&th->active, 0, __ATOMIC_RELEASE);
    __asm__ volatile("syscall" :: "a"(60L /* SYS_exit */), "D"(0L)
                     : "rcx", "r11", "memory");
    _exit(0);                                /* unreachable */
}

/* Three-arg raw syscall helper (tgkill). */
static int64_t um_raw3(long nr, long a0, long a1, long a2) {
    long ret;
    __asm__ volatile("syscall" : "=a"(ret)
                     : "a"(nr), "D"(a0), "S"(a1), "d"(a2)
                     : "rcx", "r11", "memory");
    return (int64_t)ret;
}

/* Raw fcntl(fd, cmd, arg) for fd admission from the SIGSYS handler (guest
 * %fs): F_DUPFD_CLOEXEC holds a stable OFD handle; F_GETFD reads the guest's
 * FD_CLOEXEC bit.  glibc's fcntl() writes errno through the guest TCB. */
static long um_raw_fcntl(long fd, long cmd, long arg) {
    long ret;
    __asm__ volatile("syscall" : "=a"(ret)
                     : "a"(72L /* SYS_fcntl */), "D"(fd), "S"(cmd), "d"(arg)
                     : "rcx", "r11", "memory");
    return ret;
}

/* Raw kcmp(pid,pid,KCMP_FILE,a,b) for open-file-description identity.  The
 * caller passes pid from raw getpid() so no glibc/TLS is touched.  Kernel
 * return: 0 = same struct file (same OFD), >0 = different OFD, -errno on
 * error (fd closed or kcmp unavailable) — the caller treats only 0 as a
 * match, so all failures fail closed. */
static long um_raw_kcmp(long pid, long a, long b) {
    register long r10 __asm__("r10") = a;
    register long r8  __asm__("r8")  = b;
    long ret;
    __asm__ volatile("syscall" : "=a"(ret)
                     : "a"((long)WEMU_UM_SYS_KCMP), "D"(pid), "S"(pid),
                       "d"((long)UM_KCMP_FILE), "r"(r10), "r"(r8)
                     : "rcx", "r11", "memory");
    return ret;
}

/* Raw fstat for the dev/ino fallback.  This runs from the SIGSYS handler
 * (guest %fs), so it must not use glibc's fstat wrapper.  The x86-64 kernel
 * stat layout has st_dev at offset 0 and st_ino at offset 8 (both 64-bit);
 * the kernel writes the whole 144-byte struct, so provide a full buffer.
 * Returns 0 and the identity on success, -1 on any fstat error. */
static int um_raw_fstat_devino(long fd, uint64_t *dev, uint64_t *ino) {
    unsigned long kstat[18];          /* 144 bytes: x86-64 kernel struct stat */
    long ret;
    __asm__ volatile("syscall" : "=a"(ret)
                     : "a"(5L /* SYS_fstat */), "D"(fd), "S"(kstat)
                     : "rcx", "r11", "memory");
    if (ret < 0) return -1;
    *dev = (uint64_t)kstat[0];
    *ino = (uint64_t)kstat[1];
    return 0;
}

/* A CLONE_THREAD guest's stack is a static array INSIDE the image window that
 * execve replaces; mapping the new image at the same bias would clobber the
 * very stack um_exec_continue runs on.  Allocate a fresh HOST stack (outside
 * every guest window) for the loader.  Raw syscall: this is called from the
 * SIGSYS handler where %fs is the guest's and glibc is unsafe.  Returns the
 * stack TOP, or 0 on failure. */
#define UM_EXEC_STACK_SZ (1u << 20)
static uint64_t um_raw_exec_stack(void) {
    register long r10 __asm__("r10") = 0x22L; /* MAP_PRIVATE | MAP_ANONYMOUS */
    register long r8  __asm__("r8")  = -1L;
    register long r9  __asm__("r9")  = 0L;
    long ret;
    __asm__ volatile("syscall" : "=a"(ret)
        : "a"(9L /* SYS_mmap */), "D"(0L), "S"((long)UM_EXEC_STACK_SZ),
          "d"(3L /* PROT_READ|PROT_WRITE */), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    if ((uint64_t)ret >= (uint64_t)-4095ULL) return 0;
    return (uint64_t)ret + UM_EXEC_STACK_SZ;
}

/* Signal every active peer to die and wait (boundedly) for their slots to go
 * inactive.  Returns 0 when the group is down to the caller only, -1 if any
 * peer failed to quiesce in budget (the caller then fails the run closed —
 * no image is swapped under a live peer).  Called in HOST context from
 * um_exec_continue with %fs restored. */
static int um_exec_quiesce(UmThread *caller) {
    long self = um_raw_gettid();
    long pid  = (long)um_raw0(39 /* SYS_getpid */);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = um_exec_peer_die;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(UM_EXEC_QUIESCE_SIG, &sa, NULL) != 0) return -1;

    int have_peer = 0;
    for (unsigned i = 0; i < WEMU_UM_MAX_THREADS; i++) {
        UmThread *t = &g_thr[i];
        long tid = __atomic_load_n(&t->tid, __ATOMIC_ACQUIRE);
        if (t == caller || tid <= 0 || tid == self) continue;
        if (!__atomic_load_n(&t->active, __ATOMIC_ACQUIRE)) continue;
        /* A non-root peer that is not the bounded CLONE_THREAD shape is
         * unsupported: fail closed instead of replacing the image beneath
         * it.  The root (slot 0) is always an admissible peer. */
        if (t != &g_thr[0] &&
            (t->modeled_thread != UM_SHAPE_THREAD ||
             !wemu_um_thread_exec_modeled(t->clone_flags))) return -1;
        (void)um_raw3(234 /* SYS_tgkill */, pid, tid, UM_EXEC_QUIESCE_SIG);
        have_peer = 1;
    }
    if (!have_peer) return 0;

    for (unsigned tries = 0; tries < 500000u; tries++) {
        int all_quiet = 1;
        for (unsigned i = 0; i < WEMU_UM_MAX_THREADS; i++) {
            UmThread *t = &g_thr[i];
            long tid = __atomic_load_n(&t->tid, __ATOMIC_ACQUIRE);
            if (t == caller || tid <= 0 || tid == self) continue;
            if (__atomic_load_n(&t->active, __ATOMIC_ACQUIRE)) {
                all_quiet = 0; break;
            }
        }
        if (all_quiet) return 0;
        (void)um_raw0(24 /* SYS_sched_yield */);
    }
    return -1;
}

/* Raw clone(2): flags/stack/ptid/ctid/tls exactly as the guest supplied them.
 * CLONE_SETTLS in `flags` makes the KERNEL apply the guest's TLS value to the
 * new host thread's fs base — no host-side TLS surgery. */
static int64_t um_raw_clone(uint64_t flags, uint64_t stack, uint64_t ptid,
                            uint64_t ctid, uint64_t tls) {
    register long r10 __asm__("r10") = (long)ctid;
    register long r8  __asm__("r8")  = (long)tls;
    long ret;
    __asm__ volatile("syscall"
        : "=a"(ret)
        : "a"(56L /* SYS_clone */), "D"((long)flags), "S"((long)stack),
          "d"((long)ptid), "r"(r10), "r"(r8)
        : "rcx", "r11", "memory");
    return (int64_t)ret;
}

/* ---- bounded shared-VM CLONE_THREAD -------------------------------- */
int wemu_um_clone_thread_flags_modeled(uint64_t flags) {
    uint64_t sig = flags & 0xffull;
    if (sig != 0) return 0;                  /* threads have no exit signal */
    if ((flags & UM_THREAD_FLAG_MASK) != (flags & ~0xffull)) return 0;
    if (!(flags & UM_CLONE_VM) || !(flags & UM_CLONE_THREAD) ||
        !(flags & UM_CLONE_SIGHAND)) return 0;
    if (flags & ~(UM_THREAD_FLAG_MASK | 0xffull)) return 0;
    return 1;
}

/* Child edge of a shared-VM clone: it resumes inside um_sigsys's handler
 * frame but on the GUEST's new stack, with no valid sigreturn frame there.
 * Rebuild a guest ucontext from the parent's SIGSYS frame and sigreturn via
 * setcontext(), so the new host thread enters guest code with RAX=0 and the
 * guest's stack/TLS.  Never takes the dispatch lock (the parent may hold it). */
static void um_thread_child_bootstrap(void) __attribute__((noreturn));
static void um_thread_child_bootstrap(void) {
    UmThreadBoot b = g_boot;              /* copy before the parent can move on */
    UmThread *th = &g_thr[b.slot];
    __atomic_store_n(&g_boot_ready, 1, __ATOMIC_RELEASE);
    th->tid = um_raw_gettid();
    ucontext_t cu = *b.uc;
    greg_t *r = cu.uc_mcontext.gregs;
    um_skip_syscall(r);                     /* RIP past the guest syscall */
    r[REG_RAX] = 0;                         /* clone child return value */
    r[REG_RSP] = (greg_t)b.child_stack;
    sigemptyset(&cu.uc_sigmask);            /* guest signal mask (empty) */
    th->sig_mask = b.child_sigmask;         /* inherit the parent's virtual mask */
    setcontext(&cu);                        /* enters the guest child thread */
    _exit(127);                             /* setcontext failed: fail closed */
}

/* Parent edge: bounded slot, template state, raw clone with the guest's own
 * flags (honouring CLONE_SETTLS).  The new thread inherits the caller's
 * virtual signal mask, just as the kernel would inherit a real one.  Returns
 * the child tid to the guest. */
static int64_t um_thread_clone(const uint64_t a[6], ucontext_t *uc,
                               uint64_t parent_sigmask,
                               const UmSigDisp *parent_disp) {
    uint32_t used = __atomic_fetch_add(&g_um.result->threads_created, 1,
                                       __ATOMIC_SEQ_CST);
    if (used >= WEMU_UM_MAX_THREADS - 1u) {
        __atomic_fetch_sub(&g_um.result->threads_created, 1, __ATOMIC_SEQ_CST);
        __atomic_fetch_add(&g_um.denied, 1, __ATOMIC_SEQ_CST);
        return -EAGAIN;
    }
    int slot = (int)used + 1;                /* slot 0 is the root thread */
    UmThread *th = &g_thr[slot];
    memset(th, 0, sizeof *th);
    th->active = 1;
    th->is_root = 0;
    th->why = 0;
    th->exit_code = 0;
    th->child_rsp = (greg_t)((a[1] - 16) & ~15ull);
    /* Record the creation shape so a later execve can fail closed for any
     * thread that is not the bounded CLONE_THREAD form. */
    th->clone_flags = a[0];
    th->modeled_thread = wemu_um_thread_exec_modeled(a[0]) ? UM_SHAPE_THREAD : 0;
    /* A new thread inherits a COPY of its parent's signal dispositions.  The
     * child slot lives in shared VM (CLONE_VM), so seeding it before the raw
     * clone is race-free: the parent has not published the slot to any guest
     * yet.  On the negative-control path every thread reads the shared table
     * instead, so seeding is a harmless no-op there. */
    if (g_cfg.thread_disp_enabled && parent_disp)
        th->disp = *parent_disp;

    um_lock();
    __atomic_store_n(&g_boot_ready, 0, __ATOMIC_RELEASE);
    g_boot.uc = uc;
    g_boot.child_stack = a[1];
    g_boot.slot = slot;
    g_boot.child_sigmask = parent_sigmask;
    int64_t pid = um_raw_clone(a[0], a[1], a[2], a[3], a[4]);
    if (pid == 0) um_thread_child_bootstrap();   /* never returns */
    while (!__atomic_load_n(&g_boot_ready, __ATOMIC_ACQUIRE)) { }
    g_thr[slot].tid = (long)pid;
    um_unlock();
    return pid;
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
    if (um_range_has(g_um.arena_lo, g_um.arena_hi, ptr, len)) return 1;
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
    else if (ptr >= g_um.arena_lo && ptr < g_um.arena_hi) end = g_um.arena_hi;
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
    case VSL_SYS_CLONE:
        /* A shared-VM thread's ptid/ctid are written by the host kernel. */
        if (wemu_um_clone_thread_flags_modeled(a[0]))
            return um_chk(nr, a[2], 4) && um_chk(nr, a[3], 4);
        return 1;
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
static int64_t um_sigaction(UmThread *th, const uint64_t a[6]) {
    int sig = (int)a[0];
    uint64_t act = a[1], oldact = a[2], ssz = a[3];
    if (!wemu_um_sigaction_modeled(sig, ssz)) {
        th->sig_denied++;
        g_um.result->refuses[WEMU_UM_REFUSE_SIGACTION]++;
        return -EINVAL;
    }
    UmSigDisp *d = um_disp(th);        /* this thread's table, never global */
    UmKernelSigaction ksa;
    /* act == NULL is a QUERY, not a SIG_DFL registration: fill oldact from
     * this thread's disposition and leave the table untouched. */
    if (!act) {
        if (oldact) {
            UmKernelSigaction old = { d->handler[sig], d->flags[sig],
                                      d->restorer[sig], 0 };
            memcpy((void *)(uintptr_t)oldact, &old, sizeof old);
        }
        return 0;
    }
    memcpy(&ksa, (const void *)(uintptr_t)act, sizeof ksa);
    if (oldact) {
        UmKernelSigaction old = { d->handler[sig], d->flags[sig],
                                  d->restorer[sig], 0 };
        memcpy((void *)(uintptr_t)oldact, &old, sizeof old);
    }
    if (ksa.handler == SIG_DFL_ || ksa.handler == SIG_IGN_) {
        d->valid[sig] = 0;             /* unregister in THIS thread only */
        return 0;
    }
    if (ksa.handler < g_um.win_lo || ksa.handler >= g_um.win_hi) {
        th->sig_denied++;                        /* handler outside the image */
        g_um.result->refuses[WEMU_UM_REFUSE_SIGACTION]++;
        return -EINVAL;
    }
    d->handler[sig]  = ksa.handler;
    d->restorer[sig] = ksa.restorer;
    d->flags[sig]    = (uint32_t)ksa.flags;
    d->valid[sig]    = 1;
    g_um.result->sig_disp_registrations++;
    return 0;
}

/* Guest rt_sigreturn: put the fault-time registers back.  The ucontext we
 * are returning from is the SIGSYS one raised by this very syscall, so the
 * kernel resumes at the restored RIP (the faulting instruction) on sigreturn. */
static void um_sigreturn(UmThread *th, greg_t *r) {
    if (!th->in_handler || !th->saved_valid) {
        th->sig_denied++;
        r[REG_RAX] = (greg_t)-EINVAL;
        um_skip_syscall(r);
        return;
    }
    memcpy(r, th->saved_gregs, sizeof th->saved_gregs);
    th->saved_valid = 0;
    th->in_handler = 0;
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

/* Bounded fork-shaped clone3: the form admitted before the clone3 thread
 * path existed.  No pidfd/tid/tls/stack knobs — every one implies shared
 * state or a child starting on a different stack, which we do not model. */
static int um_clone3_fork_ok(const UmCloneArgs *ca, size_t size) {
    if (size != sizeof *ca) return 0;
    if (ca->pidfd || ca->child_tid || ca->parent_tid || ca->stack ||
        ca->stack_size || ca->tls || ca->set_tid || ca->set_tid_size || ca->cgroup)
        return 0;
    if (ca->flags & (UM_CLONE_PIDFD | UM_CLONE_CLEAR_SIGHAND)) return 0;
    if (ca->flags != 0) return 0;
    return ca->exit_signal == 0 || ca->exit_signal == SIGCHLD;
}

/* Pure shape predicate: is this exactly v0 clone_args for the bounded
 * shared-VM CLONE_THREAD form?  No I/O — the gate audits the same rule. */
static int um_clone3_thread_shape(const UmCloneArgs *ca, size_t size) {
    if (size != sizeof *ca) return 0;
    if (ca->flags & (UM_CLONE_PIDFD | UM_CLONE_CLEAR_SIGHAND)) return 0;
    if (ca->pidfd || ca->set_tid || ca->set_tid_size || ca->cgroup) return 0;
    if (!wemu_um_clone_thread_flags_modeled(ca->flags)) return 0;
    if (ca->exit_signal != 0) return 0;             /* a thread has no exit signal */
    /* The kernel puts the child's RSP at stack + stack_size.  Bound both so a
     * hostile guest cannot wrap the pointer or claim the whole address space. */
    if (ca->stack == 0 || ca->stack_size < 4096 ||
        ca->stack_size > (1ull << 26)) return 0;
    if (ca->stack > UINT64_MAX - ca->stack_size) return 0;
    /* TLS and the TID pointers must match the declared flags — no silent
     * extra kernel writes into guest memory through an undeclared knob. */
    if (!(ca->flags & UM_CLONE_SETTLS) && ca->tls) return 0;
    if (((ca->flags & UM_CLONE_PARENT_SETTID) != 0) != (ca->parent_tid != 0))
        return 0;
    if (((ca->flags & (UM_CLONE_CHILD_SETTID | UM_CLONE_CHILD_CLEARTID)) != 0) !=
        (ca->child_tid != 0)) return 0;
    return 1;
}

int wemu_um_clone3_thread_modeled(const void *args, size_t size) {
    UmCloneArgs ca;
    if (!args || size < sizeof ca) return 0;
    memcpy(&ca, args, sizeof ca);
    return um_clone3_thread_shape(&ca, size);
}

int wemu_um_clone3_fork_modeled(const void *args, size_t size) {
    UmCloneArgs ca;
    if (!args || size < sizeof ca) return 0;
    memcpy(&ca, args, sizeof ca);
    return um_clone3_fork_ok(&ca, size);
}

int wemu_um_sigprocmask_modeled(int how, uint64_t set) {
    if (how != UM_SIG_BLOCK && how != UM_SIG_UNBLOCK && how != UM_SIG_SETMASK)
        return 0;
    return (set & UM_WEMU_SIGMASK) == 0;
}

/* Classify a clone3 syscall: 1 = bounded CLONE_THREAD (new path), 0 = bounded
 * fork (old path), -1 = fail closed with *reason = a WEMU_UM_REFUSE_* code.
 * The guest struct is read through the mapped-range check before it is
 * copied, so a bogus pointer never makes the host read supervisor memory. */
static int um_clone3_classify(const uint64_t a[6], UmCloneArgs *ca, int *reason) {
    *reason = WEMU_UM_REFUSE_CLONE3_SHAPE;
    memset(ca, 0, sizeof *ca);
    if (!a[0] || !um_ptr_ok(a[0], sizeof *ca)) return -1;
    if (a[1] < sizeof *ca) return -1;               /* truncated struct */
    memcpy(ca, (const void *)(uintptr_t)a[0], sizeof *ca);
    /* A longer struct may carry a per-thread sigmask (unmodeled): exact
     * diagnostic, and the kernel's own -E2BIG is returned to the guest. */
    if (a[1] > sizeof *ca) {
        *reason = WEMU_UM_REFUSE_CLONE3_SIGMASK_SIZE;
        return -1;
    }
    /* pidfd (flag or field) and signal-handler reset are the two unmodeled
     * knobs; classify them separately so the gate sees an exact reason. */
    if ((ca->flags & UM_CLONE_PIDFD) || ca->pidfd) {
        *reason = WEMU_UM_REFUSE_CLONE3_PIDFD;
        return -1;
    }
    if (ca->flags & UM_CLONE_CLEAR_SIGHAND) {
        /* Hardened path: one exact code shared with the raw-clone leg.  Old
         * coarse path keeps the legacy CLONE3_SIGMASK code (negative control). */
        *reason = g_cfg.exact_refuse_enabled
                    ? WEMU_UM_REFUSE_CLONE_CLEAR_SIGHAND
                    : WEMU_UM_REFUSE_CLONE3_SIGMASK;
        return -1;
    }
    /* set_tid / cgroup hand the guest authority over host TIDs and cgroups.
     * With exact diagnostics on they get their own reasons; the old coarse
     * path folded them into CLONE3_SHAPE (negative control). */
    if (g_cfg.exact_refuse_enabled) {
        if (ca->set_tid || ca->set_tid_size) {
            *reason = WEMU_UM_REFUSE_CLONE3_SET_TID;
            return -1;
        }
        if (ca->cgroup) {
            *reason = WEMU_UM_REFUSE_CLONE3_CGROUP;
            return -1;
        }
    }
    if (um_clone3_thread_shape(ca, a[1])) return 1;
    if (um_clone3_fork_ok(ca, a[1])) return 0;
    /* A well-formed v0 struct that is neither bounded shape is an unmodeled
     * fork form (shared VM without THREAD, namespaces, odd exit signal, stray
     * TLS/stack/TID knobs...).  Give it an exact reason distinct from a bad
     * pointer or a truncated struct. */
    if (g_cfg.exact_refuse_enabled) *reason = WEMU_UM_REFUSE_CLONE3_FORK_SHAPE;
    return -1;
}

/* One shared counter bounds the whole process tree, not just this process. */
static int64_t um_do_fork(UmThread *th) {
    if (th->in_handler) { __atomic_fetch_add(&g_um.denied, 1, __ATOMIC_SEQ_CST); return -EPERM; }
    uint32_t used = __atomic_fetch_add(&g_um.result->forks, 1, __ATOMIC_SEQ_CST);
    if (used >= WEMU_UM_MAX_FORKS) {
        __atomic_fetch_sub(&g_um.result->forks, 1, __ATOMIC_SEQ_CST);
        __atomic_fetch_add(&g_um.denied, 1, __ATOMIC_SEQ_CST);
        return -EAGAIN;
    }
    int64_t pid = um_raw0(57 /* SYS_fork */);
    if (pid < 0) {
        __atomic_fetch_sub(&g_um.result->forks, 1, __ATOMIC_SEQ_CST);
        return pid;
    }
    if (pid == 0) {
        /* Private COW address space: only this thread survives in the child.
         * Re-seat the slot table on the child's own tid and demote from root;
         * a COW child reports status via wait4, never the shared result. */
        UmThread *c = &g_thr[0];
        greg_t saved_rsp = th->child_rsp;
        uint64_t inherited_mask = th->sig_mask;   /* fork inherits the mask */
        /* A private-COW child inherits the parent's signal dispositions.  The
         * slot memset below would clear this thread's table, so save it (from
         * the hardened per-thread table, or the legacy shared one) first. */
        UmSigDisp inherited_disp = *um_disp(th);
        memset(c, 0, sizeof *c);
        c->disp = inherited_disp;
        c->tid = um_raw_gettid();
        c->active = 1;
        c->is_root = 0;
        c->child_rsp = saved_rsp;
        c->sig_mask = inherited_mask;
        g_boot_thr = c;
        (void)um_raw1(37 /* SYS_alarm */, WEMU_UM_TIMEOUT_SEC);
        /* alarm timers are NOT inherited across fork */
    }
    return pid;
}

/* ---- bounded guest fd table for execveat ---------------------------- */
/* openat/dup3 results the guest legitimately obtained are recorded here; an
 * execveat that needs an fd (AT_EMPTY_PATH or a dirfd-relative path) is
 * admitted ONLY for a number in this table whose OPEN FILE DESCRIPTION is
 * still the one bound at admission.  A number is bound ONCE and never rebind:
 * after close+reopen (or dup2 onto) the number, the new OFD differs and the
 * exec is refused — even when the reopened file is the very same inode.  The
 * supervisor holds a CLOEXEC dup of the admitted OFD above the guest fd range
 * as the stable comparison handle.  A guest cannot reference a file described
 * by a supervisor fd it never opened, nor swap a trusted number underneath
 * the model.  Bounded and process-wide (CLONE_FILES shares fds), so it lives
 * in g_um under the dispatch lock. */
static const UmAdmittedFd *um_fd_lookup(long fd) {
    if (fd < 0) return NULL;
    for (uint32_t i = 0; i < g_um.n_guest_fds; i++)
        if (g_um.guest_fds[i].fd == fd) return &g_um.guest_fds[i];
    return NULL;
}

static void um_fd_admit(long fd) {
    if (fd < 0 || g_um.n_guest_fds >= UM_MAX_GUEST_FDS) return;
    if (um_fd_lookup(fd)) return;               /* bound once: never rebind */
    long held = um_raw_fcntl(fd, UM_F_DUPFD_CLOEXEC, UM_ADMITTED_FD_MIN);
    if (held < 0) return;                        /* fail closed: cannot track OFD */
    long flags = um_raw_fcntl(fd, UM_F_GETFD, 0);
    UmAdmittedFd *e = &g_um.guest_fds[g_um.n_guest_fds++];
    e->fd = fd;
    e->held = held;
    e->cloexec = (uint8_t)(flags >= 0 && (flags & UM_FD_CLOEXEC) != 0);
    /* Capture the stable identity now, for the fallback used when kcmp is
     * unavailable.  If fstat fails here, leave dev/ino as sentinels so the
     * fallback fails closed (never compares two zero identities as equal). */
    if (um_raw_fstat_devino(fd, &e->dev, &e->ino) != 0) {
        e->dev = 0;
        e->ino = 0;
    }
}

/* 1 when the guest fd still describes the EXACT admitted open-file-description.
 * kcmp(KCMP_FILE)==0 proves a shared struct file; a close+reopen (or dup2 onto
 * the number) yields >0, and a closed fd / unavailable kcmp yields -errno.
 * Only a positive proof admits: every failure mode fails closed.
 *
 * When kcmp is unavailable (-ENOSYS, e.g. no CONFIG_CHECKPOINT_RESTORE, or
 * -EPERM, e.g. seccomp-blocked), fall back to a fail-closed dev/ino identity
 * check against the values captured at admission.  dev/ino is a WEAKER proof
 * than OFD identity (a close+reopen of the very same inode is indistinguishable)
 * but still refuses a number rebound to a DIFFERENT file — the wrong-OFD
 * negative control.  Any fstat error or identity mismatch refuses. */
static int um_fd_ofd_ok(const UmAdmittedFd *e) {
    long pid = (long)um_raw0(39 /* SYS_getpid */);
    long k = g_cfg.fd_kcmp_forced_off ? -ENOSYS : um_raw_kcmp(pid, e->fd, e->held);
    if (k == 0) return 1;                        /* kcmp: same struct file */
    if (k > 0) return 0;                         /* kcmp: different OFD */
    if (k != -ENOSYS && k != -EPERM) return 0;   /* other error: fail closed */

    /* kcmp unavailable: fail-closed dev/ino fallback. */
    uint64_t dev = 0, ino = 0;
    if (um_raw_fstat_devino(e->fd, &dev, &ino) != 0) return 0;
    if (e->dev == 0 && e->ino == 0) return 0;    /* no captured identity */
    return dev == e->dev && ino == e->ino;
}

/* execveat SHAPE predicate (pure; no runtime fd state).  1 when (dirfd,flags)
 * is a form the bounded model can honour:
 *   AT_FDCWD + no flags          -> CWD-relative path
 *   fd >= 0 + no flags           -> dirfd-relative path (fd checked at runtime)
 *   fd >= 0 + AT_EMPTY_PATH      -> execute the fd itself  (runtime-checked)
 * AT_FDCWD+AT_EMPTY_PATH (no fd), unknown/negative dirfd and ANY other flag bit
 * fail closed.  The caller pairs this with the runtime OFD admission check. */
int wemu_um_execveat_modeled(long dirfd, uint64_t flags) {
    if (flags & ~(uint64_t)UM_AT_EMPTY_PATH) return 0;
    int empty = (flags & UM_AT_EMPTY_PATH) != 0;
    if (dirfd == UM_AT_FDCWD) return !empty;   /* no fd to use with EMPTY_PATH */
    return dirfd >= 0;                         /* runtime admission still required */
}

typedef struct {
    uint64_t pathp, argvp, envpp;
    long     dirfd;
    uint64_t flags;
    uint8_t  empty_path, fd_needed;
} UmExecArgs;

/* Normalise execve / execveat register args into a bounded request.  Returns
 * 0 when the syscall variant/flags are outside the bounded model. */
static int um_exec_args(uint64_t nr, const uint64_t a[6], UmExecArgs *ea) {
    memset(ea, 0, sizeof *ea);
    ea->dirfd = UM_AT_FDCWD;
    if (nr == VSL_SYS_EXECVE) {
        ea->pathp = a[0]; ea->argvp = a[1]; ea->envpp = a[2];
        return 1;
    }
    if (nr == WEMU_UM_SYS_EXECVEAT) {
        /* execveat's dirfd is an int; the kernel reads only the low 32 bits.
         * A guest passing AT_FDCWD (-100) through glibc's vararg syscall()
         * leaves the upper half zero (0x00000000ffffff9c), so normalise by
         * sign-extending the low word before comparing with AT_FDCWD. */
        long dirfd = (long)(int32_t)a[0];
        uint64_t flags = a[4];
        if (!wemu_um_execveat_modeled(dirfd, flags)) return 0;
        ea->dirfd = dirfd;
        ea->flags = flags;
        ea->empty_path = (flags & UM_AT_EMPTY_PATH) != 0;
        ea->fd_needed = (dirfd != UM_AT_FDCWD);
        ea->pathp = a[1]; ea->argvp = a[2]; ea->envpp = a[3];
        return 1;
    }
    return 0;
}

/* Handler-side gate.  Reason: 0 = admitted, 1 = unsupported form/flags,
 * 2 = unadmitted/bad/reused fd, 3 = bad guest pointers.  Nothing is loaded
 * here; the authoritative bounded string/vector copy happens in
 * um_exec_continue. */
static int um_exec_check(uint64_t nr, const uint64_t a[6], UmExecArgs *ea) {
    if (!um_exec_args(nr, a, ea)) return 1;
    if (ea->fd_needed) {
        const UmAdmittedFd *e = um_fd_lookup(ea->dirfd);
        if (!e) return 2;                        /* never admitted */
        if (g_cfg.fd_ofd_check_enabled) {
            if (!um_fd_ofd_ok(e)) return 2;      /* close+reopen/dup2: OFD changed */
            /* The kernel closes FD_CLOEXEC descriptors across exec, but
             * fexecve's internal-dup exception keeps an admitted CLOEXEC fd
             * usable: um_exec_continue reads it through a private high fd and
             * closes that dup before guest code resumes, so it never leaks.
             * The fd_cloexec_refuse switch reproduces the OLD all-refuse path
             * as a negative control. */
            if (e->cloexec && g_cfg.fd_cloexec_refuse) return 2;
        }
    }
    if (!ea->pathp || !ea->argvp) return 3;
    if (!um_chk_str(nr, ea->pathp) ||
        !um_chk(nr, ea->argvp, (UM_EXEC_MAX_NARG + 1u) * 8u)) return 3;
    if (ea->envpp && !um_chk(nr, ea->envpp, (UM_EXEC_MAX_NARG + 1u) * 8u)) return 3;
    return 0;
}

/* Host call with the dispatch lock dropped: a guest thread blocked in
 * futex/wait4 must not freeze a peer that needs to emit the wakeup. */
static int64_t um_host_unlocked(uint64_t nr, uint64_t a[6]) {
    um_unlock();
    int64_t ret = um_host(nr, a);
    um_lock();
    return ret;
}

/* Fast-path fail-closed refusal: no lock is held here (the CLONE_THREAD path
 * above runs lock-free), so take it just long enough to record the denial and
 * the exact reason.  The guest sees an errno; no host syscall is dispatched. */
static void um_refuse_fast(ucontext_t *uc, UmThread *th, greg_t *r, uint64_t nr,
                           int reason, int err) {
    __atomic_fetch_add(&g_um.syscalls, 1, __ATOMIC_SEQ_CST);
    um_lock();
    um_note_denied(nr);
    if ((unsigned)reason < WEMU_UM_N_REFUSE) g_um.result->refuses[reason]++;
    um_unlock();
    r[REG_RAX] = (greg_t)err;
    um_skip_syscall(r);
    if (__atomic_load_n(&g_um.syscalls, __ATOMIC_SEQ_CST) >= WEMU_UM_MAX_SYSCALLS ||
        __atomic_load_n(&g_um.denied, __ATOMIC_SEQ_CST) > 8)
        um_abort_to_finish(uc, th, UM_WHY_BUDGET);
}

/* ---- bounded pidfd authority: runtime admission + dispatch ---------- */
/* 1 when `tid` is a host TID WEMU actually created as a guest thread: the
 * root slot or an admitted CLONE_THREAD slot, still active.  A guest may only
 * mint a pidfd for a process it created; an arbitrary pid fails closed. */
static int um_tid_admitted(long tid) {
    if (tid <= 0) return 0;
    for (unsigned i = 0; i < WEMU_UM_MAX_THREADS; i++)
        if (g_thr[i].active && g_thr[i].tid == tid) return 1;
    return 0;
}

static UmPidfd *um_pidfd_lookup(long pfd) {
    if (pfd < 0) return NULL;
    for (uint32_t i = 0; i < g_um.n_pidfds; i++)
        if (g_um.pidfds[i].valid && g_um.pidfds[i].pfd == pfd)
            return &g_um.pidfds[i];
    return NULL;
}

static void um_pidfd_admit(long pfd, long tid) {
    if (pfd < 0 || g_um.n_pidfds >= UM_MAX_PIDFDS) return;
    if (um_pidfd_lookup(pfd)) return;            /* bound once: never rebind */
    UmPidfd *e = &g_um.pidfds[g_um.n_pidfds++];
    e->pfd = pfd; e->tid = tid; e->valid = 1;
}

/* Handle a pidfd_* syscall.  Returns 1 when handled (RAX/skip/budget done),
 * 0 when nr is not one of the three pidfd syscalls. */
static int um_pidfd_dispatch(ucontext_t *uc, UmThread *th, greg_t *r,
                             uint64_t nr, uint64_t a[6]) {
    if (nr != WEMU_UM_SYS_PIDFD_OPEN && nr != WEMU_UM_SYS_PIDFD_GETFD &&
        nr != WEMU_UM_SYS_PIDFD_SEND_SIGNAL) return 0;

    unsigned reason = nr == WEMU_UM_SYS_PIDFD_OPEN
        ? WEMU_UM_REFUSE_PIDFD_OPEN
        : (nr == WEMU_UM_SYS_PIDFD_GETFD
           ? WEMU_UM_REFUSE_PIDFD_GETFD : WEMU_UM_REFUSE_PIDFD_SEND_SIGNAL);

    if (!g_cfg.exact_refuse_enabled) {
        /* OLDEST path: pidfd_* were unlisted -> generic -ENOSYS. */
        um_lock();
        __atomic_fetch_add(&g_um.syscalls, 1, __ATOMIC_SEQ_CST);
        um_note_denied(nr);
        r[REG_RAX] = (greg_t)-ENOSYS;
        um_skip_syscall(r);
        if (g_um.denied > 8) um_abort_to_finish(uc, th, UM_WHY_BUDGET);
        um_unlock();
        return 1;
    }
    if (!g_cfg.pidfd_authority_enabled) {
        /* OLD hardening path: every pidfd shape refused, exact reason. */
        um_refuse_fast(uc, th, r, nr, (int)reason, -EINVAL);
        return 1;
    }

    /* NEW bounded authority.  Hold the lock across dispatch so the minted-
     * pidfd / admitted-fd tables stay consistent with the host fd table; the
     * three host syscalls here are non-blocking. */
    um_lock();
    __atomic_fetch_add(&g_um.syscalls, 1, __ATOMIC_SEQ_CST);
    int in_scope = 0;
    int64_t ret = -EINVAL;
    if (nr == WEMU_UM_SYS_PIDFD_OPEN) {
        if (wemu_um_pidfd_open_modeled(a[1]) && um_tid_admitted((long)a[0])) {
            in_scope = 1;
            ret = um_host(nr, a);
            if (ret >= 0) {
                um_fd_admit((long)ret);        /* pidfd is a guest-owned fd */
                um_pidfd_admit((long)ret, (long)a[0]);
                g_um.result->pidfd_created++;
            }
        }
    } else if (nr == WEMU_UM_SYS_PIDFD_GETFD) {
        if (wemu_um_pidfd_getfd_modeled(a[2]) &&
            um_pidfd_lookup((long)a[0]) && um_fd_lookup((long)a[1])) {
            in_scope = 1;
            ret = um_host(nr, a);
            if (ret >= 0) {
                um_fd_admit((long)ret);        /* the duplicate is a guest fd */
                g_um.result->pidfd_getfd_ok++;
            }
        }
    } else { /* WEMU_UM_SYS_PIDFD_SEND_SIGNAL */
        if (um_pidfd_lookup((long)a[0]) && a[2] == 0 /* info == NULL */ &&
            a[3] == 0 /* flags */ &&
            wemu_um_pidfd_signal_modeled((int)(int32_t)a[1])) {
            in_scope = 1;
            ret = um_host(nr, a);
            if (ret == 0) g_um.result->pidfd_signals++;
        }
    }
    if (!in_scope) {
        /* Out-of-scope shape: exact fail-closed, NO host syscall dispatched. */
        um_note_denied(nr);
        g_um.result->refuses[reason]++;
    }
    r[REG_RAX] = (greg_t)ret;
    um_skip_syscall(r);
    if (g_um.syscalls >= WEMU_UM_MAX_SYSCALLS || g_um.denied > 8)
        um_abort_to_finish(uc, th, UM_WHY_BUDGET);
    um_unlock();
    return 1;
}

/* Virtual per-thread signal mask: apply rt_sigprocmask to the CALLING
 * thread's private sigset and NEVER to the host thread mask.  Both buffers
 * were validated by um_ptr_args_ok (8 bytes each); a set touching a WEMU
 * control signal was refused before this call.  Returns the Linux return
 * value (0 / -EINVAL), so guest-visible semantics match a real kernel. */
static int64_t um_sigprocmask_virtual(UmThread *th, const uint64_t a[6]) {
    uint64_t how = a[0], setp = a[1], oldp = a[2], n = a[3];
    if (n != 8) return -EINVAL;
    if (how != UM_SIG_BLOCK && how != UM_SIG_UNBLOCK && how != UM_SIG_SETMASK)
        return -EINVAL;
    uint64_t set = 0;
    if (setp) memcpy(&set, (const void *)(uintptr_t)setp, 8);
    if (!wemu_um_sigprocmask_modeled((int)how, set)) return -EINVAL;
    uint64_t old = th->sig_mask;
    if (setp) {
        if (how == UM_SIG_BLOCK)         th->sig_mask = old |  set;
        else if (how == UM_SIG_UNBLOCK)  th->sig_mask = old & ~set;
        else /* SIG_SETMASK */           th->sig_mask = set;
    }
    if (oldp) memcpy((void *)(uintptr_t)oldp, &old, 8);
    __atomic_fetch_add(&g_um.result->sigmask_virtualized, 1, __ATOMIC_SEQ_CST);
    return 0;
}

static void um_sigsys(int sig, siginfo_t *si, void *ucv) {
    (void)sig;
    ucontext_t *uc = (ucontext_t *)ucv;
    greg_t *r = uc->uc_mcontext.gregs;
    uint64_t nr = (uint64_t)si->si_syscall;
    uint64_t a[6] = {
        (uint64_t)r[REG_RDI], (uint64_t)r[REG_RSI], (uint64_t)r[REG_RDX],
        (uint64_t)r[REG_R10], (uint64_t)r[REG_R8],  (uint64_t)r[REG_R9],
    };
    UmThread *th = um_thread_select();
    if (!th || !th->active) _exit(200);      /* never dispatch outside a run */

    /* Bounded pidfd authority: pidfd_open/getfd/send_signal are admitted only
     * for in-scope shapes (admitted TID / minted pidfd / admitted fd, benign
     * signal) and dispatched to the real host syscall; every other shape fails
     * closed with an exact reason.  No host syscall runs for a refusal. */
    if (um_pidfd_dispatch(uc, th, r, nr, a)) return;

    /* CLONE_CLEAR_SIGHAND asks the kernel to reset the child's signal handlers
     * to SIG_DFL.  WEMU models per-thread disposition tables inherited by copy
     * at clone, but this explicit reset knob is still unmodeled: honouring it
     * would require a second, distinct shape inside the admitted CLONE_THREAD
     * form.  Refuse BEFORE any host clone with an exact reason; with exact
     * diagnostics off it falls through to the generic clone-flag policy below
     * (OLD behaviour, negative control). */
    if (g_cfg.exact_refuse_enabled && nr == VSL_SYS_CLONE &&
        (a[0] & UM_CLONE_CLEAR_SIGHAND)) {
        um_refuse_fast(uc, th, r, nr, WEMU_UM_REFUSE_CLONE_CLEAR_SIGHAND, -EINVAL);
        return;
    }

    /* Shared-VM CLONE_THREAD is the one path that must not hold the dispatch
     * lock: the new host thread resumes in the handler on the guest stack and
     * setcontext()s straight into guest code. */
    if (nr == VSL_SYS_CLONE && wemu_um_clone_thread_flags_modeled(a[0])) {
        int64_t pid = um_thread_clone(a, uc, th->sig_mask, um_disp(th));
        __atomic_fetch_add(&g_um.syscalls, 1, __ATOMIC_SEQ_CST);
        r[REG_RAX] = (greg_t)pid;
        um_skip_syscall(r);
        if (__atomic_load_n(&g_um.syscalls, __ATOMIC_SEQ_CST) >=
                WEMU_UM_MAX_SYSCALLS ||
            __atomic_load_n(&g_um.denied, __ATOMIC_SEQ_CST) > 8)
            um_abort_to_finish(uc, th, UM_WHY_BUDGET);
        return;
    }

    /* CLONE_PIDFD is a pidfd-returning shape WEMU does not model.  Refuse
     * before any host clone, with an exact reason (raw SYS_clone form). */
    if (nr == VSL_SYS_CLONE && (a[0] & UM_CLONE_PIDFD)) {
        um_refuse_fast(uc, th, r, nr, WEMU_UM_REFUSE_CLONE_PIDFD, -EINVAL);
        return;
    }

    /* clone3 is classified here so the bounded CLONE_THREAD shape can create
     * a real host thread without the dispatch lock (same reason as above).
     * Every other shape either fails closed with an exact reason or is a
     * bounded fork, which falls through to the COW dispatch below. */
    if (nr == VSL_SYS_CLONE3) {
        UmCloneArgs ca;
        int reason = WEMU_UM_REFUSE_CLONE3_SHAPE;
        int cls = um_clone3_classify(a, &ca, &reason);
        if (cls < 0) {
            um_refuse_fast(uc, th, r, nr, reason,
                reason == WEMU_UM_REFUSE_CLONE3_SIGMASK_SIZE ? -E2BIG : -EINVAL);
            return;
        }
        if (cls == 1) {
            if (!g_cfg.clone3_thread_enabled) {   /* old path negative control */
                um_refuse_fast(uc, th, r, nr, WEMU_UM_REFUSE_CLONE3_DISABLED,
                               -EINVAL);
                return;
            }
            /* The thread path bypasses um_ptr_args_ok, so validate the two
             * TID pointers the host kernel writes before creating the thread. */
            if (((ca.flags & UM_CLONE_PARENT_SETTID) &&
                 !um_ptr_ok(ca.parent_tid, 4)) ||
                ((ca.flags & (UM_CLONE_CHILD_SETTID | UM_CLONE_CHILD_CLEARTID)) &&
                 !um_ptr_ok(ca.child_tid, 4))) {
                um_refuse_fast(uc, th, r, nr, WEMU_UM_REFUSE_CLONE3_SHAPE,
                               -EFAULT);
                return;
            }
            /* Translate v0 clone_args into the raw SYS_clone argument shape
             * the bounded thread path already models.  On x86-64 the kernel
             * starts the child at stack + stack_size (the top of the stack). */
            uint64_t na[6] = { ca.flags, ca.stack + ca.stack_size,
                               ca.parent_tid, ca.child_tid, ca.tls, 0 };
            int64_t pid = um_thread_clone(na, uc, th->sig_mask, um_disp(th));
            __atomic_fetch_add(&g_um.syscalls, 1, __ATOMIC_SEQ_CST);
            if (pid > 0)
                __atomic_fetch_add(&g_um.result->clone3_threads, 1,
                                   __ATOMIC_SEQ_CST);
            r[REG_RAX] = (greg_t)pid;
            um_skip_syscall(r);
            if (__atomic_load_n(&g_um.syscalls, __ATOMIC_SEQ_CST) >=
                    WEMU_UM_MAX_SYSCALLS ||
                __atomic_load_n(&g_um.denied, __ATOMIC_SEQ_CST) > 8)
                um_abort_to_finish(uc, th, UM_WHY_BUDGET);
            return;
        }
        /* cls == 0: bounded fork-shaped clone3; COW fork dispatch below. */
    }

    um_lock();
    const WemuUmSyscallEntry *e = um_lookup(nr);
    __atomic_fetch_add(&g_um.syscalls, 1, __ATOMIC_SEQ_CST);

    if (!e) {                                /* FAIL CLOSED: no default-allow */
        um_note_denied(nr);
        r[REG_RAX] = (greg_t)-ENOSYS;
        um_skip_syscall(r);
        if (g_um.denied > 8) { um_abort_to_finish(uc, th, UM_WHY_BUDGET); }
        um_unlock();
        return;
    }
    if (e->kind == WEMU_UM_DISPATCH_EXIT) {
        th->exit_code = (int)(int32_t)a[0];
        /* exit_group from a real host thread ends the whole thread group;
         * a fork child lives in its own process and must keep its COW status. */
        if (nr == VSL_SYS_EXIT_GROUP && th != &g_thr[0]) th->is_root = 1;
        um_abort_to_finish(uc, th, UM_WHY_EXIT);
        um_unlock();
        return;
    }
    if (e->kind == WEMU_UM_DISPATCH_SIGRETURN) {
        um_sigreturn(th, r);                  /* resumes at the saved fault RIP */
        um_unlock();
        return;
    }

    /* Bounded image replacement: execve / execveat.  Refuse here (the guest
     * sees an error, no image is loaded) for unsupported variants/flags, bad
     * guest pointers or an exhausted exec budget.  A COW forked child execs
     * as slot 0 of its own private address space (is_root=0 is preserved so
     * its exit still reports through wait4).  A bounded shared-VM
     * CLONE_THREAD guest may now exec too: the caller becomes the new root and
     * its peers are quiesced in host context (um_exec_continue) before the
     * image is swapped.  The negative-control switch reproduces the OLD
     * refusal exactly. */
    if (e->kind == WEMU_UM_DISPATCH_EXECVE) {
        UmExecArgs ea;
        int reason = um_exec_check(nr, a, &ea);
        if (reason) {
            um_note_denied(nr);
            /* An fd the guest never opened is a bad fd (host -EBADF); every
             * other refusal is an invalid form/argument (-EINVAL).  Both leave
             * the current image intact and increment `denied`. */
            r[REG_RAX] = (greg_t)(reason == 2 ? -EBADF : -EINVAL);
            um_skip_syscall(r);
            if (g_um.denied > 8) um_abort_to_finish(uc, th, UM_WHY_BUDGET);
            um_unlock();
            return;
        }
        if (g_um.result->execs >= WEMU_UM_MAX_EXECS) {
            um_note_denied(nr);
            r[REG_RAX] = (greg_t)-EBUSY;
            um_skip_syscall(r);
            if (g_um.denied > 8) um_abort_to_finish(uc, th, UM_WHY_BUDGET);
            um_unlock();
            return;
        }
        /* OLD PATH (negative control): a shared-VM thread, or a process that
         * created threads, could never replace the image (-EBUSY). */
        if (!g_cfg.thread_exec_enabled &&
            (th != &g_thr[0] || g_um.result->threads_created != 0)) {
            um_note_denied(nr);
            r[REG_RAX] = (greg_t)-EBUSY;
            um_skip_syscall(r);
            if (g_um.denied > 8) um_abort_to_finish(uc, th, UM_WHY_BUDGET);
            um_unlock();
            return;
        }
        /* NEW PATH: a non-root caller must be the bounded CLONE_THREAD shape;
         * any unmodeled thread shape fails closed with no image replacement. */
        if (th != &g_thr[0] &&
            (th->modeled_thread != UM_SHAPE_THREAD ||
             !wemu_um_thread_exec_modeled(th->clone_flags))) {
            um_note_denied(nr);
            r[REG_RAX] = (greg_t)-EINVAL;
            um_skip_syscall(r);
            if (g_um.denied > 8) um_abort_to_finish(uc, th, UM_WHY_BUDGET);
            um_unlock();
            return;
        }
        /* Save only guest pointers + the exec source; strings are copied in
         * host context where %fs is the HOST's, so malloc/stdio are safe.
         * Rewriting the SigSYS ucontext resumes um_exec_continue with correct
         * SysV entry alignment (RSP%16==8).  A thread's guest stack lives in
         * the image window we are about to replace, so the loader runs on a
         * fresh HOST stack instead; the root keeps its original stack. */
        memset(&g_exec, 0, sizeof g_exec);
        g_exec.nr = (uint32_t)nr;
        g_exec.pathp = ea.pathp; g_exec.argvp = ea.argvp; g_exec.envpp = ea.envpp;
        g_exec.dirfd = ea.dirfd; g_exec.flags = ea.flags;
        g_exec.empty_path = ea.empty_path;
        g_exec.from_thread = (uint8_t)(th != &g_thr[0]);
        uint64_t run_sp = 0;
        if (g_exec.from_thread) {
            run_sp = um_raw_exec_stack();
            if (!run_sp) {                     /* fail closed: no replacement */
                um_note_denied(nr);
                r[REG_RAX] = (greg_t)-EBUSY;
                um_skip_syscall(r);
                if (g_um.denied > 8) um_abort_to_finish(uc, th, UM_WHY_BUDGET);
                um_unlock();
                return;
            }
        }
        uc->uc_mcontext.gregs[REG_RIP] = (greg_t)(uintptr_t)um_exec_continue;
        uc->uc_mcontext.gregs[REG_RSP] = run_sp
            ? (greg_t)(run_sp - 8)
            : (greg_t)(((th->child_rsp - 16) & ~(greg_t)15) + 8);
        um_unlock();
        return;
    }

    /* Fail closed BEFORE any host syscall: the guest shares our address
     * space, so an unvalidated pointer is a host pointer.  A bad one ends
     * the run with WEMU_UM_ERR_BADPTR; no host handler sees it. */
    if (!um_ptr_args_ok(nr, a)) {
        r[REG_RAX] = (greg_t)-EFAULT;
        um_abort_to_finish(uc, th, UM_WHY_BADPTR);
        um_unlock();
        return;
    }

    if (e->kind == WEMU_UM_DISPATCH_FORK ||
        e->kind == WEMU_UM_DISPATCH_CLONE ||
        e->kind == WEMU_UM_DISPATCH_CLONE3) {
        int64_t child;
        um_unlock();                         /* raw fork: child needs the lock */
        if (e->kind == WEMU_UM_DISPATCH_CLONE) {
            /* RDI=flags, RSI=child stack: a non-zero stack means the child
             * resumes on a different stack, which we do not model. */
            if (!wemu_um_clone_flags_modeled(a[0]) || a[1] != 0) {
                um_lock(); um_note_denied(nr); um_unlock(); child = -EINVAL;
            } else child = um_do_fork(th);
        } else if (e->kind == WEMU_UM_DISPATCH_CLONE3) {
            UmCloneArgs c3;
            int c3r = WEMU_UM_REFUSE_CLONE3_SHAPE;
            /* The fast path classified this as the bounded fork form; confirm
             * again before trusting the guest struct (fail closed otherwise). */
            if (um_clone3_classify(a, &c3, &c3r) != 0) {
                um_lock();
                um_note_denied(nr);
                if ((unsigned)c3r < WEMU_UM_N_REFUSE) g_um.result->refuses[c3r]++;
                um_unlock();
                child = -EINVAL;
            } else child = um_do_fork(th);
        } else {
            /* fork(2)/vfork(2): the kernel fixes exit_signal=SIGCHLD.  Our
             * bounded COW model makes vfork's shared-stack rule moot. */
            child = um_do_fork(th);
        }
        um_lock();
        if (!th->active) {                   /* we are the fork child */
            th = um_thread_select();
            if (!th) { um_unlock(); return; }
        }
        r[REG_RAX] = (greg_t)child;
        um_skip_syscall(r);
        if (g_um.syscalls >= WEMU_UM_MAX_SYSCALLS || g_um.denied > 8)
            um_abort_to_finish(uc, th, UM_WHY_BUDGET);
        um_unlock();
        return;
    }

    int64_t ret = -EPERM;
    if (e->kind == WEMU_UM_DISPATCH_SIGACTION) {
        ret = um_sigaction(th, a);
    } else if (e->kind == WEMU_UM_DISPATCH_SIGPROCMASK) {
        /* A guest that masks SIGSYS would stop trapping its own syscalls;
         * SIGALRM is the run bound and SIGUSR2 the exec-quiesce handshake.
         * Fail closed (before any host call) when the set touches a WEMU
         * signal.  Otherwise serve rt_sigprocmask from the calling thread's
         * PRIVATE mask: the host thread's real mask is never changed.  The
         * OLD pass-through path is the negative-control switch. */
        uint64_t setmask = 0;
        if (a[1] && a[3] == 8)
            memcpy(&setmask, (const void *)(uintptr_t)a[1], 8);
        if (setmask & UM_WEMU_SIGMASK) {
            um_note_denied(nr);
            g_um.result->refuses[WEMU_UM_REFUSE_SIGPROCMASK]++;
            r[REG_RAX] = (greg_t)-EINVAL;
            um_skip_syscall(r);
            if (g_um.denied > 8) um_abort_to_finish(uc, th, UM_WHY_BUDGET);
            um_unlock();
            return;
        }
        if (g_cfg.sigmask_virtual_enabled)
            ret = um_sigprocmask_virtual(th, a);
        else
            ret = um_host_unlocked(nr, a);       /* OLD path: changes host mask */
    } else if (e->kind == WEMU_UM_DISPATCH_EXEC_GUARD) {
        /* mmap(addr,len,prot,flags,..) / mprotect(addr,len,prot): a guest may
         * only make executable memory inside the registered image window,
         * which is the ONLY range the seccomp filter traps.  No W^X escape
         * into host text/heap via a dispatched syscall. */
        int wants_exec = (a[2] & PROT_EXEC) != 0;
        int in_window = a[0] >= g_um.win_lo && a[0] < g_um.win_hi &&
                        a[1] <= g_um.win_hi - a[0];
        if (!wants_exec) {
            ret = um_host_unlocked(nr, a);
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
            if (fixed && in_window) ret = um_host_unlocked(nr, a);
        } else if (in_window) {
            ret = um_host_unlocked(nr, a);       /* mprotect: already trapped */
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
            ret = um_host_unlocked(nr, a);
            if (ret > 0) g_um.heap_hi = (uint64_t)ret;
        }
    } else if ((nr == VSL_SYS_WRITE || nr == VSL_SYS_WRITEV ||
                WEMU_UM_SYS_SENDFILE == nr) && (a[0] == 1 || a[0] == 2)) {
        /* Bound output bookkeeping; the pipe read in the parent is the
         * authoritative capture. */
        uint64_t room = WEMU_UM_OUT_MAX - 1u - g_um.result->out_len;
        if (nr == VSL_SYS_WRITE && a[2] > room) a[2] = room;
        ret = um_host_unlocked(nr, a);
        if (ret > 0) {
            uint64_t n = (uint64_t)ret;
            if (n > room) n = room;
            g_um.result->out_len += (uint32_t)n;
        }
    } else {
        ret = um_host_unlocked(nr, a);
        /* A successfully opened/duplicated fd becomes an admitted guest fd:
         * the guest legitimately owns it and may later describe an execveat
         * target with it.  Unknown/neverbefore fds stay unadmitted. */
        if (ret >= 0 && nr == VSL_SYS_OPENAT) um_fd_admit((long)ret);
        if (ret >= 0 && nr == WEMU_UM_SYS_DUP3) um_fd_admit((long)a[1]);
    }

    r[REG_RAX] = (greg_t)ret;
    um_skip_syscall(r);
    if (g_um.syscalls >= WEMU_UM_MAX_SYSCALLS ||
        g_um.result->out_len >= WEMU_UM_OUT_MAX - 1u) {
        um_abort_to_finish(uc, th, UM_WHY_BUDGET);
    }
    um_unlock();
}

/* A synchronous CPU fault inside the guest image is offered to a registered
 * guest handler.  Everything else fails closed: unknown signal, no handler,
 * a fault outside the guest window, a nested fault, or an exhausted budget. */
static void um_fault(int sig, siginfo_t *si, void *ucv) {
    UmThread *th = um_thread_select();
    if (!th || !th->active) _exit(201);
    ucontext_t *uc = (ucontext_t *)ucv;
    greg_t *r = uc->uc_mcontext.gregs;
    int signo = si ? si->si_signo : sig;
    uint64_t rip = (uint64_t)r[REG_RIP];
    int in_guest = rip >= g_um.win_lo && rip < g_um.win_hi;
    /* Kernel siginfo: SEGV_PKUERR + si_pkey is hardware proof that a
     * protection-key violation (not a plain unmapped-page fault) occurred. */
    g_um.fault_code = si ? si->si_code : 0;
    g_um.fault_pkey = (si && g_um.fault_code == SEGV_PKUERR)
                          ? (int)si->si_pkey : -1;
    int pku = (g_um.fault_code == SEGV_PKUERR);

    /* A pkey violation is never offered to a guest handler: the bytes are
     * unreadable by hardware, and retrying from a handler could only loop or
     * brute-force the key.  Fail closed straight to the result page. */
    UmSigDisp *d = um_disp(th);        /* fault uses THIS thread's disposition */
    if (pku || !um_sig_sync(signo) || !in_guest || !um_sig_registered(signo, th) ||
        th->in_handler || th->sig_deliveries >= WEMU_UM_MAX_SIGNALS) {
        th->sig_denied++;                     /* fail closed, no delivery */
        um_abort_to_finish(uc, th, UM_WHY_FAULT);
        return;
    }

    /* Stash the fault-time registers (bounded: one live delivery at a time). */
    memcpy(th->saved_gregs, r, sizeof th->saved_gregs);
    th->saved_valid = 1;
    th->in_handler = 1;
    th->sig_deliveries++;

    /* Minimal delivery frame: put the guest's SA_RESTORER where a C handler's
     * epilogue will `ret`, with SysV stack alignment at handler entry.  We
     * only supply signo in RDI; siginfo/ucontext args are not populated. */
    greg_t sp = (r[REG_RSP] - 16) & ~(greg_t)15;
    *(uint64_t *)(uintptr_t)(sp + 8) = d->restorer[signo];
    r[REG_RSP] = sp + 8;                        /* %16 == 8, [RSP]=restorer */
    r[REG_RDI] = (greg_t)signo;
    r[REG_RSI] = 0;
    r[REG_RDX] = 0;
    r[REG_RIP] = (greg_t)d->handler[signo];
}

static void um_alarm(int sig, siginfo_t *si, void *ucv) {
    (void)sig; (void)si;
    UmThread *th = um_thread_select();
    if (!th || !th->active) return;
    um_abort_to_finish((ucontext_t *)ucv, th, UM_WHY_ALARM);
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

/* Read an exec target from one of three bounded sources:
 *   empty_path      -> read the admitted fd itself (AT_EMPTY_PATH);
 *   dirfd == AT_FDCWD -> open(path) relative to the current directory;
 *   otherwise       -> openat(admitted dirfd, path) (fd-relative).
 * A borrowed fd is read with pread() so the guest's own file offset is left
 * untouched across the (emulated) image replacement.  An unreadable/oversize
 * source fails closed with NULL; no image is loaded. */
static uint8_t *um_read_target(const char *path, long dirfd, int empty_path,
                               size_t *len) {
    int fd, owned = 0;
    if (empty_path) {
        fd = (int)dirfd;                       /* already admitted by the handler */
    } else if (dirfd == UM_AT_FDCWD) {
        fd = open(path, O_RDONLY); owned = 1;
    } else {
        fd = openat((int)dirfd, path, O_RDONLY); owned = 1;
    }
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0 ||
        (uint64_t)st.st_size > (1u << 28)) {
        if (owned) close(fd);
        return NULL;
    }
    size_t n = (size_t)st.st_size;
    uint8_t *buf = malloc(n);
    if (!buf) { if (owned) close(fd); return NULL; }
    size_t got = 0;
    while (got < n) {
        ssize_t k = pread(fd, buf + got, n - got, (off_t)got);
        if (k <= 0) { free(buf); if (owned) close(fd); return NULL; }
        got += (size_t)k;
    }
    if (owned) close(fd);
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
static int um_load_from(const char *path, long dirfd, int empty_path,
                        UmImage *im) {
    memset(im, 0, sizeof *im);
    im->file = um_read_target(path, dirfd, empty_path, &im->len);
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

/* Common path-only source: the initial guest run and script interpreters. */
static int um_load(const char *path, UmImage *im) {
    return um_load_from(path, UM_AT_FDCWD, 0, im);
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
    uint8_t *mem;
    if (g_cfg.arena_hi > g_cfg.arena_lo &&
        g_cfg.arena_hi - g_cfg.arena_lo >= stacksz) {
        /* Process-per-guest: build the SysV stack inside the supervisor's
         * MAP_SHARED arena, so the guest's writable world is a region the
         * supervisor also maps and can validate against. */
        mem = (uint8_t *)(uintptr_t)g_cfg.arena_lo;
    } else {
        mem = mmap(NULL, stacksz, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mem == MAP_FAILED) return 0;
    }
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
    UmThread *th = um_thread_select();
    if (!th) th = g_boot_thr ? g_boot_thr : &g_thr[0];
    th->active = 0;
    if (!th->is_root) {
        /* A COW child is reaped by the guest parent's wait4; a shared-VM
         * host thread exits only ITSELF (raw SYS_exit, not exit_group). */
        int code = th->why == UM_WHY_EXIT ? (th->exit_code & 0xff) : 128;
        (void)um_raw1(60 /* SYS_exit */, code);   /* never returns */
        _exit(code);
    }
    (void)um_raw1(37 /* SYS_alarm */, 0);
    /* Control evidence for the virtualization differential gate: capture the
     * REAL host-thread mask with a raw rt_sigprocmask query (RIP is in host
     * context here, so it cannot re-trap).  With virtualization ON a guest's
     * blocked signal is absent from this real mask — the direct evidence that
     * no guest mask was ever applied to the host thread. */
    {
        uint64_t hm = 0;
        long hmrc;
        register long r10 __asm__("r10") = 8L;
        __asm__ volatile("syscall" : "=a"(hmrc)
            : "a"(14L /* SYS_rt_sigprocmask */), "D"(2L /* SIG_SETMASK */),
              "S"(0L), "d"((long)&hm), "r"(r10)
            : "rcx", "r11", "memory");
        if (hmrc == 0) shared->host_sigmask_end = hm;
    }
    shared->syscalls = g_um.syscalls;
    shared->denied = g_um.denied;
    uint32_t delivered = 0, denied_sig = 0;
    for (unsigned i = 0; i < WEMU_UM_MAX_THREADS; i++) {
        delivered += g_thr[i].sig_deliveries;
        denied_sig += g_thr[i].sig_denied;
    }
    shared->signals_delivered = delivered;
    shared->signals_denied = denied_sig;
    shared->bad_ptrs = g_um.bad_ptrs;
    shared->bad_ptr_nr = g_um.bad_ptr_nr;
    shared->bad_ptr_va = g_um.bad_ptr_va;
    shared->pkey_active = g_pkey_active;
    shared->pkey_fallback = g_pkey_fallback;
    shared->pkey_guest = g_pkey_guest;
    shared->pkey_host = g_pkey_host;
    shared->fault_code = g_um.fault_code;
    shared->fault_pkey = g_um.fault_pkey;
    shared->exit_code = th->exit_code;
    switch (th->why) {
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

/* ---- bounded execve: image replacement in host context -------------- */
/* Copy one bounded, NUL-terminated guest string into the host-owned store.
 * um_str_ok (already applied in the handler) guarantees the NUL is inside a
 * registered guest range, so this read cannot leave guest memory. */
static const char *um_exec_str(uint64_t vp, size_t max) {
    if (!vp) return NULL;
    if (!um_str_ok(vp)) return NULL;
    const uint8_t *s = (const uint8_t *)(uintptr_t)vp;
    size_t n = 0;
    while (n < max && s[n] != 0) n++;
    if (n >= max || g_exec.used + n + 1 > UM_EXEC_STORE) return NULL;
    char *dst = g_exec.store + g_exec.used;
    memcpy(dst, s, n);
    dst[n] = 0;
    g_exec.used += n + 1;
    return dst;
}

/* Copy a bounded guest pointer vector (argv/envp).  A NULL vector becomes
 * an empty vector; a missing terminator or an out-of-range string is refused. */
static int um_exec_vec(uint64_t vp, char **out, size_t max) {
    out[0] = NULL;
    if (!vp) return 1;
    uint64_t *v = (uint64_t *)(uintptr_t)vp;
    for (size_t i = 0; i < max; i++) {
        uint64_t sp = v[i];
        if (!sp) return 1;
        const char *s = um_exec_str(sp, UM_EXEC_MAX_ARG);
        if (!s) return 0;
        out[i] = (char *)s;
    }
    return 0;                                  /* no terminator within max */
}

/* Reached on sigreturn from execve's SIGSYS handler, on the child's original
 * host stack with %fs restored to the HOST: every glibc call below (malloc,
 * fopen, errno) touches host TLS, never the guest's.  The kernel's seccomp
 * filter traps only guest-image RIPs, so the loader's own syscalls run for
 * real.  On any failure the run fails closed with a WemuUmStatus. */
static void um_exec_continue(void) {
    WemuUmResult *shared = g_um.result;
    /* A COW forked child execs with is_root=0; preserve it so its exit is
     * reported to the guest parent through wait4, not to the shared result. */
    int keep_root = g_thr[0].is_root;
    if (um_raw_set_fs(g_host_fs) != 0)
        um_child_fail(shared, WEMU_UM_ERR_INTERNAL);
    /* Host context: restore the all-keys-enabled PKRU so glibc's loader
     * (malloc/stdio/errno) runs with normal access.  Re-applied before the
     * new image is entered below. */
    if (g_pkey_active) um_wrpkru(g_host_pkru);

    /* Exec from a shared-VM thread replaces the image for the whole thread
     * group: quiesce every peer host thread BEFORE any image/stack is swapped,
     * so no stale guest code survives over the new image.  Fail closed (no
     * replacement) if a peer cannot be quiesced or has an unsupported shape.
     * The caller is selected by raw gettid (host %fs is restored above). */
    {
        UmThread *caller = um_thread_select();
        if (!caller || um_exec_quiesce(caller) != 0)
            um_child_fail(shared, WEMU_UM_ERR_INTERNAL);
    }
    g_exec.used = 0;
    g_exec.path = um_exec_str(g_exec.pathp, UM_EXEC_MAX_ARG);
    if (!g_exec.path ||
        !um_exec_vec(g_exec.argvp, g_exec.argv, UM_EXEC_MAX_NARG) ||
        !um_exec_vec(g_exec.envpp, g_exec.envp, UM_EXEC_MAX_NARG))
        um_child_fail(shared, WEMU_UM_ERR_FAULT);

    /* fexecve parity for an admitted FD_CLOEXEC descriptor: glibc's fexecve()
     * internally dups a CLOEXEC fd before exec so the descriptor survives
     * long enough to load the image, then closes the dup.  We do the bounded
     * equivalent here in HOST context: a PRIVATE dup placed above the guest
     * fd range (>= UM_ADMITTED_FD_MIN, so guest code can never name it) is
     * used only to read the image and is closed before guest code resumes.
     * The guest's own fd number is untouched and no new guest-visible fd
     * appears.  A dup failure fails closed (no image replacement). */
    long read_dirfd = g_exec.dirfd;
    int cloexec_dup = -1;
    if (!g_cfg.fd_cloexec_refuse && g_exec.dirfd >= 0) {
        const UmAdmittedFd *e = um_fd_lookup(g_exec.dirfd);
        if (e && e->cloexec) {
            cloexec_dup = fcntl((int)g_exec.dirfd, F_DUPFD_CLOEXEC,
                                UM_ADMITTED_FD_MIN);
            if (cloexec_dup < 0) um_child_fail(shared, WEMU_UM_ERR_INTERNAL);
            read_dirfd = cloexec_dup;
        }
    }

    /* Resolve the exec target through a bounded #! chain.  Each hop rewrites
     * argv as [interp, i_arg?, script, argv[1]...] (Linux binfmt_script), then
     * re-reads the interpreter: a chain of scripts is followed at most
     * WEMU_UM_MAX_SCRIPT_DEPTH times.  A malformed/unterminated/overlong #!
     * line or an exhausted chain fails closed — no interpreter is entered. */
    UmImage im;
    const char *cur_path = g_exec.path;
    char **cur_argv = g_exec.argv;
    uint8_t *file = NULL;
    size_t file_len = 0;
    int loaded = 0;

    for (unsigned depth = 0; depth <= WEMU_UM_MAX_SCRIPT_DEPTH; depth++) {
        /* Depth 0 is the execveat target (CWD path, admitted dirfd-relative
         * path, or the admitted fd itself).  Deeper hops are #! interpreters,
         * always plain paths resolved like a normal execve. */
        file = depth == 0
            ? um_read_target(g_exec.path, read_dirfd, g_exec.empty_path, &file_len)
            : um_read_file(cur_path, &file_len);
        if (!file) um_child_fail(shared, WEMU_UM_ERR_FORMAT);
        UmShebang sh;
        int sp = um_parse_shebang((const char *)file, file_len, &sh);
        if (sp < 0) { free(file); um_child_fail(shared, WEMU_UM_ERR_SCRIPT); }
        if (sp == 0) {                         /* plain ELF candidate */
            int rc = depth == 0
                ? um_load_from(g_exec.path, read_dirfd, g_exec.empty_path, &im)
                : um_load(cur_path, &im);
            free(file);
            if (rc == -2) um_child_fail(shared, WEMU_UM_ERR_RANGE);
            if (rc != 0) um_child_fail(shared, WEMU_UM_ERR_FORMAT);
            if (im.has_interp) um_child_fail(shared, WEMU_UM_ERR_INTERP);
            loaded = 1;
            break;
        }
        if (depth == WEMU_UM_MAX_SCRIPT_DEPTH) { /* chain too deep: refuse */
            free(file);
            um_child_fail(shared, WEMU_UM_ERR_SCRIPT);
        }
        const char *interp = um_exec_store_str(sh.interp);
        const char *oarg = sh.has_opt ? um_exec_store_str(sh.opt) : NULL;
        const char *script = um_exec_store_str(cur_path);
        if (!interp || (sh.has_opt && !oarg) || !script) {
            free(file);
            um_child_fail(shared, WEMU_UM_ERR_SCRIPT);
        }
        char **dst = g_script_argv[depth];
        size_t j = 0;
        dst[j++] = (char *)interp;
        if (oarg) dst[j++] = (char *)oarg;
        if (j >= UM_EXEC_MAX_NARG) { free(file); um_child_fail(shared, WEMU_UM_ERR_SCRIPT); }
        dst[j++] = (char *)script;
        for (size_t k = 1; cur_argv[k] && j < UM_EXEC_MAX_NARG; k++)
            dst[j++] = cur_argv[k];
        dst[j] = NULL;
        free(file);
        cur_argv = dst;                        /* depth d+1 reads slot d */
        cur_path = interp;
    }
    if (!loaded) um_child_fail(shared, WEMU_UM_ERR_SCRIPT);
    if (cloexec_dup >= 0) close(cloexec_dup);  /* private fexecve dup: no leak */

    uint8_t *stack_mem;
    uint64_t lo = 0, hi = 0;
    uint64_t rsp = um_build_stack(cur_argv, g_exec.envp, &im, &stack_mem,
                                  &lo, &hi);
    if (!rsp) um_child_fail(shared, WEMU_UM_ERR_INTERNAL);
    free(im.file);                             /* strings now live in g_exec */

    /* Replace the current guest image: release the OLD image window and the
     * old SysV stack.  Only unmap the parts that the NEW image/stack do not
     * cover: a thread's stack and a re-chosen PIE bias can coincide with the
     * old window, and unmapping it wholesale would tear down the image we
     * just loaded.  Never release the supervisor's MAP_SHARED arena either. */
    {
        uint64_t wlo = g_um.win_lo, whi = g_um.win_hi;
        if (wlo < im.lo)
            (void)munmap((void *)(uintptr_t)wlo,
                         (size_t)((whi < im.lo ? whi : im.lo) - wlo));
        if (whi > im.hi) {
            uint64_t a = wlo > im.hi ? wlo : im.hi;
            (void)munmap((void *)(uintptr_t)a, (size_t)(whi - a));
        }
        if (!(g_um.stack_lo == g_cfg.arena_lo &&
              g_um.stack_hi == g_cfg.arena_lo + (1u << 20)) &&
            !(g_um.stack_lo >= im.lo && g_um.stack_hi <= im.hi) &&
            !(g_um.stack_lo >= lo && g_um.stack_hi <= hi))
            (void)munmap((void *)(uintptr_t)g_um.stack_lo,
                         (size_t)(g_um.stack_hi - g_um.stack_lo));
    }

    /* Reset every per-run state the new image must not inherit: syscall and
     * denial budgets, guest signal table, admitted mmap/heap ranges and the
     * bounded thread slots.  fork/thread accounting (shared MAP_SHARED page)
     * is reset too — the replaced image starts with a clean budget. */
    g_um.syscalls = 0;
    g_um.denied = 0;
    g_um.n_mmaps = 0;
    g_um.bad_ptrs = 0; g_um.bad_ptr_nr = 0; g_um.bad_ptr_va = 0;
    g_um.fault_code = 0; g_um.fault_pkey = -1;
    memset(&g_um.shared_disp, 0, sizeof g_um.shared_disp);
    /* Per-thread tables are cleared with their slots below (all slots are
     * memset on image replacement), so no disposition survives the exec. */
    /* A root exec resets the whole process-tree accounting (shared MAP_SHARED
     * page).  A COW forked child must NOT clobber its parent's fork/thread
     * counts: it only records that an image replacement happened. */
    if (keep_root) {
        shared->forks = 0;
        shared->threads_created = 0;
        memset(shared->denied_nrs, 0, sizeof shared->denied_nrs);
        shared->bad_ptrs = 0; shared->bad_ptr_nr = 0; shared->bad_ptr_va = 0;
        shared->fault_code = 0; shared->fault_pkey = -1;
    }
    __atomic_fetch_add(&shared->execs, 1, __ATOMIC_SEQ_CST);  /* monotonic: resets cannot reset it */
    if (g_exec.from_thread)
        __atomic_fetch_add(&shared->exec_thread, 1, __ATOMIC_SEQ_CST);
    for (unsigned i = 1; i < WEMU_UM_MAX_THREADS; i++)
        memset(&g_thr[i], 0, sizeof g_thr[i]);
    UmThread *root = &g_thr[0];
    memset(root, 0, sizeof *root);
    root->tid = um_raw_gettid();
    root->active = 1;
    root->is_root = keep_root;                 /* fork child stays non-root */
    root->child_rsp = (greg_t)((uint64_t)__builtin_frame_address(0) & ~15ull);
    g_boot_thr = root;
    g_dispatch_lock = 0;

    g_um.win_lo = im.lo;  g_um.win_hi = im.hi;
    g_um.stack_lo = lo;   g_um.stack_hi = hi;
    g_um.heap_lo = (uint64_t)(int64_t)syscall(SYS_brk, 0);
    g_um.heap_hi = g_um.heap_lo;

    /* Filters are additive: add a trap window for the NEW image.  The old
     * window stays trapped but is unmapped, so no guest code runs there. */
    if (um_install_filter(im.lo, im.hi) != 0)
        um_child_fail(shared, WEMU_UM_ERR_TRAP);

    /* As in um_child_run: getcontext snapshots PKRU, so arm the guest PKRU
     * BEFORE it and let setcontext restore host-key denial on entry. */
    if (g_pkey_active) um_wrpkru(g_guest_pkru);
    ucontext_t uc;
    if (getcontext(&uc) != 0) um_child_fail(shared, WEMU_UM_ERR_TRAP);
    uc.uc_mcontext.gregs[REG_RSP] = (greg_t)rsp;
    uc.uc_mcontext.gregs[REG_RIP] = (greg_t)im.entry;
    uc.uc_mcontext.gregs[REG_EFL] = 0x202;
    uc.uc_mcontext.gregs[REG_RDX] = 0;
    sigemptyset(&uc.uc_sigmask);
    (void)um_raw1(37 /* SYS_alarm */, WEMU_UM_TIMEOUT_SEC); /* wall bound resumes */
    (void)setcontext(&uc);
    um_finish();                               /* only on setcontext failure */
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
    memset(g_thr, 0, sizeof g_thr);
    g_dispatch_lock = 0;
    UmThread *root = &g_thr[0];
    root->tid = um_raw_gettid();
    root->active = 1;
    root->is_root = 1;
    root->child_rsp = 0;                     /* set after getcontext below */
    g_boot_thr = root;
    g_um.result = shared;
    g_um.win_lo = im.lo;
    g_um.win_hi = im.hi;
    g_um.stack_lo = stack_lo;
    g_um.stack_hi = stack_hi;
    g_um.arena_lo = g_cfg.arena_lo;          /* supervisor's MAP_SHARED region */
    g_um.arena_hi = g_cfg.arena_hi;
    shared->arena_lo = g_um.arena_lo;
    shared->arena_hi = g_um.arena_hi;
    /* The initial brk is the floor of the bounded guest heap; query it
     * BEFORE the trap filter is installed (host code, never trapped). */
    g_um.heap_lo = (uint64_t)(int64_t)syscall(SYS_brk, 0);
    g_um.heap_hi = g_um.heap_lo;
    /* Save the HOST fs base: a later execve must restore it before calling
     * the image loader (malloc/stdio/errno) in host context. */
    g_host_fs = um_raw_get_fs();

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

    /* CPU-enforced guest memory protection, installed BEFORE the guest's
     * first instruction.  With MPK support the arena and host pages are
     * stamped with separate keys and PKRU denies the host key while the
     * guest runs; if PKU is unavailable or a syscall fails, the run FAILS
     * CLOSED to the munmap hide path.  Isolation OFF is the negative-control
     * no-op that reproduces the old shared-address-space behaviour. */
    uint32_t hidden = 0;
    if (g_cfg.enabled) {
        if (um_setup_pkeys(shared) != 0)
            um_child_fail(shared, WEMU_UM_ERR_TRAP);
        hidden = g_cfg.n_hide;   /* pages unreadable to the guest (unmap OR key) */
    }
    shared->host_pages_hidden = hidden;

    /* getcontext() snapshots FPU/XSAVE state — INCLUDING PKRU.  Arm the guest
     * PKRU before it, so setcontext() restores host-key denial on entry; a
     * wrpkru() after getcontext would be overwritten by setcontext(). */
    if (g_pkey_active) um_wrpkru(g_guest_pkru);

    ucontext_t uc;
    if (getcontext(&uc) != 0) um_child_fail(shared, WEMU_UM_ERR_TRAP);
    uc.uc_mcontext.gregs[REG_RSP] = (greg_t)rsp;
    uc.uc_mcontext.gregs[REG_RIP] = (greg_t)im.entry;
    uc.uc_mcontext.gregs[REG_EFL] = 0x202;    /* IF=1, reserved bit 1 */
    uc.uc_mcontext.gregs[REG_RDX] = 0;        /* rtld_fini */
    sigemptyset(&uc.uc_sigmask);             /* all signals live in the guest */

    uintptr_t sp;
    __asm__ volatile ("mov %%rsp, %0" : "=r"(sp));
    root->child_rsp = (greg_t)sp;
    root->why = 0;
    root->active = 1;
    alarm(WEMU_UM_TIMEOUT_SEC);
    (void)setcontext(&uc);                   /* transfers to e_entry (PKRU armed) */
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