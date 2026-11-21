/* wemu_usermode.h — WEMU host-mode (native) static-ELF executor.
 *
 * This is a NEW execution mode, not the interpreter in wemu_cpu.c.  A static
 * x86-64 ET_EXEC is mapped at its link addresses in a forked child, given a
 * SysV initial stack, and entered on the HOST CPU.  Every syscall issued
 * from the guest's executable image is trapped by an IP-scoped seccomp-BPF
 * filter and routed through a bounded, fail-closed dispatch table whose
 * numbers are VSL's Linux table (include/vsl_syscall_numbers.h).
 *
 * The interpreter stays the honest oracle and the sandbox for untrusted
 * guests; this fast path is for trusted static guests (busybox applets).
 * License: WaefreBeorn Umbrella License v3.0. */
#ifndef WEMU_USERMODE_H
#define WEMU_USERMODE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WEMU_UM_OUT_MAX       65536u   /* captured stdout/stderr bytes */
#define WEMU_UM_MAX_SYSCALLS  200000u  /* hard per-run dispatch budget */
#define WEMU_UM_TIMEOUT_SEC   10       /* wall-clock bound on a run */
#define WEMU_UM_MAX_SIGNALS   16u      /* bounded guest signal deliveries/run */
#define WEMU_UM_SIG_NSIG      32       /* bounded guest signal-number table */
#define WEMU_UM_MAX_FORKS     8u       /* bounded guest fork/clone children/run */
#define WEMU_UM_MAX_THREADS   8u       /* bounded shared-VM host threads/run */
#define WEMU_UM_MAX_EXECS     4u       /* bounded image replacements/run */
#define WEMU_UM_MAX_SCRIPT_DEPTH 4u    /* bounded #! interpreter chain/run */
#define WEMU_UM_MAX_HOST_PAGES 8u      /* bounded host-only regions hidden/guest */

/* CPU-enforced protection-key (MPK/pkeys) mode for the isolation path.
 * AUTO uses x86-64 protection keys when the host supports them and falls
 * closed to the munmap hide path when it does not.  FORCE_FALLBACK forces
 * the munmap path even on a pkey-capable host (differential-gate control).
 * The master on/off switch is wemu_um_set_isolation_enabled(). */
#define WEMU_UM_PKEY_AUTO           0
#define WEMU_UM_PKEY_FORCE_FALLBACK 1

typedef enum {
    WEMU_UM_OK            =   0,
    WEMU_UM_ERR_ARGS      =  -1,
    WEMU_UM_ERR_LOAD      =  -2,
    WEMU_UM_ERR_FORMAT    =  -3,   /* not a static ET_EXEC x86-64 image */
    WEMU_UM_ERR_RANGE     =  -4,   /* link addresses collide with host */
    WEMU_UM_ERR_TRAP      =  -5,   /* seccomp/signal setup failed */
    WEMU_UM_ERR_FAULT     =  -6,   /* guest faulted outside the ABI */
    WEMU_UM_ERR_BUDGET    =  -7,   /* syscall budget / timeout exceeded */
    WEMU_UM_ERR_DENIED    =  -8,   /* an unlisted syscall was attempted */
    WEMU_UM_ERR_INTERNAL  = -9,
    WEMU_UM_ERR_INTERP    = -10,   /* ET_DYN with PT_INTERP: no ld.so model */
    WEMU_UM_ERR_BADPTR    = -11,   /* guest pointer outside the mapped ranges:
                                    * the host syscall was NOT dispatched */
    WEMU_UM_ERR_SCRIPT    = -12    /* malformed/out-of-bound #! script: refused,
                                    * no interpreter dispatched */
} WemuUmStatus;

/* Dispatch kinds.  A syscall absent from the table is NOT passed through:
 * it returns -ENOSYS and increments `denied`.  There is no default-allow. */
typedef enum {
    WEMU_UM_DISPATCH_HOST = 0,   /* raw host syscall with the guest's 6 args */
    WEMU_UM_DISPATCH_EXIT,       /* exit/exit_group: unwind, capture code */
    WEMU_UM_DISPATCH_EXEC_GUARD, /* mmap/mprotect: deny new executable maps
                                  * outside the registered guest window */
    WEMU_UM_DISPATCH_SIGACTION,  /* rt_sigaction: bounded guest signal table */
    WEMU_UM_DISPATCH_SIGRETURN,  /* rt_sigreturn: restore the saved context */
    WEMU_UM_DISPATCH_FORK,       /* fork/vfork: bounded COW guest child */
    WEMU_UM_DISPATCH_CLONE,      /* clone: same, but flags checked first */
    WEMU_UM_DISPATCH_CLONE3,     /* clone3: clone_args flags checked first */
    WEMU_UM_DISPATCH_SIGPROCMASK,/* rt_sigprocmask: per-thread masks fail closed
                                  * when they touch WEMU's own signals */
    WEMU_UM_DISPATCH_BRK,        /* brk: bounded heap growth, range tracked */
    WEMU_UM_DISPATCH_EXECVE      /* execve/execveat: bounded image replacement */
} WemuUmDispatch;

/* Exact fail-closed reasons.  `refuses[code]` in WemuUmResult counts how many
 * times each shape was refused, so a gate can assert WHY a request failed
 * instead of only that `denied` went up.  Every refusal also returns an errno
 * to the guest (-EINVAL unless noted) and leaves the image/thread state intact. */
#define WEMU_UM_REFUSE_CLONE3_PIDFD      1u  /* CLONE_PIDFD flag or clone_args.pidfd */
/* Legacy code, emitted ONLY on the old coarse-diagnostic path (exact reasons
 * switched off) for CLONE_CLEAR_SIGHAND via clone3.  On the hardened path the
 * dedicated WEMU_UM_REFUSE_CLONE_CLEAR_SIGHAND code below is used instead, so
 * the same flag gets one exact reason on BOTH the raw-clone and clone3 legs. */
#define WEMU_UM_REFUSE_CLONE3_SIGMASK    2u  /* old-path CLONE_CLEAR_SIGHAND */
#define WEMU_UM_REFUSE_CLONE3_SHAPE      3u  /* clone_args outside the bounded
                                             * fork/thread shape (incl. bad ptr) */
#define WEMU_UM_REFUSE_CLONE_PIDFD       4u  /* raw SYS_clone with CLONE_PIDFD */
#define WEMU_UM_REFUSE_SIGPROCMASK       5u  /* rt_sigprocmask masking a signal
                                             * WEMU needs (SIGSYS/ALRM/USR2) */
#define WEMU_UM_REFUSE_CLONE3_DISABLED   6u  /* bounded clone3 thread with the
                                             * new path switched off (old path) */
#define WEMU_UM_REFUSE_CLONE3_SIGMASK_SIZE 7u  /* clone_args larger than v0
                                                * (future sigmask field): -E2BIG */
#define WEMU_UM_REFUSE_PIDFD_SEND_SIGNAL 8u  /* pidfd_send_signal: no modeled
                                             * pidfd authority to signal */
#define WEMU_UM_REFUSE_CLONE3_SET_TID    9u  /* clone_args.set_tid/_size (guest
                                             * chooses a host TID) */
#define WEMU_UM_REFUSE_CLONE3_CGROUP     10u /* clone_args.cgroup (guest picks a
                                             * host cgroup fd) */
#define WEMU_UM_REFUSE_CLONE3_FORK_SHAPE 11u /* structurally valid clone3 whose
                                             * flags/knobs are outside the
                                             * bounded COW fork form */
/* Hardened-path exact refuses added for the pidfd/CLEAR_SIGHAND leg.  Each is
 * returned to the guest as -EINVAL and counted in WemuUmResult.refuses[].  With
 * exact diagnostics OFF these shapes keep their OLD behaviour: pidfd_open /
 * pidfd_getfd are unlisted syscalls (generic -ENOSYS), raw-clone CLEAR_SIGHAND
 * is refused by the generic clone-flag policy, and clone3 CLEAR_SIGHAND folds
 * back into the legacy CLONE3_SIGMASK code (2). */
#define WEMU_UM_REFUSE_PIDFD_OPEN         12u /* pidfd_open: no modeled pidfd authority */
#define WEMU_UM_REFUSE_PIDFD_GETFD        13u /* pidfd_getfd: no modeled pidfd authority */
#define WEMU_UM_REFUSE_CLONE_CLEAR_SIGHAND 14u /* CLONE_CLEAR_SIGHAND (raw clone
                                               * OR clone3): unmodeled per-thread
                                               * signal-handler reset */
#define WEMU_UM_N_REFUSE                 15u

typedef struct {
    uint32_t        nr;
    const char     *name;
    WemuUmDispatch  kind;
} WemuUmSyscallEntry;

typedef struct {
    int       status;        /* WemuUmStatus */
    int       exit_code;     /* guest exit/exit_group scalar argument */
    uint64_t  syscalls;      /* trapped+dispatched syscalls */
    uint64_t  denied;        /* unlisted syscalls refused (-ENOSYS) */
    uint32_t  signals_delivered; /* bounded guest signal deliveries */
    uint32_t  signals_denied;    /* fail-closed signal registrations/deliveries */
    uint32_t  forks;             /* bounded COW children created this run */
    uint32_t  threads_created;   /* bounded shared-VM host threads created */
    uint32_t  execs;             /* bounded successful guest image replacements */
    uint32_t  exec_thread;       /* image replacements issued by a non-root
                                    CLONE_THREAD guest (bounded thread-exec) */
    uint32_t  denied_nrs[8];     /* distinct unlisted/refused syscall numbers */
    uint32_t  refuses[WEMU_UM_N_REFUSE]; /* exact fail-closed reason counts
                                          * (indexed by WEMU_UM_REFUSE_*) */
    uint32_t  clone3_threads;    /* bounded shared-VM host threads created via
                                    * the modeled clone3 CLONE_THREAD shape */
    uint32_t  sigmask_virtualized; /* rt_sigprocmask calls served from the
                                    * thread's virtual mask (NO host call) */
    uint64_t  host_sigmask_end;  /* real host-thread mask at finish: control
                                  * evidence that no guest mask leaked to it */
    uint32_t  bad_ptrs;          /* guest pointers refused before host dispatch */
    uint32_t  bad_ptr_nr;        /* syscall number of the last refused pointer */
    uint64_t  bad_ptr_va;        /* the refused guest pointer (host-address-shaped) */
    /* Address-space isolation evidence (process-per-guest): the MAP_SHARED
     * guest arena the SysV stack was built in, and how many host-only pages
     were unmapped from the GUEST child before it began executing. */
    uint64_t  arena_lo, arena_hi;/* registered MAP_SHARED guest arena (shared region) */
    uint32_t  host_pages_hidden; /* host pages removed from the guest process */
    /* CPU-enforced memory-protection-key (MPK) evidence.  pkey_active=1 means
     * the run used hardware keys: the guest arena stays in the default key 0
     * (always accessible; signal handlers run on its stack), while registered
     * host pages get a dedicated pkey that PKRU access-disables for the guest.
     * pkey_fallback=1 means pkeys were unavailable (or forced off) and the
     * munmap hide path was used instead.  fault_code/fault_pkey report the
     * kernel's siginfo for a guest synchronous fault (SEGV_PKUERR + si_pkey
     * proves a hardware key violation, not a plain unmapped-page fault). */
    uint32_t  pkey_active;
    uint32_t  pkey_fallback;
    int       pkey_guest;        /* key assigned to arena, -1 if none */
    int       pkey_host;         /* key assigned to host pages, -1 if none */
    int       fault_code;        /* si_code of last guest sync fault, 0 if none */
    int       fault_pkey;        /* si_pkey of a SEGV_PKUERR fault, -1 if none */
    uint32_t  out_len;       /* bytes captured from fd 1/2, <= OUT_MAX */
    char      out[WEMU_UM_OUT_MAX]; /* NUL-terminated if out_len < OUT_MAX */
} WemuUmResult;

/* Run one ELF to completion.  Both ET_EXEC (mapped at its link addresses)
 * and ET_DYN / PIE (mapped at a chosen load bias) are accepted; a PIE that
 * needs a dynamic loader (PT_INTERP) is refused with WEMU_UM_ERR_INTERP —
 * this path runs self-relocating static PIE images only.  argv is a NULL
 * terminated vector (argv[0] is passed unchanged); envp may be NULL.
 * Fails closed on load/format errors. */
int wemu_um_run_elf(const char *path, char *const argv[],
                    char *const envp[], WemuUmResult *out);

/* 1 when the signal number is in the bounded synchronous-fault delivery
 * whitelist (SIGSEGV/SIGBUS/SIGILL/SIGFPE), 0 otherwise.  Unknown signals
 * are never registered or delivered — the path fails closed. */
int wemu_um_signal_modeled(int sig);

/* 1 when raw clone(2) flags describe a bounded fork (CSIGNAL 0/SIGCHLD,
 * optionally CLONE_CHILD_SETTID/CLEARTID), 0 when the native path refuses
 * them.  clone3's struct form is checked against the same policy. */
int wemu_um_clone_flags_modeled(uint64_t flags);

/* 1 when raw clone(2) flags describe a bounded shared-VM host thread:
 * CLONE_VM + CLONE_THREAD + CLONE_SIGHAND, no exit signal, and only the
 * whitelisted sharing/TLS/TID bits.  CLONE_SETTLS is honoured: the guest's
 * TLS value is applied to the host thread by the kernel.  Any namespace or
 * unlisted flag fails closed. */
int wemu_um_clone_thread_flags_modeled(uint64_t flags);

/* 1 when these raw clone flags describe a thread whose execve WEMU will
 * admit: exactly the bounded shared-VM CLONE_THREAD shape (CLONE_VM +
 * CLONE_THREAD + CLONE_SIGHAND, optional CLONE_SETTLS/TID bits, no exit
 * signal, no namespaces).  Any other thread shape — pidfd / per-thread
 * signal masks / unlisted bits — fails closed.  The bounded clone3 thread
 * shape maps onto exactly this flag set before the host clone is issued. */
int wemu_um_thread_exec_modeled(uint64_t flags);

/* 1 when a Linux x86-64 `struct clone_args` (exactly `size` bytes, v0 = 88)
 * describes the bounded shared-VM CLONE_THREAD shape WEMU admits through
 * clone3: flags == the modeled CLONE_THREAD form (no CLONE_PIDFD /
 * CLONE_CLEAR_SIGHAND / namespaces / exit signal), pidfd == 0, an in-bounds
 * stack + stack_size, TLS only with CLONE_SETTLS, and only the TID pointers
 * the declared flags require.  Anything else — pidfd fields, a larger struct
 * (future per-thread sigmask), unlisted flags, bad stack/tid knobs — fails
 * closed.  Pure predicate: no I/O, safe for the gate to audit off-line. */
int wemu_um_clone3_thread_modeled(const void *args, size_t size);

/* 1 when a v0 `struct clone_args` describes the bounded COW fork form WEMU
 * admits through clone3: exit_signal 0/SIGCHLD, no pidfd / set_tid / cgroup /
 * TLS / stack knobs and no shared or unlisted flags.  Pure predicate (no I/O),
 * so the gate audits the same rule the handler applies. */
int wemu_um_clone3_fork_modeled(const void *args, size_t size);

/* 1 when an rt_sigprocmask request is virtualizable for a modeled thread:
 * `how` is SIG_BLOCK/SIG_UNBLOCK/SIG_SETMASK and the requested set touches
 * none of WEMU's control signals (SIGSYS/SIGALRM/SIGUSR2).  A pure form check;
 * the runtime also validates the guest buffers and applies the mask to the
 * thread's private state instead of the host thread. */
int wemu_um_sigprocmask_modeled(int how, uint64_t set);

/* Negative-control switch: when disabled, a bounded clone3 CLONE_THREAD
 * request is refused with -EINVAL and no host thread is created (the OLD
 * path, where clone3 admitted only fork-shaped requests).  ON by default.
 * Returns 0, or -1 for a value other than 0/1. */
int wemu_um_set_clone3_thread_enabled(int enabled);

/* Negative-control switch for per-thread signal-mask virtualization.  ON
 * (default): rt_sigprocmask is served from the calling thread's virtual mask
 * and NEVER dispatched to the host — the host thread's real mask is intact.
 * OFF: the OLD path, where a mask touching no WEMU signal is passed through to
 * the host rt_sigprocmask (changing the host thread's real mask).  Returns 0,
 * or -1 for a value other than 0/1. */
int wemu_um_set_sigmask_virtual_enabled(int enabled);

/* Negative-control switch for the exact fail-closed reasons.  ON (default):
 * pidfd_send_signal, clone_args.set_tid/cgroup and unmodeled fork shapes carry
 * dedicated WEMU_UM_REFUSE_* codes.  OFF: the OLD coarse diagnostics (-ENOSYS
 * for pidfd_send_signal, generic CLONE3_SHAPE for the clone3 shapes).  Returns
 * 0, or -1 for a value other than 0/1. */
int wemu_um_set_exact_refuse_enabled(int enabled);

/* Negative-control switch for the differential gate: when disabled, an
 * execve issued by a non-root shared-VM thread is refused exactly as in the
 * OLD path (-EBUSY, no image replacement).  Thread-exec is ON by default.
 * Returns 0, or -1 for a value other than 0/1. */
int wemu_um_set_thread_exec_enabled(int enabled);

/* Negative-control switch for the fd-admission OFD gate.  When enabled
 * (default), every admitted execveat fd is bound to its open-file-description
 * with kcmp, so a guest close+reopen (or dup2 onto) an admitted number is
 * refused; a CLOEXEC fd is also refused (the bounded model does not reproduce
 * fexecve's internal-dup exception).  When disabled, admission is number-only
 * — the OLD path — which the differential gate uses to prove the fix changes
 * behaviour.  Returns 0, or -1 for a value other than 0/1. */
int wemu_um_set_fd_ofd_check_enabled(int enabled);

/* Negative-control switch: when enabled, kcmp(KCMP_FILE) is treated as if the
 * kernel did not provide it (-ENOSYS), forcing the bounded fail-closed
 * dev/ino fallback.  kcmp is used by default.  Returns 0, or -1 for a value
 * other than 0/1. */
int wemu_um_set_fd_kcmp_forced_off(int forced_off);

/* Negative-control switch: when enabled, the OLD path is reproduced — every
 * admitted FD_CLOEXEC descriptor is refused (-EBADF, no replacement).  When
 * disabled (default), a CLOEXEC admitted fd is honoured through a bounded
 * internal dup (fexecve parity): the image is read from a private high fd that
 * is closed before guest code resumes, so the dup never leaks into the guest.
 * Returns 0, or -1 for a value other than 0/1. */
int wemu_um_set_fd_cloexec_refuse(int refuse);

/* 1 when the execveat(dirfd, flags) SHAPE is inside the bounded model:
 * AT_FDCWD + no flags (CWD-relative path), an fd >= 0 + no flags
 * (dirfd-relative path), or an fd >= 0 + AT_EMPTY_PATH (execute the fd
 * itself).  The runtime handler still requires the fd to be in the bounded
 * guest fd table (opened/duplicated by the guest) — this predicate is the
 * pure form check used by the gate.  Any other flag bit, AT_FDCWD with
 * AT_EMPTY_PATH, and unknown/negative dirfd all fail closed. */
int wemu_um_execveat_modeled(long dirfd, uint64_t flags);

/* 1 when the leading bytes of an exec target form a well-formed, BOUNDED
 * #! line WEMU will dispatch: a non-empty interpreter path and a line
 * terminator within WEMU's script-line window.  0 otherwise — the target is
 * either a plain ELF candidate or a script WEMU refuses.  Pure predicate
 * (no I/O): the gate uses it to audit the fail-closed edges. */
int wemu_um_exec_script_modeled(const char *hdr, size_t n);

/* ---- process-per-guest address-space isolation ----------------------- */
/* Register a supervisor-owned MAP_SHARED region as the GUEST ARENA.  The
 * forked guest process builds its SysV stack inside this region, so the
 * guest's writable world is a mapping the supervisor also holds.  Every
 * host syscall pointer the guest passes is validated against the registered
 * guest ranges (image / this shared arena stack / bounded heap / admitted
 * mmap); a pointer outside all of them is refused before any host handler
 * sees it.  base must be page-aligned; len >= 2 MiB (first MiB = stack,
 * remainder = shared scratch).  Returns 0, or -1 on bad arguments. */
int wemu_um_set_guest_arena(void *base, size_t len);

/* Register a host-only region that the GUEST must not be able to observe.
 * With MPK support the supervisor assigns these pages a dedicated protection
 * key and access-disables that key via PKRU while guest code runs: a direct
 * guest load/store raises a hardware SEGV_PKUERR (reported in WemuUmResult as
 * fault_code/fault_pkey).  If the CPU lacks PKU or a pkey syscall fails, the
 * run FAILS CLOSED by munmap()ing the region in the guest child instead.  At
 * most WEMU_UM_MAX_HOST_PAGES regions.  Returns 0, or -1 if the table is full. */
int wemu_um_isolate_host_pages(void *addr, size_t len);

/* Clear the host-page hide list and the guest arena (reset between runs). */
void wemu_um_reset_isolation(void);

/* Negative-control switch for the differential gate: when disabled the
 * guest child does NOT unmap registered host pages, reproducing the
 * pre-isolation (shared-address-space) behaviour.  Isolation is ON by
 * default.  Returns 0, or -1 if the value was out of range. */
int wemu_um_set_isolation_enabled(int enabled);

/* Select the CPU-enforcement mode (WEMU_UM_PKEY_* above).  AUTO (default)
 * uses x86-64 protection keys when the host supports them; if the CPU lacks
 * PKU or pkey_alloc fails, isolation FAILS CLOSED by using the munmap hide
 * path instead of running unprotected.  FORCE_FALLBACK forces that munmap
 * path for the differential gate.  Returns 0, or -1 for an unknown mode. */
int wemu_um_set_pkey_mode(int mode);

/* Introspection for the gate: the table itself and a readable status name. */
const WemuUmSyscallEntry *wemu_um_syscall_table(size_t *count);
const char *wemu_um_status_name(int status);

#ifdef __cplusplus
}
#endif
#endif /* WEMU_USERMODE_H */
