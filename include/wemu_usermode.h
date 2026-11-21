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
/* Bounded virtual interval timer.  A single one-shot ITIMER_REAL is modelled,
 * generating SIGALRM into the ARMINING thread's one pending slot at a syscall
 * checkpoint.  True asynchronous host SIGALRM delivery is deliberately not
 * modelled: it would collide with WEMU's own SIGALRM run bound and is not
 * byte-exact reproducible.  A guest delay is mapped onto a bounded virtual
 * checkpoint clock (WEMU_UM_TIMER_TICK_USEC per tick); larger delays, periodic
 * intervals, other timer kinds and other signals fail closed. */
#define WEMU_UM_TIMER_MAX_USEC   1000000u /* 1 s: alarm(1) admitted, >1 s refused */
#define WEMU_UM_TIMER_TICK_USEC  1000u    /* one virtual checkpoint tick = 1 ms */
#define WEMU_UM_TIMER_MAX_TICKS  1000u    /* MAX_USEC / TICK_USEC */
/* Bounded nested signal delivery.  Each modeled thread keeps a bounded stack
 * of saved delivery contexts: a signal delivered while a handler is live
 * pushes a context and rt_sigreturn pops it.  The depth is capped here; a
 * delivery that would exceed it fails closed with an exact refusal instead
 * of dispatching a host handler.  Per-thread masks, dispositions and the
 * virtual alternate stack are respected at every level.  True asynchronous
 * host delivery and unbounded recursion remain unmodeled. */
#define WEMU_UM_MAX_SIG_NEST     4u       /* max live nested deliveries/thread */

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
    WEMU_UM_DISPATCH_EXECVE,     /* execve/execveat: bounded image replacement */
    WEMU_UM_DISPATCH_TGKILL,     /* tgkill: bounded cross-thread signal queued
                                  * to an admitted sibling's private slot */
    WEMU_UM_DISPATCH_KILL,       /* kill: bounded process-directed signal
                                  * queued to the calling admitted thread */
    WEMU_UM_DISPATCH_SIGALTSTACK, /* sigaltstack: bounded per-thread alternate
                                  * signal stack; SA_ONSTACK frames are placed
                                  * on it with an exact SS_ONSTACK query */
    WEMU_UM_DISPATCH_TIMER       /* setitimer/getitimer/alarm: bounded virtual
                                  * one-shot ITIMER_REAL generating SIGALRM
                                  * into the arming thread's pending slot */
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
#define WEMU_UM_REFUSE_PIDFD_SEND_SIGNAL 8u  /* pidfd_send_signal outside the
                                             * bounded authority (pidfd not
                                             * minted by WEMU / signal not
                                             * whitelisted / unsupported args) */
#define WEMU_UM_REFUSE_CLONE3_SET_TID    9u  /* clone_args.set_tid/_size (guest
                                             * chooses a host TID) */
#define WEMU_UM_REFUSE_CLONE3_CGROUP     10u /* clone_args.cgroup (guest picks a
                                             * host cgroup fd) */
#define WEMU_UM_REFUSE_CLONE3_FORK_SHAPE 11u /* structurally valid clone3 whose
                                             * flags/knobs are outside the
                                             * bounded COW fork form */
/* Hardened-path exact refuses added for the pidfd/CLEAR_SIGHAND leg.  Each is
 * returned to the guest as -EINVAL and counted in WemuUmResult.refuses[].  The
 * three PIDFD_* reasons now mark shapes OUTSIDE the bounded pidfd authority
 * (the in-scope shapes are admitted onto the real host syscall); with the
 * authority switched OFF every pidfd shape keeps the OLD unconditional refusal.
 * With exact diagnostics OFF these shapes keep their OLDEST behaviour:
 * pidfd_open / pidfd_getfd / pidfd_send_signal are unlisted syscalls (generic
 * -ENOSYS), raw-clone CLEAR_SIGHAND is refused by the generic clone-flag
 * policy, and clone3 CLEAR_SIGHAND folds back into the legacy CLONE3_SIGMASK
 * code (2). */
#define WEMU_UM_REFUSE_PIDFD_OPEN         12u /* pidfd_open outside the bounded
                                               * authority (unadmitted TID or
                                               * unsupported flags) */
#define WEMU_UM_REFUSE_PIDFD_GETFD        13u /* pidfd_getfd outside the bounded
                                               * authority (unminted pidfd or
                                               * unadmitted target fd) */
#define WEMU_UM_REFUSE_CLONE_CLEAR_SIGHAND 14u /* CLONE_CLEAR_SIGHAND (raw clone
                                               * OR clone3): unmodeled per-thread
                                               * signal-handler reset */
#define WEMU_UM_REFUSE_SIGACTION         15u /* rt_sigaction outside the bounded
                                             * per-thread disposition table:
                                             * unmodeled signal, bad sigsetsize,
                                             * or handler outside the image */
/* Cross-thread (tgkill) refusals.  A wrong tgid or an unadmitted target tid is
 * indistinguishable from a nonexistent process/thread to the guest (-ESRCH);
 * an unmodeled signal or a busy target fails closed with -EINVAL/-EAGAIN. */
#define WEMU_UM_REFUSE_TGKILL_TGID       16u /* tgkill tgid != the guest group */
#define WEMU_UM_REFUSE_TGKILL_TID        17u /* tid is not an admitted modeled
                                             * thread slot in this group */
#define WEMU_UM_REFUSE_TGKILL_SIG        18u /* signal outside the bounded set */
#define WEMU_UM_REFUSE_TGKILL_BUSY       19u /* target already has a pending
                                             * signal (one bounded slot) */
/* Bounded process-directed kill: only kill(guest tgid, modeled signal) is
 * queued, to the calling admitted thread's one pending slot.  Other pids
 * (including every process-group form) and signals fail closed. */
#define WEMU_UM_REFUSE_KILL_PID          20u /* pid is not the guest group's
                                             * tgid: -ESRCH (positive unknown)
                                             * or -EINVAL (<=0 / group form) */
#define WEMU_UM_REFUSE_KILL_SIG          21u /* signal outside the bounded set */
#define WEMU_UM_REFUSE_KILL_BUSY         22u /* caller's pending slot occupied */
#define WEMU_UM_REFUSE_KILL_DISABLED     23u /* kill path switched off (OLD path
                                             * negative control): -ENOSYS */
/* Bounded FP/XMM/x87 signal-frame preservation.  A delivered signal whose
 * kernel ucontext carries no usable FP state (NULL fpregs, an unrecognized
 * xsave header, or a saved size outside our bounded buffer) is refused: no
 * guest handler runs and the fault fails closed. */
#define WEMU_UM_REFUSE_SIGFP             24u /* unsupported FP shape at signal
                                             * delivery (frame not populated) */
/* Bounded SA_ONSTACK / alternate signal stack.  sigaltstack is virtualized
 * per thread: no host altstack is ever installed (that would move WEMU's own
 * SIGSYS/SIGSEGV handlers onto the guest stack).  Each refusal is exact and
 * returns a kernel-shaped errno without touching guest or host state. */
#define WEMU_UM_REFUSE_SIGALTSTACK_DISABLED 25u /* path switched off: -ENOSYS */
#define WEMU_UM_REFUSE_SIGALTSTACK_FLAGS 26u /* ss_flags outside {0,SS_DISABLE}:
                                              * -EINVAL (SS_ONSTACK is a query
                                              * result; SS_AUTODISARM is
                                              * unmodeled) */
#define WEMU_UM_REFUSE_SIGALTSTACK_SIZE  27u /* ss_size below MINSIGSTKSZ or
                                              * above the bounded maximum:
                                              * -ENOMEM */
#define WEMU_UM_REFUSE_SIGALTSTACK_RANGE 28u /* ss_sp outside a guest-mapped
                                              * range / wraps: -EFAULT */
#define WEMU_UM_REFUSE_SIGALTSTACK_FRAME 29u /* SA_ONSTACK frame does not fit
                                              * the registered altstack at
                                              * delivery: fail closed, no
                                              * guest handler runs */
/* Bounded virtual interval timer.  Only a one-shot ITIMER_REAL delay within
 * WEMU_UM_TIMER_MAX_USEC is admitted; every other shape fails closed with an
 * exact reason and NEVER arms a host timer or displaces WEMU's own SIGALRM
 * run bound.  Under coarse diagnostics these fold back to generic -ENOSYS.
 * Codes are appended AFTER the altstack block; values are stable by symbol. */
#define WEMU_UM_REFUSE_TIMER_WHICH       30u /* which != ITIMER_REAL */
#define WEMU_UM_REFUSE_TIMER_VALUE       31u /* delay out of bounded range */
#define WEMU_UM_REFUSE_TIMER_INTERVAL    32u /* periodic it_interval unmodeled */
#define WEMU_UM_REFUSE_TIMER_PTR         33u /* bad guest itimerval pointer */
#define WEMU_UM_REFUSE_TIMER_BUSY        34u /* target's one pending slot busy
                                             * when the virtual timer fires */
#define WEMU_UM_REFUSE_TIMER_TARGET      35u /* arming thread slot no longer
                                             * active when the timer fires */
#define WEMU_UM_REFUSE_TIMER_DISABLED    36u /* timer path off (OLD path): -ENOSYS */
/* Bounded nested signal delivery.  A nested delivery is one that happens
 * while a previous handler on the SAME thread is still live.  Only the
 * bounded depth is admitted; every out-of-scope shape fails closed with an
 * exact reason and NO host handler runs.  Codes are appended after the timer
 * block; values are stable by symbol. */
#define WEMU_UM_REFUSE_NEST_DISABLED     37u /* nested delivery attempted with
                                             * the path switched off (OLD path:
                                             * no delivery, pending dropped) */
#define WEMU_UM_REFUSE_NEST_DEPTH        38u /* live delivery depth already at
                                             * WEMU_UM_MAX_SIG_NEST: the pending
                                             * event is dropped, no handler runs */
#define WEMU_UM_REFUSE_NEST_FAULT        39u /* synchronous CPU fault taken while
                                             * a handler is live: unmodeled
                                             * nested fault, fail closed */
#define WEMU_UM_N_REFUSE                 40u

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
    uint32_t  sig_disp_registrations; /* rt_sigaction registrations recorded in
                                    * a modeled thread's disposition table */
    uint32_t  pidfd_created;     /* pidfds minted via bounded pidfd_open */
    uint32_t  pidfd_getfd_ok;    /* successful bounded pidfd_getfd duplications */
    uint32_t  pidfd_signals;     /* bounded pidfd_send_signal deliveries */
    uint32_t  tgkill_accepted;   /* tgkill requests queued to an admitted target */
    uint32_t  kill_accepted;     /* bounded process-directed kill requests
                                    queued to the calling admitted thread */
    uint32_t  siginfo_deliveries;/* deliveries that populated an SA_SIGINFO
                                  * siginfo_t + ucontext frame (byte-exact
                                  * where the host's fields are deterministic) */
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
    /* Bounded FP/XMM/x87 signal-frame preservation evidence (appended after
     * `out` so existing field offsets are unchanged).  saved=deliveries whose
     * kernel FP blob was copied into the guest frame; restored=rt_sigreturn
     * calls that put a saved blob back; unsupported=fail-closed shapes. */
    uint32_t  fpstate_saved;
    uint32_t  fpstate_restored;
    uint32_t  fpstate_unsupported;
    /* Bounded SA_ONSTACK evidence (appended last so existing offsets and the
     * FP fields above are unchanged).  altstack_calls = sigaltstack syscalls
     * served (set or query); onstack_deliveries = SA_SIGINFO/SIGSEGV frames
     * actually placed on a guest altstack; onstack_denied = fail-closed
     * altstack shapes that never ran a guest handler. */
    uint32_t  altstack_calls;
    uint32_t  onstack_deliveries;
    uint32_t  onstack_denied;
    /* Bounded virtual timer evidence (appended after FP fields so existing
     * offsets are unchanged).  armed=one-shot ITIMER_REAL arming calls;
     * ticks=virtual checkpoint clock advances; signals=SIGALRM events queued
     * into the arming thread's pending slot; dropped=events refused because
     * the one slot was busy or its thread was gone. */
    uint32_t  timer_armed;
    uint32_t  timer_ticks;
    uint32_t  timer_signals;
    uint32_t  timer_dropped;
    /* Bounded nested signal delivery evidence (appended last so existing
     * offsets are unchanged).  nested_deliveries counts frames pushed while
     * a previous handler was live; nest_depth_max is the deepest live stack
     * reached this run (0 = no delivery, 1 = a single flat delivery). */
    uint32_t  nested_deliveries;
    uint32_t  nest_depth_max;
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

/* Pure shape predicate for the bounded per-thread signal disposition table:
 * rt_sigaction is admitted for a synchronous-fault signal in the modeled
 * whitelist (SIGSEGV/SIGBUS/SIGILL/SIGFPE) OR the bounded timer signal
 * (SIGALRM, generated only by a modeled ITIMER_REAL).  The exact x86-64
 * kernel sigaction size (8) is required.  Every other signal or size fails
 * closed (-EINVAL) and is counted under WEMU_UM_REFUSE_SIGACTION; no host
 * handler is ever installed and no other thread's disposition table is
 * touched.  Handler-in-image is a runtime check (image window is runtime). */
int wemu_um_sigaction_modeled(int sig, uint64_t sigsetsize);

/* Pure shape predicate for bounded tgkill: only a signal in the modeled
 * synchronous set may be sent.  tgid/tid admission is a runtime check against
 * the group's thread slots; an unmodeled signal fails closed with -EINVAL and
 * WEMU_UM_REFUSE_TGKILL_SIG. */
int wemu_um_tgkill_modeled(int sig);

/* Pure shape predicate for bounded process-directed kill: only a signal in
 * the modeled synchronous set may be sent.  pid admission (must equal the
 * guest thread group's tgid) and the one-slot budget are runtime checks. */
int wemu_um_kill_modeled(int sig);

/* Negative-control switch for bounded kill.  ON (default): kill is dispatched
 * into the bounded pending-signal path.  OFF: the OLD path, where kill is an
 * unlisted syscall (-ENOSYS), counted under WEMU_UM_REFUSE_KILL_DISABLED.
 * Returns 0, or -1 for a value other than 0/1. */
int wemu_um_set_kill_enabled(int enabled);

/* ---- bounded virtual interval timer --------------------------------- */
/* Pure shape predicate: which == ITIMER_REAL (0), a ZERO repeat interval
 * (periodic timers are unmodeled), and a positive one-shot delay no larger
 * than WEMU_UM_TIMER_MAX_USEC.  Runtime checks (guest buffer inside the
 * registered image/stack/heap/mmap ranges, one pending slot free) are done in
 * addition; this predicate has no I/O and is safe for the gate to audit. */
int wemu_um_timer_modeled(int which, uint64_t interval_usec, uint64_t value_usec);
/* The only signal a modelled timer may generate is SIGALRM (14), with the
 * kernel's siginfo for a setitimer alarm (si_code=SI_KERNEL=128, si_pid/uid
 * zero).  Any other signal fails closed. */
int wemu_um_timer_signal_modeled(int sig);
/* Negative-control switch for the bounded timer.  ON (default): setitimer /
 * getitimer / alarm are dispatched into the virtual ITIMER_REAL model.
 * OFF: the OLD path — all three are unlisted syscalls returning -ENOSYS, with
 * no virtual timer and no exact timer refusal reasons.  Returns 0, or -1 for
 * a value other than 0/1. */
int wemu_um_set_timer_enabled(int enabled);

/* Negative-control switch for bounded tgkill.  ON (default): tgkill is
 * dispatched into the bounded pending-signal path.  OFF: the OLD path, where
 * tgkill is an unlisted syscall (-ENOSYS).  Returns 0, or -1 otherwise. */
int wemu_um_set_tgkill_enabled(int enabled);

/* Negative-control switch for FP/XMM/x87 state in delivered signal frames.
 * ON (default): the kernel-saved FXSAVE area is copied byte-exact into the
 * guest ucontext and the whole bounded kernel blob is restored by
 * rt_sigreturn (honoring handler edits to the FXSAVE area).  OFF: the OLD path — the synthetic ucontext carries a
 * NULL fpregs pointer and rt_sigreturn restores GPRs only, so guest FP state
 * is zero/clobbered across delivery.  Returns 0, or -1 for 0/1 values. */
int wemu_um_set_fp_signal_enabled(int enabled);

/* Test-only fail-closed control: when ON, delivery treats every FP shape as
 * unsupported even on a host whose kernel FP blob is perfectly preservable,
 * exercising the WEMU_UM_REFUSE_SIGFP path (no guest handler runs).  OFF by
 * default.  Returns 0, or -1 for a value other than 0/1. */
int wemu_um_set_fp_signal_force_unsupported(int enabled);

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

/* Negative-control switch for per-thread signal dispositions.  ON (default):
 * each modeled thread owns a private rt_sigaction table (a new CLONE_THREAD
 * inherits a COPY of its parent's, and a synchronous fault is delivered from
 * the faulting thread's table).  OFF: the OLD path, where every thread uses
 * one process-wide shared table (registration by one thread clobbers another).
 * Returns 0, or -1 for a value other than 0/1. */
int wemu_um_set_thread_disp_enabled(int enabled);

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

/* ---- bounded pidfd authority ---------------------------------------- */
/* Pure shape predicates for the bounded pidfd authority.  Runtime ownership
 * state (which TIDs/fds/pidfds the guest legitimately obtained) is checked by
 * the handler IN ADDITION to these pure form checks. */
/* pidfd_open is admitted only with flags == 0 (no PIDFD_NONBLOCK or unlisted
 * bits) AND a TID the guest actually created (the root slot or an admitted
 * CLONE_THREAD slot). */
int wemu_um_pidfd_open_modeled(uint64_t flags);
/* pidfd_getfd is admitted only with flags == 0, a WEMU-minted pidfd, and a
 * target fd in the guest's admitted fd table. */
int wemu_um_pidfd_getfd_modeled(uint64_t flags);
/* pidfd_send_signal is admitted only for a WEMU-minted pidfd, info == NULL,
 * flags == 0, and a whitelisted signal.  The whitelist is SIGCONT alone: its
 * default action is a no-op for a running process, which makes a byte-exact
 * host differential feasible without changing process state.  Every other
 * signal fails closed. */
int wemu_um_pidfd_signal_modeled(int sig);

/* Negative-control switch for the bounded pidfd authority.  ON (default):
 * in-scope pidfd_open/getfd/send_signal are dispatched to the real host
 * syscall and tracked; out-of-scope shapes fail closed with an exact reason.
 * OFF: the OLD path refuses EVERY pidfd syscall with its exact reason (the
 * pre-authority hardening).  With exact diagnostics OFF the oldest generic
 * -ENOSYS behaviour holds regardless of this switch.  Returns 0, or -1 for a
 * value other than 0/1. */
int wemu_um_set_pidfd_authority_enabled(int enabled);

/* ---- bounded SA_ONSTACK / alternate signal stack -------------------- */
/* Pure shape predicate: a sigaltstack request whose ss_flags carry only the
 * bounded bits (0 or SS_DISABLE==2) and whose ss_size is within the modeled
 * [MINSIGSTKSZ, max] window is admitted for runtime pointer/bounds checking.
 * SS_ONSTACK and SS_AUTODISARM are query results / unmodeled and fail closed.
 * The gate audits this same rule off-line. */
int wemu_um_sigaltstack_modeled(uint64_t ss_flags, uint64_t ss_size);

/* Negative-control switch for sigaltstack virtualization.  ON (default): the
 * syscall is served from per-thread VM state (no host altstack is installed).
 * OFF: the OLD path, where sigaltstack is an unlisted syscall (-ENOSYS) with
 * an exact WEMU_UM_REFUSE_SIGALTSTACK_DISABLED reason.  Returns 0, or -1 for a
 * value other than 0/1. */
int wemu_um_set_sigaltstack_enabled(int enabled);

/* Negative-control switch for SA_ONSTACK frame placement.  ON (default): a
 * modeled handler registered with SA_ONSTACK gets its frame on the thread's
 * registered altstack, and sigaltstack queries inside it report SS_ONSTACK.
 * OFF: the OLD path, where SA_ONSTACK is ignored and every handler frame is
 * placed on the interrupted stack.  Returns 0, or -1 for a value other than
 * 0/1. */
int wemu_um_set_onstack_enabled(int enabled);

/* Negative-control switch for bounded nested signal delivery.  ON (default):
 * a signal delivered at a syscall checkpoint while a handler on the same
 * thread is still live pushes a bounded saved-context frame (up to
 * WEMU_UM_MAX_SIG_NEST); rt_sigreturn pops it and resumes the interrupted
 * handler exactly where it stopped.  OFF: the OLD path, where any delivery
 * with a live handler is refused (pending dropped, no nested handler runs),
 * counted under WEMU_UM_REFUSE_NEST_DISABLED.  Returns 0, or -1 otherwise. */
int wemu_um_set_nested_enabled(int enabled);

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
