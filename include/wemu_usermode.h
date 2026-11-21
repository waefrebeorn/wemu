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
    WEMU_UM_ERR_BADPTR    = -11    /* guest pointer outside the mapped ranges:
                                    * the host syscall was NOT dispatched */
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
    WEMU_UM_DISPATCH_BRK         /* brk: bounded heap growth, range tracked */
} WemuUmDispatch;

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
    uint32_t  denied_nrs[8];     /* distinct unlisted/refused syscall numbers */
    uint32_t  bad_ptrs;          /* guest pointers refused before host dispatch */
    uint32_t  bad_ptr_nr;        /* syscall number of the last refused pointer */
    uint64_t  bad_ptr_va;        /* the refused guest pointer (host-address-shaped) */
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

/* Introspection for the gate: the table itself and a readable status name. */
const WemuUmSyscallEntry *wemu_um_syscall_table(size_t *count);
const char *wemu_um_status_name(int status);

#ifdef __cplusplus
}
#endif
#endif /* WEMU_USERMODE_H */
