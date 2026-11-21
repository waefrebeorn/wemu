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
    WEMU_UM_ERR_INTERNAL  =  -9,
    WEMU_UM_ERR_INTERP    = -10    /* ET_DYN with PT_INTERP: no ld.so model */
} WemuUmStatus;

/* Dispatch kinds.  A syscall absent from the table is NOT passed through:
 * it returns -ENOSYS and increments `denied`.  There is no default-allow. */
typedef enum {
    WEMU_UM_DISPATCH_HOST = 0,   /* raw host syscall with the guest's 6 args */
    WEMU_UM_DISPATCH_EXIT,       /* exit/exit_group: unwind, capture code */
    WEMU_UM_DISPATCH_EXEC_GUARD, /* mmap/mprotect: deny new executable maps
                                  * outside the registered guest window */
    WEMU_UM_DISPATCH_SIGACTION,  /* rt_sigaction: bounded guest signal table */
    WEMU_UM_DISPATCH_SIGRETURN   /* rt_sigreturn: restore the saved context */
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

/* Introspection for the gate: the table itself and a readable status name. */
const WemuUmSyscallEntry *wemu_um_syscall_table(size_t *count);
const char *wemu_um_status_name(int status);

#ifdef __cplusplus
}
#endif
#endif /* WEMU_USERMODE_H */
