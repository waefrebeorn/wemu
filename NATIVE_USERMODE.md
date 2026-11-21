# WEMU native user-mode leg (host-mode ELF executor)

New, opt-in execution mode: `wemu_um_run_elf()` in `src/wemu_usermode.c`.
The interpreter (`wemu_cpu.c`) is unchanged and stays the honest oracle /
untrusted-guest sandbox. Nothing here is enabled implicitly by `wemu_cpu_run`.

## What it does

1. Fork a child. Map an **x86-64 ELF** at its link addresses (`ET_EXEC`) or
   at a chosen load bias (`ET_DYN` / static PIE: deterministic 256 MiB
   candidates below the host stack, checked free against `/proc/self/maps`),
   with PT_LOAD, `.bss` zeroing and final `mprotect` protections.  For ET_DYN
   the bias is applied to every segment, `e_entry`, `AT_PHDR` and `AT_BASE`;
   a self-relocating `-static-pie` image then relocates itself at startup.
   Build the SysV initial stack (argc/argv/envp/auxv incl. AT_PHDR/AT_ENTRY/
   AT_RANDOM).  `PT_INTERP` images are refused — there is no ld.so model.
2. Install an **IP-scoped seccomp-BPF filter**: every syscall whose
   instruction pointer is inside the guest image window returns
   `SECCOMP_RET_TRAP`; host code (the dispatcher, libc) is allowed, so the
   dispatcher can call real host syscalls without re-trapping.
3. `setcontext()` to `e_entry`; the guest executes **natively** on the host
   CPU (same x86-64 Linux ABI, so pointer args need no marshalling).
4. `SIGSYS` reads RDI/RSI/RDX/R10/R8/R9 (siginfo has no arg array), looks the
   number up in the one dispatch table, and either calls the host syscall,
   handles exit/exit_group, or refuses. On exit it rewrites the saved
   ucontext RIP/RSP and returns from the handler: the kernel sigreturns onto
   the child's *original* stack (no cross-stack `siglongjmp`, which glibc's
   fortified `____longjmp_chk` rejects).
5. stdout/stderr are captured through a pipe; exit code, syscall/deny counts
   and signal delivery/deny counts come back in a `MAP_SHARED` page.
6. **Bounded guest signal delivery**: `rt_sigaction` is intercepted into a
   small guest signal table (never passed to the host). A synchronous CPU
   fault from guest RIP (SIGSEGV/SIGBUS/SIGILL/SIGFPE) with a registered
   handler rewrites the ucontext to that handler, passing signo in RDI and
   the guest's `SA_RESTORER` as the return address; a normal handler epilogue
   returns to `rt_sigreturn`, which restores the saved fault registers so
   the faulting instruction is retried. `wemu_usermode.c` is compiled without
   `-fstack-protector`: its handlers run on the guest stack with a
   guest-set `%fs`, so a TLS stack canary there is not the host's.

## Bounded / fail-closed

- **Fail-closed dispatch**: a number absent from the table returns `-ENOSYS`,
  is counted in `denied`, and never reaches the host kernel. There is no
  default-allow branch. `getcpu(309)` is the gate's negative control: the
  host supports it, the table does not list it, the guest gets `-ENOSYS`.
- **Fail-closed signals**: only SIGSEGV/SIGBUS/SIGILL/SIGFPE can be registered
  or delivered; `rt_sigaction` for any other signal returns `-EINVAL`. A
  fault with no handler, outside the guest image, while already in a handler,
  or after 16 deliveries is not delivered — the run unwinds with
  `WEMU_UM_ERR_FAULT`. Every refusal increments `signals_denied`.
- **Fail-closed interpreter leg**: `wemu_cpu_load_elf()` still rejects
  `ET_DYN`; load-bias handling lives only in the native path.
- **Exec guard**: guest `mmap`/`mprotect` with `PROT_EXEC` is refused unless
  the whole range lies in the registered image window.
- 200,000-syscall budget, 10-second wall-clock alarm, 64 KiB output cap.

## Ownership

WEMU owns this executor, trap scope and dispatch table. **VSL owns the Linux
syscall numbering**: `include/vsl_syscall_numbers.h` is a verbatim copy of
wubuos `src/runtime/vsl/vsl_syscall_numbers.h`, not a second invented table.
Five numbers absent from VSL (`sendfile`, `prctl`, `arch_prctl`, `rseq`,
`time`) carry an explicit `WEMU_UM_SYS_*` prefix. The gate audits every
table entry against the kernel's `asm/unistd_64.h`.

## Known gaps (genuine)

- **Static ET_EXEC and self-relocating static PIE (ET_DYN, no PT_INTERP)
  guests only.** A dynamically linked PIE (`PT_INTERP`) is refused with
  `WEMU_UM_ERR_INTERP`: loading ld.so and shared objects, and the relocations
  they need, is not modelled. No fork/threads.
- The bounded signal path delivers only signo (RSI/RDX siginfo/ucontext args
  are zero), restores general registers only (not XMM/x87 state), allows no
  nesting, and needs the guest's `SA_RESTORER` for a C handler to return.
  Asynchronous signals (kill/tgkill/timers) and guest-owned signal masks are
  not modelled; `rt_sigprocmask` still passes through to the host.
- The filter window covers ELF PT_LOAD mappings. Code executed from host
  `brk`/heap memory is outside it; this is not a sandbox for hostile guests.
- Guest pointers are host pointers (same ABI) and are not validated: a host
  syscall receives whatever address the guest supplies. Bounded execution is
  not address-space isolation.
- Gate covers real static busybox `echo`, `uname`, `cat`, `ls` (byte-exact vs
  host `execve` of the same binary) and real `-static-pie` guests for load
  bias and SIGSEGV delivery; the wider ~26-applet L14 set and LTP are not yet
  run through this path.
