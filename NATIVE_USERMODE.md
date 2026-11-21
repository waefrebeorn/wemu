# WEMU native user-mode leg (host-mode ELF executor)

New, opt-in execution mode: `wemu_um_run_elf()` in `src/wemu_usermode.c`.
The interpreter (`wemu_cpu.c`) is unchanged and stays the honest oracle /
untrusted-guest sandbox. Nothing here is enabled implicitly by `wemu_cpu_run`.

## What it does

1. Fork a child. Map a **static ET_EXEC x86-64** ELF at its own link addresses
   (PT_LOAD, `.bss` zeroing, final `mprotect` protections), after a
   `/proc/self/maps` collision check. Build the SysV initial stack
   (argc/argv/envp/auxv incl. AT_PHDR/AT_ENTRY/AT_RANDOM).
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
   come back in a `MAP_SHARED` page.

## Bounded / fail-closed

- **Fail-closed dispatch**: a number absent from the table returns `-ENOSYS`,
  is counted in `denied`, and never reaches the host kernel. There is no
  default-allow branch. `getcpu(309)` is the gate's negative control: the
  host supports it, the table does not list it, the guest gets `-ENOSYS`.
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

- Trusted static x86-64 ET_EXEC guests only: no ET_DYN/PIE, no dynamic
  loader, no fork/threads, no guest signal delivery to guest handlers.
- The filter window covers ELF PT_LOAD mappings. Code executed from host
  `brk`/heap memory is outside it; this is not a sandbox for hostile guests.
- Guest pointers are host pointers (same ABI) and are not validated: a host
  syscall receives whatever address the guest supplies. Bounded execution is
  not address-space isolation.
- `rt_sigaction`/`rt_sigprocmask` pass through to the host thread, so signal
  semantics are host approximations, not a guest signal model.
- Gate covers real static busybox `echo`, `uname`, `cat`, `ls` (byte-exact vs
  host `execve` of the same binary); the wider ~26-applet L14 set and LTP
  are not yet run through this path.
