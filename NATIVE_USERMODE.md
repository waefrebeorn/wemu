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
6. **Bounded fork/clone**: `fork`, `vfork`, `clone` and `clone3` are handled
   in the SIGSYS handler.  A fork-shaped request becomes a RAW `SYS_fork`,
   giving the guest child a PRIVATE copy-on-write address space (guest image,
   stack, TLS and `g_um` are copied by the kernel).  The child resumes after
   the syscall with RAX=0; the parent gets the pid and `wait4` returns the
   child's real exit status.  The fork budget is a shared atomic counter, so
   `WEMU_UM_MAX_FORKS` bounds the whole process tree, and each child re-arms
   its own wall-clock alarm (alarms are not inherited across fork).  Only the
   root child publishes the result page; COW children exit with their guest
   status so the guest parent's `wait4` sees it.
7. **Bounded shared-VM CLONE_THREAD**: a `clone` with CLONE_VM + CLONE_THREAD
   + CLONE_SIGHAND (and only the whitelisted FS/FILES/SYSVSEM/SETTLS/TID
   bits, no exit signal, no namespaces) creates a REAL host thread with raw
   `SYS_clone` from the SIGSYS handler.  The guest's TLS value is passed
   through to CLONE_SETTLS, so the kernel sets the new thread's `%fs` base.
   The child resumes inside the handler on the GUEST's new stack, where there
   is no sigreturn frame; it copies a guest ucontext from the parent's SIGSYS
   frame and `setcontext()`s into guest code with RAX=0 on that stack.
   Dispatch state lives in a bounded `WEMU_UM_MAX_THREADS` slot table keyed by
   raw `gettid()` (the guest owns `%fs`, so `__thread` is unusable); a spin
   lock serialises shared bookkeeping and is dropped around blocking host
   calls.  `WEMU_UM_MAX_THREADS` bounds the whole thread group.
8. **Bounded guest signal delivery**: `rt_sigaction` is intercepted into a
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
- **Fail-closed clone flags**: the FORK-ONLY policy (`wemu_um_clone_flags_modeled`)
  admits CSIGNAL 0/`SIGCHLD`, optionally with `CLONE_CHILD_SETTID`/
  `CLONE_CHILD_CLEARTID` (accepted but NOT applied — the COW child has a
  private TLS and no host thread to futex-wake), and refuses `CLONE_VM`,
  `CLONE_FS`, `CLONE_FILES`, `CLONE_SIGHAND`, `CLONE_THREAD`, `CLONE_VFORK`,
  `CLONE_NEW*`, `CLONE_SETTLS`, and nonzero `child_stack` before any kernel
  call.  A SEPARATE policy (`wemu_um_clone_thread_flags_modeled`) admits the
  shared-VM thread form — CLONE_VM + CLONE_THREAD + CLONE_SIGHAND with only
  FS/FILES/SYSVSEM/SETTLS/TID extras and no exit signal — and nothing else;
  namespace/vfork/exit-signal thread requests return `-EINVAL`.  `clone3`
  stays fork-only: any pidfd/tid/tls/stack knob or nonzero flags is refused.
  `execve` is now a bounded image replacement (see below); pidfd-bearing
  `clone3` remains unlisted.
- **Bounded execve**: `execve`/`execveat` are listed and routed to a dedicated
  handler.  The SIGSYS handler only checks the path/vector pointers and
  saves the three guest pointers; it refuses unsupported `execveat` flags
  (`AT_EMPTY_PATH`, fd-relative), bad pointers, a non-root/forked/threaded
  guest, and an exhausted budget with `-EINVAL`/`-EBUSY` and `denied++`.
  On the accepted path it rewrites the SigSYS ucontext to resume on the
  ORIGINAL host stack, restores the HOST `%fs` (so the loader's malloc/stdio
  use host TLS), copies bounded strings/vectors (`<=64` entries, `<=256`
  bytes each, 16 KiB store), and loads a new validated static `ET_EXEC`/
  `ET_DYN` image.  A `PT_INTERP` target refuses with `WEMU_UM_ERR_INTERP`;
  a malformed/missing target with `WEMU_UM_ERR_FORMAT`.  The old image and
  old stack are unmapped, every per-run counter/signal/heap/mmap/thread
  state is reset, a new additive seccomp trap window is installed for the
  new image, and `setcontext()` enters its `e_entry`.  `execs` is monotonic
  and capped at `WEMU_UM_MAX_EXECS` (4).  `test_usermode_exec` is the
  differential gate: a real self-exec chain is byte-exact vs host `execve`.
- **Bounded thread group**: at most `WEMU_UM_MAX_THREADS - 1` shared-VM host
  threads per run, counted in the shared result page.  Exhaustion returns
  `-EAGAIN` and increments `denied`.  Thread state is a fixed slot table
  (no `__thread`: the guest owns `%fs`); a spin lock serialises dispatch and
  is dropped around blocking host calls.  The child's bootstrap record is
  published with a parent spin-wait acknowledgement — without it a delayed
  child could read the NEXT clone's stack/slot and corrupt the run (this bug
  was caught by a 40-run differential stress loop, not by a single gate).
- **Negative control for threads**: `tests/threaded_guest` asks for the same
  thread flags plus `CLONE_NEWUSER`; the real kernel refuses it with `-EINVAL`
  and the guest prints `THREAD-FLAGS-RC=-22` byte-exactly.  The gate checks
  both the host oracle and the emulated run, and asserts `threads_created=2`,
  `denied=1`.
- **TLS rule for handlers**: the guest owns `%fs`, so handlers may only use
  raw syscalls and TLS-free helpers.  Using glibc's `syscall()` wrote `errno`
  into the guest's TLS slot; the `ENOENT=2` from a failed
  `newfstatat("/etc/busybox.conf")` became a pointer and crashed `head`,
  `tail`, `seq`, `expr`, `cut`, `awk`, `id`, ... before their first output.
  `um_host()` is now an inline `syscall` instruction returning raw `-errno`.
- **Exec guard**: guest `mprotect` with `PROT_EXEC` is refused unless the
  whole range lies in the trapped ELF image window. Guest `mmap` with
  `PROT_EXEC` is admitted ONLY when `MAP_FIXED` *and* the whole range lies in
  that window — a non-`MAP_FIXED` hint is not a guarantee (the kernel may
  return a page anywhere, outside the seccomp window). `brk` growth is
  bounded to 16 MiB above the initial break; the heap stays non-executable.
- **Guest pointer validation**: before a host syscall is dispatched, every
  pointer argument the host kernel would dereference must lie wholly inside
  a registered guest range (ELF image, SysV stack, bounded brk heap, or an
  admitted guest mmap). A bad pointer ends the run with `WEMU_UM_ERR_BADPTR`;
  NO host syscall sees it. The result reports `bad_ptrs`, `bad_ptr_nr` and
  `bad_ptr_va` as evidence.
- 200,000-syscall budget, 10-second wall-clock alarm, 64 KiB output cap,
  `WEMU_UM_MAX_FORKS` children per run.

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
  they need, is not modelled. Bounded fork/clone and a bounded shared-VM
  CLONE_THREAD model are supported (below), but true vfork/exec semantics are
  refused or approximated.
- **Threads are raw-clone only.** `pthread_create()` from a static glibc guest
  (with its full TLS/robust-list/rseq/setxid machinery) has NOT been verified;
  the differential fixture uses raw `SYS_clone` plus `CLONE_SETTLS` and reads
  its per-thread index from its own TLS block. `clone3` thread flags,
  `CLONE_NEW*` namespaces, nonzero thread exit signals, pidfds, thread
  priorities/sched attributes, guest-owned signal masks per thread, and LTP
  remain unmodelled. `WEMU_UM_MAX_THREADS - 1` host threads per run is a hard
  ceiling; exhaustion returns `-EAGAIN`.
- A guest signal delivered to one thread uses that thread's slot (no nesting);
  cross-thread signal targeting (`tgkill`) and `CLONE_CHILD_CLEARTID`-driven
  futex wake-ups are left to the host kernel, not modelled by the dispatcher.
- The bounded signal path delivers only signo (RSI/RDX siginfo/ucontext args
  are zero), restores general registers only (not XMM/x87 state), allows no
  nesting, and needs the guest's `SA_RESTORER` for a C handler to return.
  Asynchronous signals (kill/tgkill/timers) and guest-owned signal masks are
  not modelled; `rt_sigprocmask` still passes through to the host.
- The filter window covers ELF PT_LOAD mappings. The stack and the bounded
  brk heap are registered for **pointer validation**, but code fetched from
  them is not trapped (making them executable is refused, and non-`MAP_FIXED`
  `PROT_EXEC` mmap is refused outright). This path shares the host address
  space; it is still not a sandbox for hostile guests.
- Guest pointers are host pointers (same ABI) but are now **validated**
  against the registered guest ranges before dispatch. Validation is a
  per-syscall table: a newly added pointer-taking syscall must be added to
  `um_ptr_args_ok()` or it is not checked. `prctl` option-specific pointer
  payloads and ioctl request-specific layouts are not decoded; `ioctl` args
  that look like small scalars are passed through. Pointer validation is
  range checking, not address-space isolation.
- The gate runs **45** real static busybox applets, each byte-exact against
  host `execve` of the same binary/args/env, plus static-PIE load-bias and
  SIGSEGV fixtures, a static-PIE fork/clone fixture (private COW children), a
  static-PIE shared-VM CLONE_THREAD fixture (two TLS-distinguished host
  threads, exact output + negative clone flag), and `tests/sandbox_probe` for
  the four sandbox differentials (RWX mmap, mprotect, out-of-range pointer,
  brk). LTP, `pthread_create`, vfork sharing, clone3 pidfds and guest
  signal masks are not yet modelled. `execve` only replaces static
  ET_EXEC/ET_DYN images: PT_INTERP (ld.so), fd-relative `execveat`, exec from
  a forked child or a process with live shared-VM threads, dynamic loaders,
  and ELF interpreter/fd scripts are refused. Seccomp windows accumulate
  across execs (bounded to `WEMU_UM_MAX_EXECS`), and XMM/x87 state is not
  reset across a replacement.
