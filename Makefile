# WEMU — WuBu Emulator. C11, -Werror, behavior-gated.
CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -g -Wall -Wextra -Werror
CFLAGS  += -Iinclude -Isrc
AR      ?= ar

SRC = src/wemu_cpu.c src/wemu_mem.c src/wemu_decode.c src/wemu_exec.c \
      src/wemu_sse.c src/wemu_string.c src/wemu_machine.c src/wemu_elf.c \
      src/wemu_x87.c src/wemu_exception.c src/wemu_usermode.c
OBJ = $(SRC:.c=.o)
TESTS = test_isa test_avx test_paging test_machine test_string test_cpuid \
        test_sse2 test_usermode test_shld test_x87 test_lock_atomics \
        test_exceptions test_isa_atomic_fence test_idt test_priv test_faults \
        test_segments test_cpl test_iret test_tss test_task_switch \
        test_task_gates test_ldt test_call_gate_priv test_task_gpr \
        test_usermode_native test_usermode_exec test_usermode_isolate \
        test_usermode_mpk test_usermode_exec2 test_usermode_execfd \
        test_usermode_threadexec

all: libwemu.a

PIE_STATIC = tests/pie_hello tests/pie_signal tests/pie_nohandler tests/pie_unlisted
PIE_DYN    = tests/pie_dynamic
FORK_FIX   = tests/fork_clone
THREAD_FIX = tests/threaded_guest
EXEC_FIX   = tests/exec_chain
EXEC2_FIX  = tests/script_interp tests/exec_fork tests/exec_script
TEXEC_FIX  = tests/thread_exec
PIE_BINS   = $(PIE_STATIC) $(PIE_DYN) $(FORK_FIX) $(THREAD_FIX) $(EXEC_FIX) $(EXEC2_FIX) $(TEXEC_FIX)
SANDBOX_BIN = tests/sandbox_probe
ISOLATE_BIN = tests/isolate_probe

src/wemu_usermode.o: CFLAGS += -fno-stack-protector
# The native user-mode signal handlers run on the guest stack after the guest
# has set its own %fs base (arch_prctl ARCH_SET_FS, same ABI as the host).
# glibc's -fstack-protector canary is read from %fs:0x28, which is then the
# guest's canary slot, not the host's, so the handler epilogue aborts with a
# false "stack smashing detected". Keep the default hardening everywhere else.

libwemu.a: $(OBJ)
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

test_%: tests/test_%.c libwemu.a
	$(CC) $(CFLAGS) -o $@ $< libwemu.a -lm

test_usermode_native: tests/test_usermode_native.c libwemu.a $(PIE_BINS) $(SANDBOX_BIN)
	$(CC) $(CFLAGS) -o $@ $< libwemu.a -lm

test_usermode_exec: tests/test_usermode_exec.c libwemu.a $(EXEC_FIX) $(PIE_DYN)
	$(CC) $(CFLAGS) -o $@ $< libwemu.a -lm

# Bounded #! script + forked-child exec differential gate.
test_usermode_exec2: tests/test_usermode_exec2.c libwemu.a $(EXEC2_FIX) $(EXEC_FIX)
	$(CC) $(CFLAGS) -o $@ $< libwemu.a -lm

# Bounded fd-relative execveat differential gate (reuses exec_chain + pie_hello fixtures).
test_usermode_execfd: tests/test_usermode_execfd.c libwemu.a $(EXEC_FIX) tests/pie_hello
	$(CC) $(CFLAGS) -o $@ $< libwemu.a -lm

# Bounded execve-from-CLONE_THREAD differential gate (raw TLS-safe fixture).
test_usermode_threadexec: tests/test_usermode_threadexec.c libwemu.a $(TEXEC_FIX)
	$(CC) $(CFLAGS) -o $@ $< libwemu.a -lm

# Freestanding process-per-guest isolation differential guest (raw syscalls).
test_usermode_isolate: tests/test_usermode_isolate.c libwemu.a $(ISOLATE_BIN)
	$(CC) $(CFLAGS) -o $@ $< libwemu.a -lm

# CPU-enforced MPK differential gate (reuses the same freestanding probe).
test_usermode_mpk: tests/test_usermode_mpk.c libwemu.a $(ISOLATE_BIN)
	$(CC) $(CFLAGS) -o $@ $< libwemu.a -lm

# Freestanding sandbox differential guest (raw syscalls, no libc).
tests/sandbox_probe: tests/sandbox_probe.c
	$(CC) -static -nostdlib -no-pie -ffreestanding -fno-builtin -O2 -o $@ $<

# Freestanding isolation differential guest (raw syscalls, no libc).
tests/isolate_probe: tests/isolate_probe.c
	$(CC) -static -nostdlib -no-pie -ffreestanding -fno-builtin -O2 -o $@ $<

# Self-relocating static PIE (ET_DYN, no PT_INTERP) — also the fork/clone fixture.
tests/pie_%: tests/pie_%.c
	$(CC) -static-pie -O2 -o $@ $<

tests/fork_clone: tests/fork_clone.c
	$(CC) -static-pie -O2 -o $@ $<

# #! interpreter + fork/child-exec fixtures (static PIE, no PT_INTERP).
tests/script_interp: tests/script_interp.c
	$(CC) -static-pie -O2 -fno-stack-protector -o $@ $<

tests/exec_fork: tests/exec_fork.c
	$(CC) -static-pie -O2 -fno-stack-protector -o $@ $<

tests/exec_script: tests/exec_script.c
	$(CC) -static-pie -O2 -fno-stack-protector -o $@ $<

# Self-exec differential fixture: stage 1 execve()s itself as a static PIE.
tests/exec_chain: tests/exec_chain.c
	$(CC) -static-pie -O2 -fno-stack-protector -o $@ $<

# Guest threads run with an emulator-provided %fs base that is not glibc's
# TCB, so no handler/body may read the TLS canary.  Keep this fixture raw.
tests/threaded_guest: tests/threaded_guest.c
	$(CC) -static-pie -O2 -fno-stack-protector -o $@ $<

# Non-main-thread execve fixture: raw syscalls, no TLS canary (see above).
tests/thread_exec: tests/thread_exec.c
	$(CC) -static-pie -O2 -fno-stack-protector -o $@ $<

# Real dynamically linked PIE: ET_DYN WITH PT_INTERP, refused fail-closed.
tests/pie_dynamic: tests/pie_dynamic.c
	$(CC) -O2 -o $@ $<

test: $(TESTS)
	@for t in $(TESTS); do ./$$t || exit 1; done
	@echo "ALL WEMU GATES PASS"

clean:
	rm -f $(OBJ) $(OBJ:.o=.d) libwemu.a $(TESTS) $(PIE_BINS) $(SANDBOX_BIN) $(ISOLATE_BIN)

-include $(OBJ:.o=.d)
.PHONY: all test clean