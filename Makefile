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
        test_usermode_native

all: libwemu.a

PIE_STATIC = tests/pie_hello tests/pie_signal tests/pie_nohandler tests/pie_unlisted
PIE_DYN    = tests/pie_dynamic
FORK_FIX   = tests/fork_clone
PIE_BINS   = $(PIE_STATIC) $(PIE_DYN) $(FORK_FIX)

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

test_usermode_native: $(PIE_BINS)

# Self-relocating static PIE (ET_DYN, no PT_INTERP) — also the fork/clone fixture.
tests/pie_%: tests/pie_%.c
	$(CC) -static-pie -O2 -o $@ $<

tests/fork_clone: tests/fork_clone.c
	$(CC) -static-pie -O2 -o $@ $<

# Real dynamically linked PIE: ET_DYN WITH PT_INTERP, refused fail-closed.
tests/pie_dynamic: tests/pie_dynamic.c
	$(CC) -O2 -o $@ $<

test: $(TESTS)
	@for t in $(TESTS); do ./$$t || exit 1; done
	@echo "ALL WEMU GATES PASS"

clean:
	rm -f $(OBJ) $(OBJ:.o=.d) libwemu.a $(TESTS) $(PIE_BINS)

-include $(OBJ:.o=.d)
.PHONY: all test clean