# WEMU — WuBu Emulator. C11, -Werror, behavior-gated.
CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -g -Wall -Wextra -Werror
CFLAGS  += -Iinclude -Isrc
AR      ?= ar

SRC = src/wemu_cpu.c src/wemu_mem.c src/wemu_decode.c src/wemu_exec.c \
      src/wemu_sse.c src/wemu_string.c src/wemu_machine.c src/wemu_elf.c \
      src/wemu_x87.c src/wemu_exception.c
OBJ = $(SRC:.c=.o)
TESTS = test_isa test_avx test_paging test_machine test_string test_cpuid \
        test_sse2 test_usermode test_shld test_x87 test_lock_atomics \
        test_exceptions test_isa_atomic_fence test_idt test_priv test_faults \
        test_segments test_cpl test_iret test_tss test_task_switch \
        test_task_gates test_ldt test_call_gate_priv test_task_gpr

all: libwemu.a

libwemu.a: $(OBJ)
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

test_%: tests/test_%.c libwemu.a
	$(CC) $(CFLAGS) -o $@ $< libwemu.a -lm

test: $(TESTS)
	@for t in $(TESTS); do ./$$t || exit 1; done
	@echo "ALL WEMU GATES PASS"

clean:
	rm -f $(OBJ) $(OBJ:.o=.d) libwemu.a $(TESTS)

-include $(OBJ:.o=.d)
.PHONY: all test clean