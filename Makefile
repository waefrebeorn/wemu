# WEMU — WuBu Emulator. C11, -Werror, behavior-gated.
CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -g -Wall -Wextra -Werror
CFLAGS  += -Iinclude -Isrc
AR      ?= ar

SRC = src/wemu_cpu.c src/wemu_mem.c src/wemu_decode.c src/wemu_exec.c \
      src/wemu_sse.c src/wemu_machine.c
OBJ = $(SRC:.c=.o)
TESTS = test_isa test_avx test_paging test_machine

all: libwemu.a

libwemu.a: $(OBJ)
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

test_%: tests/test_%.c libwemu.a
	$(CC) $(CFLAGS) -o $@ $< libwemu.a

test: $(TESTS)
	@for t in $(TESTS); do ./$$t || exit 1; done
	@echo "ALL WEMU GATES PASS"

clean:
	rm -f $(OBJ) $(OBJ:.o=.d) libwemu.a $(TESTS)

-include $(OBJ:.o=.d)
.PHONY: all test clean