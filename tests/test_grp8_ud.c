/* test_grp8_ud.c — Group 8 (0F BA /digit ib) ModRM.reg extension audit.
 *
 * SDM Vol.2A Group 8: 0F BA /4 = BT, /5 = BTS, /6 = BTR, /7 = BTC.
 * Digits /0-/3 are UNDEFINED and the host CPU raises #UD (verified here
 * by executing the exact encoded bytes with a SIGILL oracle child).
 *
 * WEMU's 0F BA handler read the r/m operand and rebuilt CF for EVERY digit
 * but only wrote the destination for /5,/6,/7: /0-/3 therefore executed
 * as a silent read-only BT (destination unchanged, CF modified, RIP
 * advanced) instead of faulting.  This gate is the host-differential
 * control for that missing extension case.
 */
#define _GNU_SOURCE
#include "wemu.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mman.h>

static int fails;
#define CHECK(cond, msg) do { if (!(cond)) { \
    printf("FAIL: %s (line %d)\n", msg, __LINE__); fails++; } } while (0)

/* shared result between the forked oracle child and its parent */
struct host_res { volatile int valid; volatile uint64_t rax; volatile uint8_t cf; };

static void ud_exit(int sig) { (void)sig; _exit(99); }

/* Execute the exact bytes 0F BA /<digit> 04 on the HOST CPU in a child.
 * ud=1 means the host raised SIGILL (#UD); otherwise rax/cf are the
 * architectural result of the defined digit. */
static void host_case(int digit, uint64_t rax,
                      int *ud, uint64_t *out, uint8_t *cf) {
    struct host_res *sh = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                               MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (sh == MAP_FAILED) { perror("mmap"); exit(2); }
    memset((void *)sh, 0, sizeof *sh);
    pid_t kid = fork();
    if (kid == 0) {
        signal(SIGILL, ud_exit);
        uint64_t r = rax;
        uint8_t c = 0;
        switch (digit) {
#define H(dgt, m) case dgt: \
            __asm__ volatile(".byte 0x0f,0xba,0x" m ",0x04\n\tsetc %0" \
                             : "=qm"(c), "+a"(r) : : "cc", "memory"); break
        H(0, "c0"); H(1, "c8"); H(2, "d0"); H(3, "d8");
        H(4, "e0"); H(5, "e8"); H(6, "f0"); H(7, "f8");
#undef H
        default: _exit(2);
        }
        sh->rax = r; sh->cf = c; sh->valid = 1;
        /* _exit does not flush: never re-emit the parent's buffered log */
        _exit(0);
    }
    int st;
    waitpid(kid, &st, 0);
    int sigill = (WIFEXITED(st) && WEXITSTATUS(st) == 99) ||
                 (WIFSIGNALED(st) && WTERMSIG(st) == SIGILL);
    *ud = !sh->valid || sigill;
    *out = sh->rax;
    *cf = sh->cf;
    munmap((void *)sh, 4096);
}

static void emu_case(int digit, uint64_t rax,
                     uint64_t *out, uint8_t *cf, int *fault, uint64_t *rip) {
    WemuCpu *c = wemu_cpu_create(1u << 20);
    uint8_t prog[8] = {0};
    prog[0] = 0x0f; prog[1] = 0xba;
    prog[2] = (uint8_t)(0xc0 | (digit << 3)); /* mod=3, r/m=RAX/EAX */
    prog[3] = 0x04;                            /* imm8 bit index */
    prog[4] = 0xf4;                            /* hlt (never reached on #UD) */
    wemu_cpu_load(c, 0x1000, prog, 5);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_set_reg(c, 0, rax);
    wemu_cpu_run(c, 4);
    *fault = wemu_cpu_fault(c);
    *out = wemu_cpu_reg(c, 0);
    *cf = (uint8_t)(wemu_cpu_rflags(c) & 1);
    *rip = wemu_cpu_rip(c);
    wemu_cpu_destroy(c);
}

int main(void) {
    const uint64_t rax = 0x000000000000000full; /* bit 4 clear -> /4 CF=0 */
    for (int d = 0; d < 8; d++) {
        int hud = 0, efault = 0;
        uint64_t hr = 0, er = 0, erip = 0;
        uint8_t hcf = 0, ecf = 0;
        host_case(d, rax, &hud, &hr, &hcf);
        emu_case(d, rax, &er, &ecf, &efault, &erip);
        printf("0F BA /%d ib: host %s rax=%llx cf=%u | WEMU fault=%d "
               "rax=%llx cf=%u rip=%llx\n", d, hud ? "#UD" : "ok",
               (unsigned long long)hr, hcf, efault,
               (unsigned long long)er, ecf, (unsigned long long)erip);
        if (hud) {
            /* Undefined digit: hardware #UD.  WEMU must fault WITHOUT
             * executing a silent BT (no destination write, no RIP advance). */
            CHECK(efault == 6, "WEMU did not raise #UD for undefined 0F BA digit");
            CHECK(er == rax, "undefined 0F BA digit wrote the destination");
            CHECK(erip == 0x1000, "undefined 0F BA digit advanced RIP");
        } else {
            /* Defined digit: host ran it, WEMU must match exactly. */
            CHECK(efault == 0, "WEMU faulted on a host-valid 0F BA digit");
            CHECK(er == hr, "defined 0F BA digit result differs from host");
            CHECK(ecf == hcf, "defined 0F BA digit CF differs from host");
        }
    }
    if (fails) { printf("test_grp8_ud: %d FAILURES\n", fails); return 1; }
    printf("test_grp8_ud: PASS (0F BA /0-/3 #UD, /4-/7 host-matching)\n");
    return 0;
}
