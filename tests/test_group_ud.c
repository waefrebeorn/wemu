/* test_group_ud.c — ModRM.reg extension audit: 0F BA Group 8 plus the
 * undefined digits of FE (INC/DEC byte) and C6/C7 (MOV imm).
 *
 * SDM Vol.2A Group 8: 0F BA /4 = BT, /5 = BTS, /6 = BTR, /7 = BTC;
 * /0-/3 are UNDEFINED. FE defines /0 INC and /1 DEC only; C6/C7 define
 * /0 MOV imm only. All other digits raise #UD on hardware (verified by
 * forked SIGILL oracle children executing the exact encoded bytes).
 *
 * The original gate caught 0F BA /0-/3 silently executing a read-only BT.
 * This extended gate also controls the FE /2-/7 and C6/C7 /1-/7 cases,
 * which previously decremented or wrote the destination with fault=0.
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

/* Generic WEMU runner for the FE/C6/C7 digit encodings. */
static void emu_bytes(const uint8_t *code, size_t n, uint64_t rax,
                      int *fault, uint64_t *out, uint64_t *rip) {
    WemuCpu *c = wemu_cpu_create(1u << 20);
    wemu_cpu_load(c, 0x1000, code, n);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_set_reg(c, 0, rax);
    wemu_cpu_run(c, 8);
    *fault = wemu_cpu_fault(c);
    *out = wemu_cpu_reg(c, 0);
    *rip = wemu_cpu_rip(c);
    wemu_cpu_destroy(c);
}

/* Host SIGILL oracle for FE /digit, C6 /digit ib and C7 /digit id.
 * Only the defined digits execute; the rest must raise #UD. */
static void host_ud(int family, int digit, uint64_t rax,
                    int *ud, uint64_t *out) {
    struct host_res *sh = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                               MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (sh == MAP_FAILED) { perror("mmap"); exit(2); }
    memset((void *)sh, 0, sizeof *sh);
    pid_t kid = fork();
    if (kid == 0) {
        signal(SIGILL, ud_exit);
        uint64_t r = rax;
#define HFE(d, m) case d: __asm__ volatile(".byte 0xfe,0x" m : "+a"(r) : : "cc", "memory"); break
#define HC6(d, m) case d: __asm__ volatile(".byte 0xc6,0x" m ",0x5a" : "+a"(r) : : "cc", "memory"); break
#define HC7(d, m) case d: __asm__ volatile(".byte 0xc7,0x" m ",0x78,0x56,0x34,0x12" : "+a"(r) : : "cc", "memory"); break
        switch (family) {
        case 0xFE:
            switch (digit) {
                HFE(0, "c0"); HFE(1, "c8"); HFE(2, "d0"); HFE(3, "d8");
                HFE(4, "e0"); HFE(5, "e8"); HFE(6, "f0"); HFE(7, "f8");
            }
            break;
        case 0xC6:
            switch (digit) {
                HC6(0, "c0"); HC6(1, "c8"); HC6(2, "d0"); HC6(3, "d8");
                HC6(4, "e0"); HC6(5, "e8"); HC6(6, "f0"); HC6(7, "f8");
            }
            break;
        case 0xC7:
            switch (digit) {
                HC7(0, "c0"); HC7(1, "c8"); HC7(2, "d0"); HC7(3, "d8");
                HC7(4, "e0"); HC7(5, "e8"); HC7(6, "f0"); HC7(7, "f8");
            }
            break;
        default: _exit(2);
        }
#undef HFE
#undef HC6
#undef HC7
        sh->rax = r; sh->valid = 1;
        _exit(0);
    }
    int st;
    waitpid(kid, &st, 0);
    int sigill = (WIFEXITED(st) && WEXITSTATUS(st) == 99) ||
                 (WIFSIGNALED(st) && WTERMSIG(st) == SIGILL);
    *ud = !sh->valid || sigill;
    *out = sh->rax;
    munmap((void *)sh, 4096);
}

static void check_family(int family) {
    const uint64_t rax = 0x000000000000000full;
    for (int d = 0; d < 8; d++) {
        uint8_t modrm = (uint8_t)(0xC0 | (d << 3));
        uint8_t code[8]; size_t n = 0;
        code[n++] = (uint8_t)family; code[n++] = modrm;
        if (family == 0xC6) code[n++] = 0x5a;
        if (family == 0xC7) { code[n++] = 0x78; code[n++] = 0x56;
                              code[n++] = 0x34; code[n++] = 0x12; }
        code[n++] = 0xf4;
        int hud = 0, efault = 0;
        uint64_t hr = 0, er = 0, erip = 0;
        host_ud(family, d, rax, &hud, &hr);
        emu_bytes(code, n, rax, &efault, &er, &erip);
        if (hud) {
            CHECK(efault == 6, "undefined ModRM.reg digit did not raise #UD");
            CHECK(er == rax, "undefined ModRM.reg digit wrote the destination");
            CHECK(erip == 0x1000, "undefined ModRM.reg digit advanced RIP");
        } else {
            CHECK(efault == 0, "WEMU faulted on a host-valid ModRM.reg digit");
            CHECK(er == hr, "defined ModRM.reg digit result differs from host");
        }
    }
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
    check_family(0xFE);
    check_family(0xC6);
    check_family(0xC7);
    if (fails) { printf("test_group_ud: %d FAILURES\n", fails); return 1; }
    printf("test_group_ud: PASS (0F BA /0-/3, FE /2-/7, C6/C7 /1-/7 all #UD;"
           " defined digits match host)\n");
    return 0;
}
