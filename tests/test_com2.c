/* test_com2.c -- COM2 (0x2F8) as the 9P link.
 *
 * WuBuOS dedicates COM2 to 9P: the kernel polls LSR/DR and reads frames, and
 * writes replies back out. WEMU modelled only COM1, so the /n server could not
 * be gated without QEMU. This asserts the contract both directions:
 *   host push -> guest sees DR + the exact bytes, in order
 *   guest out -> the host callback receives the byte
 */
#include "wemu.h"
#include "wemu_internal.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int fails;
#define CHECK(c, m) do { if (!(c)) { printf("FAIL: %s\n", m); fails++; } } while (0)

static char tx_log[64];
static size_t tx_n;
static void on_tx(uint8_t b, void *ud) {
    (void)ud;
    if (tx_n + 1 < sizeof tx_log) tx_log[tx_n++] = (char)b;
}

/* load a short sequence and execute exactly `steps` instructions */
static void run(WemuCpu *c, const uint8_t *code, size_t n, const char *what,
                int steps) {
    wemu_cpu_load(c, 0x1000, code, n);
    wemu_cpu_set_rip(c, 0x1000);
    int64_t s = wemu_cpu_run(c, steps);
    CHECK(s == steps && wemu_cpu_fault(c) == 0, what);
    if (s < 0) wemu_cpu_clear_fault(c);
}

int main(void) {
    WemuMachine *m = wemu_machine_create(1u << 20, NULL, NULL);
    CHECK(m != NULL, "machine");
    if (!m) return 1;
    WemuCpu *c = wemu_machine_cpu(m);
    wemu_machine_set_com2(m, on_tx, NULL);

    /* empty FIFO: LSR must not report DR */
    { const uint8_t code[] = { 0xBA, 0xF8, 0x02, 0x00, 0x00, 0xEC } /* mov edx,0x2f8; in al,dx */; /* mov dx,0x2f8; in al,dx */
      run(c, code, sizeof code, "lsr read faulted", 2); }
    CHECK((wemu_cpu_reg(c, 0) & 0x01u) == 0, "empty COM2 reports no data");

    /* host pushes a frame prefix; the guest reads it back in order */
    CHECK(wemu_machine_com2_push(m, "9P", 2) == 2, "push accepted");
    { const uint8_t code[] = { 0xBA, 0xFD, 0x02, 0x00, 0x00, 0xEC } /* mov edx,0x2fd; in al,dx */; /* mov dx,0x2fd */
      run(c, code, sizeof code, "lsr read (data) faulted", 2); }
    CHECK(wemu_cpu_reg(c, 0) & 0x01u, "LSR reports DR when the host sent");

    for (int i = 0; i < 2; i++) {
        { const uint8_t code[] = { 0xBA, 0xF8, 0x02, 0x00, 0x00, 0xEC } /* mov edx,0x2f8; in al,dx */;
          run(c, code, sizeof code, "data read faulted", 2); }
        CHECK(wemu_cpu_reg(c, 0) == (uint64_t)(i == 0 ? '9' : 'P'),
              "COM2 RX byte order");
    }
    { const uint8_t code[] = { 0xBA, 0xFD, 0x02, 0x00, 0x00, 0xEC } /* mov edx,0x2fd; in al,dx */;
      run(c, code, sizeof code, "lsr read (drained) faulted", 2); }
    CHECK((wemu_cpu_reg(c, 0) & 0x01u) == 0, "FIFO drained reports no data");

    /* guest writes a reply byte: the host callback sees it */
    { const uint8_t code[] = { 0xBA, 0xF8, 0x02, 0x00, 0x00, 0xB0, 0x5A, 0xEE } /* mov edx; mov al,'Z'; out dx,al */;
      run(c, code, sizeof code, "out dx,al faulted", 3); }  /* mov dx; mov al,'Z'; out */
    CHECK(tx_n == 1 && tx_log[0] == 'Z', "guest TX reached the host");

    printf("test_com2: %s (COM2 9P link, RX ring + TX callback)\n",
           fails ? "FAIL" : "PASS");
    wemu_machine_destroy(m);
    return fails ? 1 : 0;
}
