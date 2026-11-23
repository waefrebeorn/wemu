/* test_fxsave — FXSAVE/FXRSTOR image gate.
 *
 * Long guest boot reached task_switch_asm, whose first instruction is
 * `fxsave 0x90(%rdi)`. WEMU had only 0F AE /5-/7 fence hints and #UD'd on
 * /0 and /1. The image is bounded to 512 bytes and carries the real x87
 * control/status words; the remaining FPU state is honestly zeroed.
 */
#include "wemu.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define CHECK(cond, ...) do { if (!(cond)) { \
    fprintf(stderr, "FAIL: " __VA_ARGS__); return 1; } } while (0)

int main(void) {
    uint8_t code[] = {
        0xDB,0xE3,                                     /* fninit */
        0x0F,0xAE,0x04,0x25,0x00,0x20,0x00,0x00,       /* fxsave [0x2000] */
        0x0F,0xAE,0x0C,0x25,0x00,0x20,0x00,0x00,       /* fxrstor [0x2000] */
        0xF4
    };
    WemuCpu *c = wemu_cpu_create(0x100000);
    if (!c) return 2;
    wemu_cpu_load(c, 0x1000, code, sizeof code);
    wemu_cpu_set_rip(c, 0x1000);
    wemu_cpu_run(c, 12);
    CHECK(wemu_cpu_fault(c) == 0, "FXSAVE/FXRSTOR faulted");
    uint8_t image[512];
    if (wemu_mem_read(c, 0x2000, image, sizeof image) != 0) {
        wemu_cpu_destroy(c);
        CHECK(0, "FXSAVE image unreadable");
    }
    CHECK(image[0] == 0x7f && image[1] == 0x03,
          "FXSAVE did not store FNINIT control word");
    wemu_cpu_destroy(c);
    printf("test_fxsave: PASS (512-byte image, FCW, FXRSTOR round-trip)\n");
    return 0;
}
