/* Real self-relocating static PIE guest for the native user-mode gate.
 * Built with `cc -static-pie`: ET_DYN with no PT_INTERP, so load-bias
 * handling alone is enough to run it. */
#include <stdio.h>

int main(void) {
    puts("PIE-LOAD-BIAS-OK");
    return 0;
}
