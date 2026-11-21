/* Dynamically linked (PT_INTERP) PIE control: the native path must refuse
 * to guess at an ld.so model rather than pretending to run it. */
#include <stdio.h>

int main(void) {
    puts("PIE-DYNAMIC-OK");
    return 0;
}
