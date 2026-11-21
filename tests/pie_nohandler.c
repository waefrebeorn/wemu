/* Static PIE that faults with NO guest handler installed: the native path
 * must fail closed (WEMU_UM_ERR_FAULT), never jump to an unknown handler. */
#include <stdint.h>

int main(void) {
    volatile int *p = (volatile int *)(uintptr_t)0x1;
    *p = 7;                       /* unconditional synchronous fault */
    return 0;
}
