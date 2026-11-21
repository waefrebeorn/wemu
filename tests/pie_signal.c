/* Real static PIE signal guest: register a SIGSEGV handler, fault on a
 * read-only page, let the handler mprotect it writable and sigreturn, then
 * observe that the faulting store re-executed.  Exercises bounded guest
 * signal delivery through the native executor. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

static volatile uintptr_t fault_page;
static volatile int handled;

static void segv_handler(int sig) {
    (void)sig;   /* only signo is supplied by the bounded delivery path */
    mprotect((void *)fault_page, 4096, PROT_READ | PROT_WRITE);
    handled = 1;
}

int main(void) {
    void *p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 90;
    fault_page = (uintptr_t)p;
    struct sigaction sa = { 0 };
    sa.sa_handler = segv_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0) return 91;
    *(volatile int *)p = 0x12345678;   /* fault -> handler -> sigreturn -> retry */
    if (!handled || *(volatile int *)p != 0x12345678) return 92;
    puts("PIE-SIGNAL-DELIVERED-OK");
    return 0;
}
