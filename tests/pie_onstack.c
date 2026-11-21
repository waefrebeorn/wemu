/* Real static PIE SA_ONSTACK guest: register a SIGSEGV handler with
 * SA_SIGINFO|SA_ONSTACK on a guest alternate stack, fault on a read-only page,
 * and observe from inside the handler whether the kernel reports SS_ONSTACK
 * and whether a handler local really lives on the alternate stack.  After
 * sigreturn, the faulting store is retried and the altstack is no longer
 * "on stack".  Every printed value is deterministic on the host, so the same
 * binary is a byte-exact oracle for WEMU's bounded SA_ONSTACK delivery.
 *
 * It also probes one fail-closed shape first: an altstack below MINSIGSTKSZ
 * must return -ENOMEM on the host and under WEMU (exact refuse reason). */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ALT_SZ  65536u
#define BAD_SZ  1024u

static volatile uintptr_t fault_page;
static volatile int handled;
static volatile int h_onstack;   /* sigaltstack(NULL) reported SS_ONSTACK */
static volatile int h_localin;   /* a handler local was inside the altstack */
static uintptr_t alt_base;

static int ss_set(void *sp, size_t sz, int flags) {
    stack_t ss;
    memset(&ss, 0, sizeof ss);
    ss.ss_sp = sp; ss.ss_size = sz; ss.ss_flags = flags;
    return (int)syscall(SYS_sigaltstack, &ss, (stack_t *)NULL);
}

static int ss_query(stack_t *out) {
    memset(out, 0, sizeof *out);
    return (int)syscall(SYS_sigaltstack, (stack_t *)NULL, out);
}

static void handler(int sig, siginfo_t *si, void *ucp) {
    (void)sig; (void)si; (void)ucp;
    stack_t cur;
    int rc = ss_query(&cur);
    volatile uintptr_t local = 0;
    uintptr_t la = (uintptr_t)&local;
    h_onstack = (rc == 0 && (cur.ss_flags & SS_ONSTACK)) ? 1 : 0;
    h_localin = (rc == 0 &&
                 la >= (uintptr_t)cur.ss_sp &&
                 la < (uintptr_t)cur.ss_sp + cur.ss_size) ? 1 : 0;
    /* (void)alt_base keeps the query's altstack identity observable. */
    (void)alt_base;
    mprotect((void *)fault_page, 4096, PROT_READ | PROT_WRITE);
    handled = 1;
}

int main(void) {
    void *alt = mmap(NULL, ALT_SZ, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (alt == MAP_FAILED) return 80;
    void *p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 81;
    fault_page = (uintptr_t)p;
    alt_base = (uintptr_t)alt;

    /* Fail-closed shape: a too-small alternate stack is refused by both the
     * host kernel and WEMU with ENOMEM. */
    stack_t bad;
    memset(&bad, 0, sizeof bad);
    bad.ss_sp = alt; bad.ss_size = BAD_SZ; bad.ss_flags = 0;
    errno = 0;
    int badret = (int)syscall(SYS_sigaltstack, &bad, (stack_t *)NULL);
    printf("BAD=%d\n", badret < 0 ? errno : 0);

    /* Bounded in-scope shape. */
    int setret = ss_set(alt, ALT_SZ, 0);
    printf("SET=%d\n", setret >= 0 ? 0 : -1);

    stack_t before;
    ss_query(&before);
    printf("BEFORE=%d\n", (before.ss_flags & SS_ONSTACK) ? 1 : 0);
    printf("BASE=%d\n", before.ss_sp == (void *)alt ? 1 : 0);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0) return 82;

    *(volatile int *)p = 0x12345678;   /* fault -> altstack handler -> retry */

    stack_t after;
    ss_query(&after);
    printf("HANDLER=%d,%d AFTER=%d OK=%d\n",
           h_onstack, h_localin,
           (after.ss_flags & SS_ONSTACK) ? 1 : 0,
           (handled && *(volatile int *)p == 0x12345678) ? 1 : 0);
    return 0;
}
