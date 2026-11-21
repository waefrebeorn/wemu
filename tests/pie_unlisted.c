/* Static PIE that tries to install a handler for an UNMODELED signal.
 * The bounded guest signal table must refuse it (fail closed) and report
 * the refusal through signals_denied. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>

static void ignored(int sig) { (void)sig; }

int main(void) {
    struct sigaction sa = { 0 };
    sa.sa_handler = ignored;
    sigemptyset(&sa.sa_mask);
    int rc = sigaction(SIGUSR1, &sa, NULL);
    printf("UNLISTED-SIGACTION-RC=%d\n", rc);
    return 0;
}
