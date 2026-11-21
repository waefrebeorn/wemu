/* exec_fork — child-exec differential fixture.
 *
 * The root process forks; the COW child prints a pre-exec marker, execve()s
 * the SAME static-PIE image with a fresh argv, and the replaced image prints
 * a post-exec marker and exits 37.  The parent wait4()s and reports the
 * child's real exit status.  On the host the kernel performs the replacement;
 * under WEMU the bounded dispatch must do so and keep the child non-root so
 * wait4 still sees 37 (not the supervisor's publish-path 0).
 * Both stdout streams and exit codes must be byte-exact.
 * License: WaefreBeorn Umbrella License v3.0. */
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void put(const char *s) {
    size_t n = strlen(s);
    while (n) {
        ssize_t k = write(STDOUT_FILENO, s, n);
        if (k <= 0) break;
        s += k; n -= (size_t)k;
    }
}

static void put_int(const char *tag, int v) {
    char b[96];
    int n = snprintf(b, sizeof b, "%s%d\n", tag, v);
    if (n > 0) put(b);
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "child-exec") == 0) {
        put("CHILD-EXEC: image replaced\n");
        return 37;
    }

    pid_t pid = fork();
    if (pid == 0) {
        put("PRE-EXEC: child before replacement\n");
        char *nargv[] = { argv[0], (char *)"child-exec", NULL };
        char *nenv[] = { (char *)"FORKEXEC=1", NULL };
        execve(argv[0], nargv, nenv);
        put("CHILD-EXECVE-FAILED\n");
        _exit(99);
    }
    if (pid < 0) { put("FORK-FAILED\n"); return 1; }

    int st = 0;
    pid_t w;
    while ((w = waitpid(pid, &st, 0)) < 0 && errno == EINTR) { }
    if (w == pid && WIFEXITED(st))
        put_int("PARENT: child exit=", WEXITSTATUS(st));
    else
        put("PARENT: wait failed\n");
    return 0;
}
