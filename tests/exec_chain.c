/* exec_chain — bounded execve differential guest fixture.
 *
 * Stage 1 execve()s itself with a fresh argv/envp; stage 2 prints all of its
 * arguments and exits 42.  On the host the kernel performs the replacement;
 * under WEMU the SIGSYS handler must perform the equivalent bounded image
 * replacement.  The two stdout byte streams and exit codes must match.
 *
 * Extra modes exercise the fail-closed edges (unsupported execveat flags,
 * PT_INTERP target, missing target).  Uses write(2) so output does not depend
 * on libc buffering across the image replacement.
 * License: WaefreBeorn Umbrella License v3.0. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static void put(const char *s) {
    size_t n = strlen(s);
    while (n) {
        ssize_t k = write(STDOUT_FILENO, s, n);
        if (k <= 0) break;
        s += k; n -= (size_t)k;
    }
}

static void put_errno(const char *tag, int e) {
    char b[128];
    snprintf(b, sizeof b, "%s=%d\n", tag, e);
    put(b);
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "stage2") == 0) {
        put("STAGE2:");
        for (int i = 2; i < argc; i++) { put(" ["); put(argv[i]); put("]"); }
        put("\n");
        return 42;
    }

    const char *path = argc >= 3 ? argv[2] : "tests/exec_chain";
    char *nargv[] = { (char *)path, (char *)"stage2", (char *)"alpha",
                      (char *)"beta (two)", NULL };
    char *nenv[] = { (char *)"EXECTEST=1", NULL };

    if (argc >= 2 && strcmp(argv[1], "flags") == 0) {
        /* AT_EMPTY_PATH is deliberately refused by the bounded model. */
        syscall(322 /* execveat */, AT_FDCWD, path, nargv, nenv, AT_EMPTY_PATH);
        put_errno("FLAGS-RC", -errno);
        return 3;
    }
    if (argc >= 2 && strcmp(argv[1], "interp") == 0) {
        execve("tests/pie_dynamic", nargv, nenv);
        put_errno("INTERP-RC", -errno);
        return 4;
    }
    if (argc >= 2 && strcmp(argv[1], "badpath") == 0) {
        execve("/no/such/wemu-exec-target", nargv, nenv);
        put_errno("BADPATH-RC", -errno);
        return 5;
    }

    execve(path, nargv, nenv);
    put_errno("STAGE1-EXECVE-FAILED", -errno);
    return 7;
}
