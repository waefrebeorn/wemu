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
#include <stdlib.h>
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
        /* Env-gated fd census: reports how many fds the NEW image can see.
         * The fexecve leak control compares this across plain-fd and CLOEXEC
         * execs — the private internal dup must be closed before stage2 runs. */
        if (getenv("WEMU_FD_CENSUS")) {
            int n = 0;
            for (int fd = 3; fd < 1024; fd++)
                if (fcntl(fd, F_GETFD) != -1) n++;
            char b[64];
            snprintf(b, sizeof b, "FDCOUNT=%d\n", n);
            put(b);
        }
        return 42;
    }

    const char *path = argc >= 3 ? argv[2] : "tests/exec_chain";
    char *nargv[] = { (char *)path, (char *)"stage2", (char *)"alpha",
                      (char *)"beta (two)", NULL };
    /* Propagate the optional fd-census marker across the (emulated) exec:
     * stage1 sees it in the inherited env, stage2 reads it to report how many
     * fds the NEW image can observe. */
    char *nenv[] = { (char *)"EXECTEST=1",
                     getenv("WEMU_FD_CENSUS") ? (char *)"WEMU_FD_CENSUS=1" : NULL,
                     NULL };

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

    /* NEW: execveat(fd, "", ..., AT_EMPTY_PATH) on a guest-opened fd.  On the
     * host the kernel executes the file the fd describes; under WEMU the fd
     * must be in the admitted guest fd table for the image to be replaced. */
    if (argc >= 2 && strcmp(argv[1], "empty") == 0) {
        int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY, 0);
        if (fd < 0) { put_errno("OPEN-RC", -errno); return 6; }
        syscall(SYS_execveat, fd, "", nargv, nenv, AT_EMPTY_PATH);
        put_errno("EMPTY-RC", -errno);
        return 8;
    }
    /* NEW: fd-relative execveat(dirfd, base, ..., 0). */
    if (argc >= 2 && strcmp(argv[1], "rel") == 0) {
        const char *dir  = argc >= 3 ? argv[2] : "tests";
        const char *base = argc >= 4 ? argv[3] : "exec_chain";
        int dfd = (int)syscall(SYS_openat, AT_FDCWD, dir,
                               O_RDONLY | O_DIRECTORY, 0);
        if (dfd < 0) { put_errno("OPENDIR-RC", -errno); return 6; }
        syscall(SYS_execveat, dfd, base, nargv, nenv, 0);
        put_errno("REL-RC", -errno);
        return 9;
    }
    /* NEW: an O_CLOEXEC fd passed to fexecve.  The host honours it via an
     * internal dup; the bounded WEMU model refuses a CLOEXEC fd (no fexecve
     * internal-dup model) with -EBADF.  With the OFD gate disabled, the old
     * number-only path admits it (byte-exact vs host). */
    if (argc >= 2 && strcmp(argv[1], "cloexec") == 0) {
        int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
        if (fd < 0) { put_errno("OPEN-RC", -errno); return 17; }
        syscall(SYS_execveat, fd, "", nargv, nenv, AT_EMPTY_PATH);
        put_errno("CLOEXEC-RC", -errno);
        return 18;
    }
    /* NEW: close+reopen reuse of an admitted fd NUMBER.  The first open is
     * admitted; after close, the SAME number is reopened on a DIFFERENT ELF.
     * On the host execveat runs the reopened file (PIE-LOAD-BIAS-OK).  WEMU
     * must refuse the reused number (-EBADF) because its open-file-description
     * no longer matches the one bound at admission. */
    if (argc >= 2 && strcmp(argv[1], "reuse") == 0) {
        const char *p1 = argc >= 3 ? argv[2] : "tests/exec_chain";
        const char *p2 = argc >= 4 ? argv[3] : "tests/pie_hello";
        int fd = (int)syscall(SYS_openat, AT_FDCWD, p1, O_RDONLY, 0);
        if (fd < 0) { put_errno("OPEN1-RC", -errno); return 14; }
        syscall(SYS_close, fd);                 /* release the admitted number */
        int fd2 = (int)syscall(SYS_openat, AT_FDCWD, p2, O_RDONLY, 0);
        if (fd2 < 0) { put_errno("OPEN2-RC", -errno); return 15; }
        syscall(SYS_execveat, fd2, "", nargv, nenv, AT_EMPTY_PATH);
        put_errno("REUSE-RC", -errno);
        return 16;
    }
    /* NEW: an fd passed in by the harness (valid, executable on the host) but
     * NEVER opened by the guest — must be refused by the fd admission table. */
    if (argc >= 2 && strcmp(argv[1], "fdarg") == 0) {
        int fd = atoi(argv[2]);
        syscall(SYS_execveat, fd, "", nargv, nenv, AT_EMPTY_PATH);
        put_errno("FDARG-RC", -errno);
        return 13;
    }

    /* NEW: an fd the guest never opened must be refused (host -EBADF). */
    if (argc >= 2 && strcmp(argv[1], "unknownfd") == 0) {
        syscall(SYS_execveat, 9999, "", nargv, nenv, AT_EMPTY_PATH);
        put_errno("UNKNOWNFD-RC", -errno);
        return 10;
    }
    /* NEW: an unsupported flag bit must be refused (host -EINVAL). */
    if (argc >= 2 && strcmp(argv[1], "badflags") == 0) {
        int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY, 0);
        if (fd < 0) { put_errno("OPEN-RC", -errno); return 6; }
        syscall(SYS_execveat, fd, "", nargv, nenv, AT_EMPTY_PATH | 0x2000u);
        put_errno("BADFLAGS-RC", -errno);
        return 11;
    }

    execve(path, nargv, nenv);
    put_errno("STAGE1-EXECVE-FAILED", -errno);
    return 7;
}
