/* fork_clone.c — positive + negative fixture for WEMU's bounded native
 * fork/clone path.  Built as a static PIE and run both natively (host
 * execve) and through wemu_um_run_elf(); the two stdout streams must be
 * byte-exact.  All writes are raw so child output is never lost to buffering.
 * License: WaefreBeorn Umbrella License v3.0. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* CLONE_NEWUSER|CLONE_FS is rejected by the real kernel too (-EINVAL), so
 * this fixture is safe to run as its own host oracle. */
#define CLONE_FS_       0x00000200u
#define CLONE_NEWUSER_  0x10000000u

struct local_clone_args {
    uint64_t flags, pidfd, child_tid, parent_tid, exit_signal,
             stack, stack_size, tls, set_tid, set_tid_size, cgroup;
};

static void emit(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    (void)!write(1, s, n);
}

static void emit_rc(const char *tag, long rc) {
    char b[64];
    size_t i = 0;
    while (tag[i]) { b[i] = tag[i]; i++; }
    if (rc < 0) { b[i++] = '-'; rc = -rc; }
    if (rc == 0) b[i++] = '0';
    else {
        char t[24]; size_t j = 0;
        while (rc > 0) { t[j++] = (char)('0' + (rc % 10)); rc /= 10; }
        while (j > 0) b[i++] = t[--j];
    }
    b[i++] = '\n';
    (void)!write(1, b, i);
}

static int wait_child(pid_t p) {
    int st = 0;
    pid_t w = waitpid(p, &st, 0);
    return w == p && WIFEXITED(st) && WEXITSTATUS(st) == 7;
}

int main(void) {
    /* 1. plain fork -> COW child writes, parent waits and checks status. */
    pid_t p = fork();
    if (p == 0) { emit("FORK-CHILD-OK\n"); _exit(7); }
    emit(wait_child(p) ? "FORK-PARENT-OK\n" : "FORK-PARENT-BAD\n");

    /* 2. raw clone(SIGCHLD, stack=0) -> same bounded model. */
    long c = syscall(SYS_clone, (unsigned long)SIGCHLD, 0UL, 0UL, 0UL, 0UL);
    if (c == 0) { emit("CLONE-CHILD-OK\n"); _exit(7); }
    emit(wait_child((pid_t)c) ? "CLONE-PARENT-OK\n" : "CLONE-PARENT-BAD\n");

    /* 3. unsupported clone flags -> -EINVAL, no child created. */
    errno = 0;
    long r = syscall(SYS_clone,
        (unsigned long)(CLONE_NEWUSER_ | CLONE_FS_ | SIGCHLD),
        0UL, 0UL, 0UL, 0UL);
    emit_rc("CLONE-FLAGS-RC=", r < 0 ? -errno : r);

    /* 4. unsupported clone3 flags -> -EINVAL too. */
    struct local_clone_args ca;
    for (size_t i = 0; i < sizeof ca; i++) ((unsigned char *)&ca)[i] = 0;
    ca.flags = CLONE_NEWUSER_ | CLONE_FS_;
    ca.exit_signal = SIGCHLD;
    errno = 0;
    r = syscall(SYS_clone3, &ca, sizeof ca);
    emit_rc("CLONE3-FLAGS-RC=", r < 0 ? -errno : r);
    return 0;
}
