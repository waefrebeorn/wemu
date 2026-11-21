/* exec_script — driver fixture for bounded #! dispatch.
 *
 * The guest is a real static PIE (the top-level run must start from an ELF).
 * Its execve(argv[1]) targets a #! script; the kernel (host oracle) or WEMU's
 * bounded dispatcher rebuilds argv and enters the interpreter.  Raw write()
 * keeps the failure marker deterministic on both paths.
 * License: WaefreBeorn Umbrella License v3.0. */
#include <stddef.h>
#include <string.h>
#include <unistd.h>

static void put(const char *s) {
    size_t n = strlen(s);
    while (n) {
        ssize_t k = write(STDOUT_FILENO, s, n);
        if (k <= 0) break;
        s += k; n -= (size_t)k;
    }
}

int main(int argc, char **argv) {
    if (argc < 2) { put("DRIVER-NO-SCRIPT\n"); return 2; }
    char *nargv[] = { argv[1], (char *)"u1", (char *)"u2", NULL };
    char *nenv[] = { (char *)"EXECTEST=1", NULL };
    execve(argv[1], nargv, nenv);
    put("DRIVER-EXECVE-FAILED\n");
    return 7;
}
