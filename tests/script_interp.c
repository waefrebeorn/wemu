/* script_interp — bounded #! differential interpreter fixture.
 *
 * Built as a static PIE (no PT_INTERP): it is the target named in a script's
 * #! line.  Linux passes it argv = [interp, i_arg?, script, argv[1]...]; this
 * program writes that vector verbatim and exits 23.  The SAME binary runs on
 * the host (kernel binfmt_script) and inside WEMU (bounded script dispatch),
 * so stdout bytes and exit code must match exactly.
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
    put("INTERP:");
    for (int i = 0; i < argc; i++) {
        put(" ["); put(argv[i]); put("]");
    }
    put("\n");
    return 23;
}
