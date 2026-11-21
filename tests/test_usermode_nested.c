/* test_usermode_nested.c -- bounded nested signal delivery differential gate.
 *
 * The fixture pie_nested is built as a static PIE and run both natively (the
 * independent host-kernel oracle) and through wemu_um_run_elf().  In the
 * deterministic "oracle" and "masked" modes the byte streams must match.
 * "depth" is WEMU-only: the bounded nest cap refuses beyond
 * WEMU_UM_MAX_SIG_NEST with an exact reason.  "NEST-OFF" is the negative
 * control: the old path refuses a nested delivery and the stream diverges.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "wemu_usermode.h"

static int failures;
#define CHECK(cond, msg) do { if (!(cond)) { \
    printf("  FAIL: %s\n", msg); failures++; } else { \
    printf("  ok: %s\n", msg); } } while (0)

static char *const ENV[] = { NULL };

static int run_wemu(const char *mode, int nested_on, WemuUmResult *out) {
    char prog[] = "tests/pie_nested";
    char *argv[] = { prog, (char *)mode, NULL };
    wemu_um_set_nested_enabled(nested_on);
    memset(out, 0, sizeof *out);
    return wemu_um_run_elf("tests/pie_nested", argv, ENV, out);
}

static int native_output(const char *mode, char *buf, size_t cap) {
    char cmd[128];
    snprintf(cmd, sizeof cmd, "./tests/pie_nested %s 2>/dev/null", mode);
    FILE *f = popen(cmd, "r");
    if (!f) return -1;
    size_t n = fread(buf, 1, cap - 1, f);
    int rc = pclose(f);
    buf[n] = 0;
    if (rc != 0) return -1;
    return (int)n;
}

int main(void) {
    WemuUmResult r;
    char host[4096];

    printf("=== bounded nested signal delivery ===\n");

    int hrc = native_output("oracle", host, sizeof host);
    CHECK(hrc > 0, "host oracle fixture produced output");
    int rc = run_wemu("oracle", 1, &r);
    CHECK(rc == 0, "WEMU oracle mode ran to OK");
    printf("  host oracle: [%s]\n", host);
    printf("  WEMU oracle: [%s]\n", r.out);
    CHECK(strcmp(r.out, host) == 0, "nested oracle byte-exact vs host");
    CHECK(r.signals_delivered == 2 && r.nested_deliveries == 1 &&
          r.nest_depth_max == 2, "one nested frame at depth 2");
    CHECK(r.refuses[WEMU_UM_REFUSE_NEST_DISABLED] == 0 &&
          r.refuses[WEMU_UM_REFUSE_NEST_DEPTH] == 0 &&
          r.refuses[WEMU_UM_REFUSE_NEST_FAULT] == 0, "no refusals in oracle shape");

    hrc = native_output("masked", host, sizeof host);
    CHECK(hrc > 0, "host masked fixture produced output");
    rc = run_wemu("masked", 1, &r);
    CHECK(rc == 0, "WEMU masked mode ran to OK");
    printf("  host masked: [%s]\n", host);
    printf("  WEMU masked: [%s]\n", r.out);
    CHECK(strcmp(r.out, host) == 0, "masked pending delivery byte-exact vs host");
    CHECK(r.nested_deliveries == 0 && r.nest_depth_max == 1,
          "masked signal stays flat until unblock");

    rc = run_wemu("depth", 1, &r);
    CHECK(rc == 0, "WEMU depth mode ran to OK");
    printf("  depth: [%s]\n", r.out);
    CHECK(r.nest_depth_max == WEMU_UM_MAX_SIG_NEST &&
          r.nested_deliveries == WEMU_UM_MAX_SIG_NEST - 1,
          "bounded nesting reaches exactly the cap");
    CHECK(r.refuses[WEMU_UM_REFUSE_NEST_DEPTH] == 1 &&
          r.signals_denied >= 1, "one over-cap delivery refused exactly");

    /* Negative control: nesting disabled restores the OLD flat-only path. */
    char oracle[4096];
    (void)native_output("oracle", oracle, sizeof oracle);
    rc = run_wemu("oracle", 0, &r);
    CHECK(rc == 0, "NEST-OFF control ran to OK");
    printf("  NEST-OFF: [%s]\n", r.out);
    CHECK(r.refuses[WEMU_UM_REFUSE_NEST_DISABLED] >= 1,
          "NEST-OFF names the disabled path");
    CHECK(r.nested_deliveries == 0 && r.nest_depth_max == 1,
          "NEST-OFF delivers no nested frame");
    CHECK(strcmp(r.out, oracle) != 0,
          "NEST-OFF byte stream differs from host oracle (non-vacuous)");

    wemu_um_set_nested_enabled(1);
    printf("=== %s: %d failure(s) ===\n",
           failures ? "WEMU BOUNDED NESTED SIGNAL GATE FAILED" :
                      "WEMU BOUNDED NESTED SIGNAL GATE PASS", failures);
    return failures ? 1 : 0;
}
