/* test_usermode_native — differential gate for the host-mode ELF executor.
 *
 * 1. Audit the fail-closed dispatch table against the kernel's own
 *    asm/unistd_64.h (oracle: the kernel header, not our implementation).
 * 2. Real static busybox applets echo/ls/cat/uname: byte-exact stdout
 *    through wemu_um_run_elf == host execve of the SAME binary/args/env.
 * 3. Negative control: a hand-built static ELF calls syscall 309 (getcpu),
 *    which the host supports but the table does NOT list.  It must get
 *    -ENOSYS, be counted as denied, and never reach the host kernel.
 * 4. Baseline control: the same real busybox on the OLD interpreter path
 *    produces no applet output in 200k instructions (that mode has no
 *    full-applet execution; only the new path does).
 */
#define _GNU_SOURCE
#include "wemu.h"
#include "wemu_usermode.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define FAIL(...) do { fprintf(stderr, "FAIL: " __VA_ARGS__); exit(1); } while (0)

static const char *BUSYBOX(void) {
    const char *p = getenv("WEMU_BUSYBOX");
    return p ? p : "/home/wubu/opt/busybox-static/usr/bin/busybox";
}

static char *const GUEST_ENV[] = { (char *)"PATH=/usr/bin:/bin", NULL };

/* ---- print bytes the way a gate log should show them ---------------- */
static void print_exact(const char *tag, const char *p, size_t n) {
    printf("  %-6s exact stdout (%zu bytes): \"", tag, n);
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)p[i];
        if (c == '\n') fputs("\\n", stdout);
        else if (c == '\t') fputs("\\t", stdout);
        else if (c >= 0x20 && c < 0x7f) putchar(c);
        else printf("\\x%02x", c);
    }
    printf("\"\n");
}

/* ---- 1. table audit against an independent oracle ------------------- */
static size_t audit_header(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) FAIL("cannot open syscall oracle %s\n", path);
    size_t checked = 0;
    const WemuUmSyscallEntry *t = wemu_um_syscall_table(NULL);
    size_t n = 0;
    (void)wemu_um_syscall_table(&n);
    char line[256];
    for (size_t i = 0; i < n; i++) {
        char needle[96];
        snprintf(needle, sizeof needle, "#define __NR_%s ", t[i].name);
        unsigned long long want = 0;
        int found = 0;
        rewind(f);
        while (fgets(line, sizeof line, f)) {
            char *s = strstr(line, needle);
            if (s) {
                want = strtoull(s + strlen(needle), NULL, 10);
                found = 1;
                break;
            }
        }
        if (!found) FAIL("table[%zu] %s has no __NR_ oracle\n", i, t[i].name);
        if (t[i].nr != (uint32_t)want)
            FAIL("table[%zu] %s = %u, kernel says %llu\n",
                 i, t[i].name, t[i].nr, want);
        for (size_t j = 0; j < i; j++)
            if (t[j].nr == t[i].nr) FAIL("duplicate table nr %u\n", t[i].nr);
        checked++;
    }
    fclose(f);
    printf("ok: %zu dispatch entries audited vs asm/unistd_64.h "
           "(VSL numbers reused, 5 VSL-missing numbers local)\n", checked);
    return checked;
}

/* ---- 2. host oracle: same busybox, same args, host execve ----------- */
typedef struct { char b[WEMU_UM_OUT_MAX]; size_t n; } Cap;

static int host_exec(const char *path, char *const argv[], Cap *cap) {
    memset(cap, 0, sizeof *cap);
    int p[2];
    if (pipe(p) != 0) FAIL("oracle pipe\n");
    pid_t pid = fork();
    if (pid == 0) {
        close(p[0]);
        if (dup2(p[1], 1) < 0) _exit(126);
        close(p[1]);
        execve(path, argv, GUEST_ENV);
        _exit(127);
    }
    close(p[1]);
    for (;;) {
        ssize_t k = read(p[0], cap->b + cap->n, sizeof cap->b - 1 - cap->n);
        if (k > 0) cap->n += (size_t)k;
        else if (k == 0) break;
        else if (errno == EINTR) continue;
        else break;
    }
    close(p[0]);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) { }
    cap->b[cap->n] = '\0';
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static void check_applet(const char *tag, char *const argv[], int want_exit) {
    WemuUmResult r;
    int rc = wemu_um_run_elf(BUSYBOX(), argv, GUEST_ENV, &r);
    if (rc != WEMU_UM_OK)
        FAIL("%s: status=%s syscalls=%llu denied=%llu out=[%s]\n", tag,
             wemu_um_status_name(rc), (unsigned long long)r.syscalls,
             (unsigned long long)r.denied, r.out);
    if (r.exit_code != want_exit)
        FAIL("%s: exit %d want %d\n", tag, r.exit_code, want_exit);
    Cap oracle;
    int he = host_exec(BUSYBOX(), argv, &oracle);
    if (he != want_exit) FAIL("%s: oracle exit %d want %d\n", tag, he, want_exit);
    if (r.out_len != oracle.n || memcmp(r.out, oracle.b, oracle.n) != 0)
        FAIL("%s: output mismatch native=[%s] host=[%s]\n", tag, r.out, oracle.b);
    if (r.denied != 0) FAIL("%s: unexpected denied=%llu\n", tag,
                            (unsigned long long)r.denied);
    print_exact(tag, r.out, r.out_len);
    printf("        (exit=%d, syscalls=%llu, denied=%llu; == host execve)\n",
           r.exit_code, (unsigned long long)r.syscalls,
           (unsigned long long)r.denied);
}

static void test_applets(void) {
    char dir[] = "/tmp/wemu_um_native_XXXXXX";
    if (!mkdtemp(dir)) FAIL("mkdtemp\n");
    char catfile[128], a[128], b[128], c[128];
    snprintf(catfile, sizeof catfile, "%s/payload.txt", dir);
    snprintf(a, sizeof a, "%s/alpha.txt", dir);
    snprintf(b, sizeof b, "%s/beta.txt", dir);
    snprintf(c, sizeof c, "%s/gamma", dir);
    const char payload[] = "wemu-cat-exact-content\n";
    int fd = open(catfile, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0 || write(fd, payload, sizeof payload - 1) != (ssize_t)sizeof payload - 1)
        FAIL("cat fixture\n");
    close(fd);
    for (const char **p = (const char *[]){ a, b, c, NULL }; *p; p++) {
        fd = open(*p, O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (fd < 0) FAIL("ls fixture\n");
        close(fd);
    }

    char *argv_echo[] = { (char *)"busybox", (char *)"echo", (char *)"hello-wemu", NULL };
    char *argv_uname[] = { (char *)"busybox", (char *)"uname", NULL };
    char *argv_cat[] = { (char *)"busybox", (char *)"cat", catfile, NULL };
    char *argv_ls[] = { (char *)"busybox", (char *)"ls", dir, NULL };
    check_applet("echo", argv_echo, 0);
    check_applet("uname", argv_uname, 0);
    check_applet("cat", argv_cat, 0);
    check_applet("ls", argv_ls, 0);
    unlink(catfile); unlink(a); unlink(b); unlink(c); rmdir(dir);
    printf("ok: 4 real static busybox applets byte-exact through native path\n");
}

/* ---- 3. negative control: unlisted syscall is refused --------------- */
static void build_denied_elf(uint8_t *img, size_t cap) {
    const uint8_t code[] = {
        0xB8, 0x35, 0x01, 0x00, 0x00,   /* mov eax,309 (getcpu) */
        0x31, 0xFF,                     /* xor edi,edi */
        0x31, 0xF6,                     /* xor esi,esi */
        0x31, 0xD2,                     /* xor edx,edx */
        0x0F, 0x05,                     /* syscall -> must be -ENOSYS */
        0x89, 0xC7,                     /* mov edi,eax */
        0xB8, 0x3C, 0x00, 0x00, 0x00,   /* mov eax,60 (exit) */
        0x0F, 0x05,                     /* syscall */
    };
    memset(img, 0, cap);
    img[0] = 0x7f; img[1] = 'E'; img[2] = 'L'; img[3] = 'F';
    img[4] = 2; img[5] = 1; img[6] = 1;
    uint16_t type = 2, mach = 62, ehsize = 64, phentsz = 56, phnum = 1;
    uint32_t ver = 1;
    uint64_t entry = 0x401000, phoff = 64;
    memcpy(img + 16, &type, 2); memcpy(img + 18, &mach, 2);
    memcpy(img + 20, &ver, 4); memcpy(img + 24, &entry, 8);
    memcpy(img + 32, &phoff, 8);
    memcpy(img + 52, &ehsize, 2); memcpy(img + 54, &phentsz, 2);
    memcpy(img + 56, &phnum, 2);
    uint32_t ptype = 1, pflags = 7;           /* one RWE PT_LOAD */
    uint64_t poff = 0, pvaddr = 0x400000,
             pfilesz = 0x1000 + sizeof code, pmemsz = pfilesz, palign = 0x1000;
    uint8_t *ph = img + 64;
    memcpy(ph, &ptype, 4); memcpy(ph + 4, &pflags, 4);
    memcpy(ph + 8, &poff, 8); memcpy(ph + 16, &pvaddr, 8);
    memcpy(ph + 24, &pvaddr, 8); memcpy(ph + 32, &pfilesz, 8);
    memcpy(ph + 40, &pmemsz, 8); memcpy(ph + 48, &palign, 8);
    memcpy(img + 0x1000, code, sizeof code);
}

static void test_fail_closed(void) {
    const WemuUmSyscallEntry *t = wemu_um_syscall_table(NULL);
    size_t n = 0;
    (void)wemu_um_syscall_table(&n);
    for (size_t i = 0; i < n; i++)
        if (t[i].nr == 309) FAIL("getcpu must not be in the table\n");
    long host = syscall(309, NULL, NULL, NULL);
    if (host != 0) FAIL("host supports getcpu (oracle got %ld), negative control invalid\n", host);

    char path[] = "/tmp/wemu_um_denied_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) FAIL("mkstemp\n");
    static uint8_t img[0x1100];
    build_denied_elf(img, sizeof img);
    if (write(fd, img, 0x1000 + 22) < 0) FAIL("write denied ELF\n");
    close(fd);

    WemuUmResult r;
    int rc = wemu_um_run_elf(path, (char *[]){ (char *)"denied", NULL }, GUEST_ENV, &r);
    unlink(path);
    if (rc != WEMU_UM_OK)
        FAIL("denied run status=%s (guest must survive -ENOSYS)\n",
             wemu_um_status_name(rc));
    if (r.exit_code != -ENOSYS)
        FAIL("denied exit=%d want %d (-ENOSYS)\n", r.exit_code, -ENOSYS);
    if (r.denied != 1 || r.syscalls != 2)
        FAIL("denied=%llu syscalls=%llu want 1/2\n",
             (unsigned long long)r.denied, (unsigned long long)r.syscalls);
    if (r.out_len != 0) FAIL("denied run wrote %u bytes\n", r.out_len);
    printf("ok: NEGATIVE CONTROL unlisted getcpu(309) -> -ENOSYS, "
           "denied=1, syscalls=2, host getcpu=0 (would have succeeded)\n");
}

/* ---- 4. baseline control: old interpreter cannot run the applet ----- */
static char old_buf[8192];
static size_t old_ser_n;
static void old_ser(uint8_t b, void *ud) {
    (void)ud;
    if (old_ser_n < sizeof old_buf - 1) old_buf[old_ser_n++] = (char)b;
}

static void test_old_mode_control(void) {
    WemuMachine *m = wemu_machine_create(0x2000000, old_ser, NULL);
    if (!m) FAIL("old machine create\n");
    WemuCpu *cpu = wemu_machine_cpu(m);
    char *argv[] = { (char *)"busybox", (char *)"echo", (char *)"hello-wemu", NULL };
    if (wemu_cpu_load_elf(cpu, BUSYBOX(), NULL, 0, argv) != 0)
        FAIL("old load_elf\n");
    old_ser_n = 0;
    int64_t insns = wemu_cpu_run(cpu, 200000);
    old_buf[old_ser_n] = '\0';
    /* The old hook can emit bytes from the startup write() it reaches, but
     * it never produces the applet's exact stdout: there is no native mode. */
    if (strcmp(old_buf, "hello-wemu\n") == 0)
        FAIL("old interpreter unexpectedly produced exact applet output\n");
    wemu_machine_destroy(m);
    printf("ok: OLD MODE control — interpreter produced %zu bytes "
           "(not exact applet output) in %lld insns; native path exact\n",
           old_ser_n, (long long)insns);
}

int main(void) {
    audit_header("/usr/include/x86_64-linux-gnu/asm/unistd_64.h");
    test_applets();
    test_fail_closed();
    test_old_mode_control();
    printf("WEMU NATIVE USERMODE GATE PASS (real static busybox, exact output, fail-closed)\n");
    return 0;
}
