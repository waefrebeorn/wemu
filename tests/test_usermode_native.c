/* test_usermode_native — differential gate for the host-mode ELF executor.
 *
 * 1. Audit the fail-closed dispatch table against the kernel's own
 *    asm/unistd_64.h (oracle: the kernel header, not our implementation).
 * 2. Real static busybox applets: byte-exact stdout + exit codes through
 *    wemu_um_run_elf == host execve of the SAME binary/args/env.  The set is
 *    the full deterministic applet subset available in the bundled busybox.
 * 3. Negative control: a hand-built static ELF calls syscall 309 (getcpu),
 *    which the host supports but the table does NOT list.  It must get
 *    -ENOSYS, be counted as denied, and never reach the host kernel.
 * 4. Baseline control: the same real busybox on the OLD interpreter path
 *    produces no applet output in 200k instructions (that mode has no
 *    full-applet execution; only the new path does).
 * 5. ET_DYN / PIE load bias, and bounded guest signal delivery.
 * 6. Bounded fork/clone: a static-PIE fixture forks, raw-clones, waits and
 *    submits unsupported clone/clone3 flags.  Its stdout is byte-exact vs
 *    host execve of the same fixture; forks/denied counters are asserted.
 *    Fail-closed flag policy is also checked through the introspection API.
 */
#define _GNU_SOURCE
#include "wemu.h"
#include "wemu_usermode.h"

#include <errno.h>
#include <elf.h>
#include <fcntl.h>
#include <signal.h>
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
    printf("  %-12s exact stdout (%zu bytes): \"", tag, n);
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
           "(VSL numbers reused, WEMU_UM_SYS_* for VSL-missing numbers)\n", checked);
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

static int g_applets_checked;

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
    g_applets_checked++;
}

static void test_applets(void) {
    char dir[] = "/tmp/wemu_um_native_XXXXXX";
    if (!mkdtemp(dir)) FAIL("mkdtemp\n");
    char catfile[160], a[160], b[160], c[160], nums[160], lnk[160];
    snprintf(catfile, sizeof catfile, "%s/payload.txt", dir);
    snprintf(a, sizeof a, "%s/alpha.txt", dir);
    snprintf(b, sizeof b, "%s/beta.txt", dir);
    snprintf(c, sizeof c, "%s/gamma", dir);
    snprintf(nums, sizeof nums, "%s/nums.txt", dir);
    snprintf(lnk, sizeof lnk, "%s/link", dir);

    const char payload[] = "alpha one,beta,10\nbeta two,gamma,20\n"
                           "alpha three,delta,30\n";
    int fd = open(catfile, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0 || write(fd, payload, sizeof payload - 1) != (ssize_t)sizeof payload - 1)
        FAIL("cat fixture\n");
    close(fd);
    fd = open(nums, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0 || write(fd, "30\n10\n20\n10\n", 12) != 12) FAIL("nums fixture\n");
    close(fd);
    if (symlink("payload.txt", lnk) != 0) FAIL("symlink fixture\n");
    for (const char **p = (const char *[]){ a, b, c, NULL }; *p; p++) {
        fd = open(*p, O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (fd < 0) FAIL("ls fixture\n");
        close(fd);
    }

    char *argv_echo[]    = { (char *)"busybox", (char *)"echo", (char *)"hello-wemu", NULL };
    char *argv_uname[]   = { (char *)"busybox", (char *)"uname", NULL };
    char *argv_cat[]     = { (char *)"busybox", (char *)"cat", catfile, NULL };
    char *argv_ls[]      = { (char *)"busybox", (char *)"ls", dir, NULL };
    char *argv_true[]    = { (char *)"busybox", (char *)"true", NULL };
    char *argv_false[]   = { (char *)"busybox", (char *)"false", NULL };
    char *argv_head[]    = { (char *)"busybox", (char *)"head", (char *)"-n", (char *)"2", catfile, NULL };
    char *argv_tail[]    = { (char *)"busybox", (char *)"tail", (char *)"-n", (char *)"2", catfile, NULL };
    char *argv_grep[]    = { (char *)"busybox", (char *)"grep", (char *)"alpha", catfile, NULL };
    char *argv_sort[]    = { (char *)"busybox", (char *)"sort", nums, NULL };
    char *argv_sed[]     = { (char *)"busybox", (char *)"sed", (char *)"s/alpha/OMEGA/", catfile, NULL };
    char *argv_seq[]     = { (char *)"busybox", (char *)"seq", (char *)"1", (char *)"5", NULL };
    char *argv_expr[]    = { (char *)"busybox", (char *)"expr", (char *)"2", (char *)"+", (char *)"3", NULL };
    char *argv_wc[]      = { (char *)"busybox", (char *)"wc", catfile, NULL };
    char *argv_cut[]     = { (char *)"busybox", (char *)"cut", (char *)"-d", (char *)",", (char *)"-f", (char *)"2", catfile, NULL };
    char *argv_awk[]     = { (char *)"busybox", (char *)"awk", (char *)"{print $1}", catfile, NULL };
    char *argv_md5[]     = { (char *)"busybox", (char *)"md5sum", catfile, NULL };
    char *argv_sha[]     = { (char *)"busybox", (char *)"sha256sum", catfile, NULL };
    char *argv_b64[]     = { (char *)"busybox", (char *)"base64", catfile, NULL };
    char *argv_pwd[]     = { (char *)"busybox", (char *)"pwd", NULL };
    char *argv_id[]      = { (char *)"busybox", (char *)"id", NULL };
    char *argv_test[]    = { (char *)"busybox", (char *)"test", (char *)"5", (char *)"-gt", (char *)"3", NULL };
    char *argv_test2[]   = { (char *)"busybox", (char *)"test", (char *)"3", (char *)"-gt", (char *)"5", NULL };
    char *argv_date[]    = { (char *)"busybox", (char *)"date", (char *)"-u", (char *)"-d", (char *)"@0", (char *)"+%Y-%m-%d %H:%M:%S", NULL };
    char *argv_host[]    = { (char *)"busybox", (char *)"hostname", NULL };
    char *argv_base[]    = { (char *)"busybox", (char *)"basename", (char *)"/x/y/z.txt", NULL };
    char *argv_dirn[]    = { (char *)"busybox", (char *)"dirname", (char *)"/x/y/z.txt", NULL };
    char *argv_rev[]     = { (char *)"busybox", (char *)"rev", catfile, NULL };
    char *argv_tac[]     = { (char *)"busybox", (char *)"tac", catfile, NULL };
    char *argv_uniq[]    = { (char *)"busybox", (char *)"uniq", nums, NULL };
    char *argv_stat[]    = { (char *)"busybox", (char *)"stat", (char *)"-c", (char *)"%s %n", catfile, NULL };
    char *argv_real[]    = { (char *)"busybox", (char *)"realpath", catfile, NULL };
    char *argv_rlink[]   = { (char *)"busybox", (char *)"readlink", lnk, NULL };
    char *argv_env[]     = { (char *)"busybox", (char *)"env", NULL };
    char *argv_which[]   = { (char *)"busybox", (char *)"which", (char *)"ls", NULL };
    char *argv_who[]     = { (char *)"busybox", (char *)"whoami", NULL };
    char *argv_nproc[]   = { (char *)"busybox", (char *)"nproc", NULL };
    char *argv_od[]      = { (char *)"busybox", (char *)"od", (char *)"-An", (char *)"-c", catfile, NULL };
    char *argv_xxd[]     = { (char *)"busybox", (char *)"xxd", catfile, NULL };
    char *argv_hex[]     = { (char *)"busybox", (char *)"hexdump", (char *)"-c", catfile, NULL };
    char *argv_nl[]      = { (char *)"busybox", (char *)"nl", catfile, NULL };
    char *argv_paste[]   = { (char *)"busybox", (char *)"paste", (char *)"-d", (char *)",", catfile, nums, NULL };
    char *argv_expand[]  = { (char *)"busybox", (char *)"expand", catfile, NULL };
    char *argv_fold[]    = { (char *)"busybox", (char *)"fold", (char *)"-w", (char *)"10", catfile, NULL };
    char *argv_sh[]      = { (char *)"busybox", (char *)"sh", (char *)"-c", (char *)"echo SH-BUILTIN-OK", NULL };

    check_applet("echo", argv_echo, 0);
    check_applet("uname", argv_uname, 0);
    check_applet("cat", argv_cat, 0);
    check_applet("ls", argv_ls, 0);
    check_applet("true", argv_true, 0);
    check_applet("false", argv_false, 1);
    check_applet("head", argv_head, 0);
    check_applet("tail", argv_tail, 0);
    check_applet("grep", argv_grep, 0);
    check_applet("sort", argv_sort, 0);
    check_applet("sed", argv_sed, 0);
    check_applet("seq", argv_seq, 0);
    check_applet("expr", argv_expr, 0);
    check_applet("wc", argv_wc, 0);
    check_applet("cut", argv_cut, 0);
    check_applet("awk", argv_awk, 0);
    check_applet("md5sum", argv_md5, 0);
    check_applet("sha256sum", argv_sha, 0);
    check_applet("base64", argv_b64, 0);
    check_applet("pwd", argv_pwd, 0);
    check_applet("id", argv_id, 0);
    check_applet("test-true", argv_test, 0);
    check_applet("test-false", argv_test2, 1);
    check_applet("date", argv_date, 0);
    check_applet("hostname", argv_host, 0);
    check_applet("basename", argv_base, 0);
    check_applet("dirname", argv_dirn, 0);
    check_applet("rev", argv_rev, 0);
    check_applet("tac", argv_tac, 0);
    check_applet("uniq", argv_uniq, 0);
    check_applet("stat", argv_stat, 0);
    check_applet("realpath", argv_real, 0);
    check_applet("readlink", argv_rlink, 0);
    check_applet("env", argv_env, 0);
    check_applet("which", argv_which, 0);
    check_applet("whoami", argv_who, 0);
    check_applet("nproc", argv_nproc, 0);
    check_applet("od", argv_od, 0);
    check_applet("xxd", argv_xxd, 0);
    check_applet("hexdump", argv_hex, 0);
    check_applet("nl", argv_nl, 0);
    check_applet("paste", argv_paste, 0);
    check_applet("expand", argv_expand, 0);
    check_applet("fold", argv_fold, 0);
    check_applet("sh", argv_sh, 0);

    unlink(catfile); unlink(nums); unlink(lnk); unlink(a); unlink(b); unlink(c); rmdir(dir);
    printf("ok: %d real static busybox applets byte-exact through native path\n",
           g_applets_checked);
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
    if (r.denied_nrs[0] != 309) FAIL("denied_nrs[0]=%u want 309\n", r.denied_nrs[0]);
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
    if (strcmp(old_buf, "hello-wemu\n") == 0)
        FAIL("old interpreter unexpectedly produced exact applet output\n");
    wemu_machine_destroy(m);
    printf("ok: OLD MODE control — interpreter produced %zu bytes "
           "(not exact applet output) in %lld insns; native path exact\n",
           old_ser_n, (long long)insns);
}

/* ---- 5/6. ET_DYN load bias + bounded guest signal delivery ----------- */
static void pie_elf_facts(const char *path, int *is_dyn, int *has_interp,
                          uint64_t *entry) {
    FILE *f = fopen(path, "rb");
    if (!f) FAIL("cannot open PIE fixture %s\n", path);
    Elf64_Ehdr eh;
    if (fread(&eh, sizeof eh, 1, f) != 1) FAIL("short ELF header: %s\n", path);
    *is_dyn = (eh.e_type == ET_DYN);
    *entry = eh.e_entry;
    *has_interp = 0;
    if (eh.e_phoff && eh.e_phnum) {
        if (fseek(f, (long)eh.e_phoff, SEEK_SET) != 0) FAIL("phoff: %s\n", path);
        for (uint16_t i = 0; i < eh.e_phnum; i++) {
            Elf64_Phdr ph;
            if (fread(&ph, sizeof ph, 1, f) != 1) FAIL("short phdr: %s\n", path);
            if (ph.p_type == PT_INTERP) *has_interp = 1;
        }
    }
    fclose(f);
}

static void check_pie(const char *path, const char *want, unsigned want_sig) {
    char *argv[] = { (char *)path, NULL };
    WemuUmResult r;
    int rc = wemu_um_run_elf(path, argv, GUEST_ENV, &r);
    if (rc != WEMU_UM_OK)
        FAIL("%s: native status=%s sigdel=%u sigden=%u out=[%s]\n", path,
             wemu_um_status_name(rc), r.signals_delivered, r.signals_denied, r.out);
    if (r.exit_code != 0) FAIL("%s: exit %d want 0\n", path, r.exit_code);
    size_t n = strlen(want);
    if (r.out_len != n || memcmp(r.out, want, n) != 0)
        FAIL("%s: native out=[%s] want=[%s]\n", path, r.out, want);
    if (r.signals_delivered != want_sig || r.signals_denied != 0 || r.denied != 0)
        FAIL("%s: sigdel=%u sigden=%u denied=%llu want %u/0/0\n", path,
             r.signals_delivered, r.signals_denied,
             (unsigned long long)r.denied, want_sig);
    Cap oracle;
    int he = host_exec(path, argv, &oracle);
    if (he != 0 || oracle.n != n || memcmp(oracle.b, want, n) != 0)
        FAIL("%s: host oracle differs (exit=%d out=[%s])\n", path, he, oracle.b);
    print_exact(path, r.out, r.out_len);
    printf("        (ET_DYN load bias, sigdel=%u; == host execve)\n",
           r.signals_delivered);
}

static void test_pie_and_signals(void) {
    int dyn = 0, interp = 0;
    uint64_t entry = 0;

    pie_elf_facts("tests/pie_hello", &dyn, &interp, &entry);
    if (!dyn || interp || entry > 0x100000)
        FAIL("pie_hello fixture is not a low-entered static ET_DYN PIE\n");
    check_pie("tests/pie_hello", "PIE-LOAD-BIAS-OK\n", 0);

    WemuMachine *m = wemu_machine_create(0x2000000, NULL, NULL);
    if (!m) FAIL("machine create\n");
    WemuCpu *cpu = wemu_machine_cpu(m);
    char *oldargv[] = { (char *)"pie_hello", NULL };
    if (wemu_cpu_load_elf(cpu, "tests/pie_hello", NULL, 0, oldargv) == 0)
        FAIL("old interpreter accepted an ET_DYN PIE\n");
    wemu_machine_destroy(m);
    printf("ok: OLD usermode interpreter rejects ET_DYN (load bias is native-only)\n");

    pie_elf_facts("tests/pie_signal", &dyn, &interp, &entry);
    if (!dyn || interp) FAIL("pie_signal fixture is not a static ET_DYN PIE\n");
    check_pie("tests/pie_signal", "PIE-SIGNAL-DELIVERED-OK\n", 1);
    printf("ok: bounded SIGSEGV -> guest handler -> SA_RESTORER sigreturn -> "
           "store retried, byte-exact vs host\n");

    WemuUmResult r;
    int rc = wemu_um_run_elf("tests/pie_nohandler",
                             (char *[]){ (char *)"pie_nohandler", NULL },
                             GUEST_ENV, &r);
    if (rc != WEMU_UM_ERR_FAULT || r.signals_delivered != 0 || r.signals_denied == 0)
        FAIL("nohandler: status=%s sigdel=%u sigden=%u want FAULT/0/>=1\n",
             wemu_um_status_name(rc), r.signals_delivered, r.signals_denied);
    printf("ok: FAIL-CLOSED no-handler fault -> %s (sigdel=0, sigden=%u)\n",
           wemu_um_status_name(rc), r.signals_denied);

    rc = wemu_um_run_elf("tests/pie_unlisted",
                         (char *[]){ (char *)"pie_unlisted", NULL },
                         GUEST_ENV, &r);
    if (rc != WEMU_UM_OK || strstr(r.out, "RC=0") != NULL || r.signals_denied == 0)
        FAIL("unlisted: status=%s out=[%s] sigden=%u\n",
             wemu_um_status_name(rc), r.out, r.signals_denied);
    if (wemu_um_signal_modeled(SIGSEGV) != 1 ||
        wemu_um_signal_modeled(SIGUSR1) != 0)
        FAIL("signal whitelist wrong (SIGSEGV=%d SIGUSR1=%d)\n",
             wemu_um_signal_modeled(SIGSEGV), wemu_um_signal_modeled(SIGUSR1));
    printf("ok: FAIL-CLOSED unmodeled SIGUSR1 registration refused (%s), "
           "sigden=%u; whitelist SIGSEGV=yes SIGUSR1=no\n",
           strstr(r.out, "RC=-1") ? "rc=-1" : r.out, r.signals_denied);

    pie_elf_facts("tests/pie_dynamic", &dyn, &interp, &entry);
    if (!dyn || !interp) FAIL("pie_dynamic fixture is not ET_DYN+PT_INTERP\n");
    rc = wemu_um_run_elf("tests/pie_dynamic",
                         (char *[]){ (char *)"pie_dynamic", NULL },
                         GUEST_ENV, &r);
    if (rc != WEMU_UM_ERR_INTERP)
        FAIL("dynamic PIE: status=%s want ERR_INTERP\n", wemu_um_status_name(rc));
    printf("ok: FAIL-CLOSED dynamically linked PIE (ET_DYN+PT_INTERP) -> %s\n",
           wemu_um_status_name(rc));
}

/* ---- 7. bounded fork/clone ------------------------------------------- */
#define CLONE_FS_       0x00000200u
#define CLONE_SIGHAND_  0x00000800u
#define CLONE_VM_       0x00000100u
#define CLONE_THREAD_   0x00010000u
#define CLONE_NEWUSER_  0x10000000u
#define CLONE_CHILD_CLEARTID_ 0x00200000u
#define CLONE_CHILD_SETTID_   0x01000000u

static void test_clone_policy(void) {
    if (!wemu_um_clone_flags_modeled(SIGCHLD) ||
        !wemu_um_clone_flags_modeled(0) ||
        !wemu_um_clone_flags_modeled(SIGCHLD | CLONE_CHILD_SETTID_ |
                                    CLONE_CHILD_CLEARTID_))
        FAIL("fork-shaped clone flags must be modeled\n");
    if (wemu_um_clone_flags_modeled(CLONE_VM_ | SIGCHLD) ||
        wemu_um_clone_flags_modeled(CLONE_THREAD_ | CLONE_SIGHAND_ | CLONE_VM_ |
                                    SIGCHLD) ||
        wemu_um_clone_flags_modeled(CLONE_NEWUSER_ | CLONE_FS_ | SIGCHLD))
        FAIL("CLONE_VM/THREAD/NEWUSER must be refused\n");
    printf("ok: FAIL-CLOSED clone flag policy — "
           "fork+TID bits allowed; VM/THREAD/NEWUSER refused\n");
}

static void test_fork_clone(void) {
    const char *out =
        "FORK-CHILD-OK\nFORK-PARENT-OK\n"
        "CLONE-CHILD-OK\nCLONE-PARENT-OK\n"
        "CLONE-FLAGS-RC=-22\nCLONE3-FLAGS-RC=-22\n";

    Cap oracle;
    char *argv[] = { (char *)"fork_clone", NULL };
    int he = host_exec("tests/fork_clone", argv, &oracle);
    if (he != 0 || oracle.n != strlen(out) || memcmp(oracle.b, out, oracle.n) != 0)
        FAIL("fork_clone host oracle differs (exit=%d out=[%s])\n", he, oracle.b);

    WemuUmResult r;
    int rc = wemu_um_run_elf("tests/fork_clone", argv, GUEST_ENV, &r);
    if (rc != WEMU_UM_OK)
        FAIL("fork_clone status=%s out=[%s]\n", wemu_um_status_name(rc), r.out);
    if (r.exit_code != 0) FAIL("fork_clone exit=%d want 0\n", r.exit_code);
    if (r.out_len != strlen(out) || memcmp(r.out, out, r.out_len) != 0)
        FAIL("fork_clone native out=[%s] want=[%s]\n", r.out, out);
    if (r.forks != 2)
        FAIL("fork_clone forks=%u want 2 (fork + clone)\n", r.forks);
    if (r.denied != 2 || r.denied_nrs[0] != 56 || r.denied_nrs[1] != 435)
        FAIL("fork_clone denied=%llu nrs=[%u,%u] want 2/[56,435]\n",
             (unsigned long long)r.denied, r.denied_nrs[0], r.denied_nrs[1]);
    print_exact("fork_clone", r.out, r.out_len);
    printf("        (forks=%u, denied=%llu, syscalls=%llu; == host execve)\n",
           r.forks, (unsigned long long)r.denied,
           (unsigned long long)r.syscalls);
    printf("ok: BOUNDED fork+clone — private COW guests, wait4 status, "
           "fail-closed clone/clone3 flags\n");
}

int main(void) {
    audit_header("/usr/include/x86_64-linux-gnu/asm/unistd_64.h");
    test_applets();
    test_fail_closed();
    test_old_mode_control();
    test_pie_and_signals();
    test_clone_policy();
    test_fork_clone();
    printf("WEMU NATIVE USERMODE GATE PASS (%d static busybox applets, "
           "ET_DYN load bias, bounded signals, bounded fork/clone, fail-closed)\n",
           g_applets_checked);
    return 0;
}
