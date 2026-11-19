/* wemu_elf.c — user-mode ELF execution: parse a static ET_EXEC x86-64
 * ELF, map PT_LOAD segments into guest RAM at their p_vaddr, zero .bss,
 * and build the minimal SysV initial stack (argc/argv/envp/auxv) at RAM
 * top. One concern: the ELF -> guest-address-space image. The decoder
 * and exec loop stay the one owner of instruction semantics; the syscall
 * hook stays the one owner of guest->kernel dispatch.
 *
 * This is the FEX-Emu/box64/qemu-user fast path, our own: translate the
 * CPU, pass syscalls to the kernel personality, nothing else. Paging is
 * OFF (cr0=0x11): flat identity memory IS user mode.
 * License: WaefreBeorn Umbrella License v3.0. */
#include "wemu_internal.h"
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

/* auxv entries we emit (AT_* from the SysV ABI / Linux) */
#define AT_NULL_    0
#define AT_PHDR_    3
#define AT_PHENT_   4
#define AT_PHNUM_   5
#define AT_PAGESZ_  6
#define AT_BASE_    7
#define AT_FLAGS_   8
#define AT_ENTRY_   9
#define AT_RANDOM_  25
#define AT_CLKTCK_  17
#define AT_SECURE_  23

static uint8_t *read_file(const char *path, size_t *out_len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    off_t end = lseek(fd, 0, SEEK_END);
    if (end <= 0 || lseek(fd, 0, SEEK_SET) < 0) { close(fd); return NULL; }
    size_t len = (size_t)end;
    uint8_t *buf = malloc(len);
    if (!buf) { close(fd); return NULL; }
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) { free(buf); close(fd); return NULL; }
        got += (size_t)n;
    }
    close(fd);
    *out_len = len;
    return buf;
}

int wemu_cpu_load_elf(WemuCpu *cpu, const char *path,
                      const uint8_t *bytes, size_t len,
                      char *const argv[]) {
    if (!cpu) return -1;
    uint8_t *owned = NULL;
    if (path) {
        owned = read_file(path, &len);
        if (!owned) return -1;
        bytes = owned;
    }
    if (!bytes || len < sizeof(Elf64_Ehdr)) { free(owned); return -1; }

    Elf64_Ehdr eh;
    memcpy(&eh, bytes, sizeof eh);
    if (eh.e_ident[EI_MAG0] != ELFMAG0 || eh.e_ident[EI_MAG1] != ELFMAG1 ||
        eh.e_ident[EI_MAG2] != ELFMAG2 || eh.e_ident[EI_MAG3] != ELFMAG3 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_ident[EI_DATA] != ELFDATA2LSB ||
        eh.e_ident[EI_VERSION] != EV_CURRENT ||
        eh.e_type != ET_EXEC || eh.e_machine != EM_X86_64 ||
        eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phnum == 0 ||
        (uint64_t)eh.e_phoff + (uint64_t)eh.e_phnum * eh.e_phentsize > len) {
        free(owned);
        return -1;
    }

    /* validate + map PT_LOAD; reject dynamic (PT_INTERP) images */
    uint64_t image_end = 0, phdr_va = 0;
    for (int i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr ph;
        memcpy(&ph, bytes + eh.e_phoff + (uint64_t)i * eh.e_phentsize, sizeof ph);
        if (ph.p_type == PT_INTERP) { free(owned); return -1; }
        if (ph.p_type != PT_LOAD) continue;
        if (ph.p_memsz < ph.p_filesz ||
            ph.p_vaddr + ph.p_memsz > cpu->ram_size ||
            ph.p_offset + ph.p_filesz > len) { free(owned); return -1; }
        if (ph.p_filesz &&
            wemu_gpa_write(cpu, ph.p_vaddr, bytes + ph.p_offset,
                           (size_t)ph.p_filesz) != 0) { free(owned); return -1; }
        if (ph.p_memsz > ph.p_filesz) { /* .bss: zero the tail */
            uint64_t bss = ph.p_vaddr + ph.p_filesz;
            uint64_t n = ph.p_memsz - ph.p_filesz;
            uint8_t zero[4096];
            memset(zero, 0, sizeof zero);
            while (n) {
                uint64_t chunk = n > sizeof zero ? sizeof zero : n;
                if (wemu_gpa_write(cpu, bss, zero, (size_t)chunk) != 0) {
                    free(owned);
                    return -1;
                }
                bss += chunk; n -= chunk;
            }
        }
        if (ph.p_vaddr + ph.p_memsz > image_end)
            image_end = ph.p_vaddr + ph.p_memsz;
        /* program headers live inside a LOAD segment on normal statics */
        if (!phdr_va && ph.p_offset <= eh.e_phoff &&
            eh.e_phoff + (uint64_t)eh.e_phnum * eh.e_phentsize <=
                ph.p_offset + ph.p_filesz)
            phdr_va = ph.p_vaddr + (eh.e_phoff - ph.p_offset);
    }
    if (!image_end || eh.e_entry >= cpu->ram_size) { free(owned); return -1; }
    cpu->elf_brk = (image_end + 0xfff) & ~0xfffull;

    /* ---- initial SysV stack at RAM top ----------------------------
     * low -> high: argc | argv ptrs | NULL | envp NULL | auxv pairs |
     *              padding | argv strings | 16 AT_RANDOM bytes | top */
    int argc = 0;
    size_t strsz = 0;
    if (argv) while (argv[argc]) { strsz += strlen(argv[argc]) + 1; argc++; }

    enum { N_AUXV = 9 };
    uint64_t auxv[N_AUXV][2];
    size_t auxsz = N_AUXV * 16;
    size_t vecsz = 8 + (size_t)(argc + 1) * 8 + 8 + auxsz; /* argc..auxv */
    size_t total = vecsz + strsz + 16 + 16;                /* +pad+random */
    if (total > cpu->ram_size - image_end) { free(owned); return -1; }
    uint64_t base = (cpu->ram_size - total) & ~0xfull;
    uint64_t top = cpu->ram_size;

    uint8_t *stack = calloc(1, (size_t)(top - base));
    if (!stack) { free(owned); return -1; }
    uint64_t off = 0;
    uint64_t strp = top - strsz;          /* strings live at the very top */
    uint64_t randp = strp - 16;           /* AT_RANDOM block below them  */

    /* argc */
    uint64_t v = (uint64_t)argc;
    memcpy(stack + off, &v, 8); off += 8;
    /* argv pointers, NULL */
    uint64_t sp = strp;
    for (int i = 0; i < argc; i++) {
        memcpy(stack + off, &sp, 8); off += 8;
        size_t n = strlen(argv[i]) + 1;
        memcpy(stack + (sp - base), argv[i], n);
        sp += n;
    }
    v = 0;
    memcpy(stack + off, &v, 8); off += 8;   /* argv NULL */
    memcpy(stack + off, &v, 8); off += 8;   /* envp NULL (empty env) */

    auxv[0][0] = AT_PHDR_;   auxv[0][1] = phdr_va;
    auxv[1][0] = AT_PHENT_;  auxv[1][1] = sizeof(Elf64_Phdr);
    auxv[2][0] = AT_PHNUM_;  auxv[2][1] = eh.e_phnum;
    auxv[3][0] = AT_PAGESZ_; auxv[3][1] = 4096;
    auxv[4][0] = AT_BASE_;   auxv[4][1] = 0; /* no interpreter */
    auxv[5][0] = AT_ENTRY_;  auxv[5][1] = eh.e_entry;
    auxv[6][0] = AT_CLKTCK_; auxv[6][1] = 100;
    auxv[7][0] = AT_SECURE_; auxv[7][1] = 0;
    auxv[8][0] = AT_RANDOM_; auxv[8][1] = randp;
    for (int i = 0; i < N_AUXV; i++) {
        memcpy(stack + off, auxv[i], 16); off += 16;
    }
    v = 0;                                  /* AT_NULL terminator */
    memcpy(stack + off, &v, 8); off += 8;
    memcpy(stack + off, &v, 8); off += 8;
    /* AT_RANDOM: 16 unpredictable-ish bytes (deterministic mix: the
     * sandbox has no host entropy source it should depend on) */
    uint64_t seed = eh.e_entry ^ (cpu->ram_size * 0x9E3779B97F4A7C15ull);
    for (int i = 0; i < 16; i++) {
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        stack[randp - base + (size_t)i] = (uint8_t)seed;
    }
    if (wemu_gpa_write(cpu, base, stack, (size_t)(top - base)) != 0) {
        free(stack); free(owned);
        return -1;
    }
    free(stack);
    free(owned);

    /* entry state: SysV wants rsp 16-aligned, rdx=rtld_fini=0 */
    memset(cpu->r, 0, sizeof cpu->r);
    cpu->r[4] = base;
    cpu->rip = eh.e_entry;
    cpu->rflags = 2;
    cpu->halted = 0;
    cpu->fault = 0;
    return 0;
}

uint64_t wemu_cpu_elf_brk(const WemuCpu *cpu) {
    return cpu ? cpu->elf_brk : 0;
}