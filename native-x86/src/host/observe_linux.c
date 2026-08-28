/*
 * Linux observation engine for the nativex86 host.
 *
 * Two passes, both user-mode and same-user only:
 *
 *   Read-only pass (no ptrace): parse /proc/PID/maps for file-backed
 *   modules and read each module's ELF symbol table from disk. Reports
 *   module-load and (for watched exports) symbol records. Reads nothing
 *   from the target's memory.
 *
 *   Live pass (ptrace, x86-64): for watched exports flagged for
 *   call-site observation, insert a one-byte software breakpoint (INT3)
 *   at the export's entry — the same mechanism a debugger uses — catch
 *   the entry, read the *return address* off the stack (a code address,
 *   nothing else), report a call-site ENTER, arm a one-shot breakpoint at
 *   that return address to report a call-site RETURN, then restore the
 *   original byte and let execution continue unchanged.
 *
 * The only target memory this file ever reads is instruction words (to
 * place/restore breakpoints) and the return address at the top of the
 * stack. It never reads argument registers, buffers, return values or
 * keys, and it never modifies program logic: a breakpoint is inserted,
 * observed, and removed, leaving the executed code byte-for-byte as it
 * was. There is no vocabulary here for TLS, Java or JNI: watched names
 * are opaque strings.
 */
#if defined(__linux__)

#define _GNU_SOURCE

#include "observe.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__x86_64__)
#  include <sys/user.h>
#  define NX86_LIVE_OK 1
#else
#  define NX86_LIVE_OK 0
#endif

#define NX86_MAX_MODULES     256
#define NX86_MAX_BREAKPOINTS 128
#define NX86_MAX_RETURNS     128
#define NX86_PATH_MAX        512

/* ------------------------------------------------------------------ */
/* Event emission                                                      */
/* ------------------------------------------------------------------ */

static nx86_str str_c(const char *s)
{
    nx86_str out;
    out.data = s;
    out.len = (uint32_t)(s != NULL ? strlen(s) : 0u);
    out.reserved = 0u;
    return out;
}

static void stamp(nx86_event_bus *bus, nx86_event_header *h, uint32_t size,
                  nx86_event_kind kind, uint32_t pid, uint32_t tid)
{
    nx86_bus_stamp(bus, h, size, kind);
    /* process_id names the observed process — exactly what it is for. */
    h->process_id = pid;
    h->thread_id = tid;
}

static void emit_note(nx86_event_bus *bus, uint32_t pid, uint32_t level,
                      const char *text)
{
    nx86_event_note note;
    memset(&note, 0, sizeof(note));
    stamp(bus, &note.header, (uint32_t)sizeof(note), NX86_EVENT_NOTE, pid, 0u);
    note.level = level;
    note.source = str_c("observe.linux");
    note.text = str_c(text);
    (void)nx86_bus_publish(bus, &note.header);
}

static void emit_module_load(nx86_event_bus *bus, uint32_t pid,
                             const char *path, const char *name,
                             uint64_t base, uint64_t size, uint32_t machine)
{
    nx86_event_module_load m;
    memset(&m, 0, sizeof(m));
    stamp(bus, &m.header, (uint32_t)sizeof(m), NX86_EVENT_MODULE_LOAD, pid, 0u);
    m.path = str_c(path);
    m.name = str_c(name);
    m.base_address = base;
    m.image_size = size;
    m.machine = machine;
    (void)nx86_bus_publish(bus, &m.header);
}

static void emit_symbol(nx86_event_bus *bus, uint32_t pid,
                        const char *module, const char *symbol,
                        uint64_t module_base, uint64_t address,
                        uint32_t binding)
{
    nx86_event_symbol s;
    memset(&s, 0, sizeof(s));
    stamp(bus, &s.header, (uint32_t)sizeof(s), NX86_EVENT_SYMBOL, pid, 0u);
    s.module_name = str_c(module);
    s.symbol_name = str_c(symbol);
    s.module_base = module_base;
    s.address = address;
    s.binding = binding;
    (void)nx86_bus_publish(bus, &s.header);
}

static void emit_call_site(nx86_event_bus *bus, uint32_t pid, uint32_t tid,
                           const char *module, const char *target,
                           uint64_t site, uint64_t target_addr,
                           uint64_t module_base, uint32_t site_kind,
                           uint32_t phase)
{
    nx86_event_call_site c;
    memset(&c, 0, sizeof(c));
    stamp(bus, &c.header, (uint32_t)sizeof(c), NX86_EVENT_CALL_SITE, pid, tid);
    c.module_name = str_c(module);
    c.target_name = str_c(target);
    c.site_address = site;
    c.target_address = target_addr;
    c.module_base = module_base;
    c.site_kind = site_kind;
    c.phase = phase;
    (void)nx86_bus_publish(bus, &c.header);
}

/* ------------------------------------------------------------------ */
/* Watch matching                                                      */
/* ------------------------------------------------------------------ */

static uint32_t match_flags(const char *sym, const nx86_watch_entry *watches,
                            uint32_t n)
{
    uint32_t flags = 0u;
    uint32_t i;
    for (i = 0; i < n; ++i) {
        const nx86_watch_entry *w = &watches[i];
        int hit = 0;
        if (w->match_kind == NX86_MATCH_EXACT) {
            hit = (strcmp(sym, w->name) == 0);
        } else if (w->match_kind == NX86_MATCH_PREFIX) {
            hit = (strncmp(sym, w->name, strlen(w->name)) == 0);
        }
        if (hit) {
            flags |= w->flags;
        }
    }
    return flags;
}

/* ------------------------------------------------------------------ */
/* Module table (from /proc/PID/maps)                                  */
/* ------------------------------------------------------------------ */

typedef struct module_row {
    char     path[NX86_PATH_MAX];
    uint64_t base;      /* lowest mapped address of this file */
    uint64_t end;       /* highest mapped end of this file */
    int      has_exec;  /* at least one x mapping */
} module_row;

static int module_index(module_row *mods, int n, const char *path)
{
    int i;
    for (i = 0; i < n; ++i) {
        if (strcmp(mods[i].path, path) == 0) {
            return i;
        }
    }
    return -1;
}

static int read_maps(uint32_t pid, module_row *mods, int cap)
{
    char maps_path[64];
    FILE *fp;
    char line[4096];
    int n = 0;

    (void)snprintf(maps_path, sizeof(maps_path), "/proc/%u/maps",
                   (unsigned)pid);
    fp = fopen(maps_path, "r");
    if (fp == NULL) {
        return -1;
    }

    while (fgets(line, (int)sizeof(line), fp) != NULL) {
        unsigned long long start = 0, end = 0;
        char perms[8];
        char path[NX86_PATH_MAX];
        int idx;
        /* address perms offset dev inode pathname */
        if (sscanf(line, "%llx-%llx %7s %*x %*x:%*x %*u %511[^\n]",
                   &start, &end, perms, path) < 4) {
            continue;
        }
        /* Trim leading spaces the %[^\n] field kept. */
        {
            char *p = path;
            while (*p == ' ') {
                ++p;
            }
            if (p != path) {
                memmove(path, p, strlen(p) + 1u);
            }
        }
        /* File-backed only: a real path, not [heap]/[stack]/[vdso]/anon. */
        if (path[0] != '/') {
            continue;
        }
        idx = module_index(mods, n, path);
        if (idx < 0) {
            if (n >= cap) {
                continue;
            }
            idx = n++;
            memset(&mods[idx], 0, sizeof(mods[idx]));
            (void)snprintf(mods[idx].path, sizeof(mods[idx].path), "%s", path);
            mods[idx].base = (uint64_t)start;
            mods[idx].end = (uint64_t)end;
        }
        if ((uint64_t)start < mods[idx].base) {
            mods[idx].base = (uint64_t)start;
        }
        if ((uint64_t)end > mods[idx].end) {
            mods[idx].end = (uint64_t)end;
        }
        if (strchr(perms, 'x') != NULL) {
            mods[idx].has_exec = 1;
        }
    }
    fclose(fp);
    return n;
}

static const char *base_name(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash != NULL ? slash + 1 : path;
}

static uint32_t elf_machine(uint16_t e_machine)
{
    switch (e_machine) {
    case EM_386:    return NX86_MACHINE_X86_32;
    case EM_X86_64: return NX86_MACHINE_X86_64;
    default:        return NX86_MACHINE_UNKNOWN;
    }
}

/* ------------------------------------------------------------------ */
/* ELF symbol scan (both classes via a small generic template)         */
/* ------------------------------------------------------------------ */

typedef struct symbol_hit {
    const char *name;
    uint64_t    address;
    uint32_t    binding; /* NX86_SYMBOL_* */
} symbol_hit;

typedef void (*sym_visitor)(void *ctx, const symbol_hit *hit);

#define DEFINE_SYM_SCAN(BITS)                                                  \
static void scan_syms_##BITS(const unsigned char *map, size_t sz,              \
                             uint64_t module_base, sym_visitor visit,          \
                             void *ctx)                                        \
{                                                                              \
    const Elf##BITS##_Ehdr *eh = (const Elf##BITS##_Ehdr *)map;                \
    const Elf##BITS##_Shdr *sh;                                                \
    const Elf##BITS##_Phdr *ph;                                                \
    uint64_t min_pvaddr = ~(uint64_t)0;                                        \
    uint64_t bias;                                                             \
    unsigned i, s;                                                             \
    if (sz < sizeof(*eh) || eh->e_shoff == 0 || eh->e_shnum == 0) {            \
        return;                                                                \
    }                                                                          \
    if ((size_t)eh->e_phoff + (size_t)eh->e_phnum * eh->e_phentsize <= sz) {   \
        for (i = 0; i < eh->e_phnum; ++i) {                                    \
            ph = (const Elf##BITS##_Phdr *)(map + eh->e_phoff +                \
                                            (size_t)i * eh->e_phentsize);      \
            if (ph->p_type == PT_LOAD && (uint64_t)ph->p_vaddr < min_pvaddr) { \
                min_pvaddr = (uint64_t)ph->p_vaddr;                            \
            }                                                                  \
        }                                                                      \
    }                                                                          \
    if (min_pvaddr == ~(uint64_t)0) {                                          \
        min_pvaddr = 0;                                                        \
    }                                                                          \
    bias = (eh->e_type == ET_DYN) ? (module_base - min_pvaddr) : 0u;           \
    if ((size_t)eh->e_shoff + (size_t)eh->e_shnum * eh->e_shentsize > sz) {    \
        return;                                                                \
    }                                                                          \
    for (s = 0; s < eh->e_shnum; ++s) {                                        \
        const Elf##BITS##_Sym *syms;                                           \
        const char *strs;                                                      \
        const Elf##BITS##_Shdr *strsh;                                         \
        size_t count, k, strsz;                                                \
        uint32_t binding;                                                      \
        sh = (const Elf##BITS##_Shdr *)(map + eh->e_shoff +                    \
                                        (size_t)s * eh->e_shentsize);          \
        if (sh->sh_type != SHT_DYNSYM && sh->sh_type != SHT_SYMTAB) {          \
            continue;                                                          \
        }                                                                      \
        if (sh->sh_entsize == 0 || sh->sh_link >= eh->e_shnum) {               \
            continue;                                                          \
        }                                                                      \
        if ((size_t)sh->sh_offset + (size_t)sh->sh_size > sz) {                \
            continue;                                                          \
        }                                                                      \
        strsh = (const Elf##BITS##_Shdr *)(map + eh->e_shoff +                 \
                    (size_t)sh->sh_link * eh->e_shentsize);                    \
        if ((size_t)strsh->sh_offset + (size_t)strsh->sh_size > sz) {          \
            continue;                                                          \
        }                                                                      \
        syms = (const Elf##BITS##_Sym *)(map + sh->sh_offset);                 \
        strs = (const char *)(map + strsh->sh_offset);                         \
        strsz = (size_t)strsh->sh_size;                                        \
        count = (size_t)sh->sh_size / (size_t)sh->sh_entsize;                  \
        binding = (sh->sh_type == SHT_DYNSYM) ? NX86_SYMBOL_EXPORT             \
                                              : NX86_SYMBOL_DEBUG;             \
        for (k = 0; k < count; ++k) {                                          \
            const Elf##BITS##_Sym *sym = &syms[k];                             \
            symbol_hit hit;                                                    \
            if (ELF##BITS##_ST_TYPE(sym->st_info) != STT_FUNC &&               \
                ELF##BITS##_ST_TYPE(sym->st_info) != STT_GNU_IFUNC) {          \
                continue;                                                      \
            }                                                                  \
            if (sym->st_shndx == SHN_UNDEF || sym->st_value == 0) {            \
                continue;                                                      \
            }                                                                  \
            if (sym->st_name == 0 || (size_t)sym->st_name >= strsz) {          \
                continue;                                                      \
            }                                                                  \
            hit.name = strs + sym->st_name;                                    \
            hit.address = (uint64_t)sym->st_value + bias;                      \
            hit.binding = binding;                                             \
            visit(ctx, &hit);                                                  \
        }                                                                      \
    }                                                                          \
}

DEFINE_SYM_SCAN(64)
DEFINE_SYM_SCAN(32)

/* ------------------------------------------------------------------ */
/* Scan one module: emit symbols and collect breakpoints               */
/* ------------------------------------------------------------------ */

typedef struct breakpoint {
    uint64_t address;
    uint64_t module_base;
    char     name[NX86_WATCH_NAME_MAX];
    char     module[NX86_PATH_MAX];
    unsigned char saved;
    int      armed;
} breakpoint;

typedef struct scan_ctx {
    nx86_event_bus          *bus;
    uint32_t                 pid;
    const char              *module_name;
    uint64_t                 module_base;
    const nx86_watch_entry  *watches;
    uint32_t                 n_watches;
    breakpoint              *bps;
    int                     *n_bps;
    int                      bp_cap;
    /* de-dup of already-emitted (addr) within this module */
    uint64_t                 seen[512];
    int                      n_seen;
} scan_ctx;

static int already_seen(scan_ctx *c, uint64_t addr)
{
    int i;
    for (i = 0; i < c->n_seen; ++i) {
        if (c->seen[i] == addr) {
            return 1;
        }
    }
    if (c->n_seen < (int)(sizeof(c->seen) / sizeof(c->seen[0]))) {
        c->seen[c->n_seen++] = addr;
    }
    return 0;
}

static void on_symbol(void *ctx, const symbol_hit *hit)
{
    scan_ctx *c = (scan_ctx *)ctx;
    uint32_t flags = match_flags(hit->name, c->watches, c->n_watches);
    if (flags == 0u) {
        return;
    }
    if (already_seen(c, hit->address)) {
        return;
    }
    if ((flags & NX86_WATCH_SYMBOL) != 0u) {
        emit_symbol(c->bus, c->pid, c->module_name, hit->name,
                    c->module_base, hit->address, hit->binding);
    }
    if ((flags & NX86_WATCH_CALL_SITE) != 0u && c->bps != NULL &&
        *c->n_bps < c->bp_cap) {
        breakpoint *bp = &c->bps[(*c->n_bps)++];
        memset(bp, 0, sizeof(*bp));
        bp->address = hit->address;
        bp->module_base = c->module_base;
        (void)snprintf(bp->name, sizeof(bp->name), "%s", hit->name);
        (void)snprintf(bp->module, sizeof(bp->module), "%s", c->module_name);
    }
}

static void scan_module(nx86_event_bus *bus, uint32_t pid,
                        const module_row *mod,
                        const nx86_watch_entry *watches, uint32_t n_watches,
                        breakpoint *bps, int *n_bps, int bp_cap)
{
    int fd;
    struct stat st;
    unsigned char *map;
    scan_ctx c;

    fd = open(mod->path, O_RDONLY);
    if (fd < 0) {
        return;
    }
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
        close(fd);
        return;
    }
    map = (unsigned char *)mmap(NULL, (size_t)st.st_size, PROT_READ,
                                MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) {
        return;
    }
    if (memcmp(map, ELFMAG, SELFMAG) != 0) {
        munmap(map, (size_t)st.st_size);
        return;
    }

    memset(&c, 0, sizeof(c));
    c.bus = bus;
    c.pid = pid;
    c.module_name = base_name(mod->path);
    c.module_base = mod->base;
    c.watches = watches;
    c.n_watches = n_watches;
    c.bps = bps;
    c.n_bps = n_bps;
    c.bp_cap = bp_cap;

    if (map[EI_CLASS] == ELFCLASS64) {
        scan_syms_64(map, (size_t)st.st_size, mod->base, on_symbol, &c);
    } else if (map[EI_CLASS] == ELFCLASS32) {
        scan_syms_32(map, (size_t)st.st_size, mod->base, on_symbol, &c);
    }
    munmap(map, (size_t)st.st_size);
}

static int scan_all_modules(nx86_event_bus *bus, uint32_t pid,
                           const nx86_watch_entry *watches, uint32_t n_watches,
                           breakpoint *bps, int *n_bps, int bp_cap,
                           void (*log_fn)(uint32_t, const char *))
{
    module_row *mods = (module_row *)calloc(NX86_MAX_MODULES, sizeof(*mods));
    int n, i;

    if (mods == NULL) {
        return -1;
    }
    n = read_maps(pid, mods, NX86_MAX_MODULES);
    if (n < 0) {
        free(mods);
        if (log_fn != NULL) {
            log_fn(NX86_LOG_ERROR, "cannot read /proc/<pid>/maps");
        }
        return -1;
    }
    for (i = 0; i < n; ++i) {
        uint32_t machine;
        int fd;
        Elf64_Ehdr eh;
        if (!mods[i].has_exec) {
            continue; /* data-only file mapping: no code to observe */
        }
        machine = NX86_MACHINE_UNKNOWN;
        fd = open(mods[i].path, O_RDONLY);
        if (fd >= 0) {
            if (read(fd, &eh, sizeof(eh)) == (ssize_t)sizeof(eh) &&
                memcmp(eh.e_ident, ELFMAG, SELFMAG) == 0) {
                machine = elf_machine(eh.e_machine);
            }
            close(fd);
        }
        emit_module_load(bus, pid, mods[i].path, base_name(mods[i].path),
                         mods[i].base, mods[i].end - mods[i].base, machine);
        scan_module(bus, pid, &mods[i], watches, n_watches, bps, n_bps,
                    bp_cap);
    }
    free(mods);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Public: ownership + capability                                      */
/* ------------------------------------------------------------------ */

int nx86_observe_owner_check(uint32_t pid, uint32_t *out_uid)
{
    char path[64];
    struct stat st;
    (void)snprintf(path, sizeof(path), "/proc/%u", (unsigned)pid);
    if (stat(path, &st) != 0) {
        return -1;
    }
    if (out_uid != NULL) {
        *out_uid = (uint32_t)st.st_uid;
    }
    return (st.st_uid == geteuid()) ? 1 : 0;
}

int nx86_observe_live_supported(void)
{
    return NX86_LIVE_OK;
}

const char *nx86_observe_backend_name(void)
{
#if NX86_LIVE_OK
    return "linux ptrace (x86-64): /proc maps + ELF symbols + INT3 entry/return";
#else
    return "linux read-only: /proc maps + ELF symbols (live path is x86-64 only)";
#endif
}

/* ------------------------------------------------------------------ */
/* Live pass (ptrace)                                                  */
/* ------------------------------------------------------------------ */

#if NX86_LIVE_OK

typedef struct return_bp {
    uint64_t      address;
    uint64_t      target_addr;
    uint64_t      module_base;
    char          name[NX86_WATCH_NAME_MAX];
    char          module[NX86_PATH_MAX];
    unsigned char saved;
    int           active;
} return_bp;

static volatile sig_atomic_t g_alarm_fired;

static void on_alarm(int sig)
{
    (void)sig;
    g_alarm_fired = 1;
}

static long peek_word(pid_t pid, unsigned long addr)
{
    errno = 0;
    return ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, (void *)0);
}

static int poke_word(pid_t pid, unsigned long addr, long value)
{
    return (int)ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)value);
}

/* Insert INT3, saving the original low byte into *saved. */
static int bp_insert(pid_t pid, unsigned long addr, unsigned char *saved)
{
    long orig = peek_word(pid, addr);
    long patched;
    if (errno != 0) {
        return -1;
    }
    *saved = (unsigned char)(orig & 0xffL);
    patched = (orig & ~0xffL) | 0xccL;
    return poke_word(pid, addr, patched);
}

/* Restore the saved original byte. */
static int bp_restore(pid_t pid, unsigned long addr, unsigned char saved)
{
    long orig = peek_word(pid, addr);
    long restored;
    if (errno != 0) {
        return -1;
    }
    restored = (orig & ~0xffL) | (long)saved;
    return poke_word(pid, addr, restored);
}

/* Restore the original byte, step over it, re-arm the breakpoint.
 * Returns 1 if the target exited during the step. */
static int bp_step_over(pid_t pid, unsigned long addr, unsigned char saved)
{
    int st;
    unsigned char tmp;
    if (bp_restore(pid, addr, saved) != 0) {
        return -1;
    }
    if (ptrace(PTRACE_SINGLESTEP, pid, (void *)0, (void *)0) != 0) {
        return -1;
    }
    if (waitpid(pid, &st, 0) < 0) {
        return -1;
    }
    if (WIFEXITED(st) || WIFSIGNALED(st)) {
        return 1;
    }
    return bp_insert(pid, addr, &tmp);
}

/* Restore the original byte and step over it without re-arming (one-shot).
 * Returns 1 if the target exited during the step. */
static int bp_step_off(pid_t pid, unsigned long addr, unsigned char saved)
{
    int st;
    if (bp_restore(pid, addr, saved) != 0) {
        return -1;
    }
    if (ptrace(PTRACE_SINGLESTEP, pid, (void *)0, (void *)0) != 0) {
        return -1;
    }
    if (waitpid(pid, &st, 0) < 0) {
        return -1;
    }
    if (WIFEXITED(st) || WIFSIGNALED(st)) {
        return 1;
    }
    return 0;
}

static int find_entry_bp(const breakpoint *bps, int n, uint64_t addr)
{
    int i;
    for (i = 0; i < n; ++i) {
        if (bps[i].armed && bps[i].address == addr) {
            return i;
        }
    }
    return -1;
}

static int find_return_bp(const return_bp *rbs, int n, uint64_t addr)
{
    int i;
    for (i = 0; i < n; ++i) {
        if (rbs[i].active && rbs[i].address == addr) {
            return i;
        }
    }
    return -1;
}

static nx86_status run_live(nx86_event_bus *bus, const nx86_observe_config *cfg,
                           const nx86_watch_entry *watches, uint32_t n_watches,
                           void (*log_fn)(uint32_t, const char *))
{
    pid_t pid = (pid_t)cfg->pid;
    breakpoint *bps;
    return_bp *rbs;
    int n_bps = 0, n_rbs = 0, i;
    int st;
    int target_alive = 1;
    uint32_t call_events = 0;
    struct sigaction sa, old_sa;

    bps = (breakpoint *)calloc(NX86_MAX_BREAKPOINTS, sizeof(*bps));
    rbs = (return_bp *)calloc(NX86_MAX_RETURNS, sizeof(*rbs));
    if (bps == NULL || rbs == NULL) {
        free(bps);
        free(rbs);
        return NX86_ERR_NO_MEMORY;
    }

    if (ptrace(PTRACE_ATTACH, pid, (void *)0, (void *)0) != 0) {
        emit_note(bus, cfg->pid, NX86_LOG_ERROR,
                  "ptrace attach was refused; live observation unavailable");
        if (log_fn != NULL) {
            log_fn(NX86_LOG_ERROR, strerror(errno));
        }
        free(bps);
        free(rbs);
        return NX86_ERR_UNSUPPORTED;
    }
    if (waitpid(pid, &st, 0) < 0) {
        free(bps);
        free(rbs);
        return NX86_ERR_INTERNAL;
    }

    /* Target is stopped: enumerate modules and resolve watched exports. */
    (void)scan_all_modules(bus, cfg->pid, watches, n_watches, bps, &n_bps,
                          NX86_MAX_BREAKPOINTS, log_fn);

    for (i = 0; i < n_bps; ++i) {
        unsigned char saved;
        if (bp_insert(pid, (unsigned long)bps[i].address, &saved) == 0) {
            bps[i].saved = saved;
            bps[i].armed = 1;
        }
    }

    if (n_bps == 0) {
        emit_note(bus, cfg->pid, NX86_LOG_INFO,
                  "no watched export resolved in the target; "
                  "detaching after the module/symbol pass");
        (void)ptrace(PTRACE_DETACH, pid, (void *)0, (void *)0);
        free(bps);
        free(rbs);
        return NX86_OK;
    }

    g_alarm_fired = 0;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, &old_sa);
    if (cfg->max_seconds > 0u) {
        alarm(cfg->max_seconds);
    }

    if (ptrace(PTRACE_CONT, pid, (void *)0, (void *)0) != 0) {
        target_alive = 0;
    }

    while (target_alive) {
        pid_t w = waitpid(pid, &st, 0);
        if (w < 0) {
            if (errno == EINTR && g_alarm_fired) {
                /* Safety budget elapsed: stop the tracee so we can detach. */
                kill(pid, SIGSTOP);
                if (waitpid(pid, &st, 0) < 0) {
                    break;
                }
                emit_note(bus, cfg->pid, NX86_LOG_INFO,
                          "observation time budget elapsed; detaching");
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            emit_note(bus, cfg->pid, NX86_LOG_INFO,
                      "target process ended during observation");
            target_alive = 0;
            break;
        }
        if (!WIFSTOPPED(st)) {
            continue;
        }
        if (WSTOPSIG(st) != SIGTRAP) {
            /* Forward any other signal so we do not alter delivery. */
            (void)ptrace(PTRACE_CONT, pid, (void *)0,
                         (void *)(long)WSTOPSIG(st));
            continue;
        }

        {
            struct user_regs_struct regs;
            uint64_t hit_addr;
            int ei, ri;
            if (ptrace(PTRACE_GETREGS, pid, (void *)0, &regs) != 0) {
                break;
            }
            hit_addr = (uint64_t)regs.rip - 1u;

            ei = find_entry_bp(bps, n_bps, hit_addr);
            if (ei >= 0) {
                /* We read ONLY the return address off the stack — a code
                 * address. Argument registers (rdi/rsi/...) are never
                 * read. */
                uint64_t ret_addr = (uint64_t)peek_word(pid,
                                        (unsigned long)regs.rsp);
                uint32_t tid = (uint32_t)pid;
                emit_call_site(bus, cfg->pid, tid, bps[ei].module,
                               bps[ei].name, ret_addr, bps[ei].address,
                               bps[ei].module_base, NX86_CALL_SITE_THUNK,
                               NX86_CALL_PHASE_ENTER);
                ++call_events;

                regs.rip = (unsigned long long)hit_addr;
                (void)ptrace(PTRACE_SETREGS, pid, (void *)0, &regs);

                {
                    int gone = bp_step_over(pid, (unsigned long)hit_addr,
                                            bps[ei].saved);
                    if (gone == 1) {
                        target_alive = 0;
                        break;
                    }
                }

                /* Arm a one-shot return breakpoint if not already present. */
                if (ret_addr != 0u && errno == 0 &&
                    find_return_bp(rbs, n_rbs, ret_addr) < 0 &&
                    n_rbs < NX86_MAX_RETURNS) {
                    unsigned char saved;
                    if (bp_insert(pid, (unsigned long)ret_addr, &saved) == 0) {
                        return_bp *rb = &rbs[n_rbs++];
                        rb->address = ret_addr;
                        rb->target_addr = bps[ei].address;
                        rb->module_base = bps[ei].module_base;
                        rb->saved = saved;
                        rb->active = 1;
                        (void)snprintf(rb->name, sizeof(rb->name), "%s",
                                       bps[ei].name);
                        (void)snprintf(rb->module, sizeof(rb->module), "%s",
                                       bps[ei].module);
                    }
                }

                if (cfg->max_call_events > 0u &&
                    call_events >= cfg->max_call_events) {
                    break;
                }
                (void)ptrace(PTRACE_CONT, pid, (void *)0, (void *)0);
                continue;
            }

            ri = find_return_bp(rbs, n_rbs, hit_addr);
            if (ri >= 0) {
                uint32_t tid = (uint32_t)pid;
                emit_call_site(bus, cfg->pid, tid, rbs[ri].module,
                               rbs[ri].name, rbs[ri].address,
                               rbs[ri].target_addr, rbs[ri].module_base,
                               NX86_CALL_SITE_THUNK, NX86_CALL_PHASE_RETURN);
                ++call_events;

                regs.rip = (unsigned long long)hit_addr;
                (void)ptrace(PTRACE_SETREGS, pid, (void *)0, &regs);
                {
                    int gone = bp_step_off(pid, (unsigned long)hit_addr,
                                           rbs[ri].saved);
                    rbs[ri].active = 0; /* one-shot: re-armed on next entry */
                    if (gone == 1) {
                        target_alive = 0;
                        break;
                    }
                }
                if (cfg->max_call_events > 0u &&
                    call_events >= cfg->max_call_events) {
                    break;
                }
                (void)ptrace(PTRACE_CONT, pid, (void *)0, (void *)0);
                continue;
            }

            /* A trap we did not set: hand it back and continue. */
            (void)ptrace(PTRACE_CONT, pid, (void *)0, (void *)0);
        }
    }

    /* Remove every breakpoint we placed, restoring the code byte-for-byte. */
    if (target_alive) {
        for (i = 0; i < n_bps; ++i) {
            if (bps[i].armed) {
                (void)bp_restore(pid, (unsigned long)bps[i].address,
                                 bps[i].saved);
            }
        }
        for (i = 0; i < n_rbs; ++i) {
            if (rbs[i].active) {
                (void)bp_restore(pid, (unsigned long)rbs[i].address,
                                 rbs[i].saved);
            }
        }
        (void)ptrace(PTRACE_DETACH, pid, (void *)0, (void *)0);
        if (g_alarm_fired) {
            (void)kill(pid, SIGCONT);
        }
    }

    if (cfg->max_seconds > 0u) {
        alarm(0);
    }
    sigaction(SIGALRM, &old_sa, NULL);

    {
        char msg[128];
        (void)snprintf(msg, sizeof(msg),
                       "live pass complete: %u call-site record(s)",
                       (unsigned)call_events);
        emit_note(bus, cfg->pid, NX86_LOG_INFO, msg);
    }

    free(bps);
    free(rbs);
    return NX86_OK;
}

#endif /* NX86_LIVE_OK */

/* ------------------------------------------------------------------ */
/* Public: run                                                         */
/* ------------------------------------------------------------------ */

nx86_status nx86_observe_run(nx86_event_bus *bus,
                            const nx86_observe_config *cfg,
                            const nx86_watch_entry *watches,
                            uint32_t n_watches,
                            void (*log_fn)(uint32_t level, const char *msg))
{
    if (bus == NULL || cfg == NULL) {
        return NX86_ERR_INVALID_ARG;
    }

#if NX86_LIVE_OK
    if (cfg->allow_live) {
        return run_live(bus, cfg, watches, n_watches, log_fn);
    }
#endif

    /* Read-only pass: module + symbol records, no ptrace, no breakpoints. */
    if (cfg->allow_live) {
        emit_note(bus, cfg->pid, NX86_LOG_WARN,
                  "live entry/return observation is not available on this "
                  "platform; running the read-only module/symbol pass only");
    }
    if (scan_all_modules(bus, cfg->pid, watches, n_watches, NULL, NULL, 0,
                        log_fn) != 0) {
        return NX86_ERR_UNSUPPORTED;
    }
    return NX86_OK;
}

#endif /* __linux__ */
