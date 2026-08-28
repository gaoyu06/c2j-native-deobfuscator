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
 * stack. From the register file it reads exactly two registers, one word
 * at a time via PTRACE_PEEKUSER: the instruction pointer (RIP, to learn
 * which breakpoint was hit) and the stack pointer (RSP, to locate the
 * return address). It never reads the argument registers (rdi, rsi, rdx,
 * rcx, r8, r9), the return-value register (rax) or any other register,
 * and it never copies the whole register file into host memory. It never
 * reads buffers, return values or keys, and it never modifies program
 * logic: a breakpoint is inserted, observed, and removed, leaving the
 * executed code byte-for-byte as it was. There is no vocabulary here for
 * TLS, Java or JNI: watched names are opaque strings.
 */
#if defined(__linux__)

#define _GNU_SOURCE

#include "observe.h"

#include <dirent.h>
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

/* Offsets, within the ptrace USER area, of the only two registers this
 * engine ever reads: the instruction pointer and the stack pointer.
 * Reading them one word at a time with PTRACE_PEEKUSER keeps the argument
 * registers (rdi/rsi/rdx/rcx/r8/r9) and the return-value register (rax)
 * out of the host's address space entirely — the whole register file is
 * never fetched. */
#define NX86_OFF_RIP offsetof(struct user_regs_struct, rip)
#define NX86_OFF_RSP offsetof(struct user_regs_struct, rsp)

/* Read one register word from the USER area at `off`. Sets errno to 0
 * before the call so the caller can distinguish a genuine -1 value from a
 * failed read. */
static long peek_user(pid_t pid, size_t off)
{
    errno = 0;
    return ptrace(PTRACE_PEEKUSER, pid, (void *)off, (void *)0);
}

/* Write one register word to the USER area at `off`. Used only to rewind
 * RIP over a restored breakpoint; no other register is ever written. */
static int poke_user(pid_t pid, size_t off, unsigned long value)
{
    return (int)ptrace(PTRACE_POKEUSER, pid, (void *)off, (void *)value);
}

/*
 * Test-only fault injection. The smoke test sets NX86_TEST_INJECT to a
 * comma/space/tab-separated list of fault names so it can exercise the
 * refusal and cleanup-failure paths deterministically, without needing a
 * sandbox that actually blocks ptrace. When the variable is unset (every
 * production run) this always returns 0 and changes nothing.
 *
 * Matching is exact per token, not substring, so one fault name can never
 * accidentally enable another.
 *
 *   attach-refused  - behave as if PTRACE_ATTACH was refused
 *   detach-fail     - skip the final detach so the attachment is treated
 *                     as possibly still active (must fail the command)
 *   step-over-fail  - fail the single-step over a watched-export entry
 *                     breakpoint as a non-ESRCH ptrace error, so the run
 *                     must restore the byte, detach, and fail rather than
 *                     report success with a breakpoint possibly in place
 *   insert-fail     - fail every bp_insert() as a non-ESRCH ptrace error,
 *                     so the entry-arming loop cannot arm any watch; the
 *                     run must restore, detach, and fail rather than
 *                     continue and later report a clean live success
 *   cont-fail       - fail every in-loop PTRACE_CONT as a non-ESRCH ptrace
 *                     error, so the run must restore any placed breakpoint,
 *                     detach, and fail rather than leave the target stopped
 *                     with a breakpoint in place and still report success
 */
static int test_inject(const char *what)
{
    const char *v = getenv("NX86_TEST_INJECT");
    size_t wlen;
    if (v == NULL) {
        return 0;
    }
    wlen = strlen(what);
    while (*v != '\0') {
        const char *start;
        size_t len;
        while (*v == ',' || *v == ' ' || *v == '\t') {
            ++v;
        }
        start = v;
        while (*v != '\0' && *v != ',' && *v != ' ' && *v != '\t') {
            ++v;
        }
        len = (size_t)(v - start);
        if (len == wlen && memcmp(start, what, wlen) == 0) {
            return 1;
        }
    }
    return 0;
}

/*
 * Count the threads of a process by listing /proc/PID/task, one entry per
 * thread. Returns the count (>= 1 for a live process), or -1 if the
 * directory cannot be read. The "." and ".." entries are skipped.
 *
 * This is a preview-policy gate, not a thread-group tracer: the live pass
 * places one process-wide software breakpoint per watched export, and
 * stepping such a breakpoint over the restored byte is only safe when no
 * other thread can run the patched entry meanwhile. Rather than attach and
 * single-step every thread (TRACECLONE and a full multi-thread debugger are
 * explicitly out of scope for this preview), a target with more than one
 * thread refuses the live pass and falls back to the read-only pass.
 */
static int count_task_threads(uint32_t pid)
{
    char path[64];
    DIR *d;
    struct dirent *ent;
    int n = 0;

    (void)snprintf(path, sizeof(path), "/proc/%u/task", (unsigned)pid);
    d = opendir(path);
    if (d == NULL) {
        return -1;
    }
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.' &&
            (ent->d_name[1] == '\0' ||
             (ent->d_name[1] == '.' && ent->d_name[2] == '\0'))) {
            continue; /* "." and ".." */
        }
        ++n;
    }
    closedir(d);
    return n;
}

/* Insert INT3, saving the original low byte into *saved. */
static int bp_insert(pid_t pid, unsigned long addr, unsigned char *saved)
{
    long orig;
    long patched;
    if (test_inject("insert-fail")) {
        /* Simulate a non-ESRCH ptrace failure while arming a breakpoint:
         * the caller must treat an un-armed watch as an incomplete live
         * pass, restore whatever did arm, detach, and fail the run. */
        errno = EIO;
        return -1;
    }
    orig = peek_word(pid, addr);
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
    if (test_inject("step-over-fail")) {
        /* Simulate a non-ESRCH ptrace failure before the byte is restored:
         * the entry breakpoint is still in place, so the caller must go
         * through the restore+detach helper and fail the run. */
        errno = EIO;
        return -1;
    }
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

/*
 * Remove every breakpoint we placed and detach, restoring the target's
 * code byte-for-byte. Returns 0 when the target is provably clean
 * afterwards (every restore and the detach succeeded, or failed only
 * because the target had already exited), and non-zero when a breakpoint
 * byte or the ptrace attachment may still be active — a condition the
 * caller must surface as a command failure rather than report as success.
 *
 * A ptrace op that fails with ESRCH means the tracee is already gone, so
 * nothing it once held can still be active; that is treated as clean.
 */
static int remove_breakpoints_and_detach(pid_t pid,
                                         breakpoint *bps, int n_bps,
                                         return_bp *rbs, int n_rbs)
{
    int leaked = 0;
    int i;

    for (i = 0; i < n_bps; ++i) {
        if (!bps[i].armed) {
            continue;
        }
        if (bp_restore(pid, (unsigned long)bps[i].address, bps[i].saved) != 0 &&
            errno != ESRCH) {
            leaked = 1;
        } else {
            bps[i].armed = 0;
        }
    }
    for (i = 0; i < n_rbs; ++i) {
        if (!rbs[i].active) {
            continue;
        }
        if (bp_restore(pid, (unsigned long)rbs[i].address, rbs[i].saved) != 0 &&
            errno != ESRCH) {
            leaked = 1;
        } else {
            rbs[i].active = 0;
        }
    }
    /* Test seam: pretend the detach failed so the caller must fail the
     * command. Skipping the real detach leaves the tracee stopped and
     * traced, which is exactly the "attachment may still be active" state
     * this path must never hide; the kernel releases it when the host
     * exits. */
    if (test_inject("detach-fail")) {
        return 1;
    }
    if (ptrace(PTRACE_DETACH, pid, (void *)0, (void *)0) != 0 &&
        errno != ESRCH) {
        leaked = 1;
    }
    return leaked;
}

/*
 * Resume the tracee with PTRACE_CONT, delivering signal `sig` (0 for
 * none). Returns 0 when the resume is known to be fine, -1 when it failed
 * in a way the caller must surface as a run failure.
 *
 * A CONT that fails for anything other than ESRCH may leave the target
 * stopped with a breakpoint byte still in place: that must never be
 * reported as success, so this returns -1 and the caller fails the run and
 * falls through to remove_breakpoints_and_detach(). ESRCH means the tracee
 * is already gone — nothing it held can still be active — so *alive is
 * cleared and 0 is returned, letting the loop end cleanly.
 */
static int cont_or_fail(pid_t pid, int sig, int *alive)
{
    if (test_inject("cont-fail")) {
        errno = EIO;
        return -1;
    }
    if (ptrace(PTRACE_CONT, pid, (void *)0, (void *)(long)sig) != 0) {
        if (errno == ESRCH) {
            *alive = 0;
            return 0;
        }
        return -1;
    }
    return 0;
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
    nx86_status run_status = NX86_OK;
    uint32_t call_events = 0;
    struct sigaction sa, old_sa;

    bps = (breakpoint *)calloc(NX86_MAX_BREAKPOINTS, sizeof(*bps));
    rbs = (return_bp *)calloc(NX86_MAX_RETURNS, sizeof(*rbs));
    if (bps == NULL || rbs == NULL) {
        free(bps);
        free(rbs);
        return NX86_ERR_NO_MEMORY;
    }

    /* Preview policy: before attaching or placing any process-wide INT3,
     * count the target's threads. Stepping a breakpoint over its restored
     * byte is only safe when no other thread can run the patched entry in
     * the meantime, so a multithreaded target refuses the live pass
     * outright (no attach, no breakpoints) and runs the documented
     * read-only module/symbol fallback with an honest note. Implementing a
     * full thread-group tracer (attaching every thread, TRACECLONE) is
     * deliberately out of scope for this preview. */
    {
        int nthreads = count_task_threads(cfg->pid);
        if (nthreads > 1) {
            nx86_status fb;
            emit_note(bus, cfg->pid, NX86_LOG_WARN,
                      "target has more than one thread; live entry/return "
                      "observation is single-thread only in this preview. "
                      "Running the read-only module/symbol pass instead "
                      "(no attach, no breakpoints)");
            if (log_fn != NULL) {
                log_fn(NX86_LOG_WARN,
                       "multithreaded target: refusing live pass, "
                       "read-only fallback");
            }
            free(bps);
            free(rbs);
            fb = (scan_all_modules(bus, cfg->pid, watches, n_watches,
                                   NULL, NULL, 0, log_fn) == 0)
                     ? NX86_OK
                     : NX86_ERR_UNSUPPORTED;
            return fb;
        }
    }

    if (test_inject("attach-refused") ||
        ptrace(PTRACE_ATTACH, pid, (void *)0, (void *)0) != 0) {
        int refused_errno = test_inject("attach-refused") ? EPERM : errno;
        nx86_status fb;
        emit_note(bus, cfg->pid, NX86_LOG_WARN,
                  "ptrace attach was refused; falling back to the read-only "
                  "module/symbol pass (no breakpoints)");
        if (log_fn != NULL) {
            log_fn(NX86_LOG_WARN, strerror(refused_errno));
        }
        free(bps);
        free(rbs);
        /* Documented fallback: no ptrace, no breakpoints, no attachment —
         * enumerate modules and resolve watched exports from disk instead
         * of pretending the target was empty. */
        fb = (scan_all_modules(bus, cfg->pid, watches, n_watches,
                               NULL, NULL, 0, log_fn) == 0)
                 ? NX86_OK
                 : NX86_ERR_UNSUPPORTED;
        return fb;
    }
    if (waitpid(pid, &st, 0) < 0) {
        /* Attached but never saw the initial stop. Detach best-effort and
         * fail: the attachment may still be active. */
        (void)ptrace(PTRACE_DETACH, pid, (void *)0, (void *)0);
        free(bps);
        free(rbs);
        return NX86_ERR_INTERNAL;
    }

    /* Target is stopped: enumerate modules and resolve watched exports.
     * A scan failure here is not something to paper over — we are attached
     * but cannot produce the module/symbol pass, so detach cleanly and
     * fail the run rather than continue as if it had succeeded. Nothing is
     * armed yet, so the helper only has to release the attachment. */
    if (scan_all_modules(bus, cfg->pid, watches, n_watches, bps, &n_bps,
                         NX86_MAX_BREAKPOINTS, log_fn) != 0) {
        emit_note(bus, cfg->pid, NX86_LOG_ERROR,
                  "module scan failed while attached; detaching without "
                  "observing");
        /* Nothing is armed yet; this only has to release the attachment.
         * Either way the run has failed. */
        (void)remove_breakpoints_and_detach(pid, bps, n_bps, rbs, n_rbs);
        free(bps);
        free(rbs);
        return NX86_ERR_INTERNAL;
    }

    if (n_bps == 0) {
        int leaked;
        emit_note(bus, cfg->pid, NX86_LOG_INFO,
                  "no watched export resolved in the target; "
                  "detaching after the module/symbol pass");
        leaked = remove_breakpoints_and_detach(pid, bps, 0, rbs, 0);
        free(bps);
        free(rbs);
        return leaked ? NX86_ERR_INTERNAL : NX86_OK;
    }

    {
        int n_arm_fail = 0;
        for (i = 0; i < n_bps; ++i) {
            unsigned char saved;
            if (bp_insert(pid, (unsigned long)bps[i].address, &saved) == 0) {
                bps[i].saved = saved;
                bps[i].armed = 1;
            } else if (errno == ESRCH) {
                /* Tracee vanished mid-arming: nothing it held is active. */
                target_alive = 0;
                break;
            } else {
                ++n_arm_fail;
            }
        }

        /* Arming a watched-export breakpoint is what turns this into a live
         * pass. If any insert failed we cannot honestly report a complete
         * live observation, and a partially-armed target must still be
         * cleaned up: restore whatever did arm, detach, and fail the run
         * rather than continue and later print a clean "shutdown ok". This
         * covers both "some watches failed to arm" and "every watch failed
         * to arm" — silently ignoring the failure is not allowed. */
        if (n_arm_fail > 0) {
            int leaked;
            emit_note(bus, cfg->pid, NX86_LOG_ERROR,
                      "could not arm one or more watched-export "
                      "breakpoints; restoring and detaching without a live "
                      "pass");
            leaked = remove_breakpoints_and_detach(pid, bps, n_bps, rbs,
                                                   n_rbs);
            (void)leaked;
            free(bps);
            free(rbs);
            return NX86_ERR_INTERNAL;
        }
        if (!target_alive) {
            /* Tracee exited while arming; nothing is left in place. */
            emit_note(bus, cfg->pid, NX86_LOG_INFO,
                      "target process ended before the live pass began");
            free(bps);
            free(rbs);
            return NX86_OK;
        }
    }

    g_alarm_fired = 0;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, &old_sa);
    if (cfg->max_seconds > 0u) {
        alarm(cfg->max_seconds);
    }

    if (ptrace(PTRACE_CONT, pid, (void *)0, (void *)0) != 0) {
        if (errno == ESRCH) {
            /* Tracee already gone: nothing it held can still be active. */
            target_alive = 0;
        } else {
            /* The target may still be alive and stopped with breakpoints
             * in place. Do not skip cleanup and do not report success:
             * fall through to the restore+detach path with the run marked
             * failed. */
            run_status = NX86_ERR_INTERNAL;
        }
    }

    while (target_alive && run_status == NX86_OK) {
        pid_t w = waitpid(pid, &st, 0);
        if (w < 0) {
            if (errno == EINTR && g_alarm_fired) {
                /* Safety budget elapsed: stop the tracee so we can detach. */
                kill(pid, SIGSTOP);
                if (waitpid(pid, &st, 0) < 0) {
                    if (errno == ESRCH) {
                        target_alive = 0;
                    } else {
                        run_status = NX86_ERR_INTERNAL;
                    }
                    break;
                }
                emit_note(bus, cfg->pid, NX86_LOG_INFO,
                          "observation time budget elapsed; detaching");
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            if (errno != ESRCH) {
                run_status = NX86_ERR_INTERNAL;
            } else {
                target_alive = 0;
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
            /* Forward any other signal so we do not alter delivery. A CONT
             * that fails for anything but ESRCH may leave the target
             * stopped with breakpoints in place, so fail the run and clean
             * up rather than silently ignore it. */
            if (cont_or_fail(pid, WSTOPSIG(st), &target_alive) != 0) {
                run_status = NX86_ERR_INTERNAL;
                break;
            }
            continue;
        }

        {
            unsigned long rip;
            unsigned long rsp;
            uint64_t hit_addr;
            int ei, ri;
            /* Read only RIP — one register word — to learn which
             * breakpoint was hit. The argument and return-value registers
             * are never fetched. */
            rip = (unsigned long)peek_user(pid, NX86_OFF_RIP);
            if (errno != 0) {
                if (errno == ESRCH) {
                    target_alive = 0;
                } else {
                    run_status = NX86_ERR_INTERNAL;
                }
                break;
            }
            hit_addr = (uint64_t)rip - 1u;

            ei = find_entry_bp(bps, n_bps, hit_addr);
            if (ei >= 0) {
                /* Read only RSP (one more register word), then read ONLY
                 * the return address it points at — a code address.
                 * Argument registers (rdi/rsi/...) are never read. */
                uint64_t ret_addr;
                int ret_ok;
                uint32_t tid = (uint32_t)pid;
                rsp = (unsigned long)peek_user(pid, NX86_OFF_RSP);
                if (errno != 0) {
                    if (errno == ESRCH) {
                        target_alive = 0;
                    } else {
                        run_status = NX86_ERR_INTERNAL;
                    }
                    break;
                }
                ret_addr = (uint64_t)peek_word(pid, rsp);
                ret_ok = (errno == 0);
                emit_call_site(bus, cfg->pid, tid, bps[ei].module,
                               bps[ei].name, ret_addr, bps[ei].address,
                               bps[ei].module_base, NX86_CALL_SITE_THUNK,
                               NX86_CALL_PHASE_ENTER);
                ++call_events;

                /* Rewind RIP over the restored breakpoint byte: one
                 * register word written, nothing else. A failed rewind
                 * would leave execution one byte past the INT3, so it can
                 * never be reported as success: fail the run and fall
                 * through to the restore+detach cleanup (the entry
                 * breakpoint is still armed and will be removed there). */
                if (poke_user(pid, NX86_OFF_RIP,
                              (unsigned long)hit_addr) != 0) {
                    if (errno == ESRCH) {
                        target_alive = 0;
                    } else {
                        run_status = NX86_ERR_INTERNAL;
                    }
                    break;
                }

                {
                    int gone = bp_step_over(pid, (unsigned long)hit_addr,
                                            bps[ei].saved);
                    if (gone == 1) {
                        target_alive = 0;
                        break;
                    }
                    if (gone < 0) {
                        /* The step (restore / single-step / re-arm) failed.
                         * A breakpoint byte may still be in place, so the
                         * cleanup helper must restore it and detach, and the
                         * run must fail. ESRCH means the tracee is gone. */
                        if (errno == ESRCH) {
                            target_alive = 0;
                        } else {
                            run_status = NX86_ERR_INTERNAL;
                        }
                        break;
                    }
                }

                /* Arm a one-shot return breakpoint if not already present. */
                if (ret_addr != 0u && ret_ok &&
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
                if (cont_or_fail(pid, 0, &target_alive) != 0) {
                    run_status = NX86_ERR_INTERNAL;
                    break;
                }
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

                /* Rewind RIP over the restored breakpoint byte. A failed
                 * rewind would leave execution past the INT3: fail and let
                 * the cleanup helper restore the still-active return
                 * breakpoint and detach. */
                if (poke_user(pid, NX86_OFF_RIP,
                              (unsigned long)hit_addr) != 0) {
                    if (errno == ESRCH) {
                        target_alive = 0;
                    } else {
                        run_status = NX86_ERR_INTERNAL;
                    }
                    break;
                }
                {
                    int gone = bp_step_off(pid, (unsigned long)hit_addr,
                                           rbs[ri].saved);
                    if (gone < 0) {
                        /* The step failed; the byte may still be in place,
                         * so leave this return breakpoint marked active for
                         * the cleanup helper to restore, and fail the run
                         * (unless the tracee is already gone). */
                        if (errno == ESRCH) {
                            target_alive = 0;
                        } else {
                            run_status = NX86_ERR_INTERNAL;
                        }
                        break;
                    }
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
                if (cont_or_fail(pid, 0, &target_alive) != 0) {
                    run_status = NX86_ERR_INTERNAL;
                    break;
                }
                continue;
            }

            /* A trap we did not set: hand it back and continue. A CONT
             * failure here is surfaced the same way, never silently
             * ignored. */
            if (cont_or_fail(pid, 0, &target_alive) != 0) {
                run_status = NX86_ERR_INTERNAL;
                break;
            }
        }
    }

    /* Remove every breakpoint we placed and detach, restoring the code
     * byte-for-byte. When the target is already gone there is nothing left
     * active, so this only runs while it is alive. A restore or detach that
     * fails (leaving a breakpoint byte or the attachment possibly active)
     * turns the whole run into a failure — success is never reported while
     * anything we installed may still be in place. */
    if (target_alive) {
        if (remove_breakpoints_and_detach(pid, bps, n_bps, rbs, n_rbs) != 0) {
            if (run_status == NX86_OK) {
                run_status = NX86_ERR_INTERNAL;
            }
        }
        if (g_alarm_fired) {
            (void)kill(pid, SIGCONT);
        }
    }

    if (cfg->max_seconds > 0u) {
        alarm(0);
    }
    sigaction(SIGALRM, &old_sa, NULL);

    if (run_status == NX86_OK) {
        char msg[128];
        (void)snprintf(msg, sizeof(msg),
                       "live pass complete: %u call-site record(s)",
                       (unsigned)call_events);
        emit_note(bus, cfg->pid, NX86_LOG_INFO, msg);
    } else {
        emit_note(bus, cfg->pid, NX86_LOG_ERROR,
                  "live pass did not complete cleanly; a breakpoint or the "
                  "attachment may not have been removed");
    }

    free(bps);
    free(rbs);
    return run_status;
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
