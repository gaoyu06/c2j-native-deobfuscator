/*
 * Windows read-only observation backend.
 *
 * This backend is deliberately not a debugger.  It verifies that the target
 * has the same user SID as the host, takes a Toolhelp module snapshot, and
 * parses each module's named PE exports from the file on disk.  It emits only
 * module and watched-symbol metadata.  It does not attach for debugging, place
 * breakpoints, read process memory, inspect registers, or observe calls.
 */
#if defined(_WIN32)

#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0600
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#include "observe.h"
#include "pe_exports.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NX86_UTF8_PATH_MAX ((MAX_PATH * 4u) + 1u)

typedef struct mapped_image {
    HANDLE               file;
    HANDLE               mapping;
    const unsigned char *bytes;
    size_t               size;
} mapped_image;

typedef struct export_context {
    nx86_event_bus         *bus;
    uint32_t                pid;
    const char             *module_name;
    uint64_t                module_base;
    const nx86_watch_entry *watches;
    uint32_t                watch_count;
} export_context;

static nx86_str str_c(const char *s)
{
    nx86_str out;
    out.data = s;
    out.len = (uint32_t)(s != NULL ? strlen(s) : 0u);
    out.reserved = 0u;
    return out;
}

static void stamp(nx86_event_bus *bus, nx86_event_header *header,
                  uint32_t size, nx86_event_kind kind, uint32_t pid)
{
    nx86_bus_stamp(bus, header, size, kind);
    header->process_id = pid;
    header->thread_id = 0u;
}

static void emit_note(nx86_event_bus *bus, uint32_t pid, uint32_t level,
                      const char *text)
{
    nx86_event_note note;
    memset(&note, 0, sizeof(note));
    stamp(bus, &note.header, (uint32_t)sizeof(note), NX86_EVENT_NOTE, pid);
    note.level = level;
    note.source = str_c("observe.windows");
    note.text = str_c(text);
    (void)nx86_bus_publish(bus, &note.header);
}

static void emit_module_load(nx86_event_bus *bus, uint32_t pid,
                             const char *path, const char *name,
                             uint64_t base, uint64_t size, uint32_t machine)
{
    nx86_event_module_load module;
    memset(&module, 0, sizeof(module));
    stamp(bus, &module.header, (uint32_t)sizeof(module),
          NX86_EVENT_MODULE_LOAD, pid);
    module.path = str_c(path);
    module.name = str_c(name);
    module.base_address = base;
    module.image_size = size;
    module.machine = machine;
    (void)nx86_bus_publish(bus, &module.header);
}

static void emit_symbol(nx86_event_bus *bus, uint32_t pid,
                        const char *module_name, const char *symbol_name,
                        uint64_t module_base, uint64_t address,
                        uint32_t ordinal)
{
    nx86_event_symbol symbol;
    memset(&symbol, 0, sizeof(symbol));
    stamp(bus, &symbol.header, (uint32_t)sizeof(symbol), NX86_EVENT_SYMBOL,
          pid);
    symbol.module_name = str_c(module_name);
    symbol.symbol_name = str_c(symbol_name);
    symbol.module_base = module_base;
    symbol.address = address;
    symbol.binding = NX86_SYMBOL_EXPORT;
    symbol.ordinal = ordinal;
    (void)nx86_bus_publish(bus, &symbol.header);
}

static uint32_t match_flags(const char *name,
                            const nx86_watch_entry *watches, uint32_t count)
{
    uint32_t flags = 0u;
    uint32_t i;

    for (i = 0; i < count; ++i) {
        const nx86_watch_entry *watch = &watches[i];
        int matched = 0;
        if (watch->match_kind == NX86_MATCH_EXACT) {
            matched = strcmp(name, watch->name) == 0;
        } else if (watch->match_kind == NX86_MATCH_PREFIX) {
            matched = strncmp(name, watch->name, strlen(watch->name)) == 0;
        }
        if (matched) {
            flags |= watch->flags;
        }
    }
    return flags;
}

static void on_export(void *opaque, const nx86_pe_export *entry)
{
    export_context *ctx = (export_context *)opaque;
    uint32_t flags = match_flags(entry->name, ctx->watches, ctx->watch_count);

    /* A forwarded entry's RVA names a forwarder string, not executable code
     * in this module, so it is not reported as an absolute symbol address. */
    if ((flags & NX86_WATCH_SYMBOL) == 0u || entry->forwarded ||
        UINT64_MAX - ctx->module_base < entry->rva) {
        return;
    }
    emit_symbol(ctx->bus, ctx->pid, ctx->module_name, entry->name,
                ctx->module_base, ctx->module_base + entry->rva,
                entry->ordinal);
}

static int wide_to_utf8(const wchar_t *wide, char *utf8, size_t capacity)
{
    int written;
    if (wide == NULL || utf8 == NULL || capacity == 0u ||
        capacity > (size_t)INT_MAX) {
        return -1;
    }
    written = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1,
                                  utf8, (int)capacity, NULL, NULL);
    return written > 0 ? 0 : -1;
}

static void close_mapped_image(mapped_image *image)
{
    if (image->bytes != NULL) {
        (void)UnmapViewOfFile(image->bytes);
    }
    if (image->mapping != NULL) {
        (void)CloseHandle(image->mapping);
    }
    if (image->file != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(image->file);
    }
    memset(image, 0, sizeof(*image));
    image->file = INVALID_HANDLE_VALUE;
}

static int open_mapped_image(const wchar_t *path, mapped_image *out)
{
    LARGE_INTEGER size;

    memset(out, 0, sizeof(*out));
    out->file = INVALID_HANDLE_VALUE;
    out->file = CreateFileW(path, GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE |
                                FILE_SHARE_DELETE,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (out->file == INVALID_HANDLE_VALUE ||
        !GetFileSizeEx(out->file, &size) || size.QuadPart <= 0 ||
        (uint64_t)size.QuadPart > (uint64_t)(size_t)-1) {
        close_mapped_image(out);
        return -1;
    }
    out->mapping = CreateFileMappingW(out->file, NULL, PAGE_READONLY, 0u, 0u,
                                      NULL);
    if (out->mapping == NULL) {
        close_mapped_image(out);
        return -1;
    }
    out->bytes = (const unsigned char *)MapViewOfFile(
        out->mapping, FILE_MAP_READ, 0u, 0u, 0u);
    if (out->bytes == NULL) {
        close_mapped_image(out);
        return -1;
    }
    out->size = (size_t)size.QuadPart;
    return 0;
}

static int get_token_user(HANDLE token, unsigned char **out_storage,
                          TOKEN_USER **out_user)
{
    DWORD needed = 0u;
    unsigned char *storage;

    (void)GetTokenInformation(token, TokenUser, NULL, 0u, &needed);
    if (needed == 0u || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return -1;
    }
    storage = (unsigned char *)malloc((size_t)needed);
    if (storage == NULL) {
        return -1;
    }
    if (!GetTokenInformation(token, TokenUser, storage, needed, &needed)) {
        free(storage);
        return -1;
    }
    *out_storage = storage;
    *out_user = (TOKEN_USER *)storage;
    return 0;
}

/*
 * Open a query-only handle and compare the target's user SID with the host's.
 * When `out_process` is non-NULL, a same-user process handle is returned so
 * its identity stays stable while the module snapshot is taken.
 */
static int open_same_user_process(uint32_t pid, HANDLE *out_process)
{
    HANDLE process = NULL;
    HANDLE target_token = NULL;
    HANDLE current_token = NULL;
    unsigned char *target_storage = NULL;
    unsigned char *current_storage = NULL;
    TOKEN_USER *target_user = NULL;
    TOKEN_USER *current_user = NULL;
    int result = -1;

    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == NULL ||
        !OpenProcessToken(process, TOKEN_QUERY, &target_token) ||
        !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &current_token) ||
        get_token_user(target_token, &target_storage, &target_user) != 0 ||
        get_token_user(current_token, &current_storage, &current_user) != 0) {
        goto done;
    }
    result = EqualSid(target_user->User.Sid, current_user->User.Sid) ? 1 : 0;
    if (result == 1 && out_process != NULL) {
        *out_process = process;
        process = NULL;
    }

done:
    free(target_storage);
    free(current_storage);
    if (target_token != NULL) {
        (void)CloseHandle(target_token);
    }
    if (current_token != NULL) {
        (void)CloseHandle(current_token);
    }
    if (process != NULL) {
        (void)CloseHandle(process);
    }
    return result;
}

static HANDLE take_module_snapshot(uint32_t pid)
{
    HANDLE snapshot = INVALID_HANDLE_VALUE;
    int attempt;

    /* ERROR_BAD_LENGTH is documented as transient for module snapshots. */
    for (attempt = 0; attempt < 4; ++attempt) {
        snapshot = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snapshot != INVALID_HANDLE_VALUE ||
            GetLastError() != ERROR_BAD_LENGTH) {
            break;
        }
    }
    return snapshot;
}

static int scan_modules(nx86_event_bus *bus, uint32_t pid,
                        const nx86_watch_entry *watches, uint32_t watch_count,
                        void (*log_fn)(uint32_t, const char *))
{
    HANDLE snapshot;
    MODULEENTRY32W module;
    BOOL more;
    DWORD enumeration_error;

    snapshot = take_module_snapshot(pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        if (log_fn != NULL) {
            log_fn(NX86_LOG_ERROR,
                   "cannot take a read-only snapshot of target modules");
        }
        return -1;
    }

    memset(&module, 0, sizeof(module));
    module.dwSize = (DWORD)sizeof(module);
    more = Module32FirstW(snapshot, &module);
    if (!more) {
        if (log_fn != NULL) {
            log_fn(NX86_LOG_ERROR,
                   "cannot enumerate modules from the read-only snapshot");
        }
        (void)CloseHandle(snapshot);
        return -1;
    }

    do {
        char path[NX86_UTF8_PATH_MAX];
        char name[NX86_UTF8_PATH_MAX];
        mapped_image image;
        uint32_t machine = NX86_MACHINE_UNKNOWN;
        uint32_t declared_size = 0u;
        uint64_t base = (uint64_t)(uintptr_t)module.modBaseAddr;
        int pe_status = -1;

        if (wide_to_utf8(module.szExePath, path, sizeof(path)) != 0 ||
            wide_to_utf8(module.szModule, name, sizeof(name)) != 0) {
            if (log_fn != NULL) {
                log_fn(NX86_LOG_WARN,
                       "skipping a module whose name cannot be represented");
            }
            module.dwSize = (DWORD)sizeof(module);
            more = Module32NextW(snapshot, &module);
            continue;
        }

        if (open_mapped_image(module.szExePath, &image) == 0) {
            pe_status = nx86_pe_visit_exports(
                image.bytes, image.size, NULL, NULL, &machine, &declared_size);
        } else {
            memset(&image, 0, sizeof(image));
            image.file = INVALID_HANDLE_VALUE;
        }

        emit_module_load(bus, pid, path, name, base,
                         declared_size != 0u ? declared_size
                                             : (uint64_t)module.modBaseSize,
                         machine);
        if (pe_status == 0) {
            export_context ctx;
            memset(&ctx, 0, sizeof(ctx));
            ctx.bus = bus;
            ctx.pid = pid;
            ctx.module_name = name;
            ctx.module_base = base;
            ctx.watches = watches;
            ctx.watch_count = watch_count;
            (void)nx86_pe_visit_exports(image.bytes, image.size, on_export,
                                        &ctx, NULL, NULL);
        } else if (log_fn != NULL) {
            log_fn(NX86_LOG_WARN,
                   "module listed, but its on-disk PE exports were unavailable");
        }
        close_mapped_image(&image);

        module.dwSize = (DWORD)sizeof(module);
        more = Module32NextW(snapshot, &module);
    } while (more);

    enumeration_error = GetLastError();
    (void)CloseHandle(snapshot);
    return enumeration_error == ERROR_NO_MORE_FILES ? 0 : -1;
}

int nx86_observe_owner_check(uint32_t pid, uint32_t *out_owner_id)
{
    if (out_owner_id != NULL) {
        /* Windows user identity is a SID, not a scalar uid. */
        *out_owner_id = 0u;
    }
    return open_same_user_process(pid, NULL);
}

int nx86_observe_live_supported(void)
{
    return 0;
}

const char *nx86_observe_backend_name(void)
{
    return "windows read-only: Toolhelp modules + on-disk PE exports "
           "(live unavailable)";
}

nx86_status nx86_observe_run(nx86_event_bus *bus,
                             const nx86_observe_config *cfg,
                             const nx86_watch_entry *watches,
                             uint32_t n_watches,
                             void (*log_fn)(uint32_t level, const char *msg))
{
    HANDLE process = NULL;
    int owned;
    int scan_status;

    if (bus == NULL || cfg == NULL ||
        (n_watches != 0u && watches == NULL)) {
        return NX86_ERR_INVALID_ARG;
    }
    owned = open_same_user_process(cfg->pid, &process);
    if (owned != 1) {
        emit_note(bus, cfg->pid, NX86_LOG_ERROR,
                  "target is not a same-user process available for inspection");
        return NX86_ERR_UNSUPPORTED;
    }

    emit_note(bus, cfg->pid, NX86_LOG_WARN,
              "live entry/return observation is unavailable on Windows; "
              "running the read-only module/symbol pass only");
    if (log_fn != NULL) {
        log_fn(NX86_LOG_INFO,
               "Windows backend is read-only; live observation is unavailable");
    }
    scan_status = scan_modules(bus, cfg->pid, watches, n_watches, log_fn);
    (void)CloseHandle(process);
    return scan_status == 0 ? NX86_OK : NX86_ERR_UNSUPPORTED;
}

#else /* !_WIN32 : this translation unit is intentionally empty */

typedef int nx86_observe_windows_unused;

#endif /* _WIN32 */
