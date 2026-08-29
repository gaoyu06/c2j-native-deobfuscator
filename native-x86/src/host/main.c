/*
 * nativex86 host.
 *
 * Loads one or more observation plugins through the versioned C ABI in
 * include/nativex86/plugin.h, hands each a host interface, and then
 * either:
 *
 *   - replays a fixed script of synthetic records (default, no target),
 *     proving the ABI links, loads and dispatches; or
 *
 *   - inspects a process the invoking user owns (--pid N, with the
 *     --i-own-this-process confirmation) and reports metadata-only
 *     records — module loads, resolved symbols, and, where implemented,
 *     live call sites for the exports the loaded plugins asked to watch.
 *
 * The host owns no library-specific knowledge: it does not know what
 * "SSL_write" or "Java_" mean. Plugins declare those names through
 * request_watch; the host resolves and observes them as ordinary
 * exported functions. No argument, buffer, key or return value is ever
 * read or reported.
 */
#include "nativex86/plugin.h"

#include "event_bus.h"
#include "observe.h"
#include "platform.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NX86_HOST_MAX_PLUGINS 8
#define NX86_HOST_MAX_WATCHES 64
#define NX86_HOST_EMIT_MAX    NX86_HOST_MAX_EVENT_SIZE

typedef struct host_state {
    nx86_event_bus   bus;
    uint64_t         sink_seen;
    nx86_watch_entry watches[NX86_HOST_MAX_WATCHES];
    uint32_t         n_watches;
} host_state;

static nx86_str str_lit(const char *s)
{
    nx86_str out;
    out.data = s;
    out.len = (uint32_t)strlen(s);
    out.reserved = 0u;
    return out;
}

static const char *kind_name(nx86_event_kind kind)
{
    switch (kind) {
    case NX86_EVENT_NOTE:          return "note";
    case NX86_EVENT_MODULE_LOAD:   return "module-load";
    case NX86_EVENT_MODULE_UNLOAD: return "module-unload";
    case NX86_EVENT_SYMBOL:        return "symbol";
    case NX86_EVENT_CALL_SITE:     return "call-site";
    default:                       return "unknown";
    }
}

static const char *phase_name(uint32_t phase)
{
    switch (phase) {
    case NX86_CALL_PHASE_ENTER:  return "enter";
    case NX86_CALL_PHASE_RETURN: return "return";
    default:                     return "none";
    }
}

/* ------------------------------------------------------------------ */
/* nx86_host implementation                                            */
/* ------------------------------------------------------------------ */

static nx86_status NX86_CALL host_register_observer(void *host_ctx,
                                                    uint32_t event_mask,
                                                    nx86_observer_fn fn,
                                                    void *user_data,
                                                    uint32_t *out_token)
{
    host_state *state = (host_state *)host_ctx;
    if (state == NULL) {
        return NX86_ERR_INVALID_ARG;
    }
    return nx86_bus_register(&state->bus, event_mask, fn, user_data, out_token);
}

static nx86_status NX86_CALL host_unregister_observer(void *host_ctx,
                                                      uint32_t token)
{
    host_state *state = (host_state *)host_ctx;
    if (state == NULL) {
        return NX86_ERR_INVALID_ARG;
    }
    return nx86_bus_unregister(&state->bus, token);
}

static nx86_status NX86_CALL host_emit(void *host_ctx,
                                       const nx86_event_header *event)
{
    host_state *state = (host_state *)host_ctx;
    if (state == NULL) {
        return NX86_ERR_INVALID_ARG;
    }
    return nx86_bus_republish(&state->bus, event);
}

static void NX86_CALL host_log(void *host_ctx,
                               uint32_t level,
                               const char *message)
{
    (void)host_ctx;
    printf("host: [log %u] %s\n", (unsigned)level,
           message != NULL ? message : "(null)");
}

/* Plain logging callback for the observation engine. */
static void host_log_level(uint32_t level, const char *message)
{
    printf("host: [observe %u] %s\n", (unsigned)level,
           message != NULL ? message : "(null)");
}

static nx86_status NX86_CALL host_request_watch(void *host_ctx,
                                                const nx86_watch_request *req)
{
    host_state *state = (host_state *)host_ctx;
    nx86_watch_entry *entry;
    uint32_t copy_len;

    if (state == NULL || req == NULL) {
        return NX86_ERR_INVALID_ARG;
    }
    if (!NX86_HAS_FIELD(req->struct_size, nx86_watch_request, flags)) {
        return NX86_ERR_INVALID_ARG;
    }
    if (req->match_kind != NX86_MATCH_EXACT &&
        req->match_kind != NX86_MATCH_PREFIX) {
        return NX86_ERR_INVALID_ARG;
    }
    if (req->name.data == NULL || req->name.len == 0u) {
        return NX86_ERR_INVALID_ARG;
    }
    if (state->n_watches >= NX86_HOST_MAX_WATCHES) {
        return NX86_ERR_NO_MEMORY;
    }

    entry = &state->watches[state->n_watches];
    memset(entry, 0, sizeof(*entry));
    copy_len = req->name.len;
    if (copy_len >= (uint32_t)sizeof(entry->name)) {
        copy_len = (uint32_t)sizeof(entry->name) - 1u;
    }
    memcpy(entry->name, req->name.data, copy_len);
    entry->name[copy_len] = '\0';
    entry->match_kind = req->match_kind;
    entry->flags = (req->flags != 0u) ? req->flags : NX86_WATCH_SYMBOL;
    state->n_watches++;
    return NX86_OK;
}

/* Console sink so records are visible in the smoke test and to a user. */
static void NX86_CALL host_console_sink(void *user_data,
                                        const nx86_event_header *event)
{
    host_state *state = (host_state *)user_data;
    state->sink_seen++;
    printf("host: sink seq=%llu kind=%s pid=%u size=%u",
           (unsigned long long)event->seq, kind_name(event->kind),
           (unsigned)event->process_id, (unsigned)event->struct_size);

    switch (event->kind) {
    case NX86_EVENT_NOTE:
        if (event->struct_size >= (uint32_t)sizeof(nx86_event_note)) {
            const nx86_event_note *e = (const nx86_event_note *)event;
            printf(" source=%.*s text=%.*s",
                   (int)e->source.len, e->source.data ? e->source.data : "",
                   (int)e->text.len, e->text.data ? e->text.data : "");
        }
        break;
    case NX86_EVENT_MODULE_LOAD:
        if (event->struct_size >= (uint32_t)sizeof(nx86_event_module_load)) {
            const nx86_event_module_load *e =
                (const nx86_event_module_load *)event;
            printf(" module=%.*s base=0x%llx size=0x%llx",
                   (int)e->name.len, e->name.data ? e->name.data : "",
                   (unsigned long long)e->base_address,
                   (unsigned long long)e->image_size);
        }
        break;
    case NX86_EVENT_SYMBOL:
        if (event->struct_size >= (uint32_t)sizeof(nx86_event_symbol)) {
            const nx86_event_symbol *e = (const nx86_event_symbol *)event;
            printf(" module=%.*s symbol=%.*s addr=0x%llx",
                   (int)e->module_name.len,
                   e->module_name.data ? e->module_name.data : "",
                   (int)e->symbol_name.len,
                   e->symbol_name.data ? e->symbol_name.data : "",
                   (unsigned long long)e->address);
        }
        break;
    case NX86_EVENT_CALL_SITE:
        if (event->struct_size >= (uint32_t)sizeof(nx86_event_call_site)) {
            const nx86_event_call_site *e =
                (const nx86_event_call_site *)event;
            printf(" module=%.*s target=%.*s site=0x%llx target=0x%llx phase=%s",
                   (int)e->module_name.len,
                   e->module_name.data ? e->module_name.data : "",
                   (int)e->target_name.len,
                   e->target_name.data ? e->target_name.data : "",
                   (unsigned long long)e->site_address,
                   (unsigned long long)e->target_address,
                   phase_name(e->phase));
        }
        break;
    default:
        break;
    }
    printf("\n");
}

/* ------------------------------------------------------------------ */
/* Synthetic record script (used when no target is given)              */
/* ------------------------------------------------------------------ */

static void publish_sample_records(host_state *state)
{
    nx86_event_module_load module;
    nx86_event_symbol symbol;
    nx86_event_call_site call_site;

    memset(&module, 0, sizeof(module));
    nx86_bus_stamp(&state->bus, &module.header, (uint32_t)sizeof(module),
                   NX86_EVENT_MODULE_LOAD);
    module.path = str_lit("/synthetic/sample-target.so");
    module.name = str_lit("sample-target.so");
    module.base_address = 0x0000555500400000ULL;
    module.image_size = 0x00040000ULL;
    module.machine = NX86_MACHINE_X86_64;
    (void)nx86_bus_publish(&state->bus, &module.header);

    memset(&symbol, 0, sizeof(symbol));
    nx86_bus_stamp(&state->bus, &symbol.header, (uint32_t)sizeof(symbol),
                   NX86_EVENT_SYMBOL);
    symbol.module_name = str_lit("sample-target.so");
    symbol.symbol_name = str_lit("sample_entry");
    symbol.module_base = module.base_address;
    symbol.address = module.base_address + 0x1120ULL;
    symbol.binding = NX86_SYMBOL_EXPORT;
    (void)nx86_bus_publish(&state->bus, &symbol.header);

    memset(&call_site, 0, sizeof(call_site));
    nx86_bus_stamp(&state->bus, &call_site.header, (uint32_t)sizeof(call_site),
                   NX86_EVENT_CALL_SITE);
    call_site.module_name = str_lit("sample-target.so");
    call_site.target_name = str_lit("sample_helper");
    call_site.module_base = module.base_address;
    call_site.site_address = module.base_address + 0x1147ULL;
    call_site.target_address = module.base_address + 0x1190ULL;
    call_site.site_kind = NX86_CALL_SITE_DIRECT;
    call_site.phase = NX86_CALL_PHASE_NONE;
    (void)nx86_bus_publish(&state->bus, &call_site.header);
}

/* ------------------------------------------------------------------ */
/* Plugin loading                                                      */
/* ------------------------------------------------------------------ */

typedef struct loaded_plugin {
    void        *library;
    nx86_plugin  plugin;
    int          started;
} loaded_plugin;

static int load_one_plugin(const char *path, const nx86_host *host,
                           loaded_plugin *out)
{
    nx86_plugin_init_fn init_fn;
    void *symbol;
    nx86_status status;

    out->library = nx86_plat_open_library(path);
    if (out->library == NULL) {
        fprintf(stderr, "host: cannot load plugin '%s': %s\n", path,
                nx86_plat_last_error());
        return -1;
    }
    symbol = nx86_plat_find_symbol(out->library, NX86_PLUGIN_INIT_SYMBOL);
    if (symbol == NULL) {
        fprintf(stderr, "host: plugin '%s' exports no %s: %s\n", path,
                NX86_PLUGIN_INIT_SYMBOL, nx86_plat_last_error());
        nx86_plat_close_library(out->library);
        out->library = NULL;
        return -1;
    }
    memcpy(&init_fn, &symbol, sizeof(init_fn));

    memset(&out->plugin, 0, sizeof(out->plugin));
    out->plugin.struct_size = (uint32_t)sizeof(out->plugin);
    status = init_fn(host, &out->plugin);
    if (status != NX86_OK) {
        fprintf(stderr, "host: plugin '%s' init failed (%d)\n", path,
                (int)status);
        nx86_plat_close_library(out->library);
        out->library = NULL;
        return -1;
    }
    if (out->plugin.struct_size > (uint32_t)sizeof(out->plugin)) {
        out->plugin.struct_size = (uint32_t)sizeof(out->plugin);
    }
    if (NX86_VERSION_MAJOR(out->plugin.abi_version) != NX86_ABI_VERSION_MAJOR ||
        !NX86_HAS_FIELD(out->plugin.struct_size, nx86_plugin, shutdown)) {
        fprintf(stderr, "host: plugin '%s' ABI %u.%u incompatible with %u.%u\n",
                path,
                (unsigned)NX86_VERSION_MAJOR(out->plugin.abi_version),
                (unsigned)NX86_VERSION_MINOR(out->plugin.abi_version),
                (unsigned)NX86_ABI_VERSION_MAJOR,
                (unsigned)NX86_ABI_VERSION_MINOR);
        nx86_plat_close_library(out->library);
        out->library = NULL;
        return -1;
    }

    printf("host: loaded plugin id=%s name=%s abi=%u.%u caps=0x%x\n",
           out->plugin.id ? out->plugin.id : "(unnamed)",
           out->plugin.display_name ? out->plugin.display_name : "(unnamed)",
           (unsigned)NX86_VERSION_MAJOR(out->plugin.abi_version),
           (unsigned)NX86_VERSION_MINOR(out->plugin.abi_version),
           (unsigned)out->plugin.capabilities);
    out->started = 0;
    return 0;
}

/* ------------------------------------------------------------------ */
/* CLI                                                                 */
/* ------------------------------------------------------------------ */

static void usage(const char *argv0)
{
    printf("usage: %s [options] <plugin.so> [<plugin.so> ...]\n", argv0);
    printf("\n");
    printf("Loads nativex86 observation plugins (ABI %u.%u).\n",
           (unsigned)NX86_ABI_VERSION_MAJOR, (unsigned)NX86_ABI_VERSION_MINOR);
    printf("\n");
    printf("With no target, replays a fixed script of synthetic records.\n");
    printf("With --pid, inspects a process you own and reports\n");
    printf("metadata-only records for the exports the plugins watch.\n");
    printf("\n");
    printf("Options:\n");
    printf("  --pid N                observe process N (a positive integer,\n");
    printf("                         owned by the same user)\n");
    printf("  --i-own-this-process   required to inspect; you assert you own N\n");
    printf("                         and are authorized to inspect it\n");
    printf("  --no-live              read-only pass only (Windows is always\n");
    printf("                         read-only; live is unavailable there)\n");
    printf("  --max-events K         stop after K call-site records (default 16)\n");
    printf("  --max-seconds T        safety time budget (default 20)\n");
    printf("  --help                 this text\n");
    printf("\n");
    printf("Records describe program structure only: module bases, symbol\n");
    printf("names and addresses, and control-flow edges. No argument bytes,\n");
    printf("buffer contents, keys or return values are read or reported.\n");
}

/* Parse a --pid argument as a strict, positive process id. The whole
 * argument must be a base-10 integer with no leading sign, no trailing
 * text, and a value in [1, INT_MAX]. Returns 0 and writes *out on
 * success, -1 otherwise. "0", "-1", "12x" and "" all fail: a live pid is
 * always a positive integer, and an unparseable --pid must be an error,
 * never a silent fall-through to the synthetic (no-target) mode. */
static int parse_positive_pid(const char *s, long *out)
{
    char *end = NULL;
    long value;

    if (s == NULL || s[0] == '\0') {
        return -1;
    }
    /* Reject a leading sign or space outright so "-1" and "+7" never pass;
     * strtol would otherwise accept them. */
    if (s[0] < '1' || s[0] > '9') {
        return -1;
    }
    errno = 0;
    value = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') {
        return -1;
    }
    if (value <= 0 || value > (long)INT_MAX) {
        return -1;
    }
    *out = value;
    return 0;
}

/* Parse a safety-bound argument (--max-events / --max-seconds) as a
 * strict non-negative integer that fits in uint32_t. The whole argument
 * must be base-10 digits with no leading sign, no trailing text, and no
 * overflow. A value of 0 keeps its documented meaning (no event / no time
 * budget); a malformed value is an error, never a silent fall-through to
 * "unlimited". "abc", "-1", "5x" and "" all fail. Returns 0 and writes
 * *out on success, -1 otherwise. */
static int parse_nonneg_u32(const char *s, uint32_t *out)
{
    char *end = NULL;
    unsigned long value;

    if (s == NULL || s[0] == '\0') {
        return -1;
    }
    /* Reject a leading sign or space so "-1" and "+7" never pass; strtoul
     * would otherwise accept "-1" as a huge wrapped value read as
     * "unlimited". */
    if (s[0] < '0' || s[0] > '9') {
        return -1;
    }
    errno = 0;
    value = strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') {
        return -1;
    }
    if (value > 0xFFFFFFFFUL) {
        return -1;
    }
    *out = (uint32_t)value;
    return 0;
}

int main(int argc, char **argv)
{
    host_state state;
    nx86_host host;
    loaded_plugin plugins[NX86_HOST_MAX_PLUGINS];
    int n_plugins = 0;
    const char *plugin_paths[NX86_HOST_MAX_PLUGINS];
    int n_paths = 0;
    uint32_t sink_token = 0u;
    nx86_status status;
    int i;
    long pid = 0;
    int pid_set = 0;
    int own_confirmed = 0;
    int no_live = 0;
    uint32_t max_events = 16u;
    uint32_t max_seconds = 20u;
    int rc = 0;

    for (i = 1; i < argc; ++i) {
        const char *a = argv[i];
        if (strcmp(a, "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(a, "--pid") == 0 && i + 1 < argc) {
            if (parse_positive_pid(argv[++i], &pid) != 0) {
                fprintf(stderr,
                        "host: --pid must be a positive integer (got '%s')\n",
                        argv[i]);
                return 2;
            }
            pid_set = 1;
        } else if (strcmp(a, "--i-own-this-process") == 0) {
            own_confirmed = 1;
        } else if (strcmp(a, "--no-live") == 0) {
            no_live = 1;
        } else if (strcmp(a, "--max-events") == 0 && i + 1 < argc) {
            if (parse_nonneg_u32(argv[++i], &max_events) != 0) {
                fprintf(stderr,
                        "host: --max-events must be a non-negative integer "
                        "(got '%s')\n", argv[i]);
                return 2;
            }
        } else if (strcmp(a, "--max-seconds") == 0 && i + 1 < argc) {
            if (parse_nonneg_u32(argv[++i], &max_seconds) != 0) {
                fprintf(stderr,
                        "host: --max-seconds must be a non-negative integer "
                        "(got '%s')\n", argv[i]);
                return 2;
            }
        } else if (a[0] == '-') {
            fprintf(stderr, "host: unknown option '%s'\n", a);
            usage(argv[0]);
            return 2;
        } else {
            if (n_paths >= NX86_HOST_MAX_PLUGINS) {
                fprintf(stderr, "host: too many plugins (max %d)\n",
                        NX86_HOST_MAX_PLUGINS);
                return 2;
            }
            plugin_paths[n_paths++] = a;
        }
    }

    if (n_paths == 0) {
        usage(argv[0]);
        return 2;
    }

    memset(&state, 0, sizeof(state));
    nx86_bus_init(&state.bus);

    memset(&host, 0, sizeof(host));
    host.struct_size = (uint32_t)sizeof(host);
    host.abi_version = NX86_ABI_VERSION;
    host.host_ctx = &state;
    host.register_observer = host_register_observer;
    host.unregister_observer = host_unregister_observer;
    host.emit = host_emit;
    host.log = host_log;
    host.request_watch = host_request_watch;

    status = nx86_bus_register(&state.bus, NX86_EVENT_MASK_ALL,
                               host_console_sink, &state, &sink_token);
    if (status != NX86_OK) {
        fprintf(stderr, "host: cannot register console sink (%d)\n",
                (int)status);
        return 1;
    }

    /* Gate attachment before loading anything if the CLI is inconsistent. */
    if (pid_set) {
        uint32_t owner_id = 0u;
        int owned;
        if (!own_confirmed) {
            fprintf(stderr,
                    "host: inspecting a process requires "
                    "--i-own-this-process\n"
                    "host: (you assert you own PID %ld and are authorized to "
                    "inspect it)\n", pid);
            return 2;
        }
        owned = nx86_observe_owner_check((uint32_t)pid, &owner_id);
        if (owned < 0) {
            fprintf(stderr, "host: process %ld does not exist or cannot be "
                    "inspected\n", pid);
            return 1;
        }
        if (owned == 0) {
            fprintf(stderr,
                    "host: process %ld is owned by a different user; "
                    "refusing inspection\n", pid);
            return 1;
        }
        printf("host: target pid=%ld owned by the current user; backend: %s\n",
               pid, nx86_observe_backend_name());
    }

    for (i = 0; i < n_paths; ++i) {
        if (load_one_plugin(plugin_paths[i], &host, &plugins[n_plugins]) != 0) {
            rc = 1;
            goto cleanup;
        }
        n_plugins++;
    }

    nx86_bus_set_accepting(&state.bus, 1);

    for (i = 0; i < n_plugins; ++i) {
        if (plugins[i].plugin.start != NULL) {
            status = plugins[i].plugin.start(plugins[i].plugin.plugin_ctx);
            if (status != NX86_OK) {
                fprintf(stderr, "host: plugin '%s' start failed (%d)\n",
                        plugins[i].plugin.id ? plugins[i].plugin.id : "?",
                        (int)status);
                rc = 1;
                goto stop_all;
            }
        }
        plugins[i].started = 1;
    }

    if (pid_set) {
        nx86_observe_config cfg;
        const char *mode;
        memset(&cfg, 0, sizeof(cfg));
        cfg.pid = (uint32_t)pid;
        cfg.allow_live = no_live ? 0 : 1;
        cfg.max_call_events = max_events;
        cfg.max_seconds = max_seconds;
        if (!nx86_observe_live_supported()) {
            mode = " (read-only pass; live unavailable)";
        } else if (no_live) {
            mode = " (read-only pass)";
        } else {
            mode = "";
        }
        printf("host: watching %u export name(s); observing pid %ld%s\n",
               (unsigned)state.n_watches, pid, mode);
        status = nx86_observe_run(&state.bus, &cfg, state.watches,
                                  state.n_watches, host_log_level);
        if (status != NX86_OK) {
            /* A non-OK status means inspection failed or a requested live
             * pass could not complete cleanly. Never report success in that
             * case: fail the command so the exit code is non-zero. */
            fprintf(stderr, "host: observation ended with status %d\n",
                    (int)status);
            rc = 1;
        }
    } else {
        publish_sample_records(&state);
    }

stop_all:
    for (i = n_plugins - 1; i >= 0; --i) {
        if (plugins[i].started && plugins[i].plugin.stop != NULL) {
            plugins[i].plugin.stop(plugins[i].plugin.plugin_ctx);
        }
    }
    nx86_bus_set_accepting(&state.bus, 0);
    for (i = n_plugins - 1; i >= 0; --i) {
        if (plugins[i].plugin.shutdown != NULL) {
            plugins[i].plugin.shutdown(plugins[i].plugin.plugin_ctx);
        }
    }

cleanup:
    for (i = 0; i < n_plugins; ++i) {
        if (plugins[i].library != NULL) {
            nx86_plat_close_library(plugins[i].library);
        }
    }

    printf("host: published=%llu delivered=%llu sink_seen=%llu\n",
           (unsigned long long)state.bus.published,
           (unsigned long long)state.bus.delivered,
           (unsigned long long)state.sink_seen);
    printf("host: shutdown %s\n", rc == 0 ? "ok" : "with errors");
    return rc;
}
