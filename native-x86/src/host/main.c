/*
 * nativex86 host stub.
 *
 * Loads one plugin through the versioned C ABI in
 * include/nativex86/plugin.h, hands it a host interface, replays a fixed
 * script of synthetic records, and shuts the plugin down again.
 *
 * It deliberately does nothing else. There is no process attachment, no
 * memory reading, no code patching and no instrumentation of any kind:
 * the records below are literals compiled into this file. The point of
 * the stub is to prove the ABI links, loads and dispatches.
 */
#include "nativex86/plugin.h"

#include "event_bus.h"
#include "platform.h"

#include <stdio.h>
#include <string.h>

typedef struct host_state {
    nx86_event_bus bus;
    uint64_t       sink_seen;
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

/* Console sink so plugin-emitted events are visible in the smoke test. */
static void NX86_CALL host_console_sink(void *user_data,
                                        const nx86_event_header *event)
{
    host_state *state = (host_state *)user_data;
    state->sink_seen++;
    printf("host: sink saw seq=%llu kind=%s size=%u",
           (unsigned long long)event->seq, kind_name(event->kind),
           (unsigned)event->struct_size);

    if (event->kind == NX86_EVENT_NOTE &&
        event->struct_size >= (uint32_t)sizeof(nx86_event_note)) {
        const nx86_event_note *note = (const nx86_event_note *)event;
        printf(" source=%.*s text=%.*s", (int)note->source.len,
               note->source.data != NULL ? note->source.data : "",
               (int)note->text.len,
               note->text.data != NULL ? note->text.data : "");
    }
    printf("\n");
}

/* ------------------------------------------------------------------ */
/* Synthetic record script                                             */
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
    (void)nx86_bus_publish(&state->bus, &call_site.header);
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

static void usage(const char *argv0)
{
    printf("usage: %s <plugin-shared-library>\n", argv0);
    printf("  Loads one nativex86 plugin (ABI %u.%u) and replays a fixed\n",
           (unsigned)NX86_ABI_VERSION_MAJOR, (unsigned)NX86_ABI_VERSION_MINOR);
    printf("  script of synthetic records. No process is inspected.\n");
}

int main(int argc, char **argv)
{
    host_state state;
    nx86_host host;
    nx86_plugin plugin;
    nx86_plugin_init_fn init_fn;
    void *library;
    void *symbol;
    uint32_t sink_token = 0u;
    nx86_status status;

    if (argc != 2 || strcmp(argv[1], "--help") == 0) {
        usage(argv[0]);
        return argc == 2 ? 0 : 2;
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

    status = nx86_bus_register(&state.bus, NX86_EVENT_MASK_ALL,
                               host_console_sink, &state, &sink_token);
    if (status != NX86_OK) {
        fprintf(stderr, "host: cannot register console sink (%d)\n",
                (int)status);
        return 1;
    }

    library = nx86_plat_open_library(argv[1]);
    if (library == NULL) {
        fprintf(stderr, "host: cannot load plugin '%s': %s\n", argv[1],
                nx86_plat_last_error());
        return 1;
    }

    symbol = nx86_plat_find_symbol(library, NX86_PLUGIN_INIT_SYMBOL);
    if (symbol == NULL) {
        fprintf(stderr, "host: plugin '%s' exports no %s: %s\n", argv[1],
                NX86_PLUGIN_INIT_SYMBOL, nx86_plat_last_error());
        nx86_plat_close_library(library);
        return 1;
    }

    /* Casting an object pointer to a function pointer is not strictly
     * conforming C, but it is what every dynamic loader hands back. */
    memcpy(&init_fn, &symbol, sizeof(init_fn));

    memset(&plugin, 0, sizeof(plugin));
    /* Tell the plugin how many bytes it may write into our object. */
    plugin.struct_size = (uint32_t)sizeof(plugin);
    status = init_fn(&host, &plugin);
    if (status != NX86_OK) {
        fprintf(stderr, "host: plugin init failed (%d)\n", (int)status);
        nx86_plat_close_library(library);
        return 1;
    }
    /* A newer plugin may report a larger struct than this host knows:
     * keep our own size and ignore any unknown tail. */
    if (plugin.struct_size > (uint32_t)sizeof(plugin)) {
        plugin.struct_size = (uint32_t)sizeof(plugin);
    }
    /* Reject only a major mismatch or a prefix too small to hold the
     * fields this host reads (through the callbacks). */
    if (NX86_VERSION_MAJOR(plugin.abi_version) != NX86_ABI_VERSION_MAJOR ||
        !NX86_HAS_FIELD(plugin.struct_size, nx86_plugin, shutdown)) {
        fprintf(stderr, "host: plugin ABI %u.%u is incompatible with %u.%u\n",
                (unsigned)NX86_VERSION_MAJOR(plugin.abi_version),
                (unsigned)NX86_VERSION_MINOR(plugin.abi_version),
                (unsigned)NX86_ABI_VERSION_MAJOR,
                (unsigned)NX86_ABI_VERSION_MINOR);
        nx86_plat_close_library(library);
        return 1;
    }

    printf("host: loaded plugin id=%s name=%s abi=%u.%u caps=0x%x\n",
           plugin.id != NULL ? plugin.id : "(unnamed)",
           plugin.display_name != NULL ? plugin.display_name : "(unnamed)",
           (unsigned)NX86_VERSION_MAJOR(plugin.abi_version),
           (unsigned)NX86_VERSION_MINOR(plugin.abi_version),
           (unsigned)plugin.capabilities);

    /* Open the delivery window: the plugin may emit from start onward. */
    nx86_bus_set_accepting(&state.bus, 1);

    if (plugin.start != NULL) {
        status = plugin.start(plugin.plugin_ctx);
        if (status != NX86_OK) {
            fprintf(stderr, "host: plugin start failed (%d)\n", (int)status);
            nx86_bus_set_accepting(&state.bus, 0);
            if (plugin.shutdown != NULL) {
                plugin.shutdown(plugin.plugin_ctx);
            }
            nx86_plat_close_library(library);
            return 1;
        }
    }

    publish_sample_records(&state);

    if (plugin.stop != NULL) {
        plugin.stop(plugin.plugin_ctx);
    }
    /* Close the window: no event authored after stop reaches an observer,
     * so an emit from shutdown is rejected. */
    nx86_bus_set_accepting(&state.bus, 0);
    if (plugin.shutdown != NULL) {
        plugin.shutdown(plugin.plugin_ctx);
    }
    nx86_plat_close_library(library);

    printf("host: published=%llu delivered=%llu sink_seen=%llu\n",
           (unsigned long long)state.bus.published,
           (unsigned long long)state.bus.delivered,
           (unsigned long long)state.sink_seen);
    printf("host: shutdown ok\n");
    return 0;
}
