/*
 * Sample nativex86 plugin.
 *
 * Emits one note event ("hello") when it starts and prints every record
 * the host delivers. It exists to exercise the plugin ABI end to end; it
 * observes nothing and touches no other process.
 */
#include "nativex86/plugin.h"

#include <stdio.h>
#include <string.h>

typedef struct hello_state {
    const nx86_host *host;
    uint32_t         token;
    uint64_t         received;
} hello_state;

static hello_state g_state;

static nx86_str str_lit(const char *s)
{
    nx86_str out;
    out.data = s;
    out.len = (uint32_t)strlen(s);
    out.reserved = 0u;
    return out;
}

static void print_str(const char *label, const nx86_str *s)
{
    printf(" %s=%.*s", label, (int)s->len, s->data != NULL ? s->data : "");
}

static void NX86_CALL hello_on_event(void *user_data,
                                     const nx86_event_header *event)
{
    hello_state *state = (hello_state *)user_data;
    state->received++;

    printf("plugin.hello: event seq=%llu kind=%u",
           (unsigned long long)event->seq, (unsigned)event->kind);

    switch (event->kind) {
    case NX86_EVENT_MODULE_LOAD:
        if (event->struct_size >= (uint32_t)sizeof(nx86_event_module_load)) {
            const nx86_event_module_load *e =
                (const nx86_event_module_load *)event;
            print_str("module", &e->name);
            printf(" base=0x%llx size=0x%llx machine=%u",
                   (unsigned long long)e->base_address,
                   (unsigned long long)e->image_size, (unsigned)e->machine);
        }
        break;
    case NX86_EVENT_SYMBOL:
        if (event->struct_size >= (uint32_t)sizeof(nx86_event_symbol)) {
            const nx86_event_symbol *e = (const nx86_event_symbol *)event;
            print_str("module", &e->module_name);
            print_str("symbol", &e->symbol_name);
            printf(" addr=0x%llx", (unsigned long long)e->address);
        }
        break;
    case NX86_EVENT_CALL_SITE:
        if (event->struct_size >= (uint32_t)sizeof(nx86_event_call_site)) {
            const nx86_event_call_site *e =
                (const nx86_event_call_site *)event;
            print_str("module", &e->module_name);
            print_str("target", &e->target_name);
            printf(" site=0x%llx kind=%u",
                   (unsigned long long)e->site_address,
                   (unsigned)e->site_kind);
        }
        break;
    case NX86_EVENT_NOTE:
        if (event->struct_size >= (uint32_t)sizeof(nx86_event_note)) {
            const nx86_event_note *e = (const nx86_event_note *)event;
            print_str("source", &e->source);
            print_str("text", &e->text);
        }
        break;
    default:
        break;
    }
    printf("\n");
}

static nx86_status NX86_CALL hello_start(void *plugin_ctx)
{
    hello_state *state = (hello_state *)plugin_ctx;
    nx86_event_note note;
    nx86_status status;

    if (state == NULL || state->host == NULL) {
        return NX86_ERR_INVALID_ARG;
    }

    status = state->host->register_observer(
        state->host->host_ctx,
        NX86_EVENT_MASK(NX86_EVENT_MODULE_LOAD) |
            NX86_EVENT_MASK(NX86_EVENT_SYMBOL) |
            NX86_EVENT_MASK(NX86_EVENT_CALL_SITE),
        hello_on_event, state, &state->token);
    if (status != NX86_OK) {
        return status;
    }

    memset(&note, 0, sizeof(note));
    note.header.struct_size = (uint32_t)sizeof(note);
    note.header.kind = NX86_EVENT_NOTE;
    note.level = NX86_LOG_INFO;
    note.source = str_lit("hello");
    note.text = str_lit("hello from the sample plugin");
    (void)state->host->emit(state->host->host_ctx, &note.header);

    state->host->log(state->host->host_ctx, NX86_LOG_INFO,
                     "plugin.hello started");
    return NX86_OK;
}

static void NX86_CALL hello_stop(void *plugin_ctx)
{
    hello_state *state = (hello_state *)plugin_ctx;
    if (state == NULL || state->host == NULL) {
        return;
    }
    if (state->token != 0u) {
        (void)state->host->unregister_observer(state->host->host_ctx,
                                               state->token);
        state->token = 0u;
    }
    printf("plugin.hello: stop after %llu events\n",
           (unsigned long long)state->received);
}

static void NX86_CALL hello_shutdown(void *plugin_ctx)
{
    hello_state *state = (hello_state *)plugin_ctx;
    if (state != NULL) {
        memset(state, 0, sizeof(*state));
    }
}

NX86_EXPORT nx86_status NX86_CALL nx86_plugin_init(const nx86_host *host,
                                                   nx86_plugin *out_plugin)
{
    uint32_t capacity;
    uint32_t written;

    if (host == NULL || out_plugin == NULL) {
        return NX86_ERR_INVALID_ARG;
    }
    /* Accept any matching major; a differing minor is allowed. Only read
     * the host fields this plugin actually calls, and require the host's
     * prefix to cover them rather than the whole (possibly newer) struct. */
    if (NX86_VERSION_MAJOR(host->abi_version) != NX86_ABI_VERSION_MAJOR) {
        return NX86_ERR_ABI_MISMATCH;
    }
    if (!NX86_HAS_FIELD(host->struct_size, nx86_host, log)) {
        return NX86_ERR_ABI_MISMATCH;
    }

    /* out_plugin->struct_size is the byte capacity the host owns. Never
     * write beyond it, even though this plugin's nx86_plugin might be
     * larger than an older host expects. The host reads the common
     * prefix; if it cannot even hold the callbacks, refuse. */
    capacity = out_plugin->struct_size;
    written = (uint32_t)sizeof(*out_plugin);
    if (written > capacity) {
        written = capacity;
    }
    if (!NX86_HAS_FIELD(written, nx86_plugin, shutdown)) {
        return NX86_ERR_ABI_MISMATCH;
    }

    memset(&g_state, 0, sizeof(g_state));
    g_state.host = host;

    memset(out_plugin, 0, written);
    out_plugin->struct_size = written;
    out_plugin->abi_version = NX86_ABI_VERSION;
    out_plugin->id = "hello";
    out_plugin->display_name = "nativex86 sample plugin";
    out_plugin->plugin_version = NX86_MAKE_VERSION(0u, 1u);
    out_plugin->capabilities = NX86_CAP_CONSUMES_EVENTS |
                               NX86_CAP_PRODUCES_EVENTS;
    out_plugin->plugin_ctx = &g_state;
    out_plugin->start = hello_start;
    out_plugin->stop = hello_stop;
    out_plugin->shutdown = hello_shutdown;
    return NX86_OK;
}
