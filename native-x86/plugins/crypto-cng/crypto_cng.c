/*
 * nativex86 observation plugin: Windows CNG (bcrypt.dll).
 *
 * Declares interest in well-known Cryptography API: Next Generation
 * export names and labels the generic records the host reports for them.
 * As with the OpenSSL plugin, it observes *that* a well-known entry was
 * reached and *where* it lives — never the buffers those functions move.
 * No plaintext, ciphertext, key, IV, argument or return value is seen or
 * reported. Content capture is out of scope.
 *
 * This source is portable: it uses only the plugin ABI and holds string
 * names, so it compiles on any platform. On Windows, the read-only host
 * backend resolves matching exports from the on-disk PE image. Live
 * entry/return observation remains unavailable on Windows. On other
 * platforms the plugin loads and stays idle unless a matching image is
 * present.
 */
#include "nativex86/plugin.h"

#include <stdio.h>
#include <string.h>

typedef struct cng_state {
    const nx86_host *host;
    uint32_t         token;
    uint64_t         observed;
} cng_state;

static cng_state g_state;

static nx86_str str_c(const char *s)
{
    nx86_str out;
    out.data = s;
    out.len = (uint32_t)strlen(s);
    out.reserved = 0u;
    return out;
}

static nx86_status watch(const nx86_host *host, const char *name,
                         uint32_t match_kind, uint32_t flags)
{
    nx86_watch_request req;
    memset(&req, 0, sizeof(req));
    req.struct_size = (uint32_t)sizeof(req);
    req.match_kind = match_kind;
    req.name = str_c(name);
    req.flags = flags;
    return host->request_watch(host->host_ctx, &req);
}

static const char *classify(const char *name, uint32_t len)
{
    if (len == 13 && memcmp(name, "BCryptEncrypt", 13) == 0) {
        return "CNG symmetric encrypt boundary";
    }
    if (len == 13 && memcmp(name, "BCryptDecrypt", 13) == 0) {
        return "CNG symmetric decrypt boundary";
    }
    if (len == 14 && memcmp(name, "BCryptSignHash", 14) == 0) {
        return "CNG signature boundary";
    }
    if (len >= 6 && strncmp(name, "BCrypt", 6) == 0) {
        return "CNG primitive";
    }
    return NULL;
}

static void report(const char *name, uint32_t name_len, const char *what,
                   const char *module, uint32_t module_len, uint64_t addr,
                   uint32_t phase)
{
    const char *label = classify(name, name_len);
    if (label == NULL) {
        return;
    }
    g_state.observed++;
    if (phase == NX86_CALL_PHASE_ENTER || phase == NX86_CALL_PHASE_RETURN) {
        printf("plugin.crypto-cng: %s %s [%s] %.*s in %.*s @0x%llx "
               "(metadata only)\n",
               label,
               phase == NX86_CALL_PHASE_ENTER ? "entered" : "returned",
               what, (int)name_len, name, (int)module_len, module,
               (unsigned long long)addr);
    } else {
        printf("plugin.crypto-cng: %s [%s] %.*s in %.*s @0x%llx\n",
               label, what, (int)name_len, name, (int)module_len, module,
               (unsigned long long)addr);
    }
}

static void NX86_CALL on_event(void *user_data,
                               const nx86_event_header *event)
{
    (void)user_data;
    if (event->kind == NX86_EVENT_SYMBOL &&
        event->struct_size >= (uint32_t)sizeof(nx86_event_symbol)) {
        const nx86_event_symbol *e = (const nx86_event_symbol *)event;
        report(e->symbol_name.data, e->symbol_name.len, "symbol",
               e->module_name.data, e->module_name.len, e->address,
               NX86_CALL_PHASE_NONE);
    } else if (event->kind == NX86_EVENT_CALL_SITE &&
               event->struct_size >= (uint32_t)sizeof(nx86_event_call_site)) {
        const nx86_event_call_site *e = (const nx86_event_call_site *)event;
        report(e->target_name.data, e->target_name.len, "call-site",
               e->module_name.data, e->module_name.len, e->target_address,
               e->phase);
    }
}

static nx86_status NX86_CALL cng_start(void *plugin_ctx)
{
    cng_state *state = (cng_state *)plugin_ctx;
    const nx86_host *host = state->host;

    if (host == NULL) {
        return NX86_ERR_INVALID_ARG;
    }

    if (!NX86_HAS_FIELD(host->struct_size, nx86_host, request_watch)) {
        host->log(host->host_ctx, NX86_LOG_WARN,
                  "host predates watch support; crypto-cng is passive");
    } else {
        (void)watch(host, "BCryptEncrypt", NX86_MATCH_EXACT,
                    NX86_WATCH_SYMBOL | NX86_WATCH_CALL_SITE);
        (void)watch(host, "BCryptDecrypt", NX86_MATCH_EXACT,
                    NX86_WATCH_SYMBOL | NX86_WATCH_CALL_SITE);
        (void)watch(host, "BCryptSignHash", NX86_MATCH_EXACT,
                    NX86_WATCH_SYMBOL | NX86_WATCH_CALL_SITE);
    }

    return host->register_observer(
        host->host_ctx,
        NX86_EVENT_MASK(NX86_EVENT_SYMBOL) |
            NX86_EVENT_MASK(NX86_EVENT_CALL_SITE),
        on_event, state, &state->token);
}

static void NX86_CALL cng_stop(void *plugin_ctx)
{
    cng_state *state = (cng_state *)plugin_ctx;
    if (state == NULL || state->host == NULL) {
        return;
    }
    if (state->token != 0u) {
        (void)state->host->unregister_observer(state->host->host_ctx,
                                               state->token);
        state->token = 0u;
    }
    printf("plugin.crypto-cng: stop after %llu record(s)\n",
           (unsigned long long)state->observed);
}

static void NX86_CALL cng_shutdown(void *plugin_ctx)
{
    cng_state *state = (cng_state *)plugin_ctx;
    if (state != NULL) {
        memset(state, 0, sizeof(*state));
    }
}

NX86_EXPORT nx86_status NX86_CALL nx86_plugin_init(const nx86_host *host,
                                                   nx86_plugin *out_plugin)
{
    uint32_t written;

    if (host == NULL || out_plugin == NULL) {
        return NX86_ERR_INVALID_ARG;
    }
    if (NX86_VERSION_MAJOR(host->abi_version) != NX86_ABI_VERSION_MAJOR) {
        return NX86_ERR_ABI_MISMATCH;
    }
    if (!NX86_HAS_FIELD(host->struct_size, nx86_host, log)) {
        return NX86_ERR_ABI_MISMATCH;
    }

    written = (uint32_t)sizeof(*out_plugin);
    if (written > out_plugin->struct_size) {
        written = out_plugin->struct_size;
    }
    if (!NX86_HAS_FIELD(written, nx86_plugin, shutdown)) {
        return NX86_ERR_ABI_MISMATCH;
    }

    memset(&g_state, 0, sizeof(g_state));
    g_state.host = host;

    memset(out_plugin, 0, written);
    out_plugin->struct_size = written;
    out_plugin->abi_version = NX86_ABI_VERSION;
    out_plugin->id = "crypto-cng";
    out_plugin->display_name = "Windows CNG export observer (metadata only)";
    out_plugin->plugin_version = NX86_MAKE_VERSION(0u, 1u);
    out_plugin->capabilities = NX86_CAP_CONSUMES_EVENTS;
    out_plugin->plugin_ctx = &g_state;
    out_plugin->start = cng_start;
    out_plugin->stop = cng_stop;
    out_plugin->shutdown = cng_shutdown;
    return NX86_OK;
}
