/*
 * Focused checks for the two ABI contracts that a plain smoke run does
 * not exercise:
 *
 *   1. minor-version prefix negotiation, in both directions, proving a
 *      newer peer never writes past an older peer's object; and
 *   2. the event-bus delivery window, proving nothing is dispatched
 *      outside the start..stop lifecycle.
 *
 * No process is observed; every value here is synthetic. The program
 * prints "abi-checks: PASS" and exits 0 when every check holds.
 */
#include "nativex86/plugin.h"

#include "event_bus.h"

#include <stdio.h>
#include <string.h>

static int g_failures;

#define CHECK(cond, msg)                                        \
    do {                                                        \
        if (!(cond)) {                                          \
            printf("abi-checks: FAIL: %s\n", (msg));            \
            g_failures++;                                       \
        }                                                       \
    } while (0)

/* ------------------------------------------------------------------ */
/* 1a. Newer plugin, older host: the plugin must clamp to the capacity  */
/*     the host advertised and never touch bytes past it.               */
/* ------------------------------------------------------------------ */

/* A plugin built against a hypothetical later minor that appended one
 * field to nx86_plugin, so its own sizeof is larger than this host's. */
typedef struct newer_plugin {
    nx86_plugin base;
    uint64_t    appended; /* a field a future minor added */
} newer_plugin;

static nx86_status newer_plugin_init(nx86_plugin *out_plugin)
{
    uint32_t capacity = out_plugin->struct_size; /* host-owned byte count */
    uint32_t written = (uint32_t)sizeof(newer_plugin);

    if (written > capacity) {
        written = capacity; /* never write past what the host owns */
    }
    if (!NX86_HAS_FIELD(written, nx86_plugin, shutdown)) {
        return NX86_ERR_ABI_MISMATCH;
    }

    memset(out_plugin, 0, written);
    out_plugin->struct_size = written;
    out_plugin->abi_version = NX86_ABI_VERSION;
    out_plugin->id = "newer";
    /* Only set the appended field when the host is new enough to hold it. */
    if (NX86_HAS_FIELD(written, newer_plugin, appended)) {
        ((newer_plugin *)out_plugin)->appended = 0x1122334455667788ULL;
    }
    return NX86_OK;
}

static void check_newer_plugin_into_older_host(void)
{
    /* Emulate an older host: an nx86_plugin object with a sentinel word
     * immediately after it. The plugin is told the capacity is exactly
     * the old struct, so it must leave the sentinel untouched. */
    struct {
        nx86_plugin plugin;
        uint32_t    sentinel;
    } holder;
    nx86_status status;

    memset(&holder, 0, sizeof(holder));
    holder.sentinel = 0xA5A5A5A5u;
    holder.plugin.struct_size = (uint32_t)sizeof(holder.plugin);

    status = newer_plugin_init(&holder.plugin);

    CHECK(status == NX86_OK, "newer plugin should init into an older host");
    CHECK(holder.sentinel == 0xA5A5A5A5u,
          "newer plugin overwrote memory past the host's object");
    CHECK(holder.plugin.struct_size == (uint32_t)sizeof(holder.plugin),
          "negotiated size should be the host's own struct size");
}

/* ------------------------------------------------------------------ */
/* 1b. Older plugin, newer host: the plugin fills a smaller prefix; the */
/*     host keeps its own size and ignores the (absent) tail.           */
/* ------------------------------------------------------------------ */

static void check_older_plugin_into_newer_host(void)
{
    /* Emulate a newer host whose nx86_plugin is larger than the plugin's:
     * a buffer bigger than sizeof(nx86_plugin) with a trailing sentinel. */
    unsigned char buffer[sizeof(nx86_plugin) + 32];
    nx86_plugin *plugin = (nx86_plugin *)buffer;
    uint32_t host_capacity = (uint32_t)sizeof(buffer);
    uint32_t readable;

    memset(buffer, 0, sizeof(buffer));
    buffer[sizeof(nx86_plugin)] = 0x5Au; /* sentinel just past the old size */

    /* The plugin only knows the 0.1 struct; it writes that much. */
    plugin->struct_size = host_capacity; /* host advertises its capacity */
    {
        uint32_t written = (uint32_t)sizeof(nx86_plugin);
        if (written > plugin->struct_size) {
            written = plugin->struct_size;
        }
        memset(plugin, 0, written);
        plugin->struct_size = written;
        plugin->abi_version = NX86_ABI_VERSION;
    }

    /* Host side: keep its own size, read only the common prefix. */
    readable = plugin->struct_size;
    if (readable > host_capacity) {
        readable = host_capacity;
    }

    CHECK(plugin->struct_size == (uint32_t)sizeof(nx86_plugin),
          "older plugin should report its own smaller size");
    CHECK(readable == (uint32_t)sizeof(nx86_plugin),
          "common prefix should be the smaller of the two structs");
    CHECK(buffer[sizeof(nx86_plugin)] == 0x5Au,
          "older plugin wrote into bytes the host did not offer");
}

/* ------------------------------------------------------------------ */
/* 1c. The shipped sample plugin honours a capacity smaller than its    */
/*     own struct without writing past it.                              */
/* ------------------------------------------------------------------ */

extern nx86_status NX86_CALL nx86_plugin_init(const nx86_host *host,
                                              nx86_plugin *out_plugin);

static void check_sample_plugin_respects_capacity(void)
{
    nx86_host host;
    struct {
        nx86_plugin plugin;
        uint32_t    sentinel;
    } holder;
    nx86_status status;

    memset(&host, 0, sizeof(host));
    host.struct_size = (uint32_t)sizeof(host);
    host.abi_version = NX86_ABI_VERSION;

    /* Full capacity: init succeeds and the sentinel is untouched. */
    memset(&holder, 0, sizeof(holder));
    holder.sentinel = 0xC3C3C3C3u;
    holder.plugin.struct_size = (uint32_t)sizeof(holder.plugin);
    status = nx86_plugin_init(&host, &holder.plugin);
    CHECK(status == NX86_OK, "sample plugin should init at full capacity");
    CHECK(holder.sentinel == 0xC3C3C3C3u,
          "sample plugin overwrote memory past the host's object");
    CHECK(holder.plugin.struct_size == (uint32_t)sizeof(nx86_plugin),
          "sample plugin should report the negotiated size");

    /* Too-small capacity (cannot hold the callbacks): refuse cleanly and
     * still leave the sentinel intact. */
    memset(&holder, 0, sizeof(holder));
    holder.sentinel = 0xC3C3C3C3u;
    holder.plugin.struct_size = (uint32_t)offsetof(nx86_plugin, start);
    status = nx86_plugin_init(&host, &holder.plugin);
    CHECK(status == NX86_ERR_ABI_MISMATCH,
          "sample plugin should refuse a capacity below its callbacks");
    CHECK(holder.sentinel == 0xC3C3C3C3u,
          "sample plugin wrote past a too-small capacity");
}

/* ------------------------------------------------------------------ */
/* 2. Lifecycle gate: publish/republish deliver nothing while closed.   */
/* ------------------------------------------------------------------ */

static uint64_t g_delivered;

static void NX86_CALL count_sink(void *user_data,
                                 const nx86_event_header *event)
{
    (void)event;
    (*(uint64_t *)user_data)++;
}

static void check_lifecycle_gate(void)
{
    nx86_event_bus bus;
    nx86_event_note note;
    uint32_t token = 0u;
    nx86_status status;

    nx86_bus_init(&bus);
    status = nx86_bus_register(&bus, NX86_EVENT_MASK_ALL, count_sink,
                               &g_delivered, &token);
    CHECK(status == NX86_OK, "observer registration should succeed");

    memset(&note, 0, sizeof(note));
    note.header.struct_size = (uint32_t)sizeof(note);
    note.header.kind = NX86_EVENT_NOTE;

    /* Closed by default: publish is rejected and reaches no observer. */
    g_delivered = 0u;
    status = nx86_bus_publish(&bus, &note.header);
    CHECK(status == NX86_ERR_LIFECYCLE,
          "publish before start should return NX86_ERR_LIFECYCLE");
    CHECK(g_delivered == 0u, "no event should be delivered while closed");
    status = nx86_bus_republish(&bus, &note.header);
    CHECK(status == NX86_ERR_LIFECYCLE,
          "republish before start should return NX86_ERR_LIFECYCLE");
    CHECK(g_delivered == 0u, "no event should be republished while closed");

    /* Open: delivery works. */
    nx86_bus_set_accepting(&bus, 1);
    g_delivered = 0u;
    status = nx86_bus_publish(&bus, &note.header);
    CHECK(status == NX86_OK, "publish inside the window should succeed");
    CHECK(g_delivered == 1u, "event should be delivered inside the window");

    /* Closed again (after stop): delivery is rejected once more. */
    nx86_bus_set_accepting(&bus, 0);
    g_delivered = 0u;
    status = nx86_bus_publish(&bus, &note.header);
    CHECK(status == NX86_ERR_LIFECYCLE,
          "publish after stop should return NX86_ERR_LIFECYCLE");
    CHECK(g_delivered == 0u, "no event should be delivered after stop");
}

/* ------------------------------------------------------------------ */
/* 3. Header stamping never labels a record with a host pid.            */
/* ------------------------------------------------------------------ */

static void check_stamp_leaves_process_id_zero(void)
{
    nx86_event_bus bus;
    nx86_event_note note;

    nx86_bus_init(&bus);
    memset(&note, 0, sizeof(note));
    note.header.process_id = 0xDEADBEEFu; /* must be cleared, not kept */
    nx86_bus_stamp(&bus, &note.header, (uint32_t)sizeof(note),
                   NX86_EVENT_NOTE);
    CHECK(note.header.process_id == 0u,
          "stamp should leave process_id zero for a no-target record");
    CHECK(note.header.seq == 1u, "stamp should assign the first seq");
}

int main(void)
{
    g_failures = 0;

    check_newer_plugin_into_older_host();
    check_older_plugin_into_newer_host();
    check_sample_plugin_respects_capacity();
    check_lifecycle_gate();
    check_stamp_leaves_process_id_zero();

    if (g_failures != 0) {
        printf("abi-checks: FAIL (%d checks failed)\n", g_failures);
        return 1;
    }
    printf("abi-checks: PASS\n");
    return 0;
}
