/*
 * nativex86 plugin ABI - version 0.1 (experimental, unstable).
 *
 * A small C ABI between a user-mode host process and observation plugins.
 * The ABI is deliberately free of any JVM / JNI concept: it describes
 * modules, symbols and call sites of an x86 process image only. Consumers
 * that care about Java (see native-x86/bridge-notes.md) live on the other
 * side of this boundary and translate records themselves.
 *
 * Specification: docs/plugin-abi.md
 * Scope + non-goals: docs/native-x86-module.md
 *
 * C99. Depends on <stddef.h> and <stdint.h> only.
 */
#ifndef NATIVEX86_PLUGIN_H
#define NATIVEX86_PLUGIN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Versioning                                                          */
/* ------------------------------------------------------------------ */

#define NX86_ABI_VERSION_MAJOR 0u
#define NX86_ABI_VERSION_MINOR 2u

#define NX86_MAKE_VERSION(major, minor) \
    ((uint32_t)(((uint32_t)(major) << 16) | ((uint32_t)(minor) & 0xFFFFu)))

#define NX86_ABI_VERSION \
    NX86_MAKE_VERSION(NX86_ABI_VERSION_MAJOR, NX86_ABI_VERSION_MINOR)

#define NX86_VERSION_MAJOR(v) ((uint32_t)(v) >> 16)
#define NX86_VERSION_MINOR(v) ((uint32_t)(v) & 0xFFFFu)

/*
 * Compatibility rule: the major version must match exactly. A host may
 * load a plugin whose minor version differs; both sides then negotiate
 * per-struct using the struct_size field that starts every versioned
 * record.
 *
 * Prefix negotiation: a struct carrying `avail` valid bytes contains a
 * given field only when the field's end offset is within `avail`. Read a
 * field a differing minor version might not carry only after this check;
 * never read or write past the size the peer actually provided.
 */
#define NX86_HAS_FIELD(avail, type, field)                    \
    ((uint32_t)(avail) >=                                     \
     (uint32_t)(offsetof(type, field) + sizeof(((type *)0)->field)))

/* ------------------------------------------------------------------ */
/* Linkage                                                             */
/* ------------------------------------------------------------------ */

#if defined(_WIN32)
#  define NX86_EXPORT __declspec(dllexport)
#else
#  define NX86_EXPORT __attribute__((visibility("default")))
#endif

/* All ABI function pointers use the platform's default C calling
 * convention; 32-bit x86 hosts must build both sides with cdecl. */
#define NX86_CALL

/* ------------------------------------------------------------------ */
/* Status codes                                                        */
/* ------------------------------------------------------------------ */

typedef int32_t nx86_status;

#define NX86_OK                 ((nx86_status)0)
#define NX86_ERR_ABI_MISMATCH   ((nx86_status)-1)
#define NX86_ERR_INVALID_ARG    ((nx86_status)-2)
#define NX86_ERR_UNSUPPORTED    ((nx86_status)-3)
#define NX86_ERR_NO_MEMORY      ((nx86_status)-4)
#define NX86_ERR_NOT_FOUND      ((nx86_status)-5)
#define NX86_ERR_INTERNAL       ((nx86_status)-6)
#define NX86_ERR_LIFECYCLE      ((nx86_status)-7) /* emit outside start..stop */

/* ------------------------------------------------------------------ */
/* Log levels                                                          */
/* ------------------------------------------------------------------ */

#define NX86_LOG_DEBUG 10u
#define NX86_LOG_INFO  20u
#define NX86_LOG_WARN  30u
#define NX86_LOG_ERROR 40u

/* ------------------------------------------------------------------ */
/* Primitive record types                                              */
/* ------------------------------------------------------------------ */

/*
 * Borrowed UTF-8 text. `data` is owned by the producer and is only valid
 * for the duration of the call that carried it; a receiver that needs the
 * text afterwards must copy it. `data` is not required to be
 * NUL-terminated; `len` is authoritative.
 */
typedef struct nx86_str {
    const char *data;
    uint32_t    len;
    uint32_t    reserved;
} nx86_str;

/* Image machine type of an observed module. */
#define NX86_MACHINE_UNKNOWN 0u
#define NX86_MACHINE_X86_32  1u
#define NX86_MACHINE_X86_64  2u

/* How a symbol record was obtained. */
#define NX86_SYMBOL_UNKNOWN 0u
#define NX86_SYMBOL_EXPORT  1u
#define NX86_SYMBOL_IMPORT  2u
#define NX86_SYMBOL_DEBUG   3u  /* from a symbol file, not the image itself */

/* Shape of an observed call site. */
#define NX86_CALL_SITE_UNKNOWN  0u
#define NX86_CALL_SITE_DIRECT   1u  /* call rel32 */
#define NX86_CALL_SITE_INDIRECT 2u  /* call [reg], call [rip+disp] */
#define NX86_CALL_SITE_THUNK    3u  /* import thunk / PLT entry */

/*
 * When a call site was observed at runtime, this says at which point it
 * was seen. Added in ABI 0.2; the `phase` field of nx86_event_call_site
 * is zero (NONE) for a purely structural record recovered from an image
 * rather than a live process. A phase never carries a return value, an
 * argument, or any buffer: it is one bit of control-flow position.
 */
#define NX86_CALL_PHASE_NONE   0u  /* structural record; not observed live */
#define NX86_CALL_PHASE_ENTER  1u  /* control reached the callee's entry */
#define NX86_CALL_PHASE_RETURN 2u  /* control returned to the caller */

/* ------------------------------------------------------------------ */
/* Events                                                              */
/* ------------------------------------------------------------------ */

typedef uint32_t nx86_event_kind;

#define NX86_EVENT_NOTE          1u  /* plugin- or host-authored message */
#define NX86_EVENT_MODULE_LOAD   2u
#define NX86_EVENT_MODULE_UNLOAD 3u
#define NX86_EVENT_SYMBOL        4u
#define NX86_EVENT_CALL_SITE     5u

/* Subscription mask bits; bit N corresponds to event kind N. */
#define NX86_EVENT_MASK(kind) ((uint32_t)1u << (kind))
#define NX86_EVENT_MASK_ALL   0xFFFFFFFFu

/*
 * Every event begins with this header. `struct_size` is the size of the
 * whole concrete event struct, so a receiver compiled against an older
 * minor version can safely read the prefix it knows and skip the rest.
 */
typedef struct nx86_event_header {
    uint32_t        struct_size;
    nx86_event_kind kind;
    uint64_t        seq;           /* monotonic per host, starts at 1 */
    uint64_t        timestamp_ns;  /* wall clock, nanoseconds since epoch */
    uint32_t        process_id;    /* observed process, 0 if not applicable */
    uint32_t        thread_id;     /* observed thread, 0 if not tracked */
} nx86_event_header;

/*
 * A short, human-readable diagnostic or status message. `text` is
 * host/status text only: a note is not a data channel and must never be
 * used to smuggle argument bytes, buffer contents, keys or any other
 * program data past the metadata-only record model. A host may reject a
 * note whose `text` is too long to be a status string.
 */
typedef struct nx86_event_note {
    nx86_event_header header;
    uint32_t          level;       /* NX86_LOG_* */
    uint32_t          reserved;
    nx86_str          source;      /* emitting component id */
    nx86_str          text;        /* status text only, not a data channel */
} nx86_event_note;

typedef struct nx86_event_module_load {
    nx86_event_header header;
    nx86_str          path;        /* filesystem path, may be empty */
    nx86_str          name;        /* base name as the loader knows it */
    uint64_t          base_address;
    uint64_t          image_size;
    uint32_t          machine;     /* NX86_MACHINE_* */
    uint32_t          flags;       /* reserved, must be 0 in ABI 0.1 */
} nx86_event_module_load;

typedef struct nx86_event_module_unload {
    nx86_event_header header;
    nx86_str          name;
    uint64_t          base_address;
} nx86_event_module_unload;

typedef struct nx86_event_symbol {
    nx86_event_header header;
    nx86_str          module_name;
    nx86_str          symbol_name;
    uint64_t          module_base;
    uint64_t          address;     /* absolute address in the observed image */
    uint32_t          binding;     /* NX86_SYMBOL_* */
    uint32_t          ordinal;     /* PE ordinal, 0 when unknown */
} nx86_event_symbol;

/*
 * A call site is a *description* of one call location: where it is, and
 * where it points. It records program structure, not argument values or
 * buffer contents.
 */
typedef struct nx86_event_call_site {
    nx86_event_header header;
    nx86_str          module_name;
    nx86_str          target_name;    /* resolved callee, may be empty */
    uint64_t          site_address;   /* address of the call instruction */
    uint64_t          target_address; /* 0 when unresolved */
    uint64_t          module_base;
    uint32_t          site_kind;      /* NX86_CALL_SITE_* */
    uint32_t          phase;          /* NX86_CALL_PHASE_* (ABI 0.2+) */
} nx86_event_call_site;

/* ------------------------------------------------------------------ */
/* Watch requests (ABI 0.2+)                                           */
/* ------------------------------------------------------------------ */

/*
 * How a watch name is matched against an observed export.
 */
#define NX86_MATCH_EXACT  1u  /* whole symbol name equals `name` */
#define NX86_MATCH_PREFIX 2u  /* symbol name begins with `name`  */

/*
 * What the host should report for a matched export. Bits may be OR'd.
 */
#define NX86_WATCH_SYMBOL    0x1u /* emit a symbol event when it resolves */
#define NX86_WATCH_CALL_SITE 0x2u /* emit call-site events on live entry/return */

/*
 * A plugin's declared interest in an exported function, by name.
 *
 * The host treats `name` as an opaque string: "SSL_write", "Java_" and
 * "RegisterNatives" are ordinary exported-symbol names to it, with no
 * TLS, Java or JNI meaning attached. Any such meaning is the plugin's,
 * derived on its own side of this boundary. `name` is borrowed for the
 * duration of the request_watch call; the host copies what it keeps.
 *
 * A watch never asks for, and the host never provides, argument values,
 * return values or buffer contents. It selects which structural records
 * (symbol, call-site) the host reports; it does not widen what a record
 * may carry.
 */
typedef struct nx86_watch_request {
    uint32_t struct_size;
    uint32_t match_kind; /* NX86_MATCH_* */
    nx86_str name;       /* symbol name or prefix */
    uint32_t flags;      /* NX86_WATCH_* bitmask */
    uint32_t reserved;   /* must be 0 in ABI 0.2 */
} nx86_watch_request;

/* ------------------------------------------------------------------ */
/* Host interface                                                      */
/* ------------------------------------------------------------------ */

/*
 * Observer callback. `event` points at an nx86_event_header followed by
 * the concrete event body selected by `event->kind`; it is valid only
 * until the callback returns. Callbacks must not call back into
 * nx86_host::emit for the event they are handling.
 */
typedef void (NX86_CALL *nx86_observer_fn)(void *user_data,
                                           const nx86_event_header *event);

typedef struct nx86_host {
    uint32_t struct_size;
    uint32_t abi_version;
    void    *host_ctx;

    /* Subscribe to the event kinds selected by `event_mask`. On success
     * `*out_token` receives a handle for unregister_observer. */
    nx86_status (NX86_CALL *register_observer)(void *host_ctx,
                                               uint32_t event_mask,
                                               nx86_observer_fn fn,
                                               void *user_data,
                                               uint32_t *out_token);

    nx86_status (NX86_CALL *unregister_observer)(void *host_ctx,
                                                 uint32_t token);

    /* Publish an event authored by the plugin. The host copies whatever
     * it needs before returning; the caller keeps ownership. The host
     * assigns `seq` and `timestamp_ns` on its copy but leaves
     * `process_id` untouched: that field identifies the observed process
     * and belongs to the producer, not the host. Callable only while the
     * plugin is running (between `start` and `stop`); outside that window
     * the host returns NX86_ERR_LIFECYCLE and dispatches nothing. */
    nx86_status (NX86_CALL *emit)(void *host_ctx,
                                  const nx86_event_header *event);

    void (NX86_CALL *log)(void *host_ctx,
                          uint32_t level,
                          const char *message);

    /* Register interest in an exported symbol by exact name or prefix
     * (ABI 0.2+). When the host later observes a module whose exports
     * match, it reports a symbol and/or call-site record per
     * `req->flags`. The host copies what it needs and returns; the
     * caller keeps ownership of `req` and its `name`. Intended to be
     * called from a plugin's `start`; a host with no observation source
     * may accept the request and simply never match it. Returns
     * NX86_ERR_INVALID_ARG for a null or malformed request,
     * NX86_ERR_NO_MEMORY when a fixed watch table is full, and
     * NX86_ERR_UNSUPPORTED when the host honours no watches at all. */
    nx86_status (NX86_CALL *request_watch)(void *host_ctx,
                                           const nx86_watch_request *req);
} nx86_host;

/* ------------------------------------------------------------------ */
/* Plugin interface                                                    */
/* ------------------------------------------------------------------ */

/* Capability bits a plugin advertises to the host. */
#define NX86_CAP_NONE            0u
#define NX86_CAP_CONSUMES_EVENTS 0x1u
#define NX86_CAP_PRODUCES_EVENTS 0x2u

typedef struct nx86_plugin {
    uint32_t    struct_size;
    uint32_t    abi_version;     /* NX86_ABI_VERSION the plugin was built with */
    const char *id;              /* stable, NUL-terminated, e.g. "hello" */
    const char *display_name;    /* NUL-terminated, human readable */
    uint32_t    plugin_version;  /* NX86_MAKE_VERSION of the plugin itself */
    uint32_t    capabilities;    /* NX86_CAP_* */
    void       *plugin_ctx;

    /* Called once after a successful init. Register observers here. */
    nx86_status (NX86_CALL *start)(void *plugin_ctx);

    /* Called before shutdown; no further events are delivered after it
     * returns. */
    void (NX86_CALL *stop)(void *plugin_ctx);

    /* Last call into the plugin. Release plugin_ctx here. */
    void (NX86_CALL *shutdown)(void *plugin_ctx);
} nx86_plugin;

/*
 * Plugin entry point, resolved by name from the loaded shared object.
 *
 * The host sets `out_plugin->struct_size` before the call to the byte
 * capacity of the caller-owned object. That capacity is an input: the
 * plugin must not write past it, even when it was built against a newer
 * minor version with a larger nx86_plugin. The plugin writes at most
 * that many bytes, stores the number it actually filled back into
 * `struct_size`, and returns NX86_OK; the host then reads only the
 * fields both sides share (the common prefix). The plugin returns
 * NX86_ERR_ABI_MISMATCH when it cannot work with `host->abi_version` or
 * when the host's capacity is too small to hold the fields the plugin
 * requires. `host` stays valid until the plugin's shutdown callback
 * returns.
 */
typedef nx86_status (NX86_CALL *nx86_plugin_init_fn)(const nx86_host *host,
                                                     nx86_plugin *out_plugin);

#define NX86_PLUGIN_INIT_SYMBOL "nx86_plugin_init"

NX86_EXPORT nx86_status NX86_CALL nx86_plugin_init(const nx86_host *host,
                                                   nx86_plugin *out_plugin);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* NATIVEX86_PLUGIN_H */
