# nativex86 plugin ABI

Version **0.2** — experimental, unstable, defined by
[`native-x86/include/nativex86/plugin.h`](../native-x86/include/nativex86/plugin.h).
That header is normative; this document explains it and states the rules
a header cannot express.

Delta from 0.1 (a minor bump, backward compatible under the negotiation
rules below): a generic `request_watch` callback appended to `nx86_host`,
a `nx86_watch_request` record with its `NX86_MATCH_*` / `NX86_WATCH_*`
constants, and a `phase` field on `nx86_event_call_site` (reusing the
0.1 `reserved` tail word, so the struct size is unchanged and a 0.1
record reads as `NX86_CALL_PHASE_NONE`). None of it introduces any
Java / JNI / TLS vocabulary: a watched name is an opaque string.

Scope and non-goals of the module that uses this ABI:
[native-x86-module.md](native-x86-module.md).

---

## Design constraints

The ABI is a binary boundary between a host executable and shared
libraries built by someone else, possibly by another compiler. It is
therefore restricted to what is stable across toolchains:

- **C99, freestanding-ish.** The header includes only `<stddef.h>` and
  `<stdint.h>`. No JNI, no OS headers, no C++.
- **Fixed-width integers only.** No `int`, `long`, `size_t`, `enum` or
  `bool` in any struct field; no bitfields; no packing pragmas. Every
  field is naturally aligned at its natural size, so layout matches
  under both System V and Microsoft x64.
- **Every versioned struct starts with `uint32_t struct_size`.** That
  is the extension mechanism: a receiver checks the size before reading
  a field added in a later minor version.
- **Callbacks in structs, not exported symbols.** The plugin exports
  exactly one symbol; everything else travels in vtable-shaped structs.
  This keeps name mangling and import libraries out of the picture.
- **Default C calling convention** (`NX86_CALL`, currently empty). On
  32-bit x86 both sides must be built cdecl.

---

## Version negotiation

```c
#define NX86_ABI_VERSION_MAJOR 0u
#define NX86_ABI_VERSION_MINOR 2u
#define NX86_ABI_VERSION  NX86_MAKE_VERSION(0u, 2u)   /* 0x00000002 */

#define NX86_VERSION_MAJOR(v) ((uint32_t)(v) >> 16)
#define NX86_VERSION_MINOR(v) ((uint32_t)(v) & 0xFFFFu)
```

Rules:

1. **Major must match exactly.** A host that sees a different major in
   `nx86_plugin::abi_version` refuses the plugin; a plugin that sees a
   different major in `nx86_host::abi_version` returns
   `NX86_ERR_ABI_MISMATCH` from its entry point.
2. **Minor may differ in either direction.** Both sides then read only
   the fields covered by the *smaller* of the two `struct_size` values —
   the common prefix. A side never reads or writes past the size its peer
   provided, so a newer peer cannot overwrite an older peer's object and
   an older peer's absent tail is simply not read. `NX86_HAS_FIELD` in
   the header performs this check for one field.
3. **`nx86_plugin_init` capacity is an input.** The host sets
   `out_plugin->struct_size` before the call to the byte capacity of the
   object it owns. The plugin writes at most that many bytes — even if it
   was built against a newer minor with a larger `nx86_plugin` — and
   stores the number it filled back into `struct_size`. The host then
   caps that value at its own size and reads only the common prefix.
4. **Minor bumps may only append fields** to the end of an existing
   struct, or add new event kinds / status codes / flag bits. Reordering,
   resizing, repurposing or removing anything is a major bump.
5. **`reserved` fields must be written as zero** and ignored on read
   until a minor version gives them meaning.

While the major version is `0`, the whole ABI is subject to change
without the courtesy above.

---

## Status codes

`nx86_status` is `int32_t`. `NX86_OK` is `0`; every failure is negative.

| Code | Value | Meaning |
|---|---|---|
| `NX86_OK` | 0 | Success |
| `NX86_ERR_ABI_MISMATCH` | -1 | Incompatible major version or undersized struct |
| `NX86_ERR_INVALID_ARG` | -2 | Null pointer, empty mask, malformed record |
| `NX86_ERR_UNSUPPORTED` | -3 | Well-formed but not implemented here |
| `NX86_ERR_NO_MEMORY` | -4 | Allocation failed, or a fixed table is full |
| `NX86_ERR_NOT_FOUND` | -5 | Unknown observer token |
| `NX86_ERR_INTERNAL` | -6 | Bug on the callee's side |
| `NX86_ERR_LIFECYCLE` | -7 | `emit` called outside the `start`…`stop` window |

Log levels are `NX86_LOG_DEBUG` (10), `INFO` (20), `WARN` (30),
`ERROR` (40) — spaced so intermediate levels can be added later.

---

## Strings and ownership

```c
typedef struct nx86_str {
    const char *data;   /* UTF-8, NOT required to be NUL-terminated */
    uint32_t    len;
    uint32_t    reserved;
} nx86_str;
```

One rule, applied everywhere: **text is borrowed for the duration of the
call that carried it.** The producer keeps ownership; a receiver that
needs the text after returning must copy it. Nothing in this ABI
transfers ownership of a pointer, so there is no free callback and no
allocator to agree on.

`data` may be `NULL` when `len` is `0`. `len` is authoritative even when
the buffer happens to be NUL-terminated.

The `const char *` fields on `nx86_plugin` (`id`, `display_name`) are
the exception: they are NUL-terminated and must stay valid until the
plugin's `shutdown` returns — string literals in the plugin image are
the intended implementation.

---

## Events

Every event begins with a common header and is identified by `kind`:

```c
typedef struct nx86_event_header {
    uint32_t        struct_size;   /* sizeof the concrete event struct */
    nx86_event_kind kind;          /* NX86_EVENT_* */
    uint64_t        seq;           /* monotonic per host, starts at 1 */
    uint64_t        timestamp_ns;  /* wall clock, ns since the Unix epoch */
    uint32_t        process_id;    /* observed process, 0 if not applicable */
    uint32_t        thread_id;     /* observed thread, 0 if not tracked */
} nx86_event_header;
```

A receiver casts `const nx86_event_header *` to the concrete type
selected by `kind`, **after** checking
`struct_size >= sizeof(concrete_type)`. If the check fails the record
came from a newer or older minor version; read the header only.

Subscription masks are 32 bits, one bit per kind:
`NX86_EVENT_MASK(kind) == 1u << kind`. Kinds `>= 32` are therefore not
representable in v0.1; the host rejects them with
`NX86_ERR_UNSUPPORTED`.

### `NX86_EVENT_NOTE` (1)

`nx86_event_note` — a diagnostic message: `level` (`NX86_LOG_*`),
`source` (component id), `text`. Used by the sample plugin for its hello
record.

### `NX86_EVENT_MODULE_LOAD` (2)

`nx86_event_module_load` — `path`, `name`, `base_address`, `image_size`,
`machine` (`NX86_MACHINE_X86_32` / `X86_64` / `UNKNOWN`), `flags`
(reserved, zero in v0.1).

### `NX86_EVENT_MODULE_UNLOAD` (3)

`nx86_event_module_unload` — `name`, `base_address`.

### `NX86_EVENT_SYMBOL` (4)

`nx86_event_symbol` — `module_name`, `symbol_name`, `module_base`,
`address` (absolute in the observed image), `binding`
(`NX86_SYMBOL_EXPORT` / `IMPORT` / `DEBUG` / `UNKNOWN`), `ordinal` (PE
ordinal, 0 when unknown).

### `NX86_EVENT_CALL_SITE` (5)

`nx86_event_call_site` — `module_name`, `target_name` (may be empty),
`site_address` (the call instruction, or the caller-side return address
for a live entry/return), `target_address` (0 when unresolved),
`module_base`, `site_kind` (`NX86_CALL_SITE_DIRECT` / `INDIRECT` /
`THUNK` / `UNKNOWN`), and `phase` (ABI 0.2): `NX86_CALL_PHASE_NONE` (0)
for a structural record recovered from an image, `NX86_CALL_PHASE_ENTER`
(1) when control reached the callee, `NX86_CALL_PHASE_RETURN` (2) when it
returned. `phase` occupies the word that was `reserved` in 0.1, so the
record size is unchanged and a 0.1 producer's zero reads as `NONE`. A
phase is one bit of control-flow position; it never carries a return
value, an argument, or a buffer.

### What events may not carry

There is no raw-bytes event and no argument or return-value field, and
none may be added. Records describe **program structure** — addresses,
names, sizes, edges — never **program data**. An extension that would
carry the contents of a buffer belongs in a different project, not in a
minor version of this ABI.

The one free-text field — a diagnostic note's `text` (`NX86_EVENT_NOTE`)
— is not made safe by construction: it can hold arbitrary text, so the
rule is stated explicitly rather than implied by the layout. It carries
host/status text only; plugins and the host must never place a key,
buffer or payload in it. A host enforces that with a length cap — the
reference host rejects a note whose `text` exceeds `NX86_NOTE_TEXT_MAX`
(512 bytes) with `NX86_ERR_INVALID_ARG` — so the guarantee is policy
plus a bound, not a structural impossibility.

---

## Host interface

The host hands the plugin one `nx86_host` at init time. It stays valid
until the plugin's `shutdown` returns.

```c
typedef struct nx86_host {
    uint32_t struct_size;
    uint32_t abi_version;
    void    *host_ctx;                 /* opaque; pass back unchanged */

    nx86_status (*register_observer)(void *host_ctx, uint32_t event_mask,
                                     nx86_observer_fn fn, void *user_data,
                                     uint32_t *out_token);
    nx86_status (*unregister_observer)(void *host_ctx, uint32_t token);
    nx86_status (*emit)(void *host_ctx, const nx86_event_header *event);
    void        (*log)(void *host_ctx, uint32_t level, const char *message);
    nx86_status (*request_watch)(void *host_ctx,          /* ABI 0.2 */
                                 const nx86_watch_request *req);
} nx86_host;
```

- **`register_observer`** — subscribe to the kinds selected by
  `event_mask`. Tokens are non-zero and unique for the host's lifetime.
  `event_mask == 0` is `NX86_ERR_INVALID_ARG`; a full table is
  `NX86_ERR_NO_MEMORY`.
- **`unregister_observer`** — idempotent only in the sense that a second
  call returns `NX86_ERR_NOT_FOUND`. Not callable from inside a
  callback in v0.1.
- **`emit`** — publish a plugin-authored event. The plugin fills
  `struct_size`, `kind` and, when it applies, `process_id` (the observed
  process). The host assigns `seq` and `timestamp_ns` on a private copy
  and leaves `process_id` as the plugin set it, so the caller's record is
  not mutated and needs no lifetime beyond the call. `emit` is only valid
  while the plugin is running (from `start` until `stop` returns); called
  before `start` or during/after `shutdown` it returns
  `NX86_ERR_LIFECYCLE` and dispatches nothing. The host stub caps emitted
  records at 256 bytes (`NX86_HOST_MAX_EVENT_SIZE`) and returns
  `NX86_ERR_INVALID_ARG` above that; any host must document its own cap.
- **`log`** — free-form diagnostics with a NUL-terminated message. Not
  an event: it never reaches observers.
- **`request_watch`** (ABI 0.2) — register interest in an exported
  function by exact name or prefix. When the host later observes a
  module whose exports match, it reports a `symbol` and/or `call-site`
  record per the request's flags. The host copies what it needs and
  returns; the caller keeps ownership of the request and its name.
  Intended to be called from `start`. A host with no observation source
  may accept the request and never match it; a host that honours no
  watches at all returns `NX86_ERR_UNSUPPORTED`. Absent on a pre-0.2
  host — a plugin checks `NX86_HAS_FIELD(host->struct_size, nx86_host,
  request_watch)` before calling and stays passive if it is missing.

### Watch requests (ABI 0.2)

```c
#define NX86_MATCH_EXACT     1u  /* whole name equals `name`  */
#define NX86_MATCH_PREFIX    2u  /* name begins with `name`    */
#define NX86_WATCH_SYMBOL    0x1u /* report a symbol when it resolves     */
#define NX86_WATCH_CALL_SITE 0x2u /* report call-site enter/return, live  */

typedef struct nx86_watch_request {
    uint32_t struct_size;
    uint32_t match_kind; /* NX86_MATCH_*  */
    nx86_str name;       /* symbol name or prefix; borrowed for the call */
    uint32_t flags;      /* NX86_WATCH_* bitmask */
    uint32_t reserved;   /* must be 0 */
} nx86_watch_request;
```

The host treats `name` as an opaque string. `"SSL_write"`, `"Java_"` and
`"RegisterNatives"` are ordinary export names to it, with no TLS, Java or
JNI meaning; that meaning belongs to the plugin that asked. A watch only
selects which structural records the host reports — it never widens what
a record may carry, and there is no watch that asks for argument values,
buffer contents or return data.

### Observer callback

```c
typedef void (*nx86_observer_fn)(void *user_data,
                                 const nx86_event_header *event);
```

- `event` is valid only until the callback returns. Copy what you keep.
- A callback must not call `emit` for the event it is handling
  (re-entrancy is not defined in v0.1) and must not register or
  unregister observers.
- Callbacks should be cheap and must not block the host.

### Threading

v0.1 is **single-threaded**: the host stub creates no threads and
delivers every event on the thread that published it. A future host that
observes concurrently must either serialize delivery per observer or bump
the minor version with an explicit threading capability flag — a plugin
written against v0.1 is entitled to assume no concurrent delivery.

---

## Plugin interface

```c
typedef struct nx86_plugin {
    uint32_t    struct_size;
    uint32_t    abi_version;    /* NX86_ABI_VERSION at plugin build time */
    const char *id;             /* stable, NUL-terminated */
    const char *display_name;
    uint32_t    plugin_version; /* NX86_MAKE_VERSION, the plugin's own */
    uint32_t    capabilities;   /* NX86_CAP_CONSUMES_EVENTS | ..._PRODUCES_... */
    void       *plugin_ctx;

    nx86_status (*start)(void *plugin_ctx);
    void        (*stop)(void *plugin_ctx);
    void        (*shutdown)(void *plugin_ctx);
} nx86_plugin;
```

Single entry point, resolved by name (`NX86_PLUGIN_INIT_SYMBOL`):

```c
NX86_EXPORT nx86_status nx86_plugin_init(const nx86_host *host,
                                         nx86_plugin *out_plugin);
```

### Lifecycle

| Step | Who | Contract |
|---|---|---|
| load | host | Platform loader opens a path the user named. No directory scanning, no auto-load. |
| `nx86_plugin_init` | plugin | Validate `host->abi_version` major and that `host->struct_size` covers the callbacks it needs; fill up to the capacity in `out_plugin->struct_size` and store the bytes written back into it; return `NX86_OK` or `NX86_ERR_ABI_MISMATCH`. Do not register observers here. |
| validate | host | Reject on major mismatch, or when the returned prefix is too small to cover the fields the host reads. Cap a larger returned `struct_size` at the host's own and ignore any unknown tail. |
| `start` | plugin | Register observers, emit anything initial. Non-`NX86_OK` aborts the run; the host still calls `shutdown`. |
| events | host | The host opens the delivery window when it calls `start` and closes it once `stop` returns. `emit` outside that window returns `NX86_ERR_LIFECYCLE`. |
| `stop` | plugin | Unregister observers, flush. No events arrive after it returns. |
| `shutdown` | plugin | Last call in. Release `plugin_ctx`. |
| unload | host | Library closed. No plugin code runs afterwards. |

Every callback is optional (`NULL` is skipped), so a purely passive
plugin can supply only `start`.

### Minimal plugin

```c
#include "nativex86/plugin.h"
#include <string.h>

static const nx86_host *g_host;

static void NX86_CALL on_event(void *user, const nx86_event_header *ev)
{
    (void)user;
    if (ev->kind == NX86_EVENT_MODULE_LOAD &&
        ev->struct_size >= sizeof(nx86_event_module_load)) {
        const nx86_event_module_load *m = (const void *)ev;
        /* m->name.data is valid only until this returns: copy to keep. */
        (void)m;
    }
}

static nx86_status NX86_CALL start(void *ctx)
{
    uint32_t token;
    (void)ctx;
    return g_host->register_observer(g_host->host_ctx,
                                     NX86_EVENT_MASK(NX86_EVENT_MODULE_LOAD),
                                     on_event, NULL, &token);
}

NX86_EXPORT nx86_status NX86_CALL nx86_plugin_init(const nx86_host *host,
                                                   nx86_plugin *out)
{
    uint32_t written;

    if (host == NULL || out == NULL) return NX86_ERR_INVALID_ARG;
    if (NX86_VERSION_MAJOR(host->abi_version) != NX86_ABI_VERSION_MAJOR)
        return NX86_ERR_ABI_MISMATCH;
    if (!NX86_HAS_FIELD(host->struct_size, nx86_host, register_observer))
        return NX86_ERR_ABI_MISMATCH;
    g_host = host;

    /* out->struct_size is the host's capacity: never write past it. */
    written = (uint32_t)sizeof(*out);
    if (written > out->struct_size) written = out->struct_size;
    if (!NX86_HAS_FIELD(written, nx86_plugin, start))
        return NX86_ERR_ABI_MISMATCH;

    memset(out, 0, written);
    out->struct_size = written;
    out->abi_version = NX86_ABI_VERSION;
    out->id = "example";
    out->display_name = "example plugin";
    out->plugin_version = NX86_MAKE_VERSION(0u, 1u);
    out->capabilities = NX86_CAP_CONSUMES_EVENTS;
    out->start = start;
    return NX86_OK;
}
```

A complete, compiling version is
[`native-x86/plugins/hello/hello.c`](../native-x86/plugins/hello/hello.c).

---

## Conformance checklist

For a host:

- [ ] Reject plugins whose ABI major differs, or whose returned prefix
      is too small to cover the fields the host reads; cap a larger
      returned `struct_size` at the host's own and ignore the tail.
- [ ] Set `out_plugin->struct_size` to the object's capacity before
      calling `nx86_plugin_init`.
- [ ] Assign `seq` monotonically from 1 and stamp `timestamp_ns`; do not
      overwrite `process_id`.
- [ ] Never deliver an event outside the `start` … `stop` window; reject
      `emit` outside it with `NX86_ERR_LIFECYCLE`.
- [ ] Copy plugin-emitted records before dispatch; never mutate the
      caller's buffer.
- [ ] Document the maximum size accepted by `emit`.
- [ ] If it honours `request_watch`, treat the watched `name` as an
      opaque string and never read argument or return data on its behalf;
      otherwise return `NX86_ERR_UNSUPPORTED`.

For a plugin:

- [ ] Validate `host->abi_version` major and that `host->struct_size`
      covers the callbacks you call.
- [ ] Zero `*out_plugin` up to the host's capacity, never write past it,
      and store the bytes written into `struct_size`.
- [ ] Check `struct_size` before casting an event to a concrete type.
- [ ] Copy any borrowed text you keep past the callback.
- [ ] Before calling `request_watch`, confirm the host carries it with
      `NX86_HAS_FIELD(host->struct_size, nx86_host, request_watch)`; stay
      passive on an older host.
- [ ] Unregister in `stop` and release state in `shutdown`.
