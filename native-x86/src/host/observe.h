/*
 * Observation engine for the nativex86 host.
 *
 * Given a target process the invoking user owns, this attaches with a
 * documented user-mode technique (ptrace on Linux), enumerates loaded
 * modules and, for exports a plugin asked to watch, reports symbol and
 * live entry/return call-site records. It reports *program structure*
 * only: module bases, symbol names and addresses, and control-flow
 * edges (which call site reached which callee). It never reads argument
 * registers, buffer contents, return values or keys, and there is no
 * code path that could.
 *
 * The engine is deliberately free of any Java / JNI / TLS vocabulary. A
 * watched name is an opaque string; the meaning of "SSL_write" or
 * "Java_" lives in the plugin that asked for it, never here.
 *
 * The Linux implementation lives in observe_linux.c. Other platforms get
 * observe_stub.c, which fails honestly.
 */
#ifndef NX86_HOST_OBSERVE_H
#define NX86_HOST_OBSERVE_H

#include "nativex86/plugin.h"
#include "event_bus.h"

#define NX86_WATCH_NAME_MAX 160u

/* One resolved watch, flattened from an nx86_watch_request. */
typedef struct nx86_watch_entry {
    char     name[NX86_WATCH_NAME_MAX];
    uint32_t match_kind; /* NX86_MATCH_* */
    uint32_t flags;      /* NX86_WATCH_* */
} nx86_watch_entry;

typedef struct nx86_observe_config {
    uint32_t pid;             /* the process to observe */
    int      allow_live;      /* set entry/return breakpoints (needs ptrace) */
    uint32_t max_call_events; /* stop after this many call-site records, 0 = no cap */
    uint32_t max_seconds;     /* wall-clock safety budget, 0 = until target exits */
} nx86_observe_config;

/* 1 when /proc/PID (or the platform equivalent) is owned by the current
 * user, 0 when it belongs to a different user, -1 when the process does
 * not exist or cannot be inspected. When non-NULL, *out_uid receives the
 * owning uid on the 1/0 paths. */
int nx86_observe_owner_check(uint32_t pid, uint32_t *out_uid);

/* True when this build can install live entry/return breakpoints on the
 * running platform and architecture; false when only the read-only
 * module/symbol pass is available. */
int nx86_observe_live_supported(void);

/* Human-readable one-liner naming the technique in use, for diagnostics. */
const char *nx86_observe_backend_name(void);

/*
 * Attach to cfg->pid and emit records through `bus`:
 *   - one module-load per file-backed module found in the target;
 *   - one symbol record per watched export that resolves (NX86_WATCH_SYMBOL);
 *   - call-site records on live entry/return for watched exports
 *     (NX86_WATCH_CALL_SITE), when cfg->allow_live and the platform
 *     supports it.
 *
 * Every emitted record carries the observed pid in its header. Returns
 * NX86_OK for a clean run, including one where live observation was
 * unavailable and only the read-only pass ran. Returns an error when the
 * target cannot be attached or inspected at all. Diagnostic detail is
 * emitted as NX86_EVENT_NOTE records and via `log_fn`.
 */
nx86_status nx86_observe_run(nx86_event_bus *bus,
                            const nx86_observe_config *cfg,
                            const nx86_watch_entry *watches,
                            uint32_t n_watches,
                            void (*log_fn)(uint32_t level, const char *msg));

#endif /* NX86_HOST_OBSERVE_H */
