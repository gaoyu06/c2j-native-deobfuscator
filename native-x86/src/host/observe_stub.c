/*
 * Fallback observation engine for platforms without a native
 * implementation. It attaches to nothing and resolves nothing; it fails
 * honestly so a caller never mistakes silence for an empty target.
 *
 * A real Windows implementation would live in an observe_windows.c
 * alongside this file, using documented user-mode debugging APIs
 * (DebugActiveProcess / WaitForDebugEvent) with the same record model
 * and the same metadata-only guarantee. It is intentionally not shipped
 * here; see docs/plugins/crypto-libraries.md.
 */
#if !defined(__linux__)

#include "observe.h"

int nx86_observe_owner_check(uint32_t pid, uint32_t *out_uid)
{
    (void)pid;
    if (out_uid != NULL) {
        *out_uid = 0u;
    }
    return -1;
}

int nx86_observe_live_supported(void)
{
    return 0;
}

const char *nx86_observe_backend_name(void)
{
    return "unsupported platform: no observation backend built";
}

nx86_status nx86_observe_run(nx86_event_bus *bus,
                            const nx86_observe_config *cfg,
                            const nx86_watch_entry *watches,
                            uint32_t n_watches,
                            void (*log_fn)(uint32_t level, const char *msg))
{
    (void)bus;
    (void)cfg;
    (void)watches;
    (void)n_watches;
    if (log_fn != NULL) {
        log_fn(NX86_LOG_ERROR,
               "no observation backend is available on this platform");
    }
    return NX86_ERR_UNSUPPORTED;
}

#else /* __linux__ : this translation unit is intentionally empty */

typedef int nx86_observe_stub_unused;

#endif /* !__linux__ */
