/*
 * Thin platform shim for the nativex86 host stub: dynamic loading and a
 * wall clock. Nothing here inspects another process. There is
 * deliberately no "current process id" helper: an event's process_id
 * names the observed process, never the host, so the stub has no reason
 * to read its own pid.
 */
#ifndef NX86_HOST_PLATFORM_H
#define NX86_HOST_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

/* Returns NULL on failure; call nx86_plat_last_error() for a reason. */
void *nx86_plat_open_library(const char *path);

void *nx86_plat_find_symbol(void *handle, const char *name);

void nx86_plat_close_library(void *handle);

/* Valid until the next platform call on the same thread. */
const char *nx86_plat_last_error(void);

uint64_t nx86_plat_now_ns(void);

/* Platform-conventional shared-library file name for a plugin, e.g.
 * "hello" -> "libnx86_plugin_hello.so". Writes at most `cap` bytes
 * including the terminator; returns 0 on success. */
int nx86_plat_plugin_filename(const char *stem, char *out, size_t cap);

#endif /* NX86_HOST_PLATFORM_H */
