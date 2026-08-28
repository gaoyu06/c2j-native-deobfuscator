/*
 * Version 1 of the optional privileged-observer userspace plugin ABI.
 *
 * Plugins report module path and address metadata only. The ABI has no
 * operation for reading process memory or returning module contents.
 */
#ifndef PRIVILEGED_OBSERVER_PLUGIN_H
#define PRIVILEGED_OBSERVER_PLUGIN_H

#include <stdint.h>

#if defined(_WIN32)
#define PO_EXPORT __declspec(dllexport)
#else
#define PO_EXPORT __attribute__((visibility("default")))
#endif

#define PO_ABI_VERSION 1u
#define PO_CAP_MAPS_READ (UINT64_C(1) << 0)

enum po_status {
    PO_STATUS_OK = 0,
    PO_STATUS_INVALID_ARGUMENT = 1,
    PO_STATUS_REFUSED = 2,
    PO_STATUS_NOT_FOUND = 3,
    PO_STATUS_IO_ERROR = 4,
    PO_STATUS_EMIT_FAILED = 5
};

typedef int (*po_emit_module_fn)(
    void *context,
    const char *path,
    uint64_t base_address,
    uint64_t end_address);

typedef int (*po_observe_pid_fn)(
    uint32_t process_id,
    po_emit_module_fn emit_module,
    void *context);

struct po_plugin_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    const char *name;
    uint64_t capabilities;
    po_observe_pid_fn observe_pid;
};

/*
 * Return NULL when host_abi_version is unsupported. The returned descriptor
 * remains owned by the plugin and valid until the shared library is unloaded.
 */
PO_EXPORT const struct po_plugin_v1 *po_plugin_query(
    uint32_t host_abi_version);

#endif
