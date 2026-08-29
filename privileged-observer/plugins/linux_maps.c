#define _POSIX_C_SOURCE 200809L

#include "privileged_observer_plugin.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int check_owner(const char *path)
{
    struct stat metadata;

    if (stat(path, &metadata) != 0) {
        return errno == ENOENT ? PO_STATUS_NOT_FOUND : PO_STATUS_IO_ERROR;
    }
    if (metadata.st_uid != geteuid()) {
        return PO_STATUS_REFUSED;
    }
    return PO_STATUS_OK;
}

static int check_open_file_owner(FILE *file)
{
    struct stat metadata;

    if (fstat(fileno(file), &metadata) != 0) {
        return PO_STATUS_IO_ERROR;
    }
    return metadata.st_uid == geteuid() ? PO_STATUS_OK : PO_STATUS_REFUSED;
}

static void trim_deleted_suffix(char *path)
{
    static const char suffix[] = " (deleted)";
    size_t path_length = strlen(path);
    size_t suffix_length = sizeof(suffix) - 1;

    if (path_length >= suffix_length &&
        strcmp(path + path_length - suffix_length, suffix) == 0) {
        path[path_length - suffix_length] = '\0';
    }
}

static int observe_pid(
    uint32_t process_id,
    po_emit_module_fn emit_module,
    void *context)
{
    char process_path[64];
    char maps_path[72];
    char *line = NULL;
    size_t line_capacity = 0;
    FILE *maps_file;
    int status;

    if (process_id == 0 || emit_module == NULL) {
        return PO_STATUS_INVALID_ARGUMENT;
    }

    if (snprintf(
            process_path,
            sizeof(process_path),
            "/proc/%u",
            process_id) >= (int)sizeof(process_path) ||
        snprintf(
            maps_path,
            sizeof(maps_path),
            "%s/maps",
            process_path) >= (int)sizeof(maps_path)) {
        return PO_STATUS_INVALID_ARGUMENT;
    }

    status = check_owner(process_path);
    if (status != PO_STATUS_OK) {
        return status;
    }

    maps_file = fopen(maps_path, "r");
    if (maps_file == NULL) {
        return errno == ENOENT ? PO_STATUS_NOT_FOUND : PO_STATUS_IO_ERROR;
    }

    status = check_open_file_owner(maps_file);
    if (status != PO_STATUS_OK) {
        fclose(maps_file);
        return status;
    }

    status = PO_STATUS_OK;
    while (getline(&line, &line_capacity, maps_file) >= 0) {
        unsigned long long start_address;
        unsigned long long end_address;
        unsigned long long file_offset;
        unsigned long long base_address;
        char *path;
        int path_offset = 0;
        size_t path_length;

        if (sscanf(
                line,
                "%llx-%llx %*4s %llx %*s %*s %n",
                &start_address,
                &end_address,
                &file_offset,
                &path_offset) != 3 ||
            path_offset <= 0 ||
            end_address <= start_address ||
            start_address < file_offset) {
            continue;
        }

        path = line + path_offset;
        while (*path == ' ' || *path == '\t') {
            ++path;
        }
        path_length = strlen(path);
        while (path_length > 0 &&
               (path[path_length - 1] == '\n' ||
                path[path_length - 1] == '\r')) {
            path[--path_length] = '\0';
        }
        if (*path == '\0' || *path == '[') {
            continue;
        }

        trim_deleted_suffix(path);
        base_address = start_address - file_offset;
        if (emit_module(
                context,
                path,
                (uint64_t)base_address,
                (uint64_t)end_address) != 0) {
            status = PO_STATUS_EMIT_FAILED;
            break;
        }
    }

    if (status == PO_STATUS_OK && ferror(maps_file)) {
        status = PO_STATUS_IO_ERROR;
    }
    free(line);
    fclose(maps_file);
    return status;
}

static const struct po_plugin_v1 plugin = {
    PO_ABI_VERSION,
    sizeof(struct po_plugin_v1),
    "linux-proc-maps",
    PO_CAP_MAPS_READ,
    observe_pid
};

PO_EXPORT const struct po_plugin_v1 *po_plugin_query(
    uint32_t host_abi_version)
{
    return host_abi_version == PO_ABI_VERSION ? &plugin : NULL;
}
