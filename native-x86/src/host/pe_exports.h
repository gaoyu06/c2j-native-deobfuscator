/*
 * Small, platform-neutral parser for named exports in an on-disk PE image.
 *
 * This is an internal host component, not part of the plugin ABI.  It reads
 * only image metadata supplied by the caller.  Export names point into
 * `image` and remain valid only for the duration of the visit.
 */
#ifndef NX86_HOST_PE_EXPORTS_H
#define NX86_HOST_PE_EXPORTS_H

#include <stddef.h>
#include <stdint.h>

typedef struct nx86_pe_export {
    const char *name;
    uint32_t    rva;
    uint32_t    ordinal;
    int         forwarded;
} nx86_pe_export;

typedef void (*nx86_pe_export_visitor)(void *ctx,
                                       const nx86_pe_export *export_entry);

/*
 * Visit every named export in `image`.
 *
 * Returns 0 for a structurally valid PE image, including one with no export
 * directory, and -1 for a truncated or malformed image.  `out_machine`
 * receives NX86_MACHINE_* and `out_image_size` receives SizeOfImage when the
 * corresponding pointer is non-NULL.
 */
int nx86_pe_visit_exports(const unsigned char *image, size_t image_size,
                          nx86_pe_export_visitor visit, void *ctx,
                          uint32_t *out_machine, uint32_t *out_image_size);

#endif /* NX86_HOST_PE_EXPORTS_H */
