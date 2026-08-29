/*
 * Bounds-checked parser for the named export table of an on-disk PE image.
 *
 * The parser intentionally has no Windows API dependency so its behavior can
 * be tested on every host.  All integer fields are decoded explicitly as
 * little-endian values; no file bytes are cast to native C structs.
 */
#include "pe_exports.h"

#include "nativex86/plugin.h"

#include <string.h>

#define NX86_PE_DOS_LFANEW        0x3cu
#define NX86_PE_COFF_SIZE         20u
#define NX86_PE_SECTION_SIZE      40u
#define NX86_PE_EXPORT_DIR_SIZE   40u
#define NX86_PE_MAGIC_32          0x10bu
#define NX86_PE_MAGIC_64          0x20bu
#define NX86_PE_MACHINE_I386      0x014cu
#define NX86_PE_MACHINE_AMD64     0x8664u

typedef struct pe_view {
    const unsigned char *image;
    size_t               size;
    size_t               sections;
    uint16_t             section_count;
    uint32_t             headers_size;
} pe_view;

static int range_ok(size_t offset, size_t length, size_t size)
{
    return offset <= size && length <= size - offset;
}

static uint16_t read_u16(const unsigned char *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t read_u32(const unsigned char *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static int read_u16_at(const unsigned char *image, size_t size, size_t offset,
                       uint16_t *out)
{
    if (!range_ok(offset, 2u, size)) {
        return -1;
    }
    *out = read_u16(image + offset);
    return 0;
}

static int read_u32_at(const unsigned char *image, size_t size, size_t offset,
                       uint32_t *out)
{
    if (!range_ok(offset, 4u, size)) {
        return -1;
    }
    *out = read_u32(image + offset);
    return 0;
}

/* Translate an image-relative address to a byte offset in the disk file. */
static int rva_to_offset(const pe_view *view, uint32_t rva, size_t *out)
{
    uint16_t i;

    if (rva < view->headers_size && (size_t)rva < view->size) {
        *out = (size_t)rva;
        return 0;
    }

    for (i = 0; i < view->section_count; ++i) {
        const unsigned char *section =
            view->image + view->sections + (size_t)i * NX86_PE_SECTION_SIZE;
        uint32_t virtual_size = read_u32(section + 8u);
        uint32_t virtual_address = read_u32(section + 12u);
        uint32_t raw_size = read_u32(section + 16u);
        uint32_t raw_offset = read_u32(section + 20u);
        uint32_t span = virtual_size > raw_size ? virtual_size : raw_size;
        uint32_t delta;
        size_t offset;

        if (rva < virtual_address) {
            continue;
        }
        delta = rva - virtual_address;
        if (delta >= span) {
            continue;
        }
        /* A zero-filled virtual tail has no bytes in the on-disk image. */
        if (delta >= raw_size) {
            return -1;
        }
        if ((size_t)raw_offset > SIZE_MAX - (size_t)delta) {
            return -1;
        }
        offset = (size_t)raw_offset + (size_t)delta;
        if (!range_ok(offset, 1u, view->size)) {
            return -1;
        }
        *out = offset;
        return 0;
    }
    return -1;
}

static uint32_t machine_kind(uint16_t machine)
{
    switch (machine) {
    case NX86_PE_MACHINE_I386:
        return NX86_MACHINE_X86_32;
    case NX86_PE_MACHINE_AMD64:
        return NX86_MACHINE_X86_64;
    default:
        return NX86_MACHINE_UNKNOWN;
    }
}

int nx86_pe_visit_exports(const unsigned char *image, size_t image_size,
                          nx86_pe_export_visitor visit, void *ctx,
                          uint32_t *out_machine, uint32_t *out_image_size)
{
    pe_view view;
    uint32_t pe_offset;
    size_t coff;
    uint16_t machine;
    uint16_t optional_size;
    uint16_t optional_magic;
    size_t optional;
    size_t number_of_dirs_offset;
    size_t export_entry_offset;
    uint32_t number_of_dirs;
    uint32_t export_rva;
    uint32_t export_size;
    uint32_t size_of_image;
    size_t export_offset;
    uint32_t ordinal_base;
    uint32_t function_count;
    uint32_t name_count;
    uint32_t functions_rva;
    uint32_t names_rva;
    uint32_t ordinals_rva;
    size_t functions_offset;
    size_t names_offset;
    size_t ordinals_offset;
    uint32_t i;

    if (out_machine != NULL) {
        *out_machine = NX86_MACHINE_UNKNOWN;
    }
    if (out_image_size != NULL) {
        *out_image_size = 0u;
    }
    if (image == NULL || !range_ok(0u, 64u, image_size) ||
        image[0] != 'M' || image[1] != 'Z') {
        return -1;
    }
    if (read_u32_at(image, image_size, NX86_PE_DOS_LFANEW, &pe_offset) != 0 ||
        !range_ok((size_t)pe_offset, 4u + NX86_PE_COFF_SIZE, image_size) ||
        memcmp(image + pe_offset, "PE\0\0", 4u) != 0) {
        return -1;
    }

    coff = (size_t)pe_offset + 4u;
    machine = read_u16(image + coff);
    memset(&view, 0, sizeof(view));
    view.image = image;
    view.size = image_size;
    view.section_count = read_u16(image + coff + 2u);
    optional_size = read_u16(image + coff + 16u);
    optional = coff + NX86_PE_COFF_SIZE;
    if (!range_ok(optional, optional_size, image_size) ||
        read_u16_at(image, image_size, optional, &optional_magic) != 0) {
        return -1;
    }

    if (optional_magic == NX86_PE_MAGIC_32) {
        number_of_dirs_offset = 92u;
        export_entry_offset = 96u;
    } else if (optional_magic == NX86_PE_MAGIC_64) {
        number_of_dirs_offset = 108u;
        export_entry_offset = 112u;
    } else {
        return -1;
    }
    if ((size_t)optional_size < export_entry_offset + 8u ||
        read_u32_at(image, image_size, optional + 56u, &size_of_image) != 0 ||
        read_u32_at(image, image_size, optional + 60u, &view.headers_size) != 0 ||
        read_u32_at(image, image_size, optional + number_of_dirs_offset,
                    &number_of_dirs) != 0) {
        return -1;
    }

    view.sections = optional + (size_t)optional_size;
    if ((size_t)view.section_count >
        (image_size - view.sections) / NX86_PE_SECTION_SIZE) {
        return -1;
    }
    if (out_machine != NULL) {
        *out_machine = machine_kind(machine);
    }
    if (out_image_size != NULL) {
        *out_image_size = size_of_image;
    }

    if (number_of_dirs == 0u) {
        return 0;
    }
    export_rva = read_u32(image + optional + export_entry_offset);
    export_size = read_u32(image + optional + export_entry_offset + 4u);
    if (export_rva == 0u || export_size == 0u) {
        return 0;
    }
    if (rva_to_offset(&view, export_rva, &export_offset) != 0 ||
        !range_ok(export_offset, NX86_PE_EXPORT_DIR_SIZE, image_size)) {
        return -1;
    }

    ordinal_base = read_u32(image + export_offset + 16u);
    function_count = read_u32(image + export_offset + 20u);
    name_count = read_u32(image + export_offset + 24u);
    functions_rva = read_u32(image + export_offset + 28u);
    names_rva = read_u32(image + export_offset + 32u);
    ordinals_rva = read_u32(image + export_offset + 36u);
    if (name_count == 0u) {
        return 0;
    }
    if (function_count == 0u ||
        (size_t)function_count > SIZE_MAX / 4u ||
        (size_t)name_count > SIZE_MAX / 4u ||
        (size_t)name_count > SIZE_MAX / 2u ||
        rva_to_offset(&view, functions_rva, &functions_offset) != 0 ||
        rva_to_offset(&view, names_rva, &names_offset) != 0 ||
        rva_to_offset(&view, ordinals_rva, &ordinals_offset) != 0 ||
        !range_ok(functions_offset, (size_t)function_count * 4u, image_size) ||
        !range_ok(names_offset, (size_t)name_count * 4u, image_size) ||
        !range_ok(ordinals_offset, (size_t)name_count * 2u, image_size)) {
        return -1;
    }

    for (i = 0; i < name_count; ++i) {
        uint32_t name_rva = read_u32(image + names_offset + (size_t)i * 4u);
        uint16_t function_index =
            read_u16(image + ordinals_offset + (size_t)i * 2u);
        uint32_t function_rva;
        size_t name_offset;
        const unsigned char *terminator;
        nx86_pe_export export_entry;

        if ((uint32_t)function_index >= function_count ||
            ordinal_base > UINT32_MAX - (uint32_t)function_index ||
            rva_to_offset(&view, name_rva, &name_offset) != 0) {
            return -1;
        }
        terminator = (const unsigned char *)memchr(
            image + name_offset, '\0', image_size - name_offset);
        if (terminator == NULL || terminator == image + name_offset) {
            return -1;
        }
        function_rva =
            read_u32(image + functions_offset + (size_t)function_index * 4u);
        if (function_rva == 0u) {
            continue;
        }

        export_entry.name = (const char *)(image + name_offset);
        export_entry.rva = function_rva;
        export_entry.ordinal = ordinal_base + (uint32_t)function_index;
        export_entry.forwarded =
            function_rva >= export_rva &&
            function_rva - export_rva < export_size;
        if (visit != NULL) {
            visit(ctx, &export_entry);
        }
    }
    return 0;
}
