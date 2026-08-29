#!/usr/bin/env python3
"""Remove the section header table from an ELF, leaving a PT_LOAD-only image.

This reproduces what ``sstrip`` (ELFkickers) does without requiring it to be
installed: it zeroes ``e_shoff`` / ``e_shentsize`` / ``e_shnum`` /
``e_shstrndx`` in the ELF header and truncates the section header table off the
end of the file when nothing loadable lives at or beyond it. The program
headers (``PT_LOAD`` / ``PT_DYNAMIC``) are untouched, so the loader — and LIEF
via its program-header parser — can still map the image and read the dynamic
symbol table, while ``b.sections`` becomes empty.

Used by ``build.sh`` to derive the section-header-removed test fixtures from
their committed base binaries. It is intentionally dependency-free (pure
``struct``) so it runs anywhere Python does.
"""

from __future__ import annotations

import struct
import sys


def strip_section_headers(src: str, dst: str) -> None:
    data = bytearray(open(src, "rb").read())
    if data[:4] != b"\x7fELF":
        raise ValueError(f"{src} is not an ELF file")
    if data[4] != 2:  # EI_CLASS: 2 == ELFCLASS64
        raise ValueError("only ELF64 is supported by this helper")

    # ELF64 header field offsets.
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]

    # Largest PT_LOAD file extent, so truncation never drops loadable bytes.
    max_load_end = 0
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        p_offset = struct.unpack_from("<Q", data, off + 8)[0]
        p_filesz = struct.unpack_from("<Q", data, off + 32)[0]
        if p_type == 1:  # PT_LOAD
            max_load_end = max(max_load_end, p_offset + p_filesz)

    # Zero the section-header table references in the ELF header.
    struct.pack_into("<Q", data, 0x28, 0)  # e_shoff
    struct.pack_into("<H", data, 0x3A, 0)  # e_shentsize
    struct.pack_into("<H", data, 0x3C, 0)  # e_shnum
    struct.pack_into("<H", data, 0x3E, 0)  # e_shstrndx

    # Drop the section header table (and section-only trailing data) when it
    # sits entirely past the last loadable byte.
    if e_shoff and e_shoff >= max_load_end:
        data = data[:e_shoff]

    with open(dst, "wb") as f:
        f.write(data)


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: strip_section_headers.py <in.so> <out.so>", file=sys.stderr)
        return 2
    strip_section_headers(argv[1], argv[2])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
