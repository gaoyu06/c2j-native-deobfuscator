"""Static introspection of native-obfuscator-style .dll/.so/.dylib."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import lief

CLASS_MAGIC = b"\xca\xfe\xba\xbe"

# Heuristic: a string is "interesting" (likely in the j2c string pool) if it's
# printable ASCII and >= 2 chars. We capture all to be safe.
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{2,}")


@dataclass
class BinaryReport:
    schema_version: int
    input_path: str
    fmt: str             # PE | ELF | MachO
    arch: str
    sha256: str
    string_pool: list[str] = field(default_factory=list)
    string_pool_total_bytes: int = 0
    string_pool_base: str | None = None
    hidden_classes: list[dict[str, Any]] = field(default_factory=list)
    exported_functions: list[dict[str, Any]] = field(default_factory=list)
    native_registry: list[dict[str, Any]] = field(default_factory=list)
    per_class_lookups: list[dict[str, Any]] = field(default_factory=list)

    def to_json_obj(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "input": {
                "libPath": self.input_path,
                "format": self.fmt,
                "arch": self.arch,
                "sha256": self.sha256,
            },
            "stringPool": {
                "base": self.string_pool_base,
                "totalBytes": self.string_pool_total_bytes,
                "strings": self.string_pool,
            },
            "exportedFunctions": self.exported_functions,
            "nativeRegistry": self.native_registry,
            "perClassLookups": self.per_class_lookups,
            "hiddenClasses": self.hidden_classes,
        }


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def detect_format(b: lief.Binary) -> tuple[str, str]:
    if b.format == lief.Binary.FORMATS.PE:
        machine = b.header.machine
        arch_map = {
            lief.PE.Header.MACHINE_TYPES.AMD64: "x86_64",
            lief.PE.Header.MACHINE_TYPES.I386: "x86",
            lief.PE.Header.MACHINE_TYPES.ARM64: "aarch64",
        }
        return "PE", arch_map.get(machine, str(machine))
    if b.format == lief.Binary.FORMATS.ELF:
        machine = b.header.machine_type
        arch_map = {
            lief.ELF.ARCH.X86_64: "x86_64",
            lief.ELF.ARCH.I386: "x86",
            lief.ELF.ARCH.AARCH64: "aarch64",
            lief.ELF.ARCH.ARM: "arm",
        }
        return "ELF", arch_map.get(machine, str(machine))
    if b.format == lief.Binary.FORMATS.MACHO:
        cpu = b.header.cpu_type
        arch_map = {
            lief.MachO.Header.CPU_TYPE.X86_64: "x86_64",
            lief.MachO.Header.CPU_TYPE.ARM64: "aarch64",
        }
        return "MachO", arch_map.get(cpu, str(cpu))
    raise ValueError(f"Unknown binary format: {b.format}")


def section_by_name(b: lief.Binary, names: list[str]) -> Any:
    for name in names:
        try:
            s = b.get_section(name)
            if s is not None and s.size > 0:
                return s
        except Exception:
            pass
    return None


def read_section_bytes(s: Any) -> bytes:
    return bytes(s.content)


# Sections to scan for the string pool. native-obfuscator declares
#   `static char pool[]` (non-const), so the pool actually lives in writable
# `.data` on most toolchains. We also scan `.rdata`/`.rodata` to pick up
# additional C string literals.
_POOL_SECTIONS = [".data", ".rdata", ".rodata", "__data", "__DATA,__data",
                  "__DATA,__const", "__const"]


def extract_string_pool(b: lief.Binary) -> tuple[list[str], int, str | None]:
    """Walk all plausible string-bearing sections and pull every
    null-terminated ASCII/UTF-8 run.

    Returns a deduplicated, order-preserving list of strings, the byte size
    of the largest contributing section (best estimate of pool size), and the
    base VA of that section.
    """
    seen: set[str] = set()
    strings: list[str] = []
    best_size = 0
    best_base = None
    for name in _POOL_SECTIONS:
        sec = section_by_name(b, [name])
        if sec is None:
            continue
        raw = read_section_bytes(sec)
        i = 0
        n = len(raw)
        section_size = 0
        section_added = 0
        while i < n:
            if raw[i] == 0:
                i += 1
                continue
            j = i
            while j < n and raw[j] != 0:
                j += 1
            if j - i >= 2:
                chunk = raw[i:j]
                try:
                    s = chunk.decode("utf-8")
                except UnicodeDecodeError:
                    s = None
                if s is not None and all(0x20 <= ord(c) < 0x7f for c in s):
                    if s not in seen:
                        seen.add(s)
                        strings.append(s)
                        section_added += 1
            section_size = j - i
            i = j + 1
        if section_added > best_size:
            best_size = section_added
            best_base = hex(b.imagebase + sec.virtual_address) if hasattr(b, "imagebase") else None
    # totalBytes = approximate size of largest contributing section, OR sum
    return strings, best_size, best_base


_CP_TAG_LEN = {
    1: None,    # Utf8: variable
    3: 4, 4: 4,
    5: 8, 6: 8,  # Long/Double — take 2 slots
    7: 2, 8: 2,
    9: 4, 10: 4, 11: 4, 12: 4,
    15: 3,
    16: 2, 17: 4, 18: 4, 19: 2, 20: 2,
}
_CP_DOUBLE_SLOT = {5, 6}


def _class_file_size(blob: bytes) -> int | None:
    """Parse a JVM class file structure to determine exact byte length.

    Returns ``None`` if the structure is malformed."""
    try:
        if len(blob) < 10 or blob[:4] != CLASS_MAGIC:
            return None
        i = 8  # past magic + minor + major
        cp_count = int.from_bytes(blob[i:i + 2], "big")
        i += 2
        cp_index = 1
        while cp_index < cp_count:
            tag = blob[i]; i += 1
            if tag == 1:
                length = int.from_bytes(blob[i:i + 2], "big")
                i += 2 + length
            else:
                size = _CP_TAG_LEN.get(tag)
                if size is None:
                    return None
                i += size
            cp_index += 2 if tag in _CP_DOUBLE_SLOT else 1
        # access(2) + this(2) + super(2)
        i += 6
        interfaces_count = int.from_bytes(blob[i:i + 2], "big"); i += 2
        i += 2 * interfaces_count
        # fields
        fields_count = int.from_bytes(blob[i:i + 2], "big"); i += 2
        for _ in range(fields_count):
            i += 6  # access+name+desc
            attr_count = int.from_bytes(blob[i:i + 2], "big"); i += 2
            for _ in range(attr_count):
                i += 2
                attr_len = int.from_bytes(blob[i:i + 4], "big"); i += 4 + attr_len
        # methods (same shape)
        methods_count = int.from_bytes(blob[i:i + 2], "big"); i += 2
        for _ in range(methods_count):
            i += 6
            attr_count = int.from_bytes(blob[i:i + 2], "big"); i += 2
            for _ in range(attr_count):
                i += 2
                attr_len = int.from_bytes(blob[i:i + 4], "big"); i += 4 + attr_len
        # class attributes
        attr_count = int.from_bytes(blob[i:i + 2], "big"); i += 2
        for _ in range(attr_count):
            i += 2
            attr_len = int.from_bytes(blob[i:i + 4], "big"); i += 4 + attr_len
        return i if 0 < i <= len(blob) else None
    except (IndexError, ValueError):
        return None


def extract_hidden_classes(b: lief.Binary) -> list[dict[str, Any]]:
    """Find embedded .class files: regions starting with CAFEBABE magic.

    native-obfuscator stores hidden-class bytes as `static const jbyte
    class_data[]` in .rdata (or .data on some toolchains). We parse the class
    file structure to determine the exact length and discard anything that
    doesn't parse cleanly.
    """
    result: list[dict[str, Any]] = []
    seen_offsets: set[tuple[str, int]] = set()
    for sec in b.sections:
        if sec.size == 0:
            continue
        raw = read_section_bytes(sec)
        start = 0
        while True:
            idx = raw.find(CLASS_MAGIC, start)
            if idx == -1:
                break
            if idx + 8 <= len(raw):
                major = int.from_bytes(raw[idx + 6:idx + 8], "big")
                if 45 <= major <= 100:
                    # parse forward to determine the exact size
                    cap = min(len(raw) - idx, 4 << 20)  # 4 MB safety cap
                    candidate = raw[idx:idx + cap]
                    size = _class_file_size(candidate)
                    if size is not None and size > 0:
                        blob = candidate[:size]
                        key = (sec.name, idx)
                        if key not in seen_offsets:
                            seen_offsets.add(key)
                            va = b.imagebase + sec.virtual_address + idx if hasattr(b, "imagebase") else sec.virtual_address + idx
                            result.append({
                                "embeddedAt": hex(va),
                                "section": sec.name,
                                "size": size,
                                "classData": base64.b64encode(blob).decode("ascii"),
                                "majorVersion": major,
                            })
            start = idx + 4
    return result


def extract_exported_functions(b: lief.Binary) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    if b.format == lief.Binary.FORMATS.PE and b.has_exports:
        for e in b.get_export().entries:
            result.append({"name": e.name, "addr": hex(b.imagebase + e.address)})
    elif b.format == lief.Binary.FORMATS.ELF:
        for s in b.exported_symbols:
            if s.name:
                result.append({"name": s.name, "addr": hex(s.value)})
    elif b.format == lief.Binary.FORMATS.MACHO:
        for s in b.exported_symbols:
            if s.name:
                result.append({"name": s.name, "addr": hex(s.value)})
    return result


def detect_native_obfuscator_classes(strings: list[str]) -> list[str]:
    """Heuristic: list class internal names plausibly present in the binary.

    A class name in the string pool typically has format ``a/b/c/ClassName``
    or just ``ClassName`` (top-level). Method descriptors and field types are
    also strings, so we filter:
      - must not start with ``(`` (that's a method desc)
      - must not start with ``L`` followed by ``;`` ending (field desc form like Lcom/foo;)
      - must be a plausible Java identifier per segment
    """
    out: list[str] = []
    ident_re = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")
    for s in strings:
        if not s or s[0] in "([" or s.endswith(";"):
            continue
        if not all(ident_re.match(seg) for seg in s.split("/")):
            continue
        out.append(s)
    return sorted(set(out))


def introspect(path: Path) -> BinaryReport:
    b = lief.parse(str(path))
    if b is None:
        raise IOError(f"LIEF could not parse {path}")
    fmt, arch = detect_format(b)
    strings, pool_bytes, pool_base = extract_string_pool(b)
    hidden = extract_hidden_classes(b)
    exports = extract_exported_functions(b)
    # The function table cannot be recovered without disassembly; we still
    # emit a placeholder list of plausibly-registered classes so manifest-merge
    # can warn the user if jar-parser found classes the binary doesn't mention.
    classes_in_pool = detect_native_obfuscator_classes(strings)
    return BinaryReport(
        schema_version=1,
        input_path=str(path),
        fmt=fmt,
        arch=arch,
        sha256=sha256_file(path),
        string_pool=strings,
        string_pool_total_bytes=pool_bytes,
        string_pool_base=pool_base,
        hidden_classes=hidden,
        exported_functions=exports,
        native_registry=[{"classNameCandidate": name} for name in classes_in_pool],
        per_class_lookups=[],
    )


def write_report(report: BinaryReport, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report.to_json_obj(), indent=2), encoding="utf-8")
