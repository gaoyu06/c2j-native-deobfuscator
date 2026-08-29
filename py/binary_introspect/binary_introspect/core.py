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

from .jni_tables import attribute_tables_to_classes, find_jni_method_tables

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
    string_pool_entries: list[dict[str, Any]] = field(default_factory=list)
    hidden_classes: list[dict[str, Any]] = field(default_factory=list)
    exported_functions: list[dict[str, Any]] = field(default_factory=list)
    native_registry: list[dict[str, Any]] = field(default_factory=list)
    per_class_lookups: list[dict[str, Any]] = field(default_factory=list)
    cache_table: dict[str, Any] = field(default_factory=dict)
    analysis: dict[str, Any] = field(default_factory=dict)

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
                "entries": self.string_pool_entries,
            },
            "exportedFunctions": self.exported_functions,
            "nativeRegistry": self.native_registry,
            "perClassLookups": self.per_class_lookups,
            "hiddenClasses": self.hidden_classes,
            "cacheTable": self.cache_table,
            "analysis": self.analysis,
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


def extract_string_pool(b: lief.Binary) -> tuple[list[str], int, str | None, list[dict[str, Any]]]:
    """Walk all plausible string-bearing sections and pull every
    null-terminated ASCII/UTF-8 run.

    Returns:
      - deduplicated, order-preserving list of strings,
      - size (count) of the largest contributing section,
      - base VA of that section (string-pool base),
      - per-string offset list `[{offset, value}, ...]` from the largest
        contributing section, where `offset` is the byte offset from the
        section's base (matches `string_pool + N` references in disasm).

    Selection is by "JVM-string density", not raw count: a section that
    contains JVM descriptors (`(I)V`, `Ljava/lang/String;`, …) and
    obfuscator-runtime error tokens (`INVOKEVIRTUAL Object npe`,
    `classloader == null`) outranks a section that happens to hold more
    generic null-terminated runs (typical of CRT data in `.rdata`).
    """
    seen: set[str] = set()
    strings: list[str] = []
    best_score = -1
    best_base = None
    best_entries: list[dict[str, Any]] = []
    for name in _POOL_SECTIONS:
        sec = section_by_name(b, [name])
        if sec is None:
            continue
        raw = read_section_bytes(sec)
        i = 0
        n = len(raw)
        section_entries: list[dict[str, Any]] = []
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
                    section_entries.append({"offset": i, "value": s})
                    if s not in seen:
                        seen.add(s)
                        strings.append(s)
            i = j + 1
        score = _score_jvm_pool(section_entries)
        if score > best_score:
            best_score = score
            best_base = hex(b.imagebase + sec.virtual_address) if hasattr(b, "imagebase") else None
            best_entries = section_entries
    return strings, len(best_entries), best_base, best_entries


_JVM_DESC_RE = re.compile(r"^(?:\([^)]*\)[VZBCSIFJD\[L].*|L[\w/$]+;|\[+[VZBCSIFJDL].*)$")
_OBFUSCATOR_TOKENS = (
    "classloader == null",
    "INVOKEVIRTUAL ",
    "INVOKESTATIC ",
    "INVOKESPECIAL ",
    "INVOKEINTERFACE ",
    "GETFIELD ",
    "PUTFIELD ",
    "AASTORE npe",
    "ARRAYLENGTH npe",
    "ANEWARRAY array size < 0",
)


def _score_jvm_pool(entries: list[dict[str, Any]]) -> int:
    """Heuristic JVM-string density score.

    +5 per obfuscator-runtime literal (rare in CRT data, common in our
    target pool); +1 per JVM-descriptor-shaped entry; +0 otherwise.
    """
    if not entries:
        return 0
    score = 0
    for e in entries:
        v = e.get("value") or ""
        if any(tok in v for tok in _OBFUSCATOR_TOKENS):
            score += 5
            continue
        if _JVM_DESC_RE.match(v):
            score += 1
    return score


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


def _canonical_jni_symbol(name: str, fmt: str) -> str:
    """Return the JNI lookup name for an exported symbol.

    Mach-O emits C symbols with a leading underscore in the symbol table
    (``_Java_...``) but the JVM resolves the unprefixed spec name via
    ``dlsym``. ELF and PE keep the spec name verbatim.
    """
    if fmt == "MachO" and name.startswith("_"):
        return name[1:]
    return name


def extract_exported_functions(b: lief.Binary) -> list[dict[str, Any]]:
    # Deduplicate by (name, addr), preserving first-seen order. LIEF exposes
    # each ELF dynamic symbol under more than one accessor on some versions, so
    # ``exported_symbols`` can list the same export twice; without this a single
    # Java_* export would be recorded as two identical native-registry entries.
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def _add(name: str, addr: str) -> None:
        key = (name, addr)
        if key not in seen:
            seen.add(key)
            result.append({"name": name, "addr": addr})

    if b.format == lief.Binary.FORMATS.PE and b.has_exports:
        for e in b.get_export().entries:
            _add(e.name, hex(b.imagebase + e.address))
    elif b.format in (lief.Binary.FORMATS.ELF, lief.Binary.FORMATS.MACHO):
        for s in b.exported_symbols:
            if s.name:
                _add(s.name, hex(s.value))
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


def introspect(path: Path, profile_name: str | None = None) -> BinaryReport:
    b = lief.parse(str(path))
    if b is None:
        raise IOError(f"LIEF could not parse {path}")
    fmt, arch = detect_format(b)
    strings, pool_bytes, pool_base, pool_entries = extract_string_pool(b)
    hidden = extract_hidden_classes(b)
    exports = extract_exported_functions(b)
    classes_in_pool = detect_native_obfuscator_classes(strings)
    # Profile selection: explicit name wins, else auto-detect.
    from .profile import detect_profile, get_profile
    profile = get_profile(profile_name) if profile_name else detect_profile(b)
    # Scan for runtime-RegisterNatives call sites. Each call site holds a
    # list of fnPtrs (one per method registered). String pointers are
    # typically built as `string_pool + offset` at runtime so we can't
    # extract names statically — manifest-merge will bind by matching
    # per-call fn-count to jar-parser's per-class ACC_NATIVE method count.
    jni_tables = find_jni_method_tables(b, profile=profile)
    jni_tables = attribute_tables_to_classes(jni_tables, strings)
    # Preserve each structurally discovered table as a first-class registry
    # record. Static tables may include exact names/descriptors; stack-built
    # tables still provide an ordered function-address list.
    flat_methods: list[dict[str, Any]] = []
    unreadable_tables: list[dict[str, Any]] = []
    for t in jni_tables:
        if t.get("source") == "register-natives-unreadable":
            # A RegisterNatives call site whose in-image JNINativeMethod[] was
            # visible (right stride and count) but whose name/descriptor bytes
            # did not decode. Recorded as an honest gap — no methods, no
            # fnAddrs are invented from the garbage.
            gap = {
                "source": "register-natives-unreadable",
                "registerNativesCallSite": t["callSite"],
                "nMethods": t.get("nMethods"),
                "reason": t.get("reason", "invalid-method-descriptors"),
                "profile": t.get("profile"),
                "abi": t.get("abi"),
            }
            if t.get("tableAddress"):
                gap["tableAddress"] = t["tableAddress"]
            unreadable_tables.append(gap)
            continue
        entry = {
            "source": t.get("source", "register-natives"),
            "registerNativesCallSite": t["callSite"],
            "nMethods": t.get("nMethods"),
            "fnAddrs": t["fnAddrs"],
            "profile": t.get("profile"),
            "abi": t.get("abi"),
        }
        if t.get("tableAddress"):
            entry["tableAddress"] = t["tableAddress"]
        if t.get("methods"):
            entry["methods"] = t["methods"]
        if t.get("classCandidates"):
            entry["classCandidates"] = t["classCandidates"]
        flat_methods.append(entry)

    # JNI name-based exports are a second specification-defined registration
    # mechanism. Keep the encoded symbol intact; manifest-merge resolves it
    # exactly against classes.json, avoiding ambiguous best-effort demangling.
    # Mach-O (and other platforms) prefix C symbols with a leading underscore
    # in the symbol table; dlsym and the JVM look the method up by its
    # unprefixed spec name, so normalize before recording so the exact
    # manifest match still succeeds.
    jni_exports = []
    for export in exports:
        symbol = _canonical_jni_symbol(export.get("name", ""), fmt)
        if symbol.startswith("Java_"):
            jni_exports.append(
                {
                    "source": "jni-export",
                    "fnSymbol": symbol,
                    "fnAddr": export["addr"],
                }
            )
    native_registry: list[dict[str, Any]] = [
        {"classNameCandidate": name} for name in classes_in_pool
    ] + jni_exports + flat_methods + unreadable_tables
    # JNI ID cache-table: bind every cclasses/cfields/cmethods slot
    # address back to its (owner_slot_addr, name, desc) by scanning the
    # binary for GetField/MethodID call sites. The lifter consumes this
    # to resolve raw DAT_xxxxxxx references in Ghidra pseudo-C back to
    # fully-qualified field/method names.
    cache_table: dict[str, Any] = {}
    if pool_base is not None and profile.extract_cache_table:
        try:
            from .cache_table import extract_cache_table
            cache_table = extract_cache_table(
                b, pool_entries,
                string_pool_base=int(pool_base, 16),
            )
        except Exception as exc:  # noqa: BLE001
            cache_table = {"error": f"{type(exc).__name__}: {exc}"}

    analysis: dict[str, Any] = {
        "profile": profile.name,
        "methodDiscovery": "jni-spec",
    }
    # Only surface the gap fact when there is one, so images with no
    # unreadable table keep a minimal, stable ``analysis`` block. The detailed
    # per-site records live in ``nativeRegistry`` under
    # ``source="register-natives-unreadable"``; this is the honest count the
    # CLI reports and manifest-merge turns into a binding gap.
    if unreadable_tables:
        analysis["unreadableTables"] = len(unreadable_tables)

    return BinaryReport(
        schema_version=1,
        input_path=str(path),
        fmt=fmt,
        arch=arch,
        sha256=sha256_file(path),
        string_pool=strings,
        string_pool_total_bytes=pool_bytes,
        string_pool_base=pool_base,
        string_pool_entries=pool_entries,
        hidden_classes=hidden,
        exported_functions=exports,
        native_registry=native_registry,
        per_class_lookups=[],
        cache_table=cache_table,
        analysis=analysis,
    )


def add_emulated_registry(
    report: BinaryReport, discovery: dict[str, Any]
) -> None:
    """Merge method tables captured by the optional emulator into a report."""
    grouped: dict[str | None, list[dict[str, Any]]] = {}
    for method in discovery.get("methods") or []:
        fn_addr = method.get("fnAddr")
        if not fn_addr:
            continue
        item = {
            key: method[key]
            for key in ("name", "desc", "fnAddr", "fnSymbol")
            if method.get(key) is not None
        }
        grouped.setdefault(method.get("className"), []).append(item)

    existing = {
        addr
        for entry in report.native_registry
        for addr in (
            entry.get("fnAddrs")
            or ([entry["fnAddr"]] if entry.get("fnAddr") else [])
        )
    }
    for class_name, methods in grouped.items():
        addresses = [m["fnAddr"] for m in methods]
        matching_table = next(
            (
                entry
                for entry in report.native_registry
                if entry.get("fnAddrs") == addresses
            ),
            None,
        )
        if matching_table is not None:
            matching_table["methods"] = methods
            matching_table["emulationCaptured"] = True
            if class_name:
                matching_table["className"] = class_name
            continue
        methods = [m for m in methods if m["fnAddr"] not in existing]
        if not methods:
            continue
        entry: dict[str, Any] = {
            "source": "register-natives-emulation",
            "abi": discovery.get("abi"),
            "fnAddrs": [m["fnAddr"] for m in methods],
            "nMethods": len(methods),
            "methods": methods,
        }
        if class_name:
            entry["className"] = class_name
        report.native_registry.append(entry)
        existing.update(entry["fnAddrs"])


def write_report(report: BinaryReport, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report.to_json_obj(), indent=2), encoding="utf-8")
