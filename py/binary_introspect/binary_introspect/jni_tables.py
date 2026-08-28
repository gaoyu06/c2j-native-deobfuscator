"""Discover JNINativeMethod descriptor tables in a native library.

This module is architecture-agnostic: every CPU-specific assumption
(which register holds ``nMethods``, how indirect vtable calls look, how
a "load address of constant" instruction is decoded) is delegated to an
:class:`~binary_introspect.arch.Abi` object. Obfuscator-variant-specific
behavior (per-class vs shared-dispatch call site harvest) is delegated
to the active :class:`~binary_introspect.profile.Profile`.

JNI's ``RegisterNatives`` consumes:

    struct JNINativeMethod {
        const char *name;
        const char *signature;
        void       *fnPtr;
    };

Libraries may keep this array in a mapped data section or build it on the
stack. Static entries provide names, descriptors, and function pointers;
stack-built entries still expose function-address LEAs in common compiler
output.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

import lief

try:
    import capstone  # noqa: F401  — presence check
    _HAS_CAPSTONE = True
except ImportError:
    _HAS_CAPSTONE = False

from .arch import Abi, detect_abi
from .profile import Profile, JNI_REGISTER_NATIVES_INDEX, detect_profile


# --------------------------------------------------------------------
# Executable / readable section discovery
# --------------------------------------------------------------------

def _exec_ranges(b: lief.Binary, image_base: int) -> list[tuple[int, int, bytes]]:
    """Return ``(start_va, end_va_exclusive, raw_bytes)`` for every
    executable section."""
    out: list[tuple[int, int, bytes]] = []
    if b.format == lief.Binary.FORMATS.PE:
        for sec in b.sections:
            if sec.size == 0 or (sec.characteristics & 0x20000000) == 0:
                continue
            raw = bytes(sec.content)
            vs = image_base + sec.virtual_address
            out.append((vs, vs + len(raw), raw))
    elif b.format == lief.Binary.FORMATS.ELF:
        for sec in b.sections:
            try:
                flags = int(sec.flags)
            except Exception:
                continue
            if (flags & 0x4) == 0 or sec.size == 0:
                continue
            raw = bytes(sec.content)
            out.append((sec.virtual_address, sec.virtual_address + len(raw), raw))
    else:
        for sec in b.sections:
            if "TEXT" in (getattr(sec, "segment_name", "") or "").upper() and sec.size > 0:
                out.append((sec.virtual_address, sec.virtual_address + sec.size, bytes(sec.content)))
    return out


def _in_any_range(va: int, ranges: list[tuple[int, int, bytes]]) -> bool:
    return any(s <= va < e for s, e, _ in ranges)


def _mapped_ranges(b: lief.Binary, image_base: int) -> list[tuple[int, int, bytes]]:
    """Return addressable bytes for every non-empty section."""
    out: list[tuple[int, int, bytes]] = []
    for sec in b.sections:
        if sec.size == 0:
            continue
        raw = bytes(sec.content)
        if not raw:
            continue
        start = sec.virtual_address
        if b.format == lief.Binary.FORMATS.PE:
            start += image_base
        out.append((start, start + len(raw), raw))
    return out


def _read_at(
    ranges: list[tuple[int, int, bytes]], va: int, size: int
) -> bytes | None:
    for start, end, raw in ranges:
        if start <= va and va + size <= end:
            offset = va - start
            return raw[offset:offset + size]
    return None


def _resolve_pointer(
    value: int,
    ranges: list[tuple[int, int, bytes]],
    image_base: int,
) -> int:
    """Resolve an absolute pointer, accepting a PE RVA as a fallback."""
    if _in_any_range(value, ranges):
        return value
    rebased = image_base + value
    if image_base and _in_any_range(rebased, ranges):
        return rebased
    return value


def _relocation_targets(
    b: lief.Binary,
    image_base: int,
    ranges: list[tuple[int, int, bytes]],
) -> dict[int, int]:
    """Map pointer-storage VAs to relocation targets when LIEF exposes them."""
    targets: dict[int, int] = {}
    for relocation in getattr(b, "relocations", []):
        try:
            location = int(relocation.address)
        except (AttributeError, TypeError, ValueError):
            continue
        if image_base and not _in_any_range(location, ranges):
            location += image_base

        try:
            addend = int(getattr(relocation, "addend", 0) or 0)
        except (TypeError, ValueError):
            addend = 0
        symbol_value = 0
        try:
            symbol = relocation.symbol
            symbol_value = int(getattr(symbol, "value", 0) or 0)
        except (AttributeError, TypeError, ValueError):
            pass
        target = symbol_value + addend
        if target:
            targets[location] = _resolve_pointer(target, ranges, image_base)
    return targets


def _read_pointer(
    ranges: list[tuple[int, int, bytes]],
    va: int,
    pointer_size: int,
    image_base: int,
    relocations: dict[int, int] | None = None,
) -> int | None:
    if relocations and va in relocations:
        return relocations[va]
    raw = _read_at(ranges, va, pointer_size)
    if raw is None:
        return None
    return _resolve_pointer(
        int.from_bytes(raw, "little", signed=False), ranges, image_base
    )


def _read_cstring(
    ranges: list[tuple[int, int, bytes]], va: int, limit: int = 4096
) -> str | None:
    for start, end, raw in ranges:
        if not (start <= va < end):
            continue
        offset = va - start
        tail = raw[offset:min(len(raw), offset + limit)]
        nul = tail.find(b"\0")
        if nul < 0:
            return None
        try:
            return tail[:nul].decode("utf-8")
        except UnicodeDecodeError:
            return None
    return None


_METHOD_NAME_RE = re.compile(r"^(?:<init>|<clinit>|[^\x00/().;\[]+)$")
_METHOD_DESC_RE = re.compile(
    r"^\((?:\[*[ZBCSIFJD]|\[*L[^;()\x00]+;)*\)"
    r"(?:V|\[*[ZBCSIFJD]|\[*L[^;()\x00]+;)$"
)


def _decode_static_method_table(
    table_va: int,
    n_methods: int | None,
    pointer_size: int,
    mapped_rngs: list[tuple[int, int, bytes]],
    exec_rngs: list[tuple[int, int, bytes]],
    image_base: int,
    relocations: dict[int, int] | None = None,
) -> list[dict[str, Any]]:
    """Decode a standard in-image ``JNINativeMethod[]`` when fully static."""
    if n_methods is None or not (0 < n_methods <= 4096):
        return []
    stride = pointer_size * 3
    methods: list[dict[str, Any]] = []
    for index in range(n_methods):
        entry = table_va + index * stride
        name_ptr = _read_pointer(
            mapped_rngs, entry, pointer_size, image_base, relocations
        )
        desc_ptr = _read_pointer(
            mapped_rngs,
            entry + pointer_size,
            pointer_size,
            image_base,
            relocations,
        )
        fn_ptr = _read_pointer(
            mapped_rngs,
            entry + pointer_size * 2,
            pointer_size,
            image_base,
            relocations,
        )
        if name_ptr is None or desc_ptr is None or fn_ptr is None:
            return []
        name = _read_cstring(mapped_rngs, name_ptr)
        desc = _read_cstring(mapped_rngs, desc_ptr)
        if (
            name is None
            or desc is None
            or _METHOD_NAME_RE.fullmatch(name) is None
            or _METHOD_DESC_RE.fullmatch(desc) is None
            or not _in_any_range(fn_ptr, exec_rngs)
        ):
            return []
        methods.append({"name": name, "desc": desc, "fnAddr": fn_ptr})
    return methods


# --------------------------------------------------------------------
# Pass 1 — find RegisterNatives call sites
# --------------------------------------------------------------------

def _find_register_natives_calls(
    cs,
    abi: Abi,
    exec_rngs: list[tuple[int, int, bytes]],
    register_natives_index: int,
) -> list[int]:
    """Collect direct and split indirect branches through the JNI slot."""
    target_offset = register_natives_index * abi.pointer_size
    sites: list[int] = []
    for start_va, _end_va, raw in exec_rngs:
        loaded_slots: dict[int, tuple[int, int]] = {}
        for ins in cs.disasm(raw, start_va):
            off = abi.is_indirect_vtable_call(ins)
            if off is not None and off == target_offset:
                sites.append(ins.address)
                continue
            loaded = abi.vtable_slot_load(ins)
            if loaded is not None:
                register, displacement = loaded
                loaded_slots[register] = (displacement, ins.address + ins.size)
                continue
            branch_register = abi.indirect_branch_register(ins)
            if branch_register is None:
                continue
            slot = loaded_slots.get(branch_register)
            if (
                slot is not None
                and slot[0] == target_offset
                and ins.address - slot[1] <= 0x20
            ):
                sites.append(ins.address)
    return sites


# --------------------------------------------------------------------
# Pass 2 — harvest per-class table (one branch per call site)
# --------------------------------------------------------------------

def _harvest_call(
    cs,
    abi: Abi,
    call_va: int,
    exec_rngs: list[tuple[int, int, bytes]],
    mapped_rngs: list[tuple[int, int, bytes]],
    image_base: int,
    relocations: dict[int, int] | None = None,
    window: int = 0x600,
) -> dict[str, Any]:
    """Back-scan up to ``window`` bytes before ``call_va`` collecting:

      - PC-relative LEAs whose target lands in an executable section
        (these are fnPtrs being stored to the local JNINativeMethod[]),
      - the most recent ``mov <nMethods-reg>, imm`` (the table size).

    If argument 3 points at an in-image standard ``JNINativeMethod[]``, names
    and descriptors are decoded too. Otherwise stack stores still provide the
    ordered function-pointer list.
    """
    raw: bytes | None = None
    base_va = 0
    for s, e, r in exec_rngs:
        if s <= call_va < e:
            raw = r
            base_va = s
            break
    if raw is None:
        return {"fnAddrs": [], "nMethods": None, "methods": []}

    end_off = call_va - base_va
    start_off = max(0, end_off - window)
    chunk = raw[start_off:end_off]

    fn_addrs: list[int] = []
    n_methods: int | None = None
    last_lea_to_reg: dict[int, int] = {}
    address_candidates: list[int] = []
    methods_table_va: int | None = None
    for ins in cs.disasm(chunk, base_va + start_off):
        tgt = abi.decode_pc_relative_lea(ins)
        if tgt is not None:
            if ins.operands[0].type == 1:  # X86_OP_REG (= REG kind)
                last_lea_to_reg[ins.operands[0].reg] = tgt
                if _in_any_range(tgt, exec_rngs):
                    pass
                elif _in_any_range(tgt, mapped_rngs):
                    address_candidates.append(tgt)
                if ins.operands[0].reg in abi.methods_arg_regs:
                    methods_table_va = tgt
            continue
        # Compilers often materialise a table address in a temporary and then
        # move it into the ABI's third-argument register.
        try:
            from capstone import x86_const
            if ins.mnemonic == "mov" and len(ins.operands) == 2:
                dst, src = ins.operands
                if (
                    dst.type == x86_const.X86_OP_REG
                    and src.type == x86_const.X86_OP_REG
                    and src.reg in last_lea_to_reg
                ):
                    last_lea_to_reg[dst.reg] = last_lea_to_reg[src.reg]
                    if dst.reg in abi.methods_arg_regs:
                        methods_table_va = last_lea_to_reg[src.reg]
        except (ImportError, AttributeError):
            pass
        stack_store = abi.is_stack_store(ins)
        if stack_store is not None:
            _disp, src_reg = stack_store
            fn = last_lea_to_reg.get(src_reg)
            if fn is not None and _in_any_range(fn, exec_rngs):
                fn_addrs.append(fn)
            continue
        imm = abi.is_n_methods_load(ins)
        if imm is not None:
            n_methods = imm

    seen: set[int] = set()
    fn_addrs = [a for a in fn_addrs if not (a in seen or seen.add(a))]
    if n_methods is not None and n_methods > 0:
        fn_addrs = fn_addrs[-n_methods:]

    methods: list[dict[str, Any]] = []
    table_candidates = (
        ([methods_table_va] if methods_table_va is not None else [])
        + list(reversed(address_candidates))
    )
    seen_tables: set[int] = set()
    for candidate in table_candidates:
        if candidate in seen_tables:
            continue
        seen_tables.add(candidate)
        decoded = _decode_static_method_table(
            candidate,
            n_methods,
            abi.pointer_size,
            mapped_rngs,
            exec_rngs,
            image_base,
            relocations,
        )
        if decoded:
            methods_table_va = candidate
            methods = decoded
            fn_addrs = [m["fnAddr"] for m in methods]
            break
    return {
        "fnAddrs": fn_addrs,
        "nMethods": n_methods,
        "methods": methods,
        "tableAddress": methods_table_va if methods else None,
    }


# --------------------------------------------------------------------
# Pass 2-alt — shared-dispatch harvest (one call site, many branches)
# --------------------------------------------------------------------

def _harvest_dispatch(
    cs,
    abi: Abi,
    call_va: int,
    exec_rngs: list[tuple[int, int, bytes]],
    window: int = 0x4000,
) -> list[dict[str, Any]]:
    """Multi-branch harvest for obfuscators that funnel every class init
    through one shared ``RegisterNatives`` call.

    Treats every ``mov <nMethods-reg>, imm`` as a fresh "branch boundary":
    each boundary closes off one class's table (composed of the fnPtrs
    seen since the previous boundary) and starts a new one.
    """
    raw: bytes | None = None
    base_va = 0
    for s, e, r in exec_rngs:
        if s <= call_va < e:
            raw = r
            base_va = s
            break
    if raw is None:
        return []
    end_off = call_va - base_va
    start_off = max(0, end_off - window)
    chunk = raw[start_off:end_off]

    branches: list[dict[str, Any]] = []
    fn_addrs_current: list[int] = []
    last_lea_to_reg: dict[int, int] = {}

    for ins in cs.disasm(chunk, base_va + start_off):
        tgt = abi.decode_pc_relative_lea(ins)
        if tgt is not None:
            if ins.operands[0].type == 1 and _in_any_range(tgt, exec_rngs):
                last_lea_to_reg[ins.operands[0].reg] = tgt
            continue
        stack_store = abi.is_stack_store(ins)
        if stack_store is not None:
            _disp, src_reg = stack_store
            fn = last_lea_to_reg.pop(src_reg, None)
            if fn is not None:
                fn_addrs_current.append(fn)
            continue
        imm = abi.is_n_methods_load(ins)
        if imm is not None:
            # Branch boundary: dedup + take last N.
            seen: set[int] = set()
            deduped = [a for a in fn_addrs_current if not (a in seen or seen.add(a))]
            if imm > 0 and len(deduped) >= imm:
                branches.append({"fnAddrs": deduped[-imm:], "nMethods": imm})
            fn_addrs_current.clear()
            last_lea_to_reg.clear()

    return branches


# --------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------

def find_jni_method_tables(
    b: lief.Binary,
    profile: Profile | None = None,
    abi: Abi | None = None,
) -> list[dict[str, Any]]:
    """Discover every RegisterNatives call site in ``b`` and return one
    record per (call site, branch).

    Both the profile (obfuscator variant) and the ABI (architecture +
    OS calling convention) can be explicitly supplied; either defaults
    to auto-detection.

    Returns ``[{"callSite", "fnAddrs", "nMethods", "profile", "abi"}, ...]``.
    Empty list when capstone is unavailable, the ABI cannot be detected,
    or no call sites are found.
    """
    if not _HAS_CAPSTONE or b is None:
        return []

    abi = abi or detect_abi(b)
    if abi is None:
        return []
    profile = profile or detect_profile(b)
    cs = abi.disassembler()
    if cs is None:
        return []

    image_base = getattr(b, "imagebase", 0) or 0
    exec_rngs = _exec_ranges(b, image_base)
    if not exec_rngs:
        return []
    mapped_rngs = _mapped_ranges(b, image_base)
    relocations = _relocation_targets(b, image_base, mapped_rngs)

    sites = _find_register_natives_calls(
        cs, abi, exec_rngs, profile.register_natives_index
    )

    tables: list[dict[str, Any]] = []
    for site in sites:
        h = _harvest_call(
            cs,
            abi,
            site,
            exec_rngs,
            mapped_rngs,
            image_base,
            relocations,
        )
        if profile.harvest_strategy == "shared_dispatch":
            branches = _harvest_dispatch(cs, abi, site, exec_rngs)
            if branches:
                for br in branches:
                    tables.append({
                        "callSite": hex(site),
                        "fnAddrs": [hex(a) for a in br["fnAddrs"]],
                        "nMethods": br["nMethods"],
                        "profile": profile.name,
                        "abi": abi.name,
                        "source": "register-natives-stack",
                    })
                continue
        elif profile.harvest_strategy == "auto" and not h["methods"]:
            branches = _harvest_dispatch(cs, abi, site, exec_rngs)
            # A shared call site is only established when more than one
            # independently sized table was recovered. A single branch is
            # equivalent to the normal call-site harvest.
            if len(branches) > 1:
                for br in branches:
                    tables.append({
                        "callSite": hex(site),
                        "fnAddrs": [hex(a) for a in br["fnAddrs"]],
                        "nMethods": br["nMethods"],
                        "profile": profile.name,
                        "abi": abi.name,
                        "source": "register-natives-stack",
                    })
                continue
        if not h["fnAddrs"]:
            continue
        table = {
            "callSite": hex(site),
            "fnAddrs": [hex(a) for a in h["fnAddrs"]],
            "nMethods": h["nMethods"],
            "profile": profile.name,
            "abi": abi.name,
            "source": (
                "register-natives-static"
                if h["methods"]
                else "register-natives-stack"
            ),
        }
        if h["methods"]:
            table["tableAddress"] = hex(h["tableAddress"])
            table["methods"] = [
                {
                    "name": method["name"],
                    "desc": method["desc"],
                    "fnAddr": hex(method["fnAddr"]),
                }
                for method in h["methods"]
            ]
        tables.append(table)
    return tables


def attribute_tables_to_classes(
    tables: list[dict[str, Any]],
    string_pool: Iterable[str],
) -> list[dict[str, Any]]:
    """Stamp each table with the list of plausible Java class names from
    the binary's string pool. Final per-table class binding happens at
    manifest-merge time using jar-parser's known (class, methods) tuples.
    """
    import re
    classes_in_pool = [
        s for s in string_pool
        if s and "/" in s and not s.startswith("(") and not s.endswith(";")
        and re.fullmatch(r"[A-Za-z_$/][A-Za-z0-9_$/]*", s)
    ]
    for t in tables:
        t["classCandidates"] = classes_in_pool
    return tables
