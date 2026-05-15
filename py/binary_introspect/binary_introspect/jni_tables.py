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

Native-obfuscator-style libraries build this array on the **stack** and
pass it to ``RegisterNatives``. String pointers are typically computed
at runtime as ``string_pool + offset`` so they're not compile-time
constants; function pointers, however, ARE PC-relative absolute LEAs
that we can recover by disassembly alone.
"""

from __future__ import annotations

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


# --------------------------------------------------------------------
# Pass 1 — find RegisterNatives call sites
# --------------------------------------------------------------------

def _find_register_natives_calls(
    cs,
    abi: Abi,
    exec_rngs: list[tuple[int, int, bytes]],
    register_natives_index: int,
) -> list[int]:
    """Disassemble every executable section and collect VAs of every
    indirect vtable call at offset ``register_natives_index * ptr_size``.
    """
    target_offset = register_natives_index * abi.pointer_size
    sites: list[int] = []
    for start_va, _end_va, raw in exec_rngs:
        for ins in cs.disasm(raw, start_va):
            off = abi.is_indirect_vtable_call(ins)
            if off is not None and off == target_offset:
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
    window: int = 0x600,
) -> dict[str, Any]:
    """Back-scan up to ``window`` bytes before ``call_va`` collecting:

      - PC-relative LEAs whose target lands in an executable section
        (these are fnPtrs being stored to the local JNINativeMethod[]),
      - the most recent ``mov <nMethods-reg>, imm`` (the table size).

    Returns ``{"fnAddrs": [...], "nMethods": int | None}``.
    """
    raw: bytes | None = None
    base_va = 0
    for s, e, r in exec_rngs:
        if s <= call_va < e:
            raw = r
            base_va = s
            break
    if raw is None:
        return {"fnAddrs": [], "nMethods": None}

    end_off = call_va - base_va
    start_off = max(0, end_off - window)
    chunk = raw[start_off:end_off]

    fn_addrs: list[int] = []
    n_methods: int | None = None
    last_lea_to_reg: dict[int, int] = {}
    for ins in cs.disasm(chunk, base_va + start_off):
        tgt = abi.decode_pc_relative_lea(ins)
        if tgt is not None:
            if ins.operands[0].type == 1:  # X86_OP_REG (= REG kind)
                if _in_any_range(tgt, exec_rngs):
                    last_lea_to_reg[ins.operands[0].reg] = tgt
            continue
        stack_store = abi.is_stack_store(ins)
        if stack_store is not None:
            _disp, src_reg = stack_store
            fn = last_lea_to_reg.pop(src_reg, None)
            if fn is not None:
                fn_addrs.append(fn)
            continue
        imm = abi.is_n_methods_load(ins)
        if imm is not None:
            n_methods = imm

    seen: set[int] = set()
    fn_addrs = [a for a in fn_addrs if not (a in seen or seen.add(a))]
    if n_methods is not None and n_methods > 0:
        fn_addrs = fn_addrs[-n_methods:]
    return {"fnAddrs": fn_addrs, "nMethods": n_methods}


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

    sites = _find_register_natives_calls(
        cs, abi, exec_rngs, profile.register_natives_index
    )

    tables: list[dict[str, Any]] = []
    for site in sites:
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
                    })
                continue
        h = _harvest_call(cs, abi, site, exec_rngs)
        if not h["fnAddrs"]:
            continue
        tables.append({
            "callSite": hex(site),
            "fnAddrs": [hex(a) for a in h["fnAddrs"]],
            "nMethods": h["nMethods"],
            "profile": profile.name,
            "abi": abi.name,
        })
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
