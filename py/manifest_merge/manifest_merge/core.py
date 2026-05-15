"""Merge classes.json (jar-parser) + binary.json (binary-introspect)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def merge(classes: dict[str, Any], binary: dict[str, Any] | None) -> dict[str, Any]:
    """Produce a manifest.json by joining the two reports.

    The merge is permissive: missing native-side data (fn addresses, lookups)
    is left ``null`` rather than raising. Downstream consumers (dynamic-trace,
    static-reverse) populate those fields later.
    """
    out: dict[str, Any] = {
        "schemaVersion": 1,
        "input": {
            "jar": classes.get("input", {}).get("jarPath"),
            "lib": (binary or {}).get("input", {}).get("libPath"),
        },
        "loaderClass": classes.get("loaderClass"),
        "loaderRegisterMethod": classes.get("loaderRegisterMethod"),
        "loaderRegisterDesc": classes.get("loaderRegisterDesc"),
        "nativeDir": classes.get("nativeDir"),
        "stringPool": ((binary or {}).get("stringPool") or {}).get("strings") or [],
        "stringPoolEntries": ((binary or {}).get("stringPool") or {}).get("entries") or [],
        "classes": [],
        "hiddenClasses": (binary or {}).get("hiddenClasses") or [],
        "cacheTable": (binary or {}).get("cacheTable") or {},
    }

    # Build the candidate-class set from the binary report (Phase 1 hint: which
    # classes were registered natively). Use this set to *cross-check* jar
    # findings, not as the source of truth — the jar is authoritative.
    binary_candidates: set[str] = set()
    for entry in (binary or {}).get("nativeRegistry") or []:
        if name := entry.get("classNameCandidate"):
            binary_candidates.add(name)
        elif name := entry.get("className"):
            binary_candidates.add(name)

    # Per-class fn-address index (if static disasm produced one)
    fn_index: dict[tuple[str, str, str], dict[str, Any]] = {}
    for entry in (binary or {}).get("nativeRegistry") or []:
        cls = entry.get("className")
        if not cls:
            continue
        for m in entry.get("methods", []):
            fn_index[(cls, m["name"], m["desc"])] = m

    # ALSO bind by position: when binary-introspect found a RegisterNatives
    # call site with N fnAddrs, and a jar-parser class has N obfuscated
    # native methods, assume the binary's fn list matches the class's
    # declaration order (native-obfuscator emits __ngen_methods[] in source
    # declaration order). This is the primary signal when the binary has
    # no `Java_<class>_<method>` exports — common with j2cc-style obfuscators.
    register_sites: list[dict[str, Any]] = [
        e for e in (binary or {}).get("nativeRegistry") or []
        if "fnAddrs" in e
    ]
    # Pre-compute (class -> ordered native methods) for jar-parser data.
    class_natives: list[tuple[str, list[dict[str, Any]]]] = []
    for cls in classes.get("classes", []):
        nats = [m for m in cls.get("methods", []) if m.get("isObfuscatedNative")]
        if nats:
            class_natives.append((cls["name"], nats))
    # Match each call site to the first class with a matching native count.
    # Each class can only be bound once.
    used_classes: set[str] = set()
    for site in register_sites:
        addrs = site.get("fnAddrs") or []
        n = len(addrs)
        if n == 0:
            continue
        for cname, nats in class_natives:
            if cname in used_classes or len(nats) != n:
                continue
            used_classes.add(cname)
            for nat, addr in zip(nats, addrs):
                fn_index[(cname, nat["name"], nat["desc"])] = {
                    "fnAddr": addr,
                    "fnSymbol": f"__j2c_native_{cname.replace('/', '_')}_{nat['name']}",
                }
            site["boundTo"] = cname
            break

    lookups_by_class: dict[str, dict[str, Any]] = {}
    for entry in (binary or {}).get("perClassLookups") or []:
        # Some implementations key per-class lookups by classId (int); we accept either
        # key. Bind by class name when supplied; otherwise leave unattached.
        if cls := entry.get("className"):
            lookups_by_class[cls] = {
                "cstrings": _entries(entry.get("cstrings")),
                "cclasses": _entries(entry.get("cclasses")),
                "cmethods": _entries(entry.get("cmethods")),
                "cfields":  _entries(entry.get("cfields")),
            }

    for cls in classes.get("classes", []):
        cname = cls["name"]
        merged_methods = []
        for m in cls.get("methods", []):
            mm: dict[str, Any] = {
                "name": m["name"],
                "desc": m["desc"],
                "access": m["access"],
                "isObfuscatedNative": bool(m.get("isObfuscatedNative")),
            }
            if m.get("signature") is not None:
                mm["signature"] = m["signature"]
            fn = fn_index.get((cname, m["name"], m["desc"]))
            if fn:
                if fn.get("fnAddr"):
                    mm["fnAddr"] = fn["fnAddr"]
                if fn.get("fnSymbol"):
                    mm["fnSymbol"] = fn["fnSymbol"]
            merged_methods.append(mm)

        merged_cls: dict[str, Any] = {
            "name": cname,
            "superName": cls.get("superName"),
            "interfaces": cls.get("interfaces") or [],
            "version": cls.get("version", 52),
            "access": cls.get("access", 0),
            "sourceFile": cls.get("sourceFile"),
            "fields": cls.get("fields") or [],
            "methods": merged_methods,
        }
        if cls.get("signature") is not None:
            merged_cls["signature"] = cls["signature"]
        if cname in lookups_by_class:
            merged_cls["lookups"] = lookups_by_class[cname]
        if cname in binary_candidates:
            # If the binary "knows" about this class, surface that fact.
            merged_cls["knownByBinary"] = True
        out["classes"].append(merged_cls)

    return out


def _entries(table: Any) -> list[Any]:
    if not table:
        return []
    return table.get("entries", []) if isinstance(table, dict) else table


def write(merged: dict[str, Any], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")


def stats(merged: dict[str, Any]) -> dict[str, int]:
    total_classes = len(merged["classes"])
    obf_methods = 0
    resolved_fn = 0
    for cls in merged["classes"]:
        for m in cls["methods"]:
            if m.get("isObfuscatedNative"):
                obf_methods += 1
                if m.get("fnAddr"):
                    resolved_fn += 1
    return {
        "classes": total_classes,
        "obfuscatedMethods": obf_methods,
        "fnAddrResolved": resolved_fn,
        "hiddenClasses": len(merged.get("hiddenClasses") or []),
    }
