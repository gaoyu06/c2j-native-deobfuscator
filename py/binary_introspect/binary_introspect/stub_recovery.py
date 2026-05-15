"""Synthesize recovered/*.json stubs for native methods with known fnAddr
but no decompiled body.

Produces a minimal but VERIFY-CLEAN body for each native method:
    - For void: simply RETURN.
    - For numeric returns: ICONST_0 / LCONST_0 / FCONST_0 / DCONST_0 + xRETURN.
    - For object returns: ACONST_NULL + ARETURN.
    - All bodies carry a marker INVOKESTATIC `j2c/Trace.NATIVE_STUB:()V`
      whose method name embeds the original fnAddr, so the recovered
      jar's class files clearly mark "this method's real body lives at
      <fnAddr> in the native blob — recovery pending".

Why this is useful even without real body recovery:
    - The output jar's classes lose ACC_NATIVE on these methods, so
      static analysis tools (decompilers, IDE indexing) treat them as
      regular methods.
    - The fnAddr marker is preserved in bytecode, so reverse-engineers
      can map back to the binary.
    - When the Ghidra script later produces actual pseudo-C, these
      stubs can be replaced incrementally without redoing the rest of
      the pipeline.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def _safe_filename(owner: str, name: str, desc: str) -> str:
    raw = f"{owner}__{name}__{desc}"
    return re.sub(r"[^A-Za-z0-9_]", "_", raw)


def _return_op_and_default(desc: str) -> list[dict[str, Any]]:
    """For a method descriptor like (II)I, return the JVM instructions
    needed to satisfy the verifier with a default value + return."""
    ret = desc.rsplit(")", 1)[-1]
    ch = ret[0] if ret else "V"
    if ch == "V":
        return [{"op": "RETURN"}]
    if ch in ("I", "B", "C", "S", "Z"):
        return [{"op": "ICONST_0"}, {"op": "IRETURN"}]
    if ch == "J":
        return [{"op": "LCONST_0"}, {"op": "LRETURN"}]
    if ch == "F":
        return [{"op": "FCONST_0"}, {"op": "FRETURN"}]
    if ch == "D":
        return [{"op": "DCONST_0"}, {"op": "DRETURN"}]
    # Object/array: ACONST_NULL + (optional CHECKCAST) + ARETURN
    if ch == "[" or (ch == "L" and ret.endswith(";")):
        type_internal = ret if ch == "[" else ret[1:-1]
        out: list[dict[str, Any]] = [{"op": "ACONST_NULL"}]
        if ch == "L" and type_internal != "java/lang/Object":
            out.append({"op": "CHECKCAST", "type": type_internal})
        out.append({"op": "ARETURN"})
        return out
    return [{"op": "ACONST_NULL"}, {"op": "ARETURN"}]


def synthesize_stubs(
    manifest_path: Path,
    output_dir: Path,
    include_unbound: bool = True,
) -> int:
    """Read manifest.json; emit a recovered/*.json stub for every native
    method. Methods with a known fnAddr get a marker encoding the address;
    methods without get an "unbound" marker. Returns the number of stubs.

    Skips files that already exist in `output_dir` so this can be called
    as a "fill-in" after real recovery has covered some methods.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    existing = {p.stem for p in output_dir.glob("*.json")}
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    count = 0
    for cls in manifest.get("classes", []):
        owner = cls["name"]
        for m in cls.get("methods", []):
            if not m.get("isObfuscatedNative"):
                continue
            fn_addr = m.get("fnAddr")
            if not fn_addr and not include_unbound:
                continue
            stem = _safe_filename(owner, m["name"], m["desc"])
            if stem in existing:
                continue
            if fn_addr:
                marker_method = f"NATIVE_STUB_{fn_addr.replace('0x', 'at_')}"
                note = (
                    f"native body resides at {fn_addr} — full pseudo-C "
                    f"recovery requires Ghidra (use ExtractRegisterNatives.java)."
                )
                kind = "native_stub"
                confidence = "stub"
            else:
                marker_method = "NATIVE_STUB_unbound"
                note = (
                    "native body address not yet recovered: static-path "
                    "table extraction couldn't match this method to a "
                    "RegisterNatives call site. Run Ghidra with "
                    "ExtractRegisterNatives.java for deeper analysis."
                )
                kind = "native_stub_unbound"
                confidence = "stub_unbound"
            instructions: list[dict[str, Any]] = [
                {
                    "op": "INVOKESTATIC",
                    "owner": "j2c/Trace",
                    "name": marker_method,
                    "desc": "()V",
                    "dynamic": kind,
                },
            ]
            instructions.extend(_return_op_and_default(m["desc"]))
            recovered = {
                "schemaVersion": 1,
                "owner": owner,
                "name": m["name"],
                "desc": m["desc"],
                "source": "static",
                "confidence": confidence,
                "instructions": instructions,
                "note": note,
            }
            if fn_addr:
                recovered["fnAddr"] = fn_addr
            if m.get("fnSymbol"):
                recovered["fnSymbol"] = m["fnSymbol"]
            (output_dir / f"{stem}.json").write_text(
                json.dumps(recovered, indent=2), encoding="utf-8"
            )
            count += 1
    return count
