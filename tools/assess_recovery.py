#!/usr/bin/env python3
"""Assess recovery quality on a clean.jar produced by j2c-dumper.

Compares the original jar (with obfuscated native stubs) to the recovered
jar, counting:
  - total classes / methods
  - methods that were native-obfuscated in the input
  - of those, how many have non-trivial recovered bytecode (more than just
    a single TRETURN)
  - sample bytecode for a few representative methods
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def list_class_methods(jar: Path, javap_extra: list[str] = []) -> dict[str, list[dict]]:
    """Return per-class list of methods with their bytecode lines."""
    out: dict[str, list[dict]] = {}
    with zipfile.ZipFile(jar) as zf:
        class_names = [n[:-6].replace("/", ".") for n in zf.namelist() if n.endswith(".class")]
    for cn in class_names:
        try:
            r = subprocess.run(
                ["javap", "-p", "-c", "-classpath", str(jar), cn, *javap_extra],
                capture_output=True, text=True, check=False,
            )
        except FileNotFoundError:
            return {}
        out[cn] = parse_javap(r.stdout)
    return out


METHOD_HEADER_RE = re.compile(r"^\s+(?:public|private|protected|static|final|native|abstract|synchronized|\s)+.*?\s*([\w<>$]+\s*\([^)]*\))")
CODE_LINE_RE = re.compile(r"^\s+(\d+):\s*(\w+)")


def normalize_sig(sig: str) -> str:
    """Collapse whitespace and strip access modifiers to allow matching across
    pre/post-recovery jars where access flags may differ (e.g. ACC_NATIVE)."""
    s = re.sub(r"\s+", " ", sig).strip()
    for mod in ("public ", "private ", "protected ", "static ", "final ",
                "native ", "abstract ", "synchronized ", "transient "):
        s = s.replace(mod, "")
    return s.strip()


def parse_javap(text: str) -> list[dict]:
    methods: list[dict] = []
    current = None
    in_code = False
    for line in text.splitlines():
        m = METHOD_HEADER_RE.match(line)
        if m and " " in line and "{" not in line:
            if current:
                methods.append(current)
            current = {"sig": line.strip().rstrip(";"), "ops": [], "is_native": "native" in line}
            in_code = False
            continue
        if line.strip() == "Code:":
            in_code = True
            continue
        if in_code:
            mc = CODE_LINE_RE.match(line)
            if mc:
                current["ops"].append(mc.group(2))
    if current:
        methods.append(current)
    return methods


def assess(original: Path, recovered: Path):
    orig = list_class_methods(original)
    rec = list_class_methods(recovered)
    print(f"Original jar: {len(orig)} classes")
    print(f"Recovered jar: {len(rec)} classes")
    print()

    obf_total = 0
    non_trivial = 0
    runnable = 0
    method_size = collections.Counter()
    examples: list[tuple[str, str, list[str]]] = []

    # The recovery target = methods that are `native` in the *original* jar
    # (these are the ones the obfuscator replaced with stubs). We then match
    # them up with the corresponding methods in the *recovered* jar (where
    # they have non-native bytecode bodies — if recovery succeeded).
    return_ops = {"return", "ireturn", "lreturn", "freturn", "dreturn", "areturn"}
    for cn, methods in orig.items():
        rec_class = rec.get(cn)
        if rec_class is None:
            continue
        rec_by_sig = {normalize_sig(m["sig"]): m for m in rec_class}
        for m in methods:
            if not m["is_native"]:
                continue
            obf_total += 1
            r = rec_by_sig.get(normalize_sig(m["sig"]))
            if not r:
                continue
            ops = r["ops"]
            n = len(ops)
            method_size[n] += 1
            non_return = [o for o in ops if o not in return_ops]
            if len(non_return) >= 3:
                non_trivial += 1
                if len(examples) < 5 and 5 <= n <= 40:
                    examples.append((cn, m["sig"], ops))

    print(f"obfuscated-native methods: {obf_total}")
    print(f"non-trivial recovery (>=3 non-return ops): {non_trivial}  "
          f"({(100*non_trivial//obf_total) if obf_total else 0}%)")
    print()
    print("method-size histogram (recovered):")
    for size in sorted(method_size):
        bar = "#" * method_size[size]
        print(f"  {size:3d} insns: {bar} ({method_size[size]})")

    print()
    print(f"sample recoveries (up to 5 representative methods):")
    for cn, sig, ops in examples:
        print(f"\n  --- {cn} :: {sig} ---")
        for op in ops:
            print(f"    {op}")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--original", required=True, type=Path)
    ap.add_argument("--recovered", required=True, type=Path)
    args = ap.parse_args(argv)
    assess(args.original, args.recovered)


if __name__ == "__main__":
    main()
