"""Bytecode lifter package.

Three top-level entry points:

  - :func:`lift_ghidra_function` — single decompiled function body
    → list of JVM instructions.
  - :func:`lift_ghidra_dump`     — full ghidra-dump.json → recovered/*.json.
  - :class:`LifterOptions`       — per-feature on/off flags.

Submodules:

  - :mod:`syms`         — symbol table types tracking inferred semantics
                          of local variables (jclass, jmethodID, jstring, ...).
  - :mod:`throw_reason` — recovers ``INVOKE owner.name(desc)`` from
                          ``"Cannot invoke X.Y.Z(args)"`` error strings.
  - :mod:`if_guard`     — recognises native-side exception-check guards
                          so they don't pollute the lifted body.
  - :mod:`jni_call`     — translates ``env->FnName(args)`` JNI calls into
                          JVM instruction sequences.
"""

from __future__ import annotations

from .options import LifterOptions
from .driver import lift_ghidra_function, lift_ghidra_dump

__all__ = ["LifterOptions", "lift_ghidra_function", "lift_ghidra_dump"]
