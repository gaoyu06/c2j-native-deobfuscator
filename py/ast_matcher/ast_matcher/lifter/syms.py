"""Symbol-table types used by the lifter to track local-variable semantics.

Each variable in the decompiled function body is mapped to one of these
:class:`Sym` subtypes as soon as the lifter sees an assignment whose RHS
implies a known semantic (e.g. ``var = env->FindClass("foo/Bar")``).

Downstream JNI calls can then resolve their arguments to typed symbols
and emit fully-qualified JVM ops (``INVOKEVIRTUAL foo/Bar.baz:(I)V``)
instead of opaque placeholders.
"""

from __future__ import annotations

from dataclasses import dataclass


class Sym:
    """Marker base for variable-semantic types."""


@dataclass
class SymClass(Sym):
    """A jclass with known internal name."""
    internal_name: str | None = None


@dataclass
class SymMethodId(Sym):
    """A jmethodID bound to a known (owner, name, desc) triple."""
    owner: str | None = None
    name: str | None = None
    desc: str | None = None


@dataclass
class SymFieldId(Sym):
    """A jfieldID bound to a known (owner, name, desc) triple."""
    owner: str | None = None
    name: str | None = None
    desc: str | None = None


@dataclass
class SymStringLit(Sym):
    """A jstring whose content is a known source-pool literal."""
    value: str
    source: str = "literal"


@dataclass
class SymObject(Sym):
    """A jobject whose runtime type is known (descriptor form, e.g.
    ``"Ljava/util/List;"`` or ``"[I"``)."""
    desc: str
