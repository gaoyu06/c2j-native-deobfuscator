"""Parse "Cannot invoke X.Y.Z(args)" error-string hints.

When the lifter can't resolve a JNI method-id argument via symbol
tracking (because it came from an obfuscator helper function we don't
model), the fallback is to look at error-strings emitted just before
the JNI call. Native-obfuscator-style obfuscators precede every Java
call with a ``throw_re(env, file, message, line)`` whose message is
the SOURCE-LEVEL form of the call being made.

This module exposes a single ``InvokeHintParser`` that uses the active
profile's :attr:`Profile.invoke_error_re` regex.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from binary_introspect.profile import Profile


# Map Java source type names to JVM type descriptors.
_PRIMITIVES = {
    "void": "V", "boolean": "Z", "byte": "B", "char": "C", "short": "S",
    "int": "I", "long": "J", "float": "F", "double": "D",
}


def _java_to_desc(java_type: str) -> str:
    """Best-effort Java-source-name → JVM descriptor.

    Examples:
        ``int``            -> ``I``
        ``String``         -> ``Ljava/lang/String;``
        ``java.util.List`` -> ``Ljava/util/List;``
        ``int[]``          -> ``[I``
        ``String[]``       -> ``[Ljava/lang/String;``
    """
    t = java_type.strip()
    dims = 0
    while t.endswith("[]"):
        t = t[:-2]
        dims += 1
    if t in _PRIMITIVES:
        return "[" * dims + _PRIMITIVES[t]
    return "[" * dims + "L" + t.replace(".", "/") + ";"


@dataclass
class InvokeHint:
    owner: str            # internal name, e.g. ``"java/util/HashMap"``
    name: str             # method name (may be ``"<init>"``)
    void_desc: str        # ``(args...)V`` — caller patches the return type


@dataclass
class FieldHint:
    op: str               # ``"read"`` (getfield/static) or ``"assign"`` (put*)
    name: str             # field name


class InvokeHintParser:
    """Scans a function body for invoke-error strings and yields hints
    in source order. The active :class:`Profile`'s :attr:`invoke_error_re`
    controls the matching regex.
    """

    _LITERAL = re.compile(r'"([^"]+)"')

    def __init__(self, profile: Profile):
        self.regex = profile.invoke_error_re

    def parse(self, code: str) -> list[InvokeHint]:
        out: list[InvokeHint] = []
        for m in self._LITERAL.finditer(code):
            msg = m.group(1)
            mm = self.regex.match(msg)
            if not mm:
                continue
            owner = mm.group("owner").replace(".", "/")
            name = mm.group("name")
            args_text = mm.group("args")
            arg_descs = [
                _java_to_desc(a.strip())
                for a in args_text.split(",")
                if a.strip()
            ]
            out.append(InvokeHint(owner, name, "(" + "".join(arg_descs) + ")V"))
        return out


class FieldHintParser:
    """Like :class:`InvokeHintParser` but for field-access error strings
    (e.g. ``"Cannot read field \\"ADD\\""``). The active profile's
    :attr:`Profile.field_error_re` controls matching.
    """

    _LITERAL = re.compile(r'"((?:\\.|[^"\\])*)"')

    def __init__(self, profile: Profile):
        self.regex = profile.field_error_re

    def parse(self, code: str) -> list[FieldHint]:
        out: list[FieldHint] = []
        for m in self._LITERAL.finditer(code):
            msg = m.group(1).encode("utf-8").decode("unicode_escape", errors="replace")
            mm = self.regex.match(msg)
            if not mm:
                continue
            out.append(FieldHint(op=mm.group("op"), name=mm.group("name")))
        return out
