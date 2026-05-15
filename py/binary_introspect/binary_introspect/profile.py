"""Obfuscator profile registry.

A *profile* captures all the variant-specific knobs the static-analysis
path needs to disassemble + lift a native-obfuscator-style binary:

  - target architecture / ABI (which register holds nMethods, pointer size)
  - JNI vtable offset for `RegisterNatives` (almost always 215*ptr but
    profile lets you override)
  - call-site harvest strategy (per-class register vs shared dispatch)
  - throw-reason error-string format (used by the ast-matcher to recover
    INVOKE owner/name/desc when symbol-tracking fails)
  - if-guard skip patterns (e.g. `if (env->ExceptionCheck()) return 0;`)

Two built-in profiles ship today:

  * ``native_obfuscator`` — radioegor146/native-obfuscator and any
    derivative that emits the original error-string layout AND uses
    one RegisterNatives call site per registered class.

  * ``j2cc`` — me.x150.j2cc; inherits the error-string layout from
    native-obfuscator but uses a single shared ``initClass()`` that
    dispatches by class name and reuses ONE RegisterNatives call site
    for every registered class.

New variants can register themselves by extending :class:`Profile`
(or copying one of the built-ins) and calling :func:`register_profile`.
Out-of-the-box detection runs every profile's :meth:`Profile.detect`
against the binary and picks the highest-scoring one; the user can
override with ``--profile <name>`` on the CLI.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import lief


# ------------------------------------------------------------------
# JNI-spec constants (kept centralised so a profile can override per
# JDK version if anything ever moves).
# ------------------------------------------------------------------

#: Index of ``RegisterNatives`` in ``JNINativeInterface_`` (JNI 1.1+).
JNI_REGISTER_NATIVES_INDEX = 215


# ------------------------------------------------------------------
# Profile data class
# ------------------------------------------------------------------

@dataclass
class Profile:
    """A single obfuscator variant's knobs."""

    #: Unique name used by ``--profile`` and reported back in JSON.
    name: str

    #: Human description.
    description: str = ""

    # ---------- architecture / ABI ----------
    #: Architectures this profile applies to. Used by :meth:`detect`.
    arch_filter: tuple[str, ...] = ("x86_64",)

    #: OS / ABI filter. ``("windows",)`` = Windows x64 (RCX/RDX/R8/R9);
    #: ``("linux", "macos")`` = SysV (RDI/RSI/RDX/RCX); ``()`` = any.
    os_filter: tuple[str, ...] = ()

    # ---------- JNI vtable ----------
    #: Override for ``RegisterNatives`` vtable index.
    register_natives_index: int = JNI_REGISTER_NATIVES_INDEX

    # ---------- harvest strategy ----------
    #: Strategy for extracting method tables from RegisterNatives call
    #: sites. One of:
    #:
    #:   * ``"per_class"``  — one call site = one class's table
    #:   * ``"shared_dispatch"`` — one call site reused by multiple
    #:     classes, with each branch setting its own ``nMethods``
    harvest_strategy: str = "per_class"

    # ---------- throw-reason parsing ----------
    #: Regex matching the error-string format emitted before each
    #: would-be Java call. Must define named groups ``owner`` /
    #: ``name`` / ``args``. ``owner`` is dot-separated; ``args`` is a
    #: comma-separated Java-source arg list (e.g. ``"int, java.util.List"``).
    invoke_error_re: re.Pattern[str] = field(
        default_factory=lambda: re.compile(
            r"^Cannot\s+invoke\s+"
            r"(?P<owner>[\w.$]+)\.(?P<name>[\w$<>]+)"
            r"\((?P<args>[^)]*)\)$"
        )
    )

    #: Regex matching the error-string format emitted before each
    #: would-be Java field access. Must define named groups ``op``
    #: (``"read"`` for getfield/getstatic, ``"assign"`` for
    #: putfield/putstatic) and ``name`` (the field name). Owner is
    #: inferred from the enclosing method's declaring class — j2cc and
    #: native-obfuscator both emit the throw at the call site, so the
    #: containing class is almost always the field's owner.
    field_error_re: re.Pattern[str] = field(
        default_factory=lambda: re.compile(
            r'^Cannot\s+(?P<op>read|assign)\s+field\s+"(?P<name>[^"]+)"'
        )
    )

    # ---------- if-guard skip patterns ----------
    #: A list of (condition-regex, body-regex) tuples. When the
    #: ast-matcher walks an ``if`` whose condition matches the first
    #: regex AND consequence matches the second, the whole if is
    #: dropped (treated as native-side bookkeeping, not user logic).
    skip_if_patterns: list[tuple[re.Pattern[str], re.Pattern[str]]] = field(
        default_factory=list
    )

    # ---------- detection ----------
    #: Optional detector. Receives the parsed ``lief.Binary`` and
    #: returns a score 0..1. The default detector just checks arch /
    #: OS filters and returns 0.5 (= "could work, no positive signal").
    detector: Optional[Callable[[lief.Binary], float]] = None

    # ---------- helper-function fingerprints ----------
    #: Optional list of (signature → semantic) hints used by the
    #: ast-matcher to recognise FUN_xxxx helper calls in Ghidra-style
    #: decompile output. Each entry is a dict like:
    #:
    #:   {"arg_shape": "env, pool_off, length, ANY",
    #:    "returns":   "jclass",
    #:    "semantic":  "find_class_by_pool_offset"}
    #:
    #: The lifter uses these to bind FUN_xxxx return values to typed
    #: symbols even when we can't run the helper.
    helper_fingerprints: list[dict[str, str]] = field(default_factory=list)

    def detect(self, binary: lief.Binary) -> float:
        """Default detection: filter by arch + OS, return 0.5 / 0."""
        if self.detector is not None:
            return self.detector(binary)
        return self._default_detect(binary)

    def _default_detect(self, binary: lief.Binary) -> float:
        arch = _arch_of(binary)
        if self.arch_filter and arch not in self.arch_filter:
            return 0.0
        os = _os_of(binary)
        if self.os_filter and os not in self.os_filter:
            return 0.0
        return 0.5


# ------------------------------------------------------------------
# Architecture / OS detection (cheap)
# ------------------------------------------------------------------

def _arch_of(b: lief.Binary) -> str:
    if b.format == lief.Binary.FORMATS.PE:
        machine = int(b.header.machine)
        if machine == 0x8664: return "x86_64"
        if machine == 0x014c: return "x86"
        if machine == 0xaa64: return "aarch64"
    elif b.format == lief.Binary.FORMATS.ELF:
        try:
            m = int(b.header.machine_type)
        except Exception:
            return "?"
        if m == 0x3E: return "x86_64"
        if m == 0x03: return "x86"
        if m == 0xB7: return "aarch64"
        if m == 0x28: return "arm"
    elif b.format == lief.Binary.FORMATS.MACHO:
        try:
            cpu = int(b.header.cpu_type)
        except Exception:
            return "?"
        if cpu == 0x01000007: return "x86_64"
        if cpu == 0x0100000C: return "aarch64"
    return "?"


def _os_of(b: lief.Binary) -> str:
    if b.format == lief.Binary.FORMATS.PE:    return "windows"
    if b.format == lief.Binary.FORMATS.ELF:   return "linux"
    if b.format == lief.Binary.FORMATS.MACHO: return "macos"
    return "?"


# ------------------------------------------------------------------
# Registry
# ------------------------------------------------------------------

_registry: dict[str, Profile] = {}


def register_profile(p: Profile) -> None:
    """Register a profile by name. Used by built-ins + user plugins."""
    if p.name in _registry:
        raise ValueError(f"duplicate profile name: {p.name!r}")
    _registry[p.name] = p


def list_profiles() -> list[str]:
    return sorted(_registry.keys())


def get_profile(name: str) -> Profile:
    if name not in _registry:
        raise KeyError(
            f"unknown profile {name!r}; known: {', '.join(list_profiles())}"
        )
    return _registry[name]


def detect_profile(binary: lief.Binary) -> Profile:
    """Auto-pick the highest-scoring profile for `binary`. Falls back to
    the default ``generic`` profile when no specific one applies."""
    best: tuple[float, Profile] = (-1.0, _registry["generic"])
    for prof in _registry.values():
        score = prof.detect(binary)
        if score > best[0]:
            best = (score, prof)
    return best[1]


# ------------------------------------------------------------------
# Built-in profiles
# ------------------------------------------------------------------

def _detect_native_obfuscator(b: lief.Binary) -> float:
    """Looks for the giveaway export name + 'Cannot invoke' strings."""
    score = 0.0
    if b.format != lief.Binary.FORMATS.PE and b.format != lief.Binary.FORMATS.ELF:
        return 0.0
    # Check for the standard Java_<class>_<method> export style:
    if b.has_exports if b.format == lief.Binary.FORMATS.PE else hasattr(b, "exported_symbols"):
        try:
            names = ([e.name for e in b.get_export().entries]
                     if b.format == lief.Binary.FORMATS.PE
                     else [s.name for s in b.exported_symbols if s.name])
        except Exception:
            names = []
        if any(n and n.startswith("Java_") and "_native_" in n for n in names):
            score += 0.4
    # Look for the throw_re strings.
    for sec in b.sections:
        try:
            raw = bytes(sec.content)
        except Exception:
            continue
        if b"Cannot invoke " in raw:
            score += 0.5
            break
    return min(score, 1.0)


def _detect_j2cc(b: lief.Binary) -> float:
    """Two JNI exports total (bootstrap + initClass) + 'Cannot invoke' strings."""
    if b.format != lief.Binary.FORMATS.PE:
        return 0.0
    try:
        names = [e.name for e in b.get_export().entries]
    except Exception:
        return 0.0
    java_exports = [n for n in names if n and n.startswith("Java_")]
    if len(java_exports) > 4:                # native-obfuscator territory
        return 0.0
    has_init = any("initClass" in n for n in java_exports)
    has_boot = any("bootstrap" in n for n in java_exports)
    if not (has_init and has_boot):
        return 0.0
    has_msgs = False
    for sec in b.sections:
        try: raw = bytes(sec.content)
        except Exception: continue
        if b"Cannot invoke " in raw:
            has_msgs = True; break
    return 0.9 if has_msgs else 0.6


_EXCEPTION_CHECK_COND = re.compile(r".*ExceptionCheck\s*\(\)")
_RETURN_ZERO_BODY = re.compile(
    r"\s*\{?\s*return\s+(?:\([^)]*\)\s*)?(?:0|0L|NULL|nullptr|\(jobject\)\s*0x0)\s*;\s*\}?\s*"
)


# Register the built-ins ------------------------------------------------------

register_profile(Profile(
    name="generic",
    description="Minimal fallback. Standard JNI vtable, no obfuscator-specific tricks.",
    arch_filter=(),
    os_filter=(),
    harvest_strategy="per_class",
    skip_if_patterns=[],   # do not skip anything by default
))

register_profile(Profile(
    name="native_obfuscator",
    description="radioegor146/native-obfuscator + any throw-format compatible derivative.",
    arch_filter=("x86_64",),
    os_filter=(),               # Windows + Linux both work
    harvest_strategy="per_class",
    skip_if_patterns=[(_EXCEPTION_CHECK_COND, _RETURN_ZERO_BODY)],
    detector=_detect_native_obfuscator,
))

register_profile(Profile(
    name="j2cc",
    description="me.x150.j2cc — single shared initClass() dispatch + natives.bin blob.",
    arch_filter=("x86_64",),
    os_filter=("windows",),
    harvest_strategy="shared_dispatch",
    skip_if_patterns=[(_EXCEPTION_CHECK_COND, _RETURN_ZERO_BODY)],
    detector=_detect_j2cc,
))
