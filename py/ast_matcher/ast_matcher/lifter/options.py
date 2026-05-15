"""Per-feature toggles for the lifter.

Every inference / matching step is gated behind a boolean flag so the
user can disable any specific heuristic when it's misbehaving on a
particular binary. The CLI exposes each as ``--enable-<flag>`` /
``--disable-<flag>``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class LifterOptions:
    """Lifter feature flags. All default to ``True`` for OOB experience;
    set to ``False`` to disable a specific heuristic."""

    # ---- INVOKE recovery ----
    #: Parse ``"Cannot invoke X.Y.Z(args)"`` strings in the function body
    #: and use them as fallback when symbol-tracking can't resolve a
    #: method-id argument. Profile-controlled regex.
    use_throw_reason_invoke_hints: bool = True

    #: Parse ``"Cannot read field \\"X\\""`` / ``"Cannot assign field \\"X\\""``
    #: strings in the function body and use the captured field name as
    #: fallback when symbol-tracking can't resolve a field-id argument.
    #: Owner is taken from the enclosing method's declaring class.
    use_throw_reason_field_hints: bool = True

    # ---- Symbol-tracking ----
    #: Track variable → jclass / jmethodID / jfieldID / jstring bindings
    #: across statements so ``env->Call*Method(receiver, mid, ...)`` can
    #: emit a fully-typed INVOKE.
    track_symbol_table: bool = True

    #: Resolve ``string_pool + offset`` references against the binary's
    #: extracted offset → string map (from binary-introspect).
    resolve_string_pool_offsets: bool = True

    #: Use per-class ``cstrings`` / ``cmethods`` / ``cfields`` / ``cclasses``
    #: lookup tables (from the manifest) to bind table-indexed accesses.
    resolve_lookup_tables: bool = True

    # ---- Control-flow cleanup ----
    #: Drop ``if (env->ExceptionCheck()) return 0;`` and equivalent
    #: ``if (cVar != 0) return 0;`` patterns. Profile-controlled.
    skip_native_exception_guards: bool = True

    #: After lifting, remove jump instructions whose target label isn't
    #: defined inside the same method. ASM rejects dangling jumps.
    drop_dangling_jumps: bool = True

    # ---- Return handling ----
    #: Suppress ``return (T)0;`` / ``return NULL;`` calls — these are
    #: native-obfuscator's trailing safety pads after the real returns.
    suppress_synthetic_fallthrough_return: bool = True

    # ---- Constructor handling ----
    #: Force ``<init>`` invocations to ``()V`` return type regardless of
    #: the wrapping JNI call's "Object"/"Void" flavor.
    force_init_void_return: bool = True
