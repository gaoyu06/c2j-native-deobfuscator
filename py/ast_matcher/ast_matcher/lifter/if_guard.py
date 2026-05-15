"""Recognise and skip native-side exception-check guards.

After every JNI call, native-obfuscator-style code emits:

    cVar = env->ExceptionCheck();
    if (cVar != 0) return 0;

These are bookkeeping, not user logic — propagating them into the
lifted body fills it with spurious early-returns. The active profile's
:attr:`skip_if_patterns` list controls which (condition, body) regex
pairs are skipped.

When :attr:`LifterOptions.skip_native_exception_guards` is false the
guards pass through unchanged.
"""

from __future__ import annotations

import re

from binary_introspect.profile import Profile


class IfGuardMatcher:
    """Decides whether an ``if (cond) { body }`` is a native-side guard
    that should be skipped entirely."""

    def __init__(self, profile: Profile, enabled: bool = True):
        self.enabled = enabled
        self.patterns: list[tuple[re.Pattern[str], re.Pattern[str]]] = (
            list(profile.skip_if_patterns) if enabled else []
        )

    def should_skip(self, cond_text: str, body_text: str) -> bool:
        if not self.enabled or not self.patterns:
            return False
        cond = cond_text.strip()
        body = body_text.strip()
        for cond_re, body_re in self.patterns:
            if cond_re.search(cond) and body_re.fullmatch(body):
                return True
        return False
