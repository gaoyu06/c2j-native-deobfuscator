"""Optional native-obfuscator-specific feature.

Reads ``cppsnippets.properties`` from a native-obfuscator checkout and emits a
*supplementary* rule set that the static-reverse AST matcher can load.

Main flow does NOT depend on this module. See
docs/static-reverse-approach.md §10.1.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


# JVM opcode prefix → output JVM op family. Used to skip noise lines from the
# properties file (e.g. helper "_S_VARS", "_S_CONST_*" suffixes).
_NOISE_SUFFIXES = ("_S_VARS", "_S_CONST_NPE", "_S_CONST_ERROR_DESC")


@dataclass
class Snippet:
    op: str
    template: str
    raw_line: str


def parse_properties(path: Path) -> list[Snippet]:
    """Parse the native-obfuscator cppsnippets.properties file."""
    results: list[Snippet] = []
    text = path.read_text(encoding="utf-8")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if any(key.endswith(suf) for suf in _NOISE_SUFFIXES):
            continue
        # Strip any opcode-suffix like "_S_VARS"
        # The "real" snippet keys are pure opcode names like IADD, INVOKEVIRTUAL etc.
        results.append(Snippet(op=key, template=value, raw_line=line))
    return results


def generate_rules(snippets: list[Snippet]) -> dict[str, Any]:
    """Build a rule index keyed by JVM op.

    Each rule entry is:
        {
          "op": "IADD",
          "templateRegex": "<regex matching the snippet shape>",
          "fromNativeObfuscator": true
        }

    The regex is built by escaping the template, replacing ``$stackindex``
    style placeholders with capturing groups.
    """
    rules: dict[str, Any] = {}
    for s in snippets:
        regex = _template_to_regex(s.template)
        rules.setdefault(s.op, []).append({
            "op": s.op,
            "templateRegex": regex,
            "rawTemplate": s.template,
            "fromNativeObfuscator": True,
        })
    return {
        "schemaVersion": 1,
        "source": "native-obfuscator/cppsnippets.properties",
        "rules": rules,
    }


_PLACEHOLDER_RE = re.compile(r"\$\w+")
_PLACEHOLDER_REGEX = r"(?P<\g<0>>[^;\s]+)"


def _template_to_regex(template: str) -> str:
    """Turn a template like
        ``cstack$stackindex0.i = cstack$stackindex0.i + cstack$stackindex1.i;``
    into a regex with named groups."""
    escaped = re.escape(template)
    # restore $name placeholders that re.escape() destroyed (they become \$name)
    placeholder_re = re.compile(r"\\\$(\w+)")
    def repl(m: re.Match[str]) -> str:
        return f"(?P<{m.group(1)}>[^;\\s\\)\\,]+)"
    pattern = placeholder_re.sub(repl, escaped)
    return pattern


def main_run(properties: Path, output: Path) -> None:
    snippets = parse_properties(properties)
    rules = generate_rules(snippets)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(rules, indent=2), encoding="utf-8")
