#!/usr/bin/env bash
# End-to-end smoke test:
#   1. Build all modules
#   2. Run the full recover pipeline on a small obfuscated jar
#   3. Verify the produced jar runs (exit code 0)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WORK="$(mktemp -d)"
INPUT="$PROJECT_ROOT/../e2e-test/out/Hello.jar"

if [ ! -f "$INPUT" ]; then
    echo "FIXTURE MISSING: $INPUT" >&2
    echo "Run native-obfuscator on a small jar first (see top-level README)" >&2
    exit 2
fi

echo "=== build JVM modules ==="
( cd "$PROJECT_ROOT/jvm" && ./gradlew.bat installDist --no-daemon ) || \
( cd "$PROJECT_ROOT/jvm" && ./gradlew installDist --no-daemon )

echo "=== sync Python workspace ==="
( cd "$PROJECT_ROOT/py" && uv sync --all-packages )

echo "=== build native agent ==="
( cd "$PROJECT_ROOT/native" && JDK_HOME="${JAVA_HOME:-}" bash build.sh )

echo "=== one-shot recover ==="
PY="$PROJECT_ROOT/py/.venv/Scripts/python.exe"
[ ! -f "$PY" ] && PY="$PROJECT_ROOT/py/.venv/bin/python"
# Convert msys-style path to native style for java consumption
INPUT_NATIVE="$INPUT"
if command -v cygpath >/dev/null 2>&1; then
    INPUT_NATIVE="$(cygpath -w "$INPUT")"
fi
"$PY" -m j2c_dumper_cli.main recover "$INPUT" \
    -o "$WORK/recovered.jar" \
    --run-cmd "java -jar \"$INPUT_NATIVE\"" \
    --workdir "$WORK"

echo "=== verify recovered jar ==="
test -f "$WORK/recovered.jar"
java -jar "$WORK/recovered.jar"

echo "=== verify pipeline artifacts ==="
test -f "$WORK/classes.json"
test -f "$WORK/binary.json"
test -f "$WORK/manifest.json"
test -f "$WORK/trace.jsonl"
test -d "$WORK/recovered"

# Each artifact should contain non-trivial content (use python — jq may be absent)
WORK_NATIVE="$WORK"
if command -v cygpath >/dev/null 2>&1; then
    WORK_NATIVE="$(cygpath -w "$WORK")"
fi
"$PY" - <<EOF
import json, sys
import pathlib
work = pathlib.Path(r"$WORK_NATIVE")
classes = json.loads((work / "classes.json").read_text())
binary = json.loads((work / "binary.json").read_text())
assert len(classes["classes"]) >= 1, "no classes in classes.json"
assert len(binary["stringPool"]["strings"]) >= 100, "string pool too small"
trace_lines = (work / "trace.jsonl").read_text().count('"ev":"enter"')
assert trace_lines >= 1, "no enter events in trace.jsonl"
rec = list((work / "recovered").glob("*.json"))
assert len(rec) >= 1, "no recovered methods"
print(f"artifacts OK: {len(classes['classes'])} classes, {len(binary['stringPool']['strings'])} strings, {trace_lines} enters, {len(rec)} recovered")
EOF

echo "PASS"
