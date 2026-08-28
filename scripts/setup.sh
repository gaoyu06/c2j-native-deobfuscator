#!/usr/bin/env bash
# Idempotent one-shot setup for the default (dynamic) recovery path.
#
#   1. Build the JVM modules (Gradle installDist)
#   2. Sync the Python workspace (uv)
#   3. Build the native JVMTI agent when a JDK is available
#
# Re-running is safe: Gradle and uv skip up-to-date work, and the native
# agent is only rebuilt when its inputs changed (or --force is passed).
#
# On success, run:  python -m j2c_dumper_cli doctor
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

FORCE=0
SKIP_NATIVE=0
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        --skip-native) SKIP_NATIVE=1 ;;
        -h|--help)
            echo "usage: scripts/setup.sh [--force] [--skip-native]"
            echo "  --force        rebuild the native agent even if up to date"
            echo "  --skip-native  build JVM + Python only (dynamic path needs native)"
            exit 0
            ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

info() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# ------------------------------------------------------------------
# Preconditions
# ------------------------------------------------------------------
command -v java >/dev/null 2>&1 || die \
    "java not found. Install a JDK 21+ (Temurin/Adoptium) and set JAVA_HOME, then re-run."

# ------------------------------------------------------------------
# 1. JVM modules
# ------------------------------------------------------------------
info "Building JVM modules (installDist)"
if [ ! -f "$ROOT/jvm/gradlew" ]; then
    die "jvm/gradlew is missing."
fi
# Invoke through `sh` so a missing exec bit (common after a plain checkout)
# does not block the build.
( cd "$ROOT/jvm" && sh ./gradlew installDist --no-daemon ) \
    || die "Gradle build failed. See the output above."

# ------------------------------------------------------------------
# 2. Python workspace
# ------------------------------------------------------------------
info "Syncing Python workspace"
if command -v uv >/dev/null 2>&1; then
    ( cd "$ROOT/py" && uv sync --all-packages ) \
        || die "uv sync failed. See the output above."
else
    warn "uv not found; falling back to 'pip install -e' for each package."
    PYTHON="${PYTHON:-python3}"
    command -v "$PYTHON" >/dev/null 2>&1 || die "python3 not found."
    "$PYTHON" -m pip install -e "$ROOT/py/j2c_dumper_cli" \
        -e "$ROOT/py/binary_introspect" \
        -e "$ROOT/py/manifest_merge" \
        -e "$ROOT/py/ast_matcher" \
        -e "$ROOT/py/snippet_importer" \
        || die "pip install failed. Install uv (https://docs.astral.sh/uv/) and re-run."
fi

# ------------------------------------------------------------------
# 3. Native JVMTI agent (dynamic path)
# ------------------------------------------------------------------
if [ "$SKIP_NATIVE" -eq 1 ]; then
    warn "Skipping native agent build (--skip-native). The dynamic path needs it."
else
    JDK_HOME="${JDK_HOME:-${JAVA_HOME:-}}"
    if [ -z "$JDK_HOME" ]; then
        # Derive JAVA_HOME from the java on PATH if possible.
        JAVA_BIN="$(command -v java)"
        JAVA_REAL="$(readlink -f "$JAVA_BIN" 2>/dev/null || echo "$JAVA_BIN")"
        JDK_HOME="$(dirname "$(dirname "$JAVA_REAL")")"
    fi
    LIBDIR="$ROOT/native/build/lib"
    have_lib=0
    for name in j2c_agent.so j2c_agent.dylib j2c_agent.dll; do
        [ -f "$LIBDIR/$name" ] && have_lib=1
    done
    if [ "$have_lib" -eq 1 ] && [ "$FORCE" -eq 0 ]; then
        info "Native agent already built ($LIBDIR); pass --force to rebuild."
    elif [ ! -d "$JDK_HOME/include" ]; then
        warn "No JDK headers under '$JDK_HOME/include'; skipping native agent."
        warn "Install a full JDK (not just a JRE), set JAVA_HOME, then re-run."
    elif ! command -v zig >/dev/null 2>&1 && [ -z "${ZIG:-}" ]; then
        warn "zig not found; skipping native agent (needed only for the dynamic path)."
        warn "Install zig 0.16.x or set ZIG, then re-run. Emulation path needs no native build."
    else
        info "Building native JVMTI agent (JDK_HOME=$JDK_HOME)"
        ( cd "$ROOT/native" && JDK_HOME="$JDK_HOME" ZIG="${ZIG:-zig}" bash build.sh ) \
            || die "Native agent build failed. See the output above."
    fi
fi

info "Setup finished. Verify with: python -m j2c_dumper_cli doctor"
