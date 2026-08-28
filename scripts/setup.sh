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
# On success, run:  python3 -m j2c_dumper_cli doctor
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
    "java not found. Install a JDK 17+ (Temurin/Adoptium) and set JAVA_HOME, then re-run."

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
NATIVE_READY=0
NATIVE_NOTE="the dynamic path was not set up"
if [ "$SKIP_NATIVE" -eq 1 ]; then
    warn "Skipping native agent build (--skip-native). The dynamic path needs it."
    NATIVE_NOTE="native agent skipped (--skip-native); the dynamic path is unavailable"
else
    JDK_HOME="${JDK_HOME:-${JAVA_HOME:-}}"
    if [ -z "$JDK_HOME" ]; then
        # Derive JAVA_HOME from the java on PATH if possible.
        JAVA_BIN="$(command -v java)"
        JAVA_REAL="$(readlink -f "$JAVA_BIN" 2>/dev/null || echo "$JAVA_BIN")"
        JDK_HOME="$(dirname "$(dirname "$JAVA_REAL")")"
    fi
    LIBDIR="$ROOT/native/build/lib"
    # Only the host-matching artifact is usable; a leftover build for another
    # OS must not be treated as ready. native/build.sh currently targets
    # x86-64, so the produced agent is x86-64 for this OS.
    case "$(uname -s)" in
        Linux)               AGENT_NAME="j2c_agent.so" ;;
        Darwin)              AGENT_NAME="j2c_agent.dylib" ;;
        MINGW*|MSYS*|CYGWIN*) AGENT_NAME="j2c_agent.dll" ;;
        *)                   AGENT_NAME="j2c_agent.so" ;;
    esac
    HOST_ARCH="$(uname -m)"
    case "$HOST_ARCH" in
        x86_64|amd64) : ;;
        *) warn "native/build.sh targets x86-64 but this host is $HOST_ARCH; the agent may not load. " \
                "Rebuild for $HOST_ARCH if the dynamic path fails to attach." ;;
    esac
    AGENT="$LIBDIR/$AGENT_NAME"
    # Rebuild when the artifact is missing, empty, or older than any input.
    needs_build=0
    if [ ! -s "$AGENT" ]; then
        needs_build=1
    else
        for src in "$ROOT"/native/src/*.cpp "$ROOT"/native/include/* "$ROOT/native/build.sh"; do
            [ -e "$src" ] || continue
            if [ "$src" -nt "$AGENT" ]; then needs_build=1; break; fi
        done
    fi
    if [ "$needs_build" -eq 0 ] && [ "$FORCE" -eq 0 ]; then
        info "Native agent up to date ($AGENT); pass --force to rebuild."
        NATIVE_READY=1
    elif [ ! -d "$JDK_HOME/include" ]; then
        warn "No JDK headers under '$JDK_HOME/include'; skipping native agent."
        warn "Install a full JDK (not just a JRE), set JAVA_HOME, then re-run."
        NATIVE_NOTE="native agent skipped (no JDK headers); the dynamic path is unavailable"
    elif ! command -v zig >/dev/null 2>&1 && [ -z "${ZIG:-}" ]; then
        warn "zig not found; skipping native agent (needed only for the dynamic path)."
        warn "Install zig 0.16.x or set ZIG, then re-run. Emulation path needs no native build."
        NATIVE_NOTE="native agent skipped (zig not found); the dynamic path is unavailable"
    else
        info "Building native JVMTI agent (JDK_HOME=$JDK_HOME)"
        ( cd "$ROOT/native" && JDK_HOME="$JDK_HOME" ZIG="${ZIG:-zig}" bash build.sh ) \
            || die "Native agent build failed. See the output above."
        NATIVE_READY=1
    fi
fi

if [ "$NATIVE_READY" -eq 1 ]; then
    info "Setup finished (default dynamic path ready). Verify with: python3 -m j2c_dumper_cli doctor"
else
    warn "Setup finished, but $NATIVE_NOTE."
    warn "Use the emulation fallback, or install the missing piece and re-run."
    info "Verify with: python3 -m j2c_dumper_cli doctor"
fi
