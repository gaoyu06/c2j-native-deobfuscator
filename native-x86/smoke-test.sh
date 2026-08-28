#!/usr/bin/env bash
# Compile the nativex86 skeleton and run the host stub against the sample
# plugin. Skips (exit 0) when no C compiler is available.
#
# Usage: bash native-x86/smoke-test.sh [--no-cmake]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${NX86_BUILD_DIR:-$SCRIPT_DIR/build}"
USE_CMAKE=1
[ "${1:-}" = "--no-cmake" ] && USE_CMAKE=0

CC_BIN="${CC:-}"
if [ -z "$CC_BIN" ]; then
    for candidate in cc gcc clang; do
        if command -v "$candidate" >/dev/null 2>&1; then
            CC_BIN="$candidate"
            break
        fi
    done
fi

if [ -z "$CC_BIN" ]; then
    echo "SKIP: no C compiler found; sources left unbuilt."
    exit 0
fi

echo "== nativex86 smoke test =="
echo "compiler: $CC_BIN"

set -e
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

if [ "$USE_CMAKE" = "1" ] && command -v cmake >/dev/null 2>&1; then
    echo "-- configuring with cmake"
    cmake -S "$SCRIPT_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release >/dev/null
    cmake --build "$BUILD_DIR" >/dev/null
    HOST_BIN="$BUILD_DIR/bin/nx86_host"
    PLUGIN_LIB="$BUILD_DIR/lib/libnx86_plugin_hello.so"
else
    echo "-- configuring without cmake"
    mkdir -p "$BUILD_DIR/bin" "$BUILD_DIR/lib"
    WARN="-std=c99 -Wall -Wextra -Wpedantic -O2"
    # shellcheck disable=SC2086
    "$CC_BIN" $WARN -I "$SCRIPT_DIR/include" -I "$SCRIPT_DIR/src/host" \
        -o "$BUILD_DIR/bin/nx86_host" \
        "$SCRIPT_DIR/src/host/main.c" \
        "$SCRIPT_DIR/src/host/event_bus.c" \
        "$SCRIPT_DIR/src/host/platform.c" \
        -ldl
    # shellcheck disable=SC2086
    "$CC_BIN" $WARN -I "$SCRIPT_DIR/include" -fPIC -shared \
        -o "$BUILD_DIR/lib/libnx86_plugin_hello.so" \
        "$SCRIPT_DIR/plugins/hello/hello.c"
    HOST_BIN="$BUILD_DIR/bin/nx86_host"
    PLUGIN_LIB="$BUILD_DIR/lib/libnx86_plugin_hello.so"
fi

echo "-- running host stub"
OUTPUT="$("$HOST_BIN" "$PLUGIN_LIB")"
echo "$OUTPUT"

set +e
FAILED=0
for expected in \
    "host: loaded plugin id=hello" \
    "hello from the sample plugin" \
    "plugin.hello: event" \
    "host: shutdown ok"
do
    if ! grep -qF "$expected" <<<"$OUTPUT"; then
        echo "FAIL: expected output not found: $expected"
        FAILED=1
    fi
done

if [ "$FAILED" != "0" ]; then
    exit 1
fi

echo "PASS: skeleton builds, loads the sample plugin and dispatches events."
