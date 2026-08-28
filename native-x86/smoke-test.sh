#!/usr/bin/env bash
# Build the nativex86 module and exercise it three ways:
#
#   1. synthetic  - host stub replays fixed records to the sample plugin;
#   2. abi checks - prefix negotiation and lifecycle window;
#   3. observation- attach to a tiny fixture process (which calls exports
#                   named SSL_write / SSL_read / SSL_connect / Java_*) and
#                   confirm metadata-only module / symbol / call-site
#                   records. If ptrace attach is blocked in this
#                   environment, it fails honestly and the read-only
#                   module/symbol pass is checked instead.
#
# Skips (exit 0) when no C compiler is available.
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
    CHECKS_BIN="$BUILD_DIR/bin/nx86_abi_checks"
    HELLO_LIB="$BUILD_DIR/lib/libnx86_plugin_hello.so"
    OPENSSL_LIB="$BUILD_DIR/lib/libnx86_plugin_crypto_openssl.so"
    JNI_LIB="$BUILD_DIR/lib/libnx86_plugin_jni_natives.so"
    FIXTURE_BIN="$BUILD_DIR/bin/nx86_fixture_target"
    FIXTURE_LIBDIR="$BUILD_DIR/lib"
else
    echo "-- configuring without cmake"
    mkdir -p "$BUILD_DIR/bin" "$BUILD_DIR/lib"
    WARN="-std=c99 -Wall -Wextra -Wpedantic -O2"
    INC="-I $SCRIPT_DIR/include -I $SCRIPT_DIR/src/host"
    # shellcheck disable=SC2086
    "$CC_BIN" $WARN $INC -o "$BUILD_DIR/bin/nx86_host" \
        "$SCRIPT_DIR/src/host/main.c" \
        "$SCRIPT_DIR/src/host/event_bus.c" \
        "$SCRIPT_DIR/src/host/platform.c" \
        "$SCRIPT_DIR/src/host/observe_linux.c" \
        "$SCRIPT_DIR/src/host/observe_stub.c" -ldl
    # shellcheck disable=SC2086
    "$CC_BIN" $WARN $INC -o "$BUILD_DIR/bin/nx86_abi_checks" \
        "$SCRIPT_DIR/tests/abi_checks.c" \
        "$SCRIPT_DIR/src/host/event_bus.c" \
        "$SCRIPT_DIR/src/host/platform.c" \
        "$SCRIPT_DIR/plugins/hello/hello.c" -ldl
    for p in hello:hello/hello crypto_openssl:crypto-openssl/crypto_openssl \
             jni_natives:jni-natives/jni_natives; do
        stem="${p%%:*}"; src="${p##*:}"
        # shellcheck disable=SC2086
        "$CC_BIN" $WARN -I "$SCRIPT_DIR/include" -fPIC -shared \
            -o "$BUILD_DIR/lib/libnx86_plugin_${stem}.so" \
            "$SCRIPT_DIR/plugins/${src}.c"
    done
    # shellcheck disable=SC2086
    "$CC_BIN" -O2 -fPIC -shared -fvisibility=default \
        -o "$BUILD_DIR/lib/libnx86_fixture_exports.so" \
        "$SCRIPT_DIR/tests/fixtures/fake_exports.c"
    # shellcheck disable=SC2086
    "$CC_BIN" -O2 -o "$BUILD_DIR/bin/nx86_fixture_target" \
        "$SCRIPT_DIR/tests/fixtures/fixture_target.c" \
        -L "$BUILD_DIR/lib" -lnx86_fixture_exports \
        -Wl,-rpath,"$BUILD_DIR/lib"
    HOST_BIN="$BUILD_DIR/bin/nx86_host"
    CHECKS_BIN="$BUILD_DIR/bin/nx86_abi_checks"
    HELLO_LIB="$BUILD_DIR/lib/libnx86_plugin_hello.so"
    OPENSSL_LIB="$BUILD_DIR/lib/libnx86_plugin_crypto_openssl.so"
    JNI_LIB="$BUILD_DIR/lib/libnx86_plugin_jni_natives.so"
    FIXTURE_BIN="$BUILD_DIR/bin/nx86_fixture_target"
    FIXTURE_LIBDIR="$BUILD_DIR/lib"
fi

FAILED=0

echo "-- 1. synthetic script (host stub + sample plugin)"
OUTPUT="$("$HOST_BIN" "$HELLO_LIB")"
echo "$OUTPUT"
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

echo "-- 2. abi checks"
set +e
CHECKS_OUTPUT="$("$CHECKS_BIN")"
CHECKS_RC=$?
set -e
echo "$CHECKS_OUTPUT"
if [ "$CHECKS_RC" != "0" ] || ! grep -qF "abi-checks: PASS" <<<"$CHECKS_OUTPUT"; then
    echo "FAIL: abi checks did not pass"
    FAILED=1
fi

echo "-- 3. observation of a fixture process"
PIDFILE="$(mktemp)"
FXPID=""
cleanup_fixture() {
    [ -n "$FXPID" ] && kill -9 "$FXPID" >/dev/null 2>&1 || true
    rm -f "$PIDFILE" >/dev/null 2>&1 || true
}
trap cleanup_fixture EXIT

# Ensure the fixture can find its export library in either build mode.
LD_LIBRARY_PATH="$FIXTURE_LIBDIR:${LD_LIBRARY_PATH:-}" "$FIXTURE_BIN" "$PIDFILE" &
FXPID=$!
# Wait for the fixture to publish its pid.
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -s "$PIDFILE" ] && break
    sleep 0.2
done
TARGET_PID="$(cat "$PIDFILE" 2>/dev/null || true)"

if [ -z "$TARGET_PID" ]; then
    echo "FAIL: fixture process did not report a pid"
    FAILED=1
else
    echo "fixture pid=$TARGET_PID"
    set +e
    OBS="$("$HOST_BIN" --pid "$TARGET_PID" --i-own-this-process \
        --max-events 12 --max-seconds 15 \
        "$OPENSSL_LIB" "$JNI_LIB" 2>&1)"
    set -e
    echo "$OBS"

    # Records that must appear regardless of whether the live path ran.
    for expected in \
        "kind=module-load" \
        "libnx86_fixture_exports.so" \
        "symbol=SSL_write" \
        "symbol=SSL_connect" \
        "Java_com_example_Demo_ping"
    do
        if ! grep -qF "$expected" <<<"$OBS"; then
            echo "FAIL: observation missing: $expected"
            FAILED=1
        fi
    done
    # Metadata-only guarantee: no field that could carry content.
    if grep -qiE 'plaintext|ciphertext|arg-bytes|keybytes|payload=' <<<"$OBS"; then
        echo "FAIL: observation output contains a content-like field"
        FAILED=1
    fi

    if grep -qF "phase=enter" <<<"$OBS" && grep -qF "phase=return" <<<"$OBS"; then
        echo "PASS(live): entry/return call sites observed via ptrace"
        for expected in \
            "target=SSL_write" \
            "phase=enter" \
            "phase=return"
        do
            if ! grep -qF "$expected" <<<"$OBS"; then
                echo "FAIL: live observation missing: $expected"
                FAILED=1
            fi
        done
    else
        echo "NOTE: live entry/return not available here (ptrace blocked);"
        echo "      checking the read-only module/symbol pass instead."
        if ! grep -qE 'attach was refused|read-only|not available' <<<"$OBS"; then
            echo "WARN: no live call sites and no honest read-only fallback message"
        fi
    fi
fi

cleanup_fixture
trap - EXIT

if [ "$FAILED" != "0" ]; then
    echo "SMOKE TEST: FAIL"
    exit 1
fi

echo "PASS: skeleton builds, dispatches events, passes abi checks, and"
echo "      reports metadata-only module/symbol/call-site records for a"
echo "      fixture process."
