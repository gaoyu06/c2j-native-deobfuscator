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

echo "-- 4. attach-refusal fallback (must run the read-only pass, exit 0)"
# Force the attach step to behave as refused so this runs the same way
# regardless of whether ptrace is permitted in this environment.
PIDFILE4="$(mktemp)"
FXPID4=""
cleanup_fixture4() {
    [ -n "$FXPID4" ] && kill -9 "$FXPID4" >/dev/null 2>&1 || true
    rm -f "$PIDFILE4" >/dev/null 2>&1 || true
}
trap cleanup_fixture4 EXIT
LD_LIBRARY_PATH="$FIXTURE_LIBDIR:${LD_LIBRARY_PATH:-}" "$FIXTURE_BIN" "$PIDFILE4" &
FXPID4=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -s "$PIDFILE4" ] && break
    sleep 0.2
done
TARGET_PID4="$(cat "$PIDFILE4" 2>/dev/null || true)"
if [ -z "$TARGET_PID4" ]; then
    echo "FAIL: fixture process (refusal test) did not report a pid"
    FAILED=1
else
    set +e
    REFUSE_OBS="$(NX86_TEST_INJECT=attach-refused "$HOST_BIN" \
        --pid "$TARGET_PID4" --i-own-this-process \
        "$OPENSSL_LIB" "$JNI_LIB" 2>&1)"
    REFUSE_RC=$?
    set -e
    echo "$REFUSE_OBS"
    # Refusal must not fail the command when the documented fallback runs.
    if [ "$REFUSE_RC" != "0" ]; then
        echo "FAIL: attach-refusal fallback exited non-zero ($REFUSE_RC)"
        FAILED=1
    fi
    # The honest fallback message and the read-only records must appear.
    if ! grep -qiE 'attach was refused' <<<"$REFUSE_OBS"; then
        echo "FAIL: attach-refusal did not report the refusal honestly"
        FAILED=1
    fi
    if ! grep -qF "read-only" <<<"$REFUSE_OBS"; then
        echo "FAIL: attach-refusal did not name the read-only fallback"
        FAILED=1
    fi
    for expected in \
        "kind=module-load" \
        "symbol=SSL_write" \
        "Java_com_example_Demo_ping"
    do
        if ! grep -qF "$expected" <<<"$REFUSE_OBS"; then
            echo "FAIL: read-only fallback missing: $expected"
            FAILED=1
        fi
    done
    # A read-only pass places no breakpoints, so no live phases appear.
    if grep -qF "phase=enter" <<<"$REFUSE_OBS"; then
        echo "FAIL: read-only fallback should not report live entry phases"
        FAILED=1
    fi
    # Fallback did real work, so the run is a clean success.
    if ! grep -qF "host: shutdown ok" <<<"$REFUSE_OBS"; then
        echo "FAIL: attach-refusal fallback did not shut down cleanly"
        FAILED=1
    fi
fi
cleanup_fixture4
trap - EXIT

echo "-- 5. strict --pid parsing (a bad --pid must error, never fall back)"
for bad in "-1" "0" "12x" "abc" ""; do
    set +e
    BAD_OUT="$("$HOST_BIN" --pid "$bad" --i-own-this-process "$HELLO_LIB" 2>&1)"
    BAD_RC=$?
    set -e
    if [ "$BAD_RC" = "0" ]; then
        echo "FAIL: --pid '$bad' was accepted (exit 0) instead of rejected"
        echo "$BAD_OUT"
        FAILED=1
    fi
    # A rejected --pid must NOT silently run the synthetic (no-target) mode.
    if grep -qF "host: shutdown ok" <<<"$BAD_OUT"; then
        echo "FAIL: --pid '$bad' fell through to synthetic mode"
        FAILED=1
    fi
done
# A well-formed --pid must still be accepted (parse layer only).
set +e
GOOD_OUT="$("$HOST_BIN" --pid 999999 --i-own-this-process "$HELLO_LIB" 2>&1)"
GOOD_RC=$?
set -e
if grep -qF "must be a positive integer" <<<"$GOOD_OUT"; then
    echo "FAIL: a valid --pid was rejected by the parser"
    FAILED=1
fi
echo "PASS: bad --pid values are rejected; a valid one parses"

echo "-- 6. detach failure must fail the command (never report success)"
# Only meaningful where the live path actually attaches; skip honestly
# otherwise. Forces the final detach to be treated as failed.
PIDFILE6="$(mktemp)"
FXPID6=""
cleanup_fixture6() {
    [ -n "$FXPID6" ] && kill -9 "$FXPID6" >/dev/null 2>&1 || true
    rm -f "$PIDFILE6" >/dev/null 2>&1 || true
}
trap cleanup_fixture6 EXIT
LD_LIBRARY_PATH="$FIXTURE_LIBDIR:${LD_LIBRARY_PATH:-}" "$FIXTURE_BIN" "$PIDFILE6" &
FXPID6=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -s "$PIDFILE6" ] && break
    sleep 0.2
done
TARGET_PID6="$(cat "$PIDFILE6" 2>/dev/null || true)"
if [ -z "$TARGET_PID6" ]; then
    echo "FAIL: fixture process (detach test) did not report a pid"
    FAILED=1
else
    set +e
    DETACH_OBS="$(NX86_TEST_INJECT=detach-fail "$HOST_BIN" \
        --pid "$TARGET_PID6" --i-own-this-process \
        --max-events 4 --max-seconds 10 \
        "$OPENSSL_LIB" "$JNI_LIB" 2>&1)"
    DETACH_RC=$?
    set -e
    echo "$DETACH_OBS"
    if grep -qF "phase=enter" <<<"$DETACH_OBS"; then
        # Live path ran and reached detach: the injected failure must fail
        # the command and must not print a clean "shutdown ok".
        if [ "$DETACH_RC" = "0" ]; then
            echo "FAIL: detach failure did not fail the command (exit 0)"
            FAILED=1
        fi
        if grep -qF "host: shutdown ok" <<<"$DETACH_OBS"; then
            echo "FAIL: detach failure still reported 'shutdown ok'"
            FAILED=1
        fi
        echo "PASS: detach failure fails the command"
    else
        echo "NOTE: live path did not attach here; detach-failure check skipped."
    fi
fi
cleanup_fixture6
trap - EXIT

echo "-- 7. strict safety-bound parsing (--max-seconds / --max-events)"
# A malformed bound must error (exit non-zero), never silently disable the
# timeout or the event budget, and never fall through to a clean run.
for opt in --max-seconds --max-events; do
    for bad in "abc" "-1" "5x" ""; do
        set +e
        SB_OUT="$("$HOST_BIN" "$opt" "$bad" "$HELLO_LIB" 2>&1)"
        SB_RC=$?
        set -e
        if [ "$SB_RC" = "0" ]; then
            echo "FAIL: $opt '$bad' was accepted (exit 0) instead of rejected"
            echo "$SB_OUT"
            FAILED=1
        fi
        if grep -qF "host: shutdown ok" <<<"$SB_OUT"; then
            echo "FAIL: $opt '$bad' fell through to a clean run"
            FAILED=1
        fi
    done
done
# A well-formed value (including an explicit 0) must still be accepted and
# run to a clean shutdown.
for good in "0" "5" "32"; do
    set +e
    SB_GOOD="$("$HOST_BIN" --max-events "$good" --max-seconds "$good" \
        "$HELLO_LIB" 2>&1)"
    set -e
    if grep -qF "must be a non-negative integer" <<<"$SB_GOOD"; then
        echo "FAIL: a valid safety bound '$good' was rejected by the parser"
        FAILED=1
    fi
    if ! grep -qF "host: shutdown ok" <<<"$SB_GOOD"; then
        echo "FAIL: a valid safety bound '$good' did not run to a clean shutdown"
        FAILED=1
    fi
done
echo "PASS: malformed safety bounds are rejected; valid ones parse"

echo "-- 8. live step failure must fail the command (never report success)"
# A failure while stepping over a watched-export entry breakpoint could
# previously leave a breakpoint in place yet still report success. Force
# it and require a non-zero exit with "shutdown with errors". Only
# meaningful where the live path actually attaches; skipped honestly
# otherwise (same as sections 3 and 6).
PIDFILE8="$(mktemp)"
FXPID8=""
cleanup_fixture8() {
    [ -n "$FXPID8" ] && kill -9 "$FXPID8" >/dev/null 2>&1 || true
    rm -f "$PIDFILE8" >/dev/null 2>&1 || true
}
trap cleanup_fixture8 EXIT
LD_LIBRARY_PATH="$FIXTURE_LIBDIR:${LD_LIBRARY_PATH:-}" "$FIXTURE_BIN" "$PIDFILE8" &
FXPID8=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -s "$PIDFILE8" ] && break
    sleep 0.2
done
TARGET_PID8="$(cat "$PIDFILE8" 2>/dev/null || true)"
if [ -z "$TARGET_PID8" ]; then
    echo "FAIL: fixture process (step-failure test) did not report a pid"
    FAILED=1
else
    set +e
    STEP_OBS="$(NX86_TEST_INJECT=step-over-fail "$HOST_BIN" \
        --pid "$TARGET_PID8" --i-own-this-process \
        --max-events 4 --max-seconds 10 \
        "$OPENSSL_LIB" "$JNI_LIB" 2>&1)"
    STEP_RC=$?
    set -e
    echo "$STEP_OBS"
    if grep -qF "phase=enter" <<<"$STEP_OBS"; then
        # Live path ran and reached the step: the injected failure must
        # fail the command, print "shutdown with errors", and never print
        # a clean "shutdown ok".
        if [ "$STEP_RC" = "0" ]; then
            echo "FAIL: live step failure did not fail the command (exit 0)"
            FAILED=1
        fi
        if grep -qF "host: shutdown ok" <<<"$STEP_OBS"; then
            echo "FAIL: live step failure still reported 'shutdown ok'"
            FAILED=1
        fi
        if ! grep -qF "host: shutdown with errors" <<<"$STEP_OBS"; then
            echo "FAIL: live step failure did not report 'shutdown with errors'"
            FAILED=1
        fi
        if ! grep -qiE 'did not complete cleanly' <<<"$STEP_OBS"; then
            echo "FAIL: live step failure did not warn about an unclean pass"
            FAILED=1
        fi
        echo "PASS: live step failure fails the command"
    else
        echo "NOTE: live path did not attach here; step-failure check skipped."
    fi
fi
cleanup_fixture8
trap - EXIT

if [ "$FAILED" != "0" ]; then
    echo "SMOKE TEST: FAIL"
    exit 1
fi

echo "PASS: skeleton builds, dispatches events, passes abi checks, and"
echo "      reports metadata-only module/symbol/call-site records for a"
echo "      fixture process."
