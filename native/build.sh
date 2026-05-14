#!/usr/bin/env bash
# Build j2c_agent shared library using zig c++.
# Output: build/lib/j2c_agent.{dll,so,dylib}
set -euo pipefail

ZIG="${ZIG:-$HOME/.native-obfuscator/zig/zig-x86_64-windows-0.16.0/zig.exe}"
JDK_HOME="${JDK_HOME:-${JAVA_HOME:-}}"
if [ -z "$JDK_HOME" ]; then
    echo "JDK_HOME / JAVA_HOME unset" >&2
    exit 2
fi

# Detect host target name
HOST_OS=$(uname -s)
HOST_ARCH=$(uname -m)
case "$HOST_OS" in
    Linux)   TARGET="x86_64-linux-gnu";   OUT="j2c_agent.so";    JNI_MD_SUBDIR="linux" ;;
    Darwin)  TARGET="x86_64-macos";       OUT="j2c_agent.dylib"; JNI_MD_SUBDIR="darwin" ;;
    MINGW*|MSYS*|CYGWIN*)
             TARGET="x86_64-windows-gnu"; OUT="j2c_agent.dll";   JNI_MD_SUBDIR="win32" ;;
    *)       echo "Unknown OS: $HOST_OS" >&2; exit 2 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$SCRIPT_DIR/build/lib"

PIC_FLAG="-fPIC"
case "$TARGET" in *windows*) PIC_FLAG="" ;; esac

"$ZIG" c++ \
    -target "$TARGET" \
    -std=c++17 -O2 -DNDEBUG -shared \
    $PIC_FLAG \
    -Wno-nullability-completeness \
    -I "$JDK_HOME/include" \
    -I "$JDK_HOME/include/$JNI_MD_SUBDIR" \
    -I "$SCRIPT_DIR/include" \
    -o "$SCRIPT_DIR/build/lib/$OUT" \
    "$SCRIPT_DIR/src/agent.cpp" \
    "$SCRIPT_DIR/src/trace_writer.cpp" \
    "$SCRIPT_DIR/src/jni_hook.cpp"

echo "built: $SCRIPT_DIR/build/lib/$OUT"
