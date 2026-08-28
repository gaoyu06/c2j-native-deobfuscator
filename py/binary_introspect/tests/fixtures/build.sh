#!/usr/bin/env bash
#
# Rebuild the binary_introspect test fixtures from their committed C sources.
#
# The built binaries (.so / .dll / .dylib) are committed to the repository so
# the pytest suite runs without any cross toolchain. This script only needs to
# run when you change a fixture source or want to regenerate the binaries. It
# rebuilds whatever it has tools for and skips (with a clear message) the rest;
# it never fakes one format from another.
#
# Toolchains used, all installable on a Linux host:
#   ELF    : the host cc/gcc + strip           (always available)
#   PE     : x86_64-w64-mingw32-gcc            (apt: gcc-mingw-w64-x86-64)
#   Mach-O : clang + ld64.lld                  (apt: clang lld)
#
# Reproducibility notes:
#   - Mach-O is byte-reproducible (LC_UUID disabled via -no_uuid).
#   - The PE image base is pinned so addresses are stable; a couple of header
#     bytes (PE checksum) may still differ between rebuilds. That is why the
#     built binaries are committed rather than rebuilt in CI.
#   - libjni_registrar.so (the base ELF fixture) is NOT rebuilt here: its exact
#     addresses are asserted by test_generic_discovery.py and are not
#     byte-stable across compiler versions. It is a committed input; the
#     stripped fixture is derived from it with strip. Set REBUILD_BASE_ELF=1 to
#     regenerate it deliberately (then update the address assertions).
set -euo pipefail

cd "$(dirname "$0")"

log()  { printf '  %s\n' "$*"; }
skip() { printf '  SKIP %s\n' "$*"; }

CC="${CC:-cc}"

echo "[ELF] libjni_registrar.so (RegisterNatives static table — committed input)"
if [ "${REBUILD_BASE_ELF:-0}" = "1" ] && command -v "$CC" >/dev/null 2>&1; then
    "$CC" -O2 -shared -fPIC -nostdlib -o libjni_registrar.so jni_registrar.c
    log "rebuilt libjni_registrar.so (REBUILD_BASE_ELF=1) — verify address assertions"
else
    log "keeping committed libjni_registrar.so (set REBUILD_BASE_ELF=1 to rebuild)"
fi

echo "[ELF] libjni_registrar.stripped.so (symbols stripped, derived from base)"
if [ -f libjni_registrar.so ] && command -v strip >/dev/null 2>&1; then
    cp -f libjni_registrar.so libjni_registrar.stripped.so
    strip --strip-all libjni_registrar.stripped.so
    log "built libjni_registrar.stripped.so"
else
    skip "no strip or no source .so — keeping committed libjni_registrar.stripped.so"
fi

echo "[ELF] libjni_exports_only.so (Java_* exports, no table)"
if command -v "$CC" >/dev/null 2>&1; then
    "$CC" -O2 -shared -fPIC -nostdlib -o libjni_exports_only.so jni_exports_only.c
    log "built libjni_exports_only.so"
else
    skip "no C compiler ($CC) — keeping committed libjni_exports_only.so"
fi

echo "[PE] jni_registrar.dll (Microsoft x64 ABI)"
MINGW="${MINGW:-x86_64-w64-mingw32-gcc}"
if command -v "$MINGW" >/dev/null 2>&1; then
    "$MINGW" -O2 -shared -o jni_registrar.dll jni_registrar_pe.c \
        -nostdlib \
        -Wl,--entry=0 \
        -Wl,--no-insert-timestamp \
        -Wl,--image-base,0x180000000 \
        -Wl,--disable-dynamicbase
    log "built jni_registrar.dll"
else
    skip "no $MINGW — keeping committed jni_registrar.dll"
fi

echo "[Mach-O] libjni_registrar.dylib (System V ABI)"
# clang needs to find ld64.lld; on Debian/Ubuntu it lives in the llvm bindir.
for d in /usr/lib/llvm-*/bin; do
    [ -x "$d/ld64.lld" ] && PATH="$d:$PATH" && export PATH && break
done
if command -v clang >/dev/null 2>&1 && command -v ld64.lld >/dev/null 2>&1; then
    clang -O2 -target x86_64-apple-macos11 -dynamiclib -fuse-ld=lld -nostdlib \
        -Wl,-undefined,dynamic_lookup \
        -Wl,-install_name,@rpath/libjni_registrar.dylib \
        -Wl,-no_uuid \
        -o libjni_registrar.dylib jni_registrar_macho.c
    log "built libjni_registrar.dylib"
else
    skip "no clang + ld64.lld — keeping committed libjni_registrar.dylib"
fi

echo "done."
