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
#   ELF x86-64  : the host cc/gcc + strip          (always available)
#   ELF aarch64 : aarch64-linux-gnu-gcc            (apt: gcc-aarch64-linux-gnu)
#                 or `zig cc -target aarch64-linux-gnu`
#   ELF arm     : arm-linux-gnueabi-gcc            (apt: gcc-arm-linux-gnueabi)
#                 or `zig cc -target arm-linux-gnueabi`
#   PE          : x86_64-w64-mingw32-gcc           (apt: gcc-mingw-w64-x86-64)
#   Mach-O      : clang + ld64.lld                 (apt: clang lld)
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

echo "[ELF/aarch64] libjni_registrar_aarch64.so (AAPCS64 static table + Java_* export)"
# Prefer a dedicated cross gcc; fall back to zig if it is the only toolchain
# present. The aarch64 test cross-checks function pointers against the export
# addresses instead of hard-coding absolute VAs, so a rebuild that shifts
# addresses does not break the assertions.
AARCH64_CC="${AARCH64_CC:-aarch64-linux-gnu-gcc}"
if command -v "$AARCH64_CC" >/dev/null 2>&1; then
    "$AARCH64_CC" -O2 -shared -fPIC -nostdlib \
        -o libjni_registrar_aarch64.so jni_registrar_aarch64.c
    log "built libjni_registrar_aarch64.so ($AARCH64_CC)"
elif command -v zig >/dev/null 2>&1; then
    zig cc -target aarch64-linux-gnu -O2 -shared -fPIC -nostdlib \
        -o libjni_registrar_aarch64.so jni_registrar_aarch64.c
    log "built libjni_registrar_aarch64.so (zig cc)"
else
    skip "no aarch64 cross cc ($AARCH64_CC) or zig — keeping committed libjni_registrar_aarch64.so"
fi

echo "[ELF/arm] libjni_registrar_arm.so (AAPCS32 static table + Java_* export)"
# The 32-bit sibling of the aarch64 fixture: a genuine (ELF, EM_ARM) image,
# not a renamed aarch64/x86 binary. Prefer a dedicated cross gcc; fall back to
# zig. -marm keeps the fixture in ARM (not Thumb) state so the committed byte
# encodings match the unit-test assertions. The test cross-checks function
# pointers against the export addresses rather than hard-coding absolute VAs,
# so a rebuild that shifts addresses does not break the assertions.
ARM_CC="${ARM_CC:-arm-linux-gnueabi-gcc}"
if command -v "$ARM_CC" >/dev/null 2>&1; then
    "$ARM_CC" -O2 -shared -fPIC -nostdlib -marm \
        -o libjni_registrar_arm.so jni_registrar_arm.c
    log "built libjni_registrar_arm.so ($ARM_CC)"
elif command -v zig >/dev/null 2>&1; then
    zig cc -target arm-linux-gnueabi -O2 -shared -fPIC -nostdlib -marm \
        -o libjni_registrar_arm.so jni_registrar_arm.c
    log "built libjni_registrar_arm.so (zig cc)"
else
    skip "no arm cross cc ($ARM_CC) or zig — keeping committed libjni_registrar_arm.so"
fi

echo "[ELF] libjni_dispatch_shared.so (shared-dispatch registrar — one call site, two tables)"
# A second registration FAMILY (not just another architecture): one shared
# initClass()-style RegisterNatives call site reached by two branches, each
# building its own stack JNINativeMethod[] with its own nMethods (2 and 3).
# Hand-written x86-64 assembly on purpose — a stack-built shared dispatcher's
# instruction shape is not stable across C compilers (PIC routes function
# pointers through the GOT, stores get vectorised, and one if/else branch lands
# after the merged call, outside the back-scan window). The committed .so lets
# the suite run with no assembler step; the test cross-checks recovered fnAddrs
# against export addresses, so a rebuild that shifts addresses still holds.
if command -v "$CC" >/dev/null 2>&1; then
    "$CC" -shared -nostdlib -o libjni_dispatch_shared.so jni_dispatch_shared.s
    log "built libjni_dispatch_shared.so ($CC)"
else
    skip "no C compiler ($CC) — keeping committed libjni_dispatch_shared.so"
fi

echo "[ELF/i386] libjni_registrar_i386.so (i386 SysV cdecl static table + Java_* export)"
# The 32-bit x86 sibling of the x86-64/AArch64/ARM .so fixtures: a genuine
# (ELF, EM_386) image, NOT a renamed 64-bit .so. cdecl passes RegisterNatives'
# arguments on the stack and PIC forms the table address through the GOT base
# register; the i386-sysv backend folds both back. Prefer a dedicated i686 cross
# gcc, then zig, then a real 32-bit target from the host clang/gcc. If none can
# emit i386, the committed binary is kept and no 64-bit .so is renamed. The test
# cross-checks function pointers against the export addresses rather than
# hard-coding VAs, so a rebuild that shifts addresses does not break it.
I386_CC="${I386_CC:-i686-linux-gnu-gcc}"
if command -v "$I386_CC" >/dev/null 2>&1; then
    "$I386_CC" -O2 -shared -fPIC -nostdlib \
        -o libjni_registrar_i386.so jni_registrar_i386.c
    log "built libjni_registrar_i386.so ($I386_CC)"
elif command -v zig >/dev/null 2>&1; then
    zig cc -target x86-linux-gnu -O2 -shared -fPIC -nostdlib \
        -o libjni_registrar_i386.so jni_registrar_i386.c
    log "built libjni_registrar_i386.so (zig cc)"
elif command -v clang >/dev/null 2>&1; then
    clang --target=i386-linux-gnu -O2 -shared -fPIC -nostdlib \
        -o libjni_registrar_i386.so jni_registrar_i386.c
    log "built libjni_registrar_i386.so (clang --target=i386-linux-gnu)"
elif command -v gcc >/dev/null 2>&1 && gcc -m32 -E - </dev/null >/dev/null 2>&1; then
    gcc -m32 -O2 -shared -fPIC -nostdlib \
        -o libjni_registrar_i386.so jni_registrar_i386.c
    log "built libjni_registrar_i386.so (gcc -m32)"
else
    skip "no i386 toolchain (i686-linux-gnu-gcc / zig / clang / gcc -m32) — keeping committed libjni_registrar_i386.so"
fi

echo "[ELF] libjni_exports_only.so (Java_* exports, no table)"
if command -v "$CC" >/dev/null 2>&1; then
    "$CC" -O2 -shared -fPIC -nostdlib -o libjni_exports_only.so jni_exports_only.c
    log "built libjni_exports_only.so"
else
    skip "no C compiler ($CC) — keeping committed libjni_exports_only.so"
fi

echo "[ELF] libjni_registrar.noshdr.so + libjni_exports_only.noshdr.so (section header table removed)"
# Derive PT_LOAD-only images (no section header table) from the committed base
# binaries, mirroring what `sstrip` produces. Pure-Python so it needs no extra
# toolchain. Addresses are preserved, so the registrar's table assertions and
# the exports-only names both hold on the stripped image.
if command -v python3 >/dev/null 2>&1; then
    python3 strip_section_headers.py libjni_registrar.so libjni_registrar.noshdr.so
    python3 strip_section_headers.py libjni_exports_only.so libjni_exports_only.noshdr.so
    log "built libjni_registrar.noshdr.so and libjni_exports_only.noshdr.so"
else
    skip "no python3 — keeping committed *.noshdr.so"
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

echo "[Mach-O/arm64] libjni_registrar_arm64.dylib (AAPCS64 static table + Java_* export)"
# The arm64 sibling of the Mach-O fixture above: a genuine (MachO, aarch64)
# image, not a renamed ELF or x86-64 dylib. clang emits the compact
# adr-based table-address form for this small image, which the AArch64 backend
# folds back to the table VA. `zig cc -target aarch64-macos` produces an
# equivalent binary when clang + ld64.lld are not available.
if command -v clang >/dev/null 2>&1 && command -v ld64.lld >/dev/null 2>&1; then
    clang -O2 -target arm64-apple-macos11 -dynamiclib -fuse-ld=lld -nostdlib \
        -Wl,-undefined,dynamic_lookup \
        -Wl,-install_name,@rpath/libjni_registrar_arm64.dylib \
        -Wl,-no_uuid \
        -o libjni_registrar_arm64.dylib jni_registrar_macho_arm64.c
    log "built libjni_registrar_arm64.dylib"
elif command -v zig >/dev/null 2>&1; then
    zig cc -target aarch64-macos -O2 -shared -nostdlib \
        -Wl,-install_name,@rpath/libjni_registrar_arm64.dylib \
        -o libjni_registrar_arm64.dylib jni_registrar_macho_arm64.c
    log "built libjni_registrar_arm64.dylib (zig cc)"
else
    skip "no clang + ld64.lld or zig — keeping committed libjni_registrar_arm64.dylib"
fi

echo "done."
