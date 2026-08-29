# Generic recovery without Ghidra

The built-in `generic` profile discovers JNI-native transpiled methods from
specification-defined structures. It does not use throw-message wording,
decompiler variable names, pseudo-C rewrites, or variant-specific skip rules.
Ghidra remains an optional method-body plugin; it is not required to create a
method list, manifest, or restoration stubs.

## Supported generic inputs

The current binary introspection and emulation backends support:

| Binary | ABI | `JNINativeMethod *` argument | `nMethods` argument |
|---|---|---:|---:|
| PE x86-64 | Microsoft x64 | `r8` | `r9d` / `r9` |
| ELF or Mach-O x86-64 | System V | `rdx` | `ecx` / `rcx` |
| ELF aarch64 | AAPCS64 | `x2` | `w3` / `x3` |

`RegisterNatives` is identified as JNI vtable index 215. The scanner reads

## Proven object formats and registration families

Generic discovery started as an ELF-only, single-table proof. It is now
exercised by committed fixtures across all three x86-64 object formats, a
non-x86-64 (AArch64) image, section-header-removed images, and both
registration families, so the path is no longer tied to one workflow. Each row
below is backed by a real binary in `py/binary_introspect/tests/fixtures/`
(source `.c` + built binary, or a derivation of a committed base) and an
assertion in `test_generic_discovery.py`:

| Object format | ABI | What is proven | Fixture |
|---|---|---|---|
| ELF x86-64 | System V | `RegisterNatives` static table decoded to names/descriptors/addresses via relocations | `libjni_registrar.so` |
| ELF x86-64 (symbols stripped) | System V | Same table still recovered after `strip --strip-all` (no `.symtab`); no silent empty result | `libjni_registrar.stripped.so` |
| ELF x86-64 (exports only) | System V | Second registration family: methods registered purely by `Java_*` export names, **no** table | `libjni_exports_only.so` |
| PE x86-64 | Microsoft x64 | Static table (r8/r9d) decoded to names/addresses **and** a `Java_*` export recorded | `jni_registrar.dll` |
| Mach-O x86-64 | System V | Static table decoded to names/addresses **and** a `_Java_*` export normalized to the spec name | `libjni_registrar.dylib` |
| **ELF aarch64** | AAPCS64 | Static table decoded via `adrp`/`add` table addressing and `R_AARCH64_ABS64` fnPtr relocations; the split JNI dispatch is followed through the `x16` veneer register (`ldr`/`mov x16`/`br x16`); a `Java_*` export is recorded | `libjni_registrar_aarch64.so` |
| **ELF x86-64 (section header table removed)** | System V | `sstrip`-style image with only `PT_LOAD` segments: the static table is still decoded through the program-header (`PT_LOAD` + dynamic relocation) fallback, with no sections | `libjni_registrar.noshdr.so` |
| **ELF x86-64 (section header table removed, exports only)** | System V | `Java_*` dynamic exports recovered from `PT_DYNAMIC` with the section table gone | `libjni_exports_only.noshdr.so` |

The fixtures rebuild from source with `bash
py/binary_introspect/tests/fixtures/build.sh` when the cross toolchains are
present (`x86_64-w64-mingw32-gcc` for PE, `clang` + `ld64.lld` for Mach-O,
`aarch64-linux-gnu-gcc` or `zig cc -target aarch64-linux-gnu` for the AArch64
ELF, the host `cc` + `strip` for x86-64 ELF). The section-header-removed images
are derived from the committed base binaries by `strip_section_headers.py` (a
dependency-free `sstrip` equivalent). The built binaries are committed so the
suite runs without any toolchain; the base ELF is a committed input and is not
rebuilt by default because its exact addresses are asserted.

### AArch64 disassembly notes

AArch64 has no "call through a memory operand" instruction, so a JNI vtable
dispatch is always the split form: the slot is materialised with
`ldr xN, [xEnv, #215*8]` and then reached via `blr`/`br`, frequently through
the `x16` intra-procedure-call veneer (`mov x16, xN` / `br x16`). The split-call
scanner follows that register-to-register move so the veneer does not hide the
site. The address of an in-image `JNINativeMethod[]` is formed with an
`adrp`/`add` pair rather than one RIP-relative `lea`; the AArch64 ABI folds the
pair back into an absolute VA. If a host's Capstone build cannot decode AArch64,
the `Java_*` export is still parsed from the symbol table via LIEF and **no**
methods are fabricated.

### Section-header-removed ELF (`PT_LOAD` fallback)

When an ELF has had its section header table removed (`e_shoff`/`e_shnum`
zeroed, e.g. by `sstrip`), `b.sections` is empty. Discovery then falls back to
the program headers: executable ranges come from `PF_X` `PT_LOAD` segments and
the mapped image from all `PT_LOAD` segments, while dynamic relocations (already
section-independent) fill the zeroed `fnPtr` slots. The first `PT_LOAD` maps
virtual address 0 (the ELF header), so a null on-disk pointer is never trusted
as "in range" — it defers to its relocation. If a given LIEF build cannot map a
section-header-removed image at all, introspection **raises** rather than
returning an empty result; the tests assert that honest failure explicitly, so
this case is never a silent empty success.

### Still unproven / out of scope

These are acknowledged gaps, not silent successes — the code either records an
honest gap, raises, or returns nothing observable rather than a fabricated
binding:

- 32-bit ARM (`arm`) ELF and other architectures without a registered ABI
  backend. `detect_abi` returns `None`, so discovery yields an empty registry
  with no fabricated methods.
- Mach-O arm64: the AAPCS64 ABI is registered for it in code (`CPU_TYPE_ARM64`),
  but it is not yet exercised by a committed fixture, so it is treated as
  unproven until one exists.
- A section-header-removed ELF that a particular LIEF build cannot map through
  its program headers. Introspection raises an honest error in that case (the
  tests encode both outcomes); it never silently succeeds.
- Encrypted or runtime-decrypted method tables that emulation cannot reach.
- Custom dispatch that does not preserve `JNINativeMethod[]` order.

Whenever a `RegisterNatives` table is count-only or matches multiple classes by
count, `manifest-merge` records it in `bindingGaps` instead of guessing a bind.


Capstone operands, not rendered instruction text. It then requires supporting
facts near the call: an immediate table length in the ABI's fourth argument,
function-address LEAs into executable ranges, or a third-argument pointer to a
valid in-image `JNINativeMethod[]`.

For a static table, every entry must contain:

1. a readable method-name string;
2. a valid JVM method descriptor;
3. a function pointer into an executable range.

Stack-built tables can still yield an ordered `fnAddrs` list when names and
descriptors are materialized only at runtime. `manifest-merge` binds named
tables first and uses count/order only as a fallback.

Specification-defined `Java_*` exports are also recorded. Their encoded names
are matched exactly against the JAR's native methods during manifest creation.

## One-command static-lite path

Build the JVM command-line modules once, then run:

```bash
python -m j2c_dumper_cli.main static-lite input.jar \
  --lib path/to/native.so \
  --profile generic \
  -o work/static-lite
```

This writes:

- `classes.json` — JAR classes and native declarations;
- `binary.json` — exports and structurally discovered method tables;
- `manifest.json` — Java methods bound to native function addresses;
- `recovered/*.json` — verifier-safe restoration stubs.

No decompiler is invoked.

If registration is reachable through `JNI_OnLoad`, or through a known registrar
function, add emulation:

```bash
python -m j2c_dumper_cli.main static-lite input.jar \
  --lib path/to/native.so \
  --profile generic \
  --emulate-registration \
  --registrar 0x401000 \
  -o work/static-lite
```

`--registrar` is repeatable and optional. Registration captured by emulation is
merged into `binary.json`, including method names and descriptors when the
runtime table exposes them.

## Stage-by-stage path

```bash
python -m j2c_dumper_cli.main parse-jar input.jar -o classes.json
python -m j2c_dumper_cli.main inspect-binary native.so \
  --profile generic -o binary.json
python -m j2c_dumper_cli.main merge-manifest \
  classes.json binary.json -o manifest.json
python -m j2c_dumper_cli.main synth-stubs \
  --manifest manifest.json -o recovered/
```

Add `--emulate-registration` and optional `--registrar` values to
`inspect-binary` to use registration emulation as another method-table source.

The same top-level CLI exposes optional string and oracle output:

```bash
python -m j2c_dumper_cli.main emulate native.so --operation recover \
  --json-output methods.json
python -m j2c_dumper_cli.main emulate native.so --operation strings \
  --fn 0x401200
python -m j2c_dumper_cli.main emulate native.so --operation call \
  --fn 0x401200 --arg-bytes "input"
```

Emulation requires the optional `unicorn` package.

## What generic recovery does and does not prove

The generic profile can list and bind methods when at least one of these is
present:

- specification-defined `Java_*` exports;
- an x86-64 standard JNI `RegisterNatives` call with a static table;
- a stack-built table whose function pointers and length remain visible;
- registration that the emulation backend can reach.

It does not automatically restore arbitrary method behavior. JVMTI tracing can
restore executed JNI interactions, while emulation can expose strings and
provide a function oracle. The optional Ghidra/pseudo-C path may recover more
method-body structure.

A variant profile or backend extension is still needed for unsupported
architectures, nonstandard registration, encrypted tables that are not reached
by emulation, custom dispatch that does not preserve table order, and
variant-specific method-body patterns.

## Optional Ghidra plugin

The scripts under `ghidra/scripts/` and the `static-reverse` command are kept
for deeper method-body analysis:

```bash
python -m j2c_dumper_cli.main static-reverse ghidra-dump.json \
  --manifest manifest.json -o recovered/
```

`manifest-merge` carries `analysis.profile` from `binary.json` into
`manifest.json`. The lifter uses that profile when `--profile` is omitted.
An explicit profile still wins, and a missing profile falls back to
conservative `generic`.

Under `generic`, throw-message hints, decompiler-specific vtable rewriting,
cache-table assumptions, and exception/cache guard skipping remain disabled.
A matching variant profile may opt into each behavior, and lifter flags can
disable an enabled feature individually.
