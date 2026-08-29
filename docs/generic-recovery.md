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
| ELF or Mach-O aarch64 | AAPCS64 | `x2` | `w3` / `x3` |
| ELF 32-bit ARM | AAPCS32 | `r2` | `r3` |
| ELF 32-bit x86 (i386) | System V (cdecl) | stack (`push`) | stack (`push $imm`) |

`RegisterNatives` is identified as JNI vtable index 215. The scanner reads

## Proven object formats and registration families

Generic discovery started as an ELF-only, single-table proof. It is now
exercised by committed fixtures across all three x86-64 object formats,
non-x86-64 images (64-bit AArch64, 32-bit ARM, and 32-bit x86/i386),
section-header-removed images, and **two distinct registration families** — the
per-class one-table registrar and a shared `initClass()`-style dispatcher (one
call site, several tables) — so the path is no longer tied to one workflow or a
single obfuscator shape. Each row
below is backed by a real binary in `py/binary_introspect/tests/fixtures/`
(source `.c` + built binary, or a derivation of a committed base) and an
assertion in `test_generic_discovery.py`:

| Object format | ABI | What is proven | Fixture |
|---|---|---|---|
| ELF x86-64 | System V | `RegisterNatives` static table decoded to names/descriptors/addresses via relocations | `libjni_registrar.so` |
| ELF x86-64 (symbols stripped) | System V | Same table still recovered after `strip --strip-all` (no `.symtab`); no silent empty result | `libjni_registrar.stripped.so` |
| ELF x86-64 (exports only) | System V | Second registration family: methods registered purely by `Java_*` export names, **no** table | `libjni_exports_only.so` |
| **ELF x86-64 (shared dispatch, generic `auto`)** | System V | Second registration **family** beyond a single obfuscator: one shared `RegisterNatives` call site reached by two branches registers two classes with different `nMethods` (2 and 3). The **generic `auto` harvest** (no named detector fires — `analysis.profile` stays `generic`) recovers **both** stack-built tables from the one site — two independently sized `nMethods` groups whose fnAddrs cross-check the export addresses — instead of collapsing them into one silent bind. No names are decoded and no methods are fabricated for the stack tables | `libjni_dispatch_shared.so` (asm) |
| **PE x86-64 (named `j2cc`, `shared_dispatch`)** | Microsoft x64 | The **named `j2cc` profile detector** (`_detect_j2cc`) firing on a real Windows image — not a mocked LIEF object. Two Java_* exports (`initClass` + `bootstrap`, ≤4) plus a `Cannot invoke ` literal make `_detect_j2cc` win over the generic fallback, so `analysis.profile` is `j2cc`. That profile's `harvest_strategy="shared_dispatch"` then **always** calls `_harvest_dispatch` (not the `auto` fallback) and recovers **both** stack tables (`nMethods` 2 and 3) from the one Microsoft x64 `RegisterNatives` call site (env in `rcx`, `methods*` in `r8`, `nMethods` in `r9d`, `call *0x6b8(%rax)`). Recovered fnAddrs cross-check the `fixture_*` export addresses; no names are fabricated on the stack tables. A genuine PE (MZ/PE magic, machine `0x8664`) — never a renamed ELF | `jni_dispatch_j2cc.dll` (asm) |
| **ELF 32-bit x86 (i386)** | System V (cdecl) | A genuine `(ELF, EM_386)` image: `format=ELF`/`arch=x86` reported, `detect_abi` selects `i386-sysv`, and a `Java_*` export is recorded. cdecl passes `RegisterNatives` arguments on the stack (`push $nMethods` / `push methods`); PIC forms the table address through the GOT-base register (`call`/`pop`/`add` PC thunk, then `lea disp(%ebx), %edx`), which the backend folds back so the static table decodes to names/descriptors whose fnPtrs (from `R_386_32` relocations) cross-check the export addresses. Not a renamed 64-bit `.so` | `libjni_registrar_i386.so` |
| PE x86-64 | Microsoft x64 | Static table (r8/r9d) decoded to names/addresses **and** a `Java_*` export recorded | `jni_registrar.dll` |
| Mach-O x86-64 | System V | Static table decoded to names/addresses **and** a `_Java_*` export normalized to the spec name | `libjni_registrar.dylib` |
| **ELF aarch64** | AAPCS64 | Static table decoded via `adrp`/`add` table addressing and `R_AARCH64_ABS64` fnPtr relocations; the split JNI dispatch is followed through the `x16` veneer register (`ldr`/`mov x16`/`br x16`); a `Java_*` export is recorded | `libjni_registrar_aarch64.so` |
| **Mach-O arm64** | AAPCS64 | A genuine `(MachO, aarch64)` image: `format=MachO`/`arch=aarch64` reported, and a `_Java_*` export normalized to the spec name. When the host Capstone can decode AArch64 the static table is additionally decoded — clang forms the nearby table address with a single `adr` (not the ELF `adrp`/`add` pair), and the fnPtrs cross-check the export addresses; otherwise the export stands alone and no methods are fabricated | `libjni_registrar_arm64.dylib` |
| **ELF 32-bit ARM** | AAPCS32 | A genuine `(ELF, EM_ARM)` image: `format=ELF`/`arch=arm` reported, and a `Java_*` export recorded. When the host Capstone can decode 32-bit ARM the static table is additionally decoded — the split JNI dispatch is followed through the `ip` (r12) veneer register (`ldr lr, [ip, #860]` / `mov ip, lr` / `bx ip`), the position-independent table address is folded back from the `ldr`-literal + `add r2, pc, r2` pair, and the fnPtrs (zeroed slots filled from `R_ARM_ABS32` relocations) cross-check the export addresses; otherwise the export stands alone and no methods are fabricated | `libjni_registrar_arm.so` |
| **ELF x86-64 (section header table removed)** | System V | `sstrip`-style image with only `PT_LOAD` segments: the static table is still decoded through the program-header (`PT_LOAD` + dynamic relocation) fallback, with no sections | `libjni_registrar.noshdr.so` |
| **ELF x86-64 (section header table removed, exports only)** | System V | `Java_*` dynamic exports recovered from `PT_DYNAMIC` with the section table gone | `libjni_exports_only.noshdr.so` |

The fixtures rebuild from source with `bash
py/binary_introspect/tests/fixtures/build.sh` when the cross toolchains are
present (`x86_64-w64-mingw32-gcc` for PE, `clang` + `ld64.lld` for both Mach-O
fixtures — `-target x86_64-apple-macos` and `-target arm64-apple-macos`, or
`zig cc -target aarch64-macos` for the arm64 one — `aarch64-linux-gnu-gcc` or
`zig cc -target aarch64-linux-gnu` for the AArch64 ELF, `arm-linux-gnueabi-gcc`
or `zig cc -target arm-linux-gnueabi` for the 32-bit ARM ELF, the host `cc`
assembler for the shared-dispatch `.s`, an i386 toolchain
(`i686-linux-gnu-gcc`, `zig cc -target x86-linux-gnu`,
`clang --target=i386-linux-gnu`, or `gcc -m32`) for the i386 ELF,
`x86_64-w64-mingw32-gcc` for the PE `j2cc` shared-dispatch `.s`, and the host
`cc` + `strip` for x86-64 ELF). If no i386 toolchain is present the committed
`libjni_registrar_i386.so` is kept and **no** 64-bit `.so` is renamed to stand
in for it. The section-header-removed images
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
site. The address of an in-image `JNINativeMethod[]` is formed either with an
`adrp`/`add` pair (the wider form, used by the AArch64 ELF fixture) or with a
single `adr xN, #label` when the constant sits within ±1 MiB of the code (the
compact form clang emits for the small Mach-O arm64 dylib) rather than one
RIP-relative `lea`; the AArch64 ABI folds both back into an absolute VA. If a
host's Capstone build cannot decode AArch64, the `Java_*` export is still parsed
from the symbol table via LIEF and **no** methods are fabricated. This holds for
both the ELF aarch64 and the Mach-O arm64 fixtures.

### 32-bit ARM disassembly notes

Like AArch64, 32-bit ARM has no "call through a memory operand" instruction, so
the JNI vtable dispatch is the split form: the slot is materialised with
`ldr lr, [ip, #215*4]` (i.e. `#860`) and reached via `bx`/`blx`, frequently
through the `ip` (r12) intra-procedure-call veneer (`mov ip, lr` / `bx ip`). The
split-call scanner follows that register-to-register move so the veneer does not
hide the site. The address of an in-image `JNINativeMethod[]` is not a single
`lea` (x86) or `adrp`/`add` pair (AArch64): position-independent ARM loads a
link-time-constant offset from the function's literal pool and adds the program
counter (`ldr r2, [pc, #k]` / `add r2, pc, r2`). The AAPCS32 ABI reads the
pooled word through a per-scan literal reader and folds the pair back into the
absolute table VA. The zeroed `fnPtr` slots are filled from `R_ARM_ABS32`
relocations while the name/descriptor pointers are read from their inline
`R_ARM_RELATIVE` values. If a host's Capstone build cannot decode 32-bit ARM,
the `Java_*` export is still parsed from the symbol table via LIEF and **no**
methods are fabricated.

### i386 (cdecl, stack arguments) disassembly notes

The i386 System V C calling convention passes **every** argument on the stack,
so `RegisterNatives` is four `push` instructions (right-to-left:
`push $nMethods` first) followed by an indirect call through the vtable slot
(`call *0x35c(%ecx)`, i.e. `215 * 4`). The `i386-sysv` backend therefore reads
the count from a pushed immediate (bounded to a plausible table size so a pushed
pointer is never mistaken for a count) rather than from a register move.
Position-independent i386 has no RIP-relative addressing; it materialises the
Global Offset Table base into a register with a PC thunk — clang's inline
`call .Lnext` / `pop %ebx` / `add $off, %ebx`, or gcc's out-of-line
`call __x86.get_pc_thunk.reg` / `add $off, %reg` — and then reaches the table
with `lea disp(%ebx), %edx`. The backend tracks the GOT-base register across
either thunk form and folds the GOT-relative `lea` back to the absolute table
VA, after which the architecture-agnostic decoder reads the table exactly as on
x86-64. The zeroed `fnPtr` slots are filled from `R_386_32` relocations while
the name/descriptor pointers are read from their inline `R_386_RELATIVE` values.
Every capstone build carries the base x86 decoder, so 32-bit x86 is effectively
always disassemblable; the test still guards on it and, on the hypothetical
build that cannot decode it, claims no table and fabricates no methods while the
`Java_*` export (from LIEF's symbol table) still stands.

### Shared-dispatch registration (one call site, several tables)

The second registration family beyond the per-class registrar is a shared
`initClass()`-style dispatcher: one `RegisterNatives` call site is reached by
several branches, each building its own `JNINativeMethod[]` (on the stack) with
its own `nMethods`. The scanner splits such a site on each `nMethods` boundary
and emits one `register-natives-stack` table per branch — recovering two
independently sized `nMethods` groups from a single call rather than collapsing
them into one silent bind. This family is proven by **two committed fixtures
that exercise two different entry points into the same `_harvest_dispatch`
logic**:

- **ELF `libjni_dispatch_shared.so` — generic `auto` harvest.** No
  variant-specific detector fires, so `analysis.profile` stays `generic`; the
  `auto` strategy falls back to `_harvest_dispatch` only after the ordinary
  per-class harvest finds no single table, and only accepts the split when more
  than one independently sized table is recovered. This proves the
  specification-based path picks up a shared dispatcher on a real binary without
  any named profile.
- **PE `jni_dispatch_j2cc.dll` — named `j2cc` detector + `shared_dispatch`
  strategy.** The named `j2cc` profile detector fires on a genuine Windows image
  (two Java_* exports plus a `Cannot invoke ` literal), so `analysis.profile` is
  `j2cc`; that profile pins `harvest_strategy="shared_dispatch"`, the path that
  **always** calls `_harvest_dispatch` directly (never the `auto` fallback).
  This proves the named detector and its dedicated harvest on Microsoft x64
  (env in `rcx`, `methods*` in `r8`, `nMethods` in `r9d`), closing the gap where
  `_detect_j2cc` was previously exercised only by a mocked LIEF object.

Both fixtures are hand-written assembly on purpose: a stack-built shared
dispatcher's instruction shape is not stable across C compilers or optimisation
levels (PIC routes function pointers through the GOT, stores get vectorised, and
one if/else branch is laid out *after* the merged call, outside the back-scan
window), so a fixed sequence keeps each fixture a faithful, reproducible model
with both branches before the shared call. Stack-built tables expose an ordered
`fnAddrs` list and a per-branch `nMethods` but no decoded names; `manifest-merge`
binds them by count and **records a `bindingGaps` entry** whenever a branch's
count matches more than one class, never guessing a bind.

This is a draft development capability, not a default-release path: `recover`'s
defaults are unchanged and continue to use the conservative `generic` profile.

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

- Architectures without a registered ABI backend (for example MIPS or RISC-V).
  `detect_abi` returns `None`, so discovery yields an empty registry with no
  fabricated methods. (32-bit x86/i386 ELF is now proven — see the table above —
  as are 32-bit ARM ELF, x86-64 PE/Mach-O/ELF, and 64-bit ARM in both ELF and
  Mach-O.)
- A section-header-removed ELF that a particular LIEF build cannot map through
  its program headers. Introspection raises an honest error in that case (the
  tests encode both outcomes); it never silently succeeds.
- 32-bit x86 on Windows (PE `IMAGE_FILE_MACHINE_I386`), whose `JNICALL` is
  `__stdcall` rather than the ELF cdecl proven above. `detect_abi` matches only
  ELF `EM_386`, so a PE i386 image yields an empty registry with no fabricated
  methods until a dedicated backend is added.
- Encrypted or runtime-decrypted method tables that emulation cannot reach.
- Custom dispatch that does not preserve `JNINativeMethod[]` order. (A shared
  `initClass()` dispatcher that *does* preserve per-branch table order is now
  proven — see the shared-dispatch fixture above.)

Whenever a `RegisterNatives` table is count-only or matches multiple classes by
count — including each branch of a shared-dispatch call site — `manifest-merge`
records it in `bindingGaps` instead of guessing a bind. The default `recover`
pipeline is unchanged by this work.


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

`inspect-binary` prints the detected `profile=<name>` (from
`binary.json`'s `analysis.profile`) alongside the format, arch, and
registry-record count. `merge-manifest` prints `bindingGaps=<n>` and the gap
kinds after writing `manifest.json`. Binding gaps are a manifest-level fact — a
native table that could not be unambiguously bound to a JAR class — so they are
reported after the merge stage and are **not** written onto `binary.json`.

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
