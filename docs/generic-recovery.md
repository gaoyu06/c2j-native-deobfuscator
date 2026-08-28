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

`RegisterNatives` is identified as JNI vtable index 215. The scanner reads
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

Under `generic`, throw-message hints, decompiler-specific vtable rewriting,
cache-table assumptions, and exception/cache guard skipping remain disabled.
A matching variant profile may opt into each behavior, and lifter flags can
disable an enabled feature individually.
