# j2c-dumper

Reverse-engineer native-obfuscator-style transpiled JARs back into reasonable
Java bytecode. Multi-language tool, not strictly bound to any single
transpiler — common functionality is generic; native-obfuscator-specific
helpers live in separately-flagged commands.

See [`docs/project-structure.md`](docs/project-structure.md) for the design
and [`docs/static-reverse-approach.md`](docs/static-reverse-approach.md) for
the Ghidra-based static reverse plan. Limitations and deferred items are
catalogued in [`docs/deferred-features.md`](docs/deferred-features.md).

---

## Modules

| Module | Lang | Role |
|---|---|---|
| `jvm/jar-parser` | Kotlin + ASM | Extract class skeletons + native registry → `classes.json` |
| `py/binary_introspect` | Python + LIEF | Parse PE/ELF, dump string pool & hidden classes → `binary.json` |
| `py/manifest_merge` | Python | Join classes.json + binary.json → `manifest.json` |
| `native/` | C++ JVMTI | Hook RegisterNatives + key JNI calls → `trace.jsonl` |
| `jvm/trace-to-bytecode` | Kotlin + ASM | Lift `trace.jsonl` into `recovered/*.json` (dynamic) |
| `ghidra/scripts` + `py/ast_matcher` | Java + Python | Lift Ghidra pseudo-C into `recovered/*.json` (static) |
| `jvm/class-rebuilder` | Kotlin + ASM | Replace native stubs with recovered bytecode → clean jar |
| `py/j2c_dumper_cli` | Python + typer | Top-level orchestrator |
| `py/snippet_importer` (optional) | Python | Generate AST hints from native-obfuscator `cppsnippets.properties` |

Schemas: see `schemas/*.schema.json`.

---

## Quick start

### 0. One-time build

```
# JVM modules
cd jvm && ./gradlew installDist

# Python workspace
cd py && uv sync --all-packages

# Native agent
cd native && JDK_HOME="$JAVA_HOME" bash build.sh
```

### 1. End-to-end recovery

```
cd py
.venv/Scripts/python -m j2c_dumper_cli.main recover \
    path/to/obfuscated.jar \
    -o path/to/clean.jar \
    --run-cmd "java -jar path/to/obfuscated.jar"
```

This chains:
1. `parse-jar` → `classes.json`
2. `inspect-binary` (auto-extracts the bundled .dll/.so from the jar)
3. `merge-manifest` → `manifest.json`
4. `dynamic-trace` runs the target with the JVMTI agent; produces `trace.jsonl`
5. `trace-to-bc` lifts to `recovered/*.json`
6. (optional) `static-reverse` if `--ghidra-dump` is provided
7. `rebuild` emits the final, loader-stripped jar

### 2. Stage-by-stage

Each stage has its own subcommand:

```
j2c-dumper parse-jar         in.jar            -o classes.json
j2c-dumper inspect-binary    in.dll            -o binary.json
j2c-dumper merge-manifest    classes.json binary.json -o manifest.json
j2c-dumper dynamic-trace     --run "java -jar in.jar" -o trace.jsonl
j2c-dumper trace-to-bc       trace.jsonl       --manifest manifest.json -o recovered/
j2c-dumper static-reverse    ghidra-dump.json  --manifest manifest.json -o recovered/
j2c-dumper rebuild           --input in.jar --recovered recovered/ --manifest manifest.json -o out.jar
```

### 3. Optional: native-obfuscator snippet importer

```
j2c-dumper static-reverse [...] --hints <(j2c-dumper-snippet-importer path/to/cppsnippets.properties)
```
or pre-generate the hints file once. **Main flow does not depend on this.**

---

## What works today

| Stage | Coverage | Notes |
|---|---|---|
| jar-parser | 100% | Detects loader/nativeDir + flags obfuscated natives |
| binary-introspect | ~70% | Strings/hidden-classes/exports; **no static fn-table** (see deferred-features §1) |
| manifest-merge | 100% | Permissive; missing fn addresses left null |
| JVMTI agent | ~80% | Logs ~40 essential JNI fns; **no vararg decoding** (see deferred-features §3) |
| trace-to-bytecode | ~60% | Strong on GETFIELD/INVOKE patterns when class is in symbol table; struggles when class came via `classloader.loadClass(varargs)` |
| Ghidra static path | architecture 100%, AST coverage ~50% | GhidraScript not yet end-to-end-tested (Ghidra not installed in CI) |
| class-rebuilder | 100% | Replaces obf natives, strips loader + native libs from jar |
| CLI orchestration | 100% | typer subcommands + one-shot recover |

End-to-end e2e: feeding `e2e-test/out/Hello.jar` (a native-obfuscator-transpiled
"Hello world" that prints `sum=5050 / product=3628800 / xor=340984913`)
produces a `recovered.jar` that runs cleanly (no native libs needed) — the
recovered `Hello.main` body is currently empty (`RETURN` only) due to the
trace-to-bytecode vararg decoding limit. Adding vararg decoding in the agent
will lift this constraint.

---

## Directory layout

```
j2c-dumper/
├── README.md                 (this)
├── docs/                     design + deferred features
├── schemas/                  JSON Schema for every artifact
├── jvm/                      Kotlin/ASM modules (Gradle multi-project)
├── py/                       Python modules (uv workspace)
├── native/                   C++ JVMTI agent (cmake or build.sh)
├── ghidra/                   Ghidra headless scripts
├── tests/                    e2e fixtures
└── tools/                    dev scripts
```
