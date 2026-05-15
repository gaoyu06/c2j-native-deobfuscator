# c2j-native-deobfuscator

Reverse-engineer **JNI-native-obfuscated JARs** back into readable Java
bytecode. Targets [`native-obfuscator`](https://github.com/radioegor146/native-obfuscator)
and its derivatives (e.g. j2cc) — anything that transpiles JVM bytecode
to C++ then re-invokes Java through the JNI from a packaged
`.dll` / `.so`.

Two complementary recovery paths:

| Path | Input | Approach |
|---|---|---|
| **Dynamic** | obfuscated jar + a runnable command | Attach a JVMTI agent, observe the JNI call stream, lift it back to JVM bytecode |
| **Static** | obfuscated jar + Ghidra | Locate the JNI method tables in the native blob, decompile each function, lift pseudo-C to JVM bytecode |

Either path emits a clean `out.jar` whose native methods now have
real bytecode bodies and whose loader / native-blob entries are stripped.

License: **GPLv3**.

---

## Quick start

### One-time build

```bash
# JVM modules
cd jvm && ./gradlew installDist

# Python workspace
cd py && uv sync --all-packages

# Native agent (only needed for the dynamic path)
cd native && JDK_HOME="$JAVA_HOME" bash build.sh
```

### Dynamic recovery (preferred when the jar runs in your environment)

```bash
python -m j2c_dumper_cli.main recover \
    path/to/obfuscated.jar \
    -o path/to/clean.jar \
    --run-cmd "java -jar path/to/obfuscated.jar"
```

This chains:

1. `parse-jar`         → `classes.json`
2. `inspect-binary`    (auto-extracts the native blob from the jar)
3. `merge-manifest`    → `manifest.json`
4. `dynamic-trace`     runs the target with the JVMTI agent → `trace.jsonl`
5. `trace-to-bc`       lifts to `recovered/*.json`
6. `rebuild`           emits the loader-stripped output jar

### Static recovery (when you can't run the jar — needs Ghidra)

```bash
# 1. Parse jar + introspect binary as above (no --run-cmd needed)
python -m j2c_dumper_cli.main parse-jar      in.jar      -o classes.json
python -m j2c_dumper_cli.main inspect-binary natives.bin -o binary.json
python -m j2c_dumper_cli.main merge-manifest classes.json binary.json -o manifest.json

# 2. Run Ghidra headless against the native blob
<GHIDRA>/support/analyzeHeadless.bat <project-dir> proj \
    -import natives.bin \
    -scriptPath <repo>/ghidra/scripts \
    -postScript DumpFromManifest.java manifest.json ghidra-dump.json

# 3. Lift the pseudo-C to bytecode + rebuild
python -m ast_matcher.cli ghidra-dump.json --manifest manifest.json -o recovered/
python -m j2c_dumper_cli.main rebuild --input in.jar --recovered recovered/ \
    --manifest manifest.json -o out.jar
```

### Stage-by-stage

Every stage has its own subcommand under `j2c-dumper`; see
`python -m j2c_dumper_cli.main --help` for the full list.

---

## Generality

The project ships with two obfuscator **profiles** that auto-detect:

- `native_obfuscator` — radioegor146/native-obfuscator + compatible derivatives
- `j2cc`              — me.x150.j2cc (single shared `initClass` dispatch)
- `generic`           — fallback when no profile matches; uses pure JNI-spec knowledge only

Custom variants can plug in a new profile without touching the main flow.
See [`docs/adding-obfuscator-profile.md`](docs/adding-obfuscator-profile.md).

The static path's lifter exposes every inference / matching step as a
feature flag (throw-reason hint parsing, ExceptionCheck-guard skipping,
symbol-table tracking, lookup-table resolution, etc.). Disable a flag
when it misbehaves on a specific binary:

```bash
python -m ast_matcher.cli ghidra-dump.json -o recovered/ \
    --disable use_throw_reason_invoke_hints \
    --disable skip_native_exception_guards
python -m ast_matcher.cli --list-flags
```

---

## Repository layout

```
├── jvm/                        Kotlin/ASM modules (Gradle multi-project)
│   ├── jar-parser/             input.jar  → classes.json
│   ├── trace-to-bytecode/      manifest + trace.jsonl → recovered/*.json
│   ├── class-rebuilder/        input.jar + recovered/ → output.jar
│   └── common/                 shared schema types
├── native/                     C++ JVMTI agent (zig c++ build)
├── ghidra/scripts/             Ghidra headless scripts (Java)
├── py/                         Python modules (uv workspace)
│   ├── jar_parser/             —
│   ├── binary_introspect/      .dll / .so / natives.bin  → binary.json
│   │   ├── arch/               per-arch / ABI implementations
│   │   ├── jni_tables.py       RegisterNatives table discovery
│   │   ├── profile.py          obfuscator-variant profiles
│   │   └── stub_recovery.py    synthesize stub bodies for unrecovered methods
│   ├── manifest_merge/         classes.json + binary.json → manifest.json
│   ├── ast_matcher/            pseudo-C → JVM bytecode
│   │   └── lifter/             driver + per-feature submodules
│   ├── j2c_dumper_cli/         top-level CLI orchestrator
│   └── snippet_importer/       (optional) native-obfuscator cppsnippets ingestor
├── docs/                       ARCHITECTURE.md, ROADMAP.md, profile guide, …
├── schemas/                    JSON Schema for every artifact
└── tests/                      e2e fixtures and pipeline tests
```

---

## Documentation

- [ARCHITECTURE.md](docs/ARCHITECTURE.md) — module boundaries, pipeline,
  artifact schemas, extension points
- [ROADMAP.md](docs/ROADMAP.md) — known limitations and planned work
- [adding-obfuscator-profile.md](docs/adding-obfuscator-profile.md) — how
  to register a new obfuscator variant
- [static-reverse-approach.md](docs/static-reverse-approach.md) — design
  notes for the Ghidra-based path

---

## License

Released under **GPL v3**. See [LICENSE](LICENSE).
