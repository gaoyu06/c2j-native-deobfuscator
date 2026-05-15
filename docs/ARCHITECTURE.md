# Architecture

How `c2j-native-deobfuscator` is structured, and where to plug things in.

## Goals

- Turn a JNI-native-obfuscated jar back into a jar with **real JVM
  bytecode** in place of every native stub.
- Stay **obfuscator-agnostic** in the core pipeline; concentrate
  variant-specific knowledge in **profiles** and **architecture
  modules** that can be added without touching the main flow.
- Make every inference / matching heuristic **independently
  toggleable** so users can diagnose mis-recoveries on unusual inputs.
- Each stage is a **standalone CLI** that consumes / produces a
  well-defined JSON artifact; the top-level orchestrator just chains
  them.

## Pipeline

```
                 ┌────────────────────────────┐
   in.jar  ──┬──▶│ jar-parser                 │── classes.json ─────┐
             │   └────────────────────────────┘                     │
             │   ┌────────────────────────────┐                     │
   .dll/.so ─┴──▶│ binary-introspect          │── binary.json ──────┤
                 │  + arch/ + profile/        │                     │
                 │  + jni_tables.py           │                     │
                 └────────────────────────────┘                     │
                                                                    ▼
                                              ┌──────────────────────────┐
                                              │ manifest-merge           │
                                              └──────────────────────────┘
                                                            │
                                                            │ manifest.json
                                ┌───────────────────────────┴───────────────────────────┐
                                │                                                       │
                                ▼ Dynamic path                          Static path     ▼
              ┌────────────────────────────┐                       ┌─────────────────────────────┐
              │ JVMTI agent (native/)      │                       │ Ghidra headless             │
              │  hooks RegisterNatives +   │                       │   ExtractRegisterNatives    │
              │  every key JNI fn          │                       │   DumpFromManifest          │
              └────────────────────────────┘                       └─────────────────────────────┘
                          │                                                            │
                          │ trace.jsonl                                                │ ghidra-dump.json
                          ▼                                                            ▼
              ┌────────────────────────────┐                       ┌─────────────────────────────┐
              │ trace-to-bytecode          │                       │ ast-matcher                 │
              │  (Kotlin/ASM lifter)       │                       │  (Python tree-sitter + lifter)
              └────────────────────────────┘                       └─────────────────────────────┘
                          │                                                            │
                          └──────────────┬──── recovered/*.json ────────────────┬──────┘
                                         ▼                                      ▼
                                ┌──────────────────────────────────────────────────────┐
                                │ class-rebuilder                                      │
                                │  replaces native stubs, strips loader + native blob  │
                                └──────────────────────────────────────────────────────┘
                                                       │
                                                       ▼
                                                    out.jar
```

## Module boundaries

| Module | Lang | In | Out | Role |
|---|---|---|---|---|
| `jvm/jar-parser` | Kotlin + ASM | input.jar | `classes.json` | Walk classes, find loader, flag obfuscated natives |
| `py/binary_introspect` | Python + LIEF + capstone | .dll / .so | `binary.json` | Disassembly-driven discovery of native-method tables |
| `py/manifest_merge` | Python | `classes.json` + `binary.json` | `manifest.json` | Cross-check + bind fn addresses to (class, method, desc) |
| `native/` | C++ + JVMTI | runnable jar | `trace.jsonl` | Hook RegisterNatives + 80+ JNI fns at runtime |
| `jvm/trace-to-bytecode` | Kotlin + ASM | `manifest.json` + `trace.jsonl` | `recovered/*.json` | Translate JNI call sequences back to JVM bytecode |
| `ghidra/scripts/` | Java (Ghidra API) | native blob + manifest | `ghidra-dump.json` | Decompile each fn-addr to pseudo-C |
| `py/ast_matcher` | Python + tree-sitter | `ghidra-dump.json` + manifest | `recovered/*.json` | Lift pseudo-C to JVM bytecode |
| `jvm/class-rebuilder` | Kotlin + ASM | input.jar + recovered + manifest | output jar | Replace stubs, strip loader |
| `py/j2c_dumper_cli` | Python + typer | — | — | Top-level orchestrator |

Schemas: `schemas/*.schema.json`.

## Extension points

### Obfuscator profile

`py/binary_introspect/binary_introspect/profile.py` defines
:class:`Profile`. A profile captures:

- `harvest_strategy` (`per_class` / `shared_dispatch`)
- `invoke_error_re` (regex matching the throw-reason format used by
  the obfuscator to label "would-be Java call" sites)
- `skip_if_patterns` (pairs of `(cond_re, body_re)` recognised as
  native-side bookkeeping that the lifter drops)
- `register_natives_index` (defaults to JNI spec value)
- `detector` (callable returning a 0–1 match score)

Built-ins: `generic`, `native_obfuscator`, `j2cc`. See
[adding-obfuscator-profile.md](adding-obfuscator-profile.md) to add
your own.

### Arch / ABI

`py/binary_introspect/binary_introspect/arch/` is a per-architecture
package. Each module registers an :class:`Abi` with:

- pointer size
- capstone arch + mode
- register set holding `nMethods` for the calling convention
- methods to recognise indirect-vtable calls + PC-relative LEAs +
  stack stores

Built-ins: `amd64-windows`, `amd64-sysv`.

### Lifter feature flags

`py/ast_matcher/ast_matcher/lifter/options.py` defines :class:`LifterOptions`.
Every inference / matching step has its own boolean:

- `use_throw_reason_invoke_hints` — parse "Cannot invoke X.Y.Z(args)"
- `track_symbol_table` — propagate jclass / jmethodID / jstring bindings
- `resolve_string_pool_offsets` — bind `string_pool + N` references
- `resolve_lookup_tables` — bind `cstrings[K]` / `cmethods[K]` etc.
- `skip_native_exception_guards` — drop `if (ExceptionCheck()) return`
- `drop_dangling_jumps` — remove jumps to undefined labels
- `suppress_synthetic_fallthrough_return` — drop trailing `return (T)0;`
- `force_init_void_return` — `<init>` is always `()V`

CLI: `--enable <flag>` / `--disable <flag>` (repeatable),
`--list-flags`.

## Artifact schemas

JSON Schema documents under `schemas/`:

- `classes.schema.json`    — `jar-parser` output
- `binary.schema.json`     — `binary-introspect` output
- `manifest.schema.json`   — `manifest-merge` output
- `trace.schema.json`      — JVMTI agent line format
- `recovered.schema.json`  — per-method recovered bytecode

Each schema is versioned (`schemaVersion: int`).

## Design principles

1. **Stage isolation.** Every stage reads + writes only JSON; nothing
   crosses module boundaries except via the schemas.
2. **Profile registration over hard-coding.** All obfuscator-variant
   knobs live in :class:`Profile`; the core pipeline never branches on
   "is this j2cc / is this native-obfuscator".
3. **Feature-flag every heuristic.** Each step in the lifter and
   class-rebuilder is independently toggleable.
4. **Fail soft.** When a single method's recovery is malformed (e.g.
   stack-imbalanced), the class-rebuilder falls back to a stub for
   that method only; the rest of the jar still ships.

## Runtime requirements

| Component | Minimum |
|---|---|
| JDK (for build + runtime) | 21 |
| Python | 3.11 |
| `lief` | any 0.14+ |
| `capstone` | 5.x |
| `tree-sitter-c` | any 0.21+ |
| Ghidra (static path only) | 11.x |
| zig (native agent build) | 0.16+ |
