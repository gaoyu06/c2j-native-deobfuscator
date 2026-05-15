# Roadmap

Known limitations and planned work. Items here are concrete enough to
file an issue against; speculative ideas live elsewhere.

## Coverage / quality

### Stack-balanced bytecode synthesis

The Ghidra-path lifter emits JVM ops in source order without an
internal operand-stack model. ASM's `COMPUTE_FRAMES` rejects bodies
whose stack effects don't balance; affected methods fall back to a
`/* native body unrecovered at fnAddr */` stub.

A `StackBalancer` similar to the one already used by the dynamic
path (`jvm/trace-to-bytecode/.../StackBalancer.kt`) would close this
gap. Concrete plan:

- Add a Python `StackTracker` to `ast_matcher.lifter.driver` that
  maintains a (depth, type-stack) model after every emit.
- Before emitting INVOKE / IF*-cmp / xRETURN, ensure prerequisites
  are met by inserting POPs or default pushes.
- Drop emit calls that would underflow the stack from any reachable
  path.

### Obfuscator-helper recognition

Helpers like j2cc's cached-`FindClass` / cached-`GetMethodID`
(`FUN_180043520(env, &cls, name_pool, sig_pool, idx)`) currently aren't
modeled, so variables they return reach JNI call sites as opaque
locals. Adding a `helper_fingerprints` table to :class:`Profile` that
encodes argument shapes → return semantics is on the path.

### `<clinit>` string-table decryption

Each obfuscated class has an opaque `<clinit>` that decrypts a
`String[]` table used everywhere via `MyClass.a(int,int)`. Today the
recovered output references these indices verbatim
(`Kg.a(0, 17)` etc.). Decoding the XOR / rotate loop would replace
those with real string literals.

This is best done by running the `<clinit>` once in a sandboxed JVM
after `class-rebuilder` produces the cleaned jar (and snapshotting
the resulting `String[]` field via reflection). A dedicated
`clinit-eval` stage is sketched but not yet shipped.

## Generality / compatibility

### Architectures

Only `amd64-windows` and `amd64-sysv` ABIs ship today. AArch64 +
non-x86 obfuscator outputs require:

- a new `binary_introspect/arch/aarch64*.py` with the AArch64 capstone
  setup, `ADRP`+`ADD` PC-relative decoding, and the AAPCS64 register
  bank;
- adapting `is_indirect_vtable_call` / `decode_pc_relative_lea` /
  `is_stack_store` for the architecture's idioms.

### Other JNI-native obfuscators

Adding a new variant means writing a 30-line profile (see
[adding-obfuscator-profile.md](adding-obfuscator-profile.md)). When a
new variant uses an entirely novel `RegisterNatives` dispatch
strategy (neither per-class nor j2cc-style shared dispatch), the
profile needs a new `harvest_strategy` value and a matching function
in `binary_introspect.jni_tables`.

### `jnic` annotation-based obfuscation

Classes using the `jnic.JNICInclude` / `JNICExclude` annotation
mechanism (separate from j2cc's loader) currently aren't detected as
obfuscated by `jar-parser`. Plan: identify the annotation set and
add a recognition pass that flags annotated methods.

## INVOKEDYNAMIC

`AsmEmitter` supports emitting INVOKEDYNAMIC and the schema carries
the bootstrap-method + bsm-args fields, but the dynamic-path
translator only marks indy chain participants with
`dynamic="indy_chain"` without collapsing them into a single
INVOKEDYNAMIC instruction. Full collapse needs:

- pattern matching the `MethodHandles$Lookup` → `LambdaMetafactory`
  bootstrap chain in the JNI trace;
- reconstructing samMethodType / implMethod / instantiatedMethodType
  from the variadic args.

## Exception-handler recovery

The agent subscribes to JVMTI `Exception` / `ExceptionCatch` events
and forwards them, but in practice they don't fire reliably for
exceptions that the native code's wrappers catch + clear before
returning. Result: `RecoveredMethod.exceptionsObserved` is populated
only for exceptions that escape through ordinary Java call frames;
the per-bci `tryCatchBlocks` table is currently emitted empty.

Two paths forward:

- Hook `JNIEnv->ExceptionOccurred` / `ExceptionCheck` /
  `ExceptionClear` directly so we observe the catch-and-clear pattern
  even when JVMTI events miss.
- Parse exception-handler markers in `<clinit>`-decrypted constant
  tables when available.

## CI / test infrastructure

The static-path coverage tests (`tests/e2e/test_pipeline.sh`) currently
require Ghidra to be installed on the host. Two follow-ups:

- Containerise the headless Ghidra invocation so CI can pull a
  pre-built image.
- Stash a Ghidra-dump JSON fixture in `tests/fixtures/` for at least
  one canonical input, so the ast-matcher half can be tested without
  re-running Ghidra.
