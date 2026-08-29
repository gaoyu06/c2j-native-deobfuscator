---
name: j2c-deobfuscate
description: >
  Reverse-engineer a JNI-native-obfuscated JAR (native-obfuscator, j2cc, or any
  tool that transpiles Java methods to C/C++ and calls back through the JNI) back
  toward readable Java. Use when the user wants to deobfuscate / dump / crack /
  understand such a jar or its bundled .dll/.so native blob, recover native
  method bodies, extract decrypted string tables, or trace/emulate the native
  code. Covers all three recovery paths (dynamic JVMTI, static Ghidra, emulation)
  and how to adapt them per-target.
---

# j2c-dumper — deobfuscation playbook

This project recovers JNI-native-obfuscated JARs. It is a **universal approach +
tooling**, not a one-click decompiler: every real target needs some adaptation
(reading a decompile, supplying state, extending a harness). Your job as the
agent is to *drive and adapt* these tools, not just run them.

Repo root: the `j2c-dumper/` directory. Build once before use with
`scripts/setup.sh` (`scripts/setup.ps1` on Windows): `jvm/` via gradle, `py/`
via uv, `native/` via zig (dynamic path only). For the emulation path also run
`(cd py && uv pip install unicorn)`, which puts unicorn in the same workspace
venv (`py/.venv`) setup installed the packages into.

**One interpreter.** Run the CLI through `scripts/j2c ...`; it selects the
interpreter setup installed into. The two things the CLI does not wrap — the
emulation harness and the lifter's feature flags — run under that same
interpreter, written below as `py/.venv/bin/python`
(`py\.venv\Scripts\python.exe` on Windows). A system `python3 -m ...` would not
see the packages. `scripts/j2c doctor` reports which interpreter is in use.

## Pick a path

| Situation | Path | Why |
|---|---|---|
| Jar runs in your env and you can exercise the target classes | **Dynamic** (JVMTI) | Highest-fidelity bytecode for executed branches; immune to native-side packing/anti-debug |
| Jar won't run, but Ghidra can decompile the blob | **Static** (Ghidra) | Covers every registered method offline |
| Logic is rewritten to pure C (compare/crypto/string tables), or jar won't run AND Ghidra can't structure the code, or you need the decrypted constants | **Emulation** (Unicorn) | Executes the hidden C; recovers constants + gives a pure-function oracle; no JVM, no Ghidra |

Often the right move is **combine**: dynamic/static to rebuild the jar shape,
emulation to extract the C-only secrets the others miss.

## Path 1 — Dynamic (JVMTI)

One-shot: `scripts/j2c recover IN.jar -o clean.jar --run-cmd "java -jar IN.jar"`
(chains parse-jar → inspect-binary → merge-manifest → dynamic-trace → trace-to-bc → rebuild).

Adaptation you will likely need:
- **JDK-version match.** Blobs built for JDK 8 crash with `NoSuchMethodError <init>`
  on JDK 9+ (compact-strings `String` layout). Run the trace under the JDK the
  blob was built for. Symptom + fix detailed in memory `dynamic-trace-jdk-match`.
- Feed real input via stdin so the target reaches the code you care about; only
  executed branches are recovered.

Docs: README "Dynamic path", [`docs/manual-restoration.md`](../../docs/manual-restoration.md)
(cleaning the auto-output by hand).

## Path 2 — Static (Ghidra)

```
parse-jar → inspect-binary → merge-manifest → (Ghidra headless DumpFromManifest.java)
→ ast_matcher.cli (pseudo-C → recovered/*.json) → rebuild
```
Ghidra headless invocation and the lifter flags are in README "Static recovery"
and "Generality". Disable a misfiring lifter feature with
`py/.venv/bin/python -m ast_matcher.cli --list-flags` / `--disable <flag>`
(the flags are not exposed by `scripts/j2c static-reverse`).

Adaptation: add an obfuscator **profile** for an unseen variant
([`docs/adding-obfuscator-profile.md`](../../docs/adding-obfuscator-profile.md));
design notes in [`docs/static-reverse-approach.md`](../../docs/static-reverse-approach.md).

## Path 3 — Emulation (Unicorn + mock JNI)

The tool: `py/.venv/bin/python py/native_emulate/j2c_emu.py`. Three commands:
- `recover DLL_OR_SO` — list native methods; entry points auto-discovered
  (`Java_*` exports → `JNI_OnLoad` emulation → `--registrar 0x..` / `--binary-json`).
- `strings DLL --fn 0xADDR` — dump a function's decrypted string constants
  (alphabets, secrets, messages — the `<clinit>` table the other paths can't get).
- `call DLL --fn 0xADDR --arg-bytes "..." | --arg-str "..." [--static v=@file]`
  — oracle: run a method as a pure function.

The loop: **recover → strings → call → reverse**. Full how-to in
[`docs/emulation-recovery.md`](../../docs/emulation-recovery.md); command
reference + verified matrix in [`py/native_emulate/README.md`](../../py/native_emulate/README.md).

Adaptation you will likely need (this is expected, not failure):
- Read the Ghidra decompile of the target `fnPtr` to understand the algorithm.
- Supply state the method depends on: `--static field=value`/`@file` for a static
  field it reads; a warmup run for cached `jmethodID`s (self-contained methods
  like an encoder work standalone; ones using `String.indexOf` etc. need warmup).
- Extend the harness: new arch/ABI = add an `ABI`+`Fmt` pair; a JNI function the
  method calls that isn't modelled = add a case; adjust result-capture if the
  return isn't the last filled buffer.
- The vtable indices are the fixed JNI spec (`GetArrayLength`=171,
  `RegisterNatives`=215, `ExceptionCheck`=228 → must return 0 or `main` bails).
  Background in memory `j2cc-c-rewrite-emulation`.

## Key reference docs
- README / README.zh-CN — overview, all three paths, quick start, when-to-use.
- [`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md) — modules, pipeline, schemas, extension points.
- [`docs/emulation-recovery.md`](../../docs/emulation-recovery.md) — emulation how-to.
- [`py/native_emulate/README.md`](../../py/native_emulate/README.md) — emulation command reference.
- [`docs/manual-restoration.md`](../../docs/manual-restoration.md) — hand-cleaning recovered output.
- [`docs/static-reverse-approach.md`](../../docs/static-reverse-approach.md), [`docs/adding-obfuscator-profile.md`](../../docs/adding-obfuscator-profile.md) — static path internals & extension.
- [`docs/ROADMAP.md`](../../docs/ROADMAP.md) — known limits.

## Mindset
Expect to read decompiled C, supply per-target state, and patch the harness.
The tools get you 80% there mechanically; the last 20% is adaptation that a
coding agent is well-suited to. Don't report success until you've **verified**
(rebuilt jar runs / oracle output matches / recovered password works).
