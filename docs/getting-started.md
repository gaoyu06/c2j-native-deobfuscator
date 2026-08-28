[English](getting-started.md) | [中文](getting-started.zh-CN.md)

# Getting started (10 minutes)

This is the shortest path from a fresh checkout to a recovered jar, using the
**default (dynamic) path** — no Ghidra and no coding agent required.

The dynamic path works when you can *launch* the obfuscated jar in your
environment. If you can't run it, jump to
[When you can't run the jar](#when-you-cant-run-the-jar).

---

## 0. Prerequisites

- **JDK 21+** with `JAVA_HOME` pointing at it (`java -version` should print 21+).
- **Python 3.11+**.
- For the native agent build only: **[zig](https://ziglang.org/) 0.16.x**.
  Optional; skip it and use the emulation fallback if you can't install it.

Everything else (`uv`, ASM, capstone, …) is pulled in by the setup script.

---

## 1. Install (build everything) — ~3–5 min

```bash
git clone <this repo> && cd c2j-native-deobfuscator
bash scripts/setup.sh            # Linux / macOS
# Windows (PowerShell):  pwsh scripts/setup.ps1
```

`scripts/setup.sh` is idempotent (safe to re-run). It:

1. builds the JVM modules (`jvm/*/build/install/...`),
2. syncs the Python workspace (`uv sync`, or `pip install -e` as a fallback),
3. builds the native JVMTI agent when a JDK **and** `zig` are present — otherwise
   it prints a clear note and continues (only the dynamic path needs it).

## 2. Check the toolchain — ~10 s

```bash
python -m j2c_dumper_cli doctor
```

It prints a table and, for anything missing, the exact next command. Example of
a not-yet-ready machine:

```
JVM modules (installDist)   MISSING   not built: jar-parser, ...
Native JVMTI agent          MISSING   no j2c_agent.(so|dll|dylib) under native/build/lib
...
Not ready. Missing: ... Run scripts/setup.sh (or scripts/setup.ps1) to fix.
```

`doctor` exits non-zero until the default path is ready, so you can gate a
script on it. The optional tools (Ghidra, unicorn, zig) never block.

## 3. Recover — ~1–2 min

```bash
python -m j2c_dumper_cli recover \
    path/to/obfuscated.jar \
    -o path/to/clean.jar \
    --run-cmd "java -jar path/to/obfuscated.jar"
```

The `--run-cmd` is a command that actually *runs* the obfuscated jar so the
JVMTI agent can observe it. Exercise the classes you care about (a CLI that just
prints help won't trace the interesting code paths).

When it finishes you get `path/to/clean.jar` whose native methods now have real
bytecode bodies and whose loader / native-blob entries are stripped.

---

## Where the JSON artifacts appear

`recover` writes its intermediates to a working directory. By default that is a
fresh temp dir printed on the first line (`workdir: /tmp/j2c-XXXX`). Pass
`--workdir ./work` to choose your own. Inside it:

| File | Produced by | What it is |
|---|---|---|
| `classes.json`   | `parse-jar`      | class skeletons + native-method registry |
| `binary.json`    | `inspect-binary` | string pool + hidden classes from the blob |
| `manifest.json`  | `merge-manifest` | the two merged; includes the `cacheTable` |
| `trace.jsonl`    | `dynamic-trace`  | one JSON line per observed JNI call |
| `recovered/*.json` | `trace-to-bc`  | lifted bytecode, one file per native method |
| your `-o` jar    | `rebuild`        | the final loader-stripped output |

The `recovered/*.json` files are the artifacts you hand-edit if a hard target
needs a human pass — see [`manual-restoration.md`](manual-restoration.md).

---

## Common failures

**`recover cannot start: required build artifacts are missing`**
The JVM modules or native agent aren't built. Run `scripts/setup.sh` (or
`scripts/setup.ps1`) and then `python -m j2c_dumper_cli doctor`.

**`doctor` says `Java / JDK 21+  WARN` — JAVA_HOME is not set**
Java is new enough but `JAVA_HOME` is unset; the native agent build needs it.
Set `JAVA_HOME` to your JDK directory and re-run `scripts/setup.sh`.

**`doctor` says `Native JVMTI agent  MISSING` and setup skipped it**
`zig` (or the JDK headers) wasn't found. Install
[zig](https://ziglang.org/) 0.16.x (or set `ZIG` to its path), set `JAVA_HOME`,
then `bash scripts/setup.sh --force`. If you can't install `zig`, use the
emulation fallback below.

**The Gradle build can't find a matching Java toolchain**
Install a JDK 21+ and set `JAVA_HOME`, then re-run. `doctor` shows which Java it
found.

**`recover` ran but `trace.jsonl` has no `enter` events**
Your `--run-cmd` didn't reach the obfuscated classes. Use a command that
actually exercises them; only executed branches are recovered on the dynamic
path.

---

## When you can't run the jar

Use the **emulation fallback** — no JVM and no Ghidra. It runs the native code
under a CPU emulator with a mock JNI, so it can list the native methods, dump
decrypted constants, and call methods as pure-function oracles:

```bash
pip install unicorn
python py/native_emulate/j2c_emu.py recover natives.bin --binary-json binary.json
```

Full walkthrough: [`emulation-recovery.md`](emulation-recovery.md).

The **static path** (Ghidra) is an *advanced, optional* route for offline
per-method coverage; see the "Advanced" section of the
[README](../README.md#advanced-static-recovery-offline-needs-ghidra).
