[English](getting-started.md) | [中文](getting-started.zh-CN.md)

# Getting started (10 minutes)

This is the shortest path from a fresh checkout to a recovered jar, using the
**default (dynamic) path** — no Ghidra and no coding agent required.

The dynamic path works when you can *launch* the obfuscated jar in your
environment. If you can't run it, jump to
[When you can't run the jar](#when-you-cant-run-the-jar).

---

## 0. Prerequisites

- **JDK 17+** with `JAVA_HOME` pointing at it (`java -version` should print 17+).
- **Python 3.11+**.
- For the native agent build only: **[zig](https://ziglang.org/) 0.16.x**.
  Optional; skip it and use the emulation fallback if you can't install it.
- On **Windows**, the native agent build additionally needs **Git Bash** (from
  [Git for Windows](https://git-scm.com/download/win)) so `native/build.sh` can
  run and produce the Windows DLL. WSL is *not* an equivalent: it builds a Linux
  `.so`, not the Windows `.dll` the JVM loads here.

Everything else (`uv`, ASM, `capstone`, `lief`, …) is pulled in by the setup
script. The default recover path imports `capstone`, so it is a required
dependency of `binary-introspect`, not optional.

> **Run the CLI through `scripts/j2c`** (`scripts\j2c.ps1` on Windows). Setup
> installs the Python workspace into `py/.venv` via `uv`, so a bare
> `python3 -m j2c_dumper_cli` on the *system* interpreter would not find the
> packages. The launcher runs the interpreter the packages are actually in (the
> `uv` venv, or the interpreter the `pip` fallback used).

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
3. builds the native JVMTI agent when a JDK **and** `zig` are present **and the
   host is x86-64** — otherwise it prints a clear note and continues (only the
   dynamic path needs it). `native/build.sh` targets x86-64; on ARM (or any
   other CPU) setup skips the native agent and does *not* report the dynamic
   path as ready.

## 2. Check the toolchain — ~10 s

```bash
scripts/j2c doctor       # Windows:  scripts\j2c.ps1 doctor
```

It prints a table and, for anything missing, the exact next command. Example of
a not-yet-ready machine:

```
JVM modules (installDist)   MISSING   not built: jar-parser, ...
Native JVMTI agent          MISSING   no j2c_agent.so under native/build/lib
...
Not ready. Missing: ... Run scripts/setup.sh (or scripts/setup.ps1) to fix.
```

`doctor` checks tool versions and that the build artifacts the default path
needs are present (it does not launch the JVM modules or load the agent). It
exits non-zero only when a required piece is *missing*, so you can gate a script
on it. A `WARN` (for example, Java is new enough but `JAVA_HOME` is unset) is a
caveat, not a failure, and does not flip the ready bit. The optional tools
(Ghidra, unicorn, zig) never block. On this host `doctor` only accepts the agent
name it can actually load (`j2c_agent.so` on Linux, `.dylib` on macOS, `.dll` on
Windows) *and* a file whose header says it was built for this CPU; a leftover
build for another OS, a different architecture, or an unreadable file is
reported as missing. Because `native/build.sh` only targets x86-64, a non-x86-64
host (ARM, for example) always reports the agent as missing — the dynamic path
is unavailable there, whatever sits in `native/build/lib`. Use the emulation
fallback or the static path instead; neither needs the agent.

## 3. Recover — ~1–2 min

```bash
scripts/j2c recover \
    path/to/obfuscated.jar \
    -o path/to/clean.jar \
    --run-cmd "java -jar path/to/obfuscated.jar"
```

The `--run-cmd` is a command that actually *runs* the obfuscated jar so the
JVMTI agent can observe it. Exercise the classes you care about (a CLI that just
prints help won't trace the interesting code paths).

When it finishes you get `path/to/clean.jar` whose native-method stubs are
replaced with *best-effort recovered bodies for the behavior that was observed*,
and whose loader / native-blob entries are stripped. Dynamic tracing only covers
the paths your `--run-cmd` actually executed; unobserved methods may keep a stub
or a partial body, so inspect the output and expect some manual completion on
hard targets.

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
`scripts/setup.ps1`) and then `scripts/j2c doctor`.

**`doctor` says `Java / JDK 17+  WARN` — JAVA_HOME is not set**
Java is new enough but `JAVA_HOME` is unset; the native agent build needs it.
This is a warning, not a blocker: if the agent is already built you can still
run the dynamic path. Set `JAVA_HOME` to your JDK directory and re-run
`scripts/setup.sh` when you next need to build the agent.

**`doctor` says `Native JVMTI agent  MISSING` and setup skipped it**
`zig` (or the JDK headers) wasn't found — or a leftover agent for a different OS
is present. Install [zig](https://ziglang.org/) 0.16.x (or set `ZIG` to its
path), set `JAVA_HOME`, then `bash scripts/setup.sh --force`. If you can't
install `zig`, use the emulation fallback below.

**The Gradle build can't find a matching Java toolchain**
Install a JDK 17+ and set `JAVA_HOME`, then re-run. `doctor` shows which Java it
found.

**`recover` ran but `trace.jsonl` has no `enter` events**
Your `--run-cmd` didn't reach the obfuscated classes. Use a command that
actually exercises them; only executed branches are recovered on the dynamic
path.

---

## When you can't run the jar

Start with the generic, Ghidra-free discovery pipeline. It combines the JAR's
native declarations with standard JNI entry-point evidence: direct `Java_*`
exports and dynamic `RegisterNatives` registrations.

```bash
scripts/j2c parse-jar      in.jar      -o classes.json
scripts/j2c inspect-binary natives.bin -o binary.json
scripts/j2c merge-manifest classes.json binary.json -o manifest.json
```

These three steps do **not** require a live run or Ghidra. They produce the
method-discovery manifest, not recovered method bodies. The generic discovery
implementation lives in
[`py/binary_introspect`](../py/binary_introspect); broader generic-first
coverage is being completed on
[PR #4](https://github.com/gaoyu06/c2j-native-deobfuscator/pull/4).

For executable behavior and C-only constants, use the **emulation fallback**.
It also needs no JVM or Ghidra: it runs the native code under a CPU emulator
with a mock JNI, so it can list the native methods, dump decrypted constants,
and call methods as pure-function oracles.

Install `unicorn` into the interpreter setup used, and run the harness with it
(the launcher only wraps the CLI subcommands):

```bash
(cd py && uv pip install unicorn)    # no uv? `scripts/j2c doctor` prints the exact command
py/.venv/bin/python py/native_emulate/j2c_emu.py recover natives.bin --binary-json binary.json
```

Full walkthrough: [`emulation-recovery.md`](emulation-recovery.md).

Ghidra Headless is an **optional later step** when the JAR cannot run and you
want pseudo-C to lift into static method bodies. See the "Advanced" section of
the [README](../README.md#advanced-static-recovery-offline-needs-ghidra).
