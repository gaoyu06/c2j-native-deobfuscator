**English** | [中文](README.zh-CN.md)

# c2j-native-deobfuscator

Reverse-engineer **JNI-native-obfuscated JARs** back into readable Java
bytecode. Targets [`native-obfuscator`](https://github.com/radioegor146/native-obfuscator)
and its derivatives (e.g. j2cc) — anything that transpiles JVM bytecode
to C++ then re-invokes Java through the JNI from a packaged
`.dll` / `.so`.

Four complementary recovery paths (only **Dynamic** is the default
`recover` flow):

| Path | Input | Approach |
|---|---|---|
| **Dynamic** | obfuscated jar + a runnable command | Load a JVMTI agent at startup, observe the JNI call stream, lift it back to JVM bytecode |
| **Static-lite** | transpiled jar + native blob | Discover JNI method tables, build a manifest, and emit restoration stubs without Ghidra |
| **Static body** | offline manifest + optional Ghidra | After discovery, optionally decompile each function and lift pseudo-C to JVM bytecode |
| **Emulation** | obfuscated blob (no run, no Ghidra) | Run the native code under a CPU emulator + mock JNI; recover the method table, dump decrypted constants, and call methods as pure-function oracles |

Offline discovery is a common, **Ghidra-free** first step:
`parse-jar` reads the JAR declarations, `inspect-binary` inspects JNI entry
points (direct `Java_*` exports and `RegisterNatives` registrations), and
`merge-manifest` combines the evidence. The discovery implementation lives in
[`py/binary_introspect`](py/binary_introspect); see
[`docs/generic-recovery.md`](docs/generic-recovery.md). Ghidra is only a later
option when the JAR cannot run and you want pseudo-C method bodies.

The dynamic path and optional method-body plugins can emit an `out.jar` whose
native-method stubs are replaced with *best-effort recovered bodies*. Coverage
is per method: unobserved or unlifted methods may keep a stub. Static-lite
first produces an auditable method manifest and verifier-safe stubs. Emulation
can add runtime registration data, decrypted constants, and a pure-function
oracle.

License: **GPLv3**.

The [optional observer contract](docs/privileged-observer.md) is off by
default and unsigned by this project. It is not required for JAR recovery; no
kernel image or kernel source is shipped.

Current architecture, every surface, and default-vs-preview status:
**[docs/overview.md](docs/overview.md)**
([中文](docs/overview.zh-CN.md)).

---

## Architecture at a glance

```
  CLI (scripts/j2c)  ·  optional desktop viewer (scripts/gui.sh)
                         │  versioned JSON (schemas/)
          Discovery ─────┼───── Recovery engines ───── Rebuild
   parse-jar / inspect-  │   dynamic JVMTI (default)    class-rebuilder
   binary / merge-       │   attach (preview)           → out.jar
   manifest              │   static-lite (draft-dev)
                         │   emulate / Ghidra body (optional)

  Adjacent, not on the JAR path:
    native-x86/                 user-mode metadata observation
    privileged-observer/        userspace maps; default off
```

| Surface | Role | Default? |
|---|---|---|
| `scripts/j2c recover` | Startup `-agentpath` dynamic recovery | **Yes** |
| `parse-jar` / `inspect-binary` / `merge-manifest` / `static-lite` | Ghidra-free method discovery + stubs | No (draft-dev) |
| `emulate` | Unicorn + mock JNI (table / strings / oracle) | No |
| Ghidra + `static-reverse` | Optional pseudo-C method bodies | No |
| `scripts/j2c attach` | Live same-user JVMTI attach | No (preview) |
| `scripts/gui.sh` | Swing + FlatLaf artifact / attach viewer | No (optional) |
| `native-x86/` | Process-image metadata, plugin ABI 0.2 | No (preview; not on the JAR path) |
| `privileged-observer/` | Userspace `/proc` maps | No (default **off**) |

---

## Run it yourself

You can run the default recovery path by hand — no coding agent required:

```bash
git clone <this repo> && cd c2j-native-deobfuscator
bash scripts/setup.sh                      # build JVM + Python (+ native agent on x86-64)
scripts/j2c doctor                         # check versions + build artifacts
scripts/j2c recover in.jar -o out.jar --run-cmd "java -jar in.jar"
```

> **Run the CLI through `scripts/j2c`** (`scripts\j2c.ps1` on Windows). Setup
> installs the Python workspace into `py/.venv` (via `uv`), so a bare
> `python3 -m j2c_dumper_cli` on the *system* interpreter would not find the
> packages. The launcher picks the interpreter that actually has them.

See [Quick start](#quick-start) below, the
[10-minute getting-started guide](docs/getting-started.md)
([中文](docs/getting-started.zh-CN.md)), and the
[architecture overview](docs/overview.md).

**When the auto-output needs a human pass.** This project is a *universal*
approach for the whole "transpile Java → C/C++ and call back via JNI"
obfuscator family, so hard targets can still need per-method adaptation
(reading a decompile, supplying per-method state, extending a harness, adding a
profile). For those, the recovered `*.json` intermediates are meant to be
hand-edited — see [`docs/manual-restoration.md`](docs/manual-restoration.md).

**Optional:** a coding agent handles that adaptation well. If you use one, load
the bundled skill
([`.claude/skills/j2c-deobfuscate`](.claude/skills/j2c-deobfuscate/SKILL.md))
and hand it the target. This is a convenience, not a requirement — the CLI runs
fine on its own.

---

## How it works

### Dynamic path

- **JVMTI agent** (`native/`, C++). Loaded via `-agentpath:` at startup
  (default), or — as an opt-in preview — attached to an already-running,
  same-user JVM via `Agent_OnAttach` (see
  [`docs/jvm-attach.md`](docs/jvm-attach.md)). At startup it subscribes to
  `NativeMethodBind`, `MethodEntry`, `MethodExit`, `Exception`,
  `ExceptionCatch`; on a live attach it subscribes only to the events whose
  capability the JDK still grants (often just `NativeMethodBind` — e.g. on
  OpenJDK 21).
- **JNI function table swap**. On `VMInit` and every `ThreadStart`, the
  agent overwrites the `JNIEnv->functions` pointer with a copy whose
  ~80 entries are redirected through logging wrappers. Each wrapper
  delegates to the original function and records the call as a JSON
  line in `trace.jsonl`. Variadic `Call*Method` flavours decode their
  `va_list` against a per-class jmethodID descriptor cache.
- **Symbol-table propagation** (`jvm/trace-to-bytecode/`). The lifter
  walks the trace, classifies each jobject reference by what produced
  it (`FindClass` → jclass, `GetMethodID` → jmethodID, etc.), and emits
  the corresponding JVM op with fully resolved owner / name / desc.
- **SSA-style synthetic locals**. Each jobject that the method reuses
  across statements gets a synthetic local slot. The lifter emits
  `DUP + ASTORE <slot>` after the producing JNI call and `ALOAD <slot>`
  at every reuse site, so the recovered bytecode keeps real reference
  identity without re-deriving the value.
- **Operand-stack balancer**. Tracks the live stack and inserts
  `POP` / `CHECKCAST` / `ACONST_NULL` corrections so the emitted
  sequence verifies under ASM `COMPUTE_FRAMES`.

### Offline discovery (no Ghidra)

- **JNI-spec table discovery** (`jar-parser`, `py/binary_introspect/`,
  `manifest-merge`, `capstone`). `parse-jar`, `inspect-binary`, and
  `merge-manifest` build `manifest.json` from JAR declarations and the JNI
  mechanisms defined by the specification: direct `Java_*` exports and
  `RegisterNatives` (vtable index 215, ABI-specific table and length
  arguments). PE/Microsoft x64, ELF/Mach-O System V, AArch64, ARM, and
  i386 ELF are supported. Static `JNINativeMethod[]`, stack-built tables,
  shared call sites, and `Java_*` exports are complementary sources. This
  stage does not require a live JVM or Ghidra.
- **Static-lite orchestration** creates `binary.json`, `manifest.json`,
  and verifier-safe stubs without a decompiler. Registration emulation can
  optionally supply runtime names and descriptors.

### Static body recovery (optional Ghidra step)

- **Optional Ghidra plugin** (`ghidra/scripts/DumpFromManifest.java`,
  Ghidra Headless). Use this later when the JAR cannot run and you want
  static method bodies. It reads the `(class, method, fnAddr)` triples from
  `manifest.json` and runs Ghidra's p-code decompiler on each address,
  yielding a single `ghidra-dump.json` with one pseudo-C body per
  method.
- **tree-sitter-c parse** (`py/ast_matcher/`, `tree-sitter-c`). Parses
  the pseudo-C, then walks the AST with a feature-flagged driver that
  recognises `env->FnName(args)` calls (rewritten from
  Ghidra's `(**(code **)(*reg + 0xN))(...)` form), JNI helper patterns,
  and exception-check guards.
- **Optional throw-reason inference**. Some variants emit
  `"Cannot invoke X.Y.Z(args)"` strings before every would-be Java call
  for use in runtime exception messages. The lifter extracts them as
  invoke hints and uses them as fallback (owner, name, args-desc) when
  symbol tracking can't resolve a jmethodID through obfuscator helpers.
- **Profile auto-detection**. A matching variant's harvest strategy
  (per-class vs shared-dispatch), throw-reason regex, and if-guard
  skip rules all come from a :class:`Profile` selected by scanning the
  binary against built-in detectors. These heuristics are disabled under
  `generic`.

### Emulation path

- **Whole-blob emulation** (`py/native_emulate/`, `unicorn`). Maps the
  native blob (PE or ELF) into a CPU emulator and runs the obfuscated
  functions directly, under a **mock JNI environment** — a fake
  `JNIEnv`/`JavaVM` whose vtable slots trap back into Python. Because it
  *executes* the C, it observes what JNI tracing cannot: inlined
  comparisons (the check that never calls `String.equals`), the decrypted
  `<clinit>` string tables, and logic hidden behind control-flow
  flattening / MBA (the emulator runs the bytes; it doesn't try to
  structure them).
- **`recover`** — emulates the registrar (or reads `Java_*` exports /
  `JNI_OnLoad`) and captures `RegisterNatives` to list every native
  method `(name, sig, fnPtr)`. Fully automatic for native-obfuscator;
  j2cc needs the regc address (from `binary.json`).
- **`strings`** — emulates a method and dumps its decrypted string
  constants (alphabets, secrets, messages) — the string table the other
  two paths leave as indexed accesses.
- **`call`** — oracle: invoke a recovered native method as a pure
  function, feed inputs, capture outputs. Turns "read 10k lines of
  flattened MBA" into input→output probing.
- **JVM-fixed JNI ABI** is the foundation (`GetArrayLength` = vtable
  index 171, `RegisterNatives` = 215, `ExceptionCheck` = 228, …), so the
  same engine generalizes across the family. Backends: x86-64 PE/Win64
  and ELF/System-V. See [`docs/emulation-recovery.md`](docs/emulation-recovery.md).

### Optional desktop viewer

- **Swing + FlatLaf** (`jvm/desktop-ui/`, **JDK 21** only for this
  module). `scripts/gui.sh [session-dir]` opens a session folder and
  shows methods, recovered bodies, pipeline status, binding gaps, and
  a live `trace.jsonl` tail. **Attach / Listen** is a front end to
  `scripts/j2c attach`; it does not invent a second protocol. Recovery
  steps stay in the CLI. See [docs/desktop-gui.md](docs/desktop-gui.md).

### Shared

- **JSON pipeline**. Every stage's input + output is a versioned JSON
  artifact under `schemas/`.
- **ASM** (`org.objectweb.asm`) drives all class-file emission.
  `ClassWriter.COMPUTE_FRAMES` is the verification gate; methods that
  trip stack-imbalance get a sentinel stub body and the jar still ships.

---

## When to use which path

All three target the same input but trade off coverage versus accuracy:

| | Dynamic | Static | Emulation |
|---|---|---|---|
| **Best fit** | The JAR runs and can exercise relevant classes. | Standard JNI exports or `RegisterNatives` are visible in a supported binary. | Logic is rewritten to pure C, registration is runtime-built, or decrypted constants are needed. |
| **Requires** | A runnable command line that exercises the transpiled classes. | JAR + native blob; no Ghidra for method lists/manifests/stubs. Optional Ghidra only for static method bodies. | Native blob + optional `unicorn`; no JVM or Ghidra. |
| **Coverage** | Only branches actually executed. | Methods whose exports/tables satisfy the structural checks; body recovery is separate. | Methods and constants reached by emulation; per-method behaviour through an oracle. |
| **Accuracy** | High for observed JNI calls. | Exact metadata for named tables/exports; ordered-address fallback for stack-built tables. | Executes the real native code, but does not automatically emit bytecode. |
| **Speed** | Target run time + agent overhead. | Fast disassembly and table decoding. | Fast when the relevant entry point is reachable. |

---

## Limitations

- **Static path correctness is best-effort.** The lifter pattern-matches
  Ghidra's pseudo-C; methods with control flow Ghidra didn't structure
  cleanly produce stack-imbalanced bytecode that `class-rebuilder`
  silently downgrades to a stub. The rest of the class still ships.
- **Dynamic path only sees branches the target actually executes.** An
  if/else where only the `if` ran is recovered as if the `else` doesn't
  exist. Loop bodies show one iteration's worth of trace; concrete
  values get baked in as LDC unless flagged dynamic by the agent.
- **Pure-native control flow / arithmetic is invisible to both paths.**
  When the obfuscator translates a computation that doesn't need a JVM
  round-trip (char-array manipulation, integer math) entirely to C++,
  no JNI calls happen, so neither dynamic tracing nor JNI-call-pattern
  matching sees anything. The recovered method body for these regions
  ends up empty or stubbed.
- **AOT-translated logic is unrecoverable.** Higher-end obfuscators
  detect Java code that doesn't require JVM cooperation (e.g.
  symmetric crypto, byte-array transformations, file I/O via
  POSIX/Win32) and emit it as straight native code instead of
  JNI-callback C++. That output has no JNI signature at all — both
  paths produce a stub for such methods. The only way back is reading
  the disassembly by hand.
- **String literals in `<clinit>`-decrypted tables remain
  unresolved.** Each obfuscated class wraps its string constants in an
  XOR/rotate table decoded at class-load time. The lifter preserves
  the indexed accesses (`Foo.a(0, 17)`) verbatim instead of substituting
  values; running the cleaned jar's `<clinit>` once + snapshotting the
  table is on the roadmap (see `docs/ROADMAP.md`).

---

## Screenshots

Auto-generated from the actual snake end-to-end fixture in
`e2e-test/snake/`. Side-by-side syntax-highlighted comparisons of
original source vs Vineflower-decompiled recovery output for both
paths. Full catalogue in [`screenshots/README.md`](screenshots/README.md).

**Static path — Snake.java end-to-end**

![](screenshots/showcase/snake-static-overview.png)

Original snake source vs Vineflower-decompiled static-path output.
Capstone-based cache-table extraction binds every cclasses/cfields/
cmethods slot back to `(owner, name, desc)`, then the lifter
pre-binds JNI `param_2` to JVM local 0 so receivers render as `this`.

**Dynamic path — Snake.java end-to-end**

![](screenshots/showcase/snake-dynamic-overview.png)

Same input via the JVMTI agent: every JNI call the obfuscated native
code makes gets logged and lifted back to JVM bytecode. Bodies match
javac output for the branches actually executed.

**Static-path progression**

![](screenshots/showcase/snake-static-progression.png)

Three stages of the static path on the same input — stub fallback,
tier-2 unverified write, and the final state with cache-table + receiver
binding. Each iteration adds another layer of semantic recovery.

**JVMTI dynamic-path intermediates**

![](screenshots/showcase/dynamic-intermediates.png)

How the dynamic path turns a runtime JNI-call stream into JVM bytecode:
the agent's `trace.jsonl` records, the per-method `recovered/*.json`
lifted bytecode artifact, and the connecting pipeline.

**Two paths, same input: Board.java**

![](screenshots/showcase/board-static-vs-dynamic.png)

The static path is faster and works offline but coverage depends on
per-obfuscator pattern matching. The dynamic path requires running the
target but produces near-pristine bytecode for any code path that
actually executes during the trace.

**Manual restoration · dynamic path**

![](screenshots/showcase/manual-restoration-dynamic.png)

What a 10–15 minute hand pass over the dynamic auto-output looks like:
drop the SSA-slot `Object varN = null;` declarations, inline single-use
temporaries, replace trace-baked constants with the symbolic form, and
restore the branches the trace never executed. Workflow:
[`docs/manual-restoration.md`](docs/manual-restoration.md).

**Manual restoration · static path**

![](screenshots/showcase/manual-restoration-static.png)

Heavier human inference, but the intermediate artifacts keep it
grounded: `recovered/*.json` records the opcode sequence the lifter
extracted, and `manifest.json.cacheTable` resolves every `?.?` to a
real `(owner, name, desc)` triple — even when the decompiler couldn't
render them.

---

## Quick start

Prerequisites: **JDK 17+** (with `JAVA_HOME` set) and **Python 3.11+**. On
Windows, building the native agent also needs **Git Bash** (from Git for
Windows); WSL builds a Linux `.so`, not the Windows `.dll` the JVM loads here.
New here? Follow the [10-minute getting-started guide](docs/getting-started.md)
([中文](docs/getting-started.zh-CN.md)).

### 1. Install (build everything)

```bash
# Idempotent: builds the JVM modules, syncs the Python workspace, and builds
# the native agent when a JDK + zig are present on an x86-64 host. Safe to re-run.
bash scripts/setup.sh            # Linux / macOS
# Windows (PowerShell):
#   pwsh scripts/setup.ps1
```

`scripts/setup.sh` uses [`uv`](https://docs.astral.sh/uv/) for the Python
workspace when available and falls back to `pip install -e` otherwise. The
native agent step needs a JDK and `zig`; it is skipped with a clear message if
either is missing (only the dynamic path needs it). `native/build.sh` targets
x86-64, so on ARM (or any other CPU) setup skips the native agent and does not
report the dynamic path as ready — use the emulation fallback there.

### 2. Check your toolchain

```bash
scripts/j2c doctor       # Windows:  scripts\j2c.ps1 doctor
```

`doctor` reports Java/JDK, Python, the importability of the Python recover
stage (`capstone` + `lief`), the built JVM modules and the host-matching native
agent, plus the optional tools (Ghidra, unicorn, zig), and prints the next
command for anything missing. It verifies tool versions and artifact presence —
it does not launch the JVM modules or load the agent. It exits non-zero only
when a required piece is *missing*; a `WARN` (e.g. `JAVA_HOME` unset) is a
caveat, not a blocker. The agent must match this host in both name and CPU: on a
non-x86-64 host, where `native/build.sh` cannot produce a loadable agent, it is
always reported missing and the dynamic path is not ready.

### 3. Recover (default path — dynamic)

**Use this when the jar can be launched in your environment.** It attaches the
JVMTI agent to a live run, observes the JNI call stream, and lifts it back to
bytecode:

```bash
scripts/j2c recover \
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

The output contains *best-effort recovered bodies for the behavior observed
during the run*. Dynamic tracing only covers executed paths, so unobserved
methods may keep a stub or a partial body; inspect the result and expect manual
completion on hard targets (see the human-pass note above).

> **One interpreter.** `scripts/j2c ...` runs the CLI through the interpreter
> setup installed the packages into (the `uv` venv at `py/.venv`, or the
> `pip`-fallback interpreter), so you never have to pick one. The few things the
> CLI does not wrap — the emulation harness and the lifter's feature flags below
> — run under that same interpreter, written here as `py/.venv/bin/python`
> (`py\.venv\Scripts\python` on Windows). If setup fell back to `pip`, use the
> interpreter it installed into instead.

### Live process attach (preview — opt-in, same-user)

For a JVM you own that is **already running** and can't be restarted, you can
attach the same JVMTI agent to the live process instead of using `-agentpath`:

```bash
scripts/j2c attach --pid <pid> --i-own-this-process -o trace.jsonl
```

This is a **preview** diagnostic path, **not** the default — `recover` still
uses startup `-agentpath` instrumentation, which observes more. Live attach only
sees work after attach, and coverage depends on which JVMTI capabilities the JDK
grants *after* attach. On many JDKs (**observed on OpenJDK 21**) only
native-method-bind is available on a live attach, so the trace holds `bind`
events and method entry/exit, local-variable, and exception events are **not**
captured; the agent's `capability` / `gap` records state exactly what was
obtained. For full method-body recovery use the startup path. Live attach
requires an explicit `--pid` and the `--i-own-this-process` confirmation, and
refuses cross-user targets. Full details: [`docs/jvm-attach.md`](docs/jvm-attach.md).

### Optional desktop viewer

The Swing viewer is **not** required for recovery. After a `recover`
`--workdir` run (or any session folder with the JSON artifacts):

```bash
scripts/gui.sh ./work          # Windows: scripts\gui.ps1 .\work
```

It shows methods, recovered bodies, pipeline status, and can run or
listen to `attach`. The module needs **JDK 21**; the rest of the
repository stays on JDK 17. See [`docs/desktop-gui.md`](docs/desktop-gui.md).

### Offline discovery and static-lite (no live run, no Ghidra)

Start here when the JAR cannot run. These generic discovery stages inspect
standard JNI exports and `RegisterNatives` registration evidence; they do
**not** require Ghidra:

```bash
scripts/j2c parse-jar      in.jar      -o classes.json
scripts/j2c inspect-binary natives.bin -o binary.json
scripts/j2c merge-manifest classes.json binary.json -o manifest.json

# or one command: binary.json + manifest.json + recovered/*.json stubs
scripts/j2c static-lite in.jar --lib natives.bin --profile generic -o static-lite/
```

See [`docs/generic-recovery.md`](docs/generic-recovery.md). `inspect-binary`
prints `format/arch/profile=` and `unreadableTables=` on stderr;
`merge-manifest` prints `bindingGaps=<n> kinds=…`. `bindingGaps` is not
written into `binary.json`. A visible-but-unreadable `JNINativeMethod[]`
becomes an `unreadable-table` gap, not a fabricated binding.

For optional pseudo-C method-body lifting, run Ghidra after static-lite.
`manifest.json` preserves `analysis.profile` from `binary.json`.

### Emulation recovery (no JVM, no Ghidra)

```bash
# add unicorn to the workspace interpreter (`scripts/j2c doctor` prints the
# exact command if setup fell back to pip)
(cd py && uv pip install unicorn)

# list native methods (entry points auto-discovered)
scripts/j2c emulate natives.bin --operation recover --binary-json binary.json

# dump a function's decrypted string constants (alphabet, secret, messages)
scripts/j2c emulate natives.bin --operation strings --fn 0x<addr>

# call a native method as a pure function (oracle)
scripts/j2c emulate natives.bin --operation call --fn 0x<addr> \
    --arg-bytes "input" --static "v=@alphabet.txt"
```

Full walkthrough: [`docs/emulation-recovery.md`](docs/emulation-recovery.md);
command reference + verified matrix: [`py/native_emulate/README.md`](py/native_emulate/README.md).

### Stage-by-stage

Every stage has its own subcommand; see
`scripts/j2c --help` for the full list.

---

## Advanced: static recovery (offline, needs Ghidra)

This is an **optional later step** after the Ghidra-free discovery above. Use
it only when you cannot run the JAR and want pseudo-C for static method bodies
that the emulation fallback does not auto-emit. This step requires
**Ghidra 11.x**:

```bash
# 1. Generic JNI discovery (no --run-cmd and no Ghidra needed)
scripts/j2c parse-jar      in.jar      -o classes.json
scripts/j2c inspect-binary natives.bin -o binary.json
scripts/j2c merge-manifest classes.json binary.json -o manifest.json

# 2. Optional: lift static bodies through Ghidra headless
<GHIDRA>/support/analyzeHeadless.bat <project-dir> proj \
    -import natives.bin \
    -scriptPath <repo>/ghidra/scripts \
    -postScript DumpFromManifest.java manifest.json ghidra-dump.json

# 3. Lift the pseudo-C to bytecode + rebuild
scripts/j2c static-reverse ghidra-dump.json --manifest manifest.json -o recovered/
scripts/j2c rebuild --input in.jar --recovered recovered/ \
    --manifest manifest.json -o out.jar
```

---

## Generality

`generic` is the default fallback and depends on JNI specification facts:

- `RegisterNatives` vtable index 215;
- ABI-specific argument passing for Microsoft x64, System V x86-64,
  AArch64 AAPCS64 (`x2` for the method table, `w3`/`x3` for `nMethods`),
  32-bit ARM AAPCS32 (`r2` for the method table, `r3` for `nMethods`), and
  32-bit x86/i386 System V cdecl (arguments on the stack: `push $nMethods` /
  `push methods`);
- valid `JNINativeMethod` names/descriptors and executable function pointers;
- specification-defined `Java_*` exports;
- optional registration capture through binary emulation.

It does not enable throw-message regexes, decompiler-output rewrites,
cache-table naming assumptions, or exception/cache guard skip patterns.
Matching variant profiles can opt into those features. Ghidra scripts are
optional plugins for method-body lifting and are not part of generic method
discovery.

Generic discovery is proven by committed fixtures across all three x86-64
object formats (ELF, PE, Mach-O) and **two distinct registration families** —
the per-class one-table registrar (a `RegisterNatives` static table or `Java_*`
export names) and a shared `initClass()`-style dispatcher where one call site
registers two classes with different `nMethods` (both stack tables recovered,
not collapsed into one bind). The shared dispatcher is proven from two
directions: the generic `auto` harvest picking it up on an **ELF** with no named
detector (`libjni_dispatch_shared.so`, `analysis.profile` stays `generic`), and
the **named `j2cc` profile detector** firing on a genuine **PE x86-64** image
(`jni_dispatch_j2cc.dll`) whose `shared_dispatch` strategy recovers both
Microsoft x64 tables. Coverage also includes a symbol-stripped ELF, an **AArch64**
ELF (`adrp`/`add` table addressing, JNI dispatch reached through the `x16`
veneer register), a **Mach-O arm64** dylib (`format=MachO`/`arch=aarch64` with a
`_Java_*` export, and the static table decoded through the compact single-`adr`
table addressing when the host Capstone can decode AArch64), a **32-bit ARM**
ELF (`format=ELF`/`arch=arm` with a `Java_*` export, and the static table
decoded through the literal-pool + `add r2, pc, r2` table addressing and the
`ip` veneer register when the host Capstone can decode ARM), a **32-bit
x86/i386** ELF (`format=ELF`/`arch=x86` cdecl with stack arguments and a
GOT-base `lea` table address, a genuine `EM_386` image rather than a renamed
64-bit `.so`), and **section-header-removed ELF** images recovered through a
`PT_LOAD` program-header fallback. See the proven/unproven matrix in
[`docs/generic-recovery.md`](docs/generic-recovery.md). This remains a
development path: it is not promoted to the default `recover` flow, and it does
not claim to restore method bytecode.

Generic recovery is intentionally bounded: unsupported ABIs, nonstandard or
encrypted registration that emulation cannot reach, and custom method-body
layouts still need a profile/backend extension. See
[`docs/generic-recovery.md`](docs/generic-recovery.md) and
[`docs/adding-obfuscator-profile.md`](docs/adding-obfuscator-profile.md).

Optional lifter heuristics remain individually switchable:

The flags are not exposed by `scripts/j2c static-reverse`, so drive the lifter
directly with the workspace interpreter:

```bash
py/.venv/bin/python -m ast_matcher.cli ghidra-dump.json -o recovered/ \
    --disable use_throw_reason_invoke_hints \
    --disable skip_native_exception_guards
py/.venv/bin/python -m ast_matcher.cli --list-flags
```

---

## Preview: `native-x86/` (not on the JAR path)

[`native-x86/`](native-x86/) is an **experimental / preview** user-mode
host plus plugins for process-image metadata. It has **no Java types**
in the public ABI (v0.2). The dynamic, static, and emulation paths do
not depend on it; the directory can be deleted without affecting them.

What it does today:

- Linux: same-user + `--i-own-this-process`; read-only modules/exports,
  or a **single-thread** live pass (ptrace / INT3) that records
  metadata-only entry/return of named exports.
- Windows: read-only module/export snapshot (no live breakpoints).
- Sample plugins name OpenSSL `SSL_*` / `RSA_*` / `AES_*` / `EVP_*`,
  JNI-convention `Java_*`, and Windows CNG `BCrypt*` exports.

What it does **not** do: TLS interception, buffer/key/content capture,
stealth, or any kernel component. See
[`docs/native-x86-module.md`](docs/native-x86-module.md) and
[`docs/plugin-abi.md`](docs/plugin-abi.md).

## Preview: privileged observer (userspace, default off)

[`privileged-observer/`](privileged-observer/) is a separate userspace
plugin host. The shipped Linux backend reads `/proc/<pid>/maps` and
emits module path/address records. Both
`--i-enable-privileged-observer` and `--i-own-this-process` are
required. This repository ships **no kernel image and no kernel
source**. See [`docs/privileged-observer.md`](docs/privileged-observer.md).

---

## Repository layout

```
├── scripts/                    j2c / j2c.ps1, setup, gui.sh / gui.ps1
├── jvm/                        Kotlin/ASM modules (Gradle; JDK 17 except desktop-ui)
│   ├── jar-parser/             input.jar  → classes.json
│   ├── trace-to-bytecode/      manifest + trace.jsonl → recovered/*.json
│   ├── class-rebuilder/        input.jar + recovered/ → output.jar
│   ├── common/                 shared schema types
│   └── desktop-ui/             Swing + FlatLaf viewer (JDK 21)
├── native/                     C++ JVMTI agent (OnLoad + OnAttach; zig c++)
├── native-x86/                 preview user-mode observation host + plugins
│                               (not used by any recovery path)
├── privileged-observer/        userspace maps host; default off; no kernel image
├── ghidra/scripts/             Ghidra headless scripts (Java)
├── py/                         Python modules (uv workspace)
│   ├── binary_introspect/      .dll / .so / natives.bin  → binary.json
│   │   ├── arch/               per-arch / ABI implementations
│   │   ├── jni_tables.py       RegisterNatives table discovery
│   │   ├── profile.py          obfuscator-variant profiles
│   │   └── stub_recovery.py    synthesize stub bodies for unrecovered methods
│   ├── manifest_merge/         classes.json + binary.json → manifest.json
│   ├── ast_matcher/            pseudo-C → JVM bytecode
│   │   └── lifter/             driver + per-feature submodules
│   ├── j2c_dumper_cli/         top-level CLI orchestrator
│   ├── native_emulate/         emulation path: j2c_emu.py (Unicorn + mock JNI)
│   └── snippet_importer/       (optional) native-obfuscator cppsnippets ingestor
├── .claude/skills/             j2c-deobfuscate skill (agent playbook)
├── docs/                       overview, ARCHITECTURE, ROADMAP, …
├── schemas/                    JSON Schema for every artifact
└── tests/                      e2e fixtures and pipeline tests
```

---

## Documentation

- [overview.md](docs/overview.md) — **start here for architecture and every
  feature** ([中文](docs/overview.zh-CN.md))
- [getting-started.md](docs/getting-started.md) — 10-minute default-path
  walkthrough, common failures, where the JSON artifacts land
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) — module boundaries, pipeline,
  artifact schemas, extension points
- [desktop-gui.md](docs/desktop-gui.md) — optional Swing viewer
  ([module README](jvm/desktop-ui/README.md))
- [jvm-attach.md](docs/jvm-attach.md) — opt-in live JVMTI attach (preview)
- [emulation-recovery.md](docs/emulation-recovery.md) — emulation path how-to
  (+ command reference in [`py/native_emulate/README.md`](py/native_emulate/README.md))
- [generic-recovery.md](docs/generic-recovery.md) — Ghidra-free method discovery,
  manifests, stubs, honest gaps, and optional emulation
- [manual-restoration.md](docs/manual-restoration.md) — hand-cleaning recovered output
- [options-and-status.md](docs/options-and-status.md) — decisions, merge status,
  promotion gates
- [ROADMAP.md](docs/ROADMAP.md) — known limitations and planned work
- [adding-obfuscator-profile.md](docs/adding-obfuscator-profile.md) — how
  to register a new obfuscator variant
- [static-reverse-approach.md](docs/static-reverse-approach.md) — design
  notes for the Ghidra-based path
- [native-x86-module.md](docs/native-x86-module.md) — preview user-mode
  observation ([plugin ABI](docs/plugin-abi.md),
  [crypto plugins](docs/plugins/crypto-libraries.md),
  [privileged observer](docs/privileged-observer.md))
- [`.claude/skills/j2c-deobfuscate`](.claude/skills/j2c-deobfuscate/SKILL.md) —
  the agent playbook (load this into your coding agent)

---

## License

Released under **GPL v3**. See [LICENSE](LICENSE).
