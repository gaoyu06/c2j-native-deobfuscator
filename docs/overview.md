# Architecture and features

[English](overview.md) | [中文](overview.zh-CN.md)

This page is the current map of `c2j-native-deobfuscator`: how the pieces
fit together, what each surface does, and what is **not** a default or
not shipped. It describes the tree on `main` after the #2–#14 wrap-up.
It does not change runtime defaults.

Companion pages: [ARCHITECTURE.md](ARCHITECTURE.md) (module contracts),
[options-and-status.md](options-and-status.md) (decisions and promotion
gates), [getting-started.md](getting-started.md) (10-minute default path).

Terminology is deliberately neutral: JNI-native transpiled JAR recovery,
JVMTI, process inspection, library instrumentation, plugin ABI, and
privileged observer.

---

## What this project is

The core product is a **CLI recovery toolkit** for JARs whose Java
methods were transpiled to C/C++ and re-entered through JNI (the
[`native-obfuscator`](https://github.com/radioegor146/native-obfuscator)
family and derivatives such as j2cc).

`scripts/j2c` is the automation contract. The optional Swing viewer
shows artifacts; it does not replace the CLI. Adjacent user-mode
observation modules sit **outside** the JAR pipeline and can be ignored
or deleted without affecting recovery.

The repository baseline is **JDK 17** and **Python 3.11+**. The desktop
module alone requires **JDK 21**. The native JVMTI agent builds for
**x86-64**.

---

## Layered architecture

```
  ┌──────────────────────────────────────────────────────────────────┐
  │ Surfaces                                                         │
  │   CLI  scripts/j2c  (doctor, recover, attach, stages)            │
  │   Desktop viewer  scripts/gui.sh  (optional, read-mostly)        │
  └───────────────────────────────┬──────────────────────────────────┘
                                  │ versioned JSON under schemas/
  ┌───────────────────────────────┼──────────────────────────────────┐
  │ Discovery                     │  Recovery engines                │
  │   jar-parser → classes.json   │   Dynamic JVMTI  (default)       │
  │   binary-introspect           │   Live attach    (preview)       │
  │     → binary.json             │   Static-lite stubs (draft-dev)  │
  │   manifest-merge              │   Emulation      (optional)      │
  │     → manifest.json           │   Ghidra body    (optional)      │
  └───────────────────────────────┼──────────────────────────────────┘
                                  │ recovered/*.json
                                  ▼
                     class-rebuilder → out.jar

  Adjacent, not on the JAR path (safe to delete):
    native-x86/              user-mode metadata observation, plugin ABI 0.2
    privileged-observer/     userspace /proc maps plugin; default off
```

Every recovery stage reads and writes **versioned JSON**. Nothing
crosses a module boundary except through `schemas/`. The orchestrator
(`py/j2c_dumper_cli`) only chains those stages.

Two adjacent trees produce process-image records, not bytecode:

- [`native-x86/`](../native-x86/) — user-mode host + plugins; no Java
  types in the public ABI.
- [`privileged-observer/`](../privileged-observer/) — optional userspace
  maps backend; **no** kernel image or kernel source.

---

## Recovery pipeline (default and alternatives)

### Default: dynamic `recover`

When the JAR can run, `scripts/j2c recover … --run-cmd "…"` chains:

1. `parse-jar` → `classes.json`
2. `inspect-binary` → `binary.json` (blob extracted from the JAR)
3. `merge-manifest` → `manifest.json`
4. `dynamic-trace` — start the target with `-agentpath` → `trace.jsonl`
5. `trace-to-bc` → `recovered/*.json`
6. `rebuild` → loader-stripped `out.jar`

Coverage is **executed branches only**. Unobserved methods may stay
stubs. This remains the default release path.

### Offline discovery and static-lite (no run, no Ghidra)

`parse-jar` + `inspect-binary` + `merge-manifest` (or one-shot
`static-lite`) build an auditable method manifest and verifier-safe
stubs from JNI-spec facts: `Java_*` exports and `RegisterNatives`
(vtable index 215). This is **draft-dev**, not the default `recover`
flow, and it does not claim restored method bodies.

Honest gaps are first-class: ambiguous count-only tables become
`bindingGaps` of kind `ambiguous-count-only-table`; a visible table
whose name/descriptor bytes are garbage becomes `unreadable-table`
(not silent skip, not fabricated names). Details:
[generic-recovery.md](generic-recovery.md).

### Optional static method bodies (Ghidra)

After discovery, Ghidra Headless can decompile each `fnAddr` to
pseudo-C; `ast_matcher` lifts that to `recovered/*.json`. Ghidra is
**not** required for discovery.

### Optional emulation

`scripts/j2c emulate` / `py/native_emulate` runs the blob under Unicorn
plus a mock JNI: list registrations, dump decrypted constants, call a
method as a pure-function oracle. It does not auto-emit bytecode.

### Live attach (preview)

`scripts/j2c attach --pid <pid> --i-own-this-process` loads the same
agent into an already-running **same-user** JVM. Startup `-agentpath`
still sees more. On many JDKs (observed on OpenJDK 21) attach is
bind-only. There is no stealth or bypass. See
[jvm-attach.md](jvm-attach.md).

---

## Feature catalog

| Surface | What it does | Status | Default for recovery? |
|---|---|---|---|
| `scripts/setup.sh` / `setup.ps1` | Build JVM modules, Python workspace, x86-64 agent | Shipped | Setup only |
| `scripts/j2c doctor` | Versions + artifacts; next command for gaps | Shipped | Check only |
| `scripts/j2c recover` | One-shot dynamic recovery | Shipped | **Yes** |
| Stage CLIs (`parse-jar`, `inspect-binary`, `merge-manifest`, `dynamic-trace`, `trace-to-bc`, `static-reverse`, `rebuild`, `synth-stubs`, `static-lite`, `emulate`) | Isolated JSON stages | Shipped | No (except as `recover` chains them) |
| Generic JNI discovery | PE/ELF/Mach-O; x86-64, AArch64, ARM, i386 ELF; `j2cc` PE detector; shared-dispatch harvest | Draft-dev | **No** |
| Honest binding gaps | `bindingGaps` + `analysis.unreadableTables` | Draft-dev | Reporting only |
| Ghidra `DumpFromManifest` + `ast_matcher` | Optional pseudo-C body lift | Optional plugin | **No** |
| Emulation (`unicorn`) | Registration / strings / oracle | Optional | **No** |
| `scripts/j2c attach` | Opt-in live JVMTI attach | Preview | **No** |
| `scripts/gui.sh` | Swing + FlatLaf artifact / attach viewer | Optional desktop | **No** |
| `native-x86/` | User-mode metadata observation, ABI 0.2 | Preview | **No** (not on the JAR path) |
| `privileged-observer/` | Userspace Linux maps plugin | Preview, default **off** | **No** |
| `.claude/skills/j2c-deobfuscate` | Agent playbook | Optional | Convenience only |

---

## Surfaces in more detail

### CLI

Run everything through `scripts/j2c` (`scripts\j2c.ps1` on Windows) so
the workspace interpreter at `py/.venv` is used. `doctor` never launches
the JVM modules or loads the agent; it only checks versions and
artifacts.

### Desktop viewer

[`jvm/desktop-ui/`](../jvm/desktop-ui/) is a read-mostly Swing + FlatLaf
client. Launch with `scripts/gui.sh [session-dir]`. It lists methods,
recovered bodies, pipeline status, binding gaps, and can tail
`trace.jsonl`. **Attach / Listen** is a front end to the same `attach`
CLI (ownership checkbox, refusal banners, no second protocol). Recovery
steps stay in the CLI. The module uses JDK 21; the rest of the
repository stays on JDK 17. See [desktop-gui.md](desktop-gui.md).

### native-x86 (preview)

User-mode host plus plugins for modules, exports, and — on Linux —
metadata-only entry/return of named exports (`SSL_*` / `RSA_*` /
`AES_*` / `EVP_*`, `Java_*`, Windows CNG `BCrypt*` by name). Windows is
read-only (modules/exports). Live Linux work is single-thread only
(ptrace / INT3). **Metadata only**: no TLS interception, no buffer or
key capture, no stealth, no kernel component. Same-user +
`--i-own-this-process`. See [native-x86-module.md](native-x86-module.md)
and [plugin-abi.md](plugin-abi.md).

### Privileged observer (userspace, default off)

[`privileged-observer/`](../privileged-observer/) loads a versioned
userspace plugin. The shipped Linux backend reads `/proc/<pid>/maps`
and emits module path/address records. Both
`--i-enable-privileged-observer` and `--i-own-this-process` are
required. This repository ships **no kernel image and no kernel
source**. See [privileged-observer.md](privileged-observer.md).

---

## Repository map

```
├── scripts/                    j2c, j2c.ps1, setup, gui.sh / gui.ps1
├── jvm/                        Kotlin/ASM (Gradle; JDK 17 except desktop-ui)
│   ├── jar-parser/             jar → classes.json
│   ├── trace-to-bytecode/      trace.jsonl → recovered/*.json
│   ├── class-rebuilder/        recovered/ → output.jar
│   ├── common/                 shared schema types
│   └── desktop-ui/             Swing + FlatLaf viewer (JDK 21)
├── native/                     C++ JVMTI agent (OnLoad + OnAttach)
├── native-x86/                 user-mode observation host + plugins
├── privileged-observer/        userspace maps host + Linux plugin
├── ghidra/scripts/             optional Headless body dump
├── py/                         uv workspace
│   ├── binary_introspect/      blob → binary.json
│   ├── manifest_merge/         classes + binary → manifest.json
│   ├── ast_matcher/            pseudo-C → bytecode
│   ├── j2c_dumper_cli/         CLI orchestrator
│   └── native_emulate/         Unicorn + mock JNI
├── schemas/                    versioned JSON Schema
└── docs/                       this page and the guides below
```

---

## Decisions that stay frozen

Recorded in [options-and-status.md](options-and-status.md) and
[decisions.md](decisions.md):

| Topic | Choice |
|---|---|
| Meaning of “restored” | Verified coverage plus behavior checks; lesser results stay labeled |
| Partial output | Hybrid runnable JAR when possible; otherwise inspection-only |
| Desktop toolkit | Swing + FlatLaf; no Web UI |
| Attach policy | Same-user + `--i-own-this-process` |
| Crypto observation | Metadata only |
| Privileged observer | Default **no**; userspace preview only |
| Generic discovery | Not the default `recover` path |

---

## What is still not true

- Generic discovery is **not** the default release path.
- Recording an `unreadable-table` gap does **not** decrypt table contents.
- Live attach is **not** equivalent to startup `-agentpath`.
- The GUI does **not** replace the CLI.
- native-x86 is **not** part of JAR recovery and is **not** a product ABI.
- The privileged observer is **not** a kernel feature and is **not** on
  by default.
- There is **no** stealth, TLS content capture, or shipped kernel driver.

---

## Where to go next

| If you want to… | Read |
|---|---|
| Recover a runnable JAR in 10 minutes | [getting-started.md](getting-started.md) |
| Understand stage contracts | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Discover methods without Ghidra | [generic-recovery.md](generic-recovery.md) |
| Attach to a live JVM | [jvm-attach.md](jvm-attach.md) |
| Open the desktop viewer | [desktop-gui.md](desktop-gui.md) |
| Emulate a blob | [emulation-recovery.md](emulation-recovery.md) |
| Hand-edit recovered JSON | [manual-restoration.md](manual-restoration.md) |
| Inspect a process image | [native-x86-module.md](native-x86-module.md) |
| Enable the userspace observer | [privileged-observer.md](privileged-observer.md) |
| See decisions and merge status | [options-and-status.md](options-and-status.md) |
