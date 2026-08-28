# native-x86 module

Status: **experimental skeleton**. The code under
[`native-x86/`](../native-x86/) compiles and loads a plugin; it does not
observe anything yet. Nothing in the JAR-recovery pipeline depends on
it, and no recovery workflow requires it.

This document defines the boundary: what the module is for, what it will
never do, how it is structured as a process, what it reports, and how a
JVM-side consumer would use those reports without the module knowing
that Java exists.

---

## Why a separate module

The repository already contains native code: `native/` is a C++ JVMTI
agent. It is *inside* the JVM, speaks `JNIEnv`, and exists purely to
serve JNI-native deobfuscation. Everything it does is Java-shaped.

The x86 tooling this document describes is the opposite: it is about a
process image — modules, symbols, call sites — and has no Java concepts
at all. Mixing the two would be a mistake in both directions:

- The JVM/JNI recovery paths would inherit a dependency on
  platform-specific process inspection they do not need. Today
  `recover` works with three code paths, none of which needs to touch a
  foreign process; that property is worth keeping.
- The x86 tooling would inherit JNI vocabulary it cannot honour. A call
  site is a call site whether the callee is `Java_Foo_bar` or
  `memcpy`; encoding "native method" into the record format bakes in an
  assumption that only holds for one consumer.

So the split is: **`native-x86/` produces generic records about an x86
process image; anything that wants Java meaning derives it on its own
side of a documented boundary.**

---

## Purpose

For authorized diagnostics on software the user owns or is otherwise
permitted to analyze, provide a small, reviewable, user-mode host that:

1. loads observation plugins through a stable, versioned C ABI;
2. gives them a uniform record stream describing loaded modules,
   resolved symbols and call sites;
3. keeps that stream free of any consumer-specific vocabulary.

The motivating gap is in `docs/ROADMAP.md`: **AOT-translated logic is
unrecoverable** by the three existing paths, because code that never
calls back through the JNI produces no trace and no recognisable
pattern. Structural facts about the native image — which module got
loaded at which base, which symbols it exposes, which call sites point
where — are the kind of evidence that helps a human or an agent attack
that residue. Collecting them is a systems problem, not a JVM problem.

## Non-goals

These are boundaries, not a backlog.

- **Not a requirement for JAR recovery.** The dynamic, static and
  emulation paths must continue to work with this directory deleted.
- **No traffic interception or modification.** No TLS interception, no
  man-in-the-middle, no rewriting of data in flight.
- **No credential or secret capture.** Records describe program
  structure (addresses, names, sizes), not buffer contents.
- **No stealth.** No anti-debug evasion, no hiding from the target, no
  hidden loaders, no injection tricks meant to be unnoticeable. A
  target that looks for the module should find it.
- **No signature or protection bypass.** Nothing here exists to defeat
  licensing, integrity checks or code signing.
- **No kernel component in this tree.** See
  [privileged-observer.md](privileged-observer.md): the privileged path
  is documentation only, and no signed driver is provided.
- **No Java coupling.** No JNI header, no Gradle module, no
  `jni.h` include, ever, under `native-x86/`. See
  [`native-x86/bridge-notes.md`](../native-x86/bridge-notes.md).

On cryptographic library entry points: a future observer may find it
useful to *name* well-known functions (OpenSSL's EVP interface, Windows
CNG, AES primitives) as points of interest in a symbol map. Naming an
API in a design note is in scope. Implementing hooks on it is not, and
no hooking code belongs in this module.

---

## Process model

The module is a **plain user-mode process**. It runs with whatever
privileges the invoking user already has, and it does not ask for more.

```
  ┌─────────────────────────────────────────────────────┐
  │ nx86_host (user-mode process)                       │
  │                                                     │
  │   ┌───────────────┐        ┌──────────────────────┐ │
  │   │ record sources│ ──────▶│ event bus            │ │
  │   │ (none today)  │        │  - assigns seq       │ │
  │   └───────────────┘        │  - stamps timestamps │ │
  │                            │  - fans out by kind  │ │
  │                            └──────────┬───────────┘ │
  │                                       │             │
  │        plugin ABI (C, versioned) ─────┼──────────┐  │
  │                                       ▼          ▼  │
  │                              ┌────────────┐ ┌──────┐│
  │                              │ plugin A   │ │ sink ││
  │                              └────────────┘ └──────┘│
  └─────────────────────────────────────────────────────┘
                   │ records (out-of-process transport)
                   ▼
        consumers: JVM bridge, analysis scripts, humans
```

Properties that the skeleton already enforces:

- **One process, no privilege escalation.** The host is an ordinary
  executable. There is no service, no installer, no driver.
- **Plugins are ordinary shared libraries** loaded with the platform
  loader (`dlopen` / `LoadLibrary`) from a path the user passes in.
  Plugin discovery is explicit; the host never scans directories or
  auto-loads anything.
- **The ABI is the only contract.** The host exposes exactly the four
  callbacks in `nx86_host`; plugins expose exactly one entry point.
  Plugins do not see host internals, and the host does not see plugin
  internals.
- **Deterministic lifecycle**: `nx86_plugin_init` → `start` → events →
  `stop` → `shutdown` → library unload. The host stops delivering
  events before `stop` returns.
- **Records are copies.** Text handed across the ABI is borrowed for
  the duration of one call; anything a receiver keeps, it copies. This
  is what makes an out-of-process transport a drop-in later.

What a future observation source would and would not be allowed to do,
staying inside the non-goals above: enumerate the modules of a process
the user is entitled to inspect, read symbol tables from files on disk,
and decode instructions from an image. Reconstructing user data from a
target's memory is not part of the record model.

---

## Event types

Full field-by-field definition lives in [plugin-abi.md](plugin-abi.md).
Summarised by intent:

| Kind | Answers | Deliberately absent |
|---|---|---|
| `note` | "a component wants to say something" (diagnostics, plugin hello) | — |
| `module-load` | which image, at which base, how large, which machine | image contents |
| `module-unload` | which base stopped being valid | — |
| `symbol` | which name maps to which address in which module | anything about what the symbol computes |
| `call-site` | which address calls which target, and how (direct / indirect / thunk) | argument values, buffer contents, return values |

The distinction in the last column is the safety property that matters:
every record describes **program structure**, and none describes
**program data**. A record stream is a map of the binary, not a
recording of what it processed. That is also what makes the stream
useful to a static lifter, which needs addresses and edges rather than
values.

Two ABI-level choices keep this honest:

- There is no generic "raw bytes" event. Adding one would silently
  convert the format into a data-capture format.
- `call-site` carries addresses and a resolved callee name, not a
  parameter list.

---

## How a JVM bridge would consume events

The module must not know Java exists. The projection therefore lives
entirely on the consumer side, and it is a pure function of the generic
record stream.

Worked example, using artifacts this repository already has:

1. **Transport.** The consumer reads records out of process — the
   natural fit is a JSON-lines file in the same spirit as the dynamic
   path's `trace.jsonl` (`schemas/trace-event.schema.json`). The C
   module writes records; the bridge reads them. No JVM ever loads the
   host, and no `jni.h` appears in `native-x86/`.

2. **Rebasing.** `py/binary_introspect` reports *file* offsets in
   `binary.json`. A `module-load` record for the same blob supplies the
   observed base address, so the bridge can rebase those offsets onto
   runtime addresses. The x86 module supplied a base address; it never
   learned that the blob was a native-obfuscator payload.

3. **Naming.** The JNI export convention
   (`Java_<mangled-class>_<mangled-method>`) is a *string pattern*. The
   bridge applies that pattern to `symbol` records to nominate native
   method entry points, then cross-checks them against
   `manifest.json`. The C module reported a name and an address; the
   Java-shaped interpretation is entirely the bridge's.

4. **Structure.** `call-site` records that fall inside a method's
   address range become hints for the static lifter: this site targets
   that callee. `docs/static-reverse-approach.md` already treats such
   inputs as advisory, alongside throw-reason strings — bridge output
   joins that category and is allowed to be absent or wrong.

5. **Output.** The bridge emits an existing artifact shape (a
   `binary.json` supplement or a manifest overlay) validated against
   `schemas/`, so no downstream stage changes.

The test for whether the boundary is intact: **you can delete every
consumer and the C module still makes sense**, and **you can delete the
C module and every recovery path still runs**. Both directions hold
today, and any change to this module should keep them holding.

---

## Current state and what review must settle

Shipped in this skeleton:

- `include/nativex86/plugin.h` — ABI v0.1
- `src/host/` — host stub: plugin loading, observer registry, event
  dispatch, a console sink, and a hard-coded script of synthetic
  records
- `plugins/hello/` — sample plugin
- `CMakeLists.txt`, `smoke-test.sh` — build and a Linux compile+run
  check

Not shipped, on purpose: any observation source. The synthetic records
in `src/host/main.c` are literals.

Open questions that a human should answer before observation code is
written: which platforms are in scope first, which transport the record
stream uses, whether plugins are trusted or sandboxed, and whether the
privileged path in [privileged-observer.md](privileged-observer.md) is
worth its support burden at all.
