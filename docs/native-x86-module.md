# native-x86 module

Status: **experimental / preview**. The code under
[`native-x86/`](../native-x86/) compiles, loads plugins, and — as of the
first observation plugins — can attach to a process the invoking user
owns and report *metadata-only* records about well-known library
exports. It remains outside the JAR-recovery pipeline: nothing in that
pipeline depends on it, and no recovery workflow requires it. The first
plugins and the technique they use are documented in
[plugins/crypto-libraries.md](plugins/crypto-libraries.md).

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

1. loads observation plugins through an experimental, versioned C ABI
   (v0.1; unstable while the major version is 0);
2. gives them a uniform record stream describing loaded modules,
   resolved symbols and call sites;
3. keeps that stream free of any consumer-specific vocabulary.

The motivating gap is in `docs/ROADMAP.md`: **AOT-translated logic is
unrecoverable** by the three existing paths, because code that never
calls back through the JNI produces no trace and no recognisable
pattern. Structural facts about the native image — which module got
loaded at which base, which symbols it exposes, which call sites point
where — are the kind of evidence that helps a human or an agent make
sense of that residue. Collecting them is a systems problem, not a JVM
problem.

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

On cryptographic and JNI library entry points: the observation plugins
([plugins/crypto-libraries.md](plugins/crypto-libraries.md)) *name*
well-known exports (OpenSSL `SSL_*`/`RSA_*`/`AES_*`/`EVP_*`, Windows CNG
`BCrypt*`, and JNI-convention `Java_*`) and observe *when* they are
entered and returned. That observation is deliberately bounded:

- **In scope:** reporting the module, symbol name, address, and the
  control-flow edge (which call site reached which callee, at entry and
  return). This is the map and the timing, not the traffic.
- **Out of scope, permanently:** capturing the bytes those functions
  move. No plaintext, ciphertext, key, IV, argument value or return
  value is read or reported. No event field is defined to carry a
  payload; the one free-text field that exists — a diagnostic note's
  `text` — is host/status text only. Plugins and the host must not place
  keys, buffers or payloads in it, and the host rejects any note whose
  text exceeds a fixed length cap (`NX86_NOTE_TEXT_MAX`, 512 bytes). That
  is a policy plus a length cap, not a structural impossibility.
  Observation never intercepts, rewrites, decrypts or alters what the
  target computes — a breakpoint is inserted, the entry/return is noted,
  and the original code is restored, changing no program logic.

Naming and *observing* an export is in scope; interception, alteration
and content capture are not, at any privilege level.

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
  │   │ ptrace observe│        │  - assigns seq       │ │
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

Properties the host enforces:

- **Same-user, opt-in, and visible.** The host observes a process only
  when the invoking user passes an explicit `--pid` *and* the
  `--i-own-this-process` confirmation, and only when `/proc/PID` is owned
  by the current user. A process owned by another user is rejected before
  any attach is attempted. Attachment is ordinary ptrace: not stealthy,
  and observable by the target.
- **Single-thread only for the live pass (preview).** The live pass places
  process-wide software breakpoints (`INT3`) and steps over them, which is
  only safe when the target has a single thread. Before it attaches or
  places any breakpoint, the host counts the threads in `/proc/PID/task`;
  a target with more than one thread is refused the live pass — no attach,
  no breakpoints — and falls back to the read-only module/symbol pass with
  an honest note. This preview deliberately does not implement a
  thread-group tracer (no `PTRACE_O_TRACECLONE`, no attaching every
  thread); a single-threaded target still gets the full live pass.
- **One process, no privilege escalation.** The host is an ordinary
  executable running with the invoking user's privileges. There is no
  service, no installer, no driver, no kernel component.
- **Plugins are ordinary shared libraries** loaded with the platform
  loader (`dlopen` / `LoadLibrary`) from a path the user passes in.
  Plugin discovery is explicit; the host never scans directories or
  auto-loads anything.
- **The ABI is the only contract.** The host exposes exactly the four
  callbacks in `nx86_host`; plugins expose exactly one entry point.
  Plugins do not see host internals, and the host does not see plugin
  internals.
- **Deterministic lifecycle**: `nx86_plugin_init` → `start` → events →
  `stop` → `shutdown` → library unload. The event bus opens its delivery
  window when the host calls `start` and closes it once `stop` returns,
  so `emit` before `start` or during `shutdown` is rejected with
  `NX86_ERR_LIFECYCLE` and reaches no observer.
- **Records are copies within one process.** Text handed across the ABI
  is borrowed for the duration of one call; anything a receiver keeps, it
  copies. This makes in-process fan-out safe. It does **not** make an
  out-of-process transport a drop-in: the event copy is shallow and
  `nx86_str` holds process-local pointers, so a cross-process path is
  future work that still needs deep copying, serialization, and a wire
  schema (see below).

What the observation source does, staying inside the non-goals above:
enumerate the modules of a process the user is entitled to inspect
(`/proc/PID/maps`), read symbol tables from the module files on disk, and
— on an opt-in live pass — place a debugger-style software breakpoint at
a watched export to note its entry and return. The only target memory it
reads is instruction words (to place and restore breakpoints) and the
return address at the top of the stack (a code address). It never reads
argument registers or buffers, and reconstructing user data from a
target's memory is not part of the record model. The engine and its
exact reads are described in
[plugins/crypto-libraries.md](plugins/crypto-libraries.md).

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
| `call-site` | which address calls which target, how (direct / indirect / thunk), and — when observed live — whether at `enter` or `return` (the `phase` field, ABI 0.2) | argument values, buffer contents, return values |

The distinction in the last column is the safety property that matters:
every record describes **program structure**, and none describes
**program data**. A record stream is a map of the binary, not a
recording of what it processed. That is also what makes the stream
useful to a static lifter, which needs addresses and edges rather than
values.

These record-model choices keep this honest:

- There is no generic "raw bytes" event. Adding one would silently
  convert the format into a data-capture format.
- `call-site` carries addresses and a resolved callee name, not a
  parameter list.
- The one free-text field, a diagnostic note's `text`, is bounded and
  policed rather than structurally safe. The fixed 512-byte cap
  (`NX86_NOTE_TEXT_MAX`) only bounds the field's *length*; it does not make
  it safe by construction. What keeps `text` from becoming a data channel
  is policy, not the cap: it is documented as host/status text only,
  plugins and the host must not place keys, buffers or payloads in it, and
  the host never parses `note.text` as data and rejects any note whose text
  exceeds the cap. A determined plugin can still put up to 512 bytes of
  arbitrary text there — the cap limits *how much*, not *what* — so this is
  a policed bound, not an impossibility.

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

Shipped:

- `include/nativex86/plugin.h` — ABI v0.2 (adds a generic `request_watch`
  callback and a `call-site` `phase`; still no Java/JNI/TLS vocabulary)
- `src/host/` — host: plugin loading (one or more), observer registry,
  event dispatch, a console sink, a synthetic script for the no-target
  case, and a Linux observation engine (`observe_linux.c`) that attaches
  with ptrace and reports module/symbol/call-site records
- `plugins/hello/` — sample plugin
- `plugins/crypto-openssl/`, `plugins/jni-natives/`,
  `plugins/crypto-cng/` — the first observation plugins
  ([plugins/crypto-libraries.md](plugins/crypto-libraries.md))
- `tests/fixtures/` — a name-only fixture library and target process, so
  the observation path is testable without OpenSSL, a JVM, or real
  traffic
- `CMakeLists.txt`, `smoke-test.sh` — build and a Linux compile + run +
  observe check

Not shipped, on purpose: a Windows host observation backend (the CNG
plugin is source-complete but matches nothing without it), a
cross-process transport for the record stream, and anything that would
capture the content a watched function moves.

Open questions that a human should still settle: which additional
platforms are in scope, which transport an out-of-process consumer uses
(see [the bridge sketch](../native-x86/bridge-notes.md)), whether plugins
are trusted or sandboxed, and whether the privileged path in
[privileged-observer.md](privileged-observer.md) is worth its support
burden at all.
