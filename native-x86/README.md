# native-x86 (experimental skeleton)

A user-mode x86 process-inspection module that is **not** part of the
JAR-recovery pipeline. Nothing in `jvm/`, `py/`, `native/` or `ghidra/`
depends on it, and no recovery workflow requires it.

What is here today:

| Path | What it is |
|---|---|
| `include/nativex86/plugin.h` | The versioned C plugin ABI (v0.1). The only contract. |
| `src/host/` | Host stub: loads one plugin, replays synthetic records, shuts it down. |
| `plugins/hello/` | Sample plugin: emits a hello note, prints what it receives. |
| `CMakeLists.txt` | Build for the host stub and the sample plugin. |
| `smoke-test.sh` | Linux compile + run check (skips when no C compiler). |
| `bridge-notes.md` | Sketch of a future JVM-side adapter. No code, by design. |

What is **not** here, deliberately: any instrumentation. The host stub
does not attach to a process, read another process's memory, patch code
or hook anything. Its "events" are literals compiled into
`src/host/main.c`. This is a boundary and a compilable skeleton so the
ABI can be reviewed before any observation code is written.

## Build + smoke test

```bash
bash native-x86/smoke-test.sh            # cmake if available
bash native-x86/smoke-test.sh --no-cmake # direct cc invocation
```

Expected tail:

```
plugin.hello: stop after 3 events
host: published=4 delivered=7 sink_seen=4
host: shutdown ok
PASS: skeleton builds, loads the sample plugin and dispatches events.
```

Manual run:

```bash
cmake -S native-x86 -B native-x86/build && cmake --build native-x86/build
./native-x86/build/bin/nx86_host ./native-x86/build/lib/libnx86_plugin_hello.so
```

## Documentation

- [`docs/native-x86-module.md`](../docs/native-x86-module.md) — purpose,
  non-goals, process model, event types, how a JVM bridge would consume
  events
- [`docs/plugin-abi.md`](../docs/plugin-abi.md) — the ABI specification
- [`docs/privileged-observer.md`](../docs/privileged-observer.md) — the
  optional privileged path, and why it stays documentation-only
- [`bridge-notes.md`](bridge-notes.md) — future JVM-side adapter

## Scope guard

Contributions to this module must stay user-mode and observation-only.
Out of scope: TLS interception, traffic modification, credential
capture, anti-debug or stealth techniques, signature-bypass helpers, and
hidden loaders. Well-known cryptographic library entry points
(e.g. OpenSSL, CNG, AES primitives) may be *named* in design notes as
future points of interest; no hooking implementation belongs here.
