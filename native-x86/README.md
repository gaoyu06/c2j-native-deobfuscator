# native-x86 (experimental / preview)

A user-mode x86 process-observation module that is **not** part of the
JAR-recovery pipeline. Nothing in `jvm/`, `py/`, `native/` or `ghidra/`
depends on it, and no recovery workflow requires it.

What is here today:

| Path | What it is |
|---|---|
| `include/nativex86/plugin.h` | The versioned C plugin ABI (v0.2). The only contract. |
| `src/host/` | Host: loads plugins, dispatches events, and — given a pid you own — runs the Linux or Windows observation engine. |
| `plugins/hello/` | Sample plugin: emits a hello note, prints what it receives. |
| `plugins/crypto-openssl/` | Observes OpenSSL `SSL_*` / `RSA_*` / `AES_*` / `EVP_*` exports (metadata only). |
| `plugins/jni-natives/` | Observes JNI-convention `Java_*` / `JNI_OnLoad` exports by name/address (no `jni.h`). |
| `plugins/crypto-cng/` | Observes Windows CNG `BCrypt*` exports by name/address through the Windows read-only backend. |
| `tests/abi_checks.c` | Prefix-negotiation, lifecycle-window, phase and watch-request checks. |
| `tests/fixtures/` | Name-only native fixtures, including a committed PE image for export-parser tests that run on any host. |
| `CMakeLists.txt` | Build for the host, plugins, fixtures, and the checks. |
| `smoke-test.sh` | Linux compile + run + observe check (skips when no C compiler). |
| `bridge-notes.md` | Sketch of a future JVM-side adapter. No code, by design. |

What is **not** here, deliberately: any capture of the *content* a
watched function moves (no argument bytes, buffer contents, keys, IVs or
return values), any traffic interception or modification, any stealth,
and any kernel component. The observation engine reads program structure
only — module bases, symbol names and addresses, and control-flow edges.
See [`docs/plugins/crypto-libraries.md`](../docs/plugins/crypto-libraries.md).

## Build + smoke test

```bash
bash native-x86/smoke-test.sh            # cmake if available
bash native-x86/smoke-test.sh --no-cmake # direct cc invocation
```

The smoke test exercises the synthetic script against the sample plugin,
the ABI checks, the platform-neutral PE parser, and a live observation of a tiny fixture process (attaching
with ptrace to confirm metadata-only module / symbol / call-site records).
If ptrace attach is blocked in the environment, it falls back to the
read-only module/symbol pass and says so. Further sections drive the strict
CLI parsing and the deterministic failure seams — attach refusal, detach
failure, live single-step failure, resume (`PTRACE_CONT`) failure, and
breakpoint-arming failure must each fail the run rather than report a false
success — and confirm that a multithreaded target is refused the live pass
and falls back to the read-only pass (single-thread-only preview policy).

The `abi checks` step ([`tests/abi_checks.c`](tests/abi_checks.c))
exercises the contracts a plain run does not: minor-version prefix
negotiation in both directions (a newer peer never writes past an older
peer's object), the event-bus delivery window (nothing is dispatched
outside `start`…`stop`), the `call-site` `phase` field, and watch-request
negotiation.

## Manual runs

```bash
cmake -S native-x86 -B native-x86/build && cmake --build native-x86/build

# Synthetic script (no target), original skeleton behaviour:
./native-x86/build/bin/nx86_host ./native-x86/build/lib/libnx86_plugin_hello.so

# Observe a process you own (explicit pid + confirmation required):
./native-x86/build/bin/nx86_host \
    --pid <PID> --i-own-this-process \
    ./native-x86/build/lib/libnx86_plugin_crypto_openssl.so \
    ./native-x86/build/lib/libnx86_plugin_jni_natives.so
```

```powershell
# Windows is read-only by default; --no-live states the same choice explicitly:
.\native-x86\build\bin\nx86_host.exe `
    --pid <PID> --i-own-this-process --no-live `
    .\native-x86\build\lib\nx86_plugin_crypto_cng.dll
```

## Documentation

- [`docs/native-x86-module.md`](../docs/native-x86-module.md) — purpose,
  non-goals, process model, event types, how a JVM bridge would consume
  events
- [`docs/plugins/crypto-libraries.md`](../docs/plugins/crypto-libraries.md)
  — the observation plugins, the technique, and the metadata-only guarantee
- [`docs/plugin-abi.md`](../docs/plugin-abi.md) — the ABI specification
- [`docs/privileged-observer.md`](../docs/privileged-observer.md) — the
  optional privileged path, and why it stays documentation-only
- [`bridge-notes.md`](bridge-notes.md) — future JVM-side adapter

## Scope guard

Contributions to this module must stay user-mode and observation-only.
Well-known library entry points may be *named* and, on the Linux live
preview, *observed* at entry/return, reporting program structure (module,
symbol, address, control-flow edge). Windows reports module and symbol
records only. Out of scope, permanently: capturing the
content those functions move (arguments, buffers, keys, IVs, return
values), TLS interception or traffic modification, credential capture,
anti-debug or stealth techniques, signature-bypass helpers, hidden
loaders, and any kernel component. Observation must never alter what the
target computes. Windows never places breakpoints; its backend only takes a
module snapshot and parses export metadata from image files on disk.
