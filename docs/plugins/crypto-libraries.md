# Observation plugins for well-known library exports

Status: **preview**. These are the first observation plugins for the
experimental [`native-x86/`](../../native-x86/) module. They let the
user-mode host resolve well-known library exports in a process the user
owns. The Linux preview can also report entry/return metadata; Windows is
read-only and reports module/symbol records only. This is a diagnostics
preview, **not** a traffic tool.

> Content capture is out of scope. These plugins observe *that* a
> well-known entry was reached and *where* it lives — module, symbol
> name, address, and the control-flow edge. They never read, request or
> report the bytes those functions move: no plaintext, no ciphertext, no
> key, no IV, no argument value, and no return value. No event field is
> defined to carry a payload; the one free-text field — a diagnostic
> note's `text` — is host/status text only, and the host enforces that
> with a fixed 512-byte length cap (`NX86_NOTE_TEXT_MAX`) rather than
> relying on it being impossible by construction (see
> [`plugin-abi.md`](../plugin-abi.md), "What events may not carry").

---

## What is observed

Each plugin declares interest in a set of **export names** through the
host's `request_watch` callback (ABI 0.2). The host — which knows nothing
about TLS, RSA, CNG or Java — resolves those names against the modules
loaded in the target and reports generic records:

- `module-load` — which file-backed image is loaded, at which base;
- `symbol` — a watched export's name and absolute address in a module;
- `call-site` — on the Linux live preview, an entry (`phase = enter`) or return
  (`phase = return`) at a watched export, carrying the callee name, the
  callee address, the caller-side return address (a code address), and
  the module. Nothing else.

The plugins then apply their own library-specific *labels* to those
generic records. The meaning ("this is a TLS boundary", "this is a JNI
native entry") lives entirely on the plugin side of the ABI; the host and
the record format stay free of that vocabulary.

### `crypto-openssl` — OpenSSL / libssl / libcrypto

| Watched name | Match | Reports | Label |
|---|---|---|---|
| `SSL_read`, `SSL_write` | exact | symbol + entry/return | TLS record I/O boundary |
| `SSL_connect`, `SSL_accept`, `SSL_do_handshake` | exact | symbol + entry/return | TLS session boundary |
| `RSA_*` | prefix | symbol | RSA primitive |
| `AES_*` | prefix | symbol | AES primitive |
| `EVP_*` | prefix | symbol | EVP cipher/digest boundary |

The `SSL_*` session boundaries are watched for live entry/return so you
can see *when* a TLS I/O or handshake boundary is crossed (never the
data crossing it). The `RSA_*` / `AES_*` / `EVP_*` families are reported
as symbols — where those primitives live in the loaded image — which is
the map a static analyst wants without a breakpoint on every variant.

### `crypto-cng` — Windows CNG (`bcrypt.dll`)

| Watched name | Match | Reports | Label |
|---|---|---|---|
| `BCryptEncrypt` | exact | symbol | CNG symmetric encrypt boundary |
| `BCryptDecrypt` | exact | symbol | CNG symmetric decrypt boundary |
| `BCryptSignHash` | exact | symbol | CNG signature boundary |

The plugin source is portable and builds on any platform. On Windows, the
read-only host enumerates loaded modules and resolves these names from each
module's on-disk PE export table. Windows live entry/return observation is
not shipped. See [Platforms](#platforms) below.

### `jni-natives` — JNI-transpiled native entries

Some obfuscators move Java method bodies into native code exported under
the JNI naming convention and reached through a registration call. This
plugin observes those entries **by symbol name and address only**.

| Watched name | Match | Reports | Label |
|---|---|---|---|
| `Java_*` | prefix | symbol + entry/return | JNI-convention native entry |
| `JNI_OnLoad` | exact | symbol + entry/return | JNI library load callback |
| `RegisterNatives` | exact | symbol | native registration entry |

Crucially, the `jni-natives` plugin contains **no `jni.h`, no `JNIEnv`,
no `jobject`, and no Java type of any kind**. `Java_` and
`RegisterNatives` are ordinary exported-symbol name strings to it, and to
the host. The x86 side never gains a Java dependency; any Java meaning is
inferred on this side of the boundary, from the string. `RegisterNatives`
is typically reached through the JNI function table rather than exported,
so it usually will not resolve as a symbol; it is watched by name for the
runtimes where it is present.

---

## How to run it (Linux)

```bash
cmake -S native-x86 -B native-x86/build && cmake --build native-x86/build

# Observe a process you own. --i-own-this-process is required: you are
# asserting you own the pid and are authorized to inspect it.
./native-x86/build/bin/nx86_host \
    --pid <PID> --i-own-this-process \
    --max-events 32 --max-seconds 20 \
    ./native-x86/build/lib/libnx86_plugin_crypto_openssl.so \
    ./native-x86/build/lib/libnx86_plugin_jni_natives.so
```

CLI options that gate and bound the run:

- `--pid N` — the process to observe. The host refuses to attach unless
  `/proc/N` is owned by the current user; a process owned by another user
  is rejected before any attach is attempted.
- `--i-own-this-process` — **required** to attach to a live process. Its
  only purpose is an explicit, visible confirmation of authorization.
- `--no-live` — run the read-only module/symbol pass only: parse
  `/proc/PID/maps` and read symbol tables from disk, with no ptrace and
  no breakpoints.
- `--max-events K` (default 16), `--max-seconds T` (default 20) — bound
  the live pass, then detach cleanly.

With no `--pid`, the host replays a fixed synthetic script instead — the
original skeleton behaviour, useful for exercising the ABI without a
target.

### Windows read-only preview

```powershell
cmake -S native-x86 -B native-x86/build
cmake --build native-x86/build --config Release

.\native-x86\build\bin\Release\nx86_host.exe `
    --pid <PID> --i-own-this-process --no-live `
    .\native-x86\build\lib\Release\nx86_plugin_crypto_cng.dll
```

`--no-live` is optional on Windows because read-only is the default and only
available mode. With or without it, the host says that live observation is
unavailable, verifies that the target token has the same user SID as the
host, takes a Toolhelp module snapshot, and reads named exports from the
module files on disk. It does not start a debug session, set breakpoints,
read process memory, or inspect registers.

---

## The techniques, stated plainly

The Linux engine
([`native-x86/src/host/observe_linux.c`](../../native-x86/src/host/observe_linux.c))
uses documented user-mode facilities:

1. **Read-only pass.** Parse `/proc/PID/maps` for file-backed modules and
   read each module's ELF symbol table *from disk*. This resolves watched
   exports to addresses and needs no ptrace. It reads nothing from the
   target's memory.

2. **Live pass (x86-64, opt-in).** Attach with `ptrace(PTRACE_ATTACH)`,
   place a one-byte software breakpoint (`INT3`) at a watched export's
   entry — the same mechanism a debugger uses — catch the entry, read the
   **return address** off the top of the stack (a code address, and the
   only stack read the engine performs), report a `call-site` `enter`,
   arm a one-shot breakpoint at that return address to report a
   `call-site` `return`, then restore the original byte and let execution
   continue. Every breakpoint is removed before detaching, leaving the
   target's code byte-for-byte as it was.

The engine reads instruction words (to place and restore breakpoints) and
the stack return address (a code address). It never reads the argument
registers (`rdi`, `rsi`, …) or any buffer, and it never modifies program
logic or control flow: a breakpoint is inserted, observed, and removed.
If a technique is unavailable — attach refused, wrong architecture, or a
multithreaded target (see below) — the host says so honestly and falls
back to the read-only pass rather than pretending the target was empty.

**Single-thread only for the live pass (preview).** A process-wide `INT3`
is only safe to place and step when no other thread can run the patched
entry while the engine restores the original byte and single-steps over
it. This preview does **not** implement a thread-group tracer (no
`PTRACE_O_TRACECLONE`, no attaching every thread). Instead, before it
attaches or places any breakpoint the host counts the threads in
`/proc/PID/task`; if the target has more than one thread it refuses the
live pass outright — no attach, no breakpoints — and runs the read-only
module/symbol pass with an honest note that live observation is
single-thread only. A single-threaded target still gets the full live
entry/return pass.

The Windows engine
([`native-x86/src/host/observe_windows.c`](../../native-x86/src/host/observe_windows.c))
is a separate, strictly read-only path:

1. Compare the target process token's user SID with the host's and refuse
   inspection unless they match.
2. Enumerate the target's current modules with a Toolhelp module snapshot.
3. Open each listed image file read-only and parse its PE named-export table.
4. Emit module records and watched symbol names, ordinals, and absolute
   addresses (`module base + export RVA`).

There is no Windows live pass. The backend does not start a debug session,
place or remove breakpoints, read target memory, or inspect arguments,
returns, registers, or buffers.

### What this is not

- **Not TLS interception or modification.** Nothing decrypts, rewrites,
  proxies or man-in-the-middles traffic. The plugins observe control-flow
  boundaries, not the data at them.
- **Not credential or key capture.** No argument, buffer, key, IV or
  return value is read or reported.
- **Not stealthy.** Inspection is explicit, same-user, and visible in the
  host invocation.
- **No kernel component.** Everything here is an ordinary user-mode
  process using ptrace with the privileges the invoking user already has.

---

## Platforms

| Platform | Read-only pass | Live entry/return |
|---|---|---|
| Linux x86-64 | implemented | implemented (ptrace + INT3) |
| Linux x86-32 target | module/symbol only | not in this preview |
| Windows | implemented (Toolhelp modules + on-disk PE exports) | not shipped |

The Windows read-only backend is shipped as a preview. Live Windows
breakpoints and call-site events remain unshipped.

---

## Limits and honest caveats

- **Modules present at inspection time.** The passes enumerate a snapshot of
  the modules already loaded in the target. A module loaded after that
  snapshot is not picked up; re-run after the module is present.
- **Single-threaded targets only for the Linux live pass.** The live pass places
  process-wide software breakpoints and steps them, which is only safe in a
  single-threaded target. A target with more than one thread (counted from
  `/proc/PID/task` before any attach) is refused the live pass and gets the
  read-only module/symbol pass instead, with an honest note. Tracing every
  thread of a multithreaded process is out of scope for this preview.
- **Linux return observation is best-effort.** A one-shot breakpoint at the
  captured return address reports the matching return for the common
  case of sequential, non-recursive calls (the fixture's shape). Deep
  recursion can miss or mis-pair a return in this preview; entries are
  always reported. (Multithreaded targets do not reach the live pass at
  all — see above.)
- **x86-64 only for the Linux live pass.** Other architectures get the
  read-only module/symbol pass.
- **ptrace must be permitted.** In some sandboxes attach is blocked
  (`PTRACE_ATTACH` refused); the host reports this and runs the
  read-only pass.

---

## Testing without real crypto traffic

The smoke test ([`native-x86/smoke-test.sh`](../../native-x86/smoke-test.sh))
ships a tiny fixture: a shared library
([`tests/fixtures/fake_exports.c`](../../native-x86/tests/fixtures/fake_exports.c))
whose exports are *named* `SSL_write`, `SSL_read`, `SSL_connect` and
`Java_com_example_Demo_ping` but do no cryptography and read no data, and
a process ([`tests/fixtures/fixture_target.c`](../../native-x86/tests/fixtures/fixture_target.c))
that calls them in a loop. The smoke test attaches to that fixture and
asserts the expected module/symbol/call-site records appear — so CI never
needs OpenSSL, a JVM, or any real traffic. If ptrace is blocked in the
environment, the smoke test checks the read-only pass instead and says so.

A second, multithreaded fixture
([`tests/fixtures/fixture_target_mt.c`](../../native-x86/tests/fixtures/fixture_target_mt.c))
spawns an idle worker thread before publishing its pid, so the smoke test
can confirm the single-thread-only policy: the host counts the target's
threads, refuses the live pass, and runs the read-only pass with the
honest multithread note. That check needs no ptrace — the refusal happens
before any attach — so it holds even where live attach is unavailable. The
smoke test also drives the deterministic cleanup-failure seams
(`NX86_TEST_INJECT`) for a resume (`PTRACE_CONT`) failure and a
breakpoint-arming (`bp_insert`) failure, asserting each fails the run with
"shutdown with errors" rather than a false "shutdown ok".

The same smoke test opens the committed
[`jni_registrar.dll`](../../native-x86/tests/fixtures/jni_registrar.dll)
as an ordinary file and verifies its machine type, named export RVAs, and
ordinals. That PE parser test runs on Linux and does not load or execute the
fixture or require a Windows process.
