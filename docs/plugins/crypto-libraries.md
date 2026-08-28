# Observation plugins for well-known library exports

Status: **preview**. These are the first observation plugins for the
experimental [`native-x86/`](../../native-x86/) module. They let the
user-mode host report *metadata-only* records when a process the user
owns enters or returns from well-known library exports. This is a
diagnostics preview, **not** a cryptographic debugger and **not** a
traffic tool.

> Content capture is out of scope. These plugins observe *that* a
> well-known entry was reached and *where* it lives — module, symbol
> name, address, and the control-flow edge. They never read, request or
> report the bytes those functions move: no plaintext, no ciphertext, no
> key, no IV, no argument value, and no return value. There is no code
> path that could, by construction of the plugin ABI (see
> [`plugin-abi.md`](../plugin-abi.md), "What events may not carry").

---

## What is observed

Each plugin declares interest in a set of **export names** through the
host's `request_watch` callback (ABI 0.2). The host — which knows nothing
about TLS, RSA, CNG or Java — resolves those names against the modules
loaded in the target and reports generic records:

- `module-load` — which file-backed image is loaded, at which base;
- `symbol` — a watched export's name and absolute address in a module;
- `call-site` — a live entry (`phase = enter`) or return
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
| `BCryptEncrypt` | exact | symbol + entry/return | CNG symmetric encrypt boundary |
| `BCryptDecrypt` | exact | symbol + entry/return | CNG symmetric decrypt boundary |
| `BCryptSignHash` | exact | symbol + entry/return | CNG signature boundary |

The plugin source is portable and builds on any platform, but it only
matches when `bcrypt.dll` is loaded in the target, which needs a Windows
host observation backend. See [Platforms](#platforms) below.

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

---

## The technique, stated plainly

The engine ([`native-x86/src/host/observe_linux.c`](../../native-x86/src/host/observe_linux.c))
uses documented user-mode debugging only:

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
If a technique is unavailable — attach refused, wrong architecture — the
host says so honestly and falls back to the read-only pass rather than
pretending the target was empty.

### What this is not

- **Not TLS interception or modification.** Nothing decrypts, rewrites,
  proxies or man-in-the-middles traffic. The plugins observe control-flow
  boundaries, not the data at them.
- **Not credential or key capture.** No argument, buffer, key, IV or
  return value is read or reported.
- **Not stealthy.** Attachment is explicit, same-user, and visible; a
  target that looks will see it is being traced.
- **No kernel component.** Everything here is an ordinary user-mode
  process using ptrace with the privileges the invoking user already has.

---

## Platforms

| Platform | Read-only pass | Live entry/return |
|---|---|---|
| Linux x86-64 | implemented | implemented (ptrace + INT3) |
| Linux x86-32 target | module/symbol only | not in this preview |
| Windows | not shipped | not shipped |

The Windows CNG plugin source is complete and portable, but a Windows
host observation backend (an `observe_windows.c` using documented
user-mode debugging APIs such as `DebugActiveProcess` /
`WaitForDebugEvent`, with the same record model and the same
metadata-only guarantee) is **not shipped in this preview**. Until it
exists, the CNG plugin loads and stays idle on non-Windows hosts, and
`BCrypt*` names match nothing.

---

## Limits and honest caveats

- **Modules present at attach time.** The read-only and live passes
  enumerate the modules loaded when the host attaches. A module the
  target `dlopen`s *after* attach is not (yet) picked up; re-run against
  a target that has already loaded the library of interest.
- **Return observation is best-effort.** A one-shot breakpoint at the
  captured return address reports the matching return for the common
  case of sequential, non-recursive calls (the fixture's shape). Deep
  recursion or heavy multithreading through the same watched export can
  miss or mis-pair a return in this preview; entries are always reported.
- **x86-64 only for the live pass.** Other architectures get the
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
