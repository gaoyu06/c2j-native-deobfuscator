# Live JVM process attach (preview)

This document describes the **opt-in** live process-attach path for the JVMTI
diagnostics agent in [`native/`](../native). It lets you load the agent into a
JVM that is **already running**, instead of instrumenting it from startup with
`-agentpath`.

> **Preview, not the default.** The default, highest-fidelity recovery path is
> still startup instrumentation via `-agentpath` (used by `recover` and
> `dynamic-trace`). Attaching to a live process observes strictly less: only
> work that happens *after* the attach, and — for per-JNI-call argument
> capture — only on threads started after the attach. Use it when you cannot
> restart the target, or to take a quick diagnostic look at a running JVM.

## Authorized, same-user use only

This path is intended for JVMs **you own or are otherwise authorized to
inspect**, running as the **same user**. The CLI enforces this with a
best-effort same-user check and an explicit confirmation flag; it does not, and
must not, be used to bypass another party's protections. It performs no stealth,
does not hide the agent, and does not modify the target's behavior beyond
loading a standard JVMTI agent through the documented attach mechanism.

## How it works

The agent exports `Agent_OnAttach` alongside `Agent_OnLoad`. Both share one
phase-aware initializer:

- **Startup (`Agent_OnLoad`, `-agentpath`)** — the VM calls `VMInit` and every
  `ThreadStart`, so the agent installs its logging `JNIEnv` function table on
  every thread from the beginning.
- **Live attach (`Agent_OnAttach`)** — the VM is already initialized, so
  `VMInit` never fires. The agent bootstraps the function-table swap on the
  attach (listener) thread and picks up every thread started *after* attach via
  `ThreadStart`. JVMTI event subscriptions (`NativeMethodBind`, `MethodEntry`,
  `MethodExit`, `Exception`, `ExceptionCatch`) apply process-wide immediately.

Because a JNIEnv function table is per-thread and the agent can only reach the
attach thread directly, threads that were **already running** at attach time
keep their original table until they exit. Those threads still produce
`bind` / `enter` / `exit` / `exception` events (JVMTI, thread-independent) but
**not** per-JNI-call argument events. The agent records this honestly as a
capability/coverage gap rather than implying full coverage (see
[Capability and gap records](#capability-and-gap-records)).

## Usage

### 1. Build the agent

The live-attach path needs the native agent built for the host (dynamic path
prerequisite). See the README "Quick start":

```bash
cd native && JDK_HOME="$JAVA_HOME" bash build.sh
```

`build.sh` uses `zig c++`. If `zig` is not installed the script exits; you can
build the same three sources with any host C++17 toolchain, e.g.:

```bash
cd native && mkdir -p build/lib
g++ -std=c++17 -O2 -shared -fPIC \
    -I "$JAVA_HOME/include" -I "$JAVA_HOME/include/linux" -I include \
    -o build/lib/j2c_agent.so \
    src/agent.cpp src/trace_writer.cpp src/jni_hook.cpp
```

(or `cmake -S native -B native/build && cmake --build native/build`). The
result must expose both `Agent_OnLoad` and `Agent_OnAttach`
(`nm -D build/lib/j2c_agent.so | grep Agent_On`).

### 2. Find the target PID

```bash
jps -l            # JVM processes for the current user
# or: pgrep -u "$USER" -f java
```

### 3. Attach

```bash
python -m j2c_dumper_cli.main attach \
    --pid <pid> \
    --i-own-this-process \
    -o trace.jsonl
```

Options:

| Flag | Meaning |
|---|---|
| `--pid <pid>` | **Required.** PID of the same-user JVM to attach to. |
| `--i-own-this-process` | **Required** confirmation of authorized, same-user use. Without it the command refuses before touching the target. |
| `-o, --output <path>` | Where the agent writes the JSONL trace (default `trace.jsonl`). |
| `--agent <path>` | Override the agent library (default `native/build/lib/j2c_agent.*`). |
| `--log-all` | Log JNI calls even outside user native frames. |
| `--max-frame-events <n>` | Cap JNI events per native frame (`0` = unlimited). |
| `--mechanism auto\|jcmd\|vm` | Attach mechanism (default `auto`). |

### 4. Exercise the target, then stop cleanly

Drive the target so it executes the obfuscated native methods you care about.
When done, **stop the target JVM normally** (let it exit, or terminate it the
way you normally would). `Agent_OnUnload` flushes and closes the trace on VM
exit. There is no separate detach step; the preview does not support hot
unloading of the agent.

### 5. Consume the trace

The output is the same `trace.jsonl` schema the startup path produces, so it
feeds straight into the existing lifter:

```bash
python -m j2c_dumper_cli.main trace-to-bc trace.jsonl \
    --manifest manifest.json -o recovered/
```

(Generate `manifest.json` with `parse-jar` + `inspect-binary` + `merge-manifest`
as in the README, if you don't already have one.)

## Attach mechanisms

Both mechanisms use the platform's documented JVM attach facility and invoke
`Agent_OnAttach`:

- **`jcmd`** (default in `auto`): `jcmd <pid> JVMTI.agent_load <lib> "<opts>"`.
  Ships with the JDK, needs no compilation.
- **`vm`** (`com.sun.tools.attach`): a tiny helper compiled on demand that calls
  `VirtualMachine.attach(pid).loadAgentPath(lib, opts)`. Selected with
  `--mechanism vm`, or used as the `auto` fallback if `jcmd` is unavailable.

## Capability and gap records

On attach the agent writes structured records to the trace before normal events:

- `{"ev":"agent-attached","mode":"live-attach","phase":"live", ...}` — lifecycle
  marker (the startup path emits `agent-loaded` with `mode":"startup"`).
- `{"ev":"capability","name":"can_generate_method_entry_events","available":true|false,"phase":"live"}`
  — one per capability. If a capability is unavailable in the live phase, it is
  reported `false` (with the JVMTI error code) and the corresponding events are
  not enabled — coverage is reduced, not faked.
- `{"ev":"gap","kind":"jni-table-running-threads","tableInstalled":...,"runningThreads":N, ...}`
  — quantifies the JNI-interception coverage gap for threads already running at
  attach time.
- `{"ev":"gap","kind":"no-core-capabilities", ...}` — emitted if neither
  native-method-bind nor method entry/exit capabilities could be enabled (the
  trace will be effectively empty).

If the target probes for common inspection flags, the agent continues to use
only documented JVMTI capabilities and records "capability unavailable" where
applicable. It does **not** attempt to hide itself or patch the target's checks.

## Supported vs unsupported

**Supported (best-effort):**

- Loading the agent into a live, same-user JVM via `jcmd` or
  `com.sun.tools.attach`.
- Full JVMTI event coverage (`bind` / `enter` / `exit` / `exception`) for work
  that runs after attach, process-wide.
- Per-JNI-call argument capture on the attach thread and threads started after
  attach.

**Unsupported / known gaps:**

- **Attach disabled on the target.** If the JVM was started with
  `-XX:+DisableAttachMechanism` (or `-Djdk.attach.allowAttachSelf=false` for
  self-attach), the attach handshake fails. There is no workaround from this
  tool — restart the target and use the startup `-agentpath` path instead.
- **Dynamic agent loading disabled / warned.** Recent JDKs restrict or warn on
  dynamically loaded agents (`-XX:-EnableDynamicAgentLoading`, and the
  "a dynamically loaded agent has been loaded" warning). If dynamic loading is
  disabled, the attach fails; if it only warns, the attach still succeeds.
- **Missing `Agent_OnAttach`.** An agent build that does not export
  `Agent_OnAttach` cannot be attached to a live VM (`AgentInitializationException`
  / non-zero return). Rebuild the current `native/` sources, which export it.
- **Permission / same-user errors.** Attaching to another user's process is
  refused by the JVM attach layer (and pre-refused by this CLI's same-user
  check). Run as the owning user; do not use elevated privileges to cross users.
- **Threads already running at attach time** do not get per-JNI-call argument
  capture (see above) — reported via the `jni-table-running-threads` gap record.
- **No hot unload.** The preview does not remove the agent from a running VM;
  stop the target to finish.

## See also

- [README](../README.md) "Quick start" → "Dynamic recovery" for the default
  startup path.
- [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) for the agent and pipeline design.
- [`docs/manual-restoration.md`](manual-restoration.md) for cleaning recovered
  output by hand.
