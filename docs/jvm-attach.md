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
>
> **Coverage caveat (important).** Several JVMTI capabilities can only be added
> during the `OnLoad` phase. On many JDKs — **observed on OpenJDK 21** — a live
> attach can add only `can_generate_native_method_bind_events`; method
> entry/exit, local-variable access, and exception capabilities return
> `JVMTI_ERROR_NOT_AVAILABLE` (98). When that happens the live-attach trace
> contains **only `bind` events** (plus limited `jni-init` records on the attach
> thread), which is **not** enough for full method-body recovery. The agent
> records exactly which capabilities it obtained (see
> [Capability and gap records](#capability-and-gap-records)); do not assume
> entry/exit/locals/exception coverage unless the matching `capability` record
> says `available:true`.

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
  `ThreadStart`. It then *attempts* to add each JVMTI capability
  (`can_generate_native_method_bind_events`, `..._method_entry_events`,
  `..._method_exit_events`, `can_access_local_variables`,
  `..._exception_events`) and subscribes only to the events whose capability was
  actually granted in the live phase. On JDKs where the entry/exit/locals/
  exception capabilities are `OnLoad`-only (e.g. OpenJDK 21), only
  `NativeMethodBind` is subscribed.

Because a JNIEnv function table is per-thread and the agent can only reach the
attach thread directly, threads that were **already running** at attach time
keep their original table until they exit. Those threads still produce whichever
of the `bind` / `enter` / `exit` / `exception` events the agent could enable
(thread-independent JVMTI events) — **typically only `bind` on a live attach** —
but **not** per-JNI-call argument events. The agent records this honestly as
`capability` and `gap` records rather than implying full coverage (see
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

- **`jcmd`** (default in `auto`): `jcmd <pid> JVMTI.agent_load <lib> '<opts>'`.
  Ships with the JDK, needs no compilation. **The option string must be
  single-quoted.** `jcmd JVMTI.agent_load` routes the option string through the
  diagnostic-command argument parser, which treats a `key=value` token as one of
  its *own* named arguments and, for a positional argument, keeps only the part
  before `=`. A bare `trace=out.jsonl` therefore reaches the agent as an empty
  trace path; single-quoting makes the parser take the whole string as one
  literal positional value so the agent receives it intact. The CLI does this
  for you.
- **`vm`** (`com.sun.tools.attach`): a tiny helper compiled on demand that calls
  `VirtualMachine.attach(pid).loadAgentPath(lib, opts)`. Selected with
  `--mechanism vm`, or used as the `auto` fallback if `jcmd` is unavailable.
  `loadAgentPath` passes the option string verbatim (no quoting needed).

**Failure reporting.** `jcmd JVMTI.agent_load` prints `return code: <N>` (the
value `Agent_OnAttach` returned) but the `jcmd` process itself exits 0 *even when
the agent failed*. The CLI parses that line and treats any non-zero agent return
(or a non-zero `jcmd` exit) as a hard failure: it exits non-zero and does **not**
print `attached`. The `vm` helper surfaces the same failure as an
`AgentInitializationException`, which likewise fails the CLI.

## Common refusals and what this tool does

Live attach can be blocked, or produce only reduced coverage, for several
routine reasons. The CLI **classifies** each situation into a stable reason code,
**explains** it, and **recommends** the honest next step — it never bypasses the
target's flags, hides the agent, patches the target's checks, or reports success
when the attach did not happen.

Two detection points feed the same small set of reason codes:

- a **pre-attach cmdline scan** of the target's `/proc/<pid>/cmdline` (Linux),
  so the obvious cases are refused *before* `jcmd`/`VirtualMachine` is invoked;
- a **post-failure classifier** of the launcher/attach-layer output for cases
  the argv scan cannot see (e.g. flags set via `JAVA_TOOL_OPTIONS`, or a stale
  attach socket).

On any refusal the CLI exits non-zero, prints
`attach failed (reason=<code>): …`, and points to the startup `-agentpath` path.
It never prints `attached (preview)` in these cases.

| Reason code | Detected when | What the tool does |
|---|---|---|
| `attach-disabled` | `-XX:+DisableAttachMechanism` on argv, or the attach handshake is unavailable (`AttachNotSupportedException`, "unable to open socket file", "attach listener", "doesn't respond within …") | Refuse; recommend restarting under startup `-agentpath`. **No bypass** of `DisableAttachMechanism`. |
| `dynamic-agent-disabled` | `-XX:-EnableDynamicAgentLoading` on argv, or "dynamic agent loading is not enabled" from the attach layer | Refuse; recommend startup `-agentpath`. |
| `allow-attach-self-disabled` | `-Djdk.attach.allowAttachSelf=false` on argv | Refuse (this only blocks a *self*-attach); attach from a separate process, or use the startup path. |
| `cross-user` | Same-user check fails pre-attach, or the attach layer refuses on ownership/permission grounds ("operation not permitted", "well-known file is not secure") | Refuse; run as the owning user — **no** privilege escalation to cross users. |
| `not-a-jvm` | The target does not look like a JVM (pre-attach validation) | Refuse before touching the target. |
| `agent-onattach-missing` | Attach output shows the agent has no `Agent_OnAttach` export | Refuse; rebuild the current `native/` sources (they export it). |
| `agent-init-failed` | `Agent_OnAttach` ran but returned non-zero / `AgentInitializationException` | Refuse; check the target JVM's stderr for the agent's own diagnostics. |
| `jcmd-false-success` | `jcmd` exited 0 but `return code: <N≠0>` | Treat as failure, not success (see "Failure reporting" above). |
| `unknown` | Attach failed with an unrecognized error | Refuse; include a truncated raw snippet for context. |

**Reduced coverage is not a refusal.** If the attach *succeeds* but the JDK
grants only bind-only capabilities (the common OpenJDK 21 case), that is honest
reduced coverage, not a failure: the CLI reports `attached (preview)`, the trace
carries the `capability` / `gap` records that state exactly what was obtained,
and the CLI prints a one-line reminder that full method-body recovery needs the
startup `-agentpath` path. See [Capability and gap records](#capability-and-gap-records).

## Capability and gap records

On attach the agent writes structured records to the trace before normal events:

- `{"ev":"agent-attached","mode":"live-attach","phase":"live","logAll":true|false,"trace":"..."}`
  — lifecycle marker (the startup path emits `agent-loaded` with
  `"mode":"startup"`). `logAll` reflects the `--log-all` / `log-all=true` option.
- `{"ev":"capability","name":"can_generate_method_entry_events","available":true|false,"phase":"live"}`
  — one per capability. If a capability is unavailable in the live phase, it is
  reported `false` with the JVMTI error code (`98` =
  `JVMTI_ERROR_NOT_AVAILABLE`) and the corresponding events are not enabled —
  coverage is reduced, not faked.
- `{"ev":"gap","kind":"reduced-live-capabilities","nativeMethodBind":true,"methodEntry":false,"methodExit":false,"localVariables":false,"exceptions":false,"enabledEvents":"native-method-bind", ...}`
  — emitted on a live attach whenever entry/exit, local-variable, or exception
  capabilities could **not** be added. It states precisely which events are
  active; the missing ones will never appear in the trace. This is the common
  case on OpenJDK 21.
- `{"ev":"gap","kind":"jni-table-running-threads","tableInstalled":...,"runningThreads":N,"enabledEvents":"...", ...}`
  — quantifies the JNI-interception coverage gap for threads already running at
  attach time. `enabledEvents` names only the process-wide events actually
  enabled for the phase (so it does not imply enter/exit/exception when those
  capabilities were denied).
- `{"ev":"gap","kind":"no-core-capabilities", ...}` — emitted if neither
  native-method-bind nor method entry/exit capabilities could be enabled (the
  trace will be effectively empty).

Together these records let a reader reconstruct exactly what the attach obtained.
For example, a typical OpenJDK 21 live attach yields `native-method-bind`
`available:true` and `method-entry` / `method-exit` / `can_access_local_variables`
/ `exception` all `available:false` with `jvmtiError:98`, plus a
`reduced-live-capabilities` gap — i.e. `bind` events only.

If the target probes for common inspection flags, the agent continues to use
only documented JVMTI capabilities and records "capability unavailable" where
applicable. It does **not** attempt to hide itself or patch the target's checks.

## Supported vs unsupported

**Supported (best-effort):**

- Loading the agent into a live, same-user JVM via `jcmd` or
  `com.sun.tools.attach`.
- `NativeMethodBind` events (the `[native fn pointer -> Java method]` table) for
  work that runs after attach, process-wide — this capability is the one that
  reliably survives a live attach.
- Method `enter` / `exit` / `exception` events **and** per-JNI-call argument
  capture (on the attach thread and threads started after attach) **only when
  the JDK grants those capabilities after attach.** On JDKs where they are
  `OnLoad`-only (e.g. OpenJDK 21) these are **not** available on a live attach —
  the `capability` / `reduced-live-capabilities` records will say so, and the
  trace will hold `bind` events only. For full method-body recovery, use the
  startup `-agentpath` path.

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
