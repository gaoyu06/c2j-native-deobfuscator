# Review: opt-in live JVM process-attach preview

Scope of this review: the opt-in live process-attach path added for the JVMTI
diagnostics agent — the `attach` CLI command, its `attach_support` helpers, the
`Agent_OnAttach` entry point, and the accompanying docs. This is a **preview**
diagnostic path; the default `recover` flow still uses startup `-agentpath`
instrumentation and was left unchanged except where noted below.

All findings were reproduced empirically on **OpenJDK 21** (Linux, x86-64) with
the agent compiled from `native/`.

## Must-fix findings and resolutions

### 1. `jcmd` reported false success on agent-load failure

**Finding.** The CLI built a bare, comma-separated agent option string
(`trace=out.jsonl,log-all=true,...`) and passed it to
`jcmd <pid> JVMTI.agent_load <lib> <opts>`. Two problems compounded:

- **Option string was silently corrupted.** `jcmd JVMTI.agent_load` routes the
  option through the diagnostic-command argument parser. That parser treats a
  `key=value` token as one of its own named arguments and, for a positional
  argument, keeps only the part *before* `=`. So `trace=/path` reached the agent
  as an empty trace path. `Agent_OnAttach` then failed to open the trace file
  and returned `JNI_ERR` (`-1`).
  - Reproduction: `jcmd <pid> JVMTI.agent_load <lib> trace=/tmp/t.jsonl` →
    agent stderr `j2c-agent: failed to open trace file: ` (empty path).
- **`jcmd` masked the failure.** `jcmd JVMTI.agent_load` prints
  `return code: -1` on stdout but the `jcmd` process still exits `0`. The CLI
  keyed off the process exit code, so it printed `attached (preview).` for a
  load that had actually failed.

**Resolution.**

- The agent option string is now **single-quoted** when passed to `jcmd`
  (`build_jcmd_agent_load_argv` / `jcmd_agent_option_arg`). The diagnostic-command
  parser then takes the whole string as one literal positional value, so the
  agent receives `trace=…,log-all=…,…` intact. Verified: the trace file is
  created at the requested path and `return code: 0`.
- The CLI now captures `jcmd` stdout/stderr and parses the `return code:` line
  (`parse_jcmd_return_code` / `jcmd_load_error`). A non-zero agent return **or** a
  non-zero `jcmd` process exit is treated as a hard failure: the CLI exits
  non-zero and does **not** print `attached`. Verified end-to-end (agent forced
  to fail → CLI exit 1, no `attached`).
- The `com.sun.tools.attach` (`vm`) mechanism already passes the option string
  verbatim and surfaces failure as `AgentInitializationException`; that path was
  confirmed to fail the CLI too. The `auto` mechanism now falls back from `jcmd`
  to `vm` **only** when `jcmd` is unavailable, so a genuine load failure is no
  longer retried (which would have reloaded the agent).

**Tests added** (`tests/test_attach.py`, no JVM required):

- Option form: `jcmd_agent_option_arg` / `build_jcmd_agent_load_argv` produce a
  single-quoted option argument (would have failed against the old bare form).
- Return-code parsing: `return code: -1` → `-1`, `return code: 0` → `0`, absent
  → `None`; `jcmd_load_error` flags a `-1` agent return *despite* process exit 0.
- CLI level (mocked `subprocess.run`): a simulated `jcmd` exit-0 + `return code:
  -1` makes `attach` exit non-zero and never print `attached`; the mirrored
  success case does print it.

### 2. Coverage claims did not match what a live attach actually obtains

**Finding.** Several JVMTI capabilities are `OnLoad`-only. On OpenJDK 21 a live
attach could add **only** `can_generate_native_method_bind_events`; method
entry, method exit, local-variable access, and exception capabilities all
returned `JVMTI_ERROR_NOT_AVAILABLE` (98). The docs and README pointers,
however, promised "full JVMTI event coverage (`bind`/`enter`/`exit`/`exception`)"
and stated that already-running threads "still emit bind/enter/exit/exception
events" — neither is true when those capabilities are denied.

Reproduced capability records from a live attach on OpenJDK 21:

```
capability can_generate_native_method_bind_events available:true
capability can_generate_method_entry_events        available:false jvmtiError:98
capability can_generate_method_exit_events         available:false jvmtiError:98
capability can_access_local_variables              available:false jvmtiError:98
capability can_generate_exception_events           available:false jvmtiError:98
```

**Resolution.**

- **Emitted records now describe what was actually obtained.**
  - New `gap` record `reduced-live-capabilities` fires on a live attach whenever
    entry/exit, local-variable, or exception capabilities could not be added. It
    reports the exact per-capability booleans and the list of `enabledEvents`.
  - The `jni-table-running-threads` gap now lists only the events actually
    enabled for the phase (`enabledEvents`) instead of unconditionally claiming
    `bind/enter/exit/exception`.
  - The `agent-attached` / `agent-loaded` lifecycle record now includes
    `logAll`.
  - The per-capability `capability` records (already honest, `available:true|
    false` with the JVMTI error code) are unchanged.
- **Docs corrected** (`docs/jvm-attach.md`, `README.md`, `README.zh-CN.md`, and
  the `attach --help` text): they now state that a live attach may obtain only
  native-method-bind (observed on OpenJDK 21), that entry/exit/locals/exception
  are not promised unless the matching `capability` record says `available:true`,
  and that full method-body recovery needs the startup `-agentpath` path.

No new capabilities were added, so no coverage is now promised that the agent
does not obtain.

### 3. `--log-all` was a dead switch

**Finding.** `--log-all` flowed into the `log-all=true` agent option and set a
module-level `g_log_all` in `agent.cpp`, but nothing ever read it. The JNI-call
logging gate (`emit`) only checked `in_native_frame()`, so the flag changed
nothing.

**Resolution.** Wired the flag into the logging path:

- Added `set_log_all()` / `log_all()` to `jni_hook` and a `log-all=true` handler
  in `parse_options`.
- `emit` (and `emit_propagate`) now log calls made *outside* a user native frame
  when `log-all` is enabled, while the default behavior is unchanged (outside-
  frame calls stay suppressed). The per-frame event budget still applies only
  inside a frame.
- The redundant `agent.cpp` global was removed; the `log-all` state is surfaced
  in the `agent-attached` / `agent-loaded` record (`logAll`).

Verified on the startup path: with `-agentpath:…=…,log-all=true` the trace gained
480 outside-frame `jni` records for a short run that produced **0** without the
flag.

## What was intentionally left unchanged

- **Default `recover` path.** Startup `-agentpath` instrumentation is untouched;
  it still obtains the full capability set (all five capabilities `available:true`
  in the startup phase, verified).
- **No stealth / evasion / kernel / TLS hooks.** The agent uses only documented
  JVMTI capabilities and the documented attach mechanisms; it does not hide
  itself or alter target behavior beyond loading a standard JVMTI agent.
- **Same-user / ownership guardrails.** `--i-own-this-process`, the required
  explicit `--pid`, and the same-user / looks-like-Java validation are retained.

## Known limitations / leftovers

- On JDKs where entry/exit/locals/exception capabilities are `OnLoad`-only (e.g.
  OpenJDK 21), a live attach yields only `bind` coverage. This is a JVM
  limitation, not something this tool can work around; the startup path remains
  the way to get full coverage.
- The trace writer flushes on `Agent_OnUnload` (clean VM stop). A hard kill
  (`SIGKILL`) of the target can lose buffered records. Stopping the target
  normally is required, as the docs state.
- `jcmd` cannot carry an agent option string that itself contains a single
  quote; `jcmd_agent_option_arg` refuses such input and points the user to
  `--mechanism vm`. Trace paths with an apostrophe are out of scope for the
  preview.
- Threads already running at attach time never receive per-JNI-call argument
  capture (their JNIEnv table is not swapped); this is reported via the
  `jni-table-running-threads` gap record.
