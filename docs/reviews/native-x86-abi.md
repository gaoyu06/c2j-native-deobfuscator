# Native x86 ABI review

Reviewed:

- PR: https://github.com/gaoyu06/c2j-native-deobfuscator/pull/7
- Branch: `cursor/native-x86-plugin-abi-5384`
- Head: `b925500b49f547e6be23bb17fa2b0238b51fb7a6`
- Base: `main` at `3843ec174510b52e643df2cb2f82a0d4cb57388e`

Verdict: **must-fix**.

## Checklist evidence

1. **Java/JNI isolation: pass.** The C API and implementation contain no
   Java/JNI type or header dependency. The public header includes only
   `<stddef.h>` and `<stdint.h>`. Mentions in `bridge-notes.md` and comments
   describe the exclusion and place any future adapter outside this directory;
   they do not introduce or require a JNI dependency.
2. **Recovery pipeline isolation: pass.** `git diff --name-status main...HEAD`
   shows no change under `py/`, `jvm/`, `native/`, or `ghidra/`. Existing
   tracked files changed only in `.gitignore`, `README.md`, and
   `README.zh-CN.md`; the remaining files are new documentation or the new
   `native-x86/` tree. The README edits are pointers and scope statements.
3. **ABI and event model: must-fix.** The ABI has an explicit 0.1 version and
   strings have documented borrowing and lifetime rules. The module, symbol,
   and call-site records describe structural metadata rather than arguments,
   return values, registers, or buffer contents. However, the advertised minor
   version negotiation is unsafe, and `process_id` is assigned inconsistently
   with its documented meaning; see the blocking findings below. The
   diagnostic note is free-form, so the no-process-data policy also relies on
   producer compliance.
4. **Linux smoke test: pass.** `bash native-x86/smoke-test.sh` built through
   CMake, loaded the sample plugin, dispatched the synthetic events, shut down,
   and printed `PASS`. Separate `--no-cmake` runs also passed without warnings
   under GCC 13.3.0 and Clang 18.1.3.
5. **Privileged observer: pass.** The document is explicitly optional and not
   implemented. It has no driver source, build target, stealth mechanism, or
   signature-bypass implementation. Its default is user mode; the privileged
   option remains a later human decision.
6. **README claims: pass.** Both root READMEs and `native-x86/README.md`
   identify this as an experimental skeleton, say that records are synthetic,
   and state that no observation or instrumentation exists. They do not claim
   that the stub currently inspects a process. Some deeper design-document
   claims still need correction as described below.
7. **Build hygiene: pass.** `.gitignore` covers `native-x86/build/`,
   `git diff --check` is clean, and both available Linux compilers completed
   the warning-enabled direct build without diagnostics.

## Blocking findings

### 1. Minor-version negotiation can overwrite host memory

`nx86_plugin_init` receives an `nx86_plugin *out_plugin` but no capacity for
that caller-owned object. The sample plugin clears and fills
`sizeof(*out_plugin)` in `plugins/hello/hello.c:157-168`. If a same-major newer
plugin appends fields as the documented minor-version rules allow, it will
write past an older host's smaller object before the host can inspect
`struct_size`.

Compatibility also fails in the other direction: the sample rejects
`host->struct_size < sizeof(nx86_host)` at `plugins/hello/hello.c:149`, while
the host rejects `plugin.struct_size < sizeof(nx86_plugin)` at
`src/host/main.c:230`. This contradicts `docs/plugin-abi.md:53-54`, which says
minor versions may differ in either direction and each side reads only the
covered prefix.

Redesign the initialization handshake before treating this as a versioned
extension mechanism. The output capacity must be known, or the plugin must
return storage whose size it owns; both sides must access only the common
prefix. Add adjacent-minor compatibility tests. No observation implementation
is needed for this fix.

### 2. `process_id` is stamped with the wrong process

The public header defines `process_id` as the observed process, with zero when
not applicable. The stub observes no process, but `src/host/event_bus.c:65`
stamps synthetic host-authored records with the host's real PID.
`src/host/event_bus.c:116` also overwrites every plugin-authored event with the
host PID. This mislabels the current synthetic stream and prevents a future
producer plugin from identifying a different observed process.

Define which side owns this field and test the rule. Synthetic/no-target
events should use zero, and target metadata must not be silently replaced with
the host process ID.

### 3. Lifecycle and transport claims exceed the stub

`docs/native-x86-module.md:45` calls the ABI stable even though the ABI
document calls 0.1 experimental and unstable, and the negotiation defect above
prevents the documented compatibility.

`docs/plugin-abi.md:268-270` says events are delivered only between successful
`start` and `stop`, but `host_emit` and the event bus have no lifecycle gate.
A plugin can call `emit` from `stop` or `shutdown` and the bus will still
dispatch it.

The claim that out-of-process transport will be a drop-in also needs narrowing.
The event copy is shallow and `nx86_str` contains process-local pointers, so an
out-of-process path still requires serialization, deep copying, and a wire
schema.

Either enforce the lifecycle contract and specify the transport boundary, or
describe these as future requirements rather than properties already enforced
by the skeleton.

## Decisions left for humans

- Keep this module in the repository or split it into a separate project.
- Finalize the corrected ABI shape, event-kind limit, and threading contract.
- Choose the record transport and wire schema.
- Decide whether plugins are trusted or require isolation.
- Choose the first supported platforms.
- Decide whether the optional privileged observer should ever proceed; the
  current default remains not to implement it.

No interceptor, observer, or privileged implementation was reviewed or
requested.
