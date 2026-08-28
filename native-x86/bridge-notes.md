# Bridge notes (design sketch, no code)

This file exists so the repository does **not** grow a Java-coupled
bridge package before the ABI is settled. There is no `bridge/` source
tree, no Gradle module, and no JNI header under `native-x86/`. What
follows is the shape such an adapter would take if the module ever earns
one.

## Why the boundary matters

`native-x86` describes an x86 process image: modules, symbols, call
sites. It has no notion of a class, a method descriptor, a `JNIEnv`, or
an obfuscator profile. Every Java-specific meaning is *derived* by a
consumer from generic records. Keeping that derivation out of the C
module means:

- the C module can be reviewed and fuzzed as a plain systems component;
- the JVM side can change its heuristics without an ABI bump;
- the recovery pipeline keeps working with the module absent, because
  nothing in `jvm/` or `py/` links against it.

## Shape of a future adapter

An adapter would live outside this directory (for example a new
`jvm/native-x86-bridge` Gradle module, or a Python consumer under `py/`)
and would only ever depend on the *record stream*, never on the C headers
being loaded into a JVM process:

1. **Transport.** The host stub writes records; the adapter reads them.
   A JSON-lines file in the style of the existing `trace.jsonl`
   (`schemas/trace-event.schema.json`) is the cheapest option and keeps
   the adapter out of process. In-process loading of the host into a JVM
   is explicitly *not* the starting point.
2. **Projection.** The adapter turns generic records into pipeline
   artifacts:
   - `module-load` for a blob already named in `manifest.json` →
     confirms the load base, so file offsets in `binary.json` can be
     rebased onto observed addresses.
   - `symbol` records whose name matches the JNI export convention
     (`Java_<mangled-class>_<mangled-method>`) → candidate native-method
     entry points. The pattern lives in the adapter; the C module just
     reports the name it saw.
   - `call-site` records inside a known method range → structural hints
     for the static lifter (which callee a site targets), never argument
     values.
3. **Merge.** Output is an existing artifact (`binary.json`-shaped
   supplement or a manifest overlay), validated against `schemas/`, so
   downstream stages are unchanged.

## Rules for whoever writes it

- The adapter is additive. If it is missing, `recover` / `rebuild` must
  behave exactly as they do today.
- No JNI concept leaks back into `include/nativex86/plugin.h`. If a
  projection needs more information, add a *generic* field (an address, a
  section index, a symbol binding) rather than a Java-shaped one.
- Records are advisory. The lifter must treat bridge output as hints
  that can be wrong or absent, the same way it treats throw-reason
  strings today.
