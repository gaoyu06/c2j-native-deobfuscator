# Independent design-theory review

Status: second-opinion review of `main` at `3843ec1`. This is an authorized,
docs-only analysis based on the listed repository documentation and the current
implementations. It does not assume an unpublished platform plan.

## Executive finding

The architecture has a generic **kernel of ideas**, but the current product is
not obfuscator-agnostic end to end. The genuinely reusable parts are the
versioned artifacts, class-file emitter, JNI function-table constants,
`RegisterNatives` semantics, and some ABI registration. Around that kernel are
hard-coded producer, compiler, decompiler, operating-system, and single-run
assumptions. Several of those assumptions live outside `Profile`, so a new
variant often requires core edits.

The practical correction is not to add more profiles around the current static
lifter. Make a standards-derived method inventory and normalized evidence
stream the core. Let emulation and JVMTI produce the same evidence, fuse that
evidence conservatively, and treat Ghidra as an optional advanced plugin.

## 1. Claim versus implementation

The claim under review is explicit: variant knowledge should be confined to
profiles and architecture modules without changing the main flow
([`ARCHITECTURE.md:9-11`](ARCHITECTURE.md#L9-L11)), and the core should never
branch on a named producer
([`ARCHITECTURE.md:139-150`](ARCHITECTURE.md#L139-L150)).

The verdict is **partly disproved**. There is useful separation, but it is
neither complete nor consistently applied.

| Area | Current evidence | Finding |
|---|---|---|
| JNI slot | `RegisterNatives` is centralized as index 215 ([`profile.py:41-47`](../py/binary_introspect/binary_introspect/profile.py#L41-L47)); discovery computes `index * pointer_size` ([`jni_tables.py:81-97`](../py/binary_introspect/binary_introspect/jni_tables.py#L81-L97)). | Generic and correct in principle. On x64 this is the documented `call qword ptr [reg+0x6B8]`, but only after an x86-shaped recognizer accepts it. |
| Indirect-call shape | The base ABI uses an Intel-syntax regex for `call [word + offset]` ([`arch/base.py:62-78`](../py/binary_introspect/binary_introspect/arch/base.py#L62-L78)). | The numeric slot is generic; the instruction and rendered-operand shape are not. A non-x86 ABI must replace methods in code, not merely add profile data. |
| `nMethods` calling convention | Windows x64 explicitly names R9/R9D ([`amd64_windows.py:15-24`](../py/binary_introspect/binary_introspect/arch/amd64_windows.py#L15-L24)); System V names RCX/ECX ([`amd64_sysv.py:15-24`](../py/binary_introspect/binary_introspect/arch/amd64_sysv.py#L15-L24)). | This is a successful architecture-module boundary. It also proves that the Windows register is an ABI fact, not an obfuscator profile fact. |
| Cache-table extraction | The cache scanner declares itself Windows x64 only ([`cache_table.py:40-60`](../py/binary_introspect/binary_introspect/cache_table.py#L40-L60)), rejects non-PE/non-AMD64 input ([`cache_table.py:75-95`](../py/binary_introspect/binary_introspect/cache_table.py#L75-L95)), and directly reads RDX/R8/R9 ([`cache_table.py:273-299`](../py/binary_introspect/binary_introspect/cache_table.py#L273-L299)). | The ABI abstraction is bypassed in a major static-recovery component. Adding an ABI module does not make this feature portable. |
| Harvest strategies | `Profile` offers only `per_class` and `shared_dispatch` ([`profile.py:76-83`](../py/binary_introspect/binary_introspect/profile.py#L76-L83)); the core branches on exactly one special value and otherwise uses one backscan ([`jni_tables.py:258-286`](../py/binary_introspect/binary_introspect/jni_tables.py#L258-L286)). | Profiles select implementations; they do not contain them. A third registration shape requires editing `jni_tables.py`, exactly as the profile guide admits ([`adding-obfuscator-profile.md:62-77`](adding-obfuscator-profile.md#L62-L77)). |
| Table construction | Both harvesters assume function addresses appear as executable-target PC-relative LEAs followed by stack stores, inside fixed `0x600` or `0x4000` windows ([`jni_tables.py:104-158`](../py/binary_introspect/binary_introspect/jni_tables.py#L104-L158), [`jni_tables.py:165-219`](../py/binary_introspect/binary_introspect/jni_tables.py#L165-L219)). | This is a compiler/code-generation fingerprint. It is not implied by JNI or `RegisterNatives`. |
| “Generic” profile | The default profile still selects `per_class` ([`profile.py:291-298`](../py/binary_introspect/binary_introspect/profile.py#L291-L298)) and inherits the default `"Cannot invoke"` and field-message regexes ([`profile.py:85-109`](../py/binary_introspect/binary_introspect/profile.py#L85-L109)). | The fallback is not “pure JNI-spec knowledge.” It embeds one registration strategy and one producer's diagnostic text. |
| Profile detection | Detection searches for `Java_*`, `_native_`, bootstrap/init names, export counts, PE format, and the literal `"Cannot invoke "` ([`profile.py:232-280`](../py/binary_introspect/binary_introspect/profile.py#L232-L280)). | Reasonable producer adapters, but not generic core behavior. Detectors should be optional evidence providers, not the gate to core method discovery. |
| String-pool selection | The core scans a fixed section-name list and scores producer-specific tokens such as `INVOKEVIRTUAL`, `AASTORE npe`, and `classloader == null` ([`core.py:115-139`](../py/binary_introspect/binary_introspect/core.py#L115-L139), [`core.py:181-212`](../py/binary_introspect/binary_introspect/core.py#L181-L212)). | Variant knowledge sits directly in `binary_introspect.core`, outside profiles. |
| Ghidra pseudo-C rewrite | An x64-only 8-byte table maps offsets to names, then a regex rewrites exactly `(**(code **)(*param + 0xN))(param, ...)` ([`jni_vtable.py:1-9`](../py/ast_matcher/ast_matcher/jni_vtable.py#L1-L9), [`jni_vtable.py:113-139`](../py/ast_matcher/ast_matcher/jni_vtable.py#L113-L139)). Every Ghidra function is passed through it ([`driver.py:940-944`](../py/ast_matcher/ast_matcher/lifter/driver.py#L940-L944)). | This is a specific decompiler rendering, pointer size, and identifier-reuse pattern. It belongs in a Ghidra adapter, not a generic lifter. |
| Ghidra local names | The lifter binds `param_1`, `param_2`, and later `param_N` to JVM slots ([`driver.py:202-233`](../py/ast_matcher/ast_matcher/lifter/driver.py#L202-L233)), explicitly accommodates names such as `local_47._23_8_` ([`driver.py:335-343`](../py/ast_matcher/ast_matcher/lifter/driver.py#L335-L343)), recognizes `DAT_<hex>` ([`driver.py:168-170`](../py/ast_matcher/ast_matcher/lifter/driver.py#L168-L170)), and accepts `LAB_` labels ([`driver.py:640-658`](../py/ast_matcher/ast_matcher/lifter/driver.py#L640-L658)). | Decompiler-generated names are semantic inputs. A version or configuration that changes those names can change bytecode output. |
| Source-shaped AST | The legacy matcher requires `cstack`, `clocal`, `cmethods`, `cfields`, `cclasses`, and `cstrings` identifiers ([`core.py:49-85`](../py/ast_matcher/ast_matcher/core.py#L49-L85)); its raw-source scanner requires `__ngen_native_*` symbols ([`core.py:653-667`](../py/ast_matcher/ast_matcher/core.py#L653-L667)). | These are producer/source-template conventions, not C or JNI semantics. Feature flags do not make them generic. |
| Throw-reason hints | Literal strings are matched with a profile regex and converted to descriptors in source order ([`throw_reason.py:62-89`](../py/ast_matcher/ast_matcher/lifter/throw_reason.py#L62-L89)); unresolved calls consume the next hint ([`driver.py:118-134`](../py/ast_matcher/ast_matcher/lifter/driver.py#L118-L134), [`driver.py:599-623`](../py/ast_matcher/ast_matcher/lifter/driver.py#L599-L623)). | Parameterizing the regex does not validate that the next message belongs to the next call, nor recover overload return types. It is a low-confidence producer heuristic. |
| Cache-init skipping | The driver contains a separate producer-specific cache block recognizer and hard-coded Windows lock/helper tokens ([`driver.py:768-776`](../py/ast_matcher/ast_matcher/lifter/driver.py#L768-L776), [`driver.py:850-879`](../py/ast_matcher/ast_matcher/lifter/driver.py#L850-L879)). | This behavior is outside `Profile` and is incorrectly coupled to the exception-guard feature flag. The “every heuristic independently toggleable” claim is false. |
| Loader detection | The JVM parser accepts only `(Class)V` or `(int, Class)V` registration descriptors ([`jar-parser/Main.kt:94-143`](../jvm/jar-parser/src/main/kotlin/j2c/jarparser/Main.kt#L94-L143)) and marks a class by calls to the chosen loader from `<clinit>` ([`jar-parser/Main.kt:161-184`](../jvm/jar-parser/src/main/kotlin/j2c/jarparser/Main.kt#L161-L184)). | Producer recognition exists in a JVM module that cannot consume the Python `Profile`. A different loader convention requires a core edit. |
| Rebuild cleanup | Resource removal recognizes `natives.bin`, `natives.dat`, and selected library extensions ([`class-rebuilder/Main.kt:217-242`](../jvm/class-rebuilder/src/main/kotlin/j2c/classrebuilder/Main.kt#L217-L242)); `<clinit>` cleanup recognizes `special_clinit_` ([`class-rebuilder/Main.kt:426-494`](../jvm/class-rebuilder/src/main/kotlin/j2c/classrebuilder/Main.kt#L426-L494)). | More variant knowledge outside profiles. Stripping while methods remain partial can also make a previously runnable JAR unusable. |
| Dynamic reconstruction | The translator chooses only the longest invocation per method ([`trace-to-bytecode/Main.kt:35-60`](../jvm/trace-to-bytecode/src/main/kotlin/j2c/tracetobc/Main.kt#L35-L60)), collapses repeated event shapes ([`trace-to-bytecode/Main.kt:98-181`](../jvm/trace-to-bytecode/src/main/kotlin/j2c/tracetobc/Main.kt#L98-L181)), and guesses reference parameters by first external object ([`trace-to-bytecode/Main.kt:723-808`](../jvm/trace-to-bytecode/src/main/kotlin/j2c/tracetobc/Main.kt#L723-L808)). | JVMTI is generic, but bytecode restoration remains a concrete-trace heuristic. Longer is not necessarily more complete, and collapsing can erase meaningful repeated behavior. |
| Dynamic event coverage | The hook table is a hand-selected subset ([`jni_hook.cpp:910-1026`](../native/src/jni_hook.cpp#L910-L1026)); the translator silently ignores unmatched events ([`trace-to-bytecode/Main.kt:516-689`](../jvm/trace-to-bytecode/src/main/kotlin/j2c/tracetobc/Main.kt#L516-L689)). | “Every key JNI function” is not a specification-backed coverage guarantee. Missing events are not surfaced as unsupported evidence. |
| Emulation | The emulator is fixed to x86-64 ([`j2c_emu.py:53-81`](../py/native_emulate/j2c_emu.py#L53-L81), [`j2c_emu.py:301-303`](../py/native_emulate/j2c_emu.py#L301-L303)), PE/ELF ([`j2c_emu.py:84-101`](../py/native_emulate/j2c_emu.py#L84-L101)), a subset of JNI slots ([`j2c_emu.py:32-48`](../py/native_emulate/j2c_emu.py#L32-L48)), three C-runtime imports ([`j2c_emu.py:328-337`](../py/native_emulate/j2c_emu.py#L328-L337)), and at most 64 registrations per capture ([`j2c_emu.py:462-469`](../py/native_emulate/j2c_emu.py#L462-L469)). | Executing bytes is valuable, but the surrounding machine, OS, runtime, and JNI models are explicitly partial. |

### Bottom line

The correct statement is:

> The project has standards-derived primitives and some extension points.
> Current end-to-end recovery is optimized for two related producer families,
> two x86-64 ABIs, one pseudo-C dialect, and incomplete JNI models. Profiles
> parameterize a subset of those assumptions.

That wording is less impressive, but it is supportable by the code.

## 2. Recovery-path scorecard

Scale: **5 is favorable**. For setup, 5 means low setup cost. “Finish” means a
new user can produce a truthfully labeled, verifier-clean bytecode-restoration
result, not merely a method list, an input/output observation, or a JAR that
contains default bodies.

| Path | Setup cost | Variant generality | Accuracy | Coverage | Finish without extra tools? |
|---|---:|---:|---:|---:|---|
| Dynamic JVMTI | **3/5** | **3/5** | **4/5 for observed JNI calls; 2/5 for whole-method semantics** | **2/5** | **2/5 — generally no** |
| Static Ghidra | **1/5** | **1/5** | **2/5** | **2/5** | **1/5 — no** |
| Emulation | **3/5** | **2/5** | **4/5 inside the modeled environment** | **2/5** | **2/5 — no** |

### Dynamic JVMTI

- Setup needs JVM and native builds, a compatible runtime, and a workload that
  reaches the target behavior. The CLI injects only startup `-agentpath`
  ([`main.py:104-114`](../py/j2c_dumper_cli/j2c_dumper_cli/main.py#L104-L114)).
- Observed JNI calls are high-fidelity, but native arithmetic and control flow
  are absent. Primitive parameters are not recovered
  ([`trace-to-bytecode/Main.kt:744-759`](../jvm/trace-to-bytecode/src/main/kotlin/j2c/tracetobc/Main.kt#L744-L759)).
- Coverage is workload and branch dependent. The implementation emits one
  chosen invocation rather than a union of paths.
- It is the best current bytecode-producing path, but “finish” still requires
  targeted test inputs, manual validation, and often restoration of missing
  control flow.

### Static Ghidra

- Setup includes an external Ghidra installation and a manual headless command;
  the one-shot CLI consumes an already generated dump but does not launch
  Ghidra ([`main.py:212-282`](../py/j2c_dumper_cli/j2c_dumper_cli/main.py#L212-L282)).
- Accuracy depends on decompiler output names, regex rewriting, producer
  messages, cache layouts, and a stack model that can invent defaults.
- Nominal reach is broader than one dynamic run, but only for functions whose
  addresses are found and whose decompile is accepted. Each output is labeled
  low confidence ([`driver.py:1057-1104`](../py/ast_matcher/ast_matcher/lifter/driver.py#L1057-L1104)).
- Frame failure defaults to a non-loadable but decompilable class
  ([`class-rebuilder/Main.kt:324-359`](../jvm/class-rebuilder/src/main/kotlin/j2c/classrebuilder/Main.kt#L324-L359)).
  That is an inspection artifact, not successful restoration.

### Emulation

- Setup is comparatively small, but only when the object format, architecture,
  imports, JNI calls, and required state are already modeled.
- The executed instruction stream is exact within that model. However, an
  emulation error is optionally printed and execution still returns the current
  RAX ([`j2c_emu.py:535-550`](../py/native_emulate/j2c_emu.py#L535-L550)); an
  unknown JNI slot receives a generic return value
  ([`j2c_emu.py:403-460`](../py/native_emulate/j2c_emu.py#L403-L460)).
  Results therefore need explicit completeness/error status.
- The `call` result is RAX or the last filled buffer
  ([`j2c_emu.py:637-652`](../py/native_emulate/j2c_emu.py#L637-L652)), which is a
  useful heuristic, not a general function contract.
- It inventories methods, extracts constants, and provides an oracle; it does
  not synthesize bytecode. Per-target state and model work prevent a new user
  from completing bytecode restoration with this path alone.

## 3. Impressive-looking features that should not define the core

| Feature | Why it is not generic or practical today | Recommendation |
|---|---|---|
| `ApplyJ2CDataTypes.java` | Its header promises a JNI interface, stack/local discovery, and lookup-table typing, but the implementation only creates one `jvalue` union and prints success ([`ApplyJ2CDataTypes.java:1-13`](../ghidra/scripts/ApplyJ2CDataTypes.java#L1-L13), [`ApplyJ2CDataTypes.java:21-44`](../ghidra/scripts/ApplyJ2CDataTypes.java#L21-L44)). | **Demote** to experimental until it verifies each applied type and reports coverage. |
| `ExtractRegisterNatives.java` | It scans initialized data for contiguous three-pointer records ([`ExtractRegisterNatives.java:100-180`](../ghidra/scripts/ExtractRegisterNatives.java#L100-L180)), while the primary Python discovery says the target family commonly builds the array on the stack ([`jni_tables.py:18-22`](../py/binary_introspect/binary_introspect/jni_tables.py#L18-L22)). A one-record “table” is accepted ([`ExtractRegisterNatives.java:223-230`](../ghidra/scripts/ExtractRegisterNatives.java#L223-L230)). | **Isolate** as a static-table plugin with false-positive metrics; do not advertise it as universal registration discovery. |
| `DumpJ2CDecompiledFunctions.java` | Despite its name, it accepts nearly every function and excludes names by ad hoc prefixes ([`DumpJ2CDecompiledFunctions.java:58-95`](../ghidra/scripts/DumpJ2CDecompiledFunctions.java#L58-L95)). | **Demote** to a broad dump/debug utility. Manifest-address decompilation should be the only supported input. |
| `DumpFromManifest.java` | It parses JSON with field-order-sensitive regexes ([`DumpFromManifest.java:187-249`](../ghidra/scripts/DumpFromManifest.java#L187-L249)), drops duplicate-address methods while only saying downstream “can replicate” ([`DumpFromManifest.java:95-103`](../ghidra/scripts/DumpFromManifest.java#L95-L103)), and expands helpers only one level ([`DumpFromManifest.java:147-172`](../ghidra/scripts/DumpFromManifest.java#L147-L172)). | **Replace** the parser with a supported JSON library or a line-oriented target list; retain duplicate method bindings; emit structured per-function failures. |
| Pseudo-C-to-bytecode AST lifter | It combines a real parser with regex extraction of decompiler identifiers, literals, calls, labels, and producer messages. Untracked JNI functions are silently swallowed ([`driver.py:625-633`](../py/ast_matcher/ast_matcher/lifter/driver.py#L625-L633)). | **Isolate** behind a `ghidra-pseudoc-v1` plugin ABI. Require normalized IR, unsupported-node counts, and provenance on every emitted instruction. |
| Per-variant profiles | Profiles currently mix producer detection, ABI filters, message text, and dispatch choice, while actual strategy code remains central. | **Replace** with composable providers: method-inventory provider, ABI decoder, decompiler adapter, and optional producer hints. A “profile” may select providers but must not imply coverage. |
| Windows cache-table scanner | It is a substantial target-specific symbolic scanner with fixed argument registers and helper shapes. | **Isolate** as `cache-layout/windows-x64-v1`; never let its failure lower the generic method inventory. |
| Automatic “clean JAR” output | The rebuilder may write non-loadable classes by default, restub methods, and strip native resources. The output can look complete while being inspection-only. | **Replace** one output with three explicit products: evidence bundle, hybrid runnable JAR, and fully restored JAR available only when every required method passes verification and behavior checks. |
| Emulation `strings` and `call` | These are valuable diagnostic operations, but memory-wide string scanning and “last filled buffer” result capture are target heuristics. | **Keep**, but label them observation tools. Move result decoding into per-signature adapters and expose stop reason, unsupported calls, and state assumptions. |
| Feature flags | Flags expose several lifter heuristics, but not the fixed pseudo-C grammar, cache-init token list, dynamic trace selection, or emulation model. | **Replace** “toggle every heuristic” with capability reports and per-evidence provenance. Flags remain useful for optional plugins. |

Test posture reinforces the skepticism: the checked-in static tests are four
hand-written source-shaped snippets
([`test_lifter.py:1-79`](../py/ast_matcher/tests/test_lifter.py#L1-L79)); the
end-to-end script requires an external fixture and exits if it is absent
([`test_pipeline.sh:11-17`](../tests/e2e/test_pipeline.sh#L11-L17)); and the
workflow only builds CLI distributions on manual dispatch
([`main.yml:1-44`](../.github/workflows/main.yml#L1-L44)).

## 4. Generic-first pipeline

The unit of truth should be **evidence about a method**, not a pseudo-C pattern
that happens to emit bytecode.

1. **Authorized ingest and immutable identity**
   - Read the JAR and native blobs without modifying the originals.
   - Hash every input and assign stable module/method identities.
   - Parse class native declarations independently of any loader convention.

2. **Standards-derived native inventory**
   - Inspect object-format exports and symbols.
   - Decode standard `Java_*` exports.
   - Capture `RegisterNatives` as a semantic operation, first by emulating
     `JNI_OnLoad`/candidate registrars and then, when available, from a live
     process.
   - Merge `(owner, name, descriptor, address, module, source, confidence)`
     records; never bind solely by equal method counts.

3. **Generated JNI model**
   - Keep one machine-readable catalogue of JNI and invocation-interface slots,
     signatures, side effects, and version availability.
   - Generate native hooks, emulator traps, event validators, and documentation
     from that catalogue. Pointer width and calling convention remain ABI
     plugins; producer names do not enter this layer.

4. **Normalized event IR**
   - Both emulation and JVMTI emit the same versioned events:
     `module-load`, `method-register`, `method-bind`, `method-enter`,
     `jni-call`, `native-call`, `exception`, `method-exit`, `gap`, and
     `unsupported`.
   - Every event carries timestamp/order, process/thread, module, method,
     producer, confidence, and redaction state. An unsupported slot is an event,
     not a generic success value.

5. **Emulation evidence**
   - Execute registration and selected methods in an explicitly declared CPU,
     ABI, object-format, import, and JNI model.
   - Record branch coverage, stop reason, unmapped access, unsupported imports,
     unsupported JNI slots, supplied state, and outputs.
   - Treat constants and input/output observations as evidence; do not call
     them bytecode.

6. **JVMTI evidence**
   - Support both startup and owner-authorized live attach.
   - Record class/method identity, future native binds, method boundaries,
     exceptions, and JNI calls. Preserve multiple invocations and path
     signatures instead of choosing only the longest one.
   - Represent native-only intervals as explicit gaps.

7. **Evidence fusion and bytecode proposal**
   - Correlate by method identity and address, then build a control-flow-aware
     proposal from all runs.
   - Rank each instruction/edge as `spec-derived`, `observed`, `emulated`,
     `plugin-inferred`, or `synthetic`.
   - Contradictory evidence blocks a “complete” status. Default values used only
     to satisfy a verifier remain visibly synthetic.

8. **Verification and output policy**
   - Verify class structure, frames, linkage, method coverage, and target tests.
   - Always emit an evidence bundle and restoration report.
   - Emit a **hybrid runnable JAR** by replacing only verified methods and
     retaining the original loader/blob for unresolved methods.
   - Emit a **fully restored JAR** only when all required native methods have
     verified bodies and the loader/blob can be removed safely.
   - Keep an explicitly named **inspection-only JAR** option for non-loadable or
     synthetic bodies; never call it clean or restored.

9. **Optional advanced plugins**
   - Ghidra receives the method inventory and may return normalized CFG/dataflow
     evidence. Its pseudo-C syntax stays inside the adapter.
   - Producer-specific cache/message helpers can add evidence but cannot decide
     whether the core runs.

The CLI remains the automation contract. Each stage accepts and emits versioned
JSON/JSONL, supports deterministic replay, and has `--capabilities` plus
`--explain-unsupported`. The desktop application is a client of those CLI
contracts.

## 5. Desktop GUI decision

A browser-based interface is outside scope. The candidates for a lightweight,
good-looking Java desktop are:

| Stack | Strengths | Costs/risks | Fit |
|---|---|---|---|
| **Swing + FlatLaf** | Swing ships in `java.desktop`; excellent tables, trees, split panes, log views, accessibility, and mature threading patterns. FlatLaf is a small, dependency-free look-and-feel with light/dark themes and HiDPI support ([official overview](https://www.formdev.com/flatlaf/)). | Imperative UI and careful event-dispatch-thread discipline; custom visualizations take more work. | **Best fit** for a data-heavy diagnostic client. |
| **JavaFX** | Strong CSS, binding, controls, and charts; clean separation for a new UI. | Platform-specific modules/JMODs and a custom runtime image are part of packaging ([official runtime-image guide](https://openjfx.io/openjfx-docs/modular)). This is more distribution surface than the current CLI project needs. | Good second choice if rich visualization becomes dominant. |
| **Compose Desktop** | Concise declarative Kotlin and modern custom rendering. | Adds another build plugin, a Skia-based rendering layer, and self-contained platform packaging; native packages must be built on their target OS ([official packaging guide](https://kotlinlang.org/docs/multiplatform/compose-native-distribution.html)). | Attractive, but too much runtime/build surface for this viewer. |

**Pick: Swing + FlatLaf.** It reuses the current JVM build, keeps the desktop
artifact small, and is well matched to tables and event streams. Package with
`jlink`/`jpackage` only after the unpackaged module is stable.

The GUI is not a second orchestrator. It launches the CLI with structured event
output and shows:

- pipeline stages, elapsed state, capability/unsupported badges, and exact
  artifact paths;
- a method table with owner/name/descriptor, module/address, registration
  source, dynamic/emulated coverage, confidence, verifier state, and unresolved
  gaps;
- a live event view filtered by process, thread, module, method, event kind, and
  severity;
- details for registration, bind, JNI/native calls, exceptions, dropped events,
  and emulator stops, with content redacted by default;
- explicit actions for launch, attach to an owned JVM, stop recording, export
  evidence, and open the generated report.

## 6. Attaching to an already-running owned JVM

### Current gap

The agent exports `Agent_OnLoad` and `Agent_OnUnload`, but no
`Agent_OnAttach` ([`agent.cpp:251-312`](../native/src/agent.cpp#L251-L312)).
Initialization depends on `VMInit` to capture and install the JNI table
([`agent.cpp:106-117`](../native/src/agent.cpp#L106-L117)), an event that has
already passed in a running JVM. The CLI's “attached” wording currently means
launching a new process with `-agentpath`, not live attach.

### Proposed evolution

1. Add a small Java `attach` CLI using `jdk.attach`. It lists local JVM
   descriptors, verifies that the OS process owner matches the current user,
   requires an explicit PID confirmation, and calls
   `VirtualMachine.loadAgentPath`. That documented API invokes
   `Agent_OnAttach` ([Attach API](https://docs.oracle.com/en/java/javase/21/docs/api/jdk.attach/com/sun/tools/attach/VirtualMachine.html)).
2. Export `Agent_OnAttach` and make both startup functions delegate to one
   idempotent initializer. Parse options, open a session transport, obtain
   JVMTI, query phase/potential capabilities, request the minimum available
   subset, install callbacks, and emit a capability report.
3. In live phase, do not wait for `VMInit`. Install the hook for the attach
   callback's current `JNIEnv`, retain `ThreadStart`, and also install
   idempotently at the beginning of every future `MethodEntry` callback so
   already-existing threads are covered before subsequent native invocations.
   Record a `gap` for activity before installation.
4. Enumerate loaded classes and declared methods for identity, but do not claim
   that public JVMTI can recover native addresses that were bound before attach.
   Merge future `NativeMethodBind` events with export/emulated
   `RegisterNatives` inventory.
5. Replace the single truncating file writer with a bounded local transport
   (named pipe or Unix-domain socket) plus optional JSONL recording. Include
   sequence numbers, dropped-event counters, heartbeat, session id, and clean
   stop. “Stop” disables recording/callbacks and restores tables where tracked;
   it does not promise to unload an in-process native library.
6. Test startup and live phases across supported JDKs because the JVMTI
   specification warns that some capabilities may be unavailable to an agent
   started in live phase
   ([JVMTI live-phase startup](https://docs.oracle.com/en/java/javase/26/docs/specs/jvmti.html)).

### Inspection checks and honest fallbacks

Some applications document checks for debugger arguments, attach availability,
dynamic-agent warnings, or the presence of diagnostic agents. The diagnostic
agent does not need JDWP or common debugger flags, so checks limited to those
flags do not block it. It should request only required JVMTI capabilities and
avoid unrelated management properties.

That is not invisibility. `-XX:+DisableAttachMechanism` can disable attach, and
dynamic loading can require explicit user opt-in
([JEP 451](https://openjdk.org/jeps/451)). A target can also deliberately detect
an in-process agent. The supported response is to explain the limitation and
offer documented modes: launch with `-agentpath`, offline emulation, or
user-mode process/library observation. Do not patch checks, falsify process
state, suppress audit signals, or conceal the agent.

The GUI should display an attach timeline: request, ownership/preflight result,
load result, available/missing capabilities, hook coverage by thread, first
sequence number, gaps, bind/enter/JNI/exception/exit events, dropped counts, and
stop state. A red “partial since attach” badge remains for the session.

## 7. Native-x86 module and JVM bridge

The proposed `native-x86` public API must contain **no Java or JNI types**. Its
job is general user-mode native observation:

- enumerate processes owned by the current user and inspect loaded modules;
- parse PE/ELF exports, symbols, relocations, and module identities;
- resolve addresses and module-relative offsets;
- instrument selected user-mode functions at entry/return with explicit
  session scope and reversible cleanup;
- provide well-known-library plugins for SSL/TLS, RSA, AES, Windows CNG, and
  OpenSSL entry points;
- emit versioned, bounded, redaction-aware events;
- load out-of-process plugins through a stable ABI similar in spirit to an
  extensible native debugger.

### Public C ABI sketch

Use opaque handles and neutral records such as `nx_session`, `nx_process_id`,
`nx_thread_id`, `nx_module_id`, `nx_address`, `nx_symbol`, `nx_probe_spec`,
`nx_value`, `nx_buffer_view`, and `nx_event`. Event kinds include
`process-start`, `module-load`, `symbol-resolved`, `function-enter`,
`function-exit`, `buffer-observed`, `error`, `gap`, and `session-stop`.

A plugin exports one version-negotiation entry point such as
`nx_plugin_query(host_abi_version, descriptor_out)`. The descriptor provides
name/version/capabilities plus init, enumerate-probes, decode-event, flush, and
shutdown callbacks. Boundary rules:

- C layout with explicit `size` and `abi_version` fields; no C++ STL or
  exceptions across the boundary;
- host-owned allocators and lifetime rules;
- architecture/OS capability masks;
- bounded buffers and explicit truncation/redaction flags;
- no implicit global hooks; every probe belongs to an authorized session;
- failures produce events and cannot terminate the target.

The crypto/library plugins should default to function metadata, sizes,
algorithm identifiers, return status, and call correlation. Capturing buffer
contents or key material is sensitive and must be a separate explicit option,
local-only, visibly indicated, and covered by retention/redaction policy.

### Separate `jvm-bridge`

`jvm-bridge` depends on `native-x86`, never the reverse. It recognizes VM
modules and relevant registration/library events, maps neutral addresses and
buffers into `method-register`, `native-call`, and restoration evidence, and
joins them with class/method identities from the JAR/JVMTI side. Java-specific
types remain private to this adapter. This preserves a reusable native observer
and prevents the restoration pipeline from leaking into its public ABI.

## 8. Optional privileged observer

A privileged observer must be a later, optional PR and must not be the
foundation:

- the user explicitly enables the OS debug/test-signing configuration and
  accepts the security/reboot implications;
- this project provides **no signed driver**;
- no normal workflow, method inventory, GUI, or plugin depends on it;
- it exports the same neutral event contract as `native-x86`, with a capability
  bit identifying privileged provenance.

The support burden is disproportionate: OS-build compatibility, Secure Boot and
virtualization-based security interactions, test-signing setup, crash and
unload safety, architecture matrices, symbols, installation rollback,
administrator policy, and limited CI coverage. A failure has system-wide rather
than process-local impact. It should proceed only after user-mode telemetry
shows a concrete, common visibility gap and maintainers approve an explicit
support matrix and threat model. This review proposes no kernel code.

## 9. Recommended PR sequence

The sequence deliberately establishes truthful contracts before adding more
front ends or observers:

1. docs and capability truth;
2. evidence/status schemas and generated JNI catalogue;
3. generic method inventory;
4. modular emulation evidence;
5. live JVMTI attach and transport;
6. evidence fusion and safe output policy;
7. Swing + FlatLaf desktop viewer;
8. optional Ghidra adapter isolation;
9. neutral native-x86/plugin ABI;
10. well-known-library plugins plus JVM bridge;
11. optional privileged-observer RFC/prototype.

The authoritative per-PR table—scope, whether it can ship independently,
required review, review preconditions, and accompanying docs—is in
[`pr-sequence.md`](pr-sequence.md).

Cross-PR rules:

- no PR claims restoration from a verifier-only or inspection-only artifact;
- schemas land before producers/consumers and remain backward-readable;
- each backend ships fixtures containing both supported and unsupported cases;
- GUI and plugins consume public CLI/event contracts, not implementation
  internals;
- privileged observation cannot become a prerequisite through convenience.

## 10. Human and no-human decisions

### Decisions requiring human approval

| Decision | Concrete options | Recommendation | Why a human decides |
|---|---|---|---|
| Definition of “restored” | (A) decompilable, (B) verifier-clean, (C) verifier-clean plus method coverage and behavior checks | **C**, with separate inspection/hybrid labels | This sets user expectations and compatibility policy. |
| Partial-output policy | (A) strip native resources anyway, (B) retain a hybrid runnable JAR, (C) emit evidence only | **B by default**, C when safe retention is impossible | It trades output simplicity against runtime correctness. |
| Desktop stack | Swing + FlatLaf, JavaFX, Compose Desktop | **Swing + FlatLaf** | It commits maintainers to a UI/toolchain and packaging surface. |
| Attach policy | any accessible PID, same-user PID, explicit allowlist | **Same-user plus explicit PID confirmation**; allow stronger enterprise policy | Process access is a security/product policy, not an implementation detail. |
| Dynamic-load fallback | hide/alter checks, launch-time agent, offline analysis | **Launch-time agent or offline analysis; never conceal** | The project must choose an ethical and supportable diagnostic posture. |
| Sensitive native buffers | always capture, metadata-only, explicit content opt-in | **Metadata-only default; per-session content opt-in with redaction and no remote upload** | Buffer contents can include credentials and personal data. |
| Plugin ABI stability | unstable C++, versioned C, in-process language-specific API | **Versioned C ABI**, freeze only after two real plugins | ABI compatibility creates long-term maintenance obligations. |
| First supported platform set | Windows x64 only, Windows/Linux x64, all current formats/architectures | **Windows/Linux x64 user mode first** | Support scope must match maintainer and CI capacity. |
| Ghidra status | required core, optional supported plugin, experimental scripts | **Optional supported plugin after normalization tests; current scripts experimental** | This changes documentation promises and release support. |
| Privileged observer | foundation, parallel early work, later optional gate | **Later optional gate** after measured user-mode gaps | System-level support and safety costs require maintainer ownership. |
| Dependency distribution | download at runtime, bundle all tools, user-supplied optional tools | **Bundle only the GUI/runtime; user supplies optional Ghidra** | Licensing, package size, updates, and platform signing need project-owner review. |

### Decisions that should be mechanical once contracts are accepted

These should not need case-by-case human judgment:

- JNI indices/signatures are generated from the chosen specification source;
- architecture and calling convention are selected by explicit capability
  probes, never producer name;
- unknown calls/imports produce `unsupported` events;
- every artifact contains schema version, input hash, producer version, and
  provenance;
- fully restored output is blocked by unresolved required methods, verifier
  failures, or contradictory evidence;
- GUI state is a projection of CLI artifacts/events;
- native-x86 public headers reject Java/JNI types in an automated API check;
- attach is limited to owned processes unless a future documented policy says
  otherwise;
- no browser interface and no privileged dependency enter the default path.

## 11. Direct disagreements with current design documents

### `ARCHITECTURE.md`

1. **“Obfuscator-agnostic core” is too broad.** Profiles cover detection,
   messages, and one strategy selector, while string scoring, loader detection,
   cache recognition, cleanup, Ghidra grammar, and dynamic heuristics remain in
   core modules.
2. **“Profile registration over hard-coding” is not achieved.** A new harvest
   strategy requires a new branch/function in `jni_tables.py`; the guide says
   so explicitly.
3. **“Every heuristic independently toggleable” is false.** Cache-init
   detection and Windows helper tokens share an unrelated exception-guard flag;
   dynamic selection/collapse and emulation fallbacks have no equivalent
   capability controls.
4. **“Fail soft” is underspecified.** The default may write a non-loadable class
   or a synthetic default body while stripping native resources. That is useful
   for inspection, but not a restored JAR.
5. **The architecture diagram omits emulation.** The README presents three
   paths, while the architecture pipeline shows only dynamic and static
   ([`ARCHITECTURE.md:18-60`](ARCHITECTURE.md#L18-L60)).

### `static-reverse-approach.md`

1. The document says “not started” and locks Ghidra as the only path
   ([`static-reverse-approach.md:1-14`](static-reverse-approach.md#L1-L14)),
   but code now exists and emulation is a third path. Its decision record is
   stale.
2. The claim that JNI slot plus stack/table index survive optimization and are
   sufficient ([`static-reverse-approach.md:29-42`](static-reverse-approach.md#L29-L42))
   ignores inlining, alias loss, value promotion, table construction variants,
   native-only operations, and decompiler rewriting.
3. The 100% rows for arithmetic, loads/stores, calls, arrays, control flow,
   exceptions, and prologue handling
   ([`static-reverse-approach.md:348-368`](static-reverse-approach.md#L348-L368))
   are contradicted by the implemented subset and silent unknown-call behavior.
4. The proposed typed decompile is not implemented as described:
   `ApplyJ2CDataTypes` does not apply the promised JNI interface or local/global
   array types.
5. Ghidra should not be the unique static foundation. Its useful role is an
   optional producer of CFG/dataflow evidence after standards-derived inventory
   and emulation have already established method identities.

## Scope and safety

This design is for analysis of software and processes the user owns or is
authorized to inspect. It uses documented JVM/OS diagnostic interfaces,
user-mode instrumentation, explicit consent, and transparent failure modes. It
does not propose concealment, persistence, unauthorized access, or kernel code.
