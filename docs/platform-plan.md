# Platform plan: generic-first recovery and a desktop shell

> Status: **docs-only planning proposal** for `main` at `3843ec1`. This is an
> independent, second plan. A separate review already exists on another branch
> (`docs/design-theory-review.md`, `docs/pr-sequence.md`); this document was
> written from the code and reaches its own conclusions. Where the two overlap
> and where they part company is recorded in
> [`plan-crosscheck.md`](plan-crosscheck.md). Decisions this plan makes versus
> those reserved for a human are in [`decisions.md`](decisions.md).
>
> Scope guard: this document proposes **no product implementation**. It writes
> down a direction, an ordering, and the decisions each step needs. It contains
> no kernel-driver design, no browser interface, and no concealment technique.
> Every claim below cites the current source so the plan can be checked.

---

## 摘要（中文简述）

本项目当前的核心思想是：把"把 JVM 字节码转译成 C/C++ 再经 JNI 回调"的这一类
混淆 JAR 还原回可读字节码，并宣称"混淆器无关（profile-agnostic）"。**实际代码
只部分满足这个宣称**：真正通用的是 JNI ABI 常量、`RegisterNatives` 语义、
版本化 JSON artifact 和字节码发射器；而架构/ABI 形态、反编译器方言、生产者
（producer）字符串、单次运行假设等，很多都写死在 `Profile` 之外，加新变体常常
要改核心代码。

本计划的组织原则是**通用优先（generic-first）+ 降低使用门槛**：先交付最稳、
风险最低、不依赖人类决策的东西（环境自检 `doctor`、复用现有产物的通用方法清单、
只读的桌面产物查看器、把 Ghidra 静态路径在文档层"降级"为可选、插件 ABI 设计
文档），把"重建为统一证据/事件模型 + 证据融合"这种大改动放到后面、并明确标注
为需要人类拍板的方向。

其余关键取向（均在正文有证据支撑）：
- **界面**：否决 Web；在 Swing+FlatLaf / JavaFX / Compose Desktop 之间，**选
  Swing+FlatLaf**（复用现有 JVM/Gradle 构建、`java.desktop` 随 JDK 自带、工作
  负载是表格/树/日志流、可后置 `jpackage` 打包）。CLI 仍是自动化契约，GUI 只是
  CLI 产物的可视化客户端。
- **进程附加**：不新增第二个相互冲突的 agent，而是**演进现有 JVMTI agent**
  （新增 `Agent_OnAttach`，与 `Agent_OnLoad` 共享同一个幂等初始化器；配一个
  基于 `jdk.attach` 的同用户附加 CLI）。仅限用户拥有/被授权的进程。
- **原生观测**：默认只采集元数据（函数、大小、算法标识、返回状态、调用关联），
  众所周知的加密库入口点作为**未来插件**接入；缓冲区/密钥内容为单独的、显式的、
  本地的、可打码的可选项。
- **特权观测者**：仅作为后期可选项，由用户自行开启操作系统调试/测试签名；
  **本项目不提供任何签名驱动**，默认流程不依赖它。

如果任何子章节被环境限制卡住，改用有文档记载的 JVM/OS 诊断 API 重新表述并继续。

---

## 1. Reading of the current design theory

### 1.1 What the project claims

The architecture states the core should be **obfuscator-agnostic**, with
variant knowledge confined to profiles and architecture modules that can be
added "without touching the main flow"
([`ARCHITECTURE.md:9-11`](ARCHITECTURE.md#L9-L11)), and that the core "never
branches on 'is this j2cc / is this native-obfuscator'"
([`ARCHITECTURE.md:139-150`](ARCHITECTURE.md#L139-L150)). The README extends
the same generality claim to three recovery paths and a `generic` profile that
"uses pure JNI-spec knowledge only" ([`README.md:334-343`](../README.md#L334-L343)).

### 1.2 What the code supports

The claim is **directionally right but only partly true today**. There is a
genuinely reusable kernel, and there is a ring of producer / compiler /
decompiler / OS / single-run assumptions around it, several of which live
*outside* `Profile`.

**Family-wide invariants (truly generic — these are the assets to build on):**

- The `RegisterNatives` vtable index is centralized as a JNI constant and the
  call-site search is `index * pointer_size`, not a producer fact
  ([`profile.py:46-47`](../py/binary_introspect/binary_introspect/profile.py#L46-L47),
  [`jni_tables.py:90-97`](../py/binary_introspect/binary_introspect/jni_tables.py#L90-L97)).
- The `nMethods` calling-convention register is cleanly an ABI fact, separated
  into per-ABI modules (Windows x64 names R9; System V names RCX)
  ([`profile.py:68-70`](../py/binary_introspect/binary_introspect/profile.py#L68-L70)).
  This is the one boundary that already works the way the architecture promises.
- The emulation path rests explicitly on the "JVM-fixed JNI ABI" — canonical
  vtable indices such as `GetArrayLength=171`, `RegisterNatives=215`,
  `ExceptionCheck=228` ([`j2c_emu.py:32-48`](../py/native_emulate/j2c_emu.py#L32-L48),
  [`README.md:122-125`](../README.md#L122-L125)).
- Versioned JSON artifacts (`schemas/*.schema.json`) and the ASM class-file
  emitter with `COMPUTE_FRAMES` as the verification gate
  ([`ARCHITECTURE.md:127-137`](ARCHITECTURE.md#L127-L137)).

**Variant-specific assumptions that leak outside `Profile` (the gap between
claim and code):**

- The `generic` fallback is not "pure JNI-spec": it still selects the
  `per_class` harvest strategy and inherits the default `"Cannot invoke"` /
  field-message regexes from the dataclass defaults
  ([`profile.py:90-109`](../py/binary_introspect/binary_introspect/profile.py#L90-L109),
  [`profile.py:291-298`](../py/binary_introspect/binary_introspect/profile.py#L291-L298)).
  It embeds one registration strategy and one producer's diagnostic text.
- A third registration shape is not expressible in profile data. The core
  branches on exactly one special value (`shared_dispatch`) and otherwise runs
  a single back-scan
  ([`jni_tables.py:262-286`](../py/binary_introspect/binary_introspect/jni_tables.py#L262-L286)),
  and the profile guide states plainly that a new strategy requires editing
  `jni_tables.py`
  ([`adding-obfuscator-profile.md:62-77`](adding-obfuscator-profile.md#L62-L77)).
- Table construction assumes function addresses appear as executable-target
  PC-relative LEAs followed by stack stores inside fixed `0x600` / `0x4000`
  windows ([`jni_tables.py:104-158`](../py/binary_introspect/binary_introspect/jni_tables.py#L104-L158),
  [`jni_tables.py:165-219`](../py/binary_introspect/binary_introspect/jni_tables.py#L165-L219)).
  That is a code-generation fingerprint, not something JNI implies.
- The cache-table scanner declares itself "AMD64 / Windows x64 only" and returns
  empty for anything else
  ([`cache_table.py:40-41`](../py/binary_introspect/binary_introspect/cache_table.py#L40-L41),
  [`cache_table.py:75-92`](../py/binary_introspect/binary_introspect/cache_table.py#L75-L92)).
  Adding an ABI module does not make this feature portable, because it bypasses
  the ABI abstraction entirely.
- Producer knowledge is duplicated across languages, none of it reachable from
  `Profile`: loader detection lives in the Kotlin jar-parser
  ([`jar-parser/Main.kt:111-159`](../jvm/jar-parser/src/main/kotlin/j2c/jarparser/Main.kt#L111-L159)),
  and native-blob stripping recognizes `natives.bin` / `natives.dat` / library
  extensions in the Kotlin class-rebuilder
  ([`class-rebuilder/Main.kt:217-243`](../jvm/class-rebuilder/src/main/kotlin/j2c/classrebuilder/Main.kt#L217-L243)).
  The Python `Profile` cannot influence either.
- The Ghidra pseudo-C lifter is a single-dialect assumption: it depends on the
  `(**(code **)(*reg + 0xN))(...)` rewrite and identifier shapes such as
  `param_N`, `DAT_<hex>`, `LAB_` that a different decompiler or version can
  change. This dialect coupling belongs in an adapter, not a "generic" lifter.

### 1.3 Where Ghidra / toolchain lock-in fights "profile-agnostic"

The static path is the most producer- and toolchain-coupled part of the system,
which directly undercuts the generic claim:

- The static path *requires* an external Ghidra 11.x install and a manual
  headless command; the one-shot CLI consumes a pre-generated dump and does not
  launch Ghidra ([`main.py:274-278`](../py/j2c_dumper_cli/j2c_dumper_cli/main.py#L274-L278),
  [`README.md:290-308`](../README.md#L290-L308)).
- `ApplyJ2CDataTypes.java` advertises JNI-interface, stack/local, and
  lookup-table typing in its header, but the implementation defines only a
  `jvalue` union and prints success
  ([`ApplyJ2CDataTypes.java:1-13`](../ghidra/scripts/ApplyJ2CDataTypes.java#L1-L13),
  [`ApplyJ2CDataTypes.java:21-44`](../ghidra/scripts/ApplyJ2CDataTypes.java#L21-L44)).
- `ExtractRegisterNatives.java` scans read-only data sections for contiguous
  three-pointer records
  ([`ExtractRegisterNatives.java:100-107`](../ghidra/scripts/ExtractRegisterNatives.java#L100-L107)),
  while the primary Python discovery documents that this family builds the array
  on the **stack** ([`jni_tables.py:18-22`](../py/binary_introspect/binary_introspect/jni_tables.py#L18-L22)).
  The two discovery mechanisms disagree about where the table lives.
- `static-reverse-approach.md` still says "not started," locks Ghidra as the
  only static path, and lists 100% coverage rows for arithmetic, calls, arrays,
  and control flow
  ([`static-reverse-approach.md:1-14`](static-reverse-approach.md#L1-L14),
  [`static-reverse-approach.md:348-368`](static-reverse-approach.md#L348-L368)).
  The shipped lifter is a best-effort subset that falls back to stubs
  ([`README.md:151-166`](../README.md#L151-L166)), so the decision record is
  stale and the coverage table overstates reality.

**Conclusion of the reading.** The honest, code-supportable statement is:

> The project has standards-derived primitives (JNI ABI, `RegisterNatives`
> semantics, versioned artifacts, an ASM emitter) and some real extension
> points. End-to-end recovery is currently optimized for two related producer
> families, two x86-64 ABIs, and one pseudo-C dialect. Profiles parameterize a
> subset of the variant assumptions; the rest live in core Python, in two Kotlin
> modules, and in Ghidra scripts.

This plan does not treat that as a failure. It treats it as a map: **grow the
generic kernel into the front door, and demote the producer/toolchain-coupled
parts to optional, clearly-labeled plugins.**

---

## 2. Goals

1. **Lower the usage barrier.** A new user should be able to run one preflight
   command that tells them exactly what is installed, what is missing, and what
   each recovery path can do on their machine — before they touch a target.
2. **Generic-first recovery.** Make the JNI-ABI-derived work (method inventory,
   emulation `recover`, dynamic tracing) the default entry point, since those
   rest on family-wide invariants. Treat the pseudo-C static lifter as one
   optional producer of evidence, not the spine.
3. **Java desktop GUI, not a browser.** A local desktop application for people
   who do not want to memorize CLI flags. No web server, no browser UI.
4. **CLI stays the automation interface.** Every capability is a CLI command
   with versioned JSON in/out. The GUI is a client of those contracts and holds
   no recovery logic of its own.
5. **Attach to an authorized running JVM.** Support inspecting a JVM the user
   already owns, in addition to launching one — by evolving the existing JVMTI
   agent, not adding a competing one.
6. **A user-mode native module whose public API has no Java types.** A reusable
   x86 user-mode observer (process/module enumeration, symbol/export parsing,
   scoped entry/return instrumentation) whose public ABI never mentions Java or
   JNI. A separate bridge maps its neutral events into restoration evidence.
7. **A plugin ABI.** A versioned, C-level plugin boundary so library-specific
   observers and future producers can be added out-of-tree.
8. **Optional privileged observer, later.** A privileged observation mode is a
   late, optional, user-enabled step (OS debug / test-signing configuration
   turned on by the user). The project ships **no signed driver**, and no
   default workflow depends on it.

---

## 3. Organizing principle: generic-first, ship-value-first

Two ideas drive the ordering below.

**Generic-first.** The unit that generalizes across the whole family is a
**method and the evidence we have about it** — its identity `(owner, name,
descriptor)`, where it is registered, and what each path could observe. That is
derivable from JNI ABI facts and standard object-format data, independent of any
producer. The pseudo-C pattern that "happens to emit bytecode" is the least
generic artifact in the system and should not define the core.

**Ship-value-first (avoid premature abstraction).** The other review reaches a
similar diagnosis but proposes rebuilding the core around a new normalized event
IR, a generated JNI catalogue, and an evidence-fusion engine *before* most user
value lands. This plan deliberately front-loads the low-risk, high-value,
decision-free work (preflight, a generic inventory that reuses today's
artifacts, a read-only viewer, honest capability labels) and treats the
event-IR/fusion subsystem as a **later, human-gated** track. Rationale: a large
schema authored before two real producers exist will be rewritten once they do;
it is cheaper to add provenance/confidence fields to the existing artifacts now
and formalize a shared event schema only after emulation and live attach both
need to emit it. This is the single biggest divergence between the two plans and
is written up as decision **B5** in [`decisions.md`](decisions.md).

---

## 4. UI stack decision

**A browser-based interface is vetoed** (goal 3). It would add a server, a
front-end toolchain, and a network surface to what is a local, offline analysis
tool. The choice is among Java desktop toolkits.

| Stack | Strengths | Costs / risks | Fit here |
|---|---|---|---|
| **Swing + FlatLaf** | Swing ships inside `java.desktop`, so no new runtime dependency; mature tables, trees, split panes, and log/console views; well-understood Event Dispatch Thread model; FlatLaf is a small, dependency-light look-and-feel with light/dark themes and HiDPI. | Imperative UI; custom visualizations take more code; EDT discipline required. | **Best fit.** The workload is data-heavy tables and event streams, and it reuses the existing Gradle/Kotlin JVM build. |
| **JavaFX** | Strong properties/binding, CSS styling, charts. | No longer bundled with the JDK; adds platform modules/JMODs and a custom runtime image to packaging. | Reasonable second choice if rich charting later dominates. |
| **Compose Desktop** | Concise declarative Kotlin; modern Skia rendering. | Adds a compiler plugin, a Skia runtime layer, and per-OS self-contained packaging built on the target OS. | Attractive but the most build/runtime surface for a viewer. |

**Pick: Swing + FlatLaf.** Evidence-based reasons specific to this repository:

1. The JVM side is already a Gradle multi-project in Kotlin
   ([`ARCHITECTURE.md:64-74`](ARCHITECTURE.md#L64-L74)); a Swing client is a new
   Gradle module with zero new UI runtime to distribute.
2. `java.desktop` (Swing) is part of the JDK the build already requires (JDK 21,
   [`ARCHITECTURE.md:152-163`](ARCHITECTURE.md#L152-L163)), so the unpackaged app
   runs anywhere the CLI already runs.
3. The core screens are a **method table** (owner/name/descriptor, module,
   registration source, coverage, confidence, verifier state) and a **live
   event/log view** — exactly Swing's `JTable`/`JTree`/streaming strengths.
4. Packaging with `jlink`/`jpackage` can be added *after* the unpackaged module
   is stable, so distribution cost is deferred, not paid up front.

This pick matches the other review's conclusion. It is still recorded as a
maintainer-level commitment (**B3**) because it commits the project to a UI
toolchain and packaging surface.

**GUI shape.** The GUI is not a second orchestrator. It launches CLI stages,
reads their JSON/JSONL artifacts, and renders: pipeline stage status with
capability/unsupported badges and exact artifact paths; the method table above;
a filterable live event view (by process, thread, module, method, kind,
severity); and explicit actions (launch with the agent, attach to an owned JVM,
stop recording, export an evidence bundle, open the report). Content that could
contain sensitive data is redacted by default.

---

## 5. Process attach: evolve the existing JVMTI agent

### 5.1 The gap, from the code

The agent exports `Agent_OnLoad` and `Agent_OnUnload` but **no
`Agent_OnAttach`** ([`agent.cpp:251-312`](../native/src/agent.cpp#L251-L312)).
Its initialization installs the hooked JNI table on `VMInit`
([`agent.cpp:106-117`](../native/src/agent.cpp#L106-L117)) — an event that has
already passed in an already-running JVM. The CLI's "attach" today means
launching a *new* process with `-agentpath`
([`main.py:104-114`](../py/j2c_dumper_cli/j2c_dumper_cli/main.py#L104-L114)), not
live attach to an existing one.

### 5.2 The approach: one agent, two entry points

Do **not** ship a second, competing agent. Evolve this one:

1. **Export `Agent_OnAttach`** and make both `Agent_OnLoad` and `Agent_OnAttach`
   delegate to a single idempotent initializer (parse options, obtain JVMTI,
   query phase and available capabilities, request the minimum available subset,
   install callbacks, emit a capability report).
2. **A same-user attach CLI** using the documented `jdk.attach` API. It lists
   local JVM descriptors, verifies the target process owner matches the current
   user, requires an explicit PID confirmation, and calls
   `VirtualMachine.loadAgentPath`, which invokes `Agent_OnAttach`.
3. **Do not wait for `VMInit` in live phase.** Install the hook for the attach
   callback's current `JNIEnv`, keep `ThreadStart`
   ([`agent.cpp:115-117`](../native/src/agent.cpp#L115-L117)), and also install
   idempotently at the top of each future `MethodEntry` so already-running
   threads are covered before their next native call. Record a `gap` for
   activity before installation.
4. **Be honest about pre-attach binds.** Enumerate loaded classes/methods for
   identity, but do not claim public JVMTI can recover native addresses bound
   before attach. Merge future `NativeMethodBind` events
   ([`agent.cpp:119-130`](../native/src/agent.cpp#L119-L130)) with the
   export/emulated `RegisterNatives` inventory from section 2.
5. **Replace the single truncating file writer** with a bounded local transport
   (named pipe / Unix-domain socket) plus optional JSONL recording, carrying
   sequence numbers, dropped-event counts, a heartbeat, and a clean stop. "Stop"
   disables recording/callbacks and restores tables where tracked; it does not
   promise to unload an in-process library.
6. **Test startup and live phases across supported JDKs**, because the JVMTI
   specification warns some capabilities may be unavailable to an agent started
   in live phase.

### 5.3 Honest posture, not concealment

Attach can be disabled by the target (`-XX:+DisableAttachMechanism`), dynamic
agent loading can require explicit opt-in, and a target may deliberately detect
an in-process agent. The supported responses are documented modes: launch with
`-agentpath`, offline emulation, or user-mode process/library observation. This
plan does **not** patch checks, falsify process state, suppress audit signals,
or conceal the agent. Attach is limited to processes the user owns or is
authorized to inspect (policy **B4**).

---

## 6. Native observation

Two separated concerns, matching goal 6.

**`native-x86` (neutral, reusable).** A user-mode module for owned-process and
module enumeration, PE/ELF export/symbol/relocation parsing, address and
module-relative offset resolution, and scoped function entry/return
instrumentation with reversible cleanup. Its **public C ABI contains no Java or
JNI types** — opaque handles and neutral records only (session, process, module,
address, symbol, probe, value, buffer view, event). An automated header check
should reject Java/JNI names in the public API. Events are versioned, bounded,
and redaction-aware. The design of this ABI ships as a document first (see PR
A5); code is later and behind decisions **B7**/**B8**.

**Well-known crypto library entry points as future plugins.** Observers for
common SSL/TLS, RSA, AES, and platform crypto (e.g. system crypto APIs, common
open-source crypto) entry points are **opt-in plugins over the plugin ABI**, not
core. The **default is metadata-only**: function identity, sizes, algorithm
identifiers, return status, and call correlation. Capturing buffer or key
material is a **separate, explicit, per-session, local-only, redaction-aware
option** (decision **B6**). This is authorized diagnostics of software the user
owns; it is never covert interception.

**`jvm-bridge` (adapter).** A separate module that depends on `native-x86` and
never the reverse. It recognizes VM modules and registration/library events and
maps neutral addresses/buffers into `method-register` / `native-call` /
restoration evidence, joining them with class/method identity from the
JAR/JVMTI side. Java-specific types stay private to this adapter, so the native
observer remains reusable and the restoration pipeline never leaks into its
public ABI.

---

## 7. PR split

Two sections. **Section A** needs no human decision to start — each PR is
docs-only or purely additive with a small blast radius. **Section B** lists
decisions a human should make; each names concrete options, a recommendation,
and consequences.

Definitions: **"Ship as-is?"** means the PR can merge and be released for its
stated scope without waiting for a later PR; it never means "skip review."

### Section A — no human decision needed (just do)

| PR | Scope | Ship as-is? | Review required? | Review preconditions | Docs shipped in the PR |
|---:|---|---|---|---|---|
| **A0. This platform plan** | Add `platform-plan.md`, `decisions.md`, `plan-crosscheck.md`. No runtime change. | **Yes, docs-only.** | **Yes** — maintainer/design review. | Re-check every `file:line` citation against the base commit; confirm neutral terminology; confirm contracts are proposals, not implemented claims. | these three files |
| **A1. `doctor` / setup preflight** | New CLI command that reports installed vs missing dependencies (JDK 21, Python 3.11, `uv`, `lief`, `capstone`, `tree-sitter-c`, `unicorn`, optional Ghidra 11.x per [`ARCHITECTURE.md:152-163`](ARCHITECTURE.md#L152-L163)) and prints, per recovery path, what is runnable now. Optional one-command bootstrap that wraps the existing build steps ([`README.md:256-270`](../README.md#L256-L270)). | **Yes, additive command.** Read-only diagnostics + a wrapper. | **Yes** — CLI-UX and correctness review. | Matrix of present/absent dependencies produces correct, non-misleading output; no network writes; exit codes documented. | `docs/doctor.md` |
| **A2. Generic method inventory** | New `inventory` command that merges native declarations from `classes.json`, exports/`RegisterNatives` from `binary.json`, and emulation `recover` records into one `(owner, name, descriptor, address, module, source, confidence)` report. Merge only on stable identity/evidence, **never on equal method counts**. Producer detectors stay optional hints. Reuses existing artifacts; not yet the default rebuild input. | **Yes as a new command**; not yet default. | **Yes** — binary-format and false-binding review. | PE/ELF fixtures with exports, stack-built tables, duplicate addresses, overloads, and an unsupported arch; zero silent class bindings; every record carries a source + confidence. | `docs/method-inventory.md`, capability/limitations notes |
| **A3. Read-only artifact GUI viewer (Swing + FlatLaf)** | New optional Gradle module: a desktop client that opens existing artifacts (`classes.json`, `binary.json`, `manifest.json`, `recovered/*.json`, `trace.jsonl`) and renders the method table + a filterable event/log view. It launches CLI stages and shows their status/paths. **No recovery logic, no browser server.** | **Yes, optional**, on top of stable artifact shapes. | **Yes** — UX, accessibility, packaging, process-control review. | Large-table/event-load smoke test; EDT audit; keyboard/accessibility pass; Windows/Linux unpackaged smoke run; no GUI-only hidden settings. | `docs/desktop-gui.md`, operator quick start, screenshots |
| **A4. Ghidra demotion + honest capability labels** | Documentation demotion of the static path to "optional / experimental," correcting the stale "not started" and 100% coverage claims in [`static-reverse-approach.md:1-14`](static-reverse-approach.md#L1-L14) / [`static-reverse-approach.md:348-368`](static-reverse-approach.md#L348-L368), and adding the emulation path to the [`ARCHITECTURE.md:18-60`](ARCHITECTURE.md#L18-L60) pipeline diagram. Add a cheap `--capabilities` / status output to stages where it is trivial. No behavior change to recovery. | **Yes, docs + additive flags.** | **Yes** — docs-accuracy review. | Each corrected claim re-verified against code; `--capabilities` output validated against actual modeled features. | updates to `ARCHITECTURE.md`, `static-reverse-approach.md`, README notes |
| **A5. Plugin ABI + native-x86 design docs** | Design-only documents for the future versioned C plugin ABI and the neutral `native-x86` public surface (opaque handles, event kinds, boundary rules, no Java/JNI types, capability masks). No code. | **Yes, docs-only.** | **Yes** — API-shape review. | Reviewers confirm the sketched ABI has explicit `size`/`abi_version` fields, host-owned allocation, and a Java/JNI-type rejection rule. | `docs/native-x86-abi.md`, `docs/plugin-abi.md` |
| **A6. Additive provenance / confidence fields** | Add backward-readable `source`, `confidence`, and `capability`/`unsupported` fields to existing artifact schemas (`schemas/*.schema.json`) and populate them from the current producers. Add an explicit **hybrid runnable JAR** *opt-in* output mode to the rebuilder that replaces only recovered methods and retains the loader/blob for the rest ([`class-rebuilder/Main.kt:245-276`](../jvm/class-rebuilder/src/main/kotlin/j2c/classrebuilder/Main.kt#L245-L276), [`class-rebuilder/Main.kt:217-243`](../jvm/class-rebuilder/src/main/kotlin/j2c/classrebuilder/Main.kt#L217-L243)). The *default* output policy is unchanged here (its change is decision **B2**). | **Yes, additive** if old artifacts stay readable. | **Yes** — schema-compatibility review. | Golden schema fixtures; old artifacts still parse; hybrid mode is opt-in and does not alter the default path. | `docs/artifact-provenance.md`, schema notes |

**Immediate start order within Section A** (each is independent enough to begin
now, no B decision required): **A1 → A2 → A3 → A4 → A5**, with **A6** runnable in
parallel. This is exactly the "doctor/setup, generic inventory, artifact GUI
viewer, Ghidra demotion, ABI docs" sequence the goals call for.

### Section B — likely needs a human decision

Each row: the decision, concrete options, this plan's recommendation, and the
consequence of choosing it. These are elaborated as ADRs in
[`decisions.md`](decisions.md).

| # | Decision | Options | Recommendation | Consequence |
|---|---|---|---|---|
| **B1** | Meaning of "restored" | (a) decompilable, (b) verifier-clean, (c) verifier-clean + method coverage + behavior checks | **(c)**, with separate `hybrid` and `inspection-only` labels | Sets user expectations and blocks over-claiming; more work per "restored" claim. |
| **B2** | Default partial-output policy | (a) strip native resources anyway, (b) hybrid runnable JAR by default, (c) evidence-only | **(b)** default; (c) when safe retention is impossible | Output is runnable when recovery is partial; slightly more complex default artifact. Changes today's strip-by-default behavior. |
| **B3** | Desktop stack | Swing+FlatLaf / JavaFX / Compose Desktop | **Swing+FlatLaf** | Commits the project to one UI toolchain + packaging surface (small, JDK-native). |
| **B4** | Attach policy | any accessible PID / same-user + explicit PID confirm / explicit allowlist | **Same-user + explicit PID confirmation**; allow stricter enterprise policy | Safe default; power users in shared environments need extra config. |
| **B5** | Build the normalized event IR + evidence-fusion subsystem now, or later? | (a) now, as the new core (the other plan) / (b) later, after adding provenance fields to existing artifacts and getting two real producers | **(b) later** | Less up-front schema churn and faster user value now; a unified cross-path fusion view arrives later than in the other plan. **This is the main divergence from the other review.** |
| **B6** | Sensitive native buffers | always capture / metadata-only / explicit content opt-in | **Metadata-only default; per-session, local-only, redacted content opt-in** | Protects credentials/PII by default; full content needs a deliberate switch. |
| **B7** | Plugin ABI stability | unstable C++ / versioned C / language-specific in-process API | **Versioned C ABI; freeze only after two real plugins exist** | Long-term ABI maintenance obligation, deferred until proven by two consumers. |
| **B8** | First supported platform set | Windows x64 only / Windows + Linux x64 / all formats+arches | **Windows + Linux x64 user mode first** | Matches current ABI coverage; AArch64/macOS deferred until demanded. |
| **B9** | Privileged observer | foundation / early parallel work / later optional gate | **Later optional gate**, after measured user-mode gaps; no signed driver | Keeps system-level risk out of the default; a real visibility gap must be shown first. |
| **B10** | Cross-language producer knowledge | port the Python `Profile` into the JVM modules / a single shared producer-hints JSON artifact consumed by both / leave duplicated | **Shared producer-hints JSON** consumed by Python and Kotlin | Removes the duplicated loader/strip/detector knowledge ([`jar-parser/Main.kt:111-159`](../jvm/jar-parser/src/main/kotlin/j2c/jarparser/Main.kt#L111-L159), [`class-rebuilder/Main.kt:217-243`](../jvm/class-rebuilder/src/main/kotlin/j2c/classrebuilder/Main.kt#L217-L243)); adds one shared schema to maintain. **This plan's addition beyond the other review.** |
| **B11** | Dependency distribution | bundle everything / download at runtime / bundle GUI+runtime, user supplies optional Ghidra | **Bundle GUI/runtime; user supplies Ghidra** | Keeps package size/licensing sane; static path stays a bring-your-own-tool option. |

### PRs that depend on Section B decisions (the later track)

These do not start until their gating decision is made; listed so the whole arc
is visible. They are intentionally *after* Section A.

| PR | Scope | Gated by | Ship as-is? | Review required? |
|---:|---|---|---|---|
| **C1. JVMTI startup + live attach** | Export `Agent_OnAttach`, share one idempotent initializer with `Agent_OnLoad`, add same-user `jdk.attach` CLI, lazy per-thread hook install, bounded local transport with drop/gap/heartbeat (section 5). Retain startup mode. | B4 | **No initially**; opt-in preview. | **Yes** — JVM, concurrency, privacy, security. |
| **C2. Provenance-aware outputs + default hybrid** | Flip the default output to the hybrid runnable JAR, gate the "fully restored" label on verified coverage, name non-loadable output inspection-only. Builds on A6. | B1, B2 | **Yes after gates pass**; first candidate for a new default workflow. | **Yes** — bytecode, behavior, compatibility. |
| **C3. Shared producer-hints artifact** | One JSON producer-hints schema consumed by the Python profile layer and the two Kotlin modules, replacing the duplicated loader/strip/detector logic. | B10 | **Yes, additive** if defaults preserved. | **Yes** — cross-language schema review. |
| **C4. Ghidra adapter isolation (code)** | Move pseudo-C rewriting, decompiler-identifier handling, cache-layout rules, and producer message hints behind a versioned adapter; replace regex JSON parsing in `DumpFromManifest.java`; emit normalized CFG/dataflow evidence; mark broad scripts experimental. | B5 (light), B11 | **Yes as optional plugin; no as required path.** | **Yes** — Ghidra-version, normalization, false-inference. |
| **C5. Normalized event IR + evidence fusion** | The larger subsystem: one versioned event stream both emulation and JVMTI emit, correlation by method identity, CFG-aware proposals with per-instruction provenance ranking, contradiction blocking a "complete" status. | B5 | **No** until contracts stabilize. | **Yes** — schema, correctness, compatibility. |
| **C6. Neutral native-x86 core + plugin ABI (code)** | Implement the A5 design: user-mode enumeration, symbol/export inspection, scoped instrumentation, versioned C ABI with no Java/JNI types, reversible cleanup. | B7, B8 | **No**; developer preview. | **Yes** — ABI, native safety, concurrency, platform security. |
| **C7. Library plugins + `jvm-bridge`** | Opt-in crypto-library entry-point plugins (metadata-only default) and the neutral→restoration-evidence bridge (section 6). | B6, B7 | **No** until privacy/compat gates pass. | **Yes** — library-version, cryptography, privacy, JVM integration. |
| **C8. Privileged-observer RFC, then prototype** | First an RFC + measured-gap report; a later prototype adapts privileged observations to the same neutral event contract. User enables OS debug/test-signing; **no signed driver shipped**; default stays user mode. | B9 | **RFC yes; prototype experimental only.** | **Yes** — mandatory maintainer, OS-security, operations, support. |

### Cross-PR rules

- No PR claims "restored" from a verifier-only or inspection-only artifact.
- Additive schema fields land before any consumer relies on them and stay
  backward-readable.
- Each backend ships fixtures with **both** supported and unsupported cases;
  unknown operations are observable failures, never silent success.
- The GUI and every plugin consume the public CLI/JSON contracts, not module
  internals.
- Same-user, explicit, local, bounded, reversible for any process observation.
- Privileged observation can never become a prerequisite for a normal workflow.

---

## 8. Implementation order that can start immediately

No Section B decision is required to begin any of these:

1. **A1 `doctor` / setup** — biggest single reduction in usage barrier; pure
   diagnostics over the documented dependency matrix.
2. **A2 generic inventory** — the generic-first front door, built by reusing
   `classes.json` + `binary.json` + emulation `recover`; no new heavy subsystem.
3. **A3 artifact GUI viewer** — read-only Swing+FlatLaf client over existing
   artifacts; proves the CLI-as-contract shape with zero recovery logic.
4. **A4 Ghidra demotion + honesty** — documentation truth-up plus cheap
   capability labels; removes the largest overclaim.
5. **A5 plugin/native-x86 ABI docs** — locks the neutral boundary on paper
   before any code, so later `native-x86` work cannot leak Java types.

**A6** (additive provenance fields + opt-in hybrid output) can proceed in
parallel because it does not change any default behavior.

Everything in the C-series waits for its Section B gate.

---

## 9. Scope and safety

This plan is for analysis of software and processes the user owns or is
authorized to inspect. It relies on documented JVM/OS diagnostic interfaces
(JVMTI, the `jdk.attach` API), user-mode instrumentation, explicit consent, and
transparent failure modes. It proposes no concealment, no persistence, no
unauthorized access, and no kernel code. Where a capability would otherwise
require a privileged or covert mechanism, the plan re-expresses it using
documented diagnostic APIs and clearly labeled, user-enabled modes, and
continues.
