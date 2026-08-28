# Options and status report for platform work

> Scope: this is a **decision-and-status synthesis** of eight already-opened
> draft pull requests (#2–#9) and their in-repository reviews, written for the
> repository owners. It implements **no product feature**; it only records what
> those branches landed, how their reviews judged them, what is now true versus
> what the original documentation claimed, and which decisions still need a
> human. It is docs-only and is **not a product ship**. Every draft branch was
> read but left unchanged; this report is the only new file, added on a fresh
> branch from `main`.
>
> Terminology is deliberately neutral: JNI-native transpiled JARs, bytecode
> restoration, JVMTI diagnostics, process inspection, library instrumentation,
> plugin ABI, privileged observer. No tool or product names.

---

## 中文摘要（先读这一节）

本报告汇总 8 个已经打开的**草稿 PR（#2–#9）**及其仓库内评审结论，供仓库所有者
决策。**本报告不实现任何产品功能**，只做"落地了什么 / 评审怎么判 / 现状与原始
宣称的差距 / 还需人来拍板的决策 / 建议合并顺序"的梳理。所有功能分支只读不改，
本报告是唯一新增文件，基于 `main` 新建分支提交，属于纯文档、**不是产品发布**。

### (a) 以草稿 PR 形式落地了什么

- **#2 设计理论评审 + PR 拆解序列**（纯文档）：判定"混淆器无关内核"只部分成立，
  给出"通用优先 + 证据/状态契约"的方向和 0–10 的 PR 排序。可原样合并。
- **#3 通用性审计**（纯文档）：逐条列出 85 处写死变体/编译器/操作系统/反编译器
  形态的假设，只陈述事实、不改代码。可原样合并。
- **#4 无需 Ghidra 的通用方法发现**（代码）：真正基于 JNI 结构（vtable 索引 215、
  ABI 参数寄存器）发现方法表，ELF 路径有真实 fixture 在 CI 中验证；Ghidra 被降级
  为可选的方法体插件。评审判定：**可作为草稿/开发分支合并，但不能作为默认发布**。
- **#5 平台计划 + 决策记录 + 交叉核对**（纯文档）：第二份独立计划，区分"本计划可
  自行决定"与"必须人来拍板"的决策（D1–D11 / B1–B11）。可原样合并。
- **#6 doctor / setup 脚本 / 上手指南**（代码）：新增环境自检、安装脚本、双语上手
  文档，把"手动 CLI"重新定位为默认用法。评审判定：**可作为草稿合并，但合并前必须
  修复**（缺 `capstone` 依赖、JDK17→21 越级、doctor 误报就绪/把告警当阻断等 7 项）。
- **#7 native-x86 隔离 + 插件 ABI**（文档 + 骨架）：独立的用户态观测骨架 + 版本化
  C 插件 ABI，公共头**不含任何 Java/JNI 类型**，且**尚未实现任何观测**。评审判定：
  **必须修复**（次版本协商会越界写内存、`process_id` 打错进程、生命周期/传输过度宣称）。
- **#8 Swing 桌面查看器**（代码）：只读的 CLI 产物查看器（Swing + FlatLaf），不含任何
  还原逻辑。视觉评审发现并修复 6 个问题，并删除了一个"附加—暂不可用"的假按钮。测试通过。
- **#9 可选的 JVMTI 实时附加预览**（代码）：新增 `Agent_OnAttach` 与基于 `jdk.attach`
  的**同用户**附加 CLI；默认 `recover` 流程不变。评审判定：**仅作为可选预览**，且已修复
  三个必修项（jcmd 误报成功、能力宣称过高、`--log-all` 空开关）。

**所有 8 个 PR 目前都是 OPEN + 草稿状态**，评审结论以仓库内文档形式存在（GitHub 上无
正式 review 记录）。

### (b) 现状 vs 原始仓库宣称

- **通用优先**：原文档宣称"混淆器无关内核"。实际只有 JNI ABI 常量、`RegisterNatives`
  语义、版本化 artifact、字节码发射器是真正通用的；#4 新增了真正通用的方法发现路径
  （ELF 已验证），但它在草稿分支上、尚未成为默认，`main` 上仍有大量变体耦合（见 #3）。
- **Ghidra 可选**：原文档把静态路径写成"需要 Ghidra"。#4/#6 在文档与命令层把 Ghidra
  降级为可选方法体插件，并提供无 Ghidra 的发现/桩生成路径；但这尚未合并进 `main`。
- **使用门槛**：原 README 主张"用编码 agent 驱动、别指望手动跑脚本"。#6 用 doctor + 安装
  脚本 + 上手指南把手动 CLI 变成默认路径；但存在未修复的必修项，尚未合并。
- **GUI**：原仓库只有静态截图，无桌面应用。#8 提供了只读桌面查看器（Swing + FlatLaf）。
- **附加（attach）**：原实现里"attach"其实是用 `-agentpath` 启动新进程。#9 才提供真正的
  实时附加预览（同用户 + 显式 `--pid`），但受 JVM 限制，实时附加通常只能拿到
  native-method-bind 能力；完整方法体恢复仍需启动期 `-agentpath`。
- **native-x86 隔离**：原仓库只有 `native/`（JVMTI agent）。#7 新增独立的 `native-x86/`
  用户态模块，公共 ABI 不含 Java/JNI 类型，但目前是**骨架 + 文档**，未实现任何观测。

### (c) 仍需人来拍板的决策（含推荐 + 是否已按推荐开工）

| 决策 | 推荐 | 是否已按推荐开工 |
|---|---|---|
| "restored" 的含义 / 默认部分输出策略 | 定义为"通过校验 + 覆盖 + 行为检查"，另设 hybrid / inspection-only 标签；部分结果默认输出可运行的 hybrid JAR | **未**：`main` 仍是"剥离即默认"；默认翻转被显式推迟到人决策之后 |
| 桌面技术栈 | Swing + FlatLaf | **已**：#8 已按此实现 |
| 实时附加策略 | 同用户 + 显式 PID 确认；允许更严的企业策略 | **已**：#9 已按此实现为预览 |
| native-x86 是否留在本仓库 | 留在仓库但保持隔离（可后续再拆分） | **部分**：骨架已在仓库内且已隔离；"留还是拆"仍开放 |
| 插件信任 / 传输 | 版本化 C ABI，出现两个真实插件后再冻结；进程内先行，跨进程传输另行定义线格式 | **部分**：#7 给出 ABI 设计与骨架，但有内存安全必修项，传输尚未定义 |
| 是否要做特权观测者 | **默认否**，仅在测得用户态确有反复无法覆盖的盲区后，作为后期可选项 | **未**（符合推荐）：仅有边界文档，无任何代码 |
| 敏感缓冲区 / 库观测 | **默认只采集元数据**；如需内容，须单会话、本地、可打码、显式开启、不外传 | **未**（符合推荐）：未实现；native-x86 记录仅为结构性元数据 |

### (d) 建议合并顺序

先文档（#2、#3、#5、以及本报告）→ 再 doctor/setup（#6，修完必修项后）→
通用发现（#4，作为草稿/开发合并，未达默认发布）→ 桌面查看器（#8）→
实时附加（#9，保持可选预览）→ native-x86（#7，修完必修项后仅作开发者预览）。

**在各自评审说 OK 之前不得合并/提升**：#4 在未关闭"仅按数量的无名表定位误绑"前不得
成为默认发布路径；#6 未修完 7 项必修项不得合并；#7 未修好次版本协商越界写与
`process_id` 打错前不得被当作稳定 ABI；#9 必须保持可选预览、不得提升为默认或宣称完整
覆盖；未获人决策前不得开工敏感缓冲区/库内容采集与特权观测者。

### 明确不在范围内 / 未做

真实用户态加密库插桩（内容采集）、内核驱动 / 特权观测者实现、任何 Web / 浏览器界面。
以上都只有边界或"未来插件"文档，没有任何实现，也不应在缺少对应人决策前实现。

---

## How to read this report

- **"Ship as-is?"** means the branch can be merged and released **for its stated
  scope** without waiting on a later branch. It never means "skip review."
- **"Review status"** summarizes the verdict recorded in each branch's own review
  document (`docs/reviews/*.md`, or the review sections inside the docs branches).
  On GitHub all eight are `OPEN` drafts with no formal review decision recorded;
  the substantive review lives in-repo.
- Base for all diffs is `main` at `3843ec1`.

---

## 1. What landed as draft pull requests

| PR | Branch | Scope | Ship as-is? | Review status |
|---:|---|---|---|---|
| **#2** | `cursor/design-theory-review-465c` | Docs only: skeptical design-theory review of `main`, recovery-path scorecard, generic-first direction, desktop pick, observer boundaries, human/no-human decision split, and a 0–10 PR-sequence (`docs/design-theory-review.md`, `docs/pr-sequence.md`). No runtime change. | **Yes — docs-only.** | Self-described authorized second-opinion review; changes no behavior. Mergeable as documentation; owner/design sign-off is the only gate. |
| **#3** | `cursor/genericity-audit-966b` | Docs only: inventory of **85 findings** where code assumes a specific variant, compiler, OS/CPU, or decompiler output shape (`docs/genericity-audit.md`). Facts only, no fix. | **Yes — docs-only.** | Factual inventory; nothing is "fixed" by it. Mergeable as a reference for later generality work. |
| **#4** | `cursor/generic-first-discovery-ca12` | Code: generic method discovery from JNI structure (vtable index 215 via decoded operands, ABI arg registers, `Java_*` exports), Ghidra demoted to an optional method-body plugin, new `static-lite`/`inventory`-style commands, schema additions, tests + a real ELF fixture (`docs/reviews/generic-first-pr.md`, `docs/generic-recovery.md`). | **As a draft / dev merge: yes. As the default release: no.** | Reviewed twice. Both original must-fixes resolved (real-ELF loading test committed; lifter derives profile from the artifact). Full Python suite 21 passed. Residual (not must-fix): unnamed count-only positional mis-binding; PE/Mach-O loading unproven; section-stripped ELF returns a silent empty registry. |
| **#5** | `cursor/platform-plan-docs-7274` | Docs only: a second, independent platform plan plus ADR-style decision records that split "decisions this plan makes" (D1–D11) from "decisions reserved for a human" (B1–B11), and a cross-check against #2 (`docs/platform-plan.md`, `docs/decisions.md`, `docs/plan-crosscheck.md`). | **Yes — docs-only.** | Endorses #2's diagnosis; differs on sequencing (front-load decision-free value; defer the event-IR/fusion rebuild). Mergeable as documentation. |
| **#6** | `cursor/cli-doctor-setup-getting-started-b8b1` | Code: read-only `doctor` preflight, `setup.sh`/`setup.ps1`, `j2c` launchers, bilingual getting-started, Ghidra-free tests; both READMEs reframed so manual CLI is the default and assisted adaptation is optional (`docs/reviews/cli-doctor-setup.md`). | **Ship as draft; must-fix before merge.** | Directionally right, but 7 must-fix items: missing `capstone` dependency (doctor can print `Ready` before `recover` fails), unneeded repo-wide JDK 17→21 bump, native-artifact checks that neither prove readiness nor rebuild staleness, warnings treated as blocking, no-argument path exits non-zero, an undocumented Windows `bash` prerequisite, and readiness/output claims that overstate what `doctor` checks. May still be in re-review. |
| **#7** | `cursor/native-x86-plugin-abi-5384` | Docs + skeleton: a separate user-mode `native-x86/` module (owned-process/module enumeration, PE/ELF inspection, scoped instrumentation — **none implemented yet**), a versioned C plugin ABI whose public header carries **no Java/JNI types**, and a boundary doc for an optional, unimplemented privileged observer (`docs/reviews/native-x86-abi.md`, `docs/plugin-abi.md`, `docs/privileged-observer.md`). | **No — developer preview / design only.** | Must-fix: minor-version negotiation can overwrite host memory; `process_id` is stamped with the host PID instead of the observed process (or zero); lifecycle/transport docs claim guarantees the skeleton does not enforce. Java/JNI isolation, recovery-pipeline isolation, and the Linux smoke build all pass. |
| **#8** | `cursor/swing-desktop-viewer-7389` | Code: an optional read-only Swing + FlatLaf desktop viewer that launches CLI stages and renders pipeline status, the method table, and JVMTI trace — **no recovery logic, no browser server** (`docs/reviews/desktop-ui-visual.md`, `jvm/desktop-ui/README.md`). | **Yes, optional** — after CLI/event contracts are stable. | Visual review found and fixed 6 issues (clipped detail pane, mid-token command wrap, centered headers, jumping divider, non-reproducible screenshots) and **removed a permanently-disabled "Attach — not available yet" button**. `:desktop-ui:test` passes. Note: the module targets JDK 21 while the rest of `jvm/` targets JDK 17. |
| **#9** | `cursor/opt-in-jvmti-live-attach-1155` | Code: opt-in live attach preview — export `Agent_OnAttach`, a `jdk.attach` **same-user** CLI (`--i-own-this-process` + required explicit `--pid`), lazy per-thread install, capability/gap/drop records over the existing agent; default `recover` (startup `-agentpath`) unchanged (`docs/reviews/jvm-attach.md`, `docs/jvm-attach.md`). | **No initially — opt-in preview only.** | Three must-fix items resolved: `jcmd` false success on load failure, coverage claims that exceeded what a live attach obtains, and a dead `--log-all` switch. Empirically on OpenJDK 21 a live attach obtains **only** `native-method-bind`; entry/exit/locals/exception are `OnLoad`-only, so records and docs were corrected to say so. Full method-body recovery still needs the startup path. |

---

## 2. What is true now versus what the original repo claimed

Each row states the **original claim** (from `main`'s README/architecture docs),
what the draft PRs make **true now** (on their branches, not yet on `main`), and
the **gap** an owner should keep in mind.

### 2.1 Generic-first

- **Original claim.** The core is "obfuscator-agnostic," with variant knowledge
  confined to profiles and architecture modules, and the core "never branches on
  a named producer."
- **True now.** Only the standards-derived kernel is genuinely generic: JNI ABI
  constants, `RegisterNatives` semantics, versioned JSON artifacts, and the ASM
  emitter. #3 documents 85 places where producer/compiler/OS/decompiler shape is
  assumed outside `Profile`. #4 adds a genuinely generic discovery path
  (structural `RegisterNatives` detection + ABI arg registers + `Java_*` exports)
  and proves the ELF loading path in CI.
- **Gap.** #4 is a draft, not the default and not merged. On `main` the static
  lifter, cache-table scanner, string-pool scoring, loader detection, and rebuild
  cleanup remain variant/OS-coupled. The correct summary is "standards-derived
  primitives plus some extension points," not "agnostic end to end."

### 2.2 Ghidra optional

- **Original claim.** The static path "requires Ghidra"; static coverage tables
  read as near-complete.
- **True now.** #4 demotes Ghidra to an optional method-body plugin in help text,
  stub notes, the `static-reverse` command, both READMEs, and
  `docs/generic-recovery.md`; discovery, manifest, and restoration stubs are
  produced with no decompiler. #6 labels Ghidra "Advanced / optional" and its new
  tests run without it. #5/#2 mark the stale static-approach doc for correction.
- **Gap.** Not yet on `main`. The one remaining "requires Ghidra" string (in
  `docs/ROADMAP.md`) accurately describes a CI limitation of the static-path
  end-to-end tests, not a hard tool requirement.

### 2.3 Usage barrier

- **Original claim.** "The best way to use this project is to drive it with a
  coding agent… don't expect to just run the ready-made scripts by hand."
- **True now.** #6 adds a read-only `doctor` preflight, `setup.sh`/`setup.ps1`,
  `j2c` launchers, and a bilingual getting-started guide, and reframes both
  READMEs so **manual CLI use is the default** and assisted adaptation is
  optional.
- **Gap.** Not merged, and its own review lists 7 must-fix items — most notably
  that `doctor` can approve an unusable install (missing `capstone`) and reject a
  usable one (warnings treated as blocking). The barrier is lowered on the branch
  but not yet reliably.

### 2.4 GUI

- **Original claim.** None — the repo shipped only auto-generated static
  screenshots.
- **True now.** #8 adds an optional read-only desktop viewer (Swing + FlatLaf)
  that is strictly a client of the CLI: it launches stages and renders their JSON
  (pipeline status, method table, trace) and contains no recovery logic and no
  browser server.
- **Gap.** It waits on stable CLI/event contracts, and the module targets JDK 21
  while the rest of `jvm/` targets JDK 17 (a toolchain split to resolve).

### 2.5 Attach

- **Original claim.** The CLI's "attach" wording actually meant launching a new
  process with `-agentpath`; the agent had `Agent_OnLoad`/`Agent_OnUnload` but no
  `Agent_OnAttach`, and initialized on `VMInit` (already past in a running JVM).
- **True now.** #9 adds a real live-attach **preview**: `Agent_OnAttach`, a
  `jdk.attach` same-user CLI gated by `--i-own-this-process` and a required
  explicit `--pid`, lazy per-thread install, and honest capability/gap/drop
  records. The default `recover` path is unchanged.
- **Gap.** Live attach is JVM-limited: on OpenJDK 21 it obtains only
  native-method-bind; entry/exit/locals/exception are `OnLoad`-only. Full
  method-body recovery still requires the startup `-agentpath` path. Threads
  already running at attach time never get per-JNI-call argument capture (reported
  as a gap record).

### 2.6 Native-x86 isolation

- **Original claim.** The only native component was `native/` — the in-process
  JVMTI agent.
- **True now.** #7 adds a separate `native-x86/` user-mode module with a versioned
  C plugin ABI whose public header carries **no Java/JNI types** (verified), and
  keeps the recovery pipeline (`py/`, `jvm/`, `native/`, `ghidra/`) untouched. A
  future JVM adapter is documented as living *outside* this directory.
- **Gap.** It is a **skeleton plus documentation** — no process observation or
  instrumentation is implemented — and it has memory-safety and labeling must-fix
  items (see §3.5). Some design docs overclaim ABI stability, lifecycle gating,
  and out-of-process transport relative to what the skeleton enforces.

---

## 3. Human decisions still open

For each: the concrete options, the recommendation carried by the reviews, the
consequences, and **whether work already proceeded** on the recommended option.
These are the decisions the reviews explicitly reserve for a human because they
commit the project to user expectations, security policy, toolchains, or
long-term maintenance.

### 3.1 Meaning of "restored" and the default partial-output policy

- **Options — "restored".** (A) decompilable; (B) verifier-clean; (C)
  verifier-clean **plus** method coverage and behavior checks.
- **Options — partial output.** (A) strip native resources anyway; (B) emit a
  hybrid runnable JAR by default; (C) evidence-only.
- **Recommendation.** "Restored" = (C), with separate **`hybrid`** and
  **`inspection-only`** labels. Partial output = (B) by default; (C) only when
  safe retention is impossible. A verifier-clean body full of synthetic defaults
  is still **partial**, and a "clean JAR" that is non-loadable must never be
  called restored.
- **Consequences.** A higher, clearer bar per "restored" claim and partial
  results that stay runnable, at the cost of a slightly more complex default
  artifact and a migration of today's "clean JAR" wording.
- **Work already proceeded?** **No — and this is the most important open gap.**
  Today's rebuilder can strip the loader/native blob while methods remain stubbed,
  and artifacts do not yet carry source/confidence. The reviews recommend adding
  additive `source`/`confidence`/`capability` fields and an *opt-in* hybrid mode
  first, and deferring the **default** policy flip until this decision is made. No
  branch in this set flips the default; #4's review flags the strip-while-stubbed
  behavior as a should-fix.

### 3.2 Desktop stack

- **Options.** Swing + FlatLaf; JavaFX; Compose Desktop.
- **Recommendation.** **Swing + FlatLaf** — it reuses the existing JVM/Gradle
  build, `java.desktop` ships with the JDK, the workload is tables/trees/log
  streams, and packaging (`jlink`/`jpackage`) can wait until the module is stable.
  A browser interface is explicitly out of scope.
- **Consequences.** Small, JDK-native footprint; an imperative UI style that needs
  disciplined event-dispatch-thread handling.
- **Work already proceeded?** **Yes — confirm.** #8 already built the viewer on
  Swing + FlatLaf as a read-only CLI client, with the visual review's fixes
  applied and tests passing. The open sub-item is the JDK 17/21 toolchain split,
  not the toolkit choice. Recommendation: **confirm Swing + FlatLaf** and scope
  JDK 21 to the desktop module only.

### 3.3 Live attach policy

- **Options.** Any accessible PID; same-user + explicit PID confirmation; explicit
  allowlist.
- **Recommendation.** **Same-user + explicit PID confirmation**, while allowing a
  stricter enterprise policy. Never conceal the agent, never patch attach checks;
  offer documented modes (startup `-agentpath`, offline emulation, user-mode
  observation) when a target disables or detects attach.
- **Consequences.** A safe default; power users on shared hosts need extra
  configuration. Process access is a security/product policy, not an
  implementation detail.
- **Work already proceeded?** **Yes — as a preview.** #9 implements same-user +
  `--i-own-this-process` + required explicit `--pid`, retains the same-user /
  looks-like-Java validation, and adds no stealth/evasion/kernel/TLS behavior. The
  open decision is whether to keep it same-user by default (recommended) and
  whether to add an enterprise allowlist; the implementation must remain an
  **opt-in preview** until the JVM/concurrency/privacy/security review clears it.

### 3.4 Whether native-x86 stays in this repository

- **Options.** Keep it in this repository (isolated); split it into a separate
  project.
- **Recommendation.** **Keep it in-repo but strictly isolated** for now: no
  dependency from the recovery pipeline into `native-x86/`, no Java/JNI types in
  its public ABI, and any JVM adapter placed outside the directory. Revisit a
  split only if the module grows its own release cadence.
- **Consequences.** Keeping it in-repo keeps one review surface and shared CI;
  splitting later is cheap **because** the isolation rules are enforced now.
  Letting the boundary blur would make a later split expensive.
- **Work already proceeded?** **Partially.** The skeleton already lives in-repo
  and is isolated (recovery pipeline untouched; Java/JNI isolation verified). The
  keep-vs-split call itself remains open and is listed as a human decision in #7's
  review.

### 3.5 Plugin trust and transport

- **Options — ABI stability.** Unstable C++; **versioned C ABI**; a
  language-specific in-process API.
- **Options — trust.** Trust plugins in-process; require out-of-process isolation.
- **Options — transport.** In-process only; a defined out-of-process wire schema.
- **Recommendation.** A **versioned C ABI** (opaque handles, explicit `size` /
  `abi_version` fields, host-owned allocators, bounded/redaction-aware events),
  **frozen only after two real plugins exist**. Treat the in-process path as the
  starting point and **define a real wire schema before claiming out-of-process
  transport**. Decide trust explicitly rather than defaulting to in-process trust.
- **Consequences.** A stable, long-lived extension point, but ABI compatibility
  becomes a maintenance obligation, so the freeze is deliberately evidence-gated.
- **Work already proceeded?** **Partially, and it is not yet safe to rely on.** #7
  publishes the C ABI design and a working skeleton, but the review found the
  minor-version negotiation can **overwrite host memory** (both sides currently
  reject `struct_size` mismatches instead of reading only the common prefix), the
  event copy is shallow with process-local pointers (so "drop-in" out-of-process
  transport is overclaimed), and the lifecycle "events only between start/stop" is
  not enforced. These must be fixed before the ABI is treated as a versioned
  extension mechanism. The trust model is explicitly left to a human.

### 3.6 Whether a privileged observer should ever be built

- **Options.** Make it a foundation; do early parallel work; treat it as a later,
  optional, gated component.
- **Recommendation.** **Default: no.** Only a **later optional gate**, and only
  after user-mode telemetry demonstrates a concrete, repeated visibility gap that
  user-mode observation provably cannot serve, with maintainer-approved threat and
  support models. The user would enable OS debug/test-signing themselves; **the
  project ships no signed driver**, automates no security-weakening step, and adds
  no stealth, no signature/integrity bypass, no hidden loaders, no interception,
  and no data exfiltration. It would emit the *same* neutral records as the
  user-mode path behind the *same* plugin ABI.
- **Consequences.** Keeps system-wide crash/blast-radius, per-kernel maintenance,
  and un-CI-able configurations out of the default path. The cost is high,
  permanent, and paid by maintainers; the benefit is narrow.
- **Work already proceeded?** **No, by design.** Only a boundary document exists
  (`docs/privileged-observer.md`): no kernel source, driver project, build target,
  or binary. Nothing in the default workflow, method inventory, GUI, or plugin ABI
  depends on it. This matches the recommendation; keep it doc-only until the bar
  is met.

### 3.7 Sensitive buffer / library observation

- **Options.** Always capture buffer/key contents; **metadata-only**; explicit
  content opt-in.
- **Recommendation.** **Metadata-only by default** (function identity, sizes,
  algorithm identifiers, return status, call correlation). Any content capture
  must be a separate, per-session, **local-only**, redaction-aware, explicitly
  indicated option with a retention policy and **no remote upload**. Well-known
  cryptographic entry points may be *named* as points of interest; hooking them is
  a later opt-in plugin, not a default.
- **Consequences.** A safe default posture; full-content diagnostics require a
  deliberate switch and a redaction/retention policy, because buffers can contain
  credentials and personal data.
- **Work already proceeded?** **No — not implemented (correctly).** The
  `native-x86/` records are structural metadata only; there is no buffer or key
  capture, and the crypto-library plugins + JVM bridge are a later, gated,
  still-unbuilt step. If content observation is ever built, it must be metadata-only
  by default with content strictly opt-in as above.

### 3.8 Other reserved decisions (for completeness)

These also require a human but were not called out individually in the task.

| Decision | Options | Recommendation | Work proceeded? |
|---|---|---|---|
| Event-IR + evidence-fusion: now or later | build now as the new core; defer behind additive provenance fields | **Defer**; formalize a shared event schema only after two real producers (emulation + live attach) need it | No — additive fields recommended first; the fusion subsystem is deliberately deferred |
| First supported platform set | Windows x64 only; **Windows + Linux x64**; all formats/arches | Windows + Linux x64 user mode first (matches current two x86-64 ABI modules) | Matches current coverage; AArch64/macOS deferred |
| Cross-language producer knowledge | port the Python `Profile` into the JVM modules; a shared producer-hints JSON; leave duplicated | **Shared producer-hints JSON** consumed by both the Python profile layer and the two Kotlin modules | No — proposed only |
| Dependency distribution | bundle everything; download at runtime; **bundle GUI/runtime, user supplies Ghidra** | Bundle GUI/runtime; user supplies optional Ghidra | No — proposed only |

---

## 4. Suggested merge order for the draft PRs

The order deliberately establishes **truthful docs and lowered setup friction
before** adding more front ends or observers. Docs branches are mergeable now
(owner sign-off aside); code branches merge only after their review gates clear.

1. **Docs first — #2, #3, #5 (+ this report).** Docs-only; they change no runtime
   behavior and set the contracts and honest labels everything else references.
   Merge in any order among themselves.
2. **#6 — doctor / setup / getting-started.** After its **7 must-fix items** are
   resolved. It removes the largest usage barrier and is a prerequisite for a
   good first-run experience.
3. **#4 — generic-first discovery.** As a **draft / development merge**, not as
   the default release path. It proves the generic front door (ELF verified).
4. **#8 — Swing desktop viewer.** After the CLI/event contracts it consumes are
   stable; visual fixes are already applied.
5. **#9 — live attach.** Kept an **opt-in preview**; the default `recover` path
   stays on startup `-agentpath`.
6. **#7 — native-x86 core + plugin ABI.** After its **must-fix items** are fixed,
   and only as a **developer preview**.

### What must not be merged / promoted until its review says so

- **#4 must not become the default release path** until the unnamed **count-only
  positional mis-binding** is closed (it silently binds a stack table to the first
  class with a matching native-method count); PE (`.dll`) and Mach-O loading paths
  should also be proven by committed fixtures.
- **#6 must not merge** until the missing `capstone` dependency, the unnecessary
  repo-wide JDK 17→21 bump, the native-artifact readiness/idempotence checks, the
  warnings-as-blocking bug, the non-zero no-argument exit, the undocumented Windows
  `bash` prerequisite, and the overstated readiness/output claims are addressed.
- **#7 must not be treated as a stable ABI or shipped beyond a developer preview**
  until the minor-version negotiation memory-overwrite and the `process_id`
  mislabeling are fixed and the lifecycle/transport docs are narrowed to what is
  enforced.
- **#9 must stay an opt-in preview**; it must not be promoted to the default
  `recover` path and must not claim entry/exit/locals/exception coverage unless the
  per-capability record reports it available.
- **No branch may label output "restored" from an inspection-only or verifier-only
  artifact**, and the default output policy must not be flipped, until the meaning
  of "restored" and the partial-output policy (§3.1) are decided.
- **Sensitive buffer/library-content capture and any privileged observer must not
  be built** until their human decisions (§3.6, §3.7) are made.

---

## 5. Explicitly out of scope / not done

The following are **not implemented anywhere** in these branches, exist only as
boundary or "future plugin" documentation, and must not be built before their
corresponding human decisions are made:

- **Real user-mode cryptographic-library instrumentation with content capture.**
  Well-known entry points may be *named* as points of interest; the crypto-library
  plugins and the JVM bridge are a later, gated, unbuilt step. Default remains
  metadata-only.
- **Kernel driver / privileged observer implementation.** Documentation-only
  boundary (`docs/privileged-observer.md`): no kernel source, driver project,
  build target, or binary. Default is user mode; the project ships no signed
  driver.
- **Any Web / browser interface.** Explicitly vetoed. The only UI is the optional
  read-only desktop viewer (#8); the CLI remains the sole automation contract.

This report itself implements no product feature and is docs-only.
