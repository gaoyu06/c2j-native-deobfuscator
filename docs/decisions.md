# Decisions (ADR-style)

Companion to [`platform-plan.md`](platform-plan.md). Each record states whether
the decision is **made by this plan** (safe to act on now) or **reserved for a
human** (a maintainer must choose before the dependent code lands). Records use a
short Architecture-Decision-Record shape: context, decision, status,
consequences.

Terminology follows the neutral vocabulary used throughout: JNI-native
transpiled JARs, bytecode restoration, JVMTI, process inspection, library
instrumentation, plugin ABI, privileged observer. No product or model names.

---

## Part 1 — Decisions this plan makes (no human needed)

These are low-risk because they are docs-only or purely additive, do not change
any default recovery behavior, and are reversible.

### D1. Adopt a generic-first framing as the organizing principle

- **Context.** The reusable kernel (JNI ABI constants, `RegisterNatives`
  semantics, versioned artifacts, ASM emitter) generalizes across the family;
  the pseudo-C static lifter is the most producer/toolchain-coupled component
  ([`platform-plan.md` §1](platform-plan.md)).
- **Decision.** Treat "a method and the evidence about it" as the unit of work,
  and make the JNI-ABI-derived inventory the front door. Documentation and new
  commands are organized around this framing.
- **Status.** Made by this plan.
- **Consequences.** New work (A1–A2) targets the generic layer first; the static
  path is documented as one optional evidence producer.

### D2. Ship value before abstraction

- **Context.** A full event-IR/fusion rebuild before user value risks schema
  churn once real producers land.
- **Decision.** Front-load decision-free, additive PRs (A1–A6). Defer the
  event-IR/fusion subsystem (see **D14 / B5**).
- **Status.** Made by this plan (the *timing*; the subsystem itself is B5).
- **Consequences.** Faster usability wins; a unified cross-path fusion view
  arrives later than in the other review.

### D3. Provide a `doctor` / setup preflight command

- **Context.** Setup spans JDK 21, Python 3.11, `uv`, `lief`, `capstone`,
  `tree-sitter-c`, `unicorn`, and optional Ghidra 11.x
  ([`ARCHITECTURE.md:152-163`](ARCHITECTURE.md#L152-L163),
  [`README.md:256-270`](../README.md#L256-L270)); a new user cannot easily tell
  what works on their machine.
- **Decision.** Add an additive, read-only diagnostics command that reports
  present/missing dependencies and per-path runnability, with an optional
  bootstrap wrapper.
- **Status.** Made by this plan (PR A1).
- **Consequences.** Directly lowers the usage barrier; no network writes; must
  never misreport availability.

### D4. Add a generic method-inventory command that reuses existing artifacts

- **Context.** Inventory can be derived from `classes.json` native declarations,
  `binary.json` exports/`RegisterNatives`, and emulation `recover` — all
  standards-derived.
- **Decision.** Add an `inventory` command producing merged
  `(owner, name, descriptor, address, module, source, confidence)` records,
  merging only on stable identity, never on equal method counts.
- **Status.** Made by this plan (PR A2). Not yet the default rebuild input.
- **Consequences.** A generic front door that works before any producer-specific
  machinery; requires PE/ELF fixtures including unsupported cases.

### D5. Build the desktop viewer read-only first, as a CLI client

- **Context.** The GUI must not become a second orchestrator; the CLI is the
  automation contract.
- **Decision.** First GUI PR (A3) is a read-only artifact viewer that launches
  CLI stages and renders their JSON. No recovery logic in the GUI.
- **Status.** Made by this plan (PR A3). (Toolkit choice is **B3**.)
- **Consequences.** Keeps recovery logic in one place; the GUI can lag CLI schema
  changes safely.

### D6. Demote the Ghidra static path in documentation and add honest labels

- **Context.** `static-reverse-approach.md` says "not started," locks Ghidra as
  the only static path, and lists 100% coverage
  ([`static-reverse-approach.md:1-14`](static-reverse-approach.md#L1-L14),
  [`static-reverse-approach.md:348-368`](static-reverse-approach.md#L348-L368)),
  while the shipped lifter is a best-effort subset with stub fallback
  ([`README.md:151-166`](../README.md#L151-L166)); the architecture diagram omits
  emulation ([`ARCHITECTURE.md:18-60`](ARCHITECTURE.md#L18-L60)).
- **Decision.** Correct these documents, mark the static path optional /
  experimental, add emulation to the diagram, and add cheap `--capabilities`
  output where trivial. No recovery-behavior change.
- **Status.** Made by this plan (PR A4).
- **Consequences.** Removes the largest overclaim; sets up the later code-level
  adapter isolation (**C4**) without doing it yet.

### D7. Publish the plugin ABI and native-x86 public surface as design docs first

- **Context.** A neutral native module must never leak Java/JNI types; the
  cheapest place to enforce that is on paper, before code.
- **Decision.** Ship design-only docs for a versioned C plugin ABI and the
  `native-x86` public surface (opaque handles, event kinds, boundary rules, a
  Java/JNI-type rejection rule).
- **Status.** Made by this plan (PR A5). Implementation is **C6** (gated by
  B7/B8).
- **Consequences.** Locks the boundary early; no runtime commitment yet.

### D8. Add provenance/confidence fields additively and offer an opt-in hybrid output

- **Context.** Today's rebuilder can strip the loader/blob while methods remain
  stubbed ([`class-rebuilder/Main.kt:217-243`](../jvm/class-rebuilder/src/main/kotlin/j2c/classrebuilder/Main.kt#L217-L243),
  [`class-rebuilder/Main.kt:245-276`](../jvm/class-rebuilder/src/main/kotlin/j2c/classrebuilder/Main.kt#L245-L276)),
  and artifacts do not carry source/confidence.
- **Decision.** Add backward-readable `source` / `confidence` /
  `capability` fields to `schemas/*.schema.json` and populate them; add an
  *opt-in* hybrid runnable JAR mode. Leave the *default* output policy unchanged
  here (its change is **B2**).
- **Status.** Made by this plan (PR A6).
- **Consequences.** Truthful artifacts without breaking readers; the default
  behavior change is deferred to a human decision.

### D9. Evolve the single JVMTI agent rather than adding a second one

- **Context.** The agent has `Agent_OnLoad`/`Agent_OnUnload` but no
  `Agent_OnAttach`, and initializes on `VMInit`
  ([`agent.cpp:106-117`](../native/src/agent.cpp#L106-L117),
  [`agent.cpp:251-312`](../native/src/agent.cpp#L251-L312)).
- **Decision.** Design attach as an evolution of this agent (shared idempotent
  initializer, `Agent_OnAttach`, lazy per-thread install), not a competing agent
  ([`platform-plan.md` §5](platform-plan.md)).
- **Status.** Made by this plan (design); implementation is **C1** (gated by B4).
- **Consequences.** One code path to maintain; avoids two agents fighting over
  the JNI function table.

### D10. Keep the CLI as the sole automation contract

- **Context.** Goal 4.
- **Decision.** Every capability is a CLI command with versioned JSON in/out; GUI
  and plugins are clients.
- **Status.** Made by this plan.
- **Consequences.** Stable automation surface; GUI/plugins cannot bypass it.

### D11. Neutral-by-default native observation

- **Context.** Goal 6 and safety.
- **Decision.** Native observation defaults to metadata-only; the public
  `native-x86` API carries no Java/JNI types; crypto-library observers are opt-in
  plugins.
- **Status.** Made by this plan (design). Sensitive-content policy is **B6**.
- **Consequences.** Safe default posture; buffer/key capture requires an explicit
  later opt-in.

---

## Part 2 — Decisions reserved for a human

These commit the project to expectations, security policy, toolchains, or
long-term maintenance obligations. Each maps to a **B#** row in
[`platform-plan.md` §7](platform-plan.md).

### B1. Definition of "restored"

- **Options.** (a) decompilable; (b) verifier-clean; (c) verifier-clean + method
  coverage + behavior checks.
- **Recommendation.** (c), with separate `hybrid` and `inspection-only` labels.
- **Why a human.** It sets the core promise of the tool and downstream
  compatibility expectations.
- **Consequences.** Higher bar per "restored" claim; clearer user trust.

### B2. Default partial-output policy

- **Options.** (a) strip native resources anyway; (b) hybrid runnable JAR by
  default; (c) evidence-only.
- **Recommendation.** (b) default; (c) when safe retention is impossible.
- **Why a human.** It trades output simplicity against runtime correctness and
  changes today's strip-by-default behavior.
- **Consequences.** Partial results stay runnable; the default artifact is
  slightly more complex.

### B3. Desktop toolkit

- **Options.** Swing + FlatLaf; JavaFX; Compose Desktop.
- **Recommendation.** Swing + FlatLaf (evidence in [`platform-plan.md` §4](platform-plan.md)).
- **Why a human.** Commits the project to a UI toolchain and packaging surface.
- **Consequences.** Small, JDK-native footprint; imperative UI style.

### B4. Attach policy

- **Options.** any accessible PID; same-user + explicit PID confirmation;
  explicit allowlist.
- **Recommendation.** Same-user + explicit PID confirmation; allow stricter
  enterprise policy.
- **Why a human.** Process access is a security/product policy, not an
  implementation detail.
- **Consequences.** Safe default; shared-host power users need extra config.

### B5. Event-IR + evidence-fusion subsystem: now or later?

- **Options.** (a) build it now as the new core (the other review's approach);
  (b) defer — add provenance fields to existing artifacts first and formalize a
  shared event schema only after two real producers (emulation + live attach)
  need it.
- **Recommendation.** (b) later.
- **Why a human.** It is the largest architectural commitment and the main point
  where the two plans differ.
- **Consequences.** Less up-front schema churn and faster user value now; a
  unified fusion view lands later. This is deliberately the opposite ordering
  from the other review, which sequences the schema/JNI-catalogue/fusion work
  ahead of most user-facing value.

### B6. Sensitive native buffers

- **Options.** always capture; metadata-only; explicit content opt-in.
- **Recommendation.** metadata-only default; per-session, local-only, redacted
  content opt-in; no remote upload.
- **Why a human.** Buffer contents can include credentials and personal data.
- **Consequences.** Safe default; full-content diagnostics need a deliberate
  switch and a retention/redaction policy.

### B7. Plugin ABI stability

- **Options.** unstable C++; versioned C; language-specific in-process API.
- **Recommendation.** versioned C ABI; freeze only after two real plugins exist.
- **Why a human.** ABI compatibility is a long-term maintenance obligation.
- **Consequences.** Stable extension point; the freeze is evidence-gated by two
  consumers.

### B8. First supported platform set

- **Options.** Windows x64 only; Windows + Linux x64; all formats/architectures.
- **Recommendation.** Windows + Linux x64 user mode first.
- **Why a human.** Support scope must match maintainer and CI capacity; current
  ABI modules are the two x86-64 conventions
  ([`platform-plan.md` §1.2](platform-plan.md)).
- **Consequences.** Matches present coverage; AArch64/macOS deferred until
  demanded.

### B9. Privileged observer

- **Options.** foundation; early parallel work; later optional gate.
- **Recommendation.** later optional gate, after measured user-mode visibility
  gaps; the user enables OS debug/test-signing; **no signed driver is shipped**;
  default workflows stay user mode.
- **Why a human.** System-level support, safety, and operational costs require
  maintainer ownership.
- **Consequences.** Keeps system-wide risk out of the default path; a real gap
  must be demonstrated before any prototype.

### B10. Cross-language producer knowledge

- **Options.** port the Python `Profile` into the JVM modules; a single shared
  producer-hints JSON artifact consumed by both languages; leave it duplicated.
- **Recommendation.** shared producer-hints JSON, consumed by the Python profile
  layer and the two Kotlin modules.
- **Why a human.** It changes a cross-cutting internal contract and adds a schema
  to own.
- **Consequences.** Removes duplicated loader/strip/detector knowledge
  ([`jar-parser/Main.kt:111-159`](../jvm/jar-parser/src/main/kotlin/j2c/jarparser/Main.kt#L111-L159),
  [`class-rebuilder/Main.kt:217-243`](../jvm/class-rebuilder/src/main/kotlin/j2c/classrebuilder/Main.kt#L217-L243));
  one more shared schema to maintain. This is an addition beyond the other
  review, which notes the leakage but does not propose a shared cross-language
  artifact.

### B11. Dependency distribution

- **Options.** bundle everything; download at runtime; bundle GUI/runtime and
  have the user supply optional Ghidra.
- **Recommendation.** bundle GUI/runtime; user supplies Ghidra.
- **Why a human.** Licensing, package size, updates, and platform signing need
  project-owner review.
- **Consequences.** Sane package size; the static path stays a bring-your-own-tool
  option.

---

## Decision index

| ID | Title | Status |
|---|---|---|
| D1 | Generic-first framing | Made by this plan |
| D2 | Ship value before abstraction | Made by this plan |
| D3 | `doctor` / setup preflight | Made by this plan (A1) |
| D4 | Generic method inventory | Made by this plan (A2) |
| D5 | Read-only GUI viewer first | Made by this plan (A3) |
| D6 | Ghidra demotion in docs | Made by this plan (A4) |
| D7 | Plugin/native-x86 design docs first | Made by this plan (A5) |
| D8 | Additive provenance + opt-in hybrid | Made by this plan (A6) |
| D9 | Evolve the single JVMTI agent | Made by this plan (design; C1) |
| D10 | CLI as sole automation contract | Made by this plan |
| D11 | Neutral-by-default native observation | Made by this plan (design) |
| B1 | Meaning of "restored" | Reserved for human |
| B2 | Default partial-output policy | Reserved for human |
| B3 | Desktop toolkit | Reserved for human |
| B4 | Attach policy | Reserved for human |
| B5 | Event-IR + fusion now vs later | Reserved for human |
| B6 | Sensitive native buffers | Reserved for human |
| B7 | Plugin ABI stability | Reserved for human |
| B8 | First supported platform set | Reserved for human |
| B9 | Privileged observer | Reserved for human |
| B10 | Cross-language producer knowledge | Reserved for human |
| B11 | Dependency distribution | Reserved for human |
