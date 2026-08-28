# Cross-check against the independent review

This plan (`platform-plan.md` / `decisions.md`) was written as a **second,
independent** opinion. A prior review lives on another branch
(`cursor/design-theory-review-465c`, commit `2ea0ca0`) as
`docs/design-theory-review.md` and `docs/pr-sequence.md`. This file records,
briefly, where the two agree, where they disagree, and what this plan changes.
The other branch was read but not modified, and its documents were not copied.

Both reviews are docs-only, evidence-based, and reach the **same central
diagnosis**: the "obfuscator-agnostic core" claim is only partly supported by
the code, because several producer/ABI/decompiler/OS assumptions live outside
`Profile`. The disagreements are about **sequencing, scope of new abstraction,
and a couple of additions**, not about the diagnosis.

## Agreements (verified independently against the same code)

| Topic | Both plans conclude | Evidence I re-checked |
|---|---|---|
| Core claim is over-broad | `generic` profile embeds a strategy + producer text; a new harvest strategy needs core edits | [`profile.py:291-298`](../py/binary_introspect/binary_introspect/profile.py#L291-L298), [`jni_tables.py:262-286`](../py/binary_introspect/binary_introspect/jni_tables.py#L262-L286), [`adding-obfuscator-profile.md:62-77`](adding-obfuscator-profile.md#L62-L77) |
| ABI boundary is the one that works | `nMethods` register is a clean per-ABI fact | [`profile.py:68-70`](../py/binary_introspect/binary_introspect/profile.py#L68-L70) |
| Windows-only cache scanner bypasses the ABI layer | Adding an ABI module won't make it portable | [`cache_table.py:40-41`](../py/binary_introspect/binary_introspect/cache_table.py#L40-L41), [`cache_table.py:75-92`](../py/binary_introspect/binary_introspect/cache_table.py#L75-L92) |
| Ghidra scripts overclaim | `ApplyJ2CDataTypes` only defines `jvalue`; `ExtractRegisterNatives` scans data sections though the family builds on the stack | [`ApplyJ2CDataTypes.java:21-44`](../ghidra/scripts/ApplyJ2CDataTypes.java#L21-L44), [`ExtractRegisterNatives.java:100-107`](../ghidra/scripts/ExtractRegisterNatives.java#L100-L107), [`jni_tables.py:18-22`](../py/binary_introspect/binary_introspect/jni_tables.py#L18-L22) |
| Static-approach doc is stale | "not started" + 100% rows contradict the shipped subset | [`static-reverse-approach.md:1-14`](static-reverse-approach.md#L1-L14), [`static-reverse-approach.md:348-368`](static-reverse-approach.md#L348-L368), [`README.md:151-166`](../README.md#L151-L166) |
| Attach gap | No `Agent_OnAttach`; init depends on `VMInit`; evolve the one agent | [`agent.cpp:106-117`](../native/src/agent.cpp#L106-L117), [`agent.cpp:251-312`](../native/src/agent.cpp#L251-L312) |
| Dynamic path picks one trace | Longest invocation is chosen per method | [`trace-to-bytecode/Main.kt:49-57`](../jvm/trace-to-bytecode/src/main/kotlin/j2c/tracetobc/Main.kt#L49-L57) |
| UI: Web vetoed → Swing + FlatLaf | Same pick, independently justified | [`platform-plan.md` §4](platform-plan.md) |
| Native module: no Java types in public ABI; crypto observers as plugins; metadata-only default | Same | [`platform-plan.md` §6](platform-plan.md) |
| Privileged observer: later, optional, user-enabled, no signed driver | Same | [`platform-plan.md` §8](platform-plan.md) |
| Output honesty: hybrid vs restored vs inspection-only labels | Same direction | `decisions.md` B1/B2 |

## Disagreements and changes

| # | Where the other review lands | Where this plan lands | Why / consequence |
|---|---|---|---|
| 1 | Sequences a new evidence/status schema + generated JNI catalogue (its PR 1) and generic inventory (its PR 2) **before** most user value; inventory PR is gated behind the schema PR. | **Reorders.** Ship `doctor` (A1) and a generic inventory that **reuses today's artifacts** (A2) first; do not gate inventory behind a new schema. Formalize a shared event schema only after two producers need it. | Avoids authoring a large schema before real producers exist (premature abstraction). Faster barrier reduction. Trade-off: a fully unified schema arrives later. (`decisions.md` B5.) |
| 2 | Makes the **normalized event IR + evidence fusion** a mainline, early subsystem (its PRs 1 and 5) — a substantial new core. | **Defers** it to the later C-series and marks it an explicit human decision (B5). Adds **additive provenance/confidence fields** to existing artifacts first (A6). | Lower blast radius for the same truthfulness win; the big subsystem lands once it is justified by two real producers. |
| 3 | Ghidra: recommends code-level adapter isolation + JSON-parser replacement as the isolation step. | **Splits it in time.** Documentation demotion + honest capability labels are immediate and decision-free (A4); the code-level adapter isolation and parser replacement follow later (C4). | Removes the overclaim now without a refactor; the refactor is scheduled, not skipped. |
| 4 | Notes loader/strip/detector knowledge leaking across modules, but does not propose a concrete cross-language fix. | **Adds** a shared **producer-hints JSON artifact** consumed by both the Python profile layer and the two Kotlin modules (B10 / C3). | Directly removes the cross-language duplication ([`jar-parser/Main.kt:111-159`](../jvm/jar-parser/src/main/kotlin/j2c/jarparser/Main.kt#L111-L159), [`class-rebuilder/Main.kt:217-243`](../jvm/class-rebuilder/src/main/kotlin/j2c/classrebuilder/Main.kt#L217-L243)) rather than only naming it. New shared schema to own. |
| 5 | Organizes around "evidence about a method" as the abstraction to build. | **Same idea, different emphasis:** names the generic-first *front door* concretely (emulation `recover` + dynamic + inventory, because they rest on JNI ABI invariants) and demotes the pseudo-C lifter, so the reorder is derived from which parts are already generic. | Same destination; this plan derives the PR order from which components are already ABI-generic today. |
| 6 | Default output policy change is embedded in its fusion PR (its PR 5). | **Separates** the additive fields (A6, no decision) from the **default policy flip** (C2, gated by B1/B2). | Keeps the decision-free part shippable immediately; the behavior change waits for a human. |

## Net

This plan endorses the other review's diagnosis and most of its endpoints (UI,
attach, native-module boundary, privileged-observer caution, output honesty). It
differs mainly by **front-loading decision-free, artifact-reusing value** and
**deferring the large event-IR/fusion rebuild** behind an explicit human
decision, and it **adds** a shared cross-language producer-hints artifact. If a
maintainer prefers to commit to the unified evidence model up front, the other
review's ordering is the alternative; decision **B5** in
[`decisions.md`](decisions.md) is exactly that fork.
