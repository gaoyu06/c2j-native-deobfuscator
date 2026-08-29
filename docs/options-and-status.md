# Options and status report for JNI-native recovery platform work

> Status checked against GitHub on 2026-08-29. Pull requests #2 through #12 are
> all open, unmerged drafts. This report is documentation only; it does not
> implement or promote a product feature.
>
> Terminology in this report is deliberately neutral: JNI-native transpiled JAR
> recovery, JVMTI, process inspection, library instrumentation, plugin ABI, and
> privileged observer.

## Executive recommendation

Keep the command-line recovery path as the automation contract. Merge truthful
documentation and setup work first, then add the generic discovery path only as
a development draft. Layer the optional desktop work and JVMTI attach preview
after their dependencies. Treat native-x86 as a preview draft rather than a
product feature, and merge the privileged-observer userspace preview last.

Nothing in the current drafts justifies making generic discovery, live attach,
native-x86, or privileged observation a default release path.

## Pull request status and shipping verdicts

“Can ship” below means only within the stated draft or documentation scope. It
does not mean that a draft is merged, that a preview is a default, or that owner
review can be skipped.

| PR | Scope and current verdict | Can ship? | Is review still needed? |
|---:|---|---|---|
| **#2** | Design-theory assessment and PR sequence; documentation only and mergeable as documentation. | **Yes, as docs.** | Owner documentation sign-off only. |
| **#3** | Genericity audit; documentation only. | **Yes, as docs.** | Owner factual spot-check only. |
| **#4** | Generic-first discovery at `d6d2637a8aee382c409844603a0631f4197d6e1f`. In addition to the x86-64 formats, committed fixtures now prove real AArch64 ELF and section-header-removed ELF mapped from `PT_LOAD`; independent review confirmed the AArch64 image and zero section headers. Pytest covers at least 23 introspection-and-merge cases, and the implementer reports 31 passing in the full suite. | **Yes: ship-as-draft-dev; not as the default release.** | Yes before default promotion. Mach-O arm64, 32-bit ARM, and encrypted or shuffled tables remain unproven. |
| **#5** | Platform plan selecting Swing + FlatLaf and recording reserved decisions; documentation only. | **Yes, as docs.** | Owner documentation sign-off only. |
| **#6** | `doctor`, setup scripts, launchers, and getting-started material. JDK 17 is retained. | **Yes, as a draft.** | Normal merge review remains; no JDK migration is implied. |
| **#7** | Native-x86 process inspection, library instrumentation, and plugin ABI at `8b9231c145e80acbc723fbc893d072398cba143b`, after multiple must-fix rounds. | **Yes, as a preview draft only.** | Yes for later promotion, broader platform support, ABI trust, and transport decisions. The current preview verdict is supported by the completed review rounds and smoke evidence. |
| **#8** | Optional Swing + FlatLaf artifact viewer. The visual pass is complete. The desktop module uses JDK 21 while the repository baseline remains JDK 17. | **Yes, as an optional desktop draft.** | Yes, principally for the JDK 21 module boundary and normal merge review. |
| **#9** | Opt-in JVMTI attach at `f7664e46f89b83bc6ffb6c3680193412c8cbff36`. Common attach refusals are classified, there is no stealth or bypass behavior, and default recovery remains startup `-agentpath`. | **Yes: ship-as-preview-draft.** | `allowAttachSelf=false` warns rather than hard-refusing the external CLI; `cross-user` and `not-a-jvm` failures print `attach failed (reason=…)`; pytest reports 55 passed. Review remains required before capability or default-policy expansion. |
| **#10** | This options and status report; documentation only. | **Yes, as docs.** | Owner accuracy and decision sign-off. |
| **#11** | Optional privileged observer at `dc30188118a6579c024978fa9ff52ca154012170`, with a versioned plugin ABI and Linux maps backend. It is default-off userspace code with no kernel files. | **Yes: ship-as-preview-userspace.** | Yes for later promotion and merge-order integration with #7. It is not a kernel feature, and the default remains **no**. |
| **#12** | Desktop live-attach/listen GUI at `e07275c1dc0500db3afe79b78792835f510c4a35`, based on PR #8. The must-fixes cover clipping, honest Run disabling when the attach CLI is absent, `outcomeFor` tests, the `allowAttachSelf` warning, and manifest-derived `bindingGaps`; visual shots 07–12 are preview-ok. | **Yes: ship-as-preview after #8.** | Yes for integration review after #8. An enabled attach Run also needs the #9 CLI; the GUI does not replace the CLI. |

## Current evidence and boundaries

### Generic-first discovery (#4)

- The reviewed revision is
  `d6d2637a8aee382c409844603a0631f4197d6e1f`.
- Committed x86-64 fixtures exercise real PE, Mach-O, stripped ELF without
  `.symtab`, and exports-only ELF images.
- Committed fixtures also exercise a real AArch64 ELF and a
  section-header-removed ELF mapped from `PT_LOAD`.
- Independent review confirmed that the former is a real AArch64 ELF and the
  latter has zero section headers.
- Pytest covers at least 23 introspection-and-merge cases; the implementer
  reports 31 passing in the full suite.
- Ambiguous count-only matching is represented with `bindingGaps`; it is not
  silently treated as a complete binding.
- The branch can ship as a draft/development path.
- The `recover` default is unchanged.
- It is not the default release path.
- Mach-O arm64, 32-bit ARM, and encrypted or shuffled tables remain unproven.

The consequence is deliberate: developers can continue validating the generic
path without presenting incomplete platform coverage as a released default.

### Setup and launchers (#6)

- The branch can ship as a draft.
- The repository baseline remains JDK 17.
- Desktop-specific JDK 21 requirements do not move this setup path to JDK 21.

This keeps the baseline stable while allowing the optional desktop module to
carry an explicit module-local toolchain requirement.

### Native-x86 preview (#7)

The reviewed preview revision is
`8b9231c145e80acbc723fbc893d072398cba143b`.

- `bash native-x86/smoke-test.sh` passes sections 1–14.
- Observation is metadata-only.
- Live register metadata is limited to RIP and RSP.
- Command-line integer parsing is strict.
- A live-operation error fails the operation and restores the target state.
- Multi-threaded targets refuse live operation and fall back to read-only
  inspection.
- Windows live operation is not shipped.
- No kernel component is shipped.
- `note.text` is constrained by policy and a 512-byte cap. This is a policy and
  bounded-record decision, not a claim of structural impossibility.

PR #7 and PR #11 overlap on `docs/privileged-observer.md`. PR #7 stopped editing
that file, but the branch histories still make this a merge-order concern.
Merge #7 after the main documentation set and merge #11 last.

These facts support **ship-as-preview-draft**, not a stable ABI claim or product
feature claim.

### Optional desktop work (#8 and #12)

- PR #8’s visual pass is complete.
- PR #8 is an optional artifact viewer and does not replace the CLI.
- Its module requires JDK 21 while the repository baseline remains JDK 17.
- PR #12 is reviewed at
  `e07275c1dc0500db3afe79b78792835f510c4a35` and remains stacked on PR #8.
- PR #12 fixed clipping, disables Run honestly when the attach CLI is absent,
  tests `outcomeFor`, surfaces the `allowAttachSelf` warning, and derives
  `bindingGaps` from the manifest.
- PR #12’s visual shots 07–12 are preview-ok.
- The attach CLI itself is #9; the GUI does not replace the CLI.

The consequence is that #12 can ship as a preview after #8, and the desktop
toolchain split must remain explicit rather than silently changing the
repository baseline. Its attach Run remains disabled until the #9 CLI is
available.

### JVMTI attach (#9)

- The reviewed revision is
  `f7664e46f89b83bc6ffb6c3680193412c8cbff36`.
- Attach is opt-in and uses the existing same-user plus explicit confirmation
  policy.
- Common attach refusals are classified.
- There is no stealth or bypass behavior.
- On OpenJDK 21, live attach is often bind-only.
- Startup `-agentpath` remains the default recovery path.
- `allowAttachSelf=false` warns and does not hard-refuse the external CLI.
- `cross-user` and `not-a-jvm` failures print `attach failed (reason=…)`.
- The test run reports `pytest`: 55 passed.

The consequence is that attach can ship as a preview, but the GUI and CLI must
display the capability actually obtained and must not imply startup-equivalent
coverage.

### Optional privileged observer (#11)

- The reviewed revision is
  `dc30188118a6579c024978fa9ff52ca154012170`.
- The branch implements a versioned plugin ABI and a Linux maps backend.
- It is an opt-in userspace preview and remains off by default.
- There are no kernel files or shipped kernel components; this is not a kernel
  feature.
- Its `docs/privileged-observer.md` overlap with #7 remains a merge-order issue.

The consequence is **ship-as-preview-userspace**, without creating a kernel
maintenance or deployment commitment. The recommended default remains **no**.

## Human decision table

These are decisions, not implementation questions. Each row records the options,
the recommendation, and the consequence of adopting it.

| Decision | Options | Recommendation | Consequence |
|---|---|---|---|
| Meaning of **“restored”** | Verifier-clean; verifier-clean with coverage evidence; verified coverage plus behavior checks. | Reserve “restored” for verified coverage plus behavior checks. Label lesser results explicitly. | Claims become auditable; existing output labels and acceptance checks may need migration. |
| Default for partial output | Hybrid runnable JAR; inspection-only artifact; strip native resources while stubs remain. | Default to **hybrid** when it can remain runnable; otherwise produce an explicitly labeled **inspection-only** artifact. Do not call either fully restored without the evidence above. | Safer partial results and clearer user expectations, at the cost of retaining native material in hybrid output and maintaining two explicit states. |
| Desktop toolkit | Swing + FlatLaf; JavaFX; Compose Desktop. | **Confirm Swing + FlatLaf.** | Keeps the implemented #8 path and avoids a toolkit restart; the JDK 21 module boundary still requires review against the JDK 17 baseline. |
| Attach policy | Any accessible process; same-user plus explicit confirmation; administrator allowlist. | Keep the already implemented **same-user plus confirmation flag** default; permit stricter deployment policy. | Preserves explicit consent and a narrow access boundary; does not remove JVM capability limits. |
| Native-x86 repository placement | Keep isolated in this repository; split into a separate repository. | Keep it in-repo while enforcing the existing isolation, and revisit only if release cadence or ownership diverges. | Shared review and CI remain simple; strict boundaries preserve a later split option. |
| Plugin trust and transport | Trusted in-process plugins; isolated plugins with an out-of-process protocol; support both. | Keep the ABI versioned and preview-only, define trust explicitly, and freeze transport only after real plugin evidence exists. | Avoids prematurely freezing unsafe trust or transport assumptions; stable compatibility is deferred. |
| Privileged observer default | Default component; opt-in userspace preview; no shipped component. | **Default: no.** Permit #11 only as an explicitly enabled userspace preview; do not represent it as a kernel feature. | Preserves the versioned ABI and Linux maps evidence without creating kernel support or default deployment risk; promotion still requires separate evidence and review. |
| Cryptographic library observation | Content capture; metadata-only; metadata by default with content opt-in. | **Metadata-only.** | Preserves useful call, size, status, and correlation evidence without collecting sensitive content. |

## What is still not true

- The generic path is **not** the default release path.
- Live attach is **not** equivalent to startup instrumentation and is often
  bind-only on OpenJDK 21.
- Live attach does **not** provide stealth or bypass behavior.
- The GUI does **not** replace the CLI as the automation or recovery contract.
- Native-x86 is a **preview draft**, not a product feature.
- The privileged observer is an **opt-in userspace preview**, not a kernel
  feature; it has no kernel files and is not enabled by default.
- None of PRs #2–#12 is merged; GitHub currently shows every one as an open
  draft.

## Recommended merge order

1. **#2 / #3 / #5 / #10** — documentation first, in any order within the group.
2. **#6** — setup, `doctor`, launchers, and getting started; keep JDK 17.
3. **#4** — draft/development generic discovery, explicitly not the default.
4. **#8** — optional desktop artifact viewer.
5. **#12** — only after #8, because #12 is based on #8’s branch.
6. **#9** — opt-in JVMTI attach preview.
7. **#7** — native-x86 preview, after the main documentation set.
8. **#11** — last, because of the `docs/privileged-observer.md` overlap with #7.

## Promotion gates

- #4 now has committed x86-64 PE, Mach-O, stripped-ELF-without-`.symtab`, and
  exports-only ELF fixtures, plus real AArch64 ELF and
  section-header-removed-ELF fixtures. Default promotion remains blocked on
  Mach-O arm64, 32-bit ARM, and encrypted or shuffled table evidence.
- #7 needs explicit plugin trust and transport decisions, additional platform
  evidence, and a separate promotion review before it can move beyond preview.
- #8/#12 must keep their JDK 21 requirement module-local unless the repository
  separately approves a baseline migration.
- #12 is preview-ok at the reviewed revision after its must-fixes, but it still
  depends on #8. An enabled attach Run needs the #9 CLI; without that CLI, Run
  must remain disabled.
- #9/#12 must report actual attach capabilities and retain startup `-agentpath`
  as the default recovery path. #9 now warns for `allowAttachSelf=false` rather
  than hard-refusing the external CLI, and prints reason codes for `cross-user`
  and `not-a-jvm` failures.
- #11 is a userspace preview with a versioned plugin ABI and Linux maps backend.
  It must remain default-off, and any promotion or kernel scope requires a
  separate decision backed by new evidence.

This report records current choices and consequences; it does not itself change
any runtime default.
