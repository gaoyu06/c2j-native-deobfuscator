# Options and status report for JNI-native recovery platform work

> Status checked against GitHub on 2026-08-29 after wrap-up. Pull requests
> #2 through #13 are closed. Their code is on `main` at
> `591d5e2d3157bcbddc7be2a6b72baf53ec8728e5`. GitHub recorded #2–#11 as
> merged. #12 and #13 were stacked on earlier desktop branches, so GitHub
> could not retarget them onto `main`; both heads were already ancestors of
> `main` and the PRs were closed after the local stack merge. This report is
> documentation only; it does not implement or promote a product feature.
>
> Terminology in this report is deliberately neutral: JNI-native transpiled JAR
> recovery, JVMTI, process inspection, library instrumentation, plugin ABI, and
> privileged observer.
>
> Product-level architecture and the feature catalog:
> [overview.md](overview.md) ([中文](overview.zh-CN.md)).

## Executive recommendation

Keep the command-line recovery path as the automation contract. The
documentation, setup, generic-discovery draft, optional desktop stack, JVMTI
attach preview, native-x86 preview, and privileged-observer userspace preview
have landed on `main`. None of those landings change a default release path.

Nothing on `main` justifies making generic discovery, live attach, native-x86,
or privileged observation a default release path.

## Pull request status and shipping verdicts

“Can ship” below records the review verdict that justified the merge. It does
not mean a preview is a default, or that later promotion review can be skipped.

| PR | Scope and landed verdict | On `main`? | Later review still needed? |
|---:|---|---|---|
| **#2** | Design-theory assessment and PR sequence; documentation only. | **Yes**, merged. | Owner documentation sign-off only. |
| **#3** | Genericity audit; documentation only. | **Yes**, merged. | Owner factual spot-check only. |
| **#4** | Generic-first discovery at `eddfb86e590d08e4e392f13179edf01e9977cfd0`. A committed genuine PE x86-64 DLL makes the named `j2cc` detector fire on a real image; a Microsoft x64 shared-dispatch harvest recovers two tables from one `RegisterNatives` site; a visible-but-unreadable table is recorded as an honest gap; schemas accept `unreadable-table` gaps. The separate generic ELF shared-dispatch proof is unchanged. | **Yes**, merged as draft-dev. | Yes before default promotion. Encrypted, runtime-decrypted, or shuffled *recovery* and unregistered ABIs (MIPS, RISC-V, PE i386 stdcall) remain unproven. |
| **#5** | Platform plan selecting Swing + FlatLaf and recording reserved decisions; documentation only. | **Yes**, merged. | Owner documentation sign-off only. |
| **#6** | `doctor`, setup scripts, launchers, and getting-started material. Offline discovery is documented as `parse-jar` + `inspect-binary` + `merge-manifest`, with Ghidra optional; `recover` still defaults to dynamic recovery. JDK 17 is retained. | **Yes**, merged as draft. | Neither a JDK migration nor an offline `recover` default is implied. |
| **#7** | Native-x86 process inspection, library instrumentation, and plugin ABI at `1817e2d664b0a72269f188cbc4a9ddc342b62f0a`. Linux smoke passes sections 1–15. Windows supports read-only module/export observation, with no live breakpoints. No kernel component is shipped. | **Yes**, merged as preview. | Yes for later promotion, broader platform support, ABI trust, and transport decisions. |
| **#8** | Optional Swing + FlatLaf artifact viewer. The visual pass is complete. The desktop module uses JDK 21 while the repository baseline remains JDK 17. | **Yes**, merged as optional desktop. | Yes, principally for the JDK 21 module boundary. |
| **#9** | Opt-in JVMTI attach at `f7664e46f89b83bc6ffb6c3680193412c8cbff36`. Common attach refusals are classified, there is no stealth or bypass behavior, and default recovery remains startup `-agentpath`. The files also arrived through #13. | **Yes**, already contained by #13 and then recorded as merged. | Review remains required before capability or default-policy expansion. `allowAttachSelf=false` warns rather than hard-refusing the external CLI. |
| **#10** | The pre-merge options report; documentation only. This wrap-up revises that report against landed `main`. | **Yes**, merged; this file is the post-merge refresh. | Owner accuracy and decision sign-off. |
| **#11** | Optional privileged observer at `dc30188118a6579c024978fa9ff52ca154012170`, with a versioned plugin ABI and Linux maps backend. It is default-off userspace code with no kernel files. | **Yes**, merged as preview-userspace. Combined on `main` with #7’s `docs/privileged-observer.md`. | Yes for later promotion. It is not a kernel feature, and the default remains **no**. |
| **#12** | Desktop live-attach/listen GUI at `e07275c1dc0500db3afe79b78792835f510c4a35`. Must-fixes cover clipping, honest Run disabling when the attach CLI is absent, `outcomeFor` tests, the `allowAttachSelf` warning, and manifest-derived `bindingGaps`; visual shots 07–12 are preview-ok. | **Yes**, incorporated by local merge; PR closed (stacked base, not GitHub-button-merged). | The GUI does not replace the CLI. |
| **#13** | Desktop attach wiring at `52f21efa8e3676cf314edda102c2b3b5cb4bca0f`. It merges #9’s attach CLI and `Agent_OnAttach` into the desktop stack so GUI Run works. Relative `-o` values and viewer tailing use the same absolute path, and remaining-stub guidance leads with `dynamic-trace`/`recover`. | **Yes**, incorporated by local merge; PR closed (stacked base, not GitHub-button-merged). | Same preview limits as #9 and #12. |

## Current evidence and boundaries

### Generic-first discovery (#4)

- The landed revision is
  `eddfb86e590d08e4e392f13179edf01e9977cfd0`.
- Committed x86-64 fixtures exercise real PE, Mach-O, stripped ELF without
  `.symtab`, and exports-only ELF images.
- Committed fixtures also exercise a real AArch64 ELF and a
  section-header-removed ELF mapped from `PT_LOAD`.
- A real Mach-O arm64 dylib proves that format and architecture.
- A committed real ELF32 ARM fixture and its tests prove 32-bit ARM ELF
  discovery through the AAPCS32 backend.
- A genuine i386 ELF fixture proves 32-bit x86 discovery through the System V
  cdecl backend, including stack arguments and GOT-relative table addressing.
- `py/binary_introspect/tests/fixtures/jni_dispatch_j2cc.dll`, assembled from
  the committed `jni_dispatch_j2cc.s`, is a genuine PE x86-64 image: it starts
  with `MZ`, LIEF parses it as PE, and its machine value is `0x8664`.
- The named `j2cc` detector fires on that real DLL, reporting
  `analysis.profile == "j2cc"`.
- On that fixture the `shared_dispatch` harvest on the Microsoft x64 backend
  recovers two stack-built tables, with `nMethods` 2 and 3, from a single
  `RegisterNatives` site at `0x1800010ef`; the reported abi is
  `amd64-windows`, and the only `Java_*` exports are
  `Java_com_example_Boot_initClass` and `Java_com_example_Boot_bootstrap`.
- The existing `jni_registrar.dll` fixture still selects `generic`, so the
  named detector is not being applied indiscriminately to PE images.
- The ELF `libjni_dispatch_shared.so` fixture still proves the generic `auto`
  shared-dispatch harvest with `profile=generic`. That proof and the PE
  `j2cc` proof are separate; neither replaces the other.
- Ambiguous count-only matching is represented with `bindingGaps`; it is not
  silently treated as a complete binding, including for each shared-dispatch
  branch.
- On the command line, `inspect-binary` prints `format/arch/profile=`,
  `registry-records`, and `unreadableTables=` on stderr.
  `merge-manifest` prints `bindingGaps=<n> kinds=…`. `bindingGaps` is a
  reported count only; it is not written into `binary.json`.
- A visible-but-unreadable `JNINativeMethod[]` (right stride and `nMethods`,
  garbage name/descriptor bytes) is recorded as a first-class
  `register-natives-unreadable` registry record with a reason such as
  `invalid-method-descriptors`, plus `analysis.unreadableTables` on
  `binary.json`. `manifest-merge` emits an `unreadable-table` binding gap.
  Names and function pointers are not fabricated from the garbage. This is an
  honest gap, not table-content recovery. The fixture is
  `libjni_unreadable_table.so`.
- `schemas/manifest.schema.json` accepts `bindingGaps` as `oneOf`
  `ambiguous-count-only-table` (still requires `candidateClasses` min 2) or
  `unreadable-table` (no `candidateClasses`). `schemas/binary.schema.json`
  declares `analysis.unreadableTables`.
- The `recover` default is unchanged; generic discovery is not the default
  release path.
- Encrypted or runtime-decrypted *content recovery*, shuffled tables, and
  architectures without a registered ABI backend — including MIPS, RISC-V,
  and PE i386 stdcall — remain unproven.

The consequence is deliberate: the generic path is on `main` as draft-dev
without presenting incomplete platform coverage as a released default.

### Setup and launchers (#6)

- The landed setup path is a draft on `main`.
- The repository baseline remains JDK 17.
- Desktop-specific JDK 21 requirements do not move this setup path to JDK 21.
- The documented offline discovery path is `parse-jar` + `inspect-binary` +
  `merge-manifest`; those steps produce a method-discovery manifest rather than
  recovered method bodies.
- Ghidra is an optional later static-recovery step, not a prerequisite for
  offline discovery.
- `recover` continues to default to the dynamic path.

This keeps the baseline stable while allowing the optional desktop module to
carry an explicit module-local toolchain requirement. It also makes offline
discovery visible without changing the established recovery default.

### Native-x86 preview (#7)

The landed preview revision is
`1817e2d664b0a72269f188cbc4a9ddc342b62f0a`.

- `bash native-x86/smoke-test.sh` passes sections 1–15 on Linux.
- Observation is metadata-only.
- Live register metadata is limited to RIP and RSP.
- Command-line integer parsing is strict.
- A live-operation error fails the operation and restores the target state.
- Multi-threaded targets refuse live operation and fall back to read-only
  inspection.
- Windows provides read-only module/export observation; live breakpoints are not
  shipped there.
- No kernel component is shipped.
- `note.text` is constrained by policy and a 512-byte cap. This is a policy and
  bounded-record decision, not a claim of structural impossibility.

PR #7 and PR #11 overlapped on `docs/privileged-observer.md`. The wrap-up merge
combined them on `main`: shipped **userspace** Linux maps module (default off,
both flags required); **no** kernel image or source; kernel backend remains
unimplemented / default **no**.

These facts support **preview**, not a stable ABI claim or product feature
claim.

### Optional desktop work (#8, #12, and #13)

- PR #8’s visual pass is complete and is on `main`.
- PR #8 is an optional artifact viewer and does not replace the CLI.
- Its module requires JDK 21 while the repository baseline remains JDK 17.
- PR #12 landed at
  `e07275c1dc0500db3afe79b78792835f510c4a35` through the desktop stack merge.
- PR #12 fixed clipping, disables Run honestly when the attach CLI is absent,
  tests `outcomeFor`, surfaces the `allowAttachSelf` warning, and derives
  `bindingGaps` from the manifest.
- PR #12’s visual shots 07–12 are preview-ok.
- The attach CLI itself is #9; the GUI does not replace the CLI.
- PR #13 landed at
  `52f21efa8e3676cf314edda102c2b3b5cb4bca0f` and brought #9’s attach CLI and
  `Agent_OnAttach` into that stack so GUI Run works.
- A relative `-o` is resolved before launch so the attach process and the
  viewer tail use the same absolute path.
- Shot `13-attach-ready` is the visual preview evidence.
- When methods remain as stubs, the next-step copy leads with capturing more of
  the run through `dynamic-trace`, startup `-agentpath`, or one-shot `recover`.
  It presents a Ghidra `static-reverse` lift only as an optional last resort.

The desktop toolchain split must remain explicit rather than silently changing
the repository baseline. The absolute-path fix removes the relative-output
launch/tail mismatch, and the revised stub guidance puts higher-fidelity run
capture ahead of static lifting; neither changes the preview verdict.

### JVMTI attach (#9)

- The landed revision is
  `f7664e46f89b83bc6ffb6c3680193412c8cbff36`.
- Attach is opt-in and uses the existing same-user plus explicit confirmation
  policy (`--i-own-this-process`).
- Common attach refusals are classified.
- There is no stealth or bypass behavior.
- On OpenJDK 21, live attach is often bind-only.
- Startup `-agentpath` remains the default recovery path.
- `allowAttachSelf=false` warns and does not hard-refuse the external CLI.
- `cross-user` and `not-a-jvm` failures print `attach failed (reason=…)`.
- Hard refusals include `-XX:+DisableAttachMechanism` and
  `-XX:-EnableDynamicAgentLoading`.

The consequence is that attach can remain a preview, but the GUI and CLI must
display the capability actually obtained and must not imply startup-equivalent
coverage.

### Optional privileged observer (#11)

- The landed revision is
  `dc30188118a6579c024978fa9ff52ca154012170`.
- The tree implements a versioned plugin ABI and a Linux maps backend
  (`privileged-observer/`).
- It is an opt-in userspace preview and remains off by default.
- There are no kernel files or shipped kernel components; this is not a kernel
  feature.
- On `main`, `docs/privileged-observer.md` describes the shipped userspace
  module and states that a kernel backend is unimplemented.

The consequence is **preview-userspace**, without creating a kernel
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
- Generic discovery does **not** cover architectures without a registered ABI
  backend — including MIPS, RISC-V, and PE i386 stdcall — and does **not**
  recover encrypted, runtime-decrypted, or shuffled table *contents*.
- Recording a visible-but-unreadable table as an `unreadable-table` gap does
  **not** decrypt or invent method names.
- A named `j2cc` profile on one real PE fixture does **not** make named-profile
  detection general; the existing PE registrar fixture still resolves to
  `generic`.
- `bindingGaps` is **not** persisted in `binary.json`; it is reported by
  `merge-manifest` on stderr. `analysis.unreadableTables` is the count on
  `binary.json`.
- Documenting the offline discovery sequence does **not** change `recover`;
  dynamic recovery remains its default.
- Live attach is **not** equivalent to startup instrumentation and is often
  bind-only on OpenJDK 21.
- Live attach does **not** provide stealth or bypass behavior.
- The GUI does **not** replace the CLI as the automation or recovery contract.
- Native-x86 is a **preview**, not a product feature.
- The privileged observer is an **opt-in userspace preview**, not a kernel
  feature; it has no kernel files and is not enabled by default.

## Completed merge order

Used during wrap-up, with conflict resolutions already on `main`:

1. **#2 / #3 / #5 / #10** — documentation first.
2. **#6** — setup, `doctor`, launchers, and getting started; keep JDK 17.
3. **#4** — draft/development generic discovery, explicitly not the default.
   README / getting-started now point at `docs/generic-recovery.md` rather than
   “being completed on PR #4”.
4. **#8** — optional desktop artifact viewer.
5. **#12** — desktop live-attach/listen viewer (stacked on #8).
6. **#13** — desktop attach CLI wiring (stacked on #12; includes #9).
7. **#9** — already contained after #13 (`git merge` reported already up to
   date).
8. **#7** — native-x86 preview.
9. **#11** — userspace observer last; combined `docs/privileged-observer.md`
   with #7.

Conflict notes already resolved on `main`:

- **#6 vs #4** (README, README.zh-CN, `docs/adding-obfuscator-profile.md`,
  CLI): kept #6 `scripts/j2c` / `scripts/setup.sh` / doctor / HELP / venv
  invocation, and kept #4 generic discovery, `static-lite`, `profile=` /
  `bindingGaps=` / `unreadableTables=` CLI.
- **#13 vs merged main** (README + CLI): doctor/HELP plus attach support;
  attach preview section plus offline/static-lite; attach examples use
  `scripts/j2c attach --pid … --i-own-this-process`.
- **#7 vs #11** (`docs/privileged-observer.md`): combined userspace Linux maps
  module (default off) with an unimplemented kernel backend.

## Promotion gates

These remain future gates. Landing on `main` did not promote any preview.

- #4 now has committed x86-64 PE, Mach-O, stripped-ELF-without-`.symtab`, and
  exports-only ELF fixtures, plus real AArch64 ELF, real ELF32 ARM, genuine
  i386 ELF, section-header-removed ELF, and real Mach-O arm64 fixtures. A
  genuine PE x86-64 DLL makes the named `j2cc` detector fire on a real image,
  and its Microsoft x64 shared-dispatch harvest recovers two tables from one
  `RegisterNatives` site; the ELF fixture separately proves the generic
  shared-dispatch harvest. A visible-but-unreadable table is recorded as an
  honest gap rather than silently dropped. Default promotion remains blocked
  on evidence for encrypted, runtime-decrypted, or shuffled *content recovery*
  and for architectures without a registered ABI backend, including MIPS,
  RISC-V, and PE i386 stdcall.
- #7 needs explicit plugin trust and transport decisions, additional platform
  evidence beyond Linux smoke sections 1–15 and Windows read-only module/export
  observation, and a separate promotion review before it can move beyond
  preview. Windows live breakpoints and any kernel path are not present.
- #8/#12 must keep their JDK 21 requirement module-local unless the repository
  separately approves a baseline migration.
- #12/#13 remain preview: an enabled attach Run needs the attach CLI; without
  that CLI, Run must remain disabled.
- #9/#12 must report actual attach capabilities and retain startup `-agentpath`
  as the default recovery path. #9 warns for `allowAttachSelf=false` rather
  than hard-refusing the external CLI, and prints reason codes for `cross-user`
  and `not-a-jvm` failures.
- #11 is a userspace preview with a versioned plugin ABI and Linux maps backend.
  It must remain default-off, and any promotion or kernel scope requires a
  separate decision backed by new evidence.

This report records current choices and consequences; it does not itself change
any runtime default.
