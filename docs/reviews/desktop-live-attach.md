# Desktop viewer — live attach visual review

Review of the live-attach additions to the Swing desktop viewer
(`jvm/desktop-ui`, PR #12, branch `cursor/desktop-viewer-live-attach-c9be`
vs `cursor/swing-desktop-viewer-7389`). This was a look, copy, and gating
pass, not a feature change. Everything was checked against rendered PNGs in
`jvm/desktop-ui/screenshots/`, re-exported with
`xvfb-run ./gradlew :desktop-ui:exportShots`.

New in this PR: the **Attach / Listen…** toolbar entry, the attach form
(`07-attach-form`), and two live-tail states (`08-live-tail`,
`09-capability-gap`). The `01`–`06` artifact-session shots were re-checked
for the changed toolbar.

**Verdict: preview-ok** after the fixes below.

## Update — attach refusals and the analysis strip

A follow-up pass made the viewer show *key attach and analysis data*, not just
a log tail. Two additions, both read-only, both screenshotted:

- **First-class attach refusals** (`10-attach-refused`). The attach form now
  refuses honestly instead of quietly appending to the log:
  - a Linux `/proc/<pid>/cmdline` **pre-scan** (`AttachDiagnostics`) blocks Run
    before launch when the target's argv carries
    `-XX:+DisableAttachMechanism` (`attach-disabled`) or
    `-XX:-EnableDynamicAgentLoading` (`dynamic-agent-disabled`);
  - a **parser** reads the CLI's `attach failed (reason=<code>): …` line, when
    present, and maps the code to a banner (code, one-line meaning, and the one
    honest remedy: use startup `-agentpath` / `recover`).
  - `-Djdk.attach.allowAttachSelf=false` is intentionally **not** a refusal (it
    disables self-attach only); it surfaces as a warning and proceeds. On any
    refusal or non-zero exit the viewer never tails and never claims it
    attached. This branch parses the CLI's reason code — it does **not**
    re-implement the CLI's Python classifier in Kotlin.
- **Binary analysis strip** on the session viewer (`11-analysis-strip`; also
  visible in the refreshed `04-pipeline`). `binary.json` is shown as more than
  "N native classes, M strings": the container format (PE/ELF/MachO), arch,
  the obfuscator `profile` and `methodDiscovery` strategy (when recorded), the
  registry/string counts, and any `bindingGaps` (count + short list). The
  bundled `sample-session/binary.json` gained an `analysis` block and one
  `unbound-native-method` binding gap so the shot proves PE + a real gap.

Both additions are backed by headless tests (`AttachControllerTest` for the
parser + cmdline scan, `SessionScannerTest` for the analysis parse); the JDK
21 toolchain stays module-local. `./gradlew :desktop-ui:test` passes (42
tests) and screenshots were re-exported.

## Issues found

1. **Gap explanation unreadable — clipped mid-sentence.** In the
   no-capabilities case (`09`) the `gap` row carries the one sentence a
   reviewer actually needs — *why the trace will be empty* — and it was cut
   off as `no-core-capabilities — neither native-method-b…`. The trace's
   `detail` column was a fixed single line, so the longest capability and
   `bind` lines were clipped too (e.g. the `decrypt` bind with its address
   in `08`).
2. **Live tail wasted half the window and rendered inconsistently.** When a
   tail runs without an open session there are no methods to list, yet the
   viewer still showed the methods table beside the trace. Worse, the empty
   panel landed at a different width each time: a thin sliver in `08`, a full
   empty half in `09`. The trace — the only content in that state — was
   squeezed into the right half.
3. **`#` / `event` / `thread` columns bled width from `detail`.** The three
   fixed columns stretched wider than their content, taking room the long
   `detail` text needed.
4. **`agent-attached` event label clipped** to `agent-atta…` once the event
   column was pinned.
5. **Attach-form intro copy was dense.** The opening paragraph packed the
   gate, the ownership rule, and the coverage caveat into one long run-on.

The **Run attach** gate was checked and is correct: the button stays
disabled until a valid PID, the ownership tick, and an output path are all
present, and the shown command only carries `--i-own-this-process` when the
box is ticked. No "run without ownership" path exists. No generic chrome
was found — the toolbar and buttons use plain, neutral labels and the
single-accent instrument-panel palette holds.

## Issues fixed

1. The `detail` column now wraps (`TraceDetailRenderer`) and the table grows
   the row to fit (`ViewerFrame.fitTraceRowHeights`, recomputed on data
   change and on resize). The `no-core-capabilities` sentence in `09` now
   shows in full across two lines; the long `bind` and capability lines in
   `08` are complete.
2. A session-less live tail now hands the whole window to the trace: the
   methods pane is collapsed deterministically (divider set to 0 via an
   explicit `setDividerLocation`, methods panel `minimumSize` 0), and a real
   session restores the balanced split. `08` and `09` now look the same and
   the trace uses the full width.
3. The three fixed columns are hard-pinned (min/preferred/max) so `detail`,
   the last column, keeps every spare pixel.
4. The event column was widened to fit the longest label
   (`agent-attached`).
5. The intro was rewritten shorter and plainer: what it runs, that it needs
   a PID and confirmation first, and that coverage is whatever the JDK
   grants — pointing at the capability / gap rows for the specifics.

## Leftovers

- The long `detail` explanations are visible in full via wrapping, but the
  raw JSON fields behind a `gap` (the individual `methodEntry` /
  `localVariables` booleans) are still summarised into one line rather than
  broken out. The summary plus the per-capability rows above it already tell
  the same story, so this was left as-is.
- The **Attach / Listen…** button shows the focus ring in the shots because
  it is the default-focused button when the window opens. This is ordinary
  focus state, not a highlight. Left as-is.

## Build / test notes

- The module targets JDK 21 while the rest of `jvm/` targets JDK 17. On a
  box with only JDK 21 the build fails to resolve the `:common` toolchain;
  installing a JDK 17 alongside 21 lets Gradle's toolchain auto-detection
  build it. No gradle change was needed, so the JDK split was left alone.
- `./gradlew :desktop-ui:test` passes.
- Screenshots re-exported after the changes.
