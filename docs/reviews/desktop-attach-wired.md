# Desktop viewer — attach wired in (merge review)

Short review note for branch `cursor/desktop-attach-wired-5e25`. This is a
**merge**, not a new feature: it brings the opt-in JVMTI live-attach CLI
(PR #9, `cursor/opt-in-jvmti-live-attach-1155`) into the desktop viewer branch
(PR #12, `cursor/desktop-viewer-live-attach-c9be`) so the viewer's **Run
attach** button can drive the real `attach` subcommand instead of honestly
refusing because the subcommand was absent.

**Verdict: merge-ok.** No conflicts; both sides kept intact.

## What was combined

The two branches touched disjoint files, so the three-way merge was clean:

- From PR #9 (attach CLI): `py/j2c_dumper_cli/j2c_dumper_cli/main.py` gains the
  `attach` subcommand and its helpers (`_do_attach`, `_report_refusal`,
  `_jdk_tool`), `attach_support.py` (validation, cmdline scan, refusal
  classification, jcmd false-success handling), the native `Agent_OnAttach`
  entry point (`native/src/agent.cpp`, `native/src/jni_hook.cpp`,
  `native/include/jni_hook.hpp`), `docs/jvm-attach.md`, its review note, the
  root README additions, and `tests/test_attach.py` (+ `conftest.py`).
- From PR #12 (desktop viewer): the whole `jvm/desktop-ui` module, its
  screenshots, `scripts/gui.*`, and the desktop review notes — including the GUI
  honesty (first-class refusals, the analysis strip, Listen-without-attach, and
  the CLI-missing notice).

## Why Run now enables

`AttachController.attachSubcommandAvailable()` inspects the same
`py/j2c_dumper_cli/.../main.py` the GUI would launch and looks for an `attach`
command. Before the merge that file had no `attach`, so the value was `false`,
the form showed the amber "attach CLI not in this checkout" notice, and Run was
held disabled — honest, but unable to attach. After the merge `main.py` declares
`@app.command("attach")`, so the value is `true`: the notice is hidden and Run
enables as soon as a PID is entered, ownership is confirmed
(`--i-own-this-process`), and the Linux `/proc/<pid>/cmdline` pre-scan finds no
hard blocker. The gates are unchanged; only the availability input flipped.

## What stayed honest (unchanged from PR #12)

- The pre-launch `/proc` refusals (`attach-disabled`, `dynamic-agent-disabled`)
  still block Run; `allowAttachSelf=false` is still a **warning only**, never a
  refusal.
- On any parsed `attach failed (reason=<code>)` or non-zero exit the viewer
  never tails and never claims it attached.
- **Listen (tail only)** still needs only an output path — no attach CLI.
- The CLI-missing notice path is kept for checkouts that genuinely lack the
  subcommand; `AttachPanel.previewAttachAvailability(...)` lets both states be
  screenshotted deterministically (`07-attach-form` = absent, `13-attach-ready`
  = present).
- The default recovery path is untouched: `recover` / `dynamic-trace` still use
  startup `-agentpath`. Live attach remains an opt-in, reduced-coverage preview.

## Tests / evidence

- `:desktop-ui:test` — the availability test was flipped from "no attach
  subcommand" to "has the wired-in attach subcommand"; the rest of the attach
  command-assembly, refusal-parse, cmdline-scan, and outcome tests are unchanged.
- `py/j2c_dumper_cli/tests/test_attach.py` — PR #9's attach suite, kept green.
- Screenshots re-exported with `xvfb-run ./gradlew :desktop-ui:exportShots`;
  `13-attach-ready.png` shows Run enabled with no CLI-missing notice.

No kernel code, no stealth, no bypass was added.
