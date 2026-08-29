# desktop-ui

A desktop viewer for recovery-pipeline artifacts and live JVM sessions. It
opens a session directory (the folder a pipeline run wrote its JSON into),
lists the methods, shows a recovered method body, and reports where the run
stands. It can also follow a live `trace.jsonl` as a target JVM writes it, and
it will show — plainly — which JVMTI capabilities an attach obtained and which
it could not. It never runs recovery and never invents its own attach
mechanism: recovery and attach both stay in the CLI.

Built with Swing and [FlatLaf](https://www.formdev.com/flatlaf/). No web
UI, no browser, no JavaFX.

## Run it

From the repo root:

```bash
scripts/gui.sh                     # start empty, open a folder from the toolbar
scripts/gui.sh /path/to/session    # open a session folder on launch
```

On Windows:

```powershell
scripts\gui.ps1 C:\path\to\session
```

Or straight through Gradle:

```bash
cd jvm
./gradlew :desktop-ui:run --args="/path/to/session"
```

A "session directory" is any folder holding one or more of:

```
classes.json      jar-parser output
binary.json       binary-introspect output
manifest.json     manifest-merge output
recovered/        per-method recovered bodies (JSON)
trace.jsonl       JVMTI agent trace (optional)
```

There is a bundled sample under
`src/test/resources/sample-session/` you can open to see a populated
window.

## What each screen shows

- **Methods** — one row per method: class, name, descriptor, native
  address (when known), and recovery status.
  - `recovered` — a body exists in `recovered/`.
  - `stub` — an obfuscated native method whose address is known but whose
    body hasn't been recovered yet; the rebuilder would leave a stub.
  - `missing` — an obfuscated native method with no known address and no
    body, or a recovered body whose method isn't in the manifest.
- **Detail** — the selected method's recovered instructions, one per
  line, with operands spelled out. Read-only; it prints what the recovery
  stage wrote, it does not assemble bytecode.
- **Pipeline** — which artifacts are present or missing, and the single
  CLI command to run next. The command is shown, never run. When a
  `binary.json` is present it also shows a compact **binary analysis** strip:
  the container format (PE/ELF/MachO), target arch, the obfuscator profile and
  method-discovery strategy the introspection used (when recorded), the native
  registry / string counts, and any **binding gaps** — native methods the pass
  could not bind to a call site — as a count plus a short list. Format, arch,
  and the analysis facts come from `binary.json`; binding gaps are read from
  `manifest.json` (where the merge step records them), falling back to
  `binary.json`. Missing fields are simply omitted, so older reports still show
  format and arch.
- **Artifact JSON** — the raw recovered JSON for the selected method.
- **Trace** — the trace events. A static `trace.jsonl` is loaded when the
  session has one; **Tail this trace** follows it live as it grows. Rows are
  tinted by kind: native-method **bind** in the accent colour, a granted
  **capability** in green, an **unavailable** capability (with its JVMTI
  error code) in red, and **gap** records — the agent stating what it could
  not observe — in amber.

Empty, missing-artifact, and "folder has no artifacts" states are all
handled and point at the first command to run.

The viewer never runs a recovery step. Capturing a trace, reading the
native library, and rebuilding all happen through the CLI; the Pipeline
tab shows the exact command for the next step.

## Attach / Listen (live session, preview)

**Attach / Listen…** in the toolbar opens a form for a live JVM session. It is
an honest front end to the `attach` CLI (see
[`docs/jvm-attach.md`](../../docs/jvm-attach.md)), not a separate mechanism:

- It shows the exact command it would run, e.g.

  ```
  python -m j2c_dumper_cli.main attach --pid <pid> --i-own-this-process -o trace.jsonl
  ```

  and updates it live as you edit the form. **Copy command** puts it on the
  clipboard so you can run it yourself.
- **Run attach** stays disabled until you enter a PID and tick *I own or may
  inspect this process*. That box adds the required `--i-own-this-process`
  flag; without it the CLI refuses before touching the target, and so does the
  GUI. Attach is for a same-user JVM you are authorized to inspect.
- **This checkout wires the `attach` subcommand in**, so once a PID is entered,
  ownership is confirmed, and the `/proc` pre-scan finds no blocker, **Run is
  enabled** and launches the real CLI. (The subcommand + `attach_support` come
  from the JVMTI live-attach change; see [`docs/jvm-attach.md`](../../docs/jvm-attach.md).)
- **If a checkout has no `attach` subcommand, Run is disabled and says so.**
  The form inspects the same CLI it would launch; when the `attach` preview
  subcommand is absent it shows an honest notice instead of pretending the
  displayed command works. **Listen** and the `/proc` pre-scan still work, so
  you can tail a trace and inspect a target's flags regardless.
- On a successful attach the viewer starts tailing the trace. **Listen (tail
  only)** skips running anything and just follows a trace file — useful when
  you started the attach from a terminal.
- Coverage is not promised. On many JDKs a live attach can only add
  native-method-bind; method entry/exit, locals, and exceptions come back
  unavailable. The viewer shows the `capability` / `gap` records verbatim so
  reduced coverage is obvious. It does not hide the agent or patch the
  target's inspection checks; if the target refuses attach, the CLI output is
  shown as-is. For full method-body recovery, use the startup `-agentpath`
  path (`recover` / `dynamic-trace`), which remains the default.
- **Refusals are first-class, never silent.** Two honest guardrails, both
  read-only:
  - *Before launch*, on Linux, the form scans the target's
    `/proc/<pid>/cmdline` for `-XX:+DisableAttachMechanism`
    (`attach-disabled`) and `-XX:-EnableDynamicAgentLoading`
    (    `dynamic-agent-disabled`). If either is present, **Run is blocked** and a
    banner names the reason. `-Djdk.attach.allowAttachSelf=false` is *not* a
    refusal — it governs self-attach only — so it does not block a same-user
    attach; the form surfaces it as an amber **warning** and proceeds.
  - *After a run*, if the CLI printed `attach failed (reason=<code>): …`, the
    viewer parses that code and shows the same banner. The recognized codes are
    `attach-disabled`, `dynamic-agent-disabled`, `cross-user`, `not-a-jvm`,
    `agent-onattach-missing`, `agent-init-failed`, `jcmd-false-success`, and
    `unknown`. The banner gives the code, a one-line meaning, and the one honest
    remedy — *use startup `-agentpath` / `recover` for full coverage*. On any
    refusal or non-zero exit the viewer never tails and never claims it
    attached; nothing is bypassed.

## What the GUI shows vs what stays CLI-only

The desktop viewer surfaces the recovery/analysis **data** so a run reads at a
glance; the CLI remains the automation contract and the only thing that
actually *does* work. Concretely:

| Shown in the GUI | Still CLI-only |
|---|---|
| Method table + recovery status, recovered bodies, artifact JSON | Running `parse-jar` / `inspect-binary` / `merge-manifest` / `trace-to-bc` / `static-reverse` / `rebuild` |
| Pipeline status + the exact next command (shown, not run) | Executing that next command |
| Binary analysis strip (format, arch, profile, method discovery, binding gaps) | Producing `binary.json` (`inspect-binary`) |
| Live `trace.jsonl` tail with capability / gap rows | The attach itself — the GUI assembles and runs the same `attach` command, it does not invent a second attach protocol |
| Attach refusals (argv pre-scan + parsed `reason=<code>`) | The CLI's own refusal classification (the GUI reads the printed code; it does not re-implement the Python classifier) |

## Visual style (keep it this way)

The look is meant to feel like a small instrument panel, not a dashboard.
If you extend the UI, hold this line:

- **One accent colour** — amber (`#d9a441`), used for focus, the active
  tab underline, and the suggested command. Nothing else competes.
- **Narrow neutral palette** — a few close greys for background, panels,
  and lines. Text is a light grey; secondary text is dimmer.
- **Status is ink, not blocks** — recovery status tints the *text*
  (muted green / amber / red). No coloured cells, chips, or fills.
- **Monospace for data** — classes, descriptors, addresses, listings, and
  the trace all use a monospaced face so columns line up. Labels and
  buttons use the system sans.
- **Tight typography** — small type (11–13px), short row height, section
  headings in small caps-style dim labels.
- **Flat and square** — no rounded corners, no gradients, thin 1px lines
  between regions.

What to avoid, on purpose:

- no coloured sidebar blocks or filled navigation rails
- no card grids; regions are plain panels separated by hairlines
- no glow, halos, neon, glass, or gradients
- no animation

Colours and fonts live in `Theme.kt`; changing them there changes the
whole app.

## Layout of the code

- `Model.kt` — plain data types (`Session`, `MethodRow`, statuses,
  `TraceKind`, `AttachRequest`).
- `SessionScanner.kt` — reads a directory into a `Session`. Pure I/O, no
  Swing, so it can be tested headless.
- `TraceParser.kt` — classifies one `trace.jsonl` line (event / bind /
  capability / gap / lifecycle). Shared by the scanner and the tailer.
- `TraceTailer.kt` — follows a trace file as it grows, on a Swing timer.
- `AttachController.kt` — builds (and, on confirmation, runs) the `attach`
  CLI command, detects whether this checkout has an `attach` subcommand, and
  decides the post-run tail / announce outcome. Command building, validation,
  availability detection, and the outcome rule are Swing-free and tested.
- `AttachDiagnostics.kt` — Swing-free refusal classification: the
  `/proc/<pid>/cmdline` argv pre-scan and the `attach failed (reason=<code>)`
  output parser. Tested without a live JVM.
- `AttachPanel.kt` — the attach / listen form, including the refusal banner.
- `NextCommandPlanner.kt` — picks the next CLI step from which artifacts
  exist.
- `Listing.kt` — turns a recovered method into a readable listing.
- `Theme.kt` — the look-and-feel setup and palette.
- `Components.kt` — table models and small UI helpers.
- `ViewerFrame.kt` — the window.
- `Main.kt` — entry point.

## Tests

Scanning, status derivation, the binary-analysis parse, the attach-command
assembly, the `/proc/<pid>/cmdline` refusal pre-scan, and the
`attach failed (reason=<code>)` output parser are all covered by headless
JUnit tests (no display, no live JVM needed):

```bash
cd jvm
./gradlew :desktop-ui:test
```

## Screenshots

`screenshots/` holds rendered images of each state:

- `01-empty` … `06-trace` — the artifact-session states (empty, missing
  artifacts, pipeline, method detail, static trace). `04-pipeline` now includes
  the binary analysis strip.
- `07-attach-form` — the attach / listen form, with the exact CLI shown, pinned
  to the honest fallback for a checkout *without* the `attach` subcommand: the
  "attach CLI not in this checkout" notice is shown and Run stays disabled. (See
  `13-attach-ready` for the live state on this branch, which does have it.)
- `08-live-tail` — a live tail: bind events plus honest capability / gap rows
  (a reduced-capability live attach: bind only).
- `09-capability-gap` — the empty case shown plainly: no core capabilities
  granted, nothing usable captured.
- `10-attach-refused` — a first-class refusal: the target's argv carries
  `-XX:+DisableAttachMechanism`, so the form refuses before launch with the
  reason code, meaning, and startup-path remedy. Run stays disabled.
- `11-analysis-strip` — the binary analysis strip: PE + arch + profile +
  method discovery, and a binding gap (`checksum` left unbound) called out.
- `12-attach-self-warning` — the non-fatal warning path: the target sets
  `-Djdk.attach.allowAttachSelf=false`, which the form flags in amber without
  refusing (it governs self-attach only).
- `13-attach-ready` — the ready-to-run form on a checkout that *has* the
  `attach` subcommand (this branch): a PID and ownership are set, the pre-scan
  finds no blocker, there is no "CLI missing" notice, and **Run is enabled**.

Regenerate them with:

```bash
cd jvm
xvfb-run ./gradlew :desktop-ui:exportShots   # or just :desktop-ui:exportShots with a display
```

The exporter (`src/test/kotlin/.../ShotExporter.kt`) builds each state and
writes a PNG, so the look can be reviewed without a person driving the UI.
