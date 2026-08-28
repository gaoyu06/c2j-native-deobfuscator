# desktop-ui

A read-only desktop viewer for recovery-pipeline artifacts. It opens a
session directory (the folder a pipeline run wrote its JSON into), lists
the methods, shows a recovered method body, and reports where the run
stands. It does not run recovery — that stays in the CLI.

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
  CLI command to run next. The command is shown, never run.
- **Artifact JSON** — the raw recovered JSON for the selected method.
- **Trace** — the trace events, when a `trace.jsonl` is present.

Empty, missing-artifact, and "folder has no artifacts" states are all
handled and point at the first command to run.

The **Attach** button in the toolbar is disabled and labelled "not
available yet". Live process attach is not implemented; capture a trace
with the CLI instead.

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

- `Model.kt` — plain data types (`Session`, `MethodRow`, statuses).
- `SessionScanner.kt` — reads a directory into a `Session`. Pure I/O, no
  Swing, so it can be tested headless.
- `NextCommandPlanner.kt` — picks the next CLI step from which artifacts
  exist.
- `Listing.kt` — turns a recovered method into a readable listing.
- `Theme.kt` — the look-and-feel setup and palette.
- `Components.kt` — table models and small UI helpers.
- `ViewerFrame.kt` — the window.
- `Main.kt` — entry point.

## Tests

Scanning and status derivation are covered by headless JUnit tests (no
display needed):

```bash
cd jvm
./gradlew :desktop-ui:test
```

## Screenshots

`screenshots/` holds rendered images of each state. Regenerate them with:

```bash
cd jvm
xvfb-run ./gradlew :desktop-ui:exportShots   # or just :desktop-ui:exportShots with a display
```

The exporter (`src/test/kotlin/.../ShotExporter.kt`) builds each state and
writes a PNG, so the look can be reviewed without a person driving the UI.
