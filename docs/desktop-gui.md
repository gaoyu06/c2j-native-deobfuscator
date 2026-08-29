# Desktop artifact viewer

Optional **Swing + FlatLaf** client for recovery-pipeline artifacts and
live attach sessions. It is a viewer and an honest front end to the
`attach` CLI. It does **not** replace `scripts/j2c`, does not invent a
second attach protocol, and is not on the default recovery path.

There is no Web UI and no browser server.

## Run

```bash
scripts/gui.sh                     # empty window; open a folder from the toolbar
scripts/gui.sh /path/to/session    # open a session directory
```

Windows: `scripts\gui.ps1 C:\path\to\session`.

The module lives at [`jvm/desktop-ui/`](../jvm/desktop-ui/) and targets
**JDK 21**. The rest of the repository stays on **JDK 17**. Gradle:
`cd jvm && ./gradlew :desktop-ui:run --args="/path/to/session"`.

A session directory is any folder that holds one or more of
`classes.json`, `binary.json`, `manifest.json`, `recovered/`,
`trace.jsonl`.

## What it shows

- Method table and recovery status (`recovered` / `stub` / `missing`)
- Read-only recovered instruction listing and raw JSON
- Pipeline status plus the **next CLI command** (shown, not run)
- Binary analysis strip: format, arch, profile, discovery strategy,
  `bindingGaps`
- Live or static `trace.jsonl`, including `capability` / `gap` rows
- Attach / Listen form: same-user confirmation, `/proc` refusal
  pre-scan, parsed `attach failed (reason=…)` banners

Full screen-by-screen notes, visual rules, and screenshot list:
[`jvm/desktop-ui/README.md`](../jvm/desktop-ui/README.md).

Attach policy and coverage limits:
[jvm-attach.md](jvm-attach.md). Architecture context:
[overview.md](overview.md).
