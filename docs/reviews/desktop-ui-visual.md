# Desktop viewer — visual review

Review of the Swing desktop viewer (`jvm/desktop-ui`, PR #8, branch
`cursor/swing-desktop-viewer-7389`). This was a look-and-usability pass,
not a feature change. Everything was checked against rendered PNGs in
`jvm/desktop-ui/screenshots/`, re-exported with
`xvfb-run ./gradlew :desktop-ui:exportShots`.

## Issues found

1. **Detail pane too narrow — code clipped.** The method/detail split gave
   the detail side only ~440px, so even the short header comment and most
   instruction lines ran off the right edge and needed horizontal
   scrolling to read (`05-method-detail.png`).
2. **Suggested command wrapped mid-token.** The command box wrapped on any
   character, so paths and flags broke in half: `--recovered recover` /
   `ed/`, and `inspect-binary ... -o bina` / `ry.json`
   (`02`, `03`, `04`).
3. **"Attach — not available yet" toolbar button.** A button that is
   permanently disabled and advertises a feature that does not exist. It
   reads like a roadmap teaser and adds toolbar noise.
4. **Table headers centered over left-aligned data.** Every table
   (methods and trace) painted its column titles centered while the cell
   text was left-aligned, so headings floated off from their columns.
5. **Divider position jumped between states.** The split divider landed in
   a different place depending on which session was open (compare the old
   `02` vs `04`).
6. **Screenshots not reproducible.** The empty/partial shots opened
   `Files.createTempDirectory(...)`, so the header showed a random
   `/tmp/...` path and `02`/`03` changed on every re-export. Also a dead
   `if/else` branch in the method cell renderer (both arms returned the
   same alignment).

## Issues fixed

1. Rebalanced the split: method panel preferred width 660 → 548, detail
   tabs 440 → 556, resize weight 0.6 → 0.5, and trimmed the method column
   widths to fit. The detail header and the common instruction lines now
   fit without scrolling.
2. Command box now wraps at word boundaries (`wrapStyleWord = true`), so a
   long command breaks between arguments. The two sample commands that used
   to break mid-token now wrap cleanly or fit on one line.
3. Removed the Attach button. The toolbar is now just **Open session…**
   and **Reload**. Dropped the matching paragraph from the module README.
4. Left-aligned the column headers on both tables (small shared helper,
   `Ui.leftAlignHeader`) so titles sit over their data.
5. With the fixed preferred widths and even resize weight, the divider now
   lands in the same place in every state.
6. The screenshot exporter writes to fixed temp dirs
   (`j2c-viewer-shot-empty` / `-partial`), so re-exports are stable.
   Removed the dead alignment branch in the renderer.

## Leftovers

- One long instruction in the Detail view (the `INVOKESTATIC ... xor(...)`
  line, ~90 chars) still runs past the right edge and needs the horizontal
  scrollbar. This is normal for a disassembly-style listing; wrapping
  bytecode lines would hurt readability more than the scroll does. Left
  as-is.
- The **Open session…** button shows the focus ring in the screenshots
  because it is the default-focused button when the window opens. This is
  ordinary focus state, not a highlight, and moves as soon as the user
  interacts. Left as-is.

## Build / test notes

- The module targets JDK 21 while the rest of `jvm/` targets JDK 17. On a
  box with only JDK 21 the build fails to resolve the `:common` toolchain.
  Installing a JDK 17 alongside 21 lets Gradle's toolchain auto-detection
  build it; no gradle change was needed, so the JDK split was left alone
  (out of scope for this pass).
- `./gradlew :desktop-ui:test` passes.
- Screenshots re-exported after the changes.
