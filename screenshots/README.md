# Screenshots

## Auto-generated showcase images (`showcase/`)

Side-by-side decompiler comparisons rendered from the actual pipeline
output on the `snake` end-to-end fixture (`e2e-test/snake/`). Generated
via HTML + Prism.js + Chrome headless from the real recovered jars —
not hand-edited.

| File | Subject |
|---|---|
| `snake-static-overview.png`     | snake's original `Snake.java` vs Vineflower-decompiled output from the static path |
| `snake-dynamic-overview.png`    | snake's original `Snake.java` vs Vineflower-decompiled output from the dynamic path |
| `snake-static-progression.png`  | three stages of static recovery: stub fallback → tier-2 unverified → cache-table + receiver bind |
| `dynamic-intermediates.png`     | the JVMTI dynamic path's intermediate files: `trace.jsonl` JNI-call records + the lifted `recovered/*.json` + pipeline diagram |
| `board-static-vs-dynamic.png`   | same input (Board.java), the two paths side by side; coverage tradeoff visible |
| `manual-restoration-dynamic.png` | 3-pane: dynamic auto-output → hand-cleaned → original. Workflow doc: [`docs/manual-restoration.md`](../docs/manual-restoration.md) |
| `manual-restoration-static.png`  | 3-pane: static auto-output → hand-completed (using `recovered/*.json` + `manifest.cacheTable`) → original |
| `decompiler-before.png`         | original IntelliJ screenshot of an obfuscated Kiritan class (`Dp`) before any recovery — all method bodies are `native` |

## Layout

```
screenshots/
└── showcase/
    ├── snake-static-overview.png
    ├── snake-dynamic-overview.png
    ├── snake-static-progression.png
    ├── dynamic-intermediates.png
    ├── board-static-vs-dynamic.png
    └── decompiler-before.png        ← real IntelliJ shot (obfuscated input)
```

## Regenerating

The showcase PNGs come from a generator script that reads the
recovered jars + intermediate files and renders Chrome-headless
screenshots of syntax-highlighted HTML pages. To regenerate after a
pipeline change:

1. Re-run the snake pipeline (`e2e-test/snake/`) end-to-end through
   both static and dynamic paths, producing `snake-static-v*.jar`
   and `snake-dynamic-v*.jar`.
2. Decompile both jars with Vineflower into `vf-stc/` / `vf-dyn/`.
3. Run the generator (script lives in the temp workdir during a
   demo session, not in the repo — see `dynamic-intermediates.png`
   for the pipeline shape).
4. Copy the PNGs back into `screenshots/showcase/`.

For a new fixture, add a subdirectory `screenshots/<fixture-name>/`
with the same structure.
