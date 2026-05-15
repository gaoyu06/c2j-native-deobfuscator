# Screenshots

Side-by-side comparisons between the **obfuscated input** and the
**recovered output** for fixtures processed by either path.

Each fixture lives in its own subdirectory. Within a subdirectory we
expect three image pairs (`before.png` / `after.png`) and one
free-form `notes.md`:

```
screenshots/
└── <fixture-name>/
    ├── notes.md          short description of the fixture
    ├── classlist/        `javap -p` of the bytecode class list
    │   ├── before.png
    │   └── after.png
    ├── method-body/      `javap -c -p` of one representative method
    │   ├── before.png
    │   └── after.png
    └── decompiler/       CFR / Procyon / IntelliJ decompiler output
        ├── before.png
        └── after.png
```

## Naming convention

- `before.*` — the obfuscated jar (native method stubs, encoded string
  tables, generated `*ClInit` loader classes still present).
- `after.*` — the recovered jar emitted by `class-rebuilder` (real
  bytecode bodies, loader classes stripped).

For dynamic-path fixtures the `after.*` shot should be annotated with
the `--run-cmd` used to produce the trace, since coverage depends on
which branches the target executed.

## Catalogue

| Fixture | Path | Source obfuscator | Notes |
|---|---|---|---|
| _(none yet)_ | — | — | — |

Add a row per fixture as screenshots land.
