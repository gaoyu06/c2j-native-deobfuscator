# Screenshots

Side-by-side comparisons between the **obfuscated input** and the
**recovered output**.

## Layout

```
screenshots/
├── showcase/                   images embedded in the top-level README
│   ├── decompiler-before.png   IntelliJ/CFR view, obfuscated jar
│   ├── decompiler-after.png    IntelliJ/CFR view, recovered jar
│   ├── javap-before.png        `javap -c -p` of one representative method (native)
│   ├── javap-after.png         `javap -c -p` of the same method (recovered)
│   ├── pipeline.png            terminal screenshot of `j2c-dumper recover`
│   └── ghidra-pseudoc.png      Ghidra decompiler view of one `fnAddr`
│
└── <fixture-name>/             per-fixture deep-dive (optional)
    ├── notes.md                short description of the fixture
    ├── classlist/              `javap -p` of the class list
    │   ├── before.png
    │   └── after.png
    ├── method-body/            `javap -c -p` of one representative method
    │   ├── before.png
    │   └── after.png
    └── decompiler/             CFR / Procyon / IntelliJ decompiler output
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

## Fixture catalogue

| Fixture | Path | Source obfuscator | Notes |
|---|---|---|---|
| _(none yet)_ | — | — | — |

Add a row per fixture as deep-dive screenshots land.
