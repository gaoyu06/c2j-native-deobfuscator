# Setup release ZIPs

Windows x64 and ARM64 packages include a complete CPython runtime and installed
workspace packages in `runtime/python`. Run `scripts/j2c.ps1`; it selects this
runtime automatically. A separate Python installation, uv, and internet access
are not needed to run the packaged CLI. Java 21 must still be installed.

```powershell
.\scripts\j2c.ps1 parse-jar ".\input.jar" -o ".\classes.json"
```

The packager installs workspace packages without editable source links and
excludes the CI-only Windows `py/.venv`. It unpacks the finished ZIP into a new
directory, checks the bundled interpreter and native libraries there, then runs
`parse-jar` through the PowerShell launcher against a small test JAR. A failure
prevents that package from being uploaded.

All four platform ZIPs exclude `.zig-cache`, `zig-cache`, `.cache/zig`, Gradle,
Kotlin, uv, and Python bytecode caches. Built agents and JVM distributions remain
in the archive.

Older Windows packages containing only `py/.venv` can reference a Python under
`C:\hostedtoolcache` and cannot be moved to another computer. Download a newly
built package containing `runtime/python/python.exe`. To repair an old package
locally instead, install Python, uv, and Java 21, remove its `py/.venv`, then rerun
`scripts/setup.ps1`. That rebuild also needs the native build tools described by
the setup script.
