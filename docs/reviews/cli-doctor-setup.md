# CLI doctor/setup review

PR: https://github.com/gaoyu06/c2j-native-deobfuscator/pull/6

Verdict: **ship as draft; must fix before merge**.

The new entry point, help text, diagnostics, bilingual documentation, and
Ghidra-free tests move the project in the right direction. The documented
fresh-checkout path is not reliable yet, however, and `doctor` can both reject
a usable runtime and approve an unusable installation.

## Verification

- `python3 -m j2c_dumper_cli --help`: passed in an isolated dependency path;
  the default dynamic command is shown before the command list.
- `python3 -m j2c_dumper_cli doctor`: ran and produced actionable setup
  pointers; it exited 1 because the native agent was absent.
- `python3 -m j2c_dumper_cli`: displayed help but exited 2.
- Exact `python -m ...` commands could not be run on this Ubuntu environment
  because only `python3` is installed. `setup.sh` also selects `python3` for its
  fallback install but still prints `python -m ...` as the next command.
- `python3 -m pytest py/j2c_dumper_cli/tests/ -q`: **27 passed** without
  Ghidra.
- `sh ./gradlew installDist --no-daemon`: passed on JDK 21; all three
  generated CLI jars contain Java class-file major version 65.
- `bash -n scripts/setup.sh`: passed.
- PowerShell was unavailable, so `setup.ps1` was reviewed statically.

## Must fix

### 1. The setup path omits a required Python dependency

`scripts/setup.sh` and `scripts/setup.ps1` install the five editable Python
packages, but `py/binary_introspect/pyproject.toml` does not declare
`capstone`. Importing the stage used by `recover` then fails:

```text
from binary_introspect.cli import main
...
ModuleNotFoundError: No module named 'capstone'
```

The failure occurs because `binary_introspect.arch` imports its built-in
backends, which import `capstone` unconditionally. `doctor` does not probe this
dependency, so it can print `Ready` before `recover` fails at binary
introspection. Declare the dependency, install it through both setup paths,
and add a post-setup/import check or an orchestration test that reaches this
stage.

### 2. The repository-wide JDK 17 to 21 bump is not required by this PR

The JVM source contains no Java 21 API use, and this PR changes only the
toolchain configuration. The bump makes every existing CLI distribution emit
Java 21-only class files, unnecessarily dropping JDK 17 runtime compatibility.
The desktop module proposed separately needs 21, while the existing JVM CLI
modules are still designed for 17. Keep the shared CLI modules on 17 and scope
21 to the desktop module if and when it lands. Align `doctor`, setup, CI, and
the new documentation with the actual minimum.

### 3. Native artifact checks do not establish readiness or idempotence

Both setup scripts skip the native build when *any* of
`j2c_agent.dll`, `j2c_agent.so`, or `j2c_agent.dylib` exists. They do not check
the current OS, architecture, source freshness, or loadability. `doctor` uses
the same any-suffix existence test. Consequently:

- a stale agent remains stale unless the user knows to pass `--force`;
- a DLL can make Linux `doctor` report the native agent as ready;
- `native/build.sh` reads `HOST_ARCH` but always targets x86-64, while setup is
  documented for Linux and macOS without an architecture qualification.

This contradicts the setup comment that inputs are rebuilt when changed and
the claim that `doctor` verifies default-path readiness. Select the
host-specific filename, account for architecture, rebuild when inputs are
newer (or always delegate incremental work to a build tool), and make
`doctor` validate the artifact it will actually load.

### 4. `doctor` treats warnings as missing requirements

`Report.blocking` includes every non-optional status other than `OK`, including
`WARN`. On a machine with Java 21 on `PATH` and no `JAVA_HOME`, the report
therefore says `Missing: Java / JDK 21+` even though it just found Java 21.
Either warnings must not block, or this condition must be represented as a
required build precondition with accurate wording. Add an aggregate-report
test for this case.

### 5. The advertised no-argument and interpreter paths are not successful

The no-argument module entry point prints the intended help but exits with
status 2. The focused tests cover only `doctor`, not
`python -m j2c_dumper_cli` or top-level help. In addition, the POSIX setup
fallback installs with `python3` but tells users to invoke `python`, which is
not present in a standard minimal Ubuntu environment.

Make the no-argument help path exit 0, test both entry points, and consistently
use or print the interpreter that setup actually selected (a managed virtual
environment would make this deterministic).

### 6. The Windows native setup has an undocumented and misleading prerequisite

`setup.ps1` cannot build the agent directly: it requires `bash`, although the
getting-started prerequisite list mentions only JDK, Python, and Zig. Its
message recommends either Git Bash or WSL. WSL runs `native/build.sh` as Linux,
selects a Linux target, and cannot directly use a normal Windows `JAVA_HOME`;
it is not an equivalent way to produce the Windows DLL.

Document and validate Git Bash specifically, or add a native Windows build
invocation. A missing prerequisite for the default path should not end with an
unqualified `Setup finished`.

### 7. Narrow the readiness and output claims

`doctor` currently checks versions and file existence. It does not execute the
installed JVM launchers, import the default Python stages, validate the
host/architecture of the agent, attempt to load it, or verify that a target
command exercises useful code. Documentation should describe those checks
precisely rather than call the result full default-path readiness.

The getting-started guide also says a completed run yields real bytecode bodies
for the native methods. Dynamic tracing covers only executed paths, and the
rebuilder can preserve unverified output or fall back to stubs. State that the
output contains best-effort recovered bodies for observed behavior and may
require inspection or manual completion.

## Checklist notes

- Missing JVM-module and native-agent errors do point to `doctor` and both
  setup scripts.
- The English and Chinese READMEs now present manual CLI use as the default;
  assisted adaptation is optional.
- Ghidra is clearly labeled Advanced/optional, and the new doctor tests do not
  require it.
- Missing Zig is skipped with a clear warning in both scripts, but that leaves
  the default dynamic path unavailable; the final setup message should say so
  explicitly.
