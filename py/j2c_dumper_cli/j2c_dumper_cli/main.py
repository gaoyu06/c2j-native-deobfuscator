"""j2c-dumper top-level CLI."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from j2c_dumper_cli import doctor as doctor_mod


def _cli_invocation() -> str:
    """How to re-invoke this CLI in a way that actually works here.

    `scripts/setup.sh` installs the packages into `py/.venv` (via uv), so a
    bare ``python3 -m j2c_dumper_cli`` on a *system* interpreter would not find
    them. Every hint the CLI prints must therefore point at an interpreter that
    has the packages:

    * when launched through ``scripts/j2c`` (or ``scripts/j2c.ps1``), echo that
      launcher — it resolves the venv/pip interpreter itself;
    * otherwise echo :data:`sys.executable`, which by definition already
      imported this module, so the command is guaranteed to run.
    """
    launcher = os.environ.get("J2C_CMD")
    if launcher:
        return launcher
    exe = sys.executable or ("python" if os.name == "nt" else "python3")
    return f"{shlex.quote(exe)} -m j2c_dumper_cli"


CLI = _cli_invocation()

HELP = f"""\
Recover JNI-native transpiled JARs back to readable JVM bytecode.

DEFAULT PATH (dynamic): if the JAR can be launched, run

    scripts/j2c recover IN.jar -o OUT.jar --run-cmd "java -jar IN.jar"

FIRST TIME? run `scripts/setup.sh` (or `scripts/setup.ps1` on Windows) to build
everything, then `scripts/j2c doctor` to check your toolchain. The `scripts/j2c`
launcher runs the interpreter the setup step installed the packages into.

FALLBACK (no live run): the emulation path needs no JVM and no Ghidra.
ADVANCED (offline, needs Ghidra): the static path — see `--help` of the
individual stage commands and docs/getting-started.md.
"""

app = typer.Typer(
    add_completion=False,
    help=HELP,
)
console = Console(stderr=True)


@app.callback(invoke_without_command=True)
def _root(ctx: typer.Context) -> None:
    # Running with no subcommand prints help and exits 0 (a successful,
    # intentional "show me what's here"), rather than Typer's default
    # usage-error exit code.
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(code=0)


# ------------------------------------------------------------------
# Path discovery
# ------------------------------------------------------------------

def project_root() -> Path:
    """Locate the j2c-dumper project root from this file's path."""
    here = Path(__file__).resolve()
    for ancestor in [here] + list(here.parents):
        if (ancestor / "jvm" / "settings.gradle.kts").exists():
            return ancestor
    raise RuntimeError("Could not locate j2c-dumper project root")


def jvm_bin(name: str) -> Path:
    """Path to a Gradle-installed JVM CLI script."""
    root = project_root()
    suffix = ".bat" if os.name == "nt" else ""
    candidate = root / "jvm" / name / "build" / "install" / name / "bin" / f"{name}{suffix}"
    if not candidate.exists():
        raise FileNotFoundError(
            f"JVM module '{name}' is not built.\n"
            f"  Fix: run scripts/setup.sh (or scripts/setup.ps1 on Windows),\n"
            f"       or `cd jvm && ./gradlew :{name}:installDist`.\n"
            f"  Diagnose: {CLI} doctor"
        )
    return candidate


def native_lib() -> Path:
    """Path to the JVMTI agent shared library, if built."""
    root = project_root()
    libdir = root / "native" / "build" / "lib"
    hint = (
        "  Fix: run scripts/setup.sh (or scripts/setup.ps1 on Windows),\n"
        "       or `cd native && JDK_HOME=\"$JAVA_HOME\" bash build.sh`.\n"
        f"  Diagnose: {CLI} doctor"
    )
    if not libdir.exists():
        raise FileNotFoundError(
            "Native JVMTI agent is not built (the dynamic path needs it).\n" + hint
        )
    # Only the host-matching artifact can be loaded here; a leftover .so on
    # Windows (or .dll on Linux) is not usable.
    want = doctor_mod.host_agent_name()
    target = libdir / want
    if target.exists():
        return target
    raise FileNotFoundError(
        f"Native JVMTI agent is not built for this host: no {want} under {libdir}.\n"
        + hint
    )


def run(cmd: list[str | Path], **kwargs) -> subprocess.CompletedProcess:
    """Run a subprocess, raise on non-zero exit."""
    str_cmd = [str(x) for x in cmd]
    console.log(f"[dim]$ {' '.join(str_cmd)}[/]")
    res = subprocess.run(str_cmd, check=False, **kwargs)
    if res.returncode != 0:
        raise typer.Exit(code=res.returncode)
    return res


# ------------------------------------------------------------------
# Subcommands — one per module
# ------------------------------------------------------------------

def _run_parse_jar(jar: Path, output: Path) -> None:
    run([jvm_bin("jar-parser"), str(jar), "-o", str(output)])


def _run_inspect_binary(lib: Path, output: Path) -> None:
    from binary_introspect.cli import main as bi_main
    sys.argv = ["binary-introspect", str(lib), "-o", str(output)]
    try:
        bi_main(standalone_mode=False)
    except SystemExit:
        pass


def _run_merge_manifest(classes: Path, binary: Optional[Path], output: Path) -> None:
    from manifest_merge.cli import main as mm_main
    args = ["manifest-merge", str(classes)]
    if binary:
        args.append(str(binary))
    args += ["-o", str(output)]
    sys.argv = args
    try:
        mm_main(standalone_mode=False)
    except SystemExit:
        pass


def _run_dynamic_trace(run_cmd: str, output: Path) -> None:
    import shlex
    agent = native_lib()
    # Use POSIX-style splitting (strips matching quotes) so paths with spaces
    # come through as a single argv element when the user used "..." in --run.
    args = shlex.split(run_cmd, posix=True)
    if args and Path(args[0]).name.startswith("java"):
        args = [args[0], f"-agentpath:{agent}=trace={output}"] + args[1:]
    else:
        args = ["java", f"-agentpath:{agent}=trace={output}"] + args
    run(args)


def _run_trace_to_bc(trace: Path, manifest: Path, output: Path, confidence: str = "low") -> None:
    run([jvm_bin("trace-to-bytecode"),
         "--trace", trace, "--manifest", manifest,
         "-o", output, "--confidence", confidence])


def _run_static_reverse(ghidra_dump: Path, output: Path, manifest: Optional[Path] = None) -> None:
    from ast_matcher.cli import main as am_main
    args = ["ast-matcher", str(ghidra_dump), "-o", str(output)]
    if manifest:
        args += ["--manifest", str(manifest)]
    sys.argv = args
    try:
        am_main(standalone_mode=False)
    except SystemExit:
        pass


def _run_rebuild(input: Path, recovered: Path, output: Path, manifest: Optional[Path] = None) -> None:
    args = [jvm_bin("class-rebuilder"),
            "--input", input, "--recovered", recovered, "-o", output]
    if manifest:
        args += ["--manifest", manifest]
    run(args)


def _preflight_recover(run_cmd: Optional[str], no_dynamic: bool) -> None:
    """Fail early with a clear pointer when the toolchain the default path
    needs is missing, instead of a mid-pipeline traceback."""
    try:
        root = project_root()
    except RuntimeError:
        return  # non-fatal; the stage that needs it will report specifically

    problems: list[str] = []
    jvm_check = doctor_mod.check_jvm_modules(root)
    if not jvm_check.ok:
        problems.append(f"{jvm_check.detail} — {jvm_check.fix}")
    if run_cmd and not no_dynamic:
        agent_check = doctor_mod.check_native_agent(root)
        if not agent_check.ok:
            problems.append(f"{agent_check.detail} — {agent_check.fix}")

    if problems:
        console.print("[bold red]recover cannot start:[/] required build "
                      "artifacts are missing.")
        for p in problems:
            console.print(f"  - {p}")
        console.print(f"Run [bold]{CLI} doctor[/] for a full "
                      "report, then [bold]scripts/setup.sh[/] "
                      "(or scripts/setup.ps1 on Windows).")
        raise typer.Exit(code=2)


@app.command("parse-jar")
def cli_parse_jar(
    jar: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(..., "-o", "--output"),
):
    """Parse a jar into classes.json (class skeletons + native registry)."""
    _run_parse_jar(jar, output)


@app.command("inspect-binary")
def cli_inspect_binary(
    lib: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(..., "-o", "--output"),
):
    """Parse a .dll/.so/.dylib into binary.json (strings + hidden classes)."""
    _run_inspect_binary(lib, output)


@app.command("merge-manifest")
def cli_merge_manifest(
    classes: Path = typer.Argument(..., exists=True, dir_okay=False),
    binary: Optional[Path] = typer.Argument(None),
    output: Path = typer.Option(..., "-o", "--output"),
):
    """Merge classes.json + binary.json into manifest.json."""
    _run_merge_manifest(classes, binary, output)


@app.command("dynamic-trace")
def cli_dynamic_trace(
    run_cmd: str = typer.Option(..., "--run"),
    output: Path = typer.Option(..., "-o", "--output"),
):
    """Run a target with the JVMTI agent attached and capture trace.jsonl."""
    _run_dynamic_trace(run_cmd, output)


@app.command("trace-to-bc")
def cli_trace_to_bc(
    trace: Path = typer.Argument(..., exists=True, dir_okay=False),
    manifest: Path = typer.Option(..., "--manifest", exists=True, dir_okay=False),
    output: Path = typer.Option(..., "-o", "--output"),
    confidence: str = typer.Option("low", "--confidence"),
):
    """Translate trace.jsonl + manifest into recovered/*.json (dynamic path)."""
    _run_trace_to_bc(trace, manifest, output, confidence)


@app.command("static-reverse")
def cli_static_reverse(
    ghidra_dump: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(..., "-o", "--output"),
    manifest: Optional[Path] = typer.Option(None, "--manifest"),
):
    """Lift Ghidra pseudo-C dump into recovered/*.json (static path)."""
    _run_static_reverse(ghidra_dump, output, manifest)


@app.command("rebuild")
def cli_rebuild(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False),
    recovered: Path = typer.Option(..., "--recovered", exists=True),
    output: Path = typer.Option(..., "-o", "--output"),
    manifest: Optional[Path] = typer.Option(None, "--manifest"),
):
    """Replace native stubs with recovered bytecode and strip the loader."""
    _run_rebuild(input, recovered, output, manifest)


@app.command()
def doctor() -> None:
    """Check that your toolchain is ready for the default (dynamic) path.

    Reports Java/JDK, Python, the built JVM modules and native agent, plus
    the optional tools (Ghidra, unicorn, zig). Exits non-zero if a required
    piece is missing so it is safe to gate a setup script on it.
    """
    from rich.table import Table

    try:
        root = project_root()
    except RuntimeError:
        root = Path.cwd()

    report = doctor_mod.build_report(root)

    symbol = {
        doctor_mod.STATUS_OK: "[green]OK[/]",
        doctor_mod.STATUS_MISSING: "[red]MISSING[/]",
        doctor_mod.STATUS_WARN: "[yellow]WARN[/]",
        doctor_mod.STATUS_OPTIONAL: "[dim]optional[/]",
    }

    table = Table(title="j2c-dumper doctor", show_lines=False)
    table.add_column("Check", style="bold")
    table.add_column("Status")
    table.add_column("Detail")
    for c in report.checks:
        table.add_row(c.name, symbol.get(c.status, c.status), c.detail)
    console.print(table)

    fixes = [c for c in report.checks if c.fix and c.status != doctor_mod.STATUS_OK]
    if fixes:
        console.print("\n[bold]Next steps:[/]")
        for c in fixes:
            tag = "(optional) " if c.optional else ""
            console.print(f"  - {tag}{c.name}: {c.fix}")

    if report.healthy:
        # These checks confirm the required tool versions and that the build
        # artifacts the default path needs are present. They do not launch the
        # JVM modules or load the agent, so this is a readiness of the inputs,
        # not a guarantee that a given target recovers cleanly.
        console.print("\n[bold green]Required checks passed.[/] "
                      "Versions and build artifacts for the default path are "
                      "in place.")
        for c in report.warnings:
            console.print(f"[yellow]note:[/] {c.name}: {c.detail}")
        console.print(f"Try: {CLI} recover IN.jar -o OUT.jar "
                      "--run-cmd \"java -jar IN.jar\"")
    else:
        missing = ", ".join(c.name for c in report.blocking)
        console.print(f"\n[bold red]Not ready.[/] Missing: {missing}. "
                      "Run scripts/setup.sh (or scripts/setup.ps1) to fix.")
        raise typer.Exit(code=1)


@app.command()
def recover(
    jar: Path = typer.Argument(..., exists=True, dir_okay=False, help="Input (obfuscated) jar"),
    lib: Optional[Path] = typer.Option(None, "--lib", help="Native library (auto-extracted from jar if omitted)"),
    output: Path = typer.Option(..., "-o", "--output", help="Output (clean) jar"),
    run_cmd: Optional[str] = typer.Option(None, "--run-cmd",
                                          help="Command to execute the jar for dynamic trace (e.g. 'java -jar in.jar')"),
    no_dynamic: bool = typer.Option(False, "--no-dynamic"),
    no_static: bool = typer.Option(False, "--no-static"),
    ghidra_dump: Optional[Path] = typer.Option(None, "--ghidra-dump", help="Pre-generated Ghidra dump JSON (skip Ghidra invocation)"),
    workdir: Optional[Path] = typer.Option(None, "--workdir", help="Working directory for intermediate files"),
):
    """One-shot orchestration: parse → introspect → merge → trace → recover → rebuild.

    This is the default path. With --run-cmd it runs the JVMTI agent against a
    live launch of the JAR (dynamic recovery). Without a runnable JAR, use the
    emulation fallback instead — see docs/getting-started.md.
    """
    _preflight_recover(run_cmd=run_cmd, no_dynamic=no_dynamic)
    if workdir is None:
        workdir = Path(tempfile.mkdtemp(prefix="j2c-"))
    workdir.mkdir(parents=True, exist_ok=True)
    console.log(f"[green]workdir:[/] {workdir}")

    classes_json = workdir / "classes.json"
    binary_json = workdir / "binary.json"
    manifest_json = workdir / "manifest.json"
    trace_jsonl = workdir / "trace.jsonl"
    recovered_dir = workdir / "recovered"

    console.rule("[1/6] parse-jar")
    _run_parse_jar(jar, classes_json)

    # Auto-extract a native lib if not given
    if lib is None:
        with zipfile.ZipFile(jar) as zf:
            candidates = [n for n in zf.namelist()
                          if n.endswith((".dll", ".so", ".dylib"))]
            if candidates:
                extract_to = workdir / "extracted-lib"
                extract_to.mkdir(exist_ok=True)
                # Prefer host-matching lib name
                host_marker = "windows" if os.name == "nt" else ("macos" if sys.platform == "darwin" else "linux")
                pick = next((c for c in candidates if host_marker in c), candidates[0])
                lib = extract_to / Path(pick).name
                lib.write_bytes(zf.read(pick))
                console.log(f"[cyan]extracted native lib:[/] {lib}")
    if lib is None:
        console.print("[yellow]warning:[/] no native lib found in jar; binary-introspect will be skipped")

    console.rule("[2/6] inspect-binary")
    if lib is not None:
        _run_inspect_binary(lib, binary_json)
    else:
        binary_json.write_text(json.dumps({"schemaVersion": 1, "input": {"format": "PE", "arch": "?", "sha256": "0" * 64, "libPath": ""}, "stringPool": {"strings": [], "totalBytes": 0}, "nativeRegistry": [], "hiddenClasses": []}, indent=2))

    console.rule("[3/6] merge-manifest")
    _run_merge_manifest(classes_json, binary_json if lib else None, manifest_json)

    if not no_dynamic and run_cmd:
        console.rule("[4/6] dynamic-trace")
        _run_dynamic_trace(run_cmd, trace_jsonl)
        console.rule("[4b/6] trace-to-bytecode")
        _run_trace_to_bc(trace_jsonl, manifest_json, recovered_dir, "low")
    else:
        console.log("[yellow]skipping dynamic trace[/]")
        recovered_dir.mkdir(exist_ok=True)

    if not no_static and ghidra_dump:
        console.rule("[5/6] static-reverse")
        _run_static_reverse(ghidra_dump, recovered_dir, manifest_json)
    else:
        console.log("[yellow]skipping static reverse[/] (no --ghidra-dump)")

    console.rule("[6/6] rebuild")
    _run_rebuild(jar, recovered_dir, output, manifest_json)
    console.print(f"[bold green]done:[/] {output}")


if __name__ == "__main__":
    app()
