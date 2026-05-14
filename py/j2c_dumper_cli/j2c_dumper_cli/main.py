"""j2c-dumper top-level CLI."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Reverse-engineer native-obfuscator-style transpiled jars.",
)
console = Console(stderr=True)


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
            f"JVM module '{name}' not built. Run "
            f"`./gradlew :{name}:installDist` from jvm/ first."
        )
    return candidate


def native_lib() -> Path:
    """Path to the JVMTI agent shared library, if built."""
    root = project_root()
    libdir = root / "native" / "build" / "lib"
    if not libdir.exists():
        raise FileNotFoundError("native agent not built. Run native/build.sh first.")
    for name in ("j2c_agent.dll", "j2c_agent.so", "j2c_agent.dylib"):
        if (libdir / name).exists():
            return libdir / name
    raise FileNotFoundError(f"No j2c_agent.* under {libdir}")


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
    """One-shot orchestration: parse → introspect → merge → trace → recover → rebuild."""
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
