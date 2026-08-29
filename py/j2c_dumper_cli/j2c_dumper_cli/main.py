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
    help="Inspect JNI-native transpiled methods and restore bytecode.",
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


def _emulation_script() -> Path:
    return project_root() / "py" / "native_emulate" / "j2c_emu.py"


def _run_native_emulate(args: list[str | Path]) -> None:
    run([sys.executable, _emulation_script(), *args])


def _run_inspect_binary(
    lib: Path,
    output: Path,
    *,
    profile: str | None = None,
    emulate_registration: bool = False,
    registrars: list[str] | None = None,
) -> None:
    from binary_introspect.core import (
        add_emulated_registry,
        introspect,
        write_report,
    )

    report = introspect(lib, profile_name=profile)
    if emulate_registration:
        with tempfile.TemporaryDirectory(prefix="j2c-emu-") as tmp:
            captured = Path(tmp) / "methods.json"
            args: list[str | Path] = [
                "recover", lib, "--json-output", captured,
            ]
            if registrars:
                args += ["--registrar", *registrars]
            _run_native_emulate(args)
            if captured.exists():
                add_emulated_registry(
                    report,
                    json.loads(captured.read_text(encoding="utf-8")),
                )
    write_report(report, output)
    # Surface the selected profile and registry size so the user can see which
    # obfuscator variant was detected. bindingGaps are intentionally NOT printed
    # here: they live on the manifest, not binary.json, and only exist after the
    # merge stage binds tables to jar classes.
    selected_profile = (report.analysis or {}).get("profile", "?")
    # An unreadable table is a visible RegisterNatives site whose method
    # name/descriptor bytes did not decode; surface the honest count so the
    # gap is never silently dropped from the human output.
    unreadable_tables = (report.analysis or {}).get("unreadableTables", 0)
    console.print(
        f"inspect-binary: {output} "
        f"format={report.fmt} arch={report.arch} "
        f"profile={selected_profile} "
        f"registry-records={len(report.native_registry)} "
        f"unreadableTables={unreadable_tables}"
    )


def _print_binding_gaps(manifest: Path) -> None:
    """Print the manifest's bindingGaps count and kinds to the console.

    bindingGaps are a manifest-level fact (a native table that could not be
    unambiguously bound to a jar class); they never appear on binary.json.
    """
    try:
        doc = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    gaps = doc.get("bindingGaps") or []
    if not gaps:
        console.print("merge-manifest: bindingGaps=0")
        return
    kinds = sorted({str(gap.get("kind", "unknown")) for gap in gaps})
    console.print(
        f"merge-manifest: bindingGaps={len(gaps)} kinds={','.join(kinds)}"
    )


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
    _print_binding_gaps(output)


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
    profile: Optional[str] = typer.Option(
        None, "--profile", help="Discovery profile; defaults to auto-detection."
    ),
    emulate_registration: bool = typer.Option(
        False,
        "--emulate-registration",
        help="Optionally capture RegisterNatives while emulating exports/JNI_OnLoad.",
    ),
    registrar: Optional[list[str]] = typer.Option(
        None,
        "--registrar",
        help="Registrar address for optional emulation (repeatable).",
    ),
):
    """Create binary.json with a JNI method list; no Ghidra required."""
    _run_inspect_binary(
        lib,
        output,
        profile=profile,
        emulate_registration=emulate_registration,
        registrars=registrar,
    )


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
    """Optional: lift a Ghidra pseudo-C dump into recovered/*.json."""
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


@app.command("synth-stubs")
def cli_synth_stubs(
    manifest: Path = typer.Option(
        ..., "--manifest", exists=True, dir_okay=False
    ),
    output: Path = typer.Option(..., "-o", "--output"),
):
    """Create bytecode-restoration stubs from a method manifest."""
    from binary_introspect.stub_recovery import synthesize_stubs

    count = synthesize_stubs(manifest, output)
    console.print(f"created {count} stub(s) in {output}")


@app.command("static-lite")
def cli_static_lite(
    jar: Path = typer.Argument(..., exists=True, dir_okay=False),
    lib: Path = typer.Option(..., "--lib", exists=True, dir_okay=False),
    output: Path = typer.Option(..., "-o", "--output"),
    profile: str = typer.Option(
        "generic", "--profile", help="Method-discovery profile."
    ),
    emulate_registration: bool = typer.Option(
        False,
        "--emulate-registration",
        help="Also capture registration through binary emulation.",
    ),
    registrar: Optional[list[str]] = typer.Option(
        None,
        "--registrar",
        help="Registrar address for optional emulation (repeatable).",
    ),
):
    """Build binary.json, manifest.json, and stubs without Ghidra."""
    from binary_introspect.stub_recovery import synthesize_stubs

    output.mkdir(parents=True, exist_ok=True)
    classes_json = output / "classes.json"
    binary_json = output / "binary.json"
    manifest_json = output / "manifest.json"
    recovered_dir = output / "recovered"

    _run_parse_jar(jar, classes_json)
    _run_inspect_binary(
        lib,
        binary_json,
        profile=profile,
        emulate_registration=emulate_registration,
        registrars=registrar,
    )
    _run_merge_manifest(classes_json, binary_json, manifest_json)
    count = synthesize_stubs(manifest_json, recovered_dir)
    console.print(
        f"static-lite wrote binary.json, manifest.json, and "
        f"{count} stub(s) under {output}"
    )


@app.command("emulate")
def cli_emulate(
    lib: Path = typer.Argument(..., exists=True, dir_okay=False),
    operation: str = typer.Option(
        "recover", "--operation", help="recover, strings, or call"
    ),
    fn: Optional[str] = typer.Option(
        None, "--fn", help="Function address for strings/call."
    ),
    binary_json: Optional[Path] = typer.Option(
        None, "--binary-json", exists=True, dir_okay=False
    ),
    json_output: Optional[Path] = typer.Option(None, "--json-output"),
    registrar: Optional[list[str]] = typer.Option(
        None, "--registrar", help="Registrar address (repeatable)."
    ),
    arg_bytes: Optional[str] = typer.Option(None, "--arg-bytes"),
    arg_str: Optional[str] = typer.Option(None, "--arg-str"),
    static: Optional[list[str]] = typer.Option(
        None, "--static", help="field=value or field=@file (repeatable)."
    ),
):
    """Optional binary emulation for method, string, and oracle output."""
    if operation not in {"recover", "strings", "call"}:
        raise typer.BadParameter("operation must be recover, strings, or call")
    if operation in {"strings", "call"} and fn is None:
        raise typer.BadParameter("--fn is required for strings and call")

    args: list[str | Path] = [operation, lib]
    if fn is not None:
        args += ["--fn", fn]
    if operation == "recover":
        if binary_json is not None:
            args += ["--binary-json", binary_json]
        if json_output is not None:
            args += ["--json-output", json_output]
        if registrar:
            args += ["--registrar", *registrar]
    if operation == "call":
        if arg_bytes is not None:
            args += ["--arg-bytes", arg_bytes]
        if arg_str is not None:
            args += ["--arg-str", arg_str]
    if operation in {"strings", "call"} and static:
        args += ["--static", *static]
    _run_native_emulate(args)


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
