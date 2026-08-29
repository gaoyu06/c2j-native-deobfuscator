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
from .attach_support import (
    CONFIRM_FLAG,
    STARTUP_PATH_RECOMMENDATION,
    AttachRefusal,
    build_agent_options,
    build_jcmd_agent_load_argv,
    classify_attach_error,
    current_uid,
    jcmd_load_error,
    parse_jcmd_return_code,
    read_proc_info,
    scan_cmdline_for_refusals,
    scan_cmdline_for_warnings,
    validate_attach_target,
)


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
    no_args_is_help=True,
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
# Live process attach (opt-in preview) — mechanism helpers
# ------------------------------------------------------------------

# Minimal helper using the documented JDK attach API (com.sun.tools.attach).
# Compiled on demand so the preview path doesn't need its own Gradle module.
_ATTACH_HELPER_SOURCE = """\
import com.sun.tools.attach.VirtualMachine;

public class J2cAttach {
    public static void main(String[] args) throws Exception {
        String pid = args[0];
        String path = args[1];
        String opts = args.length > 2 ? args[2] : "";
        VirtualMachine vm = VirtualMachine.attach(pid);
        try {
            vm.loadAgentPath(path, opts.isEmpty() ? null : opts);
        } finally {
            vm.detach();
        }
        System.out.println("j2c-attach: loaded " + path + " into pid " + pid);
    }
}
"""


def _jdk_tool(name: str) -> str:
    """Locate a JDK command-line tool (java / javac / jcmd)."""
    exe = f"{name}.exe" if os.name == "nt" else name
    java_home = os.environ.get("JAVA_HOME") or os.environ.get("JDK_HOME")
    if java_home:
        candidate = Path(java_home) / "bin" / exe
        if candidate.exists():
            return str(candidate)
    found = shutil.which(name)
    if found:
        return found
    raise FileNotFoundError(
        f"could not find '{name}'. Set JAVA_HOME or put the JDK bin/ on PATH."
    )


def _report_refusal(refusal: AttachRefusal) -> None:
    """Print a classified attach refusal/failure and exit non-zero.

    Never prints ``attached``: reaching here means the attach did not happen.
    """
    console.print(
        f"[red]error:[/] attach failed (reason={refusal.reason}): "
        f"{refusal.message}"
    )
    if refusal.detail:
        console.print(f"[dim]target output: {refusal.detail}[/]")
    if refusal.recommend_startup:
        console.print(f"[yellow]next step:[/] {STARTUP_PATH_RECOMMENDATION}")
    raise typer.Exit(code=1)


def _attach_via_jcmd(pid: int, agent_path: Path, opts: str) -> None:
    """Attach via `jcmd <pid> JVMTI.agent_load` (documented diagnostic command,
    routed through the same attach mechanism, invokes Agent_OnAttach).

    Two subtleties make a naive invocation report false success:
      * the diagnostic-command parser strips the value from a bare ``key=value``
        agent option, so the option string must be passed single-quoted; and
      * ``jcmd`` exits 0 even when ``Agent_OnAttach`` fails, printing
        ``return code: <N>`` on stdout — so we parse that and fail loudly.

    On any failure the error is classified into a stable reason code and the
    honest next step (startup ``-agentpath``) is printed.
    """
    jcmd = _jdk_tool("jcmd")
    argv = build_jcmd_agent_load_argv(jcmd, pid, str(agent_path), opts)
    console.log(f"[dim]$ {' '.join(argv)}[/]")
    res = subprocess.run(argv, check=False, capture_output=True, text=True)
    combined = f"{res.stdout}{res.stderr}"
    if combined.strip():
        console.log(combined.rstrip())
    error = jcmd_load_error(res.returncode, combined)
    if error:
        refusal = classify_attach_error(
            res.returncode, combined, parse_jcmd_return_code(combined)
        )
        _report_refusal(refusal)


def _attach_via_vm(pid: int, agent_path: Path, opts: str) -> None:
    """Attach via com.sun.tools.attach.VirtualMachine using a compiled helper.

    The compile step is a local-toolchain concern (surfaced by ``run``); the
    attach invocation itself captures output so a failure is classified into a
    stable reason code rather than an opaque Java stack trace.
    """
    javac = _jdk_tool("javac")
    java = _jdk_tool("java")
    helper_dir = Path(tempfile.mkdtemp(prefix="j2c-attach-"))
    src = helper_dir / "J2cAttach.java"
    src.write_text(_ATTACH_HELPER_SOURCE)
    run([javac, "-d", str(helper_dir), str(src)])
    argv = [java, "-cp", str(helper_dir), "J2cAttach", str(pid), str(agent_path), opts]
    console.log(f"[dim]$ {' '.join(str(x) for x in argv)}[/]")
    res = subprocess.run([str(x) for x in argv], check=False,
                         capture_output=True, text=True)
    combined = f"{res.stdout}{res.stderr}"
    if combined.strip():
        console.log(combined.rstrip())
    if res.returncode != 0:
        refusal = classify_attach_error(res.returncode, combined)
        _report_refusal(refusal)


def _do_attach(pid: int, agent_path: Path, opts: str, mechanism: str) -> None:
    mechanism = (mechanism or "auto").lower()
    if mechanism == "jcmd":
        _attach_via_jcmd(pid, agent_path, opts)
        return
    if mechanism == "vm":
        _attach_via_vm(pid, agent_path, opts)
        return
    if mechanism != "auto":
        raise typer.BadParameter(
            f"unknown --mechanism {mechanism!r}; choose auto | jcmd | vm"
        )
    # auto: prefer jcmd (no compile step); fall back to the VirtualMachine helper
    # only when jcmd itself is unavailable. A genuine agent-load failure must
    # propagate (not silently trigger a second attempt that reloads the agent).
    try:
        _attach_via_jcmd(pid, agent_path, opts)
    except FileNotFoundError as exc:
        console.log(
            f"[yellow]jcmd unavailable ({exc!r}); "
            "falling back to com.sun.tools.attach[/]"
        )
        _attach_via_vm(pid, agent_path, opts)


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


@app.command("attach")
def cli_attach(
    pid: int = typer.Option(
        ..., "--pid",
        help="PID of the already-running, same-user JVM to attach to (required).",
    ),
    output: Path = typer.Option(
        Path("trace.jsonl"), "-o", "--output",
        help="Where the agent writes the JSONL trace.",
    ),
    i_own_this_process: bool = typer.Option(
        False, "--i-own-this-process",
        help="Required confirmation that you own or may inspect this JVM "
             "(authorized, same-user use only).",
    ),
    agent: Optional[Path] = typer.Option(
        None, "--agent",
        help="Path to the built JVMTI agent (default: native/build/lib/j2c_agent.*).",
    ),
    log_all: bool = typer.Option(
        False, "--log-all",
        help="Log JNI calls even outside user native frames.",
    ),
    max_frame_events: Optional[int] = typer.Option(
        None, "--max-frame-events",
        help="Cap JNI events per native frame (0 = unlimited).",
    ),
    mechanism: str = typer.Option(
        "auto", "--mechanism",
        help="Attach mechanism: auto | jcmd | vm (com.sun.tools.attach).",
    ),
):
    """(preview) Attach the JVMTI agent to an already-running JVM you own.

    Opt-in diagnostic path — NOT the default recover flow. The default,
    highest-fidelity path is still startup instrumentation via -agentpath
    (see `recover` / `dynamic-trace`). Live attach only observes work that
    happens after attach. Coverage depends on which JVMTI capabilities the JDK
    grants after attach: on OpenJDK 21 typically only native-method-bind is
    available, so the trace holds `bind` events and method entry/exit,
    local-variable, and exception events are NOT captured. The trace's
    `capability` / `gap` records state exactly what was obtained. See
    docs/jvm-attach.md.
    """
    # 1. Refuse before touching the target unless ownership is confirmed.
    if not i_own_this_process:
        console.print(
            f"[red]refusing to attach without {CONFIRM_FLAG}.[/]\n"
            "Live process attach is opt-in and for same-user, authorized use "
            f"only. Re-run with {CONFIRM_FLAG} to confirm you own or may "
            "inspect this JVM."
        )
        raise typer.Exit(code=2)

    # 2. Best-effort same-user / looks-like-Java validation.
    proc = read_proc_info(pid)
    result = validate_attach_target(pid, proc, current_uid())
    for warning in result.warnings:
        console.print(f"[yellow]warning:[/] {warning}")
    if not result.ok:
        # cross-user / not-a-jvm carry a stable reason code: print the same
        # `attach failed (reason=<code>):` form as every other refusal.
        if result.refusals:
            _report_refusal(result.refusals[0])
        for problem in result.problems:
            console.print(f"[red]error:[/] {problem}")
        raise typer.Exit(code=2)

    # 2b. Non-fatal cmdline notes (e.g. jdk.attach.allowAttachSelf=false, which
    # only disables self-attach and does not block this external attach).
    for note in scan_cmdline_for_warnings(proc.cmdline):
        console.print(f"[yellow]warning:[/] {note}")

    # 2c. Pre-attach cmdline scan: if the target's own argv shows the attach or
    # dynamic-agent-loading mechanism is disabled, classify and refuse *before*
    # invoking jcmd/VirtualMachine. This is honest handling, not a bypass: the
    # remedy is to restart under startup instrumentation.
    refusal = scan_cmdline_for_refusals(proc.cmdline)
    if refusal is not None:
        _report_refusal(refusal)

    # 3. Resolve the agent library.
    if agent is not None:
        agent_path = agent
        if not agent_path.exists():
            console.print(f"[red]error:[/] agent not found: {agent_path}")
            raise typer.Exit(code=2)
    else:
        try:
            agent_path = native_lib()
        except FileNotFoundError as exc:
            console.print(f"[red]error:[/] {exc}")
            raise typer.Exit(code=2)

    opts = build_agent_options(str(output), log_all, max_frame_events)
    console.print(
        f"[cyan]attaching[/] agent={agent_path} pid={pid} "
        f"(comm={proc.comm or '?'}) mechanism={mechanism}"
    )
    _do_attach(pid, agent_path, opts, mechanism)
    console.print(
        f"[bold green]attached (preview).[/] trace -> {output}\n"
        "Clean stop: terminate the target JVM normally; the agent flushes and "
        "closes the trace on VM exit. Then feed the trace to `trace-to-bc`."
    )
    # Reduced coverage is not a refusal: the attach happened. Remind the user
    # that a live attach commonly obtains only native-method-bind (see the
    # trace's capability/gap records) and full method-body recovery needs the
    # startup -agentpath path.
    console.print(
        "[dim]note: a live attach commonly obtains only native-method-bind "
        "coverage (see the trace's capability/gap records); for full "
        "method-body recovery use the startup -agentpath path.[/]"
    )


if __name__ == "__main__":
    app()
