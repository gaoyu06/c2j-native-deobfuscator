"""CLI: binary-introspect <lib> -o binary.json   (default)
         binary-introspect synth-stubs --manifest <m.json> -o <recovered/>
"""

from pathlib import Path

import click

from .core import introspect, write_report
from .stub_recovery import synthesize_stubs


@click.group(invoke_without_command=True, help="Native-binary introspection tools.")
@click.pass_context
def cli(ctx: click.Context) -> None:
    if ctx.invoked_subcommand is None and ctx.args:
        # legacy single-arg invocation: `binary-introspect <lib> -o binary.json`
        ctx.invoke(introspect_cmd)


@cli.command("introspect", help="Parse a native-obfuscator-style .dll/.so/.dylib.")
@click.argument("lib", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-o", "--output", required=True, type=click.Path(path_type=Path),
              help="Path to write binary.json")
@click.option("--profile", "profile_name", default=None,
              help="Obfuscator profile to apply (auto-detect when omitted). "
                   "Use --list-profiles to see installed profiles.")
@click.option("--list-profiles", is_flag=True,
              help="List installed obfuscator profiles and exit.")
def introspect_cmd(lib: Path, output: Path, profile_name: str | None,
                   list_profiles: bool) -> None:
    if list_profiles:
        from .profile import list_profiles as lp, get_profile
        for n in lp():
            p = get_profile(n)
            click.echo(f"  {n:20}  {p.description}")
        return
    report = introspect(lib, profile_name=profile_name)
    write_report(report, output)
    click.echo(
        f"Wrote {output}\n"
        f"  format={report.fmt} arch={report.arch}\n"
        f"  strings={len(report.string_pool)} hidden-classes={len(report.hidden_classes)} "
        f"exports={len(report.exported_functions)}",
        err=True,
    )


@cli.command("synth-stubs", help="Synthesize stub recovered/*.json for native methods with known fnAddr.")
@click.option("--manifest", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-o", "--output", required=True, type=click.Path(path_type=Path))
def synth_stubs_cmd(manifest: Path, output: Path) -> None:
    n = synthesize_stubs(manifest, output)
    click.echo(f"Synthesized {n} stub(s) → {output}", err=True)


@click.command(help="Parse a native-obfuscator-style .dll/.so/.dylib and dump metadata.")
@click.argument("lib", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-o", "--output", required=True, type=click.Path(path_type=Path),
              help="Path to write binary.json")
def main(lib: Path, output: Path) -> None:
    """Backward-compatible single-arg entry."""
    report = introspect(lib)
    write_report(report, output)
    click.echo(
        f"Wrote {output}\n"
        f"  format={report.fmt} arch={report.arch}\n"
        f"  strings={len(report.string_pool)} hidden-classes={len(report.hidden_classes)} "
        f"exports={len(report.exported_functions)}",
        err=True,
    )


if __name__ == "__main__":
    main()
