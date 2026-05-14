"""CLI: binary-introspect <lib> -o binary.json"""

from pathlib import Path

import click

from .core import introspect, write_report


@click.command(help="Parse a native-obfuscator-style .dll/.so/.dylib and dump metadata.")
@click.argument("lib", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-o", "--output", required=True, type=click.Path(path_type=Path), help="Path to write binary.json")
def main(lib: Path, output: Path) -> None:
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
