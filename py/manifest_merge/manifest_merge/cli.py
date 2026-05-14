"""CLI: manifest-merge <classes.json> <binary.json> -o manifest.json"""

from pathlib import Path

import click

from .core import load, merge, stats, write


@click.command(help="Join classes.json (jar-parser) + binary.json (binary-introspect) into a manifest.json.")
@click.argument("classes", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("binary", required=False, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-o", "--output", required=True, type=click.Path(path_type=Path))
def main(classes: Path, binary: Path | None, output: Path) -> None:
    classes_doc = load(classes)
    binary_doc = load(binary) if binary else None
    merged = merge(classes_doc, binary_doc)
    write(merged, output)
    s = stats(merged)
    click.echo(
        f"Wrote {output}\n"
        f"  classes={s['classes']} obfuscatedMethods={s['obfuscatedMethods']} "
        f"fnAddrResolved={s['fnAddrResolved']} hiddenClasses={s['hiddenClasses']}",
        err=True,
    )


if __name__ == "__main__":
    main()
