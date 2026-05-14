"""CLI: snippet-importer <cppsnippets.properties> -o supplementary-rules.json"""

from pathlib import Path

import click

from .core import main_run


@click.command(help="(Optional, native-obfuscator-specific) Generate supplementary AST matching rules from cppsnippets.properties.")
@click.argument("properties_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-o", "--output", required=True, type=click.Path(path_type=Path))
def main(properties_path: Path, output: Path) -> None:
    main_run(properties_path, output)
    click.echo(f"Wrote {output}", err=True)


if __name__ == "__main__":
    main()
