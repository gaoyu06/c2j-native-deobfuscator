"""CLI: ast-matcher <ghidra-dump.json> -o recovered/"""

from pathlib import Path

import click
import json

from .core import lift_ghidra_dump


@click.command(help="Lift Ghidra pseudo-C dump into per-method recovered/*.json.")
@click.argument("dump", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-o", "--output", required=True, type=click.Path(path_type=Path))
@click.option("--manifest", default=None, type=click.Path(exists=True, dir_okay=False, path_type=Path))
def main(dump: Path, output: Path, manifest: Path | None) -> None:
    import re
    output.mkdir(parents=True, exist_ok=True)
    results = lift_ghidra_dump(dump, manifest)
    for r in results:
        raw = r["owner"] + "__" + r["name"] + "__" + r["desc"]
        safe = re.sub(r'[^A-Za-z0-9_]', '_', raw)
        (output / f"{safe}.json").write_text(json.dumps(r, indent=2), encoding="utf-8")
    click.echo(f"Wrote {len(results)} methods to {output}", err=True)


if __name__ == "__main__":
    main()
