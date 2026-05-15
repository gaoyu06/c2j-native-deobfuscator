"""CLI: ast-matcher [ghidra-dump.json | .cpp file] -o recovered/

The lifter recognises two inputs:
  - a Ghidra pseudo-C dump JSON  ({"functions": [{addr, name, code}, ...]});
  - a raw ``.cpp`` / ``.c`` file from a native-obfuscator output directory
    (where ``cstack[N].x`` / ``clocal[N].x`` slot naming is still present).

Every per-feature inference can be toggled with ``--enable-<flag>`` /
``--disable-<flag>``. See :class:`ast_matcher.lifter.LifterOptions` for
the catalogue.
"""

from __future__ import annotations

import dataclasses
import json
import re
from pathlib import Path

import click

from .core import lift_cpp_file, lift_ghidra_dump
from .lifter import LifterOptions


_LIFTER_FLAGS = [f.name for f in dataclasses.fields(LifterOptions)]


@click.command(help=__doc__)
@click.argument("source", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-o", "--output", required=True, type=click.Path(path_type=Path),
              help="Recovered output directory.")
@click.option("--manifest", default=None,
              type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="manifest.json from manifest-merge — used for per-class "
                   "lookup tables + string-pool offsets.")
@click.option("--profile", "profile_name", default=None,
              help="Obfuscator profile (auto-detect when omitted).")
@click.option("--enable", "enables", multiple=True,
              type=click.Choice(_LIFTER_FLAGS),
              help="Force-enable a lifter feature (repeatable).")
@click.option("--disable", "disables", multiple=True,
              type=click.Choice(_LIFTER_FLAGS),
              help="Force-disable a lifter feature (repeatable).")
@click.option("--list-flags", is_flag=True,
              help="List lifter feature flags and exit.")
def main(
    source: Path,
    output: Path,
    manifest: Path | None,
    profile_name: str | None,
    enables: tuple[str, ...],
    disables: tuple[str, ...],
    list_flags: bool,
) -> None:
    if list_flags:
        opts = LifterOptions()
        for f in dataclasses.fields(LifterOptions):
            default = getattr(opts, f.name)
            doc = (f.metadata.get("help") if f.metadata else None) or ""
            click.echo(f"  {f.name:42s}  default={default}  {doc}")
        return

    options = LifterOptions()
    for flag in enables:
        setattr(options, flag, True)
    for flag in disables:
        setattr(options, flag, False)

    output.mkdir(parents=True, exist_ok=True)
    if source.suffix.lower() in (".cpp", ".cc", ".cxx", ".c"):
        results = lift_cpp_file(source, manifest)
    else:
        results = lift_ghidra_dump(
            source, manifest, options=options, profile_name=profile_name
        )

    for r in results:
        raw = r["owner"] + "__" + r["name"] + "__" + r["desc"]
        safe = re.sub(r"[^A-Za-z0-9_]", "_", raw)
        (output / f"{safe}.json").write_text(json.dumps(r, indent=2), encoding="utf-8")
    click.echo(f"Wrote {len(results)} methods to {output}", err=True)


if __name__ == "__main__":
    main()
