#!/usr/bin/env python3
"""Same-user Linux mock for the optional observer JSON-lines contract."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Iterable


class ObserverError(RuntimeError):
    """A user-facing contract smoke-test failure."""


def positive_pid(value: str) -> int:
    pid = int(value)
    if pid <= 0:
        raise argparse.ArgumentTypeError("PID must be a positive integer")
    return pid


def parse_maps(lines: Iterable[str], process_id: int) -> list[dict[str, object]]:
    """Convert file-backed Linux maps entries to module-load records."""
    modules: dict[tuple[str, int], int] = {}

    for line in lines:
        fields = line.rstrip("\n").split(maxsplit=5)
        if len(fields) != 6:
            continue

        address_range, _permissions, offset_text, _device, _inode, path = fields
        if path.startswith("["):
            continue
        if path.endswith(" (deleted)"):
            path = path.removesuffix(" (deleted)")

        try:
            start_text, end_text = address_range.split("-", maxsplit=1)
            start = int(start_text, 16)
            end = int(end_text, 16)
            offset = int(offset_text, 16)
        except ValueError:
            continue

        base_address = start - offset
        if base_address < 0 or end <= start:
            continue

        key = (path, base_address)
        modules[key] = max(modules.get(key, base_address), end)

    records = []
    for (path, base_address), mapped_end in sorted(
        modules.items(), key=lambda item: (item[0][1], item[0][0])
    ):
        records.append(
            {
                "kind": "module-load",
                "process_id": process_id,
                "module_name": Path(path).name,
                "base_address": base_address,
                "image_size": mapped_end - base_address,
            }
        )
    return records


def read_same_user_maps(pid: int) -> list[dict[str, object]]:
    process_dir = Path("/proc") / str(pid)
    try:
        owner = process_dir.stat().st_uid
    except FileNotFoundError as exc:
        raise ObserverError(f"process {pid} does not exist") from exc
    except OSError as exc:
        raise ObserverError(f"cannot inspect process {pid}: {exc}") from exc

    current_user = os.geteuid()
    if owner != current_user:
        raise ObserverError(
            f"process {pid} belongs to user ID {owner}, not current user ID "
            f"{current_user}"
        )

    maps_path = process_dir / "maps"
    try:
        with maps_path.open(encoding="utf-8") as maps_file:
            if os.fstat(maps_file.fileno()).st_uid != current_user:
                raise ObserverError(f"process {pid} maps are not owned by current user")
            return parse_maps(maps_file, pid)
    except ObserverError:
        raise
    except OSError as exc:
        raise ObserverError(f"cannot read maps for process {pid}: {exc}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Emit module-load JSON-lines from a same-user Linux process. "
            "This is a userspace contract smoke test."
        )
    )
    parser.add_argument("--pid", required=True, type=positive_pid)
    parser.add_argument(
        "--i-own-this-process",
        action="store_true",
        help="confirm that the target process belongs to you",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.i_own_this_process:
        parser.error("--i-own-this-process confirmation is required")

    try:
        records = read_same_user_maps(args.pid)
    except ObserverError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for record in records:
        print(json.dumps(record, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
