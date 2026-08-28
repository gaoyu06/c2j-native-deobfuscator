#!/usr/bin/env python3
"""Opt-in host for metadata-only privileged-observer userspace plugins."""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
import json
import os
from pathlib import Path
import sys
from typing import Iterable


ABI_VERSION = 1
CAP_MAPS_READ = 1 << 0
DEFAULT_PLUGIN = Path(__file__).resolve().parent / "build" / "linux_maps.so"

_STATUS_MESSAGES = {
    1: "plugin rejected its arguments",
    2: "plugin refused the target",
    3: "target process was not found",
    4: "plugin could not read the module map",
    5: "plugin could not emit a module record",
}


class ObserverError(RuntimeError):
    """A refusal or plugin error that is safe to show to the operator."""


_EmitModule = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_uint64,
    ctypes.c_uint64,
)
_ObservePid = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_uint32,
    _EmitModule,
    ctypes.c_void_p,
)


class _PluginV1(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint32),
        ("struct_size", ctypes.c_uint32),
        ("name", ctypes.c_char_p),
        ("capabilities", ctypes.c_uint64),
        ("observe_pid", _ObservePid),
    ]


@dataclass
class Plugin:
    """A loaded ABI v1 plugin; the library field keeps callbacks valid."""

    path: Path
    name: str
    capabilities: int
    _library: ctypes.CDLL
    _observe_pid: _ObservePid

    @property
    def capability_names(self) -> tuple[str, ...]:
        names = []
        if self.capabilities & CAP_MAPS_READ:
            names.append("maps-read")
        return tuple(names)

    def module_records(self, process_id: int) -> list[dict[str, object]]:
        regions: list[tuple[str, int, int]] = []
        callback_error: list[str] = []

        @_EmitModule
        def emit_module(
            _context: int,
            path_bytes: bytes | None,
            base_address: int,
            end_address: int,
        ) -> int:
            if not path_bytes:
                callback_error.append("plugin emitted an empty module path")
                return 1
            if end_address <= base_address:
                callback_error.append("plugin emitted an invalid address range")
                return 1
            regions.append(
                (os.fsdecode(path_bytes), int(base_address), int(end_address))
            )
            return 0

        status = self._observe_pid(process_id, emit_module, None)
        if callback_error:
            raise ObserverError(callback_error[0])
        if status != 0:
            message = _STATUS_MESSAGES.get(status, f"plugin failed with status {status}")
            raise ObserverError(message)
        return _records_from_regions(regions, process_id)


def positive_pid(value: str) -> int:
    try:
        process_id = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("PID must be a positive integer") from exc
    if process_id <= 0 or process_id > 0xFFFFFFFF:
        raise argparse.ArgumentTypeError("PID must be a positive 32-bit integer")
    return process_id


def ensure_same_user(
    process_id: int,
    *,
    proc_root: Path = Path("/proc"),
    effective_uid: int | None = None,
) -> None:
    """Refuse a missing process or one not owned by the effective user."""
    process_dir = proc_root / str(process_id)
    try:
        owner = process_dir.stat().st_uid
    except FileNotFoundError as exc:
        raise ObserverError(f"process {process_id} does not exist") from exc
    except OSError as exc:
        raise ObserverError(f"cannot inspect process {process_id}: {exc}") from exc

    current_user = os.geteuid() if effective_uid is None else effective_uid
    if owner != current_user:
        raise ObserverError(
            f"process {process_id} belongs to user ID {owner}, "
            f"not current user ID {current_user}"
        )


def _records_from_regions(
    regions: Iterable[tuple[str, int, int]],
    process_id: int,
) -> list[dict[str, object]]:
    modules: dict[tuple[str, int], int] = {}
    for path, base_address, end_address in regions:
        if not path or base_address < 0 or end_address <= base_address:
            continue
        key = (path, base_address)
        modules[key] = max(modules.get(key, base_address), end_address)

    records = []
    for (path, base_address), end_address in sorted(
        modules.items(), key=lambda item: (item[0][1], item[0][0])
    ):
        records.append(
            {
                "kind": "module-load",
                "process_id": process_id,
                "module_name": Path(path).name,
                "path": path,
                "base_address": base_address,
                "end_address": end_address,
                "image_size": end_address - base_address,
            }
        )
    return records


def parse_maps(
    lines: Iterable[str],
    process_id: int,
) -> list[dict[str, object]]:
    """Parse Linux maps text using the same normalization as the C plugin."""
    regions = []
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
            start_address = int(start_text, 16)
            end_address = int(end_text, 16)
            file_offset = int(offset_text, 16)
        except ValueError:
            continue
        base_address = start_address - file_offset
        if base_address < 0 or end_address <= start_address:
            continue
        regions.append((path, base_address, end_address))

    return _records_from_regions(regions, process_id)


def load_plugin(path: Path) -> Plugin:
    """Load and negotiate one ABI v1 shared-library plugin."""
    try:
        library = ctypes.CDLL(str(path))
    except OSError as exc:
        raise ObserverError(f"cannot load plugin {path}: {exc}") from exc

    try:
        query = library.po_plugin_query
    except AttributeError as exc:
        raise ObserverError("plugin does not export po_plugin_query") from exc
    query.argtypes = [ctypes.c_uint32]
    query.restype = ctypes.POINTER(_PluginV1)

    descriptor_pointer = query(ABI_VERSION)
    if not descriptor_pointer:
        raise ObserverError(f"plugin does not support ABI version {ABI_VERSION}")
    descriptor = descriptor_pointer.contents
    if descriptor.abi_version != ABI_VERSION:
        raise ObserverError(
            f"plugin returned ABI version {descriptor.abi_version}; "
            f"host requires {ABI_VERSION}"
        )
    if descriptor.struct_size < ctypes.sizeof(_PluginV1):
        raise ObserverError("plugin descriptor is smaller than ABI version 1")
    if not descriptor.name:
        raise ObserverError("plugin has no name")
    if not descriptor.observe_pid:
        raise ObserverError("plugin has no process observer")
    if not descriptor.capabilities & CAP_MAPS_READ:
        raise ObserverError("plugin does not declare the maps-read capability")

    try:
        name = descriptor.name.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ObserverError("plugin name is not UTF-8") from exc
    return Plugin(
        path=path,
        name=name,
        capabilities=descriptor.capabilities,
        _library=library,
        _observe_pid=descriptor.observe_pid,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Load an opt-in userspace plugin and print same-user module "
            "path/address metadata as JSON lines."
        )
    )
    parser.add_argument("--pid", required=True, type=positive_pid)
    parser.add_argument(
        "--plugin",
        type=Path,
        default=DEFAULT_PLUGIN,
        help=f"ABI plugin shared library (default: {DEFAULT_PLUGIN})",
    )
    parser.add_argument(
        "--i-enable-privileged-observer",
        action="store_true",
        help="explicitly enable this optional module",
    )
    parser.add_argument(
        "--i-own-this-process",
        action="store_true",
        help="confirm that the target process belongs to you",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.i_enable_privileged_observer:
        parser.error("--i-enable-privileged-observer is required")
    if not args.i_own_this_process:
        parser.error("--i-own-this-process confirmation is required")

    try:
        ensure_same_user(args.pid)
        plugin = load_plugin(args.plugin)
        records = plugin.module_records(args.pid)
    except ObserverError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for record in records:
        print(json.dumps(record, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
