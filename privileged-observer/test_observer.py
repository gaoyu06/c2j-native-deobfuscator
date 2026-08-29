from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import observer  # noqa: E402


class ObserverTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary_directory = tempfile.TemporaryDirectory()
        cls.build_dir = Path(cls._temporary_directory.name)
        cls.plugin_path = cls.build_dir / "linux_maps.so"
        cls._compile_shared_library(
            HERE / "plugins" / "linux_maps.c",
            cls.plugin_path,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary_directory.cleanup()

    @classmethod
    def _compile_shared_library(cls, source: Path, output: Path) -> None:
        subprocess.run(
            [
                os.environ.get("CC", "cc"),
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fPIC",
                "-shared",
                "-I",
                str(HERE / "include"),
                str(source),
                "-o",
                str(output),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    def run_host(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(HERE / "observer.py"), *arguments],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_refuses_without_enable_flag(self) -> None:
        result = self.run_host(
            "--pid",
            str(os.getpid()),
            "--plugin",
            str(self.build_dir / "must-not-load.so"),
            "--i-own-this-process",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--i-enable-privileged-observer is required", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_refuses_without_ownership_confirmation(self) -> None:
        result = self.run_host(
            "--pid",
            str(os.getpid()),
            "--plugin",
            str(self.plugin_path),
            "--i-enable-privileged-observer",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--i-own-this-process confirmation is required", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_refuses_cross_user_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            proc_root = Path(temporary_directory)
            process_dir = proc_root / "77"
            process_dir.mkdir()
            owner = process_dir.stat().st_uid

            with self.assertRaisesRegex(
                observer.ObserverError,
                "belongs to user ID",
            ):
                observer.ensure_same_user(
                    77,
                    proc_root=proc_root,
                    effective_uid=owner + 1,
                )

    def test_parses_fake_maps_fixture(self) -> None:
        with (HERE / "fixtures" / "maps.txt").open(encoding="utf-8") as fixture:
            records = observer.parse_maps(fixture, process_id=77)

        self.assertEqual(
            records,
            [
                {
                    "kind": "module-load",
                    "process_id": 77,
                    "module_name": "demo",
                    "path": "/opt/example/bin/demo",
                    "base_address": 0x00400000,
                    "end_address": 0x00404000,
                    "image_size": 0x4000,
                },
                {
                    "kind": "module-load",
                    "process_id": 77,
                    "module_name": "libexample.so",
                    "path": "/usr/lib/libexample.so",
                    "base_address": 0x7F0000000000,
                    "end_address": 0x7F0000003000,
                    "image_size": 0x3000,
                },
            ],
        )

    def test_rejects_plugin_returning_another_abi_version(self) -> None:
        source = self.build_dir / "wrong_version.c"
        source.write_text(
            textwrap.dedent(
                """\
                #include "privileged_observer_plugin.h"

                static const struct po_plugin_v1 plugin = {
                    PO_ABI_VERSION + 1,
                    sizeof(struct po_plugin_v1),
                    "wrong-version",
                    PO_CAP_MAPS_READ,
                    0
                };

                PO_EXPORT const struct po_plugin_v1 *po_plugin_query(
                    uint32_t host_abi_version)
                {
                    (void)host_abi_version;
                    return &plugin;
                }
                """
            ),
            encoding="utf-8",
        )
        plugin_path = self.build_dir / "wrong_version.so"
        self._compile_shared_library(source, plugin_path)

        with self.assertRaisesRegex(observer.ObserverError, "returned ABI version 2"):
            observer.load_plugin(plugin_path)

    def test_linux_plugin_declares_maps_read(self) -> None:
        plugin = observer.load_plugin(self.plugin_path)

        self.assertEqual(plugin.name, "linux-proc-maps")
        self.assertEqual(plugin.capability_names, ("maps-read",))

    def test_linux_plugin_refuses_unsupported_host_abi(self) -> None:
        library = ctypes.CDLL(str(self.plugin_path))
        query = library.po_plugin_query
        query.argtypes = [ctypes.c_uint32]
        query.restype = ctypes.c_void_p

        self.assertIsNotNone(query(observer.ABI_VERSION))
        self.assertIsNone(query(observer.ABI_VERSION + 1))

    def test_reads_self_maps_as_metadata_only(self) -> None:
        result = self.run_host(
            "--pid",
            str(os.getpid()),
            "--plugin",
            str(self.plugin_path),
            "--i-enable-privileged-observer",
            "--i-own-this-process",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        records = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertTrue(records)
        allowed_fields = {
            "kind",
            "process_id",
            "module_name",
            "path",
            "base_address",
            "end_address",
            "image_size",
        }
        for record in records:
            self.assertEqual(set(record), allowed_fields)
            self.assertEqual(record["kind"], "module-load")
            self.assertEqual(record["process_id"], os.getpid())
            self.assertLess(record["base_address"], record["end_address"])


if __name__ == "__main__":
    unittest.main()
