from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import unittest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import mock_observer  # noqa: E402


class MockObserverTest(unittest.TestCase):
    def test_refuses_without_ownership_confirmation(self) -> None:
        result = subprocess.run(
            [sys.executable, str(HERE / "mock_observer.py"), "--pid", str(os.getpid())],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--i-own-this-process confirmation is required", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_parses_fake_maps_fixture(self) -> None:
        with (HERE / "fixtures" / "maps.txt").open(encoding="utf-8") as fixture:
            records = mock_observer.parse_maps(fixture, process_id=77)

        self.assertEqual(
            records,
            [
                {
                    "kind": "module-load",
                    "process_id": 77,
                    "module_name": "demo",
                    "base_address": 0x00400000,
                    "image_size": 0x4000,
                },
                {
                    "kind": "module-load",
                    "process_id": 77,
                    "module_name": "libexample.so",
                    "base_address": 0x7F0000000000,
                    "image_size": 0x3000,
                },
            ],
        )


if __name__ == "__main__":
    unittest.main()
