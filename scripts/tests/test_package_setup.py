"""Portable Windows packaging and cache-filter regression tests.

Run: python -m unittest discover -s scripts/tests
"""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'package_setup', Path(__file__).resolve().parents[1] / 'package_setup.py')
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)


class PackagingTests(unittest.TestCase):
    def test_caches_excluded_at_any_depth(self):
        for path in ('native/.zig-cache/o/hash', 'native/zig-cache/tmp/file',
                     '.zig-cache', '.cache/zig/hash', 'native/.cache/zig/hash',
                     'jvm/.gradle/cache', 'py/.uv-cache/wheels',
                     'py/module/__pycache__/a.pyc'):
            with self.subTest(path=path):
                self.assertTrue(packager.excluded(Path(path), windows=True))
                self.assertTrue(packager.excluded(Path(path), windows=False))

    def test_outputs_retained_but_windows_venv_excluded(self):
        for path in ('native/build/lib/j2c_agent.dll',
                     'jvm/jar-parser/build/install/jar-parser/lib/parser.jar',
                     'runtime/python/python.exe', 'native/zig-out/lib/agent.dll'):
            self.assertFalse(packager.excluded(Path(path), windows=True))
        self.assertTrue(packager.excluded(Path('py/.venv'), windows=True))
        self.assertFalse(packager.excluded(Path('py/.venv'), windows=False))

    def test_standalone_runtime_copies_base_and_noneditable_packages(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'checkout'
            base = Path(tmp) / 'runner Python'
            source_site = root / 'py/.venv/Lib/site-packages'
            (base / 'Lib/encodings').mkdir(parents=True)
            (base / 'DLLs').mkdir()
            (base / 'python.exe').write_bytes(b'base-executable')
            (base / 'python313.dll').write_bytes(b'base-dll')
            (base / 'Lib/site-packages').mkdir()
            (base / 'Lib/site-packages/unwanted.py').touch()
            for package in packager.WORKSPACE_PACKAGES:
                (source_site / package).mkdir(parents=True)
                (source_site / package / '__init__.py').write_text('# wheel')
            (source_site / '_virtualenv.pth').write_text('import _virtualenv')
            (source_site / 'capstone.dll').write_bytes(b'native-dependency')
            info = json.dumps(dict(base=str(base), site=str(source_site), version='313'))
            with patch.object(packager.subprocess, 'run') as sync, \
                    patch.object(packager.subprocess, 'check_output', return_value=info):
                python = packager.prepare_windows_runtime(root, Path('venv-python'))
            self.assertEqual(sync.call_args.args[0],
                             ['uv', 'sync', '--all-packages', '--no-editable'])
            self.assertEqual(python.read_bytes(), b'base-executable')
            runtime = root / 'runtime/python'
            site = runtime / 'Lib/site-packages'
            self.assertEqual((site / 'capstone.dll').read_bytes(), b'native-dependency')
            self.assertFalse((site / 'unwanted.py').exists())
            self.assertFalse((site / '_virtualenv.pth').exists())
            paths = (runtime / 'python313._pth').read_text().splitlines()
            self.assertEqual(paths, ['.', 'DLLs', 'Lib', 'Lib/site-packages', 'import site'])
            self.assertFalse((runtime / 'pyvenv.cfg').exists())


if __name__ == '__main__':
    unittest.main()
