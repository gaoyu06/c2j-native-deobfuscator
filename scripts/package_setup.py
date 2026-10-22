"""Package setup outputs, omitting build caches and Windows runner-only venvs.

Run from the repository root after setup. Output lives outside the checkout.
Symlinks and Unix permissions are retained in the ZIP.
"""
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import tempfile
import zipfile


CACHE_NAMES = {'.git', '.zig-cache', 'zig-cache', '.gradle', '.kotlin',
               '.uv-cache', '__pycache__'}
WORKSPACE_PACKAGES = ('j2c_dumper_cli', 'binary_introspect', 'manifest_merge',
                      'ast_matcher', 'snippet_importer')
NATIVE_PROBE = (
    'import capstone, lief; '
    'x86 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); '
    'arm = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM); '
    'assert next(x86.disasm(bytes.fromhex("90"), 0)).mnemonic == "nop"; '
    'assert next(arm.disasm(bytes.fromhex("1f2003d5"), 0)).mnemonic == "nop"; '
    'print("Native dependencies OK: Capstone", capstone.__version__, '
    '"/ LIEF", lief.__version__)'
)


def excluded(relative, windows):
    parts = relative.parts
    return (bool(set(parts) & CACHE_NAMES)
            or any(parts[i:i + 2] == ('.cache', 'zig') for i in range(len(parts) - 1))
            or (windows and parts[:2] == ('py', '.venv')))


def prepare_windows_runtime(root, python):
    # Wheel installs remove editable .pth references to the runner checkout.
    subprocess.run(['uv', 'sync', '--all-packages', '--no-editable'],
                   cwd=root / 'py', check=True)
    info = json.loads(subprocess.check_output([
        str(python), '-c',
        'import json, sys, sysconfig; print(json.dumps({'
        '"base": sys.base_prefix, "site": sysconfig.get_path("purelib"), '
        '"version": str(sys.version_info.major) + str(sys.version_info.minor)}))',
    ], text=True))
    base = Path(info['base'])
    runtime = root / 'runtime/python'
    if not (base / 'python.exe').is_file() or not (base / 'Lib/encodings').is_dir():
        raise RuntimeError(f'Expected a full Windows CPython installation at {base}')
    if runtime.exists():
        shutil.rmtree(runtime)
    shutil.copytree(base, runtime, ignore=shutil.ignore_patterns(
        'site-packages', 'Scripts', '__pycache__', '*.pyc', '*.pdb'))
    site = runtime / 'Lib/site-packages'
    shutil.copytree(info['site'], site, ignore=shutil.ignore_patterns(
        '__pycache__', '*.pyc', '_virtualenv.pth', '_virtualenv.py'))
    for package in WORKSPACE_PACKAGES:
        if not (site / package / '__init__.py').is_file():
            raise RuntimeError(f'Non-editable installation missing: {package}')
    # CPython's isolated path file prevents registry/PYTHONHOME settings from
    # selecting an installation outside this relocated runtime.
    (runtime / f'python{info["version"]}._pth').write_text(
        '.\nDLLs\nLib\nLib/site-packages\nimport site\n', encoding='utf-8')
    return runtime / 'python.exe'


def verify_windows_archive(archive, prefix):
    # Test the actual ZIP after moving it to a new path, through the user launcher.
    with tempfile.TemporaryDirectory(prefix='c2j relocated ') as temporary:
        with zipfile.ZipFile(archive) as z:
            z.extractall(temporary)
        moved = Path(temporary) / prefix
        python = moved / 'runtime/python/python.exe'
        subprocess.run([str(python), '-I', '-c',
                        'import pathlib, sys; '
                        'r = pathlib.Path(sys.executable).resolve().parent; '
                        'assert pathlib.Path(sys.base_prefix).resolve() == r; '
                        'assert all(pathlib.Path(p).resolve().is_relative_to(r) '
                        'for p in sys.path); '
                        'from j2c_dumper_cli.main import project_root; '
                        'assert project_root() == r.parent.parent; ' + NATIVE_PROBE],
                       check=True, cwd=moved, timeout=120)
        jar = moved / 'relocation-test.jar'
        with zipfile.ZipFile(jar, 'w') as z:
            z.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\n\n')
        subprocess.run(['pwsh', '-NoProfile', '-File',
                        str(moved / 'scripts/j2c.ps1'), 'parse-jar',
                        str(jar), '-o', str(moved / 'classes.json')],
                       check=True, cwd=moved, timeout=120)
        result = json.loads((moved / 'classes.json').read_text(encoding='utf-8'))
        assert result['classes'] == [], 'Relocated parse-jar returned unexpected data'
    print('Relocated Windows ZIP: Python, native dependencies and parse-jar OK')


def main():
    root = Path(__file__).resolve().parents[1]
    platform = os.environ['PACKAGE_PLATFORM']
    agent = root / 'native/build/lib' / os.environ['PACKAGE_AGENT']
    arch = os.environ['J2C_ARCH']
    data = agent.read_bytes()
    if platform.startswith('windows-'):
        assert data[:2] == b'MZ', 'Agent is not a Windows PE file'
        pe = struct.unpack_from('<I', data, 0x3C)[0]
        assert data[pe:pe + 4] == b'PE\0\0', 'Invalid PE header'
        machine = struct.unpack_from('<H', data, pe + 4)[0]
        assert machine == {'x64': 0x8664, 'arm64': 0xAA64}[arch], 'Wrong DLL architecture'
        python = root / 'py/.venv/Scripts/python.exe'
    else:
        assert data[:5] == b'\x7fELF\x02', 'Agent is not a 64-bit ELF file'
        machine = struct.unpack_from('<H' if data[5] == 1 else '>H', data, 18)[0]
        assert machine == {'x64': 62, 'arm64': 183}[arch], 'Wrong SO architecture'
        python = root / 'py/.venv/bin/python'
    assert python.is_file(), 'Setup did not create the Python environment'
    windows = platform.startswith('windows-')
    if windows:
        python = prepare_windows_runtime(root, python)
    subprocess.run([str(python), '-c', NATIVE_PROBE], check=True, cwd=root)
    for module in ('jar-parser', 'class-rebuilder', 'trace-to-bytecode', 'desktop-ui'):
        assert (root / f'jvm/{module}/build/install/{module}/lib').is_dir(), f'Missing JVM distribution: {module}'
    output = Path(os.environ['RUNNER_TEMP']) / 'c2j-packages'
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f'c2j-native-deobfuscator-{platform}.zip'
    prefix = f'c2j-native-deobfuscator-{platform}'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for directory, dirs, files in os.walk(root, followlinks=False):
            base = Path(directory)
            dirs[:] = [d for d in dirs if not excluded((base / d).relative_to(root), windows)]
            files = [f for f in files if not excluded((base / f).relative_to(root), windows)]
            for name in sorted(dirs + files):
                path = base / name
                dest = f'{prefix}/{path.relative_to(root).as_posix()}'
                if path.is_symlink():
                    info = zipfile.ZipInfo(dest)
                    info.create_system = 3
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    z.writestr(info, os.readlink(path))
                else:
                    z.write(path, dest)
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None, 'ZIP integrity check failed'
        assert not any(excluded(Path(n).relative_to(prefix), windows) for n in z.namelist()), 'Excluded cache or venv leaked into ZIP'
    if windows:
        verify_windows_archive(archive, prefix)
    print(f'Created {archive} ({archive.stat().st_size:,} bytes)')


if __name__ == '__main__':
    main()
