"""Tests for the `doctor` diagnostics.

None of these need Ghidra, a JVM build, or the native agent: every probe is
driven with mocked "present" / "missing" tool states.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from j2c_dumper_cli import doctor


# ------------------------------------------------------------------
# Java version parsing
# ------------------------------------------------------------------

@pytest.mark.parametrize(
    "text,expected",
    [
        ('openjdk version "21.0.10" 2026-01-20', 21),
        ('openjdk version "17.0.9" 2023-10-17', 17),
        ('java version "1.8.0_202"', 8),
        ('openjdk version "11.0.2" 2019-01-15', 11),
        ("garbage without a version", None),
    ],
)
def test_parse_java_major(text, expected):
    assert doctor._parse_java_major(text) == expected


# ------------------------------------------------------------------
# Java probe
# ------------------------------------------------------------------

def test_check_java_missing(monkeypatch):
    monkeypatch.delenv("JAVA_HOME", raising=False)
    monkeypatch.setattr(doctor, "_java_executable", lambda: None)
    c = doctor.check_java()
    assert c.status == doctor.STATUS_MISSING
    assert c.fix


def test_check_java_too_old(monkeypatch):
    monkeypatch.setenv("JAVA_HOME", "/opt/jdk8")
    monkeypatch.setattr(doctor, "_java_executable", lambda: "/opt/jdk8/bin/java")
    monkeypatch.setattr(doctor, "_query_java_version",
                        lambda exe: 'openjdk version "1.8.0_202"')
    c = doctor.check_java()
    assert c.status == doctor.STATUS_MISSING
    assert "8" in c.detail


def test_check_java_ok(monkeypatch):
    monkeypatch.setenv("JAVA_HOME", "/opt/jdk21")
    monkeypatch.setattr(doctor, "_java_executable", lambda: "/opt/jdk21/bin/java")
    monkeypatch.setattr(doctor, "_query_java_version",
                        lambda exe: 'openjdk version "21.0.10" 2026-01-20')
    c = doctor.check_java()
    assert c.status == doctor.STATUS_OK
    assert "21" in c.detail


def test_check_java_ok_but_no_java_home(monkeypatch):
    monkeypatch.delenv("JAVA_HOME", raising=False)
    monkeypatch.setattr(doctor, "_java_executable", lambda: "/usr/bin/java")
    monkeypatch.setattr(doctor, "_query_java_version",
                        lambda exe: 'openjdk version "21.0.10" 2026-01-20')
    c = doctor.check_java()
    # 21 is fine but JAVA_HOME missing → warn (native build needs it).
    assert c.status == doctor.STATUS_WARN
    assert c.fix


# ------------------------------------------------------------------
# Python probe
# ------------------------------------------------------------------

def test_check_python_ok(monkeypatch):
    monkeypatch.setattr(sys, "version_info", (3, 11, 5))
    assert doctor.check_python().status == doctor.STATUS_OK


def test_check_python_too_old(monkeypatch):
    monkeypatch.setattr(sys, "version_info", (3, 9, 18))
    c = doctor.check_python()
    assert c.status == doctor.STATUS_MISSING
    assert c.fix


# ------------------------------------------------------------------
# JVM modules probe
# ------------------------------------------------------------------

def _make_jvm_installs(root: Path, modules) -> None:
    suffix = ".bat" if os.name == "nt" else ""
    for m in modules:
        script = root / "jvm" / m / "build" / "install" / m / "bin" / f"{m}{suffix}"
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text("#!/bin/sh\n")


def test_check_jvm_modules_missing(tmp_path):
    c = doctor.check_jvm_modules(tmp_path)
    assert c.status == doctor.STATUS_MISSING
    assert "jar-parser" in c.detail


def test_check_jvm_modules_partial(tmp_path):
    _make_jvm_installs(tmp_path, ["jar-parser"])
    c = doctor.check_jvm_modules(tmp_path)
    assert c.status == doctor.STATUS_MISSING
    assert "trace-to-bytecode" in c.detail
    assert "jar-parser" not in c.detail


def test_check_jvm_modules_ok(tmp_path):
    _make_jvm_installs(tmp_path, doctor.REQUIRED_JVM_MODULES)
    assert doctor.check_jvm_modules(tmp_path).status == doctor.STATUS_OK


# ------------------------------------------------------------------
# Native agent probe
# ------------------------------------------------------------------

def _write_agent(tmp_path, libname, size=doctor._MIN_AGENT_BYTES + 1):
    libdir = tmp_path / "native" / "build" / "lib"
    libdir.mkdir(parents=True, exist_ok=True)
    (libdir / libname).write_bytes(b"\x7fELF" + b"\x00" * (size - 4))
    return libdir


def test_host_agent_name_per_platform():
    assert doctor.host_agent_name("linux") == "j2c_agent.so"
    assert doctor.host_agent_name("darwin") == "j2c_agent.dylib"
    assert doctor.host_agent_name("win32") == "j2c_agent.dll"


def test_check_native_agent_missing(tmp_path):
    c = doctor.check_native_agent(tmp_path)
    assert c.status == doctor.STATUS_MISSING
    assert c.fix


def test_check_native_agent_present_host_match(tmp_path):
    # The host-matching name (as this interpreter sees it) reads as ready.
    _write_agent(tmp_path, doctor.host_agent_name())
    assert doctor.check_native_agent(tmp_path).status == doctor.STATUS_OK


def test_check_native_agent_rejects_wrong_platform(tmp_path, monkeypatch):
    # Pretend we are on Linux; a leftover Windows DLL must not read as ready.
    monkeypatch.setattr(doctor.sys, "platform", "linux")
    monkeypatch.setattr(doctor.os, "name", "posix")
    _write_agent(tmp_path, "j2c_agent.dll")
    c = doctor.check_native_agent(tmp_path)
    assert c.status == doctor.STATUS_MISSING
    assert "j2c_agent.so" in c.detail  # tells the user what this host needs
    assert "j2c_agent.dll" in c.detail  # names the wrong-platform leftover


def test_check_native_agent_rejects_empty_file(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor.sys, "platform", "linux")
    monkeypatch.setattr(doctor.os, "name", "posix")
    libdir = tmp_path / "native" / "build" / "lib"
    libdir.mkdir(parents=True)
    (libdir / "j2c_agent.so").write_bytes(b"")  # 0 bytes → not a real library
    c = doctor.check_native_agent(tmp_path)
    assert c.status == doctor.STATUS_MISSING
    assert "empty" in c.detail or "truncated" in c.detail


# ------------------------------------------------------------------
# Architecture normalisation + agent-arch header reading
# ------------------------------------------------------------------

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("x86_64", "x86_64"), ("AMD64", "x86_64"), ("x64", "x86_64"),
        ("aarch64", "arm64"), ("arm64", "arm64"),
        ("i686", "x86"), ("armv7l", "arm"),
    ],
)
def test_host_machine_normalises(raw, expected):
    assert doctor.host_machine(raw) == expected


def _write_elf(path: Path, e_machine: int, size=doctor._MIN_AGENT_BYTES + 1):
    header = bytearray(size)
    header[0:4] = b"\x7fELF"
    header[4] = 2  # 64-bit
    header[5] = 1  # little-endian
    header[18:20] = e_machine.to_bytes(2, "little")
    path.write_bytes(bytes(header))


def test_agent_arch_reads_elf(tmp_path):
    p = tmp_path / "lib.so"
    _write_elf(p, 0x3E)  # x86-64
    assert doctor.agent_arch(p) == "x86_64"
    _write_elf(p, 0xB7)  # aarch64
    assert doctor.agent_arch(p) == "arm64"


def test_check_native_agent_rejects_wrong_arch(tmp_path, monkeypatch):
    # A host-named agent whose machine code is x86-64 must not read as ready on
    # an ARM host (native/build.sh only ever emits x86-64).
    monkeypatch.setattr(doctor.sys, "platform", "linux")
    monkeypatch.setattr(doctor.os, "name", "posix")
    monkeypatch.setattr(doctor, "host_machine", lambda machine=None: "arm64")
    libdir = tmp_path / "native" / "build" / "lib"
    libdir.mkdir(parents=True)
    _write_elf(libdir / "j2c_agent.so", 0x3E)  # built for x86-64
    c = doctor.check_native_agent(tmp_path)
    assert c.status == doctor.STATUS_MISSING
    assert "x86_64" in c.detail  # names what it was built for
    assert "arm64" in c.detail   # names this host


def test_check_native_agent_ok_when_arch_matches(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor.sys, "platform", "linux")
    monkeypatch.setattr(doctor.os, "name", "posix")
    monkeypatch.setattr(doctor, "host_machine", lambda machine=None: "x86_64")
    libdir = tmp_path / "native" / "build" / "lib"
    libdir.mkdir(parents=True)
    _write_elf(libdir / "j2c_agent.so", 0x3E)
    assert doctor.check_native_agent(tmp_path).status == doctor.STATUS_OK


# ------------------------------------------------------------------
# Optional tools
# ------------------------------------------------------------------

def test_check_ghidra_optional_when_absent(monkeypatch):
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    c = doctor.check_ghidra()
    assert c.optional is True
    assert c.status == doctor.STATUS_OPTIONAL


def test_check_ghidra_present_via_env(monkeypatch, tmp_path):
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path))
    c = doctor.check_ghidra()
    assert c.status == doctor.STATUS_OK
    assert c.optional is True


def test_check_zig_optional_when_absent(monkeypatch):
    monkeypatch.delenv("ZIG", raising=False)
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    c = doctor.check_zig()
    assert c.optional is True
    assert c.status == doctor.STATUS_OPTIONAL


def test_check_zig_present(monkeypatch):
    monkeypatch.delenv("ZIG", raising=False)
    monkeypatch.setattr(doctor.shutil, "which",
                        lambda name: "/usr/bin/zig" if name == "zig" else None)
    assert doctor.check_zig().status == doctor.STATUS_OK


def test_check_unicorn_is_optional():
    # Regardless of whether unicorn is installed, it must be marked optional.
    c = doctor.check_unicorn()
    assert c.optional is True
    assert c.status in (doctor.STATUS_OK, doctor.STATUS_OPTIONAL)


# ------------------------------------------------------------------
# Aggregate report
# ------------------------------------------------------------------

def test_build_report_blocking_when_nothing_built(tmp_path, monkeypatch):
    monkeypatch.delenv("JAVA_HOME", raising=False)
    monkeypatch.setattr(doctor, "_java_executable", lambda: None)
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    report = doctor.build_report(tmp_path)
    assert not report.healthy
    names = {c.name for c in report.blocking}
    # Missing java, jvm modules and native agent are all blocking.
    assert "JVM modules (installDist)" in names
    assert "Native JVMTI agent" in names
    # Optional tools never block.
    assert all(not c.optional for c in report.blocking)


def test_build_report_healthy_when_everything_present(tmp_path, monkeypatch):
    monkeypatch.setenv("JAVA_HOME", "/opt/jdk21")
    monkeypatch.setattr(doctor, "_java_executable", lambda: "/opt/jdk21/bin/java")
    monkeypatch.setattr(doctor, "_query_java_version",
                        lambda exe: 'openjdk version "21.0.10"')
    monkeypatch.setattr(sys, "version_info", (3, 11, 5))
    _make_jvm_installs(tmp_path, doctor.REQUIRED_JVM_MODULES)
    _write_agent(tmp_path, doctor.host_agent_name())
    report = doctor.build_report(tmp_path)
    assert report.healthy
    assert report.blocking == []


def test_warn_does_not_block():
    # A required check that only WARNs is a caveat, not a blocker.
    r = doctor.Report()
    r.add(doctor.Check("Java / JDK 17+", doctor.STATUS_WARN, "no JAVA_HOME"))
    r.add(doctor.Check("Python 3.11+", doctor.STATUS_OK, "3.12"))
    assert r.healthy
    assert r.blocking == []
    assert [c.name for c in r.warnings] == ["Java / JDK 17+"]


def test_build_report_warn_stays_healthy(tmp_path, monkeypatch):
    # Java new enough but JAVA_HOME unset -> WARN, yet the report is healthy
    # because the agent and modules are present.
    monkeypatch.delenv("JAVA_HOME", raising=False)
    monkeypatch.setattr(doctor, "_java_executable", lambda: "/usr/bin/java")
    monkeypatch.setattr(doctor, "_query_java_version",
                        lambda exe: 'openjdk version "17.0.9"')
    monkeypatch.setattr(sys, "version_info", (3, 11, 5))
    _make_jvm_installs(tmp_path, doctor.REQUIRED_JVM_MODULES)
    _write_agent(tmp_path, doctor.host_agent_name())
    report = doctor.build_report(tmp_path)
    assert report.healthy
    assert any(c.status == doctor.STATUS_WARN for c in report.warnings)


# ------------------------------------------------------------------
# Python recover-stage dependency probe
# ------------------------------------------------------------------

def test_check_python_recover_deps_ok():
    # capstone + lief are installed in the test/setup environment.
    c = doctor.check_python_recover_deps()
    assert c.status == doctor.STATUS_OK
    assert not c.optional


def test_check_python_recover_deps_missing(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "binary_introspect.cli" or name.startswith("capstone"):
            raise ModuleNotFoundError("No module named 'capstone'", name="capstone")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    c = doctor.check_python_recover_deps()
    assert c.status == doctor.STATUS_MISSING
    assert not c.optional
    assert c.fix


def _make_venv_python(root: Path) -> Path:
    if os.name == "nt":
        py = root / "py" / ".venv" / "Scripts" / "python.exe"
    else:
        py = root / "py" / ".venv" / "bin" / "python"
    py.parent.mkdir(parents=True, exist_ok=True)
    py.write_text("")
    return py


def test_venv_python_detected(tmp_path):
    assert doctor.venv_python(tmp_path) is None
    made = _make_venv_python(tmp_path)
    assert doctor.venv_python(tmp_path) == made


def test_check_python_recover_deps_points_at_venv(tmp_path, monkeypatch):
    # When the import fails but a uv venv exists (and is not the current
    # interpreter), the fix must send the user to that interpreter/launcher
    # rather than only suggesting a reinstall.
    _make_venv_python(tmp_path)
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "binary_introspect.cli" or name.startswith("capstone"):
            raise ModuleNotFoundError("No module named 'capstone'", name="capstone")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    c = doctor.check_python_recover_deps(tmp_path)
    assert c.status == doctor.STATUS_MISSING
    assert "scripts/j2c" in c.fix or "j2c.ps1" in c.fix
    assert ".venv" in c.fix
