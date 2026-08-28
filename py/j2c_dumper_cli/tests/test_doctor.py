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

def test_check_native_agent_missing(tmp_path):
    c = doctor.check_native_agent(tmp_path)
    assert c.status == doctor.STATUS_MISSING
    assert c.fix


@pytest.mark.parametrize("libname", ["j2c_agent.so", "j2c_agent.dll", "j2c_agent.dylib"])
def test_check_native_agent_present(tmp_path, libname):
    libdir = tmp_path / "native" / "build" / "lib"
    libdir.mkdir(parents=True)
    (libdir / libname).write_bytes(b"\x7fELF")
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
    libdir = tmp_path / "native" / "build" / "lib"
    libdir.mkdir(parents=True)
    (libdir / "j2c_agent.so").write_bytes(b"\x7fELF")
    report = doctor.build_report(tmp_path)
    assert report.healthy
    assert report.blocking == []
