"""CLI-level checks for the `doctor` command (exit codes + rendering).

Uses Typer's test runner with a mocked report, so it needs neither Ghidra
nor a real toolchain build.
"""

from __future__ import annotations

from typer.testing import CliRunner

from j2c_dumper_cli import doctor as doctor_mod
from j2c_dumper_cli.main import app

runner = CliRunner()


def _report(*checks):
    r = doctor_mod.Report()
    for c in checks:
        r.add(c)
    return r


def test_doctor_exits_zero_when_healthy(monkeypatch):
    healthy = _report(
        doctor_mod.Check("Java / JDK 17+", doctor_mod.STATUS_OK, "Java 17"),
        doctor_mod.Check("Python 3.11+", doctor_mod.STATUS_OK, "3.12"),
    )
    monkeypatch.setattr(doctor_mod, "build_report", lambda root: healthy)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "Required checks passed" in result.output


def test_doctor_healthy_with_warning_exits_zero(monkeypatch):
    # A WARN on a required check is a caveat, not a failure: still exit 0,
    # and the caveat is surfaced as a note.
    healthy = _report(
        doctor_mod.Check("Java / JDK 17+", doctor_mod.STATUS_WARN,
                         "Java 17 but JAVA_HOME is not set"),
        doctor_mod.Check("Python 3.11+", doctor_mod.STATUS_OK, "3.12"),
    )
    monkeypatch.setattr(doctor_mod, "build_report", lambda root: healthy)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "Required checks passed" in result.output
    assert "note:" in result.output


def test_doctor_exits_nonzero_when_missing(monkeypatch):
    broken = _report(
        doctor_mod.Check("Java / JDK 17+", doctor_mod.STATUS_OK, "Java 17"),
        doctor_mod.Check(
            "Native JVMTI agent",
            doctor_mod.STATUS_MISSING,
            "no j2c_agent.*",
            fix="run scripts/setup.sh",
        ),
    )
    monkeypatch.setattr(doctor_mod, "build_report", lambda root: broken)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 1
    assert "Not ready" in result.output
    assert "scripts/setup.sh" in result.output


# ------------------------------------------------------------------
# Entry-point exit codes (no-args help + top-level --help)
# ------------------------------------------------------------------

def test_no_args_prints_help_and_exits_zero():
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    # The default-path guidance from the group help is shown.
    assert "recover" in result.output


def test_top_level_help_exits_zero():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "recover" in result.output
