"""Tests for the opt-in live process-attach path.

Covers:
  * PID / same-user / looks-like-Java validation (pure helpers).
  * The CLI refusing to proceed without the confirmation flag.
  * `attach --help` / top-level help text.

None of these start a JVM or actually attach: the CLI-level tests all fail the
confirmation or validation gate before any attach is attempted, and the pure
tests exercise the validation helpers directly.
"""

import os

import pytest

from j2c_dumper_cli import attach_support as A


# ---------------------------------------------------------------------------
# Pure helpers: looks_like_java
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "comm,cmdline,expected",
    [
        ("java", ["/usr/bin/java", "-jar", "app.jar"], True),
        ("java", [], True),
        ("openjdk", ["/opt/jdk/bin/javaw", "-Xmx1g", "-jar", "x.jar"], True),
        ("wrapper", ["wrapper", "-jar", "app.jar"], True),
        ("launcher", ["launcher", "-XX:+UseZGC", "MainClass"], True),
        ("python3", ["python3", "script.py"], False),
        ("bash", ["bash", "run.sh"], False),
        ("node", ["node", "server.js"], False),
    ],
)
def test_looks_like_java(comm, cmdline, expected):
    assert A.looks_like_java(comm, cmdline) is expected


# ---------------------------------------------------------------------------
# Pure helpers: validate_attach_target
# ---------------------------------------------------------------------------

def _java_proc(pid=1234, uid=1000):
    return A.ProcInfo(
        pid=pid, exists=True, uid=uid, comm="java",
        cmdline=["/usr/bin/java", "-jar", "app.jar"],
    )


def test_validate_rejects_non_positive_pid():
    res = A.validate_attach_target(0, _java_proc(pid=0), current=1000)
    assert not res.ok
    assert any("positive" in p for p in res.problems)


def test_validate_rejects_missing_process():
    proc = A.ProcInfo(pid=4242, exists=False)
    res = A.validate_attach_target(4242, proc, current=1000)
    assert not res.ok
    assert any("no process" in p for p in res.problems)


def test_validate_rejects_cross_user():
    proc = _java_proc(uid=1000)
    res = A.validate_attach_target(1234, proc, current=1001)
    assert not res.ok
    assert any("same-user only" in p for p in res.problems)


def test_validate_rejects_non_java():
    proc = A.ProcInfo(
        pid=1234, exists=True, uid=1000, comm="python3",
        cmdline=["python3", "server.py"],
    )
    res = A.validate_attach_target(1234, proc, current=1000)
    assert not res.ok
    assert any("does not look like a Java process" in p for p in res.problems)


def test_validate_accepts_same_user_java():
    proc = _java_proc(uid=1000)
    res = A.validate_attach_target(1234, proc, current=1000)
    assert res.ok
    assert res.problems == []


def test_validate_warns_when_uid_unknown_but_still_ok():
    proc = A.ProcInfo(
        pid=1234, exists=True, uid=None, comm="java",
        cmdline=["java", "-jar", "app.jar"],
    )
    res = A.validate_attach_target(1234, proc, current=1000)
    assert res.ok
    assert any("same-user check" in w for w in res.warnings)


def test_validate_warns_when_current_uid_unknown():
    proc = _java_proc(uid=1000)
    res = A.validate_attach_target(1234, proc, current=None)
    assert res.ok
    assert any("current uid" in w for w in res.warnings)


# ---------------------------------------------------------------------------
# Pure helpers: read_proc_info / build_agent_options
# ---------------------------------------------------------------------------

def test_read_proc_info_self():
    info = A.read_proc_info(os.getpid())
    assert info.exists
    if hasattr(os, "getuid"):
        assert info.uid == os.getuid()


def test_read_proc_info_missing():
    # A pid far above any plausible live process.
    info = A.read_proc_info(2_147_480_000)
    assert not info.exists


def test_build_agent_options_minimal():
    assert A.build_agent_options("trace.jsonl") == "trace=trace.jsonl"


def test_build_agent_options_full():
    got = A.build_agent_options("out/t.jsonl", log_all=True, max_frame_events=0)
    assert got == "trace=out/t.jsonl,log-all=true,max-frame-events=0"


# ---------------------------------------------------------------------------
# CLI-level: refuse-without-flag / validation / help text
# ---------------------------------------------------------------------------

def _flat(result):
    """Whitespace-normalized output (rich wraps lines at FORCED_WIDTH)."""
    return " ".join(result.output.split())


@pytest.fixture()
def runner():
    from typer.testing import CliRunner
    return CliRunner()


@pytest.fixture()
def app():
    from j2c_dumper_cli.main import app as _app
    return _app


def test_attach_refuses_without_confirmation_flag(runner, app):
    # Huge pid that does not exist: proves the flag check happens *first*,
    # before we probe the target at all.
    result = runner.invoke(app, ["attach", "--pid", "4294967295"])
    assert result.exit_code == 2
    assert "own-this-process" in _flat(result)


def test_attach_requires_pid(runner, app):
    result = runner.invoke(app, ["attach", "--i-own-this-process"])
    assert result.exit_code != 0


def test_attach_rejects_non_java_process(runner, app):
    # Our own (Python) process: same uid, but not a JVM -> validation refuses.
    result = runner.invoke(
        app, ["attach", "--pid", str(os.getpid()), "--i-own-this-process"]
    )
    assert result.exit_code == 2
    assert "does not look like a Java process" in _flat(result)


def test_attach_help_marks_preview_and_flag(runner, app):
    result = runner.invoke(app, ["attach", "--help"])
    assert result.exit_code == 0
    flat = _flat(result)
    assert "preview" in flat
    assert "own-this-process" in flat
    assert "--pid" in flat


def test_top_level_help_lists_attach(runner, app):
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "attach" in _flat(result)
