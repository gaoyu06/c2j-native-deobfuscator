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
# jcmd option form + return-code parsing (regression for the false-success bug)
# ---------------------------------------------------------------------------

def test_jcmd_agent_option_is_single_quoted():
    # A bare `trace=...,...` option makes jcmd's diagnostic-command parser drop
    # the value; the option must be single-quoted so it reaches Agent_OnAttach
    # intact. This test would have failed against the pre-fix (bare) form.
    opts = "trace=out.jsonl,log-all=true,max-frame-events=0"
    assert A.jcmd_agent_option_arg(opts) == "'trace=out.jsonl,log-all=true,max-frame-events=0'"


def test_build_jcmd_argv_quotes_options():
    argv = A.build_jcmd_agent_load_argv("jcmd", 4321, "/x/j2c_agent.so", "trace=t.jsonl")
    assert argv == ["jcmd", "4321", "JVMTI.agent_load", "/x/j2c_agent.so", "'trace=t.jsonl'"]
    # The option argument must be quoted (not bare) to survive DCmd parsing.
    assert argv[-1].startswith("'") and argv[-1].endswith("'")


def test_build_jcmd_argv_omits_empty_options():
    argv = A.build_jcmd_agent_load_argv("jcmd", 1, "/x/a.so", "")
    assert argv == ["jcmd", "1", "JVMTI.agent_load", "/x/a.so"]


def test_jcmd_option_rejects_embedded_single_quote():
    with pytest.raises(ValueError):
        A.jcmd_agent_option_arg("trace=/tmp/it's/t.jsonl")


def test_parse_jcmd_return_code_success():
    assert A.parse_jcmd_return_code("4321:\nreturn code: 0\n") == 0


def test_parse_jcmd_return_code_failure():
    # This is exactly the false-success output: jcmd process exit 0 but the
    # agent's Agent_OnAttach returned -1.
    assert A.parse_jcmd_return_code("4321:\nreturn code: -1\n") == -1


def test_parse_jcmd_return_code_absent():
    assert A.parse_jcmd_return_code("some unrelated output") is None


def test_jcmd_load_error_flags_agent_failure_despite_exit_zero():
    # The core regression: jcmd exited 0, but the agent failed. Must be an error.
    err = A.jcmd_load_error(0, "4321:\nreturn code: -1\n")
    assert err is not None
    assert "-1" in err


def test_jcmd_load_error_none_on_success():
    assert A.jcmd_load_error(0, "4321:\nreturn code: 0\n") is None


def test_jcmd_load_error_flags_nonzero_process_exit():
    err = A.jcmd_load_error(1, "java.lang.IllegalArgumentException: Unknown argument")
    assert err is not None


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


# ---------------------------------------------------------------------------
# CLI-level: jcmd false-success must become a hard failure (must-fix #1)
# ---------------------------------------------------------------------------

class _FakeCompleted:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _patch_attach_gate(monkeypatch, pid, agent_file):
    """Get past the ownership/validation gate and agent resolution so the test
    can exercise the actual jcmd invocation path."""
    from j2c_dumper_cli import main as M

    monkeypatch.setattr(M, "_jdk_tool", lambda name: name)
    monkeypatch.setattr(
        M, "read_proc_info",
        lambda p: A.ProcInfo(pid=p, exists=True, uid=None, comm="java",
                             cmdline=["/usr/bin/java", "-jar", "app.jar"]),
    )


def test_attach_jcmd_false_success_is_failure(runner, app, monkeypatch, tmp_path):
    """jcmd exits 0 while Agent_OnAttach returned -1 -> CLI must fail, not
    print 'attached'. This is the exact regression the review flagged."""
    from j2c_dumper_cli import main as M

    agent = tmp_path / "j2c_agent.so"
    agent.write_bytes(b"\x7fELF")
    _patch_attach_gate(monkeypatch, 4321, agent)

    seen = {}

    def fake_run(argv, check=False, capture_output=False, text=False):
        seen["argv"] = argv
        # Emulate jcmd's false success: process exit 0, agent return code -1.
        return _FakeCompleted(0, stdout="4321:\nreturn code: -1\n")

    monkeypatch.setattr(M.subprocess, "run", fake_run)

    result = runner.invoke(app, [
        "attach", "--pid", "4321", "--i-own-this-process",
        "--agent", str(agent), "--mechanism", "jcmd",
    ])
    assert result.exit_code != 0
    assert "attached (preview)" not in result.output
    # And the options were passed single-quoted (would-be-corrupted otherwise).
    opt_arg = seen["argv"][-1]
    assert opt_arg.startswith("'") and opt_arg.endswith("'")
    assert "trace=" in opt_arg


def test_attach_jcmd_success_reports_attached(runner, app, monkeypatch, tmp_path):
    from j2c_dumper_cli import main as M

    agent = tmp_path / "j2c_agent.so"
    agent.write_bytes(b"\x7fELF")
    _patch_attach_gate(monkeypatch, 4321, agent)

    monkeypatch.setattr(
        M.subprocess, "run",
        lambda *a, **k: _FakeCompleted(0, stdout="4321:\nreturn code: 0\n"),
    )

    result = runner.invoke(app, [
        "attach", "--pid", "4321", "--i-own-this-process",
        "--agent", str(agent), "--mechanism", "jcmd",
    ])
    assert result.exit_code == 0
    assert "attached (preview)" in _flat(result)
