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
    # Our own (Python) process: same uid, but not a JVM -> validation refuses
    # with the shared `attach failed (reason=not-a-jvm):` form (must-fix #2).
    result = runner.invoke(
        app, ["attach", "--pid", str(os.getpid()), "--i-own-this-process"]
    )
    assert result.exit_code != 0
    flat = _flat(result)
    assert "attach failed (reason=not-a-jvm)" in flat
    assert "does not look like a Java process" in flat
    assert "attached (preview)" not in result.output


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
    # Reduced coverage is not a refusal, but a one-line startup reminder is shown.
    assert "startup -agentpath" in _flat(result)


# ---------------------------------------------------------------------------
# Pure helpers: pre-attach cmdline scan (scan_cmdline_for_refusals)
# ---------------------------------------------------------------------------

def test_scan_clean_cmdline_returns_none():
    assert A.scan_cmdline_for_refusals(
        ["/usr/bin/java", "-Xmx1g", "-jar", "app.jar"]
    ) is None
    assert A.scan_cmdline_for_refusals([]) is None


def test_scan_detects_disable_attach_mechanism():
    r = A.scan_cmdline_for_refusals(
        ["java", "-XX:+DisableAttachMechanism", "-jar", "app.jar"]
    )
    assert r is not None
    assert r.reason == A.REASON_ATTACH_DISABLED
    assert r.recommend_startup is True


def test_scan_detects_dynamic_agent_loading_disabled():
    r = A.scan_cmdline_for_refusals(
        ["java", "-XX:-EnableDynamicAgentLoading", "-jar", "app.jar"]
    )
    assert r is not None
    assert r.reason == A.REASON_DYNAMIC_AGENT_DISABLED


def test_scan_does_not_flag_dynamic_agent_loading_enabled():
    # The '+' (enabled) form must NOT be treated as a refusal.
    assert A.scan_cmdline_for_refusals(
        ["java", "-XX:+EnableDynamicAgentLoading", "-jar", "app.jar"]
    ) is None


def test_scan_does_not_refuse_allow_attach_self_false():
    # allowAttachSelf=false disables *self*-attach only; it must NOT hard-refuse
    # this external, same-user attach. It is surfaced as a warning instead.
    assert A.scan_cmdline_for_refusals(
        ["java", "-Djdk.attach.allowAttachSelf=false", "-jar", "app.jar"]
    ) is None
    warnings = A.scan_cmdline_for_warnings(
        ["java", "-Djdk.attach.allowAttachSelf=false", "-jar", "app.jar"]
    )
    assert any("allowAttachSelf=false" in w for w in warnings)
    assert any("self-attach only" in w for w in warnings)


def test_scan_ignores_allow_attach_self_true():
    assert A.scan_cmdline_for_refusals(
        ["java", "-Djdk.attach.allowAttachSelf=true", "-jar", "app.jar"]
    ) is None
    assert A.scan_cmdline_for_warnings(
        ["java", "-Djdk.attach.allowAttachSelf=true", "-jar", "app.jar"]
    ) == []


def test_scan_priority_attach_disabled_first():
    # If several blockers are present, the most fundamental one wins.
    r = A.scan_cmdline_for_refusals([
        "java",
        "-XX:-EnableDynamicAgentLoading",
        "-XX:+DisableAttachMechanism",
        "-Djdk.attach.allowAttachSelf=false",
    ])
    assert r.reason == A.REASON_ATTACH_DISABLED


# ---------------------------------------------------------------------------
# Pure helpers: post-failure classification (classify_attach_error)
# ---------------------------------------------------------------------------

def test_classify_attach_disabled_from_output():
    r = A.classify_attach_error(
        1, "com.sun.tools.attach.AttachNotSupportedException: Unable to open "
           "socket file: target process not responding",
    )
    assert r.reason == A.REASON_ATTACH_DISABLED
    assert r.detail  # keeps a raw snippet


def test_classify_dynamic_agent_disabled_from_output():
    r = A.classify_attach_error(
        1, "Dynamic agent loading is not enabled. "
           "Use -XX:+EnableDynamicAgentLoading",
    )
    assert r.reason == A.REASON_DYNAMIC_AGENT_DISABLED


def test_classify_cross_user_from_output():
    r = A.classify_attach_error(
        1, "java.io.IOException: well-known file is not secure: not owned by "
           "the current user",
    )
    assert r.reason == A.REASON_CROSS_USER


def test_classify_agent_onattach_missing():
    r = A.classify_attach_error(
        1, "The agent library does not have Agent_OnAttach and cannot be "
           "loaded into a running VM",
    )
    assert r.reason == A.REASON_AGENT_ONATTACH_MISSING


def test_classify_jcmd_false_success():
    # jcmd process exit 0 but Agent_OnAttach returned -1.
    r = A.classify_attach_error(0, "4321:\nreturn code: -1\n", agent_return_code=-1)
    assert r.reason == A.REASON_JCMD_FALSE_SUCCESS
    assert "-1" in r.message


def test_classify_agent_init_failed():
    r = A.classify_attach_error(
        1, "com.sun.tools.attach.AgentInitializationException: "
           "Agent_OnAttach failed",
    )
    assert r.reason == A.REASON_AGENT_INIT_FAILED


def test_classify_agent_init_failed_from_nonzero_agent_rc():
    r = A.classify_attach_error(1, "some java noise", agent_return_code=2)
    assert r.reason == A.REASON_AGENT_INIT_FAILED


def test_classify_unknown_keeps_truncated_snippet():
    noise = "x" * 1000
    r = A.classify_attach_error(3, noise)
    assert r.reason == A.REASON_UNKNOWN
    assert "truncated" in r.detail
    assert len(r.detail) < len(noise)


# ---------------------------------------------------------------------------
# CLI-level: pre-attach cmdline scan refuses before invoking jcmd
# ---------------------------------------------------------------------------

def test_attach_refuses_disable_attach_mechanism_before_jcmd(
    runner, app, monkeypatch, tmp_path
):
    """A target started with -XX:+DisableAttachMechanism must be refused with a
    stable reason code *before* any attach subprocess runs, and must never print
    'attached (preview)'."""
    from j2c_dumper_cli import main as M

    agent = tmp_path / "j2c_agent.so"
    agent.write_bytes(b"\x7fELF")

    monkeypatch.setattr(M, "_jdk_tool", lambda name: name)
    monkeypatch.setattr(
        M, "read_proc_info",
        lambda p: A.ProcInfo(
            pid=p, exists=True, uid=None, comm="java",
            cmdline=["/usr/bin/java", "-XX:+DisableAttachMechanism",
                     "-jar", "app.jar"],
        ),
    )

    def boom(*a, **k):
        raise AssertionError("subprocess.run must not be called after refusal")

    monkeypatch.setattr(M.subprocess, "run", boom)

    result = runner.invoke(app, [
        "attach", "--pid", "4321", "--i-own-this-process",
        "--agent", str(agent), "--mechanism", "jcmd",
    ])
    assert result.exit_code != 0
    flat = _flat(result)
    assert "attach-disabled" in flat
    assert "attached (preview)" not in result.output


def test_attach_cross_user_prints_reason_form(runner, app, monkeypatch, tmp_path):
    """A cross-user target must print the shared
    `attach failed (reason=cross-user):` form (must-fix #2), exit non-zero, and
    never print 'attached (preview)'."""
    from j2c_dumper_cli import main as M

    agent = tmp_path / "j2c_agent.so"
    agent.write_bytes(b"\x7fELF")

    monkeypatch.setattr(M, "current_uid", lambda: 1000)
    monkeypatch.setattr(
        M, "read_proc_info",
        lambda p: A.ProcInfo(
            pid=p, exists=True, uid=4242, comm="java",
            cmdline=["/usr/bin/java", "-jar", "app.jar"],
        ),
    )

    def boom(*a, **k):
        raise AssertionError("subprocess.run must not be called after refusal")

    monkeypatch.setattr(M.subprocess, "run", boom)

    result = runner.invoke(app, [
        "attach", "--pid", "4321", "--i-own-this-process", "--agent", str(agent),
    ])
    assert result.exit_code != 0
    flat = _flat(result)
    assert "attach failed (reason=cross-user)" in flat
    assert "attached (preview)" not in result.output


def test_attach_allow_attach_self_false_warns_but_proceeds(
    runner, app, monkeypatch, tmp_path
):
    """allowAttachSelf=false disables *self*-attach only; an external same-user
    attach must NOT be refused for it (must-fix #1). The CLI warns and proceeds
    to a normal (here faked-successful) attach."""
    from j2c_dumper_cli import main as M

    agent = tmp_path / "j2c_agent.so"
    agent.write_bytes(b"\x7fELF")

    monkeypatch.setattr(M, "_jdk_tool", lambda name: name)
    monkeypatch.setattr(
        M, "read_proc_info",
        lambda p: A.ProcInfo(
            pid=p, exists=True, uid=None, comm="java",
            cmdline=["/usr/bin/java", "-Djdk.attach.allowAttachSelf=false",
                     "-jar", "app.jar"],
        ),
    )
    monkeypatch.setattr(
        M.subprocess, "run",
        lambda *a, **k: _FakeCompleted(0, stdout="4321:\nreturn code: 0\n"),
    )

    result = runner.invoke(app, [
        "attach", "--pid", "4321", "--i-own-this-process",
        "--agent", str(agent), "--mechanism", "jcmd",
    ])
    assert result.exit_code == 0
    flat = _flat(result)
    assert "allowAttachSelf=false" in flat  # warned
    assert "attach failed" not in flat      # not refused
    assert "attached (preview)" in flat      # proceeded


def test_attach_jcmd_failure_prints_reason_and_startup_path(
    runner, app, monkeypatch, tmp_path
):
    """A post-failure jcmd error is classified and the startup path recommended;
    'attached (preview)' is never printed."""
    from j2c_dumper_cli import main as M

    agent = tmp_path / "j2c_agent.so"
    agent.write_bytes(b"\x7fELF")
    _patch_attach_gate(monkeypatch, 4321, agent)

    monkeypatch.setattr(
        M.subprocess, "run",
        lambda *a, **k: _FakeCompleted(
            1, stderr="Dynamic agent loading is not enabled"
        ),
    )

    result = runner.invoke(app, [
        "attach", "--pid", "4321", "--i-own-this-process",
        "--agent", str(agent), "--mechanism", "jcmd",
    ])
    assert result.exit_code != 0
    flat = _flat(result)
    assert "dynamic-agent-disabled" in flat
    assert "-agentpath" in flat
    assert "attached (preview)" not in result.output
