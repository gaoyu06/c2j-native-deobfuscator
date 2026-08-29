"""Support helpers for the opt-in live process-attach path.

Deliberately free of ``typer`` / ``rich`` imports so the PID and same-user
validation logic can be unit-tested without the CLI framework installed, and so
it can be reused headless.

Scope reminder: process attach is a *preview* diagnostic path for JVMs the
current user owns or may inspect (same user only). The default, highest-fidelity
recovery path is still startup instrumentation via ``-agentpath``.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# Explicit confirmation the caller must pass to proceed with an attach.
CONFIRM_FLAG = "--i-own-this-process"


@dataclass
class ProcInfo:
    """A best-effort snapshot of a target process."""

    pid: int
    exists: bool
    uid: Optional[int] = None       # owning uid, or None if it can't be read
    comm: str = ""                  # short command name (e.g. "java")
    cmdline: List[str] = field(default_factory=list)


@dataclass
class ValidationResult:
    ok: bool
    problems: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    # Structured refusals for the cases that have a stable reason code
    # (cross-user, not-a-jvm) so the CLI can print the same
    # ``attach failed (reason=<code>):`` form as every other refusal.
    refusals: List["AttachRefusal"] = field(default_factory=list)


def looks_like_java(comm: str, cmdline: List[str]) -> bool:
    """Best-effort test for whether a process looks like a JVM.

    Accepts when ``java`` appears in the short command name or the basename of
    ``argv[0]``, or when the argument vector carries an unmistakable JVM launch
    signature (``-jar``, a ``.jar`` argument, ``-XX:`` / ``-D`` / ``-javaagent``
    flags). Intentionally permissive but not blind: this is a guardrail, not an
    authorization check — the explicit confirmation flag is the real gate.
    """
    comm_l = (comm or "").lower()
    if "java" in comm_l:
        return True
    if cmdline:
        exe = os.path.basename(cmdline[0]).lower()
        if "java" in exe:
            return True
    joined = " ".join(cmdline).lower()
    if (
        " -jar" in f" {joined}"
        or joined.endswith(".jar")
        or "-xx:" in joined
        or "-javaagent" in joined
        or "-agentpath" in joined
    ):
        return True
    return False


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Exists but owned by another user — the same-user check will catch it.
        return True
    except (OSError, AttributeError):
        # AttributeError: platform without os.kill; treat as unknown-but-present.
        return True
    return True


def current_uid() -> Optional[int]:
    """The current user's uid, or None on platforms without ``os.getuid``."""
    getuid = getattr(os, "getuid", None)
    return getuid() if getuid is not None else None


def read_proc_info(pid: int) -> ProcInfo:
    """Read a best-effort snapshot of ``pid``.

    On Linux this reads ``/proc/<pid>/{comm,cmdline}`` and the owning uid via
    ``stat``. On platforms without procfs it falls back to a liveness probe and
    leaves ``uid``/``comm``/``cmdline`` empty (callers should degrade to
    warnings, not hard failures, for the fields it can't fill).
    """
    proc = Path("/proc") / str(pid)
    if proc.exists():
        uid: Optional[int] = None
        try:
            uid = proc.stat().st_uid
        except OSError:
            uid = None
        comm = ""
        try:
            comm = (proc / "comm").read_text(errors="replace").strip()
        except OSError:
            pass
        cmdline: List[str] = []
        try:
            raw = (proc / "cmdline").read_bytes()
            cmdline = [p.decode("utf-8", "replace") for p in raw.split(b"\x00") if p]
        except OSError:
            pass
        return ProcInfo(pid=pid, exists=True, uid=uid, comm=comm, cmdline=cmdline)
    return ProcInfo(pid=pid, exists=_pid_alive(pid))


def validate_attach_target(
    pid: int,
    proc: ProcInfo,
    current: Optional[int],
) -> ValidationResult:
    """Validate that ``pid`` is a same-user Java process worth attaching to.

    Hard failures (``problems``): non-positive pid, process not running, or a
    clear cross-user / non-Java mismatch. Soft, best-effort gaps (``warnings``):
    an owner or current uid we couldn't determine.
    """
    problems: List[str] = []
    warnings: List[str] = []
    refusals: List[AttachRefusal] = []

    if pid <= 0:
        problems.append(f"pid must be a positive integer, got {pid}")
        return ValidationResult(ok=False, problems=problems, warnings=warnings)

    if not proc.exists:
        problems.append(f"no process with pid {pid} is running")
        return ValidationResult(ok=False, problems=problems, warnings=warnings)

    if current is None:
        warnings.append(
            "cannot determine the current uid on this platform; "
            "skipping the same-user check"
        )
    elif proc.uid is None:
        warnings.append(
            f"cannot determine the owner uid of pid {pid}; "
            "skipping the same-user check"
        )
    elif proc.uid != current:
        msg = (
            f"pid {pid} is owned by uid {proc.uid}, not the current uid "
            f"{current}; attach is same-user only"
        )
        problems.append(msg)
        refusals.append(
            AttachRefusal(
                reason=REASON_CROSS_USER,
                message=(
                    f"{msg}. Run as the owning user; do not use elevated "
                    "privileges to cross users."
                ),
            )
        )

    if not looks_like_java(proc.comm, proc.cmdline):
        msg = (
            f"pid {pid} does not look like a Java process "
            f"(comm={proc.comm!r}); refusing to attach"
        )
        problems.append(msg)
        refusals.append(
            AttachRefusal(
                reason=REASON_NOT_A_JVM,
                message=msg,
                recommend_startup=False,
            )
        )

    return ValidationResult(
        ok=not problems, problems=problems, warnings=warnings, refusals=refusals
    )


def build_agent_options(
    output: str,
    log_all: bool = False,
    max_frame_events: Optional[int] = None,
) -> str:
    """Assemble the ``key=value,...`` option string the agent parses."""
    opts = [f"trace={output}"]
    if log_all:
        opts.append("log-all=true")
    if max_frame_events is not None:
        opts.append(f"max-frame-events={max_frame_events}")
    return ",".join(opts)


# ---------------------------------------------------------------------------
# jcmd JVMTI.agent_load helpers
#
# `jcmd <pid> JVMTI.agent_load <lib> <opts>` routes <opts> through the
# diagnostic-command argument parser, which treats ``key=value`` tokens as its
# *own* named arguments and, for a positional argument, keeps only the part
# before ``=`` (dropping the value). A bare option string such as
# ``trace=out.jsonl`` therefore reaches the agent as an empty trace path, the
# agent returns JNI_ERR, and — critically — ``jcmd`` still exits 0, printing
# ``return code: -1`` on stdout. Wrapping the option string in single quotes
# makes the DCmd parser take it as one literal positional value, so the agent
# receives the options intact. These helpers are typer-free so both the option
# form and the return-code parsing are unit-testable without a live JVM.
# ---------------------------------------------------------------------------

_JCMD_RETURN_CODE_RE = re.compile(r"return code:\s*(-?\d+)", re.IGNORECASE)


def jcmd_agent_option_arg(opts: str) -> str:
    """Quote ``opts`` for ``jcmd JVMTI.agent_load`` so ``key=value`` survives.

    The diagnostic-command parser only preserves an option string containing
    ``=`` when it is a single-quoted literal. We refuse rather than silently
    corrupt if the option string itself contains a single quote (paths with an
    apostrophe are out of scope for this preview; use ``--mechanism vm``).
    """
    if "'" in opts:
        raise ValueError(
            "agent option string contains a single quote, which cannot be "
            "passed safely through jcmd; use --mechanism vm instead"
        )
    return f"'{opts}'"


def build_jcmd_agent_load_argv(
    jcmd: str, pid: int, agent_path: str, opts: str
) -> List[str]:
    """Build the argv for ``jcmd <pid> JVMTI.agent_load <lib> '<opts>'``."""
    argv = [jcmd, str(pid), "JVMTI.agent_load", agent_path]
    if opts:
        argv.append(jcmd_agent_option_arg(opts))
    return argv


def parse_jcmd_return_code(output: str) -> Optional[int]:
    """Return the agent's ``Agent_OnAttach`` code from jcmd output, or None.

    ``jcmd JVMTI.agent_load`` prints ``return code: <N>`` where ``<N>`` is the
    value ``Agent_OnAttach`` returned (0 == success). It reports this even when
    the agent fails, while the ``jcmd`` process itself still exits 0.
    """
    match = None
    for match in _JCMD_RETURN_CODE_RE.finditer(output or ""):
        pass
    return int(match.group(1)) if match else None


def jcmd_load_error(returncode: int, output: str) -> Optional[str]:
    """Return a human-readable failure reason, or None if the load succeeded.

    Treats both a non-zero ``jcmd`` process exit and a non-zero agent
    ``return code:`` as failures, so an agent that fails to initialize can never
    be reported as a successful attach.
    """
    if returncode != 0:
        return f"jcmd exited with status {returncode}"
    agent_rc = parse_jcmd_return_code(output)
    if agent_rc is not None and agent_rc != 0:
        return (
            f"agent Agent_OnAttach returned {agent_rc} "
            "(load failed; see the target JVM's stderr for details)"
        )
    return None


# ---------------------------------------------------------------------------
# Refusal / failure classification
#
# The point of these helpers is *honesty*: detect the common situations where a
# live attach cannot happen (or already failed), map them to a small set of
# stable reason codes, and hand the caller an explanation plus the honest next
# step. None of this bypasses, hides, or patches anything on the target — the
# recommended remedy is always to restart the target with startup
# instrumentation (``-agentpath``), the default highest-fidelity recovery path.
# ---------------------------------------------------------------------------

# Stable reason codes (kept intentionally short and machine-greppable).
REASON_ATTACH_DISABLED = "attach-disabled"
REASON_DYNAMIC_AGENT_DISABLED = "dynamic-agent-disabled"
REASON_NOT_A_JVM = "not-a-jvm"
REASON_CROSS_USER = "cross-user"
REASON_AGENT_ONATTACH_MISSING = "agent-onattach-missing"
REASON_AGENT_INIT_FAILED = "agent-init-failed"
REASON_JCMD_FALSE_SUCCESS = "jcmd-false-success"
REASON_UNKNOWN = "unknown"

# The one honest remedy this tool offers for every refusal below. It does not
# bypass the target's flags; it restarts the target under instrumentation.
STARTUP_PATH_RECOMMENDATION = (
    "Restart the target under startup instrumentation instead: "
    "java -agentpath:<path-to-j2c_agent> ... (see `recover` / `dynamic-trace` "
    "and docs/jvm-attach.md). This tool does not, and will not, bypass the "
    "target JVM's own attach/agent flags."
)

# How much raw error text an `unknown` classification keeps for context.
_UNKNOWN_SNIPPET_LIMIT = 400


@dataclass
class AttachRefusal:
    """A classified reason a live attach will not / did not happen.

    ``reason`` is one of the stable ``REASON_*`` codes; ``message`` explains it
    for a human; ``detail`` optionally carries a (truncated) raw snippet for the
    ``unknown`` case. ``recommend_startup`` is True for every case here — the
    honest remedy is always the startup ``-agentpath`` path.
    """

    reason: str
    message: str
    detail: str = ""
    recommend_startup: bool = True


def _truncate(text: str, limit: int = _UNKNOWN_SNIPPET_LIMIT) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + " …[truncated]"


def _allow_attach_self_disabled(cmdline: List[str]) -> bool:
    """True if argv sets ``jdk.attach.allowAttachSelf`` to a false-y value.

    Java's ``Boolean.getBoolean`` treats only ``"true"`` (case-insensitively) as
    true, so any other value — most obviously ``false`` — disables it. We only
    flag the obvious explicit ``=false`` form the docs mention.

    Note this property governs *self*-attach only (a JVM attaching to its own
    process). It does **not** block an external, same-user attach from this CLI,
    so it is surfaced as a warning, not a refusal.
    """
    for tok in cmdline:
        low = tok.lower()
        if "jdk.attach.allowattachself=" in low:
            value = low.split("jdk.attach.allowattachself=", 1)[1]
            if value != "true":
                return True
    return False


def scan_cmdline_for_refusals(cmdline: List[str]) -> Optional[AttachRefusal]:
    """Scan a target's argv for flags that make a live attach fail/refused.

    Runs *before* jcmd/VirtualMachine is invoked so the CLI can classify and
    refuse cleanly instead of surfacing an opaque attach-layer error. Detects:

      * ``-XX:+DisableAttachMechanism``          -> ``attach-disabled``
      * ``-XX:-EnableDynamicAgentLoading``       -> ``dynamic-agent-disabled``

    Returns the most severe matching refusal, or None if nothing was detected
    (which is not a guarantee the attach will succeed — the target may carry the
    flags in ``JAVA_TOOL_OPTIONS`` etc. that argv does not show).

    ``-Djdk.attach.allowAttachSelf=false`` is deliberately **not** a refusal
    here: it disables *self*-attach only and does not block this external,
    same-user attach. See :func:`scan_cmdline_for_warnings`.
    """
    tokens = list(cmdline or [])
    joined = " ".join(tokens)

    if "-XX:+DisableAttachMechanism" in joined:
        return AttachRefusal(
            reason=REASON_ATTACH_DISABLED,
            message=(
                "target was started with -XX:+DisableAttachMechanism; the JVM "
                "attach handshake is disabled, so no agent can be loaded into "
                "this live process."
            ),
        )

    if "-XX:-EnableDynamicAgentLoading" in joined:
        return AttachRefusal(
            reason=REASON_DYNAMIC_AGENT_DISABLED,
            message=(
                "target was started with -XX:-EnableDynamicAgentLoading; "
                "dynamically loading a JVMTI agent into this live process is "
                "disallowed."
            ),
        )

    return None


def scan_cmdline_for_warnings(cmdline: List[str]) -> List[str]:
    """Non-fatal notes about a target's argv that do **not** block an attach.

    ``jdk.attach.allowAttachSelf=false`` disables a JVM attaching to *itself*
    only; an external, same-user attach from this CLI is unaffected. We surface
    it as a warning and proceed, rather than refusing a valid target on the
    strength of a flag that does not apply to us.
    """
    warnings: List[str] = []
    if _allow_attach_self_disabled(list(cmdline or [])):
        warnings.append(
            "target sets jdk.attach.allowAttachSelf=false; this disables "
            "self-attach only and does not block this external, same-user "
            "attach — proceeding."
        )
    return warnings


def classify_attach_error(
    returncode: int, output: str, agent_return_code: Optional[int] = None
) -> AttachRefusal:
    """Map a jcmd / VirtualMachine attach failure to a stable reason code.

    ``returncode`` is the launcher process exit status, ``output`` its combined
    stdout+stderr, and ``agent_return_code`` (if known) the value
    ``Agent_OnAttach`` returned as parsed from jcmd output. This is a pure text
    classifier — it never spawns a JVM — so callers can unit-test it directly.
    Unrecognized failures return ``unknown`` with a truncated raw snippet.
    """
    text = output or ""
    low = text.lower()

    # Attach mechanism / handshake unavailable.
    if (
        "disableattachmechanism" in low
        or "attach mechanism is disabled" in low
        or "attachnotsupportedexception" in low
        or "unable to open socket file" in low
        or "the attach listener" in low
        or "doesn't respond within" in low
    ):
        return AttachRefusal(
            reason=REASON_ATTACH_DISABLED,
            message=(
                "the JVM attach mechanism is unavailable on the target "
                "(commonly -XX:+DisableAttachMechanism or a stale/rejected "
                "attach socket); no agent could be loaded."
            ),
            detail=_truncate(text),
        )

    # Dynamic agent loading disabled.
    if (
        "enabledynamicagentloading" in low
        or "dynamic agent loading is not enabled" in low
        or "dynamic loading of agents" in low
    ):
        return AttachRefusal(
            reason=REASON_DYNAMIC_AGENT_DISABLED,
            message=(
                "dynamic agent loading is disabled on the target "
                "(-XX:-EnableDynamicAgentLoading); the agent cannot be attached "
                "to this live process."
            ),
            detail=_truncate(text),
        )

    # Cross-user / permission refusal from the attach layer.
    if (
        "operation not permitted" in low
        or "well-known file is not secure" in low
        or "not owned by the current user" in low
        or ("permission denied" in low and "socket" in low)
    ):
        return AttachRefusal(
            reason=REASON_CROSS_USER,
            message=(
                "the attach layer refused for permission / ownership reasons; "
                "attach is same-user only — run as the owning user, do not use "
                "elevated privileges to cross users."
            ),
            detail=_truncate(text),
        )

    # Agent library present but does not export Agent_OnAttach. Match only the
    # "missing export" phrasings, not any mention of Agent_OnAttach (an init
    # *failure* also names it and is classified separately below).
    if (
        "does not have agent_onattach" in low
        or "no agent_onattach" in low
        or "failed to find agent_onattach" in low
        or "agent_onattach not found" in low
        or "can't find agent_onattach" in low
        or "cannot find agent_onattach" in low
    ):
        return AttachRefusal(
            reason=REASON_AGENT_ONATTACH_MISSING,
            message=(
                "the agent library does not export Agent_OnAttach, so it cannot "
                "be loaded into a live VM; rebuild the current native/ sources, "
                "which export it (nm -D ... | grep Agent_On)."
            ),
            detail=_truncate(text),
        )

    # jcmd's false success: process exit 0 but Agent_OnAttach returned non-zero.
    if returncode == 0 and agent_return_code is not None and agent_return_code != 0:
        return AttachRefusal(
            reason=REASON_JCMD_FALSE_SUCCESS,
            message=(
                f"jcmd exited 0 but Agent_OnAttach returned {agent_return_code}; "
                "the agent did not initialize (this is a failure, not a "
                "successful attach)."
            ),
            detail=_truncate(text),
        )

    # Agent reached Agent_OnAttach but initialization failed.
    if (
        "agentinitializationexception" in low
        or "agent_onattach failed" in low
        or "the agent library failed to init" in low
        or (agent_return_code is not None and agent_return_code != 0)
    ):
        rc = (
            f" (Agent_OnAttach returned {agent_return_code})"
            if agent_return_code is not None
            else ""
        )
        return AttachRefusal(
            reason=REASON_AGENT_INIT_FAILED,
            message=(
                f"the agent reached Agent_OnAttach but failed to initialize{rc}; "
                "see the target JVM's stderr for the agent's own diagnostics."
            ),
            detail=_truncate(text),
        )

    return AttachRefusal(
        reason=REASON_UNKNOWN,
        message=(
            f"attach failed and the error was not recognized "
            f"(launcher exit status {returncode}); treating as a failure, not a "
            "successful attach."
        ),
        detail=_truncate(text),
    )
