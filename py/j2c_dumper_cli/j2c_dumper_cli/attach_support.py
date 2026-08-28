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
        problems.append(
            f"pid {pid} is owned by uid {proc.uid}, not the current uid "
            f"{current}; attach is same-user only"
        )

    if not looks_like_java(proc.comm, proc.cmdline):
        problems.append(
            f"pid {pid} does not look like a Java process "
            f"(comm={proc.comm!r}); refusing to attach"
        )

    return ValidationResult(ok=not problems, problems=problems, warnings=warnings)


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
