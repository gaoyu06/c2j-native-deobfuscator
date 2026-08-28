"""Environment diagnostics for the j2c-dumper CLI.

The logic here is deliberately free of any UI framework so it can be unit
tested without the recovery toolchain (or Ghidra) installed. Each probe
returns a :class:`Check`; the CLI layer renders them.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Status values. "ok" = ready, "missing" = required but absent,
# "warn" = present-but-suboptimal, "optional" = absent optional tool.
STATUS_OK = "ok"
STATUS_MISSING = "missing"
STATUS_WARN = "warn"
STATUS_OPTIONAL = "optional"

MIN_JAVA = 21
MIN_PYTHON = (3, 11)

# JVM modules the default (dynamic) path invokes as installDist scripts.
REQUIRED_JVM_MODULES = ("jar-parser", "trace-to-bytecode", "class-rebuilder")


@dataclass
class Check:
    """One diagnostic line."""

    name: str
    status: str
    detail: str = ""
    fix: str = ""
    optional: bool = False

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK


@dataclass
class Report:
    """Aggregate of all checks."""

    checks: list[Check] = field(default_factory=list)

    def add(self, check: Check) -> None:
        self.checks.append(check)

    @property
    def blocking(self) -> list[Check]:
        """Required checks that are not satisfied."""
        return [c for c in self.checks if not c.optional and c.status != STATUS_OK]

    @property
    def healthy(self) -> bool:
        return not self.blocking


# ------------------------------------------------------------------
# Individual probes (each is easy to monkeypatch in tests)
# ------------------------------------------------------------------

def _parse_java_major(version_output: str) -> Optional[int]:
    """Extract the Java feature version from `java -version` stderr text."""
    m = re.search(r'version "?(\d+)(?:\.(\d+))?', version_output)
    if not m:
        return None
    major = int(m.group(1))
    # Legacy 1.x scheme (1.8 = Java 8); modern scheme reports the feature
    # version directly (21, 17, ...).
    if major == 1 and m.group(2):
        return int(m.group(2))
    return major


def _java_executable() -> Optional[str]:
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        suffix = ".exe" if os.name == "nt" else ""
        candidate = Path(java_home) / "bin" / f"java{suffix}"
        if candidate.exists():
            return str(candidate)
    return shutil.which("java")


def _query_java_version(java_exe: str) -> str:
    proc = subprocess.run(
        [java_exe, "-version"],
        capture_output=True,
        text=True,
        check=False,
    )
    # `java -version` prints to stderr.
    return (proc.stderr or "") + (proc.stdout or "")


def check_java() -> Check:
    java_home = os.environ.get("JAVA_HOME")
    java_exe = _java_executable()
    if not java_exe:
        return Check(
            name="Java / JDK 21+",
            status=STATUS_MISSING,
            detail="no `java` on PATH and JAVA_HOME unset",
            fix="install a JDK 21+ (Temurin / Adoptium) and set JAVA_HOME",
        )
    try:
        major = _parse_java_major(_query_java_version(java_exe))
    except Exception as exc:  # pragma: no cover - defensive
        return Check(
            name="Java / JDK 21+",
            status=STATUS_MISSING,
            detail=f"could not run `{java_exe} -version`: {exc}",
            fix="install a JDK 21+ (Temurin / Adoptium) and set JAVA_HOME",
        )
    home_note = f"JAVA_HOME={java_home}" if java_home else "JAVA_HOME is not set"
    if major is None:
        return Check(
            name="Java / JDK 21+",
            status=STATUS_WARN,
            detail=f"found {java_exe} but could not parse its version; {home_note}",
            fix="verify `java -version` reports 21 or newer",
        )
    if major < MIN_JAVA:
        return Check(
            name="Java / JDK 21+",
            status=STATUS_MISSING,
            detail=f"found Java {major} at {java_exe}; need {MIN_JAVA}+; {home_note}",
            fix=f"install a JDK {MIN_JAVA}+ and point JAVA_HOME at it",
        )
    if not java_home:
        return Check(
            name="Java / JDK 21+",
            status=STATUS_WARN,
            detail=f"Java {major} at {java_exe}, but JAVA_HOME is not set "
                   "(the native agent build needs it)",
            fix="set JAVA_HOME to your JDK install directory",
        )
    return Check(
        name="Java / JDK 21+",
        status=STATUS_OK,
        detail=f"Java {major} at {java_exe}; {home_note}",
    )


def check_python() -> Check:
    info = sys.version_info
    ver = f"{info[0]}.{info[1]}.{info[2]}"
    if (info[0], info[1]) < MIN_PYTHON:
        return Check(
            name="Python 3.11+",
            status=STATUS_MISSING,
            detail=f"running Python {ver}; need "
                   f"{MIN_PYTHON[0]}.{MIN_PYTHON[1]}+",
            fix="run the CLI under Python 3.11 or newer",
        )
    return Check(
        name="Python 3.11+",
        status=STATUS_OK,
        detail=f"Python {ver} at {sys.executable}",
    )


def _jvm_install_script(root: Path, module: str) -> Path:
    suffix = ".bat" if os.name == "nt" else ""
    return root / "jvm" / module / "build" / "install" / module / "bin" / f"{module}{suffix}"


def check_jvm_modules(root: Path) -> Check:
    missing = [m for m in REQUIRED_JVM_MODULES
               if not _jvm_install_script(root, m).exists()]
    if not missing:
        return Check(
            name="JVM modules (installDist)",
            status=STATUS_OK,
            detail=f"all built: {', '.join(REQUIRED_JVM_MODULES)}",
        )
    return Check(
        name="JVM modules (installDist)",
        status=STATUS_MISSING,
        detail=f"not built: {', '.join(missing)}",
        fix="run scripts/setup.sh (or scripts/setup.ps1), "
            "or `cd jvm && ./gradlew installDist`",
    )


def check_native_agent(root: Path) -> Check:
    libdir = root / "native" / "build" / "lib"
    for name in ("j2c_agent.dll", "j2c_agent.so", "j2c_agent.dylib"):
        if (libdir / name).exists():
            return Check(
                name="Native JVMTI agent",
                status=STATUS_OK,
                detail=f"found {libdir / name}",
            )
    return Check(
        name="Native JVMTI agent",
        status=STATUS_MISSING,
        detail=f"no j2c_agent.(so|dll|dylib) under {libdir}",
        fix="run scripts/setup.sh (needs JAVA_HOME + zig), "
            "or `cd native && JDK_HOME=\"$JAVA_HOME\" bash build.sh`",
    )


def check_ghidra() -> Check:
    ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if ghidra_dir and Path(ghidra_dir).exists():
        return Check(
            name="Ghidra (optional)",
            status=STATUS_OK,
            detail=f"GHIDRA_INSTALL_DIR={ghidra_dir}",
            optional=True,
        )
    for tool in ("analyzeHeadless", "analyzeHeadless.bat"):
        found = shutil.which(tool)
        if found:
            return Check(
                name="Ghidra (optional)",
                status=STATUS_OK,
                detail=f"found {found}",
                optional=True,
            )
    return Check(
        name="Ghidra (optional)",
        status=STATUS_OPTIONAL,
        detail="not found; only needed for the static (Advanced) path",
        fix="install Ghidra 11.x and set GHIDRA_INSTALL_DIR (optional)",
        optional=True,
    )


def check_unicorn() -> Check:
    try:
        import unicorn  # noqa: F401
    except Exception:
        return Check(
            name="unicorn (optional)",
            status=STATUS_OPTIONAL,
            detail="not installed; only needed for the emulation fallback",
            fix="pip install unicorn (optional)",
            optional=True,
        )
    return Check(
        name="unicorn (optional)",
        status=STATUS_OK,
        detail="importable",
        optional=True,
    )


def check_zig() -> Check:
    zig_env = os.environ.get("ZIG")
    if zig_env and Path(zig_env).exists():
        return Check(
            name="zig (optional)",
            status=STATUS_OK,
            detail=f"ZIG={zig_env}",
            optional=True,
        )
    found = shutil.which("zig")
    if found:
        return Check(
            name="zig (optional)",
            status=STATUS_OK,
            detail=f"found {found}",
            optional=True,
        )
    return Check(
        name="zig (optional)",
        status=STATUS_OPTIONAL,
        detail="not found; only needed to build the native agent from source",
        fix="install zig 0.16.x or set ZIG to its path (optional)",
        optional=True,
    )


def build_report(root: Path) -> Report:
    """Run every probe and return an aggregate report."""
    report = Report()
    report.add(check_java())
    report.add(check_python())
    report.add(check_jvm_modules(root))
    report.add(check_native_agent(root))
    report.add(check_ghidra())
    report.add(check_unicorn())
    report.add(check_zig())
    return report
