"""Environment diagnostics for the j2c-dumper CLI.

The logic here is deliberately free of any UI framework so it can be unit
tested without the recovery toolchain (or Ghidra) installed. Each probe
returns a :class:`Check`; the CLI layer renders them.
"""

from __future__ import annotations

import os
import platform
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

MIN_JAVA = 17
MIN_PYTHON = (3, 11)

# The name shown for the Java check; kept in one place so the required
# minimum stays consistent between the probe and its messages.
JAVA_CHECK_NAME = f"Java / JDK {MIN_JAVA}+"

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
        """Required checks that actually block the default path.

        Only a required check reported ``MISSING`` blocks. A ``WARN`` is a
        non-fatal caveat (for example, Java is new enough but ``JAVA_HOME`` is
        unset) and must not flip the required-ready bit; optional tools never
        block.
        """
        return [c for c in self.checks if not c.optional and c.status == STATUS_MISSING]

    @property
    def warnings(self) -> list[Check]:
        """Required checks that are usable but flagged with a caveat."""
        return [c for c in self.checks if not c.optional and c.status == STATUS_WARN]

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
            name=JAVA_CHECK_NAME,
            status=STATUS_MISSING,
            detail="no `java` on PATH and JAVA_HOME unset",
            fix=f"install a JDK {MIN_JAVA}+ (Temurin / Adoptium) and set JAVA_HOME",
        )
    try:
        major = _parse_java_major(_query_java_version(java_exe))
    except Exception as exc:  # pragma: no cover - defensive
        return Check(
            name=JAVA_CHECK_NAME,
            status=STATUS_MISSING,
            detail=f"could not run `{java_exe} -version`: {exc}",
            fix=f"install a JDK {MIN_JAVA}+ (Temurin / Adoptium) and set JAVA_HOME",
        )
    home_note = f"JAVA_HOME={java_home}" if java_home else "JAVA_HOME is not set"
    if major is None:
        return Check(
            name=JAVA_CHECK_NAME,
            status=STATUS_WARN,
            detail=f"found {java_exe} but could not parse its version; {home_note}",
            fix=f"verify `java -version` reports {MIN_JAVA} or newer",
        )
    if major < MIN_JAVA:
        return Check(
            name=JAVA_CHECK_NAME,
            status=STATUS_MISSING,
            detail=f"found Java {major} at {java_exe}; need {MIN_JAVA}+; {home_note}",
            fix=f"install a JDK {MIN_JAVA}+ and point JAVA_HOME at it",
        )
    if not java_home:
        return Check(
            name=JAVA_CHECK_NAME,
            status=STATUS_WARN,
            detail=f"Java {major} at {java_exe}, but JAVA_HOME is not set "
                   "(the native agent build needs it)",
            fix="set JAVA_HOME to your JDK install directory",
        )
    return Check(
        name=JAVA_CHECK_NAME,
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


def venv_python(root: Optional[Path]) -> Optional[Path]:
    """The uv-managed interpreter under ``py/.venv``, if it exists.

    ``scripts/setup.sh`` runs ``uv sync``, which installs the packages into this
    interpreter — not the system ``python3``. Probes point users at it (via the
    ``scripts/j2c`` launcher) when the current interpreter lacks the packages.
    """
    if root is None:
        return None
    if os.name == "nt":
        candidate = root / "py" / ".venv" / "Scripts" / "python.exe"
    else:
        candidate = root / "py" / ".venv" / "bin" / "python"
    return candidate if candidate.exists() else None


def check_python_recover_deps(root: Optional[Path] = None) -> Check:
    """Import the Python stage the default path runs (binary introspection).

    Importing ``binary_introspect.cli`` pulls in its architecture backends,
    which require ``capstone`` and ``lief``. Probing it here catches a
    half-installed workspace before ``recover`` fails mid-pipeline.

    When the import fails but a uv-managed ``py/.venv`` exists (and is not the
    interpreter running this probe), the packages are almost certainly installed
    there: the real fix is to run the *right* interpreter, so the message says
    so instead of only suggesting a reinstall.
    """
    name = "Python recover deps (capstone, lief)"
    try:
        import binary_introspect.cli  # noqa: F401
    except Exception as exc:
        missing = getattr(exc, "name", "") or str(exc)
        venv = venv_python(root)
        if venv is not None and Path(sys.executable).resolve() != venv.resolve():
            fix = (f"the workspace is installed in {venv.parent.parent}; run it "
                   "through that interpreter — use `scripts/j2c doctor` "
                   "(or `scripts\\j2c.ps1 doctor` on Windows), which selects it")
        else:
            fix = ("run scripts/setup.sh (or scripts/setup.ps1), or "
                   "`pip install -e py/binary_introspect` (installs capstone + lief)")
        return Check(
            name=name,
            status=STATUS_MISSING,
            detail=f"cannot import binary_introspect.cli under {sys.executable}: {missing}",
            fix=fix,
        )
    return Check(
        name=name,
        status=STATUS_OK,
        detail="binary_introspect stage imports (capstone + lief present)",
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


def host_agent_name(platform: Optional[str] = None) -> str:
    """The JVMTI agent filename this host can actually load.

    A ``.so`` on Windows or a ``.dll`` on Linux belongs to another platform and
    cannot be loaded here, so the default path only ever looks for the single
    host-matching name.
    """
    plat = platform if platform is not None else sys.platform
    if plat.startswith("win") or os.name == "nt":
        return "j2c_agent.dll"
    if plat == "darwin":
        return "j2c_agent.dylib"
    return "j2c_agent.so"


# Agents smaller than this are almost certainly a truncated or placeholder
# build rather than a real shared library, so treat them as not ready.
_MIN_AGENT_BYTES = 4096

# The three names the build can emit; used only to explain a wrong-platform
# leftover, never to accept one.
_ALL_AGENT_NAMES = ("j2c_agent.so", "j2c_agent.dylib", "j2c_agent.dll")

# CPU architectures this project can actually build an agent for.
# ``native/build.sh`` passes `-target x86_64-*` for every host OS, so x86-64 is
# the only architecture whose agent the default (dynamic) path can rely on.
SUPPORTED_AGENT_MACHINES = ("x86_64",)


def host_machine(machine: Optional[str] = None) -> str:
    """Normalise the host CPU architecture to a small, comparable label.

    ``platform.machine()`` reports many spellings for the same ISA
    (``x86_64``/``amd64``/``AMD64``, ``aarch64``/``arm64``). Collapsing them
    lets the native-agent probe compare the host against what the artifact was
    actually built for.
    """
    m = (machine if machine is not None else platform.machine()).lower()
    if m in ("x86_64", "amd64", "x64", "em64t"):
        return "x86_64"
    if m in ("aarch64", "arm64", "armv8", "armv8l"):
        return "arm64"
    if m in ("i386", "i486", "i586", "i686", "x86"):
        return "x86"
    if m.startswith("arm"):
        return "arm"
    return m or "unknown"


# ELF e_machine / Mach-O cputype / PE machine values, mapped to the same
# normalised labels host_machine() returns. Only the architectures the build
# can plausibly emit are listed; anything else stays unknown (and unenforced).
_ELF_MACHINES = {0x03: "x86", 0x3E: "x86_64", 0x28: "arm", 0xB7: "arm64"}
_MACHO_CPUS = {0x00000007: "x86", 0x01000007: "x86_64",
               0x0000000C: "arm", 0x0100000C: "arm64"}
_PE_MACHINES = {0x014C: "x86", 0x8664: "x86_64", 0x01C0: "arm",
                0x01C4: "arm", 0xAA64: "arm64"}


def agent_arch(path: Path) -> Optional[str]:
    """Read a shared library's target CPU from its header (ELF/Mach-O/PE).

    Returns a :func:`host_machine`-style label, or ``None`` when the format or
    architecture is unrecognised (in which case the caller does not enforce an
    architecture match — it only blocks on a *known* mismatch).
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return None
    if len(head) < 6:
        return None

    if head[:4] == b"\x7fELF":  # ELF (Linux, etc.)
        endian = "little" if head[5] == 1 else "big"
        if len(head) < 20:
            return None
        return _ELF_MACHINES.get(int.from_bytes(head[18:20], endian))

    magic = head[:4]
    if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):  # Mach-O little-endian
        return _MACHO_CPUS.get(int.from_bytes(head[4:8], "little"))
    if magic in (b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):  # Mach-O big-endian
        return _MACHO_CPUS.get(int.from_bytes(head[4:8], "big"))

    if head[:2] == b"MZ":  # PE / COFF (Windows DLL)
        if len(head) < 0x40:
            return None
        pe_off = int.from_bytes(head[0x3C:0x40], "little")
        if pe_off + 6 > len(head) or head[pe_off:pe_off + 4] != b"PE\x00\x00":
            return None
        return _PE_MACHINES.get(int.from_bytes(head[pe_off + 4:pe_off + 6], "little"))

    return None


def check_native_agent(root: Path) -> Check:
    libdir = root / "native" / "build" / "lib"
    want = host_agent_name()
    host = host_machine()
    supported = "/".join(SUPPORTED_AGENT_MACHINES)
    fix = ("run scripts/setup.sh (needs JAVA_HOME + zig), "
           "or `cd native && JDK_HOME=\"$JAVA_HOME\" bash build.sh`")
    target = libdir / want

    # The default path loads the agent into *this* JVM, so it needs an agent
    # built for this CPU — and native/build.sh can only build x86-64. On any
    # other host there is no supported way to produce one, so nothing found in
    # build/lib proves the dynamic path is usable: an x86-64 artifact cannot be
    # loaded here, and a same-arch one did not come from this build. Report the
    # agent as missing rather than guessing, and point at the paths that need
    # no agent.
    if host not in SUPPORTED_AGENT_MACHINES:
        present = [n for n in _ALL_AGENT_NAMES if (libdir / n).exists()]
        found = ""
        if present:
            arch = agent_arch(libdir / present[0])
            found = (f"; ignoring {', '.join(present)} under {libdir}"
                     + (f" (built for {arch})" if arch else ""))
        return Check(
            name="Native JVMTI agent",
            status=STATUS_MISSING,
            detail=f"this host is {host}, but native/build.sh only targets "
                   f"{supported}, so the dynamic path has no agent it can "
                   f"load here{found}",
            fix=f"use the emulation fallback or the static path (neither needs "
                f"the agent), run the dynamic path on {supported}, or port "
                f"native/build.sh to {host}",
        )

    if target.exists():
        size = target.stat().st_size
        if size < _MIN_AGENT_BYTES:
            return Check(
                name="Native JVMTI agent",
                status=STATUS_MISSING,
                detail=f"{target} is only {size} bytes; looks empty or truncated",
                fix="delete it and rebuild: " + fix,
            )
        built = agent_arch(target)
        # An agent whose architecture cannot be read is not a library this JVM
        # is known to be able to load, so it does not count as ready either.
        if built is None:
            return Check(
                name="Native JVMTI agent",
                status=STATUS_MISSING,
                detail=f"cannot read a target architecture from {target}; it is "
                       "not a recognised ELF/Mach-O/PE shared library, so it "
                       "may not load here",
                fix="delete it and rebuild: " + fix,
            )
        if built != host:
            return Check(
                name="Native JVMTI agent",
                status=STATUS_MISSING,
                detail=f"{target} is built for {built} but this host is {host}; "
                       "native/build.sh targets x86-64 and its output cannot be "
                       "loaded here",
                fix="rebuild for this architecture: " + fix,
            )
        return Check(
            name="Native JVMTI agent",
            status=STATUS_OK,
            detail=f"found {target} ({built})",
        )

    # A leftover build for another OS must not read as ready.
    stray = [n for n in _ALL_AGENT_NAMES if n != want and (libdir / n).exists()]
    if stray:
        return Check(
            name="Native JVMTI agent",
            status=STATUS_MISSING,
            detail=f"found {', '.join(stray)} under {libdir} but this host needs "
                   f"{want}; a wrong-platform agent cannot be loaded here",
            fix="rebuild on this host: " + fix,
        )

    return Check(
        name="Native JVMTI agent",
        status=STATUS_MISSING,
        detail=f"no {want} under {libdir}",
        fix=fix,
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
            # Name the interpreter explicitly: unicorn must land in the one the
            # emulation harness runs under, not in whichever `pip` is on PATH.
            fix=f"install it for this interpreter — `(cd py && uv pip install "
                f"unicorn)`, or `{sys.executable} -m pip install unicorn` "
                f"(optional)",
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
    report.add(check_python_recover_deps(root))
    report.add(check_jvm_modules(root))
    report.add(check_native_agent(root))
    report.add(check_ghidra())
    report.add(check_unicorn())
    report.add(check_zig())
    return report
