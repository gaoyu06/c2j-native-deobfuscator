<#
.SYNOPSIS
  Idempotent one-shot setup for the default (dynamic) recovery path on Windows.

.DESCRIPTION
  1. Build the JVM modules (Gradle installDist)
  2. Sync the Python workspace (uv, or pip fallback)
  3. Build the native JVMTI agent when a JDK is available

  Re-running is safe. uv installs the Python workspace into py/.venv, so use the
  scripts\j2c.ps1 launcher (which selects that interpreter) rather than a bare
  `python -m j2c_dumper_cli`. On success, run:  scripts\j2c.ps1 doctor

.PARAMETER Force
  Rebuild the native agent even if it is already up to date.

.PARAMETER SkipNative
  Build JVM + Python only. The dynamic path still needs the native agent.
#>
[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$SkipNative
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = (Resolve-Path (Join-Path $ScriptDir "..")).Path

function Info($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Warn($msg) { Write-Host "warn: $msg" -ForegroundColor Yellow }
function Die($msg)  { Write-Host "error: $msg" -ForegroundColor Red; exit 1 }

# ------------------------------------------------------------------
# Preconditions
# ------------------------------------------------------------------
if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    Die "java not found. Install a JDK 17+ (Temurin/Adoptium) and set JAVA_HOME, then re-run."
}

# ------------------------------------------------------------------
# 1. JVM modules
# ------------------------------------------------------------------
Info "Building JVM modules (installDist)"
$gradlew = Join-Path $Root "jvm/gradlew.bat"
if (-not (Test-Path $gradlew)) { Die "jvm/gradlew.bat is missing." }
Push-Location (Join-Path $Root "jvm")
try {
    & $gradlew installDist --no-daemon
    if ($LASTEXITCODE -ne 0) { Die "Gradle build failed. See the output above." }
} finally { Pop-Location }

# ------------------------------------------------------------------
# 2. Python workspace
# ------------------------------------------------------------------
Info "Syncing Python workspace"
if (Get-Command uv -ErrorAction SilentlyContinue) {
    Push-Location (Join-Path $Root "py")
    try {
        uv sync --all-packages
        if ($LASTEXITCODE -ne 0) { Die "uv sync failed. See the output above." }
    } finally { Pop-Location }
} else {
    Warn "uv not found; falling back to 'pip install -e' for each package."
    $python = if ($env:PYTHON) { $env:PYTHON } else { "python" }
    if (-not (Get-Command $python -ErrorAction SilentlyContinue)) { Die "python not found." }
    & $python -m pip install `
        -e (Join-Path $Root "py/j2c_dumper_cli") `
        -e (Join-Path $Root "py/binary_introspect") `
        -e (Join-Path $Root "py/manifest_merge") `
        -e (Join-Path $Root "py/ast_matcher") `
        -e (Join-Path $Root "py/snippet_importer")
    if ($LASTEXITCODE -ne 0) { Die "pip install failed. Install uv (https://docs.astral.sh/uv/) and re-run." }
}

# ------------------------------------------------------------------
# 3. Native JVMTI agent (dynamic path)
# ------------------------------------------------------------------
$nativeReady = $false
$nativeNote = "the dynamic path was not set up"
if ($SkipNative) {
    Warn "Skipping native agent build (-SkipNative). The dynamic path needs it."
    $nativeNote = "native agent skipped (-SkipNative); the dynamic path is unavailable"
} else {
    $jdkHome = if ($env:JDK_HOME) { $env:JDK_HOME } elseif ($env:JAVA_HOME) { $env:JAVA_HOME } else { "" }
    if (-not $jdkHome) {
        $javaCmd = (Get-Command java).Source
        $jdkHome = Split-Path -Parent (Split-Path -Parent $javaCmd)
    }
    $libDir = Join-Path $Root "native/build/lib"
    # On Windows only j2c_agent.dll is loadable; a leftover .so/.dylib is a
    # wrong-platform artifact and must not count as "already built".
    $agent = Join-Path $libDir "j2c_agent.dll"
    # native/build.sh cross-targets x86-64 only; on an ARM64 Windows host it
    # would emit a DLL the JVM here cannot load, so do not build it and do not
    # report the default dynamic path as ready.
    $hostArch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    $archOk = ($hostArch -eq "AMD64")
    # Rebuild when the DLL is missing, empty, or older than any input.
    $needsBuild = $true
    if ((Test-Path $agent) -and ((Get-Item $agent).Length -gt 0)) {
        $agentTime = (Get-Item $agent).LastWriteTimeUtc
        $inputs = @()
        $inputs += Get-ChildItem (Join-Path $Root "native/src") -File -ErrorAction SilentlyContinue
        $inputs += Get-ChildItem (Join-Path $Root "native/include") -File -Recurse -ErrorAction SilentlyContinue
        $buildScript = Join-Path $Root "native/build.sh"
        if (Test-Path $buildScript) { $inputs += Get-Item $buildScript }
        $newer = $inputs | Where-Object { $_.LastWriteTimeUtc -gt $agentTime }
        if (-not $newer) { $needsBuild = $false }
    }
    $hasZig = (Get-Command zig -ErrorAction SilentlyContinue) -or $env:ZIG
    # The build is driven by native/build.sh, so a POSIX-style shell is required.
    # Git Bash (from Git for Windows) runs it as a Windows toolchain and produces
    # the Windows DLL. WSL runs it as Linux: it selects a Linux target and emits a
    # .so, not the Windows .dll the JVM here loads, so it is NOT equivalent.
    $hasBash = Get-Command bash -ErrorAction SilentlyContinue
    if (-not $archOk) {
        Warn "This host is $hostArch, but native/build.sh targets x86-64; skipping native agent."
        Warn "The default dynamic path needs a host-matching agent. Use the emulation fallback,"
        Warn "or port native/build.sh to $hostArch and rebuild."
        $nativeNote = "native agent skipped ($hostArch host; build.sh targets x86-64); the dynamic path is unavailable"
    } elseif ((-not $needsBuild) -and (-not $Force)) {
        Info "Native agent up to date ($agent); pass -Force to rebuild."
        $nativeReady = $true
    } elseif (-not (Test-Path (Join-Path $jdkHome "include"))) {
        Warn "No JDK headers under '$jdkHome/include'; skipping native agent."
        Warn "Install a full JDK (not just a JRE), set JAVA_HOME, then re-run."
        $nativeNote = "native agent skipped (no JDK headers); the dynamic path is unavailable"
    } elseif (-not $hasZig) {
        Warn "zig not found; skipping native agent (needed only for the dynamic path)."
        Warn "Install zig 0.16.x or set ZIG, then re-run. Emulation path needs no native build."
        $nativeNote = "native agent skipped (zig not found); the dynamic path is unavailable"
    } elseif (-not $hasBash) {
        Warn "Git Bash not found; the native DLL build needs it (it runs native/build.sh)."
        Warn "Install Git for Windows (provides Git Bash) so 'bash' is on PATH, then re-run."
        Warn "Do NOT use WSL for this: WSL builds a Linux .so, not the Windows .dll the JVM here loads."
        $nativeNote = "native agent skipped (Git Bash not found); the dynamic path is unavailable"
    } else {
        Info "Building native JVMTI agent (JDK_HOME=$jdkHome)"
        Push-Location (Join-Path $Root "native")
        try {
            $env:JDK_HOME = $jdkHome
            if (-not $env:ZIG) { $env:ZIG = "zig" }
            bash build.sh
            if ($LASTEXITCODE -ne 0) { Die "Native agent build failed. See the output above." }
            $nativeReady = $true
        } finally { Pop-Location }
    }
}

if ($nativeReady) {
    Info "Setup finished: required versions and build artifacts for the default (dynamic) path are in place."
    Info "Recovery is still best-effort per target — inspect the output. Verify the toolchain with: scripts\j2c.ps1 doctor"
} else {
    Warn "Setup finished, but $nativeNote."
    Warn "Use the emulation fallback, or install the missing piece and re-run."
    Info "Verify with: scripts\j2c.ps1 doctor"
}
