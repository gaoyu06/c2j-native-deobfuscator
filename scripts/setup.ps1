<#
.SYNOPSIS
  Idempotent one-shot setup for the default (dynamic) recovery path on Windows.

.DESCRIPTION
  1. Build the JVM modules (Gradle installDist)
  2. Sync the Python workspace (uv, or pip fallback)
  3. Build the native JVMTI agent when a JDK is available

  Re-running is safe. On success, run:  python -m j2c_dumper_cli doctor

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
    Die "java not found. Install a JDK 21+ (Temurin/Adoptium) and set JAVA_HOME, then re-run."
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
if ($SkipNative) {
    Warn "Skipping native agent build (-SkipNative). The dynamic path needs it."
} else {
    $jdkHome = if ($env:JDK_HOME) { $env:JDK_HOME } elseif ($env:JAVA_HOME) { $env:JAVA_HOME } else { "" }
    if (-not $jdkHome) {
        $javaCmd = (Get-Command java).Source
        $jdkHome = Split-Path -Parent (Split-Path -Parent $javaCmd)
    }
    $libDir = Join-Path $Root "native/build/lib"
    $haveLib = (Test-Path (Join-Path $libDir "j2c_agent.dll")) -or `
               (Test-Path (Join-Path $libDir "j2c_agent.so"))  -or `
               (Test-Path (Join-Path $libDir "j2c_agent.dylib"))
    $hasZig = (Get-Command zig -ErrorAction SilentlyContinue) -or $env:ZIG
    if ($haveLib -and -not $Force) {
        Info "Native agent already built ($libDir); pass -Force to rebuild."
    } elseif (-not (Test-Path (Join-Path $jdkHome "include"))) {
        Warn "No JDK headers under '$jdkHome/include'; skipping native agent."
        Warn "Install a full JDK (not just a JRE), set JAVA_HOME, then re-run."
    } elseif (-not $hasZig) {
        Warn "zig not found; skipping native agent (needed only for the dynamic path)."
        Warn "Install zig 0.16.x or set ZIG, then re-run. Emulation path needs no native build."
    } else {
        Info "Building native JVMTI agent (JDK_HOME=$jdkHome)"
        if (-not (Get-Command bash -ErrorAction SilentlyContinue)) {
            Warn "bash not found; run native/build.sh under Git Bash / WSL to build the agent."
        } else {
            Push-Location (Join-Path $Root "native")
            try {
                $env:JDK_HOME = $jdkHome
                if (-not $env:ZIG) { $env:ZIG = "zig" }
                bash build.sh
                if ($LASTEXITCODE -ne 0) { Die "Native agent build failed. See the output above." }
            } finally { Pop-Location }
        }
    }
}

Info "Setup finished. Verify with: python -m j2c_dumper_cli doctor"
