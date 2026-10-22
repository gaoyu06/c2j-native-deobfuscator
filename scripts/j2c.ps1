<#
.SYNOPSIS
  Single entry point for the j2c-dumper CLI on Windows.

.DESCRIPTION
  scripts/setup.ps1 syncs the Python workspace with uv, which installs the
  packages into py/.venv — a system `python -m j2c_dumper_cli` cannot see them.
  Release ZIPs include a standalone runtime under runtime/python. This launcher
  prefers that runtime, then the uv-managed venv, otherwise $env:PYTHON / python (the pip
  fallback installs into that interpreter's own environment).

    scripts\j2c.ps1 doctor
    scripts\j2c.ps1 recover in.jar -o out.jar --run-cmd "java -jar in.jar"
#>
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = (Resolve-Path (Join-Path $ScriptDir "..")).Path

$venvPy = Join-Path $Root "py/.venv/Scripts/python.exe"
$portablePy = Join-Path $Root "runtime/python/python.exe"
if (Test-Path $portablePy) {
    $py = $portablePy
} elseif (Test-Path $venvPy) {
    $venvOk = $false
    try {
        & $venvPy -c "import sys" 2>$null
        $venvOk = ($LASTEXITCODE -eq 0)
    } catch { $venvOk = $false }
    if (-not $venvOk) {
        throw "This Python environment belongs to another computer. Use a new release ZIP with runtime/python, or remove py/.venv and rerun scripts/setup.ps1 with a local Python installation."
    }
    $py = $venvPy
} elseif ($env:PYTHON) {
    $py = $env:PYTHON
} else {
    $py = "python"
}

# Let the CLI echo this launcher in its own hints, so every printed follow-up
# command is one that actually works here.
$env:J2C_CMD = "scripts\j2c.ps1"
$env:J2C_PYTHON = $py

& $py -m j2c_dumper_cli @args
exit $LASTEXITCODE
