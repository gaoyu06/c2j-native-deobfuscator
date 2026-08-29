<#
.SYNOPSIS
  Single entry point for the j2c-dumper CLI on Windows.

.DESCRIPTION
  scripts/setup.ps1 syncs the Python workspace with uv, which installs the
  packages into py/.venv — a system `python -m j2c_dumper_cli` cannot see them.
  This launcher always runs the interpreter that has the packages: the
  uv-managed venv when it exists, otherwise $env:PYTHON / python (the pip
  fallback installs into that interpreter's own environment).

    scripts\j2c.ps1 doctor
    scripts\j2c.ps1 recover in.jar -o out.jar --run-cmd "java -jar in.jar"
#>
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = (Resolve-Path (Join-Path $ScriptDir "..")).Path

$venvPy = Join-Path $Root "py/.venv/Scripts/python.exe"
if (Test-Path $venvPy) {
    $py = $venvPy
} elseif ($env:PYTHON) {
    $py = $env:PYTHON
} else {
    $py = "python"
}

# Let the CLI echo this launcher in its own hints, so every printed follow-up
# command is one that actually works here.
$env:J2C_CMD = "scripts\j2c.ps1"

& $py -m j2c_dumper_cli @args
exit $LASTEXITCODE
