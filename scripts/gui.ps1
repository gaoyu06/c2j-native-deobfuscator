# Launch the read-only Swing artifact viewer.
#
# Usage:
#   scripts/gui.ps1 [session-directory]
#
# The optional argument opens a session folder on start. The viewer is a
# viewer only - recovery still runs through the j2c-dumper CLI.
param(
    [string]$SessionDir
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location (Join-Path $root "jvm")

if ($SessionDir) {
    & .\gradlew.bat --console=plain -q ":desktop-ui:run" "--args=$SessionDir"
} else {
    & .\gradlew.bat --console=plain -q ":desktop-ui:run"
}
