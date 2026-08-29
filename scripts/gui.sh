#!/usr/bin/env bash
# Launch the read-only Swing artifact viewer.
#
# Usage:
#   scripts/gui.sh [session-directory]
#
# The optional argument opens a session folder on start. The viewer is a
# viewer only — recovery still runs through the j2c-dumper CLI.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here/jvm"

if [[ $# -gt 0 ]]; then
    exec ./gradlew --console=plain -q :desktop-ui:run --args="$1"
else
    exec ./gradlew --console=plain -q :desktop-ui:run
fi
