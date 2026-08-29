"""Make the ``j2c_dumper_cli`` package importable when tests run without an
editable install (e.g. plain ``pytest`` from a checkout)."""

import pathlib
import sys

_PKG_PARENT = pathlib.Path(__file__).resolve().parents[1]
if str(_PKG_PARENT) not in sys.path:
    sys.path.insert(0, str(_PKG_PARENT))
