"""Architecture / ABI abstractions used by the disassembly path.

Every architecture this project knows how to inspect exposes an
:class:`Abi` object describing:

  - the pointer size,
  - capstone init parameters (arch + mode),
  - the register-id of the argument that holds ``nMethods`` in a
    ``RegisterNatives`` call,
  - how to recognise an indirect-vtable call instruction,
  - how to decode an "address of constant" instruction (RIP-relative
    LEA on x86_64, ADRP/ADD on AArch64, etc.).

To support a new architecture, add a module under this package and
register its :class:`Abi` instance with :func:`register_abi`.
"""

from __future__ import annotations

from .base import Abi, register_abi, get_abi, list_abis, detect_abi
from . import amd64_windows, amd64_sysv  # ensure built-ins register

__all__ = ["Abi", "register_abi", "get_abi", "list_abis", "detect_abi"]
