"""x86_64 System V ABI (Linux, macOS, BSD).

First six integer / pointer args are passed in RDI, RSI, RDX, RCX, R8, R9.
JNI ``RegisterNatives(JNIEnv*, jclass, JNINativeMethod*, jint)`` therefore
puts ``jint nMethods`` in RCX (the 4th arg).
"""

from __future__ import annotations

from capstone import CS_ARCH_X86, CS_MODE_64, x86_const

from .base import Abi, register_abi


AMD64_SYSV = Abi(
    name="amd64-sysv",
    description="x86_64 System V ABI (Linux/macOS/BSD). nMethods passed in RCX.",
    pointer_size=8,
    cs_arch=CS_ARCH_X86,
    cs_mode=CS_MODE_64,
    n_methods_arg_regs=(x86_const.X86_REG_RCX, x86_const.X86_REG_ECX),
    pc_register=x86_const.X86_REG_RIP,
    binary_matches=[("ELF", 0x3E), ("MachO", 0x01000007)],
)

register_abi(AMD64_SYSV)
