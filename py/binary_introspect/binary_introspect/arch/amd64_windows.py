"""x86_64 Windows ABI (Microsoft x64 calling convention).

First four integer / pointer args are passed in RCX, RDX, R8, R9. JNI
``RegisterNatives(JNIEnv*, jclass, JNINativeMethod*, jint)`` therefore
puts ``jint nMethods`` in R9.
"""

from __future__ import annotations

from capstone import CS_ARCH_X86, CS_MODE_64, x86_const

from .base import Abi, register_abi


AMD64_WINDOWS = Abi(
    name="amd64-windows",
    description="x86_64 Microsoft x64 ABI (Windows). nMethods passed in R9.",
    pointer_size=8,
    cs_arch=CS_ARCH_X86,
    cs_mode=CS_MODE_64,
    n_methods_arg_regs=(x86_const.X86_REG_R9, x86_const.X86_REG_R9D),
    pc_register=x86_const.X86_REG_RIP,
    binary_matches=[("PE", 0x8664)],
)

register_abi(AMD64_WINDOWS)
