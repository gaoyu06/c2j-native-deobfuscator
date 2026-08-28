"""AArch64 AAPCS64 ABI (ELF, and Mach-O arm64).

The first eight integer / pointer arguments are passed in ``x0``–``x7``.
``RegisterNatives(JNIEnv*, jclass, JNINativeMethod*, jint)`` therefore places
``JNIEnv*`` in ``x0``, ``jclass`` in ``x1``, ``JNINativeMethod*`` in ``x2`` and
``jint nMethods`` in ``x3`` (``w3`` for the 32-bit view).

AArch64 does not have a "call through a memory operand" instruction, so a JNI
vtable dispatch is always the split form the base scanner already understands:
the slot is materialised with ``ldr xN, [xEnv, #index*8]`` and then reached via
``blr``/``br`` (frequently through the ``x16`` intra-procedure-call veneer
register). The address of an in-image constant such as a static
``JNINativeMethod[]`` is formed with an ``adrp``/``add`` pair rather than a
single RIP-relative ``lea``; :meth:`Aarch64Abi.decode_pc_relative_lea` folds
that pair back into an absolute VA.
"""

from __future__ import annotations

from typing import Any

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, arm64_const

from .base import Abi, register_abi


#: capstone kind ids for AArch64 operands.
_OP_REG = arm64_const.ARM64_OP_REG
_OP_IMM = arm64_const.ARM64_OP_IMM
_OP_MEM = arm64_const.ARM64_OP_MEM

#: Stack-pointer / frame-pointer bases for a spilled JNINativeMethod[].
_STACK_BASES = (arm64_const.ARM64_REG_SP, arm64_const.ARM64_REG_X29)


class Aarch64Abi(Abi):
    """AArch64 ABI with AArch64-specific instruction decoding.

    The base :class:`Abi` decodes x86 operands; every method that inspects a
    concrete instruction is overridden here so AArch64 operands are read
    correctly. ``adrp``/``add`` address formation is intrinsically a
    two-instruction sequence, so :meth:`decode_pc_relative_lea` keeps a small
    per-scan map of the page value each register received from an ``adrp``. The
    map is reset whenever the disassembly stream is discontinuous (a fresh
    ``cs.disasm`` pass), so state never leaks between call sites.
    """

    def _adrp_state(self) -> dict[int, int]:
        state = getattr(self, "_adrp_pages", None)
        if state is None:
            state = {}
            self._adrp_pages = state
        return state

    def is_indirect_vtable_call(self, ins: Any) -> int | None:
        # AArch64 has no call/jmp through a memory operand; a vtable slot is
        # always loaded to a register first (handled by vtable_slot_load) and
        # then reached with blr/br. Never a single-instruction memory call.
        return None

    def vtable_slot_load(self, ins: Any) -> tuple[int, int] | None:
        """Recognise ``ldr xDst, [xBase, #disp]`` and return ``(dst, disp)``.

        Literal loads (``ldr xDst, =const`` / PC-relative) carry an immediate
        or label operand, not a base-register memory operand, and are excluded.
        """
        if ins.mnemonic != "ldr" or len(ins.operands) != 2:
            return None
        dst, src = ins.operands
        if dst.type != _OP_REG or src.type != _OP_MEM:
            return None
        if src.mem.base == 0 or src.mem.index != 0:
            return None
        return dst.reg, src.mem.disp

    def indirect_branch_register(self, ins: Any) -> int | None:
        """Return the register used by ``blr``/``br`` (indirect call / tail
        jump). ``bl``/``b`` take a PC-relative label, not a register."""
        if ins.mnemonic not in ("blr", "br") or len(ins.operands) != 1:
            return None
        operand = ins.operands[0]
        return operand.reg if operand.type == _OP_REG else None

    def register_move(self, ins: Any) -> tuple[int, int] | None:
        """``mov xDst, xSrc`` — a plain register-to-register copy."""
        if ins.mnemonic != "mov" or len(ins.operands) != 2:
            return None
        dst, src = ins.operands
        if dst.type != _OP_REG or src.type != _OP_REG:
            return None
        return dst.reg, src.reg

    def decode_pc_relative_lea(self, ins: Any) -> int | None:
        """Fold an ``adrp``/``add`` address-of-constant pair into an absolute
        VA, returned when the completing ``add`` is decoded.

        ``adrp xN, #page`` records ``page`` for ``xN`` (capstone already
        resolves the operand to the absolute page base). A following
        ``add xDst, xSrc, #lo12`` where ``xSrc`` holds a recorded page yields
        ``page + lo12``. ``adrp``/``ldr`` (which loads the *value* at the
        address, not the address) is deliberately not treated as an address.
        """
        state = self._adrp_state()
        expected = getattr(self, "_adrp_next_addr", None)
        if expected is None or ins.address != expected:
            state.clear()
        self._adrp_next_addr = ins.address + ins.size

        if ins.mnemonic == "adrp" and len(ins.operands) == 2:
            dst, page = ins.operands
            if dst.type == _OP_REG and page.type == _OP_IMM:
                state[dst.reg] = page.imm
            return None

        if ins.mnemonic == "add" and len(ins.operands) == 3:
            dst, src, imm = ins.operands
            if (
                dst.type == _OP_REG
                and src.type == _OP_REG
                and imm.type == _OP_IMM
                and src.reg in state
            ):
                full = state[src.reg] + imm.imm
                # The destination now holds a completed pointer, not a page.
                # If it aliases the source register, drop the stale page so a
                # later add on the same register is not mis-folded.
                if dst.reg == src.reg:
                    state.pop(src.reg, None)
                return full
        return None

    def is_stack_store(self, ins: Any) -> tuple[int, int] | None:
        """``str xSrc, [sp/x29, #disp]`` → ``(disp, src_reg)``.

        AArch64 stores name the source register first and the destination
        memory operand second (the reverse of x86's ``mov [mem], reg``)."""
        if ins.mnemonic != "str" or len(ins.operands) != 2:
            return None
        src, dst = ins.operands
        if src.type != _OP_REG or dst.type != _OP_MEM:
            return None
        if dst.mem.base not in _STACK_BASES or dst.mem.index != 0:
            return None
        return dst.mem.disp, src.reg

    def is_n_methods_load(self, ins: Any) -> int | None:
        """``mov`` / ``movz`` of an immediate into ``w3``/``x3``."""
        if ins.mnemonic not in ("mov", "movz") or len(ins.operands) != 2:
            return None
        dst, src = ins.operands
        if dst.type != _OP_REG or src.type != _OP_IMM:
            return None
        if dst.reg not in self.n_methods_arg_regs:
            return None
        return src.imm

    def methods_address_load(self, ins: Any) -> int | None:
        # The third-argument table address is materialised by the adrp/add
        # pair handled in decode_pc_relative_lea; there is no single-instruction
        # form to recognise here.
        return None


AARCH64_AAPCS64 = Aarch64Abi(
    name="aarch64-aapcs64",
    description="AArch64 AAPCS64 (ELF / Mach-O arm64). nMethods passed in w3/x3.",
    pointer_size=8,
    cs_arch=CS_ARCH_ARM64,
    cs_mode=CS_MODE_ARM,
    n_methods_arg_regs=(arm64_const.ARM64_REG_X3, arm64_const.ARM64_REG_W3),
    methods_arg_regs=(arm64_const.ARM64_REG_X2,),
    # AArch64 forms PC-relative constant addresses with adrp/add, not a single
    # instruction against a PC register, so no capstone PC register applies.
    pc_register=0,
    binary_matches=[("ELF", 0xB7), ("MachO", 0x0100000C)],
)

register_abi(AARCH64_AAPCS64)
