"""32-bit ARM AAPCS ABI (ELF ``EM_ARM``).

The first four integer / pointer arguments are passed in ``r0``–``r3``.
``RegisterNatives(JNIEnv*, jclass, JNINativeMethod*, jint)`` therefore places
``JNIEnv*`` in ``r0``, ``jclass`` in ``r1``, ``JNINativeMethod*`` in ``r2`` and
``jint nMethods`` in ``r3``.

Like AArch64, 32-bit ARM has no "call through a memory operand" instruction, so
a JNI vtable dispatch is always the split form the base scanner understands: the
slot is materialised with ``ldr rN, [rEnv, #index*4]`` and then reached via
``blx``/``bx`` (frequently through the ``ip`` (r12) intra-procedure-call veneer
register, e.g. ``ldr lr, [ip, #860]`` / ``mov ip, lr`` / ``bx ip``).

The address of an in-image constant such as a static ``JNINativeMethod[]`` is
not a single ``lea`` (x86) or ``adrp``/``add`` pair (AArch64). Position-
independent 32-bit ARM code loads a PC-relative *offset* from the function's
literal pool and then adds the program counter:

    ldr r2, [pc, #k]     ; r2 = *(pc + 8 + k)  (a link-time constant offset)
    add r2, pc, r2       ; r2 = (pc + 8) + offset  = &JNINativeMethod[]

:meth:`ArmAapcs32Abi.decode_pc_relative_lea` folds that two-instruction form
back into the absolute VA. It reads the literal-pool word through a per-scan
reader supplied by :meth:`Abi.begin_scan`; the base class stores the reader and
this backend consumes it.
"""

from __future__ import annotations

from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_ARM, arm_const

from .base import Abi, register_abi


#: capstone kind ids for ARM operands.
_OP_REG = arm_const.ARM_OP_REG
_OP_IMM = arm_const.ARM_OP_IMM
_OP_MEM = arm_const.ARM_OP_MEM

_REG_PC = arm_const.ARM_REG_PC

#: Stack / frame bases for a spilled JNINativeMethod[]. ARM frame pointer is
#: ``r11`` (``fp``) in ARM state and ``r7`` in Thumb state; include both plus
#: ``sp`` so a stack-built table is recognised regardless of frame layout.
_STACK_BASES = (
    arm_const.ARM_REG_SP,
    arm_const.ARM_REG_R11,   # fp in ARM state
    arm_const.ARM_REG_R7,    # fp in Thumb state
)


class ArmAapcs32Abi(Abi):
    """32-bit ARM ABI with ARM-specific instruction decoding.

    The base :class:`Abi` decodes x86 operands; every method that inspects a
    concrete instruction is overridden here so ARM operands are read correctly.
    PC-relative address formation is a ``ldr``-literal followed by ``add rX,
    pc, rX``, so :meth:`decode_pc_relative_lea` keeps a small per-scan map of
    the offset each register received from a literal-pool load. The map is reset
    whenever the disassembly stream is discontinuous (a fresh ``cs.disasm``
    pass), so state never leaks between call sites.
    """

    def _literal_state(self) -> dict[int, int]:
        state = getattr(self, "_arm_literals", None)
        if state is None:
            state = {}
            self._arm_literals = state
        return state

    def is_indirect_vtable_call(self, ins: Any) -> int | None:
        # ARM has no call/jmp through a memory operand; a vtable slot is always
        # loaded to a register first (handled by vtable_slot_load) and then
        # reached with blx/bx. Never a single-instruction memory call.
        return None

    def vtable_slot_load(self, ins: Any) -> tuple[int, int] | None:
        """Recognise ``ldr rDst, [rBase, #disp]`` and return ``(dst, disp)``.

        Literal-pool loads (``ldr rDst, [pc, #disp]``) address a constant, not
        a ``JNIEnv`` vtable slot, so a ``pc`` base is excluded. Indexed and
        write-back forms (a non-zero index register) are likewise not a plain
        slot load.
        """
        if ins.mnemonic != "ldr" or len(ins.operands) != 2:
            return None
        dst, src = ins.operands
        if dst.type != _OP_REG or src.type != _OP_MEM:
            return None
        if src.mem.base in (0, _REG_PC) or src.mem.index != 0:
            return None
        return dst.reg, src.mem.disp

    def indirect_branch_register(self, ins: Any) -> int | None:
        """Return the register used by ``bx``/``blx`` (indirect call / tail
        jump). ``b``/``bl`` take a PC-relative label, not a register."""
        if ins.mnemonic not in ("bx", "blx") or len(ins.operands) != 1:
            return None
        operand = ins.operands[0]
        return operand.reg if operand.type == _OP_REG else None

    def register_move(self, ins: Any) -> tuple[int, int] | None:
        """``mov rDst, rSrc`` — a plain register-to-register copy (the veneer
        move that carries the vtable slot pointer into ``ip`` before ``bx``)."""
        if ins.mnemonic != "mov" or len(ins.operands) != 2:
            return None
        dst, src = ins.operands
        if dst.type != _OP_REG or src.type != _OP_REG:
            return None
        return dst.reg, src.reg

    def decode_pc_relative_lea(self, ins: Any) -> int | None:
        """Fold a 32-bit ARM "address of constant" form into an absolute VA.

        Position-independent ARM materialises an in-image address in two steps:

        * ``ldr rN, [pc, #k]`` loads a link-time-constant offset from the
          function's literal pool (``*(Align(PC,4) + 8 + k)``). ARM instructions
          are 4-byte aligned, so ``Align(PC,4)`` is just ``ins.address``. The
          offset is recorded for ``rN`` via the per-scan reader.
        * ``add rDst, pc, rN`` completes the pointer: ``(ins.address + 8) +
          offset``. ``add rDst, pc, #imm`` is the rarer single-instruction form
          and is folded directly.

        A load whose literal cannot be read (no reader, or out of the mapped
        image) records nothing, so a later ``add`` on that register yields
        ``None`` rather than a fabricated address.
        """
        state = self._literal_state()
        expected = getattr(self, "_arm_next_addr", None)
        if expected is None or ins.address != expected:
            state.clear()
        self._arm_next_addr = ins.address + ins.size

        if ins.mnemonic == "ldr" and len(ins.operands) == 2:
            dst, src = ins.operands
            if (
                dst.type == _OP_REG
                and src.type == _OP_MEM
                and src.mem.base == _REG_PC
                and src.mem.index == 0
            ):
                read_word = getattr(self, "_scan_read_word", None)
                literal_va = ins.address + 8 + src.mem.disp
                word = read_word(literal_va, 4) if read_word is not None else None
                if word is None:
                    state.pop(dst.reg, None)
                else:
                    state[dst.reg] = word
            return None

        if ins.mnemonic == "add" and len(ins.operands) == 3:
            dst, base, off = ins.operands
            if (
                dst.type == _OP_REG
                and base.type == _OP_REG
                and base.reg == _REG_PC
            ):
                if off.type == _OP_IMM:
                    return (ins.address + 8 + off.imm) & 0xFFFFFFFF
                if off.type == _OP_REG and off.reg in state:
                    full = (ins.address + 8 + state[off.reg]) & 0xFFFFFFFF
                    # The completed pointer is no longer an offset; drop the
                    # stale literal so a later add on the same register is not
                    # mis-folded.
                    state.pop(off.reg, None)
                    if dst.reg != off.reg:
                        state.pop(dst.reg, None)
                    return full
        return None

    def is_stack_store(self, ins: Any) -> tuple[int, int] | None:
        """``str rSrc, [sp/fp, #disp]`` → ``(disp, src_reg)``.

        ARM stores name the source register first and the destination memory
        operand second (the reverse of x86's ``mov [mem], reg``)."""
        if ins.mnemonic != "str" or len(ins.operands) != 2:
            return None
        src, dst = ins.operands
        if src.type != _OP_REG or dst.type != _OP_MEM:
            return None
        if dst.mem.base not in _STACK_BASES or dst.mem.index != 0:
            return None
        return dst.mem.disp, src.reg

    def is_n_methods_load(self, ins: Any) -> int | None:
        """``mov`` / ``movw`` of an immediate into ``r3``."""
        if ins.mnemonic not in ("mov", "movw") or len(ins.operands) != 2:
            return None
        dst, src = ins.operands
        if dst.type != _OP_REG or src.type != _OP_IMM:
            return None
        if dst.reg not in self.n_methods_arg_regs:
            return None
        return src.imm

    def methods_address_load(self, ins: Any) -> int | None:
        # The third-argument table address is materialised by the ldr-literal /
        # add-pc pair handled in decode_pc_relative_lea; there is no single
        # instruction form to recognise here.
        return None


ARM_AAPCS32 = ArmAapcs32Abi(
    name="arm-aapcs32",
    description="32-bit ARM AAPCS (ELF EM_ARM). nMethods passed in r3.",
    pointer_size=4,
    cs_arch=CS_ARCH_ARM,
    cs_mode=CS_MODE_ARM,
    n_methods_arg_regs=(arm_const.ARM_REG_R3,),
    methods_arg_regs=(arm_const.ARM_REG_R2,),
    # ARM forms PC-relative constant addresses with a literal-pool load plus an
    # add against PC, not a single instruction against a PC register, so no
    # capstone PC register applies for the base decoder's use.
    pc_register=0,
    binary_matches=[("ELF", 0x28)],  # EM_ARM
)

register_abi(ARM_AAPCS32)
