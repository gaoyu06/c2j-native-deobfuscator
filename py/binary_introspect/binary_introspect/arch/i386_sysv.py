"""32-bit x86 System V ABI (ELF ``EM_386``, cdecl).

The i386 SysV C calling convention passes **every** argument on the stack, not
in registers. ``RegisterNatives(JNIEnv*, jclass, JNINativeMethod*, jint)`` is
therefore emitted as four ``push`` instructions in right-to-left order followed
by an indirect call through the ``JNIEnv`` vtable slot::

    push   $0x2              ; jint nMethods            (pushed first)
    push   %edx              ; JNINativeMethod *methods
    push   <clazz>           ; jclass
    push   %eax              ; JNIEnv *env
    call   *0x35c(%ecx)      ; (*env)->RegisterNatives  (215 * 4 = 0x35c)

Two i386-specific decoding rules follow from this:

* ``nMethods`` is a ``push $imm``, never a ``mov reg, imm``. The base ABI reads
  the count from a register move, so :meth:`is_n_methods_load` is overridden to
  read a pushed immediate (bounded to a plausible table size so a pushed
  address is not mistaken for a count).

* The address of an in-image constant such as a static ``JNINativeMethod[]`` is
  not a single RIP-relative ``lea`` (x86-64 has no equivalent on i386). Position-
  independent i386 code first materialises the Global Offset Table base into a
  register with a PC thunk, then reaches the table with a GOT-relative ``lea``::

      call   __x86.get_pc_thunk / call .Lnext ; pop %ebx
      add    $off, %ebx                        ; %ebx = _GLOBAL_OFFSET_TABLE_
      lea    -0x88(%ebx), %edx                 ; %edx = &JNINativeMethod[]

  :meth:`decode_pc_relative_lea` tracks the GOT-base register across the thunk
  (both the clang ``call/pop/add`` inline form and the gcc
  ``call __x86.get_pc_thunk.reg`` / ``add`` form) and folds the GOT-relative
  ``lea`` back into the absolute table VA. The base ``_harvest_call`` then adds
  that VA to its table candidates exactly as it does for an x86-64 RIP-relative
  ``lea``, so the static table decodes with names/descriptors with no other
  change to the architecture-agnostic discovery core.
"""

from __future__ import annotations

from typing import Any

from capstone import CS_ARCH_X86, CS_MODE_32, x86_const

from .base import Abi, register_abi


_MASK32 = 0xFFFFFFFF


class I386SysvAbi(Abi):
    """i386 cdecl ABI with x86-32-specific instruction decoding.

    Only the two forms that differ from x86-64 are overridden — the GOT-base
    ``lea`` fold and the pushed ``nMethods`` immediate. The indirect vtable call
    detection, register-to-register moves and stack-store recognition inherited
    from :class:`Abi` already operate on capstone x86 operands and work
    unchanged in 32-bit mode.
    """

    def _pc_state(self) -> dict[str, Any]:
        state = getattr(self, "_i386_pc", None)
        if state is None:
            state = {"regs": {}, "next": None}
            self._i386_pc = state
        return state

    def begin_scan(self, read_word=None) -> None:  # noqa: D401
        super().begin_scan(read_word)
        # A fresh scan must not inherit a GOT-base register from a previous
        # binary; clear the per-scan tracking state.
        self._i386_pc = {"regs": {}, "next": None}
        self._i386_pending = None

    def is_n_methods_load(self, ins: Any) -> int | None:
        """cdecl passes ``nMethods`` as ``push $imm``.

        The immediate is bounded to a plausible ``JNINativeMethod[]`` length so
        a pushed pointer (a large immediate) is never mistaken for a count; a
        wrong small value is in any case rejected by the static-table decoder,
        which validates every recovered name/descriptor.
        """
        if ins.mnemonic == "push" and len(ins.operands) == 1:
            operand = ins.operands[0]
            if operand.type == x86_const.X86_OP_IMM and 0 < operand.imm <= 4096:
                return operand.imm
        return None

    def decode_pc_relative_lea(self, ins: Any) -> int | None:
        """Fold an i386 GOT-relative ``lea`` into an absolute VA.

        A small state machine, reset whenever the disassembly stream is
        discontinuous, tracks which register currently holds the GOT base:

        * ``call`` records the return address (the next instruction VA) as a
          one-instruction "pending PC".
        * ``pop reg`` right after such a call assigns the pending PC to ``reg``
          (clang's inline ``call .Lnext ; pop %ebx``).
        * ``add $imm, reg`` completes the GOT base: it either advances a
          register already carrying a PC value or, for gcc's out-of-line
          ``call __x86.get_pc_thunk.reg`` (which leaves the PC in ``reg``
          directly), consumes the pending PC.
        * ``mov dst, src`` propagates a GOT base copied between registers.

        ``lea disp(%reg), %dst`` where ``%reg`` holds the GOT base then yields
        ``got_base + disp`` — the absolute address of the in-image constant.
        A ``lea`` off any other register returns ``None`` (no fabricated VA).
        """
        state = self._pc_state()
        if state["next"] is None or ins.address != state["next"]:
            state["regs"].clear()
            self._i386_pending = None
        state["next"] = ins.address + ins.size

        pending = getattr(self, "_i386_pending", None)
        self._i386_pending = None  # a pending PC survives exactly one instruction

        mnemonic = ins.mnemonic
        regs: dict[int, int] = state["regs"]

        if mnemonic == "call":
            self._i386_pending = (ins.address + ins.size) & _MASK32
            return None

        if (
            mnemonic == "pop"
            and pending is not None
            and len(ins.operands) == 1
            and ins.operands[0].type == x86_const.X86_OP_REG
        ):
            regs[ins.operands[0].reg] = pending
            return None

        if mnemonic == "add" and len(ins.operands) == 2:
            dst, src = ins.operands
            if dst.type == x86_const.X86_OP_REG and src.type == x86_const.X86_OP_IMM:
                if dst.reg in regs:
                    regs[dst.reg] = (regs[dst.reg] + src.imm) & _MASK32
                elif pending is not None:
                    regs[dst.reg] = (pending + src.imm) & _MASK32
            return None

        if mnemonic == "lea" and len(ins.operands) == 2:
            dst, src = ins.operands
            if (
                dst.type == x86_const.X86_OP_REG
                and src.type == x86_const.X86_OP_MEM
                and src.mem.index == 0
                and src.mem.base in regs
            ):
                return (regs[src.mem.base] + src.mem.disp) & _MASK32
            return None

        if mnemonic == "mov" and len(ins.operands) == 2:
            dst, src = ins.operands
            if (
                dst.type == x86_const.X86_OP_REG
                and src.type == x86_const.X86_OP_REG
                and src.reg in regs
            ):
                regs[dst.reg] = regs[src.reg]
            return None

        return None


I386_SYSV = I386SysvAbi(
    name="i386-sysv",
    description="32-bit x86 System V ABI (ELF EM_386, cdecl). Args on the stack.",
    pointer_size=4,
    cs_arch=CS_ARCH_X86,
    cs_mode=CS_MODE_32,
    # cdecl passes nMethods on the stack, so there is no nMethods argument
    # register; the pushed immediate is recognised by is_n_methods_load instead.
    n_methods_arg_regs=(),
    # The table address is materialised into a scratch register by a GOT-relative
    # lea and then pushed; decode_pc_relative_lea surfaces it as a table
    # candidate, so no dedicated methods-argument register is needed.
    methods_arg_regs=(),
    # i386 has no PC register operand; PC-relative addresses are formed through
    # the GOT-base thunk handled in decode_pc_relative_lea.
    pc_register=0,
    binary_matches=[("ELF", 0x03)],  # EM_386
)

register_abi(I386_SYSV)
