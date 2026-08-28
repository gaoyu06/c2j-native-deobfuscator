"""Abstract base for arch / ABI implementations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import lief


@dataclass
class Abi:
    """Describes one arch + OS calling convention.

    Each concrete implementation is registered with :func:`register_abi`
    and selected either by name (``--abi <name>``) or by auto-detection
    against the binary's format + machine type.
    """

    name: str
    description: str
    pointer_size: int

    #: Capstone arch constant (e.g. ``CS_ARCH_X86``).
    cs_arch: int

    #: Capstone mode constant (e.g. ``CS_MODE_64``).
    cs_mode: int

    #: capstone register ids whose value the calling convention places
    #: as the 4th argument to an indirect ``RegisterNatives`` call —
    #: that argument is ``jint nMethods``.
    #: Tuple to accept both 32- and 64-bit aliases (e.g. ``r9`` / ``r9d``).
    n_methods_arg_regs: tuple[int, ...]

    #: Register(s) used for the third argument, ``JNINativeMethod *methods``.
    #: Pointer arguments only use the architecture's full-width register.
    methods_arg_regs: tuple[int, ...]

    #: capstone register id used by the calling convention for the
    #: PC-relative argument addressing (``RIP`` on x86_64). Used by
    #: :meth:`decode_pc_relative_lea` to recognise "load address of
    #: constant" instructions.
    pc_register: int

    #: lief Format / machine-id pairs this Abi applies to, for auto-detect.
    #: Example: ``[("PE", 0x8664), ("ELF", 0x3E)]``.
    binary_matches: list[tuple[str, int]]

    # ----------------------------------------------------------------
    # Methods (overridable but with sensible defaults).
    # ----------------------------------------------------------------

    def disassembler(self):
        """Construct a configured capstone Cs object. Lazy import so
        capstone is only required for arches that actually use it."""
        from capstone import Cs, CsError
        try:
            cs = Cs(self.cs_arch, self.cs_mode)
            cs.detail = True
            return cs
        except CsError:
            return None

    def is_indirect_vtable_call(self, ins: Any) -> int | None:
        """Return the displacement of an indirect memory call.

        This deliberately inspects Capstone operands rather than rendered
        instruction text. Intel/AT&T syntax selection and register naming are
        presentation details; the memory operand and its displacement are the
        structural facts relevant to a JNI vtable slot.
        """
        from capstone import x86_const

        if ins.mnemonic not in ("call", "jmp"):
            return None
        if len(ins.operands) != 1:
            return None
        operand = ins.operands[0]
        if operand.type != x86_const.X86_OP_MEM or operand.mem.base == 0:
            return None
        return operand.mem.disp

    def vtable_slot_load(self, ins: Any) -> tuple[int, int] | None:
        """Return ``(destination_register, displacement)`` for a vtable load.

        Optimizing compilers may split ``call [table + slot]`` into
        ``mov tmp, [table + slot]`` followed by ``call tmp`` or tail ``jmp
        tmp``. PC-relative loads are excluded because they address globals,
        not a function slot through ``JNIEnv``.
        """
        from capstone import x86_const

        if ins.mnemonic != "mov" or len(ins.operands) != 2:
            return None
        dst, src = ins.operands
        if (
            dst.type != x86_const.X86_OP_REG
            or src.type != x86_const.X86_OP_MEM
            or src.mem.base in (0, self.pc_register)
        ):
            return None
        return dst.reg, src.mem.disp

    def indirect_branch_register(self, ins: Any) -> int | None:
        """Return the register used by an indirect call or tail jump."""
        from capstone import x86_const

        if ins.mnemonic not in ("call", "jmp") or len(ins.operands) != 1:
            return None
        operand = ins.operands[0]
        return operand.reg if operand.type == x86_const.X86_OP_REG else None

    def decode_pc_relative_lea(self, ins: Any) -> int | None:
        """If ``ins`` is a "load effective address of a constant"
        (e.g. ``lea reg, [rip + disp32]`` on x86_64), return the
        absolute VA of the constant. Otherwise return ``None``.

        Default implementation matches x86 ``lea`` with RIP-base.
        Override for non-x86 arches (e.g. AArch64 ``adrp``+``add``).
        """
        # Lazy import — same reason as :meth:`disassembler`.
        from capstone import x86_const
        if ins.mnemonic != "lea" or len(ins.operands) != 2:
            return None
        src = ins.operands[1]
        if src.type != x86_const.X86_OP_MEM:
            return None
        if src.mem.base == self.pc_register:
            return ins.address + ins.size + src.mem.disp
        return None

    def is_stack_store(self, ins: Any) -> tuple[int, int] | None:
        """If ``ins`` writes a register to a stack slot
        (e.g. ``mov [rbp+disp], reg``), return ``(stack_disp, src_reg)``.
        Otherwise return ``None``.

        Default implementation: x86 ``mov`` with memory destination based
        on a stack-pointer register.
        """
        from capstone import x86_const
        if ins.mnemonic != "mov" or len(ins.operands) != 2:
            return None
        dst, src = ins.operands[0], ins.operands[1]
        if dst.type != x86_const.X86_OP_MEM:
            return None
        if src.type != x86_const.X86_OP_REG:
            return None
        if dst.mem.base not in (x86_const.X86_REG_RSP, x86_const.X86_REG_RBP,
                                x86_const.X86_REG_ESP, x86_const.X86_REG_EBP):
            return None
        return dst.mem.disp, src.reg

    def is_n_methods_load(self, ins: Any) -> int | None:
        """If ``ins`` is loading an immediate into the
        :attr:`n_methods_arg_regs` register, return that immediate.
        Otherwise return ``None``.
        """
        from capstone import x86_const
        if ins.mnemonic != "mov" or len(ins.operands) != 2:
            return None
        dst, src = ins.operands[0], ins.operands[1]
        if dst.type != x86_const.X86_OP_REG:
            return None
        if src.type != x86_const.X86_OP_IMM:
            return None
        if dst.reg not in self.n_methods_arg_regs:
            return None
        return src.imm

    def methods_address_load(self, ins: Any) -> int | None:
        """Return a statically known method-table address loaded into arg 3.

        On x86-64 this recognises ``lea <methods-arg>, [rip + disp]``. Stack
        tables use ``rsp``/``rbp`` addressing and are handled by the stack
        store harvester instead.
        """
        from capstone import x86_const

        if ins.mnemonic != "lea" or len(ins.operands) != 2:
            return None
        dst, src = ins.operands
        if dst.type != x86_const.X86_OP_REG or dst.reg not in self.methods_arg_regs:
            return None
        if src.type != x86_const.X86_OP_MEM or src.mem.base != self.pc_register:
            return None
        return ins.address + ins.size + src.mem.disp

    def applies_to(self, binary: lief.Binary) -> bool:
        """Default: match by (binary format, machine id) against the
        :attr:`binary_matches` list."""
        if not self.binary_matches:
            return False
        fmt_str = self._fmt_str(binary)
        machine = self._machine_id(binary)
        for f, m in self.binary_matches:
            if fmt_str == f and machine == m:
                return True
        return False

    @staticmethod
    def _fmt_str(b: lief.Binary) -> str:
        if b.format == lief.Binary.FORMATS.PE: return "PE"
        if b.format == lief.Binary.FORMATS.ELF: return "ELF"
        if b.format == lief.Binary.FORMATS.MACHO: return "MachO"
        return "?"

    @staticmethod
    def _machine_id(b: lief.Binary) -> int:
        try:
            if b.format == lief.Binary.FORMATS.PE:
                return int(b.header.machine)
            if b.format == lief.Binary.FORMATS.ELF:
                return int(b.header.machine_type)
            if b.format == lief.Binary.FORMATS.MACHO:
                return int(b.header.cpu_type)
        except Exception:
            pass
        return 0


# --------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------

_registry: dict[str, Abi] = {}


def register_abi(abi: Abi) -> None:
    """Add an :class:`Abi` to the global registry."""
    if abi.name in _registry:
        raise ValueError(f"duplicate ABI name: {abi.name!r}")
    _registry[abi.name] = abi


def list_abis() -> list[str]:
    return sorted(_registry.keys())


def get_abi(name: str) -> Abi:
    if name not in _registry:
        raise KeyError(f"unknown ABI {name!r}; known: {', '.join(list_abis())}")
    return _registry[name]


def detect_abi(binary: lief.Binary) -> Abi | None:
    """Return the first registered ABI whose ``applies_to`` accepts the
    binary, or ``None`` when nothing matches. Caller decides whether to
    error out or fall back."""
    for abi in _registry.values():
        if abi.applies_to(binary):
            return abi
    return None
