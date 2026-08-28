from __future__ import annotations

import struct
from types import SimpleNamespace

import lief
import pytest

from binary_introspect.arch.amd64_sysv import AMD64_SYSV
from binary_introspect.arch.amd64_windows import AMD64_WINDOWS
from binary_introspect.jni_tables import (
    _find_register_natives_calls,
    _harvest_call,
)
from binary_introspect.profile import detect_profile, get_profile


def _lea(insn: bytes, address: int, target: int) -> bytes:
    return insn + struct.pack("<i", target - (address + len(insn) + 4))


@pytest.mark.parametrize(
    ("abi", "table_lea", "n_methods"),
    [
        (AMD64_WINDOWS, b"\x4c\x8d\x05", b"\x41\xb9\x02\x00\x00\x00"),
        (AMD64_SYSV, b"\x48\x8d\x15", b"\xb9\x02\x00\x00\x00"),
    ],
)
def test_generic_decodes_static_jni_table_for_both_abis(
    abi, table_lea: bytes, n_methods: bytes
) -> None:
    code_va = 0x1000
    table_va = 0x3000
    code = _lea(table_lea, code_va, table_va)
    code += n_methods
    call_va = code_va + len(code)
    code += b"\xff\x90\xb8\x06\x00\x00"  # call [rax + 215 * 8]
    code += b"\x90" * (0x300 - len(code))

    data = bytearray(0x300)
    name1, desc1 = table_va + 0x100, table_va + 0x110
    name2, desc2 = table_va + 0x120, table_va + 0x130
    struct.pack_into("<QQQ", data, 0, name1, desc1, 0x1100)
    struct.pack_into("<QQQ", data, 24, name2, desc2, 0x1120)
    data[0x100:0x106] = b"alpha\0"
    data[0x110:0x114] = b"()V\0"
    data[0x120:0x125] = b"beta\0"
    data[0x130:0x135] = b"(I)I\0"

    exec_ranges = [(code_va, code_va + len(code), bytes(code))]
    mapped_ranges = exec_ranges + [(table_va, table_va + len(data), bytes(data))]
    cs = abi.disassembler()

    sites = _find_register_natives_calls(cs, abi, exec_ranges, 215)
    assert sites == [call_va]

    result = _harvest_call(
        cs, abi, call_va, exec_ranges, mapped_ranges, image_base=0
    )
    assert result["nMethods"] == 2
    assert result["tableAddress"] == table_va
    assert result["methods"] == [
        {"name": "alpha", "desc": "()V", "fnAddr": 0x1100},
        {"name": "beta", "desc": "(I)I", "fnAddr": 0x1120},
    ]


def test_indirect_call_detection_uses_operands_not_rendered_text() -> None:
    cs = AMD64_WINDOWS.disassembler()
    insn = next(cs.disasm(b"\xff\x90\xb8\x06\x00\x00", 0x1000))
    proxy = SimpleNamespace(
        mnemonic=insn.mnemonic,
        operands=insn.operands,
        op_str="presentation text is irrelevant",
    )
    assert AMD64_WINDOWS.is_indirect_vtable_call(proxy) == 215 * 8


def test_profile_selection_falls_back_to_conservative_generic() -> None:
    binary = SimpleNamespace(format=object(), sections=[])
    profile = detect_profile(binary)

    assert profile.name == "generic"
    assert profile.harvest_strategy == "auto"
    assert profile.invoke_error_re is None
    assert profile.skip_if_patterns == []
    assert profile.rewrite_ghidra_vtable_calls is False
    assert profile.enable_exception_guard_heuristics is False


def test_specific_profile_wins_when_its_detector_matches() -> None:
    entries = [
        SimpleNamespace(name="Java_sample_bootstrap"),
        SimpleNamespace(name="Java_sample_initClass"),
    ]
    binary = SimpleNamespace(
        format=lief.Binary.FORMATS.PE,
        has_exports=True,
        get_export=lambda: SimpleNamespace(entries=entries),
        sections=[SimpleNamespace(content=list(b"Cannot invoke sample"))],
    )

    assert detect_profile(binary) is get_profile("j2cc")
