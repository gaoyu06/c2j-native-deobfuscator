from __future__ import annotations

import struct
from pathlib import Path
from types import SimpleNamespace

import lief
import pytest

from binary_introspect.arch.amd64_sysv import AMD64_SYSV
from binary_introspect.arch.amd64_windows import AMD64_WINDOWS
from binary_introspect.core import introspect
from binary_introspect.jni_tables import (
    _find_register_natives_calls,
    _harvest_call,
    _harvest_dispatch,
)
from binary_introspect.profile import detect_profile, get_profile


FIXTURES = Path(__file__).with_name("fixtures")


def _lea(insn: bytes, address: int, target: int) -> bytes:
    return insn + struct.pack("<i", target - (address + len(insn) + 4))


def test_introspect_real_elf_resolves_static_jni_table_relocations() -> None:
    report = introspect(FIXTURES / "libjni_registrar.so")

    assert report.fmt == "ELF"
    assert report.arch == "x86_64"
    assert report.analysis == {
        "profile": "generic",
        "methodDiscovery": "jni-spec",
    }

    tables = [
        entry
        for entry in report.native_registry
        if entry.get("source") == "register-natives-static"
    ]
    assert tables == [
        {
            "source": "register-natives-static",
            "registerNativesCallSite": "0x103a",
            "nMethods": 2,
            "fnAddrs": ["0x1000", "0x1010"],
            "profile": "generic",
            "abi": "amd64-sysv",
            "tableAddress": "0x3ee0",
            "methods": [
                {"name": "alpha", "desc": "()V", "fnAddr": "0x1000"},
                {"name": "beta", "desc": "(I)I", "fnAddr": "0x1010"},
            ],
        }
    ]


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


def test_harvest_rejects_static_table_with_invalid_entries() -> None:
    """A candidate table whose entries fail the JNI name/descriptor checks
    must not be emitted as a (wrong) static method table — generic stays
    conservative and yields no methods rather than false ones."""
    code_va = 0x1000
    table_va = 0x3000
    code = _lea(b"\x48\x8d\x15", code_va, table_va)   # lea rdx, [rip+table]
    code += b"\xb9\x02\x00\x00\x00"                     # mov ecx, 2
    call_va = code_va + len(code)
    code += b"\xff\x90\xb8\x06\x00\x00"                 # call [rax + 215*8]
    code += b"\x90" * (0x300 - len(code))

    data = bytearray(0x300)
    struct.pack_into("<QQQ", data, 0, table_va + 0x100, table_va + 0x110, 0x1100)
    struct.pack_into("<QQQ", data, 24, table_va + 0x120, table_va + 0x130, 0x1120)
    data[0x100:0x106] = b"alpha\0"
    data[0x110:0x114] = b"()V\0"
    # Second entry has a bogus name and descriptor.
    data[0x120:0x130] = b"\xff\xfe not/valid"

    exec_ranges = [(code_va, code_va + len(code), bytes(code))]
    mapped_ranges = exec_ranges + [(table_va, table_va + len(data), bytes(data))]
    cs = AMD64_SYSV.disassembler()

    result = _harvest_call(
        cs, AMD64_SYSV, call_va, exec_ranges, mapped_ranges, image_base=0
    )
    assert result["methods"] == []
    # No stack stores either, so no ordered fnAddr fallback: the call site
    # produces nothing rather than a fabricated table.
    assert result["fnAddrs"] == []


def test_shared_dispatch_splits_branches_on_nmethods_boundaries() -> None:
    """One shared RegisterNatives call site fed by several per-class tables
    must be split into one branch per ``mov <nMethods>, imm`` boundary."""
    code_va = 0x2000
    buf = bytearray()

    def emit_lea_store(target: int, stack_disp: int) -> None:
        addr = code_va + len(buf)
        buf.extend(_lea(b"\x48\x8d\x05", addr, target))   # lea rax, [rip+tgt]
        buf.extend(bytes((0x48, 0x89, 0x44, 0x24, stack_disp)))  # mov [rsp+d], rax

    emit_lea_store(0x2100, 0x10)
    emit_lea_store(0x2110, 0x18)
    buf += b"\xb9\x02\x00\x00\x00"   # mov ecx, 2  -> branch boundary A
    emit_lea_store(0x2120, 0x10)
    emit_lea_store(0x2130, 0x18)
    buf += b"\xb9\x02\x00\x00\x00"   # mov ecx, 2  -> branch boundary B
    call_va = code_va + len(buf)
    buf += b"\xff\x90\xb8\x06\x00\x00"
    buf += b"\x90" * (0x400 - len(buf))

    exec_ranges = [(code_va, code_va + len(buf), bytes(buf))]
    branches = _harvest_dispatch(
        AMD64_SYSV.disassembler(), AMD64_SYSV, call_va, exec_ranges
    )
    assert [(b["nMethods"], b["fnAddrs"]) for b in branches] == [
        (2, [0x2100, 0x2110]),
        (2, [0x2120, 0x2130]),
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


def test_split_vtable_load_and_tail_jump_is_discovered() -> None:
    code = (
        b"\x48\x8b\x80\xb8\x06\x00\x00"  # mov rax, [rax + 215 * 8]
        b"\xff\xe0"                      # jmp rax
    )
    ranges = [(0x1000, 0x1000 + len(code), code)]
    sites = _find_register_natives_calls(
        AMD64_SYSV.disassembler(), AMD64_SYSV, ranges, 215
    )
    assert sites == [0x1007]


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
