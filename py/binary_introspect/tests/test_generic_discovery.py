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


def _static_tables(report) -> list[dict]:
    return [
        entry
        for entry in report.native_registry
        if entry.get("source") == "register-natives-static"
    ]


def _jni_exports(report) -> list[dict]:
    return [
        entry
        for entry in report.native_registry
        if entry.get("source") == "jni-export"
    ]


def _export_addr(report, name: str) -> str | None:
    """Address of an exported symbol, tolerating a Mach-O leading underscore."""
    for export in report.exported_functions:
        if export["name"] in (name, f"_{name}"):
            return export["addr"]
    return None


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


def test_introspect_real_pe_resolves_static_table_and_jni_export() -> None:
    """PE / Microsoft x64 ABI proven end-to-end on a committed DLL: the
    RegisterNatives static table decodes with names/descriptors, and a
    specification-defined Java_* export is recorded."""
    report = introspect(FIXTURES / "jni_registrar.dll")

    assert report.fmt == "PE"
    assert report.arch == "x86_64"
    assert report.analysis == {"profile": "generic", "methodDiscovery": "jni-spec"}

    tables = _static_tables(report)
    assert len(tables) == 1
    table = tables[0]
    assert table["abi"] == "amd64-windows"
    assert table["nMethods"] == 2
    assert [(m["name"], m["desc"]) for m in table["methods"]] == [
        ("alpha", "()V"),
        ("beta", "(I)I"),
    ]
    # The table's function pointers cross-check against the export addresses:
    # a broken PE pointer/section read would desync these.
    assert table["methods"][0]["fnAddr"] == _export_addr(report, "fixture_alpha")
    assert table["methods"][1]["fnAddr"] == _export_addr(report, "fixture_beta")

    exports = _jni_exports(report)
    assert [e["fnSymbol"] for e in exports] == ["Java_com_example_Sample_ping"]
    assert exports[0]["fnAddr"] == _export_addr(
        report, "Java_com_example_Sample_ping"
    )


def test_introspect_real_macho_resolves_static_table_and_jni_export() -> None:
    """Mach-O / System V ABI proven end-to-end on a committed dylib. The
    Java_* export is stored as _Java_... in the Mach-O symbol table and is
    normalized back to the spec name; the static table decodes with names."""
    report = introspect(FIXTURES / "libjni_registrar.dylib")

    assert report.fmt == "MachO"
    assert report.arch == "x86_64"
    assert report.analysis == {"profile": "generic", "methodDiscovery": "jni-spec"}

    tables = _static_tables(report)
    assert len(tables) == 1
    table = tables[0]
    assert table["abi"] == "amd64-sysv"
    assert table["nMethods"] == 2
    assert [(m["name"], m["desc"]) for m in table["methods"]] == [
        ("alpha", "()V"),
        ("beta", "(I)I"),
    ]
    assert table["methods"][0]["fnAddr"] == _export_addr(report, "fixture_alpha")
    assert table["methods"][1]["fnAddr"] == _export_addr(report, "fixture_beta")

    exports = _jni_exports(report)
    assert [e["fnSymbol"] for e in exports] == ["Java_com_example_Sample_ping"]


def _capstone_disassembles_aarch64() -> bool:
    """True when the host capstone can actually decode AArch64. The ABI can
    still parse exports via LIEF without this, so table assertions are guarded
    on it while the export assertion is not."""
    try:
        from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
    except ImportError:
        return False
    try:
        cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    except Exception:
        return False
    # ldr x4, [x4, #1720]  (little-endian bytes) — a smoke check that this
    # capstone build carries the AArch64 backend.
    return any(cs.disasm(bytes.fromhex("845c43f9"), 0))


def test_introspect_real_aarch64_elf_recovers_static_table_and_export() -> None:
    """AArch64 / AAPCS64 proven end-to-end on a committed ELF .so.

    A non-x86-64 image: ``RegisterNatives`` reaches its slot through the
    ``x16`` veneer register (``ldr``/``mov x16``/``br x16``) and the method
    table address is formed with ``adrp``/``add``. When capstone can decode
    AArch64 the static table is recovered with names/descriptors whose
    function pointers cross-check the export addresses; when it cannot, the
    ``Java_*`` export is still parsed via LIEF and no methods are fabricated.
    """
    path = FIXTURES / "libjni_registrar_aarch64.so"

    binary = lief.parse(str(path))
    assert binary.format == lief.Binary.FORMATS.ELF
    assert int(binary.header.machine_type) == 0xB7  # EM_AARCH64

    report = introspect(path)
    assert report.fmt == "ELF"
    assert report.arch == "aarch64"
    assert report.analysis == {"profile": "generic", "methodDiscovery": "jni-spec"}

    # The specification-defined Java_* export is recovered on every host,
    # capstone or not — it comes from the LIEF symbol table, not disassembly.
    exports = _jni_exports(report)
    assert [e["fnSymbol"] for e in exports] == ["Java_com_example_Sample_ping"]
    assert exports[0]["fnAddr"] == _export_addr(
        report, "Java_com_example_Sample_ping"
    )

    tables = _static_tables(report)
    if not _capstone_disassembles_aarch64():
        # Honest fallback: no AArch64 disassembler means no table is claimed,
        # and crucially no fabricated methods.
        assert tables == []
        return

    assert len(tables) == 1, "AArch64 table must not silently yield nothing"
    table = tables[0]
    assert table["abi"] == "aarch64-aapcs64"
    assert table["nMethods"] == 2
    assert [(m["name"], m["desc"]) for m in table["methods"]] == [
        ("alpha", "()V"),
        ("beta", "(I)I"),
    ]
    # Function pointers resolve through R_AARCH64_ABS64 relocations on the
    # zeroed fnPtr slots and cross-check against the exported addresses; a
    # broken adrp/add fold or relocation read would desync these.
    assert table["methods"][0]["fnAddr"] == _export_addr(report, "fixture_alpha")
    assert table["methods"][1]["fnAddr"] == _export_addr(report, "fixture_beta")


def test_aarch64_split_call_is_found_through_veneer_register() -> None:
    """The RegisterNatives dispatch on AArch64 loads the vtable slot into a
    general register, copies it into the ``x16`` veneer, and tail-``br``s
    through it. The split-call scanner must follow the ``mov x16, x4`` to
    still recognise the site — a regression here silently loses every
    AArch64 table."""
    from binary_introspect.arch.aarch64 import AARCH64_AAPCS64

    cs = AARCH64_AAPCS64.disassembler()
    if cs is None or not _capstone_disassembles_aarch64():
        pytest.skip("host capstone cannot decode AArch64")

    code = bytes.fromhex(
        "845c43f9"  # 0x00: ldr x4, [x4, #1720]   (215 * 8)
        "f00304aa"  # 0x04: mov x16, x4
        "00021fd6"  # 0x08: br  x16
    )
    ranges = [(0x1000, 0x1000 + len(code), code)]
    sites = _find_register_natives_calls(cs, AARCH64_AAPCS64, ranges, 215)
    assert sites == [0x1008]


def test_introspect_stripped_elf_still_recovers_table_via_generic_path() -> None:
    """A symbol-stripped copy of the registrar still yields the registration
    table via the generic path (relocations + section data, not .symtab).
    Silent empty success is not allowed: the table must still be found."""
    path = FIXTURES / "libjni_registrar.stripped.so"

    # Confirm the fixture really is stripped so the test proves resilience,
    # not that .symtab happened to survive.
    binary = lief.parse(str(path))
    assert list(binary.symtab_symbols) == []
    assert not any(section.name == ".symtab" for section in binary.sections)

    report = introspect(path)
    assert report.fmt == "ELF"
    assert report.arch == "x86_64"

    tables = _static_tables(report)
    assert len(tables) == 1, "stripped binary must not silently yield nothing"
    table = tables[0]
    assert table["abi"] == "amd64-sysv"
    assert [(m["name"], m["desc"], m["fnAddr"]) for m in table["methods"]] == [
        ("alpha", "()V", "0x1000"),
        ("beta", "(I)I", "0x1010"),
    ]


def test_introspect_exports_only_elf_uses_export_family_not_table() -> None:
    """Second registration family: a library that registers purely by Java_*
    export names (no JNINativeMethod table, no RegisterNatives call site). The
    generic path must recover it through exports, proving it is not locked to
    the table shape."""
    report = introspect(FIXTURES / "libjni_exports_only.so")

    assert report.fmt == "ELF"
    assert report.arch == "x86_64"

    assert _static_tables(report) == []

    exported = {e["fnSymbol"] for e in _jni_exports(report)}
    assert exported == {
        "Java_com_example_Widget_init",
        "Java_com_example_Widget_compute",
        "Java_com_example_Widget_hashOf__Ljava_lang_String_2",
    }


def _assert_section_header_removed(path: Path):
    """Parse a section-header-removed ELF and return the report, or drive the
    honest-failure contract when this LIEF cannot map it.

    Returns ``(report, binary)`` when LIEF parses the PT_LOAD-only image (with
    ``binary.sections`` confirmed empty), or ``None`` after asserting that
    ``introspect`` raises rather than silently returning an empty result.
    """
    binary = lief.parse(str(path))
    if binary is None:
        # Honest failure: no section headers AND this LIEF build cannot fall
        # back to the program headers, so introspection must raise, never
        # return a silent empty success.
        with pytest.raises((IOError, OSError)):
            introspect(path)
        return None
    # The image genuinely has no section header table — the fallback is
    # exercising the program headers, not surviving sections.
    assert list(binary.sections) == []
    return introspect(path), binary


def test_section_header_removed_registrar_recovers_table_via_ptload() -> None:
    """A registrar ELF with its section header table removed (``sstrip``-style,
    only ``PT_LOAD`` segments remain) still yields the RegisterNatives static
    table through the PT_LOAD fallback: executable ranges come from ``PF_X``
    segments and the zeroed fnPtr slots are filled from dynamic relocations.
    Silent empty success is not allowed."""
    result = _assert_section_header_removed(FIXTURES / "libjni_registrar.noshdr.so")
    if result is None:
        return
    report, _binary = result
    assert report.fmt == "ELF"
    assert report.arch == "x86_64"

    tables = _static_tables(report)
    assert len(tables) == 1, "PT_LOAD fallback must not silently yield nothing"
    table = tables[0]
    assert table["abi"] == "amd64-sysv"
    assert [(m["name"], m["desc"], m["fnAddr"]) for m in table["methods"]] == [
        ("alpha", "()V", "0x1000"),
        ("beta", "(I)I", "0x1010"),
    ]


def test_section_header_removed_exports_only_recovers_java_exports_via_ptload() -> None:
    """The explicit requirement: a section-header-removed, PT_LOAD-only ELF
    whose methods register purely by ``Java_*`` name still surfaces those
    dynamic exports (read from ``PT_DYNAMIC``), so the fallback finds the
    export family with no sections at all."""
    result = _assert_section_header_removed(
        FIXTURES / "libjni_exports_only.noshdr.so"
    )
    if result is None:
        return
    report, _binary = result
    assert report.fmt == "ELF"
    assert report.arch == "x86_64"

    assert _static_tables(report) == []
    exported = {e["fnSymbol"] for e in _jni_exports(report)}
    assert exported == {
        "Java_com_example_Widget_init",
        "Java_com_example_Widget_compute",
        "Java_com_example_Widget_hashOf__Ljava_lang_String_2",
    }


def test_real_pe_table_binds_through_manifest_merge_without_silent_gap() -> None:
    """End-to-end: the PE-discovered named table binds to the matching class by
    (name, desc), and an ambiguous duplicate leaves the table unbound with a
    gap rather than silently mis-binding."""
    from manifest_merge.core import merge

    report = introspect(FIXTURES / "jni_registrar.dll")
    binary = report.to_json_obj()

    def _classes(class_names):
        return {
            "input": {"jarPath": "input.jar"},
            "classes": [
                {
                    "name": name,
                    "methods": [
                        {
                            "name": "alpha",
                            "desc": "()V",
                            "access": 0x0100,
                            "isObfuscatedNative": True,
                        },
                        {
                            "name": "beta",
                            "desc": "(I)I",
                            "access": 0x0100,
                            "isObfuscatedNative": True,
                        },
                    ],
                }
                for name in class_names
            ],
        }

    unique = merge(_classes(["com/example/Native"]), binary)
    bound = {
        m["name"]: m.get("fnAddr")
        for m in unique["classes"][0]["methods"]
    }
    assert bound["alpha"] and bound["beta"]
    assert unique["bindingGaps"] == []

    ambiguous = merge(
        _classes(["com/example/First", "com/example/Second"]), binary
    )
    assert all(
        "fnAddr" not in method
        for cls in ambiguous["classes"]
        for method in cls["methods"]
    )


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
