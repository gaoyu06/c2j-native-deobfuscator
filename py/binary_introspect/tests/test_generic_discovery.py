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


def _stack_tables(report) -> list[dict]:
    return [
        entry
        for entry in report.native_registry
        if entry.get("source") == "register-natives-stack"
    ]


def _capstone_disassembles_x86_32() -> bool:
    """True when the host capstone can decode 32-bit x86. This is the base x86
    backend that every capstone build carries, so it is effectively always
    available; the guard mirrors the AArch64/ARM ones for honesty and keeps the
    i386 assertions from masking a genuinely broken capstone as a table loss."""
    try:
        from capstone import CS_ARCH_X86, CS_MODE_32, Cs
    except ImportError:
        return False
    try:
        cs = Cs(CS_ARCH_X86, CS_MODE_32)
    except Exception:
        return False
    # push 0x2 ; ret  — a smoke check that the 32-bit x86 decoder works.
    return any(cs.disasm(bytes.fromhex("6a02c3"), 0))


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


def test_introspect_real_macho_arm64_reports_format_arch_export_and_table() -> None:
    """Mach-O arm64 proven on a committed ``.dylib``.

    This is the arm64 sibling of the Mach-O x86-64 dylib and the ELF aarch64
    ``.so``: a genuine ``(MachO, aarch64)`` image, not a renamed ELF or
    x86-64 dylib. LIEF confirms the Mach-O magic and the ARM64 cpu type, so
    ``introspect`` reports ``format=MachO`` and ``arch=aarch64``.

    The specification-defined ``Java_*`` export is recovered on every host via
    the LIEF symbol table (Mach-O stores it as ``_Java_...``, normalized back
    to the spec name). When the host capstone can decode AArch64 the static
    ``RegisterNatives`` table is additionally recovered: clang materialises the
    table address with a single ``adr`` (rather than the ELF's ``adrp``/``add``
    pair), and the AAPCS64 backend folds it back so names/descriptors decode
    and their function pointers cross-check the export addresses. When capstone
    cannot decode AArch64, no table is claimed and no methods are fabricated.
    """
    path = FIXTURES / "libjni_registrar_arm64.dylib"

    binary = lief.parse(str(path))
    assert binary.format == lief.Binary.FORMATS.MACHO
    assert int(binary.header.cpu_type) == 0x0100000C  # CPU_TYPE_ARM64

    report = introspect(path)
    assert report.fmt == "MachO"
    assert report.arch == "aarch64"
    assert report.analysis == {"profile": "generic", "methodDiscovery": "jni-spec"}

    # The Java_* export is recovered regardless of capstone, from the symbol
    # table rather than disassembly.
    exports = _jni_exports(report)
    assert [e["fnSymbol"] for e in exports] == ["Java_com_example_Sample_ping"]
    assert exports[0]["fnAddr"] == _export_addr(
        report, "Java_com_example_Sample_ping"
    )

    tables = _static_tables(report)
    if not _capstone_disassembles_aarch64():
        # Honest fallback: no AArch64 disassembler means no table is claimed,
        # and crucially no fabricated methods. The export above still holds.
        assert tables == []
        return

    assert len(tables) == 1, "Mach-O arm64 table must not silently yield nothing"
    table = tables[0]
    assert table["abi"] == "aarch64-aapcs64"
    assert table["nMethods"] == 2
    assert [(m["name"], m["desc"]) for m in table["methods"]] == [
        ("alpha", "()V"),
        ("beta", "(I)I"),
    ]
    assert table["methods"][0]["fnAddr"] == _export_addr(report, "fixture_alpha")
    assert table["methods"][1]["fnAddr"] == _export_addr(report, "fixture_beta")


def test_aarch64_adr_single_instruction_table_address_is_folded() -> None:
    """clang reaches a nearby ``JNINativeMethod[]`` with a single
    ``adr x2, #label`` instead of the ``adrp``/``add`` pair. The AArch64
    backend must fold that compact form back to the absolute table VA — a
    regression here silently loses every ``adr``-addressed table (the shape a
    small Mach-O arm64 image emits)."""
    from binary_introspect.arch.aarch64 import AARCH64_AAPCS64

    cs = AARCH64_AAPCS64.disassembler()
    if cs is None or not _capstone_disassembles_aarch64():
        pytest.skip("host capstone cannot decode AArch64")

    # adr x2, #0x4000  encoded for a PC of 0x398 (the form clang emits for the
    # committed libjni_registrar_arm64.dylib).
    (insn,) = cs.disasm(bytes.fromhex("42e30110"), 0x398)
    assert insn.mnemonic == "adr"
    assert AARCH64_AAPCS64.decode_pc_relative_lea(insn) == 0x4000


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


def _capstone_disassembles_arm() -> bool:
    """True when the host capstone can actually decode 32-bit ARM. As with
    AArch64, exports still parse via LIEF without this, so the ARM table
    assertions are guarded on it while the export assertion is not."""
    try:
        from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs
    except ImportError:
        return False
    try:
        cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    except Exception:
        return False
    # ldr lr, [ip, #860]  (little-endian bytes) — a smoke check that this
    # capstone build carries the 32-bit ARM backend.
    return any(cs.disasm(bytes.fromhex("5ce39ce5"), 0))


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


def test_introspect_real_arm_elf_reports_format_arch_export_and_table() -> None:
    """32-bit ARM / AAPCS proven on a committed ELF ``.so``.

    This is the 32-bit sibling of the AArch64 ``.so``: a genuine
    ``(ELF, EM_ARM)`` image built with ``arm-linux-gnueabi-gcc``, not a renamed
    aarch64 or x86 binary. LIEF confirms the ELF magic and the ``EM_ARM``
    machine type, so ``introspect`` reports ``format=ELF`` and this project's
    existing ARM arch string, ``arm``.

    The specification-defined ``Java_*`` export is recovered on every host via
    the LIEF symbol table. When the host capstone can decode 32-bit ARM the
    static ``RegisterNatives`` table is additionally recovered: the dispatch
    reaches its slot through the ``ip`` veneer register (``ldr lr, [ip, #860]``
    / ``mov ip, lr`` / ``bx ip``) and the position-independent table address is
    formed with a literal-pool load plus ``add r2, pc, r2``, which the AAPCS32
    backend folds back so names/descriptors decode and their function pointers
    cross-check the export addresses. When capstone cannot decode ARM, no table
    is claimed and no methods are fabricated.
    """
    path = FIXTURES / "libjni_registrar_arm.so"

    binary = lief.parse(str(path))
    assert binary.format == lief.Binary.FORMATS.ELF
    assert int(binary.header.machine_type) == 0x28  # EM_ARM

    report = introspect(path)
    assert report.fmt == "ELF"
    assert report.arch == "arm"
    assert report.analysis == {"profile": "generic", "methodDiscovery": "jni-spec"}

    # The specification-defined Java_* export is recovered on every host,
    # capstone or not — it comes from the LIEF symbol table, not disassembly.
    exports = _jni_exports(report)
    assert [e["fnSymbol"] for e in exports] == ["Java_com_example_Sample_ping"]
    assert exports[0]["fnAddr"] == _export_addr(
        report, "Java_com_example_Sample_ping"
    )

    tables = _static_tables(report)
    if not _capstone_disassembles_arm():
        # Honest fallback: no 32-bit ARM disassembler means no table is
        # claimed, and crucially no fabricated methods. The export above holds.
        assert tables == []
        return

    assert len(tables) == 1, "ARM table must not silently yield nothing"
    table = tables[0]
    assert table["abi"] == "arm-aapcs32"
    assert table["nMethods"] == 2
    assert [(m["name"], m["desc"]) for m in table["methods"]] == [
        ("alpha", "()V"),
        ("beta", "(I)I"),
    ]
    # Function pointers resolve through R_ARM_ABS32 relocations on the zeroed
    # fnPtr slots and cross-check against the exported addresses; a broken
    # literal-pool/add-pc fold or relocation read would desync these.
    assert table["methods"][0]["fnAddr"] == _export_addr(report, "fixture_alpha")
    assert table["methods"][1]["fnAddr"] == _export_addr(report, "fixture_beta")


def test_arm_pc_relative_literal_pool_table_address_is_folded() -> None:
    """Position-independent 32-bit ARM reaches its ``JNINativeMethod[]`` by
    loading a link-time-constant offset from the literal pool and adding the
    program counter (``ldr r2, [pc, #k]`` / ``add r2, pc, r2``). The AAPCS32
    backend must read the pooled word and fold the pair back to the absolute
    table VA — a regression here silently loses every ARM table (the shape
    ``-fPIC`` ARM emits)."""
    from binary_introspect.arch.arm_aapcs32 import ARM_AAPCS32

    cs = ARM_AAPCS32.disassembler()
    if cs is None or not _capstone_disassembles_arm():
        pytest.skip("host capstone cannot decode 32-bit ARM")

    # ldr r2, [pc, #0x14] ; add r2, pc, r2  — the exact encodings emitted for
    # the committed libjni_registrar_arm.so. The literal at pc+8+0x14 holds a
    # PC-relative offset; supply it through the begin_scan reader.
    buf = bytes.fromhex("14209fe5" "02208fe0")
    ARM_AAPCS32.begin_scan(lambda va, size=4: 0x3FF4 if va == 0x101C else None)

    folded = None
    for ins in cs.disasm(buf, 0x1000):
        result = ARM_AAPCS32.decode_pc_relative_lea(ins)
        if result is not None:
            folded = result
    # add is at 0x1004: (0x1004 + 8) + 0x3ff4 == 0x5000.
    assert folded == 0x5000


def test_arm_split_call_is_found_through_veneer_register() -> None:
    """The RegisterNatives dispatch on 32-bit ARM loads the vtable slot into a
    general register, copies it into the ``ip`` veneer, and tail-``bx``s
    through it. The split-call scanner must follow the ``mov ip, lr`` to still
    recognise the site — a regression here silently loses every ARM table."""
    from binary_introspect.arch.arm_aapcs32 import ARM_AAPCS32

    cs = ARM_AAPCS32.disassembler()
    if cs is None or not _capstone_disassembles_arm():
        pytest.skip("host capstone cannot decode 32-bit ARM")

    code = bytes.fromhex(
        "5ce39ce5"  # 0x00: ldr lr, [ip, #860]   (215 * 4)
        "0ec0a0e1"  # 0x04: mov ip, lr
        "1cff2fe1"  # 0x08: bx  ip
    )
    ranges = [(0x1000, 0x1000 + len(code), code)]
    sites = _find_register_natives_calls(cs, ARM_AAPCS32, ranges, 215)
    assert sites == [0x1008]


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


def test_introspect_shared_dispatch_elf_recovers_two_tables_from_one_call_site() -> None:
    """Second registration FAMILY (not just another architecture): a shared
    initClass()-style dispatcher that reuses ONE RegisterNatives call site for
    two classes, each with its own stack-built table and its own nMethods.

    The generic profile (``harvest_strategy="auto"``) must recover BOTH branches
    from the single call site — two independently sized nMethods groups (2 and
    3) — instead of collapsing them into a single silent bind. Proven on a
    committed x86-64 ELF whose branch layout puts both tables before the shared
    call. This exercises the ``auto`` → shared-dispatch harvest on a real
    binary, the gap the j2cc profile (Windows/PE only) previously left with no
    fixture.
    """
    report = introspect(FIXTURES / "libjni_dispatch_shared.so")

    assert report.fmt == "ELF"
    assert report.arch == "x86_64"
    # A genuinely generic recovery: no obfuscator-variant detector fires, so the
    # shared-dispatch split is driven by the spec-based auto harvest, not a
    # profile that hard-codes the shape.
    assert report.analysis == {"profile": "generic", "methodDiscovery": "jni-spec"}

    tables = _stack_tables(report)
    assert len(tables) == 2, (
        "shared dispatch must yield two tables, not one collapsed bind"
    )

    # Both branches were harvested from the SAME RegisterNatives call site.
    call_sites = {t["registerNativesCallSite"] for t in tables}
    assert len(call_sites) == 1

    # Stack-built tables expose ordered function pointers and a per-branch
    # nMethods but no decoded names — and crucially NO fabricated methods.
    assert all("methods" not in t for t in tables)
    assert all(t["abi"] == "amd64-sysv" for t in tables)

    by_count = {t["nMethods"]: t["fnAddrs"] for t in tables}
    assert set(by_count) == {2, 3}

    # Each recovered fnAddr cross-checks against its export address; a collapsed
    # or misordered harvest would desync these.
    assert by_count[2] == [
        _export_addr(report, "fixture_alpha"),
        _export_addr(report, "fixture_beta"),
    ]
    assert by_count[3] == [
        _export_addr(report, "fixture_gamma"),
        _export_addr(report, "fixture_delta"),
        _export_addr(report, "fixture_epsilon"),
    ]

    # The dispatcher's own Java_* exports (initClass/bootstrap) are recorded via
    # the export family; the per-method natives register through the tables.
    exported = {e["fnSymbol"] for e in _jni_exports(report)}
    assert exported == {
        "Java_com_example_Boot_initClass",
        "Java_com_example_Boot_bootstrap",
    }


def test_shared_dispatch_tables_bind_by_count_and_gap_when_ambiguous() -> None:
    """End-to-end merge of the shared-dispatch tables against a classes.json.

    When each branch's method count uniquely identifies a class, the two tables
    bind by count with no gaps. When counts are ambiguous (several classes share
    a branch's method count), the tables are left UNBOUND and a ``bindingGaps``
    entry is emitted for each — never a silent, arbitrary bind.
    """
    import copy

    from manifest_merge.core import merge

    report = introspect(FIXTURES / "libjni_dispatch_shared.so")
    # merge() mutates the native-registry site dicts (stamping ``boundTo``), so
    # give each merge call its own deep copy to keep the two scenarios isolated.
    binary = report.to_json_obj()

    def _classes(specs: list[tuple[str, int]]) -> dict:
        return {
            "input": {"jarPath": "input.jar"},
            "classes": [
                {
                    "name": name,
                    "methods": [
                        {
                            "name": f"m{index}",
                            "desc": "()V",
                            "access": 0x0100,
                            "isObfuscatedNative": True,
                        }
                        for index in range(count)
                    ],
                }
                for name, count in specs
            ],
        }

    # Unambiguous: exactly one 2-method class and one 3-method class. Each shared
    # branch binds to its unique count match, and no gap remains.
    unique = merge(
        _classes([("com/example/ClassA", 2), ("com/example/ClassB", 3)]),
        copy.deepcopy(binary),
    )
    bound = {
        cls["name"]: [m.get("fnAddr") for m in cls["methods"]]
        for cls in unique["classes"]
    }
    assert all(bound["com/example/ClassA"]), "2-method class must bind by count"
    assert all(bound["com/example/ClassB"]), "3-method class must bind by count"
    assert bound["com/example/ClassA"] == [
        _export_addr(report, "fixture_alpha"),
        _export_addr(report, "fixture_beta"),
    ]
    assert bound["com/example/ClassB"] == [
        _export_addr(report, "fixture_gamma"),
        _export_addr(report, "fixture_delta"),
        _export_addr(report, "fixture_epsilon"),
    ]
    assert unique["bindingGaps"] == []

    # Ambiguous: two classes share each branch's count, so neither branch can be
    # attributed by count alone. Both stay unbound and both raise a gap.
    ambiguous = merge(
        _classes(
            [
                ("com/example/First", 2),
                ("com/example/Second", 2),
                ("com/example/Third", 3),
                ("com/example/Fourth", 3),
            ]
        ),
        copy.deepcopy(binary),
    )
    assert all(
        "fnAddr" not in method
        for cls in ambiguous["classes"]
        for method in cls["methods"]
    )
    gaps = ambiguous["bindingGaps"]
    assert [g["kind"] for g in gaps] == [
        "ambiguous-count-only-table",
        "ambiguous-count-only-table",
    ]
    assert {g["nMethods"] for g in gaps} == {2, 3}
    assert {tuple(g["candidateClasses"]) for g in gaps} == {
        ("com/example/First", "com/example/Second"),
        ("com/example/Third", "com/example/Fourth"),
    }
    # Every gap points back at the shared RegisterNatives call site.
    assert all(g["source"] == "register-natives-stack" for g in gaps)
    assert {g["registerNativesCallSite"] for g in gaps} == {
        table["registerNativesCallSite"] for table in _stack_tables(report)
    }


def test_pe_j2cc_detector_selects_named_profile_on_real_dll() -> None:
    """The NAMED ``j2cc`` profile detector (``_detect_j2cc``) fires on a REAL PE
    x86-64 DLL — not the mocked LIEF object of
    ``test_specific_profile_wins_when_its_detector_matches``.

    LIEF confirms the PE magic and the AMD64 machine id; the two Java_* exports
    (``initClass`` + ``bootstrap``, ``<=4``) plus a ``Cannot invoke `` literal
    make ``_detect_j2cc`` outscore the generic fallback. ``introspect`` then
    stamps the selected profile onto the report's ``analysis`` block. This is
    the Windows sibling of the ELF ``auto``-harvest fixture and closes the gap
    where the named detector was proven only by a mock (the committed ELF proved
    generic ``auto`` harvest, not this detector, which returns 0.0 on ELF).
    """
    path = FIXTURES / "jni_dispatch_j2cc.dll"

    binary = lief.parse(str(path))
    assert binary.format == lief.Binary.FORMATS.PE
    assert int(binary.header.machine) == 0x8664  # IMAGE_FILE_MACHINE_AMD64

    assert detect_profile(binary) is get_profile("j2cc")

    report = introspect(path)
    assert report.fmt == "PE"
    assert report.arch == "x86_64"
    assert report.analysis == {"profile": "j2cc", "methodDiscovery": "jni-spec"}


def test_pe_j2cc_shared_dispatch_recovers_two_tables_from_one_call_site() -> None:
    """The ``j2cc`` profile's ``shared_dispatch`` harvest recovers BOTH stack
    tables (``nMethods`` 2 and 3) from the ONE Microsoft x64 ``RegisterNatives``
    call site on a real PE.

    Unlike the ELF fixture (which exercises the generic ``auto`` fallback), this
    binary selects the named ``j2cc`` profile, whose ``harvest_strategy`` is
    ``shared_dispatch`` — the path in ``find_jni_method_tables`` that ALWAYS
    calls ``_harvest_dispatch`` rather than the ``auto`` fallback. The two
    branches (env in RCX, ``methods*`` in R8, ``nMethods`` in R9D, one
    ``call *0x6b8(%rax)``) both precede the shared call, so both tables land in
    the back-scan window. Recovered fnAddrs cross-check the ``fixture_*`` export
    addresses; stack-built tables expose ordered fnAddrs but no fabricated
    method names/descriptors.
    """
    path = FIXTURES / "jni_dispatch_j2cc.dll"
    report = introspect(path)

    assert report.analysis["profile"] == "j2cc"

    tables = _stack_tables(report)
    assert len(tables) == 2, (
        "shared dispatch must yield two tables, not one collapsed bind"
    )

    # Both branches were harvested from the SAME RegisterNatives call site.
    call_sites = {t["registerNativesCallSite"] for t in tables}
    assert len(call_sites) == 1

    assert all(t["abi"] == "amd64-windows" for t in tables)
    assert all(t["profile"] == "j2cc" for t in tables)
    # Stack-built tables carry ordered function pointers and a per-branch
    # nMethods but NO decoded/fabricated names.
    assert all("methods" not in t for t in tables)

    by_count = {t["nMethods"]: t["fnAddrs"] for t in tables}
    assert set(by_count) == {2, 3}

    # Each recovered fnAddr cross-checks against its export address; a collapsed
    # or misordered harvest would desync these.
    assert by_count[2] == [
        _export_addr(report, "fixture_alpha"),
        _export_addr(report, "fixture_beta"),
    ]
    assert by_count[3] == [
        _export_addr(report, "fixture_gamma"),
        _export_addr(report, "fixture_delta"),
        _export_addr(report, "fixture_epsilon"),
    ]


def test_pe_j2cc_java_exports_are_exactly_initclass_and_bootstrap() -> None:
    """The dispatcher exports exactly the two Java_* names the detector budgets
    for — ``initClass`` + ``bootstrap`` (``<=4``). The five method bodies are
    exported under ``fixture_*`` names and register through the stack tables, not
    by Java_* export."""
    report = introspect(FIXTURES / "jni_dispatch_j2cc.dll")
    exported = {e["fnSymbol"] for e in _jni_exports(report)}
    assert exported == {
        "Java_com_example_Boot_initClass",
        "Java_com_example_Boot_bootstrap",
    }


def test_pe_j2cc_shared_dispatch_tables_bind_by_count_and_gap_when_ambiguous() -> None:
    """End-to-end merge of the PE ``j2cc`` shared-dispatch tables (the Windows
    sibling of the ELF shared-dispatch merge test).

    When each branch's method count uniquely identifies a class, the two tables
    bind by count with no gaps. When counts are ambiguous (several classes share
    a branch's method count), the tables are left UNBOUND and an
    ``ambiguous-count-only-table`` gap is emitted for each — never a silent,
    arbitrary bind.
    """
    import copy

    from manifest_merge.core import merge

    report = introspect(FIXTURES / "jni_dispatch_j2cc.dll")
    binary = report.to_json_obj()

    def _classes(specs: list[tuple[str, int]]) -> dict:
        return {
            "input": {"jarPath": "input.jar"},
            "classes": [
                {
                    "name": name,
                    "methods": [
                        {
                            "name": f"m{index}",
                            "desc": "()V",
                            "access": 0x0100,
                            "isObfuscatedNative": True,
                        }
                        for index in range(count)
                    ],
                }
                for name, count in specs
            ],
        }

    # Unambiguous: exactly one 2-method class and one 3-method class. Each shared
    # branch binds to its unique count match, and no gap remains.
    unique = merge(
        _classes([("com/example/ClassA", 2), ("com/example/ClassB", 3)]),
        copy.deepcopy(binary),
    )
    bound = {
        cls["name"]: [m.get("fnAddr") for m in cls["methods"]]
        for cls in unique["classes"]
    }
    assert all(bound["com/example/ClassA"]), "2-method class must bind by count"
    assert all(bound["com/example/ClassB"]), "3-method class must bind by count"
    assert bound["com/example/ClassA"] == [
        _export_addr(report, "fixture_alpha"),
        _export_addr(report, "fixture_beta"),
    ]
    assert bound["com/example/ClassB"] == [
        _export_addr(report, "fixture_gamma"),
        _export_addr(report, "fixture_delta"),
        _export_addr(report, "fixture_epsilon"),
    ]
    assert unique["bindingGaps"] == []

    # Ambiguous: two classes share each branch's count, so neither branch can be
    # attributed by count alone. Both stay unbound and both raise a gap.
    ambiguous = merge(
        _classes(
            [
                ("com/example/First", 2),
                ("com/example/Second", 2),
                ("com/example/Third", 3),
                ("com/example/Fourth", 3),
            ]
        ),
        copy.deepcopy(binary),
    )
    assert all(
        "fnAddr" not in method
        for cls in ambiguous["classes"]
        for method in cls["methods"]
    )
    gaps = ambiguous["bindingGaps"]
    assert [g["kind"] for g in gaps] == [
        "ambiguous-count-only-table",
        "ambiguous-count-only-table",
    ]
    assert {g["nMethods"] for g in gaps} == {2, 3}
    assert {tuple(g["candidateClasses"]) for g in gaps} == {
        ("com/example/First", "com/example/Second"),
        ("com/example/Third", "com/example/Fourth"),
    }
    # Every gap points back at the shared RegisterNatives call site.
    assert all(g["source"] == "register-natives-stack" for g in gaps)
    assert {g["registerNativesCallSite"] for g in gaps} == {
        table["registerNativesCallSite"] for table in _stack_tables(report)
    }


def test_introspect_real_i386_elf_recovers_static_table_and_export() -> None:
    """i386 / System V cdecl proven end-to-end on a committed 32-bit ELF ``.so``.

    A genuine ``(ELF, EM_386)`` image — not a renamed 64-bit ``.so``. cdecl
    passes RegisterNatives' arguments on the stack (``push $nMethods`` /
    ``push methods``), and position-independent i386 forms the table address
    through the GOT-base register (``call``/``pop``/``add`` PC thunk, then
    ``lea disp(%ebx), %edx``). The i386-sysv backend detects the machine, reads
    the pushed count, and folds the GOT-relative ``lea`` back to the table VA so
    the static table decodes with names/descriptors whose function pointers
    cross-check the export addresses. The ``Java_*`` export is recovered on
    every host from the LIEF symbol table; when capstone somehow cannot decode
    32-bit x86, no table is claimed and no methods are fabricated.
    """
    path = FIXTURES / "libjni_registrar_i386.so"

    binary = lief.parse(str(path))
    assert binary.format == lief.Binary.FORMATS.ELF
    assert int(binary.header.machine_type) == 0x03  # EM_386

    from binary_introspect.arch import detect_abi

    abi = detect_abi(binary)
    assert abi is not None and abi.name == "i386-sysv"

    report = introspect(path)
    assert report.fmt == "ELF"
    assert report.arch == "x86"
    assert report.analysis == {"profile": "generic", "methodDiscovery": "jni-spec"}

    # The specification-defined Java_* export is recovered on every host — it
    # comes from the LIEF symbol table, not disassembly.
    exports = _jni_exports(report)
    assert [e["fnSymbol"] for e in exports] == ["Java_com_example_Sample_ping"]
    assert exports[0]["fnAddr"] == _export_addr(
        report, "Java_com_example_Sample_ping"
    )

    tables = _static_tables(report)
    if not _capstone_disassembles_x86_32():
        # Honest fallback: no 32-bit x86 disassembler means no table is claimed,
        # and crucially no fabricated methods. The export above still holds.
        assert tables == []
        return

    assert len(tables) == 1, "i386 table must not silently yield nothing"
    table = tables[0]
    assert table["abi"] == "i386-sysv"
    assert table["nMethods"] == 2
    assert [(m["name"], m["desc"]) for m in table["methods"]] == [
        ("alpha", "()V"),
        ("beta", "(I)I"),
    ]
    # Function pointers resolve through R_386_32 relocations on the table's fnPtr
    # slots and cross-check against the exported addresses; a broken GOT-base
    # fold or relocation read would desync these.
    assert table["methods"][0]["fnAddr"] == _export_addr(report, "fixture_alpha")
    assert table["methods"][1]["fnAddr"] == _export_addr(report, "fixture_beta")


def test_i386_got_relative_lea_table_address_is_folded() -> None:
    """Position-independent i386 forms an in-image constant's address through the
    GOT base: a ``call``/``pop``/``add`` PC thunk materialises
    ``_GLOBAL_OFFSET_TABLE_`` in a register, then ``lea disp(%ebx), %edx``
    reaches the table. The i386-sysv backend must fold that back to the absolute
    VA — a regression here silently loses every PIC i386 table."""
    from binary_introspect.arch.i386_sysv import I386_SYSV

    cs = I386_SYSV.disassembler()
    if cs is None or not _capstone_disassembles_x86_32():
        pytest.skip("host capstone cannot decode 32-bit x86")

    # call .Lnext ; pop %ebx ; add $0x2fbb, %ebx ; lea -0x88(%ebx), %edx
    # This is the exact clang sequence emitted for libjni_registrar_i386.so.
    # ebx = 0x1039 + 0x2fbb = 0x3ff4 (the GOT base); table = 0x3ff4 - 0x88.
    code = bytes.fromhex(
        "e800000000"      # 0x1034: call 0x1039
        "5b"              # 0x1039: pop  %ebx
        "81c3bb2f0000"    # 0x103a: add  $0x2fbb, %ebx
        "8d9378ffffff"    # 0x1040: lea  -0x88(%ebx), %edx
    )
    I386_SYSV.begin_scan(None)
    folded = None
    for ins in cs.disasm(code, 0x1034):
        result = I386_SYSV.decode_pc_relative_lea(ins)
        if result is not None:
            folded = result
    assert folded == 0x3F6C
