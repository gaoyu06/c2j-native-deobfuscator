"""Per-binary cache-table extractor for native-obfuscator output.

native-obfuscator emits each obfuscated JVM method as inline C++ that
lazy-caches every referenced class / field / method ID in a global
array (``cclasses[N]`` / ``cfields[N]`` / ``cmethods[N]``). Ghidra
strips the array-index abstraction and shows raw global addresses
(``DAT_xxxxxxxx``) in pseudo-C, which leaves the static lifter with no
way to resolve ``env->GetFieldID(DAT_X, ..., ...)`` back to a real
``(owner, name, desc)`` triple.

This scanner runs at the binary level (capstone) and produces:

    {
      "stringPoolBase":  absolute_addr,
      "stringPoolVar":   absolute_addr,   # address of the `char* g_pool` var
      "fields":  { absolute_addr -> {"owner_addr": addr, "name": str, "desc": str} },
      "methods": { absolute_addr -> {"owner_addr": addr, "name": str, "desc": str} },
    }

``owner_addr`` is the address of the cclasses slot. Resolving it to a
real class name is a follow-up pass (TODO) — for now the lifter emits
``GETFIELD ?.<name>:<desc>`` when only the field/method side resolves.

The interesting part: native-obfuscator's emitted code loads the string
pool's base pointer once into a register, then references each entry
as ``lea reg, [pool_reg + small_offset]`` or ``add pool_reg, imm``.
The scanner therefore tracks per-register "what does this hold" state
across the local instruction window:

    mov reg, [rip + POOL_VAR]      → reg = ("pool", 0)
    lea reg, [pool_reg + N]        → reg = ("pool", off + N)
    add pool_reg, N                → pool_reg = ("pool", off + N)
    mov reg, [rip + ADDR]          → reg = ("slot", ADDR)  (loaded value
                                                            from a global slot
                                                            — used for jclass arg)

Then at a GetField/MethodID call, the arg regs' final state tells us
the slot/name/desc identities.

Scope today: AMD64 / Windows x64 only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import lief

# JNI vtable offsets (pointer size = 8 on x64).
_JNI_FIND_CLASS              = 0x30   # idx 6
_JNI_GET_METHOD_ID           = 0x108  # idx 33
_JNI_GET_FIELD_ID            = 0x2f0  # idx 94
_JNI_GET_STATIC_METHOD_ID    = 0x238  # idx 71
_JNI_GET_STATIC_FIELD_ID     = 0x308  # idx 97
_JNI_NEW_STRING_UTF          = 0x538  # idx 167 — used to populate cstrings[N]
_JNI_NEW_GLOBAL_REF          = 0xa8   # idx 21 — wraps cstrings[N] result

_VTABLE_CALL_RE = re.compile(r"\[(?:r|e)\w+\s*\+\s*(0x[0-9a-fA-F]+|\d+)\]")


def extract_cache_table(
    binary: lief.Binary,
    string_pool_entries: list[dict[str, Any]],
    *,
    string_pool_base: int | None = None,
) -> dict[str, Any]:
    """Build (slot_addr → (owner_addr, name, desc)) maps for fields and
    methods by scanning the binary's executable sections.

    Returns a JSON-friendly dict — slot addresses are keyed as decimal
    strings so they survive JSON roundtrips losslessly.
    """
    if binary.format != lief.Binary.FORMATS.PE:
        return _empty_table()
    try:
        if int(binary.header.machine) != 0x8664:
            return _empty_table()
    except Exception:
        return _empty_table()

    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, x86_const
    except ImportError:
        return _empty_table()

    pool_by_offset = {e["offset"]: e["value"] for e in string_pool_entries
                      if isinstance(e, dict) and "offset" in e}

    if string_pool_base is None:
        return _empty_table()

    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True

    # Pre-decode every executable section so we can re-run the scanner
    # against several candidate pool_var addresses cheaply.
    section_insns = []
    for sec in binary.sections:
        if sec.size == 0 or (sec.characteristics & 0x20000000) == 0:
            continue
        start_va = binary.imagebase + sec.virtual_address
        section_insns.append(list(cs.disasm(bytes(sec.content), start_va)))

    # Identify the address of `string_pool::get_pool()` (a tiny helper
    # whose body is `lea rax, [rip + pool_base]; ret`). When a call site
    # invokes this function the result register holds the pool base, so
    # any `lea reg2, [rax + N]` after the call references pool offset N.
    # Without this, the cstrings/cclasses init code (which uses
    # `mov [slot], rax; lea rdx, [rax + N]; ...NewStringUTF`) doesn't
    # propagate state correctly.
    get_pool_addr = _find_get_pool_helper(section_insns, string_pool_base)

    # native-obfuscator emits a separate `char *string_pool` global PER
    # class namespace (see e.g. `namespace native_jvm::classes::Snake_4`
    # in the generated cpp). So we don't have ONE pool_var to pick — we
    # have N, one per class. Enumerate all candidates whose offset
    # patterns plausibly match the pool, run the scanner against each,
    # and merge resolved entries into a single combined table.
    candidates = _enumerate_pool_var_candidates(section_insns, cs, pool_by_offset)
    pool_var_addrs: list[int] = [addr for addr, _ in candidates[:24]]

    fields: dict[str, dict[str, Any]] = {}
    methods: dict[str, dict[str, Any]] = {}
    # cstrings[slot_addr] = pool_string (via NewStringUTF)
    cstrings: dict[str, str] = {}
    # classes[slot_addr] = internal_class_name (via FindClass direct OR
    # via helper-with-cstrings r8 arg)
    classes: dict[str, str] = {}

    for pv in pool_var_addrs:
        for insns in section_insns:
            if not insns:
                continue
            _scan_section(
                insns, cs, pv, string_pool_base, pool_by_offset,
                fields, methods, cstrings, classes, get_pool_addr,
            )
    pool_var_addr = pool_var_addrs[0] if pool_var_addrs else None

    # Cross-validate the heuristically-bound `classes` table: a slot
    # is genuinely a cclasses slot only if at least one field or method
    # entry references it as `owner_addr`. The `_try_bind_class_via_helper`
    # heuristic is intentionally greedy (binds on any call where r8 was
    # loaded from a cstrings slot), so cstrings-reading non-class
    # helpers can sneak entries in. Filter them out.
    owner_slot_addrs = {
        e["owner_addr"] for e in list(fields.values()) + list(methods.values())
        if e.get("owner_addr") is not None
    }
    classes = {k: v for k, v in classes.items() if int(k) in owner_slot_addrs}

    # Resolve owner_addr → class_name for each field/method entry.
    for tbl in (fields, methods):
        for entry in tbl.values():
            owner_addr = entry.get("owner_addr")
            if owner_addr is not None:
                entry["owner"] = classes.get(str(owner_addr))

    return {
        "stringPoolBase": str(string_pool_base),
        "stringPoolVar": str(pool_var_addr) if pool_var_addr else None,
        "fields": fields,
        "methods": methods,
        "classes": classes,
        "cstrings": cstrings,
    }


def _empty_table() -> dict[str, Any]:
    return {"stringPoolBase": None, "stringPoolVar": None,
            "fields": {}, "methods": {}}


# ----------------------------------------------------------------
# Scanner
# ----------------------------------------------------------------

@dataclass
class _RegState:
    """Per-register: what kind of value does it hold right now?

    kind ∈ {"pool", "slot", "addr", None}:
      - "pool":  register == string_pool_base + payload  (payload is offset)
      - "slot":  register == VALUE loaded from RIP-relative address `payload`
                 (i.e. dereferenced — typical for jclass cache slot reads)
      - "addr":  register == constant address `payload` (from a LEA)
      - None:    state unknown / clobbered
    """
    kind: str | None
    payload: int


def _prefer_resolved(tbl: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """No-op stub: ``_scan_section`` already overwrites entries per
    pool_var trial. Real preference happens because the LAST writer wins,
    and we iterate pool_var candidates in descending plausibility order.
    Resolved-name entries naturally accumulate as later passes find them.
    """
    return tbl


def _state_to_pool_offset(state, pool_base: int | None) -> int | None:
    """Translate a register state to a string-pool offset.

    Two emission styles seen in native-obfuscator output:
      - ``mov reg, [rip+pool_var]; lea r8, [reg+N]`` → state kind="pool",
        payload is already the offset.
      - ``lea r8, [rip+ABS]`` → state kind="addr", payload is the
        absolute string address; convert via pool_base.
    """
    if state is None:
        return None
    if state.kind == "pool":
        return state.payload
    if state.kind == "addr" and pool_base is not None:
        return state.payload - pool_base
    return None


def _scan_section(insns, cs, pool_var_addr, string_pool_base, pool_by_offset,
                  fields, methods, cstrings, classes, get_pool_addr=None):
    from capstone import x86_const

    FIELD_METHOD_HANDLERS = {
        _JNI_GET_FIELD_ID:        (fields, False),
        _JNI_GET_STATIC_FIELD_ID: (fields, True),
        _JNI_GET_METHOD_ID:       (methods, False),
        _JNI_GET_STATIC_METHOD_ID:(methods, True),
    }

    # We restart the register-state tracker at the start of each function
    # boundary. Since we don't have function boundaries here, we treat
    # every `int3` / `ret` as a soft reset.
    regs: dict[int, _RegState] = {}

    for idx, ins in enumerate(insns):
        # Soft reset at common function-terminator-ish mnemonics.
        if ins.mnemonic in ("ret", "retn", "retf", "int3"):
            regs.clear()
            continue

        # Update register state from this instruction (BEFORE handling
        # any call, since the call's arg regs are determined by the
        # state ENTERING the call — i.e. AFTER the LEAs/MOVs that just
        # set them up. The call itself doesn't modify the arg regs.)
        _apply_state(ins, regs, pool_var_addr)

        if ins.mnemonic != "call":
            continue

        # `call get_pool_addr` — the helper returns the pool base, so
        # rax becomes ("pool", 0) right after. Without this, cstrings/
        # cclasses init blocks (which start `mov rax, get_pool(); lea
        # rdx, [rax + N]; NewStringUTF`) fail to propagate state.
        if get_pool_addr is not None and _is_direct_call_to(ins, get_pool_addr):
            regs[x86_const.X86_REG_RAX] = _RegState("pool", 0)
        m = _VTABLE_CALL_RE.search(ins.op_str)
        if m is None:
            # Direct (non-vtable) call: this might be
            # `utils::find_class_wo_static(env, classloader, jstring)`
            # — check by looking at r8's state. If r8 was loaded from a
            # known cstrings slot AND the result eventually stores to a
            # global slot, bind that global as a cclasses entry.
            _try_bind_class_via_helper(insns, idx, regs, cstrings, classes)
            continue
        try:
            off = int(m.group(1), 16) if m.group(1).startswith("0x") else int(m.group(1))
        except ValueError:
            continue

        # Field / method binding.
        handler = FIELD_METHOD_HANDLERS.get(off)
        if handler is not None:
            tbl, _is_static = handler
            rdx_state = regs.get(x86_const.X86_REG_RDX)
            r8_state  = regs.get(x86_const.X86_REG_R8)
            r9_state  = regs.get(x86_const.X86_REG_R9)
            owner_addr = (rdx_state.payload
                          if rdx_state and rdx_state.kind == "slot" else None)
            name_off = _state_to_pool_offset(r8_state, string_pool_base)
            desc_off = _state_to_pool_offset(r9_state, string_pool_base)
            if owner_addr is None or name_off is None or desc_off is None:
                continue
            result_slot = _find_result_slot(insns, idx)
            if result_slot is None:
                continue
            entry = {
                "owner_addr": owner_addr,
                "name": pool_by_offset.get(name_off),
                "desc": pool_by_offset.get(desc_off),
            }
            existing = tbl.get(str(result_slot))
            if existing is not None:
                if (existing.get("name") is not None and existing.get("desc") is not None
                    and (entry["name"] is None or entry["desc"] is None)):
                    continue
            tbl[str(result_slot)] = entry
            continue

        # FindClass direct: rdx = const char* class name.
        # In native-obfuscator: only used for array types.
        if off == _JNI_FIND_CLASS:
            rdx_state = regs.get(x86_const.X86_REG_RDX)
            name_off = _state_to_pool_offset(rdx_state, string_pool_base)
            if name_off is None:
                continue
            class_name = pool_by_offset.get(name_off)
            if class_name is None:
                continue
            result_slot = _find_result_slot(insns, idx, look_forward=24)
            if result_slot is None:
                continue
            classes[str(result_slot)] = class_name
            continue

        # NewStringUTF: rdx = const char* utf8. Used to populate
        # cstrings[N]. The result usually goes through NewGlobalRef
        # before being stored, so look further ahead.
        if off == _JNI_NEW_STRING_UTF:
            rdx_state = regs.get(x86_const.X86_REG_RDX)
            str_off = _state_to_pool_offset(rdx_state, string_pool_base)
            if str_off is None:
                continue
            value = pool_by_offset.get(str_off)
            if value is None:
                continue
            result_slot = _find_result_slot(insns, idx, look_forward=24)
            if result_slot is None:
                continue
            cstrings[str(result_slot)] = value


_REG64 = {}  # populated lazily from capstone


def _to64(reg: int) -> int:
    """Normalise a capstone x86 register id to its 64-bit alias.

    `mov edx, 0x2d9` writes the EDX (32-bit) alias of RDX. Capstone
    reports a different reg id for each width, so without this
    normalisation the state stored under EDX is invisible to a later
    lookup of RDX. We map RAX/EAX/AX/AL → RAX, RDX/EDX/DX/DL → RDX, etc.
    """
    from capstone import x86_const
    global _REG64
    if not _REG64:
        aliases = [
            ("RAX", "EAX", "AX", "AL", "AH"),
            ("RBX", "EBX", "BX", "BL", "BH"),
            ("RCX", "ECX", "CX", "CL", "CH"),
            ("RDX", "EDX", "DX", "DL", "DH"),
            ("RSI", "ESI", "SI", "SIL"),
            ("RDI", "EDI", "DI", "DIL"),
            ("RBP", "EBP", "BP", "BPL"),
            ("RSP", "ESP", "SP", "SPL"),
            ("R8",  "R8D", "R8W", "R8B"),
            ("R9",  "R9D", "R9W", "R9B"),
            ("R10", "R10D", "R10W", "R10B"),
            ("R11", "R11D", "R11W", "R11B"),
            ("R12", "R12D", "R12W", "R12B"),
            ("R13", "R13D", "R13W", "R13B"),
            ("R14", "R14D", "R14W", "R14B"),
            ("R15", "R15D", "R15W", "R15B"),
        ]
        for group in aliases:
            head = getattr(x86_const, f"X86_REG_{group[0]}")
            for n in group:
                rid = getattr(x86_const, f"X86_REG_{n}", None)
                if rid is not None:
                    _REG64[rid] = head
    return _REG64.get(reg, reg)


def _apply_state(ins, regs: dict[int, _RegState], pool_var_addr: int | None) -> None:
    """Update `regs` to reflect this instruction's effect on register
    state. We only model the patterns the cache-init blocks use."""
    from capstone import x86_const

    if ins.mnemonic == "mov" and len(ins.operands) == 2:
        dst, src = ins.operands
        if dst.type == x86_const.X86_OP_REG:
            # mov reg, [rip + d]    → load from absolute address
            if (src.type == x86_const.X86_OP_MEM and
                src.mem.base == x86_const.X86_REG_RIP and src.mem.index == 0):
                target = ins.address + ins.size + src.mem.disp
                if pool_var_addr is not None and target == pool_var_addr:
                    regs[_to64(dst.reg)] = _RegState("pool", 0)
                else:
                    regs[_to64(dst.reg)] = _RegState("slot", target)
                return
            # mov reg, imm — track as "imm" so a later
            # `add reg, [rip + pool_var]` can recover the pool offset.
            if src.type == x86_const.X86_OP_IMM:
                regs[_to64(dst.reg)] = _RegState("imm", src.imm)
                return
            # mov reg, other_reg     → copy state
            if src.type == x86_const.X86_OP_REG:
                st = regs.get(_to64(src.reg))
                if st is not None:
                    regs[_to64(dst.reg)] = _RegState(st.kind, st.payload)
                else:
                    regs.pop(_to64(dst.reg), None)
                return
            # any other mov clobbers dst's tracked state
            regs[_to64(dst.reg)] = _RegState(None, 0)
        return

    if ins.mnemonic == "lea" and len(ins.operands) == 2:
        dst, src = ins.operands
        if (dst.type == x86_const.X86_OP_REG and
            src.type == x86_const.X86_OP_MEM and src.mem.index == 0):
            disp = src.mem.disp
            if src.mem.base == x86_const.X86_REG_RIP:
                # lea reg, [rip + d]  → reg = absolute address
                regs[_to64(dst.reg)] = _RegState("addr", ins.address + ins.size + disp)
                return
            base_state = regs.get(_to64(src.mem.base))
            if base_state is not None and base_state.kind in ("pool", "addr"):
                regs[_to64(dst.reg)] = _RegState(base_state.kind,
                                          base_state.payload + disp)
                return
            # base register is unknown → dst loses state
            regs[_to64(dst.reg)] = _RegState(None, 0)
        return

    if ins.mnemonic == "add" and len(ins.operands) == 2:
        dst, src = ins.operands
        if dst.type == x86_const.X86_OP_REG:
            # add reg, imm — propagate pool/addr/imm states.
            if src.type == x86_const.X86_OP_IMM:
                st = regs.get(_to64(dst.reg))
                if st is not None and st.kind in ("pool", "addr", "imm"):
                    regs[_to64(dst.reg)] = _RegState(st.kind, st.payload + src.imm)
                    return
                regs.pop(_to64(dst.reg), None)
                return
            # add reg, [rip + d] — when d resolves to pool_var AND reg
            # currently holds an immediate, the combination yields
            # `reg = pool_base + imm` → kind="pool" payload=imm.
            if (src.type == x86_const.X86_OP_MEM and
                src.mem.base == x86_const.X86_REG_RIP and src.mem.index == 0):
                target = ins.address + ins.size + src.mem.disp
                if pool_var_addr is not None and target == pool_var_addr:
                    st = regs.get(_to64(dst.reg))
                    if st is not None and st.kind == "imm":
                        regs[_to64(dst.reg)] = _RegState("pool", st.payload)
                        return
                # otherwise clear: we don't know what was added.
                regs.pop(_to64(dst.reg), None)
                return
            regs.pop(_to64(dst.reg), None)
        return

    # Conservative: any other instruction that writes a register clears
    # its tracked state. We can't model every mutation, so it's safer
    # to drop than carry stale info forward.
    if ins.operands and ins.operands[0].type == x86_const.X86_OP_REG:
        # Skip pure read-mnemonics (e.g. test, cmp, push).
        if ins.mnemonic not in ("test", "cmp", "push", "jmp", "je", "jne",
                                 "jg", "jl", "jge", "jle", "ja", "jb",
                                 "jae", "jbe", "jz", "jnz", "call", "nop"):
            dst = ins.operands[0]
            regs[_to64(dst.reg)] = _RegState(None, 0)


def _find_get_pool_helper(section_insns, pool_base: int) -> int | None:
    """Find ``string_pool::get_pool()``'s entry address by recognising
    its body shape: ``lea rax, [rip + pool_base]; ret`` (possibly with
    a stock prologue/epilogue around it).

    Returns the function's entry VA, or ``None`` if no such helper is
    present (the compiler may have inlined it everywhere).
    """
    from capstone import x86_const

    for insns in section_insns:
        for i, ins in enumerate(insns):
            if ins.mnemonic != "lea" or len(ins.operands) != 2:
                continue
            dst, src = ins.operands
            if dst.type != x86_const.X86_OP_REG or dst.reg != x86_const.X86_REG_RAX:
                continue
            if (src.type != x86_const.X86_OP_MEM or
                src.mem.base != x86_const.X86_REG_RIP or src.mem.index != 0):
                continue
            if ins.address + ins.size + src.mem.disp != pool_base:
                continue
            # Confirm the next non-noise instruction is `ret`.
            for j in range(i + 1, min(len(insns), i + 4)):
                nxt = insns[j]
                if nxt.mnemonic in ("ret", "retn"):
                    # Walk backwards for the function prologue (push rbp,
                    # mov rbp,rsp). Take the earliest contiguous push.
                    start_idx = i
                    while start_idx > 0:
                        prev = insns[start_idx - 1]
                        if prev.mnemonic in ("push", "mov", "sub") and \
                           prev.address + prev.size == insns[start_idx].address:
                            start_idx -= 1
                        else:
                            break
                    return insns[start_idx].address
                if nxt.mnemonic not in ("pop", "mov", "nop"):
                    break
    return None


def _is_direct_call_to(ins, target: int) -> bool:
    """Match ``call <abs_addr>`` where the encoded target equals
    ``target``. Capstone renders these as e.g. ``call 0x1800199c0``."""
    if ins.mnemonic != "call":
        return False
    try:
        # capstone op_str for `call rel32` is the resolved absolute addr.
        s = ins.op_str.strip()
        if s.startswith("0x"):
            return int(s, 16) == target
        if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
            return int(s) == target
    except ValueError:
        pass
    return False


def _try_bind_class_via_helper(insns, call_idx: int, regs, cstrings, classes):
    """Recognise the ``utils::find_class_wo_static(env, classloader,
    jstring)`` helper-call pattern. We don't know the helper's address
    a priori; instead, we look at:

      1. The call's arg-3 state — must be a load from a known cstrings
         slot (r8 = ``mov r8, [rip + CSTRINGS_SLOT]``).
      2. The post-call wrap chain — must include a ``NewWeakGlobalRef``
         vtable call (offset ``0x710``) before the final
         ``mov [rip + CCLASSES_SLOT], rax``.

      Requiring (2) distinguishes cclasses init from generic helpers
      that happen to take a jstring arg (e.g. logging utilities, string
      interning). cclasses_mtx-protected init uses NewWeakGlobalRef
      specifically; cstrings init uses ``NewGlobalRef`` (offset 0xa8).
    """
    from capstone import x86_const

    r8_state = regs.get(x86_const.X86_REG_R8)
    if r8_state is None or r8_state.kind != "slot":
        return
    cstrings_slot_addr = r8_state.payload
    value = cstrings.get(str(cstrings_slot_addr))
    if value is None:
        return
    if not _has_weak_globalref_wrap(insns, call_idx, look_forward=32):
        return
    result_slot = _find_result_slot(insns, call_idx, look_forward=32)
    if result_slot is None:
        return
    internal = value.replace(".", "/")
    classes.setdefault(str(result_slot), internal)


def _has_weak_globalref_wrap(insns, call_idx: int, look_forward: int) -> bool:
    """True iff a ``call qword ptr [reg + 0x710]`` (NewWeakGlobalRef)
    appears between ``insns[call_idx]`` and the next ``ret``, within
    ``look_forward`` instructions."""
    end = min(len(insns), call_idx + 1 + look_forward)
    for j in range(call_idx + 1, end):
        ins = insns[j]
        if ins.mnemonic in ("ret", "retn"):
            return False
        if ins.mnemonic != "call":
            continue
        m = _VTABLE_CALL_RE.search(ins.op_str)
        if m is None:
            continue
        try:
            off = int(m.group(1), 16) if m.group(1).startswith("0x") else int(m.group(1))
        except ValueError:
            continue
        if off == 0x710:  # NewWeakGlobalRef
            return True
    return False


def _find_result_slot(insns, call_idx: int, look_forward: int = 16):
    """Scan forward for the first ``mov [rip + ADDR], rax`` after the call
    and return ADDR (absolute VA). None if not found."""
    from capstone import x86_const

    end = min(len(insns), call_idx + 1 + look_forward)
    for j in range(call_idx + 1, end):
        ins = insns[j]
        if ins.mnemonic == "ret":
            return None
        if ins.mnemonic != "mov" or len(ins.operands) != 2:
            continue
        dst, src = ins.operands
        if (dst.type == x86_const.X86_OP_MEM and
            dst.mem.base == x86_const.X86_REG_RIP and dst.mem.index == 0 and
            src.type == x86_const.X86_OP_REG and src.reg == x86_const.X86_REG_RAX):
            return ins.address + ins.size + dst.mem.disp
    return None


# ----------------------------------------------------------------
# Pool-var discovery
# ----------------------------------------------------------------

def _pick_pool_var(
    section_insns: list,
    cs,
    string_pool_base: int,
    pool_by_offset: dict[int, str],
) -> int | None:
    """Pick the best pool_var address by trial: enumerate the top
    candidates (per :func:`_find_pool_var_address`), run the cache-table
    extractor against each, and pick the one that yields the most
    fully-resolved (name, desc) entries.

    This is robust against decoy globals that happen to be loaded with
    known pool offsets — those produce few fully-resolved entries
    because the offsets only coincidentally match. The actual pool_var
    produces dozens of resolved name+desc pairs."""
    candidates = _enumerate_pool_var_candidates(section_insns, cs, pool_by_offset)
    if not candidates:
        return None

    best = (-1, candidates[0][0])  # (score, addr)
    for addr, _votes in candidates[:8]:
        fields: dict[str, dict[str, Any]] = {}
        methods: dict[str, dict[str, Any]] = {}
        for insns in section_insns:
            _scan_section(
                insns, cs, addr, string_pool_base, pool_by_offset,
                fields, methods,
            )
        fr = sum(1 for e in fields.values()
                 if e.get("name") is not None and e.get("desc") is not None)
        mr = sum(1 for e in methods.values()
                 if e.get("name") is not None and e.get("desc") is not None)
        # Fields resolve ONLY when the pool_var assignment is correct
        # (the field-access pattern always uses the `mov reg,[rip+POOL]
        # ; lea r8,[reg+N]` style). Methods sometimes resolve via the
        # alternate direct-LEA pattern regardless. So weight fields
        # heavily — any field resolution is decisive evidence.
        score = fr * 1000 + mr
        if score > best[0]:
            best = (score, addr)
    return best[1]


def _enumerate_pool_var_candidates(
    section_insns: list,
    cs,
    pool_by_offset: dict[int, str],
) -> list[tuple[int, int]]:
    """Find every address that gets loaded via ``mov reg, [rip+ADDR]``
    and then used in a ``lea/add`` whose constant is a known pool
    offset. Return ``(addr, unique-offset-count)`` sorted desc."""
    from capstone import x86_const

    known = set(pool_by_offset.keys())
    if not known:
        return []
    candidate_offsets: dict[int, set[int]] = {}
    for insns in section_insns:
        for i, ins in enumerate(insns):
            if ins.mnemonic != "mov" or len(ins.operands) != 2:
                continue
            dst, src = ins.operands
            if dst.type != x86_const.X86_OP_REG:
                continue
            if (src.type != x86_const.X86_OP_MEM or
                src.mem.base != x86_const.X86_REG_RIP or src.mem.index != 0):
                continue
            rip_target = ins.address + ins.size + src.mem.disp
            tracked = dst.reg
            for j in range(i + 1, min(len(insns), i + 6)):
                nxt = insns[j]
                if nxt.mnemonic == "lea" and len(nxt.operands) == 2:
                    s = nxt.operands[1]
                    if (s.type == x86_const.X86_OP_MEM and
                        s.mem.base == tracked and s.mem.index == 0 and
                        s.mem.disp in known):
                        candidate_offsets.setdefault(rip_target, set()).add(s.mem.disp)
                        break
                if nxt.mnemonic == "add" and len(nxt.operands) == 2:
                    d, s = nxt.operands
                    if (d.type == x86_const.X86_OP_REG and d.reg == tracked and
                        s.type == x86_const.X86_OP_IMM and s.imm in known):
                        candidate_offsets.setdefault(rip_target, set()).add(s.imm)
                        break
    return sorted(
        ((addr, len(offs)) for addr, offs in candidate_offsets.items()),
        key=lambda kv: -kv[1],
    )


def _find_pool_var_address(
    binary: lief.Binary,
    pool_base: int,
    cs,
    pool_by_offset: dict[int, str],
) -> int | None:
    """Find the address of ``char* g_string_pool`` — the global the
    obfuscated code dereferences to recover the string-pool base.

    On disk the slot is NULL (filled in at runtime by ``init_utils``), so
    we can't find it by value scan. Instead identify it by usage pattern:
    look for ``mov reg, [rip + d]`` immediately followed (within a few
    instructions) by ``lea reg2, [reg + small_const]`` or
    ``add reg, small_const`` where ``small_const`` matches a known
    string-pool offset. The most-popular RIP target wins.
    """
    from capstone import x86_const

    # Pre-build the offset set we trust.
    known_offsets = set(pool_by_offset.keys())
    if not known_offsets:
        return None

    # Per candidate RIP target, collect the set of distinct
    # known-offsets that show up as `lea reg, [reg+OFFSET]` or
    # `add reg, OFFSET` right after `mov reg, [rip+TARGET]`. The real
    # pool_var combines with many distinct offsets; coincidental
    # candidates only see a handful.
    candidate_offsets: dict[int, set[int]] = {}

    for sec in binary.sections:
        if sec.size == 0 or (sec.characteristics & 0x20000000) == 0:
            continue
        start_va = binary.imagebase + sec.virtual_address
        insns = list(cs.disasm(bytes(sec.content), start_va))
        for i, ins in enumerate(insns):
            if ins.mnemonic != "mov" or len(ins.operands) != 2:
                continue
            dst, src = ins.operands
            if dst.type != x86_const.X86_OP_REG:
                continue
            if (src.type != x86_const.X86_OP_MEM or
                src.mem.base != x86_const.X86_REG_RIP or src.mem.index != 0):
                continue
            rip_target = ins.address + ins.size + src.mem.disp
            tracked_reg = dst.reg
            # Look forward up to 5 instructions for a derivation that
            # uses tracked_reg as a base with a known pool offset.
            for j in range(i + 1, min(len(insns), i + 6)):
                nxt = insns[j]
                if nxt.mnemonic == "lea" and len(nxt.operands) == 2:
                    s = nxt.operands[1]
                    if (s.type == x86_const.X86_OP_MEM and
                        s.mem.base == tracked_reg and
                        s.mem.index == 0 and
                        s.mem.disp in known_offsets):
                        candidate_offsets.setdefault(rip_target, set()).add(s.mem.disp)
                        break
                if nxt.mnemonic == "add" and len(nxt.operands) == 2:
                    d, s = nxt.operands
                    if (d.type == x86_const.X86_OP_REG and d.reg == tracked_reg and
                        s.type == x86_const.X86_OP_IMM and
                        s.imm in known_offsets):
                        candidate_offsets.setdefault(rip_target, set()).add(s.imm)
                        break
                # If tracked_reg gets clobbered, stop.
                if nxt.operands and nxt.operands[0].type == x86_const.X86_OP_REG \
                   and nxt.operands[0].reg == tracked_reg:
                    if nxt.mnemonic in ("lea", "add", "mov"):
                        # These are the only ops we already checked above.
                        # Other writes clobber.
                        if nxt.mnemonic == "mov" and len(nxt.operands) == 2:
                            ss = nxt.operands[1]
                            if not (ss.type == x86_const.X86_OP_MEM and
                                    ss.mem.base == x86_const.X86_REG_RIP):
                                break
    if not candidate_offsets:
        return None
    return max(candidate_offsets.items(), key=lambda kv: len(kv[1]))[0]
