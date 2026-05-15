"""tree-sitter-c based AST matcher.

Walks Ghidra-decompiled pseudo C and turns each statement into a JVM bytecode
instruction, following the patterns documented in
``docs/static-reverse-approach.md``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import tree_sitter
import tree_sitter_c

from .jni_vtable import rewrite_vtable_calls


# ------------------------------------------------------------------
# Tree-sitter helpers
# ------------------------------------------------------------------

_LANG = tree_sitter.Language(tree_sitter_c.language())
_PARSER = tree_sitter.Parser(_LANG)


def parse(code: str) -> tree_sitter.Tree:
    return _PARSER.parse(code.encode("utf-8"))


def text(node: tree_sitter.Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def find_descendants(node: tree_sitter.Node, kind: str) -> Iterable[tree_sitter.Node]:
    if node.type == kind:
        yield node
    for child in node.children:
        yield from find_descendants(child, kind)


# ------------------------------------------------------------------
# Matchers
# ------------------------------------------------------------------

CSTACK_RE = re.compile(r"^c?stack(\d+)\.(\w)$")
CLOCAL_RE = re.compile(r"^c?local(\d+)\.(\w)$")
CSTACK_IDX_RE = re.compile(r"^cstack\[(\d+)\]\.(\w)$")
CLOCAL_IDX_RE = re.compile(r"^clocal\[(\d+)\]\.(\w)$")

# Lookup table indices, e.g. cmethods[42], cfields[7], cclasses[5], cstrings[N]
TABLE_RE = re.compile(r"^(cmethods|cfields|cclasses|cstrings)\[(\d+)\]$")


@dataclass
class Slot:
    """A logical cstack/clocal slot reference (index + value type)."""
    table: str           # "stack" or "local"
    index: int
    field: str           # "i", "j", "f", "d", "l"


def parse_slot(expr: str) -> Slot | None:
    expr = expr.strip()
    for rx, t in [
        (CSTACK_RE, "stack"),
        (CLOCAL_RE, "local"),
        (CSTACK_IDX_RE, "stack"),
        (CLOCAL_IDX_RE, "local"),
    ]:
        m = rx.match(expr)
        if m:
            return Slot(table=t, index=int(m.group(1)), field=m.group(2))
    return None


def parse_table_ref(expr: str) -> tuple[str, int] | None:
    expr = expr.strip().strip("()")
    m = TABLE_RE.match(expr)
    if not m:
        return None
    return m.group(1), int(m.group(2))


# ------------------------------------------------------------------
# AST → instruction list
# ------------------------------------------------------------------

@dataclass
class MatchContext:
    lookups: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    # Symbolic stack height tracker, for inferring var/stack movement.
    instructions: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def emit(self, **kwargs: Any) -> None:
        self.instructions.append({k: v for k, v in kwargs.items() if v is not None})


def lift_function(
    func_code: str, lookups: dict[str, list[dict[str, Any]]] | None = None
) -> dict[str, Any]:
    """Lift one decompiled function body into a list of JVM instruction dicts."""
    ctx = MatchContext(lookups=lookups or {})
    tree = parse(func_code)
    source = func_code.encode("utf-8")

    # Walk all assignment_expression and call_expression nodes inside the
    # function body, in textual order.
    func_body = None
    for n in find_descendants(tree.root_node, "function_definition"):
        for c in n.children:
            if c.type == "compound_statement":
                func_body = c
                break
        if func_body:
            break
    if func_body is None:
        ctx.warnings.append("no function_definition found")
        return _result(ctx)

    walk(func_body, source, ctx)
    return _result(ctx)


def _result(ctx: MatchContext) -> dict[str, Any]:
    return {"instructions": ctx.instructions, "warnings": ctx.warnings}


def walk(node: tree_sitter.Node, source: bytes, ctx: MatchContext) -> None:
    # Hunt for any JNI call wherever it appears (often nested in
    # `if (lazy_init) { ... } else env->Call*Method(...)` blocks that the
    # structured handlers don't reach).
    if node.type == "call_expression":
        callee = node.child_by_field_name("function")
        if callee is not None and callee.type == "field_expression":
            member = callee.child_by_field_name("field")
            if member is not None:
                fname = text(member, source)
                if fname == "AllocObject":
                    match_alloc_object(node, source, ctx)
                    return
                if fname == "Throw":
                    ctx.emit(op="ATHROW")
                    return
                if fname in JNI_CALL_TO_INVOKE:
                    match_void_call(node, source, ctx)
                    return
                if fname in JNI_FIELD_GET:
                    match_field_get(node, source, ctx)
                    return
                if fname in JNI_FIELD_SET:
                    # Set* is void; emit via match_void_call which handles it.
                    match_void_call(node, source, ctx)
                    return
    if node.type == "labeled_statement":
        # `L1: <body>;` — emit a LABEL pseudo-instruction so jumps can resolve.
        # Native-obfuscator labels are short identifiers like L1, L2, ...; skip
        # C++ namespace tokens (`std::`, `utils::`, etc.) that tree-sitter-c
        # parses as labeled_statement when they appear at statement position.
        label_id = None
        for c in node.children:
            if c.type == "statement_identifier":
                label_id = text(c, source)
                break
        if label_id is not None and re.fullmatch(r"L\d+", label_id):
            ctx.emit(op="LABEL", label=label_id)
        for c in node.children:
            if c.type not in ("statement_identifier", ":"):
                walk(c, source, ctx)
        return
    if node.type == "goto_statement":
        for c in node.children:
            if c.type == "statement_identifier":
                ctx.emit(op="GOTO", target=text(c, source))
                return
        return
    if node.type == "assignment_expression":
        match_assignment(node, source, ctx)
        return
    if node.type == "expression_statement":
        # peek at the inner expression
        inner = node.children[0] if node.children else None
        if inner is not None and inner.type == "call_expression":
            match_void_call(inner, source, ctx)
        elif inner is not None and inner.type == "assignment_expression":
            match_assignment(inner, source, ctx)
        return
    if node.type == "if_statement":
        consumed_consequence = match_if(node, source, ctx)
        # If the cond+goto pattern matched, the `consequence` (which contains
        # only the goto) has already been emitted; skip it to avoid a
        # duplicate. Otherwise descend into both branches so nested
        # AllocObject / Throw / etc. still trigger their pattern handlers.
        for c in node.children:
            if consumed_consequence and c is node.child_by_field_name("consequence"):
                continue
            if c.type in ("if", "(", ")", ";"):
                continue
            if c is node.child_by_field_name("condition"):
                continue
            walk(c, source, ctx)
        return
    if node.type == "return_statement":
        match_return(node, source, ctx)
        return
    for c in node.children:
        walk(c, source, ctx)


def match_return(node: tree_sitter.Node, source: bytes, ctx: MatchContext) -> None:
    # `return (jint) cstack0.i;` → IRETURN (value already on operand stack)
    # `return (jint) clocal3.i;` → ILOAD 3 + IRETURN
    # `return (jint) 0;`         → ICONST_0 + IRETURN (synthetic fallthrough)
    # `return;`                  → RETURN
    arg = None
    for c in node.children:
        if c.type not in ("return", ";"):
            arg = c
            break
    if arg is None:
        ctx.emit(op="RETURN")
        return
    # Strip a cast wrapper if present: `(jint) <expr>` -> <expr>
    if arg.type == "cast_expression":
        cast_val = arg.child_by_field_name("value")
        if cast_val is not None:
            arg = cast_val
    expr = text(arg, source).strip().rstrip(";")
    slot = parse_slot(expr)
    field_for_op = "i"
    if slot is not None:
        field_for_op = slot.field
        if slot.table == "local":
            # Load from the local variable; it carries the value to return.
            ctx.emit(op=_xload(slot.field), **{"var": slot.index})
        else:
            # cstack slot — the value is already on the operand stack from
            # the prior op; just emit the return.
            pass
    elif arg.type == "number_literal" and expr.lstrip("-").rstrip("LlUu").isdigit():
        # `return (jint) 0;` — synthetic fallthrough from native-obfuscator.
        # Suppress this entirely; previous return already covered the path.
        return
    op = {"i": "IRETURN", "j": "LRETURN", "f": "FRETURN", "d": "DRETURN",
          "l": "ARETURN"}.get(field_for_op, "IRETURN")
    ctx.emit(op=op)


# ---- Patterns ----

CONST_FOLD_OPS = {"ICONST_0": 0, "ICONST_1": 1, "ICONST_2": 2, "ICONST_3": 3,
                  "ICONST_4": 4, "ICONST_5": 5, "ICONST_M1": -1}

JNI_CALL_TO_INVOKE = {
    "CallObjectMethod":   "INVOKEVIRTUAL",
    "CallBooleanMethod":  "INVOKEVIRTUAL",
    "CallByteMethod":     "INVOKEVIRTUAL",
    "CallCharMethod":     "INVOKEVIRTUAL",
    "CallShortMethod":    "INVOKEVIRTUAL",
    "CallIntMethod":      "INVOKEVIRTUAL",
    "CallLongMethod":     "INVOKEVIRTUAL",
    "CallFloatMethod":    "INVOKEVIRTUAL",
    "CallDoubleMethod":   "INVOKEVIRTUAL",
    "CallVoidMethod":     "INVOKEVIRTUAL",
    "CallStaticObjectMethod":  "INVOKESTATIC",
    "CallStaticBooleanMethod": "INVOKESTATIC",
    "CallStaticByteMethod":    "INVOKESTATIC",
    "CallStaticCharMethod":    "INVOKESTATIC",
    "CallStaticShortMethod":   "INVOKESTATIC",
    "CallStaticIntMethod":     "INVOKESTATIC",
    "CallStaticLongMethod":    "INVOKESTATIC",
    "CallStaticVoidMethod":    "INVOKESTATIC",
    "CallNonvirtualObjectMethod":  "INVOKESPECIAL",
    "CallNonvirtualVoidMethod":    "INVOKESPECIAL",
}

JNI_FIELD_GET = {
    "GetObjectField":  "GETFIELD",
    "GetBooleanField": "GETFIELD",
    "GetByteField":    "GETFIELD",
    "GetCharField":    "GETFIELD",
    "GetShortField":   "GETFIELD",
    "GetIntField":     "GETFIELD",
    "GetLongField":    "GETFIELD",
    "GetFloatField":   "GETFIELD",
    "GetDoubleField":  "GETFIELD",
    "GetStaticObjectField":  "GETSTATIC",
    "GetStaticBooleanField": "GETSTATIC",
    "GetStaticIntField":     "GETSTATIC",
    "GetStaticLongField":    "GETSTATIC",
}

JNI_FIELD_SET = {
    "SetObjectField":  "PUTFIELD",
    "SetBooleanField": "PUTFIELD",
    "SetByteField":    "PUTFIELD",
    "SetCharField":    "PUTFIELD",
    "SetShortField":   "PUTFIELD",
    "SetIntField":     "PUTFIELD",
    "SetLongField":    "PUTFIELD",
    "SetFloatField":   "PUTFIELD",
    "SetDoubleField":  "PUTFIELD",
    "SetStaticObjectField":  "PUTSTATIC",
    "SetStaticIntField":     "PUTSTATIC",
}


def match_assignment(node: tree_sitter.Node, source: bytes, ctx: MatchContext) -> None:
    lhs = node.child_by_field_name("left")
    rhs = node.child_by_field_name("right")
    if lhs is None or rhs is None:
        return
    lhs_text = text(lhs, source)
    rhs_text = text(rhs, source).strip()

    lhs_slot = parse_slot(lhs_text)
    rhs_slot = parse_slot(rhs_text)

    # local <-> stack moves: ISTORE / ILOAD
    if lhs_slot and rhs_slot:
        if lhs_slot.table == "local" and rhs_slot.table == "stack":
            ctx.emit(op=_xstore(lhs_slot.field), **{"var": lhs_slot.index})
            return
        if lhs_slot.table == "stack" and rhs_slot.table == "local":
            ctx.emit(op=_xload(rhs_slot.field), **{"var": rhs_slot.index})
            return

    # Constant assignments: cstack[N].i = 3;
    if lhs_slot and rhs.type == "number_literal":
        v = rhs_text
        try:
            val = int(v.rstrip("LlUu"), 0)
        except ValueError:
            try:
                val = float(v)
                ctx.emit(op="LDC", value=val)
                return
            except ValueError:
                return
        if lhs_slot.field == "i":
            if -1 <= val <= 5:
                ctx.emit(op=f"ICONST_{'M1' if val == -1 else val}")
            elif -128 <= val < 128:
                ctx.emit(op="BIPUSH", value=val)
            elif -32768 <= val < 32768:
                ctx.emit(op="SIPUSH", value=val)
            else:
                ctx.emit(op="LDC", value=val)
        elif lhs_slot.field == "j":
            ctx.emit(op="LDC", value=val, desc="long")
        elif lhs_slot.field == "f":
            ctx.emit(op="LDC", value=val, desc="float")
        elif lhs_slot.field == "d":
            ctx.emit(op="LDC", value=val, desc="double")
        return

    # Type conversion: cstack0.d = (jdouble) cstack0.i;
    # Stack-slot copy (DUP family): cstack1 = cstack0;  (no .field on either side)
    if lhs_slot and rhs.type == "cast_expression":
        inner = rhs.child_by_field_name("value")
        if inner is not None:
            inner_slot = parse_slot(text(inner, source))
            if inner_slot is not None:
                op = CAST_TO_OP.get((inner_slot.field, lhs_slot.field))
                if op is not None:
                    ctx.emit(op=op)
                    return
                # Cast that doesn't change the field type is a no-op at the
                # bytecode level (just a narrowing in C).

    # DUP-style: `cstackN = cstackM;` (full jvalue copy, no field selector).
    if (
        rhs.type == "identifier"
        and lhs.type == "identifier"
        and re.fullmatch(r"cstack\d+", text(lhs, source))
        and re.fullmatch(r"cstack\d+", rhs_text)
    ):
        ctx.emit(op="DUP")
        return

    # Arithmetic: cstack[N].i = cstack[N].i + cstack[N+1].i;
    if lhs_slot and rhs.type == "binary_expression":
        left = rhs.child_by_field_name("left")
        right = rhs.child_by_field_name("right")
        op_node = next((c for c in rhs.children if c.type in {"+", "-", "*", "/", "%", "<<", ">>", "&", "|", "^"}), None)
        if left is None or right is None or op_node is None:
            return
        op = source[op_node.start_byte:op_node.end_byte].decode()
        ls = parse_slot(text(left, source))
        rs = parse_slot(text(right, source))
        if ls and rs:
            ctx.emit(op=_arith_op(op, lhs_slot.field))
            return

    # JNI field get: cstack[N].x = env->GetXxxField(...)
    if lhs_slot and rhs.type == "call_expression":
        match_field_get(rhs, source, ctx)
        return

    # cstack[N].l = (jstring) cstrings[K]; → LDC string K
    if lhs_slot and "cstrings" in rhs_text:
        m = re.search(r"cstrings\[(\d+)\]", rhs_text)
        if m:
            idx = int(m.group(1))
            entries = ctx.lookups.get("cstrings") or []
            if idx < len(entries):
                e = entries[idx]
                lit = e.get("value") if isinstance(e, dict) else e
                ctx.emit(op="LDC", value=lit)
            else:
                ctx.emit(op="LDC", value=f"<cstrings[{idx}]>")
            return


def match_field_get(call: tree_sitter.Node, source: bytes, ctx: MatchContext) -> None:
    callee = call.child_by_field_name("function")
    if callee is None or callee.type != "field_expression":
        return
    member = callee.child_by_field_name("field")
    if member is None:
        return
    name = text(member, source)
    jvm = JNI_FIELD_GET.get(name)
    if not jvm:
        return
    args = _call_args(call, source)
    # In env->GetXxxField(recv_or_class, fieldID), `env` is implicit (it's the
    # field_expression base), so args list is [recv_or_class, fieldID].
    if len(args) < 2:
        return
    field_idx = parse_table_ref(args[1])
    if field_idx and field_idx[0] == "cfields" and ctx.lookups.get("cfields"):
        e = ctx.lookups["cfields"][field_idx[1]]
        ctx.emit(op=jvm, owner=e.get("owner"), name=e.get("name"), desc=e.get("desc"))
    else:
        ctx.emit(op=jvm)


def match_void_call(call: tree_sitter.Node, source: bytes, ctx: MatchContext) -> None:
    callee = call.child_by_field_name("function")
    if callee is None or callee.type != "field_expression":
        return
    member = callee.child_by_field_name("field")
    if member is None:
        return
    name = text(member, source)
    args = _call_args(call, source)
    invoke = JNI_CALL_TO_INVOKE.get(name)
    if invoke:
        # env->Call*Method(recv_or_class, methodID, ...) — args = [recv, mid, ...]
        if len(args) < 2:
            return
        # CallNonvirtual* has an extra `class` arg between recv and mid.
        mid_idx = 2 if name.startswith("CallNonvirtual") else 1
        if mid_idx >= len(args):
            return
        mid = parse_table_ref(args[mid_idx])
        if mid and mid[0] == "cmethods" and ctx.lookups.get("cmethods"):
            e = ctx.lookups["cmethods"][mid[1]]
            ctx.emit(op=invoke, owner=e.get("owner"), name=e.get("name"), desc=e.get("desc"))
        else:
            ctx.emit(op=invoke)
        return

    setter = JNI_FIELD_SET.get(name)
    if setter:
        # env->SetXxxField(recv_or_class, fieldID, value) — args = [recv, fid, val]
        if len(args) < 3:
            return
        fid = parse_table_ref(args[1])
        if fid and fid[0] == "cfields" and ctx.lookups.get("cfields"):
            e = ctx.lookups["cfields"][fid[1]]
            ctx.emit(op=setter, owner=e.get("owner"), name=e.get("name"), desc=e.get("desc"))
        else:
            ctx.emit(op=setter)
        return

    if name in ("Throw", "ThrowNew"):
        ctx.emit(op="ATHROW")


def match_alloc_object(call: tree_sitter.Node, source: bytes, ctx: MatchContext) -> None:
    """`env->AllocObject((cclasses[K]))` → NEW <class>. Native-obfuscator
    always wraps this in an `if (jobject obj = ...)` to handle the null-on-OOM
    case; we don't care about the wrapper, only the AllocObject call."""
    callee = call.child_by_field_name("function")
    if callee is None or callee.type != "field_expression":
        return
    member = callee.child_by_field_name("field")
    if member is None or text(member, source) != "AllocObject":
        return
    args = _call_args(call, source)
    if not args:
        return
    cls_ref = parse_table_ref(args[0])
    if cls_ref and cls_ref[0] == "cclasses" and ctx.lookups.get("cclasses"):
        e = ctx.lookups["cclasses"][cls_ref[1]]
        cls_name = e.get("internalName") or e.get("name") if isinstance(e, dict) else str(e)
        ctx.emit(op="NEW", type=cls_name)
    else:
        ctx.emit(op="NEW", type="?")


# ---- Type conversions inside assignment RHS ----

CAST_TO_OP = {
    # source field -> target field
    ("i", "j"): "I2L", ("i", "f"): "I2F", ("i", "d"): "I2D",
    ("j", "i"): "L2I", ("j", "f"): "L2F", ("j", "d"): "L2D",
    ("f", "i"): "F2I", ("f", "j"): "F2L", ("f", "d"): "F2D",
    ("d", "i"): "D2I", ("d", "j"): "D2L", ("d", "f"): "D2F",
}


def match_if(node: tree_sitter.Node, source: bytes, ctx: MatchContext) -> bool:
    """Match `if (cstack...<rel>...) goto L;` shape, emit IF_*. Returns True
    iff the consequence branch was consumed (caller skips it during recursion).
    """
    cond = node.child_by_field_name("condition")
    if cond is None or cond.type != "parenthesized_expression":
        return False
    inner = next((c for c in cond.children if c.type != "(" and c.type != ")"), None)
    if inner is None or inner.type != "binary_expression":
        return False
    op_node = next((c for c in inner.children if c.type in {"==", "!=", "<", "<=", ">", ">="}), None)
    if op_node is None:
        return False
    op = text(op_node, source)
    left_text = text(inner.children[0], source).strip()
    right_text = text(inner.children[-1], source).strip()
    consequence = node.child_by_field_name("consequence")
    target = None
    if consequence is not None:
        for g in find_descendants(consequence, "goto_statement"):
            for c in g.children:
                if c.type == "statement_identifier":
                    label_name = text(c, source)
                    if re.fullmatch(r"L\d+", label_name):
                        target = label_name
                        break
            if target:
                break
    if target is None:
        return False
    # Distinguish IFEQ-vs-zero (single-operand compare to 0/null) from
    # IF_ICMPxx (two-operand compare).
    is_zero_cmp = right_text in ("0", "(jint) 0", "nullptr", "NULL")
    if is_zero_cmp:
        op_map_zero = {"==": "IFEQ", "!=": "IFNE", "<": "IFLT",
                       "<=": "IFLE", ">": "IFGT", ">=": "IFGE"}
        ctx.emit(op=op_map_zero.get(op, "IFEQ"), target=target)
    else:
        op_map = {"==": "IF_ICMPEQ", "!=": "IF_ICMPNE", "<": "IF_ICMPLT",
                  "<=": "IF_ICMPLE", ">": "IF_ICMPGT", ">=": "IF_ICMPGE"}
        ctx.emit(op=op_map.get(op, "IF_ICMPEQ"), target=target)
    return True


def _call_args(call: tree_sitter.Node, source: bytes) -> list[str]:
    arg_list = call.child_by_field_name("arguments")
    if arg_list is None:
        return []
    out: list[str] = []
    for c in arg_list.children:
        if c.type in {"(", ")", ","}:
            continue
        out.append(text(c, source).strip())
    return out


def _xload(field: str) -> str:
    return {"i": "ILOAD", "j": "LLOAD", "f": "FLOAD", "d": "DLOAD", "l": "ALOAD"}[field]


def _xstore(field: str) -> str:
    return {"i": "ISTORE", "j": "LSTORE", "f": "FSTORE", "d": "DSTORE", "l": "ASTORE"}[field]


def _arith_op(op: str, t: str) -> str:
    type_prefix = {"i": "I", "j": "L", "f": "F", "d": "D"}.get(t, "I")
    name = {
        "+": "ADD", "-": "SUB", "*": "MUL", "/": "DIV", "%": "REM",
        "<<": "SHL", ">>": "SHR", "&": "AND", "|": "OR", "^": "XOR",
    }[op]
    return f"{type_prefix}{name}"


# ------------------------------------------------------------------
# Entrypoint
# ------------------------------------------------------------------

def lift_ghidra_dump(
    ghidra_json_path: Path,
    manifest_path: Path | None = None,
    *,
    options=None,
    profile_name: str | None = None,
) -> list[dict[str, Any]]:
    """Lift a ghidra-dump.json into recovered/*.json entries via the
    :mod:`ast_matcher.lifter` package. ``options`` controls per-feature
    on/off flags; ``profile_name`` selects an obfuscator profile (auto
    when omitted).

    Entries without explicit ``(owner, methodName, methodDesc)`` are
    routed through the cstack/clocal AST matcher in :func:`lift_function`
    — that path is for legacy .cpp-source inputs, not Ghidra dumps.
    """
    from .lifter import lift_ghidra_dump as _lift
    return _lift(ghidra_json_path, manifest_path,
                 options=options, profile_name=profile_name)


def lift_function_with_lookups(
    func_code: str, lookups: dict[str, list[dict[str, Any]]]
) -> dict[str, Any]:
    """Variant of :func:`lift_function` that takes pre-populated
    ``cstrings`` / ``cmethods`` / ``cfields`` / ``cclasses`` lookup
    tables. Used for ``.cpp`` source lifts (where the obfuscator's
    cstack/clocal naming is preserved) and as a fallback inside
    Ghidra-dump processing when no per-class lookups are bound.
    """
    ctx = MatchContext(lookups=lookups)
    tree = parse(func_code)
    source = func_code.encode("utf-8")
    func_body = None
    for n in find_descendants(tree.root_node, "function_definition"):
        for c in n.children:
            if c.type == "compound_statement":
                func_body = c
                break
        if func_body:
            break
    if func_body is None:
        ctx.warnings.append("no function_definition found")
        return _result(ctx)
    walk(func_body, source, ctx)
    return _result(ctx)


def _split_symbol(symbol: str) -> tuple[str, str, str]:
    # Best-effort: "__ngen_com_example_Foo_bar" → ("?", "bar", "?")
    if not symbol.startswith("__ngen_"):
        return ("?", symbol, "?")
    tail = symbol[len("__ngen_"):]
    parts = tail.split("_")
    return ("/".join(parts[:-1]) if len(parts) > 1 else "?", parts[-1], "?")


# ------------------------------------------------------------------
# Direct .cpp file lifter (for native-obfuscator output)
# ------------------------------------------------------------------

# Match the function signature of a native-obfuscator emitted JNI method:
#     <ret> JNICALL __ngen_native_<name><id>(JNIEnv *env, jobject obj, ...)
# Captures: jvm_return_type / name / params-string
_FUNC_SIG_RE = re.compile(
    r"^\s*(?P<ret>j\w+|void)\s+JNICALL\s+(?P<sym>__ngen_native_\w+)\s*\((?P<params>[^)]*)\)\s*\{",
    re.MULTILINE,
)

# Pull (name, classId) out of __ngen_native_<methodName><id>. The number suffix
# is the classId index; bridging to (owner, name, desc) needs the manifest.
_NGEN_NAME_RE = re.compile(r"^__ngen_native_(?P<name>[A-Za-z_$][A-Za-z0-9_$]*?)(?P<id>\d+)$")

_JNI_TO_JVM_PARAM = {
    "jboolean": "Z", "jbyte": "B", "jchar": "C", "jshort": "S",
    "jint": "I", "jlong": "J", "jfloat": "F", "jdouble": "D",
    "jobject": "Ljava/lang/Object;", "jstring": "Ljava/lang/String;",
    "jclass": "Ljava/lang/Class;",
    "jbooleanArray": "[Z", "jbyteArray": "[B", "jcharArray": "[C",
    "jshortArray": "[S", "jintArray": "[I", "jlongArray": "[J",
    "jfloatArray": "[F", "jdoubleArray": "[D", "jobjectArray": "[Ljava/lang/Object;",
    "void": "V",
}


def _split_top_level(s: str) -> list[str]:
    """Split a comma-separated argument list, respecting parens."""
    out: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in s:
        if ch in "([{<": depth += 1
        elif ch in ")]}>": depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        out.append(tail)
    return out


def _params_to_desc(params_text: str, is_static_hint: bool) -> tuple[str, bool]:
    """Convert a C param list (`JNIEnv *env, jobject obj, jint a, jint b`) into
    a JVM method descriptor. The first two args are always JNIEnv/this-or-class.
    Returns (desc, is_static): is_static iff the 2nd arg type is `jclass`."""
    parts = _split_top_level(params_text)
    if len(parts) < 2:
        return ("()V", is_static_hint)
    # Drop JNIEnv*
    parts = parts[1:]
    # Look at receiver type
    is_static = parts[0].lstrip().split()[0].rstrip("*").strip() == "jclass"
    parts = parts[1:]
    jvm_params: list[str] = []
    for p in parts:
        tokens = p.strip().rstrip("*").split()
        if not tokens:
            continue
        ty = tokens[0]
        jvm_params.append(_JNI_TO_JVM_PARAM.get(ty, "Ljava/lang/Object;"))
    return ("(" + "".join(jvm_params) + ")V", is_static)


def _scan_functions(cpp_source: str) -> list[dict[str, str]]:
    """Find each native-obfuscator-style JNI function in cpp_source. Returns
    a list of {sym, ret, params, body} dicts. body is everything between the
    opening { and the matching close }."""
    out: list[dict[str, str]] = []
    for m in _FUNC_SIG_RE.finditer(cpp_source):
        sig_end = m.end()
        depth = 1
        i = sig_end
        while i < len(cpp_source) and depth > 0:
            if cpp_source[i] == "{": depth += 1
            elif cpp_source[i] == "}": depth -= 1
            i += 1
        body = cpp_source[sig_end:i - 1]  # exclude closing }
        # Build a synthetic single-function unit the tree-sitter parser can ingest.
        synth = m.group(0) + body + "\n}"
        out.append({
            "sym": m.group("sym"),
            "ret": m.group("ret"),
            "params": m.group("params"),
            "body": body,
            "synth": synth,
        })
    return out


def _resolve_owner_desc(sym: str, manifest: dict | None) -> tuple[str, str, str]:
    """Resolve (owner, name, desc) for a __ngen_native_<name><id> symbol via
    the manifest's per-class fn symbol table (when present). Falls back to
    a best-effort split if manifest is missing."""
    nm = _NGEN_NAME_RE.match(sym)
    if not nm:
        return ("?", sym, "?")
    plain_name = nm.group("name")
    if manifest:
        for cls in manifest.get("classes", []):
            for m in cls.get("methods", []):
                if (m.get("fnSymbol") or "").endswith(sym):
                    return (cls["name"], m["name"], m["desc"])
    return ("?", plain_name, "?")


def lift_cpp_file(cpp_path: Path, manifest_path: Path | None = None) -> list[dict[str, Any]]:
    """Lift every JNI method body in a native-obfuscator-emitted .cpp file.
    Designed for testing the lifter against the obfuscator's own output where
    the JVM bytecode operations are present as `// <OP>; Stack: N` comments."""
    code = cpp_path.read_text(encoding="utf-8", errors="replace")
    manifest = (
        json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest_path is not None else None
    )
    funcs = _scan_functions(code)
    out: list[dict[str, Any]] = []
    for f in funcs:
        result = lift_function(f["synth"])
        owner, name, desc_from_manifest = _resolve_owner_desc(f["sym"], manifest)
        # Fall back to a desc derived from the C param list when manifest
        # didn't carry one.
        derived_desc, _static = _params_to_desc(f["params"], is_static_hint=False)
        # When we have a return type and the derived desc says (...)V, splice
        # the return in.
        ret_token = (f["ret"] or "void").lstrip()
        jvm_ret = _JNI_TO_JVM_PARAM.get(ret_token, "V")
        if derived_desc.endswith(")V") and jvm_ret != "V":
            derived_desc = derived_desc[:-1] + jvm_ret
        desc = desc_from_manifest if desc_from_manifest != "?" else derived_desc
        out.append({
            "schemaVersion": 1,
            "owner": owner,
            "name": name,
            "desc": desc,
            "source": "static",
            "confidence": "medium" if owner != "?" else "low",
            "instructions": result["instructions"],
            "warnings": result["warnings"],
            "symbol": f["sym"],
        })
    return out
