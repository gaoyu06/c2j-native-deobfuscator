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
    if node.type == "assignment_expression":
        match_assignment(node, source, ctx)
    elif node.type == "expression_statement":
        # peek at the inner expression
        inner = node.children[0] if node.children else None
        if inner is not None and inner.type == "call_expression":
            match_void_call(inner, source, ctx)
    elif node.type == "if_statement":
        match_if(node, source, ctx)
    elif node.type == "return_statement":
        ctx.emit(op="RETURN")  # void return — the caller corrects to the right TRETURN later
        return
    for c in node.children:
        walk(c, source, ctx)


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
        if m and ctx.lookups.get("cstrings"):
            idx = int(m.group(1))
            entries = ctx.lookups["cstrings"]
            if idx < len(entries):
                e = entries[idx]
                lit = e.get("value") if isinstance(e, dict) else e
                ctx.emit(op="LDC", value=lit)
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
        mid = parse_table_ref(args[1])
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


def match_if(node: tree_sitter.Node, source: bytes, ctx: MatchContext) -> None:
    # Translate `if (cstack[N].i == cstack[M].i) goto L_x;` shape into
    # IF_ICMPEQ target=L_x.  Recovering full control-flow is out of scope
    # for this lifter; we emit a placeholder that downstream class-rebuilder
    # can interpret.
    cond = node.child_by_field_name("condition")
    if cond is None or cond.type != "parenthesized_expression":
        return
    inner = next((c for c in cond.children if c.type != "(" and c.type != ")"), None)
    if inner is None or inner.type != "binary_expression":
        return
    op_node = next((c for c in inner.children if c.type in {"==", "!=", "<", "<=", ">", ">="}), None)
    if op_node is None:
        return
    op = text(op_node, source)
    consequence = node.child_by_field_name("consequence")
    target = None
    if consequence is not None:
        for g in find_descendants(consequence, "goto_statement"):
            for c in g.children:
                if c.type == "statement_identifier":
                    target = text(c, source)
                    break
            if target:
                break
    if target is None:
        return
    op_map = {"==": "IF_ICMPEQ", "!=": "IF_ICMPNE", "<": "IF_ICMPLT",
              "<=": "IF_ICMPLE", ">": "IF_ICMPGT", ">=": "IF_ICMPGE"}
    ctx.emit(op=op_map.get(op, "IFEQ"), target=target)


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

def lift_ghidra_dump(ghidra_json_path: Path, manifest_path: Path | None = None) -> list[dict[str, Any]]:
    data = json.loads(ghidra_json_path.read_text(encoding="utf-8"))
    out: list[dict[str, Any]] = []
    for entry in data.get("functions", []):
        code = entry.get("code", "")
        if not code:
            continue
        result = lift_function(code)
        # Heuristically extract (owner, name, desc) from the function symbol if
        # the script generated it as `__ngen_<class>_<method>`.
        owner, name, desc = _split_symbol(entry["name"])
        out.append({
            "schemaVersion": 1,
            "owner": owner,
            "name": name,
            "desc": desc,
            "source": "static",
            "confidence": "low",
            "instructions": result["instructions"],
            "warnings": result["warnings"],
            "ghidraAddr": entry.get("addr"),
        })
    return out


def _split_symbol(symbol: str) -> tuple[str, str, str]:
    # Best-effort: "__ngen_com_example_Foo_bar" → ("?", "bar", "?")
    if not symbol.startswith("__ngen_"):
        return ("?", symbol, "?")
    tail = symbol[len("__ngen_"):]
    parts = tail.split("_")
    return ("/".join(parts[:-1]) if len(parts) > 1 else "?", parts[-1], "?")
