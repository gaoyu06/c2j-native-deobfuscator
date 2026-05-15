"""Driver: walks a decompiled function body and emits JVM instructions.

The driver is feature-flag-gated via :class:`LifterOptions`; every
inference / matching heuristic can be disabled independently to
diagnose mis-lifted code.

Profile-specific behavior is delegated to:

  - :class:`InvokeHintParser` for ``"Cannot invoke X.Y.Z(args)"`` parsing
  - :class:`IfGuardMatcher` for native-side ``ExceptionCheck`` skip

ABI-specific behavior is handled at the disassembly layer
(:mod:`binary_introspect.jni_tables`); the driver doesn't touch
machine code directly.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tree_sitter
import tree_sitter_c

from binary_introspect.profile import Profile, detect_profile, get_profile

from .options import LifterOptions
from .syms import Sym, SymClass, SymFieldId, SymMethodId, SymObject, SymStringLit
from .throw_reason import FieldHint, FieldHintParser, InvokeHint, InvokeHintParser
from .if_guard import IfGuardMatcher
from . import jni_call


# --------------------------------------------------------------------
# tree-sitter setup
# --------------------------------------------------------------------

_LANG = tree_sitter.Language(tree_sitter_c.language())
_PARSER = tree_sitter.Parser(_LANG)


def _parse(code: str) -> tree_sitter.Tree:
    return _PARSER.parse(code.encode("utf-8"))


def _text(node: tree_sitter.Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _find_descendants(node: tree_sitter.Node, kind: str):
    if node.type == kind:
        yield node
    for c in node.children:
        yield from _find_descendants(c, kind)


# --------------------------------------------------------------------
# Driver state
# --------------------------------------------------------------------

@dataclass
class _Ctx:
    options: LifterOptions
    profile: Profile
    invoke_hints: list[InvokeHint]
    invoke_hint_idx: int = 0
    field_hints: list[FieldHint] = field(default_factory=list)
    field_hint_idx: int = 0
    if_guard: IfGuardMatcher | None = None

    instructions: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    syms: dict[str, Sym] = field(default_factory=dict)
    pool: dict[int, str] = field(default_factory=dict)
    lookups: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    method_owner: str = "?"
    method_desc: str = "()V"
    #: Map of field-name -> JVM descriptor for fields declared on
    #: ``method_owner`` and any other classes we have manifest entries
    #: for. Used to fill descriptors on hint-resolved GETFIELD/PUTFIELD.
    field_descs: dict[str, str] = field(default_factory=dict)

    def emit(self, **kw: Any) -> None:
        self.instructions.append({k: v for k, v in kw.items() if v is not None})

    def next_invoke_hint(self, jni_ret_letter: str) -> tuple[str, str, str] | None:
        if not self.options.use_throw_reason_invoke_hints:
            return None
        if self.invoke_hint_idx >= len(self.invoke_hints):
            return None
        hint = self.invoke_hints[self.invoke_hint_idx]
        self.invoke_hint_idx += 1
        args_part = hint.void_desc.rsplit(")V", 1)[0] + ")"
        if self.options.force_init_void_return and hint.name == "<init>":
            ret_desc = "V"
        elif jni_ret_letter in ("I", "J", "F", "D", "Z", "B", "C", "S", "V"):
            ret_desc = jni_ret_letter
        elif jni_ret_letter == "L":
            ret_desc = "Ljava/lang/Object;"
        else:
            ret_desc = "Ljava/lang/Object;"
        return hint.owner, hint.name, args_part + ret_desc

    def next_field_hint(self, op: str) -> tuple[str, str, str] | None:
        """Return ``(owner, name, desc)`` for the next field-error hint
        whose ``op`` matches (``"read"`` for getfield/getstatic,
        ``"assign"`` for the put-flavours). Returns ``None`` when no
        further matching hint exists or the feature is disabled."""
        if not self.options.use_throw_reason_field_hints:
            return None
        while self.field_hint_idx < len(self.field_hints):
            hint = self.field_hints[self.field_hint_idx]
            self.field_hint_idx += 1
            if hint.op != op:
                continue
            desc = self.field_descs.get(hint.name) or "L?;"
            return self.method_owner, hint.name, desc
        return None


# --------------------------------------------------------------------
# Argument-expression resolution
# --------------------------------------------------------------------

_JNI_CALL = re.compile(r"(?P<recv>\w+)\s*->\s*(?P<fn>\w+)\s*\(")

# `**(longlong **)PTR_X + 0x2556`  /  `string_pool + 0x14a`
_POOL_OFFSET = re.compile(
    r"(?:\*+\([a-z]+\s*\*+\)\s*PTR_\w+|\bstring_pool|\bPTR_\w+)"
    r"\s*\+\s*(0x[0-9a-fA-F]+|\d+)"
)


def _extract_pool_offset(expr: str) -> int | None:
    m = _POOL_OFFSET.search(expr.replace("\n", " "))
    if not m:
        return None
    off = m.group(1)
    return int(off, 16) if off.startswith("0x") else int(off)


def _is_string_literal(expr: str) -> str | None:
    s = expr.strip()
    if s.startswith('"') and s.endswith('"'):
        try:
            return bytes(s[1:-1], "ascii").decode("unicode_escape")
        except UnicodeDecodeError:
            return s[1:-1]
    return None


def _split_call_args(args_text: str) -> list[str]:
    out: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in args_text:
        if ch in "([{": depth += 1
        elif ch in ")]}": depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail: out.append(tail)
    return out


def _extract_jni_call(expr: str) -> tuple[str, str, list[str]] | None:
    m = _JNI_CALL.search(expr)
    if not m:
        return None
    start = m.end()
    depth = 1
    i = start
    while i < len(expr) and depth > 0:
        if expr[i] == '(': depth += 1
        elif expr[i] == ')': depth -= 1
        i += 1
    args = _split_call_args(expr[start:i - 1])
    return m.group("recv"), m.group("fn"), args


def _resolve_arg(ctx: _Ctx, arg: str) -> Any:
    """Resolve a call-arg expression to a typed value (Sym subclass /
    str / int) or None if unresolvable."""
    s = arg.strip()
    # Strip simple C casts.
    while s.startswith("(") and ")" in s and " " not in s.split(")", 1)[0]:
        head, _, tail = s[1:].partition(")")
        if re.fullmatch(r"\s*[\w\s*]+\s*", head) and tail:
            s = tail.strip()
        else:
            break

    lit = _is_string_literal(s)
    if lit is not None:
        return SymStringLit(value=lit, source="literal")

    m = re.fullmatch(r"-?(0x[0-9a-fA-F]+|\d+)", s)
    if m:
        return int(m.group(1), 16) if m.group(1).startswith("0x") else int(m.group(1))

    if re.fullmatch(r"\w+", s) and ctx.options.track_symbol_table:
        return ctx.syms.get(s)

    if ctx.options.resolve_string_pool_offsets:
        off = _extract_pool_offset(s)
        if off is not None:
            v = ctx.pool.get(off)
            if v is not None:
                return SymStringLit(value=v, source="literal")

    if ctx.options.resolve_lookup_tables:
        m = re.fullmatch(r"\(?(cstrings|cmethods|cfields|cclasses)\[(\d+)\]\)?", s)
        if m:
            tbl, idx = m.group(1), int(m.group(2))
            entries = ctx.lookups.get(tbl, [])
            if idx < len(entries):
                e = entries[idx]
                if tbl == "cstrings":
                    v = e.get("value") if isinstance(e, dict) else e
                    if v is not None:
                        return SymStringLit(value=v, source="literal")
                elif tbl == "cclasses" and isinstance(e, dict):
                    return SymClass(internal_name=e.get("name") or e.get("internalName"))
                elif tbl == "cmethods" and isinstance(e, dict):
                    return SymMethodId(owner=e.get("owner"), name=e.get("name"),
                                       desc=e.get("desc"))
                elif tbl == "cfields" and isinstance(e, dict):
                    return SymFieldId(owner=e.get("owner"), name=e.get("name"),
                                      desc=e.get("desc"))
    return None


def _emit_push(ctx: _Ctx, value: Any) -> None:
    """Emit a stack-push for a resolved value or placeholder."""
    if isinstance(value, SymStringLit):
        ctx.emit(op="LDC", value=value.value)
        return
    if isinstance(value, SymClass) and value.internal_name:
        ctx.emit(op="LDC", type=value.internal_name)
        return
    if isinstance(value, int):
        if -1 <= value <= 5:
            ctx.emit(op=f"ICONST_{'M1' if value == -1 else value}")
        elif -128 <= value < 128:
            ctx.emit(op="BIPUSH", value=value)
        elif -32768 <= value < 32768:
            ctx.emit(op="SIPUSH", value=value)
        else:
            ctx.emit(op="LDC", value=value)
        return
    if isinstance(value, SymObject):
        ctx.emit(op="ACONST_NULL")
        ctx.emit(op="CHECKCAST",
                 type=(value.desc[1:-1] if value.desc.startswith("L") else value.desc))
        return
    ctx.emit(op="ACONST_NULL")


# --------------------------------------------------------------------
# JNI call dispatch
# --------------------------------------------------------------------

def _handle_call(ctx: _Ctx, fn: str, args: list[str], assign_to: str | None) -> None:
    # `rewrite_vtable_calls` already consumes the leading env identifier when
    # rewriting `(**(code **)(*env + 0xN))(env, ...)`, so for Ghidra-dump input
    # the first arg is already the user-facing first arg. Only strip when the
    # call form actually carried an explicit env (e.g. C-style
    # `(*env)->FindClass(env, "X")` from raw native-obfuscator C++ source).
    real_args = args[1:] if args and args[0].strip() == "env" else args

    # Symbol-creating
    if fn == "FindClass":
        if not real_args: return
        v = _resolve_arg(ctx, real_args[0])
        if isinstance(v, SymStringLit) and assign_to:
            ctx.syms[assign_to] = SymClass(internal_name=v.value)
        return
    if fn in ("GetMethodID", "GetStaticMethodID"):
        if len(real_args) < 3: return
        cls = _resolve_arg(ctx, real_args[0])
        nm  = _resolve_arg(ctx, real_args[1])
        ds  = _resolve_arg(ctx, real_args[2])
        if assign_to:
            ctx.syms[assign_to] = SymMethodId(
                owner=cls.internal_name if isinstance(cls, SymClass) else None,
                name=nm.value if isinstance(nm, SymStringLit) else None,
                desc=ds.value if isinstance(ds, SymStringLit) else None,
            )
        return
    if fn in ("GetFieldID", "GetStaticFieldID"):
        if len(real_args) < 3: return
        cls = _resolve_arg(ctx, real_args[0])
        nm  = _resolve_arg(ctx, real_args[1])
        ds  = _resolve_arg(ctx, real_args[2])
        if assign_to:
            ctx.syms[assign_to] = SymFieldId(
                owner=cls.internal_name if isinstance(cls, SymClass) else None,
                name=nm.value if isinstance(nm, SymStringLit) else None,
                desc=ds.value if isinstance(ds, SymStringLit) else None,
            )
        return
    if fn == "NewStringUTF":
        if not real_args: return
        v = _resolve_arg(ctx, real_args[0])
        if isinstance(v, SymStringLit):
            if assign_to:
                ctx.syms[assign_to] = v
            ctx.emit(op="LDC", value=v.value)
        return
    if fn in ("NewGlobalRef", "NewLocalRef", "NewWeakGlobalRef"):
        if not real_args: return
        src = _resolve_arg(ctx, real_args[0])
        if src is not None and assign_to:
            ctx.syms[assign_to] = src
        return

    # Object production
    if fn == "AllocObject":
        if not real_args: return
        cls = _resolve_arg(ctx, real_args[0])
        if isinstance(cls, SymClass) and cls.internal_name:
            ctx.emit(op="NEW", type=cls.internal_name)
            if assign_to:
                ctx.syms[assign_to] = SymObject(desc=f"L{cls.internal_name};")
        return
    if fn in ("NewObject", "NewObjectV", "NewObjectA"):
        if len(real_args) < 2: return
        cls = _resolve_arg(ctx, real_args[0])
        mid = _resolve_arg(ctx, real_args[1])
        if isinstance(cls, SymClass) and cls.internal_name:
            ctx.emit(op="NEW", type=cls.internal_name)
            ctx.emit(op="DUP")
            for a in real_args[2:]:
                _emit_push(ctx, _resolve_arg(ctx, a))
            if isinstance(mid, SymMethodId) and mid.owner:
                ctx.emit(op="INVOKESPECIAL", owner=mid.owner,
                         name=mid.name or "<init>", desc=mid.desc or "()V")
            if assign_to:
                ctx.syms[assign_to] = SymObject(desc=f"L{cls.internal_name};")
        return
    if fn in jni_call.NEWARRAY_PRIM_KIND:
        if not real_args: return
        _emit_push(ctx, _resolve_arg(ctx, real_args[0]))
        atype, elem_desc = jni_call.NEWARRAY_PRIM_KIND[fn]
        ctx.emit(op="NEWARRAY", value=atype)
        if assign_to:
            ctx.syms[assign_to] = SymObject(desc=elem_desc)
        return
    if fn == "NewObjectArray":
        if len(real_args) < 2: return
        _emit_push(ctx, _resolve_arg(ctx, real_args[0]))
        cls = _resolve_arg(ctx, real_args[1])
        if isinstance(cls, SymClass) and cls.internal_name:
            ctx.emit(op="ANEWARRAY", type=cls.internal_name)
            if assign_to:
                ctx.syms[assign_to] = SymObject(desc=f"[L{cls.internal_name};")
        return

    # Field access
    if fn in jni_call.GET_FIELD_NAMES:
        if len(real_args) < 2: return
        _emit_push(ctx, _resolve_arg(ctx, real_args[0]))
        fid = _resolve_arg(ctx, real_args[1])
        if isinstance(fid, SymFieldId) and fid.owner and fid.name and fid.desc:
            ctx.emit(op="GETFIELD", owner=fid.owner, name=fid.name, desc=fid.desc)
            if assign_to:
                ctx.syms[assign_to] = SymObject(desc=fid.desc)
        else:
            hint = ctx.next_field_hint("read")
            if hint:
                owner, name, desc = hint
                ctx.emit(op="GETFIELD", owner=owner, name=name, desc=desc)
                if assign_to and desc != "L?;":
                    ctx.syms[assign_to] = SymObject(desc=desc)
            else:
                ctx.emit(op="GETFIELD", owner="?", name="?", desc="L?;")
        return
    if fn in jni_call.GET_STATIC_FIELD_NAMES:
        if len(real_args) < 2: return
        fid = _resolve_arg(ctx, real_args[1])
        if isinstance(fid, SymFieldId) and fid.owner and fid.name and fid.desc:
            ctx.emit(op="GETSTATIC", owner=fid.owner, name=fid.name, desc=fid.desc)
            if assign_to:
                ctx.syms[assign_to] = SymObject(desc=fid.desc)
        else:
            hint = ctx.next_field_hint("read")
            if hint:
                owner, name, desc = hint
                ctx.emit(op="GETSTATIC", owner=owner, name=name, desc=desc)
                if assign_to and desc != "L?;":
                    ctx.syms[assign_to] = SymObject(desc=desc)
            else:
                ctx.emit(op="GETSTATIC", owner="?", name="?", desc="L?;")
        return
    if fn in jni_call.SET_FIELD_NAMES:
        if len(real_args) < 3: return
        _emit_push(ctx, _resolve_arg(ctx, real_args[0]))
        _emit_push(ctx, _resolve_arg(ctx, real_args[2]))
        fid = _resolve_arg(ctx, real_args[1])
        if isinstance(fid, SymFieldId) and fid.owner and fid.name and fid.desc:
            ctx.emit(op="PUTFIELD", owner=fid.owner, name=fid.name, desc=fid.desc)
        else:
            hint = ctx.next_field_hint("assign")
            if hint:
                owner, name, desc = hint
                ctx.emit(op="PUTFIELD", owner=owner, name=name, desc=desc)
            else:
                ctx.emit(op="PUTFIELD", owner="?", name="?", desc="L?;")
        return
    if fn in jni_call.SET_STATIC_FIELD_NAMES:
        if len(real_args) < 3: return
        _emit_push(ctx, _resolve_arg(ctx, real_args[2]))
        fid = _resolve_arg(ctx, real_args[1])
        if isinstance(fid, SymFieldId) and fid.owner and fid.name and fid.desc:
            ctx.emit(op="PUTSTATIC", owner=fid.owner, name=fid.name, desc=fid.desc)
        else:
            hint = ctx.next_field_hint("assign")
            if hint:
                owner, name, desc = hint
                ctx.emit(op="PUTSTATIC", owner=owner, name=name, desc=desc)
            else:
                ctx.emit(op="PUTSTATIC", owner="?", name="?", desc="L?;")
        return

    # Method invocation
    invoke = jni_call.INVOKE_OP.get(fn)
    if invoke is not None:
        if invoke == "INVOKESPECIAL":
            recv_idx, mid_idx, vararg_start = 0, 2, 3
        elif invoke == "INVOKESTATIC":
            recv_idx, mid_idx, vararg_start = None, 1, 2
        else:
            recv_idx, mid_idx, vararg_start = 0, 1, 2

        if recv_idx is not None:
            v = _resolve_arg(ctx, real_args[recv_idx]) if recv_idx < len(real_args) else None
            _emit_push(ctx, v)
        if mid_idx >= len(real_args):
            return
        mid = _resolve_arg(ctx, real_args[mid_idx])
        for a in real_args[vararg_start:]:
            _emit_push(ctx, _resolve_arg(ctx, a))

        ret_letter = jni_call.ret_letter_for_jni_call(fn)
        if isinstance(mid, SymMethodId) and mid.owner and mid.name and mid.desc:
            ctx.emit(op=invoke, owner=mid.owner, name=mid.name, desc=mid.desc)
            if assign_to:
                ret = mid.desc.rsplit(")", 1)[-1]
                if ret.startswith(("L", "[")):
                    ctx.syms[assign_to] = SymObject(desc=ret)
        else:
            hint = ctx.next_invoke_hint(ret_letter)
            if hint:
                owner, name, desc = hint
                ctx.emit(op=invoke, owner=owner, name=name, desc=desc)
                if assign_to and ret_letter == "L":
                    ret = desc.rsplit(")", 1)[-1]
                    ctx.syms[assign_to] = SymObject(desc=ret)
            else:
                ctx.emit(op=invoke, owner="?", name="?", desc="()V")
        return

    # Throw / ExceptionCheck
    if fn in ("Throw", "ThrowNew"):
        ctx.emit(op="ATHROW")
        return
    # ExceptionCheck and other untracked JNI fns are silently swallowed.


# --------------------------------------------------------------------
# Statement walker
# --------------------------------------------------------------------

def _walk_stmt(ctx: _Ctx, node: tree_sitter.Node, source: bytes) -> None:
    t = node.type
    if t == "labeled_statement":
        label_id = next(
            (_text(c, source) for c in node.children if c.type == "statement_identifier"),
            None,
        )
        if label_id is not None and re.fullmatch(r"(L|LAB_)\w+", label_id):
            ctx.emit(op="LABEL", label=label_id)
        for c in node.children:
            if c.type not in ("statement_identifier", ":"):
                _walk_stmt(ctx, c, source)
        return
    if t == "goto_statement":
        for c in node.children:
            if c.type == "statement_identifier":
                ctx.emit(op="GOTO", target=_text(c, source))
                return
        return
    if t == "assignment_expression":
        lhs = node.child_by_field_name("left")
        rhs = node.child_by_field_name("right")
        if lhs is not None and rhs is not None:
            _handle_rhs(ctx, _text(lhs, source).strip(), _text(rhs, source).strip())
        return
    if t == "expression_statement":
        if not node.children:
            return
        inner = node.children[0]
        if inner.type == "assignment_expression":
            lhs = inner.child_by_field_name("left")
            rhs = inner.child_by_field_name("right")
            if lhs is not None and rhs is not None:
                _handle_rhs(ctx, _text(lhs, source).strip(), _text(rhs, source).strip())
            return
        jc = _extract_jni_call(_text(inner, source))
        if jc is not None:
            _, fn, args = jc
            _handle_call(ctx, fn, args, assign_to=None)
        return
    if t == "if_statement":
        cond = node.child_by_field_name("condition")
        cons = node.child_by_field_name("consequence")
        alt = node.child_by_field_name("alternative")
        _emit_if(ctx, cond, cons, alt, source)
        return
    if t == "return_statement":
        _emit_return(ctx, node, source)
        return
    if t in ("while_statement", "for_statement", "do_statement", "switch_statement"):
        for c in node.children:
            if c.is_named:
                _walk_stmt(ctx, c, source)
        return
    for c in node.children:
        if c.is_named:
            _walk_stmt(ctx, c, source)


def _handle_rhs(ctx: _Ctx, lhs: str, rhs: str) -> None:
    jc = _extract_jni_call(rhs)
    if jc is not None:
        _, fn, args = jc
        _handle_call(ctx, fn, args, assign_to=lhs)
        return
    if ctx.options.track_symbol_table:
        resolved = _resolve_arg(ctx, rhs)
        if isinstance(resolved, (SymStringLit, SymClass, SymMethodId, SymFieldId)):
            ctx.syms[lhs] = resolved
            return
        if re.fullmatch(r"\w+", rhs) and rhs in ctx.syms:
            ctx.syms[lhs] = ctx.syms[rhs]


def _emit_if(
    ctx: _Ctx,
    cond: tree_sitter.Node | None,
    cons: tree_sitter.Node | None,
    alt: tree_sitter.Node | None,
    source: bytes,
) -> None:
    if cond is None:
        return
    cond_text = _text(cond, source).strip().strip("()").strip()
    cons_text = _text(cons, source) if cons is not None else ""

    # Profile-driven native-side guard skip.
    if ctx.if_guard is not None and ctx.if_guard.should_skip(cond_text, cons_text):
        if alt is not None:
            _walk_stmt(ctx, alt, source)
        return

    # cond+goto-target → IF*
    target: str | None = None
    if cons is not None:
        for g in _find_descendants(cons, "goto_statement"):
            for c in g.children:
                if c.type == "statement_identifier":
                    target = _text(c, source)
                    break
            if target: break
    if target is None:
        if cons is not None: _walk_stmt(ctx, cons, source)
        if alt is not None: _walk_stmt(ctx, alt, source)
        return

    m = re.match(r"(\w+)\s*(==|!=|<|<=|>|>=)\s*(.+)", cond_text)
    if m:
        opc, rhs_v = m.group(2), m.group(3).strip()
        is_zero_cmp = rhs_v in ("0", "NULL", "(void *)0x0", "(jobject)0x0",
                                "'\\0'", "(char *)0x0")
        if is_zero_cmp:
            ctx.emit(op={"==": "IFEQ", "!=": "IFNE", "<": "IFLT",
                         "<=": "IFLE", ">": "IFGT", ">=": "IFGE"}.get(opc, "IFNE"),
                     target=target)
        else:
            ctx.emit(op={"==": "IF_ICMPEQ", "!=": "IF_ICMPNE", "<": "IF_ICMPLT",
                         "<=": "IF_ICMPLE", ">": "IF_ICMPGT", ">=": "IF_ICMPGE"}.get(opc, "IF_ICMPNE"),
                     target=target)
    else:
        ctx.emit(op="IFNE", target=target)


def _emit_return(ctx: _Ctx, node: tree_sitter.Node, source: bytes) -> None:
    arg = next(
        (c for c in node.children if c.type not in ("return", ";")),
        None,
    )
    ret = ctx.method_desc.rsplit(")", 1)[-1]
    ch = ret[0] if ret else "V"
    if arg is None or ch == "V":
        ctx.emit(op="RETURN")
        return

    expr = _text(arg, source).strip().rstrip(";")
    # Strip leading casts: `(jint) (jobject) 0`, `(byte *)0x0`, ...
    while True:
        mc = re.match(r"\(\s*\w[\w\s*]*\)\s*(.*)", expr)
        if mc and mc.group(1) != expr:
            expr = mc.group(1).strip()
        else:
            break

    if (ctx.options.suppress_synthetic_fallthrough_return and
            re.fullmatch(r"0[xX]?0?[lLuU]*|NULL|nullptr|0\.0[fF]?", expr)):
        return

    _emit_push(ctx, _resolve_arg(ctx, expr))
    ctx.emit(op={"I": "IRETURN", "B": "IRETURN", "S": "IRETURN", "C": "IRETURN", "Z": "IRETURN",
                 "J": "LRETURN", "F": "FRETURN", "D": "DRETURN"}.get(ch, "ARETURN"))


# --------------------------------------------------------------------
# Post-passes
# --------------------------------------------------------------------

_JUMP_OPS = {
    "GOTO", "IFEQ", "IFNE", "IFLT", "IFLE", "IFGT", "IFGE",
    "IF_ICMPEQ", "IF_ICMPNE", "IF_ICMPLT", "IF_ICMPLE",
    "IF_ICMPGT", "IF_ICMPGE", "IF_ACMPEQ", "IF_ACMPNE",
    "IFNULL", "IFNONNULL",
}


def _drop_dangling_jumps(ctx: _Ctx) -> None:
    labels: set[str] = {i["label"] for i in ctx.instructions
                        if i["op"] == "LABEL" and "label" in i}
    cleaned: list[dict[str, Any]] = []
    for ins in ctx.instructions:
        if ins["op"] in _JUMP_OPS and ins.get("target") not in labels:
            if ins["op"].startswith(("IF_ICMP", "IF_ACMP")):
                cleaned.append({"op": "POP"}); cleaned.append({"op": "POP"})
            elif ins["op"] in {"IFEQ", "IFNE", "IFLT", "IFLE", "IFGT", "IFGE",
                               "IFNULL", "IFNONNULL"}:
                cleaned.append({"op": "POP"})
            continue
        cleaned.append(ins)
    ctx.instructions = cleaned


# --------------------------------------------------------------------
# Public entry points
# --------------------------------------------------------------------

def lift_ghidra_function(
    code: str,
    method_desc: str,
    *,
    options: LifterOptions | None = None,
    profile: Profile | None = None,
    lookups: dict[str, list[dict[str, Any]]] | None = None,
    string_pool_entries: list[dict[str, Any]] | None = None,
    method_owner: str = "?",
    field_descs: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Lift one Ghidra-decompiled function body to JVM instructions.

    Parameters
    ----------
    code:
        Pseudo-C source produced by Ghidra (or any decompiler that emits
        ``env->FnName(args)`` after vtable type-application).
    method_desc:
        Target method's JVM descriptor (e.g. ``"()Ljava/lang/String;"``).
        Drives the return opcode selected by the trailing fall-through emit.
    options:
        Per-feature on/off flags. Defaults to all enabled.
    profile:
        Obfuscator profile (provides the throw-reason regex and
        ``if (ExceptionCheck) return`` skip patterns).
    lookups:
        Per-class manifest lookup tables (``cstrings`` / ``cmethods`` /
        ``cfields`` / ``cclasses``). Each entry is a dict.
    string_pool_entries:
        Binary's offset → string map (from binary-introspect).

    Returns
    -------
    ``{"instructions": [...], "warnings": [...]}``.
    """
    from .. import jni_vtable
    options = options or LifterOptions()
    profile = profile or get_profile("generic")
    code_rewritten = jni_vtable.rewrite_vtable_calls(code)

    ctx = _Ctx(
        options=options,
        profile=profile,
        invoke_hints=[],
        method_owner=method_owner,
        method_desc=method_desc,
        lookups=lookups or {},
        field_descs=dict(field_descs or {}),
    )
    ctx.if_guard = IfGuardMatcher(profile, enabled=options.skip_native_exception_guards)
    if string_pool_entries:
        ctx.pool = {e["offset"]: e["value"] for e in string_pool_entries
                    if isinstance(e, dict)}
    if options.use_throw_reason_invoke_hints:
        ctx.invoke_hints = InvokeHintParser(profile).parse(code_rewritten)
    if options.use_throw_reason_field_hints:
        ctx.field_hints = FieldHintParser(profile).parse(code_rewritten)

    tree = _parse(code_rewritten)
    body = None
    for fn in _find_descendants(tree.root_node, "function_definition"):
        for c in fn.children:
            if c.type == "compound_statement":
                body = c
                break
        if body: break
    if body is None:
        ctx.warnings.append("no function body found")
        return {"instructions": ctx.instructions, "warnings": ctx.warnings}

    src_bytes = code_rewritten.encode("utf-8")
    for c in body.children:
        if c.is_named:
            _walk_stmt(ctx, c, src_bytes)

    if options.drop_dangling_jumps:
        _drop_dangling_jumps(ctx)

    # Ensure a trailing return-family instruction.
    if not ctx.instructions or ctx.instructions[-1]["op"] not in {
        "RETURN", "IRETURN", "LRETURN", "FRETURN", "DRETURN", "ARETURN", "ATHROW",
    }:
        ret = method_desc.rsplit(")", 1)[-1]
        ch = ret[0] if ret else "V"
        if ch == "V":
            ctx.emit(op="RETURN")
        elif ch in "IBSCZ":
            ctx.emit(op="ICONST_0"); ctx.emit(op="IRETURN")
        elif ch == "J":
            ctx.emit(op="LCONST_0"); ctx.emit(op="LRETURN")
        elif ch == "F":
            ctx.emit(op="FCONST_0"); ctx.emit(op="FRETURN")
        elif ch == "D":
            ctx.emit(op="DCONST_0"); ctx.emit(op="DRETURN")
        else:
            ctx.emit(op="ACONST_NULL"); ctx.emit(op="ARETURN")

    return {"instructions": ctx.instructions, "warnings": ctx.warnings}


def lift_ghidra_dump(
    ghidra_json_path: Path,
    manifest_path: Path | None = None,
    *,
    options: LifterOptions | None = None,
    profile_name: str | None = None,
) -> list[dict[str, Any]]:
    """Lift every entry in a ghidra-dump.json into recovered/*.json
    records. Returns the list of records (caller writes them).
    """
    options = options or LifterOptions()
    data = json.loads(ghidra_json_path.read_text(encoding="utf-8"))
    manifest: dict[str, Any] | None = None
    if manifest_path is not None and manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    profile = get_profile(profile_name) if profile_name else get_profile("generic")
    pool_entries = (manifest or {}).get("stringPoolEntries") or []

    # Index every class's fields by simple-name → descriptor so the
    # field-hint resolver can fill descriptors on hint-bound GETFIELDs
    # without re-scanning the manifest per call.
    class_field_descs: dict[str, dict[str, str]] = {}
    if manifest:
        for cls in manifest.get("classes", []):
            cname = cls.get("name")
            if not cname:
                continue
            class_field_descs[cname] = {
                f["name"]: f["desc"]
                for f in (cls.get("fields") or [])
                if f.get("name") and f.get("desc")
            }

    out: list[dict[str, Any]] = []
    for entry in data.get("functions", []):
        code = entry.get("code", "")
        if not code:
            continue

        owner = entry.get("owner")
        name  = entry.get("methodName")
        desc  = entry.get("methodDesc")
        lookups: dict[str, list[dict[str, Any]]] = {}
        if manifest and owner:
            for cls in manifest.get("classes", []):
                if cls.get("name") == owner and cls.get("lookups"):
                    lookups = cls["lookups"]
                    break
        fld_descs = class_field_descs.get(owner or "", {})

        if owner and name and desc:
            result = lift_ghidra_function(
                code, desc,
                options=options, profile=profile,
                lookups=lookups, string_pool_entries=pool_entries,
                method_owner=owner, field_descs=fld_descs,
            )
        else:
            # No owner/methodName/methodDesc -> use generic fallback shape.
            result = lift_ghidra_function(
                code, "()V",
                options=options, profile=profile,
                lookups=lookups, string_pool_entries=pool_entries,
                method_owner=owner or "?", field_descs=fld_descs,
            )
            owner, name, desc = "?", entry.get("name", "?"), "()V"

        out.append({
            "schemaVersion": 1,
            "owner": owner or "?",
            "name":  name or "?",
            "desc":  desc or "?",
            "source": "static",
            "confidence": "low",
            "instructions": result["instructions"],
            "warnings": result["warnings"],
            "ghidraAddr": entry.get("addr"),
        })
    return out
