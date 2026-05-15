"""JNI call → JVM instruction translator.

Each ``env->FnName(args)`` JNI call in the decompiled function body
maps to zero or more JVM instructions plus symbol-table updates.

This module is *not* concerned with control flow or how individual
arguments resolve to values — that's the driver's job. It just owns
the catalogue of (JNI function name → emitter callback) pairs.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from .syms import Sym, SymClass, SymFieldId, SymMethodId, SymObject, SymStringLit


# --------------------------------------------------------------------
# Static catalogues (no obfuscator-specific assumption — these come
# straight from the JNI 1.1+ specification).
# --------------------------------------------------------------------

CALL_OBJ_NAMES = {
    "CallObjectMethod", "CallObjectMethodV", "CallObjectMethodA",
    "CallStaticObjectMethod", "CallStaticObjectMethodV", "CallStaticObjectMethodA",
    "CallNonvirtualObjectMethod", "CallNonvirtualObjectMethodV", "CallNonvirtualObjectMethodA",
}
CALL_VOID_NAMES = {"CallVoidMethod", "CallStaticVoidMethod", "CallNonvirtualVoidMethod"}
CALL_PRIM_TO_JVMRET = {
    "CallBooleanMethod": "Z", "CallByteMethod": "B", "CallCharMethod": "C",
    "CallShortMethod": "S", "CallIntMethod": "I", "CallLongMethod": "J",
    "CallFloatMethod": "F", "CallDoubleMethod": "D",
    "CallStaticBooleanMethod": "Z", "CallStaticByteMethod": "B",
    "CallStaticCharMethod": "C", "CallStaticShortMethod": "S",
    "CallStaticIntMethod": "I", "CallStaticLongMethod": "J",
    "CallStaticFloatMethod": "F", "CallStaticDoubleMethod": "D",
    "CallNonvirtualBooleanMethod": "Z", "CallNonvirtualByteMethod": "B",
    "CallNonvirtualCharMethod": "C", "CallNonvirtualShortMethod": "S",
    "CallNonvirtualIntMethod": "I", "CallNonvirtualLongMethod": "J",
    "CallNonvirtualFloatMethod": "F", "CallNonvirtualDoubleMethod": "D",
}

GET_FIELD_NAMES = {
    "GetObjectField", "GetBooleanField", "GetByteField",
    "GetCharField", "GetShortField", "GetIntField",
    "GetLongField", "GetFloatField", "GetDoubleField",
}
GET_STATIC_FIELD_NAMES = {
    "GetStaticObjectField", "GetStaticBooleanField", "GetStaticByteField",
    "GetStaticCharField", "GetStaticShortField", "GetStaticIntField",
    "GetStaticLongField", "GetStaticFloatField", "GetStaticDoubleField",
}
SET_FIELD_NAMES = {
    "SetObjectField", "SetBooleanField", "SetByteField",
    "SetCharField", "SetShortField", "SetIntField",
    "SetLongField", "SetFloatField", "SetDoubleField",
}
SET_STATIC_FIELD_NAMES = {
    "SetStaticObjectField", "SetStaticBooleanField", "SetStaticByteField",
    "SetStaticCharField", "SetStaticShortField", "SetStaticIntField",
    "SetStaticLongField", "SetStaticFloatField", "SetStaticDoubleField",
}

INVOKE_OP = {
    **{n: "INVOKEVIRTUAL" for n in (
        "CallObjectMethod", "CallObjectMethodV", "CallObjectMethodA",
        "CallBooleanMethod", "CallByteMethod", "CallCharMethod",
        "CallShortMethod", "CallIntMethod", "CallLongMethod",
        "CallFloatMethod", "CallDoubleMethod", "CallVoidMethod",
    )},
    **{n: "INVOKESTATIC" for n in (
        "CallStaticObjectMethod", "CallStaticBooleanMethod",
        "CallStaticByteMethod", "CallStaticCharMethod",
        "CallStaticShortMethod", "CallStaticIntMethod",
        "CallStaticLongMethod", "CallStaticFloatMethod",
        "CallStaticDoubleMethod", "CallStaticVoidMethod",
    )},
    **{n: "INVOKESPECIAL" for n in (
        "CallNonvirtualObjectMethod", "CallNonvirtualObjectMethodV",
        "CallNonvirtualObjectMethodA",
        "CallNonvirtualVoidMethod", "CallNonvirtualVoidMethodV",
        "CallNonvirtualVoidMethodA",
    )},
}

NEWARRAY_PRIM_KIND = {
    "NewBooleanArray": (4, "[Z"), "NewCharArray":    (5, "[C"),
    "NewFloatArray":   (6, "[F"), "NewDoubleArray":  (7, "[D"),
    "NewByteArray":    (8, "[B"), "NewShortArray":   (9, "[S"),
    "NewIntArray":     (10, "[I"), "NewLongArray":   (11, "[J"),
}


def ret_letter_for_jni_call(fn: str) -> str:
    """Map JNI Call*Method name to the return-type letter."""
    if fn in CALL_VOID_NAMES:
        return "V"
    if fn in CALL_OBJ_NAMES:
        return "L"
    return CALL_PRIM_TO_JVMRET.get(fn, "L")
