"""JNI function table byte-offset map for x64.

When Ghidra is run without a proper JNINativeInterface_ data type, vtable calls
show up as ``(**(code **)(*param_1 + 0xOFFSET))(args)``. This map lets us
rewrite those into ``env->FunctionName(args)`` so the AST matcher can pattern-
match the same way it would on a typed decompile.

Offsets are from the spec-defined JNINativeInterface_ struct layout (8 bytes
per function pointer on x64). Indices 0..3 are reserved.
"""

from __future__ import annotations

import re


_NAMES = [
    # 0..3 reserved
    "_reserved0", "_reserved1", "_reserved2", "_reserved3",
    "GetVersion",
    "DefineClass", "FindClass",
    "FromReflectedMethod", "FromReflectedField",
    "ToReflectedMethod",
    "GetSuperclass", "IsAssignableFrom",
    "ToReflectedField",
    "Throw", "ThrowNew", "ExceptionOccurred",
    "ExceptionDescribe", "ExceptionClear", "FatalError",
    "PushLocalFrame", "PopLocalFrame",
    "NewGlobalRef", "DeleteGlobalRef", "DeleteLocalRef",
    "IsSameObject", "NewLocalRef", "EnsureLocalCapacity",
    "AllocObject", "NewObject", "NewObjectV", "NewObjectA",
    "GetObjectClass", "IsInstanceOf",
    "GetMethodID",
    "CallObjectMethod", "CallObjectMethodV", "CallObjectMethodA",
    "CallBooleanMethod", "CallBooleanMethodV", "CallBooleanMethodA",
    "CallByteMethod",    "CallByteMethodV",    "CallByteMethodA",
    "CallCharMethod",    "CallCharMethodV",    "CallCharMethodA",
    "CallShortMethod",   "CallShortMethodV",   "CallShortMethodA",
    "CallIntMethod",     "CallIntMethodV",     "CallIntMethodA",
    "CallLongMethod",    "CallLongMethodV",    "CallLongMethodA",
    "CallFloatMethod",   "CallFloatMethodV",   "CallFloatMethodA",
    "CallDoubleMethod",  "CallDoubleMethodV",  "CallDoubleMethodA",
    "CallVoidMethod",    "CallVoidMethodV",    "CallVoidMethodA",
    "CallNonvirtualObjectMethod",  "CallNonvirtualObjectMethodV",  "CallNonvirtualObjectMethodA",
    "CallNonvirtualBooleanMethod", "CallNonvirtualBooleanMethodV", "CallNonvirtualBooleanMethodA",
    "CallNonvirtualByteMethod",    "CallNonvirtualByteMethodV",    "CallNonvirtualByteMethodA",
    "CallNonvirtualCharMethod",    "CallNonvirtualCharMethodV",    "CallNonvirtualCharMethodA",
    "CallNonvirtualShortMethod",   "CallNonvirtualShortMethodV",   "CallNonvirtualShortMethodA",
    "CallNonvirtualIntMethod",     "CallNonvirtualIntMethodV",     "CallNonvirtualIntMethodA",
    "CallNonvirtualLongMethod",    "CallNonvirtualLongMethodV",    "CallNonvirtualLongMethodA",
    "CallNonvirtualFloatMethod",   "CallNonvirtualFloatMethodV",   "CallNonvirtualFloatMethodA",
    "CallNonvirtualDoubleMethod",  "CallNonvirtualDoubleMethodV",  "CallNonvirtualDoubleMethodA",
    "CallNonvirtualVoidMethod",    "CallNonvirtualVoidMethodV",    "CallNonvirtualVoidMethodA",
    "GetFieldID",
    "GetObjectField",  "GetBooleanField", "GetByteField",  "GetCharField",
    "GetShortField",   "GetIntField",     "GetLongField",  "GetFloatField",
    "GetDoubleField",
    "SetObjectField",  "SetBooleanField", "SetByteField",  "SetCharField",
    "SetShortField",   "SetIntField",     "SetLongField",  "SetFloatField",
    "SetDoubleField",
    "GetStaticMethodID",
    "CallStaticObjectMethod",  "CallStaticObjectMethodV",  "CallStaticObjectMethodA",
    "CallStaticBooleanMethod", "CallStaticBooleanMethodV", "CallStaticBooleanMethodA",
    "CallStaticByteMethod",    "CallStaticByteMethodV",    "CallStaticByteMethodA",
    "CallStaticCharMethod",    "CallStaticCharMethodV",    "CallStaticCharMethodA",
    "CallStaticShortMethod",   "CallStaticShortMethodV",   "CallStaticShortMethodA",
    "CallStaticIntMethod",     "CallStaticIntMethodV",     "CallStaticIntMethodA",
    "CallStaticLongMethod",    "CallStaticLongMethodV",    "CallStaticLongMethodA",
    "CallStaticFloatMethod",   "CallStaticFloatMethodV",   "CallStaticFloatMethodA",
    "CallStaticDoubleMethod",  "CallStaticDoubleMethodV",  "CallStaticDoubleMethodA",
    "CallStaticVoidMethod",    "CallStaticVoidMethodV",    "CallStaticVoidMethodA",
    "GetStaticFieldID",
    "GetStaticObjectField",  "GetStaticBooleanField", "GetStaticByteField",
    "GetStaticCharField",    "GetStaticShortField",   "GetStaticIntField",
    "GetStaticLongField",    "GetStaticFloatField",   "GetStaticDoubleField",
    "SetStaticObjectField",  "SetStaticBooleanField", "SetStaticByteField",
    "SetStaticCharField",    "SetStaticShortField",   "SetStaticIntField",
    "SetStaticLongField",    "SetStaticFloatField",   "SetStaticDoubleField",
    "NewString",
    "GetStringLength", "GetStringChars", "ReleaseStringChars",
    "NewStringUTF", "GetStringUTFLength", "GetStringUTFChars", "ReleaseStringUTFChars",
    "GetArrayLength",
    "NewObjectArray", "GetObjectArrayElement", "SetObjectArrayElement",
    "NewBooleanArray", "NewByteArray", "NewCharArray",  "NewShortArray",
    "NewIntArray",     "NewLongArray", "NewFloatArray", "NewDoubleArray",
    "GetBooleanArrayElements", "GetByteArrayElements",  "GetCharArrayElements",
    "GetShortArrayElements",   "GetIntArrayElements",   "GetLongArrayElements",
    "GetFloatArrayElements",   "GetDoubleArrayElements",
    "ReleaseBooleanArrayElements", "ReleaseByteArrayElements",  "ReleaseCharArrayElements",
    "ReleaseShortArrayElements",   "ReleaseIntArrayElements",   "ReleaseLongArrayElements",
    "ReleaseFloatArrayElements",   "ReleaseDoubleArrayElements",
    "GetBooleanArrayRegion", "GetByteArrayRegion",  "GetCharArrayRegion",
    "GetShortArrayRegion",   "GetIntArrayRegion",   "GetLongArrayRegion",
    "GetFloatArrayRegion",   "GetDoubleArrayRegion",
    "SetBooleanArrayRegion", "SetByteArrayRegion",  "SetCharArrayRegion",
    "SetShortArrayRegion",   "SetIntArrayRegion",   "SetLongArrayRegion",
    "SetFloatArrayRegion",   "SetDoubleArrayRegion",
    "RegisterNatives", "UnregisterNatives",
    "MonitorEnter", "MonitorExit",
    "GetJavaVM",
    "GetStringRegion", "GetStringUTFRegion",
    "GetPrimitiveArrayCritical", "ReleasePrimitiveArrayCritical",
    "GetStringCritical", "ReleaseStringCritical",
    "NewWeakGlobalRef", "DeleteWeakGlobalRef",
    "ExceptionCheck",
    "NewDirectByteBuffer", "GetDirectBufferAddress", "GetDirectBufferCapacity",
    "GetObjectRefType",
    "GetModule",
    "IsVirtualThread",
    "GetStringUTFLengthAsLong",
]

# Build offset -> name (8 bytes per slot on x64).
OFFSET_TO_NAME: dict[int, str] = {i * 8: name for i, name in enumerate(_NAMES)}


# Match Ghidra-style vtable calls. Examples (whitespace + newlines tolerated):
#   (**(code **)(*param_1 + 0x30))(param_1,"java/lang/String")
#   (**(code **)(*pvVar1 + 0x108))(pvVar1,DAT_X,"name","desc")
_VTABLE_RE = re.compile(
    r"""\(\*\*\(code\s*\*\*\)\(\*(\w+)\s*\+\s*0x([0-9a-fA-F]+)\)\)\s*\(\s*\1\s*,?\s*""",
    re.VERBOSE,
)


def rewrite_vtable_calls(code: str) -> str:
    """Replace ``(**(code **)(*env + 0xOFF))(env, ...)`` with ``env->FnName(...)``.

    The leading ``env,`` (matched as the inner reference to the same identifier)
    is consumed so the resulting argument list is the user-facing one.
    """
    def repl(m: re.Match[str]) -> str:
        ident = m.group(1)
        offset = int(m.group(2), 16)
        name = OFFSET_TO_NAME.get(offset)
        if name is None:
            return m.group(0)   # leave unchanged
        return f"{ident}->{name}("
    return _VTABLE_RE.sub(repl, code)
