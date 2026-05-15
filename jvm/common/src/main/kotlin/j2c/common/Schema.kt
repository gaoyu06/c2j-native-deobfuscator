package j2c.common

import com.fasterxml.jackson.annotation.JsonInclude

/* ---------- classes.json ---------- */

@JsonInclude(JsonInclude.Include.NON_NULL)
data class ClassesJson(
    val schemaVersion: Int = 1,
    val input: JarInput,
    val loaderClass: String?,
    val loaderRegisterMethod: String? = null,   // e.g. "registerNativesForClass" / "initClass"
    val loaderRegisterDesc: String? = null,     // descriptor of that method
    val nativeDir: String?,
    val classes: List<ClassInfo>,
)

data class JarInput(val jarPath: String, val sha256: String)

@JsonInclude(JsonInclude.Include.NON_NULL)
data class ClassInfo(
    val name: String,
    val superName: String?,
    val interfaces: List<String>,
    val version: Int,
    val access: Int,
    val signature: String?,
    val sourceFile: String?,
    val fields: List<FieldInfo>,
    val methods: List<MethodInfo>,
)

data class FieldInfo(
    val name: String,
    val desc: String,
    val access: Int,
    val signature: String? = null,
    val value: Any? = null,
)

@JsonInclude(JsonInclude.Include.NON_NULL)
data class MethodInfo(
    val name: String,
    val desc: String,
    val access: Int,
    val signature: String? = null,
    val isNative: Boolean,
    val isObfuscatedNative: Boolean,
    val tryCatchBlocks: List<Any> = emptyList(),
    val maxStack: Int = -1,
    val maxLocals: Int = -1,
    val originalBody: String? = null,
)

/* ---------- manifest.json (read-only on JVM side) ---------- */

@JsonInclude(JsonInclude.Include.NON_NULL)
data class ManifestJson(
    val schemaVersion: Int = 1,
    val input: ManifestInput? = null,
    val loaderClass: String? = null,
    val loaderRegisterMethod: String? = null,   // e.g. "registerNativesForClass" / "initClass"
    val loaderRegisterDesc: String? = null,
    val nativeDir: String? = null,
    val stringPool: List<String> = emptyList(),
    val classes: List<ManifestClass>,
    val hiddenClasses: List<HiddenClass> = emptyList(),
)

data class ManifestInput(val jar: String? = null, val lib: String? = null)

@JsonInclude(JsonInclude.Include.NON_NULL)
data class ManifestClass(
    val name: String,
    val superName: String? = null,
    val interfaces: List<String> = emptyList(),
    val version: Int = 52,
    val access: Int = 0,
    val signature: String? = null,
    val sourceFile: String? = null,
    val classId: Int? = null,
    val fields: List<FieldInfo> = emptyList(),
    val methods: List<ManifestMethod>,
    val lookups: ManifestLookups? = null,
)

@JsonInclude(JsonInclude.Include.NON_NULL)
data class ManifestMethod(
    val name: String,
    val desc: String,
    val access: Int,
    val signature: String? = null,
    val isObfuscatedNative: Boolean = false,
    val fnAddr: String? = null,
    val fnSymbol: String? = null,
    val originalBody: String? = null,
)

data class ManifestLookups(
    val cstrings: List<Any?> = emptyList(),
    val cclasses: List<Any?> = emptyList(),
    val cmethods: List<Any?> = emptyList(),
    val cfields: List<Any?> = emptyList(),
)

data class HiddenClass(val classData: String)

/* ---------- recovered-method.json ---------- */

@JsonInclude(JsonInclude.Include.NON_NULL)
data class RecoveredMethod(
    val schemaVersion: Int = 1,
    val owner: String,
    val name: String,
    val desc: String,
    val source: String,          // dynamic | static | merged
    val confidence: String? = null,
    val instructions: List<RecoveredInsn>,
    val tryCatchBlocks: List<RecoveredTryCatch> = emptyList(),
    val localVariables: List<Any> = emptyList(),
    val lineNumbers: List<Any> = emptyList(),
    // Exception class names observed propagating out of (or caught within)
    // this method during the trace. Surfaced by class-rebuilder as part of
    // the @j2c.RuntimeTrace annotation so the reverse engineer knows what
    // exception types this method handles at runtime, even when per-bci
    // try/catch recovery is not yet implemented.
    val exceptionsObserved: List<String> = emptyList(),
)

@JsonInclude(JsonInclude.Include.NON_NULL)
data class RecoveredInsn(
    val op: String,
    val `var`: Int? = null,
    val incr: Int? = null,
    val value: Any? = null,
    val owner: String? = null,
    val name: String? = null,
    val desc: String? = null,
    val itf: Boolean? = null,
    val label: String? = null,
    val target: String? = null,
    val type: String? = null,
    val dims: Int? = null,
    val min: Int? = null,
    val max: Int? = null,
    val keys: List<Int>? = null,
    val labels: List<String>? = null,
    val default: String? = null,
    // Short tag identifying the provenance of a runtime-observed value baked
    // into this insn (e.g. "int_arg" / "long_arg" / "arr_idx" / "str_computed").
    // null = source-level constant or structural insn. Surfaced by the
    // class-rebuilder as @j2c.Trace annotations and/or inline marker invokes.
    val dynamic: String? = null,
    // ---- INVOKEDYNAMIC ----
    // Bootstrap method handle. Tag is one of H_GETFIELD..H_INVOKEINTERFACE
    // (asm Opcodes.H_*). Itf for the bootstrap (almost always false for
    // LambdaMetafactory.metafactory which lives on a regular class).
    val bsmTag: Int? = null,
    val bsmOwner: String? = null,
    val bsmName: String? = null,
    val bsmDesc: String? = null,
    val bsmItf: Boolean? = null,
    // Bootstrap args. Each entry is a tagged constant — see [BsmArg].
    val bsmArgs: List<BsmArg>? = null,
)

/** A constant pool entry usable as an INVOKEDYNAMIC bootstrap arg. */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class BsmArg(
    /** "int" / "long" / "float" / "double" / "string" / "type" / "handle". */
    val kind: String,
    val value: Any? = null,           // int / long / float / double / string / type descriptor
    val handleTag: Int? = null,        // for kind=handle
    val handleOwner: String? = null,
    val handleName: String? = null,
    val handleDesc: String? = null,
    val handleItf: Boolean? = null,
)

@JsonInclude(JsonInclude.Include.NON_NULL)
data class RecoveredTryCatch(
    val start: String,
    val end: String,
    val handler: String,
    val type: String? = null,
)
