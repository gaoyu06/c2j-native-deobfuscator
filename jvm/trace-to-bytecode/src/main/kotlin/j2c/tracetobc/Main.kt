package j2c.tracetobc

import com.fasterxml.jackson.databind.JsonNode
import j2c.common.JsonIO
import j2c.common.ManifestJson
import j2c.common.RecoveredInsn
import j2c.common.RecoveredMethod
import picocli.CommandLine
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.Callable
import kotlin.system.exitProcess

@Command(
    name = "trace-to-bytecode",
    mixinStandardHelpOptions = true,
    description = ["Reconstruct JVM bytecode for native methods from a JVMTI trace."]
)
class TraceToBytecodeCmd : Callable<Int> {

    @Option(names = ["--trace"], required = true, description = ["trace.jsonl from JVMTI agent"])
    lateinit var trace: Path

    @Option(names = ["--manifest"], required = true, description = ["manifest.json from manifest-merge"])
    lateinit var manifest: Path

    @Option(names = ["-o", "--output"], required = true, description = ["Output directory for recovered/*.json"])
    lateinit var output: Path

    @Option(names = ["--confidence"], description = ["Confidence label to attach to outputs"])
    var confidence: String = "low"

    override fun call(): Int {
        val mani: ManifestJson = JsonIO.read(manifest)
        val events = parseTrace(trace)
        val groups = groupByMethodInvocation(events)
        val byMethod = mutableMapOf<MethodKey, MutableList<List<JsonNode>>>()
        for (g in groups) {
            byMethod.getOrPut(g.method) { mutableListOf() }.add(g.events)
        }
        Files.createDirectories(output)
        // One shared translator so symbols (jclass/jmethodID/jfieldID/jstring
        // observed in any frame) carry across method invocations.
        val translator = TraceTranslator(mani)
        translator.warmup(events)
        var produced = 0
        for ((mk, invocations) in byMethod) {
            // Pick the longest (most informative) trace for this method
            val pick = invocations.maxByOrNull { it.size } ?: continue
            val recovered = translator.translate(mk, pick, confidence)
            val file = output.resolve("${safeFilename(mk)}.json")
            JsonIO.write(file, recovered)
            produced++
        }
        System.err.println("Recovered $produced methods → $output")
        return 0
    }

    private fun safeFilename(mk: MethodKey): String {
        val safe = "${mk.owner}__${mk.name}__${mk.desc}"
        return safe.replace('/', '_').replace('<', '_').replace('>', '_')
            .replace('(', '_').replace(')', '_').replace(';', '_').replace('[', '_')
    }
}

data class MethodKey(val owner: String, val name: String, val desc: String)

data class TraceGroup(val method: MethodKey, val events: List<JsonNode>)

private fun parseTrace(path: Path): List<JsonNode> {
    val list = mutableListOf<JsonNode>()
    Files.newBufferedReader(path).use { r ->
        r.lines().forEach { line ->
            val l = line.trim()
            if (l.isEmpty()) return@forEach
            try {
                list.add(JsonIO.mapper.readTree(l))
            } catch (ignore: Throwable) { /* skip malformed */ }
        }
    }
    return list
}

private fun groupByMethodInvocation(events: List<JsonNode>): List<TraceGroup> {
    // Per-thread stack of active enter events; we collect all `jni` events
    // between an enter and its matching exit and attribute them to the
    // outermost frame on that thread.
    data class Frame(val key: MethodKey, val jniBuf: MutableList<JsonNode>)
    val perThread = mutableMapOf<Long, ArrayDeque<Frame>>()
    val result = mutableListOf<TraceGroup>()
    for (ev in events) {
        val thr = ev["thr"]?.asLong() ?: continue
        val type = ev["ev"]?.asText() ?: continue
        when (type) {
            "enter" -> {
                val key = MethodKey(
                    ev["owner"]?.asText() ?: continue,
                    ev["name"]?.asText() ?: continue,
                    ev["desc"]?.asText() ?: continue,
                )
                perThread.getOrPut(thr) { ArrayDeque() }.addLast(Frame(key, mutableListOf()))
            }
            "exit" -> {
                val stack = perThread[thr] ?: continue
                val frame = stack.removeLastOrNull() ?: continue
                result.add(TraceGroup(frame.key, frame.jniBuf))
            }
            "jni" -> {
                val stack = perThread[thr] ?: continue
                stack.lastOrNull()?.jniBuf?.add(ev)
            }
        }
    }
    return result
}

class TraceTranslator(private val manifest: ManifestJson) {

    // Symbol table: maps jobject hex string -> known semantic.
    // Persists across method translations so jclass / jmethodID observed in
    // (e.g.) Loader.registerNativesForClass remain usable in Hello.main.
    private sealed class Sym {
        data class Class(val internalName: String) : Sym()
        data class MethodId(val owner: String?, val name: String?, val desc: String?) : Sym()
        data class FieldId(val owner: String?, val name: String?, val desc: String?) : Sym()
        data class StringLit(val value: String) : Sym()
        data class Unknown(val origin: String) : Sym()
    }

    private val symbols = mutableMapOf<String, Sym>()

    /**
     * First pass over the entire trace: feed every JNI event through the
     * symbol-table updates (without emitting instructions). After this, the
     * symbol table is populated with every jclass / jmethodID / jfieldID /
     * jstring observed at agent load time and during class-loader bootstrap.
     */
    fun warmup(allEvents: List<JsonNode>) {
        for (ev in allEvents) {
            if (ev["ev"]?.asText() != "jni") continue
            val call = ev["call"]?.asText() ?: continue
            updateSymbols(call, ev)
        }
    }

    fun translate(method: MethodKey, jniEvents: List<JsonNode>, confidence: String): RecoveredMethod {
        val out = mutableListOf<RecoveredInsn>()
        for (ev in jniEvents) {
            val call = ev["call"]?.asText() ?: continue
            translateCall(call, ev, out)
        }
        out += RecoveredInsn(op = returnOp(method.desc))
        return RecoveredMethod(
            owner = method.owner,
            name = method.name,
            desc = method.desc,
            source = "dynamic",
            confidence = confidence,
            instructions = out,
        )
    }

    private fun returnOp(desc: String): String {
        val ret = desc.substringAfterLast(')')
        return when (ret) {
            "V" -> "RETURN"
            "Z", "B", "C", "S", "I" -> "IRETURN"
            "J" -> "LRETURN"
            "F" -> "FRETURN"
            "D" -> "DRETURN"
            else -> "ARETURN"
        }
    }

    private fun translateCall(call: String, ev: JsonNode, out: MutableList<RecoveredInsn>) {
        // Always update the symbol table first; THEN emit any bytecode.
        updateSymbols(call, ev)

        val args = ev["args"]
        val ret = ev["ret"]
        when (call) {
            "GetStaticObjectField", "GetStaticBooleanField", "GetStaticByteField",
            "GetStaticCharField", "GetStaticShortField", "GetStaticIntField",
            "GetStaticLongField" -> {
                val fid = symbols[args?.get(1)?.asText()] as? Sym.FieldId ?: return
                out += RecoveredInsn(
                    op = "GETSTATIC",
                    owner = fid.owner,
                    name = fid.name,
                    desc = fid.desc,
                )
            }

            "GetObjectField", "GetBooleanField", "GetByteField",
            "GetCharField", "GetShortField", "GetIntField", "GetLongField" -> {
                val fid = symbols[args?.get(1)?.asText()] as? Sym.FieldId ?: return
                out += RecoveredInsn(
                    op = "GETFIELD",
                    owner = fid.owner,
                    name = fid.name,
                    desc = fid.desc,
                )
            }

            "SetObjectField", "SetBooleanField", "SetByteField",
            "SetCharField", "SetShortField", "SetIntField", "SetLongField" -> {
                val fid = symbols[args?.get(1)?.asText()] as? Sym.FieldId ?: return
                out += RecoveredInsn(
                    op = "PUTFIELD",
                    owner = fid.owner,
                    name = fid.name,
                    desc = fid.desc,
                )
            }

            "NewObject" -> {
                val cls = symbols[args?.get(0)?.asText()] as? Sym.Class
                val mid = symbols[args?.get(1)?.asText()] as? Sym.MethodId
                if (cls != null) out += RecoveredInsn(op = "NEW", type = cls.internalName)
                out += RecoveredInsn(op = "DUP")
                if (mid != null) {
                    out += RecoveredInsn(
                        op = "INVOKESPECIAL",
                        owner = mid.owner,
                        name = mid.name,
                        desc = mid.desc,
                    )
                }
            }

            in CALL_OBJECT_VARIANTS, in CALL_PRIM_VARIANTS -> {
                val isStatic = call.startsWith("CallStatic")
                val mid = symbols[args?.get(1)?.asText()] as? Sym.MethodId
                val midDesc = ev["midDesc"]?.asText()
                if (mid != null && mid.owner != null) {
                    out += RecoveredInsn(
                        op = if (isStatic) "INVOKESTATIC" else "INVOKEVIRTUAL",
                        owner = mid.owner,
                        name = mid.name,
                        desc = mid.desc ?: midDesc,
                    )
                }
                // Drop calls whose method ID we couldn't bind to an owner
                // (these are native-obfuscator's find_class_wo_static and
                // similar infrastructure that aren't part of the source bytecode).
            }

            "CallNonvirtualVoidMethod", "CallNonvirtualObjectMethod" -> {
                // args[0]=obj, args[1]=cls, args[2]=mid, args[3+]=variadic
                val mid = symbols[args?.get(2)?.asText()] as? Sym.MethodId
                val midDesc = ev["midDesc"]?.asText()
                if (mid != null && mid.owner != null) {
                    out += RecoveredInsn(
                        op = "INVOKESPECIAL",
                        owner = mid.owner,
                        name = mid.name,
                        desc = mid.desc ?: midDesc,
                    )
                }
            }

            "AllocObject" -> {
                val cls = symbols[args?.get(0)?.asText()] as? Sym.Class
                if (cls != null) {
                    out += RecoveredInsn(op = "NEW", type = cls.internalName)
                    out += RecoveredInsn(op = "DUP")
                }
            }

            "IsInstanceOf" -> {
                val cls = symbols[args?.get(1)?.asText()] as? Sym.Class
                if (cls != null) {
                    out += RecoveredInsn(op = "INSTANCEOF", type = cls.internalName)
                }
            }

            "GetArrayLength" -> out += RecoveredInsn(op = "ARRAYLENGTH")

            "NewObjectArray" -> {
                val cls = symbols[args?.get(1)?.asText()] as? Sym.Class
                if (cls != null) {
                    out += RecoveredInsn(op = "ANEWARRAY", type = cls.internalName)
                }
            }

            "NewBooleanArray" -> out += RecoveredInsn(op = "NEWARRAY", value = 4)
            "NewCharArray"    -> out += RecoveredInsn(op = "NEWARRAY", value = 5)
            "NewFloatArray"   -> out += RecoveredInsn(op = "NEWARRAY", value = 6)
            "NewDoubleArray"  -> out += RecoveredInsn(op = "NEWARRAY", value = 7)
            "NewByteArray"    -> out += RecoveredInsn(op = "NEWARRAY", value = 8)
            "NewShortArray"   -> out += RecoveredInsn(op = "NEWARRAY", value = 9)
            "NewIntArray"     -> out += RecoveredInsn(op = "NEWARRAY", value = 10)
            "NewLongArray"    -> out += RecoveredInsn(op = "NEWARRAY", value = 11)

            "GetObjectArrayElement" -> out += RecoveredInsn(op = "AALOAD")
            "SetObjectArrayElement" -> out += RecoveredInsn(op = "AASTORE")

            "GetBooleanArrayRegion" -> out += RecoveredInsn(op = "BALOAD")
            "GetByteArrayRegion"    -> out += RecoveredInsn(op = "BALOAD")
            "GetCharArrayRegion"    -> out += RecoveredInsn(op = "CALOAD")
            "GetShortArrayRegion"   -> out += RecoveredInsn(op = "SALOAD")
            "GetIntArrayRegion"     -> out += RecoveredInsn(op = "IALOAD")
            "GetLongArrayRegion"    -> out += RecoveredInsn(op = "LALOAD")
            "GetFloatArrayRegion"   -> out += RecoveredInsn(op = "FALOAD")
            "GetDoubleArrayRegion"  -> out += RecoveredInsn(op = "DALOAD")

            "SetBooleanArrayRegion" -> out += RecoveredInsn(op = "BASTORE")
            "SetByteArrayRegion"    -> out += RecoveredInsn(op = "BASTORE")
            "SetCharArrayRegion"    -> out += RecoveredInsn(op = "CASTORE")
            "SetShortArrayRegion"   -> out += RecoveredInsn(op = "SASTORE")
            "SetIntArrayRegion"     -> out += RecoveredInsn(op = "IASTORE")
            "SetLongArrayRegion"    -> out += RecoveredInsn(op = "LASTORE")
            "SetFloatArrayRegion"   -> out += RecoveredInsn(op = "FASTORE")
            "SetDoubleArrayRegion"  -> out += RecoveredInsn(op = "DASTORE")

            "Throw", "ThrowNew" -> out += RecoveredInsn(op = "ATHROW")

            else -> {}
        }
    }

    /**
     * Update the symbol table from a single JNI event.
     *
     * Handles three special inference cases used by native-obfuscator-style
     * transpilers:
     *  1. ``NewStringUTF("foo") -> jstring`` registers the literal.
     *  2. ``CallObjectMethod`` whose ``midDesc`` ends in ``Ljava/lang/Class;``
     *     and whose decoded string arg is a class name binds the returned
     *     jobject to a Class. This covers the ``ClassLoader.loadClass(String)``
     *     path.
     *  3. ``CallObjectMethod`` whose ``midDesc`` returns ``Ljava/lang/String;``
     *     and whose receiver is a known String (e.g. ``String.intern``) keeps
     *     the same content on the result.
     */
    private fun updateSymbols(call: String, ev: JsonNode) {
        val args = ev["args"]
        val ret = ev["ret"]
        val retHex = ret?.takeIf { it.isTextual }?.asText()
        val midDesc = ev["midDesc"]?.asText()

        when (call) {
            "NewStringUTF" -> {
                val s = args?.get(0)?.takeIf { it.isTextual }?.asText() ?: return
                if (retHex != null) symbols[retHex] = Sym.StringLit(s)
            }

            "FindClass" -> {
                val n = args?.get(0)?.takeIf { it.isTextual }?.asText() ?: return
                if (retHex != null) symbols[retHex] = Sym.Class(n)
            }

            "GetMethodID", "GetStaticMethodID" -> {
                val cls = symbols[args?.get(0)?.asText()] as? Sym.Class
                val name = args?.get(1)?.asText() ?: return
                val desc = args?.get(2)?.asText() ?: return
                if (retHex != null) {
                    symbols[retHex] = Sym.MethodId(cls?.internalName, name, desc)
                }
            }

            "GetFieldID", "GetStaticFieldID" -> {
                val cls = symbols[args?.get(0)?.asText()] as? Sym.Class
                val name = args?.get(1)?.asText() ?: return
                val desc = args?.get(2)?.asText() ?: return
                if (retHex != null) {
                    symbols[retHex] = Sym.FieldId(cls?.internalName, name, desc)
                }
            }

            "NewGlobalRef", "NewWeakGlobalRef", "NewLocalRef" -> {
                // Propagate semantic from source jobject to the new reference.
                val src = symbols[args?.get(0)?.asText()]
                if (src != null && retHex != null) symbols[retHex] = src
            }

            in CALL_OBJECT_VARIANTS -> {
                // Heuristic 2: classloader.loadClass(String) -> jclass
                if (midDesc != null && midDesc.endsWith(")Ljava/lang/Class;")) {
                    // The first variadic arg starts at args[2]; if it is a
                    // plain string literal (the agent inlined it), bind the
                    // result to a Class.
                    val first = args?.get(2)
                    val name = if (first != null && first.isTextual) {
                        val v = first.asText()
                        if (!v.startsWith("0x")) v.replace('.', '/') else null
                    } else null
                    if (name != null && retHex != null) {
                        symbols[retHex] = Sym.Class(name)
                    }
                }
                // Heuristic 3: String.intern / String.toString — propagate content
                if (midDesc != null && midDesc.endsWith(")Ljava/lang/String;")) {
                    val recv = args?.get(0)?.asText()
                    val lit = symbols[recv] as? Sym.StringLit
                    if (lit != null && retHex != null) {
                        symbols[retHex] = Sym.StringLit(lit.value)
                    }
                }
            }
            else -> {}
        }
    }

    companion object {
        private val CALL_OBJECT_VARIANTS = setOf(
            "CallObjectMethod", "CallStaticObjectMethod",
        )
        private val CALL_PRIM_VARIANTS = setOf(
            "CallBooleanMethod", "CallByteMethod", "CallCharMethod",
            "CallShortMethod", "CallIntMethod", "CallLongMethod",
            "CallVoidMethod",
            "CallStaticIntMethod", "CallStaticVoidMethod",
        )
    }
}

fun main(args: Array<String>) {
    exitProcess(CommandLine(TraceToBytecodeCmd()).execute(*args))
}
