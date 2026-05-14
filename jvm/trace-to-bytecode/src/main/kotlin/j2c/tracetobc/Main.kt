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
        // Look up the access flags so we know whether `this` is available
        val mc = manifest.classes.firstOrNull { it.name == method.owner }
        val mm = mc?.methods?.firstOrNull { it.name == method.name && it.desc == method.desc }
        val isStatic = mm != null && (mm.access and 0x0008) != 0  // ACC_STATIC
        val balancer = StackBalancer(isStatic)
        for (ev in jniEvents) {
            val call = ev["call"]?.asText() ?: continue
            translateCall(call, ev, balancer)
        }
        // Final return instruction
        balancer.out += RecoveredInsn(op = returnOp(method.desc))
        return RecoveredMethod(
            owner = method.owner,
            name = method.name,
            desc = method.desc,
            source = "dynamic",
            confidence = confidence,
            instructions = balancer.out,
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

    private fun translateCall(call: String, ev: JsonNode, b: StackBalancer) {
        // Always update the symbol table first; THEN emit any bytecode.
        updateSymbols(call, ev)

        val args = ev["args"]
        val midDesc = ev["midDesc"]?.asText()
        when (call) {
            "GetStaticObjectField", "GetStaticBooleanField", "GetStaticByteField",
            "GetStaticCharField", "GetStaticShortField", "GetStaticIntField",
            "GetStaticLongField" -> {
                val fid = symbols[args?.get(1)?.asText()] as? Sym.FieldId ?: return
                val produce = produceFor(fid.desc, ev["ret"]?.asText())
                b.emitRaw(
                    RecoveredInsn(op = "GETSTATIC", owner = fid.owner, name = fid.name, desc = fid.desc),
                    consume = 0, produce = produce,
                )
            }

            "GetObjectField", "GetBooleanField", "GetByteField",
            "GetCharField", "GetShortField", "GetIntField", "GetLongField" -> {
                val fid = symbols[args?.get(1)?.asText()] as? Sym.FieldId ?: return
                b.ensureReceiver(args?.get(0)?.asText())
                val produce = produceFor(fid.desc, ev["ret"]?.asText())
                b.emitRaw(
                    RecoveredInsn(op = "GETFIELD", owner = fid.owner, name = fid.name, desc = fid.desc),
                    consume = 1, produce = produce,
                )
            }

            "SetObjectField", "SetBooleanField", "SetByteField",
            "SetCharField", "SetShortField", "SetIntField", "SetLongField" -> {
                val fid = symbols[args?.get(1)?.asText()] as? Sym.FieldId ?: return
                b.ensureReceiver(args?.get(0)?.asText())
                b.pushArg(extractScalar(args?.get(2)), fid.desc ?: "I")
                b.emitRaw(
                    RecoveredInsn(op = "PUTFIELD", owner = fid.owner, name = fid.name, desc = fid.desc),
                    consume = 2, produce = null,
                )
            }

            "AllocObject" -> {
                val cls = symbols[args?.get(0)?.asText()] as? Sym.Class
                val retHex = ev["ret"]?.asText()
                if (cls != null) {
                    // NEW pushes 1; DUP duplicates so subsequent INVOKESPECIAL
                    // (consumes 1) leaves exactly one instance on the stack.
                    b.emitRaw(RecoveredInsn(op = "NEW", type = cls.internalName), 0,
                              if (retHex != null) StackBalancer.V.ObjHex(retHex) else StackBalancer.V.Obj)
                    b.emitRaw(RecoveredInsn(op = "DUP"), 0,
                              if (retHex != null) StackBalancer.V.ObjHex(retHex) else StackBalancer.V.Obj)
                }
            }

            "NewObject" -> {
                val cls = symbols[args?.get(0)?.asText()] as? Sym.Class
                val mid = symbols[args?.get(1)?.asText()] as? Sym.MethodId
                val newRetHex = ev["ret"]?.asText()
                if (cls != null) {
                    b.emitRaw(RecoveredInsn(op = "NEW", type = cls.internalName), 0,
                              if (newRetHex != null) StackBalancer.V.ObjHex(newRetHex) else StackBalancer.V.Obj)
                    b.emitRaw(RecoveredInsn(op = "DUP"), 0,
                              if (newRetHex != null) StackBalancer.V.ObjHex(newRetHex) else StackBalancer.V.Obj)
                }
                if (mid != null && mid.owner != null) {
                    val ctorDesc = mid.desc ?: midDesc
                    val pairs = collectVariadicPairs(ev, mid.desc, midDesc, varadicStartIdx = 2)
                    // For NewObject the receiver-equivalent (the just-NEWed object) is already on stack.
                    b.prepareCall(receiverHex = newRetHex, argDescAndHex = pairs)
                    b.emitInvoke(RecoveredInsn(op = "INVOKESPECIAL", owner = mid.owner, name = mid.name, desc = ctorDesc))
                }
            }

            "CallNonvirtualVoidMethod", "CallNonvirtualObjectMethod" -> {
                val mid = symbols[args?.get(2)?.asText()] as? Sym.MethodId
                if (mid != null && mid.owner != null) {
                    val pairs = collectVariadicPairs(ev, mid.desc, midDesc, varadicStartIdx = 3)
                    b.prepareCall(receiverHex = args?.get(0)?.asText(), argDescAndHex = pairs)
                    b.emitInvoke(RecoveredInsn(op = "INVOKESPECIAL", owner = mid.owner, name = mid.name, desc = mid.desc ?: midDesc),
                                 returnHex = ev["ret"]?.asText())
                }
            }

            in CALL_OBJECT_VARIANTS, in CALL_PRIM_VARIANTS -> {
                val isStaticCall = call.startsWith("CallStatic")
                val mid = symbols[args?.get(1)?.asText()] as? Sym.MethodId
                if (mid != null && mid.owner != null) {
                    val pairs = collectVariadicPairs(ev, mid.desc, midDesc, varadicStartIdx = 2)
                    b.prepareCall(
                        receiverHex = if (isStaticCall) null else args?.get(0)?.asText(),
                        argDescAndHex = pairs,
                    )
                    b.emitInvoke(
                        RecoveredInsn(
                            op = if (isStaticCall) "INVOKESTATIC" else "INVOKEVIRTUAL",
                            owner = mid.owner, name = mid.name, desc = mid.desc ?: midDesc,
                        ),
                        returnHex = ev["ret"]?.asText(),
                    )
                }
            }

            "IsInstanceOf" -> {
                val cls = symbols[args?.get(1)?.asText()] as? Sym.Class
                if (cls != null) {
                    b.ensureReceiver(args?.get(0)?.asText())
                    b.emitRaw(RecoveredInsn(op = "INSTANCEOF", type = cls.internalName), 1, StackBalancer.V.Int)
                }
            }

            "GetArrayLength" -> {
                b.ensureReceiver(args?.get(0)?.asText())
                b.emitRaw(RecoveredInsn(op = "ARRAYLENGTH"), 1, StackBalancer.V.Int)
            }

            "NewObjectArray" -> {
                val cls = symbols[args?.get(1)?.asText()] as? Sym.Class
                if (cls != null) {
                    b.pushInt(args?.get(0)?.asInt() ?: 0)
                    b.emitRaw(RecoveredInsn(op = "ANEWARRAY", type = cls.internalName), 1, StackBalancer.V.Obj)
                }
            }

            "NewBooleanArray" -> { b.pushInt(args?.get(0)?.asInt() ?: 0); b.emitRaw(RecoveredInsn(op = "NEWARRAY", value = 4), 1, StackBalancer.V.Obj) }
            "NewCharArray"    -> { b.pushInt(args?.get(0)?.asInt() ?: 0); b.emitRaw(RecoveredInsn(op = "NEWARRAY", value = 5), 1, StackBalancer.V.Obj) }
            "NewFloatArray"   -> { b.pushInt(args?.get(0)?.asInt() ?: 0); b.emitRaw(RecoveredInsn(op = "NEWARRAY", value = 6), 1, StackBalancer.V.Obj) }
            "NewDoubleArray"  -> { b.pushInt(args?.get(0)?.asInt() ?: 0); b.emitRaw(RecoveredInsn(op = "NEWARRAY", value = 7), 1, StackBalancer.V.Obj) }
            "NewByteArray"    -> { b.pushInt(args?.get(0)?.asInt() ?: 0); b.emitRaw(RecoveredInsn(op = "NEWARRAY", value = 8), 1, StackBalancer.V.Obj) }
            "NewShortArray"   -> { b.pushInt(args?.get(0)?.asInt() ?: 0); b.emitRaw(RecoveredInsn(op = "NEWARRAY", value = 9), 1, StackBalancer.V.Obj) }
            "NewIntArray"     -> { b.pushInt(args?.get(0)?.asInt() ?: 0); b.emitRaw(RecoveredInsn(op = "NEWARRAY", value = 10), 1, StackBalancer.V.Obj) }
            "NewLongArray"    -> { b.pushInt(args?.get(0)?.asInt() ?: 0); b.emitRaw(RecoveredInsn(op = "NEWARRAY", value = 11), 1, StackBalancer.V.Obj) }

            "GetObjectArrayElement" -> {
                b.ensureReceiver(args?.get(0)?.asText())
                b.pushInt(args?.get(1)?.asInt() ?: 0)
                b.emitRaw(RecoveredInsn(op = "AALOAD"), 2, StackBalancer.V.Obj)
            }
            "SetObjectArrayElement" -> {
                b.ensureReceiver(args?.get(0)?.asText())
                b.pushInt(args?.get(1)?.asInt() ?: 0)
                b.pushObjLiteral(args?.get(2)?.asText() ?: "0x0")
                b.emitRaw(RecoveredInsn(op = "AASTORE"), 3, null)
            }

            "Throw", "ThrowNew" -> b.emitRaw(RecoveredInsn(op = "ATHROW"), 1, null)

            else -> {}
        }
    }

    private fun extractScalar(node: JsonNode?): Any? {
        if (node == null) return null
        return when {
            node.isTextual -> node.asText()
            node.isLong -> node.asLong()
            node.isInt -> node.asInt()
            node.isDouble -> node.asDouble()
            else -> null
        }
    }

    private fun produceFor(desc: String?, retHex: String? = null): StackBalancer.V? = when (desc?.firstOrNull() ?: '?') {
        'V' -> null
        'I', 'B', 'S', 'C', 'Z' -> StackBalancer.V.Int
        'J' -> StackBalancer.V.Long
        'F' -> StackBalancer.V.Float
        'D' -> StackBalancer.V.Double
        else -> if (retHex != null) StackBalancer.V.ObjHex(retHex) else StackBalancer.V.Obj
    }

    private fun collectVariadicPairs(ev: JsonNode, knownDesc: String?, fallbackDesc: String?, varadicStartIdx: Int): List<Pair<String, Any?>> {
        val desc = knownDesc ?: fallbackDesc ?: return emptyList()
        val argTypes = StackBalancer.parseArgTypes(desc)
        val args = ev["args"] ?: return emptyList()
        val out = mutableListOf<Pair<String, Any?>>()
        for (i in argTypes.indices) {
            val n = args[varadicStartIdx + i] ?: continue
            val v: Any? = when {
                n.isTextual -> n.asText()
                n.isLong -> n.asLong()
                n.isInt -> n.asInt()
                n.isDouble -> n.asDouble()
                else -> null
            }
            out.add(argTypes[i] to v)
        }
        return out
    }

    private fun pushVariadicArgs(b: StackBalancer, ev: JsonNode, knownDesc: String?, fallbackDesc: String?) {
        val desc = knownDesc ?: fallbackDesc ?: return
        val argTypes = StackBalancer.parseArgTypes(desc)
        val args = ev["args"] ?: return
        for (i in argTypes.indices) {
            val n = args[2 + i] ?: continue
            val v: Any? = when {
                n.isTextual -> n.asText()
                n.isLong -> n.asLong()
                n.isInt -> n.asInt()
                n.isDouble -> n.asDouble()
                else -> null
            }
            b.pushArg(v, argTypes[i])
        }
    }

    private fun pushVariadicArgsForNonvirtual(b: StackBalancer, ev: JsonNode, knownDesc: String?, fallbackDesc: String?) {
        val desc = knownDesc ?: fallbackDesc ?: return
        val argTypes = StackBalancer.parseArgTypes(desc)
        val args = ev["args"] ?: return
        for (i in argTypes.indices) {
            val n = args[3 + i] ?: continue   // Nonvirtual has [obj, cls, mid, ...varargs]
            val v: Any? = when {
                n.isTextual -> n.asText()
                n.isLong -> n.asLong()
                n.isInt -> n.asInt()
                n.isDouble -> n.asDouble()
                else -> null
            }
            b.pushArg(v, argTypes[i])
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
