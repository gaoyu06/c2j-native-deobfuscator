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
        var produced = 0
        for ((mk, invocations) in byMethod) {
            // Pick the longest (most informative) trace for this method
            val pick = invocations.maxByOrNull { it.size } ?: continue
            val recovered = TraceTranslator(mani).translate(mk, pick, confidence)
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

    // Symbol table: maps jobject hex string -> known semantic
    private sealed class Sym {
        data class Class(val internalName: String) : Sym()
        data class MethodId(val owner: String, val name: String, val desc: String) : Sym()
        data class FieldId(val owner: String, val name: String, val desc: String) : Sym()
        data class StringLit(val value: String) : Sym()
        data class Unknown(val origin: String) : Sym()
    }

    private val symbols = mutableMapOf<String, Sym>()

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
        val args = ev["args"]
        val ret = ev["ret"]
        when (call) {
            "NewStringUTF" -> {
                val s = args?.get(0)?.asText() ?: return
                val retHex = ret?.asText() ?: return
                symbols[retHex] = Sym.StringLit(s)
                // We emit LDC only when this constant is USED — the symbol
                // table records it for now.
            }

            "FindClass" -> {
                val n = args?.get(0)?.asText() ?: return
                val retHex = ret?.asText() ?: return
                symbols[retHex] = Sym.Class(n)
            }

            "GetMethodID", "GetStaticMethodID" -> {
                val cls = symbols[args?.get(0)?.asText()] as? Sym.Class
                val name = args?.get(1)?.asText() ?: return
                val desc = args?.get(2)?.asText() ?: return
                val retHex = ret?.asText() ?: return
                if (cls != null) symbols[retHex] = Sym.MethodId(cls.internalName, name, desc)
            }

            "GetFieldID", "GetStaticFieldID" -> {
                val cls = symbols[args?.get(0)?.asText()] as? Sym.Class
                val name = args?.get(1)?.asText() ?: return
                val desc = args?.get(2)?.asText() ?: return
                val retHex = ret?.asText() ?: return
                if (cls != null) symbols[retHex] = Sym.FieldId(cls.internalName, name, desc)
            }

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
                if (ret != null) symbols[ret.asText()] = Sym.Unknown("getstatic-${fid.owner}.${fid.name}")
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
                if (ret != null) symbols[ret.asText()] = Sym.Unknown("getfield-${fid.owner}.${fid.name}")
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
                val cls = symbols[args?.get(0)?.asText()] as? Sym.Class ?: return
                val mid = symbols[args?.get(1)?.asText()] as? Sym.MethodId
                out += RecoveredInsn(op = "NEW", type = cls.internalName)
                out += RecoveredInsn(op = "DUP")
                if (mid != null) {
                    out += RecoveredInsn(
                        op = "INVOKESPECIAL",
                        owner = mid.owner,
                        name = mid.name,
                        desc = mid.desc,
                    )
                }
                if (ret != null) symbols[ret.asText()] = Sym.Unknown("new-${cls.internalName}")
            }

            in CALL_OBJECT_VARIANTS, in CALL_PRIM_VARIANTS -> {
                val isStatic = call.startsWith("CallStatic")
                val mid = symbols[args?.get(1)?.asText()] as? Sym.MethodId ?: return
                val op = if (isStatic) "INVOKESTATIC" else "INVOKEVIRTUAL"
                out += RecoveredInsn(
                    op = op,
                    owner = mid.owner,
                    name = mid.name,
                    desc = mid.desc,
                )
                if (ret != null && call != "CallVoidMethod" && call != "CallStaticVoidMethod") {
                    symbols[ret.asText()] = Sym.Unknown("call-${mid.owner}.${mid.name}")
                }
            }

            "Throw", "ThrowNew" -> {
                out += RecoveredInsn(op = "ATHROW")
            }

            else -> {
                // Untranslated: surface as a comment-like NOP using LABEL with a synthetic name
                // (downstream class-rebuilder will ignore unknown LABEL refs — they're noise.)
            }
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
