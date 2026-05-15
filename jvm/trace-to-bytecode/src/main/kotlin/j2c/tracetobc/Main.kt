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
        val byMethod = mutableMapOf<MethodKey, MutableList<TraceGroup>>()
        for (g in groups) {
            byMethod.getOrPut(g.method) { mutableListOf() }.add(g)
        }
        Files.createDirectories(output)
        // One shared translator so symbols (jclass/jmethodID/jfieldID/jstring
        // observed in any frame) carry across method invocations.
        val translator = TraceTranslator(mani)
        translator.warmup(events)
        var produced = 0
        for ((mk, invocations) in byMethod) {
            // Pick the longest (most informative) trace for this method
            val pick = invocations.maxByOrNull { it.events.size } ?: continue
            // Union of exception types observed across ALL invocations of
            // this method — single-invocation traces may not exercise every
            // catch path, but we want to surface every type we ever saw.
            val excTypes = invocations.flatMap { it.exceptionsObserved }.toSortedSet().toList()
            val recovered = translator.translate(mk, pick.events, confidence)
                .copy(exceptionsObserved = excTypes)
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

data class TraceGroup(
    val method: MethodKey,
    val events: List<JsonNode>,
    // Exception class names observed propagating out of or caught within
    // this method during the trace (collected from JVMTI `exc` / `excCatch`
    // events that fired while this frame was on the per-thread stack).
    val exceptionsObserved: List<String> = emptyList(),
)

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

/**
 * Detect and collapse repeated multi-event patterns within a single
 * method-invocation frame.
 *
 * Long-running programs (game loops, request handlers, etc.) produce
 * traces with the same call sequence repeated N times — e.g. a game loop
 * running 8 iterations gives 8 copies of `[NEW Piece, INVOKESPECIAL <init>,
 * INVOKEVIRTUAL collides, ..., INVOKEVIRTUAL lock]`. Without collapsing,
 * the recovered bytecode contains 8 unrolled copies, making the
 * decompiled output hundreds of lines instead of one iteration.
 *
 * Strategy: scan left-to-right; at each position try pattern lengths
 * 1..maxLen and find the (length, repetition-count) pair maximizing
 * total covered events. Keep one copy of the pattern, advance past the
 * rest. Two events are considered "same shape" iff their `call` and
 * `midDesc` fields match — concrete jobject hexes and primitive values
 * are ignored, which is the right granularity for loops where each
 * iteration touches fresh objects with the same operation sequence.
 */
private fun collapseRepeats(events: MutableList<JsonNode>, maxLen: Int = 32): MutableList<JsonNode> {
    if (events.size < 4) return events
    /**
     * Shape signature: identifies "the same kind of operation" across loop
     * iterations while ignoring concrete jobject hexes and primitive values
     * (those typically differ each iteration).  But it DOES include literal
     * string args so that e.g. `GetMethodID(c, "head", "()LCell;")` is not
     * confused with `GetMethodID(c, "tail", "()V")` — those have the same
     * call name and empty midDesc but are entirely different operations.
     */
    fun sig(e: JsonNode): String {
        val call = e["call"]?.asText() ?: return "?"
        val midDesc = e["midDesc"]?.asText() ?: ""
        val sb = StringBuilder()
        sb.append(call).append('|').append(midDesc)
        val args = e["args"]
        if (args != null) {
            for (i in 0 until args.size()) {
                val v = args[i]
                sb.append('|')
                when {
                    v.isTextual && v.asText().startsWith("0x") -> sb.append('h')  // opaque jobject
                    v.isTextual -> sb.append('s').append(v.asText().take(80))    // literal string content
                    v.isInt || v.isLong -> sb.append('p')                          // primitive value
                    v.isNull -> sb.append('n')
                    else -> sb.append('?')
                }
            }
        }
        return sb.toString()
    }
    val out = ArrayList<JsonNode>(events.size)
    var i = 0
    while (i < events.size) {
        var bestL = 0
        var bestReps = 1
        var L = 1
        val ceil = minOf(maxLen, (events.size - i) / 2)
        while (L <= ceil) {
            // count consecutive immediate repetitions of events[i..i+L) at strides of L
            var reps = 1
            while (i + reps * L + L <= events.size) {
                var match = true
                for (k in 0 until L) {
                    if (sig(events[i + k]) != sig(events[i + reps * L + k])) { match = false; break }
                }
                if (!match) break
                reps++
            }
            if (reps > 1 && L * reps > bestL * bestReps) {
                bestL = L; bestReps = reps
            }
            L++
        }
        if (bestReps > 1 && bestL > 0) {
            for (k in 0 until bestL) out.add(events[i + k])
            i += bestL * bestReps
        } else {
            out.add(events[i])
            i++
        }
    }
    // If we actually collapsed something, return a fresh list; otherwise
    // return the original to avoid extra allocation.
    return if (out.size != events.size) out.toMutableList() else events
}


private fun groupByMethodInvocation(events: List<JsonNode>): List<TraceGroup> {
    // Per-thread stack of active enter events; we collect all `jni` events
    // between an enter and its matching exit and attribute them to the
    // outermost frame on that thread. Exception events are recorded against
    // every frame currently on the stack, since an exception in one frame
    // can propagate up to be caught in another.
    data class Frame(
        val key: MethodKey,
        val jniBuf: MutableList<JsonNode>,
        val excTypes: MutableSet<String>,
    )
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
                perThread.getOrPut(thr) { ArrayDeque() }.addLast(
                    Frame(key, mutableListOf(), mutableSetOf())
                )
            }
            "exit" -> {
                val stack = perThread[thr] ?: continue
                val frame = stack.removeLastOrNull() ?: continue
                result.add(TraceGroup(
                    frame.key,
                    collapseRepeats(frame.jniBuf),
                    frame.excTypes.toList(),
                ))
            }
            "jni" -> {
                val stack = perThread[thr] ?: continue
                stack.lastOrNull()?.jniBuf?.add(ev)
            }
            "exc", "excCatch" -> {
                val stack = perThread[thr] ?: continue
                val excType = ev["excType"]?.asText() ?: continue
                // The exception was raised inside the topmost frame and may
                // propagate through (or be caught in) any frame up the stack.
                // Tag every active frame so each gets credit for handling it.
                for (f in stack) f.excTypes.add(excType)
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
        // Source-pool string literal (from NewStringUTF or .intern()-style
        // propagation). Safe to LDC without dynamic marker.
        data class StringLit(val value: String) : Sym()
        // Runtime-computed string content (e.g. CallObjectMethod returning
        // Ljava/lang/String; — toString(), concat results, etc.). The content
        // is observed for *this* trace but the source code doesn't hardcode
        // it; we mark any LDC with this content as dynamic="str_computed".
        data class StringComputed(val value: String) : Sym()
        // A jobject whose runtime type is known (from the method/field
        // descriptor that produced it, or from a NEW/ANEWARRAY). `desc`
        // is a JVM type descriptor (e.g. "Ljava/util/HashMap;" or "[I").
        // This is the workhorse for cross-frame identity propagation:
        // jobjects returned from a callee become typed at their caller's
        // call site too, so receivers/args downstream can ALOAD or
        // CHECKCAST to the right narrow type rather than fall through to
        // ACONST_NULL + CHECKCAST<best-guess>.
        data class Object(val desc: String) : Sym()
        data class Unknown(val origin: String) : Sym()
    }

    /**
     * Best-effort: return the internal-name type for a jobject hex, drawing
     * on the cross-frame [symbols] table populated during warmup + the
     * per-call updateSymbols pass. Returns null if the hex is unknown or its
     * recorded sym doesn't carry a useful type.
     */
    private fun symbolType(hex: String?): String? {
        if (hex == null) return null
        val sym = symbols[hex] ?: return null
        return when (sym) {
            is Sym.Class -> "java/lang/Class"
            is Sym.MethodId, is Sym.FieldId -> null
            is Sym.StringLit, is Sym.StringComputed -> "java/lang/String"
            is Sym.Object -> {
                val d = sym.desc
                when {
                    d.startsWith("L") && d.endsWith(";") -> d.substring(1, d.length - 1)
                    d.startsWith("[") -> d   // array descriptor used as-is
                    else -> null
                }
            }
            is Sym.Unknown -> null
        }
    }

    /** Set of string contents observed as runtime-computed (via retStr on
     *  Call*Method events). Used by [pushArg] / [pushString]-callers to
     *  mark LDC<String> insns as dynamic="str_computed" when the literal
     *  matches a known computed-content string. */
    private val computedStringContents = mutableSetOf<String>()

    /**
     * Method-name fragments characteristic of invokedynamic bootstrap chains
     * produced by native-obfuscator's IndyPreprocessor. When the translator
     * sees a JNI call whose targeted Java method name matches one of these,
     * it tags the emitted insn `dynamic="indy_chain"` so the per-method
     * @j2c.RuntimeTrace annotation flags "a lambda / dynamic call was here".
     *
     * The schema ({@link BsmArg} etc.) and AsmEmitter support for emitting
     * INVOKEDYNAMIC are in place; full chain-collapse (reconstructing
     * bootstrap args samMethodType / implMethod / instantiatedMethodType
     * from the variadic-decoded JNI call sequence) is tracked in ROADMAP.md.
     */
    private val INDY_BOOTSTRAP_METHOD_FRAGMENTS = listOf(
        "linkCallSite",                 // HotSpot internal entry point
        "metafactory",                  // LambdaMetafactory.metafactory
        "altMetafactory",
        "makeConcat",                   // StringConcatFactory.makeConcat*
        "makeConcatWithConstants",
        "invokeWithArguments",          // MethodHandle.invokeWithArguments
        "getTarget",                    // CallSite.getTarget (final step)
    )

    /** Method-name -> midDesc-suffix patterns we'll treat as indy chain
     *  participants. Returning Ljava/lang/invoke/CallSite; or MemberName;
     *  is also a strong signal. */
    private val INDY_RET_TYPE_SUFFIXES = listOf(
        ")Ljava/lang/invoke/CallSite;",
        ")Ljava/lang/invoke/MemberName;",
        ")Ljava/lang/invoke/MethodHandle;",
        ")Ljava/lang/invoke/MethodType;",
    )

    /** Set of insn indices in `out` that should be tagged as indy chain. */
    private val pendingIndyMarks = mutableSetOf<Int>()

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

    /** The class of the method currently being translated — used as a
     *  fallback owner when a GETFIELD/PUTFIELD/INVOKE's owner couldn't be
     *  resolved from the trace. Set by `translate`. */
    private var currentOwner: String = "java/lang/Object"

    fun translate(method: MethodKey, jniEvents: List<JsonNode>, confidence: String): RecoveredMethod {
        currentOwner = method.owner
        // Look up the access flags so we know whether `this` is available
        val mc = manifest.classes.firstOrNull { it.name == method.owner }
        val mm = mc?.methods?.firstOrNull { it.name == method.name && it.desc == method.desc }
        val isStatic = mm != null && (mm.access and 0x0008) != 0  // ACC_STATIC
        val balancer = StackBalancer(isStatic)
        val slotMap = mutableMapOf<String, Int>()
        // Param slots (slot index, descriptor letter for the param) in JVM
        // local-var layout order. Long/Double consume 2 slots; the second
        // half is unused by anything but verifier wide-store rules.
        val paramLayout = parseParamLayout(method.desc, isStatic)
        val paramSlotsTotal = paramSlotCount(method.desc, isStatic)

        // 1) Bind `this` (for non-static) and reference parameters via the
        //    "external jobject ordering" heuristic — see [bindParams] for
        //    detail. This handles both methods that do an explicit
        //    GetObjectClass(this) prologue and ones that don't.
        bindParams(jniEvents, paramLayout, isStatic, slotMap)

        // 2) Allocate SSA slots for every jobject that's used as an arg in
        //    some later event. Slots start at paramSlotsTotal.
        var nextSlot = paramSlotsTotal
        if (slotMap.values.any { it == 0 }) nextSlot = maxOf(nextSlot, 1)

        // Position-aware: only allocate a slot for hex H if there exists a
        // producer event at index i with ret=H AND a consumer event at
        // index j > i with H in args. Also skip hexes used as args only
        // *adjacent* to their producer (those are the "chain" case that
        // prepareCall's matchesTop already handles for free).
        val producers = mutableMapOf<String, Int>()  // hex -> earliest producer idx
        for ((i, ev) in jniEvents.withIndex()) {
            if (ev["ev"]?.asText() != "jni") continue
            val retHex = ev["ret"]?.takeIf { it.isTextual }?.asText() ?: continue
            if (retHex.startsWith("0x") && retHex !in producers) producers[retHex] = i
        }
        val needSlot = mutableSetOf<String>()
        for ((i, ev) in jniEvents.withIndex()) {
            if (ev["ev"]?.asText() != "jni") continue
            val args = ev["args"] ?: continue
            for (k in 0 until args.size()) {
                val v = args[k]
                if (!v.isTextual) continue
                val h = v.asText()
                if (!h.startsWith("0x")) continue
                val pIdx = producers[h] ?: continue
                if (i > pIdx + 1) needSlot.add(h)  // skip chain case (i == pIdx+1)
            }
        }
        for ((retHex, _) in producers.entries.sortedBy { it.value }) {
            if (retHex in needSlot && retHex !in slotMap) {
                slotMap[retHex] = nextSlot
                nextSlot += 1
            }
        }

        balancer.slotMap = slotMap
        balancer.typeOracle = { hex -> symbolType(hex) }

        // 3) Initialize each SSA slot to `null` at method entry. Subsequent
        //    producers will overwrite via DUP+ASTORE; consumers (ALOAD) are
        //    then always safe even if the producer event didn't actually
        //    emit (e.g. it was dropped as infrastructure noise). Slots 0..
        //    paramSlotsTotal-1 are NOT initialized — the JVM already placed
        //    the real `this` and method parameter values there.
        for ((_, slot) in slotMap.toList().sortedBy { it.second }) {
            if (slot < paramSlotsTotal) continue
            balancer.out += RecoveredInsn(op = "ACONST_NULL")
            balancer.out += RecoveredInsn(op = "ASTORE", `var` = slot)
        }

        for (ev in jniEvents) {
            val call = ev["call"]?.asText() ?: continue
            translateCall(call, ev, balancer)
        }
        // Final return instruction with stack fixup
        balancer.fixupReturn(method.desc)
        // Post-pass: any LDC<String> whose value matches a known
        // runtime-computed string content (recorded as we processed
        // Call*Method returns with the agent's `retStr` field) gets tagged
        // dynamic="str_computed", so the @j2c.RuntimeTrace annotation /
        // inline marker surfaces it to the reverse-engineer reading the
        // recovered code.
        if (computedStringContents.isNotEmpty()) {
            for (i in balancer.out.indices) {
                val ins = balancer.out[i]
                if (ins.op != "LDC") continue
                if (ins.dynamic != null) continue
                val v = ins.value as? String ?: continue
                if (v in computedStringContents) {
                    balancer.out[i] = ins.copy(dynamic = "str_computed")
                }
            }
        }
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
        val isIndyEvent = looksLikeIndyChainEvent(call, ev, midDesc)
        val outSizeBefore = b.out.size
        translateCallInner(call, ev, args, midDesc, b)
        if (isIndyEvent) {
            for (i in outSizeBefore until b.out.size) {
                if (b.out[i].dynamic == null) {
                    b.out[i] = b.out[i].copy(dynamic = "indy_chain")
                }
            }
        }
    }

    /**
     * Heuristic: does this JNI call event participate in an invokedynamic
     * bootstrap chain (as produced by native-obfuscator's IndyPreprocessor)?
     *
     * Two signals:
     *  - midDesc returns one of [INDY_RET_TYPE_SUFFIXES] (CallSite / MemberName
     *    / MethodHandle / MethodType — bootstrap intermediaries)
     *  - target method name (resolved via the symbol table) contains an
     *    [INDY_BOOTSTRAP_METHOD_FRAGMENTS] fragment
     */
    private fun looksLikeIndyChainEvent(call: String, ev: JsonNode, midDesc: String?): Boolean {
        // Static / virtual / nonvirtual Call*Method only.
        if (!call.startsWith("Call")) return false
        if (midDesc != null) {
            for (suf in INDY_RET_TYPE_SUFFIXES) if (midDesc.endsWith(suf)) return true
        }
        // Try to resolve the targeted Java method via the global symbol table.
        val args = ev["args"] ?: return false
        val midHexIdx = if (call == "CallNonvirtualVoidMethod" || call == "CallNonvirtualObjectMethod") 2
                        else if (call.startsWith("CallStatic")) 1
                        else 1
        if (midHexIdx >= args.size()) return false
        val mid = symbols[args[midHexIdx]?.asText()] as? Sym.MethodId ?: return false
        val name = mid.name ?: return false
        for (frag in INDY_BOOTSTRAP_METHOD_FRAGMENTS) if (name.contains(frag)) return true
        return false
    }

    private fun translateCallInner(call: String, ev: JsonNode, args: JsonNode?, midDesc: String?, b: StackBalancer) {
        when (call) {
            "GetStaticObjectField", "GetStaticBooleanField", "GetStaticByteField",
            "GetStaticCharField", "GetStaticShortField", "GetStaticIntField",
            "GetStaticLongField" -> {
                val fid = symbols[args?.get(1)?.asText()] as? Sym.FieldId ?: return
                val rawOwner = fid.owner ?: currentOwner
                val owner = if (rawOwner.startsWith("[")) currentOwner else rawOwner
                val produce = produceFor(fid.desc, ev["ret"]?.asText())
                b.emitRaw(
                    RecoveredInsn(op = "GETSTATIC", owner = owner, name = fid.name, desc = fid.desc),
                    consume = 0, produce = produce,
                )
                if (call == "GetStaticObjectField") b.maybeStash(ev["ret"]?.asText())
            }

            "GetObjectField", "GetBooleanField", "GetByteField",
            "GetCharField", "GetShortField", "GetIntField", "GetLongField" -> {
                val fid = symbols[args?.get(1)?.asText()] as? Sym.FieldId ?: return
                val rawOwner = fid.owner ?: currentOwner
                val owner = if (rawOwner.startsWith("[")) currentOwner else rawOwner
                b.ensureReceiver(args?.get(0)?.asText(), owner)
                val produce = produceFor(fid.desc, ev["ret"]?.asText())
                b.emitRaw(
                    RecoveredInsn(op = "GETFIELD", owner = owner, name = fid.name, desc = fid.desc),
                    consume = 1, produce = produce,
                )
                if (call == "GetObjectField") b.maybeStash(ev["ret"]?.asText())
            }

            "SetObjectField", "SetBooleanField", "SetByteField",
            "SetCharField", "SetShortField", "SetIntField", "SetLongField" -> {
                val fid = symbols[args?.get(1)?.asText()] as? Sym.FieldId ?: return
                val rawOwner = fid.owner ?: currentOwner
                val owner = if (rawOwner.startsWith("[")) currentOwner else rawOwner
                b.ensureReceiver(args?.get(0)?.asText(), owner)
                b.pushArg(extractScalar(args?.get(2)), fid.desc ?: "I", dynamicKind = "field_value")
                b.emitRaw(
                    RecoveredInsn(op = "PUTFIELD", owner = owner, name = fid.name, desc = fid.desc),
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
                    b.prepareCall(receiverHex = newRetHex, receiverType = mid.owner, argDescAndHex = pairs)
                    b.emitInvoke(RecoveredInsn(op = "INVOKESPECIAL", owner = mid.owner, name = mid.name, desc = ctorDesc))
                    // After init, the just-constructed object is on stack (initialized).
                    b.maybeStash(newRetHex)
                }
            }

            "CallNonvirtualVoidMethod", "CallNonvirtualObjectMethod" -> {
                val mid = symbols[args?.get(2)?.asText()] as? Sym.MethodId
                if (mid != null && mid.owner != null) {
                    val pairs = collectVariadicPairs(ev, mid.desc, midDesc, varadicStartIdx = 3)
                    b.prepareCall(receiverHex = args?.get(0)?.asText(), receiverType = mid.owner, argDescAndHex = pairs)
                    b.emitInvoke(RecoveredInsn(op = "INVOKESPECIAL", owner = mid.owner, name = mid.name, desc = mid.desc ?: midDesc),
                                 returnHex = ev["ret"]?.asText())
                    // <init> via Nonvirtual leaves the receiver initialized on stack
                    if (mid.name == "<init>") b.maybeStash(args?.get(0)?.asText())
                    else if (call == "CallNonvirtualObjectMethod") b.maybeStash(ev["ret"]?.asText())
                }
            }

            in CALL_OBJECT_VARIANTS, in CALL_PRIM_VARIANTS -> {
                val isStaticCall = call.startsWith("CallStatic")
                val mid = symbols[args?.get(1)?.asText()] as? Sym.MethodId
                if (mid != null && mid.owner != null) {
                    val pairs = collectVariadicPairs(ev, mid.desc, midDesc, varadicStartIdx = 2)
                    b.prepareCall(
                        receiverHex = if (isStaticCall) null else args?.get(0)?.asText(),
                        receiverType = if (isStaticCall) null else mid.owner,
                        argDescAndHex = pairs,
                    )
                    b.emitInvoke(
                        RecoveredInsn(
                            op = if (isStaticCall) "INVOKESTATIC" else "INVOKEVIRTUAL",
                            owner = mid.owner, name = mid.name, desc = mid.desc ?: midDesc,
                        ),
                        returnHex = ev["ret"]?.asText(),
                    )
                    if (call in CALL_OBJECT_VARIANTS) b.maybeStash(ev["ret"]?.asText())
                }
            }

            "IsInstanceOf" -> {
                val cls = symbols[args?.get(1)?.asText()] as? Sym.Class
                if (cls != null) {
                    b.ensureReceiver(args?.get(0)?.asText(), "java/lang/Object")
                    b.emitRaw(RecoveredInsn(op = "INSTANCEOF", type = cls.internalName), 1, StackBalancer.V.Int)
                }
            }

            "GetArrayLength" -> {
                b.ensureReceiver(args?.get(0)?.asText(), "[Ljava/lang/Object;")
                b.emitRaw(RecoveredInsn(op = "ARRAYLENGTH"), 1, StackBalancer.V.Int)
            }

            "NewObjectArray" -> {
                val cls = symbols[args?.get(1)?.asText()] as? Sym.Class
                if (cls != null) {
                    b.pushInt(args?.get(0)?.asInt() ?: 0, dynamicKind = "arr_size")
                    b.emitRaw(RecoveredInsn(op = "ANEWARRAY", type = cls.internalName), 1, StackBalancer.V.Obj)
                }
            }

            "NewBooleanArray" -> { b.pushInt(args?.get(0)?.asInt() ?: 0, dynamicKind = "arr_size"); b.emitRaw(RecoveredInsn(op = "NEWARRAY", value = 4), 1, StackBalancer.V.Obj) }
            "NewCharArray"    -> { b.pushInt(args?.get(0)?.asInt() ?: 0, dynamicKind = "arr_size"); b.emitRaw(RecoveredInsn(op = "NEWARRAY", value = 5), 1, StackBalancer.V.Obj) }
            "NewFloatArray"   -> { b.pushInt(args?.get(0)?.asInt() ?: 0, dynamicKind = "arr_size"); b.emitRaw(RecoveredInsn(op = "NEWARRAY", value = 6), 1, StackBalancer.V.Obj) }
            "NewDoubleArray"  -> { b.pushInt(args?.get(0)?.asInt() ?: 0, dynamicKind = "arr_size"); b.emitRaw(RecoveredInsn(op = "NEWARRAY", value = 7), 1, StackBalancer.V.Obj) }
            "NewByteArray"    -> { b.pushInt(args?.get(0)?.asInt() ?: 0, dynamicKind = "arr_size"); b.emitRaw(RecoveredInsn(op = "NEWARRAY", value = 8), 1, StackBalancer.V.Obj) }
            "NewShortArray"   -> { b.pushInt(args?.get(0)?.asInt() ?: 0, dynamicKind = "arr_size"); b.emitRaw(RecoveredInsn(op = "NEWARRAY", value = 9), 1, StackBalancer.V.Obj) }
            "NewIntArray"     -> { b.pushInt(args?.get(0)?.asInt() ?: 0, dynamicKind = "arr_size"); b.emitRaw(RecoveredInsn(op = "NEWARRAY", value = 10), 1, StackBalancer.V.Obj) }
            "NewLongArray"    -> { b.pushInt(args?.get(0)?.asInt() ?: 0, dynamicKind = "arr_size"); b.emitRaw(RecoveredInsn(op = "NEWARRAY", value = 11), 1, StackBalancer.V.Obj) }

            "GetObjectArrayElement" -> {
                b.ensureReceiver(args?.get(0)?.asText(), "[Ljava/lang/Object;")
                b.pushInt(args?.get(1)?.asInt() ?: 0, dynamicKind = "arr_idx")
                b.emitRaw(RecoveredInsn(op = "AALOAD"), 2, StackBalancer.V.Obj)
            }
            "SetObjectArrayElement" -> {
                b.ensureReceiver(args?.get(0)?.asText(), "[Ljava/lang/Object;")
                b.pushInt(args?.get(1)?.asInt() ?: 0, dynamicKind = "arr_idx")
                b.pushObjLiteral(args?.get(2)?.asText() ?: "0x0", "java/lang/Object")
                b.emitRaw(RecoveredInsn(op = "AASTORE"), 3, null)
            }

            "GetBooleanArrayRegion" -> emitArrayLoad(b, args, "[Z", "BALOAD", StackBalancer.V.Int)
            "GetByteArrayRegion"    -> emitArrayLoad(b, args, "[B", "BALOAD", StackBalancer.V.Int)
            "GetCharArrayRegion"    -> emitArrayLoad(b, args, "[C", "CALOAD", StackBalancer.V.Int)
            "GetShortArrayRegion"   -> emitArrayLoad(b, args, "[S", "SALOAD", StackBalancer.V.Int)
            "GetIntArrayRegion"     -> emitArrayLoad(b, args, "[I", "IALOAD", StackBalancer.V.Int)
            "GetLongArrayRegion"    -> emitArrayLoad(b, args, "[J", "LALOAD", StackBalancer.V.Long)
            "GetFloatArrayRegion"   -> emitArrayLoad(b, args, "[F", "FALOAD", StackBalancer.V.Float)
            "GetDoubleArrayRegion"  -> emitArrayLoad(b, args, "[D", "DALOAD", StackBalancer.V.Double)

            "SetBooleanArrayRegion" -> emitArrayStore(b, args, "[Z", "Z", "BASTORE")
            "SetByteArrayRegion"    -> emitArrayStore(b, args, "[B", "B", "BASTORE")
            "SetCharArrayRegion"    -> emitArrayStore(b, args, "[C", "C", "CASTORE")
            "SetShortArrayRegion"   -> emitArrayStore(b, args, "[S", "S", "SASTORE")
            "SetIntArrayRegion"     -> emitArrayStore(b, args, "[I", "I", "IASTORE")
            "SetLongArrayRegion"    -> emitArrayStore(b, args, "[J", "J", "LASTORE")
            "SetFloatArrayRegion"   -> emitArrayStore(b, args, "[F", "F", "FASTORE")
            "SetDoubleArrayRegion"  -> emitArrayStore(b, args, "[D", "D", "DASTORE")

            "Throw", "ThrowNew" -> b.emitRaw(RecoveredInsn(op = "ATHROW"), 1, null)

            else -> {}
        }
    }

    private fun paramSlotCount(desc: String, isStatic: Boolean): Int {
        var slots = if (isStatic) 0 else 1
        val args = StackBalancer.parseArgTypes(desc)
        for (a in args) {
            slots += if (a == "J" || a == "D") 2 else 1
        }
        return slots
    }

    /**
     * Return the JVM local-slot layout of a method's parameters, as a list
     * of (slot, paramDesc) pairs in declaration order. Slot 0 == `this`
     * for non-static methods (emitted as ("Lowner;" placeholder for the
     * descriptor — callers that need the precise owner can look it up via
     * [MethodKey.owner]). Long/Double consume 2 slots; only the first slot
     * is in the list since the second is implicit.
     */
    private fun parseParamLayout(desc: String, isStatic: Boolean): List<Pair<Int, String>> {
        val out = mutableListOf<Pair<Int, String>>()
        var slot = 0
        if (!isStatic) {
            out += slot to "Ljava/lang/Object;"
            slot += 1
        }
        for (a in StackBalancer.parseArgTypes(desc)) {
            out += slot to a
            slot += if (a == "J" || a == "D") 2 else 1
        }
        return out
    }

    /**
     * Heuristic — populate `slotMap` with `paramHex -> slot` for `this` and
     * each reference-typed parameter.
     *
     * Mechanics: a jobject that appears as an arg of some JNI call but was
     * NEVER itself returned by a prior JNI call in this frame must have
     * entered the frame from outside — i.e. it was a method parameter (or
     * `this` for non-static methods). We collect these "external" jobjects
     * in order of first appearance and match them positionally to the L/[
     * slots of `paramLayout`:
     *
     *   - non-static: first external -> slot 0 (this), next -> first ref
     *     param slot, etc.
     *   - static: first external -> first ref param slot.
     *
     * native-obfuscator's `cstack[0] = arg1` prologue is C++-side (no JNI
     * call), so we can't detect `this` from the prologue itself — but the
     * first time `this` is USED as a receiver (in any CallObjectMethod /
     * GetObjectField / etc.) we observe it in JNI args, and since it was
     * never produced by a JNI call it's the first external.
     *
     * Limitations:
     *  - Primitive params (I/J/F/D/B/S/C/Z) aren't handled. On HotSpot
     *    JVMTI cannot read locals of a native frame (OPAQUE_FRAME), so
     *    capturing primitives would require libffi-style trampolines —
     *    tracked in ROADMAP.md.
     *  - A ref param that the method NEVER touches via JNI is invisible
     *    and stays unbound. That's the right outcome — if the recovered
     *    body doesn't use it, no slot is needed.
     *  - If a frame's first external IS a param (not `this`) — e.g. when
     *    `this` is never used at all but a param is — we mis-assign. In
     *    practice native-obfuscator's prologue copies `this` to a cstack
     *    slot even when unused, but the COPY is C++-only and invisible;
     *    if the method body genuinely never references `this`, our slot 0
     *    binding goes to the first used param. Mitigation: a body that
     *    doesn't reference `this` won't ALOAD slot 0, so the mis-binding
     *    is harmless.
     */
    private fun bindParams(
        jniEvents: List<JsonNode>,
        paramLayout: List<Pair<Int, String>>,
        isStatic: Boolean,
        slotMap: MutableMap<String, Int>,
    ) {
        // Target slot list: for non-static, prepend `this` slot 0 to the ref
        // param slot list (since `this` is also a reference and consumes
        // slot 0 in JVM local-var layout). For static, just ref params.
        val targetSlots = mutableListOf<Int>()
        if (!isStatic) targetSlots += 0
        for ((slot, d) in paramLayout) {
            if (slot == 0 && !isStatic) continue  // already counted above
            if (d.startsWith("L") || d.startsWith("[")) targetSlots += slot
        }
        if (targetSlots.isEmpty()) return

        val produced = mutableSetOf<String>()
        val firstExternalSeen = mutableListOf<String>()
        outer@ for (ev in jniEvents) {
            if (ev["ev"]?.asText() != "jni") continue
            val retNode = ev["ret"]
            if (retNode != null && retNode.isTextual) {
                val r = retNode.asText()
                if (r.startsWith("0x")) produced += r
            }
            val args = ev["args"] ?: continue
            for (k in 0 until args.size()) {
                val v = args[k]
                if (!v.isTextual) continue
                val h = v.asText()
                if (!h.startsWith("0x")) continue
                if (h in produced) continue
                if (slotMap.containsKey(h)) continue
                // Skip globally-known infrastructure (jclass / jmethodID /
                // jfieldID / known string literal) — these came from prior
                // frames (e.g. registerNativesForClass), not from caller
                // arg slots, so they aren't params.
                if (symbols[h] != null) continue
                if (h !in firstExternalSeen) firstExternalSeen += h
                if (firstExternalSeen.size >= targetSlots.size) break@outer
            }
        }
        for ((idx, hex) in firstExternalSeen.withIndex()) {
            if (idx >= targetSlots.size) break
            slotMap[hex] = targetSlots[idx]
        }
    }

    private fun emitArrayLoad(b: StackBalancer, args: JsonNode?, arrType: String, op: String, produces: StackBalancer.V) {
        // ArrayRegion args: [array, start, len, (value)] — when len==1 we
        // treat this as a single element load (xALOAD).
        b.ensureReceiver(args?.get(0)?.asText(), arrType)
        b.pushInt(args?.get(1)?.asInt() ?: 0, dynamicKind = "arr_idx")
        b.emitRaw(RecoveredInsn(op = op), 2, produces)
    }

    private fun emitArrayStore(b: StackBalancer, args: JsonNode?, arrType: String, elemDesc: String, op: String) {
        b.ensureReceiver(args?.get(0)?.asText(), arrType)
        b.pushInt(args?.get(1)?.asInt() ?: 0, dynamicKind = "arr_idx")
        b.pushArg(extractScalar(args?.get(3)), elemDesc, dynamicKind = "arr_value")
        b.emitRaw(RecoveredInsn(op = op), 3, null)
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

            // ---- Cross-frame typing: any JNI call whose return type is
            //      directly inferable from its args gets a Sym.Object entry.

            "NewObject" -> {
                val cls = symbols[args?.get(1)?.asText()] as? Sym.MethodId
                val owner = cls?.owner
                if (owner != null && retHex != null && symbols[retHex] == null) {
                    symbols[retHex] = Sym.Object("L$owner;")
                }
            }
            "AllocObject" -> {
                val cls = symbols[args?.get(0)?.asText()] as? Sym.Class
                if (cls != null && retHex != null && symbols[retHex] == null) {
                    symbols[retHex] = Sym.Object("L${cls.internalName};")
                }
            }
            "NewObjectArray" -> {
                val cls = symbols[args?.get(1)?.asText()] as? Sym.Class
                if (cls != null && retHex != null && symbols[retHex] == null) {
                    symbols[retHex] = Sym.Object("[L${cls.internalName};")
                }
            }
            "NewBooleanArray" -> retHex?.let { if (symbols[it] == null) symbols[it] = Sym.Object("[Z") }
            "NewCharArray"    -> retHex?.let { if (symbols[it] == null) symbols[it] = Sym.Object("[C") }
            "NewFloatArray"   -> retHex?.let { if (symbols[it] == null) symbols[it] = Sym.Object("[F") }
            "NewDoubleArray"  -> retHex?.let { if (symbols[it] == null) symbols[it] = Sym.Object("[D") }
            "NewByteArray"    -> retHex?.let { if (symbols[it] == null) symbols[it] = Sym.Object("[B") }
            "NewShortArray"   -> retHex?.let { if (symbols[it] == null) symbols[it] = Sym.Object("[S") }
            "NewIntArray"     -> retHex?.let { if (symbols[it] == null) symbols[it] = Sym.Object("[I") }
            "NewLongArray"    -> retHex?.let { if (symbols[it] == null) symbols[it] = Sym.Object("[J") }

            "GetObjectField" -> {
                val fid = symbols[args?.get(1)?.asText()] as? Sym.FieldId
                val d = fid?.desc
                if (d != null && retHex != null && (d.startsWith("L") || d.startsWith("[")) && symbols[retHex] == null) {
                    symbols[retHex] = Sym.Object(d)
                }
            }
            "GetStaticObjectField" -> {
                val fid = symbols[args?.get(1)?.asText()] as? Sym.FieldId
                val d = fid?.desc
                if (d != null && retHex != null && (d.startsWith("L") || d.startsWith("[")) && symbols[retHex] == null) {
                    symbols[retHex] = Sym.Object(d)
                }
            }

            in CALL_OBJECT_VARIANTS -> {
                // Heuristic 1 (cross-frame typing): if midDesc declares an
                // object return type and we haven't already pinned the return
                // hex to a more specific Sym variant, record the type so any
                // downstream frame that uses this jobject can recover a real
                // CHECKCAST / receiver type. Skip overwriting Class /
                // StringLit / StringComputed / etc. so we don't clobber
                // more-specific info from other heuristics.
                if (midDesc != null && retHex != null) {
                    val ret = midDesc.substringAfterLast(')')
                    if ((ret.startsWith("L") || ret.startsWith("[")) && ret != "Ljava/lang/Object;") {
                        if (symbols[retHex] == null) {
                            symbols[retHex] = Sym.Object(ret)
                        }
                    }
                }
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
                // Heuristic 3: a Call*Method returning Ljava/lang/String;
                //  - if the receiver was already a StringLit (e.g. .intern()),
                //    propagate as StringLit (source-pool literal).
                //  - if the agent attached retStr (runtime jstring content
                //    snapshot), bind the return jstring to StringComputed so
                //    any later use of this jstring's content via the agent's
                //    arg-inlining path is recognised as runtime-computed.
                if (midDesc != null && midDesc.endsWith(")Ljava/lang/String;")) {
                    val recv = args?.get(0)?.asText()
                    val lit = symbols[recv] as? Sym.StringLit
                    if (lit != null && retHex != null) {
                        symbols[retHex] = Sym.StringLit(lit.value)
                    } else {
                        val retStrNode = ev["retStr"]
                        if (retStrNode != null && retStrNode.isTextual && retHex != null) {
                            val content = retStrNode.asText()
                            symbols[retHex] = Sym.StringComputed(content)
                            computedStringContents += content
                        }
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
