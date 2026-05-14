package j2c.tracetobc

import com.fasterxml.jackson.databind.JsonNode
import j2c.common.RecoveredInsn

/**
 * Best-effort operand-stack balancer.
 *
 * For each emit decision the translator makes, this helper:
 *   1. consults the JNI event's variadic args to know what *should* be
 *      sitting on the operand stack at that point;
 *   2. compares with the model stack to figure out what needs to be pushed;
 *   3. pushes the missing items via the most plausible bytecode:
 *      - String content -> LDC
 *      - Numeric primitive -> ICONST_x / BIPUSH / SIPUSH / LDC
 *      - Class reference -> LDC type
 *      - Unknown jobject when a previous INVOKE returned the same hex ->
 *        nothing (already on stack)
 *      - Unknown jobject otherwise -> ALOAD 0 for non-static methods
 *        (best-effort assumption it is ``this``); ACONST_NULL for static
 *        contexts.
 *
 * The balancer does not try to be perfectly correct — it aims to produce
 * verifiable bytecode for the common shapes that native-obfuscator-style
 * transpilers emit. When uncertain it falls back to ALOAD_0 / ACONST_NULL.
 */
class StackBalancer(private val isStatic: Boolean) {

    sealed class V {
        data class ObjHex(val hex: String) : V()
        object Obj : V()
        object Int : V()
        object Long : V()
        object Float : V()
        object Double : V()
    }

    val out: MutableList<RecoveredInsn> = mutableListOf()
    private val stack = ArrayDeque<V>()

    /**
     * SSA-style mapping: `jobject hex -> local var slot`. Populated once per
     * method-translation. When set, each producer-event emit will stash its
     * jobject return (via DUP + ASTORE), and any subsequent push of the same
     * jobject will ALOAD from the slot instead of falling back to a typed
     * null placeholder. Result: the recovered jar reuses real references
     * across the method body instead of NPE'ing on synthetic nulls.
     */
    var slotMap: Map<String, Int> = emptyMap()

    fun stackTop(): V? = stack.lastOrNull()
    fun stackSize(): Int = stack.size

    // ------------------------------------------------------------------
    // Push primitives & known values

    fun pushString(s: String) {
        out += RecoveredInsn(op = "LDC", value = s)
        stack.addLast(V.Obj)
    }

    fun pushNull() {
        out += RecoveredInsn(op = "ACONST_NULL")
        stack.addLast(V.Obj)
    }

    /**
     * Push a null reference cast to the given type. Verifier accepts this
     * (null is assignable to any reference type, CHECKCAST never throws on
     * null). At runtime this NPEs if used, but the goal is verification +
     * readability, not execution.
     *
     * `type` should be either an internal class name ("java/lang/String"),
     * an array descriptor ("[I", "[Ljava/lang/Object;"), or `null`/`?` to
     * fall back to plain ACONST_NULL.
     */
    fun pushNullAs(type: String?) {
        out += RecoveredInsn(op = "ACONST_NULL")
        if (!type.isNullOrEmpty() && type != "?") {
            out += RecoveredInsn(op = "CHECKCAST", type = type)
        }
        stack.addLast(V.Obj)
    }

    fun pushThis() {
        out += RecoveredInsn(op = "ALOAD", `var` = 0)
        stack.addLast(V.Obj)
    }

    fun pushInt(v: Int) {
        when (v) {
            in -1..5 -> out += RecoveredInsn(op = if (v == -1) "ICONST_M1" else "ICONST_$v")
            in Byte.MIN_VALUE.toInt()..Byte.MAX_VALUE.toInt() -> out += RecoveredInsn(op = "BIPUSH", value = v)
            in Short.MIN_VALUE.toInt()..Short.MAX_VALUE.toInt() -> out += RecoveredInsn(op = "SIPUSH", value = v)
            else -> out += RecoveredInsn(op = "LDC", value = v)
        }
        stack.addLast(V.Int)
    }

    fun pushLong(v: Long) {
        when (v) {
            0L -> out += RecoveredInsn(op = "LCONST_0")
            1L -> out += RecoveredInsn(op = "LCONST_1")
            else -> out += RecoveredInsn(op = "LDC", value = v, desc = "long")
        }
        stack.addLast(V.Long)
    }

    fun pushFloat(v: Double) { out += RecoveredInsn(op = "LDC", value = v, desc = "float"); stack.addLast(V.Float) }
    fun pushDouble(v: Double) { out += RecoveredInsn(op = "LDC", value = v, desc = "double"); stack.addLast(V.Double) }

    fun pushObjPlaceholder(type: String?) {
        pushNullAs(type)
    }

    fun pushObjLiteral(hex: String, type: String? = null) {
        // If this jobject has been stashed in the SSA slot map, reload it
        // — far better than synthesizing a null. Only fall through to the
        // `aconst_null + checkcast` path when no slot is available.
        val slot = slotMap[hex]
        if (slot != null) {
            out += RecoveredInsn(op = "ALOAD", `var` = slot)
            if (!type.isNullOrEmpty() && type != "?" && type != "java/lang/Object") {
                out += RecoveredInsn(op = "CHECKCAST", type = type)
            }
            stack.addLast(V.ObjHex(hex))
            return
        }
        out += RecoveredInsn(op = "ACONST_NULL")
        if (!type.isNullOrEmpty() && type != "?") {
            out += RecoveredInsn(op = "CHECKCAST", type = type)
        }
        stack.addLast(V.ObjHex(hex))
    }

    // ------------------------------------------------------------------
    // Emit an opcode that has known stack effects

    /**
     * Emit a "free" opcode that doesn't have args we need to balance for
     * (e.g. a `RETURN`).  Just adds the insn and adjusts the model.
     */
    fun emitRaw(insn: RecoveredInsn, consume: Int = 0, produce: V? = null) {
        repeat(consume) { stack.removeLastOrNull() }
        if (produce != null) stack.addLast(produce)
        out += insn
    }

    /**
     * Ensure the top of the stack matches `wantHex` (an object identity).
     * If the top matches by hex, nothing happens. Otherwise we push a
     * placeholder (`this` for instance methods, null otherwise) since we
     * don't track the true origin of every jobject.
     */
    fun ensureReceiver(wantHex: String?, type: String? = null) {
        if (wantHex == null) return
        val top = stack.lastOrNull()
        if (top is V.ObjHex && top.hex == wantHex) return
        // If the requested jobject is in the SSA slot map, reload it.
        val slot = slotMap[wantHex]
        if (slot != null) {
            out += RecoveredInsn(op = "ALOAD", `var` = slot)
            if (type != null && type != "java/lang/Object" && type != "?") {
                // ASTORE doesn't preserve the precise declared type; ALOAD
                // returns Object (or the slot's "merged" type). Cast to the
                // receiver type so verify sees the right narrow type.
                out += RecoveredInsn(op = "CHECKCAST", type = type)
            }
            stack.addLast(V.ObjHex(wantHex))
            return
        }
        pushObjLiteral(wantHex, type)
    }

    /**
     * Lookahead-aware preparation: before emitting an INVOKE that expects
     * ``[receiver, arg1, arg2, ...]`` on top of the stack, check whether
     * those items are already sitting there from previous operations. Only
     * push what's missing.
     *
     * `argDescAndHex` is a list of (jvm-type-letter, value) where value is
     * either a jobject hex string (for L/[ types) or a Number/String literal.
     */
    fun prepareCall(
        receiverHex: String?,
        receiverType: String?,
        argDescAndHex: List<Pair<String, Any?>>,
    ) {
        // Case 1: stack already has [receiver, args...] on top — perfect chain
        // (common for ``b.append(...).append(...)``).
        if (matchesTop(receiverHex, argDescAndHex)) return

        // If the receiver is somewhere DEEPER on the stack (e.g. NEW+DUP put
        // it at -2 and an intervening GETSTATIC pushed an unrelated value at
        // -1), pop items above it so the receiver becomes the new top.  This
        // is the common shape when a constructor has args that come from
        // GETSTATIC / GETFIELD in between AllocObject and the <init> call —
        // native-obfuscator's cstack scheduling can interleave them.
        if (receiverHex != null) {
            val depth = findReceiverDepth(receiverHex)
            if (depth > 0) {
                repeat(depth) {
                    val t = stack.removeLast()
                    if (t is V.Long || t is V.Double) out += RecoveredInsn(op = "POP2")
                    else out += RecoveredInsn(op = "POP")
                }
            }
        }

        // Case 2: receiver is on top (e.g. just produced by NEW+DUP or a
        // previous INVOKE returning self). Just push the args.
        if (receiverHex != null && stack.lastOrNull().let { it is V.ObjHex && it.hex == receiverHex }) {
            for ((desc, value) in argDescAndHex) pushArg(value, desc)
            return
        }

        // Case 3: nothing matches — push receiver (if any) then all args.
        if (receiverHex != null) pushObjLiteral(receiverHex, receiverType)
        for ((desc, value) in argDescAndHex) pushArg(value, desc)
    }

    /**
     * Scan the stack from top down looking for an ObjHex matching `hex`.
     * Returns the number of items above it (0 if it's already on top, -1 if
     * not found).
     */
    private fun findReceiverDepth(hex: String): Int {
        for (i in stack.indices.reversed()) {
            val v = stack[i]
            if (v is V.ObjHex && v.hex == hex) {
                return stack.size - 1 - i
            }
        }
        return -1
    }

    private fun matchesTop(receiverHex: String?, argDescAndHex: List<Pair<String, Any?>>): Boolean {
        val total = (if (receiverHex != null) 1 else 0) + argDescAndHex.size
        if (stack.size < total) return false
        var i = stack.size - total
        if (receiverHex != null) {
            val r = stack[i]
            if (r !is V.ObjHex || r.hex != receiverHex) return false
            i++
        }
        for ((desc, value) in argDescAndHex) {
            val s = stack[i]
            val c = desc.firstOrNull() ?: '?'
            val ok = when (c) {
                'L', '[' -> when {
                    // Known-identity jobject: stack must hold the same hex.
                    value is String && value.startsWith("0x") -> s is V.ObjHex && s.hex == value
                    // Literal (string content) or unknown: we have no way to
                    // verify identity from the stack model; assume it's NOT
                    // already in place so we'll push fresh.
                    else -> false
                }
                'J' -> false   // primitives are pushed per-arg; never claim already-in-place
                'F' -> false
                'D' -> false
                else -> false
            }
            if (!ok) return false
            i++
        }
        return true
    }

    /**
     * Push one argument for an INVOKE-like call. `value` may be:
     *   - String — LDC the literal
     *   - Long/Int/Double — pushed as primitive
     *   - hex string starting with "0x" — an opaque jobject; assume top of
     *     stack (no push) if matches, else push placeholder
     * `desc` (a JVM type descriptor like ``I`` / ``J`` / ``Ljava/lang/String;``)
     * decides primitive vs object handling.
     */
    fun pushArg(value: Any?, desc: String) {
        when (val c = desc.firstOrNull() ?: '?') {
            'L', '[' -> {
                // The expected reference type comes from the descriptor.
                // For L-types, strip the leading 'L' and trailing ';'. For
                // array types ([I, [Ljava/lang/Object;) use the whole desc.
                val refType: String? = when (c) {
                    '[' -> desc
                    'L' -> if (desc.length > 2 && desc.endsWith(";")) desc.substring(1, desc.length - 1) else null
                    else -> null
                }
                if (value is String && !value.startsWith("0x")) {
                    pushString(value)
                } else if (value is String && value.startsWith("0x")) {
                    val top = stack.lastOrNull()
                    if (top is V.ObjHex && top.hex == value) return
                    // Try the SSA slot map before falling back to null+checkcast.
                    val slot = slotMap[value]
                    if (slot != null) {
                        out += RecoveredInsn(op = "ALOAD", `var` = slot)
                        if (refType != null && refType != "java/lang/Object") {
                            out += RecoveredInsn(op = "CHECKCAST", type = refType)
                        }
                        stack.addLast(V.ObjHex(value))
                        return
                    }
                    pushObjLiteral(value, refType)
                } else {
                    pushNullAs(refType)
                }
            }
            'I', 'B', 'S', 'C', 'Z' -> when (value) {
                is Number -> pushInt(value.toInt())
                else -> pushInt(0)
            }
            'J' -> when (value) {
                is Number -> pushLong(value.toLong())
                else -> pushLong(0L)
            }
            'F' -> when (value) {
                is Number -> pushFloat(value.toDouble())
                else -> pushFloat(0.0)
            }
            'D' -> when (value) {
                is Number -> pushDouble(value.toDouble())
                else -> pushDouble(0.0)
            }
            else -> pushNull()
        }
    }

    /**
     * If `hex` has been allocated an SSA slot, emit `DUP + ASTORE <slot>`
     * so subsequent uses of that jobject can `ALOAD <slot>`. Called by the
     * translator after each event that produces a jobject return.
     *
     * Net stack effect: zero (DUP pushes, ASTORE pops).
     */
    fun maybeStash(hex: String?) {
        if (hex == null) return
        val slot = slotMap[hex] ?: return
        if (stack.isEmpty()) return
        val top = stack.last()
        if (top !is V.Obj && top !is V.ObjHex) return
        out += RecoveredInsn(op = "DUP")
        out += RecoveredInsn(op = "ASTORE", `var` = slot)
        // model unchanged: DUP added one, ASTORE removed one
    }

    /**
     * Helper: emit an INVOKE.  Computes the consumed/produced from `desc`.
     * `returnHex` (optional) lets us track the identity of an object return
     * so downstream `ensureReceiver` calls can avoid spurious pushes when
     * the same jobject is used as the next receiver.
     */
    /**
     * Make sure the operand stack at the end of a method matches what the
     * declared return type requires. Inserts a default value if the stack
     * is short or has the wrong type — guarantees the closing RETURN/IRETURN
     * etc. doesn't underflow.
     */
    fun fixupReturn(methodDesc: String) {
        val ret = methodDesc.substringAfterLast(')')
        val c = ret.firstOrNull() ?: 'V'
        when (c) {
            'V' -> {
                // pop everything left on stack
                while (stack.isNotEmpty()) {
                    val t = stack.removeLast()
                    if (t is V.Long || t is V.Double) out += RecoveredInsn(op = "POP2")
                    else out += RecoveredInsn(op = "POP")
                }
                out += RecoveredInsn(op = "RETURN")
            }
            'I', 'B', 'S', 'C', 'Z' -> {
                if (stack.lastOrNull() !is V.Int) {
                    while (stack.isNotEmpty()) {
                        val t = stack.removeLast()
                        if (t is V.Long || t is V.Double) out += RecoveredInsn(op = "POP2")
                        else out += RecoveredInsn(op = "POP")
                    }
                    out += RecoveredInsn(op = "ICONST_0"); stack.addLast(V.Int)
                }
                stack.removeLast(); out += RecoveredInsn(op = "IRETURN")
            }
            'J' -> {
                if (stack.lastOrNull() !is V.Long) {
                    while (stack.isNotEmpty()) {
                        val t = stack.removeLast()
                        if (t is V.Long || t is V.Double) out += RecoveredInsn(op = "POP2")
                        else out += RecoveredInsn(op = "POP")
                    }
                    out += RecoveredInsn(op = "LCONST_0"); stack.addLast(V.Long)
                }
                stack.removeLast(); out += RecoveredInsn(op = "LRETURN")
            }
            'F' -> {
                if (stack.lastOrNull() !is V.Float) {
                    while (stack.isNotEmpty()) {
                        val t = stack.removeLast()
                        if (t is V.Long || t is V.Double) out += RecoveredInsn(op = "POP2")
                        else out += RecoveredInsn(op = "POP")
                    }
                    out += RecoveredInsn(op = "FCONST_0"); stack.addLast(V.Float)
                }
                stack.removeLast(); out += RecoveredInsn(op = "FRETURN")
            }
            'D' -> {
                if (stack.lastOrNull() !is V.Double) {
                    while (stack.isNotEmpty()) {
                        val t = stack.removeLast()
                        if (t is V.Long || t is V.Double) out += RecoveredInsn(op = "POP2")
                        else out += RecoveredInsn(op = "POP")
                    }
                    out += RecoveredInsn(op = "DCONST_0"); stack.addLast(V.Double)
                }
                stack.removeLast(); out += RecoveredInsn(op = "DRETURN")
            }
            else -> {
                // 'L' or '['
                val expectedType = if (c == '[') ret else if (ret.startsWith("L") && ret.endsWith(";")) ret.substring(1, ret.length - 1) else null
                val top = stack.lastOrNull()
                val topOk = top is V.Obj || top is V.ObjHex
                if (!topOk) {
                    while (stack.isNotEmpty()) {
                        val t = stack.removeLast()
                        if (t is V.Long || t is V.Double) out += RecoveredInsn(op = "POP2")
                        else out += RecoveredInsn(op = "POP")
                    }
                    pushNullAs(expectedType)
                } else if (expectedType != null
                    && expectedType != "java/lang/Object"
                    && expectedType != "[Ljava/lang/Object;") {
                    // Insert a CHECKCAST to keep the verifier's type system
                    // narrow enough — we tracked the value as generic Object,
                    // but the declared return type may be more specific.
                    out += RecoveredInsn(op = "CHECKCAST", type = expectedType)
                }
                stack.removeLast(); out += RecoveredInsn(op = "ARETURN")
            }
        }
    }

    fun emitInvoke(insn: RecoveredInsn, returnHex: String? = null) {
        val desc = insn.desc ?: return out.run { add(insn) }
        val isStaticCall = insn.op == "INVOKESTATIC"
        val argCount = parseArgTypes(desc).size
        repeat(argCount) { stack.removeLastOrNull() }
        if (!isStaticCall) stack.removeLastOrNull()  // receiver
        out += insn
        val ret = desc.substringAfterLast(')')
        when (ret.firstOrNull() ?: '?') {
            'V' -> {}
            'I', 'B', 'S', 'C', 'Z' -> stack.addLast(V.Int)
            'J' -> stack.addLast(V.Long)
            'F' -> stack.addLast(V.Float)
            'D' -> stack.addLast(V.Double)
            else -> stack.addLast(if (returnHex != null) V.ObjHex(returnHex) else V.Obj)
        }
    }

    companion object {
        fun parseArgTypes(desc: String): List<String> {
            val out = mutableListOf<String>()
            var i = 1
            while (i < desc.length && desc[i] != ')') {
                val start = i
                while (i < desc.length && desc[i] == '[') i++
                if (i < desc.length && desc[i] == 'L') {
                    while (i < desc.length && desc[i] != ';') i++
                    if (i < desc.length) i++
                } else if (i < desc.length) i++
                out += desc.substring(start, i)
            }
            return out
        }
    }
}
