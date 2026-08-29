package j2c.desktop

import j2c.common.RecoveredInsn
import j2c.common.RecoveredMethod

/**
 * Turn a recovered method into a plain, readable instruction listing.
 *
 * This is a viewer, not the rebuilder: it never assembles bytecode, it
 * just prints what the recovery stage already wrote so a person can read
 * it. One instruction per line, index on the left, operands spelled out.
 */
object Listing {

    fun render(m: RecoveredMethod): String {
        val sb = StringBuilder()
        sb.append("// ").append(m.owner.replace('/', '.'))
            .append('.').append(m.name).append(m.desc).append('\n')
        val meta = buildList {
            m.source?.let { add("source: $it") }
            m.confidence?.let { add("confidence: $it") }
            add("instructions: ${m.instructions.size}")
        }
        sb.append("// ").append(meta.joinToString("   ")).append('\n')
        if (m.exceptionsObserved.isNotEmpty()) {
            sb.append("// exceptions seen: ")
                .append(m.exceptionsObserved.joinToString(", ")).append('\n')
        }
        sb.append('\n')

        var idx = 0
        for (insn in m.instructions) {
            // Labels sit flush-left; real instructions are indented and
            // numbered, so the control flow reads like an assembler dump.
            if (insn.op == "LABEL") {
                sb.append(insn.label ?: "L?").append(":\n")
                continue
            }
            sb.append(String.format("%4d  ", idx))
            sb.append(operand(insn))
            sb.append('\n')
            idx++
        }
        if (m.tryCatchBlocks.isNotEmpty()) {
            sb.append('\n')
            for (tc in m.tryCatchBlocks) {
                sb.append("// try ").append(tc.start).append("..").append(tc.end)
                    .append(" -> ").append(tc.handler)
                tc.type?.let { sb.append(" (").append(it.replace('/', '.')).append(')') }
                sb.append('\n')
            }
        }
        return sb.toString()
    }

    private fun operand(insn: RecoveredInsn): String {
        val sb = StringBuilder(insn.op)
        fun add(part: String?) {
            if (part != null) sb.append(' ').append(part)
        }
        // Field / method references.
        if (insn.owner != null || insn.name != null) {
            val owner = insn.owner?.replace('/', '.')
            val ref = buildString {
                if (owner != null) append(owner).append('.')
                append(insn.name ?: "?")
                insn.desc?.let { append(it) }
            }
            add(ref)
        } else {
            insn.desc?.let { add(it) }
        }
        insn.`var`?.let { add("#$it") }
        insn.incr?.let { add("by $it") }
        insn.type?.let { add(it.replace('/', '.')) }
        insn.target?.let { add("-> $it") }
        insn.value?.let { add(renderValue(it)) }
        if (insn.itf == true) add("(interface)")
        insn.dynamic?.let { sb.append("    ; runtime: ").append(it) }
        return sb.toString()
    }

    private fun renderValue(v: Any): String = when (v) {
        is String -> "\"" + v.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
        else -> v.toString()
    }
}
