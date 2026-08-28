package j2c.desktop

import com.fasterxml.jackson.databind.JsonNode
import j2c.common.JsonIO

/**
 * Turns one line of a `trace.jsonl` file into a [TraceEvent]. Shared by the
 * directory [SessionScanner] (static read) and the live [TraceTailer], so a
 * tailed line and a re-read line classify identically.
 *
 * The live-attach path (see docs/jvm-attach.md) writes more than enter/exit
 * events: an `agent-attached` / `agent-loaded` lifecycle marker, one
 * `capability` record per JVMTI capability it tried to add (with
 * `available:true|false`), and `gap` records naming what it could not observe.
 * The parser keeps those distinct so the viewer can show, honestly, that a
 * capability was unavailable rather than hiding the reduced coverage.
 */
object TraceParser {

    /** Parse one raw line. Returns null for a blank line. */
    fun parse(index: Int, rawLine: String): TraceEvent? {
        val line = rawLine.trim()
        if (line.isEmpty()) return null

        val node: JsonNode = try {
            JsonIO.mapper.readTree(line)
        } catch (e: Exception) {
            return TraceEvent(index, "?", "?", "malformed line", TraceKind.MALFORMED)
        }

        val ev = node["ev"]?.asText() ?: "?"
        val thread = node["thr"]?.asText() ?: ""
        return TraceEvent(index, ev, thread, summarize(ev, node), kindOf(ev, node))
    }

    private fun kindOf(ev: String, node: JsonNode): TraceKind = when (ev) {
        "agent-attached", "agent-loaded" -> TraceKind.LIFECYCLE
        "bind" -> TraceKind.BIND
        "capability" ->
            if (node["available"]?.asBoolean() == true) TraceKind.CAPABILITY_OK
            else TraceKind.CAPABILITY_UNAVAILABLE
        "gap" -> TraceKind.GAP
        else -> TraceKind.NORMAL
    }

    private fun summarize(ev: String, node: JsonNode): String = when (ev) {
        "enter", "exit" -> node["fn"]?.asText() ?: ""
        "jni" -> node["call"]?.asText() ?: ""
        "slot" -> "${node["kind"]?.asText()} slot ${node["slot"]?.asText()}"
        "bind" -> {
            val owner = node["owner"]?.asText()?.replace('/', '.') ?: "?"
            val name = node["name"]?.asText() ?: "?"
            val desc = node["desc"]?.asText() ?: ""
            val addr = node["fnAddr"]?.asText()
            buildString {
                append(owner).append('.').append(name).append(desc)
                if (addr != null) append("  ->  ").append(addr)
            }
        }
        "capability" -> {
            val name = node["name"]?.asText() ?: "?"
            if (node["available"]?.asBoolean() == true) {
                "$name — available"
            } else {
                val err = node["jvmtiError"]?.asInt()
                if (err != null) "$name — unavailable (jvmtiError $err)"
                else "$name — unavailable"
            }
        }
        "gap" -> summarizeGap(node)
        "agent-attached", "agent-loaded" -> {
            val mode = node["mode"]?.asText() ?: (if (ev == "agent-attached") "live-attach" else "startup")
            val phase = node["phase"]?.asText()
            val logAll = node["logAll"]?.asBoolean()
            buildString {
                append("mode=").append(mode)
                if (phase != null) append("  phase=").append(phase)
                if (logAll != null) append("  logAll=").append(logAll)
            }
        }
        else -> ""
    }

    private fun summarizeGap(node: JsonNode): String {
        val kind = node["kind"]?.asText() ?: "gap"
        val enabled = node["enabledEvents"]?.asText()
        return when {
            enabled != null && enabled.isNotBlank() -> "$kind — enabled: $enabled"
            else -> {
                val detail = node["detail"]?.asText()
                if (detail != null && detail.isNotBlank()) "$kind — $detail" else kind
            }
        }
    }
}
