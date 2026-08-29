package j2c.desktop

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.exists

/**
 * Honest, read-only classification of why a live attach will not — or did not —
 * happen. Two independent detection points, both Swing-free so they unit-test
 * without a live JVM:
 *
 *  - [scanCmdline] / [scanCmdlineTokens]: a Linux `/proc/<pid>/cmdline` pre-scan
 *    that catches the two flags which make an attach impossible *before* the CLI
 *    is launched, so the form can refuse cleanly instead of surfacing an opaque
 *    attach-layer error later.
 *  - [parseRefusal]: reads the `attach failed (reason=<code>): …` line the CLI
 *    prints, when present, and maps the code to a [AttachRefusal].
 *
 * Nothing here bypasses, hides, or patches anything on a target. The only remedy
 * this tool offers for a refusal is [STARTUP_RECOMMENDATION] — restart the target
 * under startup instrumentation, the default highest-fidelity recovery path.
 */
object AttachDiagnostics {

    /** The single honest next step shown on every refusal banner. */
    const val STARTUP_RECOMMENDATION =
        "use startup -agentpath / recover for full coverage"

    // The CLI prints `attach failed (reason=<code>): <message>`. Rich strips its
    // own markup when writing to a pipe, so we match the plain text and tolerate
    // a leading `error:` prefix. The code is a short kebab token.
    private val REFUSAL_RE =
        Regex("""attach failed \(reason=([a-z][a-z0-9-]*)\):\s*(.*)""")

    // Flags that make a live attach impossible, matched on the target's argv.
    private const val DISABLE_ATTACH = "-XX:+DisableAttachMechanism"
    private const val DISABLE_DYNAMIC_AGENTS = "-XX:-EnableDynamicAgentLoading"

    /**
     * Find the first `attach failed (reason=<code>): …` line in combined CLI
     * output, or null when the output carries no refusal. Unknown codes map to
     * [AttachRefusalCode.UNKNOWN] rather than being dropped.
     */
    fun parseRefusal(output: String?): AttachRefusal? {
        if (output.isNullOrBlank()) return null
        for (line in output.lineSequence()) {
            val m = REFUSAL_RE.find(line) ?: continue
            val code = AttachRefusalCode.fromCode(m.groupValues[1])
            val detail = m.groupValues[2].trim()
            return AttachRefusal(code, RefusalSource.CLI_OUTPUT, detail)
        }
        return null
    }

    /**
     * Pre-scan a target's argv (Linux `/proc/<pid>/cmdline`) for the two flags
     * that block a live attach. Returns a refusal to block Run before launch, or
     * null when nothing blocking is found (which is not a guarantee: the flags
     * can arrive via JAVA_TOOL_OPTIONS, which argv does not show). Non-Linux
     * hosts and unreadable procfs simply return null.
     */
    fun scanCmdline(pid: Int): AttachRefusal? {
        val tokens = readCmdline(pid) ?: return null
        return scanCmdlineTokens(tokens)
    }

    /**
     * The target's argv tokens (Linux `/proc/<pid>/cmdline`), or null when
     * unreadable / non-Linux. Public so the form can derive both a hard refusal
     * ([scanCmdlineTokens]) and the non-fatal warnings ([warningsForTokens])
     * from a single read on each refresh.
     */
    fun cmdlineTokens(pid: Int): List<String>? = readCmdline(pid)

    /**
     * The pure part of [scanCmdline]: classify an argv token list. Kept separate
     * so it tests without procfs.
     *
     * `-Djdk.attach.allowAttachSelf=false` is deliberately **not** a refusal: it
     * disables a JVM attaching to *itself* only and does not block this external,
     * same-user attach. See [warningsForTokens].
     */
    fun scanCmdlineTokens(tokens: List<String>): AttachRefusal? {
        val joined = tokens.joinToString(" ")
        if (joined.contains(DISABLE_ATTACH)) {
            return AttachRefusal(AttachRefusalCode.ATTACH_DISABLED, RefusalSource.CMDLINE_SCAN)
        }
        if (joined.contains(DISABLE_DYNAMIC_AGENTS)) {
            return AttachRefusal(AttachRefusalCode.DYNAMIC_AGENT_DISABLED, RefusalSource.CMDLINE_SCAN)
        }
        return null
    }

    /**
     * Non-fatal notes about a target's argv that do **not** block an attach.
     * Currently just `jdk.attach.allowAttachSelf=false`, which governs
     * self-attach only; an external same-user attach is unaffected, so it warns
     * and proceeds rather than refusing a valid target.
     */
    fun warningsForTokens(tokens: List<String>): List<String> {
        val warnings = mutableListOf<String>()
        if (allowAttachSelfDisabled(tokens)) {
            warnings += "target sets jdk.attach.allowAttachSelf=false; that disables " +
                "self-attach only and does not block this same-user attach — proceeding."
        }
        return warnings
    }

    private fun allowAttachSelfDisabled(tokens: List<String>): Boolean {
        val marker = "jdk.attach.allowattachself="
        for (tok in tokens) {
            val low = tok.lowercase()
            val at = low.indexOf(marker)
            if (at >= 0) {
                val value = low.substring(at + marker.length)
                // Boolean.getBoolean treats only "true" as true; flag the
                // obvious explicit false-y form.
                if (value != "true") return true
            }
        }
        return false
    }

    private fun readCmdline(pid: Int): List<String>? {
        if (pid <= 0) return null
        val path: Path = Path.of("/proc", pid.toString(), "cmdline")
        if (!path.exists()) return null
        return try {
            val raw = Files.readAllBytes(path)
            String(raw, Charsets.UTF_8).split('\u0000').filter { it.isNotEmpty() }
        } catch (e: Exception) {
            null
        }
    }
}
