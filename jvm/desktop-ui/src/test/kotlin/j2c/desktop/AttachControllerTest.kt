package j2c.desktop

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class AttachControllerTest {

    private fun req(
        pid: String = "1234",
        output: String = "trace.jsonl",
        own: Boolean = true,
        logAll: Boolean = false,
        mechanism: String = "auto",
        agent: String = "",
    ) = AttachRequest(pid, output, own, logAll, mechanism, agent)

    @Test
    fun `missing pid blocks run`() {
        val reason = AttachController.runBlockedReason(req(pid = ""))
        assertTrue(reason!!.contains("PID"), "got: $reason")
    }

    @Test
    fun `unconfirmed ownership blocks run`() {
        val reason = AttachController.runBlockedReason(req(own = false))
        assertTrue(reason!!.contains(AttachController.CONFIRM_FLAG), "got: $reason")
    }

    @Test
    fun `pid plus confirmation plus output unblocks run`() {
        assertNull(AttachController.runBlockedReason(req()))
    }

    @Test
    fun `command uses the documented python launcher and attach subcommand`() {
        val cmd = AttachController.commandLine(req())
        assertTrue(cmd.contains("-m j2c_dumper_cli.main attach"), "got: $cmd")
        assertTrue(cmd.contains("--pid 1234"), "got: $cmd")
        assertTrue(cmd.contains("-o trace.jsonl"), "got: $cmd")
    }

    @Test
    fun `confirmation flag appears only when confirmed`() {
        assertTrue(AttachController.commandLine(req(own = true)).contains(AttachController.CONFIRM_FLAG))
        assertFalse(AttachController.commandLine(req(own = false)).contains(AttachController.CONFIRM_FLAG))
    }

    @Test
    fun `optional flags are emitted only when set`() {
        val plain = AttachController.attachArgs(req())
        assertFalse(plain.contains("--log-all"))
        assertFalse(plain.contains("--mechanism"))
        assertFalse(plain.contains("--agent"))

        val full = AttachController.attachArgs(
            req(logAll = true, mechanism = "vm", agent = "/tmp/j2c_agent.so"),
        )
        assertTrue(full.contains("--log-all"))
        assertTrue(full.containsInOrder("--mechanism", "vm"))
        assertTrue(full.containsInOrder("--agent", "/tmp/j2c_agent.so"))
    }

    private fun List<String>.containsInOrder(a: String, b: String): Boolean {
        val i = indexOf(a)
        return i >= 0 && i + 1 < size && this[i + 1] == b
    }

    // ---------------------------------------------------------------
    // Refusal parsing — reads the CLI's `attach failed (reason=<code>):`
    // line without re-implementing the CLI's classification in Kotlin.
    // ---------------------------------------------------------------

    @Test
    fun `parses each known refusal reason code from CLI output`() {
        val codes = listOf(
            "attach-disabled" to AttachRefusalCode.ATTACH_DISABLED,
            "dynamic-agent-disabled" to AttachRefusalCode.DYNAMIC_AGENT_DISABLED,
            "cross-user" to AttachRefusalCode.CROSS_USER,
            "not-a-jvm" to AttachRefusalCode.NOT_A_JVM,
            "agent-onattach-missing" to AttachRefusalCode.AGENT_ONATTACH_MISSING,
            "agent-init-failed" to AttachRefusalCode.AGENT_INIT_FAILED,
            "jcmd-false-success" to AttachRefusalCode.JCMD_FALSE_SUCCESS,
            "unknown" to AttachRefusalCode.UNKNOWN,
        )
        for ((raw, expected) in codes) {
            val out = "error: attach failed (reason=$raw): something explaining it"
            val refusal = AttachDiagnostics.parseRefusal(out)
            assertEquals(expected, refusal?.code, "for reason=$raw")
            assertEquals(RefusalSource.CLI_OUTPUT, refusal?.source)
        }
    }

    @Test
    fun `refusal parse keeps the CLI message as detail`() {
        val out = "error: attach failed (reason=cross-user): pid 5 is owned by uid 0"
        val refusal = AttachDiagnostics.parseRefusal(out)!!
        assertEquals(AttachRefusalCode.CROSS_USER, refusal.code)
        assertTrue(refusal.detail.contains("owned by uid 0"), "got: ${refusal.detail}")
    }

    @Test
    fun `refusal parse finds the line amid other output`() {
        val out = buildString {
            appendLine("$ python -m j2c_dumper_cli.main attach --pid 5 ...")
            appendLine("some progress line")
            appendLine("error: attach failed (reason=agent-init-failed): Agent_OnAttach returned 3")
            appendLine("next step: restart under startup instrumentation")
        }
        assertEquals(AttachRefusalCode.AGENT_INIT_FAILED, AttachDiagnostics.parseRefusal(out)?.code)
    }

    @Test
    fun `an unrecognized reason code maps to unknown, not dropped`() {
        val refusal = AttachDiagnostics.parseRefusal("attach failed (reason=some-new-code): x")
        assertEquals(AttachRefusalCode.UNKNOWN, refusal?.code)
    }

    @Test
    fun `output without a refusal line parses to null`() {
        assertNull(AttachDiagnostics.parseRefusal("attached; tailing trace.jsonl"))
        assertNull(AttachDiagnostics.parseRefusal(""))
        assertNull(AttachDiagnostics.parseRefusal(null))
    }

    // ---------------------------------------------------------------
    // Cmdline pre-scan — a Linux /proc/<pid>/cmdline guardrail that
    // refuses before launch. Tested on token lists (no live JVM).
    // ---------------------------------------------------------------

    @Test
    fun `cmdline scan refuses DisableAttachMechanism`() {
        val tokens = listOf("java", "-XX:+DisableAttachMechanism", "-jar", "app.jar")
        val refusal = AttachDiagnostics.scanCmdlineTokens(tokens)
        assertEquals(AttachRefusalCode.ATTACH_DISABLED, refusal?.code)
        assertEquals(RefusalSource.CMDLINE_SCAN, refusal?.source)
    }

    @Test
    fun `cmdline scan refuses disabled dynamic agent loading`() {
        val tokens = listOf("java", "-XX:-EnableDynamicAgentLoading", "-jar", "app.jar")
        val refusal = AttachDiagnostics.scanCmdlineTokens(tokens)
        assertEquals(AttachRefusalCode.DYNAMIC_AGENT_DISABLED, refusal?.code)
    }

    @Test
    fun `cmdline scan allows an ordinary java process`() {
        val tokens = listOf("java", "-Xmx512m", "-jar", "app.jar")
        assertNull(AttachDiagnostics.scanCmdlineTokens(tokens))
    }

    @Test
    fun `allowAttachSelf false is a warning, never a refusal`() {
        val tokens = listOf("java", "-Djdk.attach.allowAttachSelf=false", "-jar", "app.jar")
        // Self-attach only: it must not block this external, same-user attach.
        assertNull(AttachDiagnostics.scanCmdlineTokens(tokens))
        val warnings = AttachDiagnostics.warningsForTokens(tokens)
        assertTrue(warnings.any { it.contains("allowAttachSelf=false") }, "got: $warnings")
    }

    @Test
    fun `the startup recommendation names agentpath and recover`() {
        // Every refusal points at the one honest remedy; no bypass is offered.
        val rec = AttachDiagnostics.STARTUP_RECOMMENDATION
        assertTrue(rec.contains("-agentpath"), "got: $rec")
        assertTrue(rec.contains("recover"), "got: $rec")
    }
}
