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
        // The output is resolved to an absolute path (see the resolve-output
        // tests below); the preview shows that same path, ending in the file.
        val out = AttachController.resolvedOutput(req())!!.toString()
        assertTrue(cmd.contains("-o $out"), "got: $cmd")
        assertTrue(out.endsWith("trace.jsonl"), "got: $out")
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
    // Output resolution — the fix for the relative-path mismatch. run()
    // launches the CLI with cwd py/j2c_dumper_cli, so a relative `-o` would
    // land there while the viewer tails relative to its own cwd. Resolving
    // to one absolute path up front makes the two agree. No live JVM needed.
    // ---------------------------------------------------------------

    /** The value passed to `-o` in the argv the process is actually launched with. */
    private fun outputInArgv(req: AttachRequest): String {
        val argv = AttachController.argv(req)
        val i = argv.indexOf("-o")
        assertTrue(i >= 0 && i + 1 < argv.size, "argv has no -o value: $argv")
        return argv[i + 1]
    }

    @Test
    fun `a relative output becomes an absolute path`() {
        val resolved = AttachController.resolvedOutput(req(output = "trace.jsonl"))!!
        assertTrue(resolved.isAbsolute, "expected absolute, got: $resolved")
        assertTrue(resolved.toString().endsWith("trace.jsonl"), "got: $resolved")
    }

    @Test
    fun `the run argv output and the viewer tail path are the same absolute path`() {
        val req = req(output = "trace.jsonl")

        // The path the process is told to write (argv -o) …
        val argvOutput = outputInArgv(req)
        // … and the path the viewer would tail after a successful attach both
        // come from resolvedOutput, so they cannot drift apart.
        val tailPath = AttachController.resolvedOutput(req)!!

        assertTrue(tailPath.isAbsolute, "tail path must be absolute, got: $tailPath")
        assertEquals(
            tailPath.toString(),
            argvOutput,
            "launch --output and tail path must be the same absolute path",
        )
    }

    @Test
    fun `an already-absolute output is preserved through argv and tail`() {
        val abs = java.nio.file.Path.of(System.getProperty("java.io.tmpdir"))
            .toAbsolutePath().resolve("j2c-trace.jsonl").toString()
        val req = req(output = abs)

        val argvOutput = outputInArgv(req)
        val tailPath = AttachController.resolvedOutput(req)!!
        assertEquals(abs, argvOutput, "absolute output must reach argv unchanged")
        assertEquals(abs, tailPath.toString(), "absolute output must reach the tail unchanged")
    }

    @Test
    fun `a blank output leaves the command preview output empty`() {
        assertNull(AttachController.resolvedOutput(req(output = "   ")))
        val cmd = AttachController.commandLine(req(output = ""))
        // `-o` with nothing after it, not a bare root path.
        assertTrue(cmd.contains("-o ") || cmd.endsWith("-o"), "got: $cmd")
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

    // ---------------------------------------------------------------
    // Outcome decision — the tail / announce rule after a finished run.
    // A refusal OR any non-zero exit must not tail and must not claim
    // attached; only a clean exit with no refusal is a real attach.
    // ---------------------------------------------------------------

    @Test
    fun `a non-zero exit never tails and never claims attached`() {
        val outcome = AttachController.outcomeFor(
            AttachController.RunResult(exitCode = 3, output = "some attach-layer error, no reason code"),
        )
        assertNull(outcome.refusal)
        assertFalse(outcome.shouldTail, "must not tail on a non-zero exit")
        assertFalse(outcome.shouldAnnounceAttached, "must not claim attached on a non-zero exit")
    }

    @Test
    fun `a parsed refusal never tails and never claims attached even on exit zero`() {
        // jcmd can exit 0 while the agent actually refused; the reason line wins.
        val outcome = AttachController.outcomeFor(
            AttachController.RunResult(
                exitCode = 0,
                output = "error: attach failed (reason=jcmd-false-success): agent returned an error",
            ),
        )
        assertEquals(AttachRefusalCode.JCMD_FALSE_SUCCESS, outcome.refusal?.code)
        assertFalse(outcome.shouldTail, "must not tail when the CLI printed a refusal")
        assertFalse(outcome.shouldAnnounceAttached, "must not claim attached when the CLI refused")
    }

    @Test
    fun `a clean exit with no refusal tails and announces attached`() {
        val outcome = AttachController.outcomeFor(
            AttachController.RunResult(exitCode = 0, output = "agent loaded; detaching\n"),
        )
        assertNull(outcome.refusal)
        assertTrue(outcome.shouldTail)
        assertTrue(outcome.shouldAnnounceAttached)
    }

    // ---------------------------------------------------------------
    // Attach subcommand availability — the GUI must not pretend the shown
    // command runs when this checkout has no `attach` subcommand.
    // ---------------------------------------------------------------

    @Test
    fun `main without an attach command is detected as unavailable`() {
        val src = """
            app = typer.Typer()
            @app.command("parse-jar")
            def cli_parse_jar(): ...
            @app.command()
            def recover(): ...
        """.trimIndent()
        assertFalse(AttachController.mainDeclaresAttach(src))
    }

    @Test
    fun `main with an explicitly named attach command is detected`() {
        val src = """
            @app.command("attach")
            def cli_attach(): ...
        """.trimIndent()
        assertTrue(AttachController.mainDeclaresAttach(src))
    }

    @Test
    fun `main with a bare attach command function is detected`() {
        val src = """
            @app.command()
            def attach(pid: int): ...
        """.trimIndent()
        assertTrue(AttachController.mainDeclaresAttach(src))
    }

    @Test
    fun `this checkout has the wired-in attach subcommand`() {
        // The attach preview CLI (the `attach` subcommand + attach_support) is
        // merged into this branch, so `py/j2c_dumper_cli` declares it. The GUI
        // relies on this reading as available to hide the CLI-missing notice and
        // let Run enable once a PID and ownership are set.
        assertTrue(
            AttachController.attachSubcommandAvailable(),
            "attach must read as available on this merged branch",
        )
    }

    @Test
    fun `the CLI-missing notice names Listen and the proc pre-scan`() {
        val notice = AttachController.ATTACH_CLI_MISSING_NOTICE
        assertTrue(notice.contains("Listen"), "got: $notice")
        assertTrue(notice.contains("/proc"), "got: $notice")
    }
}
