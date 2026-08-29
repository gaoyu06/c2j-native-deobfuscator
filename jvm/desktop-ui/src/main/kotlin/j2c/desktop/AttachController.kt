package j2c.desktop

import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.io.path.readText

/**
 * Assembles — and, only on explicit confirmation, runs — the `attach` CLI
 * command. The GUI does not attach to anything itself; it drives the same
 * `j2c_dumper_cli` command a user would type, so automation and the desktop
 * viewer stay in lockstep.
 *
 * The command mirrors docs/jvm-attach.md exactly:
 *
 *   python -m j2c_dumper_cli.main attach --pid <pid> --i-own-this-process \
 *       -o <output> [--log-all] [--mechanism vm] [--agent <path>]
 *
 * The confirmation flag is not optional decoration: without
 * `--i-own-this-process` the CLI refuses before it touches the target, and the
 * GUI enforces the same gate before it will run anything.
 */
object AttachController {

    const val CONFIRM_FLAG = "--i-own-this-process"

    /**
     * The honest notice shown when [attachSubcommandAvailable] is false: the
     * `attach` subcommand is not in this checkout, so the displayed command
     * cannot be run here. It names what still works (Listen / the /proc
     * pre-scan) rather than pretending Run does something.
     */
    const val ATTACH_CLI_MISSING_NOTICE =
        "Run attach needs the attach preview CLI, which is not in this checkout. " +
            "This viewer can still Listen — tail a trace some other attach is writing — " +
            "and still pre-scan the target's /proc flags below."

    /** The interpreter + module invocation, kept separate so the display and
     *  the process share one source of truth. */
    private fun launcher(): List<String> = listOf(pythonExe(), "-m", "j2c_dumper_cli.main")

    private fun pythonExe(): String =
        System.getenv("J2C_PYTHON")?.takeIf { it.isNotBlank() }
            ?: if (onWindows()) "python" else "python3"

    private fun onWindows(): Boolean =
        System.getProperty("os.name")?.lowercase()?.contains("win") == true

    /** Why the form's inputs cannot be run yet, or null when they can. */
    fun runBlockedReason(req: AttachRequest): String? {
        val pid = req.pid.trim().toIntOrNull()
        return when {
            pid == null || pid <= 0 -> "Enter the target PID (a positive integer)."
            !req.iOwnThisProcess -> "Confirm you own or may inspect this process ($CONFIRM_FLAG)."
            req.output.isBlank() -> "Set an output path for the trace."
            else -> null
        }
    }

    /** The full argument vector, including the launcher, for a real run. */
    fun argv(req: AttachRequest): List<String> = launcher() + attachArgs(req)

    /** Just the `attach` subcommand arguments (after the launcher). */
    fun attachArgs(req: AttachRequest): List<String> {
        val args = mutableListOf("attach", "--pid", req.pid.trim())
        if (req.iOwnThisProcess) args += CONFIRM_FLAG
        args += listOf("-o", outputArg(req))
        if (req.logAll) args += "--log-all"
        if (req.mechanism.isNotBlank() && req.mechanism != "auto") {
            args += listOf("--mechanism", req.mechanism)
        }
        if (req.agentPath.isNotBlank()) args += listOf("--agent", req.agentPath.trim())
        return args
    }

    /**
     * The single output path both the launched process and the viewer's tail
     * must agree on. Resolving here is the whole fix for the relative-path
     * mismatch: [run] starts the CLI with its working directory set to
     * `py/j2c_dumper_cli`, so a relative `-o trace.jsonl` would be written *there*,
     * while the viewer tails paths relative to its own working directory — the two
     * disagree and the tail misses the file. By resolving the output to an
     * absolute path against one stable root (the project root, or `user.dir` when
     * the root can't be located) before it reaches either side, the `--output`
     * the process writes and the path the viewer tails are byte-for-byte the same.
     *
     * An already-absolute output is returned normalized and otherwise unchanged.
     * A blank output is left blank (callers gate on it separately), so the
     * command preview shows `-o` with nothing rather than a bare root path.
     */
    fun resolveOutput(output: String): Path? {
        val trimmed = output.trim()
        if (trimmed.isEmpty()) return null
        val raw = Path.of(trimmed)
        val base = if (raw.isAbsolute) {
            raw
        } else {
            val root = projectRoot() ?: Path.of(System.getProperty("user.dir"))
            root.resolve(raw)
        }
        return base.toAbsolutePath().normalize()
    }

    /** The resolved absolute output for a request, or null when it is blank. */
    fun resolvedOutput(req: AttachRequest): Path? = resolveOutput(req.output)

    /** The `--output` token: the resolved absolute path, or "" when blank so the
     *  preview and argv stay in step with an unfinished form. */
    private fun outputArg(req: AttachRequest): String =
        resolvedOutput(req)?.toString() ?: ""

    /**
     * A copy-pasteable command line. Reflects the current form state so an
     * unconfirmed form shows the command *without* the confirmation flag — the
     * user can see exactly what is missing before anything runs.
     */
    fun commandLine(req: AttachRequest): String =
        (launcher() + attachArgs(req)).joinToString(" ") { quoteIfNeeded(it) }

    private fun quoteIfNeeded(token: String): String =
        if (token.isEmpty() || token.any { it.isWhitespace() }) "\"$token\"" else token

    /**
     * Locate the repository root so the CLI module can be run from
     * `py/j2c_dumper_cli`. Walks up from the working directory and from this
     * class's location; returns null if the layout isn't found (the command can
     * still be shown and copied).
     */
    fun projectRoot(): Path? {
        val seeds = listOfNotNull(
            runCatching { Path.of(System.getProperty("user.dir")) }.getOrNull(),
            runCatching {
                Path.of(AttachController::class.java.protectionDomain.codeSource.location.toURI())
            }.getOrNull(),
        )
        for (seed in seeds) {
            var dir: Path? = seed.toAbsolutePath()
            while (dir != null) {
                if (dir.resolve("py/j2c_dumper_cli/j2c_dumper_cli/main.py").exists() &&
                    dir.resolve("jvm/settings.gradle.kts").exists()
                ) return dir
                dir = dir.parent
            }
        }
        return null
    }

    /**
     * Whether the CLI this GUI would actually run has an `attach` subcommand.
     * On this branch the attach preview CLI is wired in (the `attach`
     * subcommand + `attach_support` from the JVMTI live-attach change), so this
     * returns true and Run can enable once a PID and ownership are set. It stays
     * honest for checkouts that lack it: if a build is run against a tree with
     * no `attach` subcommand it returns false and the form shows the CLI-missing
     * notice instead of pretending the displayed command works.
     *
     * Read-only: it inspects the same `main.py` the run path launches
     * (`py/j2c_dumper_cli`). When the project root cannot be located the CLI
     * cannot be run either, so this returns false — the honest default.
     */
    fun attachSubcommandAvailable(): Boolean {
        val root = projectRoot() ?: return false
        val main = root.resolve("py/j2c_dumper_cli/j2c_dumper_cli/main.py")
        if (!main.exists()) return false
        return runCatching { mainDeclaresAttach(main.readText()) }.getOrDefault(false)
    }

    /**
     * Pure: does a Typer CLI `main.py` register an `attach` subcommand? Matches
     * either an explicit name (`@app.command("attach")`) or a bare
     * `@app.command()` immediately above a `def attach` / `def cli_attach`.
     * Factored out so it unit-tests without a checkout on disk.
     */
    fun mainDeclaresAttach(mainPySource: String): Boolean {
        val named = Regex("""@app\.command\(\s*["']attach["']""")
        if (named.containsMatchIn(mainPySource)) return true
        val bare = Regex("""@app\.command\(\s*\)\s*\r?\n\s*def\s+(?:cli_)?attach\b""")
        return bare.containsMatchIn(mainPySource)
    }

    /** Result of a finished attach process. */
    data class RunResult(val exitCode: Int, val output: String)

    /**
     * The tail / announce decision for a finished attach, factored out of the
     * panel so it unit-tests without Swing. The rule is strict: a parsed CLI
     * refusal *or* any non-zero exit means the attach did not happen — never
     * tail the trace and never claim it attached. Only a clean exit with no
     * refusal line is a real attach.
     */
    data class AttachOutcome(
        val refusal: AttachRefusal?,
        val shouldTail: Boolean,
        val shouldAnnounceAttached: Boolean,
    )

    fun outcomeFor(result: RunResult): AttachOutcome {
        val refusal = AttachDiagnostics.parseRefusal(result.output)
        return when {
            refusal != null -> AttachOutcome(refusal, shouldTail = false, shouldAnnounceAttached = false)
            result.exitCode == 0 -> AttachOutcome(null, shouldTail = true, shouldAnnounceAttached = true)
            else -> AttachOutcome(null, shouldTail = false, shouldAnnounceAttached = false)
        }
    }

    /**
     * Run the attach command, streaming combined stdout/stderr line-by-line to
     * [onLine]. Blocks until the process exits, so callers run it off the EDT.
     * The attach command returns quickly (it loads the agent and detaches; the
     * target keeps writing the trace), so this does not hold the UI hostage.
     */
    fun run(req: AttachRequest, onLine: (String) -> Unit): RunResult {
        val root = projectRoot()
            ?: return RunResult(
                exitCode = -1,
                output = "could not locate the project root (py/j2c_dumper_cli). " +
                    "Run the shown command from a checkout instead.",
            )
        val pb = ProcessBuilder(argv(req))
            .directory(root.resolve("py/j2c_dumper_cli").toFile())
            .redirectErrorStream(true)
        val collected = StringBuilder()
        return try {
            val proc = pb.start()
            proc.inputStream.bufferedReader().useLines { lines ->
                lines.forEach {
                    collected.append(it).append('\n')
                    onLine(it)
                }
            }
            val code = proc.waitFor()
            RunResult(code, collected.toString())
        } catch (e: Exception) {
            RunResult(-1, "failed to launch attach command: ${e.message}")
        }
    }
}
