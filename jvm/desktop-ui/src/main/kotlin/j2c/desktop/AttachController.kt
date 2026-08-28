package j2c.desktop

import java.nio.file.Path
import kotlin.io.path.exists

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
        args += listOf("-o", req.output.trim())
        if (req.logAll) args += "--log-all"
        if (req.mechanism.isNotBlank() && req.mechanism != "auto") {
            args += listOf("--mechanism", req.mechanism)
        }
        if (req.agentPath.isNotBlank()) args += listOf("--agent", req.agentPath.trim())
        return args
    }

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

    /** Result of a finished attach process. */
    data class RunResult(val exitCode: Int, val output: String)

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
