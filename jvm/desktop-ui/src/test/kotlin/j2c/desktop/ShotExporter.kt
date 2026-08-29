package j2c.desktop

import java.awt.image.BufferedImage
import java.nio.file.Files
import java.nio.file.Path
import javax.imageio.ImageIO
import javax.swing.JComponent
import javax.swing.JFrame
import javax.swing.SwingUtilities

/**
 * Renders each viewer state to a PNG so the look can be reviewed without a
 * person driving the UI. Needs a display; on headless machines wrap it:
 *
 *   xvfb-run ./gradlew :desktop-ui:exportShots
 *
 * Output goes to the directory given as the first argument (default
 * "screenshots").
 */
fun main(args: Array<String>) {
    val outDir = Path.of(args.firstOrNull() ?: "screenshots")
    Files.createDirectories(outDir)
    Theme.install()

    val width = 1120
    val height = 720

    fun shot(name: String, configure: (ViewerFrame) -> Unit) {
        var frame: ViewerFrame? = null
        SwingUtilities.invokeAndWait {
            val f = ViewerFrame()
            f.setSize(width, height)
            configure(f)
            f.isVisible = true
            frame = f
        }
        // Let layout + paint settle.
        Thread.sleep(600)
        SwingUtilities.invokeAndWait {
            val f = frame!!
            // Paint the content pane only, so the OS window chrome doesn't
            // clip the toolbar or leave a native title bar in the image.
            val content = f.contentPane
            val w = content.width.coerceAtLeast(1)
            val h = content.height.coerceAtLeast(1)
            val img = BufferedImage(w, h, BufferedImage.TYPE_INT_RGB)
            val g = img.createGraphics()
            content.printAll(g)
            g.dispose()
            ImageIO.write(img, "png", outDir.resolve("$name.png").toFile())
            f.dispose()
        }
        println("wrote $name.png")
    }

    /**
     * Render a standalone component to a PNG, sizing the window to the panel's
     * own preferred size — exactly what ViewerFrame.openAttachDialog does with
     * pack(). This makes the attach-form shots match the real dialog a user
     * sees, so the intro / banner wrapping in the image is the wrapping in the
     * app.
     */
    fun dialogShot(name: String, build: () -> JComponent) {
        var frame: JFrame? = null
        SwingUtilities.invokeAndWait {
            val f = JFrame(name)
            f.contentPane = build()
            f.pack()
            f.isVisible = true
            frame = f
        }
        Thread.sleep(500)
        SwingUtilities.invokeAndWait {
            val f = frame!!
            val content = f.contentPane
            val cw = content.width.coerceAtLeast(1)
            val ch = content.height.coerceAtLeast(1)
            val img = BufferedImage(cw, ch, BufferedImage.TYPE_INT_RGB)
            val g = img.createGraphics()
            content.printAll(g)
            g.dispose()
            ImageIO.write(img, "png", outDir.resolve("$name.png").toFile())
            f.dispose()
        }
        println("wrote $name.png")
    }

    val sample = sampleSessionDir()

    shot("01-empty") { /* opens with no session */ }

    shot("02-no-artifacts") { f ->
        // Fixed path (not createTempDirectory) so the header line is stable
        // and the committed screenshot doesn't churn on every re-render.
        val dir = freshDir("j2c-viewer-shot-empty")
        f.openDirectory(dir)
    }

    shot("03-missing-artifacts") { f ->
        // Only classes.json present: pipeline shows what's missing + next step.
        val dir = freshDir("j2c-viewer-shot-partial")
        Files.copy(sample.resolve("classes.json"), dir.resolve("classes.json"))
        f.openDirectory(dir)
    }

    shot("04-pipeline") { f ->
        f.openDirectory(sample)
        f.selectTab("Pipeline")
    }

    shot("05-method-detail") { f ->
        f.openDirectory(sample)
        f.selectMethodByName("decrypt")
        f.selectTab("Detail")
    }

    shot("06-trace") { f ->
        f.openDirectory(sample)
        f.selectTab("Trace")
    }

    // The honest CLI-absent fallback. A PID and the ownership box are set so the
    // shown command carries --i-own-this-process, but the form is pinned to the
    // "attach subcommand not in this checkout" state to document that path: Run
    // is disabled and the amber notice says so — it never pretends the displayed
    // command would run. Listen and the /proc pre-scan still work. (This branch
    // itself wires the attach CLI in; see 13-attach-ready for the live state.)
    dialogShot("07-attach-form") {
        AttachPanel(
            defaultOutput = "trace.jsonl",
            onStartTail = {},
            onClose = {},
        ).apply {
            applyRequest(
                AttachRequest(
                    pid = "48213",
                    output = "trace.jsonl",
                    iOwnThisProcess = true,
                    logAll = false,
                    mechanism = "auto",
                    agentPath = "",
                )
            )
            previewAttachAvailability(false)
        }
    }

    // A live tail: reduced-live-capabilities (bind only) with honest capability
    // and gap rows, then the bind events themselves.
    shot("08-live-tail") { f ->
        f.startTail(resourceDir("sample-live").resolve("trace.jsonl"))
    }

    // The empty/gap case: no core capabilities, nothing usable captured — shown
    // plainly rather than hidden.
    shot("09-capability-gap") { f ->
        f.startTail(resourceDir("sample-live-nocaps").resolve("trace.jsonl"))
    }

    // A first-class attach refusal: the target's argv carries
    // -XX:+DisableAttachMechanism, so the form refuses before launch, names the
    // reason code, gives the one-line meaning, and points at the startup path.
    // No stealth, no bypass — reaching this banner means no attach happened.
    dialogShot("10-attach-refused") {
        AttachPanel(
            defaultOutput = "trace.jsonl",
            onStartTail = {},
            onClose = {},
        ).apply {
            applyRequest(
                AttachRequest(
                    pid = "48213",
                    output = "trace.jsonl",
                    iOwnThisProcess = true,
                    logAll = false,
                    mechanism = "auto",
                    agentPath = "",
                )
            )
            showRefusal(AttachRefusal(AttachRefusalCode.ATTACH_DISABLED, RefusalSource.CMDLINE_SCAN))
        }
    }

    // A non-fatal argv warning surfaced by the real pre-scan: the target sets
    // -Djdk.attach.allowAttachSelf=false, which governs self-attach only and
    // does NOT block this same-user attach, so the form warns (amber) and does
    // not refuse. Same scan/classification the live refresh runs.
    dialogShot("12-attach-self-warning") {
        AttachPanel(
            defaultOutput = "trace.jsonl",
            onStartTail = {},
            onClose = {},
        ).apply {
            applyRequest(
                AttachRequest(
                    pid = "48213",
                    output = "trace.jsonl",
                    iOwnThisProcess = true,
                    logAll = false,
                    mechanism = "auto",
                    agentPath = "",
                )
            )
            previewCmdlineScan(
                listOf("java", "-Djdk.attach.allowAttachSelf=false", "-jar", "app.jar"),
            )
        }
    }

    // The analysis strip on the session viewer: binary.json shown as more than a
    // count — container format (PE), arch, obfuscator profile + method-discovery
    // strategy, and a binding gap (checksum left unbound) called out in amber.
    shot("11-analysis-strip") { f ->
        f.openDirectory(sample)
        f.selectTab("Pipeline")
    }

    // The ready-to-run form on a checkout that HAS the attach subcommand (this
    // merged branch). A PID and the ownership box are set, the pre-scan finds no
    // blocker, and the attach CLI is present — so there is no "CLI missing"
    // notice and Run is enabled. This is the state deliverable (4) asks for.
    dialogShot("13-attach-ready") {
        AttachPanel(
            defaultOutput = "trace.jsonl",
            onStartTail = {},
            onClose = {},
        ).apply {
            applyRequest(
                AttachRequest(
                    pid = "48213",
                    output = "trace.jsonl",
                    iOwnThisProcess = true,
                    logAll = false,
                    mechanism = "auto",
                    agentPath = "",
                )
            )
            previewAttachAvailability(true)
        }
    }

    println("done -> ${outDir.toAbsolutePath()}")
    // Swing keeps AWT threads alive; exit explicitly.
    System.exit(0)
}

/**
 * A stable, empty temp directory with a fixed name. Recreated each run so
 * the screenshots that show its path stay byte-for-byte reproducible.
 */
private fun freshDir(name: String): Path {
    val dir = Path.of(System.getProperty("java.io.tmpdir"), name)
    if (Files.exists(dir)) {
        Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
    }
    Files.createDirectories(dir)
    return dir
}

/**
 * Locate the bundled sample session. When run from test runtime the
 * resource is on the classpath; fall back to the source tree.
 */
private fun sampleSessionDir(): Path = resourceDir("sample-session")

/** Locate a bundled test resource directory (classpath first, then source). */
private fun resourceDir(name: String): Path {
    val url = object {}.javaClass.getResource("/$name")
    if (url != null) return Path.of(url.toURI())
    val fromSource = Path.of("src/test/resources/$name")
    if (Files.isDirectory(fromSource)) return fromSource
    error("$name not found")
}
