package j2c.desktop

import java.awt.image.BufferedImage
import java.nio.file.Files
import java.nio.file.Path
import javax.imageio.ImageIO
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

    val sample = sampleSessionDir()

    shot("01-empty") { /* opens with no session */ }

    shot("02-no-artifacts") { f ->
        val dir = Files.createTempDirectory("j2c-empty-shot")
        f.openDirectory(dir)
    }

    shot("03-missing-artifacts") { f ->
        // Only classes.json present: pipeline shows what's missing + next step.
        val dir = Files.createTempDirectory("j2c-partial-shot")
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

    println("done -> ${outDir.toAbsolutePath()}")
    // Swing keeps AWT threads alive; exit explicitly.
    System.exit(0)
}

/**
 * Locate the bundled sample session. When run from test runtime the
 * resource is on the classpath; fall back to the source tree.
 */
private fun sampleSessionDir(): Path {
    val url = object {}.javaClass.getResource("/sample-session")
    if (url != null) return Path.of(url.toURI())
    val fromSource = Path.of("src/test/resources/sample-session")
    if (Files.isDirectory(fromSource)) return fromSource
    error("sample-session not found")
}
