package j2c.desktop

import java.nio.file.Path
import javax.swing.SwingUtilities
import kotlin.io.path.exists
import kotlin.io.path.isDirectory

/**
 * Read-only Swing viewer for recovery-pipeline artifacts.
 *
 * Usage:
 *   desktop-ui [session-directory]
 *
 * The optional argument opens a session folder on launch; otherwise the
 * window starts empty and you open one from the toolbar. This is a
 * viewer only — recovery still runs through the CLI.
 */
fun main(args: Array<String>) {
    val startDir: Path? = args.firstOrNull()?.let { Path.of(it) }
    Theme.install()
    SwingUtilities.invokeLater {
        val frame = ViewerFrame()
        frame.isVisible = true
        if (startDir != null && startDir.exists() && startDir.isDirectory()) {
            frame.openDirectory(startDir)
        }
    }
}
