package j2c.desktop

import java.io.RandomAccessFile
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import javax.swing.Timer
import kotlin.io.path.exists

/**
 * Follows a `trace.jsonl` file as it grows and hands new [TraceEvent]s to a
 * callback on the Swing event thread. It reads whatever already exists first,
 * then appends new complete lines as the target JVM writes them.
 *
 * A [javax.swing.Timer] drives the poll, so every callback runs on the EDT and
 * touches Swing models safely — no background thread, no locking. Polling (not
 * a filesystem watch) keeps it portable and tolerant of the file not existing
 * yet: the agent may only create the trace once it has attached.
 */
class TraceTailer(
    private val path: Path,
    private val pollMillis: Int = 400,
    private val onEvents: (List<TraceEvent>) -> Unit,
    private val onStatus: (TailStatus) -> Unit,
) {
    data class TailStatus(
        val fileExists: Boolean,
        val totalEvents: Int,
        val lastUpdateMillis: Long,
    )

    private var timer: Timer? = null
    private var offset = 0L
    private var index = 0
    private var total = 0
    private val carry = StringBuilder()
    private var lastUpdate = 0L

    fun start() {
        stop()
        offset = 0L
        index = 0
        total = 0
        carry.setLength(0)
        val t = Timer(pollMillis) { poll() }
        t.isRepeats = true
        timer = t
        t.start()
        poll()
    }

    fun stop() {
        timer?.stop()
        timer = null
    }

    val isRunning: Boolean get() = timer?.isRunning == true

    private fun poll() {
        if (!path.exists()) {
            onStatus(TailStatus(fileExists = false, totalEvents = total, lastUpdateMillis = lastUpdate))
            return
        }
        val fresh = mutableListOf<TraceEvent>()
        try {
            RandomAccessFile(path.toFile(), "r").use { raf ->
                val len = raf.length()
                // The file was truncated or replaced (e.g. a new run): restart.
                if (len < offset) {
                    offset = 0L
                    index = 0
                    total = 0
                    carry.setLength(0)
                }
                if (len > offset) {
                    raf.seek(offset)
                    val buf = ByteArray((len - offset).toInt())
                    raf.readFully(buf)
                    offset = len
                    carry.append(String(buf, StandardCharsets.UTF_8))
                    drainCompleteLines(fresh)
                }
            }
        } catch (e: Exception) {
            // A transient read error shouldn't kill the tail; try again next tick.
            return
        }
        if (fresh.isNotEmpty()) {
            total += fresh.size
            lastUpdate = System.currentTimeMillis()
            onEvents(fresh)
        }
        onStatus(TailStatus(fileExists = true, totalEvents = total, lastUpdateMillis = lastUpdate))
    }

    private fun drainCompleteLines(out: MutableList<TraceEvent>) {
        while (true) {
            val nl = carry.indexOf("\n")
            if (nl < 0) break
            val line = carry.substring(0, nl)
            carry.delete(0, nl + 1)
            TraceParser.parse(index, line)?.let {
                out += it
                index++
            }
        }
    }
}
