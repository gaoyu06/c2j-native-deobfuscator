package j2c.desktop

import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.nio.file.Path
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.SwingUtilities
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

/**
 * The attach / listen form. It never invents an attach mechanism: it shows the
 * exact `attach` CLI command for the current inputs, and only runs it once a
 * PID is entered and the ownership box is ticked. The confirmation flag is the
 * real gate — the Run button stays disabled until it is set.
 *
 * "Listen" is the no-run path: point it at a trace file (one being written by
 * an attach you started elsewhere, or a past run) and it just tails it.
 */
class AttachPanel(
    defaultOutput: String,
    private val onStartTail: (Path) -> Unit,
    private val onClose: () -> Unit,
) : JPanel(BorderLayout()) {

    private val pidField = JTextField(10)
    private val outputField = JTextField(defaultOutput, 22)
    private val confirmCheck = JCheckBox("I own or may inspect this process")
    private val logAllCheck = JCheckBox("Log all JNI calls (--log-all)")
    private val mechanismCombo = JComboBox(arrayOf("auto", "jcmd", "vm"))
    private val agentField = JTextField("", 22)

    private val commandArea = JTextArea(3, 40)
    private val hintLabel = JLabel(" ")
    private val logArea = JTextArea(7, 40)

    // A first-class refusal banner. Hidden until a pre-launch cmdline scan or a
    // parsed CLI refusal fills it in; then it names the reason code, a one-line
    // meaning, and the one honest remedy. Never claims an attach happened.
    private val refusalLabel = JLabel()
    private val refusalBanner = JPanel(BorderLayout())

    private val copyButton = JButton("Copy command")
    private val runButton = JButton("Run attach")
    private val listenButton = JButton("Listen (tail only)")

    init {
        background = Theme.BG
        border = BorderFactory.createEmptyBorder(12, 14, 12, 14)
        add(buildForm(), BorderLayout.NORTH)
        add(buildCommandAndLog(), BorderLayout.CENTER)
        add(buildButtons(), BorderLayout.SOUTH)
        wireLiveUpdates()
        refresh()
    }

    /** Fill the form from a request (test / screenshot hook). */
    fun applyRequest(req: AttachRequest) {
        pidField.text = req.pid
        outputField.text = req.output
        confirmCheck.isSelected = req.iOwnThisProcess
        logAllCheck.isSelected = req.logAll
        mechanismCombo.selectedItem = req.mechanism
        agentField.text = req.agentPath
        refresh()
    }

    /**
     * Show a classified refusal as a first-class banner: the reason code, the
     * one-line meaning, and the one honest remedy. Also disables Run — reaching
     * here means the attach did not (or will not) happen. Screenshot / test hook.
     */
    fun showRefusal(refusal: AttachRefusal) {
        val where = when (refusal.source) {
            RefusalSource.CMDLINE_SCAN -> "detected before launch (target argv)"
            RefusalSource.CLI_OUTPUT -> "reported by the attach CLI"
        }
        refusalLabel.text = buildString {
            append("<html><div style='width:452px'>")
            append("<span style='color:").append(hex(Theme.BAD)).append("'><b>")
            append("attach refused &middot; reason=").append(refusal.code.code)
            append("</b></span><br>")
            append("<span style='color:").append(hex(Theme.TEXT)).append("'>")
            append(escape(refusal.code.meaning)).append("</span><br>")
            append("<span style='color:").append(hex(Theme.WARN)).append("'>next step: ")
            append(escape(AttachDiagnostics.STARTUP_RECOMMENDATION)).append("</span><br>")
            append("<span style='color:").append(hex(Theme.DIM)).append("'>").append(where)
            if (refusal.detail.isNotBlank()) {
                append(" &mdash; ").append(escape(refusal.detail.take(220)))
            }
            append("</span></div></html>")
        }
        refusalBanner.isVisible = true
        runButton.isEnabled = false
        hintLabel.text = "Run is blocked — this attach cannot proceed (see below)."
        hintLabel.foreground = Theme.BAD
        revalidate()
        repaint()
    }

    private fun clearRefusal() {
        if (refusalBanner.isVisible) {
            refusalBanner.isVisible = false
            refusalLabel.text = ""
            revalidate()
            repaint()
        }
    }

    private fun hex(c: java.awt.Color): String = "#%02x%02x%02x".format(c.red, c.green, c.blue)

    private fun escape(s: String): String =
        s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    private fun request(): AttachRequest = AttachRequest(
        pid = pidField.text,
        output = outputField.text,
        iOwnThisProcess = confirmCheck.isSelected,
        logAll = logAllCheck.isSelected,
        mechanism = (mechanismCombo.selectedItem as? String) ?: "auto",
        agentPath = agentField.text,
    )

    // ---------------------------------------------------------------
    // Layout
    // ---------------------------------------------------------------

    private fun buildForm(): JComponent {
        val intro = JLabel(
            "<html><div style='width:460px'>" +
                "This runs the same <b>attach</b> command you would type — nothing more. " +
                "It needs a PID and your confirmation first. Attach works on a same-user " +
                "JVM you own; how much it can see depends on what the JDK grants, and the " +
                "capability / gap rows in the trace show exactly what the attach obtained." +
                "</div></html>"
        ).apply {
            font = Theme.sansSmall
            foreground = Theme.DIM
            border = BorderFactory.createEmptyBorder(0, 0, 10, 0)
        }

        val grid = JPanel(GridBagLayout()).apply { background = Theme.BG }
        val c = GridBagConstraints().apply {
            gridx = 0; gridy = 0
            anchor = GridBagConstraints.WEST
            insets = Insets(3, 0, 3, 8)
        }

        fun row(label: String, field: JComponent, gy: Int) {
            c.gridx = 0; c.gridy = gy; c.weightx = 0.0; c.fill = GridBagConstraints.NONE
            grid.add(fieldLabel(label), c)
            c.gridx = 1; c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL
            grid.add(field, c)
        }

        row("Target PID", pidField, 0)
        row("Trace output", outputField, 1)
        row("Mechanism", mechanismCombo, 2)
        row("Agent (optional)", agentField, 3)

        styleField(pidField)
        styleField(outputField)
        styleField(agentField)
        mechanismCombo.font = Theme.monoSmall

        confirmCheck.foreground = Theme.TEXT
        confirmCheck.background = Theme.BG
        confirmCheck.font = Theme.sansSmall
        confirmCheck.toolTipText = "Adds ${AttachController.CONFIRM_FLAG}; required before anything runs."
        logAllCheck.foreground = Theme.DIM
        logAllCheck.background = Theme.BG
        logAllCheck.font = Theme.sansSmall

        val checks = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            background = Theme.BG
            border = BorderFactory.createEmptyBorder(6, 0, 0, 0)
            add(left(confirmCheck))
            add(left(logAllCheck))
        }

        val wrap = JPanel(BorderLayout()).apply { background = Theme.BG }
        wrap.add(intro, BorderLayout.NORTH)
        wrap.add(grid, BorderLayout.CENTER)
        wrap.add(checks, BorderLayout.SOUTH)
        return wrap
    }

    private fun buildCommandAndLog(): JComponent {
        commandArea.apply {
            isEditable = false
            font = Theme.mono
            background = Theme.RAISED
            foreground = Theme.ACCENT
            lineWrap = true
            wrapStyleWord = true
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Theme.LINE),
                BorderFactory.createEmptyBorder(8, 10, 8, 10),
            )
        }
        hintLabel.font = Theme.sansSmall
        hintLabel.foreground = Theme.WARN
        hintLabel.border = BorderFactory.createEmptyBorder(4, 2, 6, 2)

        refusalLabel.font = Theme.sansSmall
        refusalBanner.background = Theme.BG
        refusalBanner.isVisible = false
        refusalBanner.border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Theme.BAD),
            BorderFactory.createEmptyBorder(8, 10, 8, 10),
        )
        refusalBanner.add(refusalLabel, BorderLayout.CENTER)

        logArea.apply {
            isEditable = false
            font = Theme.monoSmall
            background = Theme.BG
            foreground = Theme.DIM
            lineWrap = true
            wrapStyleWord = false
            text = ""
        }

        val stack = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            background = Theme.BG
            border = BorderFactory.createEmptyBorder(8, 0, 0, 0)
        }
        stack.add(left(Ui.sectionLabel("command")))
        stack.add(commandArea)
        stack.add(left(hintLabel))
        stack.add(bannerRow(refusalBanner))
        stack.add(left(Ui.sectionLabel("attach output")))
        stack.add(Ui.scroll(logArea).apply { preferredSize = Dimension(480, 120) })
        return stack
    }

    private fun buildButtons(): JComponent {
        copyButton.addActionListener { copyCommand() }
        runButton.addActionListener { runAttach() }
        listenButton.addActionListener { startTail() }
        val close = JButton("Close").apply { addActionListener { onClose() } }

        val bar = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.X_AXIS)
            background = Theme.BG
            border = BorderFactory.createEmptyBorder(10, 0, 0, 0)
            add(copyButton)
            add(Box.createHorizontalStrut(6))
            add(listenButton)
            add(Box.createHorizontalGlue())
            add(runButton)
            add(Box.createHorizontalStrut(6))
            add(close)
        }
        return bar
    }

    private fun fieldLabel(text: String): JLabel = JLabel(text).apply {
        font = Theme.sansSmall
        foreground = Theme.DIM
    }

    private fun styleField(f: JTextField) {
        f.font = Theme.monoSmall
    }

    private fun left(c: JComponent): JComponent = JPanel(BorderLayout()).apply {
        background = Theme.BG
        add(c, BorderLayout.WEST)
        maximumSize = Dimension(Int.MAX_VALUE, c.preferredSize.height + 4)
    }

    /** Full-width row that never stretches taller than its content — used for
     *  the refusal banner so BoxLayout does not balloon it. The max height
     *  tracks the (variable) banner height, since the text is set later. */
    private fun bannerRow(c: JComponent): JComponent =
        object : JPanel(BorderLayout()) {
            override fun getMaximumSize(): Dimension =
                Dimension(Int.MAX_VALUE, preferredSize.height)
        }.apply {
            background = Theme.BG
            border = BorderFactory.createEmptyBorder(2, 0, 4, 0)
            add(c, BorderLayout.CENTER)
        }

    // ---------------------------------------------------------------
    // Behaviour
    // ---------------------------------------------------------------

    private fun wireLiveUpdates() {
        val listener = object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent) = refresh()
            override fun removeUpdate(e: DocumentEvent) = refresh()
            override fun changedUpdate(e: DocumentEvent) = refresh()
        }
        pidField.document.addDocumentListener(listener)
        outputField.document.addDocumentListener(listener)
        agentField.document.addDocumentListener(listener)
        confirmCheck.addActionListener { refresh() }
        logAllCheck.addActionListener { refresh() }
        mechanismCombo.addActionListener { refresh() }
    }

    private fun refresh() {
        val req = request()
        commandArea.text = AttachController.commandLine(req)
        commandArea.caretPosition = 0
        val blocked = AttachController.runBlockedReason(req)

        // Pre-launch: scan the target's argv for flags that make an attach
        // impossible, and refuse before Run rather than after an opaque failure.
        // Only when the basic gates (PID / ownership / output) already pass, so
        // the banner doesn't fight the plain "enter a PID" hint.
        val preScan = if (blocked == null) {
            req.pid.trim().toIntOrNull()?.let { AttachDiagnostics.scanCmdline(it) }
        } else null

        if (preScan != null) {
            showRefusal(preScan)
            listenButton.isEnabled = req.output.isNotBlank()
            return
        }

        clearRefusal()
        runButton.isEnabled = blocked == null
        listenButton.isEnabled = req.output.isNotBlank()
        hintLabel.text = blocked ?: "Ready to run. This loads the agent; the target keeps writing the trace."
        hintLabel.foreground = if (blocked == null) Theme.OK else Theme.WARN
    }

    private fun copyCommand() {
        val sel = StringSelection(commandArea.text)
        Toolkit.getDefaultToolkit().systemClipboard.setContents(sel, sel)
        appendLog("copied command to clipboard")
    }

    private fun startTail() {
        val out = outputField.text.trim()
        if (out.isEmpty()) {
            appendLog("set an output path before listening")
            return
        }
        onStartTail(Path.of(out))
        onClose()
    }

    private fun runAttach() {
        val req = request()
        if (AttachController.runBlockedReason(req) != null) return

        // Fail before launch: re-run the argv pre-scan at the moment of Run, so a
        // target that acquired a blocking flag between edits is still refused.
        val pid = req.pid.trim().toIntOrNull()
        val preScan = pid?.let { AttachDiagnostics.scanCmdline(it) }
        if (preScan != null) {
            showRefusal(preScan)
            appendLog("refused before launch (reason=${preScan.code.code}); nothing was run.")
            return
        }

        clearRefusal()
        runButton.isEnabled = false
        listenButton.isEnabled = false
        appendLog("$ ${AttachController.commandLine(req)}")
        Thread {
            val result = AttachController.run(req) { line -> onEdt { appendLog(line) } }
            onEdt {
                appendLog("[exit ${result.exitCode}]")
                runButton.isEnabled = true
                listenButton.isEnabled = req.output.isNotBlank()

                // Classify any refusal the CLI printed. A refusal, or any
                // non-zero exit, means the attach did not happen: never tail and
                // never claim attached in that case.
                val refusal = AttachDiagnostics.parseRefusal(result.output)
                when {
                    refusal != null -> {
                        showRefusal(refusal)
                        appendLog("attach refused (reason=${refusal.code.code}) — nothing was tailed.")
                    }
                    result.exitCode == 0 -> {
                        appendLog("attached; tailing ${req.output}")
                        onStartTail(Path.of(req.output.trim()))
                        onClose()
                    }
                    else ->
                        appendLog("attach did not succeed — see the output above. Nothing was tailed.")
                }
            }
        }.apply { isDaemon = true }.start()
    }

    private fun appendLog(line: String) {
        logArea.append(if (logArea.text.isEmpty()) line else "\n$line")
        logArea.caretPosition = logArea.document.length
    }

    private fun onEdt(block: () -> Unit) {
        if (SwingUtilities.isEventDispatchThread()) block() else SwingUtilities.invokeLater(block)
    }
}
