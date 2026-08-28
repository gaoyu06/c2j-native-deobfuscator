package j2c.desktop

import java.awt.BorderLayout
import java.awt.CardLayout
import java.awt.Dimension
import java.nio.file.Path
import java.time.LocalTime
import java.time.format.DateTimeFormatter
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JDialog
import javax.swing.JFileChooser
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTabbedPane
import javax.swing.JTable
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.ListSelectionModel
import javax.swing.RowFilter
import javax.swing.SwingConstants
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.table.TableRowSorter

/**
 * The viewer window. Read-only: it opens a session directory, lists the
 * methods, shows a recovered body, and reports pipeline status. It never
 * runs a recovery step — that stays in the CLI.
 */
class ViewerFrame : JFrame("recovery artifact viewer") {

    private val methodModel = MethodTableModel()
    private val methodTable = JTable(methodModel)
    private val methodSorter = TableRowSorter(methodModel)
    private val filterField = JTextField(18)

    private val detailArea = JTextArea()
    private val jsonArea = JTextArea()
    private val traceModel = TraceTableModel()
    private val traceTable = JTable(traceModel)
    private val tabs = JTabbedPane()

    private val pathLabel = JLabel("no session open")
    private val statusLabel = JLabel(" ")
    private val notesLabel = JLabel("")

    private val artifactsBox = JPanel()
    private val nextReason = JLabel(" ")
    private val nextCommand = JTextArea()
    private val emptyBanner = JLabel("", SwingConstants.CENTER)

    private val cards = CardLayout()
    private val centerCards = JPanel(cards)

    private val traceStateLabel = JLabel(" ")
    private val traceTailButton = JButton("Tail this trace")
    private val traceStopButton = JButton("Stop")
    private var traceTailer: TraceTailer? = null

    private var current: Session? = null

    private val clock = DateTimeFormatter.ofPattern("HH:mm:ss")

    init {
        defaultCloseOperation = EXIT_ON_CLOSE
        preferredSize = Dimension(1120, 720)
        contentPane.background = Theme.BG
        layout = BorderLayout()

        add(buildHeader(), BorderLayout.NORTH)
        add(buildCenter(), BorderLayout.CENTER)
        add(buildStatusBar(), BorderLayout.SOUTH)

        showEmpty()
        updateTraceState()
        pack()
        setLocationRelativeTo(null)
    }

    // ---------------------------------------------------------------
    // Header
    // ---------------------------------------------------------------

    private fun buildHeader(): JComponent {
        val bar = JPanel(BorderLayout())
        bar.background = Theme.PANEL
        bar.border = BorderFactory.createMatteBorder(0, 0, 1, 0, Theme.LINE)

        val title = JLabel("  artifact viewer").apply {
            font = Theme.label
            foreground = Theme.ACCENT
        }
        pathLabel.font = Theme.monoSmall
        pathLabel.foreground = Theme.DIM
        pathLabel.border = BorderFactory.createEmptyBorder(0, 16, 0, 8)

        val left = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.X_AXIS)
            background = Theme.PANEL
            add(title)
            add(pathLabel)
        }

        val open = JButton("Open session…").apply { addActionListener { chooseDirectory() } }
        val reload = JButton("Reload").apply { addActionListener { reload() } }
        val attach = JButton("Attach / Listen…").apply {
            toolTipText = "Show the attach CLI, or tail a live trace"
            addActionListener { openAttachDialog() }
        }

        val right = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.X_AXIS)
            background = Theme.PANEL
            border = BorderFactory.createEmptyBorder(6, 8, 6, 8)
            add(attach)
            add(Box.createHorizontalStrut(6))
            add(open)
            add(Box.createHorizontalStrut(6))
            add(reload)
        }

        bar.add(left, BorderLayout.CENTER)
        bar.add(right, BorderLayout.EAST)
        return bar
    }

    // ---------------------------------------------------------------
    // Center (empty card + session card)
    // ---------------------------------------------------------------

    private fun buildCenter(): JComponent {
        centerCards.add(buildEmptyCard(), "empty")
        centerCards.add(buildSessionCard(), "session")
        return centerCards
    }

    private fun buildEmptyCard(): JComponent {
        val p = JPanel(BorderLayout())
        p.background = Theme.BG
        emptyBanner.font = Theme.sans
        emptyBanner.foreground = Theme.DIM
        emptyBanner.text = html(
            "<b style='color:#d4d7d9'>No session open</b><br><br>" +
                "Open a folder that holds a pipeline run:<br>" +
                "<span style='color:#868c90'>classes.json · binary.json · manifest.json · recovered/ · trace.jsonl</span>"
        )
        p.add(emptyBanner, BorderLayout.CENTER)
        return p
    }

    private fun buildSessionCard(): JComponent {
        val split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, buildMethodPanel(), buildDetailPanel())
        // Share resize evenly. The initial divider follows the two panels'
        // preferred widths (below), so it lands in the same place in every
        // state instead of jumping when the content changes.
        split.resizeWeight = 0.5
        split.border = null
        split.background = Theme.BG
        return split
    }

    private fun buildMethodPanel(): JComponent {
        methodTable.apply {
            setDefaultRenderer(Any::class.java, MethodCellRenderer(methodModel))
            setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
            rowSorter = methodSorter
            // Resize to fit the pane so the status column stays in view; the
            // descriptor column soaks up the slack and truncates when long
            // (the full text is on the tooltip and in the detail view).
            autoResizeMode = JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS
            fillsViewportHeight = true
            gridColor = Theme.LINE
            background = Theme.BG
            tableHeader.reorderingAllowed = false
            selectionModel.addListSelectionListener {
                if (!it.valueIsAdjusting) onMethodSelected()
            }
        }
        // class | method | descriptor(flex) | native addr | status
        val widths = intArrayOf(150, 85, 128, 100, 78)
        for (i in widths.indices) methodTable.columnModel.getColumn(i).preferredWidth = widths[i]
        Ui.leftAlignHeader(methodTable)

        filterField.putClientProperty("JTextField.placeholderText", "filter…")
        filterField.font = Theme.monoSmall
        filterField.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent) = applyFilter()
            override fun removeUpdate(e: DocumentEvent) = applyFilter()
            override fun changedUpdate(e: DocumentEvent) = applyFilter()
        })

        val head = JPanel(BorderLayout()).apply {
            background = Theme.PANEL
            border = BorderFactory.createMatteBorder(0, 0, 1, 0, Theme.LINE)
            add(Ui.sectionLabel("methods"), BorderLayout.WEST)
            add(JPanel().apply {
                layout = BoxLayout(this, BoxLayout.X_AXIS)
                background = Theme.PANEL
                border = BorderFactory.createEmptyBorder(4, 4, 4, 6)
                add(filterField)
            }, BorderLayout.EAST)
        }

        val p = JPanel(BorderLayout()).apply { background = Theme.BG }
        p.add(head, BorderLayout.NORTH)
        p.add(Ui.scroll(methodTable), BorderLayout.CENTER)
        // Fixed preferred width keeps the divider stable no matter which
        // detail tab is showing (long recovered listings would otherwise
        // pull the split over on first layout). The columns above sum to a
        // little under this, so nothing is clipped.
        p.preferredSize = Dimension(548, 640)
        return p
    }

    private fun buildDetailPanel(): JComponent {
        detailArea.apply {
            isEditable = false
            font = Theme.mono
            background = Theme.BG
            foreground = Theme.TEXT
            border = BorderFactory.createEmptyBorder(8, 10, 8, 10)
            lineWrap = false
        }
        jsonArea.apply {
            isEditable = false
            font = Theme.monoSmall
            background = Theme.BG
            foreground = Theme.DIM
            border = BorderFactory.createEmptyBorder(8, 10, 8, 10)
        }
        traceTable.apply {
            font = Theme.monoSmall
            background = Theme.BG
            gridColor = Theme.LINE
            tableHeader.reorderingAllowed = false
            setDefaultRenderer(Any::class.java, TraceCellRenderer(traceModel))
        }
        traceTable.columnModel.getColumn(0).preferredWidth = 44
        traceTable.columnModel.getColumn(1).preferredWidth = 96
        traceTable.columnModel.getColumn(2).preferredWidth = 56
        traceTable.columnModel.getColumn(3).preferredWidth = 360
        Ui.leftAlignHeader(traceTable)

        tabs.font = Theme.sansSmall
        tabs.addTab("Detail", Ui.scroll(detailArea))
        tabs.addTab("Pipeline", buildPipelinePanel())
        tabs.addTab("Artifact JSON", Ui.scroll(jsonArea))
        tabs.addTab("Trace", buildTracePanel())
        tabs.preferredSize = Dimension(556, 640)
        return tabs
    }

    private fun buildTracePanel(): JComponent {
        traceStateLabel.font = Theme.monoSmall
        traceStateLabel.foreground = Theme.DIM
        traceStateLabel.border = BorderFactory.createEmptyBorder(0, 8, 0, 8)

        traceTailButton.apply {
            toolTipText = "Follow this session's trace.jsonl as it grows"
            addActionListener { current?.let { startTail(it.dir.resolve("trace.jsonl")) } }
        }
        traceStopButton.apply {
            isEnabled = false
            addActionListener { stopTail() }
        }

        val head = JPanel(BorderLayout()).apply {
            background = Theme.PANEL
            border = BorderFactory.createMatteBorder(0, 0, 1, 0, Theme.LINE)
            add(traceStateLabel, BorderLayout.CENTER)
            add(JPanel().apply {
                layout = BoxLayout(this, BoxLayout.X_AXIS)
                background = Theme.PANEL
                border = BorderFactory.createEmptyBorder(4, 4, 4, 6)
                add(traceTailButton)
                add(Box.createHorizontalStrut(6))
                add(traceStopButton)
            }, BorderLayout.EAST)
        }

        val p = JPanel(BorderLayout()).apply { background = Theme.BG }
        p.add(head, BorderLayout.NORTH)
        p.add(Ui.scroll(traceTable), BorderLayout.CENTER)
        return p
    }

    private fun buildPipelinePanel(): JComponent {
        artifactsBox.layout = BoxLayout(artifactsBox, BoxLayout.Y_AXIS)
        artifactsBox.background = Theme.BG
        artifactsBox.alignmentX = JComponent.LEFT_ALIGNMENT
        artifactsBox.border = BorderFactory.createEmptyBorder(4, 10, 8, 10)

        nextReason.font = Theme.sans
        nextReason.foreground = Theme.TEXT
        nextReason.alignmentX = JComponent.LEFT_ALIGNMENT
        nextReason.border = BorderFactory.createEmptyBorder(2, 10, 6, 10)

        nextCommand.apply {
            isEditable = false
            font = Theme.mono
            background = Theme.RAISED
            foreground = Theme.ACCENT
            lineWrap = true
            // Wrap at spaces so a long command breaks between arguments
            // instead of chopping a path or flag in half.
            wrapStyleWord = true
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Theme.LINE),
                BorderFactory.createEmptyBorder(8, 10, 8, 10),
            )
        }
        val cmdWrap = JPanel(BorderLayout()).apply {
            background = Theme.BG
            alignmentX = JComponent.LEFT_ALIGNMENT
            border = BorderFactory.createEmptyBorder(0, 10, 10, 10)
            maximumSize = Dimension(Int.MAX_VALUE, 96)
            add(nextCommand, BorderLayout.CENTER)
        }

        // Stack everything top-down; a trailing glue keeps it anchored to
        // the top rather than floating in the middle.
        val stack = JPanel()
        stack.layout = BoxLayout(stack, BoxLayout.Y_AXIS)
        stack.background = Theme.BG
        stack.border = BorderFactory.createEmptyBorder(6, 0, 6, 0)
        stack.add(leftAligned(Ui.sectionLabel("artifacts")))
        stack.add(artifactsBox)
        stack.add(leftAligned(Ui.sectionLabel("suggested next step")))
        stack.add(nextReason)
        stack.add(cmdWrap)
        stack.add(Box.createVerticalGlue())

        val holder = JPanel(BorderLayout())
        holder.background = Theme.BG
        holder.add(stack, BorderLayout.NORTH)
        return holder
    }

    private fun leftAligned(c: JComponent): JComponent {
        c.alignmentX = JComponent.LEFT_ALIGNMENT
        return c
    }

    // ---------------------------------------------------------------
    // Status bar
    // ---------------------------------------------------------------

    private fun buildStatusBar(): JComponent {
        val bar = JPanel(BorderLayout())
        bar.background = Theme.PANEL
        bar.border = BorderFactory.createMatteBorder(1, 0, 0, 0, Theme.LINE)
        statusLabel.font = Theme.monoSmall
        statusLabel.foreground = Theme.DIM
        statusLabel.border = BorderFactory.createEmptyBorder(4, 10, 4, 10)
        notesLabel.font = Theme.monoSmall
        notesLabel.foreground = Theme.WARN
        notesLabel.border = BorderFactory.createEmptyBorder(4, 10, 4, 10)
        bar.add(statusLabel, BorderLayout.WEST)
        bar.add(notesLabel, BorderLayout.EAST)
        return bar
    }

    // ---------------------------------------------------------------
    // Behaviour
    // ---------------------------------------------------------------

    private fun chooseDirectory() {
        val chooser = JFileChooser().apply {
            fileSelectionMode = JFileChooser.DIRECTORIES_ONLY
            dialogTitle = "Open session directory"
        }
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            openDirectory(chooser.selectedFile.toPath())
        }
    }

    private fun reload() {
        current?.let { openDirectory(it.dir) }
    }

    fun openDirectory(dir: Path) {
        val session = SessionScanner.scan(dir)
        openSession(session)
    }

    fun openSession(session: Session) {
        // Opening a different session ends any live tail from the previous one.
        stopTail()
        current = session
        pathLabel.text = session.dir.toString()

        methodModel.setRows(session.methods)
        traceModel.setRows(session.traceEvents)
        updateTraceState()
        renderArtifacts(session)

        val c = session.counts
        statusLabel.text = "recovered ${c[RecoveryStatus.RECOVERED] ?: 0}   " +
            "stub ${c[RecoveryStatus.STUB] ?: 0}   " +
            "missing ${c[RecoveryStatus.MISSING] ?: 0}   ·   " +
            "${session.methods.size} methods   ·   ${session.traceEvents.size} trace events"
        notesLabel.text = if (session.notes.isEmpty()) "" else "${session.notes.size} read problem(s)"

        if (!session.hasAnyArtifact) {
            detailArea.text = "This folder has no pipeline artifacts.\n\n" +
                "Expected one or more of:\n" +
                "  classes.json  binary.json  manifest.json  recovered/  trace.jsonl\n\n" +
                "See the Pipeline tab for the first command to run."
            tabs.selectedIndex = tabs.indexOfTab("Pipeline")
        } else {
            detailArea.text = "Select a method to see its recovered body."
            tabs.selectedIndex = tabs.indexOfTab("Pipeline")
        }
        jsonArea.text = ""
        cards.show(centerCards, "session")

        if (session.methods.isNotEmpty()) {
            methodTable.rowSorter = methodSorter
        }
    }

    private fun showEmpty() {
        cards.show(centerCards, "empty")
        statusLabel.text = " "
        notesLabel.text = ""
    }

    // ---------------------------------------------------------------
    // Attach / live tail
    // ---------------------------------------------------------------

    private fun openAttachDialog() {
        val defaultOutput = current?.dir?.resolve("trace.jsonl")?.toString() ?: "trace.jsonl"
        val dialog = JDialog(this, "Attach / Listen", true)
        val panel = AttachPanel(
            defaultOutput = defaultOutput,
            onStartTail = { path -> startTail(path) },
            onClose = { dialog.dispose() },
        )
        dialog.contentPane = panel
        dialog.pack()
        dialog.setLocationRelativeTo(this)
        dialog.isVisible = true
    }

    /** Begin following a trace file live. Works with or without an open
     *  session — the events land in the Trace tab as the target writes them. */
    fun startTail(path: Path) {
        stopTail()
        traceModel.clear()
        cards.show(centerCards, "session")
        selectTab("Trace")
        val tailer = TraceTailer(
            path = path,
            onEvents = { events ->
                traceModel.addRows(events)
                val last = traceTable.rowCount - 1
                if (last >= 0) traceTable.scrollRectToVisible(traceTable.getCellRect(last, 0, true))
            },
            onStatus = { status -> renderTailStatus(path, status) },
        )
        traceTailer = tailer
        traceTailButton.isEnabled = false
        traceStopButton.isEnabled = true
        tailer.start()
    }

    fun stopTail() {
        traceTailer?.stop()
        val wasTailing = traceTailer != null
        traceTailer = null
        traceStopButton.isEnabled = false
        if (wasTailing) updateTraceState()
    }

    private fun renderTailStatus(path: Path, status: TraceTailer.TailStatus) {
        val updated = if (status.lastUpdateMillis > 0)
            "  ·  updated ${LocalTime.now().format(clock)}" else ""
        traceStateLabel.foreground = if (status.fileExists) Theme.OK else Theme.WARN
        traceStateLabel.text = if (status.fileExists) {
            "tailing $path  ·  ${status.totalEvents} events$updated"
        } else {
            "waiting for $path — not created yet (the agent writes it once attached)"
        }
    }

    /** Refresh the static (not-tailing) Trace tab header for the open session. */
    private fun updateTraceState() {
        val session = current
        val hasTrace = session != null && session.dir.resolve("trace.jsonl").let {
            it.toFile().exists()
        }
        traceTailButton.isEnabled = hasTrace && traceTailer == null
        traceStateLabel.foreground = Theme.DIM
        traceStateLabel.text = when {
            session == null -> "no session — use Attach / Listen to tail a trace"
            session.traceEvents.isNotEmpty() ->
                "static: ${session.traceEvents.size} events${if (hasTrace) "  ·  Tail to follow live" else ""}"
            hasTrace -> "trace.jsonl present but empty — Tail to follow live"
            else -> "no trace in this session — use Attach / Listen to capture one"
        }
    }

    /** Select the first method whose name matches (test / screenshot hook). */
    fun selectMethodByName(name: String) {
        for (view in 0 until methodTable.rowCount) {
            val modelRow = methodTable.convertRowIndexToModel(view)
            if (methodModel.rowAt(modelRow).ref.name == name) {
                methodTable.setRowSelectionInterval(view, view)
                methodTable.scrollRectToVisible(methodTable.getCellRect(view, 0, true))
                return
            }
        }
    }

    /** Show the tab with the given title (test / screenshot hook). */
    fun selectTab(title: String) {
        val i = tabs.indexOfTab(title)
        if (i >= 0) tabs.selectedIndex = i
    }

    private fun onMethodSelected() {
        val viewRow = methodTable.selectedRow
        if (viewRow < 0) return
        val modelRow = methodTable.convertRowIndexToModel(viewRow)
        val row = methodModel.rowAt(modelRow)
        val rec = row.recovered
        if (rec != null) {
            detailArea.text = rec.listing
            jsonArea.text = rec.rawJson
        } else {
            detailArea.text = buildString {
                append("// ").append(row.displayClass).append('.')
                    .append(row.ref.name).append(row.ref.desc).append('\n')
                append("// status: ").append(row.status.label).append('\n')
                row.nativeAddress?.let { append("// native address: ").append(it).append('\n') }
                append('\n')
                when (row.status) {
                    RecoveryStatus.STUB ->
                        append("No recovered body yet. This method would ship as a stub.\n" +
                            "Capture a trace that exercises it, or lift a Ghidra dump, then re-run trace-to-bc / static-reverse.")
                    RecoveryStatus.MISSING ->
                        append("No recovered body and no native address is known.\n" +
                            "Check that binary-introspect located this method in the native registry.")
                    RecoveryStatus.RECOVERED ->
                        append("Ordinary method — nothing to recover.")
                }
            }
            jsonArea.text = ""
        }
        detailArea.caretPosition = 0
        jsonArea.caretPosition = 0
        tabs.selectedIndex = tabs.indexOfTab("Detail")
    }

    private fun renderArtifacts(session: Session) {
        artifactsBox.removeAll()
        for (a in session.artifacts) {
            artifactsBox.add(artifactRow(a))
        }
        val next = session.nextCommand
        if (next != null) {
            nextReason.text = next.reason
            nextCommand.text = next.command
        } else {
            nextReason.text = "Nothing suggested."
            nextCommand.text = ""
        }
        artifactsBox.revalidate()
        artifactsBox.repaint()
    }

    private fun artifactRow(a: ArtifactState): JComponent {
        val glyph = JLabel(if (a.present) "\u25CF" else "\u25CB")
        glyph.foreground = if (a.present) Theme.OK else Theme.DIM
        glyph.font = Theme.mono
        glyph.preferredSize = Dimension(18, 20)

        val nameLabel = JLabel(a.fileName)
        nameLabel.foreground = if (a.present) Theme.TEXT else Theme.DIM
        nameLabel.font = Theme.mono
        nameLabel.preferredSize = Dimension(150, 20)

        val detailLabel = JLabel(a.detail)
        detailLabel.foreground = Theme.DIM
        detailLabel.font = Theme.monoSmall

        val panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
        panel.background = Theme.BG
        panel.alignmentX = LEFT_ALIGNMENT
        panel.border = BorderFactory.createEmptyBorder(1, 0, 1, 0)
        panel.maximumSize = Dimension(Int.MAX_VALUE, 22)
        panel.add(glyph)
        panel.add(nameLabel)
        panel.add(detailLabel)
        panel.add(Box.createHorizontalGlue())
        return panel
    }

    private fun applyFilter() {
        val text = filterField.text.trim()
        methodSorter.rowFilter = if (text.isEmpty()) {
            null
        } else {
            // Match class, method name and descriptor columns, case-insensitive.
            RowFilter.regexFilter("(?i)" + Regex.escape(text), 0, 1, 2)
        }
    }

    private fun html(body: String) = "<html><div style='text-align:center'>$body</div></html>"
}
