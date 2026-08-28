package j2c.desktop

import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component
import java.awt.Dimension
import java.awt.FlowLayout
import javax.swing.BorderFactory
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.SwingConstants
import javax.swing.table.AbstractTableModel
import javax.swing.table.DefaultTableCellRenderer

/** Method table backing model. */
class MethodTableModel(private var rows: List<MethodRow> = emptyList()) : AbstractTableModel() {

    private val cols = listOf("class", "method", "descriptor", "native addr", "status")

    fun setRows(newRows: List<MethodRow>) {
        rows = newRows
        fireTableDataChanged()
    }

    fun rowAt(i: Int): MethodRow = rows[i]

    override fun getRowCount() = rows.size
    override fun getColumnCount() = cols.size
    override fun getColumnName(c: Int) = cols[c]

    override fun getValueAt(r: Int, c: Int): Any {
        val row = rows[r]
        return when (c) {
            0 -> row.displayClass
            1 -> row.ref.name
            2 -> row.ref.desc
            3 -> row.nativeAddress ?: "—"
            4 -> row.status.label
            else -> ""
        }
    }
}

/** Renders a method-table cell: monospace data, status column tinted. */
class MethodCellRenderer(private val model: MethodTableModel) : DefaultTableCellRenderer() {
    override fun getTableCellRendererComponent(
        table: JTable, value: Any?, isSelected: Boolean,
        hasFocus: Boolean, row: Int, column: Int,
    ): Component {
        val c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
        font = Theme.monoSmall
        border = BorderFactory.createEmptyBorder(0, 8, 0, 8)
        toolTipText = value?.toString()
        val modelRow = table.convertRowIndexToModel(row)
        val status = model.rowAt(modelRow).status
        foreground = when {
            column == 4 -> Theme.inkFor(status)
            column == 3 -> Theme.DIM
            else -> Theme.TEXT
        }
        horizontalAlignment = if (column == 3 || column == 4) SwingConstants.LEFT else SwingConstants.LEFT
        return c
    }
}

/** Trace event table model. */
class TraceTableModel(private var rows: List<TraceEvent> = emptyList()) : AbstractTableModel() {
    private val cols = listOf("#", "event", "thread", "detail")
    fun setRows(newRows: List<TraceEvent>) { rows = newRows; fireTableDataChanged() }
    override fun getRowCount() = rows.size
    override fun getColumnCount() = cols.size
    override fun getColumnName(c: Int) = cols[c]
    override fun getValueAt(r: Int, c: Int): Any {
        val e = rows[r]
        return when (c) {
            0 -> e.index
            1 -> e.ev
            2 -> e.thread
            3 -> e.summary
            else -> ""
        }
    }
}

object Ui {

    /** A small caps-ish section label, the instrument-panel heading style. */
    fun sectionLabel(text: String): JLabel = JLabel(text.uppercase()).apply {
        font = Theme.label
        foreground = Theme.DIM
        border = BorderFactory.createEmptyBorder(6, 8, 6, 8)
    }

    fun panel(): JPanel = JPanel(BorderLayout()).apply { background = Theme.PANEL }

    fun hairline(): JComponent = JPanel().apply {
        background = Theme.LINE
        preferredSize = Dimension(1, 1)
        maximumSize = Dimension(Int.MAX_VALUE, 1)
    }

    fun leftRow(vararg comps: JComponent): JPanel =
        JPanel(FlowLayout(FlowLayout.LEFT, 8, 4)).apply {
            background = Theme.PANEL
            comps.forEach { add(it) }
        }

    fun scroll(view: Component): JScrollPane = JScrollPane(view).apply {
        border = BorderFactory.createLineBorder(Theme.LINE)
        viewport.background = Theme.BG
        background = Theme.BG
    }

    fun dimText(text: String, color: Color = Theme.DIM): JLabel = JLabel(text).apply {
        foreground = color
        font = Theme.sans
    }
}
