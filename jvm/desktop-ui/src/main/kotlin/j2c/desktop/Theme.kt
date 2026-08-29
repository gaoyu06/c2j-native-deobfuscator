package j2c.desktop

import com.formdev.flatlaf.FlatDarkLaf
import java.awt.Color
import java.awt.Font
import javax.swing.UIManager

/**
 * A restrained, instrument-panel look for the viewer.
 *
 * One accent colour (amber), a narrow neutral grey range, and flat
 * borders. No coloured sidebar blocks, no cards, no gradients. Data is
 * shown in a monospaced face so descriptors and addresses line up.
 */
object Theme {

    val BG = Color(0x1a, 0x1c, 0x1e)
    val PANEL = Color(0x20, 0x23, 0x25)
    val RAISED = Color(0x25, 0x28, 0x2b)
    val LINE = Color(0x33, 0x37, 0x3b)
    val TEXT = Color(0xd4, 0xd7, 0xd9)
    val DIM = Color(0x86, 0x8c, 0x90)
    val ACCENT = Color(0xd9, 0xa4, 0x41)

    // Status ink. Muted on purpose — these tint text, never fill blocks.
    val OK = Color(0x7c, 0xb3, 0x82)
    val WARN = Color(0xd9, 0xa4, 0x41)
    val BAD = Color(0xc0, 0x6a, 0x5e)

    val mono: Font = Font(Font.MONOSPACED, Font.PLAIN, 13)
    val monoSmall: Font = Font(Font.MONOSPACED, Font.PLAIN, 12)
    val sans: Font = Font(Font.SANS_SERIF, Font.PLAIN, 13)
    val sansSmall: Font = Font(Font.SANS_SERIF, Font.PLAIN, 11)
    val label: Font = Font(Font.SANS_SERIF, Font.BOLD, 11)

    fun install() {
        FlatDarkLaf.setup()
        // Tight, flat, single-accent overrides.
        UIManager.put("Component.focusWidth", 1)
        UIManager.put("Component.innerFocusWidth", 0)
        UIManager.put("Component.arc", 0)
        UIManager.put("Button.arc", 0)
        UIManager.put("TextComponent.arc", 0)
        UIManager.put("ScrollBar.thumbArc", 0)
        UIManager.put("ScrollBar.width", 12)

        UIManager.put("Panel.background", PANEL)
        UIManager.put("control", PANEL)
        UIManager.put("Component.borderColor", LINE)
        UIManager.put("Component.focusColor", ACCENT)
        UIManager.put("Component.accentColor", ACCENT)

        UIManager.put("Table.background", BG)
        UIManager.put("Table.foreground", TEXT)
        UIManager.put("Table.gridColor", LINE)
        UIManager.put("Table.showHorizontalLines", true)
        UIManager.put("Table.showVerticalLines", false)
        UIManager.put("Table.rowHeight", 22)
        UIManager.put("Table.selectionBackground", Color(0x33, 0x38, 0x3d))
        UIManager.put("Table.selectionForeground", TEXT)
        UIManager.put("Table.intercellSpacing", java.awt.Dimension(0, 0))

        UIManager.put("TableHeader.background", PANEL)
        UIManager.put("TableHeader.foreground", DIM)
        UIManager.put("TableHeader.separatorColor", LINE)
        UIManager.put("TableHeader.bottomSeparatorColor", LINE)
        UIManager.put("TableHeader.height", 24)

        UIManager.put("TextArea.background", BG)
        UIManager.put("TextArea.foreground", TEXT)
        UIManager.put("TextArea.caretColor", ACCENT)
        UIManager.put("List.background", BG)
        UIManager.put("List.foreground", TEXT)
        UIManager.put("List.selectionBackground", RAISED)

        UIManager.put("TabbedPane.background", PANEL)
        UIManager.put("TabbedPane.underlineColor", ACCENT)
        UIManager.put("TabbedPane.selectedForeground", TEXT)
        UIManager.put("TabbedPane.foreground", DIM)
        UIManager.put("TabbedPane.tabHeight", 26)
        UIManager.put("TabbedPane.showTabSeparators", true)
        UIManager.put("TabbedPane.tabSeparatorsFullHeight", true)

        UIManager.put("SplitPane.background", BG)
        UIManager.put("SplitPaneDivider.gripColor", LINE)
        UIManager.put("SplitPane.dividerSize", 4)

        UIManager.put("ScrollPane.background", BG)
        UIManager.put("Viewport.background", BG)

        UIManager.put("defaultFont", sans)
    }

    fun inkFor(status: RecoveryStatus): Color = when (status) {
        RecoveryStatus.RECOVERED -> OK
        RecoveryStatus.STUB -> WARN
        RecoveryStatus.MISSING -> BAD
    }
}
