package j2c.desktop

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class TraceParserTest {

    @Test
    fun `blank line yields nothing`() {
        assertNull(TraceParser.parse(0, "   "))
    }

    @Test
    fun `malformed json is flagged, not dropped`() {
        val e = TraceParser.parse(3, "{ not json")!!
        assertEquals(TraceKind.MALFORMED, e.kind)
        assertEquals(3, e.index)
    }

    @Test
    fun `ordinary enter stays normal`() {
        val e = TraceParser.parse(0, """{"ev":"enter","thr":1,"fn":"Java_x"}""")!!
        assertEquals(TraceKind.NORMAL, e.kind)
        assertEquals("enter", e.ev)
        assertEquals("Java_x", e.summary)
    }

    @Test
    fun `granted capability is CAPABILITY_OK`() {
        val e = TraceParser.parse(
            0,
            """{"ev":"capability","name":"can_generate_native_method_bind_events","available":true,"phase":"live"}""",
        )!!
        assertEquals(TraceKind.CAPABILITY_OK, e.kind)
        assertTrue(e.summary.contains("available"))
    }

    @Test
    fun `denied capability is CAPABILITY_UNAVAILABLE and keeps the error code`() {
        val e = TraceParser.parse(
            0,
            """{"ev":"capability","name":"can_generate_method_entry_events","available":false,"phase":"live","jvmtiError":98}""",
        )!!
        assertEquals(TraceKind.CAPABILITY_UNAVAILABLE, e.kind)
        assertTrue(e.summary.contains("unavailable"), "got: ${e.summary}")
        assertTrue(e.summary.contains("98"), "got: ${e.summary}")
    }

    @Test
    fun `reduced-capability gap names the enabled events`() {
        val e = TraceParser.parse(
            0,
            """{"ev":"gap","kind":"reduced-live-capabilities","phase":"live","enabledEvents":"native-method-bind","detail":"..."}""",
        )!!
        assertEquals(TraceKind.GAP, e.kind)
        assertTrue(e.summary.contains("reduced-live-capabilities"))
        assertTrue(e.summary.contains("native-method-bind"))
    }

    @Test
    fun `bind carries the class, method and address`() {
        val e = TraceParser.parse(
            0,
            """{"ev":"bind","thr":1,"owner":"com/example/Crypto","name":"decrypt","desc":"(Ljava/lang/String;)Ljava/lang/String;","fnAddr":"0x7f00"}""",
        )!!
        assertEquals(TraceKind.BIND, e.kind)
        assertTrue(e.summary.contains("com.example.Crypto.decrypt"))
        assertTrue(e.summary.contains("0x7f00"))
    }

    @Test
    fun `agent-attached is a lifecycle marker`() {
        val e = TraceParser.parse(
            0,
            """{"ev":"agent-attached","mode":"live-attach","phase":"live","logAll":false,"trace":"t.jsonl"}""",
        )!!
        assertEquals(TraceKind.LIFECYCLE, e.kind)
        assertTrue(e.summary.contains("live-attach"))
    }
}
