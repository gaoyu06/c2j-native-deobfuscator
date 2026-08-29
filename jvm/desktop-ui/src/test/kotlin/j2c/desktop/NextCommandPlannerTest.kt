package j2c.desktop

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class NextCommandPlannerTest {

    @Test
    fun `no classes suggests parse-jar`() {
        val n = NextCommandPlanner.plan(false, false, false, 0, 0, false)!!
        assertTrue(n.command.contains("parse-jar"))
    }

    @Test
    fun `classes only suggests inspect-binary`() {
        val n = NextCommandPlanner.plan(true, false, false, 0, 0, false)!!
        assertTrue(n.command.contains("inspect-binary"))
    }

    @Test
    fun `classes and binary suggest merge-manifest`() {
        val n = NextCommandPlanner.plan(true, true, false, 0, 0, false)!!
        assertTrue(n.command.contains("merge-manifest"))
    }

    @Test
    fun `manifest without trace suggests dynamic-trace`() {
        val n = NextCommandPlanner.plan(true, true, true, 0, 0, false)!!
        assertTrue(n.command.contains("dynamic-trace"))
    }

    @Test
    fun `manifest with trace but nothing recovered suggests trace-to-bc`() {
        val n = NextCommandPlanner.plan(true, true, true, 0, 0, true)!!
        assertTrue(n.command.contains("trace-to-bc"))
    }

    @Test
    fun `remaining stubs suggest rebuild`() {
        val n = NextCommandPlanner.plan(true, true, true, 2, 1, true)!!
        assertTrue(n.command.contains("rebuild"))
    }

    @Test
    fun `all recovered suggests rebuild`() {
        val n = NextCommandPlanner.plan(true, true, true, 4, 0, true)!!
        assertTrue(n.command.contains("rebuild"))
    }
}
