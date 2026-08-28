package j2c.desktop

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class AttachControllerTest {

    private fun req(
        pid: String = "1234",
        output: String = "trace.jsonl",
        own: Boolean = true,
        logAll: Boolean = false,
        mechanism: String = "auto",
        agent: String = "",
    ) = AttachRequest(pid, output, own, logAll, mechanism, agent)

    @Test
    fun `missing pid blocks run`() {
        val reason = AttachController.runBlockedReason(req(pid = ""))
        assertTrue(reason!!.contains("PID"), "got: $reason")
    }

    @Test
    fun `unconfirmed ownership blocks run`() {
        val reason = AttachController.runBlockedReason(req(own = false))
        assertTrue(reason!!.contains(AttachController.CONFIRM_FLAG), "got: $reason")
    }

    @Test
    fun `pid plus confirmation plus output unblocks run`() {
        assertNull(AttachController.runBlockedReason(req()))
    }

    @Test
    fun `command uses the documented python launcher and attach subcommand`() {
        val cmd = AttachController.commandLine(req())
        assertTrue(cmd.contains("-m j2c_dumper_cli.main attach"), "got: $cmd")
        assertTrue(cmd.contains("--pid 1234"), "got: $cmd")
        assertTrue(cmd.contains("-o trace.jsonl"), "got: $cmd")
    }

    @Test
    fun `confirmation flag appears only when confirmed`() {
        assertTrue(AttachController.commandLine(req(own = true)).contains(AttachController.CONFIRM_FLAG))
        assertFalse(AttachController.commandLine(req(own = false)).contains(AttachController.CONFIRM_FLAG))
    }

    @Test
    fun `optional flags are emitted only when set`() {
        val plain = AttachController.attachArgs(req())
        assertFalse(plain.contains("--log-all"))
        assertFalse(plain.contains("--mechanism"))
        assertFalse(plain.contains("--agent"))

        val full = AttachController.attachArgs(
            req(logAll = true, mechanism = "vm", agent = "/tmp/j2c_agent.so"),
        )
        assertTrue(full.contains("--log-all"))
        assertTrue(full.containsInOrder("--mechanism", "vm"))
        assertTrue(full.containsInOrder("--agent", "/tmp/j2c_agent.so"))
    }

    private fun List<String>.containsInOrder(a: String, b: String): Boolean {
        val i = indexOf(a)
        return i >= 0 && i + 1 < size && this[i + 1] == b
    }
}
