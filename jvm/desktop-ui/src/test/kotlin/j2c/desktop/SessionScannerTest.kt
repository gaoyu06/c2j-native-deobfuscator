package j2c.desktop

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.writeText

class SessionScannerTest {

    private fun sampleDir(): Path {
        val url = javaClass.getResource("/sample-session")
            ?: error("sample-session resource missing")
        return Path.of(url.toURI())
    }

    private fun statusOf(session: Session, name: String, desc: String): RecoveryStatus =
        session.methods.first { it.ref.name == name && it.ref.desc == desc }.status

    @Test
    fun `scans all artifacts in the sample session`() {
        val s = SessionScanner.scan(sampleDir())
        val present = s.artifacts.filter { it.present }.map { it.id }.toSet()
        assertEquals(setOf("classes", "binary", "manifest", "recovered", "trace"), present)
        assertTrue(s.notes.isEmpty(), "unexpected read problems: ${s.notes}")
    }

    @Test
    fun `derives recovery status per method`() {
        val s = SessionScanner.scan(sampleDir())
        // Recovered bodies exist for these two.
        assertEquals(RecoveryStatus.RECOVERED, statusOf(s, "decrypt", "(Ljava/lang/String;)Ljava/lang/String;"))
        assertEquals(RecoveryStatus.RECOVERED, statusOf(s, "boot", "()V"))
        // Obfuscated native, address known, no body -> stub.
        assertEquals(RecoveryStatus.STUB, statusOf(s, "rounds", "()I"))
        // Obfuscated native, no address, no body -> missing.
        assertEquals(RecoveryStatus.MISSING, statusOf(s, "checksum", "([B)J"))
        // Ordinary methods carry no recovery burden.
        assertEquals(RecoveryStatus.RECOVERED, statusOf(s, "main", "([Ljava/lang/String;)V"))
    }

    @Test
    fun `counts native addresses and recovered artifacts`() {
        val s = SessionScanner.scan(sampleDir())
        val decrypt = s.methods.first { it.ref.name == "decrypt" }
        assertEquals("0x180001240", decrypt.nativeAddress)
        assertNotNull(decrypt.recovered)
        assertTrue(decrypt.recovered!!.listing.contains("INVOKEVIRTUAL java.lang.String.length"))
        assertTrue(decrypt.recovered!!.listing.contains("runtime: str_computed"))
    }

    @Test
    fun `reads trace events`() {
        val s = SessionScanner.scan(sampleDir())
        assertEquals(9, s.traceEvents.size)
        assertEquals("enter", s.traceEvents.first().ev)
        assertTrue(s.traceEvents.any { it.ev == "jni" && it.summary == "NewStringUTF" })
    }

    @Test
    fun `suggests rebuild when stubs remain`() {
        val s = SessionScanner.scan(sampleDir())
        val next = s.nextCommand!!
        assertTrue(next.command.contains("rebuild"), "expected rebuild, got: ${next.command}")
        assertTrue(next.reason.contains("still need bodies"))
    }

    @Test
    fun `reads the analysis strip - format and arch from binary, gaps from manifest`() {
        val a = SessionScanner.scan(sampleDir()).binaryAnalysis
            ?: error("expected a binary analysis")
        // format / arch / analysis come from binary.json.
        assertEquals("PE", a.format)
        assertEquals("amd64", a.arch)
        assertEquals("native_obfuscator", a.profile)
        assertEquals("register-natives-call-site", a.methodDiscovery)
        assertEquals(2, a.nativeClassCount)
        assertEquals(3, a.stringCount)
        // bindingGaps come from manifest.json (the sample keeps them there).
        assertEquals(1, a.bindingGaps.size)
        assertTrue(a.hasBindingGaps)
        assertEquals("unbound-native-method", a.bindingGaps.first().kind)
        assertTrue(
            a.bindingGaps.first().line.contains("checksum"),
            "got: ${a.bindingGaps.first().line}",
        )
    }

    @Test
    fun `bindingGaps are read from manifest json, not binary json`() {
        val dir = Files.createTempDirectory("j2c-gaps-manifest")
        // binary.json carries the analysis facts but NO bindingGaps.
        dir.resolve("binary.json").writeText(
            """
            {
              "schemaVersion": 1,
              "input": { "libPath": "x.dll", "format": "PE", "arch": "amd64", "sha256": "${"0".repeat(64)}" },
              "analysis": { "profile": "native_obfuscator", "methodDiscovery": "register-natives-call-site" },
              "stringPool": { "totalBytes": 0, "strings": [] },
              "nativeRegistry": []
            }
            """.trimIndent(),
        )
        // manifest.json is the source of truth for bindingGaps (PR #4 layout).
        dir.resolve("manifest.json").writeText(
            """
            {
              "schemaVersion": 1,
              "classes": [],
              "bindingGaps": [
                { "kind": "unbound-native-method", "method": "com/example/Crypto.checksum", "desc": "([B)J" }
              ]
            }
            """.trimIndent(),
        )
        val a = SessionScanner.scan(dir).binaryAnalysis ?: error("expected a binary analysis")
        assertEquals(1, a.bindingGaps.size)
        assertEquals("unbound-native-method", a.bindingGaps.first().kind)
        assertTrue(a.bindingGaps.first().line.contains("checksum"), "got: ${a.bindingGaps.first().line}")
    }

    @Test
    fun `bindingGaps fall back to binary json when the manifest has none`() {
        val dir = Files.createTempDirectory("j2c-gaps-binary")
        // No manifest here; a run that wrote gaps onto binary.json is still read.
        dir.resolve("binary.json").writeText(
            """
            {
              "schemaVersion": 1,
              "input": { "libPath": "x.so", "format": "ELF", "arch": "aarch64", "sha256": "${"0".repeat(64)}" },
              "stringPool": { "totalBytes": 0, "strings": [] },
              "nativeRegistry": [],
              "bindingGaps": [ { "kind": "unbound-native-method", "detail": "left unbound" } ]
            }
            """.trimIndent(),
        )
        val a = SessionScanner.scan(dir).binaryAnalysis ?: error("expected a binary analysis")
        assertEquals(1, a.bindingGaps.size)
        assertEquals("unbound-native-method", a.bindingGaps.first().kind)
    }

    @Test
    fun `binary json without analysis or gaps still yields format and arch`() {
        val dir = Files.createTempDirectory("j2c-binonly")
        dir.resolve("binary.json").writeText(
            """
            {
              "schemaVersion": 1,
              "input": { "libPath": "x.so", "format": "ELF", "arch": "aarch64", "sha256": "${"0".repeat(64)}" },
              "stringPool": { "totalBytes": 0, "strings": [] },
              "nativeRegistry": []
            }
            """.trimIndent(),
        )
        val a = SessionScanner.scan(dir).binaryAnalysis ?: error("expected a binary analysis")
        assertEquals("ELF", a.format)
        assertEquals("aarch64", a.arch)
        assertNull(a.profile)
        assertNull(a.methodDiscovery)
        assertFalse(a.hasBindingGaps)
    }

    @Test
    fun `no binary json means no analysis strip`() {
        val dir = Files.createTempDirectory("j2c-nobinary")
        dir.resolve("classes.json").writeText("""{"schemaVersion":1,"input":{"jarPath":"a.jar","sha256":"${"0".repeat(64)}"},"classes":[]}""")
        assertNull(SessionScanner.scan(dir).binaryAnalysis)
    }

    @Test
    fun `empty folder reports no artifacts and points at parse-jar`() {
        val dir = Files.createTempDirectory("j2c-empty")
        val s = SessionScanner.scan(dir)
        assertFalse(s.hasAnyArtifact)
        assertTrue(s.methods.isEmpty())
        assertTrue(s.nextCommand!!.command.contains("parse-jar"))
    }

    @Test
    fun `folder with unrelated files still reports no artifacts`() {
        val dir = Files.createTempDirectory("j2c-junk")
        dir.resolve("notes.txt").writeText("hello")
        dir.resolve("data.bin").writeText("x")
        val s = SessionScanner.scan(dir)
        assertFalse(s.hasAnyArtifact)
        assertTrue(s.nextCommand!!.command.contains("parse-jar"))
    }

    @Test
    fun `malformed recovered json is noted, not fatal`() {
        val dir = Files.createTempDirectory("j2c-bad")
        Files.createDirectories(dir.resolve("recovered"))
        dir.resolve("recovered/broken.json").writeText("{ not json")
        val s = SessionScanner.scan(dir)
        assertTrue(s.notes.any { it.contains("broken.json") })
    }
}
