package j2c.desktop

import com.fasterxml.jackson.databind.JsonNode
import j2c.common.ClassesJson
import j2c.common.JsonIO
import j2c.common.ManifestJson
import j2c.common.RecoveredMethod
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.io.path.extension
import kotlin.io.path.isDirectory
import kotlin.io.path.name

/**
 * Reads a session directory (the folder a pipeline run wrote its JSON
 * into) and builds a [Session]. Pure I/O + data — no Swing here so it can
 * be unit tested headless.
 *
 * Expected layout:
 *   classes.json          jar-parser
 *   binary.json           binary-introspect
 *   manifest.json         manifest-merge
 *   recovered/            trace-to-bytecode / ast-matcher (per-method JSON)
 *   trace.jsonl           JVMTI agent            (optional)
 */
object SessionScanner {

    private const val CLASSES = "classes.json"
    private const val BINARY = "binary.json"
    private const val MANIFEST = "manifest.json"
    private const val RECOVERED_DIR = "recovered"
    private const val TRACE = "trace.jsonl"

    fun scan(dir: Path): Session {
        val notes = mutableListOf<String>()

        val classesPath = dir.resolve(CLASSES)
        val binaryPath = dir.resolve(BINARY)
        val manifestPath = dir.resolve(MANIFEST)
        val recoveredPath = dir.resolve(RECOVERED_DIR)
        val tracePath = dir.resolve(TRACE)

        val recovered = readRecovered(recoveredPath, notes)
        val recoveredByRef = recovered.associateBy { it.ref }

        // Prefer the manifest (richest: fnAddr + obfuscated flags). Fall
        // back to classes.json. binary.json only supplies addresses when
        // no manifest is present.
        val manifest = tryRead<ManifestJson>(manifestPath, notes)
        val classes = tryRead<ClassesJson>(classesPath, notes)
        val binary = tryReadTree(binaryPath, notes)

        val methods = buildMethods(manifest, classes, binary, recoveredByRef)

        val artifacts = listOf(
            artifact("classes", CLASSES, classesPath) {
                classes?.let { "${it.classes.size} classes" }
            },
            artifact("binary", BINARY, binaryPath) {
                binary?.let {
                    val n = it["nativeRegistry"]?.size() ?: 0
                    val strings = it["stringPool"]?.get("strings")?.size() ?: 0
                    "$n native classes, $strings strings"
                }
            },
            artifact("manifest", MANIFEST, manifestPath) {
                manifest?.let { "${it.classes.size} classes" }
            },
            artifactDir("recovered", RECOVERED_DIR, recoveredPath, recovered.size),
            artifact("trace", TRACE, tracePath) { "present" },
        )

        val traceEvents = readTrace(tracePath, notes)

        val next = NextCommandPlanner.plan(
            hasClasses = classesPath.exists(),
            hasBinary = binaryPath.exists(),
            hasManifest = manifestPath.exists(),
            recoveredCount = recovered.size,
            stubCount = methods.count { it.status == RecoveryStatus.STUB || it.status == RecoveryStatus.MISSING },
            hasTrace = tracePath.exists(),
        )

        return Session(dir, artifacts, methods, traceEvents, next, notes)
    }

    // ---------------------------------------------------------------
    // Method table assembly
    // ---------------------------------------------------------------

    private fun buildMethods(
        manifest: ManifestJson?,
        classes: ClassesJson?,
        binary: JsonNode?,
        recoveredByRef: Map<MethodRef, RecoveredArtifact>,
    ): List<MethodRow> {
        val rows = mutableListOf<MethodRow>()
        val seen = mutableSetOf<MethodRef>()

        if (manifest != null) {
            for (c in manifest.classes) {
                for (m in c.methods) {
                    val ref = MethodRef(c.name, m.name, m.desc)
                    seen += ref
                    val rec = recoveredByRef[ref]
                    val needs = m.isObfuscatedNative
                    val addr = m.fnAddr
                    rows += MethodRow(ref, addr, statusFor(needs, addr, rec), needs, rec)
                }
            }
        } else if (classes != null) {
            val addrIndex = binaryAddressIndex(binary)
            for (c in classes.classes) {
                for (m in c.methods) {
                    val ref = MethodRef(c.name, m.name, m.desc)
                    seen += ref
                    val rec = recoveredByRef[ref]
                    val needs = m.isObfuscatedNative
                    val addr = addrIndex[ref]
                    rows += MethodRow(ref, addr, statusFor(needs, addr, rec), needs, rec)
                }
            }
        }

        // Recovered bodies whose method isn't in the listing: surface them
        // so a stray artifact is visible rather than silently dropped.
        for (rec in recoveredByRef.values) {
            if (rec.ref in seen) continue
            rows += MethodRow(rec.ref, null, RecoveryStatus.RECOVERED, true, rec)
        }

        // Native / obfuscated methods first, then by class + name so the
        // table reads like the pipeline's worklist.
        return rows.sortedWith(
            compareByDescending<MethodRow> { it.needsRecovery }
                .thenBy { it.ref.owner }
                .thenBy { it.ref.name }
                .thenBy { it.ref.desc }
        )
    }

    private fun statusFor(
        needsRecovery: Boolean,
        address: String?,
        recovered: RecoveredArtifact?,
    ): RecoveryStatus = when {
        recovered != null -> RecoveryStatus.RECOVERED
        !needsRecovery -> RecoveryStatus.RECOVERED // ordinary method, nothing to recover
        address != null -> RecoveryStatus.STUB
        else -> RecoveryStatus.MISSING
    }

    private fun binaryAddressIndex(binary: JsonNode?): Map<MethodRef, String> {
        if (binary == null) return emptyMap()
        val out = mutableMapOf<MethodRef, String>()
        val reg = binary["nativeRegistry"] ?: return out
        for (cls in reg) {
            val className = cls["className"]?.asText() ?: continue
            val methods = cls["methods"] ?: continue
            for (m in methods) {
                val name = m["name"]?.asText() ?: continue
                val desc = m["desc"]?.asText() ?: continue
                val addr = m["fnAddr"]?.asText() ?: continue
                out[MethodRef(className, name, desc)] = addr
            }
        }
        return out
    }

    // ---------------------------------------------------------------
    // Recovered bodies
    // ---------------------------------------------------------------

    private fun readRecovered(dir: Path, notes: MutableList<String>): List<RecoveredArtifact> {
        if (!dir.exists() || !dir.isDirectory()) return emptyList()
        val out = mutableListOf<RecoveredArtifact>()
        Files.newDirectoryStream(dir).use { stream ->
            for (path in stream.sortedBy { it.name }) {
                if (path.isDirectory() || path.extension != "json") continue
                try {
                    val raw = Files.readString(path)
                    val m: RecoveredMethod = JsonIO.mapper.readValue(raw, RecoveredMethod::class.java)
                    out += RecoveredArtifact(
                        ref = MethodRef(m.owner, m.name, m.desc),
                        file = path,
                        source = m.source,
                        confidence = m.confidence,
                        instructionCount = m.instructions.size,
                        rawJson = raw,
                        listing = Listing.render(m),
                    )
                } catch (e: Exception) {
                    notes += "could not read ${path.name}: ${e.message}"
                }
            }
        }
        return out
    }

    // ---------------------------------------------------------------
    // Trace
    // ---------------------------------------------------------------

    private fun readTrace(path: Path, notes: MutableList<String>): List<TraceEvent> {
        if (!path.exists()) return emptyList()
        val out = mutableListOf<TraceEvent>()
        try {
            Files.newBufferedReader(path).use { r ->
                var i = 0
                r.lineSequence().forEach { line ->
                    val l = line.trim()
                    if (l.isEmpty()) return@forEach
                    val node = try {
                        JsonIO.mapper.readTree(l)
                    } catch (e: Exception) {
                        null
                    }
                    if (node == null) {
                        out += TraceEvent(i, "?", "?", "malformed line")
                    } else {
                        out += TraceEvent(
                            index = i,
                            ev = node["ev"]?.asText() ?: "?",
                            thread = node["thr"]?.asText() ?: "",
                            summary = summarizeEvent(node),
                        )
                    }
                    i++
                }
            }
        } catch (e: Exception) {
            notes += "could not read ${path.name}: ${e.message}"
        }
        return out
    }

    private fun summarizeEvent(node: JsonNode): String = when (node["ev"]?.asText()) {
        "enter", "exit" -> node["fn"]?.asText() ?: ""
        "jni" -> node["call"]?.asText() ?: ""
        "slot" -> "${node["kind"]?.asText()} slot ${node["slot"]?.asText()}"
        else -> ""
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private inline fun <reified T> tryRead(path: Path, notes: MutableList<String>): T? {
        if (!path.exists()) return null
        return try {
            JsonIO.read<T>(path)
        } catch (e: Exception) {
            notes += "could not read ${path.name}: ${e.message}"
            null
        }
    }

    private fun tryReadTree(path: Path, notes: MutableList<String>): JsonNode? {
        if (!path.exists()) return null
        return try {
            JsonIO.mapper.readTree(Files.readString(path))
        } catch (e: Exception) {
            notes += "could not read ${path.name}: ${e.message}"
            null
        }
    }

    private fun artifact(
        id: String,
        fileName: String,
        path: Path,
        detail: () -> String?,
    ): ArtifactState {
        val present = path.exists()
        val note = if (present) (detail() ?: "present") else "not found"
        return ArtifactState(id, fileName, present, note)
    }

    private fun artifactDir(
        id: String,
        fileName: String,
        path: Path,
        count: Int,
    ): ArtifactState {
        val present = path.exists() && path.isDirectory()
        val note = when {
            !present -> "not found"
            count == 0 -> "empty"
            else -> "$count method${if (count == 1) "" else "s"}"
        }
        return ArtifactState(id, "$fileName/", present, note)
    }
}
