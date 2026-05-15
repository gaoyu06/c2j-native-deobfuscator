package j2c.classrebuilder

import j2c.common.JsonIO
import j2c.common.RecoveredMethod
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.*
import picocli.CommandLine
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.Callable
import java.util.jar.JarEntry
import java.util.jar.JarFile
import java.util.jar.JarOutputStream
import kotlin.system.exitProcess

@Command(
    name = "class-rebuilder",
    mixinStandardHelpOptions = true,
    description = ["Replace native stubs with recovered bytecode and strip the loader."]
)
class ClassRebuilderCmd : Callable<Int> {

    @Option(names = ["--input"], required = true, description = ["Input jar (the obfuscated one)"])
    lateinit var input: Path

    @Option(names = ["--recovered"], required = true, description = ["Directory containing recovered/*.json"])
    lateinit var recoveredDir: Path

    @Option(names = ["--manifest"], description = ["Optional manifest.json (used to locate loader class + nativeDir)"])
    var manifest: Path? = null

    @Option(names = ["-o", "--output"], required = true)
    lateinit var output: Path

    @Option(
        names = ["--annotate-runtime-values"],
        description = ["Emit @j2c.RuntimeTrace annotations summarizing runtime-observed values per method (default: true). Pass --annotate-runtime-values=false to disable."],
        arity = "1",
        defaultValue = "true",
    )
    var annotateRuntimeValues: Boolean = true

    @Option(
        names = ["--inline-trace-markers"],
        description = ["Insert INVOKESTATIC j2c/Trace.RT_<kind>:()V markers before each runtime-observed value (default: false). Produces a synthetic j2c/Trace.class so the bytecode still verifies and links."],
    )
    var inlineTraceMarkers: Boolean = false

    @Option(
        names = ["--allow-unverified-classes"],
        description = ["When ASM frame computation rejects the lifted bytecode for a class, fall back to writing the methods with COMPUTE_MAXS only (no StackMapTable). The class becomes non-loadable but stays decompilable — preserves the lifted opcodes for inspection instead of stubbing them out. Default: true."],
        arity = "1",
        defaultValue = "true",
    )
    var allowUnverifiedClasses: Boolean = true

    override fun call(): Int {
        val loaderCfg = detectLoaderConfig()
        val recovered = RecoveredIndex.loadDir(recoveredDir)
        System.err.println("Loaded ${recovered.size()} recovered methods")
        val rebuilder = ClassRebuilder(
            loaderCfg, recovered,
            annotateRuntimeValues = annotateRuntimeValues,
            inlineTraceMarkers = inlineTraceMarkers,
            allowUnverifiedClasses = allowUnverifiedClasses,
        )
        val stats = rebuilder.rebuild(input, output)
        System.err.println(
            "Wrote ${output} | classes=${stats.classes} replaced=${stats.replaced} " +
                "leftAsStub=${stats.leftAsStub} unverifiedClasses=${stats.unverifiedClasses} " +
                "unverifiedMethods=${stats.unverifiedMethods} loaderStripped=${stats.loaderStripped} " +
                "nativeLibsStripped=${stats.nativeLibsStripped}"
        )
        return 0
    }

    private fun detectLoaderConfig(): LoaderConfig {
        manifest?.let {
            val node = JsonIO.mapper.readTree(Files.newInputStream(it))
            return LoaderConfig(
                loaderClass = node.path("loaderClass").asText(null),
                nativeDir = node.path("nativeDir").asText(null),
                registerMethod = node.path("loaderRegisterMethod").asText(null),
                registerDesc = node.path("loaderRegisterDesc").asText(null),
            )
        }
        return LoaderConfig()
    }
}

/** Loader config sourced from manifest.json (when available). All fields
 *  are optional; missing entries fall back to native-obfuscator defaults
 *  to keep backwards-compat with manifests produced before #6 generalised
 *  loader detection. */
data class LoaderConfig(
    val loaderClass: String? = null,
    val nativeDir: String? = null,
    val registerMethod: String? = null,
    val registerDesc: String? = null,
)

class RecoveredIndex(private val map: Map<Key, RecoveredMethod>) {
    data class Key(val owner: String, val name: String, val desc: String)

    fun lookup(owner: String, name: String, desc: String): RecoveredMethod? =
        map[Key(owner, name, desc)]

    fun size(): Int = map.size

    companion object {
        fun loadDir(dir: Path): RecoveredIndex {
            val acc = mutableMapOf<Key, RecoveredMethod>()
            if (Files.isRegularFile(dir)) {
                load(dir, acc)
            } else if (Files.isDirectory(dir)) {
                Files.walk(dir).use { stream ->
                    stream.filter { Files.isRegularFile(it) && it.toString().endsWith(".json") }
                        .forEach { load(it, acc) }
                }
            }
            return RecoveredIndex(acc)
        }

        private fun load(path: Path, acc: MutableMap<Key, RecoveredMethod>) {
            val text = Files.readString(path)
            if (text.trimStart().startsWith("[")) {
                val arr: List<RecoveredMethod> = JsonIO.mapper.readValue(
                    text,
                    JsonIO.mapper.typeFactory.constructCollectionType(List::class.java, RecoveredMethod::class.java)
                )
                for (m in arr) acc[Key(m.owner, m.name, m.desc)] = m
            } else {
                val one: RecoveredMethod = JsonIO.mapper.readValue(text, RecoveredMethod::class.java)
                acc[Key(one.owner, one.name, one.desc)] = one
            }
        }
    }
}

data class RebuildStats(
    var classes: Int = 0,
    var replaced: Int = 0,
    var leftAsStub: Int = 0,
    var unverifiedClasses: Int = 0,
    var unverifiedMethods: Int = 0,
    var loaderStripped: Int = 0,
    var nativeLibsStripped: Int = 0,
)

class ClassRebuilder(
    private val loaderCfg: LoaderConfig,
    private val recovered: RecoveredIndex,
    private val annotateRuntimeValues: Boolean = true,
    private val inlineTraceMarkers: Boolean = false,
    private val allowUnverifiedClasses: Boolean = true,
) {
    private val loaderClass: String? get() = loaderCfg.loaderClass
    private val nativeDir: String? get() = loaderCfg.nativeDir

    // Collected during processing so we can synthesize j2c/Trace.class once
    // at the end with one empty marker method per encountered kind.
    private val markerKindsUsed = sortedSetOf<String>()
    private var anyDynamicSeen = false

    fun rebuild(input: Path, output: Path): RebuildStats {
        val stats = RebuildStats()
        JarFile(input.toFile()).use { jar ->
            Files.newOutputStream(output).use { fos ->
                JarOutputStream(fos).use { out ->
                    val entries = jar.entries()
                    while (entries.hasMoreElements()) {
                        val entry = entries.nextElement()
                        val name = entry.name
                        if (shouldStrip(name)) {
                            if (name == loaderClass?.let { "$it.class" }) stats.loaderStripped++
                            else stats.nativeLibsStripped++
                            continue
                        }
                        if (!name.endsWith(".class")) {
                            val raw = jar.getInputStream(entry).use { it.readBytes() }
                            out.putNextEntry(JarEntry(name).apply { time = entry.time })
                            out.write(raw)
                            out.closeEntry()
                            continue
                        }
                        val raw = jar.getInputStream(entry).use { it.readBytes() }
                        val processed = processClass(raw, stats)
                        out.putNextEntry(JarEntry(name).apply { time = entry.time })
                        out.write(processed)
                        out.closeEntry()
                    }
                    if (inlineTraceMarkers && markerKindsUsed.isNotEmpty()) {
                        val cls = TraceClassGen.generateMarkerClass(markerKindsUsed)
                        out.putNextEntry(JarEntry("j2c/Trace.class"))
                        out.write(cls)
                        out.closeEntry()
                    }
                    if (annotateRuntimeValues && anyDynamicSeen) {
                        // Emit a minimal annotation class so the @j2c.RuntimeTrace
                        // references in method attributes can resolve.
                        val annCls = TraceClassGen.generateAnnotationClass()
                        out.putNextEntry(JarEntry("j2c/RuntimeTrace.class"))
                        out.write(annCls)
                        out.closeEntry()
                    }
                }
            }
        }
        return stats
    }

    private fun shouldStrip(entryName: String): Boolean {
        if (loaderClass != null && entryName == "$loaderClass.class") return true
        if (nativeDir != null && entryName.startsWith("$nativeDir/")) {
            // Strip native libs but keep .class files that happen to live under nativeDir/
            // (the only one is Loader, already matched above)
            if (!entryName.endsWith(".class")) return true
        }
        // Common-case strip: native blob payload files emitted by obfuscators
        // that don't co-locate with the loader class (e.g. j2cc puts the
        // loader at me/fallenbreath/.../i18n/ but the blob at j2cc/natives.bin).
        // Conservative: only catch a few well-known names.
        val tail = entryName.substringAfterLast('/')
        if (tail in setOf("natives.bin", "natives.dat") ||
            tail.endsWith(".dll") || tail.endsWith(".so") || tail.endsWith(".dylib")) {
            // Don't strip JDK-bundled or third-party native libs that happen
            // to be in the jar (e.g. webcam's OpenIMAJGrabber). Only strip
            // files that look like obfuscator output (e.g. live in the
            // loader's parent package, or are named "natives.*").
            val lc = loaderClass
            if (lc != null) {
                val loaderTopDir = lc.substringBefore('/', missingDelimiterValue = "")
                if (entryName.startsWith("$loaderTopDir/") && tail.startsWith("natives.")) return true
            }
            if (tail == "natives.bin" || tail == "natives.dat") return true
        }
        return false
    }

    private fun processClass(bytes: ByteArray, stats: RebuildStats): ByteArray {
        val reader = ClassReader(bytes)
        val cn = ClassNode()
        reader.accept(cn, 0)
        stats.classes++

        var methodReplaced = false
        var clinitChanged = false
        val replacedMethods = mutableSetOf<MethodNode>()

        // 1) Replace obfuscated-native method bodies with recovered insns
        for (m in cn.methods) {
            if ((m.access and Opcodes.ACC_NATIVE) == 0) continue
            val rec = recovered.lookup(cn.name, m.name, m.desc)
            if (rec == null) {
                if (m.name != "registerNativesForClass") stats.leftAsStub++
                continue
            }
            val emitter = AsmEmitter(
                inlineTraceMarkers = inlineTraceMarkers,
                onMarkerKindUsed = { markerKindsUsed += it },
            )
            val insns = emitter.emit(rec)
            m.instructions = insns.list
            m.tryCatchBlocks = insns.tryCatches.toMutableList()
            m.access = m.access and Opcodes.ACC_NATIVE.inv()
            // Ensure ASM recomputes
            m.maxStack = -1
            m.maxLocals = -1
            stats.replaced++
            methodReplaced = true
            replacedMethods += m

            // Build the per-method @j2c.RuntimeTrace annotation summarizing
            // every dynamic value site (in source order) and every exception
            // type observed propagating through this frame during the trace.
            val dynamics = rec.instructions.mapNotNull { it.dynamic }
            val excs = rec.exceptionsObserved
            if (dynamics.isNotEmpty() || excs.isNotEmpty()) anyDynamicSeen = true
            if (annotateRuntimeValues && (dynamics.isNotEmpty() || excs.isNotEmpty())) {
                val entries = mutableListOf<String>()
                dynamics.forEachIndexed { idx, kind -> entries += "[${idx + 1}] $kind" }
                excs.forEach { entries += "exception_observed=$it" }
                val ann = AnnotationNode("Lj2c/RuntimeTrace;")
                ann.values = listOf("value", entries)
                if (m.visibleAnnotations == null) m.visibleAnnotations = mutableListOf()
                m.visibleAnnotations.add(ann)
            }
        }

        // 2) Strip <clinit>'s registerNativesForClass instrumentation
        val lc = loaderClass
        if (lc != null) {
            cn.methods.firstOrNull { it.name == "<clinit>" }?.let { ci ->
                val sizeBefore = ci.instructions?.size() ?: 0
                stripClinitInstrumentation(ci, lc)
                if ((ci.instructions?.size() ?: 0) != sizeBefore) clinitChanged = true
            }
        }

        // If nothing changed, return the original bytes verbatim — avoids
        // ASM trying to recompute frames (and chasing the class hierarchy
        // via Class.forName) for classes we don't actually need to rewrite.
        if (!methodReplaced && !clinitChanged) return bytes

        // For replaced methods we MUST recompute frames; for clinit-only
        // changes COMPUTE_MAXS is enough (frames within clinit are still
        // valid since we only stripped a contiguous suffix of pushes).
        val framesFlags = if (methodReplaced)
            ClassWriter.COMPUTE_MAXS or ClassWriter.COMPUTE_FRAMES
        else
            ClassWriter.COMPUTE_MAXS

        fun makeWriter(flags: Int): ClassWriter = object : ClassWriter(flags) {
            override fun getCommonSuperClass(type1: String, type2: String): String =
                try { super.getCommonSuperClass(type1, type2) }
                catch (_: Throwable) { "java/lang/Object" }
        }

        // Tier 1: verifying jar — try COMPUTE_FRAMES. If the lifted opcodes
        // type-check cleanly the resulting class loads in any JVM.
        try {
            val writer = makeWriter(framesFlags)
            cn.accept(writer)
            return writer.toByteArray()
        } catch (t1: Throwable) {
            if (replacedMethods.isEmpty()) throw IllegalStateException("class write failed but no methods replaced — bug")

            // Tier 2: best-effort decompilable jar — emit with COMPUTE_MAXS
            // only. No StackMapTable means the JVM rejects the class at load
            // time, but javap / CFR / IntelliJ still see the full lifted
            // opcode stream. Each replaced method gets a leading
            // `j2c/Trace.UNVERIFIED_<name>()V` marker so a decompiler view
            // surfaces "this body is best-effort" without us pulling tricks
            // on the bytecode itself.
            //
            // Before the write we run a stack balancer over each body so a
            // decompiler walking the insns doesn't pop from an empty stack
            // (the typical Vineflower / CFR crash on lifted-but-broken
            // output — see BytecodeNormalizer).
            if (allowUnverifiedClasses) {
                try {
                    for (mm in replacedMethods) {
                        BytecodeNormalizer.normalize(mm)
                        prependUnverifiedMarker(mm)
                    }
                    val writer = makeWriter(ClassWriter.COMPUTE_MAXS)
                    cn.accept(writer)
                    stats.unverifiedClasses++
                    stats.unverifiedMethods += replacedMethods.size
                    System.err.println(
                        "Class ${cn.name}: lifted bodies failed frame verification (${t1.javaClass.simpleName}) — " +
                            "writing ${replacedMethods.size} method(s) as non-loadable but decompilable."
                    )
                    return writer.toByteArray()
                } catch (_: Throwable) {
                    // fall through to tier 3
                }
            }

            // Tier 3: full stub fallback — we couldn't even write the class
            // structurally. Reset bodies + retry with COMPUTE_FRAMES so the
            // rest of the jar still ships.
            for (mm in replacedMethods) replaceWithDefaultReturn(mm)
            System.err.println("Class ${cn.name}: ASM rejected even the unverified write — re-stubbing ${replacedMethods.size} method(s).")
            val writer = makeWriter(framesFlags)
            cn.accept(writer)
            return writer.toByteArray()
        }
    }

    /** Insert a leading `INVOKESTATIC j2c/Trace.UNVERIFIED_<name>:()V` at the
     *  top of `m`'s body so a reader of the recovered jar can tell at a
     *  glance which methods were emitted on the best-effort, non-verifying
     *  path. Has zero stack effect, so it never disturbs the lifted body. */
    private fun prependUnverifiedMarker(m: MethodNode) {
        val insns = m.instructions ?: return
        val safeTok = m.name.replace(Regex("[.;\\[/<>]"), "_")
        val marker = MethodInsnNode(
            Opcodes.INVOKESTATIC, "j2c/Trace",
            "UNVERIFIED_$safeTok", "()V", false
        )
        markerKindsUsed += "UNVERIFIED_$safeTok"
        val first = insns.first
        if (first != null) insns.insertBefore(first, marker) else insns.add(marker)
    }

    private fun isAlreadyStub(m: MethodNode): Boolean {
        val arr = m.instructions?.toArray() ?: return false
        // Heuristic: 2 or 3 insns where the first is an INVOKESTATIC to j2c/Trace.
        if (arr.size > 3) return false
        val first = arr.firstOrNull() ?: return false
        return first is MethodInsnNode && first.owner == "j2c/Trace"
    }

    /** Replace `m`'s body with a verifier-safe stub: a marker INVOKESTATIC
     *  to j2c/Trace + a default-return for the declared descriptor.
     *  Used as fallback when ASM rejects our recovered body's stack model. */
    private fun replaceWithDefaultReturn(m: MethodNode) {
        val il = InsnList()
        // Sanitize the marker method-name token: JVM method names disallow
        // `.;[/<>` but allow `$`. Replace anything we don't want.
        val safeTok = m.name.replace(Regex("[.;\\[/<>]"), "_")
        il.add(MethodInsnNode(Opcodes.INVOKESTATIC, "j2c/Trace",
            "STACK_UNRECOVERED_$safeTok", "()V", false))
        markerKindsUsed += "STACK_UNRECOVERED_$safeTok"
        val ret = m.desc.substringAfterLast(')')
        when (ret.firstOrNull() ?: 'V') {
            'V' -> il.add(InsnNode(Opcodes.RETURN))
            'I', 'B', 'C', 'S', 'Z' -> { il.add(InsnNode(Opcodes.ICONST_0)); il.add(InsnNode(Opcodes.IRETURN)) }
            'J' -> { il.add(InsnNode(Opcodes.LCONST_0)); il.add(InsnNode(Opcodes.LRETURN)) }
            'F' -> { il.add(InsnNode(Opcodes.FCONST_0)); il.add(InsnNode(Opcodes.FRETURN)) }
            'D' -> { il.add(InsnNode(Opcodes.DCONST_0)); il.add(InsnNode(Opcodes.DRETURN)) }
            else -> { il.add(InsnNode(Opcodes.ACONST_NULL)); il.add(InsnNode(Opcodes.ARETURN)) }
        }
        m.instructions = il
        m.tryCatchBlocks = mutableListOf()
        m.maxStack = -1
        m.maxLocals = -1
    }

    /**
     * native-obfuscator emits a <clinit> of the form:
     *
     *     LDC classId             ; int
     *     LDC class.class          ; Class<?>
     *     INVOKESTATIC <loader>.registerNativesForClass(I,Class)V
     *     LDC class.class
     *     INVOKESTATIC <hidden>.special_clinit_X_Y(Class)V    ; original body in disguise
     *     RETURN
     *
     * We strip:
     *  - the register call and its two LDC pushes
     *  - optionally the proxy call (so users without recovered hidden bodies still get a runnable clinit)
     *
     * If the original class had a real <clinit>, its body lives in the hidden
     * proxy method; recovering it requires running the obfuscator's hidden
     * class through the same pipeline and merging the result back in.
     */
    private fun stripClinitInstrumentation(clinit: MethodNode, loaderClass: String) {
        val insns = clinit.instructions ?: return
        val arr = insns.toArray()
        val toRemove = mutableSetOf<AbstractInsnNode>()
        // Strategy: scan clinit ONLY for INVOKESTATIC calls whose owner is the
        // loader class, regardless of method name (native-obfuscator's
        // `registerNativesForClass`, j2cc's `doInit` / `initClass`, etc.).
        // For each, also remove the preceding `pushes = arg-count` push
        // instructions (those load Class.class / classId onto the stack).
        for (i in arr.indices) {
            val node = arr[i]
            if (node !is MethodInsnNode) continue
            if (node.opcode != Opcodes.INVOKESTATIC) continue
            if (node.owner != loaderClass) continue
            toRemove += node
            val inside = node.desc.substringAfter('(').substringBeforeLast(')')
            val pushesNeeded = countDescriptorArgs(inside)
            var pushesLeft = pushesNeeded
            var k = i - 1
            while (k >= 0 && pushesLeft > 0) {
                val n = arr[k]
                if (n !is LabelNode && n !is LineNumberNode && n !is FrameNode) {
                    toRemove += n
                    pushesLeft--
                }
                k--
            }
        }
        // native-obfuscator additionally emits a `<hiddenClass>.special_clinit_N_M(Class)V`
        // proxy call that holds the original <clinit> body. Strip that too —
        // we don't have a way to recover the hidden proxy's bytecode without
        // the JNI trace.
        for (j in arr.indices) {
            val node = arr[j]
            if (node is MethodInsnNode &&
                node.opcode == Opcodes.INVOKESTATIC &&
                node.name.startsWith("special_clinit_")
            ) {
                toRemove += node
                var k = j - 1
                while (k >= 0) {
                    val n = arr[k]
                    if (n !is LabelNode && n !is LineNumberNode && n !is FrameNode) {
                        toRemove += n
                        break
                    }
                    k--
                }
            }
        }
        toRemove.forEach { insns.remove(it) }
    }

    /** Count the top-level args in a JVM type-descriptor parameter list. */
    private fun countDescriptorArgs(inside: String): Int {
        var count = 0
        var i = 0
        while (i < inside.length) {
            while (i < inside.length && inside[i] == '[') i++
            if (i >= inside.length) break
            if (inside[i] == 'L') {
                while (i < inside.length && inside[i] != ';') i++
                if (i < inside.length) i++
            } else {
                i++
            }
            count++
        }
        return count
    }
}

fun main(args: Array<String>) {
    exitProcess(CommandLine(ClassRebuilderCmd()).execute(*args))
}
