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

    override fun call(): Int {
        val (loaderClass, nativeDir) = detectLoaderAndDir()
        val recovered = RecoveredIndex.loadDir(recoveredDir)
        System.err.println("Loaded ${recovered.size()} recovered methods")
        val rebuilder = ClassRebuilder(loaderClass, nativeDir, recovered)
        val stats = rebuilder.rebuild(input, output)
        System.err.println(
            "Wrote ${output} | classes=${stats.classes} replaced=${stats.replaced} " +
                "leftAsStub=${stats.leftAsStub} loaderStripped=${stats.loaderStripped} " +
                "nativeLibsStripped=${stats.nativeLibsStripped}"
        )
        return 0
    }

    private fun detectLoaderAndDir(): Pair<String?, String?> {
        manifest?.let {
            val node = JsonIO.mapper.readTree(Files.newInputStream(it))
            return node.path("loaderClass").asText(null) to node.path("nativeDir").asText(null)
        }
        return null to null
    }
}

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
    var loaderStripped: Int = 0,
    var nativeLibsStripped: Int = 0,
)

class ClassRebuilder(
    private val loaderClass: String?,
    private val nativeDir: String?,
    private val recovered: RecoveredIndex,
) {

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
        return false
    }

    private fun processClass(bytes: ByteArray, stats: RebuildStats): ByteArray {
        val reader = ClassReader(bytes)
        val cn = ClassNode()
        reader.accept(cn, 0)
        stats.classes++

        // 1) Replace obfuscated-native method bodies with recovered insns
        for (m in cn.methods) {
            if ((m.access and Opcodes.ACC_NATIVE) == 0) continue
            val rec = recovered.lookup(cn.name, m.name, m.desc)
            if (rec == null) {
                if (m.name != "registerNativesForClass") stats.leftAsStub++
                continue
            }
            val insns = AsmEmitter().emit(rec)
            m.instructions = insns.list
            m.tryCatchBlocks = insns.tryCatches.toMutableList()
            m.access = m.access and Opcodes.ACC_NATIVE.inv()
            // Ensure ASM recomputes
            m.maxStack = -1
            m.maxLocals = -1
            stats.replaced++
        }

        // 2) Strip <clinit>'s registerNativesForClass instrumentation
        if (loaderClass != null) {
            cn.methods.firstOrNull { it.name == "<clinit>" }?.let { ci ->
                stripClinitInstrumentation(ci, loaderClass)
            }
        }

        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS or ClassWriter.COMPUTE_FRAMES)
        cn.accept(writer)
        return writer.toByteArray()
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
     * proxy method and recovering it is a separate concern (see deferred-features).
     */
    private fun stripClinitInstrumentation(clinit: MethodNode, loaderClass: String) {
        val insns = clinit.instructions ?: return
        val toRemove = mutableListOf<AbstractInsnNode>()
        var i = 0
        val arr = insns.toArray()
        while (i < arr.size) {
            val node = arr[i]
            if (node is MethodInsnNode &&
                node.opcode == Opcodes.INVOKESTATIC &&
                node.owner == loaderClass &&
                node.name == "registerNativesForClass" &&
                node.desc == "(ILjava/lang/Class;)V"
            ) {
                // Remove the call and the previous two push instructions.
                toRemove += node
                var pushesNeeded = 2
                var k = i - 1
                while (k >= 0 && pushesNeeded > 0) {
                    val n = arr[k]
                    if (n !is LabelNode && n !is LineNumberNode && n !is FrameNode) {
                        toRemove += n
                        pushesNeeded--
                    }
                    k--
                }
            }
            i++
        }
        // Also strip the proxy clinit invocation
        for (j in arr.indices) {
            val node = arr[j]
            if (node is MethodInsnNode &&
                node.opcode == Opcodes.INVOKESTATIC &&
                node.name.startsWith("special_clinit_")
            ) {
                toRemove += node
                // Drop preceding LDC class
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
        toRemove.toSet().forEach { insns.remove(it) }
    }
}

fun main(args: Array<String>) {
    exitProcess(CommandLine(ClassRebuilderCmd()).execute(*args))
}
