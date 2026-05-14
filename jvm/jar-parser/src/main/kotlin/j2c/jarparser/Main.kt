package j2c.jarparser

import j2c.common.*
import org.objectweb.asm.ClassReader
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import picocli.CommandLine
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import java.nio.file.Path
import java.nio.file.Paths
import java.util.concurrent.Callable
import java.util.jar.JarFile
import kotlin.system.exitProcess

@Command(
    name = "jar-parser",
    mixinStandardHelpOptions = true,
    description = ["Extract class skeletons + native method registry from a jar."]
)
class JarParserCmd : Callable<Int> {

    @Parameters(index = "0", description = ["Input jar"])
    lateinit var input: Path

    @Option(names = ["-o", "--output"], required = true, description = ["Path to write classes.json"])
    lateinit var output: Path

    override fun call(): Int {
        val jarPath = input.toAbsolutePath()
        val parser = JarParser()
        val result = parser.parse(jarPath)
        JsonIO.write(output.toAbsolutePath(), result)
        System.err.println("Wrote ${output} (${result.classes.size} classes)")
        return 0
    }
}

class JarParser {

    fun parse(jarPath: Path): ClassesJson {
        val classNodes = mutableListOf<ClassNode>()
        JarFile(jarPath.toFile()).use { jar ->
            val entries = jar.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                if (!entry.name.endsWith(".class")) continue
                val bytes = jar.getInputStream(entry).use { it.readBytes() }
                if (!isClassFile(bytes)) continue
                val cn = ClassNode()
                try {
                    ClassReader(bytes).accept(cn, ClassReader.SKIP_FRAMES)
                    classNodes.add(cn)
                } catch (ex: Throwable) {
                    System.err.println("Skipping ${entry.name}: ${ex.message}")
                }
            }
        }

        val loaderClass = findLoaderClass(classNodes)
        val nativeDir = loaderClass?.substringBeforeLast('/', missingDelimiterValue = "")?.ifEmpty { null }
        val classesWithLoader = if (loaderClass != null) {
            classNodes.filter { it.name == loaderClass }.toSet()
        } else emptySet()

        val obfuscatedClasses: Set<String> = classNodes
            .filter { cn -> hasRegisterNativesCall(cn, loaderClass) }
            .map { it.name }
            .toSet()

        val classes = classNodes.map { cn -> toClassInfo(cn, obfuscatedClasses, classesWithLoader.contains(cn)) }

        return ClassesJson(
            input = JarInput(jarPath.toString(), HashUtils.sha256(jarPath)),
            loaderClass = loaderClass,
            nativeDir = nativeDir,
            classes = classes,
        )
    }

    private fun isClassFile(bytes: ByteArray): Boolean =
        bytes.size >= 4 &&
                (bytes[0].toInt() and 0xff) == 0xCA &&
                (bytes[1].toInt() and 0xff) == 0xFE &&
                (bytes[2].toInt() and 0xff) == 0xBA &&
                (bytes[3].toInt() and 0xff) == 0xBE

    /**
     * Detect the loader class. native-obfuscator emits a `<nativeDir>/Loader.class`
     * containing `public static native void registerNativesForClass(int, Class)`.
     */
    private fun findLoaderClass(classes: List<ClassNode>): String? {
        for (cn in classes) {
            for (m in cn.methods) {
                if (m.name == "registerNativesForClass" &&
                    m.desc == "(ILjava/lang/Class;)V" &&
                    (m.access and Opcodes.ACC_NATIVE) != 0 &&
                    (m.access and Opcodes.ACC_STATIC) != 0
                ) {
                    return cn.name
                }
            }
        }
        return null
    }

    /**
     * A class is considered "obfuscated by native-obfuscator" if its `<clinit>`
     * calls `<loader>.registerNativesForClass(int, Class)`.
     * If no loader was identified, we fall back to "has at least one ACC_NATIVE
     * method without a body" which is a much weaker heuristic.
     */
    private fun hasRegisterNativesCall(cn: ClassNode, loaderClass: String?): Boolean {
        if (loaderClass != null) {
            val clinit = cn.methods.firstOrNull { it.name == "<clinit>" }
            if (clinit?.instructions != null) {
                for (insn in clinit.instructions) {
                    if (insn is MethodInsnNode &&
                        insn.owner == loaderClass &&
                        insn.name == "registerNativesForClass"
                    ) return true
                }
            }
            return false
        }
        // fallback heuristic
        return cn.methods.any { (it.access and Opcodes.ACC_NATIVE) != 0 && it.instructions?.size() == 0 }
    }

    private fun toClassInfo(cn: ClassNode, obfuscatedClasses: Set<String>, isLoader: Boolean): ClassInfo {
        val classObfuscated = cn.name in obfuscatedClasses
        return ClassInfo(
            name = cn.name,
            superName = cn.superName,
            interfaces = cn.interfaces ?: emptyList(),
            version = cn.version,
            access = cn.access,
            signature = cn.signature,
            sourceFile = cn.sourceFile,
            fields = (cn.fields ?: emptyList()).map { f ->
                FieldInfo(
                    name = f.name,
                    desc = f.desc,
                    access = f.access,
                    signature = f.signature,
                    value = f.value,
                )
            },
            methods = (cn.methods ?: emptyList()).map { m ->
                val isNative = (m.access and Opcodes.ACC_NATIVE) != 0
                val hasNoBody = (m.instructions == null) || (m.instructions.size() == 0)
                val isObfuscated = !isLoader && classObfuscated && isNative && hasNoBody
                MethodInfo(
                    name = m.name,
                    desc = m.desc,
                    access = m.access,
                    signature = m.signature,
                    isNative = isNative,
                    isObfuscatedNative = isObfuscated,
                    maxStack = m.maxStack,
                    maxLocals = m.maxLocals,
                )
            },
        )
    }
}

fun main(args: Array<String>) {
    exitProcess(CommandLine(JarParserCmd()).execute(*args))
}
