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

        val loader = findLoader(classNodes)
        val loaderClass = loader?.className
        val nativeDir = loaderClass?.substringBeforeLast('/', missingDelimiterValue = "")?.ifEmpty { null }
        val classesWithLoader = if (loaderClass != null) {
            classNodes.filter { it.name == loaderClass }.toSet()
        } else emptySet()

        val obfuscatedClasses: Set<String> = classNodes
            .filter { cn -> hasRegisterNativesCall(cn, loader) }
            .map { it.name }
            .toSet()

        val classes = classNodes.map { cn -> toClassInfo(cn, obfuscatedClasses, classesWithLoader.contains(cn)) }

        return ClassesJson(
            input = JarInput(jarPath.toString(), HashUtils.sha256(jarPath)),
            loaderClass = loaderClass,
            loaderRegisterMethod = loader?.registerMethodName,
            loaderRegisterDesc = loader?.registerMethodDesc,
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
     * Detect the loader class and the name of its "register natives for
     * class X" entry point. Two known dialects:
     *
     *  - native-obfuscator: `<dir>/Loader.class` with
     *    `static native void registerNativesForClass(int, Class)`.
     *  - j2cc (me.x150.j2cc, "Nativeify"): `<dir>/Loader.class` with
     *    `static native void initClass(Class)` + `static native void bootstrap([B)`.
     *
     * General rule: any class declaring at least one ACC_NATIVE | ACC_STATIC
     * method whose descriptor includes a single `Ljava/lang/Class;` parameter
     * (with or without an `int` prefix) is treated as a loader. The
     * register-entry method name is whichever such method matches and is
     * referenced from other classes' `<clinit>`.
     */
    data class LoaderInfo(val className: String, val registerMethodName: String, val registerMethodDesc: String)

    private fun findLoader(classes: List<ClassNode>): LoaderInfo? {
        val candidates = mutableListOf<LoaderInfo>()
        for (cn in classes) {
            for (m in cn.methods) {
                val isNS = (m.access and Opcodes.ACC_NATIVE) != 0 && (m.access and Opcodes.ACC_STATIC) != 0
                if (!isNS) continue
                if (!looksLikeRegisterDesc(m.desc)) continue
                candidates += LoaderInfo(cn.name, m.name, m.desc)
            }
        }
        if (candidates.isEmpty()) return null
        // Prefer the candidate that is actually called from another class's
        // <clinit> — that's the "live" loader, not a false positive on some
        // unrelated native(Class) method.
        for (cand in candidates) {
            if (isCalledFromAnyClinit(classes, cand)) return cand
        }
        // Fallback: first candidate.
        return candidates.first()
    }

    /** Does a static-native register-entry descriptor look right?
     *  Accepts (Ljava/lang/Class;)V, (ILjava/lang/Class;)V, and similar. */
    private fun looksLikeRegisterDesc(desc: String): Boolean {
        if (!desc.endsWith(")V")) return false
        // Exactly one Ljava/lang/Class; in the param list, optionally preceded
        // by an `I` for native-obfuscator's classId arg.
        val cnt = "Ljava/lang/Class;".toRegex().findAll(desc).count()
        if (cnt != 1) return false
        val inside = desc.substringAfter('(').substringBeforeLast(')')
        val withoutClass = inside.replace("Ljava/lang/Class;", "")
        // Allowed remainder: empty (j2cc-style) or just "I" (native-obfuscator).
        return withoutClass.isEmpty() || withoutClass == "I"
    }

    private fun isCalledFromAnyClinit(classes: List<ClassNode>, loader: LoaderInfo): Boolean {
        for (cn in classes) {
            if (cn.name == loader.className) continue
            val clinit = cn.methods.firstOrNull { it.name == "<clinit>" } ?: continue
            val insns = clinit.instructions ?: continue
            for (insn in insns) {
                if (insn is MethodInsnNode &&
                    insn.owner == loader.className &&
                    insn.name == loader.registerMethodName
                ) return true
            }
        }
        return false
    }

    /**
     * A class is "obfuscated" if its `<clinit>` invokes ANY static method on
     * the loader class. Two examples:
     *   - native-obfuscator: `<clinit>` does `Loader.registerNativesForClass(N, MyClass.class)`
     *     directly. The targeted method IS native.
     *   - j2cc: `<clinit>` does `Loader.doInit(MyClass.class)` where `doInit`
     *     is a non-native wrapper around `initClass(Class)V`. We still want
     *     to recognise this — checking just the wrapper call is sufficient.
     *
     * If no loader was identified, fall back to "has at least one ACC_NATIVE
     * body-less method" — weaker but better than nothing.
     */
    private fun hasRegisterNativesCall(cn: ClassNode, loader: LoaderInfo?): Boolean {
        if (loader != null) {
            val clinit = cn.methods.firstOrNull { it.name == "<clinit>" }
            if (clinit?.instructions != null) {
                for (insn in clinit.instructions) {
                    if (insn is MethodInsnNode && insn.owner == loader.className) return true
                }
            }
            return false
        }
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
