package j2c.classrebuilder

import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes

/**
 * Synthesizes the two helper classes used to surface runtime-value provenance
 * in the recovered jar:
 *
 *  - `j2c/RuntimeTrace` — a `@Retention(RUNTIME)` annotation type used to
 *    decorate recovered methods with a String[] summary of dynamic value
 *    sites (in source order).
 *
 *  - `j2c/Trace` — a regular class with one empty static method per dynamic
 *    "kind" used (`RT_int_arg`, `RT_long_arg`, …). The rebuilder inserts
 *    `INVOKESTATIC j2c/Trace.RT_<kind>:()V` ahead of each dynamic insn when
 *    `--inline-trace-markers` is on, so any decompiler renders them as
 *    visible inline marker calls.
 *
 * Both are generated only when needed (their references actually appear in
 * the rebuilt jar), to avoid polluting recovered output unnecessarily.
 */
object TraceClassGen {

    fun generateAnnotationClass(): ByteArray {
        val cw = ClassWriter(0)
        cw.visit(
            Opcodes.V1_8,
            Opcodes.ACC_PUBLIC or Opcodes.ACC_ANNOTATION or Opcodes.ACC_ABSTRACT or Opcodes.ACC_INTERFACE,
            "j2c/RuntimeTrace",
            null,
            "java/lang/Object",
            arrayOf("java/lang/annotation/Annotation"),
        )

        // @Retention(RUNTIME)
        cw.visitAnnotation("Ljava/lang/annotation/Retention;", true).let { av ->
            av.visitEnum("value", "Ljava/lang/annotation/RetentionPolicy;", "RUNTIME")
            av.visitEnd()
        }
        // @Target(METHOD)
        cw.visitAnnotation("Ljava/lang/annotation/Target;", true).let { av ->
            av.visitArray("value").let { arr ->
                arr.visitEnum(null, "Ljava/lang/annotation/ElementType;", "METHOD")
                arr.visitEnd()
            }
            av.visitEnd()
        }

        // String[] value() default {};
        val mv = cw.visitMethod(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT,
            "value",
            "()[Ljava/lang/String;",
            null,
            null,
        )
        mv.visitAnnotationDefault().let { av ->
            av.visitArray(null).visitEnd()
            av.visitEnd()
        }
        mv.visitEnd()

        cw.visitEnd()
        return cw.toByteArray()
    }

    fun generateMarkerClass(kinds: Set<String>): ByteArray {
        val cw = ClassWriter(0)
        cw.visit(
            Opcodes.V1_8,
            Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL,
            "j2c/Trace",
            null,
            "java/lang/Object",
            null,
        )
        // private no-arg ctor (utility class)
        cw.visitMethod(Opcodes.ACC_PRIVATE, "<init>", "()V", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 0)
            visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        for (kind in kinds.sorted()) {
            cw.visitMethod(
                Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC,
                "RT_$kind",
                "()V",
                null,
                null,
            ).apply {
                visitCode()
                visitInsn(Opcodes.RETURN)
                visitMaxs(0, 0)
                visitEnd()
            }
        }
        cw.visitEnd()
        return cw.toByteArray()
    }
}
