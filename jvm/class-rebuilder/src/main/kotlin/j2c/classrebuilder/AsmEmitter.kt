package j2c.classrebuilder

import j2c.common.BsmArg
import j2c.common.RecoveredInsn
import j2c.common.RecoveredMethod
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.*

/**
 * Convert a [RecoveredMethod] into an ASM [InsnList] (+ try-catch table).
 *
 * The conversion is mechanical: each entry in `instructions` maps to one ASM
 * `AbstractInsnNode`. Symbolic labels (strings) are resolved via a per-method
 * map so cross-references between jumps / try-catch blocks work.
 */
class AsmEmitter(
    private val inlineTraceMarkers: Boolean = false,
    private val onMarkerKindUsed: (String) -> Unit = {},
) {

    data class Result(val list: InsnList, val tryCatches: List<TryCatchBlockNode>)

    private val labels = mutableMapOf<String, LabelNode>()

    private fun label(name: String): LabelNode =
        labels.getOrPut(name) { LabelNode() }

    fun emit(method: RecoveredMethod): Result {
        val list = InsnList()
        for (ins in method.instructions) {
            val node = build(ins) ?: continue
            // Inline trace marker (--inline-trace-markers) — prepend an
            // INVOKESTATIC j2c/Trace.RT_<kind>:()V right before the dynamic
            // insn so any decompiler shows it as a visible marker call.
            // The marker has zero stack effect (no args, void return), so it
            // never disturbs the recovered stack model.
            val dyn = ins.dynamic
            if (inlineTraceMarkers && dyn != null) {
                onMarkerKindUsed(dyn)
                list.add(
                    MethodInsnNode(
                        Opcodes.INVOKESTATIC,
                        "j2c/Trace",
                        "RT_$dyn",
                        "()V",
                        false,
                    )
                )
            }
            list.add(node)
        }
        val tcb = method.tryCatchBlocks.map { tc ->
            TryCatchBlockNode(label(tc.start), label(tc.end), label(tc.handler), tc.type)
        }
        return Result(list, tcb)
    }

    private fun build(ins: RecoveredInsn): AbstractInsnNode? {
        val op = ins.op.uppercase()
        return when (op) {
            "LABEL" -> label(ins.label ?: ins.name ?: error("LABEL without name"))

            // ---- constants ----
            "NOP", "ACONST_NULL",
            "ICONST_M1", "ICONST_0", "ICONST_1", "ICONST_2", "ICONST_3", "ICONST_4", "ICONST_5",
            "LCONST_0", "LCONST_1",
            "FCONST_0", "FCONST_1", "FCONST_2",
            "DCONST_0", "DCONST_1" -> InsnNode(opcode(op))

            "BIPUSH" -> IntInsnNode(Opcodes.BIPUSH, (ins.value as Number).toInt())
            "SIPUSH" -> IntInsnNode(Opcodes.SIPUSH, (ins.value as Number).toInt())

            "LDC" -> LdcInsnNode(ldcValue(ins))

            // ---- local var <-> stack ----
            "ILOAD", "LLOAD", "FLOAD", "DLOAD", "ALOAD",
            "ISTORE", "LSTORE", "FSTORE", "DSTORE", "ASTORE" ->
                VarInsnNode(opcode(op), ins.`var` ?: error("$op without var"))

            // ---- array ops (single-byte) ----
            "IALOAD", "LALOAD", "FALOAD", "DALOAD", "AALOAD", "BALOAD", "CALOAD", "SALOAD",
            "IASTORE", "LASTORE", "FASTORE", "DASTORE", "AASTORE", "BASTORE", "CASTORE", "SASTORE",
            "ARRAYLENGTH" -> InsnNode(opcode(op))

            // ---- stack ----
            "POP", "POP2", "DUP", "DUP_X1", "DUP_X2", "DUP2", "DUP2_X1", "DUP2_X2", "SWAP" ->
                InsnNode(opcode(op))

            // ---- arithmetic / bitwise / conversions ----
            "IADD", "LADD", "FADD", "DADD",
            "ISUB", "LSUB", "FSUB", "DSUB",
            "IMUL", "LMUL", "FMUL", "DMUL",
            "IDIV", "LDIV", "FDIV", "DDIV",
            "IREM", "LREM", "FREM", "DREM",
            "INEG", "LNEG", "FNEG", "DNEG",
            "ISHL", "LSHL", "ISHR", "LSHR", "IUSHR", "LUSHR",
            "IAND", "LAND", "IOR", "LOR", "IXOR", "LXOR",
            "I2L", "I2F", "I2D", "L2I", "L2F", "L2D", "F2I", "F2L", "F2D", "D2I", "D2L", "D2F",
            "I2B", "I2C", "I2S",
            "LCMP", "FCMPL", "FCMPG", "DCMPL", "DCMPG" -> InsnNode(opcode(op))

            "IINC" -> IincInsnNode(ins.`var` ?: error("IINC without var"), ins.incr ?: 1)

            // ---- jumps ----
            "IFEQ", "IFNE", "IFLT", "IFGE", "IFGT", "IFLE",
            "IF_ICMPEQ", "IF_ICMPNE", "IF_ICMPLT", "IF_ICMPGE", "IF_ICMPGT", "IF_ICMPLE",
            "IF_ACMPEQ", "IF_ACMPNE",
            "GOTO", "JSR",
            "IFNULL", "IFNONNULL" ->
                JumpInsnNode(opcode(op), label(ins.target ?: error("$op without target")))

            "TABLESWITCH" -> TableSwitchInsnNode(
                ins.min ?: error("TABLESWITCH without min"),
                ins.max ?: error("TABLESWITCH without max"),
                label(ins.default ?: error("TABLESWITCH without default")),
                *(ins.labels ?: emptyList()).map(::label).toTypedArray()
            )

            "LOOKUPSWITCH" -> LookupSwitchInsnNode(
                label(ins.default ?: error("LOOKUPSWITCH without default")),
                (ins.keys ?: emptyList()).toIntArray(),
                (ins.labels ?: emptyList()).map(::label).toTypedArray()
            )

            "RET" -> VarInsnNode(Opcodes.RET, ins.`var` ?: error("RET without var"))

            // ---- returns ----
            "IRETURN", "LRETURN", "FRETURN", "DRETURN", "ARETURN", "RETURN" -> InsnNode(opcode(op))

            // ---- field access ----
            "GETSTATIC", "PUTSTATIC", "GETFIELD", "PUTFIELD" -> FieldInsnNode(
                opcode(op),
                ins.owner ?: error("$op without owner"),
                ins.name ?: error("$op without name"),
                ins.desc ?: error("$op without desc")
            )

            // ---- method calls ----
            "INVOKEVIRTUAL", "INVOKESPECIAL", "INVOKESTATIC", "INVOKEINTERFACE" -> MethodInsnNode(
                opcode(op),
                ins.owner ?: error("$op without owner"),
                ins.name ?: error("$op without name"),
                ins.desc ?: error("$op without desc"),
                ins.itf ?: (op == "INVOKEINTERFACE")
            )

            "INVOKEDYNAMIC" -> {
                val name = ins.name ?: error("INVOKEDYNAMIC without name")
                val desc = ins.desc ?: error("INVOKEDYNAMIC without desc")
                val bsmHandle = Handle(
                    ins.bsmTag ?: Opcodes.H_INVOKESTATIC,
                    ins.bsmOwner ?: error("INVOKEDYNAMIC without bsmOwner"),
                    ins.bsmName ?: error("INVOKEDYNAMIC without bsmName"),
                    ins.bsmDesc ?: error("INVOKEDYNAMIC without bsmDesc"),
                    ins.bsmItf ?: false,
                )
                val args = (ins.bsmArgs ?: emptyList()).map { decodeBsmArg(it) }.toTypedArray()
                InvokeDynamicInsnNode(name, desc, bsmHandle, *args)
            }

            // ---- new/checkcast/instanceof ----
            "NEW", "ANEWARRAY", "CHECKCAST", "INSTANCEOF" -> TypeInsnNode(
                opcode(op),
                ins.type ?: error("$op without type")
            )

            "NEWARRAY" -> IntInsnNode(Opcodes.NEWARRAY, (ins.value as Number).toInt())

            "MULTIANEWARRAY" -> MultiANewArrayInsnNode(
                ins.desc ?: error("MULTIANEWARRAY without desc"),
                ins.dims ?: error("MULTIANEWARRAY without dims")
            )

            "ATHROW" -> InsnNode(Opcodes.ATHROW)
            "MONITORENTER" -> InsnNode(Opcodes.MONITORENTER)
            "MONITOREXIT" -> InsnNode(Opcodes.MONITOREXIT)

            else -> error("Unknown opcode: $op")
        }
    }

    private fun ldcValue(ins: RecoveredInsn): Any {
        val v = ins.value
        // JSON only carries Number / String / Boolean; Class refs use `type`.
        return when {
            ins.type != null -> Type.getObjectType(ins.type)
            v is Number -> {
                when (ins.desc) {
                    "long" -> v.toLong()
                    "float" -> v.toFloat()
                    "double" -> v.toDouble()
                    else -> v
                }
            }
            v != null -> v
            else -> error("LDC without value/type")
        }
    }

    private fun opcode(name: String): Int {
        val field = Opcodes::class.java.getField(name)
        return field.getInt(null)
    }

    private fun decodeBsmArg(a: BsmArg): Any = when (a.kind) {
        "int"    -> (a.value as Number).toInt()
        "long"   -> (a.value as Number).toLong()
        "float"  -> (a.value as Number).toFloat()
        "double" -> (a.value as Number).toDouble()
        "string" -> a.value as String
        "type"   -> Type.getType(a.value as String)
        "handle" -> Handle(
            a.handleTag ?: error("BsmArg handle without tag"),
            a.handleOwner ?: error("BsmArg handle without owner"),
            a.handleName ?: error("BsmArg handle without name"),
            a.handleDesc ?: error("BsmArg handle without desc"),
            a.handleItf ?: false,
        )
        else -> error("unknown BsmArg kind: ${a.kind}")
    }
}
