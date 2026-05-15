package j2c.classrebuilder

import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.*

/**
 * Best-effort stack balancer for lifted bytecode that the lifter could not
 * produce verifiably. Walks the InsnList sequentially, tracks the running
 * stack height (in JVM slots), and:
 *
 *  - inserts `ACONST_NULL` / `LCONST_0` before instructions that would pop
 *    from a too-low stack, so the pop has something to consume;
 *  - resets the running height after unconditional terminators (return /
 *    throw / goto), since whatever follows is either the body of a separate
 *    branch target or unreachable;
 *  - appends a default-return tail when the last instruction isn't itself
 *    a terminator.
 *
 * This does not make the bytecode correct. It just keeps decompilers
 * (Vineflower / CFR / IntelliJ) from crashing on stack underflow while
 * rendering the body — `ListStack.pop` on an empty stack is the typical
 * symptom on lifted-but-broken output.
 */
object BytecodeNormalizer {

    fun normalize(m: MethodNode) {
        val insns = m.instructions ?: return
        val arr = insns.toArray()
        var height = 0
        for (insn in arr) {
            val pops = popsOf(insn)
            if (height < pops) {
                // Underflowing ATHROW is almost always a lifter mistake — the
                // static path's exception-check guard recogniser misrendered
                // `if (env.ExceptionCheck()) return` as a `throw`, with
                // nothing on the stack to actually throw. If we fabricated
                // a null and let the throw stand, the decompiler would
                // correctly treat the rest of the body as unreachable and
                // hide it. Drop the bogus throw instead so the call chain
                // below it stays visible.
                if (insn.opcode == Opcodes.ATHROW) {
                    insns.set(insn, InsnNode(Opcodes.NOP))
                    continue
                }
                val needed = pops - height
                repeat(needed) {
                    insns.insertBefore(insn, InsnNode(Opcodes.ACONST_NULL))
                }
                height = pops
            }
            height = (height - pops + pushesOf(insn)).coerceAtLeast(0)
            if (isUnconditionalTerminator(insn)) height = 0
        }
        val last = insns.last
        if (last == null || !isTerminator(last)) appendDefaultReturn(insns, m.desc)
    }

    private fun appendDefaultReturn(insns: InsnList, methodDesc: String) {
        val ret = methodDesc.substringAfterLast(')')
        when (ret.firstOrNull() ?: 'V') {
            'V' -> insns.add(InsnNode(Opcodes.RETURN))
            'I', 'B', 'C', 'S', 'Z' -> {
                insns.add(InsnNode(Opcodes.ICONST_0)); insns.add(InsnNode(Opcodes.IRETURN))
            }
            'J' -> { insns.add(InsnNode(Opcodes.LCONST_0)); insns.add(InsnNode(Opcodes.LRETURN)) }
            'F' -> { insns.add(InsnNode(Opcodes.FCONST_0)); insns.add(InsnNode(Opcodes.FRETURN)) }
            'D' -> { insns.add(InsnNode(Opcodes.DCONST_0)); insns.add(InsnNode(Opcodes.DRETURN)) }
            else -> { insns.add(InsnNode(Opcodes.ACONST_NULL)); insns.add(InsnNode(Opcodes.ARETURN)) }
        }
    }

    private fun isTerminator(insn: AbstractInsnNode): Boolean = when (insn.opcode) {
        Opcodes.IRETURN, Opcodes.LRETURN, Opcodes.FRETURN, Opcodes.DRETURN,
        Opcodes.ARETURN, Opcodes.RETURN, Opcodes.ATHROW,
        Opcodes.GOTO, Opcodes.TABLESWITCH, Opcodes.LOOKUPSWITCH, Opcodes.RET -> true
        else -> false
    }

    private fun isUnconditionalTerminator(insn: AbstractInsnNode): Boolean = isTerminator(insn)

    private fun popsOf(insn: AbstractInsnNode): Int = when (val op = insn.opcode) {
        // ----- 0 pops -----
        Opcodes.NOP,
        Opcodes.ACONST_NULL,
        Opcodes.ICONST_M1, Opcodes.ICONST_0, Opcodes.ICONST_1, Opcodes.ICONST_2,
        Opcodes.ICONST_3, Opcodes.ICONST_4, Opcodes.ICONST_5,
        Opcodes.LCONST_0, Opcodes.LCONST_1,
        Opcodes.FCONST_0, Opcodes.FCONST_1, Opcodes.FCONST_2,
        Opcodes.DCONST_0, Opcodes.DCONST_1,
        Opcodes.BIPUSH, Opcodes.SIPUSH, Opcodes.LDC,
        Opcodes.ILOAD, Opcodes.LLOAD, Opcodes.FLOAD, Opcodes.DLOAD, Opcodes.ALOAD,
        Opcodes.GOTO, Opcodes.JSR, Opcodes.RET,
        Opcodes.IINC, Opcodes.NEW,
        Opcodes.RETURN -> 0

        // ----- 1 pop -----
        Opcodes.ISTORE, Opcodes.FSTORE, Opcodes.ASTORE,
        Opcodes.POP,
        Opcodes.INEG, Opcodes.FNEG,
        Opcodes.I2L, Opcodes.I2F, Opcodes.I2D, Opcodes.F2I, Opcodes.F2L, Opcodes.F2D,
        Opcodes.I2B, Opcodes.I2C, Opcodes.I2S,
        Opcodes.IFEQ, Opcodes.IFNE, Opcodes.IFLT, Opcodes.IFGE, Opcodes.IFGT, Opcodes.IFLE,
        Opcodes.IFNULL, Opcodes.IFNONNULL,
        Opcodes.TABLESWITCH, Opcodes.LOOKUPSWITCH,
        Opcodes.IRETURN, Opcodes.FRETURN, Opcodes.ARETURN,
        Opcodes.ATHROW,
        Opcodes.NEWARRAY, Opcodes.ANEWARRAY, Opcodes.ARRAYLENGTH,
        Opcodes.CHECKCAST, Opcodes.INSTANCEOF,
        Opcodes.MONITORENTER, Opcodes.MONITOREXIT -> 1

        // ----- 2 pops -----
        Opcodes.LSTORE, Opcodes.DSTORE,
        Opcodes.POP2, Opcodes.SWAP,
        Opcodes.IADD, Opcodes.ISUB, Opcodes.IMUL, Opcodes.IDIV, Opcodes.IREM,
        Opcodes.FADD, Opcodes.FSUB, Opcodes.FMUL, Opcodes.FDIV, Opcodes.FREM,
        Opcodes.ISHL, Opcodes.ISHR, Opcodes.IUSHR,
        Opcodes.IAND, Opcodes.IOR, Opcodes.IXOR,
        Opcodes.LNEG, Opcodes.DNEG,
        Opcodes.L2I, Opcodes.L2F, Opcodes.L2D, Opcodes.D2I, Opcodes.D2L, Opcodes.D2F,
        Opcodes.FCMPL, Opcodes.FCMPG,
        Opcodes.IF_ICMPEQ, Opcodes.IF_ICMPNE, Opcodes.IF_ICMPLT, Opcodes.IF_ICMPGE,
        Opcodes.IF_ICMPGT, Opcodes.IF_ICMPLE, Opcodes.IF_ACMPEQ, Opcodes.IF_ACMPNE,
        Opcodes.IALOAD, Opcodes.FALOAD, Opcodes.AALOAD,
        Opcodes.BALOAD, Opcodes.CALOAD, Opcodes.SALOAD,
        Opcodes.LRETURN, Opcodes.DRETURN,
        Opcodes.LALOAD, Opcodes.DALOAD -> 2

        // ----- 3 pops -----
        Opcodes.LADD, Opcodes.LSUB, Opcodes.LMUL, Opcodes.LDIV, Opcodes.LREM,
        Opcodes.LSHL, Opcodes.LSHR, Opcodes.LUSHR,
        Opcodes.IASTORE, Opcodes.FASTORE, Opcodes.AASTORE,
        Opcodes.BASTORE, Opcodes.CASTORE, Opcodes.SASTORE -> 3

        // ----- 4 pops -----
        Opcodes.DADD, Opcodes.DSUB, Opcodes.DMUL, Opcodes.DDIV, Opcodes.DREM,
        Opcodes.LAND, Opcodes.LOR, Opcodes.LXOR,
        Opcodes.LCMP, Opcodes.DCMPL, Opcodes.DCMPG,
        Opcodes.LASTORE, Opcodes.DASTORE -> 4

        // ----- DUP family -----
        Opcodes.DUP -> 1
        Opcodes.DUP_X1 -> 2
        Opcodes.DUP_X2 -> 3
        Opcodes.DUP2 -> 2
        Opcodes.DUP2_X1 -> 3
        Opcodes.DUP2_X2 -> 4

        // ----- variable based on descriptor -----
        Opcodes.GETSTATIC -> 0
        Opcodes.PUTSTATIC -> Type.getType((insn as FieldInsnNode).desc).size
        Opcodes.GETFIELD -> 1
        Opcodes.PUTFIELD -> 1 + Type.getType((insn as FieldInsnNode).desc).size

        Opcodes.INVOKEVIRTUAL, Opcodes.INVOKESPECIAL, Opcodes.INVOKEINTERFACE -> {
            val m = insn as MethodInsnNode
            (Type.getArgumentsAndReturnSizes(m.desc) ushr 2)  // includes implicit this
        }
        Opcodes.INVOKESTATIC -> {
            val m = insn as MethodInsnNode
            (Type.getArgumentsAndReturnSizes(m.desc) ushr 2) - 1
        }
        Opcodes.INVOKEDYNAMIC -> {
            val d = insn as InvokeDynamicInsnNode
            (Type.getArgumentsAndReturnSizes(d.desc) ushr 2) - 1
        }

        Opcodes.MULTIANEWARRAY -> (insn as MultiANewArrayInsnNode).dims

        else -> 0  // labels, line numbers, frame nodes, opcode == -1
    }

    private fun pushesOf(insn: AbstractInsnNode): Int = when (val op = insn.opcode) {
        // ----- 0 pushes (consumers / control-flow / store) -----
        Opcodes.NOP,
        Opcodes.ISTORE, Opcodes.LSTORE, Opcodes.FSTORE, Opcodes.DSTORE, Opcodes.ASTORE,
        Opcodes.POP, Opcodes.POP2,
        Opcodes.IINC,
        Opcodes.IFEQ, Opcodes.IFNE, Opcodes.IFLT, Opcodes.IFGE, Opcodes.IFGT, Opcodes.IFLE,
        Opcodes.IF_ICMPEQ, Opcodes.IF_ICMPNE, Opcodes.IF_ICMPLT, Opcodes.IF_ICMPGE,
        Opcodes.IF_ICMPGT, Opcodes.IF_ICMPLE, Opcodes.IF_ACMPEQ, Opcodes.IF_ACMPNE,
        Opcodes.IFNULL, Opcodes.IFNONNULL,
        Opcodes.GOTO, Opcodes.RET,
        Opcodes.TABLESWITCH, Opcodes.LOOKUPSWITCH,
        Opcodes.IRETURN, Opcodes.LRETURN, Opcodes.FRETURN, Opcodes.DRETURN, Opcodes.ARETURN,
        Opcodes.RETURN, Opcodes.ATHROW,
        Opcodes.MONITORENTER, Opcodes.MONITOREXIT,
        Opcodes.PUTSTATIC, Opcodes.PUTFIELD,
        Opcodes.IASTORE, Opcodes.LASTORE, Opcodes.FASTORE, Opcodes.DASTORE,
        Opcodes.AASTORE, Opcodes.BASTORE, Opcodes.CASTORE, Opcodes.SASTORE -> 0

        // ----- 1 push -----
        Opcodes.ACONST_NULL,
        Opcodes.ICONST_M1, Opcodes.ICONST_0, Opcodes.ICONST_1, Opcodes.ICONST_2,
        Opcodes.ICONST_3, Opcodes.ICONST_4, Opcodes.ICONST_5,
        Opcodes.FCONST_0, Opcodes.FCONST_1, Opcodes.FCONST_2,
        Opcodes.BIPUSH, Opcodes.SIPUSH,
        Opcodes.ILOAD, Opcodes.FLOAD, Opcodes.ALOAD,
        Opcodes.INEG, Opcodes.FNEG,
        Opcodes.I2F, Opcodes.F2I,
        Opcodes.I2B, Opcodes.I2C, Opcodes.I2S,
        Opcodes.IADD, Opcodes.ISUB, Opcodes.IMUL, Opcodes.IDIV, Opcodes.IREM,
        Opcodes.FADD, Opcodes.FSUB, Opcodes.FMUL, Opcodes.FDIV, Opcodes.FREM,
        Opcodes.ISHL, Opcodes.ISHR, Opcodes.IUSHR,
        Opcodes.IAND, Opcodes.IOR, Opcodes.IXOR,
        Opcodes.L2I, Opcodes.L2F, Opcodes.D2I, Opcodes.D2F,
        Opcodes.FCMPL, Opcodes.FCMPG, Opcodes.LCMP, Opcodes.DCMPL, Opcodes.DCMPG,
        Opcodes.IALOAD, Opcodes.FALOAD, Opcodes.AALOAD,
        Opcodes.BALOAD, Opcodes.CALOAD, Opcodes.SALOAD,
        Opcodes.NEW, Opcodes.NEWARRAY, Opcodes.ANEWARRAY,
        Opcodes.ARRAYLENGTH, Opcodes.CHECKCAST, Opcodes.INSTANCEOF,
        Opcodes.MULTIANEWARRAY -> 1

        // ----- 2 pushes -----
        Opcodes.LCONST_0, Opcodes.LCONST_1,
        Opcodes.DCONST_0, Opcodes.DCONST_1,
        Opcodes.LLOAD, Opcodes.DLOAD,
        Opcodes.LNEG, Opcodes.DNEG,
        Opcodes.I2L, Opcodes.I2D, Opcodes.F2L, Opcodes.F2D,
        Opcodes.L2D, Opcodes.D2L,
        Opcodes.LADD, Opcodes.LSUB, Opcodes.LMUL, Opcodes.LDIV, Opcodes.LREM,
        Opcodes.DADD, Opcodes.DSUB, Opcodes.DMUL, Opcodes.DDIV, Opcodes.DREM,
        Opcodes.LSHL, Opcodes.LSHR, Opcodes.LUSHR,
        Opcodes.LAND, Opcodes.LOR, Opcodes.LXOR,
        Opcodes.LALOAD, Opcodes.DALOAD -> 2

        // ----- DUP family -----
        Opcodes.DUP -> 2
        Opcodes.DUP_X1 -> 3
        Opcodes.DUP_X2 -> 4
        Opcodes.DUP2 -> 4
        Opcodes.DUP2_X1 -> 5
        Opcodes.DUP2_X2 -> 6
        Opcodes.SWAP -> 2
        Opcodes.JSR -> 1  // return-address

        // ----- LDC: 1 or 2 depending on constant type -----
        Opcodes.LDC -> {
            val v = (insn as LdcInsnNode).cst
            if (v is Long || v is Double) 2 else 1
        }

        // ----- variable based on descriptor -----
        Opcodes.GETSTATIC, Opcodes.GETFIELD ->
            Type.getType((insn as FieldInsnNode).desc).size

        Opcodes.INVOKEVIRTUAL, Opcodes.INVOKESPECIAL,
        Opcodes.INVOKEINTERFACE, Opcodes.INVOKESTATIC -> {
            val m = insn as MethodInsnNode
            Type.getArgumentsAndReturnSizes(m.desc) and 0x03
        }
        Opcodes.INVOKEDYNAMIC -> {
            val d = insn as InvokeDynamicInsnNode
            Type.getArgumentsAndReturnSizes(d.desc) and 0x03
        }

        else -> 0
    }
}
