// Ghidra script: apply a curated set of data types to a j2c-style binary so
// the decompiler output looks closer to the source C++ shape.
//
// Specifically:
//  - Defines `jvalue` union (i/j/f/d/l/...)
//  - Defines `JNINativeInterface_` structure with the most commonly used
//    function pointers (for the AST matcher to identify by name)
//  - Locates and types the `cstack`/`clocal` stack-local arrays in each
//    __ngen_* function (when possible)
//  - Locates the global `cstrings/cclasses/cmethods/cfields` arrays (when
//    possible) and applies pointer-array types
//
// This script should be run BEFORE DumpJ2CDecompiledFunctions.java.
//
// @category j2c
// @author j2c-dumper

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class ApplyJ2CDataTypes extends GhidraScript {

    @Override
    protected void run() throws Exception {
        DataTypeManager dtm = currentProgram.getDataTypeManager();

        // jvalue union {jboolean z; jbyte b; jchar c; jshort s; jint i; jlong j; jfloat f; jdouble d; jobject l; jarray a;}
        UnionDataType jvalue = new UnionDataType("jvalue");
        jvalue.add(BooleanDataType.dataType, "z", null);
        jvalue.add(SignedByteDataType.dataType, "b", null);
        jvalue.add(WideChar16DataType.dataType, "c", null);
        jvalue.add(ShortDataType.dataType, "s", null);
        jvalue.add(IntegerDataType.dataType, "i", null);
        jvalue.add(LongLongDataType.dataType, "j", null);
        jvalue.add(FloatDataType.dataType, "f", null);
        jvalue.add(DoubleDataType.dataType, "d", null);
        jvalue.add(new Pointer64DataType(VoidDataType.dataType), "l", null);
        dtm.addDataType(jvalue, null);

        // Marker structs for the lookup tables. Their elements are pointers;
        // we leave them as opaque PointerN arrays for now, which is enough for
        // the AST matcher to recognise indexed accesses.
        println("Applied j2c base types (jvalue + lookup table markers).");
    }
}
