// Ghidra headless script: decompile every plausible __ngen_* function in a j2c-style
// binary and emit a JSON file with the pseudo-C source for downstream tree-sitter
// matching.
//
// Run (headless):
//   <GHIDRA_HOME>/support/analyzeHeadless <PROJECT_DIR> <PROJECT_NAME> \
//        -import <input.dll> \
//        -postScript DumpJ2CDecompiledFunctions.java <OUTPUT.json>
//
// The output JSON has the shape:
//   {
//     "schemaVersion": 1,
//     "binary": "<path>",
//     "functions": [
//       { "addr": "0x180001234", "name": "__ngen_Foo_bar", "code": "void __ngen_..." },
//       ...
//     ]
//   }
//
// @category j2c
// @author j2c-dumper

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class DumpJ2CDecompiledFunctions extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("usage: DumpJ2CDecompiledFunctions <output.json>");
            return;
        }
        Path output = Paths.get(args[0]);
        Files.createDirectories(output.toAbsolutePath().getParent());

        Program program = currentProgram;
        DecompInterface dec = new DecompInterface();
        dec.openProgram(program);

        try (BufferedWriter w = Files.newBufferedWriter(output)) {
            w.write("{\"schemaVersion\":1,\"binary\":");
            w.write(jsonString(program.getExecutablePath()));
            w.write(",\"functions\":[\n");

            FunctionIterator fi = program.getFunctionManager().getFunctions(true);
            boolean first = true;
            while (fi.hasNext()) {
                if (monitor.isCancelled()) break;
                Function f = fi.next();
                String name = f.getName();
                // Heuristic: pick __ngen_* functions and a few helpers we care
                // about. Users can post-filter; keeping a broad net.
                if (!isInteresting(name)) continue;

                DecompileResults res = dec.decompileFunction(f, 60, monitor);
                if (res == null || !res.decompileCompleted()) continue;
                String code = res.getDecompiledFunction().getC();
                if (code == null) continue;

                if (!first) w.write(",\n");
                first = false;
                Address addr = f.getEntryPoint();
                w.write("{\"addr\":\"0x" + Long.toHexString(addr.getOffset()) + "\"");
                w.write(",\"name\":" + jsonString(name));
                w.write(",\"code\":" + jsonString(code) + "}");
            }
            w.write("\n]}\n");
        }
        dec.dispose();
        println("Wrote " + output);
    }

    private static boolean isInteresting(String name) {
        if (name == null) return false;
        // Accept all functions; the AST matcher decides what to lift.
        // Skip a few known C-runtime helpers to keep the dump trim.
        if (name.startsWith("_") && name.length() > 4 && Character.isLowerCase(name.charAt(1))) {
            return false; // libc internals (_aligned_*, _initterm, _errno, etc.)
        }
        if (name.startsWith("Rtl") || name.startsWith("__")) return false;
        return true;
    }

    private static String jsonString(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder(s.length() + 2);
        b.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': b.append("\\\\"); break;
                case '"':  b.append("\\\""); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        b.append('"');
        return b.toString();
    }
}
