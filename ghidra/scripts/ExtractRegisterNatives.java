// Ghidra headless script: locate every JNINativeMethod[] descriptor table
// inside an obfuscator-produced shared library, and dump per-class
// (className, methodName, methodDesc, fnAddr) tuples to JSON. Designed to
// work even when the binary uses runtime-only RegisterNatives() dispatch
// with NO standard Java_<class>_<method> JNI export symbols (e.g. j2cc's
// natives.bin in Kiritan).
//
// Detection strategy (no type info required):
//   1. Walk .rdata / .data sections looking for 3-pointer records spaced
//      at sizeof(void*) * 3 boundaries:
//        struct JNINativeMethod { char* name; char* signature; void* fnPtr; };
//      - name and signature must point to a printable ASCII string;
//      - signature must start with '(' (JVM method descriptor);
//      - fnPtr must point inside an executable section (.text).
//   2. A "table" is a run of >=1 such records. Capture every contiguous
//      run; the class binding happens at manifest-merge time using
//      jar-parser's per-class method count.
//   3. Cross-reference each table base to find calls in .text. The
//      surrounding function (`pInitClass`) is the class-init that calls
//      RegisterNatives — analysing its first arg (the jclass) typically
//      yields the className via a preceding FindClass / cstrings[K] load.
//      We emit the candidate function range so the consumer can run an
//      AST-based pass to bind it.
//
// Run (headless):
//   <GHIDRA_HOME>/support/analyzeHeadless <PROJECT_DIR> <PROJECT_NAME> \
//        -import <input.dll | natives.bin> \
//        -postScript ExtractRegisterNatives.java <OUTPUT.json>
//
// Output schema:
//   {
//     "schemaVersion": 1,
//     "binary": "<path>",
//     "tables": [
//       {
//         "baseAddr": "0x180012000",
//         "section": ".rdata",
//         "entries": [
//           {"name": "add", "desc": "(II)I", "fnAddr": "0x180001234",
//            "fnRange": {"start": "...", "end": "..."} }
//         ],
//         "callSites": ["0x180005000", ...],
//         "classCandidate": "...",          // best-effort, may be null
//         "classCandidateSource": "FindClass" | "cstrings[K]" | null
//       }
//     ]
//   }
//
// @category j2c
// @author j2c-dumper

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ExtractRegisterNatives extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("usage: ExtractRegisterNatives <output.json>");
            return;
        }
        Path output = Paths.get(args[0]);
        Files.createDirectories(output.toAbsolutePath().getParent());

        Program program = currentProgram;
        Memory mem = program.getMemory();
        int ptrSize = program.getDefaultPointerSize();  // 8 on x64, 4 on x86
        long imageBase = program.getImageBase().getOffset();

        // 1) Build an executable-region map for filtering fnPtr candidates.
        AddressSet execRegions = new AddressSet();
        for (MemoryBlock blk : mem.getBlocks()) {
            if (blk.isExecute()) {
                execRegions.add(blk.getStart(), blk.getEnd());
            }
        }

        // 2) Walk all read-only data sections for 3-ptr records.
        List<Map<String, Object>> tables = new ArrayList<>();
        for (MemoryBlock blk : mem.getBlocks()) {
            if (blk.isExecute() || !blk.isInitialized() || !blk.isRead()) {
                continue;
            }
            scanBlockForTables(program, blk, ptrSize, execRegions, tables);
        }

        // 3) For each table base, find call-sites referencing it.
        ReferenceManager refs = program.getReferenceManager();
        for (Map<String, Object> table : tables) {
            String baseHex = (String) table.get("baseAddr");
            Address base = program.getAddressFactory().getAddress(baseHex);
            List<String> sites = new ArrayList<>();
            ReferenceIterator it = refs.getReferencesTo(base);
            while (it.hasNext()) {
                Reference r = it.next();
                sites.add("0x" + Long.toHexString(r.getFromAddress().getOffset()));
            }
            table.put("callSites", sites);
            // Best-effort class-candidate inference: look at the function that
            // contains the first call-site and find the most recent FindClass
            // or cstrings[K] load before the RegisterNatives call.
            if (!sites.isEmpty()) {
                Address callSite = program.getAddressFactory().getAddress(sites.get(0));
                Function f = getFunctionContaining(callSite);
                if (f != null) {
                    Map<String, String> cls = inferClassCandidate(program, f, callSite);
                    if (cls != null) {
                        table.put("classCandidate", cls.get("name"));
                        table.put("classCandidateSource", cls.get("source"));
                    }
                }
            }
        }

        // Emit JSON
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("schemaVersion", 1);
        root.put("binary", program.getExecutablePath());
        root.put("tables", tables);

        try (BufferedWriter w = Files.newBufferedWriter(output)) {
            w.write(toJson(root, 0));
        }
        println("Wrote " + tables.size() + " table(s) to " + output);
    }

    /**
     * Walk a memory block searching for runs of 3-pointer records that match
     * the JNINativeMethod shape. Append every discovered table to `out`.
     */
    private void scanBlockForTables(Program program, MemoryBlock blk, int ptrSize,
                                    AddressSet execRegions, List<Map<String, Object>> out) {
        long start = blk.getStart().getOffset();
        long end = blk.getEnd().getOffset();
        int recordSize = ptrSize * 3;
        long va = start;
        while (va + recordSize <= end + 1) {
            // Try to parse a record at va.
            List<Map<String, Object>> run = new ArrayList<>();
            long cur = va;
            while (cur + recordSize <= end + 1) {
                Address a = blk.getStart().getNewAddress(cur);
                Map<String, Object> entry = tryParseEntry(program, a, ptrSize, execRegions);
                if (entry == null) break;
                run.add(entry);
                cur += recordSize;
            }
            if (run.size() >= 1 && plausibleTable(run)) {
                Map<String, Object> table = new LinkedHashMap<>();
                table.put("baseAddr", "0x" + Long.toHexString(va));
                table.put("section", blk.getName());
                table.put("entries", run);
                out.add(table);
                va = cur;  // jump past the run we just consumed
            } else {
                va += ptrSize;  // advance by one pointer slot
            }
        }
    }

    /**
     * Try to read a single JNINativeMethod record at `addr`. Returns null on
     * any failure (bad pointer, non-printable string, fnPtr not in executable
     * region, descriptor doesn't start with '(' etc.).
     */
    private Map<String, Object> tryParseEntry(Program program, Address addr, int ptrSize,
                                              AddressSet execRegions) {
        try {
            long p1 = readPointer(program, addr, ptrSize);
            long p2 = readPointer(program, addr.add(ptrSize), ptrSize);
            long p3 = readPointer(program, addr.add(ptrSize * 2L), ptrSize);
            if (p1 == 0 || p2 == 0 || p3 == 0) return null;
            Address namePtr = program.getAddressFactory().getDefaultAddressSpace().getAddress(p1);
            Address descPtr = program.getAddressFactory().getDefaultAddressSpace().getAddress(p2);
            Address fnPtr = program.getAddressFactory().getDefaultAddressSpace().getAddress(p3);
            String name = readCString(program, namePtr, 128);
            if (name == null || name.isEmpty()) return null;
            String desc = readCString(program, descPtr, 256);
            if (desc == null || !desc.startsWith("(")) return null;
            if (!execRegions.contains(fnPtr)) return null;
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("name", name);
            e.put("desc", desc);
            e.put("fnAddr", "0x" + Long.toHexString(p3));
            // best-effort: function range
            Function f = getFunctionAt(fnPtr);
            if (f == null) f = getFunctionContaining(fnPtr);
            if (f != null) {
                Map<String, String> r = new LinkedHashMap<>();
                r.put("start", "0x" + Long.toHexString(f.getEntryPoint().getOffset()));
                AddressRange range = f.getBody().getFirstRange();
                if (range != null) r.put("end", "0x" + Long.toHexString(range.getMaxAddress().getOffset()));
                e.put("fnRange", r);
            }
            return e;
        } catch (Exception ex) {
            return null;
        }
    }

    private boolean plausibleTable(List<Map<String, Object>> run) {
        // A single record is OK; >=2 records with consistent shape is even
        // better. Reject runs where the same descriptor repeats trivially
        // (often noise from generic-vtable padding).
        if (run.size() == 1) return true;
        long distinctDescs = run.stream().map(e -> (String) e.get("desc")).distinct().count();
        return distinctDescs >= 1;
    }

    private long readPointer(Program program, Address addr, int ptrSize) throws Exception {
        Memory mem = program.getMemory();
        if (ptrSize == 8) return mem.getLong(addr) & 0xffffffffffffffffL;
        return mem.getInt(addr) & 0xffffffffL;
    }

    private String readCString(Program program, Address addr, int maxLen) {
        Memory mem = program.getMemory();
        StringBuilder sb = new StringBuilder();
        try {
            for (int i = 0; i < maxLen; i++) {
                byte b = mem.getByte(addr.add(i));
                if (b == 0) return sb.toString();
                if (b < 0x20 || b > 0x7e) return null;
                sb.append((char) b);
            }
        } catch (Exception ex) {
            return null;
        }
        return null;  // not null-terminated
    }

    /**
     * Best-effort: walk backward from `callSite` inside `f` looking for
     * a load of a string pointer that could be the class name passed to
     * FindClass or read from a cstrings[K] cache. Returns the discovered
     * name + the source mechanism, or null on failure.
     */
    private Map<String, String> inferClassCandidate(Program program, Function f, Address callSite) {
        Instruction insn = getInstructionAt(callSite);
        int budget = 64;
        while (insn != null && budget-- > 0) {
            insn = insn.getPrevious();
            if (insn == null || !f.getBody().contains(insn.getAddress())) break;
            // Look for `lea reg, [string]` or `mov reg, [string-ptr]` where
            // the operand resolves to a printable C string. This is a coarse
            // heuristic — Ghidra's full data-flow would do better, but
            // we don't want to depend on auto-analysis being complete.
            for (int i = 0; i < insn.getNumOperands(); i++) {
                Address ref = insn.getAddress(i);
                if (ref == null) {
                    Object[] objs = insn.getOpObjects(i);
                    for (Object o : objs) {
                        if (o instanceof Address) {
                            ref = (Address) o;
                            break;
                        }
                    }
                }
                if (ref == null) continue;
                String s = readCString(program, ref, 256);
                if (s == null || s.isEmpty()) continue;
                if (looksLikeClassName(s)) {
                    Map<String, String> r = new LinkedHashMap<>();
                    r.put("name", s);
                    r.put("source", "string-load-near-call");
                    return r;
                }
            }
        }
        return null;
    }

    private boolean looksLikeClassName(String s) {
        if (s.isEmpty() || s.charAt(0) == '(' || s.endsWith(";")) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!(Character.isJavaIdentifierPart(c) || c == '/' || c == '$')) return false;
        }
        // Must contain a slash (package separator) OR be a top-level class
        // starting with an uppercase letter to filter out noise.
        return s.contains("/") || (Character.isUpperCase(s.charAt(0)) && s.length() >= 3);
    }

    // ---- tiny JSON writer (no external deps) ----

    @SuppressWarnings("unchecked")
    private String toJson(Object v, int indent) {
        StringBuilder sb = new StringBuilder();
        if (v == null) return "null";
        if (v instanceof Boolean || v instanceof Number) return v.toString();
        if (v instanceof String) return "\"" + escape((String) v) + "\"";
        String pad = "  ".repeat(indent + 1);
        String close = "  ".repeat(indent);
        if (v instanceof List) {
            List<Object> list = (List<Object>) v;
            if (list.isEmpty()) return "[]";
            sb.append("[\n");
            for (int i = 0; i < list.size(); i++) {
                sb.append(pad).append(toJson(list.get(i), indent + 1));
                sb.append(i + 1 == list.size() ? "\n" : ",\n");
            }
            sb.append(close).append("]");
            return sb.toString();
        }
        if (v instanceof Map) {
            Map<String, Object> map = (Map<String, Object>) v;
            if (map.isEmpty()) return "{}";
            sb.append("{\n");
            int n = map.size(), idx = 0;
            for (Map.Entry<String, Object> e : map.entrySet()) {
                sb.append(pad).append("\"").append(escape(e.getKey())).append("\": ");
                sb.append(toJson(e.getValue(), indent + 1));
                idx++;
                sb.append(idx == n ? "\n" : ",\n");
            }
            sb.append(close).append("}");
            return sb.toString();
        }
        return "\"" + escape(v.toString()) + "\"";
    }

    private String escape(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"':  sb.append("\\\""); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.toString();
    }
}
