// Ghidra headless script: read a j2c-dumper manifest.json, locate every
// obfuscated native method's fnAddr (already bound by binary-introspect),
// decompile each function via Ghidra's decompiler, and emit a single
// ghidra-dump.json that the ast-matcher pipeline can consume.
//
// Unlike DumpJ2CDecompiledFunctions (which scans for __ngen_* symbols and
// thus only works for native-obfuscator's standard JNI exports), this
// variant uses the explicit fnAddr list from manifest.json. That makes it
// work for j2cc-style binaries that have no standard JNI export names —
// all dispatch goes through a single shared initClass() function and
// per-class fnAddrs are recovered via the RegisterNatives table scan.
//
// Run (headless):
//   analyzeHeadless <PROJECT_DIR> <PROJECT_NAME> \
//        -import <natives.bin | .dll> \
//        -scriptPath <ghidra-scripts dir> \
//        -postScript DumpFromManifest.java <manifest.json> <ghidra-dump.json>
//
// Output schema is the same as DumpJ2CDecompiledFunctions: each function
// gets a {addr, name, code} record. `name` is set to the obfuscated-class
// internal name + method + descriptor so the consumer can route the
// recovered code straight to a (class, method, desc) tuple.
//
// @category j2c
// @author j2c-dumper

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DumpFromManifest extends GhidraScript {

    /** Per-target descriptor of (owner, name, desc, fnAddr) for decompile.
     *  Light DTO — we hand-parse from JSON since we can't pull a JSON
     *  library into a Ghidra script without bundling. */
    private static final class Target {
        final String owner;
        final String name;
        final String desc;
        final long   fnAddr;
        Target(String o, String n, String d, long a) {
            this.owner = o; this.name = n; this.desc = d; this.fnAddr = a;
        }
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("usage: DumpFromManifest <manifest.json> <ghidra-dump.json>");
            return;
        }
        Path manifest = Paths.get(args[0]);
        Path output = Paths.get(args[1]);
        Files.createDirectories(output.toAbsolutePath().getParent());

        List<Target> targets = readManifest(manifest);
        println("Manifest declares " + targets.size() + " obfuscated native methods with fnAddr.");

        Program program = currentProgram;
        DecompInterface dec = new DecompInterface();
        dec.openProgram(program);

        int decompiled = 0, skipped = 0;
        try (BufferedWriter w = Files.newBufferedWriter(output)) {
            w.write("{\"schemaVersion\":1,\"binary\":");
            w.write(jsonString(program.getExecutablePath()));
            w.write(",\"functions\":[\n");
            boolean first = true;
            Set<Long> seenAddrs = new HashSet<>();
            for (Target t : targets) {
                if (monitor.isCancelled()) break;
                if (!seenAddrs.add(t.fnAddr)) {
                    // Multiple methods may resolve to the same fn (unlikely but
                    // possible for trampolines). Keep one entry; the ast-matcher
                    // can replicate downstream if needed.
                    skipped++;
                    continue;
                }
                Address addr = program.getAddressFactory().getDefaultAddressSpace()
                                      .getAddress(t.fnAddr);
                Function f = getFunctionAt(addr);
                if (f == null) f = getFunctionContaining(addr);
                if (f == null) {
                    // Force-create at the given address — binary-introspect's
                    // RegisterNatives scan said this is a function entry.
                    f = createFunction(addr, mangleName(t));
                    if (f == null) {
                        println("WARN: no function at " + addr + " for " + t.owner + "." + t.name + t.desc);
                        skipped++;
                        continue;
                    }
                }
                DecompileResults res = dec.decompileFunction(f, 90, monitor);
                if (res == null || !res.decompileCompleted()) {
                    println("WARN: decompile failed at " + addr + " for " + t.owner + "." + t.name + t.desc);
                    skipped++;
                    continue;
                }
                String code = res.getDecompiledFunction().getC();
                if (code == null) {
                    skipped++;
                    continue;
                }
                if (!first) w.write(",\n");
                first = false;
                w.write("{\"addr\":\"0x" + Long.toHexString(t.fnAddr) + "\"");
                w.write(",\"owner\":" + jsonString(t.owner));
                w.write(",\"methodName\":" + jsonString(t.name));
                w.write(",\"methodDesc\":" + jsonString(t.desc));
                // Keep the legacy `name` field too so older consumers still work.
                w.write(",\"name\":" + jsonString(mangleName(t)));
                w.write(",\"code\":" + jsonString(code) + "}");
                decompiled++;
            }
            w.write("\n]}\n");
        }
        dec.dispose();
        println("Decompiled " + decompiled + " function(s); skipped " + skipped + ".");
        println("Wrote " + output);
    }

    /** Synthesize a unique-ish name for the decompiled function, useful
     *  when the binary has no symbol for this address. */
    private static String mangleName(Target t) {
        return "__j2c_native_" + t.owner.replace('/', '_') + "_" + t.name;
    }

    /** Minimal hand-parser for the slice of manifest.json we care about:
     *  walks `classes[]` → `methods[]`, collecting entries whose
     *  isObfuscatedNative=true and fnAddr is present. */
    private static List<Target> readManifest(Path path) throws Exception {
        StringBuilder buf = new StringBuilder();
        try (BufferedReader r = Files.newBufferedReader(path)) {
            String line;
            while ((line = r.readLine()) != null) buf.append(line).append('\n');
        }
        String src = buf.toString();
        // Match `{ ... isObfuscatedNative ... }` objects inside the JSON.
        // This is intentionally over-permissive — we only need the four
        // fields we care about. JSON is well-formed by construction
        // (produced by Python json.dumps), so regex is safe.
        Pattern method = Pattern.compile(
            "\\{[^{}]*?\"name\"\\s*:\\s*\"([^\"]+)\"[^{}]*?" +
            "\"desc\"\\s*:\\s*\"([^\"]+)\"[^{}]*?" +
            "\"isObfuscatedNative\"\\s*:\\s*true[^{}]*?" +
            "\"fnAddr\"\\s*:\\s*\"(0x[0-9a-fA-F]+)\"[^{}]*?\\}",
            Pattern.DOTALL
        );
        // We need each method's owner (the enclosing class). Easier: walk
        // class-by-class. Split on top-level "name" keys in the classes array.
        // Trick: find each `"name": "owner-internal-name"` that's followed by
        // ANY content up to a `"methods":[ ... ]` array. Use a per-class scan.
        Pattern classBlock = Pattern.compile(
            "\"name\"\\s*:\\s*\"([A-Za-z0-9_\\$/]+)\"\\s*,\\s*" +
            "(?:\"superName\"|\"interfaces\"|\"version\"|\"access\")",
            Pattern.DOTALL
        );
        // For each class header, the methods array starts after its
        // `"methods": [`. We find each header position, then search the
        // next method array for matches.
        List<int[]> classRanges = new ArrayList<>();
        Matcher cm = classBlock.matcher(src);
        while (cm.find()) {
            int classNameEnd = cm.end(1);
            String owner = cm.group(1);
            // Find the methods array start
            int mIdx = src.indexOf("\"methods\"", classNameEnd);
            if (mIdx < 0) continue;
            int arrStart = src.indexOf('[', mIdx);
            if (arrStart < 0) continue;
            int arrEnd = matchingBracket(src, arrStart, '[', ']');
            if (arrEnd < 0) continue;
            classRanges.add(new int[]{arrStart, arrEnd, owner.hashCode()});
            classRanges.set(classRanges.size() - 1, new int[]{arrStart, arrEnd, classRanges.size() - 1});
            classRanges.get(classRanges.size() - 1)[2] = classRanges.size() - 1;
            // Save the owner separately
            ownersByIdx.add(owner);
        }
        List<Target> targets = new ArrayList<>();
        for (int i = 0; i < classRanges.size(); i++) {
            int[] r = classRanges.get(i);
            String owner = ownersByIdx.get(i);
            String slice = src.substring(r[0], r[1] + 1);
            Matcher mm = method.matcher(slice);
            while (mm.find()) {
                String name = mm.group(1);
                String desc = mm.group(2);
                long addr = Long.parseUnsignedLong(mm.group(3).substring(2), 16);
                targets.add(new Target(owner, name, desc, addr));
            }
        }
        return targets;
    }

    private static int matchingBracket(String s, int start, char open, char close) {
        int depth = 0;
        boolean inString = false;
        boolean escape = false;
        for (int i = start; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inString) {
                if (escape) { escape = false; }
                else if (c == '\\') { escape = true; }
                else if (c == '"') { inString = false; }
                continue;
            }
            if (c == '"') { inString = true; continue; }
            if (c == open) depth++;
            else if (c == close) {
                depth--;
                if (depth == 0) return i;
            }
        }
        return -1;
    }

    private static final List<String> ownersByIdx = new ArrayList<>();

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
