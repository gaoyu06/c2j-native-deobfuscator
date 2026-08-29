package j2c.desktop

/**
 * Works out the next CLI step for a session, based only on which
 * artifacts exist. The viewer shows this text; it never runs it. The
 * commands mirror `j2c-dumper`'s subcommands (see py/j2c_dumper_cli).
 */
object NextCommandPlanner {

    fun plan(
        hasClasses: Boolean,
        hasBinary: Boolean,
        hasManifest: Boolean,
        recoveredCount: Int,
        stubCount: Int,
        hasTrace: Boolean,
    ): NextCommand? {
        if (!hasClasses) {
            return NextCommand(
                "No classes.json yet — start by parsing the jar.",
                "j2c-dumper parse-jar <input.jar> -o classes.json",
            )
        }
        if (!hasBinary) {
            return NextCommand(
                "classes.json is here but the native library hasn't been read.",
                "j2c-dumper inspect-binary <native.dll|.so> -o binary.json",
            )
        }
        if (!hasManifest) {
            return NextCommand(
                "Merge the class and binary facts into a manifest.",
                "j2c-dumper merge-manifest classes.json binary.json -o manifest.json",
            )
        }
        if (recoveredCount == 0) {
            return if (!hasTrace) {
                NextCommand(
                    "Manifest is ready but nothing is recovered. Capture a run.",
                    "j2c-dumper dynamic-trace --run \"java -jar <input.jar>\" -o trace.jsonl",
                )
            } else {
                NextCommand(
                    "A trace exists — lift it into recovered method bodies.",
                    "j2c-dumper trace-to-bc trace.jsonl --manifest manifest.json -o recovered/",
                )
            }
        }
        if (stubCount > 0) {
            return NextCommand(
                "$stubCount method(s) still need bodies. First capture more of the run — " +
                    "j2c-dumper dynamic-trace, a startup -agentpath launch, or the one-shot " +
                    "j2c-dumper recover — then rebuild. inspect-binary and merge-manifest are " +
                    "already done, so what's left is binding gaps to close offline, with a " +
                    "Ghidra static-reverse lift only as an optional last resort.",
                "j2c-dumper rebuild --input <input.jar> --recovered recovered/ --manifest manifest.json -o out.jar",
            )
        }
        return NextCommand(
            "Every native method has a body. Rebuild the clean jar.",
            "j2c-dumper rebuild --input <input.jar> --recovered recovered/ --manifest manifest.json -o out.jar",
        )
    }
}
