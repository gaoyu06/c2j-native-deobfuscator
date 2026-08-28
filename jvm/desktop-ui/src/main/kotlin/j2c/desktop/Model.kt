package j2c.desktop

import java.nio.file.Path

/** Identifies one method by its owning class, name and JVM descriptor. */
data class MethodRef(val owner: String, val name: String, val desc: String)

/** Where a method stands in the recovery pipeline. */
enum class RecoveryStatus(val label: String) {
    /** A recovered body (recovered/ JSON) exists for this method. */
    RECOVERED("recovered"),

    /** Needs recovery, native address is known, but no body yet — the
     *  rebuilder would leave a stub here. */
    STUB("stub"),

    /** Needs recovery but we can't place it: no native address and no
     *  recovered body. Also used for a recovered body whose method is
     *  absent from the class/manifest listing. */
    MISSING("missing"),
}

/** One line in the method table. */
data class MethodRow(
    val ref: MethodRef,
    /** Native function address (hex VA) when known, else null. */
    val nativeAddress: String?,
    val status: RecoveryStatus,
    /** True when the source treats this as an obfuscated native method. */
    val needsRecovery: Boolean,
    /** Recovered body, when one was found. */
    val recovered: RecoveredArtifact?,
) {
    /** Class name in dotted form for display (com.example.Foo). */
    val displayClass: String get() = ref.owner.replace('/', '.')
}

/** A recovered method body plus the file it came from. */
data class RecoveredArtifact(
    val ref: MethodRef,
    val file: Path,
    val source: String?,
    val confidence: String?,
    val instructionCount: Int,
    /** Raw JSON text of the artifact, kept for the detail view. */
    val rawJson: String,
    /** A readable listing of the instructions. */
    val listing: String,
)

/** One pipeline artifact and whether the session directory has it. */
data class ArtifactState(
    val id: String,
    val fileName: String,
    val present: Boolean,
    /** Short human note, e.g. "27 classes" or "not found". */
    val detail: String,
)

/**
 * How a trace line should be read at a glance. The live-attach path writes
 * lifecycle, capability and gap records alongside ordinary trace events; the
 * viewer keeps them honest instead of flattening them into "just events".
 */
enum class TraceKind {
    /** enter / exit / jni / slot — ordinary instrumentation output. */
    NORMAL,

    /** A native-method-bind record (fn pointer -> Java method). */
    BIND,

    /** A JVMTI capability that was granted in this phase. */
    CAPABILITY_OK,

    /** A JVMTI capability the phase could not grant — coverage is reduced. */
    CAPABILITY_UNAVAILABLE,

    /** A gap record: the agent stating, plainly, what it could not observe. */
    GAP,

    /** agent-attached / agent-loaded lifecycle marker. */
    LIFECYCLE,

    /** A line that could not be parsed as JSON. */
    MALFORMED,
}

/** A single trace.jsonl line, kept light for the event list. */
data class TraceEvent(
    val index: Int,
    val ev: String,
    val thread: String,
    val summary: String,
    val kind: TraceKind = TraceKind.NORMAL,
)

/** Everything the viewer knows about one opened session directory. */
data class Session(
    val dir: Path,
    val artifacts: List<ArtifactState>,
    val methods: List<MethodRow>,
    val traceEvents: List<TraceEvent>,
    val nextCommand: NextCommand?,
    /** Non-fatal problems hit while reading the folder. */
    val notes: List<String>,
) {
    val hasAnyArtifact: Boolean get() = artifacts.any { it.present }

    val counts: Map<RecoveryStatus, Int>
        get() = RecoveryStatus.entries.associateWith { s -> methods.count { it.status == s } }
}

/** A suggested next CLI step, never run from the GUI — only shown. */
data class NextCommand(
    val reason: String,
    val command: String,
)

/**
 * The inputs a user fills in on the attach form. These map one-to-one to the
 * flags of the `attach` CLI subcommand; the GUI never invents its own attach
 * mechanism, it only assembles (and optionally runs) that command.
 */
data class AttachRequest(
    val pid: String,
    val output: String,
    /** Mirrors the required `--i-own-this-process` confirmation flag. */
    val iOwnThisProcess: Boolean,
    val logAll: Boolean = false,
    /** auto | jcmd | vm — mirrors `--mechanism`. */
    val mechanism: String = "auto",
    /** Optional `--agent` override; blank means the CLI's default. */
    val agentPath: String = "",
)
