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

/** One native method the introspection could not bind to a call site. */
data class BindingGap(
    val kind: String,
    val detail: String,
) {
    /** A single-line form for the compact strip. */
    val line: String get() = if (detail.isBlank()) kind else "$kind — $detail"
}

/**
 * The compact analysis facts from `binary.json` worth surfacing beyond raw
 * counts: the container format, target arch, the obfuscator profile and
 * method-discovery strategy the pass used, and any binding gaps (native methods
 * introspection could not place). Fields it did not find read as null and are
 * simply omitted from the strip, so this works against older `binary.json`
 * files that only carry the counts.
 */
data class BinaryAnalysis(
    val format: String?,
    val arch: String?,
    val profile: String?,
    val methodDiscovery: String?,
    val nativeClassCount: Int,
    val stringCount: Int,
    val bindingGaps: List<BindingGap>,
) {
    val hasBindingGaps: Boolean get() = bindingGaps.isNotEmpty()
}

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
    /** Parsed facts from binary.json, when the session has one. */
    val binaryAnalysis: BinaryAnalysis? = null,
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
 * A stable reason code for a live attach that will not — or did not — happen.
 * The codes mirror the ones the `attach` CLI prints
 * (`attach failed (reason=<code>): …`); the one-line [meaning] is the viewer's
 * own concise gloss, not the CLI's message text. The honest remedy is the
 * same for every case: restart the target under startup instrumentation.
 */
enum class AttachRefusalCode(val code: String, val meaning: String) {
    ATTACH_DISABLED(
        "attach-disabled",
        "the target's JVM attach handshake is off (-XX:+DisableAttachMechanism); no agent can be loaded",
    ),
    DYNAMIC_AGENT_DISABLED(
        "dynamic-agent-disabled",
        "the target forbids loading an agent into the live process (-XX:-EnableDynamicAgentLoading)",
    ),
    CROSS_USER(
        "cross-user",
        "the target is owned by another user; attach is same-user only",
    ),
    NOT_A_JVM(
        "not-a-jvm",
        "the target process does not look like a JVM",
    ),
    AGENT_ONATTACH_MISSING(
        "agent-onattach-missing",
        "the agent library does not export Agent_OnAttach, so it cannot load into a live VM",
    ),
    AGENT_INIT_FAILED(
        "agent-init-failed",
        "the agent loaded but Agent_OnAttach failed to initialize",
    ),
    JCMD_FALSE_SUCCESS(
        "jcmd-false-success",
        "jcmd exited 0 but the agent returned an error — this is a failure, not an attach",
    ),
    UNKNOWN(
        "unknown",
        "the attach failed for an unrecognized reason",
    );

    companion object {
        /** Map a raw code string to a known code, defaulting to [UNKNOWN]. */
        fun fromCode(raw: String): AttachRefusalCode =
            entries.firstOrNull { it.code == raw } ?: UNKNOWN
    }
}

/** Whether a refusal was found before launch (argv scan) or in the CLI output. */
enum class RefusalSource { CMDLINE_SCAN, CLI_OUTPUT }

/**
 * A classified reason a live attach will not / did not happen. Surfaced as a
 * first-class banner in the attach form rather than buried in the log. It never
 * describes a bypass: reaching a refusal means the attach did not occur.
 */
data class AttachRefusal(
    val code: AttachRefusalCode,
    val source: RefusalSource,
    /** The message text from the CLI, when parsed from output; blank for a
     *  pre-launch argv scan (the code's [meaning] carries the explanation). */
    val detail: String = "",
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
