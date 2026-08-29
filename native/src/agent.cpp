// j2c-dumper JVMTI agent.
//
// Usage:
//   -agentpath:j2c_agent.dll=trace=PATH[,native-only=true]
//
// Functions:
//   1. On VMInit: install our hooked JNIEnv function table on the main thread,
//      and arrange to install on every newly started thread.
//   2. On NativeMethodBind: capture the (class, name, sig, fn_addr) mapping
//      (emits a "bind" event). This gives downstream tools the
//      [native fn pointer -> Java method] table without disassembly.
//   3. On MethodEntry / MethodExit of native methods: emit enter/exit events
//      and toggle a per-thread "in native frame" flag so JNI wrappers know
//      they should log.

#include "trace_writer.hpp"
#include "jni_hook.hpp"

#include <jvmti.h>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>

using j2c::TraceWriter;
namespace hook = j2c::jni_hook;

namespace {

std::string g_trace_path = "trace.jsonl";

std::string esc(const char* s) {
    if (!s) return "null";
    std::string out;
    out += '"';
    for (const char* p = s; *p; ++p) {
        char c = *p;
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if ((unsigned char) c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", (unsigned) c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    out += '"';
    return out;
}

void parse_options(const char* options) {
    if (!options) return;
    std::string opts(options);
    size_t i = 0;
    while (i < opts.size()) {
        size_t j = opts.find(',', i);
        if (j == std::string::npos) j = opts.size();
        std::string pair = opts.substr(i, j - i);
        size_t eq = pair.find('=');
        std::string k = pair.substr(0, eq);
        std::string v = eq == std::string::npos ? "" : pair.substr(eq + 1);
        if (k == "trace") g_trace_path = v;
        else if (k == "log-all" && (v == "1" || v == "true")) hook::set_log_all(true);
        else if (k == "max-frame-events") {
            try { hook::set_max_frame_events(std::stoi(v)); } catch (...) {}
        }
        i = j + 1;
    }
}

bool method_is_native(jvmtiEnv* jvmti, jmethodID m) {
    jint mods = 0;
    if (jvmti->GetMethodModifiers(m, &mods) != JVMTI_ERROR_NONE) return false;
    return (mods & 0x0100) != 0; // ACC_NATIVE
}

std::tuple<std::string, std::string, std::string>
method_info(jvmtiEnv* jvmti, jmethodID m) {
    char *name = nullptr, *sig = nullptr;
    jclass declaring = nullptr;
    char* class_sig = nullptr;
    jvmti->GetMethodName(m, &name, &sig, nullptr);
    jvmti->GetMethodDeclaringClass(m, &declaring);
    if (declaring) jvmti->GetClassSignature(declaring, &class_sig, nullptr);
    std::string cname = class_sig ? class_sig : "";
    // Strip leading 'L' and trailing ';' to make it internal-name-friendly
    if (cname.size() >= 2 && cname.front() == 'L' && cname.back() == ';') {
        cname = cname.substr(1, cname.size() - 2);
    }
    std::string nm = name ? name : "";
    std::string ds = sig ? sig : "";
    if (name) jvmti->Deallocate((unsigned char*) name);
    if (sig) jvmti->Deallocate((unsigned char*) sig);
    if (class_sig) jvmti->Deallocate((unsigned char*) class_sig);
    return {cname, nm, ds};
}

void JNICALL on_vm_init(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread) {
    hook::capture_original(jni);
    hook::install(jni);
    std::ostringstream os;
    os << "{\"ev\":\"vminit\",\"ts\":" << TraceWriter::ts_now()
       << ",\"thr\":" << TraceWriter::tid() << "}";
    TraceWriter::instance().write_line(os.str());
}

void JNICALL on_thread_start(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread) {
    hook::install(jni);
}

void JNICALL on_native_method_bind(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                                   jmethodID method, void* address, void** new_address_ptr) {
    auto [cname, nm, ds] = method_info(jvmti, method);
    std::ostringstream os;
    os << "{\"ev\":\"bind\",\"ts\":" << TraceWriter::ts_now()
       << ",\"thr\":" << TraceWriter::tid()
       << ",\"owner\":" << esc(cname.c_str())
       << ",\"name\":" << esc(nm.c_str())
       << ",\"desc\":" << esc(ds.c_str())
       << ",\"fnAddr\":\"0x" << std::hex << reinterpret_cast<uintptr_t>(address) << "\"}";
    TraceWriter::instance().write_line(os.str());
}

bool is_jdk_native(const std::string& cname) {
    return cname.rfind("java/", 0) == 0 ||
           cname.rfind("javax/", 0) == 0 ||
           cname.rfind("sun/", 0) == 0 ||
           cname.rfind("jdk/", 0) == 0 ||
           cname.rfind("com/sun/", 0) == 0;
}

void JNICALL on_method_entry(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                             jmethodID method) {
    if (!method_is_native(jvmti, method)) return;
    auto [cname, nm, ds] = method_info(jvmti, method);
    // JDK native methods called from inside a user native frame should not
    // contribute JNI events to the recovery trace — they're internal noise
    // (e.g. String.getBytes uses byte-array ops we'd otherwise capture).
    if (is_jdk_native(cname)) {
        if (hook::in_native_frame()) hook::enter_suppress_frame();
        return;
    }
    hook::enter_native_frame();
    std::ostringstream os;
    os << "{\"ev\":\"enter\",\"ts\":" << TraceWriter::ts_now()
       << ",\"thr\":" << TraceWriter::tid()
       << ",\"owner\":" << esc(cname.c_str())
       << ",\"name\":" << esc(nm.c_str())
       << ",\"desc\":" << esc(ds.c_str()) << "}";
    TraceWriter::instance().write_line(os.str());
}

// Exception thrown inside (or propagated through) a user native frame. We
// record the throw site + exception type so the translator can credit each
// native frame that's currently on the per-thread stack — the catch may be
// far up the call chain, in a frame whose body is what we're recovering.
// Unlike MethodEntry we do NOT filter by is_jdk_native(throw_site), because
// the throw is often inside a JDK method (e.g. unboxing NPE from
// Integer.intValue) that propagates into user code.
void JNICALL on_exception(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                          jmethodID method, jlocation location,
                          jobject exception,
                          jmethodID catch_method, jlocation catch_location) {
    // NOTE: don't gate on in_native_frame() here. With native-obfuscator's
    // wrappers, exceptions are typically caught + cleared by the C++ side
    // before MethodExit ever fires, so the exception is reported on what
    // looks like the "outside" thread state. We record every user-method
    // exception and let the translator filter at frame association time.
    auto [tcname, tnm, tds] = method_info(jvmti, method);
    // Resolve exception class
    jclass ec = jni->GetObjectClass(exception);
    char* ec_sig = nullptr;
    if (ec) jvmti->GetClassSignature(ec, &ec_sig, nullptr);
    std::string ec_name = ec_sig ? ec_sig : "";
    if (ec_name.size() >= 2 && ec_name.front() == 'L' && ec_name.back() == ';') {
        ec_name = ec_name.substr(1, ec_name.size() - 2);
    }
    if (ec_sig) jvmti->Deallocate((unsigned char*) ec_sig);
    std::ostringstream os;
    os << "{\"ev\":\"exc\",\"ts\":" << TraceWriter::ts_now()
       << ",\"thr\":" << TraceWriter::tid()
       << ",\"owner\":" << esc(tcname.c_str())
       << ",\"name\":" << esc(tnm.c_str())
       << ",\"desc\":" << esc(tds.c_str())
       << ",\"loc\":" << static_cast<long long>(location)
       << ",\"excType\":" << esc(ec_name.c_str());
    if (catch_method != nullptr) {
        auto [ccname, cnm, cds] = method_info(jvmti, catch_method);
        os << ",\"catchOwner\":" << esc(ccname.c_str())
           << ",\"catchName\":" << esc(cnm.c_str())
           << ",\"catchDesc\":" << esc(cds.c_str())
           << ",\"catchLoc\":" << static_cast<long long>(catch_location);
    }
    os << "}";
    TraceWriter::instance().write_line(os.str());
}

void JNICALL on_exception_catch(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                                jmethodID method, jlocation location,
                                jobject exception) {
    auto [tcname, tnm, tds] = method_info(jvmti, method);
    jclass ec = jni->GetObjectClass(exception);
    char* ec_sig = nullptr;
    if (ec) jvmti->GetClassSignature(ec, &ec_sig, nullptr);
    std::string ec_name = ec_sig ? ec_sig : "";
    if (ec_name.size() >= 2 && ec_name.front() == 'L' && ec_name.back() == ';') {
        ec_name = ec_name.substr(1, ec_name.size() - 2);
    }
    if (ec_sig) jvmti->Deallocate((unsigned char*) ec_sig);
    std::ostringstream os;
    os << "{\"ev\":\"excCatch\",\"ts\":" << TraceWriter::ts_now()
       << ",\"thr\":" << TraceWriter::tid()
       << ",\"owner\":" << esc(tcname.c_str())
       << ",\"name\":" << esc(tnm.c_str())
       << ",\"desc\":" << esc(tds.c_str())
       << ",\"loc\":" << static_cast<long long>(location)
       << ",\"excType\":" << esc(ec_name.c_str()) << "}";
    TraceWriter::instance().write_line(os.str());
}

void JNICALL on_method_exit(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                            jmethodID method, jboolean was_popped_by_exception,
                            jvalue return_value) {
    if (!method_is_native(jvmti, method)) return;
    auto [cname, nm, ds] = method_info(jvmti, method);
    if (is_jdk_native(cname)) {
        if (hook::in_native_frame()) hook::exit_suppress_frame();
        return;
    }
    std::ostringstream os;
    os << "{\"ev\":\"exit\",\"ts\":" << TraceWriter::ts_now()
       << ",\"thr\":" << TraceWriter::tid()
       << ",\"owner\":" << esc(cname.c_str())
       << ",\"name\":" << esc(nm.c_str())
       << ",\"desc\":" << esc(ds.c_str())
       << ",\"exc\":" << (was_popped_by_exception ? "true" : "false") << "}";
    TraceWriter::instance().write_line(os.str());
    hook::exit_native_frame();
}

const char* phase_name(jvmtiPhase p) {
    switch (p) {
        case JVMTI_PHASE_ONLOAD:     return "onload";
        case JVMTI_PHASE_PRIMORDIAL: return "primordial";
        case JVMTI_PHASE_START:      return "start";
        case JVMTI_PHASE_LIVE:       return "live";
        case JVMTI_PHASE_DEAD:       return "dead";
        default:                     return "unknown";
    }
}

// Try to add a single JVMTI capability and emit a "capability" record noting
// whether it is available in the current phase. On a live (process attach)
// start, some capabilities the startup path takes for granted may be
// OnLoad-only or otherwise unavailable; we record that honestly instead of
// silently dropping coverage. Returns true iff the capability is now enabled.
bool add_capability(jvmtiEnv* jvmti, const jvmtiCapabilities& cap,
                    const char* name, const char* phase) {
    jvmtiError e = jvmti->AddCapabilities(&cap);
    bool ok = (e == JVMTI_ERROR_NONE);
    std::ostringstream os;
    os << "{\"ev\":\"capability\",\"ts\":" << TraceWriter::ts_now()
       << ",\"thr\":" << TraceWriter::tid()
       << ",\"name\":" << esc(name)
       << ",\"available\":" << (ok ? "true" : "false")
       << ",\"phase\":" << esc(phase);
    if (!ok) os << ",\"jvmtiError\":" << static_cast<int>(e);
    os << "}";
    TraceWriter::instance().write_line(os.str());
    return ok;
}

void emit_gap(const char* kind, const char* phase, const std::string& detail,
              const std::string& extra = std::string()) {
    std::ostringstream os;
    os << "{\"ev\":\"gap\",\"ts\":" << TraceWriter::ts_now()
       << ",\"thr\":" << TraceWriter::tid()
       << ",\"kind\":" << esc(kind)
       << ",\"phase\":" << esc(phase);
    if (!extra.empty()) os << "," << extra;
    os << ",\"detail\":" << esc(detail.c_str()) << "}";
    TraceWriter::instance().write_line(os.str());
}

// On a live attach the VM is already running, so VMInit will never fire and
// the JNIEnv function table swap that VMInit/ThreadStart normally performs must
// be bootstrapped here. We can only reach the *current* (attach-listener)
// thread's JNIEnv; already-running application threads keep their original
// table until they exit. We install on the current thread (so the hooked table
// is built and picked up by every future ThreadStart) and record the coverage
// gap for the threads we cannot reach.
void install_on_live_threads(JavaVM* vm, jvmtiEnv* jvmti, const char* phase,
                             const std::string& enabled_events) {
    JNIEnv* jni = nullptr;
    jint gr = vm->GetEnv(reinterpret_cast<void**>(&jni), JNI_VERSION_1_6);
    bool table_installed = false;
    if (gr == JNI_OK && jni != nullptr) {
        hook::capture_original(jni);
        hook::install(jni);
        table_installed = true;
    }

    jint count = -1;
    jthread* threads = nullptr;
    if (jvmti->GetAllThreads(&count, &threads) != JVMTI_ERROR_NONE) {
        count = -1;
    } else if (threads) {
        jvmti->Deallocate(reinterpret_cast<unsigned char*>(threads));
    }

    std::ostringstream extra;
    extra << "\"tableInstalled\":" << (table_installed ? "true" : "false")
          << ",\"runningThreads\":" << count
          << ",\"enabledEvents\":" << esc(enabled_events.c_str());
    // Only claim the events we actually enabled for this phase. Threads already
    // running at attach time still receive those process-wide JVMTI events, but
    // never per-JNI-call argument events (their JNIEnv table is unchanged).
    std::string detail =
        "live attach installs JNI wrappers on the attach thread and every thread "
        "started afterwards; threads already running at attach time still emit "
        "the process-wide JVMTI events enabled in this phase (" + enabled_events +
        ") but not per-JNI-call argument events";
    emit_gap("jni-table-running-threads", phase, detail, extra.str());
}

// Shared initialization for both startup (-agentpath, Agent_OnLoad) and live
// process attach (Agent_OnAttach). `live_attach` selects phase-aware behavior.
jint init_agent(JavaVM* vm, char* options, bool live_attach) {
    parse_options(options);
    TraceWriter::instance().open(g_trace_path);
    if (!TraceWriter::instance().is_open()) {
        std::fprintf(stderr, "j2c-agent: failed to open trace file: %s\n", g_trace_path.c_str());
        return JNI_ERR;
    }

    jvmtiEnv* jvmti = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&jvmti), JVMTI_VERSION_1_2) != JNI_OK) {
        std::fprintf(stderr, "j2c-agent: cannot get JVMTI env\n");
        return JNI_ERR;
    }

    jvmtiPhase phase = JVMTI_PHASE_ONLOAD;
    jvmti->GetPhase(&phase);
    const char* pname = phase_name(phase);

    std::ostringstream lc;
    lc << "{\"ev\":" << (live_attach ? "\"agent-attached\"" : "\"agent-loaded\"")
       << ",\"ts\":" << TraceWriter::ts_now()
       << ",\"thr\":" << TraceWriter::tid()
       << ",\"mode\":" << esc(live_attach ? "live-attach" : "startup")
       << ",\"phase\":" << esc(pname)
       << ",\"logAll\":" << (hook::log_all() ? "true" : "false")
       << ",\"trace\":" << esc(g_trace_path.c_str()) << "}";
    TraceWriter::instance().write_line(lc.str());

    // Add capabilities one at a time (AddCapabilities is additive) so that a
    // single unavailable capability on live attach does not sink the rest.
    auto cap_bit = [](void (*set)(jvmtiCapabilities&)) {
        jvmtiCapabilities c{};
        set(c);
        return c;
    };
    bool cap_bind = add_capability(jvmti,
        cap_bit([](jvmtiCapabilities& c) { c.can_generate_native_method_bind_events = 1; }),
        "can_generate_native_method_bind_events", pname);
    bool cap_entry = add_capability(jvmti,
        cap_bit([](jvmtiCapabilities& c) { c.can_generate_method_entry_events = 1; }),
        "can_generate_method_entry_events", pname);
    bool cap_exit = add_capability(jvmti,
        cap_bit([](jvmtiCapabilities& c) { c.can_generate_method_exit_events = 1; }),
        "can_generate_method_exit_events", pname);
    // Needed to read parameter values of a native method at MethodEntry.
    bool cap_locals = add_capability(jvmti,
        cap_bit([](jvmtiCapabilities& c) { c.can_access_local_variables = 1; }),
        "can_access_local_variables", pname);
    // Exception events drive recovery of try/catch tables.
    bool cap_exc = add_capability(jvmti,
        cap_bit([](jvmtiCapabilities& c) { c.can_generate_exception_events = 1; }),
        "can_generate_exception_events", pname);

    // Describe exactly which thread-independent JVMTI events we could enable, so
    // downstream records never imply coverage we do not actually have.
    std::string enabled_events;
    auto add_ev = [&](bool on, const char* n) {
        if (on) { if (!enabled_events.empty()) enabled_events += ", "; enabled_events += n; }
    };
    add_ev(cap_bind,  "native-method-bind");
    add_ev(cap_entry, "method-entry");
    add_ev(cap_exit,  "method-exit");
    add_ev(cap_exc,   "exception/exception-catch");
    if (enabled_events.empty()) enabled_events = "none";

    if (!cap_bind && !cap_entry && !cap_exit) {
        emit_gap("no-core-capabilities", pname,
                 "neither native-method-bind nor method entry/exit capabilities "
                 "are available in this phase; the recovery trace will be empty");
    } else if (live_attach && (!cap_entry || !cap_exit || !cap_exc || !cap_locals)) {
        // On many JDKs (observed on OpenJDK 21) a live attach can only add
        // native-method-bind; method entry/exit, local-variable access, and
        // exception capabilities return JVMTI_ERROR_NOT_AVAILABLE in the live
        // phase. Record precisely what was obtained rather than implying full
        // coverage. Without method entry/exit there is no user-native-frame
        // detection, so per-JNI-call argument events (which gate on being inside
        // such a frame) will not be produced either.
        std::ostringstream extra;
        extra << "\"nativeMethodBind\":" << (cap_bind ? "true" : "false")
              << ",\"methodEntry\":" << (cap_entry ? "true" : "false")
              << ",\"methodExit\":" << (cap_exit ? "true" : "false")
              << ",\"localVariables\":" << (cap_locals ? "true" : "false")
              << ",\"exceptions\":" << (cap_exc ? "true" : "false")
              << ",\"enabledEvents\":" << esc(enabled_events.c_str());
        emit_gap("reduced-live-capabilities", pname,
                 "live attach obtained only a subset of JVMTI capabilities; "
                 "entry/exit, local-variable, and exception events unavailable "
                 "in this phase are not enabled and will not appear in the trace. "
                 "For full method-body recovery use the startup -agentpath path.",
                 extra.str());
    }

    jvmtiEventCallbacks cbs{};
    cbs.VMInit = on_vm_init;
    cbs.ThreadStart = on_thread_start;
    if (cap_bind)  cbs.NativeMethodBind = on_native_method_bind;
    if (cap_entry) cbs.MethodEntry = on_method_entry;
    if (cap_exit)  cbs.MethodExit = on_method_exit;
    if (cap_exc) {
        cbs.Exception = on_exception;
        cbs.ExceptionCatch = on_exception_catch;
    }
    if (jvmti->SetEventCallbacks(&cbs, sizeof(cbs)) != JVMTI_ERROR_NONE) {
        std::fprintf(stderr, "j2c-agent: SetEventCallbacks failed\n");
        return JNI_ERR;
    }

    // On startup VMInit installs the JNI table; on live attach it never fires.
    if (!live_attach) {
        jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_VM_INIT, nullptr);
    }
    jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_THREAD_START, nullptr);
    if (cap_bind)  jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_NATIVE_METHOD_BIND, nullptr);
    if (cap_entry) jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_METHOD_ENTRY, nullptr);
    if (cap_exit)  jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_METHOD_EXIT, nullptr);
    if (cap_exc) {
        jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_EXCEPTION, nullptr);
        jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_EXCEPTION_CATCH, nullptr);
    }

    if (live_attach) {
        install_on_live_threads(vm, jvmti, pname, enabled_events);
    }

    return JNI_OK;
}

} // namespace

extern "C" JNIEXPORT jint JNICALL
Agent_OnLoad(JavaVM* vm, char* options, void* /*reserved*/) {
    return init_agent(vm, options, /*live_attach=*/false);
}

// Entry point for live process attach (JDK attach API / com.sun.tools.attach
// loadAgentPath, or `jcmd <pid> JVMTI.agent_load`). Shares initialization with
// Agent_OnLoad but is phase-aware: the VM is already running.
extern "C" JNIEXPORT jint JNICALL
Agent_OnAttach(JavaVM* vm, char* options, void* /*reserved*/) {
    return init_agent(vm, options, /*live_attach=*/true);
}

extern "C" JNIEXPORT void JNICALL
Agent_OnUnload(JavaVM* /*vm*/) {
    TraceWriter::instance().close();
}
