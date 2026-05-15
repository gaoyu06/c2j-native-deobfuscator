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
bool g_log_all = false; // log even outside __ngen native frames

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
        else if (k == "log-all" && (v == "1" || v == "true")) g_log_all = true;
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

} // namespace

extern "C" JNIEXPORT jint JNICALL
Agent_OnLoad(JavaVM* vm, char* options, void* /*reserved*/) {
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

    jvmtiCapabilities caps{};
    caps.can_generate_method_entry_events = 1;
    caps.can_generate_method_exit_events = 1;
    caps.can_generate_native_method_bind_events = 1;
    // Needed to read parameter values of a native method at MethodEntry —
    // see read_method_params() and `params` field on enter events.
    caps.can_access_local_variables = 1;
    // Exception events drive recovery of try/catch tables — see #4.
    caps.can_generate_exception_events = 1;
    if (jvmti->AddCapabilities(&caps) != JVMTI_ERROR_NONE) {
        std::fprintf(stderr, "j2c-agent: AddCapabilities failed\n");
        return JNI_ERR;
    }

    jvmtiEventCallbacks cbs{};
    cbs.VMInit = on_vm_init;
    cbs.ThreadStart = on_thread_start;
    cbs.NativeMethodBind = on_native_method_bind;
    cbs.MethodEntry = on_method_entry;
    cbs.MethodExit = on_method_exit;
    cbs.Exception = on_exception;
    cbs.ExceptionCatch = on_exception_catch;
    if (jvmti->SetEventCallbacks(&cbs, sizeof(cbs)) != JVMTI_ERROR_NONE) {
        std::fprintf(stderr, "j2c-agent: SetEventCallbacks failed\n");
        return JNI_ERR;
    }

    jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_VM_INIT, nullptr);
    jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_THREAD_START, nullptr);
    jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_NATIVE_METHOD_BIND, nullptr);
    jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_METHOD_ENTRY, nullptr);
    jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_METHOD_EXIT, nullptr);
    jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_EXCEPTION, nullptr);
    jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_EXCEPTION_CATCH, nullptr);

    std::ostringstream os;
    os << "{\"ev\":\"agent-loaded\",\"ts\":" << TraceWriter::ts_now()
       << ",\"thr\":" << TraceWriter::tid()
       << ",\"trace\":" << esc(g_trace_path.c_str()) << "}";
    TraceWriter::instance().write_line(os.str());
    return JNI_OK;
}

extern "C" JNIEXPORT void JNICALL
Agent_OnUnload(JavaVM* /*vm*/) {
    TraceWriter::instance().close();
}
