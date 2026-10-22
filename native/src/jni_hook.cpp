#include "jni_hook.hpp"
#include "trace_writer.hpp"
#include "class_filter.hpp"

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <iomanip>
#include <limits>
#include <type_traits>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace j2c::jni_hook {

namespace {

const JNINativeInterface_* g_original = nullptr;
jvmtiEnv* g_jvmti = nullptr;
JavaVM* g_vm = nullptr;
JNINativeInterface_* g_hooked = nullptr;
std::once_flag g_build_flag;

// jmethodID -> method descriptor (e.g. "(I[ILjava/lang/String;)V"). Populated
// by our GetMethodID/GetStaticMethodID wrappers. Needed to decode variadic
// args passed to Call*Method.
std::mutex g_mid_mu;
std::unordered_map<jmethodID, std::string> g_mid_desc;

// jstring/jobject -> UTF-8 content. Populated by NewStringUTF and propagated
// through NewGlobalRef / NewWeakGlobalRef so we can resolve cached jstrings
// without a recursive JNI call.
std::mutex g_str_mu;
std::unordered_map<jobject, std::string> g_str_content;

// Cached java/lang/String class for IsInstanceOf probing.
jclass g_string_class = nullptr;

std::string read_jstring(JNIEnv* env, jobject obj);

std::string lookup_string(jobject o) {
    // A JNI local handle is not a durable object identity. Read the live
    // object instead of accepting cached text from a recycled handle.
    JNIEnv* env = nullptr;
    if (!o || !g_original || !g_vm || g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK)
        return {};
    if (g_original->ExceptionCheck(env)) return {};
    return read_jstring(env, o);
}

void register_string(jobject o, std::string s) {
    if (o == nullptr) return;
    std::lock_guard<std::mutex> g(g_str_mu);
    g_str_content[o] = std::move(s);
}

thread_local bool t_filter_frame_selected = false;
thread_local int t_frame_depth = 0;
thread_local int t_suppress_depth = 0;
thread_local int t_frame_event_count = 0;   // events emitted within current frame
thread_local bool t_frame_truncated = false;
thread_local const char* t_current_method = nullptr;

// Max events per `enter` frame. After this many JNI events have been emitted
// within a single user-native-frame, further events are dropped. Prevents
// trace bloat on long-running programs (game loops, request handlers, etc.).
// Configurable via the `max-frame-events=N` agent option; 0 = unlimited.
int g_max_frame_events = 50000;

// When true, JNI-call wrappers emit even when not inside a user native frame.
// Wired to the `log-all=true` agent option (see set_log_all). Off by default.
std::atomic<bool> g_log_all{false};

// Parse a method descriptor into a list of arg-type tokens.
// Example: "(ILjava/lang/String;[I)V" -> ["I", "Ljava/lang/String;", "[I"].
std::vector<std::string> parse_arg_types(const std::string& desc) {
    std::vector<std::string> out;
    if (desc.size() < 2 || desc[0] != '(') return out;
    size_t i = 1;
    while (i < desc.size() && desc[i] != ')') {
        size_t start = i;
        // skip leading '['s
        while (i < desc.size() && desc[i] == '[') ++i;
        if (i < desc.size() && desc[i] == 'L') {
            // consume until ';'
            while (i < desc.size() && desc[i] != ';') ++i;
            if (i < desc.size()) ++i;
        } else if (i < desc.size()) {
            ++i;
        }
        out.emplace_back(desc.substr(start, i - start));
    }
    return out;
}

// Decode the variadic args of a Call*Method invocation, given the method's
// descriptor. JNI variadic uses C calling conventions, so smaller-than-int
// integer types are promoted to int, and float is promoted to double.
//
// Returns a string fragment like ``,42,"hello",0x123abc`` ready to append
// after the receiver+mid pair in the args JSON array.
std::string decode_variadic(jmethodID m, va_list ap) {
    std::string desc;
    {
        std::lock_guard<std::mutex> g(g_mid_mu);
        auto it = g_mid_desc.find(m);
        if (it != g_mid_desc.end()) desc = it->second;
    }
    if (desc.empty()) return "";
    auto types = parse_arg_types(desc);
    std::string out;
    char buf[64];
    for (const auto& t : types) {
        out += ',';
        char c = t[0];
        if (c == '[' || c == 'L') {
            // jobject / jstring / jclass / jarray — try to inline string content
            jobject obj = va_arg(ap, jobject);
            auto str_content = lookup_string(obj);
            if (!str_content.empty()) {
                // emit as a JSON-escaped string literal
                out += '"';
                for (char ch : str_content) {
                    if (ch == '"') out += "\\\"";
                    else if (ch == '\\') out += "\\\\";
                    else if (static_cast<unsigned char>(ch) < 0x20) {
                        std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(ch));
                        out += buf;
                    } else out += ch;
                }
                out += '"';
            } else {
                std::snprintf(buf, sizeof(buf), "\"0x%llx\"",
                              static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(obj)));
                out += buf;
            }
        } else if (c == 'J') {
            long long v = va_arg(ap, jlong);
            std::snprintf(buf, sizeof(buf), "%lld", v);
            out += buf;
        } else if (c == 'F') {
            // jfloat promoted to double in C variadic
            double v = va_arg(ap, double);
            std::snprintf(buf, sizeof(buf), "%g", v);
            out += buf;
        } else if (c == 'D') {
            double v = va_arg(ap, double);
            std::snprintf(buf, sizeof(buf), "%g", v);
            out += buf;
        } else {
            // B, C, S, Z, I  — promoted to int
            int v = va_arg(ap, int);
            std::snprintf(buf, sizeof(buf), "%d", v);
            out += buf;
        }
    }
    return out;
}

// Decode jvalue[] args (Call*MethodA variants) given the descriptor.
std::string decode_array(jmethodID m, const jvalue* a) {
    std::string desc;
    {
        std::lock_guard<std::mutex> g(g_mid_mu);
        auto it = g_mid_desc.find(m);
        if (it != g_mid_desc.end()) desc = it->second;
    }
    if (desc.empty() || a == nullptr) return "";
    auto types = parse_arg_types(desc);
    std::string out;
    char buf[64];
    for (size_t i = 0; i < types.size(); ++i) {
        out += ',';
        char c = types[i][0];
        const jvalue& v = a[i];
        if (c == '[' || c == 'L') {
            auto str_content = lookup_string(v.l);
            if (!str_content.empty()) {
                out += '"';
                for (char ch : str_content) {
                    if (ch == '"') out += "\\\""; else if (ch == '\\') out += "\\\\";
                    else if (static_cast<unsigned char>(ch) < 0x20) {
                        std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(ch));
                        out += buf;
                    } else out += ch;
                }
                out += '"';
                continue;
            }
            std::snprintf(buf, sizeof(buf), "\"0x%llx\"",
                          static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(v.l)));
        } else if (c == 'J') {
            std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(v.j));
        } else if (c == 'F') {
            std::snprintf(buf, sizeof(buf), "%g", v.f);
        } else if (c == 'D') {
            std::snprintf(buf, sizeof(buf), "%g", v.d);
        } else if (c == 'Z') {
            std::snprintf(buf, sizeof(buf), "%d", static_cast<int>(v.z));
        } else if (c == 'B') {
            std::snprintf(buf, sizeof(buf), "%d", static_cast<int>(v.b));
        } else if (c == 'C') {
            std::snprintf(buf, sizeof(buf), "%d", static_cast<int>(v.c));
        } else if (c == 'S') {
            std::snprintf(buf, sizeof(buf), "%d", static_cast<int>(v.s));
        } else {
            std::snprintf(buf, sizeof(buf), "%d", static_cast<int>(v.i));
        }
        out += buf;
    }
    return out;
}

// Helper: small JSON-escape for ASCII strings.
std::string esc(const char* s) {
    if (!s) return "null";
    std::string out;
    out.reserve(strlen(s) + 2);
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
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    out += '"';
    return out;
}

std::string hex_ptr(const void* p) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "\"0x%llx\"", static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(p)));
    return buf;
}


// JNI local handles may be recycled. Owner names are therefore read from
// JVMTI at lookup/call time, never derived from a loadClass string argument.
std::string class_name(jclass cls) {
    if (!g_jvmti || !cls) return {};
    char* sig = nullptr;
    if (g_jvmti->GetClassSignature(cls, &sig, nullptr) != JVMTI_ERROR_NONE || !sig) return {};
    std::string out(sig);
    g_jvmti->Deallocate(reinterpret_cast<unsigned char*>(sig));
    if (out.size() >= 2 && out.front() == 'L' && out.back() == ';') out = out.substr(1, out.size() - 2);
    return out;
}
void release_class(jclass cls) {
    JNIEnv* env = nullptr;
    if (cls && g_original && g_vm && g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK)
        g_original->DeleteLocalRef(env, cls);
}
std::string class_metadata(jclass cls) {
    const auto name = class_name(cls);
    return name.empty() ? std::string() : ",\"retClassName\":" + esc(name.c_str());
}
std::mutex g_member_mu;
std::unordered_map<jmethodID, std::string> g_method_metadata;
std::string method_metadata(jmethodID mid) {
    if (!g_jvmti || !mid) return {};
    std::lock_guard<std::mutex> guard(g_member_mu);
    auto it = g_method_metadata.find(mid);
    if (it != g_method_metadata.end()) return it->second;
    jclass cls = nullptr;
    char *name = nullptr, *desc = nullptr;
    if (g_jvmti->GetMethodDeclaringClass(mid, &cls) != JVMTI_ERROR_NONE) return {};
    auto owner = class_name(cls);
    release_class(cls);
    const auto status = g_jvmti->GetMethodName(mid, &name, &desc, nullptr);
    std::string out;
    if (status == JVMTI_ERROR_NONE && name && desc && !owner.empty()) {
        out = ",\"memberOwner\":" + esc(owner.c_str()) + ",\"memberName\":" + esc(name) + ",\"memberDesc\":" + esc(desc);
    }
    if (name) g_jvmti->Deallocate(reinterpret_cast<unsigned char*>(name));
    if (desc) g_jvmti->Deallocate(reinterpret_cast<unsigned char*>(desc));
    if (!out.empty()) g_method_metadata[mid] = out;
    return out;
}
std::string field_metadata(jclass lookup_class, jfieldID fid) {
    if (!g_jvmti || !lookup_class || !fid) return {};
    jclass cls = nullptr;
    if (g_jvmti->GetFieldDeclaringClass(lookup_class, fid, &cls) != JVMTI_ERROR_NONE) return {};
    auto owner = class_name(cls);
    release_class(cls);
    char *name = nullptr, *desc = nullptr;
    const auto status = g_jvmti->GetFieldName(lookup_class, fid, &name, &desc, nullptr);
    std::string out;
    if (status == JVMTI_ERROR_NONE && name && desc && !owner.empty())
        out = ",\"memberOwner\":" + esc(owner.c_str()) + ",\"memberName\":" + esc(name) + ",\"memberDesc\":" + esc(desc);
    if (name) g_jvmti->Deallocate(reinterpret_cast<unsigned char*>(name));
    if (desc) g_jvmti->Deallocate(reinterpret_cast<unsigned char*>(desc));
    return out;
}

void emit(const std::string& call, const std::string& args, const std::string& ret,
          jmethodID mid = nullptr, const std::string& ret_str = std::string(),
          const std::string& metadata = std::string()) {
    if (t_suppress_depth > 0 || (j2c::class_filter.active() && !t_filter_frame_selected)) return;
    const bool inframe = in_native_frame();
    // Outside a user native frame we normally stay silent (those JNI calls are
    // noise for recovery). The `log-all` agent option opts into logging them.
    if (!inframe && !g_log_all.load(std::memory_order_relaxed)) return;
    // The per-frame event budget only applies inside a frame (the counter is
    // reset on outermost frame entry); log-all events outside a frame are not
    // budgeted here.
    if (inframe && g_max_frame_events > 0 && t_frame_event_count >= g_max_frame_events) {
        if (!t_frame_truncated) {
            t_frame_truncated = true;
            // emit a single truncation marker once per frame
            std::ostringstream os;
            os << "{\"ev\":\"truncate\",\"ts\":" << TraceWriter::ts_now()
               << ",\"thr\":" << TraceWriter::tid()
               << ",\"limit\":" << g_max_frame_events << "}";
            TraceWriter::instance().write_line(os.str());
        }
        return;
    }
    if (inframe) ++t_frame_event_count;
    std::ostringstream os;
    os << "{\"ev\":\"jni\",\"ts\":" << TraceWriter::ts_now()
       << ",\"thr\":" << TraceWriter::tid()
       << ",\"call\":" << esc(call.c_str())
       << ",\"args\":[" << args << "]"
       << ",\"ret\":" << ret;
    if (mid != nullptr) {
        std::string desc;
        {
            std::lock_guard<std::mutex> g(g_mid_mu);
            auto it = g_mid_desc.find(mid);
            if (it != g_mid_desc.end()) desc = it->second;
        }
        if (!desc.empty()) {
            os << ",\"midDesc\":" << esc(desc.c_str());
        }
    }
    os << method_metadata(mid) << metadata;
    if (!ret_str.empty()) {
        os << ",\"retStr\":" << esc(ret_str.c_str());
    }
    os << "}";
    TraceWriter::instance().write_line(os.str());
}

std::string returned_class_metadata(jmethodID mid, jobject result) {
    if (!mid || !result) return {};
    std::string desc;
    { std::lock_guard<std::mutex> guard(g_mid_mu);
      auto it = g_mid_desc.find(mid); if (it != g_mid_desc.end()) desc = it->second; }
    const std::string suffix = ")Ljava/lang/Class;";
    if (desc.size() >= suffix.size() && desc.compare(desc.size() - suffix.size(), suffix.size(), suffix) == 0)
        return class_metadata(static_cast<jclass>(result));
    return {};
}

std::string read_jstring(JNIEnv* env, jobject obj);  // defined below

// If `m` returns Ljava/lang/String;, snapshot the returned jstring content
// via the *original* GetStringUTFChars (no recursion), register it in
// g_str_content so downstream wrappers can inline it, and return the content
// for inclusion as `retStr` on the event. Empty string -> non-String return
// or read failure.
std::string maybe_track_string_return(JNIEnv* env, jmethodID m, jobject r) {
    if (!r || !m) return std::string();
    std::string desc;
    {
        std::lock_guard<std::mutex> g(g_mid_mu);
        auto it = g_mid_desc.find(m);
        if (it != g_mid_desc.end()) desc = it->second;
    }
    auto rp = desc.rfind(')');
    if (rp == std::string::npos) return std::string();
    if (desc.compare(rp + 1, std::string::npos, "Ljava/lang/String;") != 0) {
        return std::string();
    }
    // Already tracked (e.g. propagated from a NewStringUTF via NewGlobalRef)?
    auto existing = lookup_string(r);
    if (!existing.empty()) return existing;
    auto content = read_jstring(env, r);
    if (!content.empty()) register_string(r, content);
    return content;
}

// JSON numeric encoding shared by scalar and array wrappers. Non-finite
// values use explicit strings so the event remains valid JSON.
template<class T> std::string trace_number(T value) {
    std::ostringstream out;
    if constexpr (std::is_floating_point<T>::value) {
        if (std::isnan(value)) return "\"NaN\"";
        if (std::isinf(value)) return value < 0 ? "\"-Infinity\"" : "\"Infinity\"";
        out << std::setprecision(std::numeric_limits<T>::max_digits10) << value;
    } else out << static_cast<long long>(value);
    return out.str();
}
template<class T> std::string trace_buffer(const T* buf, jsize len) {
    std::ostringstream out; out << "[";
    if (buf) for (jsize i = 0; i < len; ++i) {
        if (i) out << ",";
        out << trace_number(buf[i]);
    }
    out << "]"; return out.str();
}

#define ORIG(name) (g_original->name)

// ---------- wrappers ----------

jclass JNICALL h_FindClass(JNIEnv* env, const char* name) {
    jclass r = ORIG(FindClass)(env, name);
    std::ostringstream args; args << esc(name);
    emit("FindClass", args.str(), hex_ptr(r), nullptr, {}, class_metadata(r));
    return r;
}

void emit_outside_frame(const std::string& call, const std::string& args, const std::string& ret, jmethodID mid = nullptr) {
    if (t_suppress_depth > 0 || (j2c::class_filter.active() && !t_filter_frame_selected)) return;
    std::ostringstream os;
    os << "{\"ev\":\"jni-init\",\"ts\":" << TraceWriter::ts_now()
       << ",\"thr\":" << TraceWriter::tid()
       << ",\"call\":" << esc(call.c_str())
       << ",\"args\":[" << args << "]"
       << ",\"ret\":" << ret << method_metadata(mid)
       << "}";
    TraceWriter::instance().write_line(os.str());
}

jmethodID JNICALL h_GetMethodID(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
    jmethodID r = ORIG(GetMethodID)(env, clazz, name, sig);
    if (r && sig) {
        std::lock_guard<std::mutex> g(g_mid_mu);
        // Use insert_or_assign-equivalent: erase + emplace so we always store
        // the latest descriptor for a given jmethodID. (Defensive — should
        // never trigger if JNI gives stable IDs, but guards against any
        // internal reuse.)
        g_mid_desc[r] = sig;
    }
    std::ostringstream args;
    args << hex_ptr(clazz) << "," << esc(name) << "," << esc(sig);
    if (in_native_frame()) {
        emit("GetMethodID", args.str(), hex_ptr(r), r);
    } else {
        emit_outside_frame("GetMethodID", args.str(), hex_ptr(r), r);
    }
    return r;
}

jmethodID JNICALL h_GetStaticMethodID(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
    jmethodID r = ORIG(GetStaticMethodID)(env, clazz, name, sig);
    if (r && sig) {
        std::lock_guard<std::mutex> g(g_mid_mu);
        g_mid_desc[r] = sig;
    }
    std::ostringstream args;
    args << hex_ptr(clazz) << "," << esc(name) << "," << esc(sig);
    if (in_native_frame()) {
        emit("GetStaticMethodID", args.str(), hex_ptr(r), r);
    } else {
        emit_outside_frame("GetStaticMethodID", args.str(), hex_ptr(r), r);
    }
    return r;
}

jfieldID JNICALL h_GetFieldID(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
    jfieldID r = ORIG(GetFieldID)(env, clazz, name, sig);
    std::ostringstream args;
    args << hex_ptr(clazz) << "," << esc(name) << "," << esc(sig);
    emit("GetFieldID", args.str(), hex_ptr(r), nullptr, {}, field_metadata(clazz, r));
    return r;
}

jfieldID JNICALL h_GetStaticFieldID(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
    jfieldID r = ORIG(GetStaticFieldID)(env, clazz, name, sig);
    std::ostringstream args;
    args << hex_ptr(clazz) << "," << esc(name) << "," << esc(sig);
    emit("GetStaticFieldID", args.str(), hex_ptr(r), nullptr, {}, field_metadata(clazz, r));
    return r;
}

jstring JNICALL h_NewStringUTF(JNIEnv* env, const char* str) {
    jstring r = ORIG(NewStringUTF)(env, str);
    if (r && str) register_string(r, str);
    emit("NewStringUTF", esc(str), hex_ptr(r));
    return r;
}

// Read the UTF-8 content of a jstring via the *original* function table to
// avoid recursive hook calls. Returns empty string on failure (incl.
// IsInstanceOf check failing).
std::string read_jstring(JNIEnv* env, jobject obj) {
    if (obj == nullptr || g_string_class == nullptr) return "";
    jboolean is_str = ORIG(IsInstanceOf)(env, obj, g_string_class);
    if (!is_str) return "";
    const char* chars = ORIG(GetStringUTFChars)(env, (jstring) obj, nullptr);
    if (!chars) return "";
    std::string out(chars);
    ORIG(ReleaseStringUTFChars)(env, (jstring) obj, chars);
    return out;
}

void emit_propagate(const char* call, jobject from, jobject to) {
    if (t_suppress_depth > 0 || (j2c::class_filter.active() && !t_filter_frame_selected)) return;
    if (!in_native_frame() && !g_log_all.load(std::memory_order_relaxed)) return;
    std::ostringstream os;
    os << "{\"ev\":\"jni\",\"ts\":" << TraceWriter::ts_now()
       << ",\"thr\":" << TraceWriter::tid()
       << ",\"call\":" << esc(call)
       << ",\"args\":[" << hex_ptr(from) << "]"
       << ",\"ret\":" << hex_ptr(to) << "}";
    TraceWriter::instance().write_line(os.str());
}

jobject JNICALL h_NewGlobalRef(JNIEnv* env, jobject lobj) {
    jobject r = ORIG(NewGlobalRef)(env, lobj);
    auto content = lookup_string(lobj);
    if (content.empty()) content = read_jstring(env, lobj);
    if (!content.empty()) register_string(r, content);
    emit_propagate("NewGlobalRef", lobj, r);
    return r;
}

jweak JNICALL h_NewWeakGlobalRef(JNIEnv* env, jobject lobj) {
    jweak r = ORIG(NewWeakGlobalRef)(env, lobj);
    auto content = lookup_string(lobj);
    if (content.empty()) content = read_jstring(env, lobj);
    if (!content.empty()) register_string(r, content);
    emit_propagate("NewWeakGlobalRef", lobj, r);
    return r;
}

jobject JNICALL h_NewLocalRef(JNIEnv* env, jobject ref) {
    jobject r = ORIG(NewLocalRef)(env, ref);
    auto content = lookup_string(ref);
    if (content.empty()) content = read_jstring(env, ref);
    if (!content.empty()) register_string(r, content);
    emit_propagate("NewLocalRef", ref, r);
    return r;
}

void JNICALL h_DeleteLocalRef(JNIEnv* env, jobject ref) {
    // Crucial: local-ref jobject pointers are reused after deletion. Drop
    // the cached string content so the next caller of the same pointer
    // doesn't see a stale value.
    if (ref != nullptr) {
        std::lock_guard<std::mutex> g(g_str_mu);
        g_str_content.erase(ref);
    }
    ORIG(DeleteLocalRef)(env, ref);
}

void JNICALL h_DeleteGlobalRef(JNIEnv* env, jobject ref) {
    if (ref != nullptr) {
        std::lock_guard<std::mutex> g(g_str_mu);
        g_str_content.erase(ref);
    }
    ORIG(DeleteGlobalRef)(env, ref);
}

void JNICALL h_DeleteWeakGlobalRef(JNIEnv* env, jweak ref) {
    if (ref != nullptr) {
        std::lock_guard<std::mutex> g(g_str_mu);
        g_str_content.erase(ref);
    }
    ORIG(DeleteWeakGlobalRef)(env, ref);
}

// Field accessors (one set per type) — we only wrap GetObjectField / GetIntField
// and the static variants to keep code size manageable. Extending is mechanical.

#define WRAP_GET_FIELD(jtype, jname, fmtarg)                                                  \
    jtype JNICALL h_Get##jname##Field(JNIEnv* env, jobject obj, jfieldID f) {                 \
        jtype r = ORIG(Get##jname##Field)(env, obj, f);                                       \
        std::ostringstream args; args << hex_ptr(obj) << "," << hex_ptr(f);                   \
        std::string rb = trace_number(r);                    \
        emit("Get" #jname "Field", args.str(), rb);                                           \
        return r;                                                                              \
    }

#define WRAP_SET_FIELD(jtype, jname, fmtarg)                                                  \
    void JNICALL h_Set##jname##Field(JNIEnv* env, jobject obj, jfieldID f, jtype v) {         \
        ORIG(Set##jname##Field)(env, obj, f, v);                                              \
        std::ostringstream args; args << hex_ptr(obj) << "," << hex_ptr(f) << "," <<          \
            trace_number(v); \
        emit("Set" #jname "Field", args.str(), "null");                                       \
    }

#define WRAP_GET_STATIC_FIELD(jtype, jname, fmtarg)                                            \
    jtype JNICALL h_GetStatic##jname##Field(JNIEnv* env, jclass clazz, jfieldID f) {           \
        jtype r = ORIG(GetStatic##jname##Field)(env, clazz, f);                                \
        std::ostringstream args; args << hex_ptr(clazz) << "," << hex_ptr(f);                  \
        std::string rb = trace_number(r);                     \
        emit("GetStatic" #jname "Field", args.str(), rb);                                      \
        return r;                                                                               \
    }

// Object field variants
jobject JNICALL h_GetObjectField(JNIEnv* env, jobject obj, jfieldID f) {
    jobject r = ORIG(GetObjectField)(env, obj, f);
    std::ostringstream args; args << hex_ptr(obj) << "," << hex_ptr(f);
    emit("GetObjectField", args.str(), hex_ptr(r));
    return r;
}

void JNICALL h_SetObjectField(JNIEnv* env, jobject obj, jfieldID f, jobject v) {
    ORIG(SetObjectField)(env, obj, f, v);
    std::ostringstream args;
    args << hex_ptr(obj) << "," << hex_ptr(f) << "," << hex_ptr(v);
    emit("SetObjectField", args.str(), "null");
}

jobject JNICALL h_GetStaticObjectField(JNIEnv* env, jclass clazz, jfieldID f) {
    jobject r = ORIG(GetStaticObjectField)(env, clazz, f);
    std::ostringstream args; args << hex_ptr(clazz) << "," << hex_ptr(f);
    emit("GetStaticObjectField", args.str(), hex_ptr(r));
    return r;
}

WRAP_GET_FIELD(jboolean, Boolean, "%lld")
WRAP_GET_FIELD(jbyte,    Byte,    "%lld")
WRAP_GET_FIELD(jchar,    Char,    "%lld")
WRAP_GET_FIELD(jshort,   Short,   "%lld")
WRAP_GET_FIELD(jint,     Int,     "%lld")
WRAP_GET_FIELD(jlong,    Long,    "%lld")
WRAP_SET_FIELD(jboolean, Boolean, "%lld")
WRAP_SET_FIELD(jbyte,    Byte,    "%lld")
WRAP_SET_FIELD(jchar,    Char,    "%lld")
WRAP_SET_FIELD(jshort,   Short,   "%lld")
WRAP_SET_FIELD(jint,     Int,     "%lld")
WRAP_SET_FIELD(jlong,    Long,    "%lld")
WRAP_GET_STATIC_FIELD(jboolean, Boolean, "%lld")
WRAP_GET_STATIC_FIELD(jbyte,    Byte,    "%lld")
WRAP_GET_STATIC_FIELD(jchar,    Char,    "%lld")
WRAP_GET_STATIC_FIELD(jshort,   Short,   "%lld")
WRAP_GET_STATIC_FIELD(jint,     Int,     "%lld")
WRAP_GET_STATIC_FIELD(jlong,    Long,    "%lld")

// Method-call wrappers: we only cover the va_list / "A" variants, since
// HotSpot dispatches the variadic versions through them anyway. We also
// only wrap the most common variants — extending is mechanical.

#define WRAP_CALL_RET_OBJ(jname, kindprefix)                                                 \
    jobject JNICALL h_##kindprefix##jname##MethodV(JNIEnv* env, jobject obj, jmethodID m,    \
                                                    va_list ap) {                            \
        va_list ap2; va_copy(ap2, ap);                                                       \
        va_list ap3; va_copy(ap3, ap);                                                       \
        jobject r = ORIG(kindprefix##jname##MethodV)(env, obj, m, ap2);                      \
        va_end(ap2);                                                                          \
        std::ostringstream args; args << hex_ptr(obj) << "," << hex_ptr(m)                   \
            << decode_variadic(m, ap3);                                                       \
        va_end(ap3);                                                                          \
        auto ret_str = maybe_track_string_return(env, m, r);                                  \
        emit(#kindprefix #jname "Method", args.str(), hex_ptr(r), m, ret_str, returned_class_metadata(m, r));                  \
        return r;                                                                              \
    }                                                                                          \
    jobject JNICALL h_##kindprefix##jname##MethodA(JNIEnv* env, jobject obj, jmethodID m,    \
                                                    const jvalue* a) {                       \
        jobject r = ORIG(kindprefix##jname##MethodA)(env, obj, m, a);                        \
        std::ostringstream args; args << hex_ptr(obj) << "," << hex_ptr(m)                   \
            << decode_array(m, a);                                                            \
        auto ret_str = maybe_track_string_return(env, m, r);                                  \
        emit(#kindprefix #jname "Method", args.str(), hex_ptr(r), m, ret_str, returned_class_metadata(m, r));                  \
        return r;                                                                              \
    }

#define WRAP_CALL_RET_PRIM(jtype, jname, fmt, kindprefix)                                     \
    jtype JNICALL h_##kindprefix##jname##MethodV(JNIEnv* env, jobject obj, jmethodID m,      \
                                                  va_list ap) {                              \
        va_list ap2; va_copy(ap2, ap);                                                       \
        va_list ap3; va_copy(ap3, ap);                                                       \
        jtype r = ORIG(kindprefix##jname##MethodV)(env, obj, m, ap2);                        \
        va_end(ap2);                                                                          \
        std::string rb = trace_number(r);                      \
        std::ostringstream args; args << hex_ptr(obj) << "," << hex_ptr(m)                   \
            << decode_variadic(m, ap3);                                                       \
        va_end(ap3);                                                                          \
        emit(#kindprefix #jname "Method", args.str(), rb, m);                                   \
        return r;                                                                              \
    }                                                                                          \
    jtype JNICALL h_##kindprefix##jname##MethodA(JNIEnv* env, jobject obj, jmethodID m,      \
                                                  const jvalue* a) {                          \
        jtype r = ORIG(kindprefix##jname##MethodA)(env, obj, m, a);                          \
        std::string rb = trace_number(r);                      \
        std::ostringstream args; args << hex_ptr(obj) << "," << hex_ptr(m)                   \
            << decode_array(m, a);                                                            \
        emit(#kindprefix #jname "Method", args.str(), rb, m);                                   \
        return r;                                                                              \
    }

#define WRAP_CALL_VOID(kindprefix)                                                            \
    void JNICALL h_##kindprefix##VoidMethodV(JNIEnv* env, jobject obj, jmethodID m,           \
                                              va_list ap) {                                   \
        va_list ap2; va_copy(ap2, ap);                                                       \
        va_list ap3; va_copy(ap3, ap);                                                       \
        ORIG(kindprefix##VoidMethodV)(env, obj, m, ap2);                                     \
        va_end(ap2);                                                                          \
        std::ostringstream args; args << hex_ptr(obj) << "," << hex_ptr(m)                   \
            << decode_variadic(m, ap3);                                                       \
        va_end(ap3);                                                                          \
        emit(#kindprefix "VoidMethod", args.str(), "null", m);                                  \
    }                                                                                          \
    void JNICALL h_##kindprefix##VoidMethodA(JNIEnv* env, jobject obj, jmethodID m,           \
                                              const jvalue* a) {                              \
        ORIG(kindprefix##VoidMethodA)(env, obj, m, a);                                       \
        std::ostringstream args; args << hex_ptr(obj) << "," << hex_ptr(m)                   \
            << decode_array(m, a);                                                            \
        emit(#kindprefix "VoidMethod", args.str(), "null", m);                                  \
    }

// Variadic (...) trampolines must forward to V — JNI spec contract.
#define WRAP_CALL_VARIADIC_OBJ(jname, kindprefix)                                             \
    jobject JNICALL h_##kindprefix##jname##Method(JNIEnv* env, jobject obj, jmethodID m,     \
                                                   ...) {                                     \
        va_list ap; va_start(ap, m);                                                          \
        jobject r = h_##kindprefix##jname##MethodV(env, obj, m, ap);                          \
        va_end(ap);                                                                            \
        return r;                                                                              \
    }

#define WRAP_CALL_VARIADIC_PRIM(jtype, jname, kindprefix)                                     \
    jtype JNICALL h_##kindprefix##jname##Method(JNIEnv* env, jobject obj, jmethodID m,       \
                                                 ...) {                                       \
        va_list ap; va_start(ap, m);                                                          \
        jtype r = h_##kindprefix##jname##MethodV(env, obj, m, ap);                            \
        va_end(ap);                                                                            \
        return r;                                                                              \
    }

#define WRAP_CALL_VARIADIC_VOID(kindprefix)                                                   \
    void JNICALL h_##kindprefix##VoidMethod(JNIEnv* env, jobject obj, jmethodID m, ...) {     \
        va_list ap; va_start(ap, m);                                                          \
        h_##kindprefix##VoidMethodV(env, obj, m, ap);                                         \
        va_end(ap);                                                                            \
    }

WRAP_CALL_RET_OBJ(Object, Call)
WRAP_CALL_RET_PRIM(jboolean, Boolean, "%lld", Call)
WRAP_CALL_RET_PRIM(jbyte,    Byte,    "%lld", Call)
WRAP_CALL_RET_PRIM(jchar,    Char,    "%lld", Call)
WRAP_CALL_RET_PRIM(jshort,   Short,   "%lld", Call)
WRAP_CALL_RET_PRIM(jint,     Int,     "%lld", Call)
WRAP_CALL_RET_PRIM(jlong,    Long,    "%lld", Call)
WRAP_CALL_VOID(Call)

WRAP_CALL_VARIADIC_OBJ(Object, Call)
WRAP_CALL_VARIADIC_PRIM(jboolean, Boolean, Call)
WRAP_CALL_VARIADIC_PRIM(jbyte,    Byte,    Call)
WRAP_CALL_VARIADIC_PRIM(jchar,    Char,    Call)
WRAP_CALL_VARIADIC_PRIM(jshort,   Short,   Call)
WRAP_CALL_VARIADIC_PRIM(jint,     Int,     Call)
WRAP_CALL_VARIADIC_PRIM(jlong,    Long,    Call)
WRAP_CALL_VARIADIC_VOID(Call)

// Static-method variants need a jclass receiver, not jobject. Cast the signature.
// We mirror the receiver-as-jclass forms here.
jobject JNICALL h_CallStaticObjectMethodV(JNIEnv* env, jclass c, jmethodID m, va_list ap) {
    va_list ap2; va_copy(ap2, ap);
    va_list ap3; va_copy(ap3, ap);
    jobject r = ORIG(CallStaticObjectMethodV)(env, c, m, ap2);
    va_end(ap2);
    std::ostringstream args; args << hex_ptr(c) << "," << hex_ptr(m) << decode_variadic(m, ap3);
    va_end(ap3);
    auto ret_str = maybe_track_string_return(env, m, r);
    emit("CallStaticObjectMethod", args.str(), hex_ptr(r), m, ret_str, returned_class_metadata(m, r));
    return r;
}
jobject JNICALL h_CallStaticObjectMethod(JNIEnv* env, jclass c, jmethodID m, ...) {
    va_list ap; va_start(ap, m);
    jobject r = h_CallStaticObjectMethodV(env, c, m, ap);
    va_end(ap);
    return r;
}
jint JNICALL h_CallStaticIntMethodV(JNIEnv* env, jclass c, jmethodID m, va_list ap) {
    va_list ap2; va_copy(ap2, ap);
    va_list ap3; va_copy(ap3, ap);
    jint r = ORIG(CallStaticIntMethodV)(env, c, m, ap2);
    va_end(ap2);
    char rb[64]; std::snprintf(rb, sizeof(rb), "%lld", (long long) r);
    std::ostringstream args; args << hex_ptr(c) << "," << hex_ptr(m) << decode_variadic(m, ap3);
    va_end(ap3);
    emit("CallStaticIntMethod", args.str(), rb, m);
    return r;
}
jint JNICALL h_CallStaticIntMethod(JNIEnv* env, jclass c, jmethodID m, ...) {
    va_list ap; va_start(ap, m);
    jint r = h_CallStaticIntMethodV(env, c, m, ap);
    va_end(ap);
    return r;
}
void JNICALL h_CallStaticVoidMethodV(JNIEnv* env, jclass c, jmethodID m, va_list ap) {
    va_list ap2; va_copy(ap2, ap);
    va_list ap3; va_copy(ap3, ap);
    ORIG(CallStaticVoidMethodV)(env, c, m, ap2);
    va_end(ap2);
    std::ostringstream args; args << hex_ptr(c) << "," << hex_ptr(m) << decode_variadic(m, ap3);
    va_end(ap3);
    emit("CallStaticVoidMethod", args.str(), "null", m);
}
void JNICALL h_CallStaticVoidMethod(JNIEnv* env, jclass c, jmethodID m, ...) {
    va_list ap; va_start(ap, m);
    h_CallStaticVoidMethodV(env, c, m, ap);
    va_end(ap);
}

jobject JNICALL h_NewObjectV(JNIEnv* env, jclass c, jmethodID m, va_list ap) {
    va_list ap2; va_copy(ap2, ap);
    va_list ap3; va_copy(ap3, ap);
    jobject r = ORIG(NewObjectV)(env, c, m, ap2);
    va_end(ap2);
    std::ostringstream args; args << hex_ptr(c) << "," << hex_ptr(m) << decode_variadic(m, ap3);
    va_end(ap3);
    emit("NewObject", args.str(), hex_ptr(r), m);
    return r;
}
jobject JNICALL h_NewObject(JNIEnv* env, jclass c, jmethodID m, ...) {
    va_list ap; va_start(ap, m);
    jobject r = h_NewObjectV(env, c, m, ap);
    va_end(ap);
    return r;
}

jint JNICALL h_Throw(JNIEnv* env, jthrowable t) {
    jint r = ORIG(Throw)(env, t);
    std::ostringstream args; args << hex_ptr(t);
    char rb[16]; std::snprintf(rb, sizeof(rb), "%d", r);
    emit("Throw", args.str(), rb);
    return r;
}

jint JNICALL h_ThrowNew(JNIEnv* env, jclass c, const char* m) {
    jint r = ORIG(ThrowNew)(env, c, m);
    std::ostringstream args; args << hex_ptr(c) << "," << esc(m);
    char rb[16]; std::snprintf(rb, sizeof(rb), "%d", r);
    emit("ThrowNew", args.str(), rb);
    return r;
}

// ---------- Type / instanceof / array / alloc / nonvirtual ----------

jboolean JNICALL h_IsInstanceOf(JNIEnv* env, jobject obj, jclass clazz) {
    jboolean r = ORIG(IsInstanceOf)(env, obj, clazz);
    std::ostringstream args; args << hex_ptr(obj) << "," << hex_ptr(clazz);
    char rb[8]; std::snprintf(rb, sizeof(rb), "%d", (int) r);
    emit("IsInstanceOf", args.str(), rb);
    return r;
}

jboolean JNICALL h_IsAssignableFrom(JNIEnv* env, jclass a, jclass b) {
    jboolean r = ORIG(IsAssignableFrom)(env, a, b);
    std::ostringstream args; args << hex_ptr(a) << "," << hex_ptr(b);
    char rb[8]; std::snprintf(rb, sizeof(rb), "%d", (int) r);
    emit("IsAssignableFrom", args.str(), rb);
    return r;
}

jclass JNICALL h_GetObjectClass(JNIEnv* env, jobject obj) {
    jclass r = ORIG(GetObjectClass)(env, obj);
    std::ostringstream args; args << hex_ptr(obj);
    emit("GetObjectClass", args.str(), hex_ptr(r), nullptr, {}, class_metadata(r));
    return r;
}

jclass JNICALL h_GetSuperclass(JNIEnv* env, jclass clazz) {
    jclass r = ORIG(GetSuperclass)(env, clazz);
    std::ostringstream args; args << hex_ptr(clazz);
    emit("GetSuperclass", args.str(), hex_ptr(r), nullptr, {}, class_metadata(r));
    return r;
}

jsize JNICALL h_GetArrayLength(JNIEnv* env, jarray array) {
    jsize r = ORIG(GetArrayLength)(env, array);
    std::ostringstream args; args << hex_ptr(array);
    char rb[16]; std::snprintf(rb, sizeof(rb), "%d", (int) r);
    emit("GetArrayLength", args.str(), rb);
    return r;
}

jobject JNICALL h_AllocObject(JNIEnv* env, jclass clazz) {
    jobject r = ORIG(AllocObject)(env, clazz);
    std::ostringstream args; args << hex_ptr(clazz);
    emit("AllocObject", args.str(), hex_ptr(r));
    return r;
}

// ---------- Array constructors ----------

jobjectArray JNICALL h_NewObjectArray(JNIEnv* env, jsize len, jclass clazz, jobject init) {
    jobjectArray r = ORIG(NewObjectArray)(env, len, clazz, init);
    std::ostringstream args;
    args << len << "," << hex_ptr(clazz) << "," << hex_ptr(init);
    emit("NewObjectArray", args.str(), hex_ptr(r));
    return r;
}

#define WRAP_NEW_PRIM_ARRAY(jname, jtype)                                                 \
    jtype##Array JNICALL h_New##jname##Array(JNIEnv* env, jsize len) {                    \
        jtype##Array r = ORIG(New##jname##Array)(env, len);                               \
        char buf[16]; std::snprintf(buf, sizeof(buf), "%d", (int) len);                   \
        emit("New" #jname "Array", buf, hex_ptr(r));                                      \
        return r;                                                                          \
    }

WRAP_NEW_PRIM_ARRAY(Boolean, jboolean)
WRAP_NEW_PRIM_ARRAY(Byte,    jbyte)
WRAP_NEW_PRIM_ARRAY(Char,    jchar)
WRAP_NEW_PRIM_ARRAY(Short,   jshort)
WRAP_NEW_PRIM_ARRAY(Int,     jint)
WRAP_NEW_PRIM_ARRAY(Long,    jlong)
WRAP_NEW_PRIM_ARRAY(Float,   jfloat)
WRAP_NEW_PRIM_ARRAY(Double,  jdouble)

// ---------- Array element access ----------

jobject JNICALL h_GetObjectArrayElement(JNIEnv* env, jobjectArray arr, jsize index) {
    jobject r = ORIG(GetObjectArrayElement)(env, arr, index);
    std::ostringstream args; args << hex_ptr(arr) << "," << (int) index;
    emit("GetObjectArrayElement", args.str(), hex_ptr(r));
    return r;
}

void JNICALL h_SetObjectArrayElement(JNIEnv* env, jobjectArray arr, jsize index, jobject val) {
    ORIG(SetObjectArrayElement)(env, arr, index, val);
    std::ostringstream args; args << hex_ptr(arr) << "," << (int) index << "," << hex_ptr(val);
    emit("SetObjectArrayElement", args.str(), "null");
}

#define WRAP_GET_ARRAY_REGION(jname, jtype, fmt) \
    void JNICALL h_Get##jname##ArrayRegion(JNIEnv* env, jtype##Array arr, jsize start, jsize len, jtype* buf) { \
        ORIG(Get##jname##ArrayRegion)(env, arr, start, len, buf); \
        std::ostringstream args; args << hex_ptr(arr) << "," << start << "," << len << ","; \
        args << (ORIG(ExceptionCheck)(env) ? "null" : trace_buffer(buf, len)); \
        emit("Get" #jname "ArrayRegion", args.str(), "null"); \
    }
#define WRAP_SET_ARRAY_REGION(jname, jtype, fmt) \
    void JNICALL h_Set##jname##ArrayRegion(JNIEnv* env, jtype##Array arr, jsize start, jsize len, const jtype* buf) { \
        const auto values = trace_buffer(buf, len); \
        ORIG(Set##jname##ArrayRegion)(env, arr, start, len, buf); \
        std::ostringstream args; args << hex_ptr(arr) << "," << start << "," << len << "," << values; \
        emit("Set" #jname "ArrayRegion", args.str(), "null"); \
    }

WRAP_GET_ARRAY_REGION(Boolean, jboolean, "%lld")
WRAP_GET_ARRAY_REGION(Byte,    jbyte,    "%lld")
WRAP_GET_ARRAY_REGION(Char,    jchar,    "%lld")
WRAP_GET_ARRAY_REGION(Short,   jshort,   "%lld")
WRAP_GET_ARRAY_REGION(Int,     jint,     "%lld")
WRAP_GET_ARRAY_REGION(Long,    jlong,    "%lld")
WRAP_GET_ARRAY_REGION(Float,   jfloat,   "%lld")
WRAP_GET_ARRAY_REGION(Double,  jdouble,  "%lld")

WRAP_SET_ARRAY_REGION(Boolean, jboolean, "%lld")
WRAP_SET_ARRAY_REGION(Byte,    jbyte,    "%lld")
WRAP_SET_ARRAY_REGION(Char,    jchar,    "%lld")
WRAP_SET_ARRAY_REGION(Short,   jshort,   "%lld")
WRAP_SET_ARRAY_REGION(Int,     jint,     "%lld")
WRAP_SET_ARRAY_REGION(Long,    jlong,    "%lld")
WRAP_SET_ARRAY_REGION(Float,   jfloat,   "%lld")
WRAP_SET_ARRAY_REGION(Double,  jdouble,  "%lld")

// ---------- Nonvirtual method calls (INVOKESPECIAL for <init>) ----------

void JNICALL h_CallNonvirtualVoidMethodV(JNIEnv* env, jobject obj, jclass cls,
                                          jmethodID m, va_list ap) {
    va_list ap2; va_copy(ap2, ap);
    va_list ap3; va_copy(ap3, ap);
    ORIG(CallNonvirtualVoidMethodV)(env, obj, cls, m, ap2);
    va_end(ap2);
    std::ostringstream args;
    args << hex_ptr(obj) << "," << hex_ptr(cls) << "," << hex_ptr(m) << decode_variadic(m, ap3);
    va_end(ap3);
    emit("CallNonvirtualVoidMethod", args.str(), "null", m);
}

void JNICALL h_CallNonvirtualVoidMethod(JNIEnv* env, jobject obj, jclass cls,
                                         jmethodID m, ...) {
    va_list ap; va_start(ap, m);
    h_CallNonvirtualVoidMethodV(env, obj, cls, m, ap);
    va_end(ap);
}

jobject JNICALL h_CallNonvirtualObjectMethodV(JNIEnv* env, jobject obj, jclass cls,
                                               jmethodID m, va_list ap) {
    va_list ap2; va_copy(ap2, ap);
    va_list ap3; va_copy(ap3, ap);
    jobject r = ORIG(CallNonvirtualObjectMethodV)(env, obj, cls, m, ap2);
    va_end(ap2);
    std::ostringstream args;
    args << hex_ptr(obj) << "," << hex_ptr(cls) << "," << hex_ptr(m) << decode_variadic(m, ap3);
    va_end(ap3);
    auto ret_str = maybe_track_string_return(env, m, r);
    emit("CallNonvirtualObjectMethod", args.str(), hex_ptr(r), m, ret_str, returned_class_metadata(m, r));
    return r;
}

jobject JNICALL h_CallNonvirtualObjectMethod(JNIEnv* env, jobject obj, jclass cls,
                                              jmethodID m, ...) {
    va_list ap; va_start(ap, m);
    jobject r = h_CallNonvirtualObjectMethodV(env, obj, cls, m, ap);
    va_end(ap);
    return r;
}

WRAP_GET_FIELD(jfloat, Float, "")
WRAP_SET_FIELD(jfloat, Float, "")
WRAP_GET_STATIC_FIELD(jfloat, Float, "")
WRAP_CALL_RET_PRIM(jfloat, Float, "", Call)
WRAP_CALL_VARIADIC_PRIM(jfloat, Float, Call)
WRAP_GET_FIELD(jdouble, Double, "")
WRAP_SET_FIELD(jdouble, Double, "")
WRAP_GET_STATIC_FIELD(jdouble, Double, "")
WRAP_CALL_RET_PRIM(jdouble, Double, "", Call)
WRAP_CALL_VARIADIC_PRIM(jdouble, Double, Call)
void JNICALL h_SetStaticObjectField(JNIEnv* env, jclass c, jfieldID f, jobject v) {
    ORIG(SetStaticObjectField)(env,c,f,v);
    emit("SetStaticObjectField", hex_ptr(c)+","+hex_ptr(f)+","+hex_ptr(v), "null");
}
void JNICALL h_SetStaticBooleanField(JNIEnv* env, jclass c, jfieldID f, jboolean v) {
    ORIG(SetStaticBooleanField)(env,c,f,v);
    emit("SetStaticBooleanField", hex_ptr(c)+","+hex_ptr(f)+","+trace_number(v), "null");
}
void JNICALL h_SetStaticByteField(JNIEnv* env, jclass c, jfieldID f, jbyte v) {
    ORIG(SetStaticByteField)(env,c,f,v);
    emit("SetStaticByteField", hex_ptr(c)+","+hex_ptr(f)+","+trace_number(v), "null");
}
void JNICALL h_SetStaticCharField(JNIEnv* env, jclass c, jfieldID f, jchar v) {
    ORIG(SetStaticCharField)(env,c,f,v);
    emit("SetStaticCharField", hex_ptr(c)+","+hex_ptr(f)+","+trace_number(v), "null");
}
void JNICALL h_SetStaticShortField(JNIEnv* env, jclass c, jfieldID f, jshort v) {
    ORIG(SetStaticShortField)(env,c,f,v);
    emit("SetStaticShortField", hex_ptr(c)+","+hex_ptr(f)+","+trace_number(v), "null");
}
void JNICALL h_SetStaticIntField(JNIEnv* env, jclass c, jfieldID f, jint v) {
    ORIG(SetStaticIntField)(env,c,f,v);
    emit("SetStaticIntField", hex_ptr(c)+","+hex_ptr(f)+","+trace_number(v), "null");
}
void JNICALL h_SetStaticLongField(JNIEnv* env, jclass c, jfieldID f, jlong v) {
    ORIG(SetStaticLongField)(env,c,f,v);
    emit("SetStaticLongField", hex_ptr(c)+","+hex_ptr(f)+","+trace_number(v), "null");
}
void JNICALL h_SetStaticFloatField(JNIEnv* env, jclass c, jfieldID f, jfloat v) {
    ORIG(SetStaticFloatField)(env,c,f,v);
    emit("SetStaticFloatField", hex_ptr(c)+","+hex_ptr(f)+","+trace_number(v), "null");
}
void JNICALL h_SetStaticDoubleField(JNIEnv* env, jclass c, jfieldID f, jdouble v) {
    ORIG(SetStaticDoubleField)(env,c,f,v);
    emit("SetStaticDoubleField", hex_ptr(c)+","+hex_ptr(f)+","+trace_number(v), "null");
}
jobject JNICALL h_CallStaticObjectMethodA(JNIEnv* env, jclass c, jmethodID m, const jvalue* a) {
    auto decoded=decode_array(m,a);
    jobject r = ORIG(CallStaticObjectMethodA)(env,c,m,a);
    emit("CallStaticObjectMethod", hex_ptr(c)+","+hex_ptr(m)+decoded, hex_ptr(r), m);
    return r;
}
jboolean JNICALL h_CallStaticBooleanMethodV(JNIEnv* env, jclass c, jmethodID m, va_list ap) {
    va_list copy; va_copy(copy,ap); auto decoded=decode_variadic(m,copy); va_end(copy);
    jboolean r = ORIG(CallStaticBooleanMethodV)(env,c,m,ap);
    emit("CallStaticBooleanMethod", hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jboolean JNICALL h_CallStaticBooleanMethodA(JNIEnv* env, jclass c, jmethodID m, const jvalue* a) {
    auto decoded=decode_array(m,a);
    jboolean r = ORIG(CallStaticBooleanMethodA)(env,c,m,a);
    emit("CallStaticBooleanMethod", hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jboolean JNICALL h_CallStaticBooleanMethod(JNIEnv* env, jclass c, jmethodID m, ...) {
    va_list ap; va_start(ap,m); jboolean r = h_CallStaticBooleanMethodV(env,c,m,ap); va_end(ap); return r;
}
jbyte JNICALL h_CallStaticByteMethodV(JNIEnv* env, jclass c, jmethodID m, va_list ap) {
    va_list copy; va_copy(copy,ap); auto decoded=decode_variadic(m,copy); va_end(copy);
    jbyte r = ORIG(CallStaticByteMethodV)(env,c,m,ap);
    emit("CallStaticByteMethod", hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jbyte JNICALL h_CallStaticByteMethodA(JNIEnv* env, jclass c, jmethodID m, const jvalue* a) {
    auto decoded=decode_array(m,a);
    jbyte r = ORIG(CallStaticByteMethodA)(env,c,m,a);
    emit("CallStaticByteMethod", hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jbyte JNICALL h_CallStaticByteMethod(JNIEnv* env, jclass c, jmethodID m, ...) {
    va_list ap; va_start(ap,m); jbyte r = h_CallStaticByteMethodV(env,c,m,ap); va_end(ap); return r;
}
jchar JNICALL h_CallStaticCharMethodV(JNIEnv* env, jclass c, jmethodID m, va_list ap) {
    va_list copy; va_copy(copy,ap); auto decoded=decode_variadic(m,copy); va_end(copy);
    jchar r = ORIG(CallStaticCharMethodV)(env,c,m,ap);
    emit("CallStaticCharMethod", hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jchar JNICALL h_CallStaticCharMethodA(JNIEnv* env, jclass c, jmethodID m, const jvalue* a) {
    auto decoded=decode_array(m,a);
    jchar r = ORIG(CallStaticCharMethodA)(env,c,m,a);
    emit("CallStaticCharMethod", hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jchar JNICALL h_CallStaticCharMethod(JNIEnv* env, jclass c, jmethodID m, ...) {
    va_list ap; va_start(ap,m); jchar r = h_CallStaticCharMethodV(env,c,m,ap); va_end(ap); return r;
}
jshort JNICALL h_CallStaticShortMethodV(JNIEnv* env, jclass c, jmethodID m, va_list ap) {
    va_list copy; va_copy(copy,ap); auto decoded=decode_variadic(m,copy); va_end(copy);
    jshort r = ORIG(CallStaticShortMethodV)(env,c,m,ap);
    emit("CallStaticShortMethod", hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jshort JNICALL h_CallStaticShortMethodA(JNIEnv* env, jclass c, jmethodID m, const jvalue* a) {
    auto decoded=decode_array(m,a);
    jshort r = ORIG(CallStaticShortMethodA)(env,c,m,a);
    emit("CallStaticShortMethod", hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jshort JNICALL h_CallStaticShortMethod(JNIEnv* env, jclass c, jmethodID m, ...) {
    va_list ap; va_start(ap,m); jshort r = h_CallStaticShortMethodV(env,c,m,ap); va_end(ap); return r;
}
jint JNICALL h_CallStaticIntMethodA(JNIEnv* env, jclass c, jmethodID m, const jvalue* a) {
    auto decoded=decode_array(m,a);
    jint r = ORIG(CallStaticIntMethodA)(env,c,m,a);
    emit("CallStaticIntMethod", hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jlong JNICALL h_CallStaticLongMethodV(JNIEnv* env, jclass c, jmethodID m, va_list ap) {
    va_list copy; va_copy(copy,ap); auto decoded=decode_variadic(m,copy); va_end(copy);
    jlong r = ORIG(CallStaticLongMethodV)(env,c,m,ap);
    emit("CallStaticLongMethod", hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jlong JNICALL h_CallStaticLongMethodA(JNIEnv* env, jclass c, jmethodID m, const jvalue* a) {
    auto decoded=decode_array(m,a);
    jlong r = ORIG(CallStaticLongMethodA)(env,c,m,a);
    emit("CallStaticLongMethod", hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jlong JNICALL h_CallStaticLongMethod(JNIEnv* env, jclass c, jmethodID m, ...) {
    va_list ap; va_start(ap,m); jlong r = h_CallStaticLongMethodV(env,c,m,ap); va_end(ap); return r;
}
jfloat JNICALL h_CallStaticFloatMethodV(JNIEnv* env, jclass c, jmethodID m, va_list ap) {
    va_list copy; va_copy(copy,ap); auto decoded=decode_variadic(m,copy); va_end(copy);
    jfloat r = ORIG(CallStaticFloatMethodV)(env,c,m,ap);
    emit("CallStaticFloatMethod", hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jfloat JNICALL h_CallStaticFloatMethodA(JNIEnv* env, jclass c, jmethodID m, const jvalue* a) {
    auto decoded=decode_array(m,a);
    jfloat r = ORIG(CallStaticFloatMethodA)(env,c,m,a);
    emit("CallStaticFloatMethod", hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jfloat JNICALL h_CallStaticFloatMethod(JNIEnv* env, jclass c, jmethodID m, ...) {
    va_list ap; va_start(ap,m); jfloat r = h_CallStaticFloatMethodV(env,c,m,ap); va_end(ap); return r;
}
jdouble JNICALL h_CallStaticDoubleMethodV(JNIEnv* env, jclass c, jmethodID m, va_list ap) {
    va_list copy; va_copy(copy,ap); auto decoded=decode_variadic(m,copy); va_end(copy);
    jdouble r = ORIG(CallStaticDoubleMethodV)(env,c,m,ap);
    emit("CallStaticDoubleMethod", hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jdouble JNICALL h_CallStaticDoubleMethodA(JNIEnv* env, jclass c, jmethodID m, const jvalue* a) {
    auto decoded=decode_array(m,a);
    jdouble r = ORIG(CallStaticDoubleMethodA)(env,c,m,a);
    emit("CallStaticDoubleMethod", hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jdouble JNICALL h_CallStaticDoubleMethod(JNIEnv* env, jclass c, jmethodID m, ...) {
    va_list ap; va_start(ap,m); jdouble r = h_CallStaticDoubleMethodV(env,c,m,ap); va_end(ap); return r;
}
void JNICALL h_CallStaticVoidMethodA(JNIEnv* env, jclass c, jmethodID m, const jvalue* a) {
    auto decoded=decode_array(m,a);
    ORIG(CallStaticVoidMethodA)(env,c,m,a);
    emit("CallStaticVoidMethod", hex_ptr(c)+","+hex_ptr(m)+decoded, "null", m);
}
jobject JNICALL h_CallNonvirtualObjectMethodA(JNIEnv* env, jobject obj, jclass c, jmethodID m, const jvalue* a) {
    auto decoded=decode_array(m,a);
    jobject r = ORIG(CallNonvirtualObjectMethodA)(env,obj,c,m,a);
    emit("CallNonvirtualObjectMethod", hex_ptr(obj)+","+hex_ptr(c)+","+hex_ptr(m)+decoded, hex_ptr(r), m);
    return r;
}
jboolean JNICALL h_CallNonvirtualBooleanMethodV(JNIEnv* env, jobject obj, jclass c, jmethodID m, va_list ap) {
    va_list copy; va_copy(copy,ap); auto decoded=decode_variadic(m,copy); va_end(copy);
    jboolean r = ORIG(CallNonvirtualBooleanMethodV)(env,obj,c,m,ap);
    emit("CallNonvirtualBooleanMethod", hex_ptr(obj)+","+hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jboolean JNICALL h_CallNonvirtualBooleanMethodA(JNIEnv* env, jobject obj, jclass c, jmethodID m, const jvalue* a) {
    auto decoded=decode_array(m,a);
    jboolean r = ORIG(CallNonvirtualBooleanMethodA)(env,obj,c,m,a);
    emit("CallNonvirtualBooleanMethod", hex_ptr(obj)+","+hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jboolean JNICALL h_CallNonvirtualBooleanMethod(JNIEnv* env, jobject obj, jclass c, jmethodID m, ...) {
    va_list ap; va_start(ap,m); jboolean r = h_CallNonvirtualBooleanMethodV(env,obj,c,m,ap); va_end(ap); return r;
}
jbyte JNICALL h_CallNonvirtualByteMethodV(JNIEnv* env, jobject obj, jclass c, jmethodID m, va_list ap) {
    va_list copy; va_copy(copy,ap); auto decoded=decode_variadic(m,copy); va_end(copy);
    jbyte r = ORIG(CallNonvirtualByteMethodV)(env,obj,c,m,ap);
    emit("CallNonvirtualByteMethod", hex_ptr(obj)+","+hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jbyte JNICALL h_CallNonvirtualByteMethodA(JNIEnv* env, jobject obj, jclass c, jmethodID m, const jvalue* a) {
    auto decoded=decode_array(m,a);
    jbyte r = ORIG(CallNonvirtualByteMethodA)(env,obj,c,m,a);
    emit("CallNonvirtualByteMethod", hex_ptr(obj)+","+hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jbyte JNICALL h_CallNonvirtualByteMethod(JNIEnv* env, jobject obj, jclass c, jmethodID m, ...) {
    va_list ap; va_start(ap,m); jbyte r = h_CallNonvirtualByteMethodV(env,obj,c,m,ap); va_end(ap); return r;
}
jchar JNICALL h_CallNonvirtualCharMethodV(JNIEnv* env, jobject obj, jclass c, jmethodID m, va_list ap) {
    va_list copy; va_copy(copy,ap); auto decoded=decode_variadic(m,copy); va_end(copy);
    jchar r = ORIG(CallNonvirtualCharMethodV)(env,obj,c,m,ap);
    emit("CallNonvirtualCharMethod", hex_ptr(obj)+","+hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jchar JNICALL h_CallNonvirtualCharMethodA(JNIEnv* env, jobject obj, jclass c, jmethodID m, const jvalue* a) {
    auto decoded=decode_array(m,a);
    jchar r = ORIG(CallNonvirtualCharMethodA)(env,obj,c,m,a);
    emit("CallNonvirtualCharMethod", hex_ptr(obj)+","+hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jchar JNICALL h_CallNonvirtualCharMethod(JNIEnv* env, jobject obj, jclass c, jmethodID m, ...) {
    va_list ap; va_start(ap,m); jchar r = h_CallNonvirtualCharMethodV(env,obj,c,m,ap); va_end(ap); return r;
}
jshort JNICALL h_CallNonvirtualShortMethodV(JNIEnv* env, jobject obj, jclass c, jmethodID m, va_list ap) {
    va_list copy; va_copy(copy,ap); auto decoded=decode_variadic(m,copy); va_end(copy);
    jshort r = ORIG(CallNonvirtualShortMethodV)(env,obj,c,m,ap);
    emit("CallNonvirtualShortMethod", hex_ptr(obj)+","+hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jshort JNICALL h_CallNonvirtualShortMethodA(JNIEnv* env, jobject obj, jclass c, jmethodID m, const jvalue* a) {
    auto decoded=decode_array(m,a);
    jshort r = ORIG(CallNonvirtualShortMethodA)(env,obj,c,m,a);
    emit("CallNonvirtualShortMethod", hex_ptr(obj)+","+hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jshort JNICALL h_CallNonvirtualShortMethod(JNIEnv* env, jobject obj, jclass c, jmethodID m, ...) {
    va_list ap; va_start(ap,m); jshort r = h_CallNonvirtualShortMethodV(env,obj,c,m,ap); va_end(ap); return r;
}
jint JNICALL h_CallNonvirtualIntMethodV(JNIEnv* env, jobject obj, jclass c, jmethodID m, va_list ap) {
    va_list copy; va_copy(copy,ap); auto decoded=decode_variadic(m,copy); va_end(copy);
    jint r = ORIG(CallNonvirtualIntMethodV)(env,obj,c,m,ap);
    emit("CallNonvirtualIntMethod", hex_ptr(obj)+","+hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jint JNICALL h_CallNonvirtualIntMethodA(JNIEnv* env, jobject obj, jclass c, jmethodID m, const jvalue* a) {
    auto decoded=decode_array(m,a);
    jint r = ORIG(CallNonvirtualIntMethodA)(env,obj,c,m,a);
    emit("CallNonvirtualIntMethod", hex_ptr(obj)+","+hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jint JNICALL h_CallNonvirtualIntMethod(JNIEnv* env, jobject obj, jclass c, jmethodID m, ...) {
    va_list ap; va_start(ap,m); jint r = h_CallNonvirtualIntMethodV(env,obj,c,m,ap); va_end(ap); return r;
}
jlong JNICALL h_CallNonvirtualLongMethodV(JNIEnv* env, jobject obj, jclass c, jmethodID m, va_list ap) {
    va_list copy; va_copy(copy,ap); auto decoded=decode_variadic(m,copy); va_end(copy);
    jlong r = ORIG(CallNonvirtualLongMethodV)(env,obj,c,m,ap);
    emit("CallNonvirtualLongMethod", hex_ptr(obj)+","+hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jlong JNICALL h_CallNonvirtualLongMethodA(JNIEnv* env, jobject obj, jclass c, jmethodID m, const jvalue* a) {
    auto decoded=decode_array(m,a);
    jlong r = ORIG(CallNonvirtualLongMethodA)(env,obj,c,m,a);
    emit("CallNonvirtualLongMethod", hex_ptr(obj)+","+hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jlong JNICALL h_CallNonvirtualLongMethod(JNIEnv* env, jobject obj, jclass c, jmethodID m, ...) {
    va_list ap; va_start(ap,m); jlong r = h_CallNonvirtualLongMethodV(env,obj,c,m,ap); va_end(ap); return r;
}
jfloat JNICALL h_CallNonvirtualFloatMethodV(JNIEnv* env, jobject obj, jclass c, jmethodID m, va_list ap) {
    va_list copy; va_copy(copy,ap); auto decoded=decode_variadic(m,copy); va_end(copy);
    jfloat r = ORIG(CallNonvirtualFloatMethodV)(env,obj,c,m,ap);
    emit("CallNonvirtualFloatMethod", hex_ptr(obj)+","+hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jfloat JNICALL h_CallNonvirtualFloatMethodA(JNIEnv* env, jobject obj, jclass c, jmethodID m, const jvalue* a) {
    auto decoded=decode_array(m,a);
    jfloat r = ORIG(CallNonvirtualFloatMethodA)(env,obj,c,m,a);
    emit("CallNonvirtualFloatMethod", hex_ptr(obj)+","+hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jfloat JNICALL h_CallNonvirtualFloatMethod(JNIEnv* env, jobject obj, jclass c, jmethodID m, ...) {
    va_list ap; va_start(ap,m); jfloat r = h_CallNonvirtualFloatMethodV(env,obj,c,m,ap); va_end(ap); return r;
}
jdouble JNICALL h_CallNonvirtualDoubleMethodV(JNIEnv* env, jobject obj, jclass c, jmethodID m, va_list ap) {
    va_list copy; va_copy(copy,ap); auto decoded=decode_variadic(m,copy); va_end(copy);
    jdouble r = ORIG(CallNonvirtualDoubleMethodV)(env,obj,c,m,ap);
    emit("CallNonvirtualDoubleMethod", hex_ptr(obj)+","+hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jdouble JNICALL h_CallNonvirtualDoubleMethodA(JNIEnv* env, jobject obj, jclass c, jmethodID m, const jvalue* a) {
    auto decoded=decode_array(m,a);
    jdouble r = ORIG(CallNonvirtualDoubleMethodA)(env,obj,c,m,a);
    emit("CallNonvirtualDoubleMethod", hex_ptr(obj)+","+hex_ptr(c)+","+hex_ptr(m)+decoded, trace_number(r), m);
    return r;
}
jdouble JNICALL h_CallNonvirtualDoubleMethod(JNIEnv* env, jobject obj, jclass c, jmethodID m, ...) {
    va_list ap; va_start(ap,m); jdouble r = h_CallNonvirtualDoubleMethodV(env,obj,c,m,ap); va_end(ap); return r;
}
void JNICALL h_CallNonvirtualVoidMethodA(JNIEnv* env, jobject obj, jclass c, jmethodID m, const jvalue* a) {
    auto decoded=decode_array(m,a);
    ORIG(CallNonvirtualVoidMethodA)(env,obj,c,m,a);
    emit("CallNonvirtualVoidMethod", hex_ptr(obj)+","+hex_ptr(c)+","+hex_ptr(m)+decoded, "null", m);
}
jboolean JNICALL h_ExceptionCheck(JNIEnv* env) { auto r=ORIG(ExceptionCheck)(env); emit("ExceptionCheck", "", trace_number(r)); return r; }
jthrowable JNICALL h_ExceptionOccurred(JNIEnv* env) { auto r=ORIG(ExceptionOccurred)(env); emit("ExceptionOccurred", "", hex_ptr(r)); return r; }
jint JNICALL h_MonitorEnter(JNIEnv* env, jobject obj) { auto r=ORIG(MonitorEnter)(env,obj); emit("MonitorEnter", hex_ptr(obj), trace_number(r)); return r; }
jint JNICALL h_MonitorExit(JNIEnv* env, jobject obj) { auto r=ORIG(MonitorExit)(env,obj); emit("MonitorExit", hex_ptr(obj), trace_number(r)); return r; }
void JNICALL h_ExceptionClear(JNIEnv* env) { ORIG(ExceptionClear)(env); emit("ExceptionClear", "", "null"); }
jobject JNICALL h_NewObjectA(JNIEnv* env, jclass c, jmethodID m, const jvalue* a) {
    auto decoded=decode_array(m,a); auto r=ORIG(NewObjectA)(env,c,m,a);
    emit("NewObject",hex_ptr(c)+","+hex_ptr(m)+decoded,hex_ptr(r),m); return r;
}

jboolean* JNICALL h_GetBooleanArrayElements(JNIEnv* env, jbooleanArray arr, jboolean* copy) {
    auto r=ORIG(GetBooleanArrayElements)(env,arr,copy);
    if (r && !ORIG(ExceptionCheck)(env)) {
        auto len=ORIG(GetArrayLength)(env,arr);
        emit("GetBooleanArrayElements",hex_ptr(arr)+","+trace_number(len),trace_buffer(r,len));
    }
    return r;
}
void JNICALL h_ReleaseBooleanArrayElements(JNIEnv* env, jbooleanArray arr, jboolean* buf, jint mode) {
    // Pending exceptions permit release, but not an extra GetArrayLength call.
    std::string values="null";
    if (buf && !ORIG(ExceptionCheck)(env)) values=trace_buffer(buf,ORIG(GetArrayLength)(env,arr));
    ORIG(ReleaseBooleanArrayElements)(env,arr,buf,mode);
    emit("ReleaseBooleanArrayElements",hex_ptr(arr)+","+trace_number(mode)+","+values,"null");
}
jbyte* JNICALL h_GetByteArrayElements(JNIEnv* env, jbyteArray arr, jboolean* copy) {
    auto r=ORIG(GetByteArrayElements)(env,arr,copy);
    if (r && !ORIG(ExceptionCheck)(env)) {
        auto len=ORIG(GetArrayLength)(env,arr);
        emit("GetByteArrayElements",hex_ptr(arr)+","+trace_number(len),trace_buffer(r,len));
    }
    return r;
}
void JNICALL h_ReleaseByteArrayElements(JNIEnv* env, jbyteArray arr, jbyte* buf, jint mode) {
    // Pending exceptions permit release, but not an extra GetArrayLength call.
    std::string values="null";
    if (buf && !ORIG(ExceptionCheck)(env)) values=trace_buffer(buf,ORIG(GetArrayLength)(env,arr));
    ORIG(ReleaseByteArrayElements)(env,arr,buf,mode);
    emit("ReleaseByteArrayElements",hex_ptr(arr)+","+trace_number(mode)+","+values,"null");
}
jchar* JNICALL h_GetCharArrayElements(JNIEnv* env, jcharArray arr, jboolean* copy) {
    auto r=ORIG(GetCharArrayElements)(env,arr,copy);
    if (r && !ORIG(ExceptionCheck)(env)) {
        auto len=ORIG(GetArrayLength)(env,arr);
        emit("GetCharArrayElements",hex_ptr(arr)+","+trace_number(len),trace_buffer(r,len));
    }
    return r;
}
void JNICALL h_ReleaseCharArrayElements(JNIEnv* env, jcharArray arr, jchar* buf, jint mode) {
    // Pending exceptions permit release, but not an extra GetArrayLength call.
    std::string values="null";
    if (buf && !ORIG(ExceptionCheck)(env)) values=trace_buffer(buf,ORIG(GetArrayLength)(env,arr));
    ORIG(ReleaseCharArrayElements)(env,arr,buf,mode);
    emit("ReleaseCharArrayElements",hex_ptr(arr)+","+trace_number(mode)+","+values,"null");
}
jshort* JNICALL h_GetShortArrayElements(JNIEnv* env, jshortArray arr, jboolean* copy) {
    auto r=ORIG(GetShortArrayElements)(env,arr,copy);
    if (r && !ORIG(ExceptionCheck)(env)) {
        auto len=ORIG(GetArrayLength)(env,arr);
        emit("GetShortArrayElements",hex_ptr(arr)+","+trace_number(len),trace_buffer(r,len));
    }
    return r;
}
void JNICALL h_ReleaseShortArrayElements(JNIEnv* env, jshortArray arr, jshort* buf, jint mode) {
    // Pending exceptions permit release, but not an extra GetArrayLength call.
    std::string values="null";
    if (buf && !ORIG(ExceptionCheck)(env)) values=trace_buffer(buf,ORIG(GetArrayLength)(env,arr));
    ORIG(ReleaseShortArrayElements)(env,arr,buf,mode);
    emit("ReleaseShortArrayElements",hex_ptr(arr)+","+trace_number(mode)+","+values,"null");
}
jint* JNICALL h_GetIntArrayElements(JNIEnv* env, jintArray arr, jboolean* copy) {
    auto r=ORIG(GetIntArrayElements)(env,arr,copy);
    if (r && !ORIG(ExceptionCheck)(env)) {
        auto len=ORIG(GetArrayLength)(env,arr);
        emit("GetIntArrayElements",hex_ptr(arr)+","+trace_number(len),trace_buffer(r,len));
    }
    return r;
}
void JNICALL h_ReleaseIntArrayElements(JNIEnv* env, jintArray arr, jint* buf, jint mode) {
    // Pending exceptions permit release, but not an extra GetArrayLength call.
    std::string values="null";
    if (buf && !ORIG(ExceptionCheck)(env)) values=trace_buffer(buf,ORIG(GetArrayLength)(env,arr));
    ORIG(ReleaseIntArrayElements)(env,arr,buf,mode);
    emit("ReleaseIntArrayElements",hex_ptr(arr)+","+trace_number(mode)+","+values,"null");
}
jlong* JNICALL h_GetLongArrayElements(JNIEnv* env, jlongArray arr, jboolean* copy) {
    auto r=ORIG(GetLongArrayElements)(env,arr,copy);
    if (r && !ORIG(ExceptionCheck)(env)) {
        auto len=ORIG(GetArrayLength)(env,arr);
        emit("GetLongArrayElements",hex_ptr(arr)+","+trace_number(len),trace_buffer(r,len));
    }
    return r;
}
void JNICALL h_ReleaseLongArrayElements(JNIEnv* env, jlongArray arr, jlong* buf, jint mode) {
    // Pending exceptions permit release, but not an extra GetArrayLength call.
    std::string values="null";
    if (buf && !ORIG(ExceptionCheck)(env)) values=trace_buffer(buf,ORIG(GetArrayLength)(env,arr));
    ORIG(ReleaseLongArrayElements)(env,arr,buf,mode);
    emit("ReleaseLongArrayElements",hex_ptr(arr)+","+trace_number(mode)+","+values,"null");
}
jfloat* JNICALL h_GetFloatArrayElements(JNIEnv* env, jfloatArray arr, jboolean* copy) {
    auto r=ORIG(GetFloatArrayElements)(env,arr,copy);
    if (r && !ORIG(ExceptionCheck)(env)) {
        auto len=ORIG(GetArrayLength)(env,arr);
        emit("GetFloatArrayElements",hex_ptr(arr)+","+trace_number(len),trace_buffer(r,len));
    }
    return r;
}
void JNICALL h_ReleaseFloatArrayElements(JNIEnv* env, jfloatArray arr, jfloat* buf, jint mode) {
    // Pending exceptions permit release, but not an extra GetArrayLength call.
    std::string values="null";
    if (buf && !ORIG(ExceptionCheck)(env)) values=trace_buffer(buf,ORIG(GetArrayLength)(env,arr));
    ORIG(ReleaseFloatArrayElements)(env,arr,buf,mode);
    emit("ReleaseFloatArrayElements",hex_ptr(arr)+","+trace_number(mode)+","+values,"null");
}
jdouble* JNICALL h_GetDoubleArrayElements(JNIEnv* env, jdoubleArray arr, jboolean* copy) {
    auto r=ORIG(GetDoubleArrayElements)(env,arr,copy);
    if (r && !ORIG(ExceptionCheck)(env)) {
        auto len=ORIG(GetArrayLength)(env,arr);
        emit("GetDoubleArrayElements",hex_ptr(arr)+","+trace_number(len),trace_buffer(r,len));
    }
    return r;
}
void JNICALL h_ReleaseDoubleArrayElements(JNIEnv* env, jdoubleArray arr, jdouble* buf, jint mode) {
    // Pending exceptions permit release, but not an extra GetArrayLength call.
    std::string values="null";
    if (buf && !ORIG(ExceptionCheck)(env)) values=trace_buffer(buf,ORIG(GetArrayLength)(env,arr));
    ORIG(ReleaseDoubleArrayElements)(env,arr,buf,mode);
    emit("ReleaseDoubleArrayElements",hex_ptr(arr)+","+trace_number(mode)+","+values,"null");
}
jstring JNICALL h_NewString(JNIEnv* env, const jchar* chars, jsize len) {
    auto r=ORIG(NewString)(env,chars,len);
    emit("NewString",trace_buffer(chars,len),hex_ptr(r)); return r;
}
const jchar* JNICALL h_GetStringChars(JNIEnv* env, jstring str, jboolean* copy) {
    auto r=ORIG(GetStringChars)(env,str,copy);
    if(r && !ORIG(ExceptionCheck)(env)) emit("GetStringChars",hex_ptr(str),trace_buffer(r,ORIG(GetStringLength)(env,str)));
    return r;
}
void JNICALL h_ReleaseStringChars(JNIEnv* env,jstring str,const jchar* chars) {
    ORIG(ReleaseStringChars)(env,str,chars); emit("ReleaseStringChars",hex_ptr(str),"null");
}
const char* JNICALL h_GetStringUTFChars(JNIEnv* env,jstring str,jboolean* copy) {
    auto r=ORIG(GetStringUTFChars)(env,str,copy);
    emit("GetStringUTFChars",hex_ptr(str),r ? esc(r) : "null"); return r;
}
void JNICALL h_ReleaseStringUTFChars(JNIEnv* env,jstring str,const char* chars) {
    ORIG(ReleaseStringUTFChars)(env,str,chars); emit("ReleaseStringUTFChars",hex_ptr(str),"null");
}
jsize JNICALL h_GetStringLength(JNIEnv* env,jstring str) { auto r=ORIG(GetStringLength)(env,str); emit("GetStringLength",hex_ptr(str),trace_number(r)); return r; }
jsize JNICALL h_GetStringUTFLength(JNIEnv* env,jstring str) { auto r=ORIG(GetStringUTFLength)(env,str); emit("GetStringUTFLength",hex_ptr(str),trace_number(r)); return r; }

void build_hook_table() {
    g_hooked = new JNINativeInterface_(*g_original);
    g_hooked->GetBooleanArrayElements = h_GetBooleanArrayElements;
    g_hooked->ReleaseBooleanArrayElements = h_ReleaseBooleanArrayElements;
    g_hooked->GetByteArrayElements = h_GetByteArrayElements;
    g_hooked->ReleaseByteArrayElements = h_ReleaseByteArrayElements;
    g_hooked->GetCharArrayElements = h_GetCharArrayElements;
    g_hooked->ReleaseCharArrayElements = h_ReleaseCharArrayElements;
    g_hooked->GetShortArrayElements = h_GetShortArrayElements;
    g_hooked->ReleaseShortArrayElements = h_ReleaseShortArrayElements;
    g_hooked->GetIntArrayElements = h_GetIntArrayElements;
    g_hooked->ReleaseIntArrayElements = h_ReleaseIntArrayElements;
    g_hooked->GetLongArrayElements = h_GetLongArrayElements;
    g_hooked->ReleaseLongArrayElements = h_ReleaseLongArrayElements;
    g_hooked->GetFloatArrayElements = h_GetFloatArrayElements;
    g_hooked->ReleaseFloatArrayElements = h_ReleaseFloatArrayElements;
    g_hooked->GetDoubleArrayElements = h_GetDoubleArrayElements;
    g_hooked->ReleaseDoubleArrayElements = h_ReleaseDoubleArrayElements;
    g_hooked->NewString = h_NewString;
    g_hooked->GetStringChars = h_GetStringChars;
    g_hooked->ReleaseStringChars = h_ReleaseStringChars;
    g_hooked->GetStringUTFChars = h_GetStringUTFChars;
    g_hooked->ReleaseStringUTFChars = h_ReleaseStringUTFChars;
    g_hooked->GetStringLength = h_GetStringLength;
    g_hooked->GetStringUTFLength = h_GetStringUTFLength;
    g_hooked->GetFloatField = h_GetFloatField;
    g_hooked->SetFloatField = h_SetFloatField;
    g_hooked->GetStaticFloatField = h_GetStaticFloatField;
    g_hooked->CallFloatMethod = h_CallFloatMethod;
    g_hooked->CallFloatMethodV = h_CallFloatMethodV;
    g_hooked->CallFloatMethodA = h_CallFloatMethodA;
    g_hooked->GetDoubleField = h_GetDoubleField;
    g_hooked->SetDoubleField = h_SetDoubleField;
    g_hooked->GetStaticDoubleField = h_GetStaticDoubleField;
    g_hooked->CallDoubleMethod = h_CallDoubleMethod;
    g_hooked->CallDoubleMethodV = h_CallDoubleMethodV;
    g_hooked->CallDoubleMethodA = h_CallDoubleMethodA;
    g_hooked->SetStaticObjectField = h_SetStaticObjectField;
    g_hooked->SetStaticBooleanField = h_SetStaticBooleanField;
    g_hooked->SetStaticByteField = h_SetStaticByteField;
    g_hooked->SetStaticCharField = h_SetStaticCharField;
    g_hooked->SetStaticShortField = h_SetStaticShortField;
    g_hooked->SetStaticIntField = h_SetStaticIntField;
    g_hooked->SetStaticLongField = h_SetStaticLongField;
    g_hooked->SetStaticFloatField = h_SetStaticFloatField;
    g_hooked->SetStaticDoubleField = h_SetStaticDoubleField;
    g_hooked->CallStaticObjectMethodA = h_CallStaticObjectMethodA;
    g_hooked->CallStaticBooleanMethodV = h_CallStaticBooleanMethodV;
    g_hooked->CallStaticBooleanMethodA = h_CallStaticBooleanMethodA;
    g_hooked->CallStaticBooleanMethod = h_CallStaticBooleanMethod;
    g_hooked->CallStaticByteMethodV = h_CallStaticByteMethodV;
    g_hooked->CallStaticByteMethodA = h_CallStaticByteMethodA;
    g_hooked->CallStaticByteMethod = h_CallStaticByteMethod;
    g_hooked->CallStaticCharMethodV = h_CallStaticCharMethodV;
    g_hooked->CallStaticCharMethodA = h_CallStaticCharMethodA;
    g_hooked->CallStaticCharMethod = h_CallStaticCharMethod;
    g_hooked->CallStaticShortMethodV = h_CallStaticShortMethodV;
    g_hooked->CallStaticShortMethodA = h_CallStaticShortMethodA;
    g_hooked->CallStaticShortMethod = h_CallStaticShortMethod;
    g_hooked->CallStaticIntMethodA = h_CallStaticIntMethodA;
    g_hooked->CallStaticLongMethodV = h_CallStaticLongMethodV;
    g_hooked->CallStaticLongMethodA = h_CallStaticLongMethodA;
    g_hooked->CallStaticLongMethod = h_CallStaticLongMethod;
    g_hooked->CallStaticFloatMethodV = h_CallStaticFloatMethodV;
    g_hooked->CallStaticFloatMethodA = h_CallStaticFloatMethodA;
    g_hooked->CallStaticFloatMethod = h_CallStaticFloatMethod;
    g_hooked->CallStaticDoubleMethodV = h_CallStaticDoubleMethodV;
    g_hooked->CallStaticDoubleMethodA = h_CallStaticDoubleMethodA;
    g_hooked->CallStaticDoubleMethod = h_CallStaticDoubleMethod;
    g_hooked->CallStaticVoidMethodA = h_CallStaticVoidMethodA;
    g_hooked->CallNonvirtualObjectMethodA = h_CallNonvirtualObjectMethodA;
    g_hooked->CallNonvirtualBooleanMethodV = h_CallNonvirtualBooleanMethodV;
    g_hooked->CallNonvirtualBooleanMethodA = h_CallNonvirtualBooleanMethodA;
    g_hooked->CallNonvirtualBooleanMethod = h_CallNonvirtualBooleanMethod;
    g_hooked->CallNonvirtualByteMethodV = h_CallNonvirtualByteMethodV;
    g_hooked->CallNonvirtualByteMethodA = h_CallNonvirtualByteMethodA;
    g_hooked->CallNonvirtualByteMethod = h_CallNonvirtualByteMethod;
    g_hooked->CallNonvirtualCharMethodV = h_CallNonvirtualCharMethodV;
    g_hooked->CallNonvirtualCharMethodA = h_CallNonvirtualCharMethodA;
    g_hooked->CallNonvirtualCharMethod = h_CallNonvirtualCharMethod;
    g_hooked->CallNonvirtualShortMethodV = h_CallNonvirtualShortMethodV;
    g_hooked->CallNonvirtualShortMethodA = h_CallNonvirtualShortMethodA;
    g_hooked->CallNonvirtualShortMethod = h_CallNonvirtualShortMethod;
    g_hooked->CallNonvirtualIntMethodV = h_CallNonvirtualIntMethodV;
    g_hooked->CallNonvirtualIntMethodA = h_CallNonvirtualIntMethodA;
    g_hooked->CallNonvirtualIntMethod = h_CallNonvirtualIntMethod;
    g_hooked->CallNonvirtualLongMethodV = h_CallNonvirtualLongMethodV;
    g_hooked->CallNonvirtualLongMethodA = h_CallNonvirtualLongMethodA;
    g_hooked->CallNonvirtualLongMethod = h_CallNonvirtualLongMethod;
    g_hooked->CallNonvirtualFloatMethodV = h_CallNonvirtualFloatMethodV;
    g_hooked->CallNonvirtualFloatMethodA = h_CallNonvirtualFloatMethodA;
    g_hooked->CallNonvirtualFloatMethod = h_CallNonvirtualFloatMethod;
    g_hooked->CallNonvirtualDoubleMethodV = h_CallNonvirtualDoubleMethodV;
    g_hooked->CallNonvirtualDoubleMethodA = h_CallNonvirtualDoubleMethodA;
    g_hooked->CallNonvirtualDoubleMethod = h_CallNonvirtualDoubleMethod;
    g_hooked->CallNonvirtualVoidMethodA = h_CallNonvirtualVoidMethodA;
    g_hooked->ExceptionCheck = h_ExceptionCheck;
    g_hooked->ExceptionOccurred = h_ExceptionOccurred;
    g_hooked->MonitorEnter = h_MonitorEnter;
    g_hooked->MonitorExit = h_MonitorExit;
    g_hooked->ExceptionClear = h_ExceptionClear;
    g_hooked->NewObjectA = h_NewObjectA;
    g_hooked->FindClass             = h_FindClass;
    g_hooked->GetMethodID           = h_GetMethodID;
    g_hooked->GetStaticMethodID     = h_GetStaticMethodID;
    g_hooked->GetFieldID            = h_GetFieldID;
    g_hooked->GetStaticFieldID      = h_GetStaticFieldID;
    g_hooked->NewStringUTF          = h_NewStringUTF;

    g_hooked->GetObjectField        = h_GetObjectField;
    g_hooked->GetBooleanField       = h_GetBooleanField;
    g_hooked->GetByteField          = h_GetByteField;
    g_hooked->GetCharField          = h_GetCharField;
    g_hooked->GetShortField         = h_GetShortField;
    g_hooked->GetIntField           = h_GetIntField;
    g_hooked->GetLongField          = h_GetLongField;
    g_hooked->SetObjectField        = h_SetObjectField;
    g_hooked->SetBooleanField       = h_SetBooleanField;
    g_hooked->SetByteField          = h_SetByteField;
    g_hooked->SetCharField          = h_SetCharField;
    g_hooked->SetShortField         = h_SetShortField;
    g_hooked->SetIntField           = h_SetIntField;
    g_hooked->SetLongField          = h_SetLongField;
    g_hooked->GetStaticObjectField  = h_GetStaticObjectField;
    g_hooked->GetStaticBooleanField = h_GetStaticBooleanField;
    g_hooked->GetStaticByteField    = h_GetStaticByteField;
    g_hooked->GetStaticCharField    = h_GetStaticCharField;
    g_hooked->GetStaticShortField   = h_GetStaticShortField;
    g_hooked->GetStaticIntField     = h_GetStaticIntField;
    g_hooked->GetStaticLongField    = h_GetStaticLongField;

    g_hooked->CallObjectMethod     = h_CallObjectMethod;
    g_hooked->CallObjectMethodV    = h_CallObjectMethodV;
    g_hooked->CallObjectMethodA    = h_CallObjectMethodA;
    g_hooked->CallBooleanMethod    = h_CallBooleanMethod;
    g_hooked->CallBooleanMethodV   = h_CallBooleanMethodV;
    g_hooked->CallBooleanMethodA   = h_CallBooleanMethodA;
    g_hooked->CallByteMethod       = h_CallByteMethod;
    g_hooked->CallByteMethodV      = h_CallByteMethodV;
    g_hooked->CallByteMethodA      = h_CallByteMethodA;
    g_hooked->CallCharMethod       = h_CallCharMethod;
    g_hooked->CallCharMethodV      = h_CallCharMethodV;
    g_hooked->CallCharMethodA      = h_CallCharMethodA;
    g_hooked->CallShortMethod      = h_CallShortMethod;
    g_hooked->CallShortMethodV     = h_CallShortMethodV;
    g_hooked->CallShortMethodA     = h_CallShortMethodA;
    g_hooked->CallIntMethod        = h_CallIntMethod;
    g_hooked->CallIntMethodV       = h_CallIntMethodV;
    g_hooked->CallIntMethodA       = h_CallIntMethodA;
    g_hooked->CallLongMethod       = h_CallLongMethod;
    g_hooked->CallLongMethodV      = h_CallLongMethodV;
    g_hooked->CallLongMethodA      = h_CallLongMethodA;
    g_hooked->CallVoidMethod       = h_CallVoidMethod;
    g_hooked->CallVoidMethodV      = h_CallVoidMethodV;
    g_hooked->CallVoidMethodA      = h_CallVoidMethodA;

    g_hooked->CallStaticObjectMethod = h_CallStaticObjectMethod;
    g_hooked->CallStaticObjectMethodV = h_CallStaticObjectMethodV;
    g_hooked->CallStaticIntMethod    = h_CallStaticIntMethod;
    g_hooked->CallStaticIntMethodV   = h_CallStaticIntMethodV;
    g_hooked->CallStaticVoidMethod   = h_CallStaticVoidMethod;
    g_hooked->CallStaticVoidMethodV  = h_CallStaticVoidMethodV;

    g_hooked->NewObject  = h_NewObject;
    g_hooked->NewObjectV = h_NewObjectV;
    g_hooked->Throw      = h_Throw;
    g_hooked->ThrowNew   = h_ThrowNew;

    g_hooked->NewGlobalRef     = h_NewGlobalRef;
    g_hooked->NewWeakGlobalRef = h_NewWeakGlobalRef;
    g_hooked->NewLocalRef      = h_NewLocalRef;

    g_hooked->DeleteLocalRef      = h_DeleteLocalRef;
    g_hooked->DeleteGlobalRef     = h_DeleteGlobalRef;
    g_hooked->DeleteWeakGlobalRef = h_DeleteWeakGlobalRef;

    g_hooked->IsInstanceOf      = h_IsInstanceOf;
    g_hooked->IsAssignableFrom  = h_IsAssignableFrom;
    g_hooked->GetObjectClass    = h_GetObjectClass;
    g_hooked->GetSuperclass     = h_GetSuperclass;
    g_hooked->GetArrayLength    = h_GetArrayLength;
    g_hooked->AllocObject       = h_AllocObject;

    g_hooked->NewObjectArray  = h_NewObjectArray;
    g_hooked->NewBooleanArray = h_NewBooleanArray;
    g_hooked->NewByteArray    = h_NewByteArray;
    g_hooked->NewCharArray    = h_NewCharArray;
    g_hooked->NewShortArray   = h_NewShortArray;
    g_hooked->NewIntArray     = h_NewIntArray;
    g_hooked->NewLongArray    = h_NewLongArray;
    g_hooked->NewFloatArray   = h_NewFloatArray;
    g_hooked->NewDoubleArray  = h_NewDoubleArray;

    g_hooked->GetObjectArrayElement = h_GetObjectArrayElement;
    g_hooked->SetObjectArrayElement = h_SetObjectArrayElement;
    g_hooked->GetBooleanArrayRegion = h_GetBooleanArrayRegion;
    g_hooked->GetByteArrayRegion    = h_GetByteArrayRegion;
    g_hooked->GetCharArrayRegion    = h_GetCharArrayRegion;
    g_hooked->GetShortArrayRegion   = h_GetShortArrayRegion;
    g_hooked->GetIntArrayRegion     = h_GetIntArrayRegion;
    g_hooked->GetLongArrayRegion    = h_GetLongArrayRegion;
    g_hooked->GetFloatArrayRegion   = h_GetFloatArrayRegion;
    g_hooked->GetDoubleArrayRegion  = h_GetDoubleArrayRegion;
    g_hooked->SetBooleanArrayRegion = h_SetBooleanArrayRegion;
    g_hooked->SetByteArrayRegion    = h_SetByteArrayRegion;
    g_hooked->SetCharArrayRegion    = h_SetCharArrayRegion;
    g_hooked->SetShortArrayRegion   = h_SetShortArrayRegion;
    g_hooked->SetIntArrayRegion     = h_SetIntArrayRegion;
    g_hooked->SetLongArrayRegion    = h_SetLongArrayRegion;
    g_hooked->SetFloatArrayRegion   = h_SetFloatArrayRegion;
    g_hooked->SetDoubleArrayRegion  = h_SetDoubleArrayRegion;

    g_hooked->CallNonvirtualVoidMethod    = h_CallNonvirtualVoidMethod;
    g_hooked->CallNonvirtualVoidMethodV   = h_CallNonvirtualVoidMethodV;
    g_hooked->CallNonvirtualObjectMethod  = h_CallNonvirtualObjectMethod;
    g_hooked->CallNonvirtualObjectMethodV = h_CallNonvirtualObjectMethodV;
}

} // namespace

void set_jvmti(jvmtiEnv* env) { g_jvmti = env; }

void capture_original(JNIEnv* env) {
    if (g_original) return;
    g_original = env->functions;
    g_original->GetJavaVM(env, &g_vm);
    std::call_once(g_build_flag, build_hook_table);
    if (g_string_class == nullptr) {
        jclass local = g_original->FindClass(env, "java/lang/String");
        if (local) {
            g_string_class = (jclass) g_original->NewGlobalRef(env, local);
            g_original->DeleteLocalRef(env, local);
        }
    }
}

const JNINativeInterface_* hooked_table() {
    return g_hooked;
}

void install(JNIEnv* env) {
    if (!g_hooked) return;
    env->functions = g_hooked;
}

void set_filter_frame_selected(bool selected) { t_filter_frame_selected = selected; }

void enter_native_frame() {
    ++t_frame_depth;
    // Reset the per-frame event counter on the OUTERMOST entry (depth 1).
    // Nested native frames share the outermost's budget.
    if (t_frame_depth == 1) {
        t_frame_event_count = 0;
        t_frame_truncated = false;
    }
}
void exit_native_frame()  { if (t_frame_depth > 0) --t_frame_depth; }
bool in_native_frame()    { return t_frame_depth > 0; }

void set_max_frame_events(int n) { g_max_frame_events = n; }

void set_log_all(bool on) { g_log_all.store(on, std::memory_order_relaxed); }
bool log_all() { return g_log_all.load(std::memory_order_relaxed); }

void enter_suppress_frame() { ++t_suppress_depth; }
void exit_suppress_frame()  { if (t_suppress_depth > 0) --t_suppress_depth; }

void set_current_native_method(const char* sig) { t_current_method = sig; }
const char* current_native_method() { return t_current_method; }

} // namespace j2c::jni_hook
