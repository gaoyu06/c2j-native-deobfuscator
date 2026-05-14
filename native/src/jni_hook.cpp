#include "jni_hook.hpp"
#include "trace_writer.hpp"

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace j2c::jni_hook {

namespace {

const JNINativeInterface_* g_original = nullptr;
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

std::string lookup_string(jobject o) {
    if (o == nullptr) return "";
    std::lock_guard<std::mutex> g(g_str_mu);
    auto it = g_str_content.find(o);
    return it != g_str_content.end() ? it->second : std::string();
}

void register_string(jobject o, std::string s) {
    if (o == nullptr) return;
    std::lock_guard<std::mutex> g(g_str_mu);
    g_str_content[o] = std::move(s);
}

thread_local int t_frame_depth = 0;
thread_local int t_suppress_depth = 0;
thread_local const char* t_current_method = nullptr;

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

void emit(const std::string& call, const std::string& args, const std::string& ret,
          jmethodID mid = nullptr) {
    if (!in_native_frame() || t_suppress_depth > 0) return;
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
    os << "}";
    TraceWriter::instance().write_line(os.str());
}

#define ORIG(name) (g_original->name)

// ---------- wrappers ----------

jclass JNICALL h_FindClass(JNIEnv* env, const char* name) {
    jclass r = ORIG(FindClass)(env, name);
    std::ostringstream args; args << esc(name);
    emit("FindClass", args.str(), hex_ptr(r));
    return r;
}

void emit_outside_frame(const std::string& call, const std::string& args, const std::string& ret) {
    std::ostringstream os;
    os << "{\"ev\":\"jni-init\",\"ts\":" << TraceWriter::ts_now()
       << ",\"thr\":" << TraceWriter::tid()
       << ",\"call\":" << esc(call.c_str())
       << ",\"args\":[" << args << "]"
       << ",\"ret\":" << ret
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
        emit("GetMethodID", args.str(), hex_ptr(r));
    } else {
        emit_outside_frame("GetMethodID", args.str(), hex_ptr(r));
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
        emit("GetStaticMethodID", args.str(), hex_ptr(r));
    } else {
        emit_outside_frame("GetStaticMethodID", args.str(), hex_ptr(r));
    }
    return r;
}

jfieldID JNICALL h_GetFieldID(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
    jfieldID r = ORIG(GetFieldID)(env, clazz, name, sig);
    std::ostringstream args;
    args << hex_ptr(clazz) << "," << esc(name) << "," << esc(sig);
    emit("GetFieldID", args.str(), hex_ptr(r));
    return r;
}

jfieldID JNICALL h_GetStaticFieldID(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
    jfieldID r = ORIG(GetStaticFieldID)(env, clazz, name, sig);
    std::ostringstream args;
    args << hex_ptr(clazz) << "," << esc(name) << "," << esc(sig);
    emit("GetStaticFieldID", args.str(), hex_ptr(r));
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
    if (!in_native_frame()) return;
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
        char rb[64]; std::snprintf(rb, sizeof(rb), fmtarg, (long long) r);                    \
        emit("Get" #jname "Field", args.str(), rb);                                           \
        return r;                                                                              \
    }

#define WRAP_SET_FIELD(jtype, jname, fmtarg)                                                  \
    void JNICALL h_Set##jname##Field(JNIEnv* env, jobject obj, jfieldID f, jtype v) {         \
        ORIG(Set##jname##Field)(env, obj, f, v);                                              \
        std::ostringstream args; args << hex_ptr(obj) << "," << hex_ptr(f) << "," <<          \
            ([](jtype x){ char b[64]; std::snprintf(b, sizeof(b), fmtarg, (long long)x); return std::string(b); })(v); \
        emit("Set" #jname "Field", args.str(), "null");                                       \
    }

#define WRAP_GET_STATIC_FIELD(jtype, jname, fmtarg)                                            \
    jtype JNICALL h_GetStatic##jname##Field(JNIEnv* env, jclass clazz, jfieldID f) {           \
        jtype r = ORIG(GetStatic##jname##Field)(env, clazz, f);                                \
        std::ostringstream args; args << hex_ptr(clazz) << "," << hex_ptr(f);                  \
        char rb[64]; std::snprintf(rb, sizeof(rb), fmtarg, (long long) r);                     \
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
        emit(#kindprefix #jname "Method", args.str(), hex_ptr(r), m);                           \
        return r;                                                                              \
    }                                                                                          \
    jobject JNICALL h_##kindprefix##jname##MethodA(JNIEnv* env, jobject obj, jmethodID m,    \
                                                    const jvalue* a) {                       \
        jobject r = ORIG(kindprefix##jname##MethodA)(env, obj, m, a);                        \
        std::ostringstream args; args << hex_ptr(obj) << "," << hex_ptr(m)                   \
            << decode_array(m, a);                                                            \
        emit(#kindprefix #jname "Method", args.str(), hex_ptr(r), m);                           \
        return r;                                                                              \
    }

#define WRAP_CALL_RET_PRIM(jtype, jname, fmt, kindprefix)                                     \
    jtype JNICALL h_##kindprefix##jname##MethodV(JNIEnv* env, jobject obj, jmethodID m,      \
                                                  va_list ap) {                              \
        va_list ap2; va_copy(ap2, ap);                                                       \
        va_list ap3; va_copy(ap3, ap);                                                       \
        jtype r = ORIG(kindprefix##jname##MethodV)(env, obj, m, ap2);                        \
        va_end(ap2);                                                                          \
        char rb[64]; std::snprintf(rb, sizeof(rb), fmt, (long long) r);                      \
        std::ostringstream args; args << hex_ptr(obj) << "," << hex_ptr(m)                   \
            << decode_variadic(m, ap3);                                                       \
        va_end(ap3);                                                                          \
        emit(#kindprefix #jname "Method", args.str(), rb, m);                                   \
        return r;                                                                              \
    }                                                                                          \
    jtype JNICALL h_##kindprefix##jname##MethodA(JNIEnv* env, jobject obj, jmethodID m,      \
                                                  const jvalue* a) {                          \
        jtype r = ORIG(kindprefix##jname##MethodA)(env, obj, m, a);                          \
        char rb[64]; std::snprintf(rb, sizeof(rb), fmt, (long long) r);                      \
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
    emit("CallStaticObjectMethod", args.str(), hex_ptr(r), m);
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
    emit("GetObjectClass", args.str(), hex_ptr(r));
    return r;
}

jclass JNICALL h_GetSuperclass(JNIEnv* env, jclass clazz) {
    jclass r = ORIG(GetSuperclass)(env, clazz);
    std::ostringstream args; args << hex_ptr(clazz);
    emit("GetSuperclass", args.str(), hex_ptr(r));
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

#define WRAP_GET_ARRAY_REGION(jname, jtype, fmt)                                          \
    void JNICALL h_Get##jname##ArrayRegion(JNIEnv* env, jtype##Array arr,                 \
                                            jsize start, jsize len, jtype* buf) {        \
        ORIG(Get##jname##ArrayRegion)(env, arr, start, len, buf);                         \
        std::ostringstream args;                                                          \
        args << hex_ptr(arr) << "," << (int) start << "," << (int) len;                   \
        if (buf && len > 0) {                                                              \
            char vb[64]; std::snprintf(vb, sizeof(vb), fmt, (long long) buf[0]);          \
            args << "," << vb;                                                             \
        }                                                                                  \
        emit("Get" #jname "ArrayRegion", args.str(), "null");                             \
    }

#define WRAP_SET_ARRAY_REGION(jname, jtype, fmt)                                          \
    void JNICALL h_Set##jname##ArrayRegion(JNIEnv* env, jtype##Array arr,                 \
                                            jsize start, jsize len, const jtype* buf) {  \
        ORIG(Set##jname##ArrayRegion)(env, arr, start, len, buf);                         \
        std::ostringstream args;                                                          \
        args << hex_ptr(arr) << "," << (int) start << "," << (int) len;                   \
        if (buf && len > 0) {                                                              \
            char vb[64]; std::snprintf(vb, sizeof(vb), fmt, (long long) buf[0]);          \
            args << "," << vb;                                                             \
        }                                                                                  \
        emit("Set" #jname "ArrayRegion", args.str(), "null");                             \
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
    emit("CallNonvirtualObjectMethod", args.str(), hex_ptr(r), m);
    return r;
}

jobject JNICALL h_CallNonvirtualObjectMethod(JNIEnv* env, jobject obj, jclass cls,
                                              jmethodID m, ...) {
    va_list ap; va_start(ap, m);
    jobject r = h_CallNonvirtualObjectMethodV(env, obj, cls, m, ap);
    va_end(ap);
    return r;
}

void build_hook_table() {
    g_hooked = new JNINativeInterface_(*g_original);
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

void capture_original(JNIEnv* env) {
    if (g_original) return;
    g_original = env->functions;
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

void enter_native_frame() { ++t_frame_depth; }
void exit_native_frame()  { if (t_frame_depth > 0) --t_frame_depth; }
bool in_native_frame()    { return t_frame_depth > 0; }

void enter_suppress_frame() { ++t_suppress_depth; }
void exit_suppress_frame()  { if (t_suppress_depth > 0) --t_suppress_depth; }

void set_current_native_method(const char* sig) { t_current_method = sig; }
const char* current_native_method() { return t_current_method; }

} // namespace j2c::jni_hook
