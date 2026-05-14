#include "jni_hook.hpp"
#include "trace_writer.hpp"

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <sstream>
#include <string>

namespace j2c::jni_hook {

namespace {

const JNINativeInterface_* g_original = nullptr;
JNINativeInterface_* g_hooked = nullptr;
std::once_flag g_build_flag;

thread_local int t_frame_depth = 0;
thread_local const char* t_current_method = nullptr;

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

void emit(const std::string& call, const std::string& args, const std::string& ret) {
    if (!in_native_frame()) return;
    std::ostringstream os;
    os << "{\"ev\":\"jni\",\"ts\":" << TraceWriter::ts_now()
       << ",\"thr\":" << TraceWriter::tid()
       << ",\"call\":" << esc(call.c_str())
       << ",\"args\":[" << args << "]"
       << ",\"ret\":" << ret
       << "}";
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

jmethodID JNICALL h_GetMethodID(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
    jmethodID r = ORIG(GetMethodID)(env, clazz, name, sig);
    std::ostringstream args;
    args << hex_ptr(clazz) << "," << esc(name) << "," << esc(sig);
    emit("GetMethodID", args.str(), hex_ptr(r));
    return r;
}

jmethodID JNICALL h_GetStaticMethodID(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
    jmethodID r = ORIG(GetStaticMethodID)(env, clazz, name, sig);
    std::ostringstream args;
    args << hex_ptr(clazz) << "," << esc(name) << "," << esc(sig);
    emit("GetStaticMethodID", args.str(), hex_ptr(r));
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
    emit("NewStringUTF", esc(str), hex_ptr(r));
    return r;
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
        jobject r = ORIG(kindprefix##jname##MethodV)(env, obj, m, ap2);                      \
        va_end(ap2);                                                                          \
        std::ostringstream args; args << hex_ptr(obj) << "," << hex_ptr(m);                   \
        emit(#kindprefix #jname "Method", args.str(), hex_ptr(r));                           \
        return r;                                                                              \
    }                                                                                          \
    jobject JNICALL h_##kindprefix##jname##MethodA(JNIEnv* env, jobject obj, jmethodID m,    \
                                                    const jvalue* a) {                       \
        jobject r = ORIG(kindprefix##jname##MethodA)(env, obj, m, a);                        \
        std::ostringstream args; args << hex_ptr(obj) << "," << hex_ptr(m);                   \
        emit(#kindprefix #jname "Method", args.str(), hex_ptr(r));                           \
        return r;                                                                              \
    }

#define WRAP_CALL_RET_PRIM(jtype, jname, fmt, kindprefix)                                     \
    jtype JNICALL h_##kindprefix##jname##MethodV(JNIEnv* env, jobject obj, jmethodID m,      \
                                                  va_list ap) {                              \
        va_list ap2; va_copy(ap2, ap);                                                       \
        jtype r = ORIG(kindprefix##jname##MethodV)(env, obj, m, ap2);                        \
        va_end(ap2);                                                                          \
        char rb[64]; std::snprintf(rb, sizeof(rb), fmt, (long long) r);                      \
        std::ostringstream args; args << hex_ptr(obj) << "," << hex_ptr(m);                   \
        emit(#kindprefix #jname "Method", args.str(), rb);                                   \
        return r;                                                                              \
    }                                                                                          \
    jtype JNICALL h_##kindprefix##jname##MethodA(JNIEnv* env, jobject obj, jmethodID m,      \
                                                  const jvalue* a) {                          \
        jtype r = ORIG(kindprefix##jname##MethodA)(env, obj, m, a);                          \
        char rb[64]; std::snprintf(rb, sizeof(rb), fmt, (long long) r);                      \
        std::ostringstream args; args << hex_ptr(obj) << "," << hex_ptr(m);                   \
        emit(#kindprefix #jname "Method", args.str(), rb);                                   \
        return r;                                                                              \
    }

#define WRAP_CALL_VOID(kindprefix)                                                            \
    void JNICALL h_##kindprefix##VoidMethodV(JNIEnv* env, jobject obj, jmethodID m,           \
                                              va_list ap) {                                   \
        va_list ap2; va_copy(ap2, ap);                                                       \
        ORIG(kindprefix##VoidMethodV)(env, obj, m, ap2);                                     \
        va_end(ap2);                                                                          \
        std::ostringstream args; args << hex_ptr(obj) << "," << hex_ptr(m);                   \
        emit(#kindprefix "VoidMethod", args.str(), "null");                                  \
    }                                                                                          \
    void JNICALL h_##kindprefix##VoidMethodA(JNIEnv* env, jobject obj, jmethodID m,           \
                                              const jvalue* a) {                              \
        ORIG(kindprefix##VoidMethodA)(env, obj, m, a);                                       \
        std::ostringstream args; args << hex_ptr(obj) << "," << hex_ptr(m);                   \
        emit(#kindprefix "VoidMethod", args.str(), "null");                                  \
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
    jobject r = ORIG(CallStaticObjectMethodV)(env, c, m, ap2);
    va_end(ap2);
    std::ostringstream args; args << hex_ptr(c) << "," << hex_ptr(m);
    emit("CallStaticObjectMethod", args.str(), hex_ptr(r));
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
    jint r = ORIG(CallStaticIntMethodV)(env, c, m, ap2);
    va_end(ap2);
    char rb[64]; std::snprintf(rb, sizeof(rb), "%lld", (long long) r);
    std::ostringstream args; args << hex_ptr(c) << "," << hex_ptr(m);
    emit("CallStaticIntMethod", args.str(), rb);
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
    ORIG(CallStaticVoidMethodV)(env, c, m, ap2);
    va_end(ap2);
    std::ostringstream args; args << hex_ptr(c) << "," << hex_ptr(m);
    emit("CallStaticVoidMethod", args.str(), "null");
}
void JNICALL h_CallStaticVoidMethod(JNIEnv* env, jclass c, jmethodID m, ...) {
    va_list ap; va_start(ap, m);
    h_CallStaticVoidMethodV(env, c, m, ap);
    va_end(ap);
}

jobject JNICALL h_NewObjectV(JNIEnv* env, jclass c, jmethodID m, va_list ap) {
    va_list ap2; va_copy(ap2, ap);
    jobject r = ORIG(NewObjectV)(env, c, m, ap2);
    va_end(ap2);
    std::ostringstream args; args << hex_ptr(c) << "," << hex_ptr(m);
    emit("NewObject", args.str(), hex_ptr(r));
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
}

} // namespace

void capture_original(JNIEnv* env) {
    if (g_original) return;
    g_original = env->functions;
    std::call_once(g_build_flag, build_hook_table);
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

void set_current_native_method(const char* sig) { t_current_method = sig; }
const char* current_native_method() { return t_current_method; }

} // namespace j2c::jni_hook
