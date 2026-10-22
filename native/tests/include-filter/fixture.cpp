#include <jni.h>
static jclass selected, excluded;
static jmethodID inner, excluded_run;
static void message(JNIEnv* env, const char* text) {
    auto s = env->NewStringUTF(text);
    auto g = env->NewGlobalRef(s);
    env->DeleteGlobalRef(g);
    env->DeleteLocalRef(s);
}
static void JNICALL run_inner(JNIEnv* env, jclass) { message(env, "KEEP_INNER"); }
static void JNICALL run_excluded(JNIEnv* env, jclass) {
    message(env, "DROP_BEFORE");
    env->CallStaticVoidMethod(selected, inner);
    message(env, "DROP_AFTER");
}
static void JNICALL run_selected(JNIEnv* env, jclass) {
    message(env, "KEEP_BEFORE");
    env->CallStaticVoidMethod(excluded, excluded_run);
    auto helper = env->FindClass("obf/Helper");
    auto fail = env->GetStaticMethodID(helper, "fail", "()V");
    env->CallStaticVoidMethod(helper, fail);
    env->ExceptionClear();
    message(env, "KEEP_AFTER");
}
static void JNICALL run_native(JNIEnv* env, jclass) { message(env, "KEEP_NATIVE"); }
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    selected = static_cast<jclass>(env->NewGlobalRef(env->FindClass("obf/Selected")));
    excluded = static_cast<jclass>(env->NewGlobalRef(env->FindClass("other/Excluded")));
    auto n = env->FindClass("native/Selected");
    JNINativeMethod a[] = {{const_cast<char*>("run"), const_cast<char*>("()V"), reinterpret_cast<void*>(run_selected)},
                          {const_cast<char*>("inner"), const_cast<char*>("()V"), reinterpret_cast<void*>(run_inner)}};
    JNINativeMethod b[] = {{const_cast<char*>("run"), const_cast<char*>("()V"), reinterpret_cast<void*>(run_excluded)}};
    JNINativeMethod c[] = {{const_cast<char*>("run"), const_cast<char*>("()V"), reinterpret_cast<void*>(run_native)}};
    env->RegisterNatives(selected, a, 2);
    env->RegisterNatives(excluded, b, 1);
    env->RegisterNatives(n, c, 1);
    inner = env->GetStaticMethodID(selected, "inner", "()V");
    excluded_run = env->GetStaticMethodID(excluded, "run", "()V");
    return JNI_VERSION_1_6;
}
