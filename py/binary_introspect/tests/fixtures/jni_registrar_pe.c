/* PE x86-64 fixture for generic-first JNI method discovery.
 *
 * Exercises two specification-defined registration mechanisms on the
 * Microsoft x64 ABI (nMethods in r9d, JNINativeMethod* in r8):
 *   1. a static JNINativeMethod[] table passed to RegisterNatives, and
 *   2. a Java_* exported symbol.
 *
 * Built by fixtures/build.sh with x86_64-w64-mingw32-gcc. See that script for
 * the exact, image-base-pinned command used to produce jni_registrar.dll.
 */
typedef struct JNINativeMethod {
    const char *name;
    const char *signature;
    void *fn_ptr;
} JNINativeMethod;

struct JNINativeInterface;
typedef const struct JNINativeInterface *JNIEnv;
typedef int (*RegisterNativesFn)(
    JNIEnv *env,
    void *clazz,
    const JNINativeMethod *methods,
    int method_count
);

struct JNINativeInterface {
    void *reserved[215];
    RegisterNativesFn RegisterNatives;
};

__declspec(dllexport)
void fixture_alpha(JNIEnv *env, void *receiver) {
    (void)env;
    (void)receiver;
}

__declspec(dllexport)
int fixture_beta(JNIEnv *env, void *receiver, int value) {
    (void)env;
    (void)receiver;
    return value + 1;
}

/* A specification-defined JNI export name (the second registration family). */
__declspec(dllexport)
void Java_com_example_Sample_ping(JNIEnv *env, void *receiver) {
    (void)env;
    (void)receiver;
}

static const JNINativeMethod fixture_methods[] = {
    {"alpha", "()V", (void *)fixture_alpha},
    {"beta", "(I)I", (void *)fixture_beta},
};

__declspec(dllexport)
int fixture_register(JNIEnv *env, void *clazz) {
    return (*env)->RegisterNatives(env, clazz, fixture_methods, 2);
}
