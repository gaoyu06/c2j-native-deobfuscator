/* Mach-O x86-64 fixture for generic-first JNI method discovery.
 *
 * Exercises two specification-defined registration mechanisms on the System V
 * ABI that Mach-O x86-64 uses (nMethods in ecx, JNINativeMethod* in rdx):
 *   1. a static JNINativeMethod[] table passed to RegisterNatives, and
 *   2. a Java_* exported symbol (Mach-O stores it as _Java_..., which the
 *      generic path normalizes back to the spec name).
 *
 * Built by fixtures/build.sh with clang targeting x86_64-apple-macos and the
 * ld64.lld Mach-O linker. See that script for the exact command used to
 * produce libjni_registrar.dylib.
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

__attribute__((visibility("default")))
void fixture_alpha(JNIEnv *env, void *receiver) {
    (void)env;
    (void)receiver;
}

__attribute__((visibility("default")))
int fixture_beta(JNIEnv *env, void *receiver, int value) {
    (void)env;
    (void)receiver;
    return value + 1;
}

/* A specification-defined JNI export name (the second registration family). */
__attribute__((visibility("default")))
void Java_com_example_Sample_ping(JNIEnv *env, void *receiver) {
    (void)env;
    (void)receiver;
}

static const JNINativeMethod fixture_methods[] = {
    {"alpha", "()V", (void *)fixture_alpha},
    {"beta", "(I)I", (void *)fixture_beta},
};

__attribute__((visibility("default")))
int fixture_register(JNIEnv *env, void *clazz) {
    return (*env)->RegisterNatives(env, clazz, fixture_methods, 2);
}
