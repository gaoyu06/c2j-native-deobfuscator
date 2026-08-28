/* ELF aarch64 fixture for generic-first JNI method discovery.
 *
 * Exercises two specification-defined registration mechanisms on the AArch64
 * AAPCS64 calling convention (JNIEnv* in x0, jclass in x1,
 * JNINativeMethod* in x2, jint nMethods in x3):
 *   1. a static JNINativeMethod[] table passed to RegisterNatives, and
 *   2. a Java_* exported symbol.
 *
 * Built by fixtures/build.sh with aarch64-linux-gnu-gcc (or `zig cc -target
 * aarch64-linux-gnu`). See that script for the exact command. The built
 * libjni_registrar_aarch64.so is committed so the pytest suite runs without a
 * cross toolchain.
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
