/* 32-bit x86 (i386) ELF fixture for generic-first JNI method discovery.
 *
 * Exercises two specification-defined registration mechanisms on the i386
 * System V (cdecl) calling convention, where RegisterNatives' arguments are
 * passed on the stack (push $nMethods; push methods; push clazz; push env)
 * rather than in registers:
 *   1. a static JNINativeMethod[] table passed to RegisterNatives, and
 *   2. a Java_* exported symbol.
 *
 * This is the 32-bit sibling of the x86-64 and AArch64 .so fixtures: a genuine
 * (ELF, EM_386) image built with a real i386 toolchain, NOT a renamed 64-bit
 * .so. See fixtures/build.sh for the exact command (i686-linux-gnu-gcc, zig,
 * `clang --target=i386-linux-gnu`, or `gcc -m32`). The committed
 * libjni_registrar_i386.so lets the pytest suite run without a cross toolchain.
 *
 * Position-independent i386 forms the table address through the Global Offset
 * Table base register (call/pop/add PC thunk, then `lea disp(%ebx), %edx`); the
 * i386-sysv ABI backend folds that back to the absolute table VA. The test
 * cross-checks recovered function pointers against the export addresses instead
 * of hard-coding VAs, so a rebuild that shifts addresses does not break it.
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
