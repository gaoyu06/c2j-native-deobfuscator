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

static const JNINativeMethod fixture_methods[] = {
    {"alpha", "()V", (void *)fixture_alpha},
    {"beta", "(I)I", (void *)fixture_beta},
};

__attribute__((visibility("default")))
int fixture_register(JNIEnv *env, void *clazz) {
    return (*env)->RegisterNatives(env, clazz, fixture_methods, 2);
}
