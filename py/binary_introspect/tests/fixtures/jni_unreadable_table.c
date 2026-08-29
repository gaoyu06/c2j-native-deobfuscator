// x86-64 ELF fixture for generic-first JNI method discovery: a RegisterNatives
// call site whose in-image JNINativeMethod[] is VISIBLE but UNREADABLE.
//
// The registrar makes a standard RegisterNatives call — the third argument
// points at an in-image table of the correct stride (three pointers per entry)
// and the fourth argument is the immediate nMethods (2) — but each entry's
// name and signature pointers reference byte runs that are deliberately NOT
// valid UTF-8 (high-bit / XOR-looking garbage). This models an encrypted or
// runtime-decrypted string table: the call site and the table are structurally
// present, yet the method names/descriptors cannot be read out statically.
//
// Generic discovery must record this as an HONEST GAP — the RegisterNatives
// site was seen but the table did not decode — instead of silently skipping
// the site or fabricating method names/addresses from the garbage. This
// fixture proves only that we do NOT silently drop a visible-but-unreadable
// table; it does not decrypt or recover the table (that stays out of scope).
//
// A genuine Java_* export is also present as a SECOND registration family on
// the same image: it registers by specification-defined export name and is
// recorded honestly, independent of the unreadable RegisterNatives table.
//
// Built by fixtures/build.sh with the host cc (no cross toolchain, no mingw).
// The committed libjni_unreadable_table.so lets the pytest suite run without a
// compiler.

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

// Name/signature byte runs that are deliberately NOT valid UTF-8 (high-bit
// bytes), so the generic decoder cannot read a method name or a JVM descriptor
// out of them. NUL-terminated so a c-string read finds an end, after which the
// UTF-8 decode of the preceding bytes fails.
static const unsigned char enc_name0[] = {0xff, 0x93, 0xa1, 0xb2, 0x00};
static const unsigned char enc_sig0[]  = {0xff, 0x81, 0xc4, 0x00};
static const unsigned char enc_name1[] = {0xfe, 0x8c, 0xd4, 0xe5, 0x00};
static const unsigned char enc_sig1[]  = {0xfe, 0x82, 0xa7, 0x00};

// A JNINativeMethod[] of the correct stride and count (2). The function-pointer
// slots are left null (a real target fills them at runtime); the name/signature
// slots point at the unreadable byte runs above.
static const JNINativeMethod fixture_methods[] = {
    {(const char *)enc_name0, (const char *)enc_sig0, 0},
    {(const char *)enc_name1, (const char *)enc_sig1, 0},
};

__attribute__((visibility("default")))
int fixture_register(JNIEnv *env, void *clazz) {
    // nMethods immediate 2; the third argument points at the in-image table.
    return (*env)->RegisterNatives(env, clazz, fixture_methods, 2);
}

// A genuine Java_* export: a second, spec-defined registration family on the
// same image, recorded honestly and independent of the unreadable table above.
__attribute__((visibility("default")))
int Java_com_example_Enc_ping(JNIEnv *env, void *receiver) {
    (void)env;
    (void)receiver;
    return 0;
}
