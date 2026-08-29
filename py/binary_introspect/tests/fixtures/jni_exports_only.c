/* ELF x86-64 fixture: the "exports-only" registration family.
 *
 * These methods are registered purely by specification-defined Java_* export
 * names. There is no JNINativeMethod table and no RegisterNatives call site in
 * this library, so it proves the generic discovery path is not locked to the
 * RegisterNatives-table shape.
 *
 * Built by fixtures/build.sh with the host gcc. See that script for the exact
 * command used to produce libjni_exports_only.so.
 */
#define JNI_EXPORT __attribute__((visibility("default")))

JNI_EXPORT void Java_com_example_Widget_init(void *env, void *obj) {
    (void)env;
    (void)obj;
}

JNI_EXPORT int Java_com_example_Widget_compute(void *env, void *obj, int x) {
    (void)env;
    (void)obj;
    return x * 2;
}

/* Overloaded method: the long form encodes a (Ljava/lang/String;) descriptor. */
JNI_EXPORT long Java_com_example_Widget_hashOf__Ljava_lang_String_2(
        void *env, void *obj, void *s) {
    (void)env;
    (void)obj;
    (void)s;
    return 0;
}
