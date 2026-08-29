/*
 * A stand-in shared library for the smoke test.
 *
 * It exports functions whose NAMES match well-known crypto and JNI
 * entries, so the observation host has real exports to resolve and to
 * enter — with no OpenSSL, no JVM and no jni.h anywhere. The bodies do
 * no cryptography and read no meaningful data; only the export *names*
 * and *addresses* matter to the observer. This lets CI exercise the
 * observation path without any real TLS traffic or Java runtime.
 */
#include <stddef.h>

#if defined(_WIN32)
#  define FIXTURE_EXPORT __declspec(dllexport)
#else
#  define FIXTURE_EXPORT __attribute__((visibility("default")))
#endif

/* noinline keeps each export a real, separately-callable entry. */
#if defined(__GNUC__)
#  define FIXTURE_NOINLINE __attribute__((noinline))
#else
#  define FIXTURE_NOINLINE
#endif

FIXTURE_EXPORT FIXTURE_NOINLINE int SSL_connect(void *ssl)
{
    volatile int r = (ssl != NULL) ? 1 : 0;
    return r;
}

FIXTURE_EXPORT FIXTURE_NOINLINE int SSL_write(void *ssl, const void *buf,
                                              int num)
{
    (void)ssl;
    (void)buf;
    volatile int n = num; /* echo the length only; never touch the buffer */
    return n;
}

FIXTURE_EXPORT FIXTURE_NOINLINE int SSL_read(void *ssl, void *buf, int num)
{
    (void)ssl;
    (void)buf;
    volatile int n = num;
    return n;
}

/*
 * A JNI-convention export name. There is deliberately no jni.h and no
 * JNIEnv here: this is an ordinary function whose name happens to follow
 * the Java_<class>_<method> pattern, exactly how a JNI-transpiled native
 * would appear to a name-only observer.
 */
FIXTURE_EXPORT FIXTURE_NOINLINE int Java_com_example_Demo_ping(void *env,
                                                               void *clazz)
{
    volatile int r = (env != NULL && clazz != NULL) ? 0 : -1;
    return r;
}
