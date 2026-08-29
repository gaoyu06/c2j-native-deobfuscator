/*
 * A tiny target process for the smoke test.
 *
 * It links the fixture library (fake_exports) and calls its well-known
 * exports in a slow loop, so an observation host attached to this
 * process reliably catches entries and returns. It writes its own pid to
 * the file named by argv[1] (or stdout when none is given) so the smoke
 * test can find it, then loops until it is stopped or the iteration
 * budget runs out. It processes no real data.
 */
#include <stdio.h>

#if defined(_WIN32)
#  include <windows.h>
#  define FIXTURE_SLEEP_MS(ms) Sleep(ms)
#  define FIXTURE_GETPID() (long)GetCurrentProcessId()
#else
#  include <unistd.h>
#  define FIXTURE_SLEEP_MS(ms) usleep((ms) * 1000)
#  define FIXTURE_GETPID() (long)getpid()
#endif

int SSL_connect(void *ssl);
int SSL_write(void *ssl, const void *buf, int num);
int SSL_read(void *ssl, void *buf, int num);
int Java_com_example_Demo_ping(void *env, void *clazz);

int main(int argc, char **argv)
{
    char buf[16] = "ping";
    void *ssl = (void *)0x1;
    int i;
    int sink = 0;

    if (argc > 1) {
        FILE *f = fopen(argv[1], "w");
        if (f != NULL) {
            fprintf(f, "%ld\n", FIXTURE_GETPID());
            fclose(f);
        }
    } else {
        printf("%ld\n", FIXTURE_GETPID());
        fflush(stdout);
    }

    for (i = 0; i < 500; ++i) {
        sink += SSL_connect(ssl);
        sink += SSL_write(ssl, buf, 4);
        sink += SSL_read(ssl, buf, 4);
        sink += Java_com_example_Demo_ping(ssl, (void *)0x2);
        FIXTURE_SLEEP_MS(80);
    }
    return sink & 0x1;
}
