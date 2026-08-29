/*
 * A tiny *multithreaded* target process for the smoke test.
 *
 * It is identical in spirit to fixture_target.c — it links the fixture
 * library (fake_exports) and calls its well-known exports in a slow loop —
 * except that it first spawns a second thread that simply idles. Its only
 * purpose is to make /proc/PID/task show more than one thread so the
 * observation host exercises its single-thread live-observation policy:
 * the host must refuse the live (breakpoint) pass on a multithreaded target
 * and fall back to the read-only module/symbol pass.
 *
 * Main waits until the worker thread has actually started before it
 * publishes its pid, so by the time the smoke test hands that pid to the
 * host the second thread is guaranteed to be present. It processes no real
 * data.
 */
#define _DEFAULT_SOURCE /* for usleep() under -std=c99 */

#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

int SSL_connect(void *ssl);
int SSL_write(void *ssl, const void *buf, int num);
int SSL_read(void *ssl, void *buf, int num);
int Java_com_example_Demo_ping(void *env, void *clazz);

static volatile int g_worker_running;

static void *worker_main(void *arg)
{
    (void)arg;
    g_worker_running = 1;
    for (;;) {
        usleep(80 * 1000);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    char buf[16] = "ping";
    void *ssl = (void *)0x1;
    pthread_t worker;
    int i;
    int sink = 0;

    if (pthread_create(&worker, NULL, worker_main, NULL) != 0) {
        fprintf(stderr, "fixture: cannot create worker thread\n");
        return 1;
    }
    /* Do not publish the pid until the second thread is really running, so
     * the observer always sees a multithreaded /proc/PID/task. */
    while (!g_worker_running) {
        usleep(1000);
    }

    if (argc > 1) {
        FILE *f = fopen(argv[1], "w");
        if (f != NULL) {
            fprintf(f, "%ld\n", (long)getpid());
            fclose(f);
        }
    } else {
        printf("%ld\n", (long)getpid());
        fflush(stdout);
    }

    for (i = 0; i < 500; ++i) {
        sink += SSL_connect(ssl);
        sink += SSL_write(ssl, buf, 4);
        sink += SSL_read(ssl, buf, 4);
        sink += Java_com_example_Demo_ping(ssl, (void *)0x2);
        usleep(80 * 1000);
    }
    return sink & 0x1;
}
