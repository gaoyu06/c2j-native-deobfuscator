#if !defined(_WIN32)
#  define _POSIX_C_SOURCE 200809L
#endif

#include "platform.h"

#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#  include <windows.h>
#else
#  include <dlfcn.h>
#  include <time.h>
#  include <unistd.h>
#endif

static char g_last_error[512];

static void set_error(const char *msg)
{
    if (msg == NULL) {
        g_last_error[0] = '\0';
        return;
    }
    strncpy(g_last_error, msg, sizeof(g_last_error) - 1u);
    g_last_error[sizeof(g_last_error) - 1u] = '\0';
}

const char *nx86_plat_last_error(void)
{
    return g_last_error[0] != '\0' ? g_last_error : "no error";
}

#if defined(_WIN32)

static void set_error_from_os(void)
{
    DWORD code = GetLastError();
    (void)snprintf(g_last_error, sizeof(g_last_error), "os error %lu",
                   (unsigned long)code);
}

void *nx86_plat_open_library(const char *path)
{
    HMODULE handle = LoadLibraryA(path);
    if (handle == NULL) {
        set_error_from_os();
        return NULL;
    }
    set_error(NULL);
    return (void *)handle;
}

void *nx86_plat_find_symbol(void *handle, const char *name)
{
    FARPROC sym = GetProcAddress((HMODULE)handle, name);
    if (sym == NULL) {
        set_error_from_os();
        return NULL;
    }
    set_error(NULL);
    return (void *)(uintptr_t)sym;
}

void nx86_plat_close_library(void *handle)
{
    if (handle != NULL) {
        (void)FreeLibrary((HMODULE)handle);
    }
}

uint64_t nx86_plat_now_ns(void)
{
    FILETIME ft;
    ULARGE_INTEGER v;
    GetSystemTimeAsFileTime(&ft);
    v.LowPart = ft.dwLowDateTime;
    v.HighPart = ft.dwHighDateTime;
    /* FILETIME counts 100ns ticks since 1601-01-01; shift to the Unix
     * epoch so timestamps mean the same thing on every platform. */
    return (v.QuadPart - 116444736000000000ULL) * 100ULL;
}

uint32_t nx86_plat_process_id(void)
{
    return (uint32_t)GetCurrentProcessId();
}

int nx86_plat_plugin_filename(const char *stem, char *out, size_t cap)
{
    int n = snprintf(out, cap, "nx86_plugin_%s.dll", stem);
    return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

#else /* POSIX */

void *nx86_plat_open_library(const char *path)
{
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        set_error(dlerror());
        return NULL;
    }
    set_error(NULL);
    return handle;
}

void *nx86_plat_find_symbol(void *handle, const char *name)
{
    void *sym;
    (void)dlerror();
    sym = dlsym(handle, name);
    if (sym == NULL) {
        set_error(dlerror());
        return NULL;
    }
    set_error(NULL);
    return sym;
}

void nx86_plat_close_library(void *handle)
{
    if (handle != NULL) {
        (void)dlclose(handle);
    }
}

uint64_t nx86_plat_now_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0u;
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

uint32_t nx86_plat_process_id(void)
{
    return (uint32_t)getpid();
}

int nx86_plat_plugin_filename(const char *stem, char *out, size_t cap)
{
    int n = snprintf(out, cap, "libnx86_plugin_%s.so", stem);
    return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

#endif
