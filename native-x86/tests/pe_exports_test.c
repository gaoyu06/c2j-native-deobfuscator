/*
 * Cross-platform checks for the on-disk PE named-export parser.
 *
 * The committed fixture is an x86-64 DLL from PR #4.  This test opens it as
 * an ordinary file; no Windows host, loader, or target process is required.
 */
#include "../src/host/pe_exports.h"

#include "nativex86/plugin.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct expected_export {
    const char *name;
    uint32_t    rva;
    uint32_t    ordinal;
    int         seen;
} expected_export;

static expected_export g_expected[] = {
    {"Java_com_example_Sample_ping", 0x1020u, 1u, 0},
    {"fixture_alpha",                0x1000u, 2u, 0},
    {"fixture_beta",                 0x1010u, 3u, 0},
    {"fixture_register",             0x1030u, 4u, 0}
};
static int g_failures;
static int g_visits;

#define CHECK(cond, msg)                                      \
    do {                                                      \
        if (!(cond)) {                                        \
            printf("pe-exports-test: FAIL: %s\n", (msg));     \
            ++g_failures;                                     \
        }                                                     \
    } while (0)

static void on_export(void *ctx, const nx86_pe_export *entry)
{
    size_t i;
    int matched = 0;
    (void)ctx;
    ++g_visits;

    for (i = 0; i < sizeof(g_expected) / sizeof(g_expected[0]); ++i) {
        expected_export *expected = &g_expected[i];
        if (strcmp(entry->name, expected->name) != 0) {
            continue;
        }
        matched = 1;
        CHECK(!expected->seen, "an export name was visited more than once");
        CHECK(entry->rva == expected->rva, "export RVA differs from fixture");
        CHECK(entry->ordinal == expected->ordinal,
              "export ordinal differs from fixture");
        CHECK(!entry->forwarded, "fixture export must not be forwarded");
        expected->seen = 1;
        break;
    }
    CHECK(matched, "parser returned an unexpected named export");
}

static unsigned char *read_file(const char *path, size_t *out_size)
{
    FILE *fp;
    long length;
    unsigned char *bytes;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0 ||
        (length = ftell(fp)) <= 0 ||
        fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }
    bytes = (unsigned char *)malloc((size_t)length);
    if (bytes == NULL ||
        fread(bytes, 1u, (size_t)length, fp) != (size_t)length) {
        free(bytes);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    *out_size = (size_t)length;
    return bytes;
}

int main(int argc, char **argv)
{
    unsigned char *image;
    size_t image_size = 0u;
    uint32_t machine = NX86_MACHINE_UNKNOWN;
    uint32_t declared_size = 0u;
    size_t i;
    int status;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <fixture.dll>\n", argv[0]);
        return 2;
    }
    image = read_file(argv[1], &image_size);
    if (image == NULL) {
        fprintf(stderr, "pe-exports-test: cannot read %s\n", argv[1]);
        return 2;
    }

    status = nx86_pe_visit_exports(image, image_size, on_export, NULL,
                                   &machine, &declared_size);
    CHECK(status == 0, "committed fixture must be a valid PE image");
    CHECK(machine == NX86_MACHINE_X86_64, "fixture machine must be x86-64");
    CHECK(declared_size != 0u, "fixture SizeOfImage must be reported");
    CHECK(g_visits == 4, "fixture must expose exactly four named exports");
    for (i = 0; i < sizeof(g_expected) / sizeof(g_expected[0]); ++i) {
        CHECK(g_expected[i].seen, "an expected fixture export was not visited");
    }

    CHECK(nx86_pe_visit_exports(image, 63u, NULL, NULL, NULL, NULL) == -1,
          "truncated DOS header must be rejected");
    image[0] = 'N';
    CHECK(nx86_pe_visit_exports(image, image_size, NULL, NULL, NULL, NULL) == -1,
          "invalid DOS signature must be rejected");
    free(image);

    if (g_failures != 0) {
        printf("pe-exports-test: FAIL (%d failure(s))\n", g_failures);
        return 1;
    }
    printf("pe-exports-test: PASS\n");
    return 0;
}
