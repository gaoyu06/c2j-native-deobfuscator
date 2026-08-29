/*
 * White-box unit checks for internals of the live observation engine that
 * are awkward to reach end-to-end without ptrace: the unique-address
 * restore planner and the entry/return alias guard.
 *
 * The engine's live-path helpers are static, so this compiles the engine
 * directly (`#include`) to call them without a live target. It proves the
 * invariant behind must-fix item 2: entry and return breakpoints can name
 * the same address, and cleanup must restore each unique address exactly
 * once with its true (non-INT3) original byte — never a re-saved 0xcc.
 *
 * On a platform without the live path (NX86_LIVE_OK == 0) this degrades to
 * a clean skip.
 */
#include "../src/host/observe_linux.c"

#include <stdio.h>
#include <string.h>

#if NX86_LIVE_OK

static int g_failures;

#define CHECK(cond, msg)                                        \
    do {                                                        \
        if (!(cond)) {                                          \
            printf("observe-unit: FAIL: %s\n", (msg));          \
            ++g_failures;                                       \
        }                                                       \
    } while (0)

static const restore_site *find_site(const restore_site *sites, int n,
                                     uint64_t addr)
{
    int i;
    for (i = 0; i < n; ++i) {
        if (sites[i].address == addr) {
            return &sites[i];
        }
    }
    return NULL;
}

/* An entry and a return breakpoint at the same address must produce one
 * restore site, and the entry's true original byte must win over a return
 * record that (in the hazard being guarded against) saved a 0xcc. */
static void test_plan_restores_dedups_aliased_address(void)
{
    breakpoint bps[2];
    return_bp rbs[2];
    restore_site sites[8];
    const restore_site *s;
    int n, i, count_shared = 0;

    memset(bps, 0, sizeof(bps));
    memset(rbs, 0, sizeof(rbs));

    bps[0].address = 0x1000u; bps[0].saved = 0x55; bps[0].armed = 1;
    bps[1].address = 0x2000u; bps[1].saved = 0x66; bps[1].armed = 1;
    /* Return breakpoint sharing the first entry's address, with the INT3
     * opcode as its "saved" byte — exactly the stale-0xcc hazard. */
    rbs[0].address = 0x1000u; rbs[0].saved = 0xcc; rbs[0].active = 1;
    rbs[1].address = 0x3000u; rbs[1].saved = 0x77; rbs[1].active = 1;

    n = plan_restores(bps, 2, rbs, 2, sites, 8);
    CHECK(n == 3, "aliased address should yield three unique restore sites");
    for (i = 0; i < n; ++i) {
        if (sites[i].address == 0x1000u) {
            ++count_shared;
        }
    }
    CHECK(count_shared == 1, "the shared address must be restored exactly once");
    s = find_site(sites, n, 0x1000u);
    CHECK(s != NULL && s->saved == 0x55,
          "the entry's original byte must win over a saved 0xcc");
    s = find_site(sites, n, 0x2000u);
    CHECK(s != NULL && s->saved == 0x66, "distinct entry address preserved");
    s = find_site(sites, n, 0x3000u);
    CHECK(s != NULL && s->saved == 0x77, "distinct return address preserved");
}

/* Un-armed entries and inactive (already-fired) returns are not restored. */
static void test_plan_restores_skips_inactive(void)
{
    breakpoint bps[2];
    return_bp rbs[1];
    restore_site sites[8];
    int n;

    memset(bps, 0, sizeof(bps));
    memset(rbs, 0, sizeof(rbs));
    bps[0].address = 0x1000u; bps[0].saved = 0x55; bps[0].armed = 0;
    bps[1].address = 0x2000u; bps[1].saved = 0x66; bps[1].armed = 1;
    rbs[0].address = 0x3000u; rbs[0].saved = 0x77; rbs[0].active = 0;

    n = plan_restores(bps, 2, rbs, 1, sites, 8);
    CHECK(n == 1, "un-armed entries and inactive returns are not restored");
    CHECK(n == 1 && sites[0].address == 0x2000u, "only the armed entry remains");
}

/* run_live() refuses to place a return breakpoint on an address an entry
 * breakpoint already patches; that decision is find_entry_bp(). */
static void test_alias_guard_finds_entry(void)
{
    breakpoint bps[2];
    memset(bps, 0, sizeof(bps));
    bps[0].address = 0x4000u; bps[0].armed = 1;
    bps[1].address = 0x5000u; bps[1].armed = 1;
    CHECK(find_entry_bp(bps, 2, 0x4000u) == 0,
          "an armed entry address must be found so a return BP is skipped");
    CHECK(find_entry_bp(bps, 2, 0x9999u) == -1,
          "a non-entry address must not match");
}

int main(void)
{
    g_failures = 0;
    test_plan_restores_dedups_aliased_address();
    test_plan_restores_skips_inactive();
    test_alias_guard_finds_entry();
    if (g_failures == 0) {
        printf("observe-unit: PASS\n");
        return 0;
    }
    printf("observe-unit: FAIL (%d failure(s))\n", g_failures);
    return 1;
}

#else /* !NX86_LIVE_OK */

int main(void)
{
    printf("observe-unit: SKIP (live path unavailable on this platform)\n");
    return 0;
}

#endif /* NX86_LIVE_OK */
