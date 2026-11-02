/* User-mode tests of the driver's token bucket and hash (nlbucket.h). */
#include <stdio.h>
#include <string.h>
#include "../nlbucket.h"

static int failures;
#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
            failures++;                                                 \
        }                                                               \
    } while (0)

/* Feed 1400-byte chunks for `seconds` of simulated time, asking every
   `step` (100 ns units) as a timer would; return bytes admitted. */
static unsigned long long simulate(unsigned long long rate, unsigned long long chunk, unsigned long long step,
                                   int seconds)
{
    NL_BUCKET b;
    unsigned long long t, total = 0;
    nl_bucket_init(&b, rate, 0);
    for (t = 0; t < (unsigned long long)seconds * NL_SECOND; t += step)
        while (nl_admit(&b, chunk, t))
            total += chunk;
    return total;
}

int main(void)
{
    NL_BUCKET b;
    unsigned long long got;
    int i;

    /* Starts with a quarter second (at least 16 KB) of budget, then debt. */
    nl_bucket_init(&b, 1000000, 0);
    CHECK(b.tokens == 250000);
    CHECK(nl_admit(&b, 300000, 0));
    CHECK(b.tokens == -50000);
    CHECK(!nl_admit(&b, 1, 0));
    CHECK(!nl_admit(&b, 1, NL_SECOND / 20));      /* +50000: still 0, not > 0 */
    CHECK(nl_admit(&b, 1, NL_SECOND / 20 + 10));  /* +1 byte later: positive */

    /* Never more than the burst after a long pause, and no overflow. */
    nl_bucket_init(&b, 10ull * 1000 * 1000 * 1000, 0);
    nl_refill(&b, 1000ull * 3600 * NL_SECOND);
    CHECK(b.tokens == nl_burst(b.rate));

    /* Slow rates still accumulate across many tiny steps. */
    nl_bucket_init(&b, 100, 0);
    b.tokens = 0;
    for (i = 1; i <= 1000; i++)
        nl_refill(&b, (unsigned long long)i * 10000); /* 1 ms steps, 1 s total */
    CHECK(b.tokens >= 99 && b.tokens <= 100);

    /* Average rate holds within 2% over 10 s, for small and large chunks,
       with a 15.6 ms timer (Windows' default tick). */
    got = simulate(100 * 1024, 1400, 156250, 10);
    CHECK(got > 100 * 1024 * 10 * 98 / 100 && got < 100 * 1024 * 10 * 102 / 100 + 64 * 1024);
    got = simulate(2 * 1024 * 1024, 64 * 1024, 156250, 10);
    CHECK(got > 2ull * 1024 * 1024 * 10 * 98 / 100 && got < 2ull * 1024 * 1024 * 10 * 102 / 100 + 1024 * 1024);

    /* FNV-1a 64 reference values (also checked by src/kdriver.rs). */
    CHECK(nl_hash((const unsigned char *)"", 0) == 0xcbf29ce484222325ull);
    CHECK(nl_hash((const unsigned char *)"a", 1) == 0xaf63dc4c8601ec8cull);

    if (failures) {
        printf("%d check(s) failed\n", failures);
        return 1;
    }
    printf("bucket tests passed\n");
    return 0;
}
