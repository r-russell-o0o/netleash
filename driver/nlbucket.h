/*
 * Token bucket in plain C (no kernel headers), so tests/bucket_test.c can
 * check it on any PC. Time is in 100 ns units (KeQueryInterruptTime).
 *
 * The bucket may go into debt: a chunk is let through whenever the balance
 * is positive, and its full size is subtracted. Large TCP chunks then make
 * the program wait proportionally longer, so the average rate holds without
 * having to split chunks.
 */
#pragma once

#define NL_SECOND 10000000ull
#define NL_MIN_BURST (16ll * 1024)

typedef struct NL_BUCKET {
    long long tokens;           /* bytes; negative = debt */
    unsigned long long rate;    /* bytes per second */
    unsigned long long last;    /* time of the last refill */
} NL_BUCKET;

static __inline long long nl_burst(unsigned long long rate)
{
    long long b = (long long)(rate / 4); /* a quarter second's worth */
    return b > NL_MIN_BURST ? b : NL_MIN_BURST;
}

static __inline void nl_bucket_init(NL_BUCKET *b, unsigned long long rate, unsigned long long now)
{
    b->rate = rate;
    b->tokens = nl_burst(rate);
    b->last = now;
}

static __inline void nl_refill(NL_BUCKET *b, unsigned long long now)
{
    unsigned long long dt, add;
    if (now <= b->last)
        return;
    dt = now - b->last;
    if (dt > NL_SECOND)
        dt = NL_SECOND; /* also keeps rate * dt far from overflowing */
    add = b->rate * dt / NL_SECOND;
    if (add == 0)
        return; /* keep `last`, so slow rates still accumulate */
    b->last = now;
    b->tokens += (long long)add;
    if (b->tokens > nl_burst(b->rate))
        b->tokens = nl_burst(b->rate);
}

/* Refill, then: may `bytes` pass now? If so, they are charged. */
static __inline int nl_admit(NL_BUCKET *b, unsigned long long bytes, unsigned long long now)
{
    nl_refill(b, now);
    if (b->tokens <= 0)
        return 0;
    b->tokens -= (long long)bytes;
    return 1;
}

/* FNV-1a 64; src/kdriver.rs computes the same over the same app ID bytes. */
static __inline unsigned long long nl_hash(const unsigned char *data, unsigned long size)
{
    unsigned long long h = 0xcbf29ce484222325ull;
    unsigned long i;
    for (i = 0; i < size; i++) {
        h ^= data[i];
        h *= 0x100000001b3ull;
    }
    return h;
}
