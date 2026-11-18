#ifndef PAPER_BENCH_COUNTERS_H
#define PAPER_BENCH_COUNTERS_H
#include <stdint.h>
/* Shared by firmware and the host boundary test. Unsigned subtraction handles
 * a low-word rollover and a full 64-bit rollover without elapsed-time guesses. */
static inline void paper_split_elapsed(uint64_t now, uint64_t start,
                                       uint32_t *low, uint32_t *high)
{
    uint64_t elapsed = now - start;
    *low = (uint32_t)elapsed;
    *high = (uint32_t)(elapsed >> 32);
}
#endif
