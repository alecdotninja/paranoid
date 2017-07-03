#include <time.h>
#include "arch/cc.h"

/** Returns the current time in milliseconds,
 * may be the same as sys_jiffies or at least based on it. */
u32_t
sys_now(void)
{
    struct timespec tp;
    /* CLOCK_BOOTTIME includes time spent in suspend */
    clock_gettime(CLOCK_BOOTTIME, &tp);
    return tp.tv_sec * 1000 + tp.tv_nsec / 1000000;
}