#ifndef __SCH_TIMER_H_
#define __SCH_TIMER_H_

#include <rte_timer.h>

#define setup_timer(_timer, _function, _arg) \
do { \
    (_timer)->f = _function; \
    (_timer)->arg = _arg; \
    rte_timer_init(_timer); \
} while (0)

#define mod_timer(_timer, _ticks) \
do { \
    unsigned lcore_id = rte_lcore_id(); \
    rte_timer_reset_sync(_timer, _ticks, SINGLE, lcore_id, (_timer)->f, (_timer)->arg); \
} while (0)

static inline uint64_t JiffiesToTicks(uint64_t _jiffes) {
    return _jiffes*100;
}

#endif /* __SCH_TIMER_H_ */
