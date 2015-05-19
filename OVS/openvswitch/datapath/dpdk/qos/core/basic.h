#ifndef __BASIC_H__
#define __BASIC_H__

#include <stdbool.h>
#include <stdio.h>
#include <strings.h>

#include "typedefs.h"

#define __read_mostly __attribute__((__section__(".data..read_mostly")))

#define container_of(ptr, type, member) ({                  \
    const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
    (type *) ( (char *)__mptr - offsetof(type, member) );})

#define min_t(type, x, y) ({                                \
        type __min1 = (x);                                  \
        type __min2 = (y);                                  \
        __min1 < __min2 ? __min1 : __min2; })

#define max_t(type, x, y) ({                                \
        type __max1 = (x);                                  \
        type __max2 = (y);                                  \
        __max1 > __max2 ? __max1 : __max2; })

#define typecheck(type, x) ({                               \
        type __dummy;                                       \
        typeof(x) __dummy2;                                 \
        (void) (&__dummy == &__dummy2);                     \
        1;  })

#define WARN_ON(condition) do {                             \
    if (unlikely(condition))                                \
        printf("WARN at %s:%d %s()!\n", __FILE__, __LINE__, __func__); \
} while (0)
        

#define BUG() do { \
        printf("BUG at %s:%d %s()!\n", __FILE__, __LINE__, __func__); \
} while (0)

#define BUG_ON(condition) do { if (unlikely(condition)) BUG(); } while (0)

#define time_after(a, b)        ((long) ((b) - (a)) < 0)

#define time_before(a, b)       time_after(b,a)

/************************************************************
#define time_after_eq(a,b)                                  \
        (typecheck(unsigned long, a) &&                     \
         typecheck(unsigned long, b) &&                     \
         ((long) ((a) - (b)) >= 0))
************************************************************/

#define time_after_eq(a,b) ((long) ((a) - (b)) >= 0)

#define time_before_eq(a, b)       time_after_eq(b,a)

/* Need to test the API */
static inline bool
// test_bit(unsigned int bit, volatile unsigned long *addr) {
test_bit(unsigned int bit, unsigned long *addr) {
    unsigned long  mask = 1UL << (bit & 31);
    return  __sync_and_and_fetch(addr, mask);
//    return *addr & mask;
}

static inline void
// set_bit(unsigned int bit, volatile unsigned long *addr) {
set_bit(unsigned int bit, unsigned long *addr) {
    unsigned long mask = 1UL << (bit & 31);
    __sync_or_and_fetch(addr, mask);
//    *addr |= mask;
}

static inline void
// clear_bit(unsigned int bit, volatile unsigned long *addr) {
clear_bit(unsigned int bit, unsigned long *addr) {
    unsigned long mask = 1UL << (bit & 31);
    __sync_and_and_fetch(addr, ~mask);
//    *addr &= ~mask;
}

static inline u64
div64_u64(u64 dividend, u64 divisor) {
    return dividend / divisor;
}

#define do_div(n,base) ({                                      \
        uint32_t __base = (base);                               \
        uint32_t __rem;                                         \
        __rem = ((uint64_t)(n)) % __base;                       \
        (n) = ((uint64_t)(n)) / __base;                         \
        __rem;                                                  \
})

#define ffz(x) (ffs(~(x))-1)

#endif /* __BASIC_H__ */
