#ifndef __LINUX_GEN_STATS_H
#define __LINUX_GEN_STATS_H

#include <stdbool.h>

#include <rte_spinlock.h>

#include "pkt_sched.h"
#include "typedefs.h"
#include "../list/list.h"
#include "../list/rbtree.h"

struct sk_buf;
struct nlattr;

enum {
        TCA_STATS_UNSPEC,
        TCA_STATS_BASIC,
        TCA_STATS_RATE_EST,
        TCA_STATS_QUEUE,
        TCA_STATS_APP,
        TCA_STATS_RATE_EST64,
        __TCA_STATS_MAX,
};
#define TCA_STATS_MAX (__TCA_STATS_MAX - 1)

/**
 * struct gnet_stats_basic - byte/packet throughput statistics
 * @bytes: number of seen bytes
 * @packets: number of seen packets
 */
struct gnet_stats_basic {
        u64   bytes;
        u32   packets;
};
struct gnet_stats_basic_packed {
        u64   bytes;
        u32   packets;
} __attribute__ ((packed));

/**
 * struct gnet_stats_rate_est - rate estimator
 * @bps: current byte rate
 * @pps: current packet rate
 */
struct gnet_stats_rate_est {
        u32   bps;
        u32   pps;
};

/**
 * struct gnet_stats_rate_est64 - rate estimator
 * @bps: current byte rate
 * @pps: current packet rate
 */
struct gnet_stats_rate_est64 {
        u64   bps;
        u64   pps;
};

/**
 * struct gnet_stats_queue - queuing statistics
 * @qlen: queue length
 * @backlog: backlog size of queue
 * @drops: number of dropped packets
 * @requeues: number of requeues
 * @overlimits: number of enqueues over the limit
 */
struct gnet_stats_queue {
        u32   qlen;
        u32   backlog;
        u32   drops;
        u32   requeues;
        u32   overlimits;
};

/**
 * struct gnet_estimator - rate estimator configuration
 * @interval: sampling period
 * @ewma_log: the log of measurement window weight
 */
struct gnet_estimator {
        signed char     interval;
        unsigned char   ewma_log;
};

struct psched_ratecfg {
        u64     rate_bytes_ps;
        u32     mult;
        u16     overhead;
        u8      linklayer;
        u8      shift;
};

struct gnet_dump {
        rte_spinlock_t *    lock;
        struct sk_buf *    skb;
        struct nlattr *     tail;

        /* Backward compatibility */
        int               compat_tc_stats;
        int               compat_xstats;
        void *            xstats;
        int               xstats_len;
        struct tc_stats   tc_stats;
};

#define EST_MAX_INTERVAL        5

struct gen_estimator
{
        struct list_head        list;
        struct gnet_stats_basic_packed  *bstats;
        struct gnet_stats_rate_est64    *rate_est;
        rte_spinlock_t              *stats_lock;
        int                     ewma_log;
        u64                     last_bytes;
        u64                     avbps;
        u32                     last_packets;
        u32                     avpps;
//        struct rcu_head         e_rcu;
        struct rb_node          node;
};

int gnet_stats_copy(struct gnet_dump *d, int type, void *buf, int size);

bool gen_estimator_active(const struct gnet_stats_basic_packed *bstats,
                          const struct gnet_stats_rate_est64 *rate_est);

int gnet_stats_start_copy_compat(struct sk_buf *skb, int type, int tc_stats_type,
        int xstats_type, rte_spinlock_t *lock, struct gnet_dump *d);

int gnet_stats_copy_basic(struct gnet_dump *d, struct gnet_stats_basic_packed *b);

int gnet_stats_copy_rate_est(struct gnet_dump *d,
                         const struct gnet_stats_basic_packed *b,
                         struct gnet_stats_rate_est64 *r);

int gnet_stats_copy_queue(struct gnet_dump *d, struct gnet_stats_queue *q);

int gnet_stats_finish_copy(struct gnet_dump *d);

bool gen_estimator_active(const struct gnet_stats_basic_packed *bstats,
                          const struct gnet_stats_rate_est64 *rate_est);

struct gen_estimator *gen_find_node(const struct gnet_stats_basic_packed *bstats,
                                    const struct gnet_stats_rate_est64 *rate_est);

void gen_kill_estimator(struct gnet_stats_basic_packed *bstats,
                        struct gnet_stats_rate_est64 *rate_est);

int gen_new_estimator(struct gnet_stats_basic_packed *bstats,
                      struct gnet_stats_rate_est64 *rate_est,
                      rte_spinlock_t *stats_lock,
                      struct nlattr *opt);
int gen_replace_estimator(struct gnet_stats_basic_packed *bstats,
                          struct gnet_stats_rate_est64 *rate_est,
                          rte_spinlock_t *stats_lock, struct nlattr *opt);

int gnet_stats_copy_app(struct gnet_dump *d, void *st, int len);

#endif /* __LINUX_GEN_STATS_H */
