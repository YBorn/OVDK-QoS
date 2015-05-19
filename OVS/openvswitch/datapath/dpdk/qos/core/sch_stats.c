/*
 * =====================================================================================
 *
 *       Filename:  sch_stats.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年10月27日 14时47分30秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Y.Born (), llyangborn@gmail.com
 *   Organization:  
 *
 * =====================================================================================
 */

#include <string.h>
#include <stddef.h>

#include <rte_spinlock.h>
#include <rte_rwlock.h>
#include <rte_timer.h>
#include <rte_malloc.h>

#include "basic.h"
#include "sch_stats.h"
#include "netlink_api.h"
#include "typedefs.h"
#include "../list/list.h"
#include "../list/rbtree.h"
#include "sch_timer.h"

//#define UINT_MAX        (~0U)
#define HZ  100

struct gen_estimator_head
{
//        struct timer_list       timer;
        struct rte_timer        timer; 
        struct list_head        list;
};

static struct gen_estimator_head elist[EST_MAX_INTERVAL+1];

static rte_spinlock_t est_tree_lock = RTE_SPINLOCK_INITIALIZER;
static rte_rwlock_t est_lock = RTE_RWLOCK_INITIALIZER;
static struct rb_root est_root = RB_ROOT;

//static void est_timer(unsigned long arg)
static void est_timer(struct rte_timer *timer __rte_unused, void *arg)
{
        int idx = *((int *)arg);
        struct gen_estimator *e;

//        rcu_read_lock();
//        list_for_each_entry_rcu(e, &elist[idx].list, list) {
        list_for_each_entry(e, &elist[idx].list, list) {
                u64 nbytes;
                u64 brate;
                u32 npackets;
                u32 rate;

//                spin_lock(e->stats_lock);
//                read_lock(&est_lock);
                rte_spinlock_lock(e->stats_lock);
                rte_rwlock_read_lock(&est_lock);
                if (e->bstats == NULL)
                        goto skip;

                nbytes = e->bstats->bytes;
                npackets = e->bstats->packets;
                brate = (nbytes - e->last_bytes)<<(7 - idx);
                e->last_bytes = nbytes;
                e->avbps += (brate >> e->ewma_log) - (e->avbps >> e->ewma_log);
                e->rate_est->bps = (e->avbps+0xF)>>5;

                rate = (npackets - e->last_packets)<<(12 - idx);
                e->last_packets = npackets;
                e->avpps += (rate >> e->ewma_log) - (e->avpps >> e->ewma_log);
                e->rate_est->pps = (e->avpps+0x1FF)>>10;
skip:
                rte_rwlock_read_unlock(&est_lock);
                rte_spinlock_unlock(e->stats_lock);
        }

        unsigned lcore_id = rte_lcore_id();
        if (!list_empty(&elist[idx].list))
//                mod_timer(&elist[idx].timer, jiffies + ((HZ/4) << idx));
                mod_timer(&(elist[idx].timer), JiffiesToTicks((HZ/4) << idx)); 
//        rcu_read_unlock();
}

inline int gnet_stats_copy(struct gnet_dump *d, int type, void *buf, int size)
{
        if (nla_put(d->skb, type, size, buf))
                goto nla_put_failure;
        return 0;

nla_put_failure:
//        rte_spinlock_unlock(d->lock);
        return -1;
}

/**
 * gen_estimator_active - test if estimator is currently in use
 * @bstats: basic statistics
 * @rate_est: rate estimator statistics
 *
 * Returns true if estimator is active, and false if not.
 */
bool gen_estimator_active(const struct gnet_stats_basic_packed *bstats,
                          const struct gnet_stats_rate_est64 *rate_est)
{
        bool res;

//        ASSERT_RTNL();

        rte_spinlock_lock(&est_tree_lock);
        res = gen_find_node(bstats, rate_est) != NULL;
        rte_spinlock_unlock(&est_tree_lock);

        return res;
}

/**
 * gnet_stats_start_copy_compat - start dumping procedure in compatibility mode
 * @skb: socket buffer to put statistics TLVs into
 * @type: TLV type for top level statistic TLV
 * @tc_stats_type: TLV type for backward compatibility struct tc_stats TLV
 * @xstats_type: TLV type for backward compatibility xstats TLV
 * @lock: statistics lock
 * @d: dumping handle
 *
 * Initializes the dumping handle, grabs the statistic lock and appends
 * an empty TLV header to the socket buffer for use a container for all
 * other statistic TLVS.
 *
 * The dumping handle is marked to be in backward compatibility mode telling
 * all gnet_stats_copy_XXX() functions to fill a local copy of struct tc_stats.
 *
 * Returns 0 on success or -1 if the room in the socket buffer was not sufficient.
 */
int
gnet_stats_start_copy_compat(struct sk_buf *skb, int type, int tc_stats_type,
        int xstats_type, rte_spinlock_t *lock, struct gnet_dump *d)
{
        memset(d, 0, sizeof(*d));

//        rte_spinlock_lock(lock);
        d->lock = lock;
        if (type)
                d->tail = (struct nlattr *)skb_tail_pointer(skb);
        d->skb = skb;
        d->compat_tc_stats = tc_stats_type;
        d->compat_xstats = xstats_type;

        if (d->tail)
                return gnet_stats_copy(d, type, NULL, 0);

        return 0;
}

/**
 * gnet_stats_copy_basic - copy basic statistics into statistic TLV
 * @d: dumping handle
 * @b: basic statistics
 *
 * Appends the basic statistics to the top level TLV created by
 * gnet_stats_start_copy().
 *
 * Returns 0 on success or -1 with the statistic lock released
 * if the room in the socket buffer was not sufficient.
 */
int
gnet_stats_copy_basic(struct gnet_dump *d, struct gnet_stats_basic_packed *b)
{
        if (d->compat_tc_stats) {
                d->tc_stats.bytes = b->bytes;
                d->tc_stats.packets = b->packets;
        }

        if (d->tail) {
                struct gnet_stats_basic sb;

                memset(&sb, 0, sizeof(sb));
                sb.bytes = b->bytes;
                sb.packets = b->packets;
                return gnet_stats_copy(d, TCA_STATS_BASIC, &sb, sizeof(sb));
        }
        return 0;
}

/**
 * gnet_stats_copy_rate_est - copy rate estimator statistics into statistics TLV
 * @d: dumping handle
 * @b: basic statistics
 * @r: rate estimator statistics
 *
 * Appends the rate estimator statistics to the top level TLV created by
 * gnet_stats_start_copy().
 *
 * Returns 0 on success or -1 with the statistic lock released
 * if the room in the socket buffer was not sufficient.
 */
int
gnet_stats_copy_rate_est(struct gnet_dump *d,
                         const struct gnet_stats_basic_packed *b,
                         struct gnet_stats_rate_est64 *r)
{
        struct gnet_stats_rate_est est;
        int res;

        if (b && !gen_estimator_active(b, r))
                return 0;

        est.bps = min_t(u64, UINT_MAX, r->bps);
        /* we have some time before reaching 2^32 packets per second */
        est.pps = r->pps;

        if (d->compat_tc_stats) {
                d->tc_stats.bps = est.bps;
                d->tc_stats.pps = est.pps;
        }

        if (d->tail) {
                res = gnet_stats_copy(d, TCA_STATS_RATE_EST, &est, sizeof(est));
                if (res < 0 || est.bps == r->bps)
                        return res;
                /* emit 64bit stats only if needed */
                return gnet_stats_copy(d, TCA_STATS_RATE_EST64, r, sizeof(*r));
        }

        return 0;
}

/**
 * gnet_stats_copy_queue - copy queue statistics into statistics TLV
 * @d: dumping handle
 * @q: queue statistics
 *
 * Appends the queue statistics to the top level TLV created by
 * gnet_stats_start_copy().
 *
 * Returns 0 on success or -1 with the statistic lock released
 * if the room in the socket buffer was not sufficient.
 */
int
gnet_stats_copy_queue(struct gnet_dump *d, struct gnet_stats_queue *q)
{
        if (d->compat_tc_stats) {
                d->tc_stats.drops = q->drops;
                d->tc_stats.qlen = q->qlen;
                d->tc_stats.backlog = q->backlog;
                d->tc_stats.overlimits = q->overlimits;
        }

        if (d->tail)
                return gnet_stats_copy(d, TCA_STATS_QUEUE, q, sizeof(*q));

        return 0;
}

/**
 * gnet_stats_finish_copy - finish dumping procedure
 * @d: dumping handle
 *
 * Corrects the length of the top level TLV to include all TLVs added
 * by gnet_stats_copy_XXX() calls. Adds the backward compatibility TLVs
 * if gnet_stats_start_copy_compat() was used and releases the statistics
 * lock.
 *
 * Returns 0 on success or -1 with the statistic lock released
 * if the room in the socket buffer was not sufficient.
 */
int
gnet_stats_finish_copy(struct gnet_dump *d)
{
        if (d->tail)
                d->tail->nla_len = skb_tail_pointer(d->skb) - (u8 *)d->tail;

        if (d->compat_tc_stats)
                if (gnet_stats_copy(d, d->compat_tc_stats, &d->tc_stats,
                        sizeof(d->tc_stats)) < 0)
                        return -1;

        if (d->compat_xstats && d->xstats) {
                if (gnet_stats_copy(d, d->compat_xstats, d->xstats,
                        d->xstats_len) < 0)
                        return -1;
        }

//        rte_spinlock_unlock(d->lock);
        return 0;
}

/**
 * gnet_stats_copy_app - copy application specific statistics into statistics TLV
 * @d: dumping handle
 * @st: application specific statistics data
 * @len: length of data
 *
 * Appends the application specific statistics to the top level TLV created by
 * gnet_stats_start_copy() and remembers the data for XSTATS if the dumping
 * handle is in backward compatibility mode.
 *
 * Returns 0 on success or -1 with the statistic lock released
 * if the room in the socket buffer was not sufficient.
 */
int
gnet_stats_copy_app(struct gnet_dump *d, void *st, int len)
{
        if (d->compat_xstats) {
                d->xstats = st;
                d->xstats_len = len;
        }

        if (d->tail)
                return gnet_stats_copy(d, TCA_STATS_APP, st, len);

        return 0;
}

void gen_add_node(struct gen_estimator *est)
{
        struct rb_node **p = &est_root.rb_node, *parent = NULL;

        while (*p) {
                struct gen_estimator *e;

                parent = *p;
                e = rb_entry(parent, struct gen_estimator, node);

                if (est->bstats > e->bstats)
                        p = &parent->rb_right;
                else
                        p = &parent->rb_left;
        }
        rb_link_node(&est->node, parent, p);
        rb_insert_color(&est->node, &est_root);
}


struct gen_estimator *gen_find_node(const struct gnet_stats_basic_packed *bstats,
                                    const struct gnet_stats_rate_est64 *rate_est)
{
        struct rb_node *p = est_root.rb_node;

        while (p) {
                struct gen_estimator *e;

                e = rb_entry(p, struct gen_estimator, node);

                if (bstats > e->bstats)
                        p = p->rb_right;
                else if (bstats < e->bstats || rate_est != e->rate_est)
                        p = p->rb_left;
                else
                        return e;
        }
        return NULL;
}

/* gen_new_estimator - create a new rate estimator
 * @bstats: basic statistics
 * @rate_est: rate estimator statistics
 * @stats_lock: statistics lock
 * @opt: rate estimator configuration TLV
 *
 * Creates a new rate estimator with &bstats as source and &rate_est
 * as destination. A new timer with the interval specified in the
 * configuration TLV is created. Upon each interval, the latest statistics
 * will be read from &bstats and the estimated rate will be stored in
 * &rate_est with the statistics lock grabbed during this period.
 *
 * Returns 0 on success or a negative error code.
 *
 */
int gen_new_estimator(struct gnet_stats_basic_packed *bstats,
                      struct gnet_stats_rate_est64 *rate_est,
                      rte_spinlock_t *stats_lock,
                      struct nlattr *opt)
{
        struct gen_estimator *est;
        struct gnet_estimator *parm = nla_data(opt);
        int idx;

        if (nla_len(opt) < (int)sizeof(*parm))
                return -EINVAL;

        if (parm->interval < -2 || parm->interval > 3)
                return -EINVAL;

//        est = kzalloc(sizeof(*est), GFP_KERNEL);
        est = rte_zmalloc(NULL, sizeof(*est), 0);
        if (est == NULL)
                return -ENOBUFS;

        idx = parm->interval + 2;
        est->bstats = bstats;
        est->rate_est = rate_est;
        est->stats_lock = stats_lock;
        est->ewma_log = parm->ewma_log;
        est->last_bytes = bstats->bytes;
        est->avbps = rate_est->bps<<5;
        est->last_packets = bstats->packets;
        est->avpps = rate_est->pps<<10;

        rte_spinlock_lock(&est_tree_lock);
        if (!elist[idx].timer.f) {
                INIT_LIST_HEAD(&elist[idx].list);
                setup_timer(&elist[idx].timer, est_timer, &idx);
        }

        if (list_empty(&(elist[idx].list))) {
//                mod_timer(&elist[idx].timer, jiffies + ((HZ/4) << idx));
                mod_timer(&(elist[idx].timer), JiffiesToTicks((HZ/4) << idx));
        }
        list_add(&est->list, &elist[idx].list);
        gen_add_node(est);
        rte_spinlock_unlock(&est_tree_lock);

        return 0;
}

/**
 * gen_kill_estimator - remove a rate estimator
 * @bstats: basic statistics
 * @rate_est: rate estimator statistics
 *
 * Removes the rate estimator specified by &bstats and &rate_est.
 *
 * Note : Caller should respect an RCU grace period before freeing stats_lock
 */
void gen_kill_estimator(struct gnet_stats_basic_packed *bstats,
                        struct gnet_stats_rate_est64 *rate_est)
{
        struct gen_estimator *e;

        rte_spinlock_lock(&est_tree_lock);
        while ((e = gen_find_node(bstats, rate_est))) {
                rb_erase(&e->node, &est_root);

                rte_rwlock_write_lock(&est_lock);
                e->bstats = NULL;
                rte_rwlock_write_unlock(&est_lock);

                list_del_rcu(&e->list);
//                kfree_rcu(e, e_rcu);
                rte_free(e);
        }
        rte_spinlock_unlock(&est_tree_lock);
}

/**
 * gen_replace_estimator - replace rate estimator configuration
 * @bstats: basic statistics
 * @rate_est: rate estimator statistics
 * @stats_lock: statistics lock
 * @opt: rate estimator configuration TLV
 *
 * Replaces the configuration of a rate estimator by calling
 * gen_kill_estimator() and gen_new_estimator().
 *
 * Returns 0 on success or a negative error code.
 */
int gen_replace_estimator(struct gnet_stats_basic_packed *bstats,
                          struct gnet_stats_rate_est64 *rate_est,
                          rte_spinlock_t *stats_lock, struct nlattr *opt)
{
        gen_kill_estimator(bstats, rate_est);
        return gen_new_estimator(bstats, rate_est, stats_lock, opt);
}
// 
// /**
//  * gen_estimator_active - test if estimator is currently in use
//  * @bstats: basic statistics
//  * @rate_est: rate estimator statistics
//  *
//  * Returns true if estimator is active, and false if not.
//  */
// bool gen_estimator_active(const struct gnet_stats_basic_packed *bstats,
//                           const struct gnet_stats_rate_est64 *rate_est)
// {
//         bool res;
// 
//         ASSERT_RTNL();
// 
//         spin_lock_bh(&est_tree_lock);
//         res = gen_find_node(bstats, rate_est) != NULL;
//         spin_unlock_bh(&est_tree_lock);
// 
//         return res;
// }
