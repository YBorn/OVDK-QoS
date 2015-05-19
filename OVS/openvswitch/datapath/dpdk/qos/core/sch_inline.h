/*
 * =====================================================================================
 *
 *       Filename:  sch_inline.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年04月20日 13时55分37秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Y.Born (CD), llyangborn@gmail.com
 *   Organization:  
 *
 * =====================================================================================
 */

#ifndef __SCH_INLINE_H_
#define __SCH_INLINE_H_

#include <time.h>
#include <string.h>

#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_common.h>
#include <rte_lcore.h>
#include <rte_ring.h>
#include <rte_malloc.h>

#include "rte_generic.h"
#include "sch_generic.h"
#include "sch_qdisc.h"

#include "../list/list.h"
#include "typedefs.h"

static inline uint32_t
qdisc_class_hash(u32 classid, u32 mask) {
    classid ^= classid >> 8;
    classid ^= classid >> 4;
    return classid & mask;
//    return classid % (mask+1);
}

static inline struct Qdisc_class_common *
qdisc_class_find(const struct Qdisc_class_hash *clhash, u32 clid) {
    struct Qdisc_class_common *clcom;
    unsigned int h;
    
    h = qdisc_class_hash(clid, clhash->hashmask);
    hlist_for_each_entry(clcom, &clhash->hash[h], hnode) {
        if(clcom->classid == clid)
            return clcom;
    }

    return NULL;
}

/**
 *  TODO: The same name "class_hash_table" maybe cause problem
 */

static inline struct hlist_head*
qdisc_class_hash_alloc(uint32_t n) {
    struct hlist_head *h;
    unsigned int i;
    h = (struct hlist_head *) secure_zmalloc(NULL,
                           n * sizeof(struct hlist_head), 0);

    // Initialize class_hash_table
    for(i = 0; i < n; i++) {
        INIT_HLIST_HEAD(&h[i]);
    }
    return h;
}

static inline int
qdisc_class_hash_init(struct Qdisc_class_hash * clhash) {
    uint32_t size = 4;

    clhash->hash = qdisc_class_hash_alloc(size);
    if (clhash->hash == NULL)
        printf("hash init failed\n");
    clhash->hashsize = size;
    clhash->hashmask = size - 1;
    clhash->hashelems = 0;
    return 0;
}

static inline void
qdisc_class_hash_insert(struct Qdisc_class_hash *clhash,
                           struct Qdisc_class_common *clcom) {
    unsigned int h;
   
    INIT_HLIST_NODE(&clcom->hnode);
    h = qdisc_class_hash(clcom->classid, clhash->hashmask);
    hlist_add_head(&clcom->hnode, &clhash->hash[h]);
    clhash->hashelems++;
}

static inline void
qdisc_class_hash_remove(struct Qdisc_class_hash *clhash,
                           struct Qdisc_class_common *clcom) {
    hlist_del(&clcom->hnode);
    clhash->hashelems--;
}

static inline void
qdisc_class_hash_free(struct hlist_head *h, unsigned int n __rte_unused)
{
//        unsigned int size = n * sizeof(struct hlist_head);
//
//        if (size <= PAGE_SIZE)
                rte_free(h);
//        else
//                free_pages((unsigned long)h, get_order(size));
}

static inline void
qdisc_class_hash_grow(struct Qdisc *sch __rte_unused, struct Qdisc_class_hash *clhash) {
    struct Qdisc_class_common *cl;
    struct hlist_node *next;
    struct hlist_head *nhash, *ohash;
    unsigned int nsize, nmask, osize;
    unsigned int i, h;

    /* Rehash when load factor exceeds 0.75 */
    if (clhash->hashelems * 4 <= clhash->hashsize * 3)
            return;
    nsize = clhash->hashsize * 2;
    nmask = nsize - 1;
    nhash = qdisc_class_hash_alloc(nsize);
    if (nhash == NULL)
            return;

    ohash = clhash->hash;
    osize = clhash->hashsize;

//    sch_tree_lock(sch);
    for (i = 0; i < osize; i++) {
            hlist_for_each_entry_safe(cl, next, &ohash[i], hnode) {
                    h = qdisc_class_hash(cl->classid, nmask);
                    hlist_add_head(&cl->hnode, &nhash[h]);
            }
    }
    clhash->hash     = nhash;
    clhash->hashsize = nsize;
    clhash->hashmask = nmask;
//    sch_tree_unlock(sch);

    qdisc_class_hash_free(ohash, osize);
}

static inline void
qdisc_class_hash_destroy(struct Qdisc_class_hash *clhash) {
    qdisc_class_hash_free(clhash->hash, clhash->hashsize);
}

static inline void *
qdisc_priv(struct Qdisc *q) {
    return (char *) q + QDISC_ALIGN(sizeof(struct Qdisc));
}

static inline unsigned int
qdisc_pkt_len(const struct rte_mbuf *pkt) {
//    const struct rte_mbuf *seg = pkt;
//    int len = 0;
//    while(seg != NULL) {
//        len += rte_pktmbuf_pkt_len(seg);
//        seg = seg->pkt.next;
//    }
//    return len;
    return rte_pktmbuf_pkt_len(pkt);
}

static inline void
bstats_update(struct gnet_stats_basic_packed *bstats,
                                 const struct rte_mbuf *pkt) {
    bstats->bytes += qdisc_pkt_len(pkt);
    // 是否需要判断是否是分段的数据包
    bstats->packets += pkt->pkt.nb_segs;
}

static inline void
qdisc_bstats_update(struct Qdisc *sch, const struct rte_mbuf *pkt) {
    bstats_update(&sch->bstats, pkt);
}

static inline int
qdisc_drop(struct rte_mbuf *pkt, struct Qdisc *sch) {
    rte_pktmbuf_free(pkt);
    sch->qstats.drops++;

    return NET_XMIT_DROP;
}

//static inline struct Qdisc *
//qdisc_root_sleeping(const struct Qdisc *qdisc) {
//    return qdisc->vport->qdisc_sleeping;
//}

// TODO: Maybe need qdisc_calculate_pkt_len
static inline int
qdisc_enqueue(struct rte_mbuf *pkt, struct Qdisc *sch) {
    return sch->enqueue(pkt, sch);
}

static inline int
qdisc_enqueue_tail(struct rte_mbuf *pkt, struct Qdisc *sch) {
      rte_ring_enqueue(sch->q, (void *)pkt);
      sch->qlen++;
      sch->qstats.backlog += qdisc_pkt_len(pkt);
      return NET_XMIT_SUCCESS;
}

/* use instead of qdisc->dequeue() for all qdiscs queried with ->peek() */
static inline struct rte_mbuf *
qdisc_dequeue_peeked(struct Qdisc *sch) {
     struct rte_mbuf *pkt = sch->gso_pkt;

     if (pkt) {
             sch->gso_pkt = NULL;
             sch->qlen--;
     } else {
             pkt = sch->dequeue(sch);
     }

     return pkt;
}

static inline struct rte_mbuf *
qdisc_peek_dequeued(struct Qdisc *sch) {
    if(!sch->gso_pkt) {
        sch->gso_pkt = sch->dequeue(sch);
        if(sch->gso_pkt)
            sch->qlen++;
    }
    return sch->gso_pkt;
}

static inline struct rte_mbuf *
qdisc_dequeue_head(struct Qdisc *sch) {
    struct rte_mbuf *pkt = NULL;

    int ret = rte_ring_dequeue(sch->q, (void **)&pkt);
    if(likely(ret == 0)) {
        sch->qlen--;
        sch->qstats.backlog -= qdisc_pkt_len(pkt);
        qdisc_bstats_update(sch, pkt);
    }

    return pkt;
}

/* Avoid doing 64 bit divide */
#define PSCHED_SHIFT                    6
#define PSCHED_TICKS2NS(x)              ((s64)(x) << PSCHED_SHIFT)
#define PSCHED_NS2TICKS(x)              ((x) >> PSCHED_SHIFT)
/* time */
static inline u64
psched_l2t_ns(const struct psched_ratecfg *r,
                                unsigned int len) {
    len += r->overhead;

    
    int i = ((u64)len * r->mult) >> r->shift;
    // return ((u64)len * r->mult) >> r->shift;
     return ((u64)len * 1000000000)/r->rate_bytes_ps;
}

//struct timespec {
//    time_t   tv_sec;        /* seconds */
//    long     tv_nsec;       /* nanoseconds */
//};

typedef struct timespec ktime_t;

static inline ktime_t
ktime_get() {
    ktime_t res;

    clock_gettime(CLOCK_REALTIME, &res);
    return res;
}

#define NSEC_PER_SEC    1000000000L
static inline s64
ktime_to_ns(const ktime_t kt) {
    return (s64) kt.tv_sec * NSEC_PER_SEC + kt.tv_nsec;
}

static inline ktime_t
ns_to_ktime(u64 ns){
        ktime_t ktime = {
            .tv_sec = ns / NSEC_PER_SEC,
            .tv_nsec = ns % NSEC_PER_SEC ,
        };

        return ktime;
}

static inline u64
get_jiffies(void) {
    return rte_get_timer_cycles()/(rte_get_timer_hz()/250);
//    return ktime_to_ns(ktime_get())/4000000UL;
}

static inline bool
qdisc_is_throttled(struct Qdisc *sch) {
    return test_bit(__QDISC_STATE_THROTTLED, &sch->state) ? true : false;
}

static inline void
qdisc_throttled(struct Qdisc *sch) {
    set_bit(__QDISC_STATE_THROTTLED, &sch->state);
}

static inline void
qdisc_unthrottled(struct Qdisc *sch) {
    clear_bit(__QDISC_STATE_THROTTLED, &sch->state);
}

/**
 *  TODO: finish the netif_schedule function
 *
 */
static inline void
qdisc_watchdog(struct rte_timer *timer, void *arg __rte_unused) {
    struct Qdisc_watchdog *wd = container_of(timer, struct Qdisc_watchdog, timer);

    qdisc_unthrottled(wd->qdisc);
//    __netif_schedule(qdisc_root(wd->qdisc));
    
}

static inline unsigned long
ns_to_ticks(unsigned long ns) {
    return ns;    
}

static inline void
hrtimer_init(struct rte_timer *timer) {
    rte_timer_init(timer);
}

static inline void
hrtimer_start(struct rte_timer *timer, uint64_t ticks, const enum rte_timer_type type) {
    unsigned lcore = rte_lcore_id();
//  Why there is only one call-back arg in this fuction?
//  But there is two call-back args in rte_timer_cb_t?
//  Why ??
    rte_timer_reset_sync(timer, ticks, type, lcore, qdisc_watchdog, NULL);
}

static inline void
hrtimer_cancel(struct rte_timer *timer) {
    rte_timer_stop_sync(timer);
}

static inline void
qdisc_watchdog_cancel(struct Qdisc_watchdog *wd) {
    hrtimer_cancel(&wd->timer);
    qdisc_unthrottled(wd->qdisc);
}

/** First:
 *  There is a problem: the callback of rte_timer should be waked up
 *  by rte_timer_manager(). We have to alloc a lcore to do this.
 *  Otherwise it is not precise.
 *  Second:
 *  We can use POSIX api, because it support nanosecond-level precison.
 *      timer_create()
 *      timer_delete()
 *      timer_gettime()
 *      timer_settime()
 *  Three:
 *  Is there a way to use kernel timer in userspace ??
 */

static inline void
qdisc_watchdog_init(struct Qdisc_watchdog *wd, struct Qdisc *sch) {
    hrtimer_init(&wd->timer);
    wd->timer.f = qdisc_watchdog;
    wd->qdisc = sch;
}

#define MAX_PKTS 30
static inline void
__skb_queue_purge(struct rte_ring *q) {
    struct rte_mbuf *pkt[MAX_PKTS];
    int n;
    while((n = rte_ring_dequeue_burst(q, (void**)pkt, MAX_PKTS)) != 0) {
        while(n)
            rte_pktmbuf_free(pkt[--n]);
    }
}

static inline void
qdisc_reset(struct Qdisc *qdisc) {
    const struct Qdisc_ops *ops = qdisc->ops;

    if(ops->reset)
        ops->reset(qdisc);
    if(qdisc->gso_pkt) {
        rte_pktmbuf_free(qdisc->gso_pkt);
        qdisc->gso_pkt = NULL;
        qdisc->qlen = 0;
    }
}

static inline unsigned int
qdisc_queue_drop(struct Qdisc *qdisc) {
    int len = 0;
    struct rte_mbuf *pkt = qdisc_dequeue_head(qdisc);
    if(pkt != NULL) {
        len = qdisc_pkt_len(pkt);
        rte_pktmbuf_free(pkt);
    }
    return len;
}

static void
qdisc_tree_decrease_qlen(struct Qdisc *sch, unsigned int n)
{
        const struct Qdisc_class_ops *cops;
        unsigned long cl;
        uint32_t parentid;
        int drops;

        if (n == 0)
                return;
        drops = max_t(int, n, 0);
        while ((parentid = sch->parent)) {
                if (TC_H_MAJ(parentid) == TC_H_MAJ(TC_H_INGRESS))
                        return;

                sch = qdisc_lookup(qdisc_vport(sch), TC_H_MAJ(parentid));
                if (sch == NULL) {
                        WARN_ON(parentid != TC_H_ROOT);
                        return;
                }
                cops = sch->ops->cl_ops;
                if (cops->qlen_notify) {
                        cl = cops->get(sch, parentid);
                        cops->qlen_notify(sch, cl);
                        cops->put(sch, cl);
                }
                sch->qlen -= n;
                sch->qstats.drops += drops;
        }
}

static inline void psched_ratecfg_getrate(struct tc_ratespec *res,
                                          const struct psched_ratecfg *r)
{
        memset(res, 0, sizeof(*res));

        /* legacy struct tc_ratespec has a 32bit @rate field
         * Qdisc using 64bit rate should add new attributes
         * in order to maintain compatibility.
         */
        res->rate = min_t(u64, r->rate_bytes_ps, ~0U);

        res->overhead = r->overhead;
        res->linklayer = (r->linklayer & TC_LINKLAYER_MASK);
}

static inline void psched_ratecfg_precompute(struct psched_ratecfg *r,
                               const struct tc_ratespec *conf,
                               u64 rate64)
{
        memset(r, 0, sizeof(*r));
        r->overhead = conf->overhead;
        r->rate_bytes_ps = max_t(u64, conf->rate, rate64);
        r->linklayer = (conf->linklayer & TC_LINKLAYER_MASK);
        r->mult = 1;
        /*
         * The deal here is to replace a divide by a reciprocal one
         * in fast path (a reciprocal divide is a multiply and a shift)
         *
         * Normal formula would be :
         *  time_in_ns = (NSEC_PER_SEC * len) / rate_bps
         *
         * We compute mult/shift to use instead :
         *  time_in_ns = (len * mult) >> shift;
         *
         * We try to get the highest possible mult value for accuracy,
         * but have to make sure no overflows will ever happen.
         */
        if (r->rate_bytes_ps > 0) {
                u64 factor = NSEC_PER_SEC;

                for (;;) {
                        r->mult = div64_u64(factor, r->rate_bytes_ps);
                        if (r->mult & (1U << 31) || factor & (1ULL << 63))
                                break;
                        factor <<= 1;
                        r->shift++;
                }
        }
}

#include "../../vport_define.h"
static inline struct Qdisc *qdisc_root_sleeping(const struct Qdisc *qdisc)
{
        return qdisc->vport->qdisc_sleeping;
}

static inline void qdisc_warn_nonwc(const char *txt, struct Qdisc *qdisc)
{
        if (!(qdisc->flags & TCQ_F_WARN_NONWC)) {
                printf("%s: %s qdisc %X: is non-work-conserving?\n",
                        txt, qdisc->ops->id, qdisc->handle >> 16);
                qdisc->flags |= TCQ_F_WARN_NONWC;
        }
}

#endif /* __SCH_INLINE_H_ */
