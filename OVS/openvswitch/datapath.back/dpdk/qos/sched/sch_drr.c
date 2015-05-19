/*
 * =====================================================================================
 *
 *       Filename:  drr_sch.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年04月06日 19时54分52秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Y.Born (CD), llyangborn@gmail.com
 *   Organization:  UESTC
 *
 * =====================================================================================
 */

//#include <stdint.h>
//
//#include <rte_ring.h>
//#include <rte_mbuf.h>
//#include <rte_ethdev.h>
//#include <rte_string_fns.h>
//#include <rte_atomic.h>
//#include <rte_cycles.h>
//#include <rte_malloc.h>
//
//#include "rte_generic.h"
//#include "sch_stats.h"
//#include "list/list.h"
//#include "sch_generic.h"
//#include "sch_inline.h"
//#include "basic.h"
//#include "../vport_define.h"
//
//#include "drr_sch.h"
//
//#define MAX_CLASS_NAME_SIZE 15
//#define CLASS_NAME "drr_Class_%u"
//#define MAX_QUEUE_NAME_SIZE 15
//#define QUEUE_NAME "drr_Queue_%u"
//#define NUM_CLASS 4
//
//#define MAXBUFS 500

#include <rte_ring.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>

#include <linux/rtnetlink.h>
#include <linux/netlink.h>

#include "../core/sch_inline.h"
#include "../core/sch_generic.h"
#include "../core/netlink_api.h"
#include "../core/sch_qdisc.h"
#include "../core/errno-base.h"
#include "../core/err.h"
#include "../core/pkt_sched.h"
#include "../../vport_define.h"

#define LOGTYPE_QoS LOGTYPE_USER1
#define QUANTUM 5000

extern struct Qdisc_ops pfifo_qdisc_ops;
extern struct Qdisc     noop_qdisc;

struct drr_class {
    struct Qdisc_class_common   common;
    unsigned int                refcnt;

    
    struct gnet_stats_basic_packed  bstats;
    struct gnet_stats_queue         qstats;
    struct gnet_stats_rate_est64    rate_est;
    struct list_head            alist;
    struct Qdisc               *qdisc;

    uint32_t                quantum;
    uint32_t                deficit;
};

struct drr_sched {
    struct list_head         active;
    struct Qdisc_class_hash  clhash;
};

static struct drr_class *drr_find_class(struct Qdisc *sch, uint32_t classid)
{
        struct drr_sched *q = qdisc_priv(sch);
        struct Qdisc_class_common *clc;

        clc = qdisc_class_find(&q->clhash, classid);
        if (clc == NULL)
                return NULL;
        return container_of(clc, struct drr_class, common);
}

static void drr_purge_queue(struct drr_class *cl)
{
        unsigned int len = cl->qdisc->qlen;

        qdisc_reset(cl->qdisc);
//        qdisc_tree_decrease_qlen(cl->qdisc, len);
}

static const struct nla_policy drr_policy[TCA_DRR_MAX + 1] = {
        [TCA_DRR_QUANTUM]       = { .type = NLA_U32 },
};

static int drr_change_class(struct Qdisc *sch, uint32_t classid, uint32_t parentid __rte_unused,
                            struct nlattr **tca, unsigned long *arg)
{
        struct drr_sched *q = qdisc_priv(sch);
        struct drr_class *cl = (struct drr_class *)*arg;
        struct nlattr *opt = tca[TCA_OPTIONS];
        struct nlattr *tb[TCA_DRR_MAX + 1];
        uint32_t quantum;
        int err;

        if (!opt)
                return -EINVAL;

        err = nla_parse_nested(tb, TCA_DRR_MAX, opt, drr_policy);
        if (err < 0)
                return err;

        if (tb[TCA_DRR_QUANTUM]) {
                quantum = nla_get_u32(tb[TCA_DRR_QUANTUM]);
                if (quantum == 0)
                        return -EINVAL;
        } else
                quantum = QUANTUM;
//                quantum = psched_mtu(qdisc_dev(sch));

        if (cl != NULL) {
                if (tca[TCA_RATE]) {
                        err = gen_replace_estimator(&cl->bstats, &cl->rate_est,
                                                    NULL, //qdisc_root_sleeping_lock(sch),
                                                    tca[TCA_RATE]);
                        if (err)
                                return err;
                }

//                sch_tree_lock(sch);
                if (tb[TCA_DRR_QUANTUM])
                        cl->quantum = quantum;
//                sch_tree_unlock(sch);

                return 0;
        }

        cl = rte_zmalloc(NULL, sizeof(struct drr_class), 0);
        if (cl == NULL)
                return -ENOBUFS;

        cl->refcnt         = 1;
        cl->common.classid = classid;
        cl->quantum        = quantum;
        cl->qdisc          = qdisc_create_dflt(sch->vport,
                                               &pfifo_qdisc_ops, classid);
        if (cl->qdisc == NULL)
                cl->qdisc = &noop_qdisc;

        if (tca[TCA_RATE]) {
                err = gen_replace_estimator(&cl->bstats, &cl->rate_est,
                                            NULL, //qdisc_root_sleeping_lock(sch),
                                            tca[TCA_RATE]);
                if (err) {
                        qdisc_destroy(cl->qdisc);
                        rte_free(cl);
                        return err;
                }
        }

//        sch_tree_lock(sch);
        qdisc_class_hash_insert(&q->clhash, &cl->common);
//        sch_tree_unlock(sch);

        qdisc_class_hash_grow(sch, &q->clhash);

        *arg = (unsigned long)cl;
        return 0;
}

static void drr_destroy_class(struct Qdisc *sch __rte_unused, struct drr_class *cl)
{
        gen_kill_estimator(&cl->bstats, &cl->rate_est);
        qdisc_destroy(cl->qdisc);
        rte_free(cl);
}

static int drr_delete_class(struct Qdisc *sch, unsigned long arg)
{
        struct drr_sched *q = qdisc_priv(sch);
        struct drr_class *cl = (struct drr_class *)arg;

//        if (cl->filter_cnt > 0)
//                return -EBUSY;
//
//        sch_tree_lock(sch);

        drr_purge_queue(cl);
        qdisc_class_hash_remove(&q->clhash, &cl->common);

        if(--cl->refcnt == 0) {
            RTE_LOG(ERR, QoS, "It's a BUG!!\n");
        }
        /*
         * This shouldn't happen: we "hold" one cops->get() when called
         * from tc_ctl_tclass; the destroy method is done from cops->put().
         */

//        sch_tree_unlock(sch);
        return 0;
}

static unsigned long drr_get_class(struct Qdisc *sch, u32 classid)
{
        struct drr_class *cl = drr_find_class(sch, classid);

        if (cl != NULL)
                cl->refcnt++;

        return (unsigned long)cl;
}

static void drr_put_class(struct Qdisc *sch, unsigned long arg)
{
        struct drr_class *cl = (struct drr_class *)arg;

        if (--cl->refcnt == 0)
                drr_destroy_class(sch, cl);
}

static int drr_graft_class(struct Qdisc *sch, unsigned long arg,
                           struct Qdisc *new, struct Qdisc **old)
{
        struct drr_class *cl = (struct drr_class *)arg;

        if (new == NULL) {
                new = qdisc_create_dflt(sch->vport,
                                        &pfifo_qdisc_ops, cl->common.classid);
                if (new == NULL)
                        new = &noop_qdisc;
        }

//        sch_tree_lock(sch);
//        drr_purge_queue(cl);
        *old = cl->qdisc;
        cl->qdisc = new;
//        sch_tree_unlock(sch);
        return 0;
}

static struct Qdisc *drr_class_leaf(struct Qdisc *sch __rte_unused, unsigned long arg)
{
        struct drr_class *cl = (struct drr_class *)arg;

        return cl->qdisc;
}

static void drr_qlen_notify(struct Qdisc *csh __rte_unused, unsigned long arg)
{
        struct drr_class *cl = (struct drr_class *)arg;

        if (cl->qdisc->qlen == 0)
                list_del(&cl->alist);
}

static int drr_dump_class(struct Qdisc *sch __rte_unused, unsigned long arg,
                          struct sk_buf *skb, struct tcmsg *tcm)
{
        struct drr_class *cl = (struct drr_class *)arg;
        struct nlattr *nest;

        tcm->tcm_parent = TC_H_ROOT;
        tcm->tcm_handle = cl->common.classid;
        tcm->tcm_info   = cl->qdisc->handle;

        printf("classid: %d\n", cl->common.classid);

        nest = nla_nest_start(skb, TCA_OPTIONS);
        if (nest == NULL)
                goto nla_put_failure;
        if (nla_put_u32(skb, TCA_DRR_QUANTUM, cl->quantum))
                goto nla_put_failure;
        return nla_nest_end(skb, nest);

nla_put_failure:
        nla_nest_cancel(skb, nest);
        return -EMSGSIZE;
}

static int drr_dump_class_stats(struct Qdisc *sch __rte_unused, unsigned long arg,
                                struct gnet_dump *d)
{
        struct drr_class *cl = (struct drr_class *)arg;
        struct tc_drr_stats xstats;

        memset(&xstats, 0, sizeof(xstats));
        if (cl->qdisc->qlen) {
                xstats.deficit = cl->deficit;
                cl->qdisc->qstats.qlen = cl->qdisc->qlen;
        }

        if (gnet_stats_copy_basic(d, &cl->bstats) < 0 ||
            gnet_stats_copy_rate_est(d, &cl->bstats, &cl->rate_est) < 0 ||
            gnet_stats_copy_queue(d, &cl->qdisc->qstats) < 0)
                return -1;

        return gnet_stats_copy_app(d, &xstats, sizeof(xstats));
}

static void drr_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
        struct drr_sched *q = qdisc_priv(sch);
        struct drr_class *cl;
        unsigned int i;

        if (arg->stop)
                return;

        for (i = 0; i < q->clhash.hashsize; i++) {
                hlist_for_each_entry(cl, &q->clhash.hash[i], common.hnode) {
                        if (arg->count < arg->skip) {
                                arg->count++;
                                continue;
                        }
                        if (arg->fn(sch, (unsigned long)cl, arg) < 0) {
                                arg->stop = 1;
                                return;
                        }
                        arg->count++;
                }
        }
}

static struct drr_class *drr_classify(struct rte_mbuf *pkt __rte_unused,
                                      struct Qdisc *sch __rte_unused,
                                      int *qerr __rte_unused)
{
//        struct drr_sched *q = qdisc_priv(sch);
//        struct drr_class *cl;
//        struct tcf_result res;
//        int result;
//
//        if (TC_H_MAJ(skb->priority ^ sch->handle) == 0) {
//                cl = drr_find_class(sch, skb->priority);
//                if (cl != NULL)
//                        return cl;
//        }
//
//        *qerr = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
//        result = tc_classify(skb, q->filter_list, &res);
//        if (result >= 0) {
//#ifdef CONFIG_NET_CLS_ACT
//                switch (result) {
//                case TC_ACT_QUEUED:
//                case TC_ACT_STOLEN:
//                        *qerr = NET_XMIT_SUCCESS | __NET_XMIT_STOLEN;
//                case TC_ACT_SHOT:
//                        return NULL;
//                }
//#endif
//                cl = (struct drr_class *)res.class;
//                if (cl == NULL)
//                        cl = drr_find_class(sch, res.classid);
//                return cl;
//        }
        struct drr_class *cl = NULL;
        cl = drr_find_class(sch, pkt->pkt.hash.sched + sch->handle);
        return cl;
}

static int drr_enqueue(struct rte_mbuf *pkt, struct Qdisc *sch)
{
        struct drr_sched *q = qdisc_priv(sch);
        struct drr_class *cl;
        int err = 0;

        cl = drr_classify(pkt, sch, &err);
        if (cl == NULL) {
                if (err & __NET_XMIT_BYPASS)
                        sch->qstats.drops++;
                rte_pktmbuf_free(pkt);
                return err;
        }

        err = qdisc_enqueue(pkt, cl->qdisc);
        if (unlikely(err != NET_XMIT_SUCCESS)) {
                if (net_xmit_drop_count(err)) {
                        cl->qstats.drops++;
                        sch->qstats.drops++;
                }
                return err;
        }

        if (cl->qdisc->qlen == 1) {
            if(cl->qdisc->qlen != rte_ring_count(cl->qdisc->q)) {
                RTE_LOG(ERR, QoS, "qlen != count\n");
            }
                list_add_tail(&cl->alist, &q->active);
                cl->deficit = cl->quantum;
        }

//        sch->q.qlen++;
        sch->qlen++;
        return err;
}

static struct rte_mbuf *drr_dequeue(struct Qdisc *sch)
{
        struct drr_sched *q = qdisc_priv(sch);
        struct drr_class *cl;
        struct rte_mbuf *pkt;
        unsigned int len;

        if (list_empty(&q->active))
                goto out;
        while (1) {
                cl = list_first_entry(&q->active, struct drr_class, alist);
                pkt = cl->qdisc->ops->peek(cl->qdisc);
                if (pkt == NULL) {
//                        qdisc_warn_nonwc(__func__, cl->qdisc);
                        goto out;
                }

                len = qdisc_pkt_len(pkt);
                if (len <= cl->deficit) {
                        cl->deficit -= len;
                        pkt = qdisc_dequeue_peeked(cl->qdisc);
                        if (cl->qdisc->qlen == 0)
                                list_del(&cl->alist);

                        bstats_update(&cl->bstats, pkt);
                        qdisc_bstats_update(sch, pkt);
//                        sch->q.qlen--;
                        sch->qlen--;
                        return pkt;
                }

                cl->deficit += cl->quantum;
                list_move_tail(&cl->alist, &q->active);
        }
out:
        return NULL;
}

static unsigned int drr_drop(struct Qdisc *sch)
{
        struct drr_sched *q = qdisc_priv(sch);
        struct drr_class *cl;
        unsigned int len;

        list_for_each_entry(cl, &q->active, alist) {
                if (cl->qdisc->ops->drop) {
                        len = cl->qdisc->ops->drop(cl->qdisc);
                        if (len > 0) {
                                sch->qlen--;
                                if (cl->qdisc->qlen == 0)
                                        list_del(&cl->alist);
                                return len;
                        }
                }
        }
        return 0;
}

static int drr_init_qdisc(struct Qdisc *sch, struct nlattr *opt __rte_unused)
{
        struct drr_sched *q = qdisc_priv(sch);
        int err;

        err = qdisc_class_hash_init(&q->clhash);
        if (err < 0)
                return err;
        INIT_LIST_HEAD(&q->active);
        return 0;
}

static void drr_reset_qdisc(struct Qdisc *sch)
{
        struct drr_sched *q = qdisc_priv(sch);
        struct drr_class *cl;
        unsigned int i;

        for (i = 0; i < q->clhash.hashsize; i++) {
                hlist_for_each_entry(cl, &q->clhash.hash[i], common.hnode) {
                        if (cl->qdisc->qlen)
                                list_del(&cl->alist);
                        qdisc_reset(cl->qdisc);
                }
        }
//        sch->q.qlen = 0;
        sch->qlen = 0;
}

static void drr_destroy_qdisc(struct Qdisc *sch)
{
        struct drr_sched *q = qdisc_priv(sch);
        struct drr_class *cl;
        struct hlist_node *next;
        unsigned int i;

//        tcf_destroy_chain(&q->filter_list);

        for (i = 0; i < q->clhash.hashsize; i++) {
                hlist_for_each_entry_safe(cl, next, &q->clhash.hash[i],
                                          common.hnode)
                        drr_destroy_class(sch, cl);
        }
        qdisc_class_hash_destroy(&q->clhash);
}

static const struct Qdisc_class_ops drr_class_ops = {
        .change         = drr_change_class,
        .delete         = drr_delete_class,
        .get            = drr_get_class,
        .put            = drr_put_class,
//        .tcf_chain      = drr_tcf_chain,
//        .bind_tcf       = drr_bind_tcf,
//        .unbind_tcf     = drr_unbind_tcf,
        .graft          = drr_graft_class,
        .leaf           = drr_class_leaf,
        .qlen_notify    = drr_qlen_notify,
        .dump           = drr_dump_class,
        .dump_stats     = drr_dump_class_stats,
        .walk           = drr_walk,
};

struct Qdisc_ops drr_qdisc_ops = {
        .cl_ops         = &drr_class_ops,
        .id             = "drr",
        .priv_size      = sizeof(struct drr_sched),
        .enqueue        = drr_enqueue,
        .dequeue        = drr_dequeue,
        .peek           = qdisc_peek_dequeued,
        .drop           = drr_drop,
        .init           = drr_init_qdisc,
        .reset          = drr_reset_qdisc,
        .destroy        = drr_destroy_qdisc,
//        .owner          = THIS_MODULE,
};
