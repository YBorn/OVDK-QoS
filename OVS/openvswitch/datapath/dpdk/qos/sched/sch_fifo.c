/*
 * =====================================================================================
 *
 *       Filename:  sch_fifo.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年10月17日 15时10分24秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Kamfai (), jinhui.wu.kf@gmail.com
 *   Organization:  
 *
 * =====================================================================================
 */

/*
 * net/sched/sch_fifo.c The simplest FIFO queue.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */


/* 1 band FIFO pseudo-"scheduler" */
/**** default fifo qdisc ****/
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

#define QUEUE_RINGSIZE  4096

extern struct vport_info *vports;

struct rte_mbuf;
struct Qdisc;

static int pfifo_enqueue(struct rte_mbuf *pkt, struct Qdisc *sch)
{
//    if(rte_ring_count(sch->q) != sch->qlen) {
//        printf("qlen: %d, ring_count: %d\n", sch->qlen, rte_ring_count(sch->q));
//    }
    if((int)sch->qlen <= (int)sch->limit) {
        return qdisc_enqueue_tail(pkt, sch);
    }
    
    return qdisc_drop(pkt, sch);
}

static struct rte_mbuf *pfifo_dequeue(struct Qdisc *sch) {
    return qdisc_dequeue_head(sch);
}

static int pfifo_init(struct Qdisc *sch, struct nlattr *opt)
{
        bool bypass;
//        bool is_bfifo = sch->ops == &bfifo_qdisc_ops;

        if (opt == NULL) {
//                u32 limit = qdisc_dev(sch)->tx_queue_len ? : 1;
//
//                if (is_bfifo)
//                        limit *= psched_mtu(qdisc_dev(sch));
//
                sch->limit = QUEUE_RINGSIZE;
        } else {
                struct tc_fifo_qopt *ctl = nla_data(opt);

                if (nla_len(opt) < (int)sizeof(*ctl))
                        return -EINVAL;

                sch->limit = (ctl->limit <= QUEUE_RINGSIZE ? ctl->limit:QUEUE_RINGSIZE);
        }

 //       if (is_bfifo)
 //               bypass = sch->limit >= psched_mtu(qdisc_dev(sch));
 //       else
                bypass = sch->limit >= 1;

        if (bypass)
                sch->flags |= TCQ_F_CAN_BYPASS;
        else
                sch->flags &= ~TCQ_F_CAN_BYPASS;
        return 0;
}

static int fifo_dump(struct Qdisc *sch, struct sk_buf *skb)
{
        struct tc_fifo_qopt opt = { .limit = sch->limit };

        if (nla_put(skb, TCA_OPTIONS, sizeof(opt), &opt))
                goto nla_put_failure;
        return skb->iov_len;

nla_put_failure:
        return -1;
}

struct Qdisc_ops pfifo_qdisc_ops = {
        .id             =       "pfifo",
        .priv_size      =       0,
        .enqueue        =       pfifo_enqueue,
        .dequeue        =       pfifo_dequeue,
        .peek           =       qdisc_peek_dequeued,
        .drop           =       qdisc_queue_drop,
        .init           =       pfifo_init,
        .reset          =       qdisc_reset_queue,
        .change         =       pfifo_init,
        .dump           =       fifo_dump,
};

/* Pass size change message down to embedded FIFO */
int fifo_set_limit(struct Qdisc *q, unsigned int limit)
{
        struct nlattr *nla;
        int ret = -ENOMEM;

        /* Hack to avoid sending change message to non-FIFO */
        if (strncmp(q->ops->id + 1, "pfifo", 5) != 0)
                return 0;

        nla = (struct nlattr *)rte_zmalloc(NULL, nla_attr_size(sizeof(struct tc_fifo_qopt)), 0);
        if (nla) {
                nla->nla_type = RTM_NEWQDISC;
                nla->nla_len = nla_attr_size(sizeof(struct tc_fifo_qopt));
                ((struct tc_fifo_qopt *)nla_data(nla))->limit = limit;

                ret = q->ops->change(q, nla);
                rte_free(nla);
        }
        return ret;
}

struct Qdisc *fifo_create_dflt(struct Qdisc *sch, struct Qdisc_ops *ops,
                               unsigned int limit)
{
        struct Qdisc *q;
        int err = -ENOMEM;

        q = qdisc_create_dflt(sch->vport, ops, TC_H_MAKE(sch->handle, 1));
        if (q) {
                err = fifo_set_limit(q, limit);
                if (err < 0) {
                        qdisc_destroy(q);
                        q = NULL;
                }
        }

        return q ? : ERR_PTR(err);
}
