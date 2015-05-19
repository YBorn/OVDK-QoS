/*
 * =====================================================================================
 *
 *       Filename:  qos_qdisc.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年06月07日 13时50分37秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Y.Born (), llyangborn@gmail.com
 *   Organization:  
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <string.h>

#include <rte_malloc.h>
#include <rte_string_fns.h>
#include <rte_spinlock.h>
#include <rte_rwlock.h>
#include <rte_memcpy.h>
#include <rte_log.h>

#include "sch_qdisc.h"
#include "sch_inline.h"
#include "sch_rtnetlink.h"
#include "linux/netlink.h"
#include "netlink_api.h"
#include "rte_generic.h"
#include "sch_qdisc.h"
#include "../list/list.h"
#include "../../vport_define.h"
#include "err.h"

#define RTE_LOGTYPE_QoS RTE_LOGTYPE_USER1
#define NS_MAX 32

/*****************************************************************
 *              Traffic control messages.
 ****/

extern struct Qdisc_ops pfifo_qdisc_ops;
extern struct vport_info *vports;
extern struct Qdisc      noop_qdisc;
extern struct Qdisc_ops  noop_qdisc_ops;
extern struct rtnl_handle rth;

static struct Qdisc_ops *qdisc_base;

static struct list_head qdisc_stab_list = LIST_HEAD_INIT(qdisc_stab_list); 

static rte_spinlock_t qdisc_stab_lock = RTE_SPINLOCK_INITIALIZER;
/* Protects list of registered TC modules. It is pure SMP lock. */
static rte_rwlock_t   qdisc_mod_lock  = RTE_RWLOCK_INITIALIZER;

static struct qdisc_rate_table *qdisc_rtab_list;

static const struct nla_policy stab_policy[TCA_STAB_MAX + 1] = {
        [TCA_STAB_BASE] = { .len = sizeof(struct tc_sizespec) },
        [TCA_STAB_DATA] = { .type = NLA_BINARY },
};

#define TCA_MAX (__TCA_MAX - 1)

#define TCA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct tcmsg))))
#define TCA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct tcmsg))

#define CACHE_LINE_SIZE 64

struct Qdisc * qdisc_alloc(struct vport_info *vport, struct Qdisc_ops *ops) {
    void *p;
    struct Qdisc *sch;

    static int index = 0;
    char name[NS_MAX];
    rte_snprintf(name, NS_MAX, "%s_%d", vport->name, index);

    unsigned int size = QDISC_ALIGN(sizeof(*sch)) + ops->priv_size;
    int err = -ENOBUFS;

    sch = (struct Qdisc *) rte_zmalloc(NULL, size, CACHE_LINE_SIZE);
    if(!sch)
        goto errout;

    INIT_LIST_HEAD(&sch->list);
    sch->q  = q_create(name, 0);
    sch->qlen = 0;
    sch->gso_pkt = NULL;

    rte_spinlock_init(&sch->busylock);

    sch->ops = ops;
    sch->enqueue = ops->enqueue;
    sch->dequeue = ops->dequeue;
    sch->vport = vport;
    rte_atomic32_set(&sch->refcnt, 1);

    index++;
    return sch;
errout:
    return ERR_PTR(err);
}

void qdisc_destroy(struct Qdisc *qdisc)
{
        const struct Qdisc_ops  *ops = qdisc->ops;

        if (qdisc->flags & TCQ_F_BUILTIN ||
            !rte_atomic32_dec_and_test(&qdisc->refcnt))
                return;

//#ifdef CONFIG_NET_SCHED
        qdisc_list_del(qdisc);

        qdisc_put_stab(qdisc->stab);
//#endif
        gen_kill_estimator(&qdisc->bstats, &qdisc->rate_est);
        if (ops->reset)
                ops->reset(qdisc);
        if (ops->destroy)
                ops->destroy(qdisc);

//        module_put(ops->owner);
//        dev_put(qdisc_dev(qdisc));
//
        rte_pktmbuf_free(qdisc->gso_pkt);
        rte_free(qdisc);  // Maybe cause some problem
}

struct Qdisc * qdisc_create_dflt(struct vport_info *vport,
                  struct Qdisc_ops *ops,
                  unsigned int parentid) {
    struct Qdisc *sch;

    if(ops == NULL) {
        RTE_LOG(ERR, QoS, "Qdisc Ops is NULL!\n");
        goto  errout;
    }

    sch = qdisc_alloc(vport, ops);
    if(IS_ERR(sch)) {
        RTE_LOG(ERR, QoS, "Sch is NULL, Please check Function: qdisc_alloc\n");
        goto errout;
    }
    sch->parent = parentid;

    if(!ops->init || ops->init(sch, NULL) == 0) {
        return sch;
    }
    
    qdisc_destroy(sch);
errout:
    RTE_LOG(ERR, QoS, "Fail to create default qdisc\n");
    return NULL;
}

static void notify_and_destroy(struct vport_info *vport, struct sk_buf *skb,
                               struct nlmsghdr *n, uint32_t clid,
                               struct Qdisc *old, struct Qdisc *new)
{
        if (new || old)
                qdisc_notify(vport, skb, n, clid, old, new);

        if (old)
                qdisc_destroy(old);
}


/* Graft qdisc "new" to class "classid" of qdisc "parent" or
 * to device "dev".
 *
 * When appropriate send a netlink notification using 'skb'
 * and "n".
 *
 * On success, destroy old qdisc.
 */

// static int qdisc_graft(struct net_device *dev, struct Qdisc *parent,
//                        struct sk_buff *skb, struct nlmsghdr *n, u32 classid,
//                        struct Qdisc *new, struct Qdisc *old)
 static int qdisc_graft(struct vport_info *vport, struct Qdisc *parent,
                        struct sk_buf *skb, struct nlmsghdr *n, uint32_t classid,
                        struct Qdisc *new, struct Qdisc *old)
{
        struct Qdisc *q = old;
//         struct net *net = dev_net(dev);
        int err = 0;

        if (parent == NULL) {
                unsigned int i, num_q = 1, ingress;

                ingress = 0;
//                num_q = dev->num_tx_queues;
//                 if ((q && q->flags & TCQ_F_INGRESS) ||
//                     (new && new->flags & TCQ_F_INGRESS)) {
//                         num_q = 1;
//                         ingress = 1;
//                         if (!dev_ingress_queue(dev))
//                                 return -ENOENT;
//                 }
// 
//                 if (dev->flags & IFF_UP)
//                         dev_deactivate(dev);

                if (new && new->ops->attach) {
                        new->ops->attach(new);
                        num_q = 0;
                }

                for (i = 0; i < num_q; i++) {
//                        struct netdev_queue *dev_queue = dev_ingress_queue(dev);

//                        if (!ingress)
//                                dev_queue = netdev_get_tx_queue(dev, i);

                        old = dev_graft_qdisc(vport, new);
                        if (new && i > 0)
                                rte_atomic32_inc(&new->refcnt);

                        if (!ingress)
                                qdisc_destroy(old);
                }

                if (!ingress) {
                        notify_and_destroy(vport, skb, n, classid,
                                           vport->qdisc, new);
                        if (new && !new->ops->attach)
                                rte_atomic32_inc(&new->refcnt);
                        vport->qdisc = new ? : &noop_qdisc;
                } else {
                        notify_and_destroy(vport, skb, n, classid, old, new);
                }

//                 if (dev->flags & IFF_UP)
//                         dev_activate(dev);
        } else {
                const struct Qdisc_class_ops *cops = parent->ops->cl_ops;

                err = -EOPNOTSUPP;
                if (cops && cops->graft) {
                        unsigned long cl = cops->get(parent, classid);
                        if (cl) {
                                err = cops->graft(parent, cl, new, &old);
                                cops->put(parent, cl);
                        } else
                                err = -ENOENT;
                }
                if (!err)
                        notify_and_destroy(vport, skb, n, classid, old, new);
        }
        return err;
}





/**************** Common Qdisc API ****************/

struct vport_info *get_vport_by_index(int index) {
    struct vport_info *vport = &vports[index];

    return vport;
}

struct Qdisc *qdisc_lookup(struct vport_info *vport, uint32_t handle) {
    struct Qdisc *q;

    q = qdisc_match_from_root(vport->qdisc, handle);
// Maybe should Consider Ingress Qdisc lately;
    return q;
}

struct Qdisc *qdisc_match_from_root(struct Qdisc *root, uint32_t handle) {

    struct Qdisc *q;

    if(!(root->flags & TCQ_F_BUILTIN) &&
            root->handle == handle)
        return root;

    list_for_each_entry(q, &root->list, list) {
        if(q->handle == handle)
            return q;
    }
    return NULL;
}

struct Qdisc *qdisc_leaf(struct Qdisc *p, uint32_t classid) {

    unsigned long cl;
    struct Qdisc *leaf;
    const struct Qdisc_class_ops *cops = p->ops->cl_ops;

    if (cops == NULL)
            return NULL;
    cl = cops->get(p, classid);

    if (cl == 0)
            return NULL;
    leaf = cops->leaf(p, cl);
    cops->put(p, cl);
    return leaf;
}

void atomic_inc(rte_atomic32_t *v) {
    rte_atomic32_inc(v);
}

static struct qdisc_size_table *qdisc_get_stab(struct nlattr *opt)
{
        struct nlattr *tb[TCA_STAB_MAX + 1];
        struct qdisc_size_table *stab;
        struct tc_sizespec *s;
        unsigned int tsize = 0;
        uint16_t *tab = NULL;
        int err;

        err = nla_parse_nested(tb, TCA_STAB_MAX, opt, stab_policy);
        if (err < 0)
                return ERR_PTR((long)err);
        if (!tb[TCA_STAB_BASE])
                return ERR_PTR(-EINVAL);

        s = nla_data(tb[TCA_STAB_BASE]);

        if (s->tsize > 0) {
                if (!tb[TCA_STAB_DATA])
                        return ERR_PTR(-EINVAL);
                tab = nla_data(tb[TCA_STAB_DATA]);
                tsize = nla_len(tb[TCA_STAB_DATA]) / sizeof(u16);
        }

        if (tsize != s->tsize || (!tab && tsize > 0))
                return ERR_PTR(-EINVAL);

        rte_spinlock_lock(&qdisc_stab_lock);

        list_for_each_entry(stab, &qdisc_stab_list, list) {
                if (memcmp(&stab->szopts, s, sizeof(*s)))
                        continue;
                if (tsize > 0 && memcmp(stab->data, tab, tsize * sizeof(u16)))
                        continue;
                stab->refcnt++;
                rte_spinlock_unlock(&qdisc_stab_lock);
                return stab;
        }

       rte_spinlock_unlock(&qdisc_stab_lock);

//      stab = kmalloc(sizeof(*stab) + tsize * sizeof(u16), GFP_KERNEL);
        stab = rte_malloc(NULL, sizeof(*stab) + tsize * sizeof(u16), 0);
        if (!stab) {
            RTE_LOG(ERR, QoS, "%s[%d]: Can't malloc for stab!", __func__, __LINE__);
            return ERR_PTR(-ENOMEM);
        }

        stab->refcnt = 1;
        stab->szopts = *s;
        if (tsize > 0)
                memcpy(stab->data, tab, tsize * sizeof(u16));

        rte_spinlock_lock(&qdisc_stab_lock);
        list_add_tail(&stab->list, &qdisc_stab_list);
        rte_spinlock_unlock(&qdisc_stab_lock);

        return stab;
}

void qdisc_put_stab(struct qdisc_size_table *tab)
{
        if (!tab)
                return;

        rte_spinlock_lock(&qdisc_stab_lock);

        if (--tab->refcnt == 0) {
                list_del(&tab->list);
//                call_rcu_bh(&tab->rcu, stab_kfree_rcu); //删除stab
                rte_free(tab);
        }

        rte_spinlock_unlock(&qdisc_stab_lock);
}

void qdisc_put_rtab(struct qdisc_rate_table *tab)
{
        struct qdisc_rate_table *rtab, **rtabp;

        if (!tab || --tab->refcnt)
                return;

        for (rtabp = &qdisc_rtab_list;
             (rtab = *rtabp) != NULL;
             rtabp = &rtab->next) {
                if (rtab == tab) {
                        *rtabp = rtab->next;
                        rte_free(rtab);
                        return;
                }
        }
}

struct qdisc_rate_table *qdisc_get_rtab(struct tc_ratespec *r, struct nlattr *tab)
{
        struct qdisc_rate_table *rtab;

        if (tab == NULL || r->rate == 0 || r->cell_log == 0 ||
            nla_len(tab) != TC_RTAB_SIZE)
                return NULL;

        for (rtab = qdisc_rtab_list; rtab; rtab = rtab->next) {
                if (!memcmp(&rtab->rate, r, sizeof(struct tc_ratespec)) &&
                    !memcmp(&rtab->data, nla_data(tab), 1024)) {
                        rtab->refcnt++;
                        return rtab;
                }
        }

        rtab = rte_zmalloc(NULL, sizeof(*rtab), 0);
        if (rtab) {
                rtab->rate = *r;
                rtab->refcnt = 1;
                rte_memcpy(rtab->data, nla_data(tab), 1024);
//                if (r->linklayer == TC_LINKLAYER_UNAWARE)
//                        r->linklayer = __detect_linklayer(r, rtab->data);
                rtab->next = qdisc_rtab_list;
                qdisc_rtab_list = rtab;
        }
        return rtab;
}

int qdisc_change(struct Qdisc *sch, struct nlattr **tca) {

    struct qdisc_size_table *ostab, *stab = NULL;
    int err = 0;

    if (tca[TCA_OPTIONS]) {
            if (sch->ops->change == NULL)
                    return -EINVAL;
            err = sch->ops->change(sch, tca[TCA_OPTIONS]);
            if (err)
                    return err;
    }

    if (tca[TCA_STAB]) {
            stab = qdisc_get_stab(tca[TCA_STAB]);
            if (IS_ERR(stab))
                    return PTR_ERR(stab);
    }

//    ostab = rtnl_dereference(sch->stab); 内核对并发处理的优化
    ostab = sch->stab;
//    rcu_assign_pointer(sch->stab, stab);
    sch->stab = stab;
    qdisc_put_stab(ostab);

    if (tca[TCA_RATE]) {
            /* NB: ignores errors from replace_estimator
               because change can't be undone. */
            if (sch->flags & TCQ_F_MQROOT)
                goto out;
// TODO
//             gen_replace_estimator(&sch->bstats, &sch->rate_est,
//                                         qdisc_root_sleeping_lock(sch),
//                                         tca[TCA_RATE]);
    }
out:
    return 0;
}

// NOtice
struct sk_buf *alloc_skb(void * base, const size_t maxlen)
{
    struct sk_buf *skb = NULL;
    skb = (struct sk_buf *)rte_zmalloc(NULL, maxlen, 0);

    if(!skb) {
        RTE_LOG(ERR, QoS, "%s: Failed to Alloc SKB\n", __func__);
        return NULL;
    }
    
    skb->iov_base = base;
    skb->iov_len = 0;
    skb->max_len = maxlen;

    return skb;
}

int qdisc_notify(struct vport_info *vport __rte_unused, struct sk_buf *oskb __rte_unused,
                 struct nlmsghdr *n, uint32_t clid,
                 struct Qdisc *old, struct Qdisc *new) {
        struct sk_buf *skb;
        struct nlmsghdr *rep;
//        u32 portid = oskb ? NETLINK_CB(oskb).portid : 0;
        uint32_t pid = rth.peer.nl_pid;
        RTE_LOG(INFO, QoS, "peer pid: %d \n", pid);

        rep = (struct nlmsghdr *)rte_zmalloc(NULL, NLMSG_GOODSIZE, 0);
        if (!rep)
                return -ENOBUFS;
        
        skb = alloc_skb(rep, NLMSG_GOODSIZE);
        if(!skb) {
            rte_free(rep);
            return -ENOBUFS;
        }

        if (old && !tc_qdisc_dump_ignore(old)) {
                if (tc_fill_qdisc(skb, old, clid, pid, n->nlmsg_seq,
                                  0, RTM_DELQDISC) < 0)
                        goto err_out;
        }
        if (new && !tc_qdisc_dump_ignore(new)) {
                if (tc_fill_qdisc(skb, new, clid, pid, n->nlmsg_seq,
                                  old ? NLM_F_REPLACE : 0, RTM_NEWQDISC) < 0)
                        goto err_out;
        }

        if(skb->iov_len)
                return rtnetlink_send(skb, pid, RTNLGRP_TC,
                                      n->nlmsg_flags & NLM_F_ECHO);

err_out:
        rte_free(rep);
        rte_free(skb);
        return -EINVAL;
}

struct Qdisc *qdisc_create(struct vport_info *vport, struct Qdisc *p __rte_unused,
                            uint32_t parent, uint32_t handle,
                            struct nlattr **tca, int *errp) {
        int err;
        struct nlattr *kind = tca[TCA_KIND];
        struct Qdisc *sch;
        struct Qdisc_ops *ops;
        struct qdisc_size_table *stab;

        ops = qdisc_lookup_ops(kind);
        err = -ENOENT;
        if (ops == NULL) {
                RTE_LOG(ERR, QoS, "%s: Should register Qdisc ops!\n",__func__);
                goto err_out;
        }

        sch = qdisc_alloc(vport, ops);
        if (IS_ERR(sch)) {
                RTE_LOG(ERR, QoS, "%s: Failed to alloc qdisc!\n",__func__);
                err = PTR_ERR(sch);
                goto err_out;
        }

        sch->parent = parent;

//        if (handle == TC_H_INGRESS) {
//                sch->flags |= TCQ_F_INGRESS;
//                handle = TC_H_MAKE(TC_H_INGRESS, 0);
//                lockdep_set_class(qdisc_lock(sch), &qdisc_rx_lock);
//        } else {
                if (handle == 0) {
                        handle = qdisc_alloc_handle(vport);
                        err = -ENOMEM;
                        if (handle == 0)
                                goto err_out3;
                }
// please notice here
//                lockdep_set_class(qdisc_lock(sch), &qdisc_tx_lock);
//                if (!netif_is_multiqueue(dev))
//                        sch->flags |= TCQ_F_ONETXQUEUE;
//       }
                sch->flags |= TCQ_F_ONETXQUEUE;

        sch->handle = handle;
        RTE_LOG(INFO, QoS, "%s: Qdisc.handle is: %u\n", __func__, handle);

        if (!ops->init || (err = ops->init(sch, tca[TCA_OPTIONS])) == 0) {
                if (tca[TCA_STAB]) {
                        stab = qdisc_get_stab(tca[TCA_STAB]);
                        if (IS_ERR(stab)) {
                                err = PTR_ERR(stab);
                                goto err_out4;
                        }
//                         rcu_assign_pointer(sch->stab, stab);
                        sch->stab = stab;
                }
                if (tca[TCA_RATE]) {
                        rte_spinlock_t *root_lock;

                        err = -EOPNOTSUPP;
                        if (sch->flags & TCQ_F_MQROOT)
                                goto err_out4;

//                        if ((sch->parent != TC_H_ROOT) &&
//                            !(sch->flags & TCQ_F_INGRESS) &&
//                            (!p || !(p->flags & TCQ_F_MQROOT)))
//                                root_lock = qdisc_root_sleeping_lock(sch);
//                        else
//                                root_lock = qdisc_lock(sch);
                        
                        root_lock = NULL;
                        err = gen_new_estimator(&sch->bstats, &sch->rate_est,
                                                root_lock, tca[TCA_RATE]);
                        if (err)
                                goto err_out4;
                }

                qdisc_list_add(sch);

                return sch;
        }
err_out3:
        RTE_LOG(INFO, QoS, "%s [%d]\n",__func__, __LINE__);
//        dev_put(dev);
//        kfree((char *) sch - sch->padded);
        rte_free(sch);
//err_out2:
//        module_put(ops->owner);
err_out:
        RTE_LOG(INFO, QoS, "%s [%d]\n",__func__, __LINE__);
        *errp = err;
        return NULL;

err_out4:
        /*
         * Any broken qdiscs that would require a ops->reset() here?
         * The qdisc was never in action so it shouldn't be necessary.
         */
        qdisc_put_stab(sch->stab);
        RTE_LOG(INFO, QoS, "%s [%d]\n",__func__, __LINE__);
        if (ops->destroy)
                ops->destroy(sch);
        RTE_LOG(INFO, QoS, "%s [%d]\n",__func__, __LINE__);
        goto err_out3;
}

struct Qdisc_ops *qdisc_lookup_ops(struct nlattr *kind)
{
        struct Qdisc_ops *q = NULL;

        if (kind) {
//                rte_rwlock_read_lock(&qdisc_mod_lock);
                for (q = qdisc_base; q; q = q->next) {
                        if (nla_strcmp(kind, q->id) == 0)
                                break;
                }
//                rte_rwlock_read_unlock(&qdisc_mod_lock);
        }
        return q;
}

uint32_t qdisc_alloc_handle(struct vport_info *vport)
{
        int i = 0x8000;
        static uint32_t autohandle = TC_H_MAKE(0x80000000U, 0);

        do {
                autohandle += TC_H_MAKE(0x10000U, 0);
                if (autohandle == TC_H_MAKE(TC_H_ROOT, 0))
                        autohandle = TC_H_MAKE(0x80000000U, 0);
                if (!qdisc_lookup(vport, autohandle))
                        return autohandle;
//                cond_resched();
        } while (--i > 0);

        return 0;
}

struct vport_info * qdisc_vport(struct Qdisc *q) {
    return q->vport;
}

void qdisc_list_add(struct Qdisc *q)
{
        if ((q->parent != TC_H_ROOT) && !(q->flags & TCQ_F_INGRESS)) {
                struct Qdisc *root = qdisc_vport(q)->qdisc;

                if(root == &noop_qdisc)
                    RTE_LOG(WARNING, QoS, "It's a BUG!\n");
                list_add_tail(&q->list, &root->list);
        }
}

void qdisc_list_del(struct Qdisc *q)
{
        if ((q->parent != TC_H_ROOT) && !(q->flags & TCQ_F_INGRESS))
                list_del(&q->list);
}

/* Register/unregister queueing discipline */

int register_qdisc(struct Qdisc_ops *qops)
{
        struct Qdisc_ops *q, **qp;
        int rc = -EEXIST;

//        write_lock(&qdisc_mod_lock);  /* maybe need lock */
        for (qp = &qdisc_base; (q = *qp) != NULL; qp = &q->next)
                if (!strcmp(qops->id, q->id))
                        goto out;

        if (qops->enqueue == NULL)
                qops->enqueue = noop_qdisc_ops.enqueue;
        if (qops->peek == NULL) {
                if (qops->dequeue == NULL)
                        qops->peek = noop_qdisc_ops.peek;
                else
                        goto out_einval;
        }
        if (qops->dequeue == NULL)
                qops->dequeue = noop_qdisc_ops.dequeue;

        if (qops->cl_ops) {
                const struct Qdisc_class_ops *cops = qops->cl_ops;

                if (!(cops->get && cops->put && cops->walk && cops->leaf))
                        goto out_einval;

//                if (cops->tcf_chain && !(cops->bind_tcf && cops->unbind_tcf))
//                        goto out_einval;
        }

        qops->next = NULL;
        *qp = qops;
        rc = 0;
out:
//        write_unlock(&qdisc_mod_lock);
        return rc;

out_einval:
        rc = -EINVAL;
        goto out;
}

int qdisc_dump_stab(struct sk_buf *skb, struct qdisc_size_table *stab)
{
        struct nlattr *nest;

        nest = nla_nest_start(skb, TCA_STAB);
        if (nest == NULL)
                goto nla_put_failure;
        if (nla_put(skb, TCA_STAB_BASE, sizeof(stab->szopts), &stab->szopts))
                goto nla_put_failure;
        nla_nest_end(skb, nest);

        return skb->iov_len;

nla_put_failure:
        return -1;
}

int tc_fill_qdisc(struct sk_buf *skb, struct Qdisc *q, uint32_t clid,
                         uint32_t portid, uint32_t seq, uint16_t flags, int event) // portid is pid
{
        struct tcmsg *tcm;
        struct nlmsghdr  *nlh;
        unsigned char *b = skb_tail_pointer(skb);
        struct gnet_dump d;
        struct qdisc_size_table *stab;

//        cond_resched();
        nlh = nlmsg_put(skb, portid, seq, event, sizeof(*tcm), flags);
        if (!nlh)
                goto out_nlmsg_trim;
        tcm = nlmsg_data(nlh);
        tcm->tcm_family = AF_UNSPEC;
        tcm->tcm__pad1 = 0;
        tcm->tcm__pad2 = 0;
        tcm->tcm_ifindex = qdisc_vport(q)->vportid;
        tcm->tcm_parent = clid;
        tcm->tcm_handle = q->handle;
        tcm->tcm_info = rte_atomic32_read(&q->refcnt);
        if (nla_put_string(skb, TCA_KIND, q->ops->id))
                goto nla_put_failure;
        if (q->ops->dump && q->ops->dump(q, skb) < 0)
                goto nla_put_failure;
        q->qstats.qlen = q->qlen;
        if(q->qlen != rte_ring_count(q->q)) {
         RTE_LOG(INFO, QoS, "qlen: %d, ring_count: %d\n", q->qlen, rte_ring_count(q->q));
        }
//        q->qstats.qlen = rte_ring_count(q->q);

//        stab = rtnl_dereference(q->stab);
        stab = q->stab;
        if (stab && qdisc_dump_stab(skb, stab) < 0)
                goto nla_put_failure;

         if (gnet_stats_start_copy_compat(skb, TCA_STATS2, TCA_STATS, TCA_XSTATS,
                                          NULL, &d) < 0)
                goto nla_put_failure;

        if (q->ops->dump_stats && q->ops->dump_stats(q, &d) < 0)
                goto nla_put_failure;

        if (gnet_stats_copy_basic(&d, &q->bstats) < 0 ||
            gnet_stats_copy_rate_est(&d, &q->bstats, &q->rate_est) < 0 ||
            gnet_stats_copy_queue(&d, &q->qstats) < 0)
                goto nla_put_failure;

        if (gnet_stats_finish_copy(&d) < 0)
                goto nla_put_failure;

        nlh->nlmsg_len = skb_tail_pointer(skb) - b;
        return skb->iov_len;

out_nlmsg_trim:
nla_put_failure:
        nlmsg_trim(skb, b);
        return -1;
}

bool tc_qdisc_dump_ignore(struct Qdisc *q)
{
        return (q->flags & TCQ_F_BUILTIN) ? true : false;
}

static inline void __qdisc_reset_queue(struct Qdisc *sch, struct rte_ring *q)
{
    __skb_queue_purge(q);
    sch->qlen = 0;
}

void qdisc_reset_queue(struct Qdisc *sch)
{
    __qdisc_reset_queue(sch, sch->q);
    sch->qstats.backlog = 0;
}


/* Attach toplevel qdisc to device queue. */
struct Qdisc *dev_graft_qdisc(struct vport_info *vport,
                              struct Qdisc *qdisc)
{
        struct Qdisc *oqdisc = vport->qdisc_sleeping;
        rte_spinlock_t *root_lock;

//        root_lock = qdisc_lock(oqdisc);
        root_lock = &oqdisc->busylock;
        rte_spinlock_lock(root_lock);

        /* Prune old scheduler */
        if (oqdisc && rte_atomic32_read(&oqdisc->refcnt) <= 1)
                qdisc_reset(oqdisc);

        /* ... and graft new one */
        if (qdisc == NULL)
                qdisc = &noop_qdisc;
        vport->qdisc_sleeping = qdisc;
//        rcu_assign_pointer(dev_queue->qdisc, &noop_qdisc);
        vport->qdisc = &noop_qdisc;

        rte_spinlock_unlock(root_lock);

        return oqdisc;
}


static void attach_default_qdiscs(struct vport_info *vport)
{
//        struct netdev_queue *txq;
        struct Qdisc *qdisc;

//         txq = netdev_get_tx_queue(dev, 0);
// 
//         if (!netif_is_multiqueue(dev) || dev->tx_queue_len == 0) {
//                 netdev_for_each_tx_queue(dev, attach_one_default_qdisc, NULL);
//                 dev->qdisc = txq->qdisc_sleeping;
//                 atomic_inc(&dev->qdisc->refcnt);
//         } else {
                qdisc = qdisc_create_dflt(vport, &pfifo_qdisc_ops, TC_H_ROOT);
                if (qdisc) {
                        vport->qdisc = qdisc;
//                        qdisc->ops->attach(qdisc);
                }
//         }
}

void dev_activate(struct vport_info *vport)
{
//        int need_watchdog;

        /* No queueing discipline is attached to device;
         * create default one for devices, which need queueing
         * and noqueue_qdisc for virtual interfaces
         */

        if (vport->qdisc == &noop_qdisc)
                attach_default_qdiscs(vport);

//        if (!netif_carrier_ok(dev))
//                /* Delay activation until next carrier-on event */
//                return;

//        need_watchdog = 0;
//         netdev_for_each_tx_queue(dev, transition_one_qdisc, &need_watchdog);
//         if (dev_ingress_queue(dev))
//                 transition_one_qdisc(dev, dev_ingress_queue(dev), NULL);
}        

void dev_init_scheduler(struct vport_info *vport)
{
        vport->qdisc = &noop_qdisc;
        vport->qdisc_sleeping = &noop_qdisc;
//        netdev_for_each_tx_queue(dev, dev_init_scheduler_queue, &noop_qdisc);
//        if (dev_ingress_queue(dev))
//                dev_init_scheduler_queue(dev, dev_ingress_queue(dev), &noop_qdisc);

//        setup_timer(&dev->watchdog_timer, dev_watchdog, (unsigned long)dev);
}

static int tc_dump_qdisc_root(struct Qdisc *root, struct sk_buf *skb,
                              struct netlink_callback *cb,
                              int *q_idx_p, int s_q_idx)
{
        int ret = 0, q_idx = *q_idx_p;
        struct Qdisc *q;
        uint32_t pid = rth.peer.nl_pid;
        RTE_LOG(INFO, QoS, "peer pid: %d\n", pid);

        if (!root)
                return 0;

        q = root;
        if (q_idx < s_q_idx) {
                q_idx++;
        } else {
                if (!tc_qdisc_dump_ignore(q) &&
//                     tc_fill_qdisc(skb, q, q->parent, NETLINK_CB(cb->skb).pid,
//                                   cb->nlh->nlmsg_seq, NLM_F_MULTI, RTM_NEWQDISC) <= 0)
                     tc_fill_qdisc(skb, q, q->parent, pid,
                                   cb->nlh->nlmsg_seq, NLM_F_MULTI, RTM_NEWQDISC) <= 0)
                        goto done;
                q_idx++;
        }
        list_for_each_entry(q, &root->list, list) {
                if (q_idx < s_q_idx) {
                        q_idx++;
                        continue;
                }
                if (!tc_qdisc_dump_ignore(q) &&
                    tc_fill_qdisc(skb, q, q->parent, pid,
                                  cb->nlh->nlmsg_seq, NLM_F_MULTI, RTM_NEWQDISC) <= 0)
                        goto done;
                q_idx++;
        }

out:
        *q_idx_p = q_idx;
        return ret;
done:
        ret = -1;
        goto out;
}

/*
 * Create/change qdisc.
 */

int tc_modify_qdisc(struct sk_buf *skb, struct nlmsghdr *n)
{
//        struct net *net = sock_net(skb->sk);
        struct tcmsg *tcm;
        struct nlattr *tca[TCA_MAX + 1];
//        struct net_device *dev;
        struct vport_info *vport = NULL; // Y.Born

        uint32_t clid;
        struct Qdisc *q, *p;
        int err;

//        if (!capable(CAP_NET_ADMIN))
//                return -EPERM;

replay:
        /* Reinit, just in case something touches this. */
        err = nlmsg_parse(n, sizeof(*tcm), tca, TCA_MAX, NULL);
        if (err < 0)
                return err;

        tcm = nlmsg_data(n);
        clid = tcm->tcm_parent;
        RTE_LOG(INFO, QoS, "clid: %u\n", clid);
        q = p = NULL;

//        dev = __dev_get_by_index(net, tcm->tcm_ifindex);
        vport = get_vport_by_index(tcm->tcm_ifindex); // Y.Born
        
        if (!vport)
                return -ENODEV;
        RTE_LOG(INFO, QoS, "Success to get vport\n");

        if (clid) {
                if (clid != TC_H_ROOT) {
                        if (clid != TC_H_INGRESS) {
                                p = qdisc_lookup(vport, TC_H_MAJ(clid));
                                if (!p)
                                        return -ENOENT;
                                q = qdisc_leaf(p, clid);
                                RTE_LOG(INFO, QoS, "Line: %d\n", __LINE__);
                        }
                } else {
                        // clid == TC_H_ROOT
//                        q = dev->qdisc;
                        q = vport->qdisc;  // Y.Born
                        RTE_LOG(INFO, QoS, "Line: %d\n", __LINE__);
                }

                /* It may be default qdisc, ignore it */
                if (q && q->handle == 0)
                        q = NULL;

                if (!q || !tcm->tcm_handle || q->handle != tcm->tcm_handle) {
                        if (tcm->tcm_handle) {
                                RTE_LOG(INFO, QoS, "Line: %d\n", __LINE__);
                                if (q && !(n->nlmsg_flags & NLM_F_REPLACE)) {
                                RTE_LOG(INFO, QoS, "Line: %d\n", __LINE__);
                                        return -EEXIST;
                                }
                                if (TC_H_MIN(tcm->tcm_handle)) {
                RTE_LOG(INFO, QoS, "%s [%d]\n",__func__, __LINE__);
                                        return -EINVAL;
                                }
                RTE_LOG(INFO, QoS, "%s [%d]\n",__func__, __LINE__);
                                q = qdisc_lookup(vport, tcm->tcm_handle);
                RTE_LOG(INFO, QoS, "%s [%d]\n",__func__, __LINE__);
                                if (!q) {
                RTE_LOG(INFO, QoS, "%s [%d]\n",__func__, __LINE__);
                                        goto create_n_graft;
                                }
                                if (n->nlmsg_flags & NLM_F_EXCL) {
                RTE_LOG(INFO, QoS, "%s [%d]\n",__func__, __LINE__);
                                        return -EEXIST;
                                }
                                if (tca[TCA_KIND] && nla_strcmp(tca[TCA_KIND], q->ops->id)) {
                RTE_LOG(INFO, QoS, "%s [%d]\n",__func__, __LINE__);
                                        return -EINVAL;
                                }
//                                if (q == p ||
//                                    (p && check_loop(q, p, 0)))
//                                        return -ELOOP;
                RTE_LOG(INFO, QoS, "%s [%d]\n",__func__, __LINE__);
                                atomic_inc(&q->refcnt);
                RTE_LOG(INFO, QoS, "%s [%d]\n",__func__, __LINE__);
                                goto graft;
                        } else {
                RTE_LOG(INFO, QoS, "%s [%d]\n",__func__, __LINE__);
                                if (!q)
                                        goto create_n_graft;

                                /* This magic test requires explanation.
                                 *
                                 *   We know, that some child q is already
                                 *   attached to this parent and have choice:
                                 *   either to change it or to create/graft new one.
                                 *
                                 *   1. We are allowed to create/graft only
                                 *   if CREATE and REPLACE flags are set.
                                 *
                                 *   2. If EXCL is set, requestor wanted to say,
                                 *   that qdisc tcm_handle is not expected
                                 *   to exist, so that we choose create/graft too.
                                 *
                                 *   3. The last case is when no flags are set.
                                 *   Alas, it is sort of hole in API, we
                                 *   cannot decide what to do unambiguously.
                                 *   For now we select create/graft, if
                                 *   user gave KIND, which does not match existing.
                                 */
                RTE_LOG(INFO, QoS, "%s [%d]\n",__func__, __LINE__);
                                if ((n->nlmsg_flags & NLM_F_CREATE) &&
                                    (n->nlmsg_flags & NLM_F_REPLACE) &&
                                    ((n->nlmsg_flags & NLM_F_EXCL) ||
                                     (tca[TCA_KIND] &&
                                      nla_strcmp(tca[TCA_KIND], q->ops->id))))
                                        goto create_n_graft;
                        }
                }
        } else {
                if (!tcm->tcm_handle)
                        return -EINVAL;
                q = qdisc_lookup(vport, tcm->tcm_handle);
                RTE_LOG(INFO, QoS, "%s [%d]\n",__func__, __LINE__);
        }

//TODO: function: change qdisc -- Y.Born
        /* Change qdisc parameters */
        if (q == NULL)
                return -ENOENT;
        if (n->nlmsg_flags & NLM_F_EXCL)
                return -EEXIST;
        if (tca[TCA_KIND] && nla_strcmp(tca[TCA_KIND], q->ops->id))
                return -EINVAL;
        err = qdisc_change(q, tca);
        if (err == 0)
                qdisc_notify(vport, skb, n, clid, NULL, q);
        return err;

create_n_graft:
        if (!(n->nlmsg_flags & NLM_F_CREATE)) {
                RTE_LOG(INFO, QoS, "%s [%d]\n",__func__, __LINE__);
                return -ENOENT;
        }
//        if (clid == TC_H_INGRESS) {
//                if (dev_ingress_queue(dev))
//                        q = qdisc_create(dev, dev_ingress_queue(dev), p,
//                                         tcm->tcm_parent, tcm->tcm_parent,
//                                         tca, &err);
//                else
//                        err = -ENOENT;
//        } else {
//                struct netdev_queue *dev_queue;
//
//                if (p && p->ops->cl_ops && p->ops->cl_ops->select_queue)
//                        dev_queue = p->ops->cl_ops->select_queue(p, tcm);
//                else if (p)
//                        dev_queue = p->dev_queue;
//                else
//                        dev_queue = netdev_get_tx_queue(dev, 0);

//                q = qdisc_create(dev, dev_queue, p,
//                                 tcm->tcm_parent, tcm->tcm_handle,
//                                 tca, &err);
                RTE_LOG(INFO, QoS, "%s [%d]\n",__func__, __LINE__);
                q = qdisc_create(vport, p,
                                 tcm->tcm_parent, tcm->tcm_handle,
                                 tca, &err);
//        }
        if (q == NULL) {
                RTE_LOG(INFO, QoS, "%s [%d]\n",__func__, __LINE__);
                if (err == -EAGAIN)
                        goto replay;
                RTE_LOG(INFO, QoS, "%s [%d]\n",__func__, __LINE__);
                return err;
        }

graft:
//        err = qdisc_graft(dev, p, skb, n, clid, q, NULL);
        err = qdisc_graft(vport, p, skb, n, clid, q, NULL);
        if (err) {
        RTE_LOG(INFO, QoS, "Line: %d\n", __LINE__);
                if (q)
                        qdisc_destroy(q);
                return err;
        }
        RTE_LOG(INFO, QoS, "Line: %d\n", __LINE__);

        return 0;
}
/*
 * Delete/get qdisc.
 */

int tc_get_qdisc(struct sk_buf *skb __rte_unused, struct nlmsghdr *n __rte_unused)
{
   printf("%s\n", __func__);
//        struct net *net = sock_net(skb->sk);
        struct tcmsg *tcm = nlmsg_data(n);
        struct nlattr *tca[TCA_MAX + 1];
//        struct net_device *dev;
        uint32_t clid;
        struct Qdisc *q = NULL;
        struct Qdisc *p = NULL;
        int err;
        struct vport_info *vport = NULL; // Y.Born

//        if ((n->nlmsg_type != RTM_GETQDISC) &&
//            !netlink_ns_capable(skb, net->user_ns, CAP_NET_ADMIN))
//                return -EPERM;

        err = nlmsg_parse(n, sizeof(*tcm), tca, TCA_MAX, NULL);
        if (err < 0)
                return err;

//        dev = __dev_get_by_index(net, tcm->tcm_ifindex);
        vport = get_vport_by_index(tcm->tcm_ifindex); // Y.Born
        if (!vport)
                return -ENODEV;

        clid = tcm->tcm_parent;
        if (clid) {
                if (clid != TC_H_ROOT) {
                        if (TC_H_MAJ(clid) != TC_H_MAJ(TC_H_INGRESS)) {
                                p = qdisc_lookup(vport, TC_H_MAJ(clid));
                                if (!p)
                                        return -ENOENT;
                                q = qdisc_leaf(p, clid);
//                        } else if (dev_ingress_queue(dev)) {
//                                q = dev_ingress_queue(dev)->qdisc_sleeping;
                        }
                } else {
                        q = vport->qdisc;
                }
                if (!q)
                        return -ENOENT;

                if (tcm->tcm_handle && q->handle != tcm->tcm_handle)
                        return -EINVAL;
        } else {
                q = qdisc_lookup(vport, tcm->tcm_handle);
                if (!q)
                        return -ENOENT;
        }

        if (tca[TCA_KIND] && nla_strcmp(tca[TCA_KIND], q->ops->id))
                return -EINVAL;

        if (n->nlmsg_type == RTM_DELQDISC) {
                if (!clid)
                        return -EINVAL;
                if (q->handle == 0)
                        return -ENOENT;
                err = qdisc_graft(vport, p, skb, n, clid, NULL, q);
                if (err != 0)
                        return err;
        } else {
                qdisc_notify(vport, skb, n, clid, NULL, q);
        }
        return 0;
}

int tc_dump_qdisc(struct sk_buf *skb, struct netlink_callback *cb)
{
//        struct net *net = sock_net(skb->sk);
////////////////////////////////////////////////////////////
        struct nlmsghdr *n = nlmsg_hdr(cb->skb);
        struct tcmsg *tcm;
        struct nlattr *tca[TCA_MAX + 1];
//        struct net_device *dev;
        struct vport_info *vport = NULL; // Y.Born
        int err;
        err = nlmsg_parse(n, sizeof(*tcm), tca, TCA_MAX, NULL);
        if (err < 0)
                return err;

        tcm = nlmsg_data(n);

        vport = get_vport_by_index(tcm->tcm_ifindex); // Y.Born

        if (!vport)
                return -ENODEV;
        printf("port is: %d\n", tcm->tcm_ifindex);
/////////////////////////////////////////////////////////////

        int idx, q_idx;
        int s_idx, s_q_idx;
        // struct net_device *dev;

        s_idx = cb->args[0];
        s_q_idx = q_idx = cb->args[1];

//         rcu_read_lock();
        idx = 0;
//         for_each_netdev_rcu(net, dev) {
//                 struct netdev_queue *dev_queue;

                if (idx < s_idx)
                        goto cont;
                if (idx > s_idx)
                        s_q_idx = 0;
                q_idx = 0;

                if (tc_dump_qdisc_root(vport->qdisc, skb, cb, &q_idx, s_q_idx) < 0)
                        goto done;

//                 dev_queue = dev_ingress_queue(dev);
//                 if (dev_queue &&
//                     tc_dump_qdisc_root(dev_queue->qdisc_sleeping, skb, cb,
//                                        &q_idx, s_q_idx) < 0)
//                         goto done;

cont:
                idx++;
//         }

done:
//         rcu_read_unlock();

        cb->args[0] = idx;
        cb->args[1] = q_idx;

        return skb->iov_len;
}

static int tc_fill_tclass(struct sk_buf *skb, struct Qdisc *q,
                          unsigned long cl,
                          uint32_t portid, uint32_t seq, uint16_t flags, int event)
{
        struct tcmsg *tcm;
        struct nlmsghdr  *nlh;
        unsigned char *b = skb_tail_pointer(skb);
        struct gnet_dump d;
        const struct Qdisc_class_ops *cl_ops = q->ops->cl_ops;

//        cond_resched();
        nlh = nlmsg_put(skb, portid, seq, event, sizeof(*tcm), flags);
        if (!nlh)
                goto out_nlmsg_trim;
        tcm = nlmsg_data(nlh);
        tcm->tcm_family = AF_UNSPEC;
        tcm->tcm__pad1 = 0;
        tcm->tcm__pad2 = 0;
        tcm->tcm_ifindex = qdisc_vport(q)->vportid;
        tcm->tcm_parent = q->handle;
        tcm->tcm_handle = q->handle;
        tcm->tcm_info = 0;
        if (nla_put_string(skb, TCA_KIND, q->ops->id))
                goto nla_put_failure;
        if (cl_ops->dump && cl_ops->dump(q, cl, skb, tcm) < 0)
                goto nla_put_failure;

        if (gnet_stats_start_copy_compat(skb, TCA_STATS2, TCA_STATS, TCA_XSTATS,
                                         NULL, &d) < 0)
//                                         qdisc_root_sleeping_lock(q), &d) < 0)
                goto nla_put_failure;

        if (cl_ops->dump_stats && cl_ops->dump_stats(q, cl, &d) < 0)
                goto nla_put_failure;

        if (gnet_stats_finish_copy(&d) < 0)
                goto nla_put_failure;

        nlh->nlmsg_len = skb_tail_pointer(skb) - b;
        return skb->iov_len;

out_nlmsg_trim:
nla_put_failure:
        nlmsg_trim(skb, b);
        return -1;
}

static int tclass_notify(struct vport_info *vport __rte_unused, struct sk_buf *oskb __rte_unused,
                         struct nlmsghdr *n, struct Qdisc *q,
                         unsigned long cl, int event)
{
        struct sk_buf *skb = NULL;
//        u32 portid = oskb ? NETLINK_CB(oskb).portid : 0;
        uint32_t pid = rth.peer.nl_pid;
        struct nlmsghdr *rep = NULL;
        rep = (struct nlmsghdr *)rte_zmalloc(NULL, NLMSG_GOODSIZE, 0);
        if (!rep)
                return -ENOBUFS;
        skb = alloc_skb(rep, NLMSG_GOODSIZE);
        if (!skb)
                return -ENOBUFS;

        if (tc_fill_tclass(skb, q, cl, pid, n->nlmsg_seq, 0, event) < 0) {
                rte_free(rep);
                rte_free(skb);
                return -EINVAL;
        }

        return rtnetlink_send(skb, pid, RTNLGRP_TC,
                              n->nlmsg_flags & NLM_F_ECHO);
}

int tc_ctl_tclass(struct sk_buf *skb __rte_unused, struct nlmsghdr *n __rte_unused)
{
   printf("%s\n", __func__);
//   return 0;
//        struct net *net = sock_net(skb->sk);
        struct tcmsg *tcm = nlmsg_data(n);
        struct nlattr *tca[TCA_MAX + 1];
//        struct net_device *dev;
        struct Qdisc *q = NULL;
        const struct Qdisc_class_ops *cops;
        unsigned long cl = 0;
        unsigned long new_cl;
        uint32_t portid;
        uint32_t clid;
        uint32_t qid;
        int err;
        struct vport_info *vport = NULL; //Y.Born

//        if ((n->nlmsg_type != RTM_GETTCLASS) &&
//            !netlink_ns_capable(skb, net->user_ns, CAP_NET_ADMIN))
//                return -EPERM;

        err = nlmsg_parse(n, sizeof(*tcm), tca, TCA_MAX, NULL);
        if (err < 0)
                return err;

//        dev = __dev_get_by_index(net, tcm->tcm_ifindex);
        vport = get_vport_by_index(tcm->tcm_ifindex); // Y.Born
        if (!vport)
                return -ENODEV;

        /*
           parent == TC_H_UNSPEC - unspecified parent.
           parent == TC_H_ROOT   - class is root, which has no parent.
           parent == X:0         - parent is root class.
           parent == X:Y         - parent is a node in hierarchy.
           parent == 0:Y         - parent is X:Y, where X:0 is qdisc.

           handle == 0:0         - generate handle from kernel pool.
           handle == 0:Y         - class is X:Y, where X:0 is qdisc.
           handle == X:Y         - clear.
           handle == X:0         - root class.
         */

        /* Step 1. Determine qdisc handle X:0 */

        portid = tcm->tcm_parent;
        clid = tcm->tcm_handle;
        qid = TC_H_MAJ(clid);

        if (portid != TC_H_ROOT) {
                uint32_t qid1 = TC_H_MAJ(portid);

                if (qid && qid1) {
                        /* If both majors are known, they must be identical. */
                        if (qid != qid1)
                                return -EINVAL;
                } else if (qid1) {
                        qid = qid1;
                } else if (qid == 0)
                        qid = vport->qdisc->handle;

                /* Now qid is genuine qdisc handle consistent
                 * both with parent and child.
                 *
                 * TC_H_MAJ(portid) still may be unspecified, complete it now.
                 */
                if (portid)
                        portid = TC_H_MAKE(qid, portid);
        } else {
                if (qid == 0)
                        qid = vport->qdisc->handle;
        }

        /* OK. Locate qdisc */
        q = qdisc_lookup(vport, qid);
        if (!q)
                return -ENOENT;

        /* An check that it supports classes */
        cops = q->ops->cl_ops;
        if (cops == NULL)
                return -EINVAL;

        /* Now try to get class */
        if (clid == 0) {
                if (portid == TC_H_ROOT)
                        clid = qid;
        } else
                clid = TC_H_MAKE(qid, clid);

        if (clid)
                cl = cops->get(q, clid);

        if (cl == 0) {
                err = -ENOENT;
                if (n->nlmsg_type != RTM_NEWTCLASS ||
                    !(n->nlmsg_flags & NLM_F_CREATE))
                        goto out;
        } else {
                switch (n->nlmsg_type) {
                case RTM_NEWTCLASS:
                        err = -EEXIST;
                        if (n->nlmsg_flags & NLM_F_EXCL)
                                goto out;
                        break;
                case RTM_DELTCLASS:
                        err = -EOPNOTSUPP;
                        if (cops->delete)
                                err = cops->delete(q, cl);
                        if (err == 0)
                                tclass_notify(vport, skb, n, q, cl, RTM_DELTCLASS);
                        goto out;
                case RTM_GETTCLASS:
                        err = tclass_notify(vport, skb, n, q, cl, RTM_NEWTCLASS);
                        goto out;
                default:
                        err = -EINVAL;
                        goto out;
                }
        }

        new_cl = cl;
        err = -EOPNOTSUPP;
        if (cops->change)
                err = cops->change(q, clid, portid, tca, &new_cl);
        if (err == 0)
                tclass_notify(vport, skb, n, q, new_cl, RTM_NEWTCLASS);

out:
        if (cl)
                cops->put(q, cl);

        return err;
}

struct qdisc_dump_args {
        struct qdisc_walker     w;
        struct sk_buf           *skb;
        struct netlink_callback *cb;
};

static int qdisc_class_dump(struct Qdisc *q, unsigned long cl, struct qdisc_walker *arg)
{
        struct qdisc_dump_args *a = (struct qdisc_dump_args *)arg;

        return tc_fill_tclass(a->skb, q, cl, rth.peer.nl_pid,
                              a->cb->nlh->nlmsg_seq, NLM_F_MULTI, RTM_NEWTCLASS);
}

static int tc_dump_tclass_qdisc(struct Qdisc *q, struct sk_buf *skb,
                                struct tcmsg *tcm, struct netlink_callback *cb,
                                int *t_p, int s_t)
{
        struct qdisc_dump_args arg;

        if (tc_qdisc_dump_ignore(q) ||
            *t_p < s_t || !q->ops->cl_ops ||
            (tcm->tcm_parent &&
             TC_H_MAJ(tcm->tcm_parent) != q->handle)) {
                (*t_p)++;
                return 0;
        }
        if (*t_p > s_t)
                memset(&cb->args[1], 0, sizeof(cb->args)-sizeof(cb->args[0]));
        arg.w.fn = qdisc_class_dump;
        arg.skb = skb;
        arg.cb = cb;
        arg.w.stop  = 0;
        arg.w.skip = cb->args[1];
        arg.w.count = 0;
        q->ops->cl_ops->walk(q, &arg.w);
        cb->args[1] = arg.w.count;
        if (arg.w.stop)
                return -1;
        (*t_p)++;
        return 0;
}

static int tc_dump_tclass_root(struct Qdisc *root, struct sk_buf *skb,
                               struct tcmsg *tcm, struct netlink_callback *cb,
                               int *t_p, int s_t)
{
        struct Qdisc *q;

        if (!root)
                return 0;

        if (tc_dump_tclass_qdisc(root, skb, tcm, cb, t_p, s_t) < 0)
                return -1;

        list_for_each_entry(q, &root->list, list) {
                if (tc_dump_tclass_qdisc(q, skb, tcm, cb, t_p, s_t) < 0)
                        return -1;
        }

        return 0;
}

int tc_dump_tclass(struct sk_buf *skb, struct netlink_callback *cb)
{
        struct tcmsg *tcm = nlmsg_data(cb->nlh);
//        struct net *net = sock_net(skb->sk);
//        struct netdev_queue *dev_queue;
//        struct net_device *dev;
        struct vport_info *vport = NULL;
        int t, s_t;

        if (nlmsg_len(cb->nlh) < (int)sizeof(*tcm))
                return 0;
        
        vport = get_vport_by_index(tcm->tcm_ifindex);
        if (!vport)
                return 0;

        s_t = cb->args[0];
        t = 0;

        if (tc_dump_tclass_root(vport->qdisc, skb, tcm, cb, &t, s_t) < 0)
                goto done;

//        dev_queue = dev_ingress_queue(dev);
//        if (dev_queue &&
//            tc_dump_tclass_root(dev_queue->qdisc_sleeping, skb, tcm, cb,
//                                &t, s_t) < 0)
//                goto done;

done:
        cb->args[0] = t;

//        dev_put(dev);
        return skb->iov_len;
}

/****** Define some qdisc ******/

// noop_qdisc
static inline int
noop_enqueue(struct rte_mbuf *pkt, struct Qdisc *sch __rte_unused) {
    rte_pktmbuf_free(pkt);
    return NET_XMIT_CN;
}

static inline struct rte_mbuf *
noop_dequeue(struct Qdisc *sch __rte_unused) {
    return NULL;
}

// struct Qdisc_ops noop_qdisc_ops __read_mostly = {
struct Qdisc_ops noop_qdisc_ops = {
    .id      = "noop",
    .priv_size = 0, 
    .enqueue = noop_enqueue,
    .dequeue = noop_dequeue,
    .peek    = noop_dequeue,
//  .owner   = THIS_MODULE,
};

struct Qdisc noop_qdisc = {
        .enqueue        =       noop_enqueue,
        .dequeue        =       noop_dequeue,
        .flags          =       TCQ_F_BUILTIN,
        .ops            =       &noop_qdisc_ops,
        .list           =       LIST_HEAD_INIT(noop_qdisc.list),
//        .q.lock         =       __SPIN_LOCK_UNLOCKED(noop_qdisc.q.lock),
//        .dev_queue      =       &noop_netdev_queue,
        .busylock       =       RTE_SPINLOCK_INITIALIZER,
};

static struct Qdisc_ops noqueue_qdisc_ops = {
        .id             =       "noqueue",
        .priv_size      =       0,
        .enqueue        =       noop_enqueue,
        .dequeue        =       noop_dequeue,
        .peek           =       noop_dequeue,
//        .owner          =       THIS_MODULE,
};

//static struct Qdisc noqueue_qdisc;
//static struct netdev_queue noqueue_netdev_queue = {
//        .qdisc          =       &noqueue_qdisc,
//        .qdisc_sleeping =       &noqueue_qdisc,
//};

static struct Qdisc noqueue_qdisc = {
        .enqueue        =       NULL,
        .dequeue        =       noop_dequeue,
        .flags          =       TCQ_F_BUILTIN,
        .ops            =       &noqueue_qdisc_ops,
        .list           =       LIST_HEAD_INIT(noqueue_qdisc.list),
//        .q.lock         =       __SPIN_LOCK_UNLOCKED(noqueue_qdisc.q.lock),
//        .dev_queue      =       &noqueue_netdev_queue,
        .busylock       =       RTE_SPINLOCK_INITIALIZER,
};
