#ifndef __SCH_QDISC_H_
#define __SCH_QDISC_H_

#include <stdbool.h>

#include <rte_atomic.h>

#include "pkt_sched.h"

struct vport_info;
struct Qdisc_ops;
struct Qdisc;
struct nlattr;
struct nlmsghdr;
struct netlink_callback;
struct qdisc_size_table;
struct sk_buf;
struct qdisc_rate_table;

struct Qdisc * qdisc_alloc(struct vport_info *vport, struct Qdisc_ops *ops);

void qdisc_destroy(struct Qdisc *qdisc);

struct Qdisc * qdisc_create_dflt(struct vport_info *vport,
                                  struct Qdisc_ops *ops,
                                  unsigned int parentid);

int tc_modify_qdisc(struct sk_buf *skb, struct nlmsghdr *n);

int tc_get_qdisc(struct sk_buf *skb, struct nlmsghdr *n);

int tc_dump_qdisc(struct sk_buf *skb, struct netlink_callback *cb);

int tc_ctl_tclass(struct sk_buf *skb, struct nlmsghdr *n);

int tc_dump_tclass(struct sk_buf *skb, struct netlink_callback *cb);

struct vport_info *get_vport_by_index(int index);

struct Qdisc *qdisc_lookup(struct vport_info *vport, uint32_t handle);

struct Qdisc *qdisc_match_from_root(struct Qdisc *root, uint32_t handle);

struct Qdisc *qdisc_leaf(struct Qdisc *p, uint32_t classid);

void atomic_inc(rte_atomic32_t *v);

int qdisc_change(struct Qdisc *sch, struct nlattr **tca);

int qdisc_notify(struct vport_info *vport, struct sk_buf *oskb,
                 struct nlmsghdr *n, uint32_t clid,
                 struct Qdisc *old, struct Qdisc *new);

struct Qdisc *qdisc_create(struct vport_info *vport, struct Qdisc *p,
                            uint32_t parent, uint32_t handle,
                            struct nlattr **tca, int *errp);

struct Qdisc_ops *qdisc_lookup_ops(struct nlattr *kind);

uint32_t qdisc_alloc_handle(struct vport_info *vport);

struct vport_info * qdisc_vport(struct Qdisc *q);

void qdisc_list_add(struct Qdisc *q);

int register_qdisc(struct Qdisc_ops *qops);

int qdisc_dump_stab(struct sk_buf *skb, struct qdisc_size_table *stab);

void qdisc_put_stab(struct qdisc_size_table *tab);

int tc_fill_qdisc(struct sk_buf *skb, struct Qdisc *q, uint32_t clid,
                  uint32_t portid, uint32_t seq, uint16_t flags, int event); // portid is pid

bool tc_qdisc_dump_ignore(struct Qdisc *q);

void qdisc_put_rtab(struct qdisc_rate_table *tab);

struct qdisc_rate_table *qdisc_get_rtab(struct tc_ratespec *r, struct nlattr *tab);

void qdisc_reset_queue(struct Qdisc *sch);

void qdisc_list_del(struct Qdisc *q);

struct Qdisc *dev_graft_qdisc(struct vport_info *vport,
                              struct Qdisc *qdisc);

void dev_activate(struct vport_info *vport);

void dev_init_scheduler(struct vport_info *vport);

#endif /* __SCH_QDISC_H_ */
