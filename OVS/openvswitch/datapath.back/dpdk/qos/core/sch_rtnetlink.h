#ifndef __SCH_RTNETLINK_H_
#define __SCH_RTNETLINK_H_

#include <linux/netlink.h>

#include "typedefs.h"

#define NLMSG_GOODSIZE 4096UL

struct rtnl_handle {
    int         fd;
    struct      sockaddr_nl local;
    struct      sockaddr_nl peer;
    uint32_t    seq;
    uint32_t    dump;
};

struct netlink_callback {
        struct sk_buf          *skb;
        const struct nlmsghdr   *nlh;
        int                     (*dump)(struct sk_buf * skb,
                                        struct netlink_callback *cb);
        int                     (*done)(struct netlink_callback *cb);
        void                    *data;
        u16                     family;
        u16                     min_dump_alloc;
        unsigned int            prev_seq, seq;
        long                    args[6];
};
    
struct netlink_dump_control {
        int (*dump)(struct sk_buf *skb, struct netlink_callback *);
        int (*done)(struct netlink_callback*);
        void *data;
        u16 min_dump_alloc;
};

struct sk_buf;
struct nlmsghdr;
struct netlink_callback;
struct netlink_dump_control;

typedef int (*rtnl_doit_func)(struct sk_buf *, struct nlmsghdr *);

typedef int (*rtnl_dumpit_func)(struct sk_buf *, struct netlink_callback *);
typedef uint16_t (*rtnl_calcit_func)(struct sk_buf *, struct nlmsghdr *);

/************* Open rtnl API **************/

int rtnl_open(struct rtnl_handle *rth, unsigned subscriptions);

void rtnl_close(struct rtnl_handle *rth);

int rtnl_register(int protocol, int msgtype,
                  rtnl_doit_func doit,
                  rtnl_dumpit_func dumpit,
                  rtnl_calcit_func calcit);

void rtnetlink_rcv(struct sk_buf *skb);

int rtnetlink_send(struct sk_buf *skb, uint32_t pid, unsigned int group, int echo);

int netlink_dump_start(struct sk_buf *skb,
                       const struct nlmsghdr *nlh,
                       struct netlink_dump_control *control);

#endif /* __SCH_RTNETLINK_H_ */
