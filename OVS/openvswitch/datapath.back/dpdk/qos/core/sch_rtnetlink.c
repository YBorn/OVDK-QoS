/*
 * =====================================================================================
 *
 *       Filename:  qos_netlink.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年06月05日 22时25分26秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Y.Born (), llyangborn@gmail.com
 *   Organization:  
 *
 * =====================================================================================
 */


#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <time.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <rte_malloc.h>
#include <rte_common.h>
#include <rte_atomic.h>
#include <rte_log.h>
#include <rte_ring.h>

#include "sch_rtnetlink.h"
#include "sch_qdisc.h"
#include "sch_generic.h"
#include "netlink_api.h"
#include "sch_stats.h"
#include "../../vport_define.h"

#define RTE_LOGTYPE_QoS RTE_LOGTYPE_USER1

/***************************************************************
 * **************** rtnl relative define*****************************/

#define PF_NUM 1

extern struct rtnl_handle rth;
extern int ERR;

typedef int      (*rtnl_doit_func)(struct sk_buf *, struct nlmsghdr *);

typedef int      (*rtnl_dumpit_func)(struct sk_buf *, struct netlink_callback *);
typedef uint16_t (*rtnl_calcit_func)(struct sk_buf *, struct nlmsghdr *);

// TODO: Should redefine RTM*, Many enmu flag we don't use.
// FILE: /linux/rtnetlink.h
struct rtnl_link {
    rtnl_doit_func      doit;
    rtnl_dumpit_func    dumpit;
    rtnl_calcit_func    calcit;
};

static struct rtnl_link rtnl_msg_handlers[PF_NUM][RTM_NR_MSGTYPES];

/************* static rtnl API **************/

static int rtnl_open_byproto(struct rtnl_handle *rth, unsigned subscriptions,
                int protocol) {

    socklen_t addr_len;
    int rcvbuf = 32768;
    int sndbuf = 1024*1024;

    memset(rth, 0, sizeof(*rth));

    rth->fd = socket(AF_NETLINK, SOCK_RAW, protocol);
    if (rth->fd < 0) {
        perror("Cannot open netlink socket");
        return -1;
    }

    if (setsockopt(rth->fd,SOL_SOCKET,SO_SNDBUF,&sndbuf,sizeof(sndbuf)) < 0) {
        perror("SO_SNDBUF");
        return -1;
    }

    if (setsockopt(rth->fd,SOL_SOCKET,SO_RCVBUF,&rcvbuf,sizeof(rcvbuf)) < 0) {
        perror("SO_RCVBUF");
        return -1;
    }

    memset(&rth->local, 0, sizeof(rth->local));
    rth->local.nl_family = AF_NETLINK;
    rth->local.nl_groups = subscriptions;
    rth->local.nl_pid = getpid();

    if (bind(rth->fd, (struct sockaddr*)&rth->local, sizeof(rth->local)) < 0) {
        perror("Cannot bind netlink socket");
        return -1; 
    }
    addr_len = sizeof(rth->local);
    if (getsockname(rth->fd, (struct sockaddr*)&rth->local, &addr_len) < 0) {
        perror("Cannot getsockname");
        return -1;
    }
    if (addr_len != sizeof(rth->local)) {
        fprintf(stderr, "Wrong address length %d\n", addr_len);
        return -1;
    }
    if (rth->local.nl_family != AF_NETLINK) {
        fprintf(stderr, "Wrong address family %d\n", rth->local.nl_family);
        return -1;
    }
    rth->seq = time(NULL);
    return 0;
}

static inline int rtm_msgindex(int msgtype)
{
        int msgindex = msgtype - RTM_BASE;

        /*
         * msgindex < 0 implies someone tried to register a netlink
         * control code. msgindex >= RTM_NR_MSGTYPES may indicate that
         * the message type has not been added to linux/rtnetlink.h
         */
        if(msgindex < 0 || msgindex >= RTM_NR_MSGTYPES) {
            printf("Wrong msgtype\n");
        }

        return msgindex;
}

static rtnl_doit_func rtnl_get_doit(int protocol, int msgindex)
{
        struct rtnl_link *tab;

        if (protocol <= RTNL_FAMILY_MAX)
                tab = rtnl_msg_handlers[protocol];
        else
                tab = NULL;

        if (tab == NULL || tab[msgindex].doit == NULL)
                tab = rtnl_msg_handlers[PF_UNSPEC];

        return tab[msgindex].doit;
}

static rtnl_dumpit_func rtnl_get_dumpit(int protocol, int msgindex)
{
        struct rtnl_link *tab;

        if (protocol <= RTNL_FAMILY_MAX)
                tab = rtnl_msg_handlers[protocol];
        else
                tab = NULL;

        if (tab == NULL || tab[msgindex].dumpit == NULL)
                tab = rtnl_msg_handlers[PF_UNSPEC];

        return tab[msgindex].dumpit;
}

static rtnl_calcit_func rtnl_get_calcit(int protocol, int msgindex)
{
        struct rtnl_link *tab;

        if (protocol <= RTNL_FAMILY_MAX)
                tab = rtnl_msg_handlers[protocol];
        else
                tab = NULL;

        if (tab == NULL || tab[msgindex].calcit == NULL)
                tab = rtnl_msg_handlers[PF_UNSPEC];

        return tab[msgindex].calcit;
}

static int
rtnetlink_rcv_msg(struct sk_buf *skb, struct nlmsghdr *nlh) {

//    struct net *net = sock_net(skb->sk);
    rtnl_doit_func doit;
    int sz_idx, kind;
    int family;
    int type;
    int err;

    type = nlh->nlmsg_type;
    if (type > RTM_MAX) {
        RTE_LOG(ERR, QoS, "Operation not supported!\n");
        return -EOPNOTSUPP;
    }

    type -= RTM_BASE;

    /* All the messages must have at least 1 byte length */
    if (nlmsg_len(nlh) < (int)sizeof(struct rtgenmsg)) {
        RTE_LOG(ERR, QoS, "Message is too short!\n");
        return 0;
    }

    family = ((struct rtgenmsg *)nlmsg_data(nlh))->rtgen_family;
    sz_idx = type>>2;
    kind = type&3;

//    if (kind != 2 && !ns_capable(net->user_ns, CAP_NET_ADMIN))
//           return -EPERM;
//    if (kind != 2) {
//       RTE_LOG(ERR, QoS, "Operation is not permitted!\n");
//       return -EPERM;
//   }

    if (kind == 2 && nlh->nlmsg_flags&NLM_F_DUMP) {
//            struct sock *rtnl;
           rtnl_dumpit_func dumpit;
           rtnl_calcit_func calcit;
           u16 min_dump_alloc = 0;

           dumpit = rtnl_get_dumpit(family, type);
           if (dumpit == NULL)
                   return -EOPNOTSUPP;
           calcit = rtnl_get_calcit(family, type);
           if (calcit)
                   min_dump_alloc = calcit(skb, nlh);

//           __rtnl_unlock();
//           rtnl = net->rtnl;
           {
                   struct netlink_dump_control c = {
                           .dump           = dumpit,
                           .min_dump_alloc = min_dump_alloc,
                   };
                   err = netlink_dump_start(skb, nlh, &c);
           }
//            rtnl_lock();
           return err;
    }

    RTE_LOG(INFO, QoS, "family: %d, type: %d\n", family, type);
    doit = rtnl_get_doit(family, type);
    if (doit == NULL) {
        RTE_LOG(ERR, QoS, "Operation is not supported!\n");
        return -EOPNOTSUPP;
    }

    return doit(skb, nlh);
}


//void netlink_ack(struct sk_buff *in_skb, struct nlmsghdr *nlh, int err)
//{
//        struct sk_buff *skb;
//        struct nlmsghdr *rep;
//        struct nlmsgerr *errmsg;
//        size_t payload = sizeof(*errmsg);
//
//        /* error messages get the original request appened */
//        if (err)
//                payload += nlmsg_len(nlh);
//
//        skb = netlink_alloc_skb(in_skb->sk, nlmsg_total_size(payload),
//                                NETLINK_CB(in_skb).portid, GFP_KERNEL);
//        if (!skb) {
//                struct sock *sk;
//
//                sk = netlink_lookup(sock_net(in_skb->sk),
//                                    in_skb->sk->sk_protocol,
//                                    NETLINK_CB(in_skb).portid);
//                if (sk) {
//                        sk->sk_err = ENOBUFS;
//                        sk->sk_error_report(sk);
//                        sock_put(sk);
//                }
//                return;
//        }
//
//        rep = __nlmsg_put(skb, NETLINK_CB(in_skb).portid, nlh->nlmsg_seq,
//                          NLMSG_ERROR, payload, 0);
//        errmsg = nlmsg_data(rep);
//        errmsg->error = err;
//        memcpy(&errmsg->msg, nlh, err ? nlh->nlmsg_len : sizeof(*nlh));
//        netlink_unicast(in_skb->sk, skb, NETLINK_CB(in_skb).portid, MSG_DONTWAIT);
//}

// static inline struct nlmsghdr * __nlmsg_put(struct iovec *skb, uint32_t pid, uint32_t seq, int type, int len, int flags)
// {
//     struct nlmsghdr *nlh;
//     int size = nlmsg_msg_size(len);
// 
//     nlh = (struct nlmsghdr *)(skb->iov_base);
//     nlh->nlmsg_type = type;
//     nlh->nlmsg_len = size;
//     nlh->nlmsg_flags = flags;
//     nlh->nlmsg_pid = pid;
//     nlh->nlmsg_seq = seq;
//     if(!__builtin_constant_p(size) || NLMSG_ALIGN(size) -size != 0) {
//         if(NLMSG_HDRLEN+len > (int)NLMSG_ALIGN(size))
//             RTE_LOG(ERR, QoS, "%s [%d]\n", __func__, __LINE__);
//         memset(nlmsg_data(nlh) + len, 0, NLMSG_ALIGN(size) - size);
//     }
//     return nlh;
// }
// 
// static inline int skb_tailroom(const sk_buf *skb) {
//     return skb->max_len - skb->iov_len;
// }
// 
// // Checked
// static inline struct nlmsghdr *nlmsg_put(struct iovec *skb, uint32_t portid, uint32_t seq,
//                                          int type, int payload, int flags)
// {
// //        if (unlikely(skb_tailroom(skb) < nlmsg_total_size(payload)))
// //                return NULL;
//         if((skb_tailroom(skb) < nlmsg_total_size(payload))
//             return NULL;
// 
//         return __nlmsg_put(skb, portid, seq, type, payload, flags);
// }

/****** Construct ack ******/
//void netlink_ack(struct iovec *in_skb, struct nk_acknlmsghdr *nlh, int err) {
static void netlink_ack(struct nlmsghdr *nlh, int err) {
        
        struct nlmsghdr *rep;
        struct nlmsgerr *errmsg;
        size_t payload = sizeof(*errmsg);

        if(err)
            payload += nlmsg_len(nlh);

        int total_len = nlmsg_total_size(payload);
        rep = (struct nlmsghdr *)rte_malloc(NULL, total_len, 0);
        if(rep == NULL)
            rte_exit(EXIT_FAILURE, "Cannot malloc!");
        rep->nlmsg_len = total_len;
        struct sk_buf skb = {
            .iov_base = (void *) rep,
            .iov_len = rep->nlmsg_len,
            .max_len = rep->nlmsg_len,
        };

        struct sockaddr_nl nladdr;
        memset(&nladdr, 0, sizeof(nladdr));
        nladdr.nl_family = AF_NETLINK;
        nladdr.nl_pid = rth.peer.nl_pid;
        nladdr.nl_groups = 0;

        struct msghdr ack = {
            .msg_name = &nladdr,
            .msg_namelen = sizeof(struct sockaddr_nl),
            .msg_iov = (struct iovec *)&skb,
            .msg_iovlen = 1,
        };

//        skb = netlink_alloc_skb(nlmsg_total_size(payload));
        int pid = rth.peer.nl_pid;
        RTE_LOG(INFO, QoS, "peer pid: %d\n", pid);
        
        rep = __nlmsg_put(&skb, pid, nlh->nlmsg_seq, NLMSG_ERROR, payload, 0);
        errmsg = nlmsg_data(rep);
        errmsg->error = err;
        memcpy(&errmsg->msg, nlh, err ? nlh->nlmsg_len : sizeof(*nlh));
        int status = sendmsg(rth.fd, &ack, 0);  // netlink_unicast
        if(status < 0) {
            RTE_LOG(ERR, QoS, "P: %d fail to Send message to P: %d\n", getpid(), pid);
            return;
        }
        RTE_LOG(ERR, QoS, "P: %d success to Send message to P: %d\n", getpid(), pid);
}


#define EINTR   4
static int netlink_rcv_skb(struct sk_buf *skb, int (*cb)(struct sk_buf *, struct nlmsghdr *)) {
    struct nlmsghdr *nlh;
    int err = 0;
    int msglen;
        
    nlh = nlmsg_hdr(skb);
    
    if (nlh->nlmsg_len < NLMSG_HDRLEN || nlh->nlmsg_len > skb->iov_len) {
        RTE_LOG(ERR, QoS, "nlmsg_len: %d\n", nlh->nlmsg_len);
        RTE_LOG(ERR, QoS, "iov_len: %zu\n", skb->iov_len);
        
        RTE_LOG(ERR, QoS, "Error: TC Message is too short\n");
        return 0;
    }
    if (!(nlh->nlmsg_flags & NLM_F_REQUEST)) {
        RTE_LOG(INFO, QoS, "Go to Handle Request\n");
        goto ack;
    }
    if (nlh->nlmsg_type < NLMSG_MIN_TYPE) {
        RTE_LOG(INFO, QoS, "Skip control message\n");
        goto ack;
    }

    err = cb(skb, nlh);

    if (err == -EINTR) {
        RTE_LOG(INFO, QoS, "Interupted system call\n");
        goto skip;
    }
ack:
    if(nlh->nlmsg_flags & NLM_F_ACK || err) {
        RTE_LOG(INFO, QoS, "netlink_ack\n");
        netlink_ack(nlh, err);
    }
skip:
//    msglen = NLMSG_ALIGN(nlh->nlmsg_len);
//    if (msglen > skb->iov_len)
//        msglen = skb->iov_len;
//        skb_pull(skb, msglen);
//    }
    return 0;
}

/************* open rtnl API **************/

int rtnl_open(struct rtnl_handle *rth, unsigned subscriptions) {
    return rtnl_open_byproto(rth, subscriptions, NETLINK_ROUTE);
}

void rtnl_close(struct rtnl_handle *rth) {
    if (rth->fd >= 0) {
        close(rth->fd);
        rth->fd = -1;
    }
}


/**
 * __rtnl_register - Register a rtnetlink message type
 * @protocol: Protocol family or PF_UNSPEC
 * @msgtype: rtnetlink message type
 * @doit: Function pointer called for each request message
 * @dumpit: Function pointer called for each dump request (NLM_F_DUMP) message
 * @calcit: Function pointer to calc size of dump message
 *
 * Registers the specified function pointers (at least one of them has
 * to be non-NULL) to be called whenever a request message for the
 * specified protocol family and message type is received.
 *
 * The special protocol family PF_UNSPEC may be used to define fallback
 * function pointers for the case when no entry for the specific protocol
 * family exists.
 *
 * Returns 0 on success or a negative error code.
 */
int rtnl_register(int protocol, int msgtype,
                  rtnl_doit_func doit, rtnl_dumpit_func dumpit,
                  rtnl_calcit_func calcit)
{
        struct rtnl_link *tab;
        int msgindex;

        if(protocol < 0 || protocol > RTNL_FAMILY_MAX) {
            printf("Wrong Protocol");
        }
        // Added by Y.Born
        if(protocol != PF_UNSPEC) {
            printf("Protocol is not Supported now");
            return -1;
        }

        msgindex = rtm_msgindex(msgtype);

        tab = rtnl_msg_handlers[protocol];
//        if (tab == NULL) {
//                tab = kcalloc(RTM_NR_MSGTYPES, sizeof(*tab), GFP_KERNEL);
//                if (tab == NULL)
//                        return -ENOBUFS;
//
//                rtnl_msg_handlers[protocol] = tab;
//        }

        if (doit)
                tab[msgindex].doit = doit;

        if (dumpit)
                tab[msgindex].dumpit = dumpit;

        if (calcit)
                tab[msgindex].calcit = calcit;

        return 0;
}

/*****************************************************************
void rtnl_register(int protocol, int msgtype,
                   rtnl_doit_func doit, rtnl_dumpit_func dumpit,
                   rtnl_calcit_func calcit)
{
        if (__rtnl_register(protocol, msgtype, doit, dumpit, calcit) < 0)
                fprintf(stderr, "<%s> [%s] (%d): Unable to register rtnetlink message handler, "
                      "protocol = %d, message type = %d\n",
                      , __FILE__, __func__, __LINE__,
                      __protocol, msgtype);
}
******************************************************************/

void rtnetlink_rcv(struct sk_buf *skb) {
// Need Lock
    netlink_rcv_skb(skb, &rtnetlink_rcv_msg);
// Need Unlock
}


// 不支持组播,单播给Tc
int rtnetlink_send(struct sk_buf *skb, uint32_t pid, unsigned int group, int echo)
{
        int err = 0;

//        NETLINK_CB(skb).dst_group = group;
//        if (echo)
//                atomic_inc(&skb->users);
//        netlink_broadcast(rtnl, skb, pid, group, GFP_KERNEL);
//        if (echo)
//                err = netlink_unicast(rtnl, skb, pid, MSG_DONTWAIT);
//        return err;

        if(echo) {
            struct sockaddr_nl nladdr;
            memset(&nladdr, 0, sizeof(nladdr));
            nladdr.nl_family = AF_NETLINK;
    //        nladdr.nl_pid = rth.peer.nl_pid;
            nladdr.nl_pid = pid;
            RTE_LOG(INFO, QoS, "pid: %d, nl_pid: %d\n", pid, rth.peer.nl_pid);
    //        nladdr.nl_groups = 0;
            nladdr.nl_groups = group;
            RTE_LOG(INFO, QoS, "group: %d\n", group);

            struct msghdr ack = {
                .msg_name = &nladdr,
                .msg_namelen = sizeof(struct sockaddr_nl),
                .msg_iov = (struct iovec *)skb,
                .msg_iovlen = 1,
            };

            int status = sendmsg(rth.fd, &ack, 0);  // netlink_unicast
            if(status < 0) {
                RTE_LOG(ERR, QoS, "%s [%d]\n", __func__, __LINE__);
                err = -1;
            }
        }
        return err;
}

/**
 * nl_dump_check_consistent - check if sequence is consistent and advertise if not
 * @cb: netlink callback structure that stores the sequence number
 * @nlh: netlink message header to write the flag to
 *
 * This function checks if the sequence (generation) number changed during dump
 * and if it did, advertises it in the netlink message header.
 *
 * The correct way to use it is to set cb->seq to the generation counter when
 * all locks for dumping have been acquired, and then call this function for
 * each message that is generated.
 *
 * Note that due to initialisation concerns, 0 is an invalid sequence number
 * and must not be used by code that uses this functionality.
 */
static inline void
nl_dump_check_consistent(struct netlink_callback *cb,
                         struct nlmsghdr *nlh)
{
        if (cb->prev_seq && cb->seq != cb->prev_seq)
                nlh->nlmsg_flags |= NLM_F_DUMP_INTR;
        cb->prev_seq = cb->seq;
}

static void netlink_destroy_callback(struct netlink_callback *cb)
{
//        rte_free(cb->skb->iov_base);
        rte_free(cb);
}

static int netlink_dump(struct netlink_callback *cb)
{
//        struct netlink_sock *nlk = nlk_sk(sk);
//        struct netlink_callback *cb;
        struct sk_buf skb;
        struct nlmsghdr *nlh;
        int len, err = -ENOBUFS;
        int alloc_size;

        int pid = rth.peer.nl_pid;
        RTE_LOG(INFO, QoS, "peer pid: %d\n", pid);
//         mutex_lock(nlk->cb_mutex);

//        cb = nlk->cb;
        if (cb == NULL) {
                err = -EINVAL;
                goto errout_skb;
        }

        alloc_size = max_t(int, cb->min_dump_alloc, NLMSG_GOODSIZE);

//         skb = sock_rmalloc(sk, alloc_size, 0, GFP_KERNEL);
        void *buf = rte_zmalloc(NULL, alloc_size, 0);

        if (!buf)
                goto errout_skb;
        skb.iov_base = buf;
        skb.iov_len = 0;
        skb.max_len = alloc_size;

        len = cb->dump(&skb, cb);

        if (len > 0) {
//                 mutex_unlock(nlk->cb_mutex);
// 
//                  if (sk_filter(sk, skb))
//                          kfree_skb(skb);
//                  else
//                          __netlink_sendskb(sk, skb);
            nlmsg_put(&skb, pid, cb->nlh->nlmsg_seq,
                         NLMSG_DONE, 0, NLM_F_MULTI);
            rtnetlink_send(&skb, pid, 0, 1);
            RTE_LOG(INFO, QoS, "len is > 0\n");
                 return 0;
        }

//        nlh = nlmsg_put_answer(skb, cb, NLMSG_DONE, sizeof(len), NLM_F_MULTI);

        nlh = nlmsg_put(&skb, pid, cb->nlh->nlmsg_seq,
                         NLMSG_DONE, sizeof(len), NLM_F_MULTI);
        if (!nlh)
                goto errout_skb;

        nl_dump_check_consistent(cb, nlh);

        memcpy(nlmsg_data(nlh), &len, sizeof(len));

//         if (sk_filter(sk, skb))
//                 kfree_skb(skb);
//         else
//                 __netlink_sendskb(sk, skb);

        netlink_ack(nlh, 0);
        if (cb->done)
                cb->done(cb);
//        nlk->cb = NULL;
//         mutex_unlock(nlk->cb_mutex);

        netlink_destroy_callback(cb);
        return 0;

errout_skb:
//         mutex_unlock(nlk->cb_mutex);
        rte_free(skb.iov_base);
        return err;
}

// int netlink_dump_start(struct sock *ssk, struct sk_buff *skb,
//                        const struct nlmsghdr *nlh,
//                        struct netlink_dump_control *control)
int netlink_dump_start(struct sk_buf *skb,
                       const struct nlmsghdr *nlh,
                       struct netlink_dump_control *control)
{
         struct netlink_callback *cb;
//         struct sock *sk;
//         struct netlink_sock *nlk;
        int ret;

//         cb = kzalloc(sizeof(*cb), GFP_KERNEL);
        cb = (struct netlink_callback *)rte_zmalloc(NULL, sizeof(*cb), 0);
        if (cb == NULL)
                return -ENOBUFS;

        memset(cb, 0, sizeof(*cb));
        cb->dump = control->dump;
        cb->done = control->done;
        cb->nlh = nlh;
        cb->data = control->data;
        cb->min_dump_alloc = control->min_dump_alloc;
//        atomic_inc(&skb->users);
        cb->skb = skb;

//         sk = netlink_lookup(sock_net(ssk), ssk->sk_protocol, NETLINK_CB(skb).pid);
//         if (sk == NULL) {
//                 netlink_destroy_callback(cb);
//                 return -ECONNREFUSED;
//         }
//        nlk = nlk_sk(sk);
        /* A dump is in progress... */
//         mutex_lock(nlk->cb_mutex);
//         if (nlk->cb) {
//                 mutex_unlock(nlk->cb_mutex);
//                 netlink_destroy_callback(cb);
//                 sock_put(sk);
//                 return -EBUSY;
//         }
//         nlk->cb = cb;
//        mutex_unlock(nlk->cb_mutex);

        ret = netlink_dump(cb);

//        sock_put(sk);

        if (ret)
                return ret;

        /* We successfully started a dump, by returning -EINTR we
         * signal not to send ACK even if it was requested.
         */
        return -EINTR;
}
