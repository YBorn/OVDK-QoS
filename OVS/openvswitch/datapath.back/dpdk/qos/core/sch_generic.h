/*                DPDK-OVS QoS Implemention/Anaylise
 * Packet Path:
 *           RX-NIC ---> Rx Buffer ---> Port Cache per Core 
 *           ---> Tx Rings ---> TX-NIC
 *
 * Location: Rx Buffer/Port Cache per Core/Tx rings are at Memory Pool,
 *           What we do is only to change the point to pktmbuf.
 *
 * Functions to Handle Packet:
 *           RX-NIC ---> Rx Buffer: 
 *              receive_from_vport(uint32_t vportid, struct rte_mbuf **bufs)
 *                  |
 *                  v
 *                  send_to_port/client/kni/veth/vhost
 *                  
 *           Rx Buffer ---> Port Cache per Core:
 *              do_switch_packets(uint32_t vportid, struct rte_mbuf **bufs, int rx_count)
 *                  |
 *                  v
 *                  switch_packet(struct rte_mbuf *pkt, struct flow_key *key)
 *                      |
 *                      v
 *                      action_execute(const struct action *actions, struct rte_mbuf *mbuf)
 *                          |
 *                          v
 *                          action_output(const struct action_output *action, struct rte_mbuf *mbuf)
 *                              |
 *                              v
 *                              send_to_vport(uint32_t vportid, struct rte_mbuf *buf)
 *                                  |
 *                                  v
 *                                  send_to_port/client/kni/veth/vhost
 *          Port Cache per Core ---> Tx rings:
 *              flush_ports()
 *                  |
 *                  v
 *                  flush_phy_port_cache(uint32_t vportid)
 *                      |
 *                      v
 *                      rte_ring_mp_enqueue_burst(struct rte_ring *r, void *const *obj_table, unsigned n)
 *                      rte_ring_mp_enqueue_bulk(struct rte_ring *r, void *const *obj_table, unsigned n)
 *                      ....
 *                      *** Choose the appropriate handles ***
 *                      *** Reference to intel-dpdk-api-reference Document ***
 *          Tx rings ---> TX-NIC:
 *              flush_nic_tx_ring(unsigned vportid)
 *                  |
 *                  v
 *                  rte_ring_dequeue_bulk(struct rte_ring *r, void **obj_table, unsigned n)
 *                      |
 *                      v
 *                      rte_eth_tx_burst(uint8_t port_id, uint16_t queue_id, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
 *
 *
 */

#ifndef __SCH_GENERIC_H__
#define __SCH_GENERIC_H__

#include <rte_cycles.h>
#include <rte_timer.h>
#include <rte_atomic.h>
#include <rte_spinlock.h>

#include "sch_stats.h"
#include "pkt_sched.h"
#include "../list/types.h"

#define NET_XMIT_SUCCESS    0x01
#define NET_XMIT_DROP       0x02
#define NET_XMIT_CN         0x03
#define NET_XMIT_POLICED    0x03
#define NET_XMIT_MASK       0x0f

#define IFNAMSIZ            16

#define QDISC_ALIGNTO       64
#define QDISC_ALIGN(len)    (((len) + QDISC_ALIGNTO-1) & ~(QDISC_ALIGNTO-1))

enum net_xmit_qdisc_t {
    __NET_XMIT_STOLEN = 0x00010000,
    __NET_XMIT_BYPASS = 0x00020000,
};

struct nlattr;


#define net_xmit_drop_count(e)  ((e) & __NET_XMIT_STOLEN ? 0 : 1)

struct Qdisc;
struct rte_mbuf;
struct rte_ring;
struct sk_buf;
struct qdisc_walker;
struct tcmsg;

enum qdisc_state_t {
        __QDISC_STATE_SCHED,
        __QDISC_STATE_DEACTIVATED,
        __QDISC_STATE_THROTTLED,
};

struct Qdisc_class_ops {
        /* Child qdisc manipulation */
//        struct netdev_queue *   (*select_queue)(struct Qdisc *, struct tcmsg *);
        int                     (*graft)(struct Qdisc *, unsigned long cl,
                                        struct Qdisc *, struct Qdisc **);
        struct Qdisc *          (*leaf)(struct Qdisc *, unsigned long cl);
        void                    (*qlen_notify)(struct Qdisc *, unsigned long);

        /* Class manipulation routines */
        unsigned long           (*get)(struct Qdisc *, u32 classid);
        void                    (*put)(struct Qdisc *, unsigned long);
        int                     (*change)(struct Qdisc *, u32, u32,
                                        struct nlattr **, unsigned long *);
        int                     (*delete)(struct Qdisc *, unsigned long);
        void                    (*walk)(struct Qdisc *, struct qdisc_walker * arg);

        /* Filter manipulation */
//        struct tcf_proto **     (*tcf_chain)(struct Qdisc *, unsigned long);
//        unsigned long           (*bind_tcf)(struct Qdisc *, unsigned long,
//                                        u32 classid);
//        void                    (*unbind_tcf)(struct Qdisc *, unsigned long);

        /* rtnetlink specific */
        int                     (*dump)(struct Qdisc *, unsigned long,
                                        struct sk_buf *skb, struct tcmsg*);
        int                     (*dump_stats)(struct Qdisc *, unsigned long,
                                        struct gnet_dump *);
};

struct Qdisc_ops {
    struct Qdisc_ops    *next;
    const struct Qdisc_class_ops *cl_ops;
    char                id[IFNAMSIZ];
    int                 priv_size;

    int                 (*enqueue) (struct rte_mbuf *, struct Qdisc *);
    struct rte_mbuf *   (*dequeue) (struct Qdisc *);
    struct rte_mbuf *   (*peek) (struct Qdisc *);
    unsigned int        (*drop) (struct Qdisc *);

    int                 (*init) (struct Qdisc*, struct nlattr *arg);
    void                 (*reset)(struct Qdisc *);
    void                (*destroy) (struct Qdisc *);
    int                 (*change)(struct Qdisc *, struct nlattr *arg);
    void                (*attach)(struct Qdisc *);
    
    int                 (*dump)(struct Qdisc *, struct sk_buf *);
    int                 (*dump_stats) (struct Qdisc *, struct gnet_dump *);

};

struct Qdisc {
    int                 (*enqueue) (struct rte_mbuf *, struct Qdisc *);
    struct rte_mbuf *   (*dequeue) (struct Qdisc *);
    unsigned int        flags;

#define TCQ_F_BUILTIN           1
#define TCQ_F_INGRESS           2
#define TCQ_F_CAN_BYPASS        4
#define TCQ_F_MQROOT            8
#define TCQ_F_ONETXQUEUE        0x10
#define TCQ_F_WARN_NONWC        (1<<16)

    u32                             limit;
    const struct Qdisc_ops          *ops;
    struct qdisc_size_table         *stab;
    // fifo
    struct rte_ring                 *q;
    u32                             qlen;

    struct list_head                list;
    u32                             handle;
    u32                             parent;

    struct rte_mbuf                 *gso_pkt; // temp pkt;

    // statistics
    struct gnet_stats_rate_est64    rate_est;
    struct gnet_stats_queue         qstats;
    struct gnet_stats_basic_packed  bstats;
//    struct gnet_stats_rate_est64    rstats;

    unsigned long                   state;
    struct vport_info               *vport;
    rte_atomic32_t                  refcnt;

//    int                             padded;

    rte_spinlock_t                  busylock;
};
// qdisc_priv

struct Qdisc_class_common {
    uint32_t classid;
    struct hlist_node hnode;
};

struct Qdisc_class_hash {
    struct hlist_head   *hash;
    uint32_t            hashsize;
    uint32_t            hashmask;
    uint32_t            hashelems;
};

struct Qdisc_watchdog {
    struct rte_timer timer;
    struct Qdisc    *qdisc;
};

struct qdisc_size_table {
    struct list_head    list;
    struct tc_sizespec  szopts;
    int                 refcnt;
    uint16_t            data[];
};

struct qdisc_rate_table {
        struct tc_ratespec rate;
        u32             data[256];
        struct qdisc_rate_table *next;
        int             refcnt;
};

struct qdisc_walker {
        int     stop;
        int     skip;
        int     count;
        int     (*fn)(struct Qdisc *, unsigned long cl, struct qdisc_walker *);
};

#endif /* __SCH_GENERIC_H__ */
