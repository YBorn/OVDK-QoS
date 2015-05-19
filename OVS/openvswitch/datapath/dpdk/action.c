/*
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <rte_ether.h>
#include "packets.h"
#include "action.h"
#include "vport.h"
#include "stats.h"
#include "ofpbuf.h"
#include "ofpbuf_helper.h"

#define CHECK_NULL(ptr)   do { \
                             if ((ptr) == NULL) return -1; \
                         } while (0)
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

static void action_output(const struct action_output *action,
                          struct rte_mbuf *mbuf);
static void action_drop(struct rte_mbuf *mbuf);
static void action_pop_vlan(struct rte_mbuf *mbuf);
static void action_push_vlan(const struct action_push_vlan *action,
                             struct rte_mbuf *mbuf);
static int check_for_multiple_output(const struct action *actions);
static void action_set_ethernet(const struct ovs_key_ethernet *ethernet_key,
                    struct rte_mbuf *mbuf);
static void action_set_ipv4(const struct ovs_key_ipv4 *ipv4_key,
                    struct rte_mbuf *mbuf);
static void action_set_tcp(const struct ovs_key_tcp *tcp_key,
                    struct rte_mbuf *mbuf);
static void action_set_udp(const struct ovs_key_udp *udp_key,
                    struct rte_mbuf *mbuf);
static void action_set_queue(const struct action_set_queue *queue,
                    struct rte_mbuf *mbuf);
/*
 * Do 'action' of action_type 'type' on 'mbuf'
 */
inline int __attribute__((always_inline))
action_execute(const struct action *actions, struct rte_mbuf *mbuf)
{
	const struct rte_mempool *mp = NULL;
	struct rte_mbuf *mb;
	int i = 0;
	int multiple_outputs = 0;
	CHECK_NULL(actions);
	CHECK_NULL(mbuf);

	if (unlikely(actions[0].type == ACTION_NULL)) {
		action_drop(mbuf);
		return 0;
	}

	multiple_outputs = check_for_multiple_output(actions);
	if (multiple_outputs)
		mp = rte_mempool_from_obj(mbuf);

	for (i = 0; i < MAX_ACTIONS && actions[i].type != ACTION_NULL; i++) {
		switch (actions[i].type) {
		case ACTION_OUTPUT:
			/* need to clone only if multiple OUTPUT case */
			if (multiple_outputs) {
				mb = rte_pktmbuf_clone(mbuf, (struct rte_mempool *)mp);
				if (mb)
					action_output(&actions[i].data.output, mb);
				else
					RTE_LOG(ERR, APP, "Failed to clone pktmbuf\n");
			}
			else {
				action_output(&actions[i].data.output, mbuf);
			}
			break;
		case ACTION_POP_VLAN:
			action_pop_vlan(mbuf);
			break;
		case ACTION_PUSH_VLAN:
			action_push_vlan(&actions[i].data.vlan, mbuf);
			break;
		case ACTION_SET_ETHERNET:
			action_set_ethernet(&actions[i].data.ethernet, mbuf);
			break;
		case ACTION_SET_IPV4:
			action_set_ipv4(&actions[i].data.ipv4, mbuf);
			break;
		case ACTION_SET_TCP:
			action_set_tcp(&actions[i].data.tcp, mbuf);
			break;
		case ACTION_SET_UDP:
			action_set_udp(&actions[i].data.udp, mbuf);
			break;
        case ACTION_SET_QUEUE:
			action_set_queue(&actions[i].data.queue, mbuf);
            break;
		default:
			printf("action_execute(): action not currently"
			       " implemented %d\n", actions[i].type);
			break;
		}
	}
	/* in multiple OUTPUT case, mbuf must be freed here */
	if (multiple_outputs)
		rte_pktmbuf_free(mbuf);

	return 0;
}

/* If we have multiple output actions the mbuf must be cloned each time.
 * This is a performance hit in the case of a single output action
 */
static inline int
check_for_multiple_output(const struct action *actions)
{
	int num_output_actions = 0;

	int i = 0;

	for (i = 0; i < MAX_ACTIONS && actions[i].type != ACTION_NULL; i++) {
		if (actions[i].type == ACTION_OUTPUT) {
			num_output_actions++;
			if (num_output_actions > 1)
				return 1; /* Multiple output */
		}
	}
	return 0; /* Single output */
}

/*
 * Excutes the output action on 'mbuf'
 */
static inline void
action_output(const struct action_output *action,
                          struct rte_mbuf *mbuf)
{
	send_to_vport(action->port, mbuf);
}

/*
 * Excutes the drop action on 'mbuf' and increases the
 * vswitch's RX drop statistics
 */
static inline void
action_drop(struct rte_mbuf *mbuf)
{
	rte_pktmbuf_free(mbuf);
	stats_vswitch_rx_drop_increment(INC_BY_1);
}

/*
 * Removes 802.1Q header from the packet associated with 'mbuf'
 */
static inline void
action_pop_vlan(struct rte_mbuf *mbuf)
{
	struct ofpbuf *ovs_pkt = NULL;

	ovs_pkt = overlay_ofpbuf(mbuf);
	eth_pop_vlan(ovs_pkt);
	update_mbuf(ovs_pkt, mbuf);
}

/*
 * Adds an 802.1Q header to the packet associated with 'mbuf'
 */
static inline void
action_push_vlan(const struct action_push_vlan *action,
                             struct rte_mbuf *mbuf)
{
	struct ofpbuf *ovs_pkt = NULL;

	ovs_pkt = overlay_ofpbuf(mbuf);
	eth_push_vlan(ovs_pkt, action->tci);
	update_mbuf(ovs_pkt, mbuf);
}

/*
 * Modify the ethernet header as specified in the key
 */
static void
action_set_ethernet(const struct ovs_key_ethernet *ethernet_key,
                    struct rte_mbuf *mbuf)
{
	struct ether_hdr *ether_hdr;
	/* Note, there is no function in openvswitch.h to modify
	 * the ethernet addresses
	 */
	ether_hdr = mbuf->pkt.data;
	memcpy(&ether_hdr->d_addr, ethernet_key->eth_dst, sizeof(struct ether_addr));
	memcpy(&ether_hdr->s_addr, ethernet_key->eth_src, sizeof(struct ether_addr));
}

/*
 * Modify the IPV4 header as specified in the key
 */
static void
action_set_ipv4(const struct ovs_key_ipv4 *ipv4_key,
                    struct rte_mbuf *mbuf)
{
	struct ofpbuf *ovs_pkt = NULL;

	ovs_pkt = overlay_ofpbuf(mbuf);
	packet_set_ipv4(ovs_pkt, ipv4_key->ipv4_src, ipv4_key->ipv4_dst,
	                ipv4_key->ipv4_tos, ipv4_key->ipv4_ttl);
	update_mbuf(ovs_pkt, mbuf);
}

/*
 * Modify the TCP header as specified in the key
 */
static void
action_set_tcp(const struct ovs_key_tcp *tcp_key,
                    struct rte_mbuf *mbuf)
{
	struct ofpbuf *ovs_pkt = NULL;

	ovs_pkt = overlay_ofpbuf(mbuf);
	packet_set_tcp_port(ovs_pkt, tcp_key->tcp_src, tcp_key->tcp_dst);
	update_mbuf(ovs_pkt, mbuf);
}

/*
 * Modify the UDP header as specified in the key
 */
static void
action_set_udp(const struct ovs_key_udp *udp_key,
                    struct rte_mbuf *mbuf)
{
	struct ofpbuf *ovs_pkt = NULL;

	ovs_pkt = overlay_ofpbuf(mbuf);
	packet_set_udp_port(ovs_pkt, udp_key->udp_src, udp_key->udp_dst);
	update_mbuf(ovs_pkt, mbuf);

}

/**
 *  Added by Y.Born, Set queue_id in mbuf
 */
static void
action_set_queue(const struct action_set_queue *queue,
                    struct rte_mbuf *mbuf)
{
    mbuf->pkt.hash.sched = queue->queue_id;    
}
