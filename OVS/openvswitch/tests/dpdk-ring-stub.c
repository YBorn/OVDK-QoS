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

#include <config.h>
#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_mempool.h>
#include <rte_string_fns.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_ether.h>
#include <rte_byteorder.h>

#include "dpif-provider.h"
#include "dpif-dpdk.h"
#include "dpdk-link.h"
#include "dpif.h"
#include "dpdk-ring-stub.h"
#include "flow.h"
#include "netlink.h"
#include "odp-util.h"

struct flow flow;
struct nlattr actions_unit;

static struct rte_mempool *pktmbuf_pool = NULL;
/* ring to send packets to vswitchd */
static struct rte_ring *vswitchd_packet_ring = NULL;
/* ring to receive messages from vswitchd */
struct rte_ring *vswitchd_message_ring = NULL;
/* ring to send reply messages to vswitchd */
struct rte_ring *vswitchd_reply_ring = NULL;

/* Create dpdk flow message
 */
void
create_dpdk_flow_get_reply(struct dpif_dpdk_message *reply)
{
	struct dpif_dpdk_action action_multiple[MAX_ACTIONS];
	memset(reply, 0, sizeof(*reply));

	action_output_build(&action_multiple[0], 3);
	action_null_build(&action_multiple[1]);

	reply->type = FLOW_CMD_FAMILY;
	memcpy(reply->flow_msg.actions, action_multiple, sizeof(action_multiple));

}

void
create_dpdk_flow_put_reply(struct dpif_dpdk_message *reply)
{
	memset(reply, 0, sizeof(*reply));
	reply->type = FLOW_CMD_FAMILY;

}

void
create_dpdk_flow_del_reply(struct dpif_dpdk_message *reply, uint8_t flow_exists)
{
	memset(reply, 0, sizeof(*reply));
	if (flow_exists == NO_FLOW)
		reply->type = ENOENT;
}

static void create_dpif_flow(struct ofpbuf *buf)
{

	/* Flow key */
	/* OVS 2.0 doesn't take in_port from the flow
	 * struct, instead it's passed as a third parameter.
	 * This is to allow handling both OF ports and datapath
	 * ports.
	 */
    	memset(&flow, 0, sizeof(flow));
	flow.in_port.odp_port = 5; //unused
	flow.nw_proto = 5;
	memcpy(flow.dl_dst, "KNIO", ETHER_ADDR_LEN);
	memcpy(flow.dl_src, "ABC1", ETHER_ADDR_LEN);
	flow.dl_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	flow.nw_proto = IPPROTO_TCP;

	odp_flow_key_from_flow(buf, &flow, 5 /*in port*/);
}

/* Create a dpif flow put message
 */
void
create_dpif_flow_put_message(struct dpif_flow_put *put)
{
	struct ofpbuf *buf;

	buf = ofpbuf_new(64);

	/* Output action */
	put->actions_len = 0;
 	put->actions = NULL;

	create_dpif_flow(buf);
	put->key = buf->data;
	put->key_len = buf->size;

	/* Flags */
	put->flags = DPIF_FP_CREATE;
}

/* Create a dpif flow put message
 */
void
create_dpif_flow_del_message(struct dpif_flow_del *del)
{
	struct ofpbuf *buf;

	buf = ofpbuf_new(64);
	create_dpif_flow(buf);
	del->key = buf->data;
	del->key_len = buf->size;
}

/* Put a dpif_dpdk_message on the reply ring, ready
 * to be dequeued by flow_transact
 */
int
enqueue_reply_on_reply_ring(struct dpif_dpdk_message reply)
{
	struct rte_mbuf *mbuf = NULL;
	void *pktmbuf_data = NULL;
	int rslt = 0;

	mbuf = rte_pktmbuf_alloc(pktmbuf_pool);
	pktmbuf_data = rte_pktmbuf_mtod(mbuf, void *);
	rte_memcpy(pktmbuf_data, &reply, sizeof(reply));
	rte_pktmbuf_data_len(mbuf) = sizeof(reply);

	rslt = rte_ring_mp_enqueue(vswitchd_reply_ring, (void *)mbuf);
	if (rslt < 0) {
		if (rslt == -ENOBUFS) {
			rte_pktmbuf_free(mbuf);
			return -1;
		}
		return 0;
	}
	return 0;
}

/* dpdk_link_send() looks up each of these rings and will exit if
 * it doesn't find them so we must declare them.
 * 
 * We have to call dpdk_link send to initialise the "mp" pktmbuf pool
 * pointer used throughout dpdk_link.c
 */
void
init_test_rings(void) 
{

	pktmbuf_pool = rte_mempool_create("MProc_pktmbuf_pool",
	                     20, /* num mbufs */
	                     2048 + sizeof(struct rte_mbuf) + 128, /* pktmbuf size */
	                     0, /*cache size */
	                     sizeof(struct rte_pktmbuf_pool_private),
	                     rte_pktmbuf_pool_init,
	                     NULL, rte_pktmbuf_init, NULL, 0, 0);

	vswitchd_packet_ring = rte_ring_create(VSWITCHD_PACKET_RING_NAME,
			         VSWITCHD_RINGSIZE, SOCKET0, NO_FLAGS);
	if (vswitchd_packet_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create packet ring for vswitchd");

	vswitchd_reply_ring = rte_ring_create(VSWITCHD_REPLY_RING_NAME,
			         VSWITCHD_RINGSIZE, SOCKET0, NO_FLAGS);
	if (vswitchd_reply_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create reply ring for vswitchd");

	vswitchd_message_ring = rte_ring_create(VSWITCHD_MESSAGE_RING_NAME,
			         VSWITCHD_RINGSIZE, SOCKET0, NO_FLAGS);
	if (vswitchd_message_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create message ring for vswitchd");

	dpdk_link_init();
}


