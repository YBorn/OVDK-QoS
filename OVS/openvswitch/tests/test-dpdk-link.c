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

#include "dpdk-link.h"
#include "dpif-dpdk.h"

#include <assert.h>

#define VSWITCHD_RINGSIZE   2048
#define VSWITCHD_PACKET_RING_NAME  "MProc_Vswitchd_Packet_Ring"
#define VSWITCHD_REPLY_RING_NAME   "MProc_Vswitchd_Reply_Ring"
#define VSWITCHD_MESSAGE_RING_NAME "MProc_Vswitchd_Message_Ring"
#define NO_FLAGS            0
#define SOCKET0             0

static struct rte_mempool *pktmbuf_pool = NULL;
/* ring to send packets to vswitchd */
static struct rte_ring *vswitchd_packet_ring = NULL;
/* ring to receive messages from vswitchd */
static struct rte_ring *vswitchd_message_ring = NULL;
/* ring to send reply messages to vswitchd */
static struct rte_ring *vswitchd_reply_ring = NULL;

void init_test_rings(void);

int
main(int argc, char *argv[])
{
	struct dpif_dpdk_message request;
	const struct ofpbuf test_ofpbuf[20];
	const struct ofpbuf *const *test_ofpbuf_array =
		(const struct ofpbuf *const *) &test_ofpbuf;

	int result = 0;

	rte_eal_init(argc, argv);
	init_test_rings();

	/* Test dpdk_link_send_bulk(), num_pkts > PKT_BURST_SIZE */
	result = dpdk_link_send_bulk(&request, test_ofpbuf_array, 500);
	assert(result == EINVAL);

	/* Test dpdk_link_send_bulk(), can't alloc enough mbufs */
	result = dpdk_link_send_bulk(&request, test_ofpbuf_array, 10);
	assert(result == ENOBUFS);

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
	                     3, /* num mbufs */
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


