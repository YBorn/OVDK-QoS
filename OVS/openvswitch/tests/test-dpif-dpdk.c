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
#include <linux/openvswitch.h>
#include <getopt.h>

#include "dpif.h"
#include "dpif-provider.h"
#include "dpif-dpdk.h"
#include "dpdk-link.h"
#include "netdev-provider.h"
#include "netlink.h"
#include "common.h"

#include "dpdk-ring-stub.h"

#include <string.h>
#include <assert.h>

void
test_dpif_dpdk_get_stats(struct dpif *dpif_p);
void
test_dpif_dpdk_port_add(struct dpif *dpif_p);
void test_dpif_dpdk_port_del(struct dpif *dpif_p);
void test_dpif_dpdk_port_query_by_number(struct dpif *dpif_p);
void test_dpif_dpdk_port_query_by_name(struct dpif *dpif_p);
void test_dpif_dpdk_get_max_ports(struct dpif *dpif_p);
void test_dpif_dpdk_port_dump_start(struct dpif *dpif_p);
void test_dpif_dpdk_port_dump_next(struct dpif *dpif_p);
void
test_dpif_dpdk_port_dump_done(struct dpif *dpif_p);
void
test_dpif_dpdk_port_poll(struct dpif *dpif_p);
void
test_dpif_dpdk_port_poll_wait(struct dpif *dpif_p);
void
test_dpif_dpdk_flow_put(struct dpif *dpif_p);
void
test_dpif_dpdk_flow_get(struct dpif *dpif_p);
void
test_dpif_dpdk_flow_del(struct dpif *dpif_p);
void
test_dpif_dpdk_flow_flush(struct dpif *dpif_p);
void
test_dpif_dpdk_flow_dump_start(struct dpif *dpif_p);
void
test_dpif_dpdk_flow_dump_next(struct dpif *dpif_p);
void
test_dpif_dpdk_flow_dump_done(struct dpif *dpif_p);

int
main(int argc, char *argv[])
{
	struct dpif dpif;
	struct dpif *dpif_p = &dpif;
	struct dpif **dpifp = &dpif_p;
	int c = 0;

	rte_eal_init(argc, argv);
	init_test_rings();

	dpif_create_and_open("br0", "dpdk", dpifp);

	while(1)
	{
		static struct option long_options[] =
		{
			{"dpif_dpdk_get_stats", no_argument, 0, 'a'},
			{"dpif_dpdk_port_add", no_argument, 0, 'b'},
			{"dpif_dpdk_port_del", no_argument, 0, 'c'},
			{"dpif_dpdk_port_query_by_number", no_argument, 0, 'd'},
			{"dpif_dpdk_port_query_by_name", no_argument, 0, 'e'},
			{"dpif_dpdk_get_max_ports", no_argument, 0, 'f'},
			{"dpif_dpdk_port_dump_start", no_argument, 0, 'g'},
			{"dpif_dpdk_port_dump_next", no_argument, 0, 'h'},
			{"dpif_dpdk_port_dump_done", no_argument, 0, 'i'},
			{"dpif_dpdk_port_poll", no_argument, 0, 'j'},
			{"dpif_dpdk_port_poll_wait", no_argument, 0, 'k'},
			{"dpif_dpdk_flow_put", no_argument, 0, 'l'},
			{"dpif_dpdk_flow_del", no_argument, 0, 'm'},
			{"dpif_dpdk_flow_flush", no_argument, 0, 'n'},
			{"dpif_dpdk_flow_dump_start", no_argument, 0, 'o'},
			{"dpif_dpdk_flow_dump_next", no_argument, 0, 'p'},
			{0, 0, 0, 0}
		};
		int option_index = 0;
		c = getopt_long(argc-4, argv+4, "abcdefghijklmnop", long_options, &option_index);

		/* Can run any function from the dpif_p */
		dpif_p->dpif_class->destroy(dpif_p);

		if (c == -1)
			break;

		switch (c)
		{
			case 'a':
			test_dpif_dpdk_get_stats(dpif_p);
			break;

			case 'b':
			test_dpif_dpdk_port_add(dpif_p);
			break;

			case 'c':
			test_dpif_dpdk_port_del(dpif_p);
			break;

			case 'd':
			test_dpif_dpdk_port_query_by_number(dpif_p);
			break;

			case 'e':
			test_dpif_dpdk_port_query_by_name(dpif_p);
			break;

			case 'f':
			test_dpif_dpdk_get_max_ports(dpif_p);
			break;

			case 'g':
			test_dpif_dpdk_port_dump_start(dpif_p);
			break;

			case 'h':
			test_dpif_dpdk_port_dump_next(dpif_p);
			break;

			case 'i':
			test_dpif_dpdk_port_dump_done(dpif_p);
			break;

			case 'j':
			test_dpif_dpdk_port_poll(dpif_p);
			break;

			case 'k':
			test_dpif_dpdk_port_poll_wait(dpif_p);
			break;

			case 'l':
			test_dpif_dpdk_flow_put(dpif_p);
			break;

			case 'm':
			test_dpif_dpdk_flow_del(dpif_p);
			break;

			case 'n':
			test_dpif_dpdk_flow_flush(dpif_p);
			break;

			case 'o':
			test_dpif_dpdk_flow_dump_start(dpif_p);
			break;

			case 'p':
			test_dpif_dpdk_flow_dump_next(dpif_p);
			break;

			default:
			abort();
		}
	}

	dpif_close(dpif_p);
	return 0;
}

void
test_dpif_dpdk_get_stats(struct dpif *dpif_p)
{
	int result = -1;
	struct dpif_dp_stats stats;
	result = dpif_p->dpif_class->get_stats(dpif_p, &stats);
	assert(result == 0);
	assert(stats.n_hit == 0);
	assert(stats.n_missed == 0);
	assert(stats.n_lost == 0);
	assert(stats.n_flows == 0);
	printf(" %s\n", __FUNCTION__);
}

void
test_dpif_dpdk_port_add(struct dpif *dpif_p)
{
	int result = -1;
	struct netdev netdev;
	odp_port_t port_no = -1;

	result = dpif_p->dpif_class->port_add(dpif_p, NULL, &port_no);
	assert(result == EINVAL);
	result = dpif_p->dpif_class->port_add(dpif_p, &netdev, NULL);
	assert(result == EINVAL);

	netdev.name = "nonexistant_port";
	result = dpif_p->dpif_class->port_add(dpif_p, &netdev, &port_no);
	assert(result == ENODEV);

	netdev.name = "ovs_dpdk_17";
	result = dpif_p->dpif_class->port_add(dpif_p, &netdev, &port_no);
	assert(result == 0);
	assert(port_no == 17);

	netdev.name = "br0";
	result = dpif_p->dpif_class->port_add(dpif_p, &netdev, &port_no);
	assert(result == 0);
	assert(port_no == 0);
	printf(" %s\n", __FUNCTION__);
}

void test_dpif_dpdk_port_del(struct dpif *dpif_p)
{

	int result = -1;
	odp_port_t port_no = -1;
	result = dpif_p->dpif_class->port_del(dpif_p, port_no);
	assert(result == 0);
	printf(" %s\n", __FUNCTION__);
}

void test_dpif_dpdk_port_query_by_number(struct dpif *dpif_p)
{
	int result = -1;
	odp_port_t port_no = -1;
	struct dpif_port dpif_port;
	result = dpif_p->dpif_class->port_query_by_number(dpif_p, port_no, &dpif_port);
	assert(result == 0);
	printf(" %s\n", __FUNCTION__);
}

void test_dpif_dpdk_port_query_by_name(struct dpif *dpif_p)
{
	int result = -1;
	struct dpif_port dpif_port;

	result = dpif_p->dpif_class->port_query_by_name(dpif_p, NULL,
	                                                &dpif_port);
	assert(result == EINVAL);

	result = dpif_p->dpif_class->port_query_by_name(dpif_p, "ovs_dpdk_18",
	                                                NULL);
	assert(result == 0);

	result = dpif_p->dpif_class->port_query_by_name(dpif_p, "nonexistant_port",
	                                                &dpif_port);
	assert(result == ENODEV);

	result = dpif_p->dpif_class->port_query_by_name(dpif_p, "ovs_dpdk_18",
	                                                &dpif_port);
	assert(result == 0);
	assert(strncmp(dpif_port.type, "dpdk", 4) == 0);
	assert(dpif_port.port_no == 18);
	assert(strncmp(dpif_port.name, "ovs_dpdk_18", 11) == 0);

	result = dpif_p->dpif_class->port_query_by_name(dpif_p, "br0",
	                                                &dpif_port);
	assert(result == 0);
	assert(strncmp(dpif_port.type, "internal", 8) == 0);
	assert(dpif_port.port_no == 0);
	assert(strncmp(dpif_port.name, "br0", 3) == 0);
	printf(" %s\n", __FUNCTION__);
}

void test_dpif_dpdk_get_max_ports(struct dpif *dpif_p)
{
	int result = -1;
	result = dpif_p->dpif_class->get_max_ports(dpif_p);
	assert(result == MAX_VPORTS);
	printf(" %s\n", __FUNCTION__);
}

void test_dpif_dpdk_port_dump_start(struct dpif *dpif_p)
{
	int result = -1;
	void **statep = NULL;
	/* note: statep is null here, but port dump start doesn't
	 * use it so it doesn't matter
	 */
	result = dpif_p->dpif_class->port_dump_start(dpif_p, statep);
	assert(result == 0);
	printf(" %s\n", __FUNCTION__);
}

void test_dpif_dpdk_port_dump_next(struct dpif *dpif_p)
{
	int result = -1;
	struct dpif_port *dpif_port_p = NULL;
	void **statep = NULL;
	/* note: state is null here, but port dump next doesn't
	 * use it so it doesn't matter
	 */
	result = dpif_p->dpif_class->port_dump_next(dpif_p, statep, dpif_port_p);
	assert(result == EOF);
	printf(" %s\n", __FUNCTION__);
}

void
test_dpif_dpdk_port_dump_done(struct dpif *dpif_p)
{
	int result = -1;
	void *state_done = NULL;
	/* note: statep is null here, but port dump done doesn't
	 * use it so it doesn't matter
	 */
	result = dpif_p->dpif_class->port_dump_done(dpif_p, state_done);
	assert(result == 0);
	printf(" %s\n", __FUNCTION__);
}

void
test_dpif_dpdk_port_poll(struct dpif *dpif_p)
{
	char **devname = NULL;
	int result = -1;
	/* note: devname is null here, but port_poll doesn't
	 * use it so it doesn't matter
	 */
	result = dpif_p->dpif_class->port_poll(dpif_p, devname);
	assert(result == EAGAIN);
	printf(" %s\n", __FUNCTION__);
}

void
test_dpif_dpdk_port_poll_wait(struct dpif *dpif_p)
{
	/* note: devname is null here, but port poll wait doesn't
	 * use it so it doesn't matter
	 */
	dpif_p->dpif_class->port_poll_wait(dpif_p);
	printf(" %s\n", __FUNCTION__);
}

void
test_dpif_dpdk_flow_put(struct dpif *dpif_p)
{
	struct dpif_dpdk_message reply;
	struct dpif_dpdk_message *request;
	struct dpif_flow_put put;
	struct rte_mbuf *mbuf = NULL;
	void *pktmbuf_data = NULL;
	int result = -1;
	int num_pkts = 0;

	/* Create a fake reply to put on the reply ring. We don't use
	 * this, but transact will hang until a reply is received so
	 * there has to be something to dequeue.
	 */
	create_dpdk_flow_put_reply(&reply);
	result = enqueue_reply_on_reply_ring(reply);
	assert(result == 0);

	create_dpif_flow_put_message(&put);
	dpif_p->dpif_class->flow_put(dpif_p, &put);
	num_pkts = rte_ring_count(vswitchd_message_ring);
	assert(num_pkts == 1);
	result = rte_ring_sc_dequeue(vswitchd_message_ring, (void **)&mbuf);
	assert(result == 0);

	/* Just test that the message created and enqueued on the request ring
	 * was correct
	 */
	pktmbuf_data = rte_pktmbuf_mtod(mbuf, void *);
	request = (struct dpif_dpdk_message *)pktmbuf_data;
	assert(request->flow_msg.actions[0].type == ACTION_NULL);
	assert(request->flow_msg.key.in_port == 5);
	rte_pktmbuf_free(mbuf);
	printf(" %s\n", __FUNCTION__);
}

void
test_dpif_dpdk_flow_del(struct dpif *dpif_p)
{
	struct dpif_dpdk_message reply;
	struct dpif_dpdk_message *request;
	struct dpif_flow_del del;
	struct rte_mbuf *mbuf = NULL;
	void *pktmbuf_data = NULL;
	int result = -1;

	create_dpdk_flow_del_reply(&reply, NO_FLOW);
	result = enqueue_reply_on_reply_ring(reply);
	assert(result == 0);
	assert(rte_ring_count(vswitchd_reply_ring) == 1);

	create_dpif_flow_del_message(&del);
	dpif_p->dpif_class->flow_del(dpif_p, &del);
	assert(rte_ring_count(vswitchd_message_ring) == 1);
	result = rte_ring_sc_dequeue(vswitchd_message_ring, (void **)&mbuf);
	assert(result == 0);

	/* Just test that the message created and enqueued on the request ring
	 * was correct
	 */
    	pktmbuf_data = rte_pktmbuf_mtod(mbuf, void *);
    	request = (struct dpif_dpdk_message *)pktmbuf_data;
	assert(request->flow_msg.actions[0].type == ACTION_NULL);
	assert(request->flow_msg.key.in_port == 5);
	printf(" %s\n", __FUNCTION__);
}

void
test_dpif_dpdk_flow_flush(struct dpif *dpif_p)
{
	struct dpif_dpdk_message reply;
	struct dpif_dpdk_message *request;
	struct rte_mbuf *mbuf = NULL;
	void *pktmbuf_data = NULL;
	int result = -1;

	/* It doesn't matter what kind of reply we enqueue here*/
	create_dpdk_flow_del_reply(&reply, NO_FLOW);
	result = enqueue_reply_on_reply_ring(reply);
	assert(result == 0);
	assert(rte_ring_count(vswitchd_reply_ring) == 1);

	dpif_p->dpif_class->flow_flush(dpif_p);
	assert(rte_ring_count(vswitchd_message_ring) == 1);
	result = rte_ring_sc_dequeue(vswitchd_message_ring, (void **)&mbuf);
	assert(result == 0);

	/* Just test that the message created and enqueued on the request ring
	 * was correct
	 */
    	pktmbuf_data = rte_pktmbuf_mtod(mbuf, void *);
    	request = (struct dpif_dpdk_message *)pktmbuf_data;
	assert(request->flow_msg.cmd == OVS_FLOW_CMD_DEL);
	printf(" %s\n", __FUNCTION__);
}

void
test_dpif_dpdk_flow_dump_start(struct dpif *dpif_p)
{
	struct dpif_dpdk_flow_state *state = NULL;

	dpif_p->dpif_class->flow_dump_start(dpif_p, (void **)&state);
	assert(state->flow.cmd == OVS_FLOW_CMD_GET);
	assert(state->flow.flags == NLM_F_DUMP);
	printf(" %s\n", __FUNCTION__);

}

void
test_dpif_dpdk_flow_dump_next(struct dpif *dpif_p)
{
	int result = 0;

	/* Test null state */
	result = dpif_p->dpif_class->flow_dump_next(dpif_p, NULL, NULL, NULL,
	                                   NULL, NULL, NULL, NULL, NULL);
	assert(result == EINVAL);
	printf(" %s\n", __FUNCTION__);
}

void
test_dpif_dpdk_flow_dump_done(struct dpif *dpif_p)
{
	int result = 0;

	/* Test null state */
	result = dpif_p->dpif_class->flow_dump_done(dpif_p, NULL);
	assert(result == EINVAL);
	printf(" %s\n", __FUNCTION__);
}
