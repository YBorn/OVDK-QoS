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

#include <rte_string_fns.h>
#include <rte_ethdev.h>

#include "init.h"
#include "kni.h"
#include "veth.h"

#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE    14

/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       4

#define MAX_PACKET_SZ           2048

static int kni_change_mtu(uint8_t port_id, unsigned new_mtu);
static int kni_config_network_interface(uint8_t port_id, uint8_t if_up);

/* Dummy callback for request of configuring network interface up/down */
static int
kni_config_network_interface(uint8_t port_id __rte_unused, uint8_t if_up __rte_unused)
{
	return 0;
}

/* Dummy callback for changing MTU of port */
static int
kni_change_mtu(uint8_t port_id __rte_unused, unsigned new_mtu __rte_unused)
{
	return 0;
}

static int
veth_kni_alloc(struct rte_kni **kni, uint8_t port_id)
{
	struct rte_kni *veth;
	struct rte_kni_conf conf;
	struct rte_kni_ops ops;

	RTE_LOG(INFO, APP, "Initialising KNI vEth %d\n", port_id);

	/* Clear conf at first */
	memset(&conf, 0, sizeof(conf));
	rte_snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u", port_id);
	conf.group_id = (uint16_t)port_id;
	conf.mbuf_size = MAX_PACKET_SZ;

	memset(&ops, 0, sizeof(ops));
	ops.port_id = port_id;
	ops.change_mtu = kni_change_mtu;
	ops.config_network_if = kni_config_network_interface;

	veth = rte_kni_alloc(pktmbuf_pool, &conf, &ops);

	if (!veth)
		rte_exit(EXIT_FAILURE, "Failed to create kni for port: %d\n", port_id);
	if (rte_kni_get(conf.name) != veth)
		rte_exit(EXIT_FAILURE, "Failed to get kni dev for port: %d\n", port_id);

	RTE_LOG(INFO, APP, "Initialised KNI vEth %d\n", port_id);

	*kni = veth;

	return 0;
}

void
init_veth(void)
{
	uint8_t port_id = 0;
	struct rte_kni *kni = NULL;

	/* Create the rte_kni fifos for each KNI port */
	for (port_id = 0; port_id < num_veth; port_id++) {
		if (veth_kni_alloc(&kni, port_id) >= 0)
			rte_veth_list[port_id] = kni;
		else
			RTE_LOG(ERR, APP, "Failed to initialise vEth on invalid port %d\n",
			                port_id);
	}
}
