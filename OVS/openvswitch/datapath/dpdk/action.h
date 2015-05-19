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

#ifndef __ACTION_H_
#define __ACTION_H_

#include <stdint.h>

#include <rte_mbuf.h>
#include <linux/openvswitch.h>

/* TODO: same value as VPORTS increase if required */
#define MAX_ACTIONS	(48)

/* Set of all supported actions */
enum action_type {
	ACTION_NULL,     /* Empty action - drop packet */
	ACTION_OUTPUT,   /* Output packet to port */
	ACTION_POP_VLAN, /* Remove 802.1Q header */
	ACTION_PUSH_VLAN,/* Add 802.1Q VLAN header to packet */
	ACTION_SET_ETHERNET, /* Modify Ethernet header */
	ACTION_SET_IPV4, /* Modify IPV4 header */
	ACTION_SET_TCP, /* Modify TCP header */
	ACTION_SET_UDP, /* Modify UDP header */
    ACTION_SET_QUEUE,
	ACTION_MAX       /* Maximum number of supported actions */
};

struct action_set_queue {
	uint32_t queue_id;    /* Output queue id */
};

struct action_output {
	uint32_t port;    /* Output port */
};

struct action_push_vlan {
	uint16_t tpid; /* Tag Protocol ID (always 0x8100) */
	uint16_t tci;  /* Tag Control Information */
};

struct action {
	enum action_type type;
	union { /* union of difference action types */
		struct action_output output;
		struct action_push_vlan vlan;
		struct ovs_key_ethernet ethernet;
		struct ovs_key_ipv4 ipv4;
		struct ovs_key_tcp tcp;
		struct ovs_key_udp udp;
		/* add other action structs here */
		struct action_set_queue queue;
	} data;
};

int action_execute(const struct action *action, struct rte_mbuf *mbuf);

#endif /* __ACTION_H_ */

