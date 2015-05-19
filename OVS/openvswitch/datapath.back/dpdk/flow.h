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

#ifndef __FLOW_H_
#define __FLOW_H_

#include <stdint.h>
#include <stdbool.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

#include "action.h"

/* Maximum number of flow table entries */
#define MAX_FLOWS              (1 << 16)

/* Measured CPU frequency. Needed to translate tsk to ms. */
uint64_t cpu_freq;
/* Global timestamp counter that can be updated
 * only by vswitchd core. It's used as flow's last
 * used time, when next packet arrives.
 */
volatile uint64_t curr_tsc;

struct flow_key {
	uint32_t in_port;
	struct ether_addr ether_dst;
	struct ether_addr ether_src;
	uint16_t ether_type;
	uint16_t vlan_id;
	uint8_t vlan_prio;
	uint32_t ip_src;
	uint32_t ip_dst;
	uint8_t ip_proto;
	uint8_t ip_tos;
	uint8_t ip_ttl;
	uint8_t ip_frag;
	uint16_t tran_src_port;
	uint16_t tran_dst_port;
} __attribute__((__packed__));

struct flow_stats {
	uint64_t packet_count;	/* Number of packets matched. */
	uint64_t byte_count;	/* Number of bytes matched. */
	uint64_t used;			/* Last used time (in hpet cycles). */
	uint8_t tcp_flags;		/* Union of seen TCP flags. */
};

void flow_table_init(void);
int flow_table_lookup(const struct flow_key *key);
void flow_key_extract(const struct rte_mbuf *pkt, uint8_t in_port,
                      struct flow_key *key);
int flow_table_del_flow(const struct flow_key *key);
void flow_table_del_all(void);
int flow_table_add_flow(const struct flow_key *key, const struct action *action);
int flow_table_mod_flow(const struct flow_key *key, const struct action *action,
                        bool clear_stats);
int flow_table_get_flow(struct flow_key *key,
             struct action *action, struct flow_stats *stats);
int flow_table_get_first_flow(struct flow_key *first_key,
             struct action *action, struct flow_stats *stats);
int flow_table_get_next_flow(const struct flow_key *key,
             struct flow_key *next_key, struct action *action,
             struct flow_stats *stats);
void switch_packet(struct rte_mbuf *pkt, struct flow_key *key);

#endif /* __FLOW_H_ */


