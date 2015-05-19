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

#include <rte_fbk_hash.h>
#include <rte_memzone.h>
#include <rte_hash.h>
#include <rte_cpuflags.h>
#include <rte_tcp.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_byteorder.h>
#include <rte_rwlock.h>

/* Hash function used if none is specified */
#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
#include <rte_hash_crc.h>
#include <rte_jhash.h>
#else
#include <rte_jhash.h>
#endif

#include <linux/openvswitch.h>

#include "flow.h"
#include "action.h"
#include "datapath.h"

#define CHECK_POS(pos) do {\
                             if ((pos) >= MAX_FLOWS || (pos) < 0) return -1; \
                          } while (0)

#define CHECK_NULL(ptr)   do { \
                             if ((ptr) == NULL) return -1; \
                         } while (0)

#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1
#define NO_FLAGS             0
#define HASH_NAME           "flow_table"
#define HASH_BUCKETS        4
#define SOCKET0             0
#define VLAN_ID_MASK        0xFFF
#define VLAN_PRIO_SHIFT     13
#define TCP_FLAG_MASK       0x3F
#define MZ_FLOW_TABLE       "MProc_flow_table"

/* IP and Ethernet printing formats and arguments */
#define ETH_FMT "%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8
#define ETH_ARGS(ea) (ea)[0], (ea)[1], (ea)[2], (ea)[3], (ea)[4], (ea)[5]
#define IP_FMT "%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8
#define IP_ARGS(ip) ((ip >> 24) & 0xFF), ((ip >> 16) & 0xFF), ((ip >> 8) & 0xFF), (ip & 0xFF)

#define TCP_HDR_FROM_PKT(pkt) (struct tcp_hdr*)\
	(rte_pktmbuf_mtod(pkt, unsigned char *) + \
			sizeof(struct ether_hdr) + \
			sizeof(struct ipv4_hdr))

struct flow_table_entry {
	rte_rwlock_t lock;   /* Lock to allow multiple readers and one writer */
	struct flow_key key;     /* Flow key. */
	struct flow_stats stats; /* Flow statistics. */
	bool used;               /* Flow is used */
	struct action actions[MAX_ACTIONS];    /* Type of action */
};

/* Parameters used for hash table */
static struct rte_hash_parameters hash_table_params = {
	.name               = HASH_NAME,
	.entries            = MAX_FLOWS,
	.bucket_entries     = HASH_BUCKETS,
	.key_len            = sizeof(struct flow_key),
	.hash_func          = rte_jhash,
	.hash_func_init_val = 0,
	.socket_id          = SOCKET0,
};

static struct flow_table_entry *flow_table = NULL;
static struct rte_hash *handle = NULL;

static uint64_t ovs_flow_used_time(uint64_t flow_tsc);
static int copy_entry_from_table(int pos, struct flow_key *key,
            struct action *actions, struct flow_stats *stats);
static int flow_table_update_stats(int pos, const struct rte_mbuf *pkt);

/* Initialize the flow table  */
void
flow_table_init(void)
{
	unsigned flow_table_size = sizeof(struct flow_table_entry) * MAX_FLOWS;
	const struct rte_memzone *mz = NULL;
	int pos = 0;
	/* set up array for flow table data */
	mz = rte_memzone_reserve(MZ_FLOW_TABLE, flow_table_size,
	                         rte_socket_id(), NO_FLAGS);
	if (mz == NULL)
		rte_exit(EXIT_FAILURE, "Cannot reserve memory zone for flow"
		                       "table \n");
	memset(mz->addr, 0, flow_table_size);
	flow_table = mz->addr;
	for (pos = 0; pos < MAX_FLOWS; pos++) {
		rte_rwlock_init(&flow_table[pos].lock);
	}

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
	hash_table_params.hash_func = rte_hash_crc;
	/* Check if hardware-accelerated hashing supported */
	if (!rte_cpu_get_flag_enabled(RTE_CPUFLAG_SSE4_2)) {
		RTE_LOG(WARNING, HASH, "CRC32 instruction requires SSE4.2, "
		              "which is not supported on this system. "
		              "Falling back to software hash.\n");
		hash_table_params.hash_func = rte_jhash;
	}
	RTE_LOG(WARNING, HASH, "Enabling CRC32 instruction for hashing\n");
#endif /* This check does not compile if SSE4_2 is not enabled for build */

	handle = rte_hash_create(&hash_table_params);
	if (handle == NULL) {
		rte_exit(EXIT_FAILURE, "Failed to create hash table\n");
	}
}

/*
 * Clear flow table statistics for 'key'
 */
static int
flow_table_clear_stats(int pos)
{
	flow_table[pos].stats.used = 0;
	flow_table[pos].stats.tcp_flags = 0;
	flow_table[pos].stats.packet_count = 0;
	flow_table[pos].stats.byte_count = 0;

	return 0;
}

/*
 * Add 'key' and corresponding 'action' to flow table
 */
int
flow_table_add_flow(const struct flow_key *key, const struct action *actions)
{
	int pos = 0;
	CHECK_NULL(key);
	CHECK_NULL(actions);

	pos = flow_table_lookup(key);
	/* already exists */
	if (pos >= 0) {
		return -1;
	}

	pos = rte_hash_add_key(handle, key);
	CHECK_POS(pos);

	/* As we are writing to the table, acquire write lock */
	rte_rwlock_write_lock(&flow_table[pos].lock);

	flow_table[pos].key = *key;
	flow_table[pos].used = true;
    
    memcpy(&(flow_table[pos].actions), actions,
                sizeof(flow_table[pos].actions));

	/* release lock as table has been written */
	rte_rwlock_write_unlock(&flow_table[pos].lock);

	/* dont care about locking stats */
	flow_table_clear_stats(pos);
	return pos;
}

/*
 * Modify flow table entry referenced by 'key'. 'clear_stats' clears statistics
 * for that entry
 */
int
flow_table_mod_flow(const struct flow_key *key, const struct action *actions,
                    bool clear_stats)
{
	int ret = -1;
	int pos = 0;
	CHECK_NULL(key);
	CHECK_NULL(actions);

	pos = flow_table_lookup(key);
	CHECK_POS(pos);

	/* As we are writing to the table, acquire write lock */
	rte_rwlock_write_lock(&flow_table[pos].lock);

	if (clear_stats) {
		flow_table_clear_stats(pos);
	}

	if (actions) {
		memcpy(&(flow_table[pos].actions), actions,
				sizeof(flow_table[pos].actions));
	}

	ret = pos;
	flow_table[pos].used = true;

	/* release lock as table has been written */
	rte_rwlock_write_unlock(&flow_table[pos].lock);

	return ret;
}

inline static int
copy_entry_from_table(int pos, struct flow_key *key, struct action *actions,
                        struct flow_stats *stats)
{
	if (likely(flow_table[pos].used)) {
		if (key) {
			*key = flow_table[pos].key;
		}
		if (actions) {
			memcpy(actions, &flow_table[pos].actions,
			       sizeof(flow_table[pos].actions));
		}
		if (stats) {
			*stats = flow_table[pos].stats;
			/* vswitchd needs linux monotonic time (not TSC cycles) */
			stats->used = flow_table[pos].stats.used ? ovs_flow_used_time(flow_table[pos].stats.used) : 0;
		}
		return pos;
	}
	return -1;
}


/*
 * Return flow entry from flow table using 'key' as index.
 *
 * All data is copied
 */

inline int __attribute__((always_inline))
flow_table_get_flow(struct flow_key *key, struct action *actions,
                        struct flow_stats *stats)
{
	int pos = 0;
	int ret = -1;
	CHECK_NULL(key);
	pos = flow_table_lookup(key);
	CHECK_POS(pos);

	/* As we are reading from the table, acquire read lock */
	rte_rwlock_read_lock(&flow_table[pos].lock);

	ret = copy_entry_from_table(pos, NULL, actions, stats);

	/* release lock as we have everything we need */
	rte_rwlock_read_unlock(&flow_table[pos].lock);

	return ret;
}

/*
 * Will return the next flow entry after 'key' and corresponding data.
 *
 * All data is copied
 */
int flow_table_get_next_flow(const struct flow_key *key,
     struct flow_key *next_key, struct action *actions, struct flow_stats *stats)
{
	int pos = 0;
	int ret = -1;
	CHECK_NULL(key);
	pos = flow_table_lookup(key);
	CHECK_POS(pos);
	pos++;

	for (; pos < MAX_FLOWS; pos++) {
		/* dont lock as only writer should call this */
		ret = copy_entry_from_table(pos, next_key, actions, stats);
		if (ret == pos) {
			break;
		}
	}

	if (pos == MAX_FLOWS)
		ret = -1;

	return ret;
}

/*
 * Will return the first non-null flow entry in 'first_key'
 *
 * All data is copied
 */
int flow_table_get_first_flow(struct flow_key *first_key, struct action *actions,
                              struct flow_stats *stats)
{
	int pos = 0;
	int ret = -1;

	for (pos = 0; pos < MAX_FLOWS; pos++) {
		/* dont lock as only writer should call this */
		ret = copy_entry_from_table(pos, first_key, actions, stats);
		if (ret == pos) {
			break;
		}
	}

	if (pos == MAX_FLOWS)
		return -1;

	return ret;
}

/*
 * Delete flow table entry at 'key'
 */
int
flow_table_del_flow(const struct flow_key *key)
{
	int pos = 0;
	CHECK_NULL(key);
	pos = rte_hash_del_key(handle, key);
	CHECK_POS(pos);

	/* As we are writing to the table, acquire write lock */
	rte_rwlock_write_lock(&flow_table[pos].lock);

	memset((void *)&flow_table[pos].key, 0,
	       sizeof(flow_table[pos].key));
	memset((void *)&flow_table[pos].actions, 0,
	       sizeof(flow_table[pos].actions));
	flow_table[pos].used = false;

	/* release lock as table has been written */
	rte_rwlock_write_unlock(&flow_table[pos].lock);

	/* dont care about locking stats */
	flow_table_clear_stats(pos);
	return pos;
}

/*
 * Delete all flow table entries
 */
void
flow_table_del_all(void)
{
	int pos = 0;
	struct flow_key *key = NULL;

	for (pos = 0; pos < MAX_FLOWS; pos++) {
		key = &(flow_table[pos].key);
		flow_table_clear_stats(pos);
		rte_hash_del_key(handle, key);

		/* As we are writing to the table, acquire write lock */
		rte_rwlock_write_lock(&flow_table[pos].lock);

		memset(key, 0, sizeof(struct flow_key));
		memset((void *)&flow_table[pos].actions, 0,
		       sizeof(flow_table[pos].actions));
		flow_table[pos].used = false;

		/* release lock as table has been written */
		rte_rwlock_write_unlock(&flow_table[pos].lock);

	}

}

/*
 * Use 'pkt' to update stats at entry 'key' in flow_table
 */
static inline int __attribute__((always_inline))
flow_table_update_stats(int pos, const struct rte_mbuf *pkt)
{
	if (flow_table[pos].key.ether_type == ETHER_TYPE_IPv4 &&
	    flow_table[pos].key.ip_proto == IPPROTO_TCP) {
		struct tcp_hdr *tcp_hdr = TCP_HDR_FROM_PKT(pkt);
		flow_table[pos].stats.tcp_flags |= tcp_hdr->tcp_flags & TCP_FLAG_MASK;
	}

	flow_table[pos].stats.used = curr_tsc;
	flow_table[pos].stats.packet_count++;
	flow_table[pos].stats.byte_count += rte_pktmbuf_data_len(pkt);

	return 0;
}

struct icmp_hdr {
	uint8_t icmp_type;
	uint8_t icmp_code;
	uint16_t icmp_csum;
	union {
		struct {
			uint16_t id;
			uint16_t seq;
		} echo;
		struct {
			uint16_t empty;
			uint16_t mtu;
		} frag;
		uint32_t gateway;
	} icmp_fields;
	uint8_t icmp_data[0];
};

/*
 * Extract 13 tuple from pkt as key
 */
inline void __attribute__((always_inline))
flow_key_extract(const struct rte_mbuf *pkt, uint8_t in_port,
                 struct flow_key *key)
{
	struct ether_hdr *ether_hdr = NULL;
	struct vlan_hdr *vlan_hdr = NULL;
	struct ipv4_hdr *ipv4_hdr = NULL;
	struct tcp_hdr *tcp = NULL;
	struct udp_hdr *udp = NULL;
	struct icmp_hdr *icmp = NULL;
	unsigned char *pkt_data = NULL;
	uint16_t vlan_tci = 0;
	uint16_t be_offset = 0;

	memset(key, 0, sizeof(struct flow_key));

	key->in_port = in_port;

	/* Assume ethernet packet and get packet data */
	pkt_data = rte_pktmbuf_mtod(pkt, unsigned char *);
	ether_hdr = (struct ether_hdr *)pkt_data;
	pkt_data += sizeof(struct ether_hdr);

	key->ether_dst = ether_hdr->d_addr;
	key->ether_src = ether_hdr->s_addr;
	key->ether_type = rte_be_to_cpu_16(ether_hdr->ether_type);

	if (key->ether_type == ETHER_TYPE_VLAN) {
		vlan_hdr = (struct vlan_hdr *)pkt_data;
		pkt_data += sizeof(struct vlan_hdr);

		vlan_tci = rte_be_to_cpu_16(vlan_hdr->vlan_tci);
		key->vlan_id = vlan_tci & VLAN_ID_MASK;
		key->vlan_prio = vlan_tci >> VLAN_PRIO_SHIFT;

		key->ether_type = rte_be_to_cpu_16(vlan_hdr->eth_proto);
	}

	if (key->ether_type == ETHER_TYPE_IPv4) {
		ipv4_hdr = (struct ipv4_hdr *)pkt_data;
		pkt_data += sizeof(struct ipv4_hdr);

		key->ip_dst = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
		key->ip_src = rte_be_to_cpu_32(ipv4_hdr->src_addr);
		key->ip_proto = ipv4_hdr->next_proto_id;
		key->ip_tos = ipv4_hdr->type_of_service;
		key->ip_ttl = ipv4_hdr->time_to_live;

		be_offset = ipv4_hdr->fragment_offset;
		if (be_offset & rte_be_to_cpu_16(IPV4_HDR_OFFSET_MASK)) {
			key->ip_frag = OVS_FRAG_TYPE_LATER;
			return;
		}
		if (be_offset & rte_be_to_cpu_16(IPV4_HDR_MF_FLAG))
			key->ip_frag = OVS_FRAG_TYPE_FIRST;
		else
			key->ip_frag = OVS_FRAG_TYPE_NONE;
	}

	switch (key->ip_proto) {
		case IPPROTO_TCP:
			tcp = (struct tcp_hdr *)pkt_data;
			pkt_data += sizeof(struct tcp_hdr);

			key->tran_dst_port = rte_be_to_cpu_16(tcp->dst_port);
			key->tran_src_port = rte_be_to_cpu_16(tcp->src_port);
			break;
		case IPPROTO_UDP:
			udp = (struct udp_hdr *)pkt_data;
			pkt_data += sizeof(struct udp_hdr);

			key->tran_dst_port = rte_be_to_cpu_16(udp->dst_port);
			key->tran_src_port = rte_be_to_cpu_16(udp->src_port);
			break;
		case IPPROTO_ICMP:
			icmp = (struct icmp_hdr *)pkt_data;
			pkt_data += sizeof(struct icmp_hdr);

			key->tran_dst_port = icmp->icmp_code;
			key->tran_src_port = icmp->icmp_type;
			break;
		default:
			key->tran_dst_port = 0;
			key->tran_src_port = 0;
	}
}


/*
 * Lookup 'key' in hash table
 */
inline
int flow_table_lookup(const struct flow_key *key)
{
	return rte_hash_lookup(handle, key);
}

/*
 * Function translates TSC cycles to monotonic linux time.
 */
static uint64_t
ovs_flow_used_time(uint64_t flow_tsc)
{
	uint64_t curr_ms = 0;
	uint64_t idle_ms = 0;
	struct timespec tp = {0};

	/*
	 * Count idle time of flow. As TSC overflows infrequently
	 * (i.e. of the order of many years) and will only result
	 * in a spurious reading for flow used time, we dont check
	 * for overflow condition
	 */
	idle_ms = (curr_tsc - flow_tsc) * 1000UL / cpu_freq;

	/* Return monotonic linux time */
	clock_gettime(CLOCK_MONOTONIC, &tp);
	curr_ms = tp.tv_sec * 1000UL + tp.tv_nsec / 1000000UL;

	return curr_ms - idle_ms;
}

/*
 * This function takes a packet and routes it as per the flow table.
 */
inline void __attribute__((always_inline))
switch_packet(struct rte_mbuf *pkt, struct flow_key *key)
{
	int pos;

	pos = flow_table_lookup(key);

	if (likely(pos >= 0)) {
		rte_rwlock_read_lock(&flow_table[pos].lock);
		if (flow_table[pos].used) {
			struct action *actions;
			actions = &flow_table[pos].actions[0];
			action_execute(actions, pkt);
			flow_table_update_stats(pos, pkt);
		}
		rte_rwlock_read_unlock(&flow_table[pos].lock);
		return;
	}
	struct dpdk_upcall info;
	/* flow table miss, send unmatched packet to the daemon */
	info.cmd = PACKET_CMD_MISS;
	info.key = *key;
	send_packet_to_vswitchd(pkt, &info);
}
