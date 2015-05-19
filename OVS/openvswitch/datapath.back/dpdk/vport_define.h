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

#ifndef __VPORT_DEFINE_H__
#define __VPORT_DEFINE_H__

#include <rte_ring.h>
#include <rte_mbuf.h>

#include "qos/core/sch_generic.h"

enum vport_type {
	VPORT_TYPE_DISABLED = 0,
	VPORT_TYPE_VSWITCHD,
	VPORT_TYPE_PHY,
	VPORT_TYPE_CLIENT,
	VPORT_TYPE_KNI,
	VPORT_TYPE_VETH,
};

struct vport_phy {
    struct rte_ring *tx_q;
	uint8_t index;
};

struct vport_client {
	struct rte_ring *rx_q;
	struct rte_ring *tx_q;
	struct rte_ring *free_q;
};

struct vport_kni {
	uint8_t index;
};

struct vport_veth {
	uint8_t index;
};

/*
 * Local cache used to buffer the mbufs before enqueueing them to client's
 * or port's TX queues.
 */
#define LOCAL_MBUF_CACHE_SIZE 32
struct local_mbuf_cache {
	struct rte_mbuf *cache[LOCAL_MBUF_CACHE_SIZE];
	                   /* per-port and per-core local mbuf cache */
	unsigned count;    /* number of mbufs in the local cache */
	uint64_t next_tsc; /* tsc at which next flush is required */
};

#define VPORT_INFO_NAMESZ 32
struct vport_info {
	enum vport_type __rte_cache_aligned type;
	char __rte_cache_aligned name[VPORT_INFO_NAMESZ];
	union {
		struct vport_phy phy;
		struct vport_client client;
		struct vport_kni kni;
		struct vport_veth veth;
	};
    struct Qdisc *qdisc; // Y.Born
    struct Qdisc *qdisc_sleeping;
    int          vportid;
};

#endif /* __VPORT_DEFINE_H__ */
