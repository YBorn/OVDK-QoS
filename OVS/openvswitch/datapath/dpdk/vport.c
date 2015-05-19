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

#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_memzone.h>
#include <rte_malloc.h>
#include <rte_string_fns.h>
#include <rte_ivshmem.h>

#include "init.h"
#include "vport.h"
#include "stats.h"
#include "args.h"
#include "kni.h"
#include "veth.h"

#include "flow.h"

#include "vport_define.h"
#include "qos/core/sch_qdisc.h"

#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_QoS RTE_LOGTYPE_USER1
#define NO_FLAGS        0
#define SOCKET0         0

#define MZ_PORT_INFO "MProc_port_info"
#define MZ_VPORT_INFO "MProc_vport_info"
/* define common names for structures shared between server and client */
#define MP_CLIENT_RXQ_NAME "MProc_Client_%u_RX"
#define MP_CLIENT_TXQ_NAME "MProc_Client_%u_TX"
#define MP_CLIENT_FREE_Q_NAME "MProc_Client_%u_FREE_Q"
#define MP_PORT_TXQ_NAME "MProc_PORT_%u_TX"

/* Ethernet port TX/RX ring sizes */
#define RTE_MP_RX_DESC_DEFAULT    512
#define RTE_MP_TX_DESC_DEFAULT    512
/* Ring size for communication with clients */
#define CLIENT_QUEUE_RINGSIZE     4096

/* Template used to create QEMU's command line files */
#define QEMU_CMD_FILE_FMT "/tmp/.ivshmem_qemu_cmdline_client_%u"

#define PORT_FLUSH_PERIOD_US  (100) /* TX drain every ~100us */
#define CACHE_FLUSH_PERIOD_US  (100) /* TX drain every ~100us */
#define LOCAL_MBUF_CACHE_SIZE 32
#define CACHE_NAME_LEN 32
#define MAX_QUEUE_NAME_SIZE 32

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
/* Default configuration for rx and tx thresholds etc. */
/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#define MP_DEFAULT_PTHRESH 36
#define MP_DEFAULT_RX_HTHRESH 8
#define MP_DEFAULT_TX_HTHRESH 0
#define MP_DEFAULT_WTHRESH 0

static const struct rte_eth_rxconf rx_conf_default = {
		.rx_thresh = {
				.pthresh = MP_DEFAULT_PTHRESH,
				.hthresh = MP_DEFAULT_RX_HTHRESH,
				.wthresh = MP_DEFAULT_WTHRESH,
		},
};

static const struct rte_eth_txconf tx_conf_default = {
		.tx_thresh = {
				.pthresh = MP_DEFAULT_PTHRESH,
				.hthresh = MP_DEFAULT_TX_HTHRESH,
				.wthresh = MP_DEFAULT_WTHRESH,
		},
		.tx_free_thresh = 0, /* Use PMD default values */
		.tx_rs_thresh = 0, /* Use PMD default values */
};

//enum vport_type {
//	VPORT_TYPE_DISABLED = 0,
//	VPORT_TYPE_VSWITCHD,
//	VPORT_TYPE_PHY,
//	VPORT_TYPE_CLIENT,
//	VPORT_TYPE_KNI,
//	VPORT_TYPE_VETH,
//};
//
//struct vport_phy {
//	struct rte_ring *tx_q;
//	uint8_t index;
//};
//
//struct vport_client {
//	struct rte_ring *rx_q;
//	struct rte_ring *tx_q;
//	struct rte_ring *free_q;
//};
//
///*
// * Local cache used to buffer the mbufs before enqueueing them to client's
// * or port's TX queues.
// */
//struct local_mbuf_cache {
//	struct rte_mbuf *cache[LOCAL_MBUF_CACHE_SIZE];
//	                   /* per-port and per-core local mbuf cache */
//	unsigned count;    /* number of mbufs in the local cache */
//	uint64_t next_tsc; /* tsc at which next flush is required */
//};
//
//struct vport_kni {
//	uint8_t index;
//};
//
//struct vport_veth {
//	uint8_t index;
//};

/*
 * Per-core local buffers to cache mbufs before sending them in bursts.
 * They use a two dimensions array. One list of all vports per each used lcore.
 * Since it's based on the idea that all working threads use different cores
 * no concurrency issues should occur.
 */
static struct local_mbuf_cache **client_mbuf_cache = NULL;
static struct local_mbuf_cache **port_mbuf_cache = NULL;

//#define VPORT_INFO_NAMESZ	(32)

//struct vport_info {
//	enum vport_type __rte_cache_aligned type;
//	char __rte_cache_aligned name[VPORT_INFO_NAMESZ];
//	union {
//		struct vport_phy phy;
//		struct vport_client client;
//		struct vport_kni kni;
//		struct vport_veth veth;
//	};
//};

static int send_to_client(uint8_t client, struct rte_mbuf *buf);
static int send_to_port(uint8_t vportid, struct rte_mbuf *buf);
static int send_to_kni(uint8_t vportid, struct rte_mbuf *buf);
static int send_to_veth(uint8_t vportid, struct rte_mbuf *buf);
static uint16_t receive_from_client(uint8_t client, struct rte_mbuf **bufs);
static uint16_t receive_from_port(uint8_t vportid, struct rte_mbuf **bufs);
static uint16_t receive_from_kni(uint8_t vportid, struct rte_mbuf **bufs);
static uint16_t receive_from_veth(uint8_t vportid, struct rte_mbuf **bufs);
static void flush_phy_port_cache(uint8_t vportid);
static void flush_client_port_cache(uint8_t clientid);

/* vports details */
struct vport_info *vports;

/* Drain period to flush packets out of the physical ports and caches */
static uint64_t port_flush_period;
static uint64_t cache_flush_period;

static void set_vport_name(unsigned i, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(vports[i].name, VPORT_INFO_NAMESZ, fmt, ap);
	va_end(ap);
}

/*
 * Given the queue name template, get the queue name
 */
static inline const char *
get_queue_name(unsigned id, const char *queue_name_template)
{
	static char buffer[MAX_QUEUE_NAME_SIZE];
	rte_snprintf(buffer, sizeof(buffer), queue_name_template, id);
	return buffer;
}

static inline const char *
get_rx_queue_name(unsigned id)
{
	return get_queue_name(id, MP_CLIENT_RXQ_NAME);
}

static inline const char *
get_tx_queue_name(unsigned id)
{
	return get_queue_name(id, MP_CLIENT_TXQ_NAME);
}

static inline const char *
get_free_queue_name(unsigned id)
{
	return get_queue_name(id, MP_CLIENT_FREE_Q_NAME);
}

static inline const char *
get_port_tx_queue_name(unsigned id)
{
	return get_queue_name(id, MP_PORT_TXQ_NAME);
}


static void
save_ivshmem_cmdline_to_file(const char *cmdline, unsigned clientid)
{
	FILE *file;
	char path[PATH_MAX];

	rte_snprintf(path, sizeof(path), QEMU_CMD_FILE_FMT, clientid);

	file = fopen(path, "w");
	if (file == NULL)
	    rte_exit(EXIT_FAILURE, "Cannot create QEMU cmdline for client %u\n",
	            clientid);

	RTE_LOG(INFO, APP, "QEMU cmdline for client '%u': %s \n", clientid, cmdline);
	fprintf(file, "%s\n", cmdline);
	fclose(file);
}


/*
 * Attempts to create a ring or exit
 */
static inline struct rte_ring *
queue_create(const char *ring_name, int flags)
{
	struct rte_ring *ring;

	ring = rte_ring_create(ring_name, CLIENT_QUEUE_RINGSIZE, SOCKET0, flags);
	if (ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create '%s' ring \n", ring_name);
	return ring;
}


/**
 * Initialise an individual port:
 * - configure number of rx and tx rings
 * - set up each rx ring, to pull from the main mbuf pool
 * - set up each tx ring
 * - start the port and report its status to stdout
 */
static int
init_port(uint8_t port_num)
{
	/* for port configuration all features are off by default */
	const struct rte_eth_conf port_conf = {
		.rxmode = {
			.mq_mode = ETH_RSS
		}
	};
	const uint16_t rx_rings = 1, tx_rings = num_clients;
	struct rte_eth_link link = {0};
	uint16_t q = 0;
	int retval = 0;

	printf("Port %u init ... ", (unsigned)port_num);
	fflush(stdout);

	/* Standard DPDK port initialisation - config port, then set up
	 * rx and tx rings */
	if ((retval = rte_eth_dev_configure(port_num, rx_rings, tx_rings,
		&port_conf)) != 0)
		return retval;

	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port_num, q, RTE_MP_RX_DESC_DEFAULT,
				SOCKET0, &rx_conf_default, pktmbuf_pool);
		if (retval < 0) return retval;
	}

	for (q = 0; q < tx_rings; q ++) {
		retval = rte_eth_tx_queue_setup(port_num, q, RTE_MP_TX_DESC_DEFAULT,
				SOCKET0, &tx_conf_default);
		if (retval < 0)
			return retval;
	}

	rte_eth_promiscuous_enable(port_num);

	retval = rte_eth_dev_start(port_num);
	if (retval < 0)
		return retval;

	printf( "done: ");

	/* get link status */
	rte_eth_link_get(port_num, &link);
	if (link.link_status) {
		printf(" Link Up - speed %u Mbps - %s\n",
			   (uint32_t) link.link_speed,
			   (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
		       ("full-duplex") : ("half-duplex"));
	} else {
		printf(" Link Down\n");
	}

	return 0;
}

static void *
secure_rte_zmalloc(const char *type, size_t size, unsigned align)
{
	void *addr;

	addr = rte_zmalloc(type, size, align);
	if (addr == NULL)
		rte_exit(EXIT_FAILURE, "Cannot allocate memory for %s \n", type);

	return addr;
}

/**
 * Set up the DPDK rings which will be used to pass packets, via
 * pointers, between the multi-process server and client processes.
 * Each client needs one RX queue.
 */
static int
init_shm_rings(void)
{
	unsigned i, clientid;
	char cache_name[CACHE_NAME_LEN];
	char ivshmem_config_name[IVSHMEM_NAME_LEN];
	char cmdline[PATH_MAX];


	client_mbuf_cache = secure_rte_zmalloc("per-core-client cache",
			sizeof(*client_mbuf_cache) * rte_lcore_count(), 0);

	for (i = 0; i < rte_lcore_count(); i++) {
		rte_snprintf(cache_name, sizeof(cache_name), "core%u client cache", i);
		client_mbuf_cache[i] = secure_rte_zmalloc(cache_name,
				sizeof(**client_mbuf_cache) * num_clients, 0);
	}

	port_mbuf_cache = secure_rte_zmalloc("per-core-core cache",
			sizeof(*port_mbuf_cache) * rte_lcore_count(), 0);

	for (i = 0; i < rte_lcore_count(); i++) {
		rte_snprintf(cache_name, sizeof(cache_name), "core%u port cache", i);
		port_mbuf_cache[i] = secure_rte_zmalloc(cache_name,
				sizeof(**port_mbuf_cache) * ports->num_ports, 0);
	}

	for (i = 0; i < num_clients; i++) {
		clientid = CLIENT1 + i;

		rte_snprintf(ivshmem_config_name, IVSHMEM_NAME_LEN, "ovs_config_%d", clientid);

		/* Create IVSHMEM config file for this client */
		if (rte_ivshmem_metadata_create(ivshmem_config_name) < 0)
			rte_exit(EXIT_FAILURE, "Cannot create ivshmem config '%s'\n",
					ivshmem_config_name);

		struct vport_client *cl = &vports[clientid].client;
		RTE_LOG(INFO, APP, "Initialising Client %d\n", clientid);
		/* Create a "multi producer multi consumer" queue for each client */
		cl->rx_q = queue_create(get_rx_queue_name(clientid), NO_FLAGS);
		cl->tx_q = queue_create(get_tx_queue_name(clientid), NO_FLAGS);
		cl->free_q = queue_create(get_free_queue_name(clientid), NO_FLAGS);

		/* Adding the rings to be shared with the current client */
		rte_ivshmem_metadata_add_ring(cl->rx_q, ivshmem_config_name);
		rte_ivshmem_metadata_add_ring(cl->tx_q, ivshmem_config_name);
		rte_ivshmem_metadata_add_ring(cl->free_q, ivshmem_config_name);

		/* Generate QEMU's command line */
		rte_ivshmem_metadata_cmdline_generate(cmdline, sizeof(cmdline),
				ivshmem_config_name);

		save_ivshmem_cmdline_to_file(cmdline, clientid);
	}

	for (i = 0; i < ports->num_ports; i++) {
		struct vport_phy *phy = &vports[PHYPORT0 + i].phy;
		RTE_LOG(INFO, APP, "Initialising Port %d\n", i);
		/* Create an RX queue for each ports */
		phy->tx_q = queue_create(get_port_tx_queue_name(i), RING_F_SC_DEQ);
	}

	return 0;
}


void vport_init(void)
{
	const struct rte_memzone *mz = NULL;
	uint8_t i = 0;
	int retval = 0;

	/* set up array for port data */
	mz = rte_memzone_reserve(MZ_PORT_INFO, sizeof(*ports),
				rte_socket_id(), NO_FLAGS);
	if (mz == NULL)
		rte_exit(EXIT_FAILURE, "Cannot reserve memory zone for port information\n");
	memset(mz->addr, 0, sizeof(*ports));
	ports = mz->addr;
	RTE_LOG(INFO, APP, "memzone address is %lx\n", mz->phys_addr);

	/* set up array for vport info */
	mz = rte_memzone_reserve(MZ_VPORT_INFO,
				sizeof(struct vport_info) * MAX_VPORTS,
				rte_socket_id(), NO_FLAGS);

	if (!mz)
		rte_exit(EXIT_FAILURE, "Cannot reserve memory zone for vport information\n");
	memset(mz->addr, 0, sizeof(struct vport_info) * MAX_VPORTS);
	vports = mz->addr;
	RTE_LOG(INFO, APP, "memzone for vport info address is %lx\n", mz->phys_addr);

	ports->num_ports = port_cfg.num_ports;

	/* vports setup */

	/* vport 0 is for vswitchd */
	vports[0].type = VPORT_TYPE_VSWITCHD;
	set_vport_name(0, "vswitchd");

	/* vport for client */
	for (i = CLIENT1; i < num_clients; i++) {
		vports[i].type = VPORT_TYPE_CLIENT;
		set_vport_name(i, "Client    %2u", i);
	}
	/* vport for kni */
	for (i = 0; i < num_kni; i++) {
		vports[KNI0 + i].type = VPORT_TYPE_KNI;
		vports[KNI0 + i].kni.index = i;
		set_vport_name(KNI0 + i, "KNI Port  %2u", i);
	}
	/* vport for veth */
	for (i = 0; i < num_veth; i++) {
		vports[VETH0 + i].type = VPORT_TYPE_VETH;
		vports[VETH0 + i].veth.index = i;
		set_vport_name(VETH0 + i, "vEth Port %2u", i);
	}

	/* now initialise the ports we will use */
	for (i = 0; i < ports->num_ports; i++) {
		unsigned vportid = cfg_params[i].port_id;

		vports[vportid].type = VPORT_TYPE_PHY;
		vports[vportid].phy.index = port_cfg.id[i];
		set_vport_name(vportid, "Port      %2u", port_cfg.id[i]);
        /* (QoS) Added by Y.Born */
        dev_init_scheduler(&vports[vportid]);
        dev_activate(&vports[vportid]);
        vports[vportid].vportid = vportid;

		retval = init_port(port_cfg.id[i]);
		if (retval != 0)
			rte_exit(EXIT_FAILURE, "Cannot initialise port %u\n", i);
	}

	/* initialise the client queues/rings for inter process comms */
	init_shm_rings();

	/* initalise kni queues */
	init_kni();

	/* initalise veth queues */
	init_veth();

	/* initialize flush periods using CPU frequency */
	port_flush_period = (rte_get_tsc_hz() + US_PER_S - 1) /
	        US_PER_S * PORT_FLUSH_PERIOD_US;
	cache_flush_period = (rte_get_tsc_hz() + US_PER_S - 1) /
	        US_PER_S * CACHE_FLUSH_PERIOD_US;
}

/*
 * Enqueue a single packet to a client rx ring
 */
static inline int
send_to_client(uint8_t client, struct rte_mbuf *buf)
{
	int ret, i;
	struct rte_mbuf *freebufs[PKT_BURST_SIZE];
	struct vport_client *cl = NULL;
	struct local_mbuf_cache *per_cl_cache = NULL;

	per_cl_cache = &client_mbuf_cache[rte_lcore_id()][client - CLIENT1];

	per_cl_cache->cache[per_cl_cache->count++] = buf;

	if (unlikely(per_cl_cache->count == LOCAL_MBUF_CACHE_SIZE))
		flush_client_port_cache(client);

	cl = &vports[client].client;
	ret = rte_ring_sc_dequeue_burst(cl->free_q, (void *)freebufs, PKT_BURST_SIZE);
	for (i = 0; i < ret; i++)
		rte_pktmbuf_free(freebufs[i]);

	return 0;
}

/*
 * Enqueue single packet to a port
 */
//static inline int
//send_to_port(uint8_t vportid, struct rte_mbuf *buf)
//{
//	struct local_mbuf_cache *per_port_cache =
//			&port_mbuf_cache[rte_lcore_id()][vportid - PHYPORT0];
//
//	per_port_cache->cache[per_port_cache->count++] = buf;
//
//	if (unlikely(per_port_cache->count == LOCAL_MBUF_CACHE_SIZE))
//		flush_phy_port_cache(vportid);
//
//	return 0;
//}

static inline int
send_to_port(uint8_t vportid, struct rte_mbuf *buf) {
    struct vport_info *vport = &vports[vportid];            
    if(vport->qdisc == NULL) {
        if(rte_ring_enqueue(vport->phy.tx_q, (void*) buf) == -ENOBUFS) {
            stats_vswitch_tx_drop_increment(1);
            stats_vport_tx_drop_increment(vportid, 1);
        }
    } else {
        BUG_ON(vport->qdisc->enqueue == NULL);
        vport->qdisc->enqueue(buf, vport->qdisc);
    }
    return 0;
}

/*
 * Enqueue single packet to a KNI fifo
 */
static inline int
send_to_kni(uint8_t vportid, struct rte_mbuf *buf)
{
	int i = 0;
	int tx_count = 0;

	i = vports[vportid].kni.index;
	rte_spinlock_lock(&rte_kni_locks[i]);
	tx_count = rte_kni_tx_burst(&rte_kni_list[i], &buf, 1);
	rte_spinlock_unlock(&rte_kni_locks[i]);

	/* FIFO is full */
	if (tx_count == 0) {
		rte_pktmbuf_free(buf);
		stats_vport_rx_drop_increment(vportid, INC_BY_1);
		stats_vswitch_tx_drop_increment(INC_BY_1);
	} else {
		stats_vport_rx_increment(vportid, INC_BY_1);
	}

	return 0;
}

/*
 * Enqueue single packet to a vETH fifo
 */
static int
send_to_veth(uint8_t vportid, struct rte_mbuf *buf)
{
	int i = 0;
	int tx_count = 0;

	i = vports[vportid].veth.index;
	/* Spinlocks not needed here as veth only used for OFTest currently. This
	 * may change in the future */
	tx_count = rte_kni_tx_burst(rte_veth_list[i], &buf, 1);

	/* FIFO is full */
	if (tx_count == 0) {
		rte_pktmbuf_free(buf);
		stats_vport_rx_drop_increment(vportid, INC_BY_1);
		stats_vswitch_tx_drop_increment(INC_BY_1);
	} else {
		stats_vport_rx_increment(vportid, INC_BY_1);
	}

	return 0;
}

inline int
send_to_vport(uint8_t vportid, struct rte_mbuf *buf)
{
	if (unlikely(vportid >= MAX_VPORTS)) {
		RTE_LOG(WARNING, APP,
			"sending to invalid vport: %u\n", vportid);
		goto drop;
	}

	switch (vports[vportid].type) {
	case VPORT_TYPE_PHY:
		return send_to_port(vportid, buf);
	case VPORT_TYPE_CLIENT:
		return send_to_client(vportid, buf);
	case VPORT_TYPE_KNI:
		return send_to_kni(vportid, buf);
	case VPORT_TYPE_VETH:
		return send_to_veth(vportid, buf);
	case VPORT_TYPE_VSWITCHD:
		/* DPDK vSwitch cannot handle it now, ignore */
		break;
	default:
		RTE_LOG(WARNING, APP, "unknown vport %u type %u\n",
			vportid, vports[vportid].type);
		break;
	}
drop:
	rte_pktmbuf_free(buf);
	return -1;
}

/*
 * Receive burst of packets from a vETH fifo
 */
static uint16_t
receive_from_veth(uint8_t vportid, struct rte_mbuf **bufs)
{
	int i = 0;
	uint16_t rx_count = 0;

	i = vports[vportid].veth.index;
	rx_count = rte_kni_rx_burst(rte_veth_list[i], bufs, PKT_BURST_SIZE);

	if (likely(rx_count != 0))
		stats_vport_tx_increment(vportid, rx_count);

	/* handle callbacks, i.e. ifconfig */
	rte_kni_handle_request(rte_veth_list[i]);

	return rx_count;
}

/*
 * Receive burst of packets from a KNI fifo
 */
static inline uint16_t
receive_from_kni(uint8_t vportid, struct rte_mbuf **bufs)
{
	int i = 0;
	uint16_t rx_count = 0;

	i = vports[vportid].kni.index;
	rx_count = rte_kni_rx_burst(&rte_kni_list[i], bufs, PKT_BURST_SIZE);

	if (likely(rx_count > 0))
		stats_vport_tx_increment(vportid, rx_count);

	return rx_count;
}

/*
 * Receive burst of packets from client
 */
static inline uint16_t
receive_from_client(uint8_t client, struct rte_mbuf **bufs)
{
	uint16_t rx_count = PKT_BURST_SIZE;
	struct vport_client *cl;

	cl = &vports[client].client;

	rx_count = rte_ring_sc_dequeue_burst(cl->tx_q, (void **)bufs, PKT_BURST_SIZE);

	/* Update number of packets transmitted by client */
	stats_vport_tx_increment(client, rx_count);

	return rx_count;
}

/*
 * Receive burst of packets from physical port.
 */
static inline uint16_t
receive_from_port(uint8_t vportid, struct rte_mbuf **bufs)
{
	uint16_t rx_count = 0;

	/* Read a port */
	rx_count = rte_eth_rx_burst(vports[vportid].phy.index, 0,
			bufs, PKT_BURST_SIZE);

	/* Now process the NIC packets read */
	if (likely(rx_count > 0))
		stats_vport_rx_increment(vportid, rx_count);

	return rx_count;
}

inline uint16_t
receive_from_vport(uint8_t vportid, struct rte_mbuf **bufs)
{
	if (unlikely(vportid >= MAX_VPORTS)) {
		RTE_LOG(WARNING, APP,
			"receiving from invalid vport %u\n", vportid);
		return 0;
	}

	switch (vports[vportid].type) {
	case VPORT_TYPE_PHY:
		return receive_from_port(vportid, bufs);
	case VPORT_TYPE_CLIENT:
		return receive_from_client(vportid, bufs);
	case VPORT_TYPE_KNI:
		return receive_from_kni(vportid, bufs);
	case VPORT_TYPE_VETH:
		return receive_from_veth(vportid, bufs);
	default:
		RTE_LOG(WARNING, APP,
			"receiving from unknown vport %u type %u\n",
			vportid, vports[vportid].type);
		break;
	}
	return 0;
}

/*
 * Flush packets scheduled for transmit on ports
 */
inline void
flush_nic_tx_ring(unsigned vportid)
{
	unsigned i = 0;
	struct rte_mbuf *pkts[2*PKT_BURST_SIZE] = {NULL};
	struct vport_phy *phy = &vports[vportid].phy;
	uint8_t portid = phy->index;
	uint64_t diff_tsc = 0;
	static uint64_t prev_tsc[MAX_PHYPORTS] = {0};
	uint64_t cur_tsc = rte_rdtsc();
	unsigned num_pkts = 0;

    // Added by Y.Born
    struct vport_info *vport = &vports[vportid];
    struct rte_mbuf *pkt = NULL;
    uint16_t sent = 0;

    if(vport->qdisc == NULL) {        
        diff_tsc = cur_tsc - prev_tsc[portid];

        num_pkts = rte_ring_count(phy->tx_q);

        /* If queue idles with less than PKT_BURST packets, drain it*/
        if (num_pkts < PKT_BURST_SIZE)
            if(unlikely(diff_tsc < port_flush_period))
                return;

        /* maximum number of packets that can be handles is PKT_BURST_SIZE */
        if (unlikely(num_pkts > PKT_BURST_SIZE))
            num_pkts = PKT_BURST_SIZE;

        if (unlikely(rte_ring_dequeue_bulk(phy->tx_q, (void **)pkts, num_pkts) != 0))
            return;

        sent = rte_eth_tx_burst(portid, 0, pkts, num_pkts);

        prev_tsc[vportid & PORT_MASK] = cur_tsc;

    } else {
        BUG_ON(vport->qdisc->dequeue == NULL);
        while(num_pkts < 2*PKT_BURST_SIZE && 
            (pkts[num_pkts] = vport->qdisc->dequeue(vport->qdisc)) != NULL){
            num_pkts++;
        }
        if(num_pkts > 0)
            sent = rte_eth_tx_burst(portid, 0, pkts, num_pkts);
    }

    if (unlikely(sent < num_pkts)) {
        for (i = sent; i < num_pkts; i++)
            rte_pktmbuf_free(pkts[i]);

        stats_vport_tx_drop_increment(vportid, num_pkts - sent);
    }
    stats_vport_tx_increment(vportid, sent);
}

/* 
 * This function must be called periodically to ensure that no mbufs get
 * stuck in the port mbuf cache. 
 *
 * This must be called by each core that calls send_to_port()
 *
 */
void flush_ports(void) 
{
	uint8_t portid = 0;
	uint8_t lcore_id = rte_lcore_id();
	struct local_mbuf_cache *per_port_cache = NULL;

	/* iterate over all port caches for this core */
	for (portid = 0; portid < ports->num_ports; portid++) {
//		per_port_cache = &port_mbuf_cache[lcore_id][portid];
		/* only flush when we have exceeded our deadline */
//		if (curr_tsc > per_port_cache->next_tsc) {
				flush_phy_port_cache(portid + PHYPORT0);
//		}
	}
	
	return;
}

/* 
 * Flush any mbufs in port's cache to NIC TX pre-queue ring.
 *
 * Update 'next_tsc' to indicate when next flush is required
 */
static inline void
flush_phy_port_cache(uint8_t vportid)
{
	unsigned i = 0, tx_count = 0;
	struct local_mbuf_cache *per_port_cache = NULL;
	uint8_t portid = vportid - PHYPORT0;
	
	per_port_cache = &port_mbuf_cache[rte_lcore_id()][portid];

    // Added by Y.Born
    struct rte_mbuf *pkt = NULL;
    struct vport_info *vport = &vports[vportid];

	if (unlikely(per_port_cache->count == 0))
		return;

    if(vport->qdisc == NULL) {
        tx_count = rte_ring_mp_enqueue_burst(vports[vportid].phy.tx_q,
                (void **) per_port_cache->cache, per_port_cache->count);

        if (unlikely(tx_count < per_port_cache->count)) {
            uint8_t dropped = per_port_cache->count - tx_count;
            for (i = tx_count; i < per_port_cache->count; i++)
                rte_pktmbuf_free(per_port_cache->cache[i]);
            
            stats_vswitch_tx_drop_increment(dropped);
            stats_vport_tx_drop_increment(vportid, dropped);
            /* TODO: stats_vport_overrun_increment */
        } 
    } else {
        for(i = 0; i < per_port_cache->count; i++) {
            pkt = per_port_cache->cache[i];
            if(vport->qdisc->enqueue == NULL) {
                RTE_LOG(INFO, APP, "It's a BUG2\n");
            } else {
                vport->qdisc->enqueue(pkt, vport->qdisc);
            }
        } 
    }

	per_port_cache->count = 0;
	per_port_cache->next_tsc = curr_tsc + cache_flush_period;
}

/* 
 * This function must be called periodically to ensure that no mbufs get
 * stuck in the client mbuf cache. 
 *
 * This must be called by each core that calls send_to_client()
 *
 */
void flush_clients(void) 
{
	uint8_t clientid = 0;
	uint8_t lcore_id = rte_lcore_id();
	struct local_mbuf_cache *per_client_cache = NULL;

	/* iterate over all client caches for this core */
	for (clientid = 0; clientid < num_clients; clientid++) {
		per_client_cache = &client_mbuf_cache[lcore_id][clientid];
		/* only flush when we have exceeded our deadline */
		if (curr_tsc > per_client_cache->next_tsc) {
			flush_client_port_cache(clientid + CLIENT1);
		}
	}
	
	return;
}

/* 
 * Flush any mbufs in 'clientid' client's cache to client ring.
 *
 * Update 'next_tsc' to indicate when next flush is required
 */
static inline void
flush_client_port_cache(uint8_t clientid)
{
	struct vport_client *cl = NULL;
	struct local_mbuf_cache *per_cl_cache = NULL;
	unsigned tx_count = 0, i = 0;

	per_cl_cache = &client_mbuf_cache[rte_lcore_id()][clientid - CLIENT1];
		
	if (unlikely(per_cl_cache->count == 0))
		return;
		
	cl = &vports[clientid].client;

	tx_count = rte_ring_mp_enqueue_burst(cl->rx_q,
				(void **)per_cl_cache->cache, per_cl_cache->count);

	if (unlikely(tx_count < per_cl_cache->count)) {
		uint8_t dropped = per_cl_cache->count - tx_count;
		for (i = tx_count; i < per_cl_cache->count; i++)
			rte_pktmbuf_free(per_cl_cache->cache[i]);
	
		stats_vswitch_tx_drop_increment(dropped);
		stats_vport_rx_drop_increment(clientid, dropped);
		/* TODO: stats_vport_overrun_increment */
	}

	stats_vport_rx_increment(clientid, tx_count);

	per_cl_cache->count = 0;
	per_cl_cache->next_tsc = curr_tsc + cache_flush_period;

}

const char *vport_name(unsigned vportid)
{
	return vports[vportid].name;
}
