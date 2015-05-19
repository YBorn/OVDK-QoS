/*
* Copyright(c) 2010-2013 Intel Corporation. All rights reserved.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
* THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_memory.h>
#include <rte_log.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_memcpy.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>

#include "common.h"
#include "dpdk_link.h"

#define MBQ_CAPACITY 32

struct client {
    struct rte_ring *rx_ring;
    struct rte_ring *tx_ring;
};

static struct client clients[MAX_NUM_CLIENTS];
static struct rte_mempool *mp = NULL;
static int num_alloc_fail = 0;
static int num_alloc_succeed = 0;
static int num_overflow = 0;
static int num_underflow = 0;
static int num_frees = 0;
static int num_no_bufs = 0;
static int num_large_packets = 0;

/*
 * Send buffer to ovs_dpdk as client = client_id
 */
int dpdk_link_send(int client_id, char *ofpbuf, int size)
{
    struct rte_mbuf *buf = NULL;
    char *data = NULL;
    int rslt = 0;

    buf=rte_pktmbuf_alloc(mp);
    if (!buf) {
        num_alloc_fail++;
        return -1;
    }
    num_alloc_succeed++;

    /* copy ofpbuf to an mbuf and enqueue to client tx ring */
    data = rte_pktmbuf_mtod(buf, char *);
    rte_memcpy_func(data, ofpbuf, size);
    buf->pkt.pkt_len = size;
    buf->pkt.data_len = size;
    buf->pkt.nb_segs = 1;

    rslt = rte_ring_sp_enqueue(clients[client_id].tx_ring, (void *)buf);
    if (rslt < 0) {
        if (rslt == -ENOBUFS) {
            num_no_bufs++;
            rte_pktmbuf_free(buf);
        } else {
            num_overflow++;
        }
    }

    return size;
}

/*
 * Close link to ovs_dpdk for client_id
 */
int dpdk_link_close (int client_id)
{
    clients[client_id].rx_ring = NULL;
    clients[client_id].tx_ring = NULL;
    return 0;
}

/*
 * Open link to ovs_dpdk for client_id
 */
int dpdk_link_open(int init_sock, char *name, void *args)
{
    struct dpdk_open_args *oargs = (struct dpdk_open_args *)args;

    /* attach to ovs_dpdk rings */
    clients[oargs->port].rx_ring = rte_ring_lookup(get_rx_queue_name(oargs->port));
    if (clients[oargs->port].rx_ring == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot get RX ring - is ovs_dpdk process running?\n");
    }
    clients[oargs->port].tx_ring = rte_ring_lookup(get_tx_queue_name(oargs->port));
    if (clients[oargs->port].tx_ring == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot get TX ring - is ovs_dpdk process running?\n");
    }

    /* return non-zero number for success */
    return oargs->port;
}

/*
 * Receive buffer from ovs_dpdk as client = client_id
 */
int dpdk_link_recv(int client_id, struct dpdk_buf *buf)
{
    uint16_t rx_pkts = PACKET_READ_SIZE;
    int i = 0;
    int j = 0;
    char *data = NULL;
    struct rte_mbuf *mbuf[PACKET_READ_SIZE] = {0};
    int rslt = 0;

    rslt = rte_ring_sc_dequeue_bulk(clients[client_id].rx_ring,
             (void **)mbuf, rx_pkts);
    while (rx_pkts > 0 &&  rslt != 0) {
        rx_pkts = (uint16_t)RTE_MIN(rte_ring_count(clients[client_id].rx_ring),
                         PACKET_READ_SIZE );
        rslt = rte_ring_sc_dequeue_bulk(clients[client_id].rx_ring,
             (void **)mbuf, rx_pkts);
    }

    /* underflow condition */
    if (rslt == -ENOENT) {
        num_underflow++;
        return rslt;
    }

    /* Copy the buffers into what was passed to us */
    for (i = 0, j = 0; i < rx_pkts; i++) {
        buf[j].size = rte_pktmbuf_pkt_len((mbuf[i]));
        if (buf[j].size >= DPDK_LINK_MAX_FRAME_SIZE) {
            /* skip frame */
            RTE_LOG(ERR, APP, "Frame greater than maximum supported "
                              "frame size\n");
            rte_pktmbuf_free(mbuf[i]);
            num_large_packets++;
            continue;
        }
        data = rte_pktmbuf_mtod(mbuf[i], char *);
        rte_memcpy_func(buf[j].buf, data, rte_pktmbuf_pkt_len(mbuf[i]));

        /* Free up the packet since we don't need it anymore*/
        rte_pktmbuf_free(mbuf[i]);
        num_frees++;
        j++;
    }
    return rx_pkts;
}

/*
 * Initialize link to ovs_dpdk
 */
int dpdk_link_init(void)
{
    mp = rte_mempool_lookup(PKTMBUF_POOL_NAME);
    if (mp == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot get mempool for mbufs\n");
    }

    printf("\nQemu handling virtio packets from ovs_dpdk\n");
    return 0;
}

