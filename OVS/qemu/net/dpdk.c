/*
* Copyright (c) 2010-2013 Intel Corporation. All rights reserved.
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

#include <rte_log.h>
#include <rte_common.h>
#include <rte_config.h>
#include "config-host.h"
#include "net/net.h"
#include "qemu-common.h"
#include "dpdk_link.h"
#include "qemu/timer.h"
#include "clients.h"

#define RTE_LOGTYPE_APP        RTE_LOGTYPE_USER1
#define DPDK_TX_TO_QEMU_ENABLE 1
#define INIT_OPT_MODE          0700
#define INIT_TX_TIMEOUT        40000
#define INIT_OPT_STRING_SOCKET "sock"
#define INIT_OPT_STRING_GROUP  "group"
#define INIT_OPT_STRING_PORT   "port"
#define INIT_OPT_STRING_MODE   "mode"
#define OPEN_QEMU_STRING       "QEMU"

static void dpdk_transmit_to_qemu(NetClientState *nc, bool enable);
static ssize_t dpdk_receive(NetClientState *nc,
                            const uint8_t *buf, size_t size);
static void dpdk_cleanup(NetClientState *nc);

typedef struct DPDKState {
    NetClientState nc;
    uint8_t dpdk_client_id;
    QEMUTimer *tx_timer;
    int tx_timeout;
} DPDKState;

static NetClientInfo net_dpdk_info = {
    .type = NET_CLIENT_OPTIONS_KIND_DPDK,
    .size = sizeof(DPDKState),
    .receive = dpdk_receive,
    .poll = dpdk_transmit_to_qemu,
    .cleanup = dpdk_cleanup,
};

static void dpdk_transmit_to_qemu(NetClientState *nc, bool enable)
{
    DPDKState *state = DO_UPCAST(DPDKState, nc, nc);
    struct dpdk_buf dpdk_bufs[PACKET_READ_SIZE];
    int rx_pkts = 0;
    int i = 0;

    rx_pkts = dpdk_link_recv(state->dpdk_client_id, &dpdk_bufs[0]);
    for (i = 0; i < rx_pkts; i++) {
        if (dpdk_bufs[i].size > 0) {
            qemu_send_packet(&state->nc,
                             (uint8_t *)(&dpdk_bufs[i].buf),
                             dpdk_bufs[i].size);
        }
    }

    /*
     * Update the timer value stored in the state object by adding the timeout
     * value associated with the state.
     */
    qemu_mod_timer(state->tx_timer,
                   qemu_get_clock_ns(vm_clock) + state->tx_timeout);

}

static inline void dpdk_transmit_to_qemu_enabled(void *opaque)
{
     dpdk_transmit_to_qemu((NetClientState*)opaque, DPDK_TX_TO_QEMU_ENABLE);
}

static ssize_t dpdk_receive(NetClientState *vc, const uint8_t *buf, size_t size)
{
    DPDKState *s = DO_UPCAST(DPDKState, nc, vc);
    ssize_t ret = 0;
    do {
        ret = dpdk_link_send(s->dpdk_client_id, (char *)buf, size);
    } while (ret < 0 && errno == EINTR);

    return ret;
}

static void dpdk_cleanup(NetClientState *vc)
{
    DPDKState *s = DO_UPCAST(DPDKState, nc, vc);
    dpdk_link_close(s->dpdk_client_id);
}

int net_init_dpdk(const NetClientOptions *opts, const char *name,
                  NetClientState *peer)
{
    NetClientState *nc = NULL;
    DPDKState *s = NULL;
    uint8_t dpdk = 0;
    static int initialized = 0;
    const NetdevDpdkOptions *dpdk_opts = NULL;

    assert(opts->kind == NET_CLIENT_OPTIONS_KIND_DPDK);
    dpdk_opts = opts->dpdk;

    struct dpdk_open_args args = {
        .port = dpdk_opts->port,
        .group = (char *)dpdk_opts->group,
        .mode = dpdk_opts->has_mode ? dpdk_opts->mode : 0700,
    };

    if (!initialized) {
         dpdk_link_init();
    }

    dpdk = dpdk_link_open(0,(char *)OPEN_QEMU_STRING, &args);
    if (!dpdk) {
        RTE_LOG(ERR, APP, "Could not open dpdk link.\n");
        return -1;
    }

    nc = qemu_new_net_client(&net_dpdk_info, peer, "dpdk", name);

    snprintf(nc->info_str, sizeof(nc->info_str), "sock=%s,fd=%d",
             dpdk_opts->sock, dpdk);

    s = DO_UPCAST(DPDKState, nc, nc);

    s->dpdk_client_id = dpdk;

    s->tx_timer = qemu_new_timer_ns(vm_clock, dpdk_transmit_to_qemu_enabled, s);
    s->tx_timeout = INIT_TX_TIMEOUT;
    qemu_mod_timer(s->tx_timer, qemu_get_clock_ns(vm_clock) + s->tx_timeout);

    return 0;
}
