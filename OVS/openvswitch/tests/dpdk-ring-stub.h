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

#include "common.h"

#define VSWITCHD_RINGSIZE   2048
#define VSWITCHD_PACKET_RING_NAME  "MProc_Vswitchd_Packet_Ring"
#define VSWITCHD_REPLY_RING_NAME   "MProc_Vswitchd_Reply_Ring"
#define VSWITCHD_MESSAGE_RING_NAME "MProc_Vswitchd_Message_Ring"
#define NO_FLAGS            0
#define SOCKET0             0

#define FLOW_CMD_FAMILY        0xF
#define PACKET_CMD_FAMILY      0x1F

#define action_output_build(action_struct, vport)   do { \
                             (action_struct)->type = ACTION_OUTPUT; \
                             (action_struct)->data.output.port = (vport);\
                         } while (0)

#define action_drop_build(action_struct)   do { \
                             (action_struct)->type = ACTION_NULL; \
                         } while (0)

#define action_pop_vlan_build(action_struct)   do { \
                             (action_struct)->type = ACTION_POP_VLAN; \
                         } while (0)

#define action_push_vlan_build(action_struct, tci_)   do { \
                             (action_struct)->type = ACTION_PUSH_VLAN; \
                             (action_struct)->data.vlan.tci = tci_;\
                         } while (0)

#define action_null_build(action_struct)   do { \
                             (action_struct)->type = ACTION_NULL; \
                         } while (0)
#define NO_FLOW 0
#define FLOW_EXISTS 1

/* ring to receive messages from vswitchd */
extern struct rte_ring *vswitchd_message_ring;
extern struct rte_ring *vswitchd_reply_ring;

void
create_dpdk_flow_get_reply(struct dpif_dpdk_message *reply);
void
create_dpdk_flow_put_reply(struct dpif_dpdk_message *reply);
void
create_dpdk_flow_del_reply(struct dpif_dpdk_message *reply, uint8_t flow_exists);
void
create_dpif_flow_put_message(struct dpif_flow_put *put);
int
enqueue_reply_on_reply_ring(struct dpif_dpdk_message reply);
void
create_dpif_flow_del_message(struct dpif_flow_del *del);
void
init_test_rings(void);
