/*
 * Copyright 2012-2014 Intel Corporation All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __DPDK_LINK_H
#define __DPDK_LINK_H

#include "dpif-dpdk.h"

int dpdk_link_init(void);
int dpdk_link_send(struct dpif_dpdk_message *, const struct ofpbuf *);
int dpdk_link_send_bulk(struct dpif_dpdk_message *, const struct ofpbuf *const *, size_t);
int dpdk_link_recv_reply(struct dpif_dpdk_message *);
int dpdk_link_recv_packet(struct ofpbuf **, struct dpif_dpdk_upcall *);

#endif /* DPDK_LINK_H */
