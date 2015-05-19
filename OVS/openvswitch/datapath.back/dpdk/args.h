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


#ifndef _ARGS_H_
#define _ARGS_H_

#include "vport.h"

#define PARAM_CONFIG "config"
#define PARAM_STATS "stats"
#define PARAM_VSWITCHD "vswitchd"
#define PARAM_CSC "client_switching_core"
#define PARAM_KSC "kni_switching_core"
// Added By Born
#define PARAM_QOS "qos_core"

#define MAX_CFG_PARAMS MAX_PHYPORTS
struct cfg_params {
	uint8_t port_id;
	uint8_t queue_id;
	uint8_t lcore_id;
} __rte_cache_aligned;

extern struct cfg_params *cfg_params;
extern uint16_t nb_cfg_params;

int parse_app_args(uint8_t max_ports, int argc, char *argv[]);
int parse_config(const char *q_arg);

/* global var for number of clients - extern in header */
uint8_t num_clients;
uint8_t num_kni;
unsigned stats_display_interval; /* in seconds, set to 0 to disable update */
unsigned vswitchd_core;
unsigned client_switching_core;
struct port_info port_cfg;

// Added by Y.Born
unsigned qos_core;

#endif /* ifndef _ARGS_H_ */
