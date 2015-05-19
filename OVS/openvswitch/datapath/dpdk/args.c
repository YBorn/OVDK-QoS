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



#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>

#include <rte_memory.h>
#include <rte_string_fns.h>

#include "args.h"
#include "init.h"
#include "vport.h"
#include "kni.h"
#include "veth.h"

#define PORT_OFFSET 0x10
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

struct cfg_params cfg_params_array[MAX_CFG_PARAMS];
struct cfg_params cfg_params_array_default[] = {
	{0, 0, 2},
	{0, 1, 2},
	{0, 2, 2},
	{1, 0, 2},
	{1, 1, 2},
	{1, 2, 2},
	{2, 0, 2},
	{3, 0, 3},
	{3, 1, 3},
};
struct cfg_params * cfg_params = cfg_params_array_default;
uint16_t nb_cfg_params = sizeof(cfg_params_array_default) /
				sizeof(cfg_params_array_default[0]);

static const char *progname;

/**
 * Prints out usage information to stdout
 */
static void
usage(void)
{
	printf(
	    "%s [EAL options] -- -p PORTMASK -n NUM_CLIENTS [-k NUM_KNI] [-v NUM_VETH]\n"
	    " -p PORTMASK: hexadecimal bitmask of ports to use\n"
	    " -n NUM_CLIENTS: number of client processes to use\n"
	    " -k NUM_KNI: number of kni ports to use\n"
	    " -v NUM_VETH: number of host kni (veth) ports to use\n"
	    , progname);
}

/**
 * The ports to be used by the application are passed in
 * the form of a bitmask. This function parses the bitmask
 * and places the port numbers to be used into the port[]
 * array variable
 */
static int
parse_portmask(uint8_t max_ports, const char *portmask)
{
	char *end = NULL;
	unsigned long pm;
	uint8_t count = 0;

	if (portmask == NULL || *portmask == '\0')
		return -1;

	/* convert parameter to a number and verify */
	pm = strtoul(portmask, &end, 16);
	if (end == NULL || *end != '\0' || pm == 0)
		return -1;

	/* loop through bits of the mask and mark ports */
	
	printf("max_ports = %d\n", max_ports);
	while (pm != 0) {
		if (pm & 0x01) { /* bit is set in mask, use port */
			if (count >= max_ports)
				printf("WARNING: requested port %u not present"
				" - ignoring\n", (unsigned)count);
			else
			    port_cfg.id[port_cfg.num_ports++] = count;
		}
		pm = (pm >> 1);
		count++;
	}

	return 0;
}

/**
 * Take the number of clients parameter passed to the app
 * and convert to a number to store in the num_clients variable
 */
static int
parse_num_clients(const char *clients)
{
	char *end = NULL;
	unsigned long temp;

	if (clients == NULL || *clients == '\0')
		return -1;

	temp = strtoul(clients, &end, 10);
	if (end == NULL || *end != '\0' || temp == 0)
		return -1;

	return temp;
}

int
parse_config(const char *q_arg)
{
	char s[256];
	const char *p, *p0 = q_arg;
	char *end;
	enum fieldnames {
		FLD_PORT = 0,
		FLD_QUEUE,
		FLD_LCORE,
		_NUM_FLD
	};
	unsigned long int_fld[_NUM_FLD];
	char *str_fld[_NUM_FLD];
	int i;
	unsigned size;

	nb_cfg_params = 0;

	while ((p = strchr(p0,'(')) != NULL) {
		++p;
		if((p0 = strchr(p,')')) == NULL)
			return -1;

		size = p0 - p;
		if(size >= sizeof(s))
			return -1;

		rte_snprintf(s, sizeof(s), "%.*s", size, p);
		if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
				return -1;
		}
		if (nb_cfg_params >= MAX_CFG_PARAMS) {
			printf("exceeded max number of lcore params: %hu\n",
				nb_cfg_params);
			return -1;
		}
		/* Add port offset to calculate vport id for the port */
		cfg_params_array[nb_cfg_params].port_id = (uint8_t)int_fld[FLD_PORT] + PORT_OFFSET;
		printf("config = %d,", cfg_params_array[nb_cfg_params].port_id);
		cfg_params_array[nb_cfg_params].queue_id = (uint8_t)int_fld[FLD_QUEUE];
		printf("%d,", cfg_params_array[nb_cfg_params].queue_id);
		cfg_params_array[nb_cfg_params].lcore_id = (uint8_t)int_fld[FLD_LCORE];
		printf("%d\n", cfg_params_array[nb_cfg_params].lcore_id);
		++nb_cfg_params;
	}
	printf("nb_cfg_params = %d\n", nb_cfg_params);
	cfg_params = cfg_params_array;

	return 0;
}


/**
 * The application specific arguments follow the DPDK-specific
 * arguments which are stripped by the DPDK init. This function
 * processes these application arguments, printing usage info
 * on error.
 */
int
parse_app_args(uint8_t max_ports, int argc, char *argv[])
{
	int option_index, opt, ret, temp;
	char **argvopt = argv;
	static struct option lgopts[] = {
			{PARAM_STATS, 1, 0, 0},
			{PARAM_CONFIG, 1, 0, 0},
			{PARAM_VSWITCHD, 1, 0, 0},
			{PARAM_CSC, 1, 0, 0},
			{PARAM_QOS, 1, 0, 0},  // Added by Y.Born
			{NULL, 0, 0, 0}
	};

	progname = argv[0];

	/* Initialize the three counters to "not used" */
	num_clients = num_kni = num_veth = 0;

	while ((opt = getopt_long(argc, argvopt, "n:p:k:v:", lgopts,
		&option_index)) != EOF) {
		switch (opt) {
			case 'p':  /* Physical ports */
				if (parse_portmask(max_ports, optarg) != 0) {
					usage();
					return -1;
				}
				break;
			case 'n':  /* Client ports */
				temp = parse_num_clients(optarg);
				if (temp <= 0) {
					usage();
					return -1;
				}
				num_clients = (uint8_t)temp;
				break;
			case 'k':  /* KNI ports */
				temp = parse_num_clients(optarg);
				if (temp <= 0) {
					usage();
					return -1;
				}
				num_kni = (uint8_t)temp;
				break;
			case 'v':  /* vEth ports */
				temp = parse_num_clients(optarg);
				if (temp <= 0) {
					usage();
					return -1;
				}
				num_veth = (uint8_t)temp;
				break;
			case 0:
				if (!strcmp(lgopts[option_index].name, PARAM_CONFIG)) {
					ret = parse_config(optarg);
					if (ret) {
						printf("invalid config\n");
					}
				}
				if (strncmp(lgopts[option_index].name, PARAM_STATS, 5) == 0) {
					stats_display_interval = atoi(optarg);
				} else if (strncmp(lgopts[option_index].name, PARAM_VSWITCHD, 8) == 0) {
					vswitchd_core = atoi(optarg);
				} else if (strncmp(lgopts[option_index].name, PARAM_CSC, 16) == 0) {
					client_switching_core = atoi(optarg);
                // }
                // Added by Y.Born
				} else if (strncmp(lgopts[option_index].name, PARAM_QOS, 8) == 0) {
                    qos_core = atoi(optarg);
                }
				break;
			default:
				printf("ERROR: Unknown option '%c'\n", opt);
				usage();
				return -1;
		}
	}

	if (num_clients == 0 || num_clients > MAX_CLIENTS) {
		printf ("Number of clients is invalid\n");
		usage();
		return -1;
	}

	if (num_kni > MAX_KNI_PORTS) {
		printf ("Number of KNI ports is invalid\n");
		usage();
		return -1;
	}

	if (num_veth > MAX_VETH_PORTS) {
		printf ("Number of host KNI (vEth) ports is invalid\n");
		usage();
		return -1;
	}

	return 0;
}

