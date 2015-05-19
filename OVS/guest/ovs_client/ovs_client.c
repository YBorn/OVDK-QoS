/*
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2013 Intel Corporation. All rights reserved.
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

#include <getopt.h>

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_string_fns.h>
#include <rte_ip.h>
#include <rte_byteorder.h>

/* Number of packets to attempt to read from queue */
#define PKT_READ_SIZE  32u

/* define common names for structures shared between ovs_dpdk and client */
#define MP_CLIENT_RXQ_NAME "MProc_Client_%u_RX"
#define MP_CLIENT_TXQ_NAME "MProc_Client_%u_TX"
#define MP_CLIENT_FREE_Q_NAME "MProc_Client_%u_FREE_Q"
#define MP_CLIENT_NAME_LEN 32

#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

#define BASE_10 10

#define enqueue_mbufs_to_be_freed(queue, mbufs, n) \
  rte_ring_enqueue_bulk(queue, mbufs, n)

/* our client id number - tells us which rx queue to read, and tx 
 * queue to write to. */
static uint8_t client_id = 0;

/*
 * Given the queue name template and client id, get the queue.
 * Queue name template plus client id gives the final queue name used to
 * do the lookup.
 */
static inline struct rte_ring *
queue_lookup(const char *queue_name_template, unsigned id)
{

  static char queue_name[MP_CLIENT_NAME_LEN];
  struct rte_ring *ring;

  rte_snprintf(queue_name, sizeof(queue_name), queue_name_template, id);

  ring = rte_ring_lookup(queue_name);
  if (ring == NULL)
    rte_exit(EXIT_FAILURE, "Cannot get ring '%s'. Is server process running?\n",
             queue_name);
  return ring;
}

/*
 * print a usage message
 */
static void
usage(const char *progname)
{
	printf("\nUsage: %s [EAL args] -- -n <client_id>\n", progname);
}

/*
 * Convert the client id number from a string to an int.
 */
static int
parse_client_num(const char *client)
{
	char *end = NULL;
	unsigned long temp = 0;

	if (client == NULL || *client == '\0')
		return -1;

	temp = strtoul(client, &end, BASE_10);
	/* If valid string argument is provided, terminating '/0' character
	 * is stored in 'end' */
	if (end == NULL || *end != '\0')
		return -1;

	client_id = (uint8_t)temp;
	return 0;
}

/*
 * Parse the application arguments to the client app.
 */
static int
parse_app_args(int argc, char *argv[])
{
	int option_index = 0, opt = 0;
	char **argvopt = argv;
	const char *progname = NULL;
	static struct option lgopts[] = { 
		{NULL, 0, 0, 0 }
	};
	progname = argv[0];

	while ((opt = getopt_long(argc, argvopt, "n:s:d:", lgopts,
		&option_index)) != EOF){
		switch (opt){
			case 'n':
				if (parse_client_num(optarg) != 0){
					usage(progname);
					return -1;
				}
				break;
			default:
				usage(progname);
				return -1;
		}
	}

	return 0;
}

/*
 * Application main function - loops through
 * receiving and processing packets. Never returns
 */
int
main(int argc, char *argv[])
{
  struct rte_ring *rx_ring = NULL;
  struct rte_ring *tx_ring = NULL;
  struct rte_ring *free_q = NULL;
  int retval = 0;
  void *pkts[PKT_READ_SIZE];
  int ret = 0;
  unsigned rx_count, free_count;
  unsigned pkts_count;

  if ((retval = rte_eal_init(argc, argv)) < 0)
    return -1;

  argc -= retval;
  argv += retval;

  if (parse_app_args(argc, argv) < 0)
    rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");

  rx_ring = queue_lookup(MP_CLIENT_RXQ_NAME, client_id);
  tx_ring = queue_lookup(MP_CLIENT_TXQ_NAME, client_id);
  free_q = queue_lookup(MP_CLIENT_FREE_Q_NAME, client_id);

  RTE_LOG(INFO, APP, "Finished Process Init.\n");

  printf("\nClient process %d handling packets\n", client_id);
  printf("[Press Ctrl-C to quit ...]\n");

  for (;;) {
    rx_count = rte_ring_count(rx_ring);
    free_count = rte_ring_free_count(free_q);

    pkts_count = RTE_MIN(rx_count, free_count);
    pkts_count = RTE_MIN(pkts_count, PKT_READ_SIZE);

    if (unlikely(pkts_count == 0))
      continue;

    ret = rte_ring_dequeue_bulk(rx_ring, pkts, pkts_count);
    if (unlikely(ret < 0))
      continue;

    ret = rte_ring_enqueue_bulk(tx_ring, pkts, pkts_count);

    /*
     * There's a known issue with DPDK mempools per core caches being
     * accessed from host and guest applications. Due to this we can't call
     * rte_pktmbuf_free or rte_pktmbuf_alloc from the guest since this will
     * trigger an access to the underlying mempool cache possibly causing
     * memory corruption.
     *
     * In case we needed to free mbufs because a ring is full we basically
     * enqueue them into a special ring that will hold "mbufs to be freed".
     * The host app will be in charge to periodically check this ring and
     * free all the buffers in there. Check example below.
     *
     * A similar issue may be found in case we needed to allocate buffers
     * in the guest. This can be avoided if we added an "alloc" queue
     * where the guest could retrieve packets from. The host app will
     * be periodically allocating mbufs and adding them to this queue.
     * Add this new queue the same way the free_q queue is added.
     */
    if (ret == -ENOBUFS)
      enqueue_mbufs_to_be_freed(free_q, pkts, pkts_count);
  }

  return 0;
}
