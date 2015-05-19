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

#ifndef _COMMON_H_
#define _COMMON_H_

#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

/* define common names for structures shared between ovs_dpdk and client */
#define MP_CLIENT_RXQ_NAME "MProc_Client_%u_RX"
#define MP_CLIENT_TXQ_NAME "MProc_Client_%u_TX"
#define PKTMBUF_POOL_NAME "MProc_pktmbuf_pool"
/*
 * This is the maximum number of digits that are required to represent
 * the largest possible unsigned int on a 64-bit machine. It will be used
 * to calculate the length of the strings above when %u is substituted.
 */
#define MAX_DIGITS_UNSIGNED_INT 20

/*
 * Given the rx queue name template above, get the queue name
 */
static inline const char *
get_rx_queue_name(unsigned id)
{
	static char buffer[sizeof(MP_CLIENT_RXQ_NAME) + MAX_DIGITS_UNSIGNED_INT];

	rte_snprintf(buffer, sizeof(buffer), MP_CLIENT_RXQ_NAME, id);
	return buffer;
}

static inline const char *
get_tx_queue_name(unsigned id)
{
	static char buffer[sizeof(MP_CLIENT_TXQ_NAME) + MAX_DIGITS_UNSIGNED_INT];

	rte_snprintf(buffer, sizeof(buffer), MP_CLIENT_TXQ_NAME, id);
	return buffer;
}

#endif
