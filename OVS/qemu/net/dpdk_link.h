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

#ifndef __DPDK_LINK_H__
#define __DPDK_LINK_H__

/* Number of packets to attempt to read from queue */
#define PACKET_READ_SIZE 32
#define MAX_NUM_CLIENTS 20
#define DPDK_LINK_MAX_FRAME_SIZE 9000

struct dpdk_buf {
    char *buf[DPDK_LINK_MAX_FRAME_SIZE]; /* large enough for jumbo packet */
    int size;
};

struct dpdk_open_args {
    int port;
    char *group;
    int mode;
};

int dpdk_link_send(int client_id, char *ofpbuf, int size);
int dpdk_link_recv(int client_id, struct dpdk_buf *);
int dpdk_link_close(int client_id);
int dpdk_link_open(int init_sock, char *name, void *args);
int dpdk_link_init(void);

#endif
