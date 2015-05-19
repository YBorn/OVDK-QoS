#ifndef __TC_CORE_H_
#define __TC_CORE_H_

#include <stdio.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "core/sch_rtnetlink.h"
#include "core/netlink_api.h"

#define RTE_LOGTYPE_QoS RTE_LOGTYPE_USER1

#define OPEN_FILE "/home/born/DPDK-OVS/dpdk-ovs.pid"
#define NL_RCVBUF 4096UL


int ERR;
struct rtnl_handle rth;

static int write_pid() {
    int num, fd;
    char pid[10] = {'\0'};

    num = sprintf(pid, "%u", getpid());
    RTE_LOG(INFO, QoS, "TC PID is %d.\n", getpid());

    if((fd = open(OPEN_FILE, O_TRUNC|O_RDWR)) < 0)
        RTE_LOG(ERR, QoS, "Open file <dpdk-ovs.pid> failed.\n");
    if((write(fd, pid, num+1)) < 0)
        RTE_LOG(ERR, QoS, "Write file <dpdk-ovs.pid> Error.\n");
    if(close(fd) < 0)
        RTE_LOG(ERR, QoS, "Close file <dpdk-ovs.pid> failed.\n");
    return 0;
}

/**
 * Traffic control implementation core program
 *
 * */

// static int do_tc_core(int err) {
//     int ret;
// 
//     ERR = err;
// 
//     if(rtnl_open(&rth, 0) < 0) {
//         fprintf(stderr, "Cannot open rtnetlink\n");
//     }
//     
//     char    rcvbuf[NL_RCVBUF];
//     memset(rcvbuf, 0, sizeof(rcvbuf));
//    
//     struct iovec iov = {
//         .iov_base = rcvbuf,
//         .iov_len = sizeof(rcvbuf),
//     };
// 
//     if((int)iov.iov_len < nlmsg_total_size(0)) {
//         RTE_LOG(WARNING, QoS,"netlink rcvbuf is too smalll");
//         return -1;
//     }
// 
//     struct msghdr rcv_msg = {
//         .msg_name       = &rth.peer,
//         .msg_namelen    = sizeof(struct sockaddr_nl),
//         .msg_iov        = &iov,
//         .msg_iovlen     = 1,
//     };
// 
//     int status;    
//     struct iovec *skb;
//     while(1) {
//         RTE_LOG(INFO, QoS, "before recive a message\n");
//         status = recvmsg(rth.fd, &rcv_msg, 0);
//         RTE_LOG(INFO, QoS, "after recive a message\n");
//         skb = rcv_msg.msg_iov;
// 
//         if (status > 0)
//             printf("Receive a Message: %s\n"
//                     "Message len: %lu\n",
//                     (char *)(skb->iov_base),
//                     (skb->iov_len));
//         else
//             RTE_LOG(ERR, QoS, "Error Occur");
// 
//         rtnetlink_rcv(skb);
//     }
//     
//     rtnl_close(&rth);
// 
//     return ret;
// }

#endif
