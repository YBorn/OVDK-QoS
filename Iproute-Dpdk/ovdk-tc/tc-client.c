/*********************************************************************
 *  Name:           tc-client
 *  Description:    "tc" ultility frontend
 *  Author:         Born
 *  Release:        1.0
 *  Date:           2013.8.5
 **********************************************************************/

#include<stdio.h>
#include<strings.h>
#include<string.h>
#include<unistd.h>
#include<sys/socket.h>
//#include<linux/in.h>

#include <stdlib.h>
#include <syslog.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "SNAPSHOT.h"
#include "utils.h"
#include "tc_util.h"
#include "tc_common.h"

#define BACKLOG 1
#define LEN     100
#define A       20
#define B       10

int connect_to_server(char *addr, short portnum)
{
    int sockfd;
    struct sockaddr_in servadd;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&servadd, sizeof(servadd));
    servadd.sin_family = AF_INET;
    servadd.sin_port = htons(portnum);
    servadd.sin_addr.s_addr = inet_addr(addr);
    
    connect(sockfd, (struct sockaddr *) &servadd, sizeof(servadd));
    return sockfd;
}

int main(int argc, char **argv)
{
    int ret;
    int do_batching = 0;
    char *batchfile = NULL;


    int sockfd;
    int num, i;

    sockfd = connect_to_server(argv[1], atoi(argv[2]));
    printf("what you want to say\n");
    
    while(1){

        int i, j, k, m;
        char send[LEN] = {'\0'};
        char cargv[A][B];
        char *xargv[A];

        fgets(send, 100, stdin);
        for(i = 0; send[i] != '\n'; i++);
        send[i] = '\0';

//        write(1, buf, n); 
//        printf("\n");

        for(i = 0, j = 0, k = 0, m = -1; send[i] != '\0'; i++)
        {   
            if(send[i] != ' ')
            {   
                if(i != m + 1)
                {   
                    cargv[k][j] = '\0';
                    k++;
                    j = 0;
                }   
                cargv[k][j] = send[i];
                j++;
                m = i;
            }   
        }   
        cargv[k][j] = '\0';

        for(i = 0; i <= k; i++)
            xargv[i] = cargv[i];
        xargc = k + 1;

        while (xargc > 1) {
            if (xargv[1][0] != '-')
                break;
            if (matches(xargv[1], "-stats") == 0 ||
                    matches(xargv[1], "-statistics") == 0) {
                ++show_stats;
            } else if (matches(xargv[1], "-details") == 0) {
                ++show_details;
            } else if (matches(xargv[1], "-raw") == 0) {
                ++show_raw;
            } else if (matches(xargv[1], "-pretty") == 0) {
                ++show_pretty;
            } else if (matches(xargv[1], "-Version") == 0) {
                printf("tc utility, iproute2-ss%s\n", SNAPSHOT);
                return 0;
            } else if (matches(xargv[1], "-iec") == 0) {
                ++use_iec;
            } else if (matches(xargv[1], "-help") == 0) {
                usage();
                return 0;
            } else if (matches(xargv[1], "-force") == 0) {
                ++force;
            } else  if (matches(xargv[1], "-batch") == 0) {
                do_batching = 1;
                if (argc > 2)
                    batchfile = xargv[2];
                xargc--; xargv++;
            } else {
                fprintf(stderr, "Option \"%s\" is unknown, try \"tc -help\".\n", xargv[1]);
                return -1;
            }
            xargc--; xargv++;
        }

        if (do_batching)
            return batch(batchfile);

        if (xargc <= 1) {
            usage();
            return 0;
        }

        num = strlen(send);
        write(sockfd, send, num);
    }
    close(sockfd);
/*****************************************************
    tc_core_init();
    if (rtnl_open(&rth, 0) < 0) {
        fprintf(stderr, "Cannot open rtnetlink\n");
        exit(1);
    }

    ret = do_cmd(argc-1, argv+1);
    rtnl_close(&rth);

 *****************************************************/
    return ret;
}
