/**********************************************************************
 *  Name:           tc-server
 *  Description:    "tc" ultility backend
 *  Author:         Born
 *  Release:        1.0
 *  Date:           2013.8.5
 **********************************************************************/

#include<stdio.h>
#include<unistd.h>
#include<strings.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<linux/in.h>

#define BACKLOG 1
#define LEN     100
#define A       20
#define B       10

int make_server_socket(short portnum);

int main(int argc, char *argv[])
{
    int sockfd, fd;
    int n;
    char *xargv[A];

    sockfd = make_server_socket(atoi(argv[1]));
    if(sockfd == -1)
        return -1;

    printf("waiting for connecting\n");
    fd = accept(sockfd, NULL, NULL);
    if(fd == -1)  return -1;
    printf("connected\n");

    while(1)
    {
        char cargv[A][B];
        char buf[LEN] = {'\0'};
        int i, j, k, m;
        pid_t  pid;

        n = read(fd, buf, LEN);
        write(1, buf, n);
        printf("\n");
    
        for(i = 0, j = 0, k = 0, m = -1; buf[i] != '\0'; i++)
        {
            if(buf[i] != ' ')
            {
                if(i != m + 1)
                {
                    cargv[k][j] = '\0';
                    k++;
                    j = 0;
                }
                cargv[k][j] = buf[i];
                j++;
                m = i;
            }
        }
        cargv[k][j] = '\0';

        for(i = 0; i <= k; i++)
            xargv[i] = cargv[i];
        xargv[i] = NULL;

        if((pid = fork()) < -1)
            printf("fork failed\n");
        else if(pid == 0)
            execvp(xargv[0], xargv);
        else
            wait(NULL);
    }

        close(fd);
        close(sockfd);
}

int make_server_socket(short portnum)
{
    struct sockaddr_in addr;
    int sockfd;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    bzero((void *)&addr, sizeof(addr));
    
    addr.sin_port = htons(portnum);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if(-1 == bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)))
        return -1;
    if(-1 == listen(sockfd, BACKLOG))
        return -1;
    return sockfd;    
}
