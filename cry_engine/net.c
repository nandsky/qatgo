//
// Created by 朱宇 on 05/09/2017.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include "net.h"
#include "utils.h"


static int connect_fd = -1;


static int conn_close(ConnCtx* ctx)
{
    if (ctx && ctx->fd > 0) {
        close(ctx->fd);
        ctx->fd = -1;
    }
    return 0;
}

static int conn_set_reuse_addr(ConnCtx* ctx) {
    int on = 1;
    if (setsockopt(ctx->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) {
        conn_close(ctx->fd);
        return -1;
    }
    return 0;
}

// 创建unix，还是tcp
static int conn_create_sock(ConnCtx* ctx, int type)
{
    int s;
    if ((s = socket(type, SOCK_STREAM, 0)) == -1) {
        return -1;
    }
    ctx->fd = s;
    if (type == AF_INET) {
        if (conn_set_reuse_addr(ctx) != 0) {
            return -2;
        }
    }
    return 0;
}

int connect_tcp(ConnCtx* ctx)
{
    int sockfd;
    struct sockaddr_in serveraddr;
//    char *hostname = "192.168.47.129";
    char *hostname = "127.0.0.1";
    int port = 50051;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("ERROR opening socket\n");
        return -1;
    }

    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = inet_addr(hostname);
    serveraddr.sin_port = htons(port);//默认以8080端口连接

//    if (set_non_blocking(sockfd) < 0) {
//        printf("set non blocking failed!\n");
//        return -1;
//    }

    if (connect(sockfd, (struct sockaddr*)&serveraddr,sizeof(serveraddr)) < 0) {
        printf("connect: failed\n");
        return -1;
    }

    connect_fd = sockfd;
    return sockfd;
}


int conn_set_blocking(ConnCtx* ctx, int blocking)
{
    int flags;
    if ((flags = fcntl(ctx->fd, F_GETFL)) == -1) {
        printf("fcntl(F_GETFL)");
        conn_close(ctx->fd);
        return -1;
    }
    if (blocking)
        flags &= ~O_NONBLOCK;
    else
        flags |= O_NONBLOCK;
    if (fcntl(ctx->fd, F_SETFL, flags) == -1) {
        printf("fcntl(F_SETFL)");
        conn_close(ctx->fd);
        return -2;
    }
    return 0;
}

int conn_keepalive(ConnCtx* ctx, int interval)
{
    return 0;
}

int conn_set_tcp_nodelay(ConnCtx* ctx)
{
    int yes = 1;
    if (setsockopt(ctx->fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes)) == -1) {
        printf("setsockopt(TCP_NODELAY)");
        conn_close(ctx->fd);
        return -1;
    }
    return 0;
}

int conn_set_timeout(ConnCtx* ctx, const struct timeval tv)
{
    return 0;
}


Packet* conn_request(Packet* pkt)
{
    size_t n = 0;
    Packet *ret = NULL;
    int sock_fd = 0;
    unsigned char recv_buf[5000];

    sock_fd = connect_tcp(NULL);
    if (sock_fd < 0) {
        return -1;
    }

    n = write(sock_fd, pkt->data, (int)(pkt->total));
    printf("pkt: %d, send: %d\n", pkt->total, n);
    dumpPrint(pkt->data, pkt->total);
    n = read(sock_fd, recv_buf, 5000);

    if (n < 1) {
        printf("recv failed!\n");
        close(sock_fd);
        return ret;
    }

    printf("recv n: %d\n", n);
    ret = malloc(sizeof(Packet));
    ret->data = malloc(n);
    memcpy(ret->data, recv_buf, n);
    ret->total = n;
    close(sock_fd);
    return ret;
}
