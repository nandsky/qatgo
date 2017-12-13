//
// Created by 朱宇 on 05/09/2017.
//

#ifndef CRY_CONN_H
#define CRY_CONN_H

#include "packet.h"


typedef struct _ConnCtx{
    int fd;
}ConnCtx;


int connect_tcp(ConnCtx* ctx);

int conn_set_blocking(ConnCtx* ctx, int blocking);

int conn_keepalive(ConnCtx* ctx, int interval);

int conn_set_tcp_nodelay(ConnCtx* ctx);

int conn_set_timeout(ConnCtx* ctx, const struct timeval tv);



Packet* conn_request(Packet* pkt);
#endif //CRY_CONN_H
