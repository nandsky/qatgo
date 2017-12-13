//
// Created by 朱宇 on 14/09/2017.
//

#ifndef CRY_PACKET_H
#define CRY_PACKET_H

#include <openssl/ossl_typ.h>
#include <openssl/bn.h>

typedef struct _Packet{
    size_t total;
    unsigned char* data;
}Packet;

size_t pkt_append(Packet*, const BIGNUM*);
size_t pkt_append_bf(Packet*, size_t len, const unsigned char* buf);

#endif //CRY_PACKET_H
