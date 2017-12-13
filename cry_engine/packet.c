//
// Created by 朱宇 on 14/09/2017.
//

#include "packet.h"
#include <memory.h>
#include <string.h>
#include "utils.h"


size_t pkt_append(Packet* pk, const BIGNUM* bn)
{
    char* old_buf = pk->data;
    int bn_len = BN_num_bytes(bn);

    pk->data = realloc(old_buf, pk->total + sizeof(int) + bn_len);
    if (!pk->data) {
        printf("some error happens!\n");
        return 0;
    }
    *(int*)(pk->data + pk->total) = bn_len;

    BN_bn2bin(bn, pk->data + pk->total + sizeof(int));
    pk->total = pk->total + sizeof(int) + bn_len;
    return pk->total;
}

size_t pkt_append_bf(Packet* pk, size_t len, const unsigned char* buf)
{
    pk->data = realloc(pk->data, pk->total + sizeof(int) + len);

    *(int*)(pk->data + pk->total) = (int)len;
    memcpy(pk->data + pk->total + sizeof(int), buf, len);

    pk->total = pk->total + sizeof(int) + len;
    return pk->total;
}

