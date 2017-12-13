//
// Created by 朱宇 on 23/07/2017.
//

#include <memory.h>
#include <stdlib.h>
#include "utils.h"
#include "mem_utils.h"
#include "qae_mem.h"

void dumpPrint(unsigned char * data, int len)
{
    int i;
    printf("total len: %d\n", len);
    for (i = 0; i < len; i++) {
        printf("0x%02x, ", data[i]);
    }
    printf("\n");
    for(i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

void qat_hex_dump(const char *func, const char *var, const unsigned char p[],
                  int l)
{
    int i;

    fprintf(stderr, "%s: %s: Length %d, Address %p", func, var, l, p);
    if (NULL != p && l != 0) {
        for (i = 0; i < l; i++) {
            if (i % 16 == 0)
                fputc('\n', stderr);
            else if (i % 8 == 0)
                fputs("- ", stderr);
            fprintf(stderr, "%02x ", p[i]);
        }
    }
    fputc('\n', stderr);
}

int stripe_to_cflatbuffer(CpaFlatBuffer* dst, Stripe* src)
{
    if (src == NULL || src->len < 1) {
        DEBUG("malloc failed\n");
        return -1;
    }
    dst->dataLenInBytes = src->len;
    dst->pData = qaeCryptoMemAlloc(dst->dataLenInBytes);
    if (NULL == dst->pData) {
        return -1;
    }
    memcpy(dst->pData, src->data, dst->dataLenInBytes);
    return 0;
}

int buffer_to_stripe(Stripe* dst, unsigned char* src, int slen)
{
    if (src == NULL || slen < 1) {
        DEBUG("malloc failed\n");
        return -1;
    }
    dst->data = malloc(slen);
    dst->len = slen;
    memcpy(dst->data, src, slen);
    return 0;
}

// TODO: 修改返回值
int buffer_to_cflatbuffer(CpaFlatBuffer* dst, unsigned char* src, int slen)
{
    if (src == NULL || slen < 1) {
        DEBUG("malloc failed\n");
        return -1;
    }
    dst->dataLenInBytes = slen;
    dst->pData = qaeCryptoMemAlloc(dst->dataLenInBytes);
    if (NULL == dst->pData) {
        return -1;
    }
    memcpy(dst->pData, src, dst->dataLenInBytes);
    return 0;
}

//
int cflatbuffer_to_stripe(Stripe* dst, CpaFlatBuffer* src)
{
    // 如果dst不为空，则不允许申请拷贝
    if (dst == NULL || dst->len != 0 || dst->data != NULL) {
        return -1;
    }

    dst->len = src->dataLenInBytes;
    dst->data = malloc(dst->len);
    if (dst->data == NULL) {
        return -1;
    }
    memcpy(dst->data, src->pData, dst->len);
    return 0;
}
