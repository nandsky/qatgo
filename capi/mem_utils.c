//
// Created by 朱宇 on 24/07/2017.
//

#include <stdlib.h>
#include "mem_utils.h"
#include "qae_mem.h"
#include "utils.h"
#include <memory.h>

void* qaeCryptoMemAlloc(size_t memsize)
{
    void *pAddr = qaeMemAllocNUMA(memsize, 0, 1);
    if (pAddr == NULL) {
        return NULL;
    }
    return pAddr;
}

void qaeCryptoMemFree(void *pMemAddr)
{
    void **p = (void*)&pMemAddr;
    if (NULL != *p) {
        qaeMemFreeNUMA(p);
        *p = NULL;
    }
}

void *copyAllocPinnedMemory(const unsigned char *ptr, int size)
{
    void *nptr = NULL;

    nptr = qaeCryptoMemAlloc(size);

    if (nptr == NULL) {
        return NULL;
    }
    memcpy(nptr, ptr, size);
    return nptr;
}

void freeFlatBuffer(CpaFlatBuffer *fb)
{
    if (fb->pData) {
        qaeCryptoMemFree(fb->pData);
        fb->pData = NULL;
    }
    fb->dataLenInBytes = 0;
}
