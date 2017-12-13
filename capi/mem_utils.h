//
// Created by 朱宇 on 24/07/2017.
//

#ifndef QATCGO_MEM_UTILS_H
#define QATCGO_MEM_UTILS_H

#include <cpa_types.h>
#include <cpa.h>

// 申请内存
void* qaeCryptoMemAlloc(size_t memsize);

// 释放内存
void qaeCryptoMemFree(void *pMemAddr);

// 申请内存副本
void *copyAllocPinnedMemory(const unsigned char *ptr, int size);

void freeFlatBuffer(CpaFlatBuffer *fb);

#endif //QATCGO_MEM_UTILS_H
