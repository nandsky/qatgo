//
// Created by 朱宇 on 23/07/2017.
//

#ifndef QATCGO_DSA_H
#define QATCGO_DSA_H

#include <semaphore.h>

typedef struct _DSA_CTX {
    char uuid[4];
    int async;
    sem_t complate;
}QAT_DSA_CTX;

#endif //QATCGO_DSA_H
