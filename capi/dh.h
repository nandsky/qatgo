//
// Created by 朱宇 on 24/07/2017.
//

// 参考: pkcs#3

#ifndef QATCGO_DH_H
#define QATCGO_DH_H

#include <cpa_types.h>
#include <cpa.h>
#include <lac/cpa_cy_dh.h>
#include <semaphore.h>

typedef struct _DH_CTX_T {
    CpaInstanceHandle *cpaInstance;
    CpaCyDhPhase1KeyGenOpData* pCpaDhOpDataP1;
    CpaCyDhPhase2SecretKeyGenOpData* pCpaDhOpDataP2;

    CpaFlatBuffer* pLocalOctetStringPV;

    sem_t complate;
}QAT_DH_CTX;


// 生成DH公私钥的函数
int qat_dh_generate_key(QAT_DH_CTX *dh);

// 根据对方公钥和己方DH密钥来生成共享密钥的函数
int qat_dh_compute_key(QAT_DH_CTX *dh, unsigned char *key);

void qat_dhparams_print();
#endif //QATCGO_DH_H
