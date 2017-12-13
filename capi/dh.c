//
// Created by 朱宇 on 24/07/2017.
//

#include <stdlib.h>
#include <memory.h>


#include "qat.h"
#include "dh.h"
#include "utils.h"
#include "mem_utils.h"

static unsigned char primeP_768[] = {
        0xC7, 0x3B, 0x18, 0xB5, 0x71, 0xE1, 0xE0, 0x7C,
        0x70, 0x66, 0x5F, 0xD8, 0x8B, 0xD9, 0xC2, 0x55,
        0x3E, 0xD7, 0x09, 0x68, 0x80, 0xF2, 0x17, 0x1A,
        0x7A, 0x6D, 0xC9, 0x24, 0xF2, 0x5C, 0x84, 0x7D,
        0xB4, 0xC5, 0xA5, 0x40, 0x9A, 0x3F, 0xB7, 0xBD,
        0xD4, 0xD0, 0xE6, 0xA0, 0x01, 0xC5, 0x1E, 0xA7,
        0x60, 0x42, 0x2D, 0xF5, 0x16, 0xAF, 0x01, 0x6C,
        0xF7, 0xA5, 0x73, 0xCF, 0x36, 0xB3, 0x6E, 0x5C,
        0xE7, 0x2C, 0x18, 0x19, 0x5C, 0x21, 0x40, 0x1B,
        0xF4, 0xD5, 0xD9, 0xF4, 0x46, 0x08, 0xDA, 0x84,
        0x0B, 0x34, 0x8F, 0x80, 0xB9, 0x7C, 0x7B, 0xAF,
        0x23, 0xEA, 0x6E, 0xF2, 0x45, 0x8C, 0xC0, 0x0B
};


/*
 * Base of DH algorithm chosen by A.
 */
static unsigned char baseG1[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05
};

/*
 * Random value for DH algorithm chosen by A. It must match the
 * following condition:
 *
 *     0 < PrivateValueX < (PrimeP - 1)
 *
 * where PrimeP is the prime number (primeP_768, above).
 */
static unsigned char privateValueX[] = {
        0x00, 0x14, 0x34, 0x12, 0x93, 0xCE, 0xBF, 0x04,
        0x7C, 0x87, 0x16, 0x37, 0xEB, 0xB8, 0x75, 0xF0,
        0x69, 0x6D, 0xEA, 0x92, 0x5C, 0x3A, 0xDF, 0x87,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


static void qat_dhCallbackFn(void *pCallbackTag, CpaStatus status, void *pOpData,
                      CpaFlatBuffer * pPV)
{
    QAT_DH_CTX* ctx = NULL;
    if (pCallbackTag) {
        ctx = (QAT_DH_CTX*)pCallbackTag;
        DEBUG("callback success!\n");
        sem_post(&(ctx->complate));
    }
}


// Ya = a^Xa mod p
// p(primeP): prime number
// a(baseG): prime number, a < p
// Xa(privateValueX): Select private Xa
// @return: pLocalOctetStringPV： 已方公钥
int qat_dh_generate_key(QAT_DH_CTX *dh)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyDhPhase1KeyGenOpData *pCpaDhOpDataP1 = NULL;
    CpaFlatBuffer* pLocalOctetStringPV = NULL;

    DEBUG("start dh generate_key!\n");

    pCpaDhOpDataP1 = malloc(sizeof(CpaCyDhPhase1KeyGenOpData));
    dh->pCpaDhOpDataP1 = pCpaDhOpDataP1;
    memset(pCpaDhOpDataP1, 0, sizeof(CpaCyDhPhase1KeyGenOpData));

    // setup buffer list
    sem_init(&(dh->complate), 0, 0);

    // primeP
    pCpaDhOpDataP1->primeP.dataLenInBytes = sizeof(primeP_768);
    pCpaDhOpDataP1->primeP.pData = qaeCryptoMemAlloc(sizeof(primeP_768));
    if (NULL != pCpaDhOpDataP1->primeP.pData) {
        memcpy(pCpaDhOpDataP1->primeP.pData, primeP_768, sizeof(primeP_768));
    }

    // baseG
    pCpaDhOpDataP1->baseG.dataLenInBytes = sizeof(baseG1);
    pCpaDhOpDataP1->baseG.pData = qaeCryptoMemAlloc(sizeof(baseG1));
    if (NULL != pCpaDhOpDataP1->baseG.pData)
    {
        memcpy(pCpaDhOpDataP1->baseG.pData, baseG1, sizeof(baseG1));
    }

    // privateValueX
    pCpaDhOpDataP1->privateValueX.dataLenInBytes = sizeof(privateValueX);
    pCpaDhOpDataP1->privateValueX.pData = qaeCryptoMemAlloc(sizeof(privateValueX));
    if (NULL != pCpaDhOpDataP1->privateValueX.pData)
    {
        memcpy(pCpaDhOpDataP1->privateValueX.pData,
               privateValueX, sizeof(privateValueX));
    }

    pLocalOctetStringPV = malloc(sizeof(CpaFlatBuffer));
    if (CPA_STATUS_SUCCESS == status)
    {
        dh->pLocalOctetStringPV = pLocalOctetStringPV;
        pLocalOctetStringPV->dataLenInBytes = pCpaDhOpDataP1->primeP.dataLenInBytes;
        pLocalOctetStringPV->pData = qaeCryptoMemAlloc(pLocalOctetStringPV->dataLenInBytes);
    }

    status = cpaCyDhKeyGenPhase1(dh->cpaInstance,
                                 qat_dhCallbackFn, /* synchronous mode */
                                 (void*)dh,/* Opaque user data; */
                                 pCpaDhOpDataP1, /* Structure containing p, g and x*/
                                 pLocalOctetStringPV);

    sem_wait(&(dh->complate));

    sem_init(&(dh->complate), 0, 0);
    // todo 释放内存FlatBuffer
    return 0;
}

// K = Yb^Xa mod p
// Yb(remoteOctetStringPV) 为对方公钥
// Xa(privateValueX) 为己方私钥
// p(primeP) 为Prime
// @return 协商的密钥： pOctetStringSecretKey
int qat_dh_compute_key(QAT_DH_CTX *dh, unsigned char *key)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaFlatBuffer *pOctetStringSecretKey = NULL;
    CpaCyDhPhase2SecretKeyGenOpData* pCpaDhOpDataP2 = NULL;
    CpaCyDhPhase1KeyGenOpData* pCpaDhOpDataP1 = dh->pCpaDhOpDataP1;
    CpaFlatBuffer *pLocalOctetStringPV = dh->pLocalOctetStringPV;

    DEBUG("start dh compute_key!\n");
    pOctetStringSecretKey = malloc(sizeof(CpaFlatBuffer));

    pCpaDhOpDataP2 = malloc(sizeof(CpaCyDhPhase2SecretKeyGenOpData));

    memset(pCpaDhOpDataP2, 0, sizeof(CpaCyDhPhase2SecretKeyGenOpData));

    pCpaDhOpDataP2->primeP.pData = pCpaDhOpDataP1->primeP.pData;
    pCpaDhOpDataP2->primeP.dataLenInBytes =
            pCpaDhOpDataP1->primeP.dataLenInBytes;
    // 对方公钥
    pCpaDhOpDataP2->remoteOctetStringPV.pData =
            pLocalOctetStringPV->pData;
    pCpaDhOpDataP2->remoteOctetStringPV.dataLenInBytes =
            pLocalOctetStringPV->dataLenInBytes;
    // 已方私钥
    pCpaDhOpDataP2->privateValueX.pData =
            pCpaDhOpDataP1->privateValueX.pData;
    pCpaDhOpDataP2->privateValueX.dataLenInBytes =
            pCpaDhOpDataP1->privateValueX.dataLenInBytes;

    if (CPA_STATUS_SUCCESS == status)
    {
        /** Set the data length */
        pOctetStringSecretKey->dataLenInBytes =
                pCpaDhOpDataP1->primeP.dataLenInBytes;
        /** Allocate memory for the pOctetStringSecretKey pData*/
        pOctetStringSecretKey->pData = qaeCryptoMemAlloc(pOctetStringSecretKey->dataLenInBytes);
    }

    status = cpaCyDhKeyGenPhase2Secret(dh->cpaInstance,
                                       (const CpaCyGenFlatBufCbFunc)qat_dhCallbackFn,   /* CB function*/
                                       (void*)dh,/* pointer to the complete variable*/
                                       pCpaDhOpDataP2,/* structure containing p, the public value & x*/
                                       pOctetStringSecretKey);

    sem_wait(&(dh->complate));
    return 0;
}

void qat_dhparams_print()
{

}
