//
// Created by 朱宇 on 23/07/2017.
//

#ifndef QATCGO_CIPHER_H
#define QATCGO_CIPHER_H

#include <cpa_types.h>
#include <cpa.h>
#include <lac/cpa_cy_sym.h>

#include <semaphore.h>

# define HMAC_KEY_SIZE              64
# define TLS_VIRT_HDR_SIZE          13

typedef struct qat_op_params_t {
    CpaCySymOpData opData;

    CpaBufferList pSrcBufferList;
    CpaBufferList pDstBufferList;

    CpaFlatBuffer srcBufs[1];
    CpaFlatBuffer dstBufs[1];

}qat_op_params;

typedef struct _MD5_CTX {
    CpaInstanceHandle *cpaInstance;

    CpaCySymSessionCtx cpaSessCtx;
    CpaCySymSessionSetupData *sessionSetupData;

    qat_op_params* pOpParams;

    Cpa32U  srcDataLen;
    sem_t complate;
    unsigned char md[16];
}QAT_MD5_CTX;

unsigned char *MD5(unsigned char *d, unsigned int len, unsigned char* md);

int MD5_Init(QAT_MD5_CTX *c);
int MD5_Update(QAT_MD5_CTX *c, void *data, unsigned int len);
int MD5_Final(unsigned char *md, QAT_MD5_CTX *c);

#endif //QATCGO_CIPHER_H
