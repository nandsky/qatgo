//
// Created by 朱宇 on 23/07/2017.
//

#include <stdlib.h>
#include <stdio.h>
#include <memory.h>

#include "qat.h"
#include "utils.h"
#include "cipher.h"
#include "mem_utils.h"


static const CpaCySymSessionSetupData template_ssd = {
        .sessionPriority = CPA_CY_PRIORITY_HIGH,
        .symOperation = CPA_CY_SYM_OP_ALGORITHM_CHAINING, // CPA_CY_SYM_HASH_MD5
        .cipherSetupData = {
                .cipherAlgorithm = CPA_CY_SYM_CIPHER_AES_CBC,
                .cipherKeyLenInBytes = 0,
                .pCipherKey = NULL,
                .cipherDirection = CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT,
        },
        .hashSetupData = {
                .hashAlgorithm = CPA_CY_SYM_HASH_SHA1,
                .hashMode = CPA_CY_SYM_HASH_MODE_AUTH,
                .digestResultLenInBytes = 0,
                .authModeSetupData = {
                        .authKey = NULL,
                        .authKeyLenInBytes = HMAC_KEY_SIZE,
                        .aadLenInBytes = 0,
                },
                .nestedModeSetupData = {0},
        },
        .algChainOrder = CPA_CY_SYM_ALG_CHAIN_ORDER_HASH_THEN_CIPHER,
        .digestIsAppended = CPA_TRUE,
        .verifyDigest = CPA_FALSE,
        .partialsNotRequired = CPA_TRUE,

};

static const CpaCySymOpData template_opData = {
        .sessionCtx = NULL,
        .packetType = CPA_CY_SYM_PACKET_TYPE_FULL,
        .pIv = NULL,
        .ivLenInBytes = 0,
        .cryptoStartSrcOffsetInBytes = QAT_BYTE_ALIGNMENT,
        .messageLenToCipherInBytes = 0,
        .hashStartSrcOffsetInBytes = QAT_BYTE_ALIGNMENT - TLS_VIRT_HDR_SIZE,
        .messageLenToHashInBytes = 0,
        .pDigestResult = NULL,
        .pAdditionalAuthData = NULL
};

static void sym_callbackFn(void *callbackTag, CpaStatus status, const CpaCySymOp op_type,
                           void *op_data, CpaBufferList *dst_buffer, CpaBoolean verify_result)
{
    QAT_MD5_CTX* ctx = NULL;
    if (callbackTag) {
        ctx = (QAT_MD5_CTX*)callbackTag;
        DEBUG("callback success!\n");
        sem_post(&(ctx->complate));
    }
}

unsigned char *MD5(unsigned char *d, unsigned int len, unsigned char* md)
{
    QAT_MD5_CTX *ctx;

    ctx = malloc(sizeof(QAT_MD5_CTX));
    if (0 != MD5_Init(ctx)) {
        goto err;
    }

    if (0 != MD5_Update(ctx, d, len)) {
        goto err;
    }

    err:
    MD5_Final(md, ctx);
    return md;
}

// 初始化session
static int qat_md5_session_init(QAT_MD5_CTX *ctx)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U sessCtxSize = 0;
    // session setup
    CpaCySymSessionSetupData *ssd = malloc(sizeof(CpaCySymSessionSetupData));
    ctx->sessionSetupData = ssd;

    memcpy(ssd, &template_ssd, sizeof(template_ssd));
    ssd->symOperation = CPA_CY_SYM_OP_HASH;
    ssd->hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_MD5;
    ssd->hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_PLAIN;
    ssd->hashSetupData.digestResultLenInBytes = 16;

    ssd->digestIsAppended = CPA_FALSE;
    ssd->verifyDigest = CPA_FALSE;

    status = cpaCySymSessionCtxGetSize(ctx->cpaInstance, ssd, &sessCtxSize);
    if (CPA_STATUS_SUCCESS != status) {

        goto err_finish;
    }

    ctx->cpaSessCtx = qaeCryptoMemAlloc(sessCtxSize);
    if (!ctx->cpaSessCtx) {
        goto err_finish;
    }


    status = cpaCySymInitSession(ctx->cpaInstance, sym_callbackFn, ssd, ctx->cpaSessCtx);
    if (CPA_STATUS_SUCCESS != status) {
        goto err_finish;
    }
    return 0;

    err_finish:
    return -1;
}

static int qat_md5_setup_op_param(QAT_MD5_CTX *ctx)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U numFlatBuffer = 1;
    Cpa32U mSize = 0;
    qat_op_params *qop = NULL;
    CpaCySymOpData *opd = NULL;

    if (!ctx) {
        return -1;
    }

    ctx->pOpParams = malloc(sizeof(qat_op_params));
    if (NULL == ctx->pOpParams) {
        return -1;
    }

    qop = ctx->pOpParams;
    // setup flat
    qop->srcBufs[0].pData = NULL;
    qop->dstBufs[0].pData = NULL;

    // setup buffer list
    qop->pSrcBufferList.numBuffers = numFlatBuffer;
    qop->pSrcBufferList.pBuffers = qop->srcBufs;
    qop->pDstBufferList.numBuffers = numFlatBuffer;
    qop->pDstBufferList.pBuffers = qop->dstBufs;

    // setup meta data for buffer lists
    status = cpaCyBufferListGetMetaSize(ctx->cpaInstance, qop->pSrcBufferList.numBuffers, &mSize);
    if (status != CPA_STATUS_SUCCESS) {
        return -1;
    }
    if (mSize) {
        qop->pSrcBufferList.pPrivateMetaData = qaeCryptoMemAlloc(mSize);
        if (NULL == qop->pSrcBufferList.pPrivateMetaData) {
            DEBUG("malloc meta data failed\n");
        }
    }

    status = cpaCyBufferListGetMetaSize(ctx->cpaInstance, qop->pDstBufferList.numBuffers, &mSize);
    if (status != CPA_STATUS_SUCCESS) {
        return -1;
    }
    if (mSize) {
        qop->pDstBufferList.pPrivateMetaData = qaeCryptoMemAlloc(mSize);
        if (NULL == qop->pDstBufferList.pPrivateMetaData) {
            DEBUG("malloc meta data failed\n");
        }
    }

    //
    opd = &(ctx->pOpParams->opData);
    memcpy(opd, &template_opData, sizeof(template_opData));
    opd->sessionCtx = ctx->cpaSessCtx;

    return 0;
}

int MD5_Init(QAT_MD5_CTX *ctx)
{
    DEBUG("- MD5 start\n");

    ctx->cpaInstance = getNextCyInstance();
    if (0 != qat_md5_session_init(ctx)) {
        DEBUG("md5 session init failed\n");
    }

    if (0 != qat_md5_setup_op_param(ctx)) {
        DEBUG("md5 op param failed\n");
        return -1;
    }
    // setup buffer list
    sem_init(&(ctx->complate), 0, 0);

    return 0;
}

int MD5_Update(QAT_MD5_CTX *ctx, void *data, unsigned int len)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCySymOpData *opd = NULL;
    Cpa8U *srcData = NULL;
    Cpa32U srcDataSize = len;
    Cpa32U disgit_length = 16;
    qat_op_params* qop = NULL;

    if (NULL == ctx) {
        return -1;
    }

    qop = ctx->pOpParams;
    // capi buffer
    srcData = qaeCryptoMemAlloc(srcDataSize + disgit_length);
    if (NULL == srcData) {
        DEBUG("failed to malloc data buffer\n");
        return -1;
    }
    memcpy(srcData, data, srcDataSize);
    qop->srcBufs->dataLenInBytes = srcDataSize;
    qop->srcBufs->pData = srcData;


    // init opdata
    opd = &ctx->pOpParams->opData;
    opd->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
    opd->hashStartSrcOffsetInBytes = 0;
    opd->messageLenToHashInBytes = srcDataSize;
    opd->pDigestResult = srcData + srcDataSize;

    // 让src和dst一致
    status = cpaCySymPerformOp(
            ctx->cpaInstance, (void*)ctx, opd,
            &qop->pSrcBufferList, &qop->pSrcBufferList, NULL);

    DEBUG("op status: %d\n", status);

    sem_wait(&(ctx->complate));
    dumpPrint(opd->pDigestResult, disgit_length);
    // todo
    memcpy(ctx->md, opd->pDigestResult, 16);
    qaeCryptoMemFree(srcData);
    return 0;
}

int MD5_Final(unsigned char *md, QAT_MD5_CTX *ctx)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    if (NULL == ctx) {
        return 0;
    }

    if (ctx->pOpParams) {
        if (ctx->pOpParams->pSrcBufferList.pPrivateMetaData)
            qaeCryptoMemFree(ctx->pOpParams->pSrcBufferList.pPrivateMetaData);
        if (ctx->pOpParams->pDstBufferList.pPrivateMetaData)
            qaeCryptoMemFree(ctx->pOpParams->pDstBufferList.pPrivateMetaData);

        free(ctx->pOpParams);
        ctx->pOpParams = NULL;
    }

    if (ctx->cpaSessCtx) {
        status = cpaCySymRemoveSession(ctx->cpaInstance, ctx->cpaSessCtx);
        qaeCryptoMemFree(ctx->cpaSessCtx);
        if (ctx->sessionSetupData) {
            free(ctx->sessionSetupData);
            ctx->sessionSetupData = NULL;
        }
    }

    // todo
    memcpy(md, ctx->md, 16);
    free(ctx);
    ctx = NULL;
    DEBUG("- MD5 finish\n");
    return 0;
}
