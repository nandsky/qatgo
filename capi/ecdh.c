//
// Created by 朱宇 on 10/08/2017.
//

#include <memory.h>
#include <stdlib.h>
#include <lac/cpa_cy_ec.h>
#include "ecdh.h"
#include "mem_utils.h"
#include "callback.h"

int _ecdh_complete(QAT_ECDH_CTX *ctx, CpaBoolean multiplyStatus, CpaFlatBuffer * pXk, CpaFlatBuffer * pYk);

void qat_ecCallbackFn(void *pCallbackTag, CpaStatus status, void *pOpData,
                      CpaBoolean multiplyStatus, CpaFlatBuffer * pXk,
                      CpaFlatBuffer * pYk)
{
    //int rc = 0;
    if (pCallbackTag) {
        QAT_ECDH_CTX* ctx = (QAT_ECDH_CTX*) pCallbackTag;
        // 完成处理
        if (0 != _ecdh_complete(ctx, multiplyStatus, pXk, pYk)) {
            DEBUG("complete failed!\n");
        } else {
            DEBUG("complete success!\n");
        }
        // 完成通知
        if (ctx->async == 0) {
            sem_post(&(ctx->complete));
        } else {
            // 给上层通知
            notify_completion_port((const unsigned char*)ctx->uuid);
        }
    }
}

int _free_ctx(QAT_ECDH_CTX* ctx);

// cpaCyEcPointMultiply
int qat_ecdh_compute_key(QAT_ECDH_CTX* ctx)
{
    CpaInstanceHandle* cyInstance = NULL;
    CpaStatus status;
    CpaCyEcPointMultiplyOpData *opData = NULL;
    CpaFlatBuffer *pResultX = NULL;
    CpaFlatBuffer *pResultY = NULL;
    //CpaBoolean bEcStatus;
    int buflen = 0;

    opData = (CpaCyEcPointMultiplyOpData *)
            malloc(sizeof(CpaCyEcPointMultiplyOpData));
    if (opData == NULL) {
        //WARN("Failure to allocate opData\n");
        //QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_OPDATA_MALLOC_FAILURE);
        return -1;
    }

    opData->k.pData = NULL;
    opData->xg.pData = NULL;
    opData->yg.pData = NULL;
    opData->a.pData = NULL;
    opData->b.pData = NULL;
    opData->q.pData = NULL;

    /* To instruct the Quickassist API not to use co-factor */
    opData->h.pData = NULL;
    opData->h.dataLenInBytes = 0;

    ctx->opData = opData;

    if (0 != stripe_to_cflatbuffer(&(opData->a), &(ctx->ec_key.group.a))
        || 0 != stripe_to_cflatbuffer(&(opData->b), &(ctx->ec_key.group.b))
        || 0 != stripe_to_cflatbuffer(&(opData->xg), &(ctx->ec_key.group.xg))
        || 0 != stripe_to_cflatbuffer(&(opData->yg), &(ctx->ec_key.group.yg))
        || 0 != stripe_to_cflatbuffer(&(opData->q), &(ctx->ec_key.group.p_or_q))
        || 0 != stripe_to_cflatbuffer(&(opData->k), &(ctx->ec_key.priv_key))) {
        DEBUG("create phy memory failed!\n");
        return -1;
    }
    buflen = ctx->ec_key.group.order_or_n.len;

    pResultX = (CpaFlatBuffer *) malloc(sizeof(CpaFlatBuffer));
    if (pResultX == NULL) {
        return -1;
    }
    pResultX->pData = qaeCryptoMemAlloc(buflen);
    if (pResultX->pData == NULL) {
        return -1;
    }
    pResultX->dataLenInBytes = (Cpa32U) buflen;
    pResultY = (CpaFlatBuffer *) malloc(sizeof(CpaFlatBuffer));
    if (!pResultY) {
        return -1;
    }
    pResultY->pData = qaeCryptoMemAlloc(buflen);
    if (pResultY->pData == NULL) {
        return -1;
    }
    pResultY->dataLenInBytes = (Cpa32U) buflen;

    do{
        DEBUG("before !\n");
        status = cpaCyEcPointMultiply(cyInstance,
                                      qat_ecCallbackFn,
                                      ctx,
                                      opData,
                                      &ctx->pMultiplyStatus, // 异步模式下，该参数始终不会被赋值
                                      pResultX,
                                      pResultY);
    }
    while(CPA_STATUS_RETRY==status);
    if(CPA_STATUS_SUCCESS != status)
    {
        DEBUG("ECDSA Sign function failed with status:%d\n", status);
        return status;
    }
    DEBUG("wait for result!\n");
    // 同步情况下
    if (!ctx->async) {
        sem_wait(&(ctx->complete));
        if (0 != _ecdh_complete(ctx, ctx->pMultiplyStatus, pResultX, pResultY)) {
            DEBUG("完成失败！\n");
        } else {
            DEBUG("成功完成！\n");
        }
        return 0;
    }
    return 0;
}

int qat_ecdh_generate_key(QAT_ECDH_CTX *ctx)
{
    return 0;
}

QAT_ECDH_CTX* QAT_ECDH_CTX_new(
        char* uuid,
        unsigned char* curve_a, int curve_a_len,
        unsigned char* curve_b, int curve_b_len,
        unsigned char* curve_p, int curve_p_len,
        unsigned char* order, int order_len,
        unsigned char* generator_x, int generator_x_len,
        unsigned char* generator_y, int generator_y_len,
        unsigned char* private_key, int private_key_len)
{
    QAT_ECDH_CTX* ret = malloc(sizeof(QAT_ECDH_CTX));
    memset(ret, 0, sizeof(QAT_ECDH_CTX));
    memcpy(ret->uuid, uuid, 3);
    ret->async = 0;
    // curve参数
    buffer_to_stripe(&(ret->ec_key.group.a), curve_p, curve_p_len);
    ret->ec_key.group.a.data[curve_p_len-1] = 0xFC;
    buffer_to_stripe(&(ret->ec_key.group.b), curve_b, curve_b_len);
    buffer_to_stripe(&(ret->ec_key.group.p_or_q), curve_p, curve_p_len);
    buffer_to_stripe(&(ret->ec_key.group.order_or_n), order, order_len);
    buffer_to_stripe(&(ret->ec_key.group.xg), generator_x, generator_x_len);
    buffer_to_stripe(&(ret->ec_key.group.yg), generator_y, generator_y_len);
    // 私钥值
    buffer_to_stripe(&(ret->ec_key.priv_key), private_key, private_key_len);

    if (ret->async == 0) {
        sem_init(&(ret->complete), 0, 0);
    }
    return ret;
}

//
int _ecdh_complete(QAT_ECDH_CTX *ctx, CpaBoolean multiplyStatus, CpaFlatBuffer * pXk, CpaFlatBuffer * pYk)
{
    DEBUG("multiplyStatus: %d\n", multiplyStatus);
    ctx->pMultiplyStatus = multiplyStatus;

    if (pXk != NULL && pYk != NULL) {
        ctx->out_px.len = pXk->dataLenInBytes;
        if (0 != cflatbuffer_to_stripe(&ctx->out_px, pXk)) {
            return -1;
        }
        if (0 != cflatbuffer_to_stripe(&ctx->out_py, pYk)) {
            return -1;
        }
    }

    return 0;
}

// 释放内存
int _free_ctx(QAT_ECDH_CTX* ctx)
{
    if (ctx->out_px.data) {
        free(ctx->out_px.data);
        ctx->out_px.len = 0;
    }
    if (ctx->out_py.data) {
        free(ctx->out_py.data);
        ctx->out_px.len = 0;
    }
    return 0;
}

