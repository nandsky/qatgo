//
// Created by 朱宇 on 25/07/2017.
//

#include <lac/cpa_cy_ecdsa.h>
#include <memory.h>
#include "qat.h"
#include "ecdsa.h"
#include "qae_mem.h"
#include "callback.h"
#include "mem_utils.h"
#include "dump.h"

int dumpCurve(QAT_ECDSA_CTX *ret);

// random data
char demo_k[] = {
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
};

int _ecdsa_complete(QAT_ECDSA_CTX *ctx, CpaBoolean verifyOrSignStatus);

void ecdsaPerformCallback(void *pCallbackTag,
                          CpaStatus status,
                          void *pOpData,
                          CpaBoolean verifyOrSignStatus)
{
    if (pCallbackTag) {
        QAT_ECDSA_CTX* ctx = (QAT_ECDSA_CTX*) pCallbackTag;

        // 完成处理
        if (0 != _ecdsa_complete(ctx, verifyOrSignStatus)) {
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

/* Callback to indicate QAT completion of ECDSA Sign */
void qat_ecdsaSignCallbackFn(void *pCallbackTag, CpaStatus status,
                             void *pOpData, CpaBoolean bEcdsaSignStatus,
                             CpaFlatBuffer * pResultR,
                             CpaFlatBuffer * pResultS)
{
    ecdsaPerformCallback(pCallbackTag, status, pOpData, bEcdsaSignStatus);
}

/* Callback to indicate QAT completion of ECDSA Verify */
void qat_ecdsaVerifyCallbackFn(void *pCallbackTag, CpaStatus status,
                               void *pOpData, CpaBoolean bEcdsaVerifyStatus)
{
    ecdsaPerformCallback(pCallbackTag, status, pOpData, bEcdsaVerifyStatus);
}

// cpaCyEcdsaSignRS
int qat_ecdsa_do_sign_rs(
        QAT_ECDSA_CTX *ctx, unsigned char* digest, int digest_len,
        unsigned char* sign_r, unsigned char* sign_s)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaInstanceHandle* cyInstance = NULL;
    //CpaBoolean signStatus = CPA_FALSE;
    CpaCyEcdsaSignRSOpData* opData;
    CpaCyEcdsaSignRSCbFunc signRSCbFunc = NULL;
    int bufferLen = 0;

    CpaFlatBuffer *pResultR;
    CpaFlatBuffer *pResultS;

    DEBUG("- START\n");
    signRSCbFunc = qat_ecdsaSignCallbackFn;
    opData = malloc(sizeof(CpaCyEcdsaSignRSOpData));
    if (!opData) {
        DEBUG("malloc failed!\n");
        return -1;
    }
    memset(opData, 0, sizeof(CpaCyEcdsaSignRSOpData));
    ctx->signRSOpdata = opData;
    ctx->opType = ECDSA_OP_TYPE_SIGN;

    opData->fieldType = ctx->ec_key.fieldType;
    if (0 != stripe_to_cflatbuffer(&(opData->a), &(ctx->ec_key.group.a))
        || 0 != stripe_to_cflatbuffer(&(opData->b), &(ctx->ec_key.group.b))
        || 0 != stripe_to_cflatbuffer(&(opData->xg), &(ctx->ec_key.group.xg))
        || 0 != stripe_to_cflatbuffer(&(opData->yg), &(ctx->ec_key.group.yg))
        || 0 != stripe_to_cflatbuffer(&(opData->q), &(ctx->ec_key.group.p_or_q))
        || 0 != stripe_to_cflatbuffer(&(opData->n), &(ctx->ec_key.group.order_or_n))
        || 0 != stripe_to_cflatbuffer(&(opData->d), &(ctx->ec_key.priv_key))) {
        DEBUG("create phy memory failed!\n");
        return -1;
    }

    // TODO: 需要将digest转为m
    buffer_to_cflatbuffer(&(opData->m), digest, digest_len);
    // TODO: n 和 k可根据入参变化而变化
    dumpPrint(opData->m.pData, opData->m.dataLenInBytes);
    // 产生随机数
//    rd = malloc(ctx->ec_key.order_or_n.len);
//    DEBUG("K size: %d\n", ctx->ec_key.order_or_n.len);
//    if (NULL == rd) {
//        return -1;
//    }
//    memset(rd, 1, ctx->ec_key.order_or_n.len);

    buffer_to_cflatbuffer(&(opData->k), (unsigned char*)demo_k, sizeof(demo_k));
    dumpPrint(opData->k.pData, opData->k.dataLenInBytes);

    bufferLen = ctx->ec_key.group.order_or_n.len;
    // R & S
    pResultR = malloc(sizeof(CpaFlatBuffer));
    if (NULL == pResultR) {
        DEBUG("alloc failed\n");
        return -1;
    }
    pResultR->pData = qaeMemAlloc(bufferLen);
    pResultR->dataLenInBytes = bufferLen;
    memset(pResultR->pData, 0, bufferLen);
    // OUT_S
    pResultS = malloc(sizeof(CpaFlatBuffer));
    if (NULL == pResultS) {
        DEBUG("alloc failed\n");
        return -1;
    }
    pResultS->pData = qaeMemAlloc(bufferLen);
    pResultS->dataLenInBytes = bufferLen;
    memset(pResultS->pData, 0, bufferLen);

    ctx->out_cb_r = pResultR;
    ctx->out_cb_s = pResultS;
    ctx->out_r = sign_r;
    ctx->out_s = sign_s;

    /*perform the sign operation*/
    cyInstance = getNextCyInstance();

    DUMP_ECDSA_SIGN(cyInstance, opData, ctx->out_cb_r, ctx->out_cb_s);
    do{
        DEBUG("before !\n");
        status = cpaCyEcdsaSignRS(cyInstance,
                                  qat_ecdsaSignCallbackFn,
                                  ctx,
                                  opData,
                                  &ctx->signStatus,// 异步模式下，该参数始终不会被赋值
                                  pResultR,
                                  pResultS);
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
        if (0 != _ecdsa_complete(ctx, ctx->signStatus)) {
            DEBUG("完成失败！\n");
        } else {
            DEBUG("成功完成！\n");
        }
        return 0;
    }
    return 0;

}

int qat_ecdsa_do_verify(QAT_ECDSA_CTX *ctx, unsigned char* digest, int digest_len,
                        unsigned char* r, int r_len, unsigned char* s, int s_len,
                        unsigned char* success)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle* cyInstance = NULL;
    CpaCyEcdsaVerifyCbFunc cbFunc = NULL;
    CpaCyEcdsaVerifyOpData* opData = NULL;
    //CpaBoolean verifyStatus1 = CPA_FALSE;

    DEBUG("- START\n");

    cbFunc = ecdsaPerformCallback;
    opData = malloc(sizeof(CpaCyEcdsaVerifyOpData));
    memset(opData, 0, sizeof(CpaCyEcdsaVerifyOpData));
    ctx->verifyOpData = opData;
    ctx->opType = ECDSA_OP_TYPE_VERIFY;

    //
    opData->fieldType = ctx->ec_key.fieldType;
    opData->fieldType = CPA_CY_EC_FIELD_TYPE_PRIME;

    if (0 != stripe_to_cflatbuffer(&(opData->a), &(ctx->ec_key.group.a))
        || 0 != stripe_to_cflatbuffer(&(opData->b), &(ctx->ec_key.group.b))
        || 0 != stripe_to_cflatbuffer(&(opData->xg), &(ctx->ec_key.group.xg))
        || 0 != stripe_to_cflatbuffer(&(opData->yg), &(ctx->ec_key.group.yg))
        || 0 != stripe_to_cflatbuffer(&(opData->q), &(ctx->ec_key.group.p_or_q))
        || 0 != stripe_to_cflatbuffer(&(opData->n), &(ctx->ec_key.group.order_or_n))
        || 0 != stripe_to_cflatbuffer(&(opData->xp), &(ctx->ec_key.pub_key.x))
        || 0 != stripe_to_cflatbuffer(&(opData->yp), &(ctx->ec_key.pub_key.y))) {
        DEBUG("create phy memory failed!\n");
        return -1;
    }

    // TODO: 将digest转为m
    buffer_to_cflatbuffer(&(opData->m), digest, digest_len);

    // TODO: 应该从sig中获取s和r
    buffer_to_cflatbuffer(&(opData->r), r, r_len);
    buffer_to_cflatbuffer(&(opData->s), s, s_len);
    // get instance
    ctx->out_success = success;
    cyInstance = getNextCyInstance();

    DUMP_ECDSA_VERIFY(cyInstance, opData);
    do
    {
        status = cpaCyEcdsaVerify(cyInstance,
                                  cbFunc,
                                  ctx,
                                  opData,
                                  &ctx->verifyStatus);// 异步模式下，该参数始终不会被赋值
    } while (CPA_STATUS_RETRY == status);
    if(CPA_STATUS_SUCCESS != status)
    {
        DEBUG("ECDSA Verify function failed with status:%d\n", status);
        return status;
    }

    // 43E3AF2A0DB9086750976877650F426D2157A45E10DE646FF857198B226DF0D4B2243408E03BA711D9C34C51CB344413
    // 997F5E56BFB426F6286FD8B878E7D106F537F71E89970E675D0D20C7F446506E99C45BEDD29DD520BB9DD4546F6155E7
    // 同步情况下
    if (!ctx->async) {
        sem_wait(&(ctx->complete));
        DEBUG("--call status: %d, -verify status: %d, haha(false): %d\n", status, ctx->verifyStatus, (0==1));
        if (0 != _ecdsa_complete(ctx, ctx->verifyStatus)) {
            DEBUG("完成失败！\n");
        } else {
            DEBUG("成功完成！\n");
        }
        return 0;
    }
    return 0;
}

QAT_ECDSA_CTX* QAT_ECDSA_CTX_new(char* uuid,
                                 unsigned char* curve_a, int curve_a_len,
                                 unsigned char* curve_b, int curve_b_len,
                                 unsigned char* curve_p, int curve_p_len,
                                 unsigned char* order, int order_len,
                                 unsigned char* point_x, int point_x_len,
                                 unsigned char* point_y, int point_y_len,
                                 unsigned char* generator_x, int generator_x_len,
                                 unsigned char* generator_y, int generator_y_len,
                                 unsigned char* private_key, int private_key_len
)
{
    DEBUG("- START\n");
    QAT_ECDSA_CTX* ret = malloc(sizeof(QAT_ECDSA_CTX));

    memset(ret, 0, sizeof(QAT_ECDSA_CTX));
    memcpy(ret->uuid, uuid, 3);
    ret->async = 0;
    ret->ec_key.fieldType = CPA_CY_EC_FIELD_TYPE_PRIME;

    ret->verifyStatus = CPA_FALSE;
    // curve参数
    buffer_to_stripe(&(ret->ec_key.group.a), curve_p, curve_p_len);
    ret->ec_key.group.a.data[curve_p_len-1] = 0xFC;
    buffer_to_stripe(&(ret->ec_key.group.b), curve_b, curve_b_len);
    buffer_to_stripe(&(ret->ec_key.group.p_or_q), curve_p, curve_p_len);
    buffer_to_stripe(&(ret->ec_key.group.xg), generator_x, generator_x_len);
    buffer_to_stripe(&(ret->ec_key.group.yg), generator_y, generator_y_len);
    buffer_to_stripe(&(ret->ec_key.group.order_or_n), order, order_len);
    // 公钥值
    buffer_to_stripe(&(ret->ec_key.pub_key.x), point_x, point_x_len);
    buffer_to_stripe(&(ret->ec_key.pub_key.y), point_y, point_y_len);
    // 私钥值
    buffer_to_stripe(&(ret->ec_key.priv_key), private_key, private_key_len);

    if (ret->async == 0) {
        sem_init(&(ret->complete), 0, 0);
    }
    return ret;
}

int _free_ecdsa(QAT_ECDSA_CTX *ctx)
{
    if (ctx->opType == ECDSA_OP_TYPE_VERIFY) {
        CpaCyEcdsaVerifyOpData* op = (CpaCyEcdsaVerifyOpData*) ctx->verifyOpData;
        freeFlatBuffer(&op->a);
        freeFlatBuffer(&op->b);
        freeFlatBuffer(&op->xg);
        freeFlatBuffer(&op->xg);
        freeFlatBuffer(&op->xp);
        freeFlatBuffer(&op->yp);
        freeFlatBuffer(&op->q);
        freeFlatBuffer(&op->m);
        freeFlatBuffer(&op->n);
        freeFlatBuffer(&op->r);
        freeFlatBuffer(&op->s);
    }

    return 0;
}

// 完成处理
int _ecdsa_complete(QAT_ECDSA_CTX *ctx,  CpaBoolean verifyOrSignStatus)
{
    if (ctx->opType == ECDSA_OP_TYPE_SIGN) {
        ctx->signStatus = verifyOrSignStatus;
        DUMP_ECDSA_SIGN_OUTPUT(ctx->signStatus, ctx->out_cb_r, ctx->out_cb_s);
        memcpy(ctx->out_r, ctx->out_cb_r->pData, ctx->out_cb_r->dataLenInBytes);
        memcpy(ctx->out_s, ctx->out_cb_s->pData, ctx->out_cb_s->dataLenInBytes);
    } else if (ctx->opType == ECDSA_OP_TYPE_VERIFY) {
        ctx->verifyStatus = verifyOrSignStatus;
        DEBUG("verify: %d\n", ctx->verifyStatus);
        if (ctx->verifyStatus) {
            memset(ctx->out_success, 1, 3);
        } else {
            memset(ctx->out_success, 0, 3);
        }
    } else {
        DEBUG("FAILED!!!!!");
    }
    //_free_ecdsa(ctx);
    return 0;
}



