//
// Created by 朱宇 on 26/07/2017.
//


#include <stdlib.h>
#include <lac/cpa_cy_rsa.h>
#include <memory.h>
#include <unistd.h>
#include <sys/time.h>
#include "rsa.h"
#include "mem_utils.h"
#include "qat.h"
#include "callback.h"
#include "dump.h"

#define NO_PADDING 0
#define PADDING    1

int
_free_encrypt_op_buf(QAT_RSA_CTX* ctx,
                     CpaCyRsaEncryptOpData *enc_op_data,
                     CpaFlatBuffer *out_buf);

int
_free_decrypt_op_buf(QAT_RSA_CTX *ctx,
                     CpaCyRsaDecryptOpData *dec_op_data,
                     CpaFlatBuffer *out_buf);

int qat_remove_pad(unsigned char *out, unsigned char *in,
                   int r_len, int *out_len, int sign, int padding);


// 完成函数
static int _rsa_sign_and_encrypt_complete(QAT_RSA_CTX* rsa)
{
    DEBUG(" - Start\n");
    if (rsa->optype != RSA_OP_TYPE_SIGN && rsa->optype != RSA_OP_TYPE_ENCRYPT) {
        return -1;
    }
    // TODO: 此处可以节约拷贝操作
    memcpy(rsa->to, rsa->output_buffer->pData, rsa->output_buffer->dataLenInBytes);
    rsa->to_len = rsa->output_buffer->dataLenInBytes;
    _free_encrypt_op_buf(rsa, rsa->enc_op_data, rsa->output_buffer);
    DEBUG(" - Finish\n");
    return 0;
}
// 完成函数
int _rsa_verify_and_decrypt_complete(QAT_RSA_CTX* rsa)
{
    DEBUG(" - Start\n");
    int output_len = 0;
    int sign_relation = 0;
    if (rsa->optype != RSA_OP_TYPE_VERIFY && rsa->optype != RSA_OP_TYPE_DECRYPT) {
        return -1;
    }
    if (rsa->optype == RSA_OP_TYPE_VERIFY) {
        sign_relation = 1;
    }

    if (qat_remove_pad(
            rsa->to, rsa->output_buffer->pData,
            rsa->n.len, &output_len, sign_relation, 0) != 1) {
    }
    rsa->to_len = output_len;
    _free_decrypt_op_buf(rsa, rsa->dec_op_data, rsa->output_buffer);
    DEBUG(" - Finish\n");
    return 0;
}

// rsa完成函数
static int _rsa_complete(QAT_RSA_CTX* rsa)
{
    if (rsa->optype == RSA_OP_TYPE_SIGN || rsa->optype == RSA_OP_TYPE_ENCRYPT ) {
        return _rsa_sign_and_encrypt_complete(rsa);
    } else if (rsa->optype == RSA_OP_TYPE_VERIFY || rsa->optype == RSA_OP_TYPE_DECRYPT) {
        return _rsa_verify_and_decrypt_complete(rsa);
    }  else {
        DEBUG("rsa complete got one unknown type:%d", rsa->optype);
        return -1;
    }
}

// RSA回调函数
void
qat_rsaCallbackFn(
        void *pCallbackTag,
        CpaStatus status,
        void *pOpData,
        CpaFlatBuffer * pOut)
{
    if (pCallbackTag) {
        QAT_RSA_CTX* ctx = (QAT_RSA_CTX*) pCallbackTag;
        if (ctx->async == 0) {
            //同步
            sem_post(&(ctx->complate));
        } else {
            DEBUG("GET ONE\n");
            // 内容处理
            if (0 != _rsa_complete(ctx)) {
                DEBUG("complate failed!\n");
            } else {
                DEBUG("complete success!\n");
            }
            // 给上层通知
            notify_completion_port((const unsigned char*)ctx->uuid);
        }
    }
}

/******************************************************************************
* function:
*         qat_alloc_pad(unsigned char *in,
*                       int len,
*                       int rLen,
*                       int sign)
*
* @param in   [IN] - pointer to Flat Buffer
* @param len  [IN] - length of input data (hash)
* @param rLen [IN] - length of RSA
* @param sign [IN] - 1 for sign operation and 0 for decryption
*
* description:
*   This function is used to add PKCS#1 padding into input data buffer
*   before it pass to cpaCyRsaDecrypt() function.
*   The function returns a pointer to unsigned char buffer
******************************************************************************/
static unsigned char *qat_alloc_pad(unsigned char *in, int len, int rLen, int sign)
{
    int i = 0;
    /* out data buffer should have fix length */
    unsigned char *out = qaeCryptoMemAlloc(rLen);

    DEBUG("- Started\n");

    if (NULL == out) {
        return NULL;
    }

    /* First two char are (0x00, 0x01) or (0x00, 0x02) */
    out[0] = 0x00;
    if (sign) {
        out[1] = 0x01;
    } else {
        out[1] = 0x02;
    }

    /*
     * Fill 0xff and end up with 0x00 in out buffer until the length of
     * actual data space left
     */
    for (i = 2; i < (rLen - len - 1); i++) {
        out[i] = 0xff;
    }
    /*
     * i has been incremented on beyond the last padding byte to exit for
     * loop
     */
    out[i] = 0x00;

    /* shift actual data to the end of out buffer */
    memcpy((out + rLen - len), in, len);

    DEBUG("- Finished\n");
    return out;
}

/******************************************************************************
* function:
*         qat_data_len(unsigned char *in
*                      int  rLen, int sign)
*
* @param in   [IN] - pointer to Flat Buffer
* @param rLen [IN] - length of RSA
* @param sign [IN] - 1 for sign operation and 0 for decryption
*
* description:
*   This function is used to calculate the length of actual data
*   and padding size inside of outputBuffer returned from cpaCyRsaEncrypt() function.
*   The function counts the padding length (i) and return the length
*   of actual data (dLen) contained in the outputBuffer
******************************************************************************/
static int qat_data_len(const unsigned char *in, int rLen, int sign)
{
    /* first two bytes are 0x00, 0x01 */
    int i = 0;
    int dLen = 0;
    int pLen = 0;

    DEBUG("- Started\n");

    /* First two char of padding should be 0x00, 0x01 */
    if (sign) {
        /* First two char of padding should be 0x00, 0x01 */
        if (in[0] != 0x00 || in[1] != 0x01) {
            return 0;
        }
    } else {
        /* First two char of padding should be 0x00, 0x02 for decryption */
        if (in[0] != 0x00 || in[1] != 0x02) {
            return 0;
        }
    }

    /*
     * while loop is design to reach the 0x00 value and count all the 0xFF
     * value where filled by PKCS#1 padding
     */
    while (in[i + 2] != 0x00 && i < rLen)
        i++;

    /* padding length = 2 + length of 0xFF + 0x00 */
    pLen = 2 + i + 1;
    dLen = rLen - pLen;
    if (dLen < 0) {
        dLen = 0;
    }

    DEBUG("- Finished\n");
    return dLen;
}


int qat_remove_pad(unsigned char *out, unsigned char *in,
                          int r_len, int *out_len, int sign, int padding)
{
    int p_len = 0;
    int d_len = 0;

    DEBUG("- Started\n");
    //dumpPrint(in, r_len);
    //if (padding == RSA_NO_PADDING) {
     //   memcpy(out, in, r_len);
     //   *out_len = r_len;
    //}
    //else { /* should be RSA_PKCS1_PADDING */
        if (0 == (d_len = qat_data_len(in, r_len, sign))) {
            DEBUG("somewrong happens\n");
            return 0;
        }
        p_len = r_len - d_len;
        DEBUG("remove pad, total: %d, begin: %d, data: %d\n", r_len, p_len, d_len);
        /* shift actual data to the beginning of out buffer */
        memcpy(out, in + p_len, d_len);
        *out_len = d_len;
    //}

    DEBUG("- Finished\n");
    return 1;
}

//
static int
_build_encrypt_op_buf(int flen, const unsigned char *from, unsigned char *to,
                 QAT_RSA_CTX *rsa, int padding,
                 CpaCyRsaEncryptOpData ** enc_op_data,
                 CpaFlatBuffer ** output_buffer, int alloc_pad)
{
    CpaCyRsaPublicKey *cpa_pub_key = NULL;
    DEBUG("- START\n");

    cpa_pub_key = (CpaCyRsaPublicKey *) malloc(sizeof(CpaCyRsaPublicKey));
    if (!cpa_pub_key) {
        DEBUG("malloc rsa public key failed!\n");
        return -1;
    }
    if (0 != stripe_to_cflatbuffer(&cpa_pub_key->modulusN, &rsa->n)) {
        DEBUG("set n failed\n");
        return -1;
    }
    if (0 != stripe_to_cflatbuffer(&cpa_pub_key->publicExponentE, &rsa->e)) {
        DEBUG("set e failed\n");
        return -1;
    }

    *enc_op_data = malloc(sizeof(CpaCyRsaEncryptOpData));
    if (NULL == *enc_op_data) {
        DEBUG("Failed to allocate enc_op_data\n");
        return -1;
    }

    (*enc_op_data)->pPublicKey = cpa_pub_key;
    if (alloc_pad) {
        (*enc_op_data)->inputData.pData =
                qat_alloc_pad((Cpa8U *) from, flen, rsa->n.len, 0);
    } else {
        (*enc_op_data)->inputData.pData =
                (Cpa8U *) copyAllocPinnedMemory(from, flen);
    }

    if (alloc_pad)
        (*enc_op_data)->inputData.dataLenInBytes = rsa->n.len;
    else
        (*enc_op_data)->inputData.dataLenInBytes = (Cpa32U)flen;

    (*output_buffer) = (CpaFlatBuffer *) malloc(sizeof(CpaFlatBuffer));
    (*output_buffer)->dataLenInBytes = rsa->n.len;
    (*output_buffer)->pData = qaeCryptoMemAlloc(rsa->n.len);
    DEBUG("END\n");
    return 0;

}

int
_free_encrypt_op_buf(QAT_RSA_CTX* ctx,
                     CpaCyRsaEncryptOpData *enc_op_data,
                     CpaFlatBuffer *out_buf)
{
    DEBUG("- Started\n");
    if (enc_op_data) {
        // 清除公钥
        if (enc_op_data->pPublicKey) {
            freeFlatBuffer(&enc_op_data->pPublicKey->modulusN);
            freeFlatBuffer(&enc_op_data->pPublicKey->publicExponentE);
            free(enc_op_data->pPublicKey);
            enc_op_data->pPublicKey = NULL;
        }
        // 清除数据
        freeFlatBuffer(&enc_op_data->inputData);
        free(enc_op_data);
        // 若有必要，置空ctx中的数据
        if (ctx)
            ctx->enc_op_data = NULL;
    }

    if (out_buf) {
        freeFlatBuffer(out_buf);
        free(out_buf);
        if (ctx)
            ctx->output_buffer = NULL;
    }
    return 0;
}

//
static int
_build_decrypt_op_buf(int flen, const unsigned char *from, unsigned char *to,
                     QAT_RSA_CTX *rsa, int padding,
                     CpaCyRsaDecryptOpData ** dec_op_data,
                     CpaFlatBuffer ** output_buffer, int alloc_pad)
{

    CpaCyRsaPrivateKey *cpa_prv_key = NULL;
    cpa_prv_key = (CpaCyRsaPrivateKey *) malloc(sizeof(CpaCyRsaPrivateKey));

    DEBUG("- Start\n");
    *dec_op_data = malloc(sizeof(CpaCyRsaDecryptOpData));
    (*dec_op_data)->pRecipientPrivateKey = cpa_prv_key;

    cpa_prv_key->version = CPA_CY_RSA_VERSION_TWO_PRIME;
    DEBUG("0-----------version: %d\n", cpa_prv_key->version);

    // type 2
    cpa_prv_key->privateKeyRepType = CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2;
    if (0 != stripe_to_cflatbuffer(&cpa_prv_key->privateKeyRep2.prime1P, &rsa->p) ||
            0 != stripe_to_cflatbuffer(&cpa_prv_key->privateKeyRep2.prime2Q, &rsa->q) ||
            0 != stripe_to_cflatbuffer(&cpa_prv_key->privateKeyRep2.exponent1Dp, &rsa->dmp1) ||
            0 != stripe_to_cflatbuffer(&cpa_prv_key->privateKeyRep2.exponent2Dq, &rsa->dmq1) ||
            0 != stripe_to_cflatbuffer(&cpa_prv_key->privateKeyRep2.coefficientQInv, &rsa->iqmp)) {
        DEBUG("alloc memory failed!\n");
        return -1;
    }
    // type 1
    //cpa_prv_key->privateKeyRepType = CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1;
    //stripe_to_cflatbuffer(&cp)


    if (alloc_pad) {
        (*dec_op_data)->inputData.pData =
                qat_alloc_pad((Cpa8U *) from, flen, rsa->n.len, 1);
    } else {
        (*dec_op_data)->inputData.pData =
                (Cpa8U *) copyAllocPinnedMemory(from, flen);
    }


    if (alloc_pad)
        (*dec_op_data)->inputData.dataLenInBytes = rsa->n.len;
    else
        (*dec_op_data)->inputData.dataLenInBytes = (Cpa32U)flen;

    DUMPL("dec.op", (*dec_op_data)->inputData.pData, (*dec_op_data)->inputData.dataLenInBytes);

    *output_buffer = malloc(sizeof(CpaFlatBuffer));
    if (NULL == *output_buffer) {
        DEBUG("alloc memory failed!\n");
        return 0;
    }

    /*
     * Memory allocation for DecOpdata[IN] the size of outputBuffer
     * should big enough to contain RSA_size
     */
    (*output_buffer)->pData =
            (Cpa8U *) qaeCryptoMemAlloc(rsa->n.len);
    if (NULL == (*output_buffer)->pData) {
        DEBUG("alloc memory failed!\n");
        return 0;
    }

    DEBUG("output_buffer: %d, input_data: %d\n", rsa->n.len, flen);
    (*output_buffer)->dataLenInBytes = rsa->n.len;
    return 0;
}

int
_free_decrypt_op_buf(QAT_RSA_CTX *ctx,
                     CpaCyRsaDecryptOpData *dec_op_data,
                     CpaFlatBuffer *out_buf)
{
    CpaCyRsaPrivateKeyRep2 *key = NULL;
    DEBUG("- Started\n");

    if (dec_op_data) {
        // 清空私钥
        if (dec_op_data->pRecipientPrivateKey) {
            key = &dec_op_data->pRecipientPrivateKey->privateKeyRep2;
            freeFlatBuffer(&key->prime1P);
            freeFlatBuffer(&key->prime2Q);
            freeFlatBuffer(&key->exponent1Dp);
            freeFlatBuffer(&key->exponent2Dq);
            freeFlatBuffer(&key->coefficientQInv);
            free(dec_op_data->pRecipientPrivateKey);
            dec_op_data->pRecipientPrivateKey = NULL;
        }
        // 清空解密所使用的输入数据
        freeFlatBuffer(&dec_op_data->inputData);
        free(dec_op_data);
        // 若有必要，直接置空ctx中关于dec_op_data的引用
        if (ctx && ctx->output_buffer == out_buf)
            ctx->dec_op_data = NULL;
    }

    // 清空解密操作的数据
    if (out_buf) {
        freeFlatBuffer(out_buf);
        free(out_buf);
        // 若有必要，直接置空ctx中关于dec_op_data的引用
        if (ctx && ctx->output_buffer == out_buf)
            ctx->output_buffer = NULL;
    }
    DEBUG("- Finished\n");
    return 0;
}

static int
_do_rsa_encrypt(QAT_RSA_CTX* ctx, CpaCyRsaEncryptOpData *enc_op_data, CpaFlatBuffer *output_buf)
{

    CpaStatus status;
    struct timeval start;
    struct timeval end;

    CpaInstanceHandle *curHandle = getNextCyInstance();
    if (curHandle == NULL || enc_op_data == NULL || output_buf == NULL) {
        DEBUG("- data failed\n");
        return -1;
    }
    gettimeofday(&start, NULL);
    do {
        status = cpaCyRsaEncrypt(getNextCyInstance(), qat_rsaCallbackFn, ctx,
                          enc_op_data, output_buf);
    } while (status == CPA_STATUS_RETRY);

    if (ctx->async == 0) {
        sem_wait(&(ctx->complate));
    }
    gettimeofday(&end, NULL);
    DEBUG("encrypt OP cost: %f usec\n", (end.tv_sec - start.tv_sec) * 1000000.0f + (end.tv_usec - start.tv_usec));
    return 0;
}

int _do_rsa_decrypt(QAT_RSA_CTX* ctx, CpaCyRsaDecryptOpData *dec_op_data, CpaFlatBuffer *output_buf)
{
    CpaStatus status;
    struct timeval start;
    struct timeval end;
    DEBUG("- Start\n");

    CpaInstanceHandle *curHandle = getNextCyInstance();
    if (curHandle == NULL || dec_op_data == NULL || output_buf == NULL) {
        DEBUG("- data failed\n");
        return -1;
    }
    gettimeofday(&start, NULL);
    do {
        status = cpaCyRsaDecrypt(getNextCyInstance(), qat_rsaCallbackFn, ctx,
                              dec_op_data, output_buf);
    } while (status == CPA_STATUS_RETRY);

    if (ctx->async == 0) {
        sem_wait(&(ctx->complate));
    }
    gettimeofday(&end, NULL);
    DEBUG("decrypt OP cost: %f usec\n", (end.tv_sec - start.tv_sec) * 1000000.0f + (end.tv_usec - start.tv_usec));

    DEBUG("- Finished\n");

    return 0;
}

// 公钥操作：公钥加密
int qat_rsa_encrypt(QAT_RSA_CTX* rsa, unsigned char *from, unsigned char *to, int flen)
{
    int ret = 0;
    CpaCyRsaEncryptOpData *enc_op_data = NULL;
    CpaFlatBuffer *output_buffer = NULL;

    DEBUG("- START\n");
    ret = _build_encrypt_op_buf(flen, from, to, rsa, 0, &enc_op_data, &output_buffer, PADDING);
    if (ret != 0 || enc_op_data == NULL || output_buffer == NULL) {
        goto exit;
    }
    rsa->to = to;
    rsa->optype = RSA_OP_TYPE_ENCRYPT;
    rsa->enc_op_data = enc_op_data;
    rsa->output_buffer = output_buffer;

    if (0 != _do_rsa_encrypt(rsa, enc_op_data, output_buffer)) {
        goto exit;
    }
    // 同步情况
    if (!rsa->async) {

        if (0 != _rsa_complete(rsa)) {
            return 0;
        }
        return rsa->to_len;
    }
    // 异步返回
    return 0;

    exit:
    _free_encrypt_op_buf(rsa, enc_op_data, output_buffer);
    return 0;
}

// 私钥操作：私钥签名
int qat_rsa_sign(QAT_RSA_CTX* rsa, unsigned char *from, unsigned char *to, int flen)
{
    CpaCyRsaDecryptOpData *dec_op_data = NULL;
    CpaFlatBuffer *output_buffer = NULL;

    int ret = 0;
    int rsa_len = 0;

    DEBUG("- START\n");
    if (rsa == NULL || from == NULL || to == NULL ||
        (flen > ((rsa_len = (rsa->n.len)) - 4))
        || flen == 0) {
        DEBUG("RSA key, input or output is NULL or invalid length,\
              flen = %d, rsa_len = %d\n", flen, rsa_len);
        return 0;
    }
    DUMPL("sign.data", from, flen);

    // 创建QAT所需的op对象
    ret = _build_decrypt_op_buf(flen, from, to, rsa, 0, &dec_op_data, &output_buffer, PADDING);
    if (ret != 0 || dec_op_data == NULL || output_buffer == NULL) {
        goto exit;
    }
    rsa->to = to;
    rsa->optype = RSA_OP_TYPE_SIGN;
    rsa->dec_op_data = dec_op_data;
    rsa->output_buffer = output_buffer;

    // 解密

    if (0 != _do_rsa_decrypt(rsa, dec_op_data, output_buffer)) {
        goto exit;
    }

    // 同步情况下
    if (!rsa->async) {
        if (0 != _rsa_complete(rsa)) {
            DEBUG("完成失败！");
            return 0;
        }
        return rsa->to_len;
    }
    // 异步返回
    return 0;

    exit:
    _free_decrypt_op_buf(rsa, dec_op_data, output_buffer);
    return 0;
}

// 私钥操作：私钥解密
int qat_rsa_decrypt(QAT_RSA_CTX* rsa, unsigned char *from, unsigned char *to, int flen)
{
    CpaCyRsaDecryptOpData *dec_op_data = NULL;
    CpaFlatBuffer *output_buffer = NULL;

    int ret = 0;

    DEBUG("- START\n");

    // 创建QAT所需的op对象
    ret = _build_decrypt_op_buf(flen, from, to, rsa, 0, &dec_op_data, &output_buffer, NO_PADDING);
    if (ret != 0 || dec_op_data == NULL || output_buffer == NULL) {
        goto exit;
    }
    DUMPL("decrypt.data", from, flen);

    rsa->to = to;
    rsa->optype = RSA_OP_TYPE_DECRYPT;
    rsa->dec_op_data = dec_op_data;
    rsa->output_buffer = output_buffer;

    // 解密
    if (0 != _do_rsa_decrypt(rsa, dec_op_data, output_buffer)) {
        goto exit;
    }

    // 同步情况下
    if (!rsa->async) {
        if (0 != _rsa_complete(rsa)) {
            DEBUG("完成失败！");
            return 0;
        }
        return rsa->to_len;
    }
    // 异步返回
    return 0;

    exit:
    _free_decrypt_op_buf(rsa, dec_op_data, output_buffer);
    return 0;
}

// 公钥操作： 公钥验签
int qat_rsa_verify(QAT_RSA_CTX* rsa, unsigned char *from, unsigned char *to, int flen)
{
    int rsa_len = 0;
    CpaCyRsaEncryptOpData *enc_op_data = NULL;
    CpaFlatBuffer *output_buffer = NULL;
    int ret = 1;

    DEBUG("- Started\n");

    /* parameter checking */
    if (rsa == NULL || from == NULL || to == NULL ||
        (flen != (rsa_len = (rsa_len = (rsa->n.len))))) {
        DEBUG("RSA key %p, input %p or output %p are NULL or invalid length, \
              flen = %d, rsa_len = %d\n", rsa, (void*)from, (void*)to, flen, rsa_len);
        return 0;
    }

    ret = _build_encrypt_op_buf(flen, from, to, rsa, 0, &enc_op_data, &output_buffer, NO_PADDING);
    if (ret != 0 || enc_op_data == NULL || output_buffer == NULL) {
        DEBUG("Failure in build_encrypt_op\n");
        return 0;
    }

    rsa->to = to;
    rsa->optype = RSA_OP_TYPE_VERIFY;
    rsa->enc_op_data = enc_op_data;
    rsa->output_buffer = output_buffer;

    if (0 != _do_rsa_encrypt(rsa, enc_op_data, output_buffer)) {
        DEBUG("Failure in qat_rsa_encrypt\n");
        return 0;
    }
    // 同步情况下
    if (!rsa->async) {
        if (0 != _rsa_complete(rsa)) {
            DEBUG("verify complete failed!！");
            return 0;
        }
        return rsa->to_len;
    }
    // 异步返回
    return 0;
}
/*
 * 在同步模式下，操作函数等待完成后才返回。
 * 在异步模式下，操作函数立即返回，完成通知通过 unix domain socket进行通知
 */
QAT_RSA_CTX* QAT_RSA_CTX_new(char* uuid,
                             unsigned char* n, int ln,
                             unsigned char* e, int le,
                             unsigned char* d, int ld,
                             unsigned char* p, int lp,
                             unsigned char* q, int lq,
                             unsigned char* dmp1, int ldmp1,
                             unsigned char* dmq1, int ldmq1,
                             unsigned char* iqmp, int liqmp)
{
    QAT_RSA_CTX* ret = malloc(sizeof(QAT_RSA_CTX));

    memset(ret, 0, sizeof(QAT_RSA_CTX));

    memcpy(ret->uuid, uuid, 3);
    ret->async = 0;
    buffer_to_stripe(&ret->n, n, ln);
    buffer_to_stripe(&ret->e, e, le);
    buffer_to_stripe(&ret->d, d, ld);
    buffer_to_stripe(&ret->p, p, lp);
    buffer_to_stripe(&ret->q, q, lq);
    buffer_to_stripe(&ret->dmp1, dmp1, ldmp1);
    buffer_to_stripe(&ret->dmq1, dmq1, ldmq1);
    buffer_to_stripe(&ret->iqmp, iqmp, liqmp);
    //rsa_dump(ret);

    if (ret->async == 0) {
        sem_init(&(ret->complate), 0, 0);
    }
    return ret;
}

int rsa_dump(QAT_RSA_CTX* ctx)
{
    DEBUG("- Start\n");
    DUMPL("modules", ctx->n.data, ctx->n.len);
    DUMPL("exp", ctx->e.data, ctx->e.len);
    DUMPL("d", ctx->e.data, ctx->e.len);
    DUMPL("p", ctx->p.data, ctx->p.len);
    DUMPL("dmp1", ctx->dmp1.data, ctx->dmp1.len);
    DUMPL("dmq1", ctx->dmq1.data, ctx->dmq1.len);
    DUMPL("iqmp", ctx->iqmp.data, ctx->iqmp.len);
    return 0;
}

void rsa_free(QAT_RSA_CTX* ctx)
{
    _free_decrypt_op_buf(ctx, ctx->dec_op_data, ctx->output_buffer);
    _free_encrypt_op_buf(ctx, ctx->enc_op_data, ctx->output_buffer);
    free(ctx);
}


