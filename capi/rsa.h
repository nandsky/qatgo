//
// Created by 朱宇 on 26/07/2017.
//

#ifndef QATCGO_RSA_H
#define QATCGO_RSA_H

#include <cpa_types.h>
#include <cpa.h>
#include <semaphore.h>
#include "utils.h"

enum rsa_op_type {
    RSA_OP_TYPE_ENCRYPT = 1,
    RSA_OP_TYPE_DECRYPT = 2,
    RSA_OP_TYPE_SIGN = 3,
    RSA_OP_TYPE_VERIFY = 4,
};


// RSA参考： https://blog.cnbluebox.com/blog/2014/03/19/rsajia-mi/
// QAT RSA操作
// 不知道为什么，CGO不支持union
typedef struct _RSA_CTX {
    int size;
    unsigned char uuid[4]; // 预留最后一位做 0
    enum rsa_op_type optype;

    // 加密
    Stripe n;
    Stripe e;
    void *enc_op_data;

    // 解密
    Stripe d;
    Stripe p;
    Stripe q;
    Stripe dmp1;
    Stripe dmq1;
    Stripe iqmp;
    void *dec_op_data;

    int async;
    sem_t complate;

    CpaFlatBuffer *output_buffer;
    unsigned char* to;
    int to_len;

}QAT_RSA_CTX;


QAT_RSA_CTX* QAT_RSA_CTX_new(char* uuid,
                             unsigned char* n, int ln,
                             unsigned char* e, int le,
                             unsigned char* d, int ld,
                             unsigned char* p, int lp,
                             unsigned char* q, int lq,
                             unsigned char* dmp1, int ldmp1,
                             unsigned char* dmq1, int ldmq1,
                             unsigned char* iqmp, int liqmp
);


int rsa_dump(QAT_RSA_CTX* ctx);
// 公钥验签
int qat_rsa_verify(QAT_RSA_CTX* ctx, unsigned char *plaintext, unsigned char *to, int plaintext_len);
// 公钥加密
int qat_rsa_encrypt(QAT_RSA_CTX* ctx, unsigned char *plaintext, unsigned char *to, int plaintext_len);
// 私钥签名
int qat_rsa_sign(QAT_RSA_CTX* ctx, unsigned char *plaintext, unsigned char *to, int plaintext_len);
// 私钥解密
int qat_rsa_decrypt(QAT_RSA_CTX* ctx, unsigned char *ciphertext, unsigned char *to, int ciphertext_len);

void rsa_free(QAT_RSA_CTX* ctx);

#endif //QATCGO_RSA_H
