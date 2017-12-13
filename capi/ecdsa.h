//
// Created by 朱宇 on 25/07/2017.
//

#ifndef QATCGO_ECDSA_H
#define QATCGO_ECDSA_H

#include <cpa_types.h>
#include <lac/cpa_cy_ec.h>
#include <semaphore.h>
#include "ec.h"
#include "utils.h"

enum ecdsa_op_type {
    ECDSA_OP_TYPE_SIGN = 1,
    ECDSA_OP_TYPE_VERIFY = 2,
};

// 主要和key关联上！
// CGO不支持union
typedef struct _ECDSA_CTX {
    unsigned char uuid[4];
    int async;
    sem_t complete;

    ec_key_t ec_key;
    void* verifyOpData;
    void* signRSOpdata;
    enum ecdsa_op_type opType;

    CpaBoolean signStatus;
    CpaBoolean verifyStatus;
    unsigned char* out_success;
    CpaFlatBuffer* out_cb_r;
    CpaFlatBuffer* out_cb_s;
    unsigned char* out_r;
    unsigned char* out_s;
}QAT_ECDSA_CTX;

QAT_ECDSA_CTX* QAT_ECDSA_CTX_new(
        char* uuid,
        unsigned char* curve_a, int curve_a_len,
        unsigned char* curve_b, int curve_b_len,
        unsigned char* curve_p, int curve_p_len,
        unsigned char* order, int order_len,
        unsigned char* point_x, int point_x_len,
        unsigned char* point_y, int point_y_len,
        unsigned char* generator_x, int generator_x_len,
        unsigned char* generator_y, int generator_y_len,
        unsigned char* private_key, int private_key_len
);

/*
签名过程如下：
   1、选择一条椭圆曲线Ep(a,b)，和基点G；
   2、选择私有密钥k（k<n，n为G的阶），利用基点G计算公开密钥K=kG；
   3、产生一个随机整数r（r<n），计算点R=rG；
   4、将原数据和点R的坐标值x,y作为参数，计算SHA1做为hash，即Hash=SHA1(原数据,x,y)；
   5、计算s≡r - Hash * k (mod n)
   6、r和s做为签名值，如果r和s其中一个为0，重新从第3步开始执行
   */
int qat_ecdsa_do_sign_rs(
        QAT_ECDSA_CTX *ec,
        unsigned char* digest, int digest_len,
        unsigned char* sign_r, unsigned char* sign_s);

/*
验证过程如下：
   1、接受方在收到消息(m)和签名值(r,s)后，进行以下运算
   2、计算：sG+H(m)P=(x1,y1), r1≡ x1 mod p。
   3、验证等式：r1 ≡ r mod p。
   4、如果等式成立，接受签名，否则签名无效
*/
int qat_ecdsa_do_verify(
        QAT_ECDSA_CTX *ec,
        unsigned char* digest, int digest_len,
        unsigned char* r, int r_len, unsigned char* s, int s_len,
        unsigned char* success);



#endif //QATCGO_EC_H
