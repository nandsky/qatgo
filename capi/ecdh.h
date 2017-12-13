//
// Created by 朱宇 on 10/08/2017.
//

#ifndef QATCGO_ECDH_H
#define QATCGO_ECDH_H

#include <cpa_types.h>
#include <semaphore.h>
#include "ec.h"


typedef struct _ECDH_CTX {
    char uuid[4];
    int async;
    sem_t complete;
    ec_key_t ec_key;

    CpaBoolean pMultiplyStatus;
    void* opData;
    Stripe out_px;
    Stripe out_py;
}QAT_ECDH_CTX;


QAT_ECDH_CTX* QAT_ECDH_CTX_new(
        char* uuid,
        unsigned char* curve_a, int curve_a_len,
        unsigned char* curve_b, int curve_b_len,
        unsigned char* curve_p, int curve_p_len,
        unsigned char* order, int order_len,
        unsigned char* generator_x, int generator_x_len,
        unsigned char* generator_y, int generator_y_len,
        unsigned char* private_key, int private_key_len
);

int qat_ecdh_generate_key(QAT_ECDH_CTX* ctx);
int qat_ecdh_compute_key(QAT_ECDH_CTX* ctx);

#endif //QATCGO_ECDH_H
