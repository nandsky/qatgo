//
// Created by 朱宇 on 04/09/2017.
//

#include "jc_rsa.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#include <openssl/async.h>
#endif
#include <openssl/err.h>
#include <string.h>
#include <unistd.h>
#include "net.h"
#include "packet.h"
#include "utils.h"

/* To specify the RSA op sizes supported by QAT engine */
#define RSA_QAT_RANGE_MIN 512
#define RSA_QAT_RANGE_MAX 4096

#define NO_PADDING 0
#define PADDING    1

static RSA_METHOD *qat_rsa_method = NULL;


static int qat_rsa_priv_dec(
        int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa, int padding);

static int qat_rsa_priv_enc(
        int flen, const unsigned char *from, unsigned char *to,
        RSA *rsa, int padding);

Packet* build_decrypt_buf(RSA* rsa);
Packet* build_encrypt_buf(RSA* rsa);

RSA_METHOD *qat_get_RSA_methods(void)
{
#ifndef OPENSSL_DISABLE_QAT_RSA
    int res = 1;
    RSA_METHOD *default_rsa_method = (RSA_METHOD *)RSA_get_default_method();
#endif

    if (qat_rsa_method != NULL)
        return qat_rsa_method;

#ifndef OPENSSL_DISABLE_QAT_RSA
    if ((qat_rsa_method = RSA_meth_new("JC RSA method", 0)) == NULL) {
        return NULL;
    }
    // 验签
    res &= RSA_meth_set_pub_enc(qat_rsa_method, RSA_meth_get_pub_enc(default_rsa_method));
    // 加密
    res &= RSA_meth_set_pub_dec(qat_rsa_method, RSA_meth_get_pub_dec(default_rsa_method));
    // 签名
    res &= RSA_meth_set_priv_enc(qat_rsa_method, qat_rsa_priv_enc);
    // 解密
    res &= RSA_meth_set_priv_dec(qat_rsa_method, RSA_meth_get_priv_dec(default_rsa_method));
    res &= RSA_meth_set_mod_exp(qat_rsa_method, RSA_meth_get_mod_exp(default_rsa_method));
    res &= RSA_meth_set_bn_mod_exp(qat_rsa_method, RSA_meth_get_bn_mod_exp(default_rsa_method));
    if (res == 0) {
        return NULL;
    }
#else
    printf("default:\n");
    qat_rsa_method = (RSA_METHOD *)RSA_get_default_method();
#endif

    return qat_rsa_method;
}

void qat_free_RSA_methods(void)
{

}

static inline int qat_rsa_range_check(int plen)
{
    return ((plen >= RSA_QAT_RANGE_MIN) && (plen <= RSA_QAT_RANGE_MAX));
}

int qat_rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to,
                    RSA *rsa, int padding)
{
    int rsa_len = 0;
    int output_len = 0;

    /* parameter checking */
    if (rsa == NULL || from == NULL || to == NULL ||
        (flen != (rsa_len = RSA_size(rsa)))) {
        printf("RSA key %p, input %p or output %p are NULL or invalid length, \
              flen = %d, rsa_len = %d\n", rsa, from, to, flen, rsa_len);
        return 0;
    }
    if (!qat_rsa_range_check(RSA_bits((const RSA*)rsa)))
        return RSA_meth_get_pub_dec(RSA_PKCS1_OpenSSL())
                (flen, from, to, rsa, padding);


    return 0;
}

int qat_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to,
                     RSA *rsa, int padding)
{
    int ret = 0;
    int rsa_len = 0;
    Packet* pkt = NULL;
    Packet* new_pkt = NULL;

    DEBUG("---------------------Start\n");
    /* Parameter Checking */
    /*
     * The input message length should less than RSA size and also have
     * minimum space of PKCS1 padding(4 bytes)
     */
    if (rsa == NULL || from == NULL || to == NULL ||
        (flen > ((rsa_len = RSA_size(rsa)) - 4))
        || flen == 0) {
        DEBUG("params error!\n");
        return 0;
    }
    /*
     * If the op sizes are not in the range supported by QAT engine then fall
     * back to software
     */
    if (!qat_rsa_range_check(RSA_bits((const RSA*)rsa)))
        return RSA_meth_get_priv_enc(RSA_PKCS1_OpenSSL())
                (flen, from, to, rsa, padding);

    DEBUG("plaintext len: %d, padding: %d, rsa_size: %d\n", flen, padding, rsa_len);
    //DUMPL("1...", from, flen);
    //DUMPL("1..padding", to, rsa_len);

//    ret = RSA_meth_get_priv_enc(RSA_PKCS1_OpenSSL())
//            (flen, from, to, rsa, padding);
    //DUMPL("origin.data", to, ret);
    //DUMPL("2...", from, flen);
    //DUMPL("2..padding", to, rsa_len);
    //memset(to, 0, ret);
    //DUMPL("origin.data--clean", to, ret);

    pkt = build_decrypt_buf(rsa);
    pkt_append_bf(pkt, flen, from);
    new_pkt = conn_request(pkt);

    if (new_pkt) {
        memcpy(to, new_pkt->data, new_pkt->total);
        DUMPL("sign.result", to, new_pkt->total);
        ret = new_pkt->total;
    } else {
        DEBUG("something wroing....\n");
        // 出错则直接写0xff
        memset(to, 0xff, rsa_len);
    }
    DEBUG("end!\n");
    return ret;
}

int qat_rsa_priv_dec(int flen, const unsigned char *from,
                     unsigned char *to, RSA *rsa, int padding)
{
    int rsa_len = 0;
    int output_len = 0;
    Packet* pkt = NULL;

    if (rsa == NULL || from == NULL || to == NULL ||
        (flen != (rsa_len = RSA_size(rsa)))) {
        return 0;
    }

    if (!qat_rsa_range_check(RSA_bits((const RSA*)rsa)))
        return RSA_meth_get_priv_dec(RSA_PKCS1_OpenSSL())
                (flen, from, to, rsa, padding);

    pkt = build_decrypt_buf(rsa);
    pkt_append_bf(pkt, flen, from);

    conn_request(pkt);
    return 0;
}

Packet* build_decrypt_buf(RSA* rsa)
{
    int rsa_len = 0;

    Packet* pkt = malloc(sizeof(Packet));
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;
    const BIGNUM *p = NULL;
    const BIGNUM *q = NULL;
    const BIGNUM *dmp1 = NULL;
    const BIGNUM *dmq1 = NULL;
    const BIGNUM *iqmp = NULL;

    RSA_get0_key((const RSA*)rsa, &n, &e, &d);
    RSA_get0_factors((const RSA*)rsa, &p, &q);
    RSA_get0_crt_params((const RSA*)rsa, &dmp1, &dmq1, &iqmp);

    if (p == NULL || q == NULL || dmp1 == NULL || dmq1 == NULL || iqmp == NULL) {
        printf("Either p %p, q %p, dmp1 %p, dmq1 %p, iqmp %p are NULL\n",
             p, q, dmp1, dmq1, iqmp);
        return 0;
    }
    /* output signature should have same length as RSA(128) */
    rsa_len = RSA_size(rsa);

    memset(pkt, 0, sizeof(Packet));
    pkt_append(pkt, n);
    pkt_append(pkt, p);
    pkt_append(pkt, q);
    pkt_append(pkt, dmp1);
    pkt_append(pkt, dmq1);
    pkt_append(pkt, iqmp);

    return pkt;
}

Packet* build_encrypt_buf(RSA* rsa)
{
    Packet* pkt = malloc(sizeof(Packet));
    int rsa_len = 0;
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;

    return pkt;
}