//
// Created by 朱宇 on 23/07/2017.
//

#ifndef QATCGO_UTILS_H
#define QATCGO_UTILS_H

#include <stdio.h>
#include <cpa_types.h>
#include <cpa.h>
#define QAT_BYTE_ALIGNMENT 64

#define QATGO_DEBUG

#ifdef QATGO_DEBUG
    void qat_hex_dump(const char *func, const char *var, const unsigned char p[],
                  int l);
    #define DEBUG(fmt_str, ...)                                              \
          fprintf(stderr, "[DEBUG][%s:%d:%s()] " fmt_str, __FILE__, __LINE__, \
                  __func__, ##__VA_ARGS__)
#else
    #define DEBUG(...)
#endif


typedef struct Stripe_s{
    unsigned char* data;
    unsigned int len;
}Stripe;

int stripe_to_cflatbuffer(CpaFlatBuffer* dst, Stripe* src);
int buffer_to_cflatbuffer(CpaFlatBuffer* dst, unsigned char* src, int slen);
int buffer_to_stripe(Stripe* dst, unsigned char* src, int slen);

int cflatbuffer_to_stripe(Stripe* dst, CpaFlatBuffer* src);
void dumpPrint(unsigned char * data, int len);

#endif //QATCGO_UTILS_H
