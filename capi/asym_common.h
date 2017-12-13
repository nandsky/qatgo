//
// Created by 朱宇 on 24/07/2017.
//

#ifndef QATCGO_ASYM_COMMON_H
#define QATCGO_ASYM_COMMON_H

#include <cpa_types.h>
#include <cpa.h>

int qat_mod_exp(CpaInstanceHandle *instance, unsigned char *base, unsigned char *exponent, unsigned char* modules,
                unsigned char* result);

#endif //QATCGO_ASYM_COMMON_H
