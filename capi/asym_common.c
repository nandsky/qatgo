//
// Created by 朱宇 on 24/07/2017.
//

#include <stdlib.h>
#include <lac/cpa_cy_ln.h>
#include "asym_common.h"
#include "mem_utils.h"
#include "utils.h"

int qat_mod_exp(CpaInstanceHandle *instance, unsigned char *base, unsigned char *exponent, unsigned char* modules,
                unsigned char* result)
{
    CpaFlatBuffer resultBuff = {0, };
    CpaStatus status = 0;
    CpaCyLnModExpOpData opData;

    opData.base.pData = NULL;
    opData.exponent.pData = NULL;
    opData.modulus.pData = NULL;

    resultBuff.dataLenInBytes = 10;
    resultBuff.pData = qaeCryptoMemAlloc(resultBuff.dataLenInBytes);

    do {
        status = cpaCyLnModExp(instance, NULL, NULL, &opData, &resultBuff);
    } while (status == CPA_STATUS_RETRY);

    return 0;
}
