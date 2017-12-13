//
// Created by 朱宇 on 19/08/2017.
//

#ifndef QATCGO_DUMP_H
#define QATCGO_DUMP_H

#include "utils.h"

# ifdef QATGO_DEBUG
#  define DUMPL(var,p,l) qat_hex_dump(__func__,var,p,l);
# else
#  define DEBUG(...)
#  define DUMPL(...)
# endif

#define DUMP_ECDSA_SIGN(instance_handle, opData, pResultR, pResultS)  \
    do {                                                                \
        fprintf(stderr,"=========================\n");                  \
        fprintf(stderr, "ECDSA Sign Request: %p\n", opData);            \
        fprintf(stderr, "instance_handle = %p\n", instance_handle);     \
        DUMPL("xg.pData", opData->xg.pData, opData->xg.dataLenInBytes); \
        DUMPL("yg.pData", opData->yg.pData, opData->yg.dataLenInBytes); \
        DUMPL("n.pData", opData->n.pData, opData->n.dataLenInBytes);    \
        DUMPL("q.pData", opData->q.pData, opData->q.dataLenInBytes);    \
        DUMPL("a.pData", opData->a.pData, opData->a.dataLenInBytes);    \
        DUMPL("b.pData", opData->b.pData, opData->b.dataLenInBytes);    \
        DUMPL("k.pData", opData->k.pData, opData->k.dataLenInBytes);    \
        DUMPL("m.pData", opData->m.pData, opData->m.dataLenInBytes);    \
        DUMPL("d.pData", opData->d.pData, opData->d.dataLenInBytes);    \
        fprintf(stderr, "opData: fieldType = %d\n", opData->fieldType); \
        fprintf(stderr, "pResultR->dataLenInBytes = %u "                \
                "pResultR->pData = %p\n",                               \
                pResultR->dataLenInBytes, pResultR->pData);             \
        fprintf(stderr, "pResultS->dataLenInBytes = %u "                \
                "pResultS->pData = %p\n",                               \
                pResultS->dataLenInBytes, pResultS->pData);             \
        fprintf(stderr,"=========================\n");                  \
    } while (0)

#define DUMP_ECDSA_SIGN_OUTPUT(bEcdsaSignStatus, pResultR, pResultS)       \
    do {                                                                     \
        fprintf(stderr,"=========================\n");                       \
        fprintf(stderr, "ECDSA Sign Output:  pResultR %p, pResultS %p\n",    \
                pResultR, pResultS);                                         \
        fprintf(stderr, "bEcdsaSignStatus = %u\n", bEcdsaSignStatus);        \
        DUMPL("pResultR->pData", pResultR->pData, pResultR->dataLenInBytes); \
        DUMPL("pResultS->pData", pResultS->pData, pResultS->dataLenInBytes); \
        fprintf(stderr,"=========================\n");                       \
    } while (0)

#define DUMP_ECDSA_VERIFY(instance_handle, opData)                    \
    do {                                                                \
        fprintf(stderr,"=========================\n");                  \
        fprintf(stderr, "ECDSA Verify Request: %p\n", opData);          \
        fprintf(stderr, "instance_handle = %p\n", instance_handle);     \
        DUMPL("xg.pData", opData->xg.pData, opData->xg.dataLenInBytes); \
        DUMPL("yg.pData", opData->yg.pData, opData->yg.dataLenInBytes); \
        DUMPL("n.pData", opData->n.pData, opData->n.dataLenInBytes);    \
        DUMPL("q.pData", opData->q.pData, opData->q.dataLenInBytes);    \
        DUMPL("a.pData", opData->a.pData, opData->a.dataLenInBytes);    \
        DUMPL("b.pData", opData->b.pData, opData->b.dataLenInBytes);    \
        DUMPL("m.pData", opData->m.pData, opData->m.dataLenInBytes);    \
        DUMPL("r.pData", opData->r.pData, opData->r.dataLenInBytes);    \
        DUMPL("s.pData", opData->s.pData, opData->s.dataLenInBytes);    \
        DUMPL("xp.pData", opData->xp.pData, opData->xp.dataLenInBytes); \
        DUMPL("yp.pData", opData->yp.pData, opData->yp.dataLenInBytes); \
        fprintf(stderr, "opData: fieldType = %d\n", opData->fieldType); \
        fprintf(stderr,"=========================\n");                  \
    } while (0)

#endif //QATCGO_DUMP_H
