//
// Created by 朱宇 on 24/07/2017.
//

#include <stdlib.h>
#include <memory.h>
#include "cpa_types.h"
#include "cpa.h"
#include "qae_mem.h"
#include "utils.h"

extern CpaStatus qaeMemInit(void);
extern void qaeMemDestroy(void);


static void* qaeCryptoMemAlloc(size_t memsize) {
    void *pAddr = qaeMemAllocNUMA(memsize, 0, 8);
    if (pAddr == NULL) {
        return NULL;
    }
    return pAddr;
}

int main(int argc, char** argv)
{
    Cpa8U *buf = NULL;
    qaeMemInit();

    buf = qaeCryptoMemAlloc(128);
    memset(buf, 0, 128);
    dumpPrint(buf, 128);
    qaeMemDestroy();
    return 0;
}