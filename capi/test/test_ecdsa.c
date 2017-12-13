//
// Created by 朱宇 on 25/07/2017.
//

#include "test_ecdsa.h"
#include "test_utils.h"
#include "qat.h"

/*enum to define ECDSA step*/
typedef enum ecdsa_step_s
{
    ECDSA_STEP_SIGNRS = 0,
    ECDSA_STEP_VERIFY
}ecdsa_step_t;

typedef struct ecdsa_test_params_s
{
    /*pointer to pre-allocated memory for thread to store performance data*/
    //perf_data_t* performanceStats;
    /*crypto instance handle of service that has already been started*/
    CpaInstanceHandle cyInstanceHandle;
    /* run test using synchronous or asynchronous mode */
    sync_mode_t syncMode;

    Cpa32U nLenInBytes;
    CpaCyEcFieldType fieldType;
    Cpa32U numBuffers;
    Cpa32U numLoops;
    ecdsa_step_t step;
    ec_curves_t* pCurve;
    Cpa32U threadID;
}ecdsa_test_params_t;

int main(int argc, char** argv)
{
    ec_curves_t *param = &curves_g[0];

    qat_init();


    qat_exit();

    return 0;
}