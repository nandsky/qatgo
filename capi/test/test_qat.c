//
// Created by 朱宇 on 24/09/2017.
//

#include <stdio.h>
#include <cpa_types.h>
#include <cpa.h>
#include "access_layer/icp_sal_user.h"
#include "lac/cpa_cy_common.h"


int main(int argc, char** argv)
{
    int qat_num_instances = 0;
    // QAT
    if (CPA_STATUS_SUCCESS != icp_sal_userStartMultiProcess("SHIM", 1)) {
        printf("-start failed\n");
        return -1;
    }
    if (CPA_STATUS_SUCCESS != cpaCyGetNumInstances(&qat_num_instances)) {
        printf("-get num instance failed\n");
        return -1;
    }
    if (!qat_num_instances ) {
        return -1;
    }
    printf("instances num: %d\n", qat_num_instances);
    return 0;
}
