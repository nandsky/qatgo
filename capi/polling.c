//
// Created by 朱宇 on 22/07/2017.
//

#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include "qat.h"
#include "polling.h"
#include "utils.h"

#include "access_layer/icp_sal_poll.h"

/*
 * The default interval in nanoseconds used for the internal polling thread
 */
#define QAT_POLL_PERIOD_IN_NS 10000
/*
 * The number of retries of the nanosleep if it gets interrupted during
 * waiting between polling.
 */
#define QAT_CRYPTO_NUM_POLLING_RETRIES (5)

int keep_polling = 1;

// 事件poll
CpaStatus poll_instances(void)
{
    unsigned int i = 0;
    CpaStatus ret_status = CPA_STATUS_SUCCESS,
            internal_status = CPA_STATUS_SUCCESS;
    Cpa32U response_quota = 0;

    for (i = 0; i < qat_num_instances; i++) {
        if (qat_instance_handles[i] != NULL) {
            internal_status = icp_sal_CyPollInstance(qat_instance_handles[i], response_quota);

            if (CPA_STATUS_SUCCESS == internal_status) {
            } else if (CPA_STATUS_RETRY == internal_status) {
                ret_status = internal_status;
            } else {
                ret_status = internal_status;
                break;
            }
        }
    }
    return ret_status;
}

// 按时间poll
void *timer_poll_func(void *ih)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle *handle = (CpaInstanceHandle*)ih;
    Cpa32U response_quota = 0;

    int retry_count = 0;
    struct timespec req_time = { 0 };
    struct timespec rem_time = { 0 };


    while (keep_polling) {
        req_time.tv_nsec = QAT_POLL_PERIOD_IN_NS;
        status = icp_sal_CyPollInstance(handle, response_quota);
        if (status == CPA_STATUS_SUCCESS) {
            ;
        }

        retry_count = 0;
        do {
            retry_count++;
            nanosleep(&req_time, &rem_time);
            req_time.tv_sec = rem_time.tv_sec;
            req_time.tv_nsec = rem_time.tv_nsec;
            if (unlikely((errno < 0) && (EINTR != errno))) {
                DEBUG("nanosleep system call failed: errno %i\n", errno);
                break;
            }
        }
        while ((retry_count <= QAT_CRYPTO_NUM_POLLING_RETRIES)
               && (EINTR == errno));
    }
}