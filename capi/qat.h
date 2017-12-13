
#ifndef QATCGO_LIBRARY_H
#define QATCGO_LIBRARY_H

#include <stdlib.h>
#include <cpa_types.h>
#include <cpa.h>

#define likely(x)   __builtin_expect (!!(x), 1)
#define unlikely(x) __builtin_expect (!!(x), 0)

// QAT状态数据
typedef struct _QatStats {
    // 操作实例
    int instances_count;
    // 总操作
    int total_op;
    // RSA操作
    int rsa_op_count;
    int dsa_op_count;
    int ec_op_count;
}QatStats;

extern CpaInstanceHandle *qat_instance_handles;
extern Cpa16U qat_num_instances;
extern int qat_completion_fd;
extern QatStats qstats;

#define UUID_LEN 3

int qat_init();
int qat_exit();
CpaInstanceHandle *getNextCyInstance();

#endif

