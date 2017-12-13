/*
 * QAT卡管理相关
 */
#include "qat.h"

#include <stdio.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <memory.h>
#include <pthread.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "utils.h"
#include "access_layer/icp_sal_user.h"
#include "lac/cpa_cy_common.h"
#include "lac/cpa_cy_im.h"
#include "qae_mem.h"
#include "polling.h"



char *ICPConfigSectionName_libcrypto = "SHIM";
CpaInstanceHandle *qat_instance_handles = NULL;
Cpa16U qat_num_instances = 0;
pthread_mutex_t qat_init_mutex = PTHREAD_MUTEX_INITIALIZER;
unsigned int qat_inited = 0;
pthread_t polling_thread;   // poll
int qat_completion_fd = 0;
int curr_inst = 0;
pthread_mutex_t qat_instance_mutex = PTHREAD_MUTEX_INITIALIZER;


QatStats qstats;

extern CpaStatus qaeMemInit(void);
extern void qaeMemDestroy(void);

int _connectUnixCompletionPort();
int _connectTcpCompletionPort();

int _createUDS();
static CpaPhysicalAddr virtualToPhysical(void *virtual_addr) {
    if (virtual_addr == NULL) {
        DEBUG("BECARFIL....\n");
    }
    return qaeVirtToPhysNUMA(virtual_addr);
}

static inline void incr_curr_inst(void)
{
    pthread_mutex_lock(&qat_instance_mutex);
    curr_inst = (curr_inst + 1) % qat_num_instances;
    pthread_mutex_unlock(&qat_instance_mutex);
}

// todo: 用多个Instance来加速
int qat_init()
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaBoolean limitDevAccess = CPA_TRUE;
    pthread_t poll_thread;
    int i = 0;

    DEBUG("- Started!\n");
    pthread_mutex_lock(&qat_init_mutex);
    if (qat_inited) {
        // 无需再次初始化
        pthread_mutex_unlock(&qat_init_mutex);
        return 0;
    }

    // Completion port
    i = _connectTcpCompletionPort();
    if (i != 0) {
        DEBUG("connectCompletionPort failed!\n");
        return -1;
    }
    // QAT
    if (CPA_STATUS_SUCCESS != icp_sal_userStartMultiProcess("SHIM", limitDevAccess)) {
        DEBUG("-start failed\n");
        pthread_mutex_unlock(&qat_init_mutex);
        return -1;
    }

    if (CPA_STATUS_SUCCESS != cpaCyGetNumInstances(&qat_num_instances)) {
        DEBUG("-get num instance failed\n");
        pthread_mutex_unlock(&qat_init_mutex);
        return -1;
    }
    if (!qat_num_instances ) {
        pthread_mutex_unlock(&qat_init_mutex);
        return -1;
    }
    DEBUG("instances num: %d\n", qat_num_instances);

    qat_instance_handles = malloc(qat_num_instances *  sizeof(CpaInstanceHandle));
    if (NULL == qat_instance_handles) {
        pthread_mutex_unlock(&qat_init_mutex);
        return -1;
    }
    memset(qat_instance_handles, 0, qat_num_instances * sizeof(CpaInstanceHandle));

    status = cpaCyGetInstances(qat_num_instances, qat_instance_handles);
    if (CPA_STATUS_SUCCESS != status) {
        pthread_mutex_unlock(&qat_init_mutex);
        return -1;
    }

    // memory
    status = qaeMemInit();
    if (CPA_STATUS_SUCCESS != status) {
        pthread_mutex_unlock(&qat_init_mutex);
        return -1;
    }

    for (i = 0; i < qat_num_instances; i++) {
        status = cpaCySetAddressTranslation(qat_instance_handles[i], virtualToPhysical);
        if (CPA_STATUS_SUCCESS != status) {
            pthread_mutex_unlock(&qat_init_mutex);
            qat_exit();
            return -1;
        }

        status = cpaCyStartInstance(qat_instance_handles[i]);
        if (CPA_STATUS_SUCCESS != status) {
            pthread_mutex_unlock(&qat_init_mutex);
            qat_exit();
            return -1;
        }
        // poll
        if (0 != pthread_create(
                &poll_thread, NULL, (void*)timer_poll_func, qat_instance_handles[i])) {
            pthread_mutex_unlock(&qat_init_mutex);
            qat_exit();
            return -1;
        }

    }

    qat_inited = 1;
    pthread_mutex_unlock(&qat_init_mutex);

    DEBUG("- QAT init success!\n");
    return 0;

}

int qat_exit()
{
    DEBUG("-begin exit!\n");
    int i = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;

    for (i = 0; i < qat_num_instances; i++) {
        if (qat_instance_handles[i]) {
            status = cpaCyStopInstance(qat_instance_handles);
            DEBUG("stop instance.. idx: %d, status: %d\n", i, status);
        }
    }
    qaeMemDestroy();

    if (qat_completion_fd > 0) {
        close(qat_completion_fd);

    }
    DEBUG("-exit finish!\n");
    return 0;
}

// 获取下一个加解密实例
CpaInstanceHandle *getNextCyInstance()
{
    CpaInstanceHandle instance_handle = NULL;

    // 迭代方式，获取下一个实例句柄
    instance_handle = qat_instance_handles[curr_inst];
    incr_curr_inst();

    return instance_handle;
}

//
int _connectUnixCompletionPort() {
    char *socket_path = "/var/run/cipherComm";
    struct sockaddr_un addr;
    int fd = 0;

    if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        return -1;
    }
    qat_completion_fd = fd;
    return 0;
}

//
int _connectTcpCompletionPort() {
    int ret = 0;
    int sockfd = 0;
    struct sockaddr_in dest_addr;
    /* 取得一个套接字*/
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        return -1;
    }
    /* 设置远程连接的信息*/
    dest_addr.sin_family = AF_INET;                 /* 注意主机字节顺序*/
    dest_addr.sin_port = htons(50052);          /* 远程连接端口, 注意网络字节顺序*/
    dest_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); /* 远程 IP 地址, inet_addr() 会返回网络字节顺序*/
    bzero(&(dest_addr.sin_zero), 8);                /* 其余结构须置 0*/

    /* 连接远程主机，出错返回 -1*/
    ret = connect(sockfd, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in));
    if (ret == -1) {
        return -1;
    }
    qat_completion_fd = sockfd;
    return 0;

}
