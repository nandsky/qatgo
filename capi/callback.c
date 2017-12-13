//
// Created by 朱宇 on 23/07/2017.
//

#include <unistd.h>
#include <stdio.h>
#include "callback.h"
#include "qat.h"
#include "utils.h"

int notify_completion_port(const unsigned char* ctx_uuid)
{
    int rc = 0;
    rc = write(qat_completion_fd, ctx_uuid, UUID_LEN);
    printf("ctx uuid: %s, send notify success: %d\n", ctx_uuid, rc);
    if (rc > 0) {
        return 0;
    } else {
        DEBUG("ctx: %s notify failed!", ctx_uuid);
        return -1;
    }
}
