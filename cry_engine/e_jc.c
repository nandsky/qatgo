#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "e_jc.h"
#include "jc_rsa.h"

#include <stdio.h>
#include "net.h"


static const char *engine_id = "jc";
static const char *engine_name = "jc engine";

static int jc_engine_init()
{
    connect_tcp(NULL);
    return 0;
}

static int bind(ENGINE *e, const char *id)
{
    int ret = 0;

    if (!ENGINE_set_id(e, engine_id)) {
        fprintf(stderr, "ENGINE_set_id failed\n");
        goto end;
    }
    if (!ENGINE_set_name(e, engine_name)) {
        printf("ENGINE_set_name failed\n");
        goto end;
    }
    jc_engine_init();

    if (!ENGINE_set_RSA(e, qat_get_RSA_methods())) {
        printf("ENGINE_set_name failed\n");
        goto end;
    }

    ret = 1;
    end:
    return ret;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()

