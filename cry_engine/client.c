//
// Created by 朱宇 on 26/08/2017.
//
#include "protobuf-c-rpc-dispatch.h"
#include "protobuf-c-rpc.h"
#include "job.pb-c.h"
#include <stdio.h>

static void
handle_query_response (const Jobserver__JobReply *result,
                       void *closure_data)
{
    if (result == NULL)
        printf ("Error processing request.\n");
    else {
        printf("query_response: %s\n", result->msg);
    }
    * (protobuf_c_boolean *) closure_data = 1;
}
/* Run the main-loop without blocking.  It would be nice
   if there was a simple API for this (protobuf_c_rpc_dispatch_run_with_timeout?),
   but there isn't for now. */
static void
do_nothing (ProtobufCRPCDispatch *dispatch, void *unused)
{

    printf("sfafa\n");
}
static void
run_main_loop_without_blocking (ProtobufCRPCDispatch *dispatch)
{
    protobuf_c_rpc_dispatch_add_idle (dispatch, do_nothing, NULL);
    protobuf_c_rpc_dispatch_run (dispatch);
}
int test()
{
    ProtobufCService *service;
    ProtobufC_RPC_Client *client;
    ProtobufC_RPC_AddressType address_type=0;
    const char *name = "127.0.0.1:50051";
    address_type = PROTOBUF_C_RPC_ADDRESS_TCP;

    service = protobuf_c_rpc_client_new (address_type, name, &jobserver__job_server__descriptor, NULL);
    client = (ProtobufC_RPC_Client *) service;

    //protobuf_c_rpc_client_set_autoreconnect_period (client, 1000);

    while (!protobuf_c_rpc_client_is_connected (client))
        protobuf_c_rpc_dispatch_run (protobuf_c_rpc_dispatch_default ());
    fprintf (stderr, "done.\n");

    for (;;) {
        ProtobufCBinaryData payload;
        unsigned char buf[1024];
        protobuf_c_boolean is_done = 0;
        Jobserver__JobRequest request = JOBSERVER__JOB_REQUEST__INIT;

        payload.len = 1024;
        payload.data = buf;
        request.optype = 1;
        request.sni = "test_rsa";
        request.payload = payload;

        jobserver__job_server__say_hello(service, &request, handle_query_response , &is_done);
        while (!is_done) {
            protobuf_c_rpc_dispatch_run (protobuf_c_rpc_dispatch_default ());
            printf("------\n");
        }

        break;
    }
    return 0;
}

int main(int argc, char* argv[])
{

    test();
    return 0;
}