cmake_minimum_required(VERSION 3.8)
project(qatcgo)

set(CMAKE_C_STANDARD 99)
#set(CMAKE_CXX_STANDARD 11)

INCLUDE_DIRECTORIES(
        "./src/"
        "./lib/qat/"
 #       "/usr/include/c++/4.2.1/"
)

set(SOURCE_FILES
        capi/qat.c capi/qat.h
        capi/polling.c capi/polling.h
        capi/cipher.c capi/cipher.h
        capi/utils.c capi/utils.h
        capi/dsa.c capi/dsa.h
        capi/callback.c capi/callback.h
        capi/mem_utils.c capi/mem_utils.h
        capi/dh.c capi/dh.h
        capi/asym_common.c capi/asym_common.h
        capi/rsa.c capi/rsa.h
        capi/ec.h capi/ec.c
        capi/ecdsa.c capi/ecdsa.h
        capi/ecdh.c capi/ecdh.h
        )

set(TEST_SOURCE_FILES
        capi/test/test_md5.c capi/test/test_dh.c
        capi/test/test_ecdsa.c capi/test/test_utils.c capi/test/test_utils.h
        )

add_library(qatcgo SHARED ${SOURCE_FILES})