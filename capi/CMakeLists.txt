cmake_minimum_required(VERSION 3.8)
project(capi)

set(CMAKE_C_STANDARD 99)
#set(CMAKE_CXX_STANDARD 11)

INCLUDE_DIRECTORIES(
        "./"
        "../lib/qat/"
        #       "/usr/include/c++/4.2.1/"
)

set(SOURCE_FILES
        asym_common.c
        asym_common.h
        callback.c
        callback.h
        cipher.c
        cipher.h
        dh.c
        dh.h
        dsa.c
        dsa.h
        ecdsa.c
        ecdsa.h
        Makefile
        mem_utils.c
        mem_utils.h
        polling.c
        polling.h
        qae_mem.h
        qae_mem_utils.c
        qat.c
        qat.h
        README.md
        rsa.c
        rsa.h
        utils.c
        utils.h
        ec.h
        ec.c
        ecdh.h
        ecdh.c
        )

ADD_LIBRARY(libqat.so SHARED ${SOURCE_FILES})
