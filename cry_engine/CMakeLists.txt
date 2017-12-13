cmake_minimum_required(VERSION 3.8)
project(cry)

set(CMAKE_C_STANDARD 99)
#set( ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:/usr/local/opt/openssl/lib/pkgconfig" )

include_directories(
        /usr/local/opt/openssl@1.1/include
        /usr/include
        /usr/local/Cellar/protobuf-c/1.3.0_1/include
        ./
)
link_libraries(
        /usr/local/opt/openssl@1.1/lib
        /usr/lib64
        /usr/local/Cellar/protobuf-c/1.3.0_1/lib
        ./
)

set(SOURCE_FILES job.pb-c.c e_jc.c e_jc.h)
add_library(cry SHARED ${SOURCE_FILES})