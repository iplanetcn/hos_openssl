# the minimum version of CMake.
cmake_minimum_required(VERSION 3.4.1)
project(hos_openssl)

set(NATIVERENDER_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

set(OPENSSL_PATH /Users/john/Library/Huawei/third_party/openssl)
set(OPENSSL_PATH_INCLUDE ${OPENSSL_PATH}/${OHOS_ARCH}/include)
set(OPENSSL_PATH_LIB ${OPENSSL_PATH}/${OHOS_ARCH}/lib)

include_directories(${NATIVERENDER_ROOT_PATH}
                    ${OPENSSL_PATH_INCLUDE})

add_library(entry SHARED hello.cpp rsa.h)

target_link_libraries(entry PUBLIC
        libace_napi.z.so
        hilog_ndk.z.so
        ${OPENSSL_PATH_LIB}/libcrypto.a
        ${OPENSSL_PATH_LIB}/libssl.a)
