#!/bin/bash
set -e

# 用于编译 workflow 安卓版
# 下载本仓库，并将 NDK_HOME 传入，例如 ANDROID_NDK_HOME=/home/user/android-ndk-r21e ./build_android.sh
# 需要自行下载 NDK
# 脚本内默认编译出来 arm64 的，如果你需要其他版本的请修改下面的  ANDROID_ABI_ARCH 和 ANDROID_ABI 的值

# arm64 <--> arm64-v8a
# arm   <--> armdabi-v7a
# x86   <--> x86
# x86   <--> x86_64
ANDROID_ABI_ARCH=arm64
ANDROID_ABI=arm64-v8a
ANDROID_API_LEVEL=26
OPEN_SSL_VERSION=1.1.1l
OPEN_SSL_DIR=

WORKFLOW_DIR=$(realpath $(dirname $0))
DEFAULT_BUILD_DIR=build.cmake

echo WORKFLOW_DIR ${WORKFLOW_DIR}
echo ANDROID_NDK_HOME ${ANDROID_NDK_HOME}
echo ANDROID_ABI_ARCH ${ANDROID_ABI_ARCH}
echo ANDROID_ABI ${ANDROID_ABI}
echo ANDROID_API_LEVEL ${ANDROID_API_LEVEL}

if [ ! -n ${ANDROID_NDK_HOME} ]; then
    echo "you must specific Android ndk direcotry"
    exit 1
fi

function check_ndk_valid()
{
    if [ ! -d ${ANDROID_NDK_HOME} ]; then
        echo -e "no such a directory: ${ANDROID_NDK_HOME}"
        exit 1
    fi
}

function check_cleanable()
{
    if [ -f Makefile ]; then
        make clean
        rm -rf *
    fi
}

function build_openssl()
{
    if [ ! -f openssl-${OPEN_SSL_VERSION}.tar.gz ]; then
        wget https://www.openssl.org/source/openssl-${OPEN_SSL_VERSION}.tar.gz
        tar -xvf openssl-${OPEN_SSL_VERSION}.tar.gz -C .
    fi

    if [ ! -d openssl-${OPEN_SSL_VERSION} ]; then
        echo not found directory openssl-${OPEN_SSL_VERSION}
        exit 1
    fi

    OPEN_SSL_DIR=`realpath openssl-${OPEN_SSL_VERSION}`
    echo OPEN_SSL_DIR ${OPEN_SSL_DIR}
    rm -rf ${OPEN_SSL_DIR}
    tar -xvf openssl-${OPEN_SSL_VERSION}.tar.gz -C .
    echo "ready to build openssl "

    pushd openssl-${OPEN_SSL_VERSION}
    PATH=${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin:${ANDROID_NDK_HOME}/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin:$PATH
    ./Configure android-${ANDROID_ABI_ARCH} -D__ANDROID_API__=${ANDROID_API_LEVEL}
    make -j$(nproc)
    popd
}

function build_workflow()
{
    echo "ready to build workflow"
    
    rm -rvf ${DEFAULT_BUILD_DIR}
    cmake -B${DEFAULT_BUILD_DIR} -DANDROID_ABI=${ANDROID_ABI} -DANDROID_PLATFORM=android-${ANDROID_API_LEVEL} -DANDROID_NDK=${ANDROID_NDK_HOME} -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake -DOPENSSL_INCLUDE_DIR=${OPEN_SSL_DIR}/include -DOPENSSL_LINK_DIR=${OPEN_SSL_DIR} ${WORKFLOW_DIR}
    echo -e "proc num: ${nproc}"
    make clean -C ${DEFAULT_BUILD_DIR}
    make -j$(nproc) -C ${DEFAULT_BUILD_DIR}

    pushd tutorial
    rm -vrf ${DEFAULT_BUILD_DIR}
    cmake -B${DEFAULT_BUILD_DIR} -DANDROID_ABI=${ANDROID_ABI} -DANDROID_PLATFORM=android-${ANDROID_API_LEVEL} -DANDROID_NDK=${ANDROID_NDK_HOME} -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake -DOPENSSL_INCLUDE_DIR=${OPEN_SSL_DIR}/include -DOPENSSL_LINK_DIR=${OPEN_SSL_DIR} -Dworkflow_DIR=${WORKFLOW_DIR} .
    make -j$(nproc) -C ${DEFAULT_BUILD_DIR}
    popd
}

check_ndk_valid
build_openssl
build_workflow
