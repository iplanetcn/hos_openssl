Build Openssl for HarmonyOS
---
### build 
[Reference Link](https://developer.huawei.com/consumer/cn/forum/topic/0201133716397307076)

[build_config.sh](scripts/build_config.sh)
```shell
set -o nounset                              # Treat unset variables as an error
#NDK路径
export OHOS_NATIVE_HOME=/Users/john/Library/Huawei/Sdk/openharmony/9/native
export PATH=$OHOS_NATIVE_HOME/llvm/bin:$PATH
#cpu架构
if [ "$#" -lt 1 ]; then
    THE_ARCH=armv7
else
    THE_ARCH=$(tr [A-Z] [a-z] <<< "$1")
fi

BASE_FLAGS="--sysroot=$OHOS_NATIVE_HOME/sysroot -fdata-sections -ffunction-sections -funwind-tables -fstack-protector-strong -no-canonical-prefixes -fno-addrsig -Wa,--noexecstack -fPIC"

#根据不同架构配置环境变量
case "$THE_ARCH" in
  armv7a|armeabi-v7a)
    OHOS_ARCH="armeabi-v7a"
    OHOS_TARGET="arm-linux-ohos"
    OPENSSL_ARCH="linux-armv4"
    FF_EXTRA_CFLAGS="--target=$OHOS_TARGET $BASE_FLAGS -march=armv7a"
    FF_CFLAGS="--target=$OHOS_TARGET $BASE_FLAGS -march=armv7a"
    ;;
  armv8|armv8a|aarch64|arm64|arm64-v8a)
    OHOS_ARCH="arm64"
    OHOS_TARGET="aarch64-linux-ohos"
    OPENSSL_ARCH="linux-aarch64"
    FF_EXTRA_CFLAGS="--target=$OHOS_TARGET $BASE_FLAGS"
    FF_CFLAGS="--target=$OHOS_TARGET $BASE_FLAGS"
    ;;
  x86_64|x64)
    OHOS_ARCH="x86_64"
    OHOS_TARGET="x86_64-linux-ohos"
    OPENSSL_ARCH="linux-x86_64"
    FF_EXTRA_CFLAGS="--target=$OHOS_TARGET $BASE_FLAGS"
    FF_CFLAGS="--target=$OHOS_TARGET $BASE_FLAGS"
    ;;
  *)
    echo "ERROR: Unknown architecture $1"
    [ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
    ;;
esac

# 工具链
TOOLCHAIN=$OHOS_NATIVE_HOME/llvm

# 交叉编译库搜索路径
SYS_ROOT=$OHOS_NATIVE_HOME/sysroot
# 编译器
CC=$TOOLCHAIN/bin/clang
CXX=$TOOLCHAIN/bin/clang++
# 链接器，将目标文件（包括静态库和共享库）合并成一个可执行文件或共享库
LD=$TOOLCHAIN/bin/ld-lld
# 汇编器，将汇编语言代码转换为机器代码
AS=$TOOLCHAIN/bin/llvm-as
# 静态库管理工具，用于创建、修改和提取静态库中的目标文件
AR=$TOOLCHAIN/bin/llvm-ar
# 符号表工具，用于显示目标文件中的符号（函数、变量等）信息
NM=$TOOLCHAIN/bin/llvm-nm
# 静态库索引工具，用于创建和更新静态库的索引，以提高库的访问速度
RANLIB=$TOOLCHAIN/bin/llvm-ranlib
# 剥离工具，用于从可执行文件或共享库中去除调试信息，从而减小文件大小
STRIP=$TOOLCHAIN/bin/llvm-strip
```

[build_openssl.sh](scripts/build_openssl.sh)
```shell
set -o nounset                              # Treat unset variables as an error
#!/bin/bash
ARCH=$1
source build_config.sh $ARCH
LIBS_DIR=$(cd `dirname $0`; pwd)/libs/openssl
PREFIX=$LIBS_DIR/$OHOS_ARCH

echo "PREFIX"=$PREFIX

export CC="$CC"
export CXX="$CXX"
export CXXFLAGS=$FF_EXTRA_CFLAGS
export CFLAGS=$FF_CFLAGS
export AR="$AR"
export LD="$LD"
export AS="$AS"
export NM="$NM"
export RANLIB="$RANLIB"
export STRIP="$STRIP"
export LDFLAGS="--rtlib=compiler-rt -fuse-ld=lld"

./Configure $OPENSSL_ARCH \
--prefix=$PREFIX \
no-engine \
no-asm \
no-threads \
shared

make clean
make -j2
make install

cd ..

```

[build.sh](scripts/build.sh)
```shell
set -o nounset                              # Treat unset variables as an error
for arch in armeabi-v7a arm64-v8a x86_64
do
    bash build_openssl.sh $arch
done
```

### Usage
1. check build archives in libs
2. rename some folders
3. CMakeLists.txt
    ```cmake
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
    ```
4. write a test