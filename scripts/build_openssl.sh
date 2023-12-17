#!/bin/bash - 
#===============================================================================
#
#          FILE: build_openssl.sh
# 
#         USAGE: ./build_openssl.sh 
# 
#   DESCRIPTION: 
# 
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: YOUR NAME (), 
#  ORGANIZATION: 
#       CREATED: 12/15/2023 22:58
#      REVISION:  ---
#===============================================================================

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


