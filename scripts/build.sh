#!/bin/bash - 
#===============================================================================
#
#          FILE: build.sh
# 
#         USAGE: ./build.sh 
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
for arch in armeabi-v7a arm64-v8a x86_64
do
    bash build_openssl.sh $arch
done


