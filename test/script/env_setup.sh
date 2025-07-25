#!/bin/bash
# SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

# Non Interactive at apt install
export DEBIAN_FRONTEND=noninteractive

# Install some packages for UnitTest
apt update && apt install cmake g++ make pkg-config libnl-genl-3-dev libcmocka-dev gcovr git lcov -y

# Clone mbedtls 
CURRENT=$(cd $(dirname $0);pwd -P)
TEST_TOP_DIR=${CURRENT}/..
TEST_INCLUDE=${TEST_TOP_DIR}/include

pushd $TEST_INCLUDE
if [ -e mbedtls ]; then
  rm -rf mbedtls
fi

git clone -b mbedtls-3.6.0 --depth=1 https://github.com/ARMmbed/mbedtls mbedtls

popd
