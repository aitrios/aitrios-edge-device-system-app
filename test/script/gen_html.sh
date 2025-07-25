#!/bin/bash
# SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

CURRENT=$(cd $(dirname $0);pwd -P)
TEST_TOP_DIR=${CURRENT}/..
pushd $TEST_TOP_DIR

if [ -e html ]; then
  rm -rf html
fi
mkdir html

lcov --capture --directory ./coverage/ --output-file ./html/tmp.info --rc lcov_branch_coverage=1
lcov --rc lcov_branch_coverage=1 -b -c -d ./coverage/ -r ./html/tmp.info '/host/test/include/*' -o ./html/output.info
genhtml ./html/output.info --branch-coverage --output-directory ./html -p "/host/src"

popd
