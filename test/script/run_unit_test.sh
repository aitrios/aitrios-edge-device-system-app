#!/bin/bash
# SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

# Check unit test result
function check_ut_result() {
  if [ ${PIPESTATUS[0]} -ne 0 ]; then
    is_unit_test_ng=1
  fi
}

# Execution build, running unit test and collecting coverage
function build_test_collect() {
  # Exec Build
  ./script/exec_unit_test.sh build $1
  if [ $? -ne 0 ]; then
    popd
    exit 1
  fi

  # Run Unit Test
  ./script/exec_unit_test.sh test $1 2>&1 | tee ut_result_$1.txt
  check_ut_result

  # Collect coverage
  ./script/exec_unit_test.sh collect $1
}

# Define current path and test directory path
CURRENT=$(cd $(dirname $0);pwd -P)
TEST_TOP_DIR=${CURRENT}/..

# Save current path and move test path
pushd $TEST_TOP_DIR

# Init unit test ng flag
is_unit_test_ng=0

if [ -d "../test/private" ]; then
  # T5 Phase
  build_test_collect T5

  # T3P Phase
  build_test_collect T3P

  # T3Ws Phase
  build_test_collect T3Ws
fi

# Raspi Phase
build_test_collect Raspi

# Output coverage rate
./script/exec_unit_test.sh c0 2>&1 | tee ut_coverage_c0.txt
./script/exec_unit_test.sh c1 2>&1 | tee ut_coverage_c1.txt

# Move current path
popd

# Check Unit Test Fail
if [ $is_unit_test_ng -eq 1 ]; then
  exit 2
fi

# All build and test OK
exit 0
