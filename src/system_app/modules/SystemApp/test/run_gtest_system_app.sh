#!/bin/bash
# SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

CURRENT=$(cd $(dirname $0);pwd -P)
pushd $CURRENT
# --- System App Test ---
# Description for running gtest
./exec_unit_test.sh build t3s3
./exec_unit_test.sh test 2>&1 | tee system_app_t3s3_gtest_result.txt
# Coverage output description (run after gtest)
./exec_unit_test.sh c0 2>&1 | tee system_app_t3s3_gtest_coverage_c0.txt
./exec_unit_test.sh c1 2>&1 | tee system_app_t3s3_gtest_coverage_c1.txt
popd

