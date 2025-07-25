/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#include <gtest/gtest.h>
#include <thread>
#include <stdlib.h>
extern "C" {
#include "int.c"
}

TEST(SampleSetNum, success) {
    int test = 1234567;
    SampleSetNum(test);
    EXPECT_EQ(num_, test);
    EXPECT_STREQ(num_string, "1234567");
}

TEST(SampleSetNum, truncate) {
    int test = 1234567890;
    SampleSetNum(test);
    EXPECT_EQ(num_, test);
    EXPECT_STREQ(num_string, "1234567");
}

TEST(SampleIsOdd, odd) {
    int test = 1;
    SampleSetNum(test);
    EXPECT_TRUE(SampleIsOdd());
}

TEST(SampleIsOdd, even) {
    int test = 2;
    SampleSetNum(test);
    EXPECT_FALSE(SampleIsOdd());
}

TEST(SampleIsEven, odd) {
    int test = 1;
    SampleSetNum(test);
    EXPECT_FALSE(SampleIsEven());
}

TEST(SampleIsEven, even) {
    int test = 2;
    SampleSetNum(test);
    EXPECT_TRUE(SampleIsEven());
}

