/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#include <gtest/gtest.h>
#include <thread>
#include <stdlib.h>
extern "C" {
#include "int_fix.c"
}

TEST(SampleSetNumFix, success) {
    int test = 1234567;
    SampleSetNumFix(test);
    EXPECT_EQ(num_fix_, test);
    EXPECT_STREQ(num_fix_string, "1234567");
}

TEST(SampleSetNumFix, truncate) {
    int test = 1234567890;
    SampleSetNumFix(test);
    EXPECT_EQ(num_fix_, test);
    EXPECT_STREQ(num_fix_string, "1234567");
}

TEST(SampleIsOddFix, odd) {
    int test = 1;
    SampleSetNumFix(test);
    EXPECT_TRUE(SampleIsOddFix());
}

TEST(SampleIsOddFix, even) {
    int test = 2;
    SampleSetNumFix(test);
    EXPECT_FALSE(SampleIsOddFix());
}

TEST(SampleIsEvenFix, odd) {
    int test = 1;
    SampleSetNumFix(test);
    EXPECT_FALSE(SampleIsEvenFix());
}

TEST(SampleIsEvenFix, even) {
    int test = 2;
    SampleSetNumFix(test);
    EXPECT_TRUE(SampleIsEvenFix());
}

