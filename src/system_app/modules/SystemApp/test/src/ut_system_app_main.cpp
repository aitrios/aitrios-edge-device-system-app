/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#include <gtest/gtest.h>
#include <thread>
#include <stdlib.h>
#if defined(__NuttX__)
#include "nuttx/compiler.h"
#endif
#define main(argc, argv) main_func(argc, argv)
extern "C" {
#include "system_app_main.c"
}
#undef main

TEST(system_app_main, main)
{
    int32_t argc = 1;
    char cmdname[] = "system_app";
    char *argv[1024] = {cmdname};
    int32_t ret = main_func(argc, argv);
    ASSERT_EQ(ret, 0);
}
