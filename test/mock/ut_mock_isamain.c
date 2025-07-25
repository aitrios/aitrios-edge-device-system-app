/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

/*----------------------------------------------------------------------------*/
#if defined(__NuttX__)
int __wrap_initial_setting_app_main(int argc, char *argv[])
{
#elif defined(__linux__)
int __wrap_initial_setting_app_main(void)
{
#endif
    return mock_type(int);
}

/*----------------------------------------------------------------------------*/
