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
#ifdef UT_LOG_OUTPUT_ENABLE
#include <stdio.h>
#include <stdarg.h>
#endif // UT_LOG_OUTPUT_ENABLE

/*----------------------------------------------------------------------------*/
void __wrap_syslog(int priority, const char *format, ...)
{
#ifdef UT_LOG_OUTPUT_ENABLE
    va_list arg;
    va_start(arg, format);
    vprintf(format, arg);
    va_end(arg);
#endif // UT_LOG_OUTPUT_ENABLE
}
