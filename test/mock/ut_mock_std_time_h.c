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

#include <time.h>

/*----------------------------------------------------------------------------*/
int __wrap_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
    int ret = mock_type(int);      // return status : {0:success | -1:error}
    tp->tv_sec = mock_type(int);   // return time (sec) : {0..}
    tp->tv_nsec = mock_type(long); // return time (ns) : {0L..999999999L}
    return ret;
}
