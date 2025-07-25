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

#include "utility_timer.h"

/*----------------------------------------------------------------------------*/
UtilityTimerErrCode __wrap_UtilityTimerInitialize(void)
{
    return mock_type(UtilityTimerErrCode);
}

/*----------------------------------------------------------------------------*/
UtilityTimerErrCode __wrap_UtilityTimerFinalize(void)
{
    function_called();

    return mock_type(UtilityTimerErrCode);
}

/*----------------------------------------------------------------------------*/
UtilityTimerErrCode __wrap_UtilityTimerCreate(const UtilityTimerCallback utility_timer_cb,
                                              void *timer_cb_params,
                                              UtilityTimerHandle *utility_timer_handle)
{
    check_expected_ptr(utility_timer_cb);
    check_expected_ptr(timer_cb_params);

    *utility_timer_handle = mock_type(UtilityTimerHandle);

    return mock_type(UtilityTimerErrCode);
}

/*----------------------------------------------------------------------------*/
UtilityTimerErrCode __wrap_UtilityTimerDelete(UtilityTimerHandle utility_timer_handle)
{
    check_expected(utility_timer_handle);

    return mock_type(UtilityTimerErrCode);
}

/*----------------------------------------------------------------------------*/
UtilityTimerErrCode __wrap_UtilityTimerStart(const UtilityTimerHandle utility_timer_handle,
                                             const struct timespec *interval_ts,
                                             const UtilityTimerRepeatType utility_timer_repeat_type)
{
    check_expected(utility_timer_handle);
    check_expected(interval_ts->tv_sec);
    check_expected(interval_ts->tv_nsec);
    check_expected(utility_timer_repeat_type);

    return mock_type(UtilityTimerErrCode);
}

/*----------------------------------------------------------------------------*/
UtilityTimerErrCode __wrap_UtilityTimerStop(const UtilityTimerHandle utility_timer_handle)
{
    check_expected(utility_timer_handle);

    return mock_type(UtilityTimerErrCode);
}

/*----------------------------------------------------------------------------*/
UtilityTimerErrCode __wrap_UtilityTimerCreateEx(const UtilityTimerCallback callback,
                                                void *cb_params, int priority, size_t stacksize,
                                                UtilityTimerHandle *timer_handle)
{
    check_expected_ptr(callback);
    check_expected_ptr(cb_params);
    check_expected(priority);
    check_expected(stacksize);

    *timer_handle = mock_type(UtilityTimerHandle);

    return mock_type(UtilityTimerErrCode);
}
