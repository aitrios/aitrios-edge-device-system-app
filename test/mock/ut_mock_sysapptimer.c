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

#include "system_app_timer.h"

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppTimerStartTimer(TimerType type, uint32_t time, TimerCallback notify_cb)
{
    return mock_type(RetCode);
}
/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppTimerStopTimer(TimerType type)
{
    return mock_type(RetCode);
}
/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppTimerInitialize(void)
{
    return mock_type(RetCode);
}
/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppTimerFinalize(void)
{
    return mock_type(RetCode);
}
/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppTimerUpdateTimer(TimerType type, uint32_t time)
{
    check_expected(type);
    check_expected(time);

    return mock_type(RetCode);
}
/*----------------------------------------------------------------------------*/
