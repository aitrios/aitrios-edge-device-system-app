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

#include "initial_setting_app_timer.h"

/*----------------------------------------------------------------------------*/
RetCode __wrap_IsaTimerInitialize(void)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_IsaTimerFinalize(void)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_IsaTimerStart(uint32_t time, IsaTimerCallback notify_cb)
{
    check_expected(time);
    check_expected(notify_cb);
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_IsaTimerStop(void)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
