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

#include "system_app_led.h"

/*----------------------------------------------------------------------------*/
void __wrap_SysAppLedSetAppStatus(LedType type, LedAppStatus app_state)
{
    check_expected(type);
    check_expected(app_state);

    return;
}

/*----------------------------------------------------------------------------*/
void __wrap_SysAppLedUnsetAppStatus(LedType type, LedAppStatus app_state)
{
    check_expected(type);
    check_expected(app_state);

    return;
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppLedSetEnable(bool led_enable)
{
    check_expected(led_enable);

    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppLedGetEnable(bool *led_enable)
{
    *led_enable = mock_type(bool);
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
