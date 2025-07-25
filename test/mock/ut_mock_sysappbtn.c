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

#include "system_app_button.h"

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppBtnInitialize(void)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
bool __wrap_SysAppBtnCheckFactoryResetRequest(void)
{
    return mock_type(bool);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppBtnFinalize(void)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppBtnExecuteFactoryResetCore(void)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
bool __wrap_SysAppBtnCheckRebootRequest(void)
{
    return mock_type(bool);
}

/*----------------------------------------------------------------------------*/
