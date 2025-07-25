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

#include <string.h>
#include "system_app_common.h"

/*----------------------------------------------------------------------------*/
SSFStatus __wrap_SsfDeviceSettingInit(void)
{
    return mock_type(SSFStatus);
}

/*----------------------------------------------------------------------------*/
SSFStatus __wrap_SsfDeviceSettingDeinit(void)
{
    return mock_type(SSFStatus);
}

/*----------------------------------------------------------------------------*/
SSFStatus __wrap_SsfDeviceSettingOpen(SsfDeviceSettingHandle* handle)
{
    return mock_type(SSFStatus);
}

/*----------------------------------------------------------------------------*/
SSFStatus __wrap_SsfDeviceSettingClose(SsfDeviceSettingHandle handle)
{
    return mock_type(SSFStatus);
}

/*----------------------------------------------------------------------------*/
