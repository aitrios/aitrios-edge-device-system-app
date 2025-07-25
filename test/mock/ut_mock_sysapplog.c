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

#include "system_app_log.h"

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppLogGetParameterNumber(CfgStLogFilter filter, SystemSettingsProperty prop,
                                           int *ret_value)
{
    switch (mock_type(SystemSettingsProperty)) {
        case LogLevel:
            *ret_value = (int)mock_type(CfgStLogLevel);
            break;
        case LogDestination:
            *ret_value = (int)mock_type(CfgStLogDestination);
            break;
        default:
            /* Do Nothing */
            break;
    }

    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppLogGetParameterString(CfgStLogFilter filter, SystemSettingsProperty prop,
                                           char *ret_value, size_t buff_size)
{
    snprintf(ret_value, buff_size, "%s", mock_type(const char *));
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppLogSetParameterNumber(CfgStLogFilter filter, SystemSettingsProperty prop,
                                           int set_value)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppLogSetParameterString(CfgStLogFilter filter, SystemSettingsProperty prop,
                                           const char *set_value, size_t buff_size)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
