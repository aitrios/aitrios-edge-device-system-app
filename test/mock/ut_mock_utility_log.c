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

#include "utility_log.h"

/*----------------------------------------------------------------------------*/
UtilityLogStatus __wrap_UtilityLogInit(void)
{
    return mock_type(UtilityLogStatus);
}

/*----------------------------------------------------------------------------*/
UtilityLogStatus __wrap_UtilityLogOpen(uint32_t module_id, UtilityLogHandle *handle)
{
    return mock_type(UtilityLogStatus);
}

/*----------------------------------------------------------------------------*/
UtilityLogStatus __wrap_UtilityLogClose(UtilityLogHandle handle)
{
    return mock_type(UtilityLogStatus);
}

/*----------------------------------------------------------------------------*/
UtilityLogStatus __wrap_UtilityLogDeinit(void)
{
    return mock_type(UtilityLogStatus);
}

/*----------------------------------------------------------------------------*/
UtilityLogStatus __wrap_UtilityLogForcedOutputToUart(const char *format, ...)
{
#ifdef UT_LOG_OUTPUT_ENABLE
    va_list arg;
    va_start(arg, format);
    vprintf(format, arg);
    va_end(arg);
#endif // UT_LOG_OUTPUT_ENABLE
    return mock_type(UtilityLogStatus);
}

/*----------------------------------------------------------------------------*/
UtilityLogStatus __wrap_UtilityLogWriteDLog(uint32_t module_id, UtilityLogDlogLevel level,
                                            const char *format, ...)
{
#ifdef UT_LOG_OUTPUT_ENABLE
    va_list arg;
    va_start(arg, format);
    vprintf(format, arg);
    va_end(arg);
#endif // UT_LOG_OUTPUT_ENABLE
    return kUtilityLogStatusOk;
}

/*----------------------------------------------------------------------------*/
UtilityLogStatus __wrap_UtilityLogWriteELog(uint32_t module_id, UtilityLogElogLevel level,
                                            uint16_t event_id)
{
    check_expected(module_id);
    check_expected(level);
    check_expected(event_id);

    return mock_type(UtilityLogStatus);
}

/*----------------------------------------------------------------------------*/
