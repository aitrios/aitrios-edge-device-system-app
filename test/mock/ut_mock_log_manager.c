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
#include "log_manager.h"

/*----------------------------------------------------------------------------*/
EsfLogManagerStatus __wrap_EsfLogManagerInit(void)
{
    return mock_type(EsfLogManagerStatus);
}

/*----------------------------------------------------------------------------*/
EsfLogManagerStatus __wrap_EsfLogManagerDeinit(void)
{
    return mock_type(EsfLogManagerStatus);
}

/*----------------------------------------------------------------------------*/
EsfLogManagerStatus __wrap_EsfLogManagerSetParameter(const EsfLogManagerSettingBlockType block_type,
                                                     const EsfLogManagerParameterValue value,
                                                     const EsfLogManagerParameterMask mask)
{
    check_expected(block_type);
    check_expected(value.dlog_level);
    check_expected(value.dlog_dest);
    check_expected(value.elog_level);
    check_expected(value.dlog_filter);
    check_expected_ptr(value.storage_name);
    check_expected_ptr(value.storage_path);
    check_expected(mask.dlog_level);
    check_expected(mask.dlog_dest);
    check_expected(mask.storage_name);
    check_expected(mask.storage_path);
    return mock_type(EsfLogManagerStatus);
}

/*----------------------------------------------------------------------------*/
EsfLogManagerStatus __wrap_EsfLogManagerGetParameter(EsfLogManagerSettingBlockType block_type,
                                                     EsfLogManagerParameterValue *value)
{
    memcpy(value, mock_type(EsfLogManagerParameterValue *), sizeof(EsfLogManagerParameterValue));
    check_expected(block_type);
    return mock_type(EsfLogManagerStatus);
}

/*----------------------------------------------------------------------------*/
EsfLogManagerStatus __wrap_EsfLogManagerStoreDlog(uint8_t *str, uint32_t size)
{
    return mock_type(EsfLogManagerStatus);
}

/*----------------------------------------------------------------------------*/
EsfLogManagerStatus __wrap_EsfLogManagerGetLogInfo(struct EsfLogManagerLogInfo *log_info)
{
    return mock_type(EsfLogManagerStatus);
}

/*----------------------------------------------------------------------------*/
EsfLogManagerStatus __wrap_EsfLogManagerGetExceptionData(uint32_t size, uint8_t *buf,
                                                         uint32_t *out_size)
{
    return mock_type(EsfLogManagerStatus);
}

/*----------------------------------------------------------------------------*/
EsfLogManagerStatus __wrap_EsfLogManagerStart(void)
{
    return mock_type(EsfLogManagerStatus);
}

/*----------------------------------------------------------------------------*/
