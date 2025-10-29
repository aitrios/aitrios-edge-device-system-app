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

#include "evp/sdk_sys.h"
#include "system_app_state.h"
#include "senscord/c_api/senscord_c_types.h"

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppStateUpdateString(uint32_t topic, uint32_t type, const char *string)
{
    check_expected(topic);
    check_expected(type);
    check_expected_ptr(string);

    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppStateSendState(uint32_t req)
{
    check_expected(req);

    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppStaInitialize(struct SYS_client *sys_client)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppStaFinalize(void)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppStateUpdateNumberWithIdx(uint32_t topic, uint32_t type, int number,
                                              uint32_t idx)
{
    check_expected(topic);
    check_expected(type);
    check_expected(number);
    check_expected(idx);

    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppStateSetInternalErrorWithIdx(uint32_t topic, uint32_t property, uint32_t idx)
{
    check_expected(topic);
    check_expected(property);
    check_expected(idx);

    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppStateSetInvalidArgErrorWithIdx(uint32_t topic, uint32_t property, uint32_t idx)
{
    check_expected(topic);
    check_expected(property);
    check_expected(idx);

    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppStateUpdateStringWithIdx(uint32_t topic, uint32_t type, const char *string,
                                              uint32_t idx)
{
    check_expected(topic);
    check_expected(type);
    check_expected_ptr(string);
    check_expected(idx);

    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppStateUpdateBoolean(uint32_t topic, uint32_t type, bool boolean)
{
    check_expected(topic);
    check_expected(type);
    check_expected(boolean);

    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppStateUpdateNumber(uint32_t topic, uint32_t type, int number)
{
    check_expected(topic);
    check_expected(type);
    check_expected(number);

    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppStateSetInvalidArgError(uint32_t topic, uint32_t property)
{
    check_expected(topic);
    check_expected(property);

    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppStateSetInternalError(uint32_t topic, uint32_t property)
{
    check_expected(topic);
    check_expected(property);

    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppStaClose(void)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppStaReopenIfClose(void)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppStateGetSensCordId(void *core_id)
{
    *(senscord_core_t *)core_id = mock_type(senscord_core_t);
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppStateGetSensCordStream(void *stream)
{
    *(senscord_stream_t *)stream = mock_type(senscord_stream_t);
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
char *__wrap_SysAppStateGetReqId(uint32_t topic)
{
    check_expected(topic);

    return mock_type(char *);
}

/*----------------------------------------------------------------------------*/
char *__wrap_SysAppStateGetProtocolVersion(void)
{
    return mock_type(char *);
}

/*----------------------------------------------------------------------------*/
void __wrap_SysAppStateGetTemperatureUpdateInterval(int *temperature_update_interval)
{
    *temperature_update_interval = mock_type(int);
    return;
}

/*----------------------------------------------------------------------------*/
bool __wrap_SysAppStaIsStateQueueEmpty(void)
{
    return mock_type(bool);
}

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
/*----------------------------------------------------------------------------*/
bool __wrap_SysAppStateIsUnimplementedTopic(const char *topic)
{
    return mock_type(bool);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppStateSendUnimplementedState(const char *topic, const char *id)
{
    return mock_type(RetCode);
}
#endif // !CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
