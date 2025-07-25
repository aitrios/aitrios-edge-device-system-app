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
#include "system_app_common.h"
#include "system_app_log.h"

extern EsfLogManagerSettingBlockType EncodeFiltertToBlockType(CfgStLogFilter filter);

/*----------------------------------------------------------------------------*/

//
// SysAppLogGetParameterNumber()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterNumber_MainFwLogLogLevelCriticalFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel ret_value;
    EsfLogManagerParameterValue value = {
        .dlog_dest = 0,
        .dlog_level = kEsfLogManagerDlogLevelCritical,
        .elog_level = 0,
        .dlog_filter = 0,
        .storage_name = "TestStorageName",
        .storage_path = "TestPathName",
    };

    // Call EsfLogManagerGetParameter
    will_return(__wrap_EsfLogManagerGetParameter, &value);
    will_return(__wrap_EsfLogManagerGetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerGetParameter, block_type, kEsfLogManagerBlockTypeSysApp);

    RetCode ret = SysAppLogGetParameterNumber(filter, prop, (int *)&ret_value);
    assert_int_equal(ret, kRetOk);
    assert_int_equal(ret_value, CriticalLv);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterNumber_MainFwLogLogLevelErrorFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel ret_value;
    EsfLogManagerParameterValue value = {
        .dlog_dest = 0,
        .dlog_level = kEsfLogManagerElogLevelError,
        .elog_level = 0,
        .dlog_filter = 0,
        .storage_name = "TestStorageName",
        .storage_path = "TestPathName",
    };

    // Call EsfLogManagerGetParameter
    will_return(__wrap_EsfLogManagerGetParameter, &value);
    will_return(__wrap_EsfLogManagerGetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerGetParameter, block_type, kEsfLogManagerBlockTypeSysApp);

    RetCode ret = SysAppLogGetParameterNumber(filter, prop, (int *)&ret_value);
    assert_int_equal(ret, kRetOk);
    assert_int_equal(ret_value, ErrorLv);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterNumber_MainFwLogLogLevelWarnFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel ret_value;
    EsfLogManagerParameterValue value = {
        .dlog_dest = 0,
        .dlog_level = kEsfLogManagerDlogLevelWarn,
        .elog_level = 0,
        .dlog_filter = 0,
        .storage_name = "TestStorageName",
        .storage_path = "TestPathName",
    };

    // Call EsfLogManagerGetParameter
    will_return(__wrap_EsfLogManagerGetParameter, &value);
    will_return(__wrap_EsfLogManagerGetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerGetParameter, block_type, kEsfLogManagerBlockTypeSysApp);

    RetCode ret = SysAppLogGetParameterNumber(filter, prop, (int *)&ret_value);
    assert_int_equal(ret, kRetOk);
    assert_int_equal(ret_value, WarningLv);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterNumber_MainFwLogLogLevelInfoFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel ret_value;
    EsfLogManagerParameterValue value = {
        .dlog_dest = 0,
        .dlog_level = kEsfLogManagerDlogLevelInfo,
        .elog_level = 0,
        .dlog_filter = 0,
        .storage_name = "TestStorageName",
        .storage_path = "TestPathName",
    };

    // Call EsfLogManagerGetParameter
    will_return(__wrap_EsfLogManagerGetParameter, &value);
    will_return(__wrap_EsfLogManagerGetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerGetParameter, block_type, kEsfLogManagerBlockTypeSysApp);

    RetCode ret = SysAppLogGetParameterNumber(filter, prop, (int *)&ret_value);
    assert_int_equal(ret, kRetOk);
    assert_int_equal(ret_value, InfoLv);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterNumber_MainFwLogLogLevelDebugFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel ret_value;
    EsfLogManagerParameterValue value = {
        .dlog_dest = 0,
        .dlog_level = kEsfLogManagerDlogLevelDebug,
        .elog_level = 0,
        .dlog_filter = 0,
        .storage_name = "TestStorageName",
        .storage_path = "TestPathName",
    };

    // Call EsfLogManagerGetParameter
    will_return(__wrap_EsfLogManagerGetParameter, &value);
    will_return(__wrap_EsfLogManagerGetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerGetParameter, block_type, kEsfLogManagerBlockTypeSysApp);

    RetCode ret = SysAppLogGetParameterNumber(filter, prop, (int *)&ret_value);
    assert_int_equal(ret, kRetOk);
    assert_int_equal(ret_value, DebugLv);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterNumber_MainFwLogLogLevelTraceFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel ret_value;
    EsfLogManagerParameterValue value = {
        .dlog_dest = 0,
        .dlog_level = kEsfLogManagerDlogLevelTrace,
        .elog_level = 0,
        .dlog_filter = 0,
        .storage_name = "TestStorageName",
        .storage_path = "TestPathName",
    };

    // Call EsfLogManagerGetParameter
    will_return(__wrap_EsfLogManagerGetParameter, &value);
    will_return(__wrap_EsfLogManagerGetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerGetParameter, block_type, kEsfLogManagerBlockTypeSysApp);

    RetCode ret = SysAppLogGetParameterNumber(filter, prop, (int *)&ret_value);
    assert_int_equal(ret, kRetOk);
    assert_int_equal(ret_value, VerboseLv);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterNumber_MainFwLogLogLevelNumDefault(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel ret_value;
    EsfLogManagerParameterValue value = {
        .dlog_dest = 0,
        .dlog_level = kEsfLogManagerDlogLevelNum,
        .elog_level = 0,
        .dlog_filter = 0,
        .storage_name = "TestStorageName",
        .storage_path = "TestPathName",
    };

    // Call EsfLogManagerGetParameter
    will_return(__wrap_EsfLogManagerGetParameter, &value);
    will_return(__wrap_EsfLogManagerGetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerGetParameter, block_type, kEsfLogManagerBlockTypeSysApp);

    RetCode ret = SysAppLogGetParameterNumber(filter, prop, (int *)&ret_value);
    assert_int_equal(ret, kRetOk);
    assert_int_equal(ret_value, LogLevelNum);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterNumber_SensorLogLogLevelFullySuccess(void **state)
{
    CfgStLogFilter filter = SensorLog;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel ret_value;
    EsfLogManagerParameterValue value = {
        .dlog_dest = 0,
        .dlog_level = kEsfLogManagerDlogLevelCritical,
        .elog_level = 0,
        .dlog_filter = 0,
        .storage_name = "TestStorageName",
        .storage_path = "TestPathName",
    };

    // Call EsfLogManagerGetParameter
    will_return(__wrap_EsfLogManagerGetParameter, &value);
    will_return(__wrap_EsfLogManagerGetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerGetParameter, block_type, kEsfLogManagerBlockTypeSensor);

    RetCode ret = SysAppLogGetParameterNumber(filter, prop, (int *)&ret_value);
    assert_int_equal(ret, kRetOk);
    assert_int_equal(ret_value, CriticalLv);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterNumber_CompanionFwLogLogLevelFullySuccess(void **state)
{
    CfgStLogFilter filter = CompanionFwLog;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel ret_value;
    EsfLogManagerParameterValue value = {
        .dlog_dest = 0,
        .dlog_level = kEsfLogManagerDlogLevelCritical,
        .elog_level = 0,
        .dlog_filter = 0,
        .storage_name = "TestStorageName",
        .storage_path = "TestPathName",
    };

    // Call EsfLogManagerGetParameter
    will_return(__wrap_EsfLogManagerGetParameter, &value);
    will_return(__wrap_EsfLogManagerGetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerGetParameter, block_type, kEsfLogManagerBlockTypeAiisp);

    RetCode ret = SysAppLogGetParameterNumber(filter, prop, (int *)&ret_value);
    assert_int_equal(ret, kRetOk);
    assert_int_equal(ret_value, CriticalLv);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterNumber_CompanionAppLogLogLevelFullySuccess(void **state)
{
    CfgStLogFilter filter = CompanionAppLog;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel ret_value;
    EsfLogManagerParameterValue value = {
        .dlog_dest = 0,
        .dlog_level = kEsfLogManagerDlogLevelCritical,
        .elog_level = 0,
        .dlog_filter = 0,
        .storage_name = "TestStorageName",
        .storage_path = "TestPathName",
    };

    // Call EsfLogManagerGetParameter
    will_return(__wrap_EsfLogManagerGetParameter, &value);
    will_return(__wrap_EsfLogManagerGetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerGetParameter, block_type, kEsfLogManagerBlockTypeVicapp);

    RetCode ret = SysAppLogGetParameterNumber(filter, prop, (int *)&ret_value);
    assert_int_equal(ret, kRetOk);
    assert_int_equal(ret_value, CriticalLv);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterNumber_LogDestinationUartFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogDestination;
    CfgStLogLevel ret_value;
    EsfLogManagerParameterValue value = {
        .dlog_dest = kEsfLogManagerDlogDestUart,
        .dlog_level = 0,
        .elog_level = 0,
        .dlog_filter = 0,
        .storage_name = "TestStorageName",
        .storage_path = "TestPathName",
    };

    // Call EsfLogManagerGetParameter
    will_return(__wrap_EsfLogManagerGetParameter, &value);
    will_return(__wrap_EsfLogManagerGetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerGetParameter, block_type, kEsfLogManagerBlockTypeSysApp);

    RetCode ret = SysAppLogGetParameterNumber(filter, prop, (int *)&ret_value);
    assert_int_equal(ret, kRetOk);
    assert_int_equal(ret_value, DestUart);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterNumber_LogDestinationStoreFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogDestination;
    CfgStLogLevel ret_value;
    EsfLogManagerParameterValue value = {
        .dlog_dest = kEsfLogManagerDlogDestStore,
        .dlog_level = 0,
        .elog_level = 0,
        .dlog_filter = 0,
        .storage_name = "TestStorageName",
        .storage_path = "TestPathName",
    };

    // Call EsfLogManagerGetParameter
    will_return(__wrap_EsfLogManagerGetParameter, &value);
    will_return(__wrap_EsfLogManagerGetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerGetParameter, block_type, kEsfLogManagerBlockTypeSysApp);

    RetCode ret = SysAppLogGetParameterNumber(filter, prop, (int *)&ret_value);
    assert_int_equal(ret, kRetOk);
    assert_int_equal(ret_value, DestCloudStorage);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterNumber_LogDestinationBothFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogDestination;
    CfgStLogLevel ret_value;
    EsfLogManagerParameterValue value = {
        .dlog_dest = kEsfLogManagerDlogDestBoth,
        .dlog_level = 0,
        .elog_level = 0,
        .dlog_filter = 0,
        .storage_name = "TestStorageName",
        .storage_path = "TestPathName",
    };

    // Call EsfLogManagerGetParameter
    will_return(__wrap_EsfLogManagerGetParameter, &value);
    will_return(__wrap_EsfLogManagerGetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerGetParameter, block_type, kEsfLogManagerBlockTypeSysApp);

    RetCode ret = SysAppLogGetParameterNumber(filter, prop, (int *)&ret_value);
    assert_int_equal(ret, kRetOk);
    assert_int_equal(ret_value, LogDestinationNum);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterNumber_LogDestinationNumFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogDestination;
    CfgStLogLevel ret_value;
    EsfLogManagerParameterValue value = {
        .dlog_dest = kEsfLogManagerDlogDestNum,
        .dlog_level = 0,
        .elog_level = 0,
        .dlog_filter = 0,
        .storage_name = "TestStorageName",
        .storage_path = "TestPathName",
    };

    // Call EsfLogManagerGetParameter
    will_return(__wrap_EsfLogManagerGetParameter, &value);
    will_return(__wrap_EsfLogManagerGetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerGetParameter, block_type, kEsfLogManagerBlockTypeSysApp);

    RetCode ret = SysAppLogGetParameterNumber(filter, prop, (int *)&ret_value);
    assert_int_equal(ret, kRetOk);
    assert_int_equal(ret_value, LogDestinationNum);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterNumber_EsfError(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel ret_value;
    EsfLogManagerParameterValue value = {0};

    // Call EsfLogManagerGetParameter
    will_return(__wrap_EsfLogManagerGetParameter, &value);
    will_return(__wrap_EsfLogManagerGetParameter, kEsfLogManagerStatusFailed);
    expect_value(__wrap_EsfLogManagerGetParameter, block_type, kEsfLogManagerBlockTypeSysApp);

    RetCode ret = SysAppLogGetParameterNumber(filter, prop, (int *)&ret_value);
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterNumber_PropError(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LedEnabled;
    CfgStLogLevel ret_value;
    EsfLogManagerParameterValue value = {0};

    // Call EsfLogManagerGetParameter
    will_return(__wrap_EsfLogManagerGetParameter, &value);
    will_return(__wrap_EsfLogManagerGetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerGetParameter, block_type, kEsfLogManagerBlockTypeSysApp);

    RetCode ret = SysAppLogGetParameterNumber(filter, prop, (int *)&ret_value);
    assert_int_equal(ret, kRetApiCallError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterNumber_FilterMaxError(void **state)
{
    CfgStLogFilter filter = LogFilterNum;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel ret_value;

    RetCode ret = SysAppLogGetParameterNumber(filter, prop, (int *)&ret_value);
    assert_int_equal(ret, kRetApiCallError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterNumber_FilterMinError(void **state)
{
    CfgStLogFilter filter = AllLog;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel ret_value;

    RetCode ret = SysAppLogGetParameterNumber(filter, prop, (int *)&ret_value);
    assert_int_equal(ret, kRetApiCallError);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppLogGetParameterString()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterString_LogStorageNameFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogStorageName;
    char buff_name[CFGST_LOG_STORAGE_NAME_LEN + 1];
    EsfLogManagerParameterValue value = {
        .dlog_dest = 0,
        .dlog_level = 0,
        .elog_level = 0,
        .dlog_filter = 0,
        .storage_name = "TestStorageName",
        .storage_path = "TestPathName",
    };

    // Call EsfLogManagerGetParameter
    will_return(__wrap_EsfLogManagerGetParameter, &value);
    will_return(__wrap_EsfLogManagerGetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerGetParameter, block_type, kEsfLogManagerBlockTypeSysApp);

    RetCode ret = SysAppLogGetParameterString(filter, prop, buff_name, sizeof(buff_name));
    assert_int_equal(ret, kRetOk);
    assert_string_equal(buff_name, value.storage_name);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterString_LogStoragePathFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogPath;
    char buff_name[CFGST_LOG_STORAGE_NAME_LEN + 1];
    EsfLogManagerParameterValue value = {
        .dlog_dest = 0,
        .dlog_level = 0,
        .elog_level = 0,
        .dlog_filter = 0,
        .storage_name = "TestStorageName",
        .storage_path = "TestPathName",
    };

    // Call EsfLogManagerGetParameter
    will_return(__wrap_EsfLogManagerGetParameter, &value);
    will_return(__wrap_EsfLogManagerGetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerGetParameter, block_type, kEsfLogManagerBlockTypeSysApp);

    RetCode ret = SysAppLogGetParameterString(filter, prop, buff_name, sizeof(buff_name));
    assert_int_equal(ret, kRetOk);
    assert_string_equal(buff_name, value.storage_path);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterString_CheckGetbuff_size(void **state)
{
#define TEST_ARRAY_MAX_NUMBER 10

    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogStorageName;
    int specified_buf_size = 3;
    char buff_name[TEST_ARRAY_MAX_NUMBER];
    char expect_buff_name[TEST_ARRAY_MAX_NUMBER];
    EsfLogManagerParameterValue value = {
        .dlog_dest = 0,
        .dlog_level = 0,
        .elog_level = 0,
        .dlog_filter = 0,
        .storage_name = "ABCDE",
        .storage_path = "TestPathName",
    };

    // Initialize buff_name and expect_buff_name
    memset(buff_name, 'Z', sizeof(buff_name));
    memset(expect_buff_name, 'Z', sizeof(expect_buff_name));

    // Generate expect_buff_name
    // Copy EsfLogManagerGetParameter -> snprintf
    memcpy(expect_buff_name, value.storage_name, specified_buf_size - 1);

    // Add Null
    expect_buff_name[specified_buf_size - 1] = '\0';

    // Call EsfLogManagerGetParameter
    will_return(__wrap_EsfLogManagerGetParameter, &value);
    will_return(__wrap_EsfLogManagerGetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerGetParameter, block_type, kEsfLogManagerBlockTypeSysApp);

    RetCode ret = SysAppLogGetParameterString(filter, prop, buff_name, specified_buf_size);
    assert_int_equal(ret, kRetOk);
    assert_memory_equal(buff_name, expect_buff_name, sizeof(buff_name));

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterString_EsfError(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogStorageName;
    char buff_name[CFGST_LOG_STORAGE_NAME_LEN + 1];
    EsfLogManagerParameterValue value = {
        .dlog_dest = 0,
        .dlog_level = 0,
        .elog_level = 0,
        .dlog_filter = 0,
        .storage_name = "TestStorageName",
        .storage_path = "TestPathName",
    };

    // Call EsfLogManagerGetParameter
    will_return(__wrap_EsfLogManagerGetParameter, &value);
    will_return(__wrap_EsfLogManagerGetParameter, kEsfLogManagerStatusFailed);
    expect_value(__wrap_EsfLogManagerGetParameter, block_type, kEsfLogManagerBlockTypeSysApp);

    RetCode ret = SysAppLogGetParameterString(filter, prop, buff_name, sizeof(buff_name));
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterString_PropError(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LedEnabled;
    char buff_name[CFGST_LOG_STORAGE_NAME_LEN + 1];
    EsfLogManagerParameterValue value = {
        .dlog_dest = 0,
        .dlog_level = 0,
        .elog_level = 0,
        .dlog_filter = 0,
        .storage_name = "TestStorageName",
        .storage_path = "TestPathName",
    };

    // Call EsfLogManagerGetParameter
    will_return(__wrap_EsfLogManagerGetParameter, &value);
    will_return(__wrap_EsfLogManagerGetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerGetParameter, block_type, kEsfLogManagerBlockTypeSysApp);

    RetCode ret = SysAppLogGetParameterString(filter, prop, buff_name, sizeof(buff_name));
    assert_int_equal(ret, kRetApiCallError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterString_FilterMaxError(void **state)
{
    CfgStLogFilter filter = LogFilterNum;
    SystemSettingsProperty prop = LogStorageName;
    char buff_name[CFGST_LOG_STORAGE_NAME_LEN + 1];

    RetCode ret = SysAppLogGetParameterString(filter, prop, buff_name, sizeof(buff_name));
    assert_int_equal(ret, kRetApiCallError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogGetParameterString_FilterMinError(void **state)
{
    CfgStLogFilter filter = AllLog;
    SystemSettingsProperty prop = LogStorageName;
    char buff_name[CFGST_LOG_STORAGE_NAME_LEN + 1];

    RetCode ret = SysAppLogGetParameterString(filter, prop, buff_name, sizeof(buff_name));
    assert_int_equal(ret, kRetApiCallError);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppLogSetParameterNumber()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppLogSetParameterNumber_LogLevelCriticalFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel set_value = CriticalLv;

    // Call EsfLogManagerSetParameter
    will_return(__wrap_EsfLogManagerSetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerSetParameter, block_type, kEsfLogManagerBlockTypeSysApp);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_level,
                 kEsfLogManagerDlogLevelCritical);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.elog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_filter, 0);
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_name, "");
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_path, "");
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_level, 1);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_name, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_path, 0);

    RetCode ret = SysAppLogSetParameterNumber(filter, prop, (int)set_value);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogSetParameterNumber_LogLevelErrorFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel set_value = ErrorLv;

    // Call EsfLogManagerSetParameter
    will_return(__wrap_EsfLogManagerSetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerSetParameter, block_type, kEsfLogManagerBlockTypeSysApp);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_level, kEsfLogManagerDlogLevelError);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.elog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_filter, 0);
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_name, "");
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_path, "");
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_level, 1);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_name, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_path, 0);

    RetCode ret = SysAppLogSetParameterNumber(filter, prop, (int)set_value);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogSetParameterNumber_LogLevelWarnFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel set_value = WarningLv;

    // Call EsfLogManagerSetParameter
    will_return(__wrap_EsfLogManagerSetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerSetParameter, block_type, kEsfLogManagerBlockTypeSysApp);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_level, kEsfLogManagerDlogLevelWarn);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.elog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_filter, 0);
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_name, "");
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_path, "");
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_level, 1);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_name, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_path, 0);

    RetCode ret = SysAppLogSetParameterNumber(filter, prop, (int)set_value);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogSetParameterNumber_LogLevelInfoFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel set_value = InfoLv;

    // Call EsfLogManagerSetParameter
    will_return(__wrap_EsfLogManagerSetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerSetParameter, block_type, kEsfLogManagerBlockTypeSysApp);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_level, kEsfLogManagerDlogLevelInfo);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.elog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_filter, 0);
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_name, "");
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_path, "");
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_level, 1);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_name, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_path, 0);

    RetCode ret = SysAppLogSetParameterNumber(filter, prop, (int)set_value);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogSetParameterNumber_LogLevelDebugFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel set_value = DebugLv;

    // Call EsfLogManagerSetParameter
    will_return(__wrap_EsfLogManagerSetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerSetParameter, block_type, kEsfLogManagerBlockTypeSysApp);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_level, kEsfLogManagerDlogLevelDebug);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.elog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_filter, 0);
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_name, "");
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_path, "");
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_level, 1);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_name, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_path, 0);

    RetCode ret = SysAppLogSetParameterNumber(filter, prop, (int)set_value);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogSetParameterNumber_LogLevelVerboseFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel set_value = VerboseLv;

    // Call EsfLogManagerSetParameter
    will_return(__wrap_EsfLogManagerSetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerSetParameter, block_type, kEsfLogManagerBlockTypeSysApp);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_level, kEsfLogManagerDlogLevelTrace);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.elog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_filter, 0);
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_name, "");
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_path, "");
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_level, 1);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_name, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_path, 0);

    RetCode ret = SysAppLogSetParameterNumber(filter, prop, (int)set_value);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogSetParameterNumber_LogLevelNumFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel set_value = LogLevelNum;

    // Call EsfLogManagerSetParameter
    will_return(__wrap_EsfLogManagerSetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerSetParameter, block_type, kEsfLogManagerBlockTypeSysApp);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_level, kEsfLogManagerDlogLevelNum);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.elog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_filter, 0);
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_name, "");
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_path, "");
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_level, 1);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_name, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_path, 0);

    RetCode ret = SysAppLogSetParameterNumber(filter, prop, (int)set_value);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogSetParameterNumber_LogDestinationUartFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogDestination;
    CfgStLogDestination set_value = DestUart;

    // Call EsfLogManagerSetParameter
    will_return(__wrap_EsfLogManagerSetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerSetParameter, block_type, kEsfLogManagerBlockTypeSysApp);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_dest, kEsfLogManagerDlogDestUart);
    expect_value(__wrap_EsfLogManagerSetParameter, value.elog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_filter, 0);
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_name, "");
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_path, "");
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_dest, 1);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_name, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_path, 0);

    RetCode ret = SysAppLogSetParameterNumber(filter, prop, (int)set_value);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogSetParameterNumber_LogDestinationCloudFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogDestination;
    CfgStLogDestination set_value = DestCloudStorage;

    // Call EsfLogManagerSetParameter
    will_return(__wrap_EsfLogManagerSetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerSetParameter, block_type, kEsfLogManagerBlockTypeSysApp);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_dest, kEsfLogManagerDlogDestStore);
    expect_value(__wrap_EsfLogManagerSetParameter, value.elog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_filter, 0);
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_name, "");
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_path, "");
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_dest, 1);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_name, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_path, 0);

    RetCode ret = SysAppLogSetParameterNumber(filter, prop, (int)set_value);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogSetParameterNumber_LogDestinationNumFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogDestination;
    CfgStLogDestination set_value = LogDestinationNum;

    // Call EsfLogManagerSetParameter
    will_return(__wrap_EsfLogManagerSetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerSetParameter, block_type, kEsfLogManagerBlockTypeSysApp);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_dest, kEsfLogManagerDlogDestNum);
    expect_value(__wrap_EsfLogManagerSetParameter, value.elog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_filter, 0);
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_name, "");
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_path, "");
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_dest, 1);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_name, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_path, 0);

    RetCode ret = SysAppLogSetParameterNumber(filter, prop, set_value);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogSetParameterNumber_PropError(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LedEnabled;
    int set_value = 0;

    RetCode ret = SysAppLogSetParameterNumber(filter, prop, set_value);
    assert_int_equal(ret, kRetApiCallError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogSetParameterNumber_EsfParamError(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel set_value = CriticalLv;

    // Call EsfLogManagerSetParameter
    will_return(__wrap_EsfLogManagerSetParameter, kEsfLogManagerStatusParamError);
    expect_value(__wrap_EsfLogManagerSetParameter, block_type, kEsfLogManagerBlockTypeSysApp);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_level,
                 kEsfLogManagerDlogLevelCritical);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.elog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_filter, 0);
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_name, "");
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_path, "");
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_level, 1);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_name, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_path, 0);

    RetCode ret = SysAppLogSetParameterNumber(filter, prop, (int)set_value);
    assert_int_equal(ret, kRetParamError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogSetParameterNumber_EsfError(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel set_value = CriticalLv;

    // Call EsfLogManagerSetParameter
    will_return(__wrap_EsfLogManagerSetParameter, kEsfLogManagerStatusFailed);
    expect_value(__wrap_EsfLogManagerSetParameter, block_type, kEsfLogManagerBlockTypeSysApp);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_level,
                 kEsfLogManagerDlogLevelCritical);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.elog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_filter, 0);
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_name, "");
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_path, "");
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_level, 1);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_name, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_path, 0);

    RetCode ret = SysAppLogSetParameterNumber(filter, prop, (int)set_value);
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogSetParameterNumber_FilterMaxError(void **state)
{
    CfgStLogFilter filter = LogFilterNum;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel set_value = CriticalLv;

    RetCode ret = SysAppLogSetParameterNumber(filter, prop, (int)set_value);
    assert_int_equal(ret, kRetApiCallError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogSetParameterNumber_FilterMinError(void **state)
{
    CfgStLogFilter filter = AllLog;
    SystemSettingsProperty prop = LogLevel;
    CfgStLogLevel set_value = CriticalLv;

    RetCode ret = SysAppLogSetParameterNumber(filter, prop, (int)set_value);
    assert_int_equal(ret, kRetApiCallError);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppLogSetParameterString()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppLogSetParameterString_LogStorageNameFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogStorageName;
    const char *storage_name = "TestStorageName";

    // Call EsfLogManagerSetParameter
    will_return(__wrap_EsfLogManagerSetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerSetParameter, block_type, kEsfLogManagerBlockTypeSysApp);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.elog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_filter, 0);
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_name, storage_name);
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_path, "");
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_name, 1);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_path, 0);

    RetCode ret = SysAppLogSetParameterString(filter, prop, storage_name, strlen(storage_name) + 1);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogSetParameterString_LogStoragePathFullySuccess(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogPath;
    const char *path_name = "TestPathName";

    // Call EsfLogManagerSetParameter
    will_return(__wrap_EsfLogManagerSetParameter, kEsfLogManagerStatusOk);
    expect_value(__wrap_EsfLogManagerSetParameter, block_type, kEsfLogManagerBlockTypeSysApp);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.elog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_filter, 0);
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_name, "");
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_path, path_name);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_name, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_path, 1);

    RetCode ret = SysAppLogSetParameterString(filter, prop, path_name, strlen(path_name) + 1);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogSetParameterString_PropError(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LedEnabled;
    const char *storage_name = "TestStorageName";

    RetCode ret = SysAppLogSetParameterString(filter, prop, storage_name, strlen(storage_name) + 1);
    assert_int_equal(ret, kRetApiCallError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogSetParameterString_EsfParamError(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogStorageName;
    const char *storage_name = "TestStorageName";

    // Call EsfLogManagerSetParameter
    will_return(__wrap_EsfLogManagerSetParameter, kEsfLogManagerStatusParamError);
    expect_value(__wrap_EsfLogManagerSetParameter, block_type, kEsfLogManagerBlockTypeSysApp);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.elog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_filter, 0);
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_name, storage_name);
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_path, "");
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_name, 1);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_path, 0);

    RetCode ret = SysAppLogSetParameterString(filter, prop, storage_name, strlen(storage_name) + 1);
    assert_int_equal(ret, kRetParamError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogSetParameterString_EsfError(void **state)
{
    CfgStLogFilter filter = MainFwLog;
    SystemSettingsProperty prop = LogStorageName;
    const char *storage_name = "TestStorageName";

    // Call EsfLogManagerSetParameter
    will_return(__wrap_EsfLogManagerSetParameter, kEsfLogManagerStatusFailed);
    expect_value(__wrap_EsfLogManagerSetParameter, block_type, kEsfLogManagerBlockTypeSysApp);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.elog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, value.dlog_filter, 0);
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_name, storage_name);
    expect_string(__wrap_EsfLogManagerSetParameter, value.storage_path, "");
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_level, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.dlog_dest, 0);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_name, 1);
    expect_value(__wrap_EsfLogManagerSetParameter, mask.storage_path, 0);

    RetCode ret = SysAppLogSetParameterString(filter, prop, storage_name, strlen(storage_name) + 1);
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogSetParameterString_FilterMaxError(void **state)
{
    CfgStLogFilter filter = LogFilterNum;
    SystemSettingsProperty prop = LogStorageName;
    const char *storage_name = "TestStorageName";

    RetCode ret = SysAppLogSetParameterString(filter, prop, storage_name, strlen(storage_name) + 1);
    assert_int_equal(ret, kRetApiCallError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLogSetParameterString_FilterMinError(void **state)
{
    CfgStLogFilter filter = AllLog;
    SystemSettingsProperty prop = LogStorageName;
    const char *storage_name = "TestStorageName";

    RetCode ret = SysAppLogSetParameterString(filter, prop, storage_name, strlen(storage_name) + 1);
    assert_int_equal(ret, kRetApiCallError);

    return;
}

/*----------------------------------------------------------------------------*/

//
// EncodeFiltertToBlockType()
//

/*----------------------------------------------------------------------------*/
static void test_EncodeFiltertToBlockType_AllLog(void **state)
{
    CfgStLogFilter filter = AllLog;
    EsfLogManagerSettingBlockType block_type;

    block_type = EncodeFiltertToBlockType(filter);

    assert_int_equal(block_type, kEsfLogManagerBlockTypeAll);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_EncodeFiltertToBlockType_Other(void **state)
{
    CfgStLogFilter filter = LogFilterNum;
    EsfLogManagerSettingBlockType block_type;

    block_type = EncodeFiltertToBlockType(filter);

    assert_int_equal(block_type, kEsfLogManagerBlockTypeNum);

    return;
}

/*----------------------------------------------------------------------------*/

//
// main()
//

/*----------------------------------------------------------------------------*/
int main(void)
{
    const struct CMUnitTest tests[] = {
        // SysAppLogGetParameterNumber
        cmocka_unit_test(test_SysAppLogGetParameterNumber_MainFwLogLogLevelCriticalFullySuccess),
        cmocka_unit_test(test_SysAppLogGetParameterNumber_MainFwLogLogLevelErrorFullySuccess),
        cmocka_unit_test(test_SysAppLogGetParameterNumber_MainFwLogLogLevelWarnFullySuccess),
        cmocka_unit_test(test_SysAppLogGetParameterNumber_MainFwLogLogLevelInfoFullySuccess),
        cmocka_unit_test(test_SysAppLogGetParameterNumber_MainFwLogLogLevelDebugFullySuccess),
        cmocka_unit_test(test_SysAppLogGetParameterNumber_MainFwLogLogLevelTraceFullySuccess),
        cmocka_unit_test(test_SysAppLogGetParameterNumber_MainFwLogLogLevelNumDefault),
        cmocka_unit_test(test_SysAppLogGetParameterNumber_SensorLogLogLevelFullySuccess),
        cmocka_unit_test(test_SysAppLogGetParameterNumber_CompanionFwLogLogLevelFullySuccess),
        cmocka_unit_test(test_SysAppLogGetParameterNumber_CompanionAppLogLogLevelFullySuccess),
        cmocka_unit_test(test_SysAppLogGetParameterNumber_LogDestinationUartFullySuccess),
        cmocka_unit_test(test_SysAppLogGetParameterNumber_LogDestinationStoreFullySuccess),
        cmocka_unit_test(test_SysAppLogGetParameterNumber_LogDestinationBothFullySuccess),
        cmocka_unit_test(test_SysAppLogGetParameterNumber_LogDestinationNumFullySuccess),
        cmocka_unit_test(test_SysAppLogGetParameterNumber_EsfError),
        cmocka_unit_test(test_SysAppLogGetParameterNumber_PropError),
        cmocka_unit_test(test_SysAppLogGetParameterNumber_FilterMaxError),
        cmocka_unit_test(test_SysAppLogGetParameterNumber_FilterMinError),

        // SysAppLogGetParameterString
        cmocka_unit_test(test_SysAppLogGetParameterString_LogStorageNameFullySuccess),
        cmocka_unit_test(test_SysAppLogGetParameterString_LogStoragePathFullySuccess),
        cmocka_unit_test(test_SysAppLogGetParameterString_CheckGetbuff_size),
        cmocka_unit_test(test_SysAppLogGetParameterString_EsfError),
        cmocka_unit_test(test_SysAppLogGetParameterString_PropError),
        cmocka_unit_test(test_SysAppLogGetParameterString_FilterMaxError),
        cmocka_unit_test(test_SysAppLogGetParameterString_FilterMinError),

        // SysAppLogSetParameterNumber
        cmocka_unit_test(test_SysAppLogSetParameterNumber_LogLevelCriticalFullySuccess),
        cmocka_unit_test(test_SysAppLogSetParameterNumber_LogLevelErrorFullySuccess),
        cmocka_unit_test(test_SysAppLogSetParameterNumber_LogLevelWarnFullySuccess),
        cmocka_unit_test(test_SysAppLogSetParameterNumber_LogLevelInfoFullySuccess),
        cmocka_unit_test(test_SysAppLogSetParameterNumber_LogLevelDebugFullySuccess),
        cmocka_unit_test(test_SysAppLogSetParameterNumber_LogLevelVerboseFullySuccess),
        cmocka_unit_test(test_SysAppLogSetParameterNumber_LogLevelNumFullySuccess),
        cmocka_unit_test(test_SysAppLogSetParameterNumber_LogDestinationUartFullySuccess),
        cmocka_unit_test(test_SysAppLogSetParameterNumber_LogDestinationCloudFullySuccess),
        cmocka_unit_test(test_SysAppLogSetParameterNumber_LogDestinationNumFullySuccess),
        cmocka_unit_test(test_SysAppLogSetParameterNumber_PropError),
        cmocka_unit_test(test_SysAppLogSetParameterNumber_EsfParamError),
        cmocka_unit_test(test_SysAppLogSetParameterNumber_EsfError),
        cmocka_unit_test(test_SysAppLogSetParameterNumber_FilterMaxError),
        cmocka_unit_test(test_SysAppLogSetParameterNumber_FilterMinError),

        // SysAppLogSetParameterString
        cmocka_unit_test(test_SysAppLogSetParameterString_LogStorageNameFullySuccess),
        cmocka_unit_test(test_SysAppLogSetParameterString_LogStoragePathFullySuccess),
        cmocka_unit_test(test_SysAppLogSetParameterString_PropError),
        cmocka_unit_test(test_SysAppLogSetParameterString_EsfParamError),
        cmocka_unit_test(test_SysAppLogSetParameterString_EsfError),
        cmocka_unit_test(test_SysAppLogSetParameterString_FilterMaxError),
        cmocka_unit_test(test_SysAppLogSetParameterString_FilterMinError),

        // EncodeFiltertToBlockType
        cmocka_unit_test(test_EncodeFiltertToBlockType_AllLog),
        cmocka_unit_test(test_EncodeFiltertToBlockType_Other),
    };

    return (((cmocka_run_group_tests(tests, NULL, NULL)) == 0) ? 0 : 1);
}
