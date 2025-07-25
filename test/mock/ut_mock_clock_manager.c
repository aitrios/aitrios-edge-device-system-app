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

#include "clock_manager.h"
#include "clock_manager_setting.h"
#include "ut_mock_isabutton.h"
#include "ut_mock_clock_manager.h"

typedef void (*CmCallback)(bool);
static CmCallback s_cm_callback;
#ifdef INITIAL_SETTING_APP_PS_STUB
static bool s_cm_sync_success;
#endif // INITIAL_SETTING_APP_PS_STUB

/*----------------------------------------------------------------------------*/
EsfClockManagerReturnValue __wrap_EsfClockManagerSetParamsForcibly(
    const EsfClockManagerParams *data, const EsfClockManagerParamsMask *mask)
{
    check_expected(mask->connect.hostname);

    if (mask->connect.hostname == 1) {
        check_expected_ptr(data->connect.hostname);
    }
    return mock_type(EsfClockManagerReturnValue);
}

/*----------------------------------------------------------------------------*/
EsfClockManagerReturnValue __wrap_EsfClockManagerSetParams(const EsfClockManagerParams *data,
                                                           const EsfClockManagerParamsMask *mask)
{
    check_expected(mask->connect.hostname);
    check_expected(mask->common.sync_interval);
    check_expected(mask->common.polling_time);
    check_expected(mask->skip_and_limit.type);
    check_expected(mask->skip_and_limit.limit_packet_time);
    check_expected(mask->skip_and_limit.limit_rtc_correction_value);
    check_expected(mask->skip_and_limit.sanity_limit);
    check_expected(mask->slew_setting.type);
    check_expected(mask->slew_setting.stable_rtc_correction_value);
    check_expected(mask->slew_setting.stable_sync_number);

    if (mask->connect.hostname == 1) {
        check_expected_ptr(data->connect.hostname);
    }
    if (mask->common.sync_interval == 1) {
        check_expected(data->common.sync_interval);
    }
    if (mask->common.polling_time == 1) {
        check_expected(data->common.polling_time);
    }
    if (mask->skip_and_limit.type == 1) {
        check_expected(data->skip_and_limit.type);
    }
    if (mask->skip_and_limit.limit_packet_time == 1) {
        check_expected(data->skip_and_limit.limit_packet_time);
    }
    if (mask->skip_and_limit.limit_rtc_correction_value == 1) {
        check_expected(data->skip_and_limit.limit_rtc_correction_value);
    }
    if (mask->skip_and_limit.sanity_limit == 1) {
        check_expected(data->skip_and_limit.sanity_limit);
    }
    if (mask->slew_setting.type == 1) {
        check_expected(data->slew_setting.type);
    }
    if (mask->slew_setting.stable_rtc_correction_value == 1) {
        check_expected(data->slew_setting.stable_rtc_correction_value);
    }
    if (mask->slew_setting.stable_sync_number == 1) {
        check_expected(data->slew_setting.stable_sync_number);
    }
    return mock_type(EsfClockManagerReturnValue);
}

/*----------------------------------------------------------------------------*/
EsfClockManagerReturnValue __wrap_EsfClockManagerGetParams(EsfClockManagerParams *const data)
{
    EsfClockManagerParams params = {};
    snprintf(params.connect.hostname, sizeof params.connect.hostname, "%s",
             mock_type(const char *));
    params.common.sync_interval = mock_type(int);
    params.common.polling_time = mock_type(int);
    params.skip_and_limit.type = mock_type(EsfClockManagerParamType);
    params.skip_and_limit.limit_packet_time = mock_type(int);
    params.skip_and_limit.limit_rtc_correction_value = mock_type(int);
    params.skip_and_limit.sanity_limit = mock_type(int);
    params.slew_setting.type = mock_type(EsfClockManagerParamType);
    params.slew_setting.stable_rtc_correction_value = mock_type(int);
    params.slew_setting.stable_sync_number = mock_type(int);

    *data = params;
    return mock_type(EsfClockManagerReturnValue);
}

/*----------------------------------------------------------------------------*/
EsfClockManagerReturnValue __wrap_EsfClockManagerRegisterCbOnNtpSyncComplete(
    void (*on_ntp_sync_complete)(bool))
{
#ifdef INITIAL_SETTING_APP_PS_STUB
    check_expected_ptr(on_ntp_sync_complete);

    ClockManagerExecCb exec_cb = mock_type(ClockManagerExecCb);
    bool sync_success_info = mock_type(bool);

    if (exec_cb == kClockManagerExecCbIsaBtn) {
        int ntp_sync_retry_count = mock_type(int);

        // To execute ClockManager callback function in IsaBtnCheckRebootRequest,
        // set callback function parameter to ut_mock_isabutton.c
        // by using IsaBtnSetClockManagerNtpSyncCallback().
        IsaBtnSetClockManagerNtpSyncCallback(on_ntp_sync_complete, sync_success_info,
                                             ntp_sync_retry_count);
    }
    else if (exec_cb == kClockManagerExecCbCM) {
        s_cm_callback = on_ntp_sync_complete;
        s_cm_sync_success = sync_success_info;
    }
    else {
        /* Do Nothing */
    }
#else  // INITIAL_SETTING_APP_PS_STUB
    s_cm_callback = on_ntp_sync_complete;
#endif // INITIAL_SETTING_APP_PS_STUB
    return mock_type(EsfClockManagerReturnValue);
}

/*----------------------------------------------------------------------------*/
EsfClockManagerReturnValue __wrap_EsfClockManagerStart(void)
{
#ifdef INITIAL_SETTING_APP_PS_STUB
    bool exec_cb_flag;

    function_called();

    exec_cb_flag = mock_type(bool);
    if (exec_cb_flag) {
        if (s_cm_callback != NULL) {
            s_cm_callback(s_cm_sync_success);

            s_cm_callback = NULL;
        }
    }
#else  // INITIAL_SETTING_APP_PS_STUB
    bool call_cb = mock_type(bool);
    if (call_cb) {
        s_cm_callback(mock_type(bool));
    }
#endif // INITIAL_SETTING_APP_PS_STUB

    return mock_type(EsfClockManagerReturnValue);
}

/*----------------------------------------------------------------------------*/
EsfClockManagerReturnValue __wrap_EsfClockManagerStop(void)
{
#ifdef INITIAL_SETTING_APP_PS_STUB
    function_called();
#else  // INITIAL_SETTING_APP_PS_STUB
#endif // INITIAL_SETTING_APP_PS_STUB
    return mock_type(EsfClockManagerReturnValue);
}

/*----------------------------------------------------------------------------*/
EsfClockManagerReturnValue __wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete(void)
{
#ifdef INITIAL_SETTING_APP_PS_STUB
    function_called();
#else  // INITIAL_SETTING_APP_PS_STUB
#endif // INITIAL_SETTING_APP_PS_STUB
    return mock_type(EsfClockManagerReturnValue);
}
/*----------------------------------------------------------------------------*/
EsfClockManagerReturnValue __wrap_EsfClockManagerInit(void)
{
    return mock_type(EsfClockManagerReturnValue);
}

/*----------------------------------------------------------------------------*/
EsfClockManagerReturnValue __wrap_EsfClockManagerDeinit(void)
{
    return mock_type(EsfClockManagerReturnValue);
}
