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

#include "initial_setting_app_button.h"
#include "ut_mock_isabutton.h"

// For executing NetworkManager Callback
static EsfNetworkManagerNotifyInfoCallback s_isa_btn_nw_callback;
static void *s_isa_btn_nw_callback_private_data;
static EsfNetworkManagerNotifyInfo s_isa_btn_nw_notify_info;
static int s_isa_btn_connect_wait_retry_count;

// For executing ClockManager Callback
static void (*s_isa_btn_cm_callback)(bool);
static bool s_isa_btn_cm_sync_success;
static int s_isa_btn_ntp_sync_retry_count;

/*----------------------------------------------------------------------------*/
RetCode __wrap_IsaBtnInitialize(void)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_IsaBtnFinalize(void)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
bool __wrap_IsaBtnCheckRebootRequest(void)
{
    function_called();

    // If IsaBtnCheckRebootRequest() is called in source code,
    // and NetworkManager callback function is set,
    // and retry count is equal to 0,
    // execute NetworkManager callback function.
    if (s_isa_btn_nw_callback != NULL) {
        if (s_isa_btn_connect_wait_retry_count == 0) {
            s_isa_btn_nw_callback(kEsfNetworkManagerModeNormal, s_isa_btn_nw_notify_info,
                                  s_isa_btn_nw_callback_private_data);

            s_isa_btn_nw_callback = NULL;
            s_isa_btn_nw_callback_private_data = NULL;
        }
        s_isa_btn_connect_wait_retry_count--;
    }

    // If IsaBtnCheckRebootRequest() is called in source code,
    // and ClockManager callback function is set,
    // and retry count is equal to 0,
    // execute ClockManager callback function.
    if (s_isa_btn_cm_callback != NULL) {
        if (s_isa_btn_ntp_sync_retry_count == 0) {
            s_isa_btn_cm_callback(s_isa_btn_cm_sync_success);

            s_isa_btn_cm_callback = NULL;
        }
        s_isa_btn_ntp_sync_retry_count--;
    }

    return mock_type(bool);
}

/*----------------------------------------------------------------------------*/
bool __wrap_IsaBtnCheckFactoryResetRequest(void)
{
    return mock_type(bool);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_IsaBtnExecuteFactoryResetCore(void)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
void IsaBtnSetNetworkManagerNotifyCallback(EsfNetworkManagerNotifyInfoCallback nw_callback,
                                           void *nw_callback_private_data,
                                           EsfNetworkManagerNotifyInfo nw_notify_info,
                                           int connect_wait_retry_count)
{
    s_isa_btn_nw_callback = nw_callback;
    s_isa_btn_nw_callback_private_data = nw_callback_private_data;
    s_isa_btn_nw_notify_info = nw_notify_info;
    s_isa_btn_connect_wait_retry_count = connect_wait_retry_count;
}

/*----------------------------------------------------------------------------*/
void IsaBtnSetClockManagerNtpSyncCallback(void (*cm_callback)(bool), bool cm_sync_success,
                                          int ntp_sync_retry_count)
{
    s_isa_btn_cm_callback = cm_callback;
    s_isa_btn_cm_sync_success = cm_sync_success;
    s_isa_btn_ntp_sync_retry_count = ntp_sync_retry_count;
}
