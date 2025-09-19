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

#include <stdio.h>
#include "network_manager.h"
#include "led_manager.h"
#include "clock_manager.h"
#include "clock_manager_setting.h"
#include "system_app_common.h"
#include "ut_mock_clock_manager.h"
#include "ut_mock_network_manager.h"

extern EsfNetworkManagerHandle s_esfnm_handle;
extern bool s_ntp_sync_notify;
extern bool s_ntp_sync_done;

extern void NetworkManagerCallback(EsfNetworkManagerMode mode, EsfNetworkManagerNotifyInfo info,
                                   void *private_data);
extern void NtpSyncCallback(bool is_sync_success);

extern RetCode ConnectNetwork(void);
extern RetCode StartSyncNtp(void);
/*----------------------------------------------------------------------------*/

//
// Initial value check for static global variable
//

/*----------------------------------------------------------------------------*/
static void test_InitialSettingAppPsStub_InitialValueOfGlobalVariable(void **state)
{
    assert_int_equal(s_esfnm_handle, ESF_NETWORK_MANAGER_INVALID_HANDLE);
    assert_false(s_ntp_sync_notify);
    assert_false(s_ntp_sync_done);

    return;
}

/*----------------------------------------------------------------------------*/

//
// Common
//

/*----------------------------------------------------------------------------*/
static void CheckEsfNetworkManagerSaveParameter(const EsfNetworkManagerParameterMask *mask,
                                                const EsfNetworkManagerParameter *parameter,
                                                EsfNetworkManagerResult esfnm_result)
{
    // Check mask
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.ip,
                 mask->normal_mode.dev_ip.ip);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.subnet_mask,
                 mask->normal_mode.dev_ip.subnet_mask);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.gateway,
                 mask->normal_mode.dev_ip.gateway);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.dns,
                 mask->normal_mode.dev_ip.dns);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.ip,
                 mask->normal_mode.dev_ip_v6.ip);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.subnet_mask,
                 mask->normal_mode.dev_ip_v6.subnet_mask);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.gateway,
                 mask->normal_mode.dev_ip_v6.gateway);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.dns,
                 mask->normal_mode.dev_ip_v6.dns);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.ssid,
                 mask->normal_mode.wifi_sta.ssid);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.password,
                 mask->normal_mode.wifi_sta.password);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.encryption,
                 mask->normal_mode.wifi_sta.encryption);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.ip_method,
                 mask->normal_mode.ip_method);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.netif_kind,
                 mask->normal_mode.netif_kind);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.ip,
                 mask->accesspoint_mode.dev_ip.ip);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.subnet_mask,
                 mask->accesspoint_mode.dev_ip.subnet_mask);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.gateway,
                 mask->accesspoint_mode.dev_ip.gateway);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.dns,
                 mask->accesspoint_mode.dev_ip.dns);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.ssid,
                 mask->accesspoint_mode.wifi_ap.ssid);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.password,
                 mask->accesspoint_mode.wifi_ap.password);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.encryption,
                 mask->accesspoint_mode.wifi_ap.encryption);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.channel,
                 mask->accesspoint_mode.wifi_ap.channel);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.url, mask->proxy.url);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.port, mask->proxy.port);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.username, mask->proxy.username);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.password, mask->proxy.password);

    // Check parameter. If mask is 0, don't care.
    if (mask->normal_mode.dev_ip.ip == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.dev_ip.ip,
                      parameter->normal_mode.dev_ip.ip);
    }
    if (mask->normal_mode.dev_ip.subnet_mask == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter,
                      parameter->normal_mode.dev_ip.subnet_mask,
                      parameter->normal_mode.dev_ip.subnet_mask);
    }
    if (mask->normal_mode.dev_ip.gateway == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.dev_ip.gateway,
                      parameter->normal_mode.dev_ip.gateway);
    }
    if (mask->normal_mode.dev_ip.dns == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.dev_ip.dns,
                      parameter->normal_mode.dev_ip.dns);
    }
    if (mask->normal_mode.dev_ip_v6.ip == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.dev_ip_v6.ip,
                      parameter->normal_mode.dev_ip_v6.ip);
    }
    if (mask->normal_mode.dev_ip_v6.subnet_mask == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter,
                      parameter->normal_mode.dev_ip_v6.subnet_mask,
                      parameter->normal_mode.dev_ip_v6.subnet_mask);
    }
    if (mask->normal_mode.dev_ip_v6.gateway == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter,
                      parameter->normal_mode.dev_ip_v6.gateway,
                      parameter->normal_mode.dev_ip_v6.gateway);
    }
    if (mask->normal_mode.dev_ip_v6.dns == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.dev_ip_v6.dns,
                      parameter->normal_mode.dev_ip_v6.dns);
    }
    if (mask->normal_mode.wifi_sta.ssid == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.wifi_sta.ssid,
                      parameter->normal_mode.wifi_sta.ssid);
    }
    if (mask->normal_mode.wifi_sta.password == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter,
                      parameter->normal_mode.wifi_sta.password,
                      parameter->normal_mode.wifi_sta.password);
    }
    if (mask->normal_mode.wifi_sta.encryption == 1) {
        expect_value(__wrap_EsfNetworkManagerSaveParameter,
                     parameter->normal_mode.wifi_sta.encryption,
                     parameter->normal_mode.wifi_sta.encryption);
    }
    if (mask->normal_mode.ip_method == 1) {
        expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.ip_method,
                     parameter->normal_mode.ip_method);
    }
    if (mask->normal_mode.netif_kind == 1) {
        expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.netif_kind,
                     parameter->normal_mode.netif_kind);
    }
    if (mask->accesspoint_mode.dev_ip.ip == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter, parameter->accesspoint_mode.dev_ip.ip,
                      parameter->accesspoint_mode.dev_ip.ip);
    }
    if (mask->accesspoint_mode.dev_ip.subnet_mask == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter,
                      parameter->accesspoint_mode.dev_ip.subnet_mask,
                      parameter->accesspoint_mode.dev_ip.subnet_mask);
    }
    if (mask->accesspoint_mode.dev_ip.gateway == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter,
                      parameter->accesspoint_mode.dev_ip.gateway,
                      parameter->accesspoint_mode.dev_ip.gateway);
    }
    if (mask->accesspoint_mode.dev_ip.dns == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter, parameter->accesspoint_mode.dev_ip.dns,
                      parameter->accesspoint_mode.dev_ip.dns);
    }
    if (mask->accesspoint_mode.wifi_ap.ssid == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter,
                      parameter->accesspoint_mode.wifi_ap.ssid,
                      parameter->accesspoint_mode.wifi_ap.ssid);
    }
    if (mask->accesspoint_mode.wifi_ap.password == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter,
                      parameter->accesspoint_mode.wifi_ap.password,
                      parameter->accesspoint_mode.wifi_ap.password);
    }
    if (mask->accesspoint_mode.wifi_ap.encryption == 1) {
        expect_value(__wrap_EsfNetworkManagerSaveParameter,
                     parameter->accesspoint_mode.wifi_ap.encryption,
                     parameter->accesspoint_mode.wifi_ap.encryption);
    }
    if (mask->accesspoint_mode.wifi_ap.channel == 1) {
        expect_value(__wrap_EsfNetworkManagerSaveParameter,
                     parameter->accesspoint_mode.wifi_ap.channel,
                     parameter->accesspoint_mode.wifi_ap.channel);
    }
    if (mask->proxy.url == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter, parameter->proxy.url,
                      parameter->proxy.url);
    }
    if (mask->proxy.port == 1) {
        expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->proxy.port,
                     parameter->proxy.port);
    }
    if (mask->proxy.username == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter, parameter->proxy.username,
                      parameter->proxy.username);
    }
    if (mask->proxy.password == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter, parameter->proxy.password,
                      parameter->proxy.password);
    }

    will_return(__wrap_EsfNetworkManagerSaveParameter, esfnm_result);
}

/*----------------------------------------------------------------------------*/
static void CheckEsfNetworkManagerLoadParameter(const EsfNetworkManagerParameterMask *mask,
                                                EsfNetworkManagerParameter *out_parameter,
                                                EsfNetworkManagerResult esfnm_result)
{
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->normal_mode.dev_ip.ip,
                 mask->normal_mode.dev_ip.ip);
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->normal_mode.dev_ip.subnet_mask,
                 mask->normal_mode.dev_ip.subnet_mask);
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->normal_mode.dev_ip.gateway,
                 mask->normal_mode.dev_ip.gateway);
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->normal_mode.dev_ip.dns,
                 mask->normal_mode.dev_ip.dns);
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->normal_mode.dev_ip_v6.ip,
                 mask->normal_mode.dev_ip_v6.ip);
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->normal_mode.dev_ip_v6.subnet_mask,
                 mask->normal_mode.dev_ip_v6.subnet_mask);
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->normal_mode.dev_ip_v6.gateway,
                 mask->normal_mode.dev_ip_v6.gateway);
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->normal_mode.dev_ip_v6.dns,
                 mask->normal_mode.dev_ip_v6.dns);
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->normal_mode.wifi_sta.ssid,
                 mask->normal_mode.wifi_sta.ssid);
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->normal_mode.wifi_sta.password,
                 mask->normal_mode.wifi_sta.password);
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->normal_mode.wifi_sta.encryption,
                 mask->normal_mode.wifi_sta.encryption);
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->normal_mode.ip_method,
                 mask->normal_mode.ip_method);
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->normal_mode.netif_kind,
                 mask->normal_mode.netif_kind);

    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->accesspoint_mode.dev_ip.ip,
                 mask->accesspoint_mode.dev_ip.ip);
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->accesspoint_mode.dev_ip.subnet_mask,
                 mask->accesspoint_mode.dev_ip.subnet_mask);
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->accesspoint_mode.dev_ip.gateway,
                 mask->accesspoint_mode.dev_ip.gateway);
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->accesspoint_mode.dev_ip.dns,
                 mask->accesspoint_mode.dev_ip.dns);
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->accesspoint_mode.wifi_ap.ssid,
                 mask->accesspoint_mode.wifi_ap.ssid);
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->accesspoint_mode.wifi_ap.password,
                 mask->accesspoint_mode.wifi_ap.password);
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->accesspoint_mode.wifi_ap.encryption,
                 mask->accesspoint_mode.wifi_ap.encryption);
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->accesspoint_mode.wifi_ap.channel,
                 mask->accesspoint_mode.wifi_ap.channel);

    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->proxy.url, mask->proxy.url);
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->proxy.port, mask->proxy.port);
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->proxy.username, mask->proxy.username);
    expect_value(__wrap_EsfNetworkManagerLoadParameter, mask->proxy.password, mask->proxy.password);

    will_return(__wrap_EsfNetworkManagerLoadParameter, out_parameter);
    will_return(__wrap_EsfNetworkManagerLoadParameter, esfnm_result);
}
/*----------------------------------------------------------------------------*/
static void CheckEsfClockManagerSetParams(const EsfClockManagerParams *data,
                                          const EsfClockManagerParamsMask *mask,
                                          EsfClockManagerReturnValue esfcm_result)
{
    // Check mask
    expect_value(__wrap_EsfClockManagerSetParams, mask->connect.hostname, mask->connect.hostname);
    expect_value(__wrap_EsfClockManagerSetParams, mask->common.sync_interval,
                 mask->common.sync_interval);
    expect_value(__wrap_EsfClockManagerSetParams, mask->common.polling_time,
                 mask->common.polling_time);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.type,
                 mask->skip_and_limit.type);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_packet_time,
                 mask->skip_and_limit.limit_packet_time);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_rtc_correction_value,
                 mask->skip_and_limit.limit_rtc_correction_value);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.sanity_limit,
                 mask->skip_and_limit.sanity_limit);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.type, mask->slew_setting.type);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_rtc_correction_value,
                 mask->slew_setting.stable_rtc_correction_value);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_sync_number,
                 mask->slew_setting.stable_sync_number);

    // Check parameter. If mask is 0, don't care.
    if (mask->connect.hostname == 1) {
        expect_string(__wrap_EsfClockManagerSetParams, data->connect.hostname,
                      data->connect.hostname);
    }
    if (mask->common.sync_interval == 1) {
        expect_value(__wrap_EsfClockManagerSetParams, data->common.sync_interval,
                     data->common.sync_interval);
    }
    if (mask->common.polling_time == 1) {
        expect_value(__wrap_EsfClockManagerSetParams, data->common.polling_time,
                     data->common.polling_time);
    }
    if (mask->skip_and_limit.type == 1) {
        expect_value(__wrap_EsfClockManagerSetParams, data->skip_and_limit.type,
                     data->skip_and_limit.type);
    }
    if (mask->skip_and_limit.limit_packet_time == 1) {
        expect_value(__wrap_EsfClockManagerSetParams, data->skip_and_limit.limit_packet_time,
                     data->skip_and_limit.limit_packet_time);
    }
    if (mask->skip_and_limit.limit_rtc_correction_value == 1) {
        expect_value(__wrap_EsfClockManagerSetParams,
                     data->skip_and_limit.limit_rtc_correction_value,
                     data->skip_and_limit.limit_rtc_correction_value);
    }
    if (mask->skip_and_limit.sanity_limit == 1) {
        expect_value(__wrap_EsfClockManagerSetParams, data->skip_and_limit.sanity_limit,
                     data->skip_and_limit.sanity_limit);
    }
    if (mask->slew_setting.type == 1) {
        expect_value(__wrap_EsfClockManagerSetParams, data->slew_setting.type,
                     data->slew_setting.type);
    }
    if (mask->slew_setting.stable_rtc_correction_value == 1) {
        expect_value(__wrap_EsfClockManagerSetParams,
                     data->slew_setting.stable_rtc_correction_value,
                     data->slew_setting.stable_rtc_correction_value);
    }
    if (mask->slew_setting.stable_sync_number == 1) {
        expect_value(__wrap_EsfClockManagerSetParams, data->slew_setting.stable_sync_number,
                     data->slew_setting.stable_sync_number);
    }

    will_return(__wrap_EsfClockManagerSetParams, esfcm_result);
}

/*----------------------------------------------------------------------------*/

//
// ConnectNetwork()
//

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_FullySuccessWifi(void **state)
{
    RetCode ret;

    EsfNetworkManagerHandle expected_esfnm_handle = (EsfNetworkManagerHandle)0x99887766;
    NetworkManagerExecCb exec_cb_location = kNetworkManagerExecCbNM;

    // This is expected paramter for ssid
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    // This is expected paramter for netif_kind
    EsfNetworkManagerParameterMask expected_netif_kind_esfnm_mask;
    EsfNetworkManagerParameter expected_netif_kind_esfnm_param;

    // Initialize
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    memset(&expected_netif_kind_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_netif_kind_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    const char *expected_ssid = "expected_ssid_name";
    snprintf(expected_esfnm_param.normal_mode.wifi_sta.ssid,
             sizeof(expected_esfnm_param.normal_mode.wifi_sta.ssid), "%s", expected_ssid);

    expected_netif_kind_esfnm_mask.normal_mode.netif_kind = 1;
    expected_netif_kind_esfnm_param.normal_mode.netif_kind = 0; // WiFi.

    expect_value(__wrap_EsfNetworkManagerOpen, mode, kEsfNetworkManagerModeNormal);
    expect_value(__wrap_EsfNetworkManagerOpen, handle_type, kEsfNetworkManagerHandleTypeControl);
    will_return(__wrap_EsfNetworkManagerOpen, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerRegisterCallback, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerRegisterCallback, notify_callback, NetworkManagerCallback);
    expect_not_value(__wrap_EsfNetworkManagerRegisterCallback, private_data, NULL);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, exec_cb_location);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    CheckEsfNetworkManagerLoadParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // WiFi NetworkManagerSaveParameter
    CheckEsfNetworkManagerSaveParameter(&expected_netif_kind_esfnm_mask,
                                        &expected_netif_kind_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Callback function exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, true);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Exec test target
    ret = ConnectNetwork();

    // Check return and global value
    assert_int_equal(ret, kRetOk);
    assert_int_equal(s_esfnm_handle, expected_esfnm_handle);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_ErrorEsfNetworkManagerOpen(void **state)
{
    RetCode ret;

    EsfNetworkManagerHandle expected_esfnm_handle = (EsfNetworkManagerHandle)0x99887766;

    expect_value(__wrap_EsfNetworkManagerOpen, mode, kEsfNetworkManagerModeNormal);
    expect_value(__wrap_EsfNetworkManagerOpen, handle_type, kEsfNetworkManagerHandleTypeControl);
    will_return(__wrap_EsfNetworkManagerOpen, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultInvalidParameter);

    // Exec test target
    ret = ConnectNetwork();

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_ErrorEsfNetworkManagerRegisterCallback(void **state)
{
    RetCode ret;

    EsfNetworkManagerHandle expected_esfnm_handle = (EsfNetworkManagerHandle)0x99887766;
    NetworkManagerExecCb exec_cb_location = kNetworkManagerExecCbNM;

    expect_value(__wrap_EsfNetworkManagerOpen, mode, kEsfNetworkManagerModeNormal);
    expect_value(__wrap_EsfNetworkManagerOpen, handle_type, kEsfNetworkManagerHandleTypeControl);
    will_return(__wrap_EsfNetworkManagerOpen, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerRegisterCallback, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerRegisterCallback, notify_callback, NetworkManagerCallback);
    expect_not_value(__wrap_EsfNetworkManagerRegisterCallback, private_data, NULL);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, exec_cb_location);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultInvalidParameter);

    expect_value(__wrap_EsfNetworkManagerClose, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerClose, kEsfNetworkManagerResultSuccess);

    // Exec test target
    ret = ConnectNetwork();

    // Check return and global value
    assert_int_equal(ret, kRetFailed);
    assert_int_equal(s_esfnm_handle, expected_esfnm_handle);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_ErrorEsfNetworkManagerLoadParameterButSuccessEther(void **state)
{
    RetCode ret;

    EsfNetworkManagerHandle expected_esfnm_handle = (EsfNetworkManagerHandle)0x99887766;
    NetworkManagerExecCb exec_cb_location = kNetworkManagerExecCbNM;

    // This is expected paramter for ssid
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    // This is expected paramter for netif_kind
    EsfNetworkManagerParameterMask expected_netif_kind_esfnm_mask;
    EsfNetworkManagerParameter expected_netif_kind_esfnm_param;

    // Initialize
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    memset(&expected_netif_kind_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_netif_kind_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    const char *expected_ssid = "expected_ssid_name";
    snprintf(expected_esfnm_param.normal_mode.wifi_sta.ssid,
             sizeof(expected_esfnm_param.normal_mode.wifi_sta.ssid), "%s", expected_ssid);

    expected_netif_kind_esfnm_mask.normal_mode.netif_kind = 1;
    expected_netif_kind_esfnm_param.normal_mode.netif_kind = 1; // Ether.

    expect_value(__wrap_EsfNetworkManagerOpen, mode, kEsfNetworkManagerModeNormal);
    expect_value(__wrap_EsfNetworkManagerOpen, handle_type, kEsfNetworkManagerHandleTypeControl);
    will_return(__wrap_EsfNetworkManagerOpen, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerRegisterCallback, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerRegisterCallback, notify_callback, NetworkManagerCallback);
    expect_not_value(__wrap_EsfNetworkManagerRegisterCallback, private_data, NULL);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, exec_cb_location);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    CheckEsfNetworkManagerLoadParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultInvalidParameter);

    // Ether NetworkManagerSaveParameter
    CheckEsfNetworkManagerSaveParameter(&expected_netif_kind_esfnm_mask,
                                        &expected_netif_kind_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Callback function exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, true);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Exec test target
    ret = ConnectNetwork();

    // Check return and global value
    assert_int_equal(ret, kRetOk);
    assert_int_equal(s_esfnm_handle, expected_esfnm_handle);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_FullySuccessEther(void **state)
{
    RetCode ret;

    EsfNetworkManagerHandle expected_esfnm_handle = (EsfNetworkManagerHandle)0x99887766;
    NetworkManagerExecCb exec_cb_location = kNetworkManagerExecCbNM;

    // This is expected paramter for ssid
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    // This is expected paramter for netif_kind
    EsfNetworkManagerParameterMask expected_netif_kind_esfnm_mask;
    EsfNetworkManagerParameter expected_netif_kind_esfnm_param;

    // Initialize
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    memset(&expected_netif_kind_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_netif_kind_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    expected_netif_kind_esfnm_mask.normal_mode.netif_kind = 1;
    expected_netif_kind_esfnm_param.normal_mode.netif_kind = 1; // Ether.

    expect_value(__wrap_EsfNetworkManagerOpen, mode, kEsfNetworkManagerModeNormal);
    expect_value(__wrap_EsfNetworkManagerOpen, handle_type, kEsfNetworkManagerHandleTypeControl);
    will_return(__wrap_EsfNetworkManagerOpen, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerRegisterCallback, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerRegisterCallback, notify_callback, NetworkManagerCallback);
    expect_not_value(__wrap_EsfNetworkManagerRegisterCallback, private_data, NULL);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, exec_cb_location);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    CheckEsfNetworkManagerLoadParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Ether NetworkManagerSaveParameter
    CheckEsfNetworkManagerSaveParameter(&expected_netif_kind_esfnm_mask,
                                        &expected_netif_kind_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Callback function exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, true);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Exec test target
    ret = ConnectNetwork();

    // Check return and global value
    assert_int_equal(ret, kRetOk);
    assert_int_equal(s_esfnm_handle, expected_esfnm_handle);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_ErrorEsfNetworkManagerSaveParameterButSuccessWiFi(void **state)
{
    RetCode ret;

    EsfNetworkManagerHandle expected_esfnm_handle = (EsfNetworkManagerHandle)0x99887766;
    NetworkManagerExecCb exec_cb_location = kNetworkManagerExecCbNM;

    // This is expected paramter for ssid
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    // This is expected paramter for netif_kind
    EsfNetworkManagerParameterMask expected_netif_kind_esfnm_mask;
    EsfNetworkManagerParameter expected_netif_kind_esfnm_param;

    // Initialize
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    memset(&expected_netif_kind_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_netif_kind_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    const char *expected_ssid = "expected_ssid_name";
    snprintf(expected_esfnm_param.normal_mode.wifi_sta.ssid,
             sizeof(expected_esfnm_param.normal_mode.wifi_sta.ssid), "%s", expected_ssid);

    expected_netif_kind_esfnm_mask.normal_mode.netif_kind = 1;
    expected_netif_kind_esfnm_param.normal_mode.netif_kind = 0; // WiFi.

    expect_value(__wrap_EsfNetworkManagerOpen, mode, kEsfNetworkManagerModeNormal);
    expect_value(__wrap_EsfNetworkManagerOpen, handle_type, kEsfNetworkManagerHandleTypeControl);
    will_return(__wrap_EsfNetworkManagerOpen, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerRegisterCallback, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerRegisterCallback, notify_callback, NetworkManagerCallback);
    expect_not_value(__wrap_EsfNetworkManagerRegisterCallback, private_data, NULL);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, exec_cb_location);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    CheckEsfNetworkManagerLoadParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // WiFi NetworkManagerSaveParameter
    CheckEsfNetworkManagerSaveParameter(&expected_netif_kind_esfnm_mask,
                                        &expected_netif_kind_esfnm_param,
                                        kEsfNetworkManagerResultInvalidParameter);

    // Callback function exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, true);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Exec test target
    ret = ConnectNetwork();

    // Check return and global value
    assert_int_equal(ret, kRetOk);
    assert_int_equal(s_esfnm_handle, expected_esfnm_handle);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_AlreadyRunningNetworkButSuccessWiFi(void **state)
{
    RetCode ret;

    EsfNetworkManagerHandle expected_esfnm_handle = (EsfNetworkManagerHandle)0x99887766;
    NetworkManagerExecCb exec_cb_location = kNetworkManagerExecCbNM;

    // This is expected paramter for ssid
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    // This is expected paramter for netif_kind
    EsfNetworkManagerParameterMask expected_netif_kind_esfnm_mask;
    EsfNetworkManagerParameter expected_netif_kind_esfnm_param;

    // Initialize
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    memset(&expected_netif_kind_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_netif_kind_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    const char *expected_ssid = "expected_ssid_name";
    snprintf(expected_esfnm_param.normal_mode.wifi_sta.ssid,
             sizeof(expected_esfnm_param.normal_mode.wifi_sta.ssid), "%s", expected_ssid);

    expected_netif_kind_esfnm_mask.normal_mode.netif_kind = 1;
    expected_netif_kind_esfnm_param.normal_mode.netif_kind = 0; // WiFi.

    expect_value(__wrap_EsfNetworkManagerOpen, mode, kEsfNetworkManagerModeNormal);
    expect_value(__wrap_EsfNetworkManagerOpen, handle_type, kEsfNetworkManagerHandleTypeControl);
    will_return(__wrap_EsfNetworkManagerOpen, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerRegisterCallback, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerRegisterCallback, notify_callback, NetworkManagerCallback);
    expect_not_value(__wrap_EsfNetworkManagerRegisterCallback, private_data, NULL);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, exec_cb_location);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    CheckEsfNetworkManagerLoadParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // WiFi NetworkManagerSaveParameter
    CheckEsfNetworkManagerSaveParameter(&expected_netif_kind_esfnm_mask,
                                        &expected_netif_kind_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // 1st AlreadyRunning and callback function don't exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, false);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultStatusAlreadyRunning);

    // 2nd Success and callback function exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, true);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Exec test target
    ret = ConnectNetwork();

    // Check return and global value
    assert_int_equal(ret, kRetOk);
    assert_int_equal(s_esfnm_handle, expected_esfnm_handle);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_ErrorWiFiEsfNetworkManagerStartButSuccessEther(void **state)
{
    RetCode ret;

    EsfNetworkManagerHandle expected_esfnm_handle = (EsfNetworkManagerHandle)0x99887766;
    NetworkManagerExecCb exec_cb_location = kNetworkManagerExecCbNM;

    // This is expected paramter for ssid
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    // This is expected paramter for netif_kind
    EsfNetworkManagerParameterMask expected_netif_kind_esfnm_mask;
    EsfNetworkManagerParameter expected_netif_kind_esfnm_param;

    // This is expected paramter for ether netif_kind
    EsfNetworkManagerParameterMask expected_ether_netif_kind_esfnm_mask;
    EsfNetworkManagerParameter expected_ether_netif_kind_esfnm_param;

    // Initialize
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    memset(&expected_netif_kind_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_netif_kind_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    memset(&expected_ether_netif_kind_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_ether_netif_kind_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    const char *expected_ssid = "expected_ssid_name";
    snprintf(expected_esfnm_param.normal_mode.wifi_sta.ssid,
             sizeof(expected_esfnm_param.normal_mode.wifi_sta.ssid), "%s", expected_ssid);

    expected_netif_kind_esfnm_mask.normal_mode.netif_kind = 1;
    expected_netif_kind_esfnm_param.normal_mode.netif_kind = 0; // WiFi.

    expected_ether_netif_kind_esfnm_mask.normal_mode.netif_kind = 1;
    expected_ether_netif_kind_esfnm_param.normal_mode.netif_kind = 1; // Ether.

    expect_value(__wrap_EsfNetworkManagerOpen, mode, kEsfNetworkManagerModeNormal);
    expect_value(__wrap_EsfNetworkManagerOpen, handle_type, kEsfNetworkManagerHandleTypeControl);
    will_return(__wrap_EsfNetworkManagerOpen, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerRegisterCallback, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerRegisterCallback, notify_callback, NetworkManagerCallback);
    expect_not_value(__wrap_EsfNetworkManagerRegisterCallback, private_data, NULL);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, exec_cb_location);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    CheckEsfNetworkManagerLoadParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // WiFi NetworkManagerSaveParameter
    CheckEsfNetworkManagerSaveParameter(&expected_netif_kind_esfnm_mask,
                                        &expected_netif_kind_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // WiFi NetworkManagerStart and callback function don't exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, false);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultInvalidParameter);

    // Ether NetworkManagerSaveParameter
    CheckEsfNetworkManagerSaveParameter(&expected_ether_netif_kind_esfnm_mask,
                                        &expected_ether_netif_kind_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Ether NetworkManagerStart and callback function exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, true);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Exec test target
    ret = ConnectNetwork();

    // Check return and global value
    assert_int_equal(ret, kRetOk);
    assert_int_equal(s_esfnm_handle, expected_esfnm_handle);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_FullySuccessWifiConnectRetry(void **state)
{
    RetCode ret;

    EsfNetworkManagerHandle expected_esfnm_handle = (EsfNetworkManagerHandle)0x99887766;
    NetworkManagerExecCb exec_cb_location = kNetworkManagerExecCbIsaBtn;
    int expect_connect_wait_retry = 15;

    // This is expected paramter for ssid
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    // This is expected paramter for netif_kind
    EsfNetworkManagerParameterMask expected_netif_kind_esfnm_mask;
    EsfNetworkManagerParameter expected_netif_kind_esfnm_param;

    // Initialize
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    memset(&expected_netif_kind_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_netif_kind_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    const char *expected_ssid = "expected_ssid_name";
    snprintf(expected_esfnm_param.normal_mode.wifi_sta.ssid,
             sizeof(expected_esfnm_param.normal_mode.wifi_sta.ssid), "%s", expected_ssid);

    expected_netif_kind_esfnm_mask.normal_mode.netif_kind = 1;
    expected_netif_kind_esfnm_param.normal_mode.netif_kind = 0; // WiFi.

    expect_value(__wrap_EsfNetworkManagerOpen, mode, kEsfNetworkManagerModeNormal);
    expect_value(__wrap_EsfNetworkManagerOpen, handle_type, kEsfNetworkManagerHandleTypeControl);
    will_return(__wrap_EsfNetworkManagerOpen, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerRegisterCallback, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerRegisterCallback, notify_callback, NetworkManagerCallback);
    expect_not_value(__wrap_EsfNetworkManagerRegisterCallback, private_data, NULL);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, exec_cb_location);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, expect_connect_wait_retry);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    CheckEsfNetworkManagerLoadParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // WiFi NetworkManagerSaveParameter
    CheckEsfNetworkManagerSaveParameter(&expected_netif_kind_esfnm_mask,
                                        &expected_netif_kind_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Callback function don't exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, false);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Check Connect Retry
    for (int i = 1; i <= (expect_connect_wait_retry + 1);
         i++) { // "+ 1" means that to execute the callback
        expect_function_call(__wrap_IsaBtnCheckRebootRequest);
        will_return(__wrap_IsaBtnCheckRebootRequest, false);

        will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);
    }

    // Exec test target
    ret = ConnectNetwork();

    // Check return and global value
    assert_int_equal(ret, kRetOk);
    assert_int_equal(s_esfnm_handle, expected_esfnm_handle);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_ConnectRetryOverWiFiButSuccessEther(void **state)
{
    RetCode ret;

    EsfNetworkManagerHandle expected_esfnm_handle = (EsfNetworkManagerHandle)0x99887766;
    NetworkManagerExecCb exec_cb_location = kNetworkManagerExecCbNM;
    int expect_connect_wait_retry = 16;

    // This is expected paramter for ssid
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    // This is expected paramter for netif_kind
    EsfNetworkManagerParameterMask expected_netif_kind_esfnm_mask;
    EsfNetworkManagerParameter expected_netif_kind_esfnm_param;

    // This is expected paramter for ether netif_kind
    EsfNetworkManagerParameterMask expected_ether_netif_kind_esfnm_mask;
    EsfNetworkManagerParameter expected_ether_netif_kind_esfnm_param;

    // Initialize
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    memset(&expected_netif_kind_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_netif_kind_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    memset(&expected_ether_netif_kind_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_ether_netif_kind_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    const char *expected_ssid = "expected_ssid_name";
    snprintf(expected_esfnm_param.normal_mode.wifi_sta.ssid,
             sizeof(expected_esfnm_param.normal_mode.wifi_sta.ssid), "%s", expected_ssid);

    expected_netif_kind_esfnm_mask.normal_mode.netif_kind = 1;
    expected_netif_kind_esfnm_param.normal_mode.netif_kind = 0; // WiFi.

    expected_ether_netif_kind_esfnm_mask.normal_mode.netif_kind = 1;
    expected_ether_netif_kind_esfnm_param.normal_mode.netif_kind = 1; // Ether.

    expect_value(__wrap_EsfNetworkManagerOpen, mode, kEsfNetworkManagerModeNormal);
    expect_value(__wrap_EsfNetworkManagerOpen, handle_type, kEsfNetworkManagerHandleTypeControl);
    will_return(__wrap_EsfNetworkManagerOpen, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerRegisterCallback, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerRegisterCallback, notify_callback, NetworkManagerCallback);
    expect_not_value(__wrap_EsfNetworkManagerRegisterCallback, private_data, NULL);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, exec_cb_location);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    CheckEsfNetworkManagerLoadParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // WiFi NetworkManagerSaveParameter
    CheckEsfNetworkManagerSaveParameter(&expected_netif_kind_esfnm_mask,
                                        &expected_netif_kind_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Callback function don't exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, false);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Check Connect Retry
    for (int i = 1; i <= expect_connect_wait_retry; i++) {
        expect_function_call(__wrap_IsaBtnCheckRebootRequest);
        will_return(__wrap_IsaBtnCheckRebootRequest, false);

        will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);
    }

    // Check IsaBtnCheckFactoryResetRequest.

    will_return(__wrap_IsaBtnCheckFactoryResetRequest, true);

    // Check EsfLedManagerSetLightingPersistence.

    will_return(__wrap_EsfLedManagerSetLightingPersistence, kEsfLedManagerSuccess);

    expect_value(__wrap_EsfNetworkManagerStop, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerStop, kEsfNetworkManagerResultSuccess);

    // Ether NetworkManagerSaveParameter
    CheckEsfNetworkManagerSaveParameter(&expected_ether_netif_kind_esfnm_mask,
                                        &expected_ether_netif_kind_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Ether NetworkManagerStart and callback function exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, true);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Exec test target
    ret = ConnectNetwork();

    // Check return and global value
    assert_int_equal(ret, kRetOk);
    assert_int_equal(s_esfnm_handle, expected_esfnm_handle);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_ConnectRetryOverWiFiErrorEsfNetworkManagerStopButSuccessEther(
    void **state)
{
    RetCode ret;

    EsfNetworkManagerHandle expected_esfnm_handle = (EsfNetworkManagerHandle)0x99887766;
    NetworkManagerExecCb exec_cb_location = kNetworkManagerExecCbNM;
    int expect_connect_wait_retry = 16;

    // This is expected paramter for ssid
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    // This is expected paramter for netif_kind
    EsfNetworkManagerParameterMask expected_netif_kind_esfnm_mask;
    EsfNetworkManagerParameter expected_netif_kind_esfnm_param;

    // This is expected paramter for ether netif_kind
    EsfNetworkManagerParameterMask expected_ether_netif_kind_esfnm_mask;
    EsfNetworkManagerParameter expected_ether_netif_kind_esfnm_param;

    // Initialize
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    memset(&expected_netif_kind_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_netif_kind_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    memset(&expected_ether_netif_kind_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_ether_netif_kind_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    const char *expected_ssid = "expected_ssid_name";
    snprintf(expected_esfnm_param.normal_mode.wifi_sta.ssid,
             sizeof(expected_esfnm_param.normal_mode.wifi_sta.ssid), "%s", expected_ssid);

    expected_netif_kind_esfnm_mask.normal_mode.netif_kind = 1;
    expected_netif_kind_esfnm_param.normal_mode.netif_kind = 0; // WiFi.

    expected_ether_netif_kind_esfnm_mask.normal_mode.netif_kind = 1;
    expected_ether_netif_kind_esfnm_param.normal_mode.netif_kind = 1; // Ether.

    expect_value(__wrap_EsfNetworkManagerOpen, mode, kEsfNetworkManagerModeNormal);
    expect_value(__wrap_EsfNetworkManagerOpen, handle_type, kEsfNetworkManagerHandleTypeControl);
    will_return(__wrap_EsfNetworkManagerOpen, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerRegisterCallback, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerRegisterCallback, notify_callback, NetworkManagerCallback);
    expect_not_value(__wrap_EsfNetworkManagerRegisterCallback, private_data, NULL);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, exec_cb_location);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    CheckEsfNetworkManagerLoadParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // WiFi NetworkManagerSaveParameter
    CheckEsfNetworkManagerSaveParameter(&expected_netif_kind_esfnm_mask,
                                        &expected_netif_kind_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Callback function don't exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, false);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Check Connect Retry
    for (int i = 1; i <= expect_connect_wait_retry; i++) {
        expect_function_call(__wrap_IsaBtnCheckRebootRequest);
        will_return(__wrap_IsaBtnCheckRebootRequest, false);

        will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);
    }

    // Check IsaBtnCheckFactoryResetRequest.

    will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);

    expect_value(__wrap_EsfNetworkManagerStop, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerStop, kEsfNetworkManagerResultInvalidParameter);

    // Ether NetworkManagerSaveParameter
    CheckEsfNetworkManagerSaveParameter(&expected_ether_netif_kind_esfnm_mask,
                                        &expected_ether_netif_kind_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Ether NetworkManagerStart and callback function exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, true);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Exec test target
    ret = ConnectNetwork();

    // Check return and global value
    assert_int_equal(ret, kRetOk);
    assert_int_equal(s_esfnm_handle, expected_esfnm_handle);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_AbortWiFiRebootRequestEnable(void **state)
{
    RetCode ret;

    EsfNetworkManagerHandle expected_esfnm_handle = (EsfNetworkManagerHandle)0x99887766;
    NetworkManagerExecCb exec_cb_location = kNetworkManagerExecCbIsaBtn;
    int expect_connect_wait_retry = 1;

    // This is expected paramter for ssid
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    // This is expected paramter for netif_kind
    EsfNetworkManagerParameterMask expected_netif_kind_esfnm_mask;
    EsfNetworkManagerParameter expected_netif_kind_esfnm_param;

    // Initialize
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    memset(&expected_netif_kind_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_netif_kind_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    const char *expected_ssid = "expected_ssid_name";
    snprintf(expected_esfnm_param.normal_mode.wifi_sta.ssid,
             sizeof(expected_esfnm_param.normal_mode.wifi_sta.ssid), "%s", expected_ssid);

    expected_netif_kind_esfnm_mask.normal_mode.netif_kind = 1;
    expected_netif_kind_esfnm_param.normal_mode.netif_kind = 0; // WiFi.

    expect_value(__wrap_EsfNetworkManagerOpen, mode, kEsfNetworkManagerModeNormal);
    expect_value(__wrap_EsfNetworkManagerOpen, handle_type, kEsfNetworkManagerHandleTypeControl);
    will_return(__wrap_EsfNetworkManagerOpen, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerRegisterCallback, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerRegisterCallback, notify_callback, NetworkManagerCallback);
    expect_not_value(__wrap_EsfNetworkManagerRegisterCallback, private_data, NULL);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, exec_cb_location);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, expect_connect_wait_retry);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    CheckEsfNetworkManagerLoadParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // WiFi NetworkManagerSaveParameter
    CheckEsfNetworkManagerSaveParameter(&expected_netif_kind_esfnm_mask,
                                        &expected_netif_kind_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Callback function don't exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, false);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Check Connect Retry
    for (int i = 1; i <= (expect_connect_wait_retry + 1);
         i++) { // "+ 1" means that to execute the callback
        expect_function_call(__wrap_IsaBtnCheckRebootRequest);

        if (i == (expect_connect_wait_retry + 1)) {
            will_return(__wrap_IsaBtnCheckRebootRequest, true);
        }
        else {
            will_return(__wrap_IsaBtnCheckRebootRequest, false);
            will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);
        }
    }

    // Check IsaBtnCheckFactoryResetRequest.

    will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);

    expect_value(__wrap_EsfNetworkManagerStop, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerStop, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerUnregisterCallback, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerUnregisterCallback, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerClose, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerClose, kEsfNetworkManagerResultSuccess);

    // Exec test target
    ret = ConnectNetwork();

    // Check return and global value
    assert_int_equal(ret, kRetAbort);
    assert_int_equal(s_esfnm_handle, expected_esfnm_handle);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_AbortWiFiFactoryResetRequestEnable(void **state)
{
    RetCode ret;

    EsfNetworkManagerHandle expected_esfnm_handle = (EsfNetworkManagerHandle)0x99887766;
    NetworkManagerExecCb exec_cb_location = kNetworkManagerExecCbIsaBtn;
    int expect_connect_wait_retry = 1;

    // This is expected paramter for ssid
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    // This is expected paramter for netif_kind
    EsfNetworkManagerParameterMask expected_netif_kind_esfnm_mask;
    EsfNetworkManagerParameter expected_netif_kind_esfnm_param;

    // Initialize
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    memset(&expected_netif_kind_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_netif_kind_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    const char *expected_ssid = "expected_ssid_name";
    snprintf(expected_esfnm_param.normal_mode.wifi_sta.ssid,
             sizeof(expected_esfnm_param.normal_mode.wifi_sta.ssid), "%s", expected_ssid);

    expected_netif_kind_esfnm_mask.normal_mode.netif_kind = 1;
    expected_netif_kind_esfnm_param.normal_mode.netif_kind = 0; // WiFi.

    expect_value(__wrap_EsfNetworkManagerOpen, mode, kEsfNetworkManagerModeNormal);
    expect_value(__wrap_EsfNetworkManagerOpen, handle_type, kEsfNetworkManagerHandleTypeControl);
    will_return(__wrap_EsfNetworkManagerOpen, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerRegisterCallback, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerRegisterCallback, notify_callback, NetworkManagerCallback);
    expect_not_value(__wrap_EsfNetworkManagerRegisterCallback, private_data, NULL);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, exec_cb_location);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, expect_connect_wait_retry);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    CheckEsfNetworkManagerLoadParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // WiFi NetworkManagerSaveParameter
    CheckEsfNetworkManagerSaveParameter(&expected_netif_kind_esfnm_mask,
                                        &expected_netif_kind_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Callback function don't exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, false);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Check Connect Retry
    for (int i = 1; i <= (expect_connect_wait_retry + 1);
         i++) { // "+ 1" means that to execute the callback
        expect_function_call(__wrap_IsaBtnCheckRebootRequest);

        if (i == (expect_connect_wait_retry + 1)) {
            will_return(__wrap_IsaBtnCheckRebootRequest, false);
            will_return(__wrap_IsaBtnCheckFactoryResetRequest, true);
        }
        else {
            will_return(__wrap_IsaBtnCheckRebootRequest, false);
            will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);
        }
    }

    // Check IsaBtnCheckFactoryResetRequest.

    will_return(__wrap_IsaBtnCheckFactoryResetRequest, true);

    // Check EsfLedManagerSetLightingPersistence.

    will_return(__wrap_EsfLedManagerSetLightingPersistence, kEsfLedManagerSuccess);

    expect_value(__wrap_EsfNetworkManagerStop, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerStop, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerUnregisterCallback, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerUnregisterCallback, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerClose, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerClose, kEsfNetworkManagerResultSuccess);

    // Exec test target
    ret = ConnectNetwork();

    // Check return and global value
    assert_int_equal(ret, kRetAbort);
    assert_int_equal(s_esfnm_handle, expected_esfnm_handle);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_FullySuccessEtherConnectRetry(void **state)
{
    RetCode ret;

    EsfNetworkManagerHandle expected_esfnm_handle = (EsfNetworkManagerHandle)0x99887766;
    NetworkManagerExecCb exec_cb_location = kNetworkManagerExecCbIsaBtn;
    int expect_connect_wait_retry = 15;

    // This is expected paramter for Ether
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    // This is expected paramter for netif_kind
    EsfNetworkManagerParameterMask expected_netif_kind_esfnm_mask;
    EsfNetworkManagerParameter expected_netif_kind_esfnm_param;

    // Initialize
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    memset(&expected_netif_kind_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_netif_kind_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;

    expected_netif_kind_esfnm_mask.normal_mode.netif_kind = 1;
    expected_netif_kind_esfnm_param.normal_mode.netif_kind = 1; // Ether.

    expect_value(__wrap_EsfNetworkManagerOpen, mode, kEsfNetworkManagerModeNormal);
    expect_value(__wrap_EsfNetworkManagerOpen, handle_type, kEsfNetworkManagerHandleTypeControl);
    will_return(__wrap_EsfNetworkManagerOpen, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerRegisterCallback, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerRegisterCallback, notify_callback, NetworkManagerCallback);
    expect_not_value(__wrap_EsfNetworkManagerRegisterCallback, private_data, NULL);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, exec_cb_location);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, expect_connect_wait_retry);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    CheckEsfNetworkManagerLoadParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Ether NetworkManagerSaveParameter
    CheckEsfNetworkManagerSaveParameter(&expected_netif_kind_esfnm_mask,
                                        &expected_netif_kind_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Callback function don't exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, false);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Check Connect Retry
    for (int i = 1; i <= (expect_connect_wait_retry + 1);
         i++) { // "+ 1" means that to execute the callback
        expect_function_call(__wrap_IsaBtnCheckRebootRequest);
        will_return(__wrap_IsaBtnCheckRebootRequest, false);

        will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);
    }

    // Exec test target
    ret = ConnectNetwork();

    // Check return and global value
    assert_int_equal(ret, kRetOk);
    assert_int_equal(s_esfnm_handle, expected_esfnm_handle);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_ErrorEsfNetworkManagerSaveParameterButSuccessEther(void **state)
{
    RetCode ret;

    EsfNetworkManagerHandle expected_esfnm_handle = (EsfNetworkManagerHandle)0x99887766;
    NetworkManagerExecCb exec_cb_location = kNetworkManagerExecCbNM;

    // This is expected paramter for Ether
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    // This is expected paramter for netif_kind
    EsfNetworkManagerParameterMask expected_netif_kind_esfnm_mask;
    EsfNetworkManagerParameter expected_netif_kind_esfnm_param;

    // Initialize
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    memset(&expected_netif_kind_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_netif_kind_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;

    expected_netif_kind_esfnm_mask.normal_mode.netif_kind = 1;
    expected_netif_kind_esfnm_param.normal_mode.netif_kind = 1; // Ether.

    expect_value(__wrap_EsfNetworkManagerOpen, mode, kEsfNetworkManagerModeNormal);
    expect_value(__wrap_EsfNetworkManagerOpen, handle_type, kEsfNetworkManagerHandleTypeControl);
    will_return(__wrap_EsfNetworkManagerOpen, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerRegisterCallback, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerRegisterCallback, notify_callback, NetworkManagerCallback);
    expect_not_value(__wrap_EsfNetworkManagerRegisterCallback, private_data, NULL);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, exec_cb_location);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    CheckEsfNetworkManagerLoadParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Ether NetworkManagerSaveParameter
    CheckEsfNetworkManagerSaveParameter(&expected_netif_kind_esfnm_mask,
                                        &expected_netif_kind_esfnm_param,
                                        kEsfNetworkManagerResultInvalidParameter);

    // Callback function exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, true);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Exec test target
    ret = ConnectNetwork();

    // Check return and global value
    assert_int_equal(ret, kRetOk);
    assert_int_equal(s_esfnm_handle, expected_esfnm_handle);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_AlreadyRunningNetworkButSuccessEther(void **state)
{
    RetCode ret;

    EsfNetworkManagerHandle expected_esfnm_handle = (EsfNetworkManagerHandle)0x99887766;
    NetworkManagerExecCb exec_cb_location = kNetworkManagerExecCbNM;

    // This is expected paramter for Ether
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    // This is expected paramter for netif_kind
    EsfNetworkManagerParameterMask expected_netif_kind_esfnm_mask;
    EsfNetworkManagerParameter expected_netif_kind_esfnm_param;

    // Initialize
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    memset(&expected_netif_kind_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_netif_kind_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;

    expected_netif_kind_esfnm_mask.normal_mode.netif_kind = 1;
    expected_netif_kind_esfnm_param.normal_mode.netif_kind = 1; // Ether.

    expect_value(__wrap_EsfNetworkManagerOpen, mode, kEsfNetworkManagerModeNormal);
    expect_value(__wrap_EsfNetworkManagerOpen, handle_type, kEsfNetworkManagerHandleTypeControl);
    will_return(__wrap_EsfNetworkManagerOpen, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerRegisterCallback, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerRegisterCallback, notify_callback, NetworkManagerCallback);
    expect_not_value(__wrap_EsfNetworkManagerRegisterCallback, private_data, NULL);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, exec_cb_location);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    CheckEsfNetworkManagerLoadParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Ether NetworkManagerSaveParameter
    CheckEsfNetworkManagerSaveParameter(&expected_netif_kind_esfnm_mask,
                                        &expected_netif_kind_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // 1st AlreadyRunning and callback function don't exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, false);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultStatusAlreadyRunning);

    // 2nd Success and callback function exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, true);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Exec test target
    ret = ConnectNetwork();

    // Check return and global value
    assert_int_equal(ret, kRetOk);
    assert_int_equal(s_esfnm_handle, expected_esfnm_handle);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_ErrorEtherEsfNetworkManagerStart(void **state)
{
    RetCode ret;

    EsfNetworkManagerHandle expected_esfnm_handle = (EsfNetworkManagerHandle)0x99887766;
    NetworkManagerExecCb exec_cb_location = kNetworkManagerExecCbNM;

    // This is expected paramter for Ether
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    // This is expected paramter for netif_kind
    EsfNetworkManagerParameterMask expected_netif_kind_esfnm_mask;
    EsfNetworkManagerParameter expected_netif_kind_esfnm_param;

    // Initialize
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    memset(&expected_netif_kind_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_netif_kind_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;

    expected_netif_kind_esfnm_mask.normal_mode.netif_kind = 1;
    expected_netif_kind_esfnm_param.normal_mode.netif_kind = 1; // Ether.

    expect_value(__wrap_EsfNetworkManagerOpen, mode, kEsfNetworkManagerModeNormal);
    expect_value(__wrap_EsfNetworkManagerOpen, handle_type, kEsfNetworkManagerHandleTypeControl);
    will_return(__wrap_EsfNetworkManagerOpen, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerRegisterCallback, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerRegisterCallback, notify_callback, NetworkManagerCallback);
    expect_not_value(__wrap_EsfNetworkManagerRegisterCallback, private_data, NULL);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, exec_cb_location);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    CheckEsfNetworkManagerLoadParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Ether NetworkManagerSaveParameter
    CheckEsfNetworkManagerSaveParameter(&expected_netif_kind_esfnm_mask,
                                        &expected_netif_kind_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Callback function exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, true);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultInvalidParameter);

    expect_value(__wrap_EsfNetworkManagerUnregisterCallback, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerUnregisterCallback, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerClose, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerClose, kEsfNetworkManagerResultSuccess);

    // Exec test target
    ret = ConnectNetwork();

    // Check return and global value
    assert_int_equal(ret, kRetFailed);
    assert_int_equal(s_esfnm_handle, expected_esfnm_handle);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_ErrorEtherConnectRetryOver(void **state)
{
    RetCode ret;

    EsfNetworkManagerHandle expected_esfnm_handle = (EsfNetworkManagerHandle)0x99887766;
    NetworkManagerExecCb exec_cb_location = kNetworkManagerExecCbNothing;
    int expect_connect_wait_retry = 31;

    // This is expected paramter for Ether
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    // This is expected paramter for netif_kind
    EsfNetworkManagerParameterMask expected_netif_kind_esfnm_mask;
    EsfNetworkManagerParameter expected_netif_kind_esfnm_param;

    // Initialize
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    memset(&expected_netif_kind_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_netif_kind_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;

    expected_netif_kind_esfnm_mask.normal_mode.netif_kind = 1;
    expected_netif_kind_esfnm_param.normal_mode.netif_kind = 1; // Ether.

    expect_value(__wrap_EsfNetworkManagerOpen, mode, kEsfNetworkManagerModeNormal);
    expect_value(__wrap_EsfNetworkManagerOpen, handle_type, kEsfNetworkManagerHandleTypeControl);
    will_return(__wrap_EsfNetworkManagerOpen, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerRegisterCallback, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerRegisterCallback, notify_callback, NetworkManagerCallback);
    expect_not_value(__wrap_EsfNetworkManagerRegisterCallback, private_data, NULL);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, exec_cb_location);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    CheckEsfNetworkManagerLoadParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Ether NetworkManagerSaveParameter
    CheckEsfNetworkManagerSaveParameter(&expected_netif_kind_esfnm_mask,
                                        &expected_netif_kind_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Callback function don't exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, false);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Check Connect Retry
    for (int i = 1; i <= expect_connect_wait_retry; i++) {
        expect_function_call(__wrap_IsaBtnCheckRebootRequest);
        will_return(__wrap_IsaBtnCheckRebootRequest, false);

        will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);
    }

    // Check IsaBtnCheckFactoryResetRequest.

    will_return(__wrap_IsaBtnCheckFactoryResetRequest, true);

    // Check EsfLedManagerSetLightingPersistence.

    will_return(__wrap_EsfLedManagerSetLightingPersistence, kEsfLedManagerSuccess);

    expect_value(__wrap_EsfNetworkManagerStop, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerStop, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerUnregisterCallback, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerUnregisterCallback, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerClose, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerClose, kEsfNetworkManagerResultSuccess);

    // Exec test target
    ret = ConnectNetwork();

    // Check return and global value
    assert_int_equal(ret, kRetFailed);
    assert_int_equal(s_esfnm_handle, expected_esfnm_handle);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_ErrorEtherConnectRetryOverErrorEsfNetworkManagerStop(void **state)
{
    RetCode ret;

    EsfNetworkManagerHandle expected_esfnm_handle = (EsfNetworkManagerHandle)0x99887766;
    NetworkManagerExecCb exec_cb_location = kNetworkManagerExecCbNothing;
    int expect_connect_wait_retry = 31;

    // This is expected paramter for Ether
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    // This is expected paramter for netif_kind
    EsfNetworkManagerParameterMask expected_netif_kind_esfnm_mask;
    EsfNetworkManagerParameter expected_netif_kind_esfnm_param;

    // Initialize
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    memset(&expected_netif_kind_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_netif_kind_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;

    expected_netif_kind_esfnm_mask.normal_mode.netif_kind = 1;
    expected_netif_kind_esfnm_param.normal_mode.netif_kind = 1; // Ether.

    expect_value(__wrap_EsfNetworkManagerOpen, mode, kEsfNetworkManagerModeNormal);
    expect_value(__wrap_EsfNetworkManagerOpen, handle_type, kEsfNetworkManagerHandleTypeControl);
    will_return(__wrap_EsfNetworkManagerOpen, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerRegisterCallback, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerRegisterCallback, notify_callback, NetworkManagerCallback);
    expect_not_value(__wrap_EsfNetworkManagerRegisterCallback, private_data, NULL);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, exec_cb_location);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    CheckEsfNetworkManagerLoadParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Ether NetworkManagerSaveParameter
    CheckEsfNetworkManagerSaveParameter(&expected_netif_kind_esfnm_mask,
                                        &expected_netif_kind_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Callback function don't exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, false);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Check Connect Retry
    for (int i = 1; i <= expect_connect_wait_retry; i++) {
        expect_function_call(__wrap_IsaBtnCheckRebootRequest);
        will_return(__wrap_IsaBtnCheckRebootRequest, false);

        will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);
    }

    // Check IsaBtnCheckFactoryResetRequest.

    will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);

    expect_value(__wrap_EsfNetworkManagerStop, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerStop, kEsfNetworkManagerResultInvalidParameter);

    expect_value(__wrap_EsfNetworkManagerUnregisterCallback, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerUnregisterCallback, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerClose, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerClose, kEsfNetworkManagerResultSuccess);

    // Exec test target
    ret = ConnectNetwork();

    // Check return and global value
    assert_int_equal(ret, kRetFailed);
    assert_int_equal(s_esfnm_handle, expected_esfnm_handle);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_AbortEtherRebootRequestEnable(void **state)
{
    RetCode ret;

    EsfNetworkManagerHandle expected_esfnm_handle = (EsfNetworkManagerHandle)0x99887766;
    NetworkManagerExecCb exec_cb_location = kNetworkManagerExecCbIsaBtn;
    int expect_connect_wait_retry = 1;

    // This is expected paramter for Ether
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    // This is expected paramter for netif_kind
    EsfNetworkManagerParameterMask expected_netif_kind_esfnm_mask;
    EsfNetworkManagerParameter expected_netif_kind_esfnm_param;

    // Initialize
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    memset(&expected_netif_kind_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_netif_kind_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;

    expected_netif_kind_esfnm_mask.normal_mode.netif_kind = 1;
    expected_netif_kind_esfnm_param.normal_mode.netif_kind = 1; // Ether.

    expect_value(__wrap_EsfNetworkManagerOpen, mode, kEsfNetworkManagerModeNormal);
    expect_value(__wrap_EsfNetworkManagerOpen, handle_type, kEsfNetworkManagerHandleTypeControl);
    will_return(__wrap_EsfNetworkManagerOpen, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerRegisterCallback, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerRegisterCallback, notify_callback, NetworkManagerCallback);
    expect_not_value(__wrap_EsfNetworkManagerRegisterCallback, private_data, NULL);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, exec_cb_location);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, expect_connect_wait_retry);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    CheckEsfNetworkManagerLoadParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Ether NetworkManagerSaveParameter
    CheckEsfNetworkManagerSaveParameter(&expected_netif_kind_esfnm_mask,
                                        &expected_netif_kind_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Callback function don't exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, false);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Check Connect Retry
    for (int i = 1; i <= (expect_connect_wait_retry + 1);
         i++) { // "+ 1" means that to execute the callback
        expect_function_call(__wrap_IsaBtnCheckRebootRequest);

        if (i == (expect_connect_wait_retry + 1)) {
            will_return(__wrap_IsaBtnCheckRebootRequest, true);
        }
        else {
            will_return(__wrap_IsaBtnCheckRebootRequest, false);
            will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);
        }
    }

    // Check IsaBtnCheckFactoryResetRequest.

    will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);

    expect_value(__wrap_EsfNetworkManagerStop, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerStop, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerUnregisterCallback, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerUnregisterCallback, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerClose, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerClose, kEsfNetworkManagerResultSuccess);

    // Exec test target
    ret = ConnectNetwork();

    // Check return and global value
    assert_int_equal(ret, kRetAbort);
    assert_int_equal(s_esfnm_handle, expected_esfnm_handle);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_AbortEtherFactoryResetRequestEnable(void **state)
{
    RetCode ret;

    EsfNetworkManagerHandle expected_esfnm_handle = (EsfNetworkManagerHandle)0x99887766;
    NetworkManagerExecCb exec_cb_location = kNetworkManagerExecCbIsaBtn;
    int expect_connect_wait_retry = 1;

    // This is expected paramter for Ether
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    // This is expected paramter for netif_kind
    EsfNetworkManagerParameterMask expected_netif_kind_esfnm_mask;
    EsfNetworkManagerParameter expected_netif_kind_esfnm_param;

    // Initialize
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    memset(&expected_netif_kind_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_netif_kind_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;

    expected_netif_kind_esfnm_mask.normal_mode.netif_kind = 1;
    expected_netif_kind_esfnm_param.normal_mode.netif_kind = 1; // Ether.

    expect_value(__wrap_EsfNetworkManagerOpen, mode, kEsfNetworkManagerModeNormal);
    expect_value(__wrap_EsfNetworkManagerOpen, handle_type, kEsfNetworkManagerHandleTypeControl);
    will_return(__wrap_EsfNetworkManagerOpen, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerRegisterCallback, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerRegisterCallback, notify_callback, NetworkManagerCallback);
    expect_not_value(__wrap_EsfNetworkManagerRegisterCallback, private_data, NULL);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, exec_cb_location);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, expect_connect_wait_retry);
    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    CheckEsfNetworkManagerLoadParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Ether NetworkManagerSaveParameter
    CheckEsfNetworkManagerSaveParameter(&expected_netif_kind_esfnm_mask,
                                        &expected_netif_kind_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Callback function don't exec
    expect_value(__wrap_EsfNetworkManagerStart, handle, expected_esfnm_handle);
    expect_value(__wrap_EsfNetworkManagerStart, start_type,
                 kEsfNetworkManagerStartTypeSaveParameter);
    expect_value(__wrap_EsfNetworkManagerStart, os_info, NULL);
    will_return(__wrap_EsfNetworkManagerStart, false);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Check Connect Retry
    for (int i = 1; i <= (expect_connect_wait_retry + 1);
         i++) { // "+ 1" means that to execute the callback
        expect_function_call(__wrap_IsaBtnCheckRebootRequest);

        if (i == (expect_connect_wait_retry + 1)) {
            will_return(__wrap_IsaBtnCheckRebootRequest, false);
            will_return(__wrap_IsaBtnCheckFactoryResetRequest, true);
        }
        else {
            will_return(__wrap_IsaBtnCheckRebootRequest, false);
            will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);
        }
    }

    // Check IsaBtnCheckFactoryResetRequest.

    will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);

    expect_value(__wrap_EsfNetworkManagerStop, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerStop, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerUnregisterCallback, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerUnregisterCallback, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerClose, handle, expected_esfnm_handle);
    will_return(__wrap_EsfNetworkManagerClose, kEsfNetworkManagerResultSuccess);

    // Exec test target
    ret = ConnectNetwork();

    // Check return and global value
    assert_int_equal(ret, kRetAbort);
    assert_int_equal(s_esfnm_handle, expected_esfnm_handle);

    return;
}

/*----------------------------------------------------------------------------*/

//
// StartSyncNtp()
//

/*----------------------------------------------------------------------------*/
static void test_StartSyncNtp_FullySuccess(void **state)
{
    RetCode ret;

    ClockManagerExecCb exec_cb_location = kClockManagerExecCbCM;
    bool expect_ntp_sync = true;

    // These are expected paramters for ClockManagerParams
    EsfClockManagerParamsMask expected_cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    EsfClockManagerParams expected_cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    s_ntp_sync_notify = false;
    s_ntp_sync_done = false;

    CheckEsfClockManagerSetParams(&expected_cm_param, &expected_cm_mask, kClockManagerSuccess);

    // Check callback
    expect_value(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, on_ntp_sync_complete,
                 NtpSyncCallback);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, exec_cb_location);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, expect_ntp_sync);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // Callback function exec
    expect_function_call(__wrap_EsfClockManagerStart);
    will_return(__wrap_EsfClockManagerStart, true);
    will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

    expect_function_call(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete);
    will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // Exec test target
    ret = StartSyncNtp();

    // Check return and global value
    assert_int_equal(ret, kRetOk);
    assert_false(s_ntp_sync_notify);
    assert_true(s_ntp_sync_done);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_StartSyncNtp_ErrorEsfClockManagerSetParams(void **state)
{
    RetCode ret;

    // These are expected paramters for ClockManagerParams
    EsfClockManagerParamsMask expected_cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    EsfClockManagerParams expected_cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    s_ntp_sync_notify = false;
    s_ntp_sync_done = false;

    CheckEsfClockManagerSetParams(&expected_cm_param, &expected_cm_mask,
                                  kClockManagerInternalError);

    // Exec test target
    ret = StartSyncNtp();

    // Check return and global value
    assert_int_equal(ret, kRetFailed);
    assert_false(s_ntp_sync_notify);
    assert_false(s_ntp_sync_done);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_StartSyncNtp_ErrorEsfClockManagerRegisterCbOnNtpSyncComplete(void **state)
{
    RetCode ret;

    ClockManagerExecCb exec_cb_location = kClockManagerExecCbCM;
    bool expect_ntp_sync = true;

    // These are expected paramters for ClockManagerParams
    EsfClockManagerParamsMask expected_cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    EsfClockManagerParams expected_cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    s_ntp_sync_notify = false;
    s_ntp_sync_done = false;

    CheckEsfClockManagerSetParams(&expected_cm_param, &expected_cm_mask, kClockManagerSuccess);

    // Check callback
    expect_value(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, on_ntp_sync_complete,
                 NtpSyncCallback);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, exec_cb_location);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, expect_ntp_sync);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerInternalError);

    // Exec test target
    ret = StartSyncNtp();

    // Check return and global value
    assert_int_equal(ret, kRetFailed);
    assert_false(s_ntp_sync_notify);
    assert_false(s_ntp_sync_done);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_StartSyncNtp_ErrorEsfClockManagerStart(void **state)
{
    RetCode ret;

    ClockManagerExecCb exec_cb_location = kClockManagerExecCbCM;
    bool expect_ntp_sync = true;

    // These are expected paramters for ClockManagerParams
    EsfClockManagerParamsMask expected_cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    EsfClockManagerParams expected_cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    s_ntp_sync_notify = false;
    s_ntp_sync_done = false;

    CheckEsfClockManagerSetParams(&expected_cm_param, &expected_cm_mask, kClockManagerSuccess);

    // Check callback
    expect_value(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, on_ntp_sync_complete,
                 NtpSyncCallback);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, exec_cb_location);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, expect_ntp_sync);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // Callback function exec
    expect_function_call(__wrap_EsfClockManagerStart);
    will_return(__wrap_EsfClockManagerStart, true);
    will_return(__wrap_EsfClockManagerStart, kClockManagerInternalError);

    expect_function_call(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete);
    will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // Exec test target
    ret = StartSyncNtp();

    // Check return and global value
    assert_int_equal(ret, kRetFailed);
    assert_true(s_ntp_sync_notify);
    assert_true(s_ntp_sync_done);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_StartSyncNtp_Success2ndSyncRetry(void **state)
{
    RetCode ret;

    ClockManagerExecCb exec_cb_location = kClockManagerExecCbCM;
    bool expect_ntp_sync = true;

    // These are expected paramters for ClockManagerParams
    EsfClockManagerParamsMask expected_cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    EsfClockManagerParams expected_cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    s_ntp_sync_notify = true;
    s_ntp_sync_done = false;

    CheckEsfClockManagerSetParams(&expected_cm_param, &expected_cm_mask, kClockManagerSuccess);

    // Check callback
    expect_value(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, on_ntp_sync_complete,
                 NtpSyncCallback);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, exec_cb_location);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, expect_ntp_sync);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // 1st wait NTP sync and callback function don't exec
    expect_function_call(__wrap_EsfClockManagerStart);
    will_return(__wrap_EsfClockManagerStart, false);
    will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

    expect_function_call(__wrap_EsfClockManagerStop);
    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    // 2nd wait NTP sync and callback function exec
    expect_function_call(__wrap_EsfClockManagerStart);
    will_return(__wrap_EsfClockManagerStart, true);
    will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

    expect_function_call(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete);
    will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // Exec test target
    ret = StartSyncNtp();

    // Check return and global value
    assert_int_equal(ret, kRetOk);
    assert_false(s_ntp_sync_notify);
    assert_true(s_ntp_sync_done);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_StartSyncNtp_ErrorEsfClockManagerStopButSuccess2ndSyncRetry(void **state)
{
    RetCode ret;

    ClockManagerExecCb exec_cb_location = kClockManagerExecCbCM;
    bool expect_ntp_sync = true;

    // These are expected paramters for ClockManagerParams
    EsfClockManagerParamsMask expected_cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    EsfClockManagerParams expected_cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    s_ntp_sync_notify = true;
    s_ntp_sync_done = false;

    CheckEsfClockManagerSetParams(&expected_cm_param, &expected_cm_mask, kClockManagerSuccess);

    // Check callback
    expect_value(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, on_ntp_sync_complete,
                 NtpSyncCallback);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, exec_cb_location);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, expect_ntp_sync);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // 1st wait NTP sync and callback function don't exec
    expect_function_call(__wrap_EsfClockManagerStart);
    will_return(__wrap_EsfClockManagerStart, false);
    will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

    expect_function_call(__wrap_EsfClockManagerStop);
    will_return(__wrap_EsfClockManagerStop, kClockManagerInternalError);

    // 2nd wait NTP sync and callback function exec
    expect_function_call(__wrap_EsfClockManagerStart);
    will_return(__wrap_EsfClockManagerStart, true);
    will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

    expect_function_call(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete);
    will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // Exec test target
    ret = StartSyncNtp();

    // Check return and global value
    assert_int_equal(ret, kRetOk);
    assert_false(s_ntp_sync_notify);
    assert_true(s_ntp_sync_done);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_StartSyncNtp_FullySuccessSyncRetry(void **state)
{
    RetCode ret;

    ClockManagerExecCb exec_cb_location = kClockManagerExecCbIsaBtn;
    int expect_ntp_sync_retry = 0;
    bool expect_ntp_sync = true;

    // These are expected paramters for ClockManagerParams
    EsfClockManagerParamsMask expected_cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    EsfClockManagerParams expected_cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    s_ntp_sync_notify = false;
    s_ntp_sync_done = false;

    CheckEsfClockManagerSetParams(&expected_cm_param, &expected_cm_mask, kClockManagerSuccess);

    // Check callback
    expect_value(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, on_ntp_sync_complete,
                 NtpSyncCallback);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, exec_cb_location);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, expect_ntp_sync);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, expect_ntp_sync_retry);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // Callback function don't exec
    expect_function_call(__wrap_EsfClockManagerStart);
    will_return(__wrap_EsfClockManagerStart, false);
    will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

    // Check Ntp Sync Retry
    for (int i = 0; i <= expect_ntp_sync_retry; i++) {
        expect_function_call(__wrap_IsaBtnCheckRebootRequest);
        will_return(__wrap_IsaBtnCheckRebootRequest, false);

        will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);
    }

    expect_function_call(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete);
    will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // Exec test target
    ret = StartSyncNtp();

    // Check return and global value
    assert_int_equal(ret, kRetOk);
    assert_false(s_ntp_sync_notify);
    assert_true(s_ntp_sync_done);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_StartSyncNtp_AbortRebootRequestEnable(void **state)
{
    RetCode ret;

    ClockManagerExecCb exec_cb_location = kClockManagerExecCbIsaBtn;
    int expect_ntp_sync_retry = 0;
    bool expect_ntp_sync = true;

    // These are expected paramters for ClockManagerParams
    EsfClockManagerParamsMask expected_cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    EsfClockManagerParams expected_cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    s_ntp_sync_notify = false;
    s_ntp_sync_done = false;

    CheckEsfClockManagerSetParams(&expected_cm_param, &expected_cm_mask, kClockManagerSuccess);

    // Check callback
    expect_value(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, on_ntp_sync_complete,
                 NtpSyncCallback);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, exec_cb_location);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, expect_ntp_sync);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, expect_ntp_sync_retry);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // Callback function don't exec
    expect_function_call(__wrap_EsfClockManagerStart);
    will_return(__wrap_EsfClockManagerStart, false);
    will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

    // Check Ntp Sync Retry
    for (int i = 0; i <= expect_ntp_sync_retry; i++) {
        expect_function_call(__wrap_IsaBtnCheckRebootRequest);
        will_return(__wrap_IsaBtnCheckRebootRequest, true);
    }

    expect_function_call(__wrap_EsfClockManagerStop);
    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    expect_function_call(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete);
    will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // Exec test target
    ret = StartSyncNtp();

    // Check return and global value
    assert_int_equal(ret, kRetAbort);
    assert_true(s_ntp_sync_notify);
    assert_true(s_ntp_sync_done);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_StartSyncNtp_AbortFactoryResetRequestEnable(void **state)
{
    RetCode ret;

    ClockManagerExecCb exec_cb_location = kClockManagerExecCbIsaBtn;
    int expect_ntp_sync_retry = 0;
    bool expect_ntp_sync = true;

    // These are expected paramters for ClockManagerParams
    EsfClockManagerParamsMask expected_cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    EsfClockManagerParams expected_cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    s_ntp_sync_notify = false;
    s_ntp_sync_done = false;

    CheckEsfClockManagerSetParams(&expected_cm_param, &expected_cm_mask, kClockManagerSuccess);

    // Check callback
    expect_value(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, on_ntp_sync_complete,
                 NtpSyncCallback);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, exec_cb_location);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, expect_ntp_sync);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, expect_ntp_sync_retry);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // Callback function don't exec
    expect_function_call(__wrap_EsfClockManagerStart);
    will_return(__wrap_EsfClockManagerStart, false);
    will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

    // Check Ntp Sync Retry
    for (int i = 0; i <= expect_ntp_sync_retry; i++) {
        expect_function_call(__wrap_IsaBtnCheckRebootRequest);
        will_return(__wrap_IsaBtnCheckRebootRequest, false);
        will_return(__wrap_IsaBtnCheckFactoryResetRequest, true);
    }

    expect_function_call(__wrap_EsfClockManagerStop);
    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    expect_function_call(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete);
    will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // Exec test target
    ret = StartSyncNtp();

    // Check return and global value
    assert_int_equal(ret, kRetAbort);
    assert_true(s_ntp_sync_notify);
    assert_true(s_ntp_sync_done);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_StartSyncNtp_TimeoutNtpSync(void **state)
{
    RetCode ret;

    ClockManagerExecCb exec_cb_location =
        kClockManagerExecCbNothing; // Don't execute callback to simulate timeout
    int expect_ntp_sync_retry =
        31; // NTP_SYNC_WAIT_MAX_SEC (30) - will timeout after 31 iterations (0-30)
    bool expect_ntp_sync = false; // NTP sync never completes due to timeout

    // These are expected parameters for ClockManagerParams
    EsfClockManagerParamsMask expected_cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    EsfClockManagerParams expected_cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    s_ntp_sync_notify = false;
    s_ntp_sync_done = false;

    CheckEsfClockManagerSetParams(&expected_cm_param, &expected_cm_mask, kClockManagerSuccess);

    // Check callback
    expect_value(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, on_ntp_sync_complete,
                 NtpSyncCallback);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, exec_cb_location);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, expect_ntp_sync);
    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // Callback function don't exec
    expect_function_call(__wrap_EsfClockManagerStart);
    will_return(__wrap_EsfClockManagerStart, false);
    will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

    // Check Ntp Sync Retry for timeout scenario
    // Button checks return false for NTP_SYNC_WAIT_MAX_SEC+1 times, then timeout occurs
    for (int i = 0; i <= expect_ntp_sync_retry; i++) {
        expect_function_call(__wrap_IsaBtnCheckRebootRequest);
        will_return(__wrap_IsaBtnCheckRebootRequest, false);
        will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);
    }

    // EsfClockManagerStop is called when timeout occurs
    expect_function_call(__wrap_EsfClockManagerStop);
    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    expect_function_call(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete);
    will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // Exec test target
    ret = StartSyncNtp();

    // Check return value: should be kRetFailed due to timeout
    assert_int_equal(ret, kRetFailed);
    // NTP sync callback was never called, so these should remain false
    assert_false(s_ntp_sync_notify);
    assert_false(s_ntp_sync_done);

    return;
}

/*----------------------------------------------------------------------------*/

//
// NetworkManagerCallback()
//

/*----------------------------------------------------------------------------*/
static void test_NetworkManagerCallback_FullySuccess(void **state)
{
    EsfNetworkManagerMode mode = kEsfNetworkManagerModeAccessPoint;
    EsfNetworkManagerNotifyInfo info = kEsfNetworkManagerNotifyInfoDisconnected;
    int expect_private_data = 3;

    // Exec test target
    NetworkManagerCallback(mode, info, (void *)&expect_private_data);
}

/*----------------------------------------------------------------------------*/
static void test_NetworkManagerCallback_InputNull(void **state)
{
    EsfNetworkManagerMode mode = kEsfNetworkManagerModeAccessPoint;
    EsfNetworkManagerNotifyInfo info = kEsfNetworkManagerNotifyInfoDisconnected;
    int *expect_private_data = NULL;

    // Exec test target
    NetworkManagerCallback(mode, info, (void *)expect_private_data);
}

/*----------------------------------------------------------------------------*/

//
// NtpSyncCallback()
//

/*----------------------------------------------------------------------------*/
static void test_NtpSyncCallback_SyncSuccess(void **state)
{
    bool input_is_sync_success = true;

    s_ntp_sync_notify = false;
    s_ntp_sync_done = false;

    // Exec test target
    NtpSyncCallback(input_is_sync_success);

    // Check global value
    assert_true(s_ntp_sync_notify);
    assert_true(s_ntp_sync_done);
}

/*----------------------------------------------------------------------------*/
static void test_NtpSyncCallback_SyncFailed(void **state)
{
    bool input_is_sync_success = false;

    s_ntp_sync_notify = false;
    s_ntp_sync_done = false;

    // Exec test target
    NtpSyncCallback(input_is_sync_success);

    // Check global value
    assert_true(s_ntp_sync_notify);
    assert_false(s_ntp_sync_done);
}

/*----------------------------------------------------------------------------*/

//
// main()
//

/*----------------------------------------------------------------------------*/
int main(void)
{
    const struct CMUnitTest tests[] = {
        // Initial value check for static global variable
        cmocka_unit_test(test_InitialSettingAppPsStub_InitialValueOfGlobalVariable),

        // ConnectNetwork
        cmocka_unit_test(test_ConnectNetwork_FullySuccessWifi),
        cmocka_unit_test(test_ConnectNetwork_ErrorEsfNetworkManagerOpen),
        cmocka_unit_test(test_ConnectNetwork_ErrorEsfNetworkManagerRegisterCallback),
        cmocka_unit_test(test_ConnectNetwork_ErrorEsfNetworkManagerLoadParameterButSuccessEther),
        cmocka_unit_test(test_ConnectNetwork_FullySuccessEther),
        cmocka_unit_test(test_ConnectNetwork_ErrorEsfNetworkManagerSaveParameterButSuccessWiFi),
        cmocka_unit_test(test_ConnectNetwork_AlreadyRunningNetworkButSuccessWiFi),
        cmocka_unit_test(test_ConnectNetwork_ErrorWiFiEsfNetworkManagerStartButSuccessEther),
        cmocka_unit_test(test_ConnectNetwork_FullySuccessWifiConnectRetry),
        cmocka_unit_test(test_ConnectNetwork_ConnectRetryOverWiFiButSuccessEther),
        cmocka_unit_test(
            test_ConnectNetwork_ConnectRetryOverWiFiErrorEsfNetworkManagerStopButSuccessEther),
        cmocka_unit_test(test_ConnectNetwork_AbortWiFiRebootRequestEnable),
        cmocka_unit_test(test_ConnectNetwork_AbortWiFiFactoryResetRequestEnable),
        cmocka_unit_test(test_ConnectNetwork_FullySuccessEtherConnectRetry),
        cmocka_unit_test(test_ConnectNetwork_ErrorEsfNetworkManagerSaveParameterButSuccessEther),
        cmocka_unit_test(test_ConnectNetwork_AlreadyRunningNetworkButSuccessEther),
        cmocka_unit_test(test_ConnectNetwork_ErrorEtherEsfNetworkManagerStart),
        cmocka_unit_test(test_ConnectNetwork_ErrorEtherConnectRetryOver),
        cmocka_unit_test(test_ConnectNetwork_ErrorEtherConnectRetryOverErrorEsfNetworkManagerStop),
        cmocka_unit_test(test_ConnectNetwork_AbortEtherRebootRequestEnable),
        cmocka_unit_test(test_ConnectNetwork_AbortEtherFactoryResetRequestEnable),

        // StartSyncNtp
        cmocka_unit_test(test_StartSyncNtp_FullySuccess),
        cmocka_unit_test(test_StartSyncNtp_ErrorEsfClockManagerSetParams),
        cmocka_unit_test(test_StartSyncNtp_ErrorEsfClockManagerRegisterCbOnNtpSyncComplete),
        cmocka_unit_test(test_StartSyncNtp_ErrorEsfClockManagerStart),
        cmocka_unit_test(test_StartSyncNtp_Success2ndSyncRetry),
        cmocka_unit_test(test_StartSyncNtp_ErrorEsfClockManagerStopButSuccess2ndSyncRetry),
        cmocka_unit_test(test_StartSyncNtp_FullySuccessSyncRetry),
        cmocka_unit_test(test_StartSyncNtp_AbortRebootRequestEnable),
        cmocka_unit_test(test_StartSyncNtp_AbortFactoryResetRequestEnable),
        cmocka_unit_test(test_StartSyncNtp_TimeoutNtpSync),

        // NetworkManagerCallback
        cmocka_unit_test(test_NetworkManagerCallback_FullySuccess),
        cmocka_unit_test(test_NetworkManagerCallback_InputNull),

        // NtpSyncCallback
        cmocka_unit_test(test_NtpSyncCallback_SyncSuccess),
        cmocka_unit_test(test_NtpSyncCallback_SyncFailed),

    };

    return (((cmocka_run_group_tests(tests, NULL, NULL)) == 0) ? 0 : 1);
}
