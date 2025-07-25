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
#include "ut_mock_isabutton.h"
#include "ut_mock_network_manager.h"

static EsfNetworkManagerNotifyInfoCallback s_nw_callback;
static void *s_nw_callback_private_data;
#ifdef INITIAL_SETTING_APP_PS_STUB
static EsfNetworkManagerNotifyInfo s_nw_notify_info;
#endif // INITIAL_SETTING_APP_PS_STUB

/*----------------------------------------------------------------------------*/
EsfNetworkManagerResult __wrap_EsfNetworkManagerInit(void)
{
    return mock_type(EsfNetworkManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfNetworkManagerResult __wrap_EsfNetworkManagerDeinit(void)
{
    return mock_type(EsfNetworkManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfNetworkManagerResult __wrap_EsfNetworkManagerOpen(EsfNetworkManagerMode mode,
                                                     EsfNetworkManagerHandleType handle_type,
                                                     EsfNetworkManagerHandle *handle)
{
#ifdef INITIAL_SETTING_APP_PS_STUB
    check_expected(mode);
    check_expected(handle_type);
    *handle = mock_type(EsfNetworkManagerHandle);
#else  // INITIAL_SETTING_APP_PS_STUB
    *handle = mock_type(int32_t);
#endif // INITIAL_SETTING_APP_PS_STUB

    return mock_type(EsfNetworkManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfNetworkManagerResult __wrap_EsfNetworkManagerClose(EsfNetworkManagerHandle handle)
{
#ifdef INITIAL_SETTING_APP_PS_STUB
    check_expected(handle);
#else  // INITIAL_SETTING_APP_PS_STUB
#endif // INITIAL_SETTING_APP_PS_STUB
    return mock_type(EsfNetworkManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfNetworkManagerResult __wrap_EsfNetworkManagerStart(EsfNetworkManagerHandle handle,
                                                      EsfNetworkManagerStartType start_type,
                                                      EsfNetworkManagerOSInfo *os_info)
{
#ifdef INITIAL_SETTING_APP_PS_STUB
    bool exec_cb_flag;

    check_expected(handle);
    check_expected(start_type);
    check_expected_ptr(os_info);

    exec_cb_flag = mock_type(bool);
    if (exec_cb_flag) {
        if (s_nw_callback != NULL) {
            s_nw_callback(kEsfNetworkManagerModeNormal, s_nw_notify_info,
                          s_nw_callback_private_data);

            s_nw_callback = NULL;
            s_nw_callback_private_data = NULL;
        }
    }
#else  // INITIAL_SETTING_APP_PS_STUB
    s_nw_callback(kEsfNetworkManagerModeNormal, mock_type(EsfNetworkManagerNotifyInfo),
                  s_nw_callback_private_data);
#endif // INITIAL_SETTING_APP_PS_STUB

    return mock_type(EsfNetworkManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfNetworkManagerResult __wrap_EsfNetworkManagerStop(EsfNetworkManagerHandle handle)
{
#ifdef INITIAL_SETTING_APP_PS_STUB
    check_expected(handle);
#else  // INITIAL_SETTING_APP_PS_STUB
#endif // INITIAL_SETTING_APP_PS_STUB
    return mock_type(EsfNetworkManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfNetworkManagerResult __wrap_EsfNetworkManagerRegisterCallback(
    EsfNetworkManagerHandle handle, EsfNetworkManagerNotifyInfoCallback notify_callback,
    void *private_data)
{
#ifdef INITIAL_SETTING_APP_PS_STUB
    check_expected(handle);
    check_expected_ptr(notify_callback);
    check_expected_ptr(private_data);

    NetworkManagerExecCb exec_cb = mock_type(NetworkManagerExecCb);
    EsfNetworkManagerNotifyInfo notify_info = mock_type(EsfNetworkManagerNotifyInfo);

    if (exec_cb == kNetworkManagerExecCbIsaBtn) {
        int connect_wait_retry_count = mock_type(int);

        // To execute NetworkManager callback function in IsaBtnCheckRebootRequest,
        // set callback function parameter to ut_mock_isabutton.c
        // by using IsaBtnSetClockManagerNtpSyncCallback().
        IsaBtnSetNetworkManagerNotifyCallback(notify_callback, private_data, notify_info,
                                              connect_wait_retry_count);
    }
    else if (exec_cb == kNetworkManagerExecCbNM) {
        s_nw_callback = notify_callback;
        s_nw_callback_private_data = private_data;
        s_nw_notify_info = notify_info;
    }
    else {
        /* Do Nothing */
    }

#else  // INITIAL_SETTING_APP_PS_STUB
    s_nw_callback = notify_callback;
    s_nw_callback_private_data = private_data;
#endif // INITIAL_SETTING_APP_PS_STUB

    return mock_type(EsfNetworkManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfNetworkManagerResult __wrap_EsfNetworkManagerSaveParameter(
    const EsfNetworkManagerParameterMask *mask, const EsfNetworkManagerParameter *parameter)
{
    check_expected(mask->normal_mode.dev_ip.ip);
    check_expected(mask->normal_mode.dev_ip.subnet_mask);
    check_expected(mask->normal_mode.dev_ip.gateway);
    check_expected(mask->normal_mode.dev_ip.dns);
    check_expected(mask->normal_mode.dev_ip_v6.ip);
    check_expected(mask->normal_mode.dev_ip_v6.subnet_mask);
    check_expected(mask->normal_mode.dev_ip_v6.gateway);
    check_expected(mask->normal_mode.dev_ip_v6.dns);
    check_expected(mask->normal_mode.wifi_sta.ssid);
    check_expected(mask->normal_mode.wifi_sta.password);
    check_expected(mask->normal_mode.wifi_sta.encryption);
    check_expected(mask->normal_mode.ip_method);
    check_expected(mask->normal_mode.netif_kind);
    check_expected(mask->accesspoint_mode.dev_ip.ip);
    check_expected(mask->accesspoint_mode.dev_ip.subnet_mask);
    check_expected(mask->accesspoint_mode.dev_ip.gateway);
    check_expected(mask->accesspoint_mode.dev_ip.dns);
    check_expected(mask->accesspoint_mode.wifi_ap.ssid);
    check_expected(mask->accesspoint_mode.wifi_ap.password);
    check_expected(mask->accesspoint_mode.wifi_ap.encryption);
    check_expected(mask->accesspoint_mode.wifi_ap.channel);
    check_expected(mask->proxy.url);
    check_expected(mask->proxy.port);
    check_expected(mask->proxy.username);
    check_expected(mask->proxy.password);

    if (mask->normal_mode.dev_ip.ip == 1) {
        check_expected_ptr(parameter->normal_mode.dev_ip.ip);
    }
    if (mask->normal_mode.dev_ip.subnet_mask == 1) {
        check_expected_ptr(parameter->normal_mode.dev_ip.subnet_mask);
    }
    if (mask->normal_mode.dev_ip.gateway == 1) {
        check_expected_ptr(parameter->normal_mode.dev_ip.gateway);
    }
    if (mask->normal_mode.dev_ip.dns == 1) {
        check_expected_ptr(parameter->normal_mode.dev_ip.dns);
    }
    if (mask->normal_mode.dev_ip_v6.ip == 1) {
        check_expected_ptr(parameter->normal_mode.dev_ip_v6.ip);
    }
    if (mask->normal_mode.dev_ip_v6.subnet_mask == 1) {
        check_expected_ptr(parameter->normal_mode.dev_ip_v6.subnet_mask);
    }
    if (mask->normal_mode.dev_ip_v6.gateway == 1) {
        check_expected_ptr(parameter->normal_mode.dev_ip_v6.gateway);
    }
    if (mask->normal_mode.dev_ip_v6.dns == 1) {
        check_expected_ptr(parameter->normal_mode.dev_ip_v6.dns);
    }
    if (mask->normal_mode.wifi_sta.ssid == 1) {
        check_expected_ptr(parameter->normal_mode.wifi_sta.ssid);
    }
    if (mask->normal_mode.wifi_sta.password == 1) {
        check_expected_ptr(parameter->normal_mode.wifi_sta.password);
    }
    if (mask->normal_mode.wifi_sta.encryption == 1) {
        check_expected(parameter->normal_mode.wifi_sta.encryption);
    }
    if (mask->normal_mode.ip_method == 1) {
        check_expected(parameter->normal_mode.ip_method);
    }
    if (mask->normal_mode.netif_kind == 1) {
        check_expected(parameter->normal_mode.netif_kind);
    }
    if (mask->accesspoint_mode.dev_ip.ip == 1) {
        check_expected_ptr(parameter->accesspoint_mode.dev_ip.ip);
    }
    if (mask->accesspoint_mode.dev_ip.subnet_mask == 1) {
        check_expected_ptr(parameter->accesspoint_mode.dev_ip.subnet_mask);
    }
    if (mask->accesspoint_mode.dev_ip.gateway == 1) {
        check_expected_ptr(parameter->accesspoint_mode.dev_ip.gateway);
    }
    if (mask->accesspoint_mode.dev_ip.dns == 1) {
        check_expected_ptr(parameter->accesspoint_mode.dev_ip.dns);
    }
    if (mask->accesspoint_mode.wifi_ap.ssid == 1) {
        check_expected_ptr(parameter->accesspoint_mode.wifi_ap.ssid);
    }
    if (mask->accesspoint_mode.wifi_ap.password == 1) {
        check_expected_ptr(parameter->accesspoint_mode.wifi_ap.password);
    }
    if (mask->accesspoint_mode.wifi_ap.encryption == 1) {
        check_expected(parameter->accesspoint_mode.wifi_ap.encryption);
    }
    if (mask->accesspoint_mode.wifi_ap.channel == 1) {
        check_expected(parameter->accesspoint_mode.wifi_ap.channel);
    }
    if (mask->proxy.url == 1) {
        check_expected_ptr(parameter->proxy.url);
    }
    if (mask->proxy.port == 1) {
        check_expected(parameter->proxy.port);
    }
    if (mask->proxy.username == 1) {
        check_expected_ptr(parameter->proxy.username);
    }
    if (mask->proxy.password == 1) {
        check_expected_ptr(parameter->proxy.password);
    }
    return mock_type(EsfNetworkManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfNetworkManagerResult __wrap_EsfNetworkManagerLoadParameter(
    const EsfNetworkManagerParameterMask *mask, EsfNetworkManagerParameter *parameter)
{
#ifdef INITIAL_SETTING_APP_PS_STUB
    check_expected(mask->normal_mode.dev_ip.ip);
    check_expected(mask->normal_mode.dev_ip.subnet_mask);
    check_expected(mask->normal_mode.dev_ip.gateway);
    check_expected(mask->normal_mode.dev_ip.dns);
    check_expected(mask->normal_mode.dev_ip_v6.ip);
    check_expected(mask->normal_mode.dev_ip_v6.subnet_mask);
    check_expected(mask->normal_mode.dev_ip_v6.gateway);
    check_expected(mask->normal_mode.dev_ip_v6.dns);
    check_expected(mask->normal_mode.wifi_sta.ssid);
    check_expected(mask->normal_mode.wifi_sta.password);
    check_expected(mask->normal_mode.wifi_sta.encryption);
    check_expected(mask->normal_mode.ip_method);
    check_expected(mask->normal_mode.netif_kind);
    check_expected(mask->accesspoint_mode.dev_ip.ip);
    check_expected(mask->accesspoint_mode.dev_ip.subnet_mask);
    check_expected(mask->accesspoint_mode.dev_ip.gateway);
    check_expected(mask->accesspoint_mode.dev_ip.dns);
    check_expected(mask->accesspoint_mode.wifi_ap.ssid);
    check_expected(mask->accesspoint_mode.wifi_ap.password);
    check_expected(mask->accesspoint_mode.wifi_ap.encryption);
    check_expected(mask->accesspoint_mode.wifi_ap.channel);
    check_expected(mask->proxy.url);
    check_expected(mask->proxy.port);
    check_expected(mask->proxy.username);
    check_expected(mask->proxy.password);

    *parameter = *(mock_type(EsfNetworkManagerParameter *));
#elif defined(SYSTEM_APP_STATE_STUB)
    parameter->proxy.port = mock_type(int);
    parameter->normal_mode.ip_method = mock_type(int);
    parameter->normal_mode.wifi_sta.encryption = mock_type(int);

    if (mask->normal_mode.wifi_sta.ssid == 1) {
        snprintf(parameter->normal_mode.wifi_sta.ssid, sizeof(parameter->normal_mode.wifi_sta.ssid),
                 "%s", mock_type(char *));
    }
#else
    if (mask->normal_mode.ip_method == 1U) {
        parameter->normal_mode.ip_method = mock_type(int32_t);
    }

    if (mask->normal_mode.dev_ip.ip == 1) {
        snprintf(parameter->normal_mode.dev_ip.ip, sizeof parameter->normal_mode.dev_ip.ip, "%s",
                 mock_type(const char *));
    }

    if (mask->normal_mode.dev_ip.subnet_mask == 1) {
        snprintf(parameter->normal_mode.dev_ip.subnet_mask,
                 sizeof parameter->normal_mode.dev_ip.subnet_mask, "%s", mock_type(const char *));
    }

    if (mask->normal_mode.dev_ip.gateway == 1) {
        snprintf(parameter->normal_mode.dev_ip.gateway,
                 sizeof parameter->normal_mode.dev_ip.gateway, "%s", mock_type(const char *));
    }

    if (mask->normal_mode.dev_ip.dns == 1) {
        snprintf(parameter->normal_mode.dev_ip.dns, sizeof parameter->normal_mode.dev_ip.dns, "%s",
                 mock_type(const char *));
    }

    if (mask->normal_mode.dev_ip_v6.ip == 1) {
        snprintf(parameter->normal_mode.dev_ip_v6.ip, sizeof parameter->normal_mode.dev_ip_v6.ip,
                 "%s", mock_type(const char *));
    }

    if (mask->normal_mode.dev_ip_v6.subnet_mask == 1) {
        snprintf(parameter->normal_mode.dev_ip_v6.subnet_mask,
                 sizeof parameter->normal_mode.dev_ip_v6.subnet_mask, "%s",
                 mock_type(const char *));
    }

    if (mask->normal_mode.dev_ip_v6.gateway == 1) {
        snprintf(parameter->normal_mode.dev_ip_v6.gateway,
                 sizeof parameter->normal_mode.dev_ip_v6.gateway, "%s", mock_type(const char *));
    }

    if (mask->normal_mode.dev_ip_v6.dns == 1) {
        snprintf(parameter->normal_mode.dev_ip_v6.dns, sizeof parameter->normal_mode.dev_ip_v6.dns,
                 "%s", mock_type(const char *));
    }

    if (mask->normal_mode.wifi_sta.password == 1U) {
        snprintf(parameter->normal_mode.wifi_sta.password,
                 sizeof parameter->normal_mode.wifi_sta.password, "%s", mock_type(const char *));
    }

    if (mask->normal_mode.wifi_sta.ssid == 1) {
        snprintf(parameter->normal_mode.wifi_sta.ssid, sizeof(parameter->normal_mode.wifi_sta.ssid),
                 "%s", mock_type(char *));
    }

    if (mask->normal_mode.wifi_sta.encryption == 1U) {
        parameter->normal_mode.wifi_sta.encryption = mock_type(int32_t);
    }

    if (mask->proxy.url == 1U) {
        snprintf(parameter->proxy.url, sizeof parameter->proxy.url, "%s", mock_type(const char *));
    }

    if (mask->proxy.port == 1U) {
        parameter->proxy.port = mock_type(int32_t);
    }

    if (mask->proxy.username == 1U) {
        snprintf(parameter->proxy.username, sizeof parameter->proxy.username, "%s",
                 mock_type(const char *));
    }

    if (mask->proxy.password == 1U) {
        snprintf(parameter->proxy.password, sizeof parameter->proxy.password, "%s",
                 mock_type(const char *));
    }
#endif // INITIAL_SETTING_APP_PS_STUB

    return mock_type(EsfNetworkManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfNetworkManagerResult __wrap_EsfNetworkManagerUnregisterCallback(EsfNetworkManagerHandle handle)
{
#ifdef INITIAL_SETTING_APP_PS_STUB
    check_expected(handle);
#else  // INITIAL_SETTING_APP_PS_STUB
#endif // INITIAL_SETTING_APP_PS_STUB
    return mock_type(EsfNetworkManagerResult);
}

/*----------------------------------------------------------------------------*/
