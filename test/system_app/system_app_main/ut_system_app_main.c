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
#include <sys/stat.h>
#if defined(__NuttX__)
#include <nuttx/compiler.h>
#endif
#include "evp/sdk_sys.h"
#include "sdk_backdoor.h"

#include "system_manager.h"
#include "network_manager.h"
#include "led_manager.h"
#include "log_manager.h"
#include "clock_manager.h"
#include "clock_manager_setting.h"
#include "sensor_main.h"
#include "power_manager.h"

#include "system_app_common.h"
#include "system_app_main_private.h"

/*----------------------------------------------------------------------------*/
extern bool s_ntp_sync_notify;
extern bool s_ntp_sync_done;

extern RetCode CheckProjectIdAndRegisterToken(void);
extern ToOperation ToOperatingStatus(void);
extern RetCode ExecInitialSettingApp(void);
extern void NetworkManagerCallback(EsfNetworkManagerMode mode, EsfNetworkManagerNotifyInfo info,
                                   void* private_data);
extern void NtpSyncCallback(bool is_sync_success);
extern RetCode ConnectNetwork(TerminationReason* abort_reason);
extern RetCode DisconnectNetwork(void);
extern RetCode StartSyncNtp(TerminationReason* abort_reason);
extern RetCode StopSyncNtp(void);
extern bool SetupDirMount(void);
#if defined(__NuttX__)
extern void* SysAppMain(void* ptr);
extern int system_app_main_for_test(int argc, FAR char* argv[]);
#elif defined(__linux__)
extern TerminationReason SysAppMain(void);
#endif

int ut_test_connect_wait_retry = 0;

#define NETWORK_CONNECT_RETRY_NUM (15)
#define SYSTEM_APP_SW_WDT_ID CONFIG_EXTERNAL_POWER_MANAGER_SW_WDT_ID_2

/*----------------------------------------------------------------------------*/
//
// task_create_delete_Success()
//
/*----------------------------------------------------------------------------*/
static void task_create_Success(void)
{
#if defined(__NuttX__)
    will_return(__wrap_task_create, 888);
#elif defined(__linux__)
    // Check evp_agent_startup
    will_return(__wrap_evp_agent_startup, 0);
#endif
    return;
}
/*----------------------------------------------------------------------------*/
//
// For EsfNetworkManager API
//
/*----------------------------------------------------------------------------*/
static void CheckEsfNetworkManagerSaveParameter(const EsfNetworkManagerParameterMask* mask,
                                                const EsfNetworkManagerParameter* parameter,
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
//
// For EsfClockManager API
//
/*----------------------------------------------------------------------------*/
static void CheckEsfClockManagerSetParams(const EsfClockManagerParams* data,
                                          const EsfClockManagerParamsMask* mask,
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

//
// CheckProjectIdAndRegisterToken()
//

/*----------------------------------------------------------------------------*/
static void CheckProjectIdAndRegisterToken_FullySuccess(void)
{
    // Check project_id malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_PROJECT_ID_MAX_SIZE);

    // Check register_token malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_REGISTER_TOKEN_MAX_SIZE);

    // Check EsfSystemManagerGetProjectId.

    will_return(__wrap_EsfSystemManagerGetProjectId, "unittest_project_id");
    will_return(__wrap_EsfSystemManagerGetProjectId, kEsfSystemManagerResultOk);

    // Check EsfSystemManagerGetRegisterToken.

    will_return(__wrap_EsfSystemManagerGetRegisterToken, "unittest_register_token");
    will_return(__wrap_EsfSystemManagerGetRegisterToken, kEsfSystemManagerResultOk);

    // For free of project_id.

    will_return(mock_free, false); // Not check parameter

    // For free of register_token.

    will_return(mock_free, false); // Not check parameter
}

/*----------------------------------------------------------------------------*/
static void CheckProjectIdAndRegisterToken_EmptyProjectIdAndRegisterToken(void)
{
    // Check project_id malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_PROJECT_ID_MAX_SIZE);

    // Check register_token malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_REGISTER_TOKEN_MAX_SIZE);

    // Check EsfSystemManagerGetProjectId.

    will_return(__wrap_EsfSystemManagerGetProjectId, "");
    will_return(__wrap_EsfSystemManagerGetProjectId, kEsfSystemManagerResultOk);

    // Check EsfSystemManagerGetRegisterToken.

    will_return(__wrap_EsfSystemManagerGetRegisterToken, "");
    will_return(__wrap_EsfSystemManagerGetRegisterToken, kEsfSystemManagerResultOk);

    // For free of project_id.

    will_return(mock_free, false); // Not check parameter

    // For free of register_token.

    will_return(mock_free, false); // Not check parameter
}

/*----------------------------------------------------------------------------*/
static void test_CheckProjectIdAndRegisterToken_FullySuccess(void** state)
{
    RetCode ret;

    CheckProjectIdAndRegisterToken_FullySuccess();

    // Execute test target.

    ret = CheckProjectIdAndRegisterToken();

    // Check return value.

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_CheckProjectIdAndRegisterToken_ProjectIdAllocError(void** state)
{
    RetCode ret;

    // Check project_id malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, false);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_PROJECT_ID_MAX_SIZE);

    // Check register_token malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_REGISTER_TOKEN_MAX_SIZE);

    // For free of register_token.

    will_return(mock_free, false); // Not check parameter

    // Execute test target.

    ret = CheckProjectIdAndRegisterToken();

    // Check return value.

    assert_int_equal(ret, kRetMemoryError);
}

/*----------------------------------------------------------------------------*/
static void test_CheckProjectIdAndRegisterToken_RegisterTokenAllocError(void** state)
{
    RetCode ret;

    // Check project_id malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_PROJECT_ID_MAX_SIZE);

    // Check register_token malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, false);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_REGISTER_TOKEN_MAX_SIZE);

    // For free of project_id.

    will_return(mock_free, false); // Not check parameter

    // Execute test target.

    ret = CheckProjectIdAndRegisterToken();

    // Check return value.

    assert_int_equal(ret, kRetMemoryError);
}

/*----------------------------------------------------------------------------*/
static void test_CheckProjectIdAndRegisterToken_GetProjectIdError(void** state)
{
    RetCode ret;

    // Check project_id malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_PROJECT_ID_MAX_SIZE);

    // Check register_token malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_REGISTER_TOKEN_MAX_SIZE);

    // Check EsfSystemManagerGetProjectId.

    will_return(__wrap_EsfSystemManagerGetProjectId, "unittest_project_id_error");
    will_return(__wrap_EsfSystemManagerGetProjectId, kEsfSystemManagerResultInternalError);

    // For free of project_id.

    will_return(mock_free, false); // Not check parameter

    // For free of register_token.

    will_return(mock_free, false); // Not check parameter

    // Execute test target.

    ret = CheckProjectIdAndRegisterToken();

    // Check return value.

    assert_int_equal(ret, kRetNotFound);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_CheckProjectIdAndRegisterToken_GetRegisterTokenError(void** state)
{
    RetCode ret;

    // Check project_id malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_PROJECT_ID_MAX_SIZE);

    // Check register_token malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_REGISTER_TOKEN_MAX_SIZE);

    // Check EsfSystemManagerGetProjectId.

    will_return(__wrap_EsfSystemManagerGetProjectId, "unittest_project_id");
    will_return(__wrap_EsfSystemManagerGetProjectId, kEsfSystemManagerResultOk);

    // Check EsfSystemManagerGetRegisterToken.

    will_return(__wrap_EsfSystemManagerGetRegisterToken, "unittest_register_token");
    will_return(__wrap_EsfSystemManagerGetRegisterToken, kEsfSystemManagerResultInternalError);

    // For free of project_id.

    will_return(mock_free, false); // Not check parameter

    // For free of register_token.

    will_return(mock_free, false); // Not check parameter

    // Execute test target.

    ret = CheckProjectIdAndRegisterToken();

    // Check return value.

    assert_int_equal(ret, kRetNotFound);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_CheckProjectIdAndRegisterToken_EmptyProjectIdAndRegisterToken(void** state)
{
    RetCode ret;

    CheckProjectIdAndRegisterToken_EmptyProjectIdAndRegisterToken();

    // Execute test target.

    ret = CheckProjectIdAndRegisterToken();

    // Check return value.

    assert_int_equal(ret, kRetNotFound);

    return;
}

/*----------------------------------------------------------------------------*/

//
// ToOperatingStatus()
//

/*----------------------------------------------------------------------------*/
static void ToOperaitingStatus_FullySuccess_ToInitialSetting(void)
{
    // Check EsfSystemManagerGetQrModeTimeoutValue.

    int32_t qr_mode_tmo = 0;
    expect_memory(__wrap_EsfSystemManagerGetQrModeTimeoutValue, data, &qr_mode_tmo,
                  sizeof(int32_t));
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, 0);
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    // Check mqtt_host malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // Check mqtt_port malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // Check EsfSystemManagerGetEvpHubUrl.

    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, "mqtt.my_evp_host.com");
    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, kEsfSystemManagerResultOk);

    // Check EsfSystemManagerGetEvpHubPort.

    will_return(__wrap_EsfSystemManagerGetEvpHubPort, "8883");
    will_return(__wrap_EsfSystemManagerGetEvpHubPort, kEsfSystemManagerResultOk);

    // Set CheckProjectIdAndRegisterToken will fully success.

    CheckProjectIdAndRegisterToken_FullySuccess();

    // For free of mqtt_host.

    will_return(mock_free, false); // Not check parameter

    // For free of mqtt_port.

    will_return(mock_free, false); // Not check parameter
}

/*----------------------------------------------------------------------------*/
static void ToOperatingStatus_FullySuccess_ToOperation(void)
{
    // Check EsfSystemManagerGetQrModeTimeoutValue.

    int32_t qr_mode_tmo = 0;
    expect_memory(__wrap_EsfSystemManagerGetQrModeTimeoutValue, data, &qr_mode_tmo,
                  sizeof(int32_t));
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, 0);
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    // Check mqtt_host malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // Check mqtt_port malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // Check EsfSystemManagerGetEvpHubUrl.

    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, "mqtt.my_evp_host.com");
    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, kEsfSystemManagerResultOk);

    // Check EsfSystemManagerGetEvpHubPort.

    will_return(__wrap_EsfSystemManagerGetEvpHubPort, "8883");
    will_return(__wrap_EsfSystemManagerGetEvpHubPort, kEsfSystemManagerResultOk);

    // Set CheckProjectIdAndRegisterToken will empty project_id and register_token.

    CheckProjectIdAndRegisterToken_EmptyProjectIdAndRegisterToken();

    // For free of mqtt_host.

    will_return(mock_free, false); // Not check parameter

    // For free of mqtt_port.

    will_return(mock_free, false); // Not check parameter
}

/*----------------------------------------------------------------------------*/
static void test_ToOperatingStatus_FullySuccess_ToInitialSetting(void** state)
{
    ToOperation to_ope;

    ToOperaitingStatus_FullySuccess_ToInitialSetting();

    // Execute test target.

    to_ope = ToOperatingStatus();

    // Check return value.

    assert_int_equal(to_ope, ToInitialSetting);
}

/*----------------------------------------------------------------------------*/
static void test_ToOperatingStatus_FullySuccess_ToOperation(void** state)
{
    ToOperation to_ope;

    ToOperatingStatus_FullySuccess_ToOperation();

    // Execute test target.

    to_ope = ToOperatingStatus();

    // Check return value.

    assert_int_equal(to_ope, ToSystem);
}

/*----------------------------------------------------------------------------*/
static void test_ToOperatingStatus_FullySuccess_EmptyMqttHostAndMqttPort(void** state)
{
    ToOperation to_ope;

    // Check EsfSystemManagerGetQrModeTimeoutValue.

    int32_t qr_mode_tmo = 0;
    expect_memory(__wrap_EsfSystemManagerGetQrModeTimeoutValue, data, &qr_mode_tmo,
                  sizeof(int32_t));
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, 0);
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, kEsfSystemManagerResultOk);

#if defined(CONFIG_BOARD_WIFI_SMALL_ES)
    // Check EsfSystemManagerSetQrModeTimeoutValue.

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, -1);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultInternalError);
#endif

    // Check mqtt_host malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // Check mqtt_port malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // Check EsfSystemManagerGetEvpHubUrl.

    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, "");
    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, kEsfSystemManagerResultOk);

    // Check EsfSystemManagerGetEvpHubPort.

    will_return(__wrap_EsfSystemManagerGetEvpHubPort, "");
    will_return(__wrap_EsfSystemManagerGetEvpHubPort, kEsfSystemManagerResultOk);

    // For free of mqtt_host.

    will_return(mock_free, false); // Not check parameter

    // For free of mqtt_port.

    will_return(mock_free, false); // Not check parameter

    // Execute test target.

    to_ope = ToOperatingStatus();

    // Check return value.

    assert_int_equal(to_ope, ToInitialSetting);
}

/*----------------------------------------------------------------------------*/
static void test_ToOperatingStatus_GetMqttPortError(void** state)
{
    ToOperation to_ope;

    // Check EsfSystemManagerGetQrModeTimeoutValue.

    int32_t qr_mode_tmo = 0;
    expect_memory(__wrap_EsfSystemManagerGetQrModeTimeoutValue, data, &qr_mode_tmo,
                  sizeof(int32_t));
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, 0);
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, kEsfSystemManagerResultOk);

#if defined(CONFIG_BOARD_WIFI_SMALL_ES)
    // Check EsfSystemManagerSetQrModeTimeoutValue.

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, -1);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultInternalError);
#endif

    // Check mqtt_host malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // Check mqtt_port malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // Check EsfSystemManagerGetEvpHubUrl.

    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, "mqtt.my_evp_host.com");
    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, kEsfSystemManagerResultOk);

    // Check EsfSystemManagerGetEvpHubPort.

    will_return(__wrap_EsfSystemManagerGetEvpHubPort, "8883");
    will_return(__wrap_EsfSystemManagerGetEvpHubPort, kEsfSystemManagerResultInternalError);

    // For free of mqtt_host.

    will_return(mock_free, false); // Not check parameter

    // For free of mqtt_port.

    will_return(mock_free, false); // Not check parameter

    // Execute test target.

    to_ope = ToOperatingStatus();

    // Check return value.

    assert_int_equal(to_ope, ToInitialSetting);
}

/*----------------------------------------------------------------------------*/
static void test_ToOperatingStatus_GetMqttHostError(void** state)
{
    ToOperation to_ope;

    // Check EsfSystemManagerGetQrModeTimeoutValue.

    int32_t qr_mode_tmo = 0;
    expect_memory(__wrap_EsfSystemManagerGetQrModeTimeoutValue, data, &qr_mode_tmo,
                  sizeof(int32_t));
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, 0);
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, kEsfSystemManagerResultOk);

#if defined(CONFIG_BOARD_WIFI_SMALL_ES)
    // Check EsfSystemManagerSetQrModeTimeoutValue.

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, -1);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultInternalError);
#endif

    // Check mqtt_host malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // Check mqtt_port malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // Check EsfSystemManagerGetEvpHubUrl.

    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, "mqtt.my_evp_host.com");
    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, kEsfSystemManagerResultInternalError);

    // Check EsfSystemManagerGetEvpHubPort.

    will_return(__wrap_EsfSystemManagerGetEvpHubPort, "8883");
    will_return(__wrap_EsfSystemManagerGetEvpHubPort, kEsfSystemManagerResultOk);

    // For free of mqtt_host.

    will_return(mock_free, false); // Not check parameter

    // For free of mqtt_port.

    will_return(mock_free, false); // Not check parameter

    // Execute test target.

    to_ope = ToOperatingStatus();

    // Check return value.

    assert_int_equal(to_ope, ToInitialSetting);
}

/*----------------------------------------------------------------------------*/
static void test_ToOperatingStatus_MqttHostAndMqttPortAllocError(void** state)
{
    ToOperation to_ope;

    // Check EsfSystemManagerGetQrModeTimeoutValue.

    int32_t qr_mode_tmo = 0;
    expect_memory(__wrap_EsfSystemManagerGetQrModeTimeoutValue, data, &qr_mode_tmo,
                  sizeof(int32_t));
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, 0);
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    // Check mqtt_host malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, false);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // Check mqtt_port malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, false);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // Execute test target.

    to_ope = ToOperatingStatus();

    // Check return value.

    assert_int_equal(to_ope, ToSystem);
}

/*----------------------------------------------------------------------------*/
static void test_ToOperatingStatus_FullySuccess_ToInitialSettingQrTimerValid(void** state)
{
    ToOperation to_ope;

    // Check EsfSystemManagerGetQrModeTimeoutValue.

    int32_t qr_mode_tmo = 0;
    expect_memory(__wrap_EsfSystemManagerGetQrModeTimeoutValue, data, &qr_mode_tmo,
                  sizeof(int32_t));
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, 10);
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    // Execute test target.

    to_ope = ToOperatingStatus();

    // Check return value.

    assert_int_equal(to_ope, ToInitialSetting);
}

/*----------------------------------------------------------------------------*/
static void test_ToOperatingStatus_FullySuccess_QrTimeoutValueGetError(void** state)
{
    ToOperation to_ope;

    // Check EsfSystemManagerGetQrModeTimeoutValue.

    int32_t qr_mode_tmo = 0;
    expect_memory(__wrap_EsfSystemManagerGetQrModeTimeoutValue, data, &qr_mode_tmo,
                  sizeof(int32_t));
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, 100);
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, kEsfSystemManagerResultInternalError);

    // Check mqtt_host malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // Check mqtt_port malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // Check EsfSystemManagerGetEvpHubUrl.

    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, "mqtt.my_evp_host.com");
    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, kEsfSystemManagerResultOk);

    // Check EsfSystemManagerGetEvpHubPort.

    will_return(__wrap_EsfSystemManagerGetEvpHubPort, "8883");
    will_return(__wrap_EsfSystemManagerGetEvpHubPort, kEsfSystemManagerResultOk);

    // Set CheckProjectIdAndRegisterToken will empty project_id and register_token.

    CheckProjectIdAndRegisterToken_EmptyProjectIdAndRegisterToken();

    // For free of mqtt_host.

    will_return(mock_free, false); // Not check parameter

    // For free of mqtt_port.

    will_return(mock_free, false); // Not check parameter

    // Execute test target.

    to_ope = ToOperatingStatus();

    // Check return value.

    assert_int_equal(to_ope, ToSystem);
}

/*----------------------------------------------------------------------------*/

//
// ExecInitialSettingApp()
//

/*----------------------------------------------------------------------------*/
static void ExecInitialSettingApp_FullySuccess(void)
{
    // Check task_create.

#if defined(__NuttX__)
    will_return(__wrap_task_create, 999);

    // Check waitpid.

    will_return(__wrap_waitpid, 999);
#endif

#if defined(__linux__)
    will_return(__wrap_initial_setting_app_main, 0);
#endif
}

/*----------------------------------------------------------------------------*/
static void test_ExecInitialSettingApp_FullySuccess(void** state)
{
    RetCode ret = kRetOk;

    ExecInitialSettingApp_FullySuccess();

    // Execute test target.

    ret = ExecInitialSettingApp();

    // Check return value.

    assert_int_equal(ret, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void test_ExecInitialSettingApp_TaskCreateError(void** state)
{
    RetCode ret = kRetOk;

    // Check task_create.

    will_return(__wrap_task_create, -1);

    // Execute test target.

    ret = ExecInitialSettingApp();

    // Check return value.

    assert_int_equal(ret, kRetFailed);
}

/*----------------------------------------------------------------------------*/
static void test_ExecInitialSettingApp_WaitpidError(void** state)
{
    RetCode ret = kRetOk;

    // Check task_create.

    will_return(__wrap_task_create, 999);

    // Check waitpid.

    will_return(__wrap_waitpid, -1);

    // Execute test target.

    ret = ExecInitialSettingApp();

    // Check return value.

    assert_int_equal(ret, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void test_ExecInitialSettingApp_Waitpid0(void** state)
{
    RetCode ret = kRetOk;

    // Check task_create.

    will_return(__wrap_task_create, 999);

    // Check waitpid.

    will_return(__wrap_waitpid, 0);

    // Check waitpid.

    will_return(__wrap_waitpid, 999);

    // Execute test target.

    ret = ExecInitialSettingApp();

    // Check return value.

    assert_int_equal(ret, kRetOk);
}

/*----------------------------------------------------------------------------*/

//
// NetworkManagerCallback
//

/*----------------------------------------------------------------------------*/
static void test_NetworkManagerCallback_FullySuccess(void** state)
{
    int data = -1;

    // Execute test target.

    NetworkManagerCallback(kEsfNetworkManagerModeNormal, kEsfNetworkManagerNotifyInfoConnected,
                           &data);

    // Check value.

    assert_int_equal(data, kEsfNetworkManagerNotifyInfoConnected);
}

/*----------------------------------------------------------------------------*/
static void test_NetworkManagerCallback_NullData(void** state)
{
    int data = -1;

    // Execute test target.

    NetworkManagerCallback(kEsfNetworkManagerModeNormal, kEsfNetworkManagerNotifyInfoConnected,
                           NULL);

    // Check value.

    assert_int_equal(data, -1);
}

/*----------------------------------------------------------------------------*/

//
// NtpSyncCallback
//

/*----------------------------------------------------------------------------*/
static void test_NtpSyncCallback_FullySuccessSync(void** state)
{
    s_ntp_sync_notify = false;
    s_ntp_sync_done = false;

    // Execute test target.

    NtpSyncCallback(true);

    // Check value.

    assert_true(s_ntp_sync_notify);
    assert_true(s_ntp_sync_done);
}

/*----------------------------------------------------------------------------*/
static void test_NtpSyncCallback_FullySuccessCannotSync(void** state)
{
    s_ntp_sync_notify = false;
    s_ntp_sync_done = false;

    // Execute test target.

    NtpSyncCallback(false);

    // Check value.

    assert_true(s_ntp_sync_notify);
    assert_false(s_ntp_sync_done);
}

/*----------------------------------------------------------------------------*/

//
// ConnectNetwork
//

/*----------------------------------------------------------------------------*/
static void ConnectNetwork_FullySuccess_WiFiConnected(EsfNetworkManagerResult ret_netif_kind)
{
    EsfNetworkManagerParameterMask esfnm_mask_expect;
    EsfNetworkManagerParameter esfnm_param_expect;

    memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 0; // WiFi.

    // Check EsfNetworkManagerOpen.

    will_return(__wrap_EsfNetworkManagerOpen, 777);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerRegisterCallback.

    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerLoadParameter(wifi ssid).

    will_return(__wrap_EsfNetworkManagerLoadParameter, "myssid");
    //  will_return(__wrap_EsfNetworkManagerLoadParameter, ret_wifi_ssid);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);
    // Check EsfNetworkManagerSaveParameter(netif kind)

    CheckEsfNetworkManagerSaveParameter(&esfnm_mask_expect, &esfnm_param_expect, ret_netif_kind);

    // Check EsfNetworkManagerStart.

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultStatusAlreadyRunning);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);
}

/*----------------------------------------------------------------------------*/
static void ConnectNetwork_WiFiAbortedByFactoryResetRequest(void)
{
    EsfNetworkManagerParameterMask esfnm_mask_expect;
    EsfNetworkManagerParameter esfnm_param_expect;

    memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 0; // WiFi.

    // Check EsfNetworkManagerOpen.

    will_return(__wrap_EsfNetworkManagerOpen, 777);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerRegisterCallback.

    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerLoadParameter(wifi ssid).

    will_return(__wrap_EsfNetworkManagerLoadParameter, "myssid");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerSaveParameter(netif kind = wifi)

    CheckEsfNetworkManagerSaveParameter(&esfnm_mask_expect, &esfnm_param_expect,
                                        kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerStart.

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoDisconnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, true);

    // Check EsfLedManagerSetLightingPersistence.

    will_return(__wrap_EsfLedManagerSetLightingPersistence, kEsfLedManagerSuccess);

    // Check EsfNetworkManagerStop

    will_return(__wrap_EsfNetworkManagerStop, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerUnregisterCallback

    will_return(__wrap_EsfNetworkManagerUnregisterCallback, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerClose

    will_return(__wrap_EsfNetworkManagerClose, kEsfNetworkManagerResultSuccess);
}

/*----------------------------------------------------------------------------*/
static void ConnectNetwork_NetworkOpenError(void)
{
    // check esfnetworkmanageropen.

    will_return(__wrap_EsfNetworkManagerOpen, 777);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultInternalError);
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_FullySuccess_WiFiConnected(void** state)
{
    RetCode ret;
    TerminationReason reason;

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultSuccess);

    // Execute test target.

    ret = ConnectNetwork(&reason);

    assert_int_equal(ret, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_FullySuceess_EtherConnected(void** state)
{
    RetCode ret;
    TerminationReason reason = UnDefined;
    EsfNetworkManagerParameterMask esfnm_mask_expect;
    EsfNetworkManagerParameter esfnm_param_expect;

    memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

    // Check EsfNetworkManagerOpen.

    will_return(__wrap_EsfNetworkManagerOpen, 777);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerRegisterCallback.

    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerLoadParameter(wifi ssid).

    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerSaveParameter(netif kind)

    CheckEsfNetworkManagerSaveParameter(&esfnm_mask_expect, &esfnm_param_expect,
                                        kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerStart.

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultStatusAlreadyRunning);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Execute test target.

    ret = ConnectNetwork(&reason);

    // Check value.

    assert_int_equal(ret, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_WiFiAbortedByFactoryResetRequest(void** state)
{
    RetCode ret;
    TerminationReason reason = UnDefined;

    ConnectNetwork_WiFiAbortedByFactoryResetRequest();

    // Execute test target.

    ret = ConnectNetwork(&reason);

    // Check value.

    assert_int_equal(ret, kRetAbort);
    assert_int_equal(reason, FactoryResetButtonRequested);
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_WiFiAbortedByRebootRequest(void** state)
{
    RetCode ret;
    TerminationReason reason = UnDefined;
    EsfNetworkManagerParameterMask esfnm_mask_expect;
    EsfNetworkManagerParameter esfnm_param_expect;

    memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 0; // WiFi.

    // Check EsfNetworkManagerOpen.

    will_return(__wrap_EsfNetworkManagerOpen, 777);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerRegisterCallback.

    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerLoadParameter(wifi ssid).

    will_return(__wrap_EsfNetworkManagerLoadParameter, "myssid");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerSaveParameter(netif kind = wifi)

    CheckEsfNetworkManagerSaveParameter(&esfnm_mask_expect, &esfnm_param_expect,
                                        kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerStart.

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoDisconnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, true);

    // Check EsfNetworkManagerStop

    will_return(__wrap_EsfNetworkManagerStop, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerUnregisterCallback

    will_return(__wrap_EsfNetworkManagerUnregisterCallback, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerClose

    will_return(__wrap_EsfNetworkManagerClose, kEsfNetworkManagerResultSuccess);

    // Execute test target.

    ret = ConnectNetwork(&reason);

    // Check value.

    assert_int_equal(ret, kRetAbort);
    assert_int_equal(reason, RebootRequested);
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_EtherAbortedByFactoryResetRequest(void** state)
{
    RetCode ret;
    TerminationReason reason = UnDefined;
    EsfNetworkManagerParameterMask esfnm_mask_expect;
    EsfNetworkManagerParameter esfnm_param_expect;

    memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

    // Check EsfNetworkManagerOpen.

    will_return(__wrap_EsfNetworkManagerOpen, 777);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerRegisterCallback.

    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerLoadParameter(wifi ssid).

    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerSaveParameter(netif kind = ether)

    CheckEsfNetworkManagerSaveParameter(&esfnm_mask_expect, &esfnm_param_expect,
                                        kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerStart.

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoDisconnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, true);

    // Check EsfLedManagerSetLightingPersistence.

    will_return(__wrap_EsfLedManagerSetLightingPersistence, kEsfLedManagerSuccess);

    // Check EsfNetworkManagerStop

    will_return(__wrap_EsfNetworkManagerStop, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerUnregisterCallback

    will_return(__wrap_EsfNetworkManagerUnregisterCallback, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerClose

    will_return(__wrap_EsfNetworkManagerClose, kEsfNetworkManagerResultSuccess);

    // Execute test target.

    ret = ConnectNetwork(&reason);

    // Check value.

    assert_int_equal(ret, kRetAbort);
    assert_int_equal(reason, FactoryResetButtonRequested);
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_EtherAbortedByRebootRequest(void** state)
{
    RetCode ret;
    TerminationReason reason = UnDefined;
    EsfNetworkManagerParameterMask esfnm_mask_expect;
    EsfNetworkManagerParameter esfnm_param_expect;

    memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

    // Check EsfNetworkManagerOpen.

    will_return(__wrap_EsfNetworkManagerOpen, 777);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerRegisterCallback.

    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerLoadParameter(wifi ssid).

    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerSaveParameter(netif kind = ether)

    CheckEsfNetworkManagerSaveParameter(&esfnm_mask_expect, &esfnm_param_expect,
                                        kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerStart.

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoDisconnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, true);

    // Check EsfNetworkManagerStop

    will_return(__wrap_EsfNetworkManagerStop, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerUnregisterCallback

    will_return(__wrap_EsfNetworkManagerUnregisterCallback, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerClose

    will_return(__wrap_EsfNetworkManagerClose, kEsfNetworkManagerResultSuccess);

    // Execute test target.

    ret = ConnectNetwork(&reason);

    // Check value.

    assert_int_equal(ret, kRetAbort);
    assert_int_equal(reason, RebootRequested);
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_WiFiStartErrorEtherStartError(void** state)
{
    RetCode ret;
    TerminationReason reason = UnDefined;
    EsfNetworkManagerParameterMask esfnm_mask_expect;
    EsfNetworkManagerParameter esfnm_param_expect;

    // Check EsfNetworkManagerOpen.

    will_return(__wrap_EsfNetworkManagerOpen, 777);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerRegisterCallback.

    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerLoadParameter(wifi ssid).

    will_return(__wrap_EsfNetworkManagerLoadParameter, "myssid");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerSaveParameter(netif kind = wifi)

    memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 0; // WiFi.

    CheckEsfNetworkManagerSaveParameter(&esfnm_mask_expect, &esfnm_param_expect,
                                        kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerStart(wifi).

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoDisconnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultInternalError);

    // Check EsfNetworkManagerSaveParameter(netif kind = ether)

    memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

    CheckEsfNetworkManagerSaveParameter(&esfnm_mask_expect, &esfnm_param_expect,
                                        kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerStart(ether).

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoDisconnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultInternalError);

    // Check EsfNetworkManagerUnregisterCallback

    will_return(__wrap_EsfNetworkManagerUnregisterCallback, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerClose

    will_return(__wrap_EsfNetworkManagerClose, kEsfNetworkManagerResultSuccess);

    // Execute test target.

    ret = ConnectNetwork(&reason);

    // Check value.

    assert_int_equal(ret, kRetFailed);
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_NetworkCallbackRegisterError(void** state)
{
    RetCode ret;
    TerminationReason reason = UnDefined;

    // Check EsfNetworkManagerOpen.

    will_return(__wrap_EsfNetworkManagerOpen, 777);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerRegisterCallback.

    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultInternalError);

    // Check EsfNetworkManagerClose.

    will_return(__wrap_EsfNetworkManagerClose, kEsfNetworkManagerResultSuccess);

    // Execute test target.

    ret = ConnectNetwork(&reason);

    // Check value.

    assert_int_equal(ret, kRetFailed);
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_NetworkOpenError(void** state)
{
    RetCode ret;
    TerminationReason reason = UnDefined;

    ConnectNetwork_NetworkOpenError();

    // Execute test target.

    ret = ConnectNetwork(&reason);

    // Check value.

    assert_int_equal(ret, kRetFailed);
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_WiFiConnected_EsfNetworkManagerSaveParameter_Error(void** state)
{
    RetCode ret;
    TerminationReason reason;

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultHWIFError);

    // Execute test target.

    ret = ConnectNetwork(&reason);

    assert_int_equal(ret, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_RetryOverStop(void** state)
{
    RetCode ret;
    TerminationReason reason = UnDefined;
    EsfNetworkManagerParameterMask esfnm_mask_expect;
    EsfNetworkManagerParameter esfnm_param_expect;

    memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 0; // WiFi.

    // Check EsfNetworkManagerOpen.

    will_return(__wrap_EsfNetworkManagerOpen, 777);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerRegisterCallback.

    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerLoadParameter(wifi ssid).

    will_return(__wrap_EsfNetworkManagerLoadParameter, "myssid");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerSaveParameter(netif kind = wifi)

    CheckEsfNetworkManagerSaveParameter(&esfnm_mask_expect, &esfnm_param_expect,
                                        kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerStart.

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoDisconnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    for (int i = 0; i <= (NETWORK_CONNECT_RETRY_NUM + 1); i++) {
        if (i > NETWORK_CONNECT_RETRY_NUM) {
            // Check SysAppBtnCheckFactoryResetRequest.

            will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

            // Check EsfNetworkManagerStop.

            will_return(__wrap_EsfNetworkManagerStop, kEsfNetworkManagerResultHWIFError);
            break;
        }
        else {
            // Check SysAppBtnCheckFactoryResetRequest.

            will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

            // Check SysAppBtnCheckRebootRequest.

            will_return(__wrap_SysAppBtnCheckRebootRequest, false);
        }
    }

    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

    // Check EsfNetworkManagerSaveParameter(netif kind = ether)

    CheckEsfNetworkManagerSaveParameter(&esfnm_mask_expect, &esfnm_param_expect,
                                        kEsfNetworkManagerResultHWIFError);

    // Check EsfNetworkManagerStart.

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoDisconnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    for (int i = 0; i <= (NETWORK_CONNECT_RETRY_NUM + 1); i++) {
        if (i > NETWORK_CONNECT_RETRY_NUM) {
            // Check SysAppBtnCheckFactoryResetRequest.

            will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

            // Check EsfNetworkManagerStop.

            will_return(__wrap_EsfNetworkManagerStop, kEsfNetworkManagerResultHWIFError);
            break;
        }
        else {
            // Check SysAppBtnCheckFactoryResetRequest.

            will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

            // Check SysAppBtnCheckRebootRequest.

            will_return(__wrap_SysAppBtnCheckRebootRequest, false);
        }
    }

    // Check EsfNetworkManagerUnregisterCallback

    will_return(__wrap_EsfNetworkManagerUnregisterCallback, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerClose

    will_return(__wrap_EsfNetworkManagerClose, kEsfNetworkManagerResultSuccess);

    // Execute test target.

    ret = ConnectNetwork(&reason);

    // Check value.
    assert_int_equal(ret, kRetFailed);
}

/*----------------------------------------------------------------------------*/
static void test_ConnectNetwork_RetryOverStopLedHold(void** state)
{
    RetCode ret;
    TerminationReason reason = UnDefined;
    EsfNetworkManagerParameterMask esfnm_mask_expect;
    EsfNetworkManagerParameter esfnm_param_expect;

    memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 0; // WiFi.

    // Check EsfNetworkManagerOpen.

    will_return(__wrap_EsfNetworkManagerOpen, 777);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerRegisterCallback.

    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerLoadParameter(wifi ssid).

    will_return(__wrap_EsfNetworkManagerLoadParameter, "myssid");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerSaveParameter(netif kind = wifi)

    CheckEsfNetworkManagerSaveParameter(&esfnm_mask_expect, &esfnm_param_expect,
                                        kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerStart.

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoDisconnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    for (int i = 0; i <= (NETWORK_CONNECT_RETRY_NUM + 1); i++) {
        if (i > NETWORK_CONNECT_RETRY_NUM) {
            // Check SysAppBtnCheckFactoryResetRequest.

            will_return(__wrap_SysAppBtnCheckFactoryResetRequest, true);

            // Check EsfLedManagerSetLightingPersistence.

            will_return(__wrap_EsfLedManagerSetLightingPersistence, kEsfLedManagerSuccess);

            // Check EsfNetworkManagerStop.

            will_return(__wrap_EsfNetworkManagerStop, kEsfNetworkManagerResultSuccess);
            break;
        }
        else {
            // Check SysAppBtnCheckFactoryResetRequest.

            will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

            // Check SysAppBtnCheckRebootRequest.

            will_return(__wrap_SysAppBtnCheckRebootRequest, false);
        }
    }

    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

    // Check EsfNetworkManagerSaveParameter(netif kind = ether)

    CheckEsfNetworkManagerSaveParameter(&esfnm_mask_expect, &esfnm_param_expect,
                                        kEsfNetworkManagerResultHWIFError);

    // Check EsfNetworkManagerStart.

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoDisconnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    for (int i = 0; i <= (NETWORK_CONNECT_RETRY_NUM + 1); i++) {
        if (i > NETWORK_CONNECT_RETRY_NUM) {
            // Check SysAppBtnCheckFactoryResetRequest.

            will_return(__wrap_SysAppBtnCheckFactoryResetRequest, true);

            // Check EsfLedManagerSetLightingPersistence.

            will_return(__wrap_EsfLedManagerSetLightingPersistence, kEsfLedManagerSuccess);

            // Check EsfNetworkManagerStop.

            will_return(__wrap_EsfNetworkManagerStop, kEsfNetworkManagerResultSuccess);
            break;
        }
        else {
            // Check SysAppBtnCheckFactoryResetRequest.

            will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

            // Check SysAppBtnCheckRebootRequest.

            will_return(__wrap_SysAppBtnCheckRebootRequest, false);
        }
    }

    // Check EsfNetworkManagerUnregisterCallback

    will_return(__wrap_EsfNetworkManagerUnregisterCallback, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerClose

    will_return(__wrap_EsfNetworkManagerClose, kEsfNetworkManagerResultSuccess);

    // Execute test target.

    ret = ConnectNetwork(&reason);

    // Check value.
    assert_int_equal(ret, kRetFailed);
}

/*----------------------------------------------------------------------------*/

//
// DisconnectNetwork
//

/*----------------------------------------------------------------------------*/
static void DisconnectNetwork_FullySuccess(void)
{
    // Check EsfNetworkManagerStop.

    will_return(__wrap_EsfNetworkManagerStop, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerUnregisterCallback.

    will_return(__wrap_EsfNetworkManagerUnregisterCallback, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerClose.

    will_return(__wrap_EsfNetworkManagerClose, kEsfNetworkManagerResultSuccess);
}

/*----------------------------------------------------------------------------*/
static void test_DisconnectNetwork_FullySuccess(void** state)
{
    RetCode ret;

    DisconnectNetwork_FullySuccess();

    // Execute test target.

    ret = DisconnectNetwork();

    // Check value.

    assert_int_equal(ret, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void test_DisconnectNetwork_NetworkCloseError(void** state)
{
    RetCode ret;

    // Check EsfNetworkManagerStop.

    will_return(__wrap_EsfNetworkManagerStop, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerUnregisterCallback.

    will_return(__wrap_EsfNetworkManagerUnregisterCallback, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerClose.

    will_return(__wrap_EsfNetworkManagerClose, kEsfNetworkManagerResultInternalError);

    // Execute test target.

    ret = DisconnectNetwork();

    // Check value.

    assert_int_equal(ret, kRetFailed);
}

/*----------------------------------------------------------------------------*/
static void test_DisconnectNetwork_NetworkCallbackUnregisterError(void** state)
{
    RetCode ret;

    // Check EsfNetworkManagerStop.

    will_return(__wrap_EsfNetworkManagerStop, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerUnregisterCallback.

    will_return(__wrap_EsfNetworkManagerUnregisterCallback, kEsfNetworkManagerResultInternalError);

    // Check EsfNetworkManagerClose.

    will_return(__wrap_EsfNetworkManagerClose, kEsfNetworkManagerResultSuccess);

    // Execute test target.

    ret = DisconnectNetwork();

    // Check value.

    assert_int_equal(ret, kRetFailed);
}

/*----------------------------------------------------------------------------*/
static void test_DisconnectNetwork_NetworkStopError(void** state)
{
    RetCode ret;

    // Check EsfNetworkManagerStop.

    will_return(__wrap_EsfNetworkManagerStop, kEsfNetworkManagerResultInternalError);

    // Check EsfNetworkManagerUnregisterCallback.

    will_return(__wrap_EsfNetworkManagerUnregisterCallback, kEsfNetworkManagerResultSuccess);

    // Check EsfNetworkManagerClose.

    will_return(__wrap_EsfNetworkManagerClose, kEsfNetworkManagerResultSuccess);

    // Execute test target.

    ret = DisconnectNetwork();

    // Check value.

    assert_int_equal(ret, kRetFailed);
}

/*----------------------------------------------------------------------------*/

//
// StartSyncNtp
//

/*----------------------------------------------------------------------------*/
static void StartSyncNtp_FullySuccess(void)
{
    EsfClockManagerParams cm_param_expect = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };
    EsfClockManagerParamsMask cm_mask_expect = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    s_ntp_sync_notify = false;
    s_ntp_sync_done = false;

    // Check EsfClockManagerSetParams.

    CheckEsfClockManagerSetParams(&cm_param_expect, &cm_mask_expect, kClockManagerSuccess);

    // Check EsfClockManagerRegisterCbOnNtpSyncComplete.

    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // Check EsfClockManagerStart.

    will_return(__wrap_EsfClockManagerStart, true);
    will_return(__wrap_EsfClockManagerStart, true);
    will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

    // Check EsfClockManagerUnregisterCbOnNtpSyncComplete.

    will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);
}

/*----------------------------------------------------------------------------*/
static void StartSyncNtp_AbortByFactoryReset(void)
{
    EsfClockManagerParams cm_param_expect = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };
    EsfClockManagerParamsMask cm_mask_expect = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    s_ntp_sync_notify = false;
    s_ntp_sync_done = false;

    // Check EsfClockManagerSetParams.

    CheckEsfClockManagerSetParams(&cm_param_expect, &cm_mask_expect, kClockManagerSuccess);

    // Check EsfClockManagerRegisterCbOnNtpSyncComplete.

    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // Check EsfClockManagerStart.

    will_return(__wrap_EsfClockManagerStart, false);
    will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, true);

    // Check EsfClockManagerStop.

    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    // Check EsfClockManagerUnregisterCbOnNtpSyncComplete.

    will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);
}

/*----------------------------------------------------------------------------*/
static void test_StartSyncNtp_FullySuccess(void** state)
{
    RetCode ret;
    TerminationReason reason = UnDefined;

    StartSyncNtp_FullySuccess();

    // Execute test target.

    ret = StartSyncNtp(&reason);

    // Check value.

    assert_int_equal(ret, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void test_StartSyncNtp_AbortByFactoryReset(void** state)
{
    RetCode ret;
    TerminationReason reason = UnDefined;

    StartSyncNtp_AbortByFactoryReset();

    // Execute test target.

    ret = StartSyncNtp(&reason);

    // Check value.

    assert_int_equal(ret, kRetAbort);
    assert_int_equal(reason, FactoryResetButtonRequested);
}

/*----------------------------------------------------------------------------*/
static void test_StartSyncNtp_s_ntp_sync_done(void** state)
{
    RetCode ret;
    TerminationReason reason = UnDefined;
    EsfClockManagerParams cm_param_expect = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };
    EsfClockManagerParamsMask cm_mask_expect = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    s_ntp_sync_notify = true;
    s_ntp_sync_done = false;

    // Check EsfClockManagerSetParams.

    CheckEsfClockManagerSetParams(&cm_param_expect, &cm_mask_expect, kClockManagerSuccess);

    // Check EsfClockManagerRegisterCbOnNtpSyncComplete.

    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // Check EsfClockManagerStart.

    will_return(__wrap_EsfClockManagerStart, false);
    will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

    // Check SysAppBtnCheckFactoryResetRequest.

    //  will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // Check SysAppBtnCheckRebootRequest.

    //  will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check EsfClockManagerStop.

    will_return(__wrap_EsfClockManagerStop, kClockManagerParamError);
    // Check EsfClockManagerStart.

    will_return(__wrap_EsfClockManagerStart, false);
    will_return(__wrap_EsfClockManagerStart, kClockManagerParamError);

    // Check EsfClockManagerUnregisterCbOnNtpSyncComplete.

    will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // Execute test target.

    ret = StartSyncNtp(&reason);

    // Check value.

    assert_int_equal(ret, kRetFailed);
}

/*----------------------------------------------------------------------------*/
static void test_StartSyncNtp_AbortByReboot(void** state)
{
    RetCode ret;
    TerminationReason reason = UnDefined;
    EsfClockManagerParams cm_param_expect = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };
    EsfClockManagerParamsMask cm_mask_expect = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    s_ntp_sync_notify = false;
    s_ntp_sync_done = false;

    // Check EsfClockManagerSetParams.

    CheckEsfClockManagerSetParams(&cm_param_expect, &cm_mask_expect, kClockManagerSuccess);

    // Check EsfClockManagerRegisterCbOnNtpSyncComplete.

    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // Check EsfClockManagerStart.

    will_return(__wrap_EsfClockManagerStart, false);
    will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, true);

    // Check EsfClockManagerStop.

    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    // Check EsfClockManagerUnregisterCbOnNtpSyncComplete.

    will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // Execute test target.

    ret = StartSyncNtp(&reason);

    // Check value.

    assert_int_equal(ret, kRetAbort);
    assert_int_equal(reason, RebootRequested);
}

/*----------------------------------------------------------------------------*/
static void test_StartSyncNtp_NtpSetParamError(void** state)
{
    RetCode ret;
    TerminationReason reason = UnDefined;
    EsfClockManagerParams cm_param_expect = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };
    EsfClockManagerParamsMask cm_mask_expect = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    // Check EsfClockManagerSetParams.

    CheckEsfClockManagerSetParams(&cm_param_expect, &cm_mask_expect, kClockManagerInternalError);

    // Execute test target.

    ret = StartSyncNtp(&reason);

    // Check value.

    assert_int_equal(ret, kRetFailed);
}

/*----------------------------------------------------------------------------*/
static void test_StartSyncNtp_NtpRegisterCallbackError(void** state)
{
    RetCode ret;
    TerminationReason reason = UnDefined;
    EsfClockManagerParams cm_param_expect = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };
    EsfClockManagerParamsMask cm_mask_expect = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    // Check EsfClockManagerSetParams.

    CheckEsfClockManagerSetParams(&cm_param_expect, &cm_mask_expect, kClockManagerSuccess);

    // Check EsfClockManagerRegisterCbOnNtpSyncComplete.

    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerInternalError);

    // Execute test target.

    ret = StartSyncNtp(&reason);

    // Check value.

    assert_int_equal(ret, kRetFailed);
}

/*----------------------------------------------------------------------------*/
static void test_StartSyncNtp_NtpStartError(void** state)
{
    RetCode ret;
    TerminationReason reason = UnDefined;
    EsfClockManagerParams cm_param_expect = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };
    EsfClockManagerParamsMask cm_mask_expect = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    // Check EsfClockManagerSetParams.

    CheckEsfClockManagerSetParams(&cm_param_expect, &cm_mask_expect, kClockManagerSuccess);

    // Check EsfClockManagerRegisterCbOnNtpSyncComplete.

    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // Check EsfClockManagerStart.

    will_return(__wrap_EsfClockManagerStart, false);
    will_return(__wrap_EsfClockManagerStart, kClockManagerInternalError);

    // Check EsfClockManagerUnregisterCbOnNtpSyncComplete.

    will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // Execute test target.

    ret = StartSyncNtp(&reason);

    // Check value.

    assert_int_equal(ret, kRetFailed);
}

/*----------------------------------------------------------------------------*/

//
// StopSyncNtp
//

/*----------------------------------------------------------------------------*/
static void StopSyncNtp_FullySuccess(void)
{
    // Check EsfClockManagerStop.

    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);
}

/*----------------------------------------------------------------------------*/
static void test_StopSyncNtp_FullySuccess(void** state)
{
    RetCode ret;

    StopSyncNtp_FullySuccess();

    // Execute test target.

    ret = StopSyncNtp();

    // Check value.

    assert_int_equal(ret, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void test_StopSyncNtp_NtpStopError(void** state)
{
    RetCode ret;

    // Check EsfClockManagerStop.

    will_return(__wrap_EsfClockManagerStop, kClockManagerInternalError);

    // Execute test target.

    ret = StopSyncNtp();

    // Check value.

    assert_int_equal(ret, kRetFailed);
}

/*----------------------------------------------------------------------------*/

//
// SetupDirMount
//

/*----------------------------------------------------------------------------*/
static void SetupDirMount_AlreadyExists(void)
{
    // Check stat.
#if defined(__NuttX__)
    will_return(__wrap_stat, (int)S_IFDIR);
    will_return(__wrap_stat, 0);
#endif
}

/*----------------------------------------------------------------------------*/
static void SetupDirMount_MountFailedAndExecuteFormatFailed(void)
{
    // Check stat.

    will_return(__wrap_stat, (int)S_IFREG);
    will_return(__wrap_stat, 0);

    // Check mount.

    will_return(__wrap_mount, -1);

    // Check mount(autoformat).

    will_return(__wrap_mount, -1);
}

/*----------------------------------------------------------------------------*/
static void test_SetupDirMount_AlreadyExists(void** state)
{
    bool ret;

    SetupDirMount_AlreadyExists();

    // Execute test target.

    ret = SetupDirMount();

    // Check value.

    assert_true(ret);
}

/*----------------------------------------------------------------------------*/
static void test_SetupDirMount_MountSuccess(void** state)
{
    bool ret;

    // Check stat.
#if defined(__NuttX__)
    will_return(__wrap_stat, (int)S_IFREG);
    will_return(__wrap_stat, 0);

    // Check mount.

    will_return(__wrap_mount, 0);
#endif
    // Execute test target.

    ret = SetupDirMount();

    // Check value.

    assert_true(ret);
}

/*----------------------------------------------------------------------------*/
static void test_SetupDirMount_MountFailedAndExecuteFormat(void** state)
{
    bool ret;

    // Check stat.
#if defined(__NuttX__)
    will_return(__wrap_stat, (int)S_IFREG);
    will_return(__wrap_stat, 0);

    // Check mount.

    will_return(__wrap_mount, -1);

    // Check mount(autoformat).

    will_return(__wrap_mount, 0);

    // Execute test target.
#endif
    ret = SetupDirMount();

    // Check value.

    assert_true(ret);
}

/*----------------------------------------------------------------------------*/
static void test_SetupDirMount_MountFailedAndExecuteFormatFailed(void** state)
{
    bool ret;

    SetupDirMount_MountFailedAndExecuteFormatFailed();

    // Execute test target.

    ret = SetupDirMount();

    // Check value.

    assert_false(ret);
}

/*----------------------------------------------------------------------------*/

//
// SysAppMain
//

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_SysProcessEventError(void** state)
{
    TerminationReason reason = UnDefined;
    struct SYS_client sys_client;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckRebootRequest

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    StartSyncNtp_FullySuccess();

    // Check task_create.
    task_create_Success();

    // Check EVP_Agent_register_sys_client.

    will_return(__wrap_EVP_Agent_register_sys_client, NULL);
    will_return(__wrap_EVP_Agent_register_sys_client, &sys_client);

    // Check SysAppTimerInitialize.

    will_return(__wrap_SysAppTimerInitialize, kRetOk);

    // Check SysAppDcmdInitialize.

    will_return(__wrap_SysAppDcmdInitialize, kRetOk);

    // Check SysAppCfgInitialize.

    will_return(__wrap_SysAppCfgInitialize, kRetOk);

    // Check SysAppStaInitialize.

    will_return(__wrap_SysAppStaInitialize, kRetOk);

    // Check SysAppUdInitialize.

    will_return(__wrap_SysAppUdInitialize, kRetOk);

    // Check SysAppDeployInitialize.

    will_return(__wrap_SysAppDeployInitialize, kRetOk);

    // Check EsfPwrMgrSwWdtStart.

    expect_value(__wrap_EsfPwrMgrSwWdtStart, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStart, kEsfPwrMgrOk);

    // Check EsfPwrMgrSwWdtKeepAlive.

    expect_value(__wrap_EsfPwrMgrSwWdtKeepalive, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtKeepalive, kEsfPwrMgrOk);

    // Check SYS_process_event.

    expect_memory(__wrap_SYS_process_event, c, &sys_client, sizeof(sys_client));
    expect_value(__wrap_SYS_process_event, ms, 1000);
    will_return(__wrap_SYS_process_event, SYS_RESULT_SHOULD_EXIT);

    // Check EsfPwrMgrWdtTerminate.

    // Check EsfPwrMgrSwWdtStop.
    expect_value(__wrap_EsfPwrMgrSwWdtStop, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStop, kEsfPwrMgrOk);

    // Check SysAppDeployFinalize.

    will_return(__wrap_SysAppDeployFinalize, kRetOk);

    // Check SysAppUdFinalize.

    will_return(__wrap_SysAppUdFinalize, kRetOk);

    // Check SysAppStaFinalize.

    will_return(__wrap_SysAppStaFinalize, kRetOk);

    // Check SysAppCfgFinalize.

    will_return(__wrap_SysAppCfgFinalize, kRetOk);

    // Check SysAppDcmdFinalize.

    will_return(__wrap_SysAppDcmdFinalize, kRetOk);

    // Check SysAppTimerFinalize.

    will_return(__wrap_SysAppTimerFinalize, kRetOk);

    // Check EVP_Agent_unregister_sys_client.

    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.

    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);

    // Check task_delete.
#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif
    StopSyncNtp_FullySuccess();

    DisconnectNetwork_FullySuccess();

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif

    assert_int_equal(reason, UnDefined);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_SelfTerminateRequested(void** state)
{
    TerminationReason reason = UnDefined;
    struct SYS_client sys_client;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // ConnectNetwork, fully success.

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckRebootRequest

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // StartSyncNtp, fully success.

    StartSyncNtp_FullySuccess();

    // Check task_create.
    task_create_Success();

    // Check EVP_Agent_register_sys_client.

    will_return(__wrap_EVP_Agent_register_sys_client, &sys_client);

    // Check SysAppTimerInitialize.

    will_return(__wrap_SysAppTimerInitialize, kRetOk);

    // Check SysAppDcmdInitialize.

    will_return(__wrap_SysAppDcmdInitialize, kRetOk);

    // Check SysAppCfgInitialize.

    will_return(__wrap_SysAppCfgInitialize, kRetOk);

    // Check SysAppStaInitialize.

    will_return(__wrap_SysAppStaInitialize, kRetOk);

    // Check SysAppUdInitialize.

    will_return(__wrap_SysAppUdInitialize, kRetOk);

    // Check SysAppDeployInitialize.

    will_return(__wrap_SysAppDeployInitialize, kRetOk);

    // Check EsfPwrMgrSwWdtStart.

    expect_value(__wrap_EsfPwrMgrSwWdtStart, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStart, kEsfPwrMgrOk);

    // Check EsfPwrMgrSwWdtKeepAlive.

    expect_value(__wrap_EsfPwrMgrSwWdtKeepalive, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtKeepalive, kEsfPwrMgrOk);

    // Check SYS_process_event.

    expect_memory(__wrap_SYS_process_event, c, &sys_client, sizeof(sys_client));
    expect_value(__wrap_SYS_process_event, ms, 1000);
    will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

    // Check SysAppDcmdCheckSelfTerminate.

    will_return(__wrap_SysAppDcmdCheckSelfTerminate, RebootRequested);
    will_return(__wrap_SysAppDcmdCheckSelfTerminate, true);

    // Check EsfPwrMgrWdtTerminate.

    // Check EsfPwrMgrSwWdtStop.
    expect_value(__wrap_EsfPwrMgrSwWdtStop, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStop, kEsfPwrMgrOk);

    // Check SysAppDeployFinalize.

    will_return(__wrap_SysAppDeployFinalize, kRetOk);

    // Check SysAppUdFinalize.

    will_return(__wrap_SysAppUdFinalize, kRetOk);

    // Check SysAppStaFinalize.

    will_return(__wrap_SysAppStaFinalize, kRetOk);

    // Check SysAppCfgFinalize.

    will_return(__wrap_SysAppCfgFinalize, kRetOk);

    // Check SysAppDcmdFinalize.

    will_return(__wrap_SysAppDcmdFinalize, kRetOk);

    // Check SysAppTimerStopTimer.

    // Check SysAppTimerFinalize.

    will_return(__wrap_SysAppTimerFinalize, kRetOk);

    // Check EVP_Agent_unregister_sys_client.

    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.

    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);

    // Check task_delete.
#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif
    StopSyncNtp_FullySuccess();

    DisconnectNetwork_FullySuccess();

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_SelfTerminateRequestedFactoryReset(void** state)
{
    TerminationReason reason = UnDefined;
    struct SYS_client sys_client;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // ConnectNetwork, fully success.

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckRebootRequest

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // StartSyncNtp, fully success.

    StartSyncNtp_FullySuccess();

    // Check task_create.
    task_create_Success();

    // Check EVP_Agent_register_sys_client.

    will_return(__wrap_EVP_Agent_register_sys_client, &sys_client);

    // Check SysAppTimerInitialize.

    will_return(__wrap_SysAppTimerInitialize, kRetOk);

    // Check SysAppDcmdInitialize.

    will_return(__wrap_SysAppDcmdInitialize, kRetOk);

    // Check SysAppCfgInitialize.

    will_return(__wrap_SysAppCfgInitialize, kRetOk);

    // Check SysAppStaInitialize.

    will_return(__wrap_SysAppStaInitialize, kRetOk);

    // Check SysAppUdInitialize.

    will_return(__wrap_SysAppUdInitialize, kRetOk);

    // Check SysAppDeployInitialize.

    will_return(__wrap_SysAppDeployInitialize, kRetOk);

    // Check EsfPwrMgrSwWdtStart.

    expect_value(__wrap_EsfPwrMgrSwWdtStart, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStart, kEsfPwrMgrOk);

    // Check EsfPwrMgrSwWdtKeepAlive.

    expect_value(__wrap_EsfPwrMgrSwWdtKeepalive, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtKeepalive, kEsfPwrMgrOk);

    // Check SYS_process_event.

    expect_memory(__wrap_SYS_process_event, c, &sys_client, sizeof(sys_client));
    expect_value(__wrap_SYS_process_event, ms, 1000);
    will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

    // Check SysAppDcmdCheckSelfTerminate.

    will_return(__wrap_SysAppDcmdCheckSelfTerminate, FactoryResetRequested);
    will_return(__wrap_SysAppDcmdCheckSelfTerminate, true);

    // Check EsfPwrMgrWdtTerminate.

    // Check EsfPwrMgrSwWdtStop.
    expect_value(__wrap_EsfPwrMgrSwWdtStop, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStop, kEsfPwrMgrOk);

    // Check SysAppDeployFinalize.

    will_return(__wrap_SysAppDeployFinalize, kRetOk);

    // Check SysAppUdFinalize.

    will_return(__wrap_SysAppUdFinalize, kRetOk);

    // Check SysAppStaFinalize.

    will_return(__wrap_SysAppStaFinalize, kRetOk);

    // Check SysAppCfgFinalize.

    will_return(__wrap_SysAppCfgFinalize, kRetOk);

    // Check SysAppDcmdFinalize.

    will_return(__wrap_SysAppDcmdFinalize, kRetOk);

    // Check SysAppTimerStopTimer.

    // Check SysAppTimerFinalize.

    will_return(__wrap_SysAppTimerFinalize, kRetOk);

    // Check EVP_Agent_unregister_sys_client.

    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.

    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);

    // Check task_delete.
#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif
    StopSyncNtp_FullySuccess();

    // Check EsfLedManagerSetLightingPersistence.
#if defined(__NuttX__)
    will_return(__wrap_EsfLedManagerSetLightingPersistence, kEsfLedManagerSuccess);
#endif
    DisconnectNetwork_FullySuccess();

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_RebootRequested(void** state)
{
    TerminationReason reason = UnDefined;
    struct SYS_client sys_client;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // ConnectNetwork, fully success.

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckRebootRequest

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // StartSyncNtp, fully success.

    StartSyncNtp_FullySuccess();

    // Check task_create.
    task_create_Success();

    // Check EVP_Agent_register_sys_client.

    will_return(__wrap_EVP_Agent_register_sys_client, &sys_client);

    // Check SysAppTimerInitialize.

    will_return(__wrap_SysAppTimerInitialize, kRetOk);

    // Check SysAppDcmdInitialize.

    will_return(__wrap_SysAppDcmdInitialize, kRetOk);

    // Check SysAppCfgInitialize.

    will_return(__wrap_SysAppCfgInitialize, kRetOk);

    // Check SysAppStaInitialize.

    will_return(__wrap_SysAppStaInitialize, kRetOk);

    // Check SysAppUdInitialize.

    will_return(__wrap_SysAppUdInitialize, kRetOk);

    // Check SysAppDeployInitialize.

    will_return(__wrap_SysAppDeployInitialize, kRetOk);

    // Check EsfPwrMgrSwWdtStart.

    expect_value(__wrap_EsfPwrMgrSwWdtStart, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStart, kEsfPwrMgrOk);

    // Check EsfPwrMgrSwWdtKeepAlive.

    expect_value(__wrap_EsfPwrMgrSwWdtKeepalive, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtKeepalive, kEsfPwrMgrOk);

    // Check SYS_process_event.

    expect_memory(__wrap_SYS_process_event, c, &sys_client, sizeof(sys_client));
    expect_value(__wrap_SYS_process_event, ms, 1000);
    will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

    // Check SysAppDcmdCheckSelfTerminate.

    will_return(__wrap_SysAppDcmdCheckSelfTerminate, RebootRequested);
    will_return(__wrap_SysAppDcmdCheckSelfTerminate, false);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, true);

    // Check EsfPwrMgrWdtTerminate.

    // Check EsfPwrMgrSwWdtStop.
    expect_value(__wrap_EsfPwrMgrSwWdtStop, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStop, kEsfPwrMgrOk);

    // Check SysAppDeployFinalize.

    will_return(__wrap_SysAppDeployFinalize, kRetOk);

    // Check SysAppUdFinalize.

    will_return(__wrap_SysAppUdFinalize, kRetOk);

    // Check SysAppStaFinalize.

    will_return(__wrap_SysAppStaFinalize, kRetOk);

    // Check SysAppCfgFinalize.

    will_return(__wrap_SysAppCfgFinalize, kRetOk);

    // Check SysAppDcmdFinalize.

    will_return(__wrap_SysAppDcmdFinalize, kRetOk);

    // Check SysAppTimerStopTimer.

    // Check SysAppTimerFinalize.

    will_return(__wrap_SysAppTimerFinalize, kRetOk);

    // Check EVP_Agent_unregister_sys_client.

    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.

    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);

    // Check task_delete.
#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif
    StopSyncNtp_FullySuccess();

    DisconnectNetwork_FullySuccess();

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_FactoryResetRequested(void** state)
{
    TerminationReason reason = UnDefined;
    struct SYS_client sys_client;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // ConnectNetwork, fully success.

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // StartSyncNtp fully success.

    StartSyncNtp_FullySuccess();

    // Check task_create.
    task_create_Success();

    // Check EVP_Agent_register_sys_client.

    will_return(__wrap_EVP_Agent_register_sys_client, &sys_client);

    // Check SysAppTimerInitialize.

    will_return(__wrap_SysAppTimerInitialize, kRetOk);

    // Check SysAppDcmdInitialize.

    will_return(__wrap_SysAppDcmdInitialize, kRetOk);

    // Check SysAppCfgInitialize.

    will_return(__wrap_SysAppCfgInitialize, kRetOk);

    // Check SysAppStaInitialize.

    will_return(__wrap_SysAppStaInitialize, kRetOk);

    // Check SysAppUdInitialize.

    will_return(__wrap_SysAppUdInitialize, kRetOk);

    // Check SysAppDeployInitialize.

    will_return(__wrap_SysAppDeployInitialize, kRetOk);

    // Check EsfPwrMgrSwWdtStart.

    expect_value(__wrap_EsfPwrMgrSwWdtStart, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStart, kEsfPwrMgrOk);

    // Check EsfPwrMgrSwWdtKeepAlive.

    expect_value(__wrap_EsfPwrMgrSwWdtKeepalive, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtKeepalive, kEsfPwrMgrOk);

    // Check SYS_process_event.

    expect_memory(__wrap_SYS_process_event, c, &sys_client, sizeof(sys_client));
    expect_value(__wrap_SYS_process_event, ms, 1000);
    will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

    // Check SysAppDcmdCheckSelfTerminate.

    will_return(__wrap_SysAppDcmdCheckSelfTerminate, RebootRequested);
    will_return(__wrap_SysAppDcmdCheckSelfTerminate, false);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, true);

    // Check EsfPwrMgrWdtTerminate.

    // Check EsfPwrMgrSwWdtStop.
    expect_value(__wrap_EsfPwrMgrSwWdtStop, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStop, kEsfPwrMgrOk);

    // Check SysAppDeployFinalize.

    will_return(__wrap_SysAppDeployFinalize, kRetOk);

    // Check SysAppUdFinalize.

    will_return(__wrap_SysAppUdFinalize, kRetOk);

    // Check SysAppStaFinalize.

    will_return(__wrap_SysAppStaFinalize, kRetOk);

    // Check SysAppCfgFinalize.

    will_return(__wrap_SysAppCfgFinalize, kRetOk);

    // Check SysAppDcmdFinalize.

    will_return(__wrap_SysAppDcmdFinalize, kRetOk);

    // Check SysAppTimerStopTimer.

    // Check SysAppTimerFinalize.

    will_return(__wrap_SysAppTimerFinalize, kRetOk);

    // Check EVP_Agent_unregister_sys_client.

    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.

    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);

    // Check task_delete.
#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif
    StopSyncNtp_FullySuccess();

    // Check EsfLedManagerSetLightingPersistence.
#if defined(__NuttX__)
    will_return(__wrap_EsfLedManagerSetLightingPersistence, kEsfLedManagerSuccess);
#endif
    DisconnectNetwork_FullySuccess();

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_DeployResetRequested(void** state)
{
    TerminationReason reason = UnDefined;
    struct SYS_client sys_client;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // ConnectNetwork, fully success.

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // StartSyncNtp, fully success.

    StartSyncNtp_FullySuccess();

    // Check task_create.
    task_create_Success();

    // Check EVP_Agent_register_sys_client.

    will_return(__wrap_EVP_Agent_register_sys_client, &sys_client);

    // Check SysAppTimerInitialize.

    will_return(__wrap_SysAppTimerInitialize, kRetOk);

    // Check SysAppDcmdInitialize.

    will_return(__wrap_SysAppDcmdInitialize, kRetOk);

    // Check SysAppCfgInitialize.

    will_return(__wrap_SysAppCfgInitialize, kRetOk);

    // Check SysAppStaInitialize.

    will_return(__wrap_SysAppStaInitialize, kRetOk);

    // Check SysAppUdInitialize.

    will_return(__wrap_SysAppUdInitialize, kRetOk);

    // Check SysAppDeployInitialize.

    will_return(__wrap_SysAppDeployInitialize, kRetOk);

    // Check EsfPwrMgrSwWdtStart.

    expect_value(__wrap_EsfPwrMgrSwWdtStart, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStart, kEsfPwrMgrOk);

    // Loop until retry max.

    {
        for (int cnt = 0; cnt < 32; cnt++) {
            // Check EsfPwrMgrSwWdtKeepAlive.

            expect_value(__wrap_EsfPwrMgrSwWdtKeepalive, id, SYSTEM_APP_SW_WDT_ID);
            will_return(__wrap_EsfPwrMgrSwWdtKeepalive, kEsfPwrMgrOk);

            // Check SYS_process_event.

            expect_memory(__wrap_SYS_process_event, c, &sys_client, sizeof(sys_client));
            expect_value(__wrap_SYS_process_event, ms, 1000);
            will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

            // Check SysAppDcmdCheckSelfTerminate.

            will_return(__wrap_SysAppDcmdCheckSelfTerminate, RebootRequested);
            will_return(__wrap_SysAppDcmdCheckSelfTerminate, false);

            // Check SysAppBtnCheckRebootRequest.

            will_return(__wrap_SysAppBtnCheckRebootRequest, false);

            // Check SysAppBtnCheckFactoryResetRequest.

            will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

            // Check SysAppDeployCheckResetRequest.

            will_return(__wrap_SysAppDeployCheckResetRequest, false);
            will_return(__wrap_SysAppDeployCheckResetRequest, true);

            // Check SysAppStaIsStateQueueEmpty.

            will_return(__wrap_SysAppStaIsStateQueueEmpty, false);
        }
    }

    // Check EsfPwrMgrWdtTerminate.

    // Check EsfPwrMgrSwWdtStop.
    expect_value(__wrap_EsfPwrMgrSwWdtStop, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStop, kEsfPwrMgrOk);

    // Check SysAppDeployFinalize.

    will_return(__wrap_SysAppDeployFinalize, kRetOk);

    // Check SysAppUdFinalize.

    will_return(__wrap_SysAppUdFinalize, kRetOk);

    // Check SysAppStaFinalize.

    will_return(__wrap_SysAppStaFinalize, kRetOk);

    // Check SysAppCfgFinalize.

    will_return(__wrap_SysAppCfgFinalize, kRetOk);

    // Check SysAppDcmdFinalize.

    will_return(__wrap_SysAppDcmdFinalize, kRetOk);

    // Check SysAppTimerFinalize.

    will_return(__wrap_SysAppTimerFinalize, kRetOk);

    // Check EVP_Agent_unregister_sys_client.

    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.

    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);

    // Check task_delete.
#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif
    StopSyncNtp_FullySuccess();

    DisconnectNetwork_FullySuccess();

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.
#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif
    // Check value.

    assert_int_equal(reason, RebootRequested);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_DeployFactoryResetRequested(void** state)
{
    TerminationReason reason = UnDefined;
    struct SYS_client sys_client;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // ConnectNetwork, fully success.

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // StartSyncNtp, fully success.

    StartSyncNtp_FullySuccess();

    task_create_Success();

    // Check EVP_Agent_register_sys_client.

    will_return(__wrap_EVP_Agent_register_sys_client, &sys_client);

    // Check SysAppTimerInitialize.

    will_return(__wrap_SysAppTimerInitialize, kRetOk);

    // Check SysAppDcmdInitialize.

    will_return(__wrap_SysAppDcmdInitialize, kRetOk);

    // Check SysAppCfgInitialize.

    will_return(__wrap_SysAppCfgInitialize, kRetOk);

    // Check SysAppStaInitialize.

    will_return(__wrap_SysAppStaInitialize, kRetOk);

    // Check SysAppUdInitialize.

    will_return(__wrap_SysAppUdInitialize, kRetOk);

    // Check SysAppDeployInitialize.

    will_return(__wrap_SysAppDeployInitialize, kRetOk);

    // Check EsfPwrMgrSwWdtStart.

    expect_value(__wrap_EsfPwrMgrSwWdtStart, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStart, kEsfPwrMgrOk);

    // Loop until retry max.

    {
        for (int cnt = 0; cnt < 32; cnt++) {
            // Check EsfPwrMgrSwWdtKeepAlive.

            expect_value(__wrap_EsfPwrMgrSwWdtKeepalive, id, SYSTEM_APP_SW_WDT_ID);
            will_return(__wrap_EsfPwrMgrSwWdtKeepalive, kEsfPwrMgrOk);

            // Check SYS_process_event.

            expect_memory(__wrap_SYS_process_event, c, &sys_client, sizeof(sys_client));
            expect_value(__wrap_SYS_process_event, ms, 1000);
            will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

            // Check SysAppDcmdCheckSelfTerminate.

            will_return(__wrap_SysAppDcmdCheckSelfTerminate, RebootRequested);
            will_return(__wrap_SysAppDcmdCheckSelfTerminate, false);

            // Check SysAppBtnCheckRebootRequest.

            will_return(__wrap_SysAppBtnCheckRebootRequest, false);

            // Check SysAppBtnCheckFactoryResetRequest.

            will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

            // Check SysAppDeployCheckResetRequest.

            will_return(__wrap_SysAppDeployCheckResetRequest, true);
            will_return(__wrap_SysAppDeployCheckResetRequest, true);

            // Check SysAppStaIsStateQueueEmpty.

            will_return(__wrap_SysAppStaIsStateQueueEmpty, false);
        }
    }

    // Check EsfPwrMgrWdtTerminate.

    // Check EsfPwrMgrSwWdtStop.
    expect_value(__wrap_EsfPwrMgrSwWdtStop, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStop, kEsfPwrMgrOk);

    // Check SysAppDeployFinalize.

    will_return(__wrap_SysAppDeployFinalize, kRetOk);

    // Check SysAppUdFinalize.

    will_return(__wrap_SysAppUdFinalize, kRetOk);

    // Check SysAppStaFinalize.

    will_return(__wrap_SysAppStaFinalize, kRetOk);

    // Check SysAppCfgFinalize.

    will_return(__wrap_SysAppCfgFinalize, kRetOk);

    // Check SysAppDcmdFinalize.

    will_return(__wrap_SysAppDcmdFinalize, kRetOk);

    // Check SysAppTimerFinalize.

    will_return(__wrap_SysAppTimerFinalize, kRetOk);

    // Check EVP_Agent_unregister_sys_client.

    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.

    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);

    // Check task_delete.
#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif
    StopSyncNtp_FullySuccess();

    // Check EsfLedManagerSetLightingPersistence.
#if defined(__NuttX__)
    will_return(__wrap_EsfLedManagerSetLightingPersistence, kEsfLedManagerSuccess);
#endif
    DisconnectNetwork_FullySuccess();

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif

    // Check value.

    assert_int_equal(reason, FactoryResetDeployRequested);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_DeployResetRequestedStateQueueEmpty(void** state)
{
    TerminationReason reason = UnDefined;
    struct SYS_client sys_client;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // ConnectNetwork, fully success.

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // StartSyncNtp, fully success.

    StartSyncNtp_FullySuccess();

    // Check task_create.
    task_create_Success();

    // Check EVP_Agent_register_sys_client.

    will_return(__wrap_EVP_Agent_register_sys_client, &sys_client);

    // Check SysAppTimerInitialize.

    will_return(__wrap_SysAppTimerInitialize, kRetOk);

    // Check SysAppDcmdInitialize.

    will_return(__wrap_SysAppDcmdInitialize, kRetOk);

    // Check SysAppCfgInitialize.

    will_return(__wrap_SysAppCfgInitialize, kRetOk);

    // Check SysAppStaInitialize.

    will_return(__wrap_SysAppStaInitialize, kRetOk);

    // Check SysAppUdInitialize.

    will_return(__wrap_SysAppUdInitialize, kRetOk);

    // Check SysAppDeployInitialize.

    will_return(__wrap_SysAppDeployInitialize, kRetOk);

    // Check EsfPwrMgrSwWdtStart.

    expect_value(__wrap_EsfPwrMgrSwWdtStart, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStart, kEsfPwrMgrOk);

    // 1st loop.

    {
        // Check EsfPwrMgrSwWdtKeepAlive.

        expect_value(__wrap_EsfPwrMgrSwWdtKeepalive, id, SYSTEM_APP_SW_WDT_ID);
        will_return(__wrap_EsfPwrMgrSwWdtKeepalive, kEsfPwrMgrOk);

        // Check SYS_process_event.

        expect_memory(__wrap_SYS_process_event, c, &sys_client, sizeof(sys_client));
        expect_value(__wrap_SYS_process_event, ms, 1000);
        will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

        // Check SysAppDcmdCheckSelfTerminate.

        will_return(__wrap_SysAppDcmdCheckSelfTerminate, RebootRequested);
        will_return(__wrap_SysAppDcmdCheckSelfTerminate, false);

        // Check SysAppBtnCheckRebootRequest.

        will_return(__wrap_SysAppBtnCheckRebootRequest, false);

        // Check SysAppBtnCheckFactoryResetRequest.

        will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

        // Check SysAppDeployCheckResetRequest.

        will_return(__wrap_SysAppDeployCheckResetRequest, false);
        will_return(__wrap_SysAppDeployCheckResetRequest, true);

        // Check SysAppStaIsStateQueueEmpty.

        will_return(__wrap_SysAppStaIsStateQueueEmpty, true);
    }

    // Loop until deploy-reboot retry max.

    {
        for (int cnt = 0; cnt < 32; cnt++) {
            // Check EsfPwrMgrSwWdtKeepAlive.

            expect_value(__wrap_EsfPwrMgrSwWdtKeepalive, id, SYSTEM_APP_SW_WDT_ID);
            will_return(__wrap_EsfPwrMgrSwWdtKeepalive, kEsfPwrMgrOk);

            // Check SYS_process_event.

            expect_memory(__wrap_SYS_process_event, c, &sys_client, sizeof(sys_client));
            expect_value(__wrap_SYS_process_event, ms, 1000);
            will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

            // Check SysAppDcmdCheckSelfTerminate.

            will_return(__wrap_SysAppDcmdCheckSelfTerminate, RebootRequested);
            will_return(__wrap_SysAppDcmdCheckSelfTerminate, false);

            // Check SysAppBtnCheckRebootRequest.

            will_return(__wrap_SysAppBtnCheckRebootRequest, false);

            // Check SysAppBtnCheckFactoryResetRequest.

            will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

            // Check SysAppDeployCheckResetRequest.

            will_return(__wrap_SysAppDeployCheckResetRequest, false);
            will_return(__wrap_SysAppDeployCheckResetRequest, true);
        }
    }

    // Check EsfPwrMgrWdtTerminate.

    // Check EsfPwrMgrSwWdtStop.
    expect_value(__wrap_EsfPwrMgrSwWdtStop, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStop, kEsfPwrMgrOk);

    // Check SysAppDeployFinalize.

    will_return(__wrap_SysAppDeployFinalize, kRetOk);

    // Check SysAppUdFinalize.

    will_return(__wrap_SysAppUdFinalize, kRetOk);

    // Check SysAppStaFinalize.

    will_return(__wrap_SysAppStaFinalize, kRetOk);

    // Check SysAppCfgFinalize.

    will_return(__wrap_SysAppCfgFinalize, kRetOk);

    // Check SysAppDcmdFinalize.

    will_return(__wrap_SysAppDcmdFinalize, kRetOk);

    // Check SysAppTimerFinalize.

    will_return(__wrap_SysAppTimerFinalize, kRetOk);

    // Check EVP_Agent_unregister_sys_client.

    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.

    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);

    // Check task_delete.
#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif
    StopSyncNtp_FullySuccess();

    DisconnectNetwork_FullySuccess();

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif
    // Check value.

    assert_int_equal(reason, RebootRequested);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_DeployResetRequestedStateQueueEmptyFactoryReset(void** state)
{
    TerminationReason reason = UnDefined;
    struct SYS_client sys_client;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // ConnectNetwork, fully success.

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // StartSyncNtp, fully success.

    StartSyncNtp_FullySuccess();

    // Check task_create.
    task_create_Success();

    // Check EVP_Agent_register_sys_client.

    will_return(__wrap_EVP_Agent_register_sys_client, &sys_client);

    // Check SysAppTimerInitialize.

    will_return(__wrap_SysAppTimerInitialize, kRetOk);

    // Check SysAppDcmdInitialize.

    will_return(__wrap_SysAppDcmdInitialize, kRetOk);

    // Check SysAppCfgInitialize.

    will_return(__wrap_SysAppCfgInitialize, kRetOk);

    // Check SysAppStaInitialize.

    will_return(__wrap_SysAppStaInitialize, kRetOk);

    // Check SysAppUdInitialize.

    will_return(__wrap_SysAppUdInitialize, kRetOk);

    // Check SysAppDeployInitialize.

    will_return(__wrap_SysAppDeployInitialize, kRetOk);

    // Check EsfPwrMgrSwWdtStart.

    expect_value(__wrap_EsfPwrMgrSwWdtStart, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStart, kEsfPwrMgrOk);

    // 1st loop.

    {
        // Check EsfPwrMgrSwWdtKeepAlive.

        expect_value(__wrap_EsfPwrMgrSwWdtKeepalive, id, SYSTEM_APP_SW_WDT_ID);
        will_return(__wrap_EsfPwrMgrSwWdtKeepalive, kEsfPwrMgrOk);

        // Check SYS_process_event.

        expect_memory(__wrap_SYS_process_event, c, &sys_client, sizeof(sys_client));
        expect_value(__wrap_SYS_process_event, ms, 1000);
        will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

        // Check SysAppDcmdCheckSelfTerminate.

        will_return(__wrap_SysAppDcmdCheckSelfTerminate, RebootRequested);
        will_return(__wrap_SysAppDcmdCheckSelfTerminate, false);

        // Check SysAppBtnCheckRebootRequest.

        will_return(__wrap_SysAppBtnCheckRebootRequest, false);

        // Check SysAppBtnCheckFactoryResetRequest.

        will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

        // Check SysAppDeployCheckResetRequest.

        will_return(__wrap_SysAppDeployCheckResetRequest, false);
        will_return(__wrap_SysAppDeployCheckResetRequest, true);

        // Check SysAppStaIsStateQueueEmpty.

        will_return(__wrap_SysAppStaIsStateQueueEmpty, true);
    }

    // Loop until deploy-reboot retry max.

    {
        for (int cnt = 0; cnt < 32; cnt++) {
            // Check EsfPwrMgrSwWdtKeepAlive.

            expect_value(__wrap_EsfPwrMgrSwWdtKeepalive, id, SYSTEM_APP_SW_WDT_ID);
            will_return(__wrap_EsfPwrMgrSwWdtKeepalive, kEsfPwrMgrOk);

            // Check SYS_process_event.

            expect_memory(__wrap_SYS_process_event, c, &sys_client, sizeof(sys_client));
            expect_value(__wrap_SYS_process_event, ms, 1000);
            will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

            // Check SysAppDcmdCheckSelfTerminate.

            will_return(__wrap_SysAppDcmdCheckSelfTerminate, RebootRequested);
            will_return(__wrap_SysAppDcmdCheckSelfTerminate, false);

            // Check SysAppBtnCheckRebootRequest.

            will_return(__wrap_SysAppBtnCheckRebootRequest, false);

            // Check SysAppBtnCheckFactoryResetRequest.

            will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

            // Check SysAppDeployCheckResetRequest.

            will_return(__wrap_SysAppDeployCheckResetRequest, true);
            will_return(__wrap_SysAppDeployCheckResetRequest, true);
        }
    }

    // Check EsfPwrMgrWdtTerminate.

    // Check EsfPwrMgrSwWdtStop.
    expect_value(__wrap_EsfPwrMgrSwWdtStop, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStop, kEsfPwrMgrOk);

    // Check SysAppDeployFinalize.

    will_return(__wrap_SysAppDeployFinalize, kRetOk);

    // Check SysAppUdFinalize.

    will_return(__wrap_SysAppUdFinalize, kRetOk);

    // Check SysAppStaFinalize.

    will_return(__wrap_SysAppStaFinalize, kRetOk);

    // Check SysAppCfgFinalize.

    will_return(__wrap_SysAppCfgFinalize, kRetOk);

    // Check SysAppDcmdFinalize.

    will_return(__wrap_SysAppDcmdFinalize, kRetOk);

    // Check SysAppTimerFinalize.

    will_return(__wrap_SysAppTimerFinalize, kRetOk);

    // Check EVP_Agent_unregister_sys_client.

    will_return(__wrap_EVP_Agent_unregister_sys_client, 1);

    // Check EsfLogManagerDeinit.

    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);

    // Check task_delete.
#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif
    StopSyncNtp_FullySuccess();

    // Check EsfLedManagerSetLightingPersistence.
#if defined(__NuttX__)
    will_return(__wrap_EsfLedManagerSetLightingPersistence, kEsfLedManagerSuccess);
#endif
    DisconnectNetwork_FullySuccess();

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif

    // Check value.

    assert_int_equal(reason, FactoryResetDeployRequested);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_SensorInitError(void** state)
{
    TerminationReason reason = UnDefined;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorFail);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_ConnectNetworkAborted(void** state)
{
    TerminationReason reason = UnDefined;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    ConnectNetwork_WiFiAbortedByFactoryResetRequest();

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_ConnectNetworkRetry(void** state)
{
    TerminationReason reason = UnDefined;
    struct SYS_client sys_client;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // ConnectNetwork, open error.

    ConnectNetwork_NetworkOpenError();

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // ConnectNetwork, fully success.

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // StartSyncNtp, fully success.

    StartSyncNtp_FullySuccess();

    // Check task_create.
    task_create_Success();

    // Check EVP_Agent_register_sys_client.

    will_return(__wrap_EVP_Agent_register_sys_client, &sys_client);

    // Check SysAppTimerInitialize.

    will_return(__wrap_SysAppTimerInitialize, kRetOk);

    // Check SysAppDcmdInitialize.

    will_return(__wrap_SysAppDcmdInitialize, kRetOk);

    // Check SysAppCfgInitialize.

    will_return(__wrap_SysAppCfgInitialize, kRetOk);

    // Check SysAppStaInitialize.

    will_return(__wrap_SysAppStaInitialize, kRetOk);

    // Check SysAppUdInitialize.

    will_return(__wrap_SysAppUdInitialize, kRetOk);

    // Check SysAppDeployInitialize.

    will_return(__wrap_SysAppDeployInitialize, kRetOk);

    // Check EsfPwrMgrSwWdtStart.

    expect_value(__wrap_EsfPwrMgrSwWdtStart, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStart, kEsfPwrMgrOk);

    // Check EsfPwrMgrSwWdtKeepAlive.

    expect_value(__wrap_EsfPwrMgrSwWdtKeepalive, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtKeepalive, kEsfPwrMgrOk);

    // Check SYS_process_event.

    expect_memory(__wrap_SYS_process_event, c, &sys_client, sizeof(sys_client));
    expect_value(__wrap_SYS_process_event, ms, 1000);
    will_return(__wrap_SYS_process_event, SYS_RESULT_SHOULD_EXIT);

    // Check EsfPwrMgrWdtTerminate.

    // Check EsfPwrMgrSwWdtStop.
    expect_value(__wrap_EsfPwrMgrSwWdtStop, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStop, kEsfPwrMgrOk);

    // Check SysAppDeployFinalize.

    will_return(__wrap_SysAppDeployFinalize, kRetOk);

    // Check SysAppUdFinalize.

    will_return(__wrap_SysAppUdFinalize, kRetOk);

    // Check SysAppStaFinalize.

    will_return(__wrap_SysAppStaFinalize, kRetOk);

    // Check SysAppCfgFinalize.

    will_return(__wrap_SysAppCfgFinalize, kRetOk);

    // Check SysAppDcmdFinalize.

    will_return(__wrap_SysAppDcmdFinalize, kRetOk);

    // Check SysAppTimerFinalize.

    will_return(__wrap_SysAppTimerFinalize, kRetOk);

    // Check EVP_Agent_unregister_sys_client.

    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.

    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);

    // Check task_delete.
#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif
    StopSyncNtp_FullySuccess();

    DisconnectNetwork_FullySuccess();

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_ConnectNetworkError_RebootRequest(void** state)
{
    TerminationReason reason = UnDefined;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // ConnectNetwork, open error.

    ConnectNetwork_NetworkOpenError();

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, true);

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif

    assert_int_equal(reason, RebootRequested);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_ConnectNetworkError_FactoryResetRequest(void** state)
{
    TerminationReason reason = UnDefined;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // ConnectNetwork, open error.

    ConnectNetwork_NetworkOpenError();

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, true);

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif

    assert_int_equal(reason, FactoryResetButtonRequested);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_NtpSyncError(void** state)
{
    TerminationReason reason = UnDefined;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // ConnectNetwork, fully success.

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // StartSyncNtp, will be aborted.

    StartSyncNtp_AbortByFactoryReset();

    // Check EsfLedManagerSetLightingPersistence.
#if defined(__NuttX__)
    will_return(__wrap_EsfLedManagerSetLightingPersistence, kEsfLedManagerSuccess);
#endif
    DisconnectNetwork_FullySuccess();

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif

    // Check value.

    assert_int_equal(reason, FactoryResetButtonRequested);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_EvpAgentTaskCreateError(void** state)
{
    TerminationReason reason = UnDefined;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // ConnectNetwork, fully success.

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // StartSyncNtp, fully success.

    StartSyncNtp_FullySuccess();

    // Check task_create.

    will_return(__wrap_task_create, -1);

    StopSyncNtp_FullySuccess();

    DisconnectNetwork_FullySuccess();

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif
    // Check value.

    assert_int_equal(reason, UnDefined);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_SysAppTimerInitializeError(void** state)
{
    TerminationReason reason = UnDefined;
    struct SYS_client sys_client;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // ConnectNetwork, fully success.

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // StartSyncNtp, fully success.

    StartSyncNtp_FullySuccess();

    // Check task_create.
    task_create_Success();

    // Check EVP_Agent_register_sys_client.

    will_return(__wrap_EVP_Agent_register_sys_client, &sys_client);

    // Check SysAppTimerInitialize.

    will_return(__wrap_SysAppTimerInitialize, kRetFailed);

    // Check EVP_Agent_unregister_sys_client.

    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.

    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);

    // Check task_delete.
#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif
    StopSyncNtp_FullySuccess();

    DisconnectNetwork_FullySuccess();

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif

    // Check value.

    assert_int_equal(reason, UnDefined);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_SysAppDcmdInitializeError(void** state)
{
    TerminationReason reason = UnDefined;
    struct SYS_client sys_client;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // ConnectNetwork, fully success.

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // StartSyncNtp, fully success.

    StartSyncNtp_FullySuccess();

    // Check task_create.
    task_create_Success();

    // Check EVP_Agent_register_sys_client.

    will_return(__wrap_EVP_Agent_register_sys_client, &sys_client);

    // Check SysAppTimerInitialize.

    will_return(__wrap_SysAppTimerInitialize, kRetOk);

    // Check SysAppDcmdInitialize.

    will_return(__wrap_SysAppDcmdInitialize, kRetFailed);

    // Check SysAppTimerFinalize.

    will_return(__wrap_SysAppTimerFinalize, kRetOk);

    // Check EVP_Agent_unregister_sys_client.

    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.

    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);

    // Check task_delete.
#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif
    StopSyncNtp_FullySuccess();

    DisconnectNetwork_FullySuccess();

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif

    // Check value.

    assert_int_equal(reason, UnDefined);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_SysAppCfgInitializeError(void** state)
{
    TerminationReason reason = UnDefined;
    struct SYS_client sys_client;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // ConnectNetwork, fully success.

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // StartSyncNtp, fully success.

    StartSyncNtp_FullySuccess();

    // Check task_create.
    task_create_Success();

    // Check EVP_Agent_register_sys_client.

    will_return(__wrap_EVP_Agent_register_sys_client, &sys_client);

    // Check SysAppTimerInitialize.

    will_return(__wrap_SysAppTimerInitialize, kRetOk);

    // Check SysAppDcmdInitialize.

    will_return(__wrap_SysAppDcmdInitialize, kRetOk);

    // Check SysAppCfgInitialize.

    will_return(__wrap_SysAppCfgInitialize, kRetFailed);

    // Check SysAppDcmdFinalize.

    will_return(__wrap_SysAppDcmdFinalize, kRetOk);

    // Check SysAppTimerFinalize.

    will_return(__wrap_SysAppTimerFinalize, kRetOk);

    // Check EVP_Agent_unregister_sys_client.

    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.

    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);

    // Check task_delete.
#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif
    StopSyncNtp_FullySuccess();

    DisconnectNetwork_FullySuccess();

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif

    // Check value.

    assert_int_equal(reason, UnDefined);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_SysAppStaInitializeError(void** state)
{
    TerminationReason reason = UnDefined;
    struct SYS_client sys_client;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // ConnectNetwork, fully success.

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // StartSyncNtp, fully success.

    StartSyncNtp_FullySuccess();

    // Check task_create.
    task_create_Success();

    // Check EVP_Agent_register_sys_client.

    will_return(__wrap_EVP_Agent_register_sys_client, &sys_client);

    // Check SysAppTimerInitialize.

    will_return(__wrap_SysAppTimerInitialize, kRetOk);

    // Check SysAppDcmdInitialize.

    will_return(__wrap_SysAppDcmdInitialize, kRetOk);

    // Check SysAppCfgInitialize.

    will_return(__wrap_SysAppCfgInitialize, kRetOk);

    // Check SysAppStaInitialize.

    will_return(__wrap_SysAppStaInitialize, kRetFailed);

    // Check SysAppCfgFinalize.

    will_return(__wrap_SysAppCfgFinalize, kRetOk);

    // Check SysAppDcmdFinalize.

    will_return(__wrap_SysAppDcmdFinalize, kRetOk);

    // Check SysAppTimerFinalize.

    will_return(__wrap_SysAppTimerFinalize, kRetOk);

    // Check EVP_Agent_unregister_sys_client.

    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.

    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);

    // Check task_delete.
#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif
    StopSyncNtp_FullySuccess();

    DisconnectNetwork_FullySuccess();

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif

    // Check value.

    assert_int_equal(reason, UnDefined);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_SysAppUdInitializeError(void** state)
{
    TerminationReason reason = UnDefined;
    struct SYS_client sys_client;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // ConnectNetwork, fully success.

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // StartSyncNtp, fully success.

    StartSyncNtp_FullySuccess();

    // Check task_create.
    task_create_Success();

    // Check EVP_Agent_register_sys_client.

    will_return(__wrap_EVP_Agent_register_sys_client, &sys_client);

    // Check SysAppTimerInitialize.

    will_return(__wrap_SysAppTimerInitialize, kRetOk);

    // Check SysAppDcmdInitialize.

    will_return(__wrap_SysAppDcmdInitialize, kRetOk);

    // Check SysAppCfgInitialize.

    will_return(__wrap_SysAppCfgInitialize, kRetOk);

    // Check SysAppStaInitialize.

    will_return(__wrap_SysAppStaInitialize, kRetOk);

    // Check SysAppUdInitialize.

    will_return(__wrap_SysAppUdInitialize, kRetFailed);

    // Check SysAppStaFinalize.

    will_return(__wrap_SysAppStaFinalize, kRetOk);

    // Check SysAppCfgFinalize.

    will_return(__wrap_SysAppCfgFinalize, kRetOk);

    // Check SysAppDcmdFinalize.

    will_return(__wrap_SysAppDcmdFinalize, kRetOk);

    // Check SysAppTimerFinalize.

    will_return(__wrap_SysAppTimerFinalize, kRetOk);

    // Check EVP_Agent_unregister_sys_client.

    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.

    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);

    // Check task_delete.
#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif
    StopSyncNtp_FullySuccess();

    DisconnectNetwork_FullySuccess();

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif

    assert_int_equal(reason, UnDefined);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_SysAppDeployInitializeError(void** state)
{
    TerminationReason reason = UnDefined;
    struct SYS_client sys_client;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // ConnectNetwork, fully success.

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // StartSyncNtp, fully success.

    StartSyncNtp_FullySuccess();

    // Check task_create.
    task_create_Success();

    // Check EVP_Agent_register_sys_client.

    will_return(__wrap_EVP_Agent_register_sys_client, &sys_client);

    // Check SysAppTimerInitialize.

    will_return(__wrap_SysAppTimerInitialize, kRetOk);

    // Check SysAppDcmdInitialize.

    will_return(__wrap_SysAppDcmdInitialize, kRetOk);

    // Check SysAppCfgInitialize.

    will_return(__wrap_SysAppCfgInitialize, kRetOk);

    // Check SysAppStaInitialize.

    will_return(__wrap_SysAppStaInitialize, kRetOk);

    // Check SysAppUdInitialize.

    will_return(__wrap_SysAppUdInitialize, kRetOk);

    // Check SysAppDeployInitialize.

    will_return(__wrap_SysAppDeployInitialize, kRetFailed);

    // Check SysAppUdFinalize.

    will_return(__wrap_SysAppUdFinalize, kRetOk);

    // Check SysAppStaFinalize.

    will_return(__wrap_SysAppStaFinalize, kRetOk);

    // Check SysAppCfgFinalize.

    will_return(__wrap_SysAppCfgFinalize, kRetOk);

    // Check SysAppDcmdFinalize.

    will_return(__wrap_SysAppDcmdFinalize, kRetOk);

    // Check SysAppTimerFinalize.

    will_return(__wrap_SysAppTimerFinalize, kRetOk);

    // Check EVP_Agent_unregister_sys_client.

    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.

    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);

    // Check task_delete.
#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif
    StopSyncNtp_FullySuccess();

    DisconnectNetwork_FullySuccess();

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif

    // Check value.

    assert_int_equal(reason, UnDefined);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_EsfPwrMgrSwWdtStartError(void** state)
{
    TerminationReason reason = UnDefined;
    struct SYS_client sys_client;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // ConnectNetwork, fully success.

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // StartSyncNtp, fully success.

    StartSyncNtp_FullySuccess();

    // Check task_create.
    task_create_Success();

    // Check EVP_Agent_register_sys_client.

    will_return(__wrap_EVP_Agent_register_sys_client, &sys_client);

    // Check SysAppTimerInitialize.

    will_return(__wrap_SysAppTimerInitialize, kRetOk);

    // Check SysAppDcmdInitialize.

    will_return(__wrap_SysAppDcmdInitialize, kRetOk);

    // Check SysAppCfgInitialize.

    will_return(__wrap_SysAppCfgInitialize, kRetOk);

    // Check SysAppStaInitialize.

    will_return(__wrap_SysAppStaInitialize, kRetOk);

    // Check SysAppUdInitialize.

    will_return(__wrap_SysAppUdInitialize, kRetOk);

    // Check SysAppDeployInitialize.

    will_return(__wrap_SysAppDeployInitialize, kRetOk);

    // Check EsfPwrMgrSwWdtStart - This will fail and cause goto sw_wdt_start_failed.

    expect_value(__wrap_EsfPwrMgrSwWdtStart, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStart, kEsfPwrMgrErrorInternal); // Return error

    // Check SysAppDeployFinalize.

    will_return(__wrap_SysAppDeployFinalize, kRetOk);

    // Check SysAppUdFinalize.

    will_return(__wrap_SysAppUdFinalize, kRetOk);

    // Check SysAppStaFinalize.

    will_return(__wrap_SysAppStaFinalize, kRetOk);

    // Check SysAppCfgFinalize.

    will_return(__wrap_SysAppCfgFinalize, kRetOk);

    // Check SysAppDcmdFinalize.

    will_return(__wrap_SysAppDcmdFinalize, kRetOk);

    // Check SysAppTimerFinalize.

    will_return(__wrap_SysAppTimerFinalize, kRetOk);

    // Check EVP_Agent_unregister_sys_client.

    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.

    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);

    // Check task_delete.
#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif

    StopSyncNtp_FullySuccess();

    DisconnectNetwork_FullySuccess();

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif

    // Check value.

    assert_int_equal(reason, UnDefined);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_EsfPwrMgrSwWdtKeepaliveError(void** state)
{
    TerminationReason reason = UnDefined;
    struct SYS_client sys_client;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // ConnectNetwork, fully success.

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // StartSyncNtp, fully success.

    StartSyncNtp_FullySuccess();

    // Check task_create.
    task_create_Success();

    // Check EVP_Agent_register_sys_client.

    will_return(__wrap_EVP_Agent_register_sys_client, &sys_client);

    // Check SysAppTimerInitialize.

    will_return(__wrap_SysAppTimerInitialize, kRetOk);

    // Check SysAppDcmdInitialize.

    will_return(__wrap_SysAppDcmdInitialize, kRetOk);

    // Check SysAppCfgInitialize.

    will_return(__wrap_SysAppCfgInitialize, kRetOk);

    // Check SysAppStaInitialize.

    will_return(__wrap_SysAppStaInitialize, kRetOk);

    // Check SysAppUdInitialize.

    will_return(__wrap_SysAppUdInitialize, kRetOk);

    // Check SysAppDeployInitialize.

    will_return(__wrap_SysAppDeployInitialize, kRetOk);

    // Check EsfPwrMgrSwWdtStart.

    expect_value(__wrap_EsfPwrMgrSwWdtStart, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStart, kEsfPwrMgrOk);

    // Check EsfPwrMgrSwWdtKeepalive - This will fail but execution continues.

    expect_value(__wrap_EsfPwrMgrSwWdtKeepalive, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtKeepalive, kEsfPwrMgrErrorInternal); // Return error

    // Check SYS_process_event.

    expect_memory(__wrap_SYS_process_event, c, &sys_client, sizeof(sys_client));
    expect_value(__wrap_SYS_process_event, ms, 1000);
    will_return(__wrap_SYS_process_event, SYS_RESULT_SHOULD_EXIT);

    // Check EsfPwrMgrWdtTerminate.

    // Check EsfPwrMgrSwWdtStop.
    expect_value(__wrap_EsfPwrMgrSwWdtStop, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStop, kEsfPwrMgrOk);

    // Check SysAppDeployFinalize.

    will_return(__wrap_SysAppDeployFinalize, kRetOk);

    // Check SysAppUdFinalize.

    will_return(__wrap_SysAppUdFinalize, kRetOk);

    // Check SysAppStaFinalize.

    will_return(__wrap_SysAppStaFinalize, kRetOk);

    // Check SysAppCfgFinalize.

    will_return(__wrap_SysAppCfgFinalize, kRetOk);

    // Check SysAppDcmdFinalize.

    will_return(__wrap_SysAppDcmdFinalize, kRetOk);

    // Check SysAppTimerFinalize.

    will_return(__wrap_SysAppTimerFinalize, kRetOk);

    // Check EVP_Agent_unregister_sys_client.

    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.

    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);

    // Check task_delete.
#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif

    StopSyncNtp_FullySuccess();

    DisconnectNetwork_FullySuccess();

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif

    // Check value.

    assert_int_equal(reason, UnDefined);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppMain_EsfPwrMgrSwWdtStopError(void** state)
{
    TerminationReason reason = UnDefined;
    struct SYS_client sys_client;

    // Check SsfSensorInit.

    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // ConnectNetwork, fully success.

    ConnectNetwork_FullySuccess_WiFiConnected(kEsfNetworkManagerResultSuccess);

    // Check SysAppBtnCheckRebootRequest.

    will_return(__wrap_SysAppBtnCheckRebootRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // StartSyncNtp, fully success.

    StartSyncNtp_FullySuccess();

    // Check task_create.
    task_create_Success();

    // Check EVP_Agent_register_sys_client.

    will_return(__wrap_EVP_Agent_register_sys_client, &sys_client);

    // Check SysAppTimerInitialize.

    will_return(__wrap_SysAppTimerInitialize, kRetOk);

    // Check SysAppDcmdInitialize.

    will_return(__wrap_SysAppDcmdInitialize, kRetOk);

    // Check SysAppCfgInitialize.

    will_return(__wrap_SysAppCfgInitialize, kRetOk);

    // Check SysAppStaInitialize.

    will_return(__wrap_SysAppStaInitialize, kRetOk);

    // Check SysAppUdInitialize.

    will_return(__wrap_SysAppUdInitialize, kRetOk);

    // Check SysAppDeployInitialize.

    will_return(__wrap_SysAppDeployInitialize, kRetOk);

    // Check EsfPwrMgrSwWdtStart.

    expect_value(__wrap_EsfPwrMgrSwWdtStart, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStart, kEsfPwrMgrOk);

    // Check EsfPwrMgrSwWdtKeepalive.

    expect_value(__wrap_EsfPwrMgrSwWdtKeepalive, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtKeepalive, kEsfPwrMgrOk);

    // Check SYS_process_event.

    expect_memory(__wrap_SYS_process_event, c, &sys_client, sizeof(sys_client));
    expect_value(__wrap_SYS_process_event, ms, 1000);
    will_return(__wrap_SYS_process_event, SYS_RESULT_SHOULD_EXIT);

    // Check EsfPwrMgrWdtTerminate.

    // Check EsfPwrMgrSwWdtStop - This will fail but execution continues.
    expect_value(__wrap_EsfPwrMgrSwWdtStop, id, SYSTEM_APP_SW_WDT_ID);
    will_return(__wrap_EsfPwrMgrSwWdtStop, kEsfPwrMgrErrorInternal); // Return error

    // Check SysAppDeployFinalize.

    will_return(__wrap_SysAppDeployFinalize, kRetOk);

    // Check SysAppUdFinalize.

    will_return(__wrap_SysAppUdFinalize, kRetOk);

    // Check SysAppStaFinalize.

    will_return(__wrap_SysAppStaFinalize, kRetOk);

    // Check SysAppCfgFinalize.

    will_return(__wrap_SysAppCfgFinalize, kRetOk);

    // Check SysAppDcmdFinalize.

    will_return(__wrap_SysAppDcmdFinalize, kRetOk);

    // Check SysAppTimerFinalize.

    will_return(__wrap_SysAppTimerFinalize, kRetOk);

    // Check EVP_Agent_unregister_sys_client.

    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.

    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);

    // Check task_delete.
#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif

    StopSyncNtp_FullySuccess();

    DisconnectNetwork_FullySuccess();

    // Check SsfSensorExit.

    will_return(__wrap_EsfSensorExit, kEsfSensorOk);

    // Check pthread_exit.

    // will_return(__wrap_pthread_exit, 0);

    // Execute test target.

#if defined(__NuttX__)
    SysAppMain(&reason);
#endif
#if defined(__linux__)
    reason = SysAppMain();
#endif

    // Check value.

    assert_int_equal(reason, UnDefined);
}

/*----------------------------------------------------------------------------*/

//
// system_app_main_for_test
//

/*----------------------------------------------------------------------------*/
static void test_system_app_main_for_test_SetupMountDirError(void** state)
{
    int ret;

    SetupDirMount_MountFailedAndExecuteFormatFailed();

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, true);

    // Check SysAppBtnExecuteFactoryResetCore.

    will_return(__wrap_SysAppBtnExecuteFactoryResetCore, true);

    // Check SysAppBtnFinalize.

    will_return(__wrap_SysAppBtnFinalize, kRetOk);

    // Execute test target.

#if defined(__NuttX__)
    ret = system_app_main_for_test(0, NULL);

    // Check value.

    assert_int_equal(ret, 0);
#else
    system_app_main(NULL);
#endif
}

/*----------------------------------------------------------------------------*/
static void test_system_app_main_for_test_BootInitialSettingApp(void** state)
{
    int ret;

    SetupDirMount_AlreadyExists();

    ToOperaitingStatus_FullySuccess_ToInitialSetting();

    ExecInitialSettingApp_FullySuccess();

    // Execute test target.
#if defined(__NuttX__)
    ret = system_app_main_for_test(0, NULL);

    // Check value.

    assert_int_equal(ret, 0);
#else
    system_app_main(NULL);
#endif
}

/*----------------------------------------------------------------------------*/
static void test_system_app_main_for_test_ExecInitialSettingAppFailed(void** state)
{
    int ret;

    SetupDirMount_AlreadyExists();

    ToOperaitingStatus_FullySuccess_ToInitialSetting();

    // Check ExecInitialSettingApp. Will fail.
#if defined(__NuttX__)
    {
        // Check task_create.
        will_return(__wrap_task_create, -1);
    }

    // Check SysAppBtnInitialize.

    will_return(__wrap_SysAppBtnInitialize, kRetOk);

    // Check SysAppBtnCheckFactoryResetRequest. 1st call false.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, false);

    // Check SysAppBtnCheckFactoryResetRequest. 2st call false.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, true);

    // Check SysAppBtnExecuteFactoryResetCore.

    will_return(__wrap_SysAppBtnExecuteFactoryResetCore, true);

    // Check SysAppBtnFinalize.

    will_return(__wrap_SysAppBtnFinalize, kRetOk);
#endif
    // Check evp_agent_startup
#if defined(__linux__)
    will_return(__wrap_initial_setting_app_main, 0);
#endif
    // Execute test target.

#if defined(__NuttX__)
    ret = system_app_main_for_test(0, NULL);

    // Check value.

    assert_int_equal(ret, 0);
#else
    system_app_main(NULL);
#endif

    return;
}

/*----------------------------------------------------------------------------*/
static void test_system_app_main_for_test_SysAppBtnInitializeError(void** state)
{
    int ret;

    SetupDirMount_AlreadyExists();

    ToOperatingStatus_FullySuccess_ToOperation();

    // Check SysAppBtnInitialize.

    will_return(__wrap_SysAppBtnInitialize, kRetFailed);

    // Check SysAppDcmdRebootCore.

    // will_return(__wrap_SysAppDcmdRebootCore, kRetFailed);

    // Check SysAppBtnFinalize.

    will_return(__wrap_SysAppBtnFinalize, kRetOk);

    // Execute test target.

#if defined(__NuttX__)
    ret = system_app_main_for_test(0, NULL);

    // Check value.

    assert_int_equal(ret, 0);
#else
    system_app_main(NULL);
#endif
}

/*----------------------------------------------------------------------------*/
static void test_system_app_main_for_test_PthreadAttrInitError(void** state)
{
    int ret;

    SetupDirMount_AlreadyExists();

    ToOperatingStatus_FullySuccess_ToOperation();

    // Check SysAppBtnInitialize.

    will_return(__wrap_SysAppBtnInitialize, kRetOk);

    // Check pthread_attr_init.

    will_return(__wrap_pthread_attr_init, -1);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, true);

    // Check SysAppBtnExecuteFactoryResetCore.

    will_return(__wrap_SysAppBtnExecuteFactoryResetCore, true);

    // Check SysAppBtnFinalize.

    will_return(__wrap_SysAppBtnFinalize, kRetOk);

#if defined(__NuttX__)
    ret = system_app_main_for_test(0, NULL);

    // Check value.

    assert_int_equal(ret, 0);
#else
    system_app_main(NULL);
#endif
}

/*----------------------------------------------------------------------------*/
static void test_system_app_main_for_test_PthreadAttrSetStackSizeError(void** state)
{
    int ret;

    SetupDirMount_AlreadyExists();

    ToOperatingStatus_FullySuccess_ToOperation();

    // Check SysAppBtnInitialize.

    will_return(__wrap_SysAppBtnInitialize, kRetOk);

    // Check pthread_attr_init.

    will_return(__wrap_pthread_attr_init, 0);

    // Check pthread_attr_setstacksize.

    will_return(__wrap_pthread_attr_setstacksize, -1);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, true);

    // Check SysAppBtnExecuteFactoryResetCore.

    will_return(__wrap_SysAppBtnExecuteFactoryResetCore, true);

    // Check SysAppBtnFinalize.

    will_return(__wrap_SysAppBtnFinalize, kRetOk);

    // Execute test target.

#if defined(__NuttX__)
    ret = system_app_main_for_test(0, NULL);

    // Check value.

    assert_int_equal(ret, 0);
#else
    system_app_main(NULL);
#endif
}

/*----------------------------------------------------------------------------*/
static void test_system_app_main_for_test_PthreadCreateError(void** state)
{
    int ret;

    SetupDirMount_AlreadyExists();

    ToOperatingStatus_FullySuccess_ToOperation();

    // Check SysAppBtnInitialize.

    will_return(__wrap_SysAppBtnInitialize, kRetOk);

    // Check pthread_attr_init.

    will_return(__wrap_pthread_attr_init, 0);

    // Check pthread_attr_setstacksize.

    will_return(__wrap_pthread_attr_setstacksize, 0);

    // Check pthread_create.

    will_return(__wrap_pthread_create, UnDefined);
    will_return(__wrap_pthread_create, -1);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, true);

    // Check SysAppBtnExecuteFactoryResetCore.

    will_return(__wrap_SysAppBtnExecuteFactoryResetCore, true);

    // Check SysAppBtnFinalize.

    will_return(__wrap_SysAppBtnFinalize, kRetOk);

    // Execute test target.

#if defined(__NuttX__)
    ret = system_app_main_for_test(0, NULL);

    // Check value.

    assert_int_equal(ret, 0);
#else
    system_app_main(NULL);
#endif
}

/*----------------------------------------------------------------------------*/
static void test_system_app_main_for_test_PthreadJoinError(void** state)
{
    int ret;

    SetupDirMount_AlreadyExists();

    ToOperatingStatus_FullySuccess_ToOperation();

    // Check SysAppBtnInitialize.

    will_return(__wrap_SysAppBtnInitialize, kRetOk);

    // Check pthread_attr_init.

    will_return(__wrap_pthread_attr_init, 0);

    // Check pthread_attr_setstacksize.

    will_return(__wrap_pthread_attr_setstacksize, 0);

    // Check pthread_create.

    will_return(__wrap_pthread_create, UnDefined);
    will_return(__wrap_pthread_create, 0);

    // Check pthread_join.

    will_return(__wrap_pthread_join, -1);

    // Check SysAppBtnCheckFactoryResetRequest.

    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, true);

    // Check SysAppBtnExecuteFactoryResetCore.

    will_return(__wrap_SysAppBtnExecuteFactoryResetCore, true);

    // Check SysAppBtnFinalize.

    will_return(__wrap_SysAppBtnFinalize, kRetOk);

    // Execute test target.

#if defined(__NuttX__)
    ret = system_app_main_for_test(0, NULL);

    // Check value.

    assert_int_equal(ret, 0);
#else
    system_app_main(NULL);
#endif
}

/*----------------------------------------------------------------------------*/
static void test_system_app_main_for_test_FullySuccess_RebootRequested(void** state)
{
    int ret;

    SetupDirMount_AlreadyExists();

    ToOperatingStatus_FullySuccess_ToOperation();

    // Check SysAppBtnInitialize.

    will_return(__wrap_SysAppBtnInitialize, kRetOk);

    // Check pthread_attr_init.

    will_return(__wrap_pthread_attr_init, 0);

    // Check pthread_attr_setstacksize.

    will_return(__wrap_pthread_attr_setstacksize, 0);

    // Check pthread_create.

    will_return(__wrap_pthread_create, RebootRequested);
    will_return(__wrap_pthread_create, 0);

    // Check pthread_join.

    will_return(__wrap_pthread_join, 0);

    // Check SysAppDcmdRebootCore.

    // will_return(__wrap_SysAppDcmdRebootCore, kRetOk);

    // Check SysAppBtnFinalize.

    will_return(__wrap_SysAppBtnFinalize, kRetOk);

    // Execute test target.

#if defined(__NuttX__)
    ret = system_app_main_for_test(0, NULL);

    // Check value.

    assert_int_equal(ret, 0);
#else
    system_app_main(NULL);
#endif
}

/*----------------------------------------------------------------------------*/
static void test_system_app_main_for_test_FullySuccess_FactoryResetByDcmdRequested(void** state)
{
    int ret;

    SetupDirMount_AlreadyExists();

    ToOperatingStatus_FullySuccess_ToOperation();

    // Check SysAppBtnInitialize.

    will_return(__wrap_SysAppBtnInitialize, kRetOk);

    // Check pthread_attr_init.

    will_return(__wrap_pthread_attr_init, 0);

    // Check pthread_attr_setstacksize.

    will_return(__wrap_pthread_attr_setstacksize, 0);

    // Check pthread_create.

    will_return(__wrap_pthread_create, FactoryResetRequested);
    will_return(__wrap_pthread_create, 0);

    // Check pthread_join.

    will_return(__wrap_pthread_join, 0);

    // Check SysAppDcmdFactoryResetCore.

    // will_return(__wrap_SysAppDcmdFactoryResetCore, kRetOk);

    // Check SysAppBtnFinalize.

    will_return(__wrap_SysAppBtnFinalize, kRetOk);

    // Execute test target.

#if defined(__NuttX__)
    ret = system_app_main_for_test(0, NULL);

    // Check value.

    assert_int_equal(ret, 0);
#else
    system_app_main(NULL);
#endif
}

/*----------------------------------------------------------------------------*/
static void test_system_app_main_for_test_FullySuccess_FactoryResetByButtonRequested(void** state)
{
    int ret;

    SetupDirMount_AlreadyExists();

    ToOperatingStatus_FullySuccess_ToOperation();

    // Check SysAppBtnInitialize.

    will_return(__wrap_SysAppBtnInitialize, kRetOk);

    // Check pthread_attr_init.

    will_return(__wrap_pthread_attr_init, 0);

    // Check pthread_attr_setstacksize.

    will_return(__wrap_pthread_attr_setstacksize, 0);

    // Check pthread_create.

    will_return(__wrap_pthread_create, FactoryResetButtonRequested);
    will_return(__wrap_pthread_create, 0);

    // Check pthread_join.

    will_return(__wrap_pthread_join, 0);

    // Check SysAppBtnExecuteFactoryResetCore.

    will_return(__wrap_SysAppBtnExecuteFactoryResetCore, kRetOk);

    // Check SysAppBtnFinalize.

    will_return(__wrap_SysAppBtnFinalize, kRetOk);

    // Execute test target.

#if defined(__NuttX__)
    ret = system_app_main_for_test(0, NULL);

    // Check value.

    assert_int_equal(ret, 0);
#else
    system_app_main(NULL);
#endif
}

/*----------------------------------------------------------------------------*/
static void test_system_app_main_for_test_FullySuccess_FactoryResetByDeployRequested(void** state)
{
    int ret;

    SetupDirMount_AlreadyExists();

    ToOperatingStatus_FullySuccess_ToOperation();

    // Check SysAppBtnInitialize.

    will_return(__wrap_SysAppBtnInitialize, kRetOk);

    // Check pthread_attr_init.

    will_return(__wrap_pthread_attr_init, 0);

    // Check pthread_attr_setstacksize.

    will_return(__wrap_pthread_attr_setstacksize, 0);

    // Check pthread_create.

    will_return(__wrap_pthread_create, FactoryResetDeployRequested);
    will_return(__wrap_pthread_create, 0);

    // Check pthread_join.

    will_return(__wrap_pthread_join, 0);

    // Check SysAppDeployFactoryReset.

    //will_return(__wrap_SysAppDeployFactoryReset, kRetOk);

    // Check SysAppBtnFinalize.

    will_return(__wrap_SysAppBtnFinalize, kRetOk);

    // Execute test target.

#if defined(__NuttX__)
    ret = system_app_main_for_test(0, NULL);

    // Check value.

    assert_int_equal(ret, 0);
#else
    system_app_main(NULL);
#endif
}

//
// main()
//

/*----------------------------------------------------------------------------*/
int main(void)
{
    const struct CMUnitTest tests[] = {
#if 1
#if 1
        // CheckProjectIdAndRegisterToken
        cmocka_unit_test(test_CheckProjectIdAndRegisterToken_FullySuccess),
        cmocka_unit_test(test_CheckProjectIdAndRegisterToken_ProjectIdAllocError),
        cmocka_unit_test(test_CheckProjectIdAndRegisterToken_RegisterTokenAllocError),
        cmocka_unit_test(test_CheckProjectIdAndRegisterToken_GetProjectIdError),
        cmocka_unit_test(test_CheckProjectIdAndRegisterToken_GetRegisterTokenError),
        cmocka_unit_test(test_CheckProjectIdAndRegisterToken_EmptyProjectIdAndRegisterToken),
#endif
#if 1
        // ToOperatingStatus
        cmocka_unit_test(test_ToOperatingStatus_FullySuccess_ToInitialSetting),
        cmocka_unit_test(test_ToOperatingStatus_FullySuccess_ToOperation),
        cmocka_unit_test(test_ToOperatingStatus_FullySuccess_EmptyMqttHostAndMqttPort),
        cmocka_unit_test(test_ToOperatingStatus_GetMqttPortError),
        cmocka_unit_test(test_ToOperatingStatus_GetMqttHostError),
        cmocka_unit_test(test_ToOperatingStatus_MqttHostAndMqttPortAllocError),
        cmocka_unit_test(test_ToOperatingStatus_FullySuccess_ToInitialSettingQrTimerValid),
        cmocka_unit_test(test_ToOperatingStatus_FullySuccess_QrTimeoutValueGetError),
#endif

        // ExecInitialSettingApp
        cmocka_unit_test(test_ExecInitialSettingApp_FullySuccess),
#if defined(__NuttX)
        cmocka_unit_test(test_ExecInitialSettingApp_TaskCreateError),
        cmocka_unit_test(test_ExecInitialSettingApp_WaitpidError),
        cmocka_unit_test(test_ExecInitialSettingApp_Waitpid0),
#endif
        // NetworkManagerCallback
        cmocka_unit_test(test_NetworkManagerCallback_FullySuccess),
        cmocka_unit_test(test_NetworkManagerCallback_NullData),

        // NtpSyncCallback
        cmocka_unit_test(test_NtpSyncCallback_FullySuccessSync),
        cmocka_unit_test(test_NtpSyncCallback_FullySuccessCannotSync),

        // ConnectNetwork
        cmocka_unit_test(test_ConnectNetwork_FullySuccess_WiFiConnected),
        cmocka_unit_test(test_ConnectNetwork_FullySuceess_EtherConnected),
        cmocka_unit_test(test_ConnectNetwork_WiFiAbortedByFactoryResetRequest),
        cmocka_unit_test(test_ConnectNetwork_WiFiAbortedByRebootRequest),
        cmocka_unit_test(test_ConnectNetwork_EtherAbortedByFactoryResetRequest),
        cmocka_unit_test(test_ConnectNetwork_EtherAbortedByRebootRequest),
        cmocka_unit_test(test_ConnectNetwork_WiFiStartErrorEtherStartError),
        cmocka_unit_test(test_ConnectNetwork_NetworkCallbackRegisterError),
        cmocka_unit_test(test_ConnectNetwork_NetworkOpenError),
        cmocka_unit_test(test_ConnectNetwork_WiFiConnected_EsfNetworkManagerSaveParameter_Error),
#endif
        cmocka_unit_test(test_ConnectNetwork_RetryOverStop),
        cmocka_unit_test(test_ConnectNetwork_RetryOverStopLedHold),
#if 1
        // DisconnectNetwork
        cmocka_unit_test(test_DisconnectNetwork_FullySuccess),
        cmocka_unit_test(test_DisconnectNetwork_NetworkCloseError),
        cmocka_unit_test(test_DisconnectNetwork_NetworkCallbackUnregisterError),
        cmocka_unit_test(test_DisconnectNetwork_NetworkStopError),

        // StartSyncNtp
        cmocka_unit_test(test_StartSyncNtp_FullySuccess),
        cmocka_unit_test(test_StartSyncNtp_AbortByFactoryReset),
        cmocka_unit_test(test_StartSyncNtp_AbortByReboot),
        cmocka_unit_test(test_StartSyncNtp_NtpSetParamError),
        cmocka_unit_test(test_StartSyncNtp_NtpRegisterCallbackError),
        cmocka_unit_test(test_StartSyncNtp_NtpStartError),
        cmocka_unit_test(test_StartSyncNtp_s_ntp_sync_done),

        // StopSyncNtp
        cmocka_unit_test(test_StopSyncNtp_FullySuccess),
        cmocka_unit_test(test_StopSyncNtp_NtpStopError),

        // SetupDirMount
        cmocka_unit_test(test_SetupDirMount_AlreadyExists),
        cmocka_unit_test(test_SetupDirMount_MountSuccess),
        cmocka_unit_test(test_SetupDirMount_MountFailedAndExecuteFormat),
#if defined(__NuttX)
        cmocka_unit_test(test_SetupDirMount_MountFailedAndExecuteFormatFailed),
#endif
        // SysAppMain
        cmocka_unit_test(test_SysAppMain_SysProcessEventError),
        cmocka_unit_test(test_SysAppMain_SelfTerminateRequested),
        cmocka_unit_test(test_SysAppMain_SelfTerminateRequestedFactoryReset),
        cmocka_unit_test(test_SysAppMain_RebootRequested),
        cmocka_unit_test(test_SysAppMain_FactoryResetRequested),
        cmocka_unit_test(test_SysAppMain_DeployResetRequested),
        cmocka_unit_test(test_SysAppMain_DeployFactoryResetRequested),
        cmocka_unit_test(test_SysAppMain_DeployResetRequestedStateQueueEmpty),
        cmocka_unit_test(test_SysAppMain_DeployResetRequestedStateQueueEmptyFactoryReset),
        cmocka_unit_test(test_SysAppMain_SensorInitError),
        cmocka_unit_test(test_SysAppMain_ConnectNetworkAborted),
        cmocka_unit_test(test_SysAppMain_ConnectNetworkRetry),
        cmocka_unit_test(test_SysAppMain_ConnectNetworkError_RebootRequest),
        cmocka_unit_test(test_SysAppMain_ConnectNetworkError_FactoryResetRequest),
        cmocka_unit_test(test_SysAppMain_NtpSyncError),
#if defined(__NuttX)
        cmocka_unit_test(test_SysAppMain_EvpAgentTaskCreateError),
#endif
        cmocka_unit_test(test_SysAppMain_SysAppTimerInitializeError),
        cmocka_unit_test(test_SysAppMain_SysAppDcmdInitializeError),
        cmocka_unit_test(test_SysAppMain_SysAppCfgInitializeError),
        cmocka_unit_test(test_SysAppMain_SysAppStaInitializeError),
        cmocka_unit_test(test_SysAppMain_SysAppUdInitializeError),
        cmocka_unit_test(test_SysAppMain_SysAppDeployInitializeError),
        cmocka_unit_test(test_SysAppMain_EsfPwrMgrSwWdtStartError),
        cmocka_unit_test(test_SysAppMain_EsfPwrMgrSwWdtKeepaliveError),
        cmocka_unit_test(test_SysAppMain_EsfPwrMgrSwWdtStopError),

    // system_app_main_for_test
#if defined(__NuttX__)
        cmocka_unit_test(test_system_app_main_for_test_SetupMountDirError),
#endif
        cmocka_unit_test(test_system_app_main_for_test_BootInitialSettingApp),
        cmocka_unit_test(test_system_app_main_for_test_ExecInitialSettingAppFailed),
        cmocka_unit_test(test_system_app_main_for_test_SysAppBtnInitializeError),
#if defined(__NuttX__)
        cmocka_unit_test(test_system_app_main_for_test_PthreadAttrInitError),
        cmocka_unit_test(test_system_app_main_for_test_PthreadAttrSetStackSizeError),
        cmocka_unit_test(test_system_app_main_for_test_PthreadCreateError),
        cmocka_unit_test(test_system_app_main_for_test_PthreadJoinError),
        cmocka_unit_test(test_system_app_main_for_test_FullySuccess_RebootRequested),
        cmocka_unit_test(test_system_app_main_for_test_FullySuccess_FactoryResetByDcmdRequested),
        cmocka_unit_test(test_system_app_main_for_test_FullySuccess_FactoryResetByButtonRequested),
        cmocka_unit_test(test_system_app_main_for_test_FullySuccess_FactoryResetByDeployRequested),
#endif
#endif
    };

    return (((cmocka_run_group_tests(tests, NULL, NULL)) == 0) ? 0 : 1);
}
