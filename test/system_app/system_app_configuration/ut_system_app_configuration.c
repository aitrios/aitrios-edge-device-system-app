/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <setjmp.h>
#include <cmocka.h>

#include "evp/sdk_sys.h"
#include "clock_manager.h"
#include "clock_manager_setting.h"
#include "system_manager.h"
#include "system_app_timer.h"
#include "system_app_configuration.h"

extern struct SYS_client *s_sys_client;

extern void ConfigurationCallback(struct SYS_client *client, const char *topic, const char *config,
                                  enum SYS_type_configuration type, enum SYS_callback_reason reason,
                                  void *userData);
extern RetCode SysAppCfgLog(const char *param);
extern RetCode SysAppCfgProxySettings(const char *param);
extern RetCode SysAppCfgIntervalSetting(const char *param, int index);
extern RetCode SysAppCfgStaModeSetting(const char *param);
extern bool IsValidUrlOrIpAddress(const char *string, int max_len);
extern bool IsValidUrlOrNullString(const char *domain, int max_len);

typedef enum { UnitTestIPv4 = 1, UnitTestIPv6 = 2 } UnitTestIpVer;

extern RetCode SysAppCfgStaticSettings(const char *param, UnitTestIpVer ip_ver);

static const char *const log_settings = "SYSTEM SETTINGS LOG SETTINGS";
static const char *const system_settings = "SYSTEM SETTINGS PARAMETERS";
static const char *const static_settings = "NETWORK SETTINGS STATIC SETTINGS";
static const char *const ipv6_serialized = "NETWORK SETTINGS IPV6 SETTINGS";
static const char *const ipv4_serialized = "NETWORK SETTINGS IPV4 SETTINGS";
static const char *const proxy_settings = "NETWORK SETTINGS PROXY SETTINGS";
static const char *const network_settings = "NETWORK SETTINGS PARAMETERS";
static const char *const interval_settings = "PERIODIC SETTING INTERVAL SETTINGS";
static const char *const periodic_setting = "PERIODIC SETTING PARAMETERS";
static const char *const sta_mode_setting = "WIRELESS SETTING STA MODE SETTING";
static const char *const wireless_setting = "WIRELESS SETTING PARAMETERS";
static const char *const endpoint_settings = "ENDPOINT SETTINGS PARAMETERS";

#define SUCCESS_SUBDOMAIN_TBL_BLOCK_LEN 25

static char *SuccessSubdomainTbl[SUCCESS_SUBDOMAIN_TBL_BLOCK_LEN] = {
    "",
    "pool.org",
    "1ool.ntp.org",
    "pool.1tp.org",
    "pool.ntp.1rg",
    "p--l.ntp.org",
    "pool.n-p.org",
    "pool.ntp.o-g",
    "pool.ntp.org",
    "pool.n5p.org",
    "pool.n-p.org",
    "pool.nt0.org",
    "p.n.org",
    "p.L2345678901234567890L2345678901234567890L2345678901234567890123.org",
    "L2345678901234567890L2345678901234567890L2345678901234567890123."
    "L2345678901234567890L2345678901234567890L2345678901234567890123."
    "L2345678901234567890L2345678901234567890L2345678901234567890123",
    "0.jp.ntp.org",
    "a.0.ntp.org",
    "a.jp.0.org",
    "a.jp.ntp.0g",
    "192.168.1.100",
    "0.0.0.0",
    "255.255.255.255",
    "1.ne.jp",
    "a.1b.jp",
    "a.b.1p",
};

#define ERROR_SUBDOMAIN_TBL_BLOCK_LEN 38

static char *ErrorSubdomainTbl[ERROR_SUBDOMAIN_TBL_BLOCK_LEN] = {
    "org",
    "123",
    "pool.n_p.org",
    "pool-ntp-org",
    "pool.ntp.o",
    "ab",
    ".ntp.org",
    "pool..org",
    "pool.ntp.",
    ".",
    "..",
    "...",
    "....",
    "L2345678901234567890L2345678901234567890L23456789012345678901234.net.org",
    "p.L2345678901234567890L2345678901234567890L23456789012345678901234.org",
    "pool.net.L2345678901234567890L2345678901234567890L23456789012345678901234",
    "-ool.ntp.org",
    "poo-.ntp.org",
    "pool.-tp.org",
    "pool.nt-.org",
    "pool.ntp.-rg",
    "pool.ntp.or-",
    "-1.255.255.255",
    "255.-1.255.255",
    "255.255.-1.255",
    "255.255.255.-1",
    "12.34",
    "12.34.56",
    "1.2.34",
    "192.168.12",
    "192.168.1.100.1",
    "256.255.255.255",
    "255.256.255.255",
    "255.255.256.255",
    "255.255.255.256",
    "192.168.1.999",
    "192.321.0.999",
    "2001:0db8:bd05:01d2:288a:1fc0:0001:10ee",
};

/*----------------------------------------------------------------------------*/
//
// For EsfClockManager API
//
/*----------------------------------------------------------------------------*/
static void ForEsfClockManagerGetParams(const char *hostname, EsfClockManagerReturnValue result)
{
    will_return(__wrap_EsfClockManagerGetParams, hostname);
    will_return(__wrap_EsfClockManagerGetParams, 0);
    will_return(__wrap_EsfClockManagerGetParams, 0);
    will_return(__wrap_EsfClockManagerGetParams, kClockManagerParamTypeOff);
    will_return(__wrap_EsfClockManagerGetParams, 0);
    will_return(__wrap_EsfClockManagerGetParams, 0);
    will_return(__wrap_EsfClockManagerGetParams, 0);
    will_return(__wrap_EsfClockManagerGetParams, kClockManagerParamTypeOff);
    will_return(__wrap_EsfClockManagerGetParams, 0);
    will_return(__wrap_EsfClockManagerGetParams, 0);
    will_return(__wrap_EsfClockManagerGetParams, result);
}

/*----------------------------------------------------------------------------*/
//
// For EsfJson API
//
/*----------------------------------------------------------------------------*/
static void ForEsfJsonArrayGet(EsfJsonHandle handle, EsfJsonValue parent, int32_t index,
                               EsfJsonValue value, EsfJsonErrorCode result)
{
    expect_value(__wrap_EsfJsonArrayGet, handle, handle);
    expect_value(__wrap_EsfJsonArrayGet, parent, parent);
    expect_value(__wrap_EsfJsonArrayGet, index, index);
    will_return(__wrap_EsfJsonArrayGet, value);
    will_return(__wrap_EsfJsonArrayGet, result);
}

/*----------------------------------------------------------------------------*/
static void ForEsfJsonSerializeFree(EsfJsonHandle handle, EsfJsonErrorCode result)
{
    expect_value(__wrap_EsfJsonSerializeFree, handle, handle);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
//
// For EsfNetworkManager API
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
static void ForEsfNetworkManagerSaveParameterIpMethod(int32_t ip_method,
                                                      EsfNetworkManagerResult result)
{
    static EsfNetworkManagerParameterMask mask = {};
    static EsfNetworkManagerParameter param = {};

    memset(&mask, 0, sizeof mask);
    mask.normal_mode.ip_method = 1;
    memset(&param, 0, sizeof param);
    param.normal_mode.ip_method = ip_method;

    CheckEsfNetworkManagerSaveParameter(&mask, &param, result);
}

/*----------------------------------------------------------------------------*/
//
// For EsfSystemManager API
//
/*----------------------------------------------------------------------------*/
static void ForEsfSystemManagerGetEvpHubUrl(const char *url, EsfSystemManagerResult result)
{
    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, url);
    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, result);
}

/*----------------------------------------------------------------------------*/
static void ForEsfSystemManagerGetEvpHubPort(const char *port, EsfSystemManagerResult result)
{
    will_return(__wrap_EsfSystemManagerGetEvpHubPort, port);
    will_return(__wrap_EsfSystemManagerGetEvpHubPort, result);
}

/*----------------------------------------------------------------------------*/
//
// For C Standard Library
//
/*----------------------------------------------------------------------------*/
static void ForMalloc(size_t size)
{
    expect_value(mock_malloc, __size, size);
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
}

/*----------------------------------------------------------------------------*/
static void ForCalloc(size_t nmemb, size_t size)
{
    expect_value(mock_calloc, __nmemb, nmemb);
    expect_value(mock_calloc, __size, size);
    will_return(mock_calloc, true);
    will_return(mock_calloc, true);
}

/*----------------------------------------------------------------------------*/
static void ForFree(void)
{
    will_return(mock_free, false);
}

/*----------------------------------------------------------------------------*/

//
// Common
//

/*----------------------------------------------------------------------------*/
static void ForSysSetConfigurationCb(struct SYS_client *client, const char *topic,
                                     enum SYS_result result)
{
    will_return(__wrap_SYS_set_configuration_cb, result);

    expect_value(__wrap_SYS_set_configuration_cb, c, client);
    expect_string(__wrap_SYS_set_configuration_cb, topic, topic);
    expect_value(__wrap_SYS_set_configuration_cb, cb, ConfigurationCallback);
    expect_value(__wrap_SYS_set_configuration_cb, type, SYS_CONFIG_ANY);
    expect_value(__wrap_SYS_set_configuration_cb, user, NULL);

    return;
}

/*----------------------------------------------------------------------------*/
static void ForSysAppCmnExtractNumberValue(EsfJsonHandle handle, EsfJsonValue parent,
                                           const char *key, int value, int result)
{
    expect_value(__wrap_SysAppCmnExtractNumberValue, handle, handle);
    expect_value(__wrap_SysAppCmnExtractNumberValue, parent_val, parent);
    expect_string(__wrap_SysAppCmnExtractNumberValue, jsonkey, key);
    will_return(__wrap_SysAppCmnExtractNumberValue, value);
    will_return(__wrap_SysAppCmnExtractNumberValue, result);
}

/*----------------------------------------------------------------------------*/
static void ForSysAppCmnExtractStringValue(EsfJsonHandle handle, EsfJsonValue parent,
                                           const char *key, const char *value, int result)
{
    expect_value(__wrap_SysAppCmnExtractStringValue, handle, handle);
    expect_value(__wrap_SysAppCmnExtractStringValue, parent_val, parent);
    expect_string(__wrap_SysAppCmnExtractStringValue, jsonkey, key);
    will_return(__wrap_SysAppCmnExtractStringValue, value);
    will_return(__wrap_SysAppCmnExtractStringValue, result);
}

/*----------------------------------------------------------------------------*/
static void ForSysAppCmnExtractBooleanValue(EsfJsonHandle handle, EsfJsonValue parent,
                                            const char *key, bool value, int result)
{
    expect_value(__wrap_SysAppCmnExtractBooleanValue, handle, handle);
    expect_value(__wrap_SysAppCmnExtractBooleanValue, parent_val, parent);
    expect_string(__wrap_SysAppCmnExtractBooleanValue, jsonkey, key);
    will_return(__wrap_SysAppCmnExtractBooleanValue, value);
    will_return(__wrap_SysAppCmnExtractBooleanValue, result);
}

/*----------------------------------------------------------------------------*/
static void ForSysAppLogGetParameterNumber(uint32_t index __attribute__((unused)), uint32_t type,
                                           int value, RetCode result)
{
    will_return(__wrap_SysAppLogGetParameterNumber, type);
    will_return(__wrap_SysAppLogGetParameterNumber, value);
    will_return(__wrap_SysAppLogGetParameterNumber, result);
}

/*----------------------------------------------------------------------------*/
static void ForSysAppLogSetParameterNumber(uint32_t index __attribute__((unused)),
                                           uint32_t type __attribute__((unused)),
                                           int value __attribute__((unused)), RetCode result)
{
    will_return(__wrap_SysAppLogSetParameterNumber, result);
}

/*----------------------------------------------------------------------------*/
static void ForSysAppLogGetParameterString(uint32_t index __attribute__((unused)),
                                           uint32_t type __attribute__((unused)),
                                           size_t str_len __attribute__((unused)), const char *str,
                                           RetCode result)
{
    will_return(__wrap_SysAppLogGetParameterString, str);
    will_return(__wrap_SysAppLogGetParameterString, result);
}

/*----------------------------------------------------------------------------*/
static void ForSysAppLogSetParameterString(uint32_t index __attribute__((unused)),
                                           uint32_t type __attribute__((unused)),
                                           const char *str __attribute__((unused)),
                                           size_t str_len __attribute__((unused)), RetCode result)
{
    will_return(__wrap_SysAppLogSetParameterString, result);
}

/*----------------------------------------------------------------------------*/
static void ForSysAppStateUpdateBoolean(uint32_t topic, uint32_t type, bool boolean, RetCode result)
{
    expect_value(__wrap_SysAppStateUpdateBoolean, topic, topic);
    expect_value(__wrap_SysAppStateUpdateBoolean, type, type);
    expect_value(__wrap_SysAppStateUpdateBoolean, boolean, boolean);
    will_return(__wrap_SysAppStateUpdateBoolean, result);
}

/*----------------------------------------------------------------------------*/
static void ForSysAppStateUpdateNumberWithIdx(uint32_t topic, uint32_t type, uint32_t number,
                                              uint32_t index, RetCode result)
{
    expect_value(__wrap_SysAppStateUpdateNumberWithIdx, topic, topic);
    expect_value(__wrap_SysAppStateUpdateNumberWithIdx, type, type);
    expect_value(__wrap_SysAppStateUpdateNumberWithIdx, number, number);
    expect_value(__wrap_SysAppStateUpdateNumberWithIdx, idx, index);
    will_return(__wrap_SysAppStateUpdateNumberWithIdx, result);
}

/*----------------------------------------------------------------------------*/
static void ForSysAppStateUpdateStringWithIdx(uint32_t topic, uint32_t type, const char *string,
                                              uint32_t index, RetCode result)
{
    expect_value(__wrap_SysAppStateUpdateStringWithIdx, topic, topic);
    expect_value(__wrap_SysAppStateUpdateStringWithIdx, type, type);
    expect_string(__wrap_SysAppStateUpdateStringWithIdx, string, string);
    expect_value(__wrap_SysAppStateUpdateStringWithIdx, idx, index);
    will_return(__wrap_SysAppStateUpdateStringWithIdx, result);
}

/*----------------------------------------------------------------------------*/
static void ForSysAppStateSetInternalErrorWithIdx(uint32_t topic, uint32_t type, uint32_t index,
                                                  RetCode result)
{
    expect_value(__wrap_SysAppStateSetInternalErrorWithIdx, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalErrorWithIdx, property, type);
    expect_value(__wrap_SysAppStateSetInternalErrorWithIdx, idx, index);
    will_return(__wrap_SysAppStateSetInternalErrorWithIdx, result);
}

/*----------------------------------------------------------------------------*/
static void ForSysAppStateSetInvalidArgErrorWithIdx(uint32_t topic, uint32_t type, uint32_t index,
                                                    RetCode result)
{
    expect_value(__wrap_SysAppStateSetInvalidArgErrorWithIdx, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgErrorWithIdx, property, type);
    expect_value(__wrap_SysAppStateSetInvalidArgErrorWithIdx, idx, index);
    will_return(__wrap_SysAppStateSetInvalidArgErrorWithIdx, result);
}

/*----------------------------------------------------------------------------*/
static void ForEsfJsonSerialize(EsfJsonHandle handle, EsfJsonValue value, const char *serialized,
                                EsfJsonErrorCode result)
{
    expect_value(__wrap_EsfJsonSerialize, handle, handle);
    expect_value(__wrap_EsfJsonSerialize, value, value);
    will_return(__wrap_EsfJsonSerialize, serialized);
    will_return(__wrap_EsfJsonSerialize, result);
}

/*----------------------------------------------------------------------------*/
static void CheckLoadAddressFromEsf(EsfNetworkManagerResult result)
{
    // For EsfNetworkManagerLoadParameter() in LoadNetworkAddressFromEsf
    will_return(__wrap_EsfNetworkManagerLoadParameter, "-");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "-");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "-");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "-");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "-");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "-");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "-");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "-");
    will_return(__wrap_EsfNetworkManagerLoadParameter, result);
}

/*----------------------------------------------------------------------------*/
static void CheckJsonOpen(EsfJsonHandle handle, EsfJsonValue value, const char *str)
{
    // For EsfJsonOpen() XX
    will_return(__wrap_EsfJsonOpen, handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // For EsfJsonDeserialize()
    expect_value(__wrap_EsfJsonDeserialize, handle, handle);
    expect_string(__wrap_EsfJsonDeserialize, str, str);
    will_return(__wrap_EsfJsonDeserialize, value);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
static void CheckJsonClose(EsfJsonHandle handle, uint32_t req)
{
    // For SysAppStateSendState()
    expect_value(__wrap_SysAppStateSendState, req, req);
    will_return(__wrap_SysAppStateSendState, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgSystemSettingsReqId(EsfJsonHandle handle, EsfJsonValue parent)
{
    const char *req_id = "1";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, parent);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // For SysAppStateGetReqId() about req_id in CheckUpdateString
    expect_value(__wrap_SysAppStateGetReqId, topic, topic);
    will_return(__wrap_SysAppStateGetReqId, "0");

    // For SysAppStateUpdateString() about req_id
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, Id);
    expect_string(__wrap_SysAppStateUpdateString, string, req_id);
    will_return(__wrap_SysAppStateUpdateString, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgSystemSettingsLedEnabled(EsfJsonHandle handle, EsfJsonValue parent)
{
    bool led_enabled = false;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    // For SysAppCmnExtractBooleanValue() in SysAppCfgSystemSettings
    ForSysAppCmnExtractBooleanValue(handle, parent, "led_enabled", led_enabled, 1);

    // For SysAppLedGetEnable() in CheckUpdateBoolean
    will_return(__wrap_SysAppLedGetEnable, !led_enabled);
    will_return(__wrap_SysAppLedGetEnable, kRetOk);

    // For SysAppLedSetEnable() in SysAppCfgSystemSettings
    expect_value(__wrap_SysAppLedSetEnable, led_enable, led_enabled);
    will_return(__wrap_SysAppLedSetEnable, kRetOk);

    // For SysAppStateUpdateBoolean() in SysAppCfgSystemSettings
    ForSysAppStateUpdateBoolean(topic, LedEnabled, led_enabled, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgLogLevel(EsfJsonHandle handle, EsfJsonValue parent, uint32_t index)
{
    uint32_t type = LogLevel;
    uint32_t level = CriticalLv;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    // For SysAppCmnExtractNumberValue() in SysAppCfgLog
    ForSysAppCmnExtractNumberValue(handle, parent, "level", level, 1);

    // For SysAppLogGetParameterNumber() in CheckUpdateNumberWithIdx
    ForSysAppLogGetParameterNumber(index, type, ErrorLv, kRetOk);

    // For SysAppLogSetParameterNumber() in SysAppCfgLog
    ForSysAppLogSetParameterNumber(index, type, level, kRetOk);

    // For SysAppStateUpdateNumberWithIdx() in SysAppCfgLog
    ForSysAppStateUpdateNumberWithIdx(topic, type, level, index, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgLogDestination(EsfJsonHandle handle, EsfJsonValue parent, uint32_t index)
{
    uint32_t type = LogDestination;
    uint32_t destination = DestUart;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    // For SysAppCmnExtractNumberValue() in SysAppCfgLog
    ForSysAppCmnExtractNumberValue(handle, parent, "destination", destination, 1);

    // For SysAppLogGetParameterNumber() in CheckUpdateNumberWithIdx
    ForSysAppLogGetParameterNumber(index, type, DestCloudStorage, kRetOk);

    // For SysAppLogSetParameterNumber() in SysAppCfgLog
    ForSysAppLogSetParameterNumber(index, type, destination, kRetOk);

    // For SysAppStateUpdateNumberWithIdx() in SysAppCfgLog
    ForSysAppStateUpdateNumberWithIdx(topic, type, destination, index, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgLogStorageName(EsfJsonHandle handle, EsfJsonValue parent, uint32_t index)
{
    uint32_t type = LogStorageName;
    size_t buffer_size = CFGST_LOG_STORAGE_NAME_LEN + 1U;
    const char *storage_name = "storage_name";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    // For SysAppCmnExtractStringValue() in SysAppCfgLog
    ForSysAppCmnExtractStringValue(handle, parent, "storage_name", storage_name, 1);

    // For SysAppLogGetParameterString() in SysAppCfgLog
    ForSysAppLogGetParameterString(index, type, buffer_size, "", kRetOk);

    // For SysAppLogSetParameterString() in SysAppCfgLog
    ForSysAppLogSetParameterString(index, type, storage_name, buffer_size, kRetOk);

    // For SysAppStateUpdateStringWithIdx() in SysAppCfgLog
    ForSysAppStateUpdateStringWithIdx(topic, type, storage_name, index, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgLogPath(EsfJsonHandle handle, EsfJsonValue parent, uint32_t index)
{
    uint32_t type = LogPath;
    size_t buffer_size = CFGST_LOG_PATH_LEN + 1U;
    const char *path = "path";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    // For SysAppCmnExtractStringValue() in SysAppCfgLog
    ForSysAppCmnExtractStringValue(handle, parent, "path", path, 1);

    // For SysAppLogGetParameterString() in SysAppCfgLog
    ForSysAppLogGetParameterString(index, type, buffer_size, "", kRetOk);

    // For SysAppLogSetParameterString() in SysAppCfgLog
    ForSysAppLogSetParameterString(index, type, path, buffer_size, kRetOk);

    // For SysAppStateUpdateStringWithIdx() in SysAppCfgLog
    ForSysAppStateUpdateStringWithIdx(topic, type, path, index, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgLogEach(EsfJsonHandle handle, EsfJsonValue parent, uint32_t index)
{
    CheckSysAppCfgLogLevel(handle, parent, index);
    CheckSysAppCfgLogDestination(handle, parent, index);
    CheckSysAppCfgLogStorageName(handle, parent, index);
    CheckSysAppCfgLogPath(handle, parent, index);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgLogIndexZero(EsfJsonHandle handle, EsfJsonValue parent)
{
    uint32_t index = 0U;
    uint32_t level = CriticalLv;
    uint32_t destination = DestUart;
    const char *storage_name = "storage_name";
    const char *path = "path";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    // For SysAppCmnExtractNumberValue() in SysAppCfgLog
    ForSysAppCmnExtractNumberValue(handle, parent, "level", level, 1);

    // For SysAppStateUpdateNumberWithIdx() in SysAppCfgLog
    ForSysAppStateUpdateNumberWithIdx(topic, LogLevel, level, index, kRetOk);

    // For SysAppCmnExtractNumberValue() in SysAppCfgLog
    ForSysAppCmnExtractNumberValue(handle, parent, "destination", destination, 1);

    // For SysAppStateUpdateNumberWithIdx() in SysAppCfgLog
    ForSysAppStateUpdateNumberWithIdx(topic, LogDestination, destination, index, kRetOk);

    // For SysAppCmnExtractStringValue() in SysAppCfgLog
    ForSysAppCmnExtractStringValue(handle, parent, "storage_name", storage_name, 1);

    // For SysAppStateUpdateStringWithIdx() in SysAppCfgLog
    ForSysAppStateUpdateStringWithIdx(topic, LogStorageName, storage_name, index, kRetOk);

    // For SysAppCmnExtractStringValue() in SysAppCfgLog
    ForSysAppCmnExtractStringValue(handle, parent, "path", path, 1);

    // For SysAppStateUpdateStringWithIdx() in SysAppCfgLog
    ForSysAppStateUpdateStringWithIdx(topic, LogPath, path, index, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgSystemSettingsSysAppCfgLog(const char *log_settings)
{
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    // For EsfJsonOpen() in SysAppCfgLog
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // For EsfJsonDeserialize() in SysAppCfgLog
    expect_value(__wrap_EsfJsonDeserialize, handle, esfj_handle);
    expect_string(__wrap_EsfJsonDeserialize, str, log_settings);
    will_return(__wrap_EsfJsonDeserialize, json_value);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // For SysAppCmnExtractStringValue() in SysAppCfgLog
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx() in SysAppCfgLog
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogEach(esfj_handle, json_value, filter_num);

    // For EsfJsonClose() in SysAppCfgLog
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgSystemSettingsLogSettingItem(EsfJsonHandle handle, EsfJsonValue parent,
                                                       int32_t index)
{
    EsfJsonValue value = ESF_JSON_VALUE_INVALID;

    ForEsfJsonArrayGet(handle, parent, index, value, kEsfJsonSuccess);

    ForEsfJsonSerialize(handle, value, log_settings, kEsfJsonSuccess);

    CheckSysAppCfgSystemSettingsSysAppCfgLog(log_settings);

    ForEsfJsonSerializeFree(handle, kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgSystemSettingsLogSettings(EsfJsonHandle handle, EsfJsonValue parent)
{
    EsfJsonValue value = ESF_JSON_VALUE_INVALID;

    // For EsfJsonObjectGet() in SysAppCfgSystemSettings
    expect_value(__wrap_EsfJsonObjectGet, handle, handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent);
    expect_string(__wrap_EsfJsonObjectGet, key, "log_settings");
    will_return(__wrap_EsfJsonObjectGet, value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // For EsfJsonValueTypeGet() in SysAppCfgSystemSettings
    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeArray);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // For EsfJsonArrayCount() in SysAppCfgSystemSettings
    expect_value(__wrap_EsfJsonArrayCount, handle, handle);
    expect_value(__wrap_EsfJsonArrayCount, parent, value);
    will_return(__wrap_EsfJsonArrayCount, 1U);

    CheckSysAppCfgSystemSettingsLogSettingItem(handle, value, 0U);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgSystemSettingsTempUpdateInterval(EsfJsonHandle handle,
                                                           EsfJsonValue parent)
{
    int temperature_interval = 1234;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    // For SysAppCmnExtractNumberValue() in SysAppCfgSystemSettings
    ForSysAppCmnExtractNumberValue(handle, parent, "temperature_update_interval",
                                   temperature_interval, 1);

    // For SysAppStateGetTemperatureUpdateInterval() in CheckUpdateNumber
    will_return(__wrap_SysAppStateGetTemperatureUpdateInterval, 0);

    // For SysAppTimerUpdateTimer() in SysAppCfgSystemSettings
    expect_value(__wrap_SysAppTimerUpdateTimer, type, SensorTempIntervalTimer);
    expect_value(__wrap_SysAppTimerUpdateTimer, time, temperature_interval);
    will_return(__wrap_SysAppTimerUpdateTimer, kRetOk);

    // For SysAppStateUpdateNumber() in SysAppCfgSystemSettings
    expect_value(__wrap_SysAppStateUpdateNumber, topic, topic);
    expect_value(__wrap_SysAppStateUpdateNumber, type, TemperatureUpdateInterval);
    expect_value(__wrap_SysAppStateUpdateNumber, number, temperature_interval);
    will_return(__wrap_SysAppStateUpdateNumber, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgSystemSettingsSuccess(const char *param)
{
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, param);

    CheckSysAppCfgSystemSettingsReqId(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLedEnabled(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLogSettings(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsTempUpdateInterval(esfj_handle, json_value);

    CheckJsonClose(esfj_handle, topic);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgStaticSettingsIpAddress(UnitTestIpVer ip_ver, EsfJsonHandle handle,
                                                  EsfJsonValue parent)
{
    static EsfNetworkManagerParameterMask mask_ipv4 = {};
    static EsfNetworkManagerParameter param_ipv4 = {};
    static EsfNetworkManagerParameterMask mask_ipv6 = {};
    static EsfNetworkManagerParameter param_ipv6 = {};
    EsfNetworkManagerParameterMask *mask = ip_ver == UnitTestIPv4 ? &mask_ipv4 : &mask_ipv6;
    EsfNetworkManagerParameter *param = ip_ver == UnitTestIPv4 ? &param_ipv4 : &param_ipv6;
    const char *addr_ipv4 = "127.0.0.1";
    const char *addr_ipv6 = "::1";
    const char *addr = ip_ver == UnitTestIPv4 ? addr_ipv4 : addr_ipv6;
    NetworkSettingsProperty property = ip_ver == UnitTestIPv4 ? IpAddress : IpAddressV6;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    // For SysAppCmnExtractStringValue() in SysAppCfgStaticSettings
    ForSysAppCmnExtractStringValue(handle, parent, "ip_address", addr, 1);

    // For inet_pton() in CheckIpAddressType

    // For EsfNetworkManagerLoadParameter() in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For EsfNetworkManagerSaveParameter() in SysAppCfgStaticSettings
    if (ip_ver == UnitTestIPv4) {
        memset(&mask_ipv4, 0, sizeof mask_ipv4);
        memset(&param_ipv4, 0, sizeof param_ipv4);
        mask_ipv4.normal_mode.dev_ip.ip = 1;
        snprintf(param_ipv4.normal_mode.dev_ip.ip, sizeof param_ipv4.normal_mode.dev_ip.ip, "%s",
                 addr);
    }
    if (ip_ver == UnitTestIPv6) {
        memset(&mask_ipv6, 0, sizeof mask_ipv6);
        memset(&param_ipv6, 0, sizeof param_ipv6);
        mask_ipv6.normal_mode.dev_ip_v6.ip = 1;
        snprintf(param_ipv6.normal_mode.dev_ip_v6.ip, sizeof param_ipv6.normal_mode.dev_ip_v6.ip,
                 "%s", addr);
    }
    CheckEsfNetworkManagerSaveParameter(mask, param, kEsfNetworkManagerResultSuccess);

    // For SysAppStateUpdateString() in SysAppCfgStaticSettings
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, property);
    expect_string(__wrap_SysAppStateUpdateString, string, addr);
    will_return(__wrap_SysAppStateUpdateString, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIpVer ip_ver, EsfJsonHandle handle,
                                                   EsfJsonValue parent)
{
    static EsfNetworkManagerParameterMask mask_ipv4 = {};
    static EsfNetworkManagerParameter param_ipv4 = {};
    static EsfNetworkManagerParameterMask mask_ipv6 = {};
    static EsfNetworkManagerParameter param_ipv6 = {};
    EsfNetworkManagerParameterMask *mask = ip_ver == UnitTestIPv4 ? &mask_ipv4 : &mask_ipv6;
    EsfNetworkManagerParameter *param = ip_ver == UnitTestIPv4 ? &param_ipv4 : &param_ipv6;
    const char *subnet_mask_ipv4 = "127.0.0.1";
    const char *subnet_mask_ipv6 = "::1";
    const char *subnet_mask = ip_ver == UnitTestIPv4 ? subnet_mask_ipv4 : subnet_mask_ipv6;
    NetworkSettingsProperty property = ip_ver == UnitTestIPv4 ? SubnetMask : SubnetMaskV6;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    // For SysAppCmnExtractStringValue() in SysAppCfgStaticSettings
    ForSysAppCmnExtractStringValue(handle, parent, "subnet_mask", subnet_mask, 1);

    // For inet_pton() in CheckIpAddressType

    // For EsfNetworkManagerLoadParameter() in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For EsfNetworkManagerSaveParameter() in SysAppCfgStaticSettings
    if (ip_ver == UnitTestIPv4) {
        memset(&mask_ipv4, 0, sizeof mask_ipv4);
        memset(&param_ipv4, 0, sizeof param_ipv4);
        mask_ipv4.normal_mode.dev_ip.subnet_mask = 1;
        snprintf(param_ipv4.normal_mode.dev_ip.subnet_mask,
                 sizeof param_ipv4.normal_mode.dev_ip.subnet_mask, "%s", subnet_mask);
    }
    if (ip_ver == UnitTestIPv6) {
        memset(&mask_ipv6, 0, sizeof mask_ipv6);
        memset(&param_ipv6, 0, sizeof param_ipv6);
        mask_ipv6.normal_mode.dev_ip_v6.subnet_mask = 1;
        snprintf(param_ipv6.normal_mode.dev_ip_v6.subnet_mask,
                 sizeof param_ipv6.normal_mode.dev_ip_v6.subnet_mask, "%s", subnet_mask);
    }
    CheckEsfNetworkManagerSaveParameter(mask, param, kEsfNetworkManagerResultSuccess);

    // For SysAppStateUpdateString() in SysAppCfgStaticSettings
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, property);
    expect_string(__wrap_SysAppStateUpdateString, string, subnet_mask);
    will_return(__wrap_SysAppStateUpdateString, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgStaticSettingsGateway(UnitTestIpVer ip_ver, EsfJsonHandle handle,
                                                EsfJsonValue parent)
{
    static EsfNetworkManagerParameterMask mask_ipv4 = {};
    static EsfNetworkManagerParameter param_ipv4 = {};
    static EsfNetworkManagerParameterMask mask_ipv6 = {};
    static EsfNetworkManagerParameter param_ipv6 = {};
    EsfNetworkManagerParameterMask *mask = ip_ver == UnitTestIPv4 ? &mask_ipv4 : &mask_ipv6;
    EsfNetworkManagerParameter *param = ip_ver == UnitTestIPv4 ? &param_ipv4 : &param_ipv6;
    const char *addr_ipv4 = "127.0.0.1";
    const char *addr_ipv6 = "::1";
    const char *addr = ip_ver == UnitTestIPv4 ? addr_ipv4 : addr_ipv6;
    NetworkSettingsProperty property = ip_ver == UnitTestIPv4 ? GatewayAddress : GatewayAddressV6;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    // For SysAppCmnExtractStringValue() in SysAppCfgStaticSettings
    ForSysAppCmnExtractStringValue(handle, parent, "gateway_address", addr, 1);

    // For inet_pton() in CheckIpAddressType

    // For EsfNetworkManagerLoadParameter() in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For EsfNetworkManagerSaveParameter() in SysAppCfgStaticSettings
    if (ip_ver == UnitTestIPv4) {
        memset(&mask_ipv4, 0, sizeof mask_ipv4);
        memset(&param_ipv4, 0, sizeof param_ipv4);
        mask_ipv4.normal_mode.dev_ip.gateway = 1;
        snprintf(param_ipv4.normal_mode.dev_ip.gateway,
                 sizeof param_ipv4.normal_mode.dev_ip.gateway, "%s", addr);
    }
    if (ip_ver == UnitTestIPv6) {
        memset(&mask_ipv6, 0, sizeof mask_ipv6);
        memset(&param_ipv6, 0, sizeof param_ipv6);
        mask_ipv6.normal_mode.dev_ip_v6.gateway = 1;
        snprintf(param_ipv6.normal_mode.dev_ip_v6.gateway,
                 sizeof param_ipv6.normal_mode.dev_ip_v6.gateway, "%s", addr);
    }
    CheckEsfNetworkManagerSaveParameter(mask, param, kEsfNetworkManagerResultSuccess);

    // For SysAppStateUpdateString() in SysAppCfgStaticSettings
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, property);
    expect_string(__wrap_SysAppStateUpdateString, string, addr);
    will_return(__wrap_SysAppStateUpdateString, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgStaticSettingsDns(UnitTestIpVer ip_ver, EsfJsonHandle handle,
                                            EsfJsonValue parent)
{
    static EsfNetworkManagerParameterMask mask_ipv4 = {};
    static EsfNetworkManagerParameter param_ipv4 = {};
    static EsfNetworkManagerParameterMask mask_ipv6 = {};
    static EsfNetworkManagerParameter param_ipv6 = {};
    EsfNetworkManagerParameterMask *mask = ip_ver == UnitTestIPv4 ? &mask_ipv4 : &mask_ipv6;
    EsfNetworkManagerParameter *param = ip_ver == UnitTestIPv4 ? &param_ipv4 : &param_ipv6;
    const char *addr_ipv4 = "127.0.0.1";
    const char *addr_ipv6 = "::1";
    const char *addr = ip_ver == UnitTestIPv4 ? addr_ipv4 : addr_ipv6;
    NetworkSettingsProperty property = ip_ver == UnitTestIPv4 ? DnsAddress : DnsAddressV6;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    // For SysAppCmnExtractStringValue() in SysAppCfgStaticSettings
    ForSysAppCmnExtractStringValue(handle, parent, "dns_address", addr, 1);

    // For inet_pton() in CheckIpAddressType

    // For EsfNetworkManagerLoadParameter() in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For EsfNetworkManagerSaveParameter() in SysAppCfgStaticSettings
    if (ip_ver == UnitTestIPv4) {
        memset(&mask_ipv4, 0, sizeof mask_ipv4);
        memset(&param_ipv4, 0, sizeof param_ipv4);
        mask_ipv4.normal_mode.dev_ip.dns = 1;
        snprintf(param_ipv4.normal_mode.dev_ip.dns, sizeof param_ipv4.normal_mode.dev_ip.dns, "%s",
                 addr);
    }
    if (ip_ver == UnitTestIPv6) {
        memset(&mask_ipv6, 0, sizeof mask_ipv6);
        memset(&param_ipv6, 0, sizeof param_ipv6);
        mask_ipv6.normal_mode.dev_ip_v6.dns = 1;
        snprintf(param_ipv6.normal_mode.dev_ip_v6.dns, sizeof param_ipv6.normal_mode.dev_ip_v6.dns,
                 "%s", addr);
    }
    CheckEsfNetworkManagerSaveParameter(mask, param, kEsfNetworkManagerResultSuccess);

    // For SysAppStateUpdateString() in SysAppCfgStaticSettings
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, property);
    expect_string(__wrap_SysAppStateUpdateString, string, addr);
    will_return(__wrap_SysAppStateUpdateString, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgStaticSettingsIpv6(const char *param)
{
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    UnitTestIpVer ip_ver = UnitTestIPv6;

    // For EsfJsonOpen() in SysAppCfgStaticSettingsIPv6
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // For EsfJsonDeserialize() in SysAppCfgStaticSettingsIPv6
    expect_value(__wrap_EsfJsonDeserialize, handle, esfj_handle);
    expect_string(__wrap_EsfJsonDeserialize, str, param);
    will_return(__wrap_EsfJsonDeserialize, json_value);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    CheckSysAppCfgStaticSettingsIpAddress(ip_ver, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(ip_ver, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(ip_ver, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(ip_ver, esfj_handle, json_value);

    // For EsfJsonClose() in SysAppCfgStaticSettingsIPv6
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgStaticSettingsIpv4(const char *param)
{
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    UnitTestIpVer ip_ver = UnitTestIPv4;

    // For EsfJsonOpen() in SysAppCfgStaticSettingsIPv4
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // For EsfJsonDeserialize() in SysAppCfgStaticSettingsIPv4
    expect_value(__wrap_EsfJsonDeserialize, handle, esfj_handle);
    expect_string(__wrap_EsfJsonDeserialize, str, param);
    will_return(__wrap_EsfJsonDeserialize, json_value);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    CheckSysAppCfgStaticSettingsIpAddress(ip_ver, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(ip_ver, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(ip_ver, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(ip_ver, esfj_handle, json_value);

    // For EsfJsonClose() in SysAppCfgStaticSettingsIPv4
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgProxySettingsProxyUrl(EsfJsonHandle handle, EsfJsonValue parent)
{
    static EsfNetworkManagerParameterMask mask = {};
    static EsfNetworkManagerParameter param = {};
    const char *proxy_url = "192.168.0.200";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    // For SysAppCmnExtractStringValue() in SysAppCfgStaModeSetting
    ForSysAppCmnExtractStringValue(handle, parent, "proxy_url", proxy_url, 1);

    // For EsfNetworkManagerLoadParameter() in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, "old_proxy_domain");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For EsfNetworkManagerSaveParameter() in SysAppCfgStaModeSetting
    memset(&mask, 0, sizeof mask);
    mask.proxy.url = 1;
    memset(&param, 0, sizeof param);
    snprintf(param.proxy.url, sizeof param.proxy.url, "%s", proxy_url);
    CheckEsfNetworkManagerSaveParameter(&mask, &param, kEsfNetworkManagerResultSuccess);

    // For SysAppStateUpdateString() in SysAppCfgStaModeSetting
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, ProxyUrl);
    expect_string(__wrap_SysAppStateUpdateString, string, proxy_url);
    will_return(__wrap_SysAppStateUpdateString, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgProxySettingsProxyPort(EsfJsonHandle handle, EsfJsonValue parent)
{
    static EsfNetworkManagerParameterMask mask = {};
    static EsfNetworkManagerParameter param = {};
    int proxy_port = 12345;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    // For SysAppCmnExtractNumberValue() in SysAppCfgProxySettings
    ForSysAppCmnExtractNumberValue(handle, parent, "proxy_port", proxy_port, 1);

    // For EsfNetworkManagerLoadParameter() in CheckUpdateNumber
    will_return(__wrap_EsfNetworkManagerLoadParameter, 0);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For EsfNetworkManagerSaveParameter() in ProxySettings
    memset(&mask, 0, sizeof mask);
    mask.proxy.port = 1;
    memset(&param, 0, sizeof param);
    param.proxy.port = proxy_port;
    CheckEsfNetworkManagerSaveParameter(&mask, &param, kEsfNetworkManagerResultSuccess);

    // For SysAppStateUpdateNumber() in ProxySettings
    expect_value(__wrap_SysAppStateUpdateNumber, topic, topic);
    expect_value(__wrap_SysAppStateUpdateNumber, type, ProxyPort);
    expect_value(__wrap_SysAppStateUpdateNumber, number, proxy_port);
    will_return(__wrap_SysAppStateUpdateNumber, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgProxySettingsProxyUserName(EsfJsonHandle handle, EsfJsonValue parent)
{
    static EsfNetworkManagerParameterMask mask = {};
    static EsfNetworkManagerParameter param = {};
    const char *proxy_user_name = "proxy_user_name";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    // For SysAppCmnExtractStringValue() in SysAppCfgStaModeSetting
    ForSysAppCmnExtractStringValue(handle, parent, "proxy_user_name", proxy_user_name, 1);

    // For EsfNetworkManagerLoadParameter() in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, "old_proxy_user_name");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For EsfNetworkManagerSaveParameter() in SysAppCfgStaModeSetting
    memset(&mask, 0, sizeof mask);
    mask.proxy.username = 1;
    memset(&param, 0, sizeof param);
    snprintf(param.proxy.username, sizeof param.proxy.username, "%s", proxy_user_name);
    CheckEsfNetworkManagerSaveParameter(&mask, &param, kEsfNetworkManagerResultSuccess);

    // For SysAppStateUpdateString() in SysAppCfgStaModeSetting
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, ProxyUserName);
    expect_string(__wrap_SysAppStateUpdateString, string, proxy_user_name);
    will_return(__wrap_SysAppStateUpdateString, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgProxySettingsProxyPassword(EsfJsonHandle handle, EsfJsonValue parent)
{
    static EsfNetworkManagerParameterMask mask = {};
    static EsfNetworkManagerParameter param = {};
    const char *proxy_password = "proxy_password";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    // For SysAppCmnExtractStringValue() in SysAppCfgStaModeSetting
    ForSysAppCmnExtractStringValue(handle, parent, "proxy_password", proxy_password, 1);

    // For EsfNetworkManagerLoadParameter() in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, "old_proxy_password");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For EsfNetworkManagerSaveParameter() in SysAppCfgStaModeSetting
    memset(&mask, 0, sizeof mask);
    mask.proxy.password = 1;
    memset(&param, 0, sizeof param);
    snprintf(param.proxy.password, sizeof param.proxy.password, "%s", proxy_password);
    CheckEsfNetworkManagerSaveParameter(&mask, &param, kEsfNetworkManagerResultSuccess);

    // For SysAppStateUpdateString() in SysAppCfgStaModeSetting
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, ProxyPassword);
    expect_string(__wrap_SysAppStateUpdateString, string, proxy_password);
    will_return(__wrap_SysAppStateUpdateString, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgProxySettings(const char *param)
{
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    CheckJsonOpen(esfj_handle, json_value, param);

    CheckSysAppCfgProxySettingsProxyUrl(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPort(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyUserName(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPassword(esfj_handle, json_value);

    // For EsfJsonClose() in SysAppCfgProxySettings
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgNetworkSettingsReqId(EsfJsonHandle handle, EsfJsonValue parent)
{
    const char *req_id = "1";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, parent);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // For SysAppStateGetReqId() about req_id in CheckUpdateString
    expect_value(__wrap_SysAppStateGetReqId, topic, topic);
    will_return(__wrap_SysAppStateGetReqId, "0");

    // For SysAppStateUpdateString() about req_id
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, Id);
    expect_string(__wrap_SysAppStateUpdateString, string, req_id);
    will_return(__wrap_SysAppStateUpdateString, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgNetworkSettingsNtpUrl(EsfJsonHandle handle, EsfJsonValue parent)
{
    const char *ntp_url = "ntp-domain.jp";

    // For SysAppCmnExtractStringValue()
    ForSysAppCmnExtractStringValue(handle, parent, "ntp_url", ntp_url, 1);

    // For EsfClockManagerGetParams() about ntp_url in CheckUpdateString
    ForEsfClockManagerGetParams("old-ntp-domain.jp", kClockManagerSuccess);

    // For EsfClockManagerSetParamsForcibly()
    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, ntp_url);
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    // For EsfClockManagerGetParams() about ntp_url in Reread after write
    ForEsfClockManagerGetParams("ntp-domain.jp", kClockManagerSuccess);

    // For SysAppStateUpdateString() about ntp_url
    expect_value(__wrap_SysAppStateUpdateString, topic, ST_TOPIC_NETWORK_SETTINGS);
    expect_value(__wrap_SysAppStateUpdateString, type, NtpUrl);
    expect_string(__wrap_SysAppStateUpdateString, string, ntp_url);
    will_return(__wrap_SysAppStateUpdateString, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgNetworkSettingsIpv6(EsfJsonHandle handle, EsfJsonValue parent,
                                              const char *serialized)
{
    EsfJsonValue value = ESF_JSON_VALUE_INVALID;

    // For EsfJsonObjectGet() about ipv6
    expect_value(__wrap_EsfJsonObjectGet, handle, handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent);
    expect_string(__wrap_EsfJsonObjectGet, key, "static_settings_ipv6");
    will_return(__wrap_EsfJsonObjectGet, value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // For EsfJsonValueTypeGet() about ipv6
    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeObject);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // For EsfJsonSerialize() about ipv6
    ForEsfJsonSerialize(handle, value, serialized, kEsfJsonSuccess);

    // For EsfJsonSerializeFree() about ipv6
    ForEsfJsonSerializeFree(handle, kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgNetworkSettingsIpv4(EsfJsonHandle handle, EsfJsonValue parent,
                                              const char *serialized)
{
    EsfJsonValue value = ESF_JSON_VALUE_INVALID;

    // For EsfJsonObjectGet() about ipv4
    expect_value(__wrap_EsfJsonObjectGet, handle, handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent);
    expect_string(__wrap_EsfJsonObjectGet, key, "static_settings_ipv4");
    will_return(__wrap_EsfJsonObjectGet, value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // For EsfJsonValueTypeGet() about ipv4
    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeObject);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // For EsfJsonSerialize() about ipv4
    ForEsfJsonSerialize(handle, value, serialized, kEsfJsonSuccess);

    // For EsfJsonSerializeFree() about ipv4
    ForEsfJsonSerializeFree(handle, kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgNetworkSettingsProxySettings(EsfJsonHandle handle, EsfJsonValue parent,
                                                       const char *serialized)
{
    EsfJsonValue value = ESF_JSON_VALUE_INVALID;

    // For EsfJsonObjectGet() about proxy_settings
    expect_value(__wrap_EsfJsonObjectGet, handle, handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent);
    expect_string(__wrap_EsfJsonObjectGet, key, "proxy_settings");
    will_return(__wrap_EsfJsonObjectGet, value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // For EsfJsonValueTypeGet() about proxy_settings
    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeObject);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // For EsfJsonSerialize() about proxy_settings
    ForEsfJsonSerialize(handle, value, serialized, kEsfJsonSuccess);

    // For EsfJsonSerializeFree() about proxy_settings
    ForEsfJsonSerializeFree(handle, kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
static void ForExistStaticIPv4InFlash(void)
{
    // For calloc
    ForCalloc(1, sizeof(EsfNetworkManagerParameter));
    ForFree();

    // For EsfNetworkManagerLoadParameter()
    will_return(__wrap_EsfNetworkManagerLoadParameter, "192.168.0.100");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "255.255.255.0");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "192.168.0.1");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "192.168.0.1");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);
}

/*----------------------------------------------------------------------------*/
static void ForExistStaticIPv4InFlash_ErrorMalloc(void)
{
    // For calloc
    will_return(mock_calloc, false);
    will_return(mock_calloc, false);
}

/*----------------------------------------------------------------------------*/
static void ForExistStaticIPv4InFlash_NotIP(void)
{
    // For calloc
    ForCalloc(1, sizeof(EsfNetworkManagerParameter));
    ForFree();

    // For EsfNetworkManagerLoadParameter()
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "255.255.255.0");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "192.168.0.1");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "192.168.0.1");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);
}

/*----------------------------------------------------------------------------*/
static void ForExistStaticIPv4InFlash_NotSubnetmask(void)
{
    // For calloc
    ForCalloc(1, sizeof(EsfNetworkManagerParameter));
    ForFree();

    // For EsfNetworkManagerLoadParameter()
    will_return(__wrap_EsfNetworkManagerLoadParameter, "192.168.0.1");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "192.168.0.1");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "192.168.0.1");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);
}

/*----------------------------------------------------------------------------*/
static void ForExistStaticIPv4InFlash_NotGateway(void)
{
    // For calloc
    ForCalloc(1, sizeof(EsfNetworkManagerParameter));
    ForFree();

    // For EsfNetworkManagerLoadParameter()
    will_return(__wrap_EsfNetworkManagerLoadParameter, "192.168.0.1");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "255.255.255.0");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "192.168.0.1");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);
}

/*----------------------------------------------------------------------------*/
static void ForExistStaticIPv4InFlash_NotDNS(void)
{
    // For calloc
    ForCalloc(1, sizeof(EsfNetworkManagerParameter));
    ForFree();

    // For EsfNetworkManagerLoadParameter()
    will_return(__wrap_EsfNetworkManagerLoadParameter, "192.168.0.1");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "255.255.255.0");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "192.168.0.1");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);
}

/*----------------------------------------------------------------------------*/
static void ForExistStaticIPv4InFlash_ErrorEsfNetworkManagerLoadParameter(void)
{
    // For calloc
    ForCalloc(1, sizeof(EsfNetworkManagerParameter));
    ForFree();

    // For EsfNetworkManagerLoadParameter()
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "255.255.255.0");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "192.168.0.1");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "192.168.0.1");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultInternalError);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgNetworkSettingsUpdateIpMethod(int old_ip_method, int new_ip_method)
{
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    // For EsfNetworkManagerLoadParameter() in CheckUpdateNumber
    will_return(__wrap_EsfNetworkManagerLoadParameter, old_ip_method);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    ForEsfNetworkManagerSaveParameterIpMethod(new_ip_method, kEsfNetworkManagerResultSuccess);

    // For SysAppStateUpdateNumber()
    expect_value(__wrap_SysAppStateUpdateNumber, topic, topic);
    expect_value(__wrap_SysAppStateUpdateNumber, type, IpMethod);
    expect_value(__wrap_SysAppStateUpdateNumber, number, new_ip_method);
    will_return(__wrap_SysAppStateUpdateNumber, kRetOk);

    // For EsfNetworkManagerLoadParameter()
    will_return(__wrap_EsfNetworkManagerLoadParameter, new_ip_method);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgPeriodicSettingReqId(EsfJsonHandle handle, EsfJsonValue parent)
{
    const char *req_id = "1";
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, parent);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // For SysAppStateGetReqId() about req_id in CheckUpdateString
    expect_value(__wrap_SysAppStateGetReqId, topic, topic);
    will_return(__wrap_SysAppStateGetReqId, "0");

    // For SysAppStateUpdateString() about req_id
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, Id);
    expect_string(__wrap_SysAppStateUpdateString, string, req_id);
    will_return(__wrap_SysAppStateUpdateString, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckIntervalNumProperty(EsfJsonHandle handle, EsfJsonValue parent, int index,
                                     const char *prop_name, uint32_t type, int new_value,
                                     int old_value __attribute__((unused)))
{
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(handle, parent, prop_name, new_value, 1);

    ForSysAppStateUpdateNumberWithIdx(topic, type, new_value, index, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckIntervalStrProperty(EsfJsonHandle handle, EsfJsonValue parent, int index,
                                     const char *prop_name, uint32_t type, const char *new_value,
                                     const char *old_value __attribute__((unused)))
{
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    // For SysAppCmnExtractStringValue()
    ForSysAppCmnExtractStringValue(handle, parent, prop_name, new_value, 1);

    ForSysAppStateUpdateStringWithIdx(topic, type, new_value, index, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckPeriodicNumProperty(EsfJsonHandle handle, EsfJsonValue parent,
                                     const char *prop_name, uint32_t type, int new_value,
                                     int old_value __attribute__((unused)))
{
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(handle, parent, prop_name, new_value, 1);

    // For SysAppStateUpdateNumber()
    expect_value(__wrap_SysAppStateUpdateNumber, topic, topic);
    expect_value(__wrap_SysAppStateUpdateNumber, type, type);
    expect_value(__wrap_SysAppStateUpdateNumber, number, new_value);
    will_return(__wrap_SysAppStateUpdateNumber, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckPeriodicStrProperty(EsfJsonHandle handle, EsfJsonValue parent,
                                     const char *prop_name, uint32_t type, const char *new_value,
                                     const char *old_value __attribute__((unused)))
{
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    // For SysAppCmnExtractStringValue()
    ForSysAppCmnExtractStringValue(handle, parent, prop_name, new_value, 1);

    // For SysAppStateUpdateString()
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, type);
    expect_value(__wrap_SysAppStateUpdateString, string, new_value);
    will_return(__wrap_SysAppStateUpdateString, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgIntervalSetting(const char *param, int index)
{
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    // in SysAppCfgIntervalSetting
    CheckJsonOpen(esfj_handle, json_value, param);

    // in SysAppCfgIntervalSetting
    CheckIntervalStrProperty(esfj_handle, json_value, index, "base_time", BaseTime, "00:00", "");

    // in SysAppCfgIntervalSetting
    CheckIntervalNumProperty(esfj_handle, json_value, index, "capture_interval", CaptureInterval, 3,
                             4);

    // in SysAppCfgIntervalSetting
    CheckIntervalNumProperty(esfj_handle, json_value, index, "config_interval", ConfigInterval, 5,
                             6);

    // For EsfJsonClose() in SysAppCfgIntervalSetting
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgPeriodicSettingIntervalSettings(EsfJsonHandle handle, EsfJsonValue parent,
                                                          const char *serialized)
{
    EsfJsonValue value = ESF_JSON_VALUE_INVALID;

    // For EsfJsonObjectGet()
    expect_value(__wrap_EsfJsonObjectGet, handle, handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent);
    expect_string(__wrap_EsfJsonObjectGet, key, "interval_settings");
    will_return(__wrap_EsfJsonObjectGet, value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // For EsfJsonValueTypeGet()
    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeArray);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // For EsfJsonArrayCount()
    expect_value(__wrap_EsfJsonArrayCount, handle, handle);
    expect_value(__wrap_EsfJsonArrayCount, parent, value);
    will_return(__wrap_EsfJsonArrayCount, 1U);

    ForEsfJsonArrayGet(handle, value, 0U, value, kEsfJsonSuccess);

    // For EsfJsonSerialize()
    ForEsfJsonSerialize(handle, value, serialized, kEsfJsonSuccess);

    // For EsfJsonSerializeFree()
    ForEsfJsonSerializeFree(handle, kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgWirelessSettingReqId(EsfJsonHandle handle, EsfJsonValue parent)
{
    const char *req_id = "1";
    uint32_t topic = ST_TOPIC_WIRELESS_SETTING;

    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, parent);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // For SysAppStateGetReqId()
    expect_value(__wrap_SysAppStateGetReqId, topic, topic);
    will_return(__wrap_SysAppStateGetReqId, "0");

    // For SysAppStateUpdateString()
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, Id);
    expect_string(__wrap_SysAppStateUpdateString, string, req_id);
    will_return(__wrap_SysAppStateUpdateString, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgWirelessSettingPropertyStaModeSetting(EsfJsonHandle handle,
                                                                EsfJsonValue parent,
                                                                const char *serialized)
{
    EsfJsonValue value = ESF_JSON_VALUE_INVALID;

    // For EsfJsonObjectGet()
    expect_value(__wrap_EsfJsonObjectGet, handle, handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent);
    expect_string(__wrap_EsfJsonObjectGet, key, "sta_mode_setting");
    will_return(__wrap_EsfJsonObjectGet, value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // For EsfJsonValueTypeGet()
    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeObject);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    ForEsfJsonSerialize(handle, value, serialized, kEsfJsonSuccess);

    ForEsfJsonSerializeFree(handle, kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
static void CheckWirelessSettingStaModeSettingSsid(EsfJsonHandle handle, EsfJsonValue parent,
                                                   EsfNetworkManagerParameterMask *ssid_mask,
                                                   EsfNetworkManagerParameter *ssid_param,
                                                   const char *ssid)
{
    uint32_t topic = ST_TOPIC_WIRELESS_SETTING;

    assert_non_null(ssid);
    if (!ssid) {
        return;
    }

    // For SysAppCmnExtractStringValue() about ssid in SysAppCfgStaModeSetting
    ForSysAppCmnExtractStringValue(handle, parent, "ssid", ssid, 1);

    // For EsfNetworkManagerLoadParameter() about ssid in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, "SSID");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For EsfNetworkManagerSaveParameter() about ssid in SysAppCfgStaModeSetting
    memset(ssid_mask, 0, sizeof *ssid_mask);
    ssid_mask->normal_mode.wifi_sta.ssid = 1;
    memset(ssid_param, 0, sizeof *ssid_param);
    snprintf(ssid_param->normal_mode.wifi_sta.ssid, sizeof ssid_param->normal_mode.wifi_sta.ssid,
             "%s", ssid);
    CheckEsfNetworkManagerSaveParameter(ssid_mask, ssid_param, kEsfNetworkManagerResultSuccess);

    // For SysAppStateUpdateString() about ssid in SysAppCfgStaModeSetting
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, StaSsid);
    expect_string(__wrap_SysAppStateUpdateString, string, ssid);
    will_return(__wrap_SysAppStateUpdateString, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckWirelessSettingStaModeSettingPassword(
    EsfJsonHandle handle, EsfJsonValue parent, EsfNetworkManagerParameterMask *password_mask,
    EsfNetworkManagerParameter *password_param, const char *password)
{
    uint32_t topic = ST_TOPIC_WIRELESS_SETTING;

    assert_non_null(password);
    if (!password) {
        return;
    }

    // For SysAppCmnExtractStringValue() about password in SysAppCfgStaModeSetting
    ForSysAppCmnExtractStringValue(handle, parent, "password", password, 1);

    // For EsfNetworkManagerLoadParameter() about password in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, "PASSWORD");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For EsfNetworkManagerSaveParameter() about password in SysAppCfgStaModeSetting
    memset(password_mask, 0, sizeof *password_mask);
    password_mask->normal_mode.wifi_sta.password = 1;
    memset(password_param, 0, sizeof *password_param);
    snprintf(password_param->normal_mode.wifi_sta.password,
             sizeof password_param->normal_mode.wifi_sta.password, "%s", password);
    CheckEsfNetworkManagerSaveParameter(password_mask, password_param,
                                        kEsfNetworkManagerResultSuccess);

    // For SysAppStateUpdateString() about password in SysAppCfgStaModeSetting
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, StaPassword);
    expect_string(__wrap_SysAppStateUpdateString, string, password);
    will_return(__wrap_SysAppStateUpdateString, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckWirelessSettingStaModeSettingEncryption(
    EsfJsonHandle handle, EsfJsonValue parent, EsfNetworkManagerParameterMask *encryption_mask,
    EsfNetworkManagerParameter *encryption_param)
{
    uint32_t topic = ST_TOPIC_WIRELESS_SETTING;
    int encryption = EncWpa2Psk;

    // For SysAppCmnExtractNumberValue() about encryption in SysAppCfgStaModeSetting
    ForSysAppCmnExtractNumberValue(handle, parent, "encryption", encryption, 1);

    // For EsfNetworkManagerLoadParameter() about encryption in CheckUpdateNumber
    will_return(__wrap_EsfNetworkManagerLoadParameter, EncWpa3Psk);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For EsfNetworkManagerSaveParameter() about encryption in SysAppCfgStaModeSetting
    memset(encryption_mask, 0, sizeof *encryption_mask);
    encryption_mask->normal_mode.wifi_sta.encryption = 1;
    memset(encryption_param, 0, sizeof *encryption_param);
    encryption_param->normal_mode.wifi_sta.encryption = encryption;
    CheckEsfNetworkManagerSaveParameter(encryption_mask, encryption_param,
                                        kEsfNetworkManagerResultSuccess);

    // For SysAppStateUpdateNumber() about encryption in SysAppCfgStaModeSetting
    expect_value(__wrap_SysAppStateUpdateNumber, topic, topic);
    expect_value(__wrap_SysAppStateUpdateNumber, type, StaEncryption);
    expect_value(__wrap_SysAppStateUpdateNumber, number, encryption);
    will_return(__wrap_SysAppStateUpdateNumber, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgWirelessSettingSysAppCfgStaModeSetting(
    const char *param, EsfNetworkManagerParameterMask *ssid_mask,
    EsfNetworkManagerParameter *ssid_param, EsfNetworkManagerParameterMask *password_mask,
    EsfNetworkManagerParameter *password_param, EsfNetworkManagerParameterMask *encryption_mask,
    EsfNetworkManagerParameter *encryption_param)
{
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    uint32_t topic = ST_TOPIC_WIRELESS_SETTING;
    EsfJsonValue value = ESF_JSON_VALUE_INVALID;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "WIRELESS SETTING PASSWORD";
    int encryption = EncWpa2Psk;

    // in SysAppCfgStaModeSetting
    CheckJsonOpen(esfj_handle, value, param);

    // For SysAppCmnExtractStringValue() about ssid in SysAppCfgStaModeSetting
    ForSysAppCmnExtractStringValue(esfj_handle, value, "ssid", ssid, 1);

    // For EsfNetworkManagerLoadParameter() about ssid in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, "SSID");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For EsfNetworkManagerSaveParameter() about ssid in SysAppCfgStaModeSetting
    memset(ssid_mask, 0, sizeof *ssid_mask);
    ssid_mask->normal_mode.wifi_sta.ssid = 1;
    memset(ssid_param, 0, sizeof *ssid_param);
    snprintf(ssid_param->normal_mode.wifi_sta.ssid, sizeof ssid_param->normal_mode.wifi_sta.ssid,
             "%s", ssid);
    CheckEsfNetworkManagerSaveParameter(ssid_mask, ssid_param, kEsfNetworkManagerResultSuccess);

    // For SysAppStateUpdateString() about ssid in SysAppCfgStaModeSetting
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, StaSsid);
    expect_string(__wrap_SysAppStateUpdateString, string, ssid);
    will_return(__wrap_SysAppStateUpdateString, kRetOk);

    // For SysAppCmnExtractStringValue() about password in SysAppCfgStaModeSetting
    ForSysAppCmnExtractStringValue(esfj_handle, value, "password", password, 1);

    // For EsfNetworkManagerLoadParameter() about password in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, "PASSWORD");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For EsfNetworkManagerSaveParameter() about password in SysAppCfgStaModeSetting
    memset(password_mask, 0, sizeof *password_mask);
    password_mask->normal_mode.wifi_sta.password = 1;
    memset(password_param, 0, sizeof *password_param);
    snprintf(password_param->normal_mode.wifi_sta.password,
             sizeof password_param->normal_mode.wifi_sta.password, "%s", password);
    CheckEsfNetworkManagerSaveParameter(password_mask, password_param,
                                        kEsfNetworkManagerResultSuccess);

    // For SysAppStateUpdateString() about password in SysAppCfgStaModeSetting
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, StaPassword);
    expect_string(__wrap_SysAppStateUpdateString, string, password);
    will_return(__wrap_SysAppStateUpdateString, kRetOk);

    // For SysAppCmnExtractNumberValue() about encryption in SysAppCfgStaModeSetting
    ForSysAppCmnExtractNumberValue(esfj_handle, value, "encryption", encryption, 1);

    // For EsfNetworkManagerLoadParameter() about encryption in CheckUpdateNumber
    will_return(__wrap_EsfNetworkManagerLoadParameter, EncWpa3Psk);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For EsfNetworkManagerSaveParameter() about encryption in SysAppCfgStaModeSetting
    memset(encryption_mask, 0, sizeof *encryption_mask);
    encryption_mask->normal_mode.wifi_sta.encryption = 1;
    memset(encryption_param, 0, sizeof *encryption_param);
    encryption_param->normal_mode.wifi_sta.encryption = encryption;
    CheckEsfNetworkManagerSaveParameter(encryption_mask, encryption_param,
                                        kEsfNetworkManagerResultSuccess);

    // For SysAppStateUpdateNumber() about encryption in SysAppCfgStaModeSetting
    expect_value(__wrap_SysAppStateUpdateNumber, topic, topic);
    expect_value(__wrap_SysAppStateUpdateNumber, type, StaEncryption);
    expect_value(__wrap_SysAppStateUpdateNumber, number, encryption);
    will_return(__wrap_SysAppStateUpdateNumber, kRetOk);

    // For EsfJsonClose() in SysAppCfgStaModeSetting
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgEndpointSettingsReqId(EsfJsonHandle handle, EsfJsonValue parent)
{
    const char *req_id = "1";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, parent);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // For SysAppStateGetReqId() in CheckUpdateString
    expect_value(__wrap_SysAppStateGetReqId, topic, topic);
    will_return(__wrap_SysAppStateGetReqId, "0");

    // For SysAppStateUpdateString()
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, Id);
    expect_string(__wrap_SysAppStateUpdateString, string, req_id);
    will_return(__wrap_SysAppStateUpdateString, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckClearEnrollmentData(void)
{
    // For EsfSystemManagerSetProjectId()
    expect_string(__wrap_EsfSystemManagerSetProjectId, data, "");
    expect_value(__wrap_EsfSystemManagerSetProjectId, data_size, 1U);
    will_return(__wrap_EsfSystemManagerSetProjectId, kEsfSystemManagerResultOk);

    // For EsfSystemManagerSetRegisterToken()
    expect_string(__wrap_EsfSystemManagerSetRegisterToken, data, "");
    expect_value(__wrap_EsfSystemManagerSetRegisterToken, data_size, 1U);
    will_return(__wrap_EsfSystemManagerSetRegisterToken, kEsfSystemManagerResultOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgEndpointSettingsUrlBackup(const char *url)
{
    ForMalloc(ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    ForEsfSystemManagerGetEvpHubUrl(url, kEsfSystemManagerResultOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgEndpointSettingsPortBackup(const char *port)
{
    ForMalloc(ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    ForEsfSystemManagerGetEvpHubPort(port, kEsfSystemManagerResultOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgEndpointSettingsEndpointUrl(EsfJsonHandle handle, EsfJsonValue parent)
{
    const char *endpoint_url = "endpoint-url.com";
    size_t url_len = strlen(endpoint_url) + 1U;
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    // For SysAppCmnExtractStringValue()
    ForSysAppCmnExtractStringValue(handle, parent, "endpoint_url", endpoint_url, 1);

    // For malloc() of CheckUpdateString
    ForMalloc(ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // For EsfSystemManagerGetEvpHubUrl() in CheckUpdateString
    ForEsfSystemManagerGetEvpHubUrl("", kEsfSystemManagerResultOk);

    // For free() of CheckUpdateString
    ForFree();

    // For EsfSystemManagerSetEvpHubUrl()
    expect_string(__wrap_EsfSystemManagerSetEvpHubUrl, data, endpoint_url);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size, url_len);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    // For SysAppStateUpdateString()
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, EndpointUrl);
    expect_string(__wrap_SysAppStateUpdateString, string, endpoint_url);
    will_return(__wrap_SysAppStateUpdateString, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgEndpointSettingsEndpointPort(EsfJsonHandle handle, EsfJsonValue parent)
{
    int endpoint_port = 1;
    const char *endpoint_port_str = "1";
    size_t port_str_len = strlen(endpoint_port_str) + 1U;
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(handle, parent, "endpoint_port", endpoint_port, 1);

    ForMalloc(ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // For malloc() of CheckUpdateString
    ForMalloc(ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // For EsfSystemManagerGetEvpHubPort() in CheckUpdateString
    ForEsfSystemManagerGetEvpHubPort("0", kEsfSystemManagerResultOk);

    // For free() of CheckUpdateString
    ForFree();

    // For EsfSystemManagerSetEvpHubPort()
    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, endpoint_port_str);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size, port_str_len);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    // For SysAppStateUpdateNumber()
    expect_value(__wrap_SysAppStateUpdateNumber, topic, topic);
    expect_value(__wrap_SysAppStateUpdateNumber, type, EndpointPort);
    expect_value(__wrap_SysAppStateUpdateNumber, number, endpoint_port);
    will_return(__wrap_SysAppStateUpdateNumber, kRetOk);

    ForFree();
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgEndpointSettingsProtocolVersion(EsfJsonHandle handle, EsfJsonValue parent)
{
    const char *protocol_version = "TB";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    // For SysAppCmnExtractStringValue()
    ForSysAppCmnExtractStringValue(handle, parent, "protocol_version", protocol_version, 1);

    // For SysAppStateGetProtocolVersion() in CheckUpdateString
    will_return(__wrap_SysAppStateGetProtocolVersion, "");

    // For SysAppStateUpdateString()
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, ProtocolVersion);
    expect_string(__wrap_SysAppStateUpdateString, string, protocol_version);
    will_return(__wrap_SysAppStateUpdateString, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgEndpointSettingsRevert(const char *url, const char *port)
{
    size_t url_len = strlen(url);
    size_t port_len = strlen(port);

    // For EsfSystemManagerSetEvpHubUrl() about endpoint_url
    expect_string(__wrap_EsfSystemManagerSetEvpHubUrl, data, url);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size, url_len);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    // For EsfSystemManagerSetEvpHubPort() about endpoint_port
    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, port);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size, port_len);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);
}

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
/*----------------------------------------------------------------------------*/
static void CheckSysAppCfgEProcessUnimplementedConfigurationSuccess(const char *param)
{
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    // SysAppStateIsUnimplementedTopic
    will_return(__wrap_SysAppStateIsUnimplementedTopic, true);

    CheckJsonOpen(esfj_handle, json_value, param);

    // SysAppCmnGetReqId
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, param);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // SysAppStateSendUnimplementedState
    will_return(__wrap_SysAppStateSendUnimplementedState, kRetOk);

    // EsfJsonClose
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
}
#endif // !CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION

/*----------------------------------------------------------------------------*/

//
// Initial value check for static global variable
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCfg_InitialValueOfGlobalVariable(void **state)
{
    assert_null(s_sys_client);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCfgInitialize()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgInitialize_FullySuccess(void **state)
{
    RetCode ret;
    struct SYS_client *expect_evp_client = (struct SYS_client *)0x12345678;

    // For SYS_set_configuration_cb()
    ForSysSetConfigurationCb(expect_evp_client, "system_settings", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "network_settings", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "periodic_setting", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "wireless_setting", SYS_RESULT_OK);
#if defined(CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING)
    ForSysSetConfigurationCb(expect_evp_client, "streaming_settings", SYS_RESULT_OK);
#endif /* CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING */
    ForSysSetConfigurationCb(expect_evp_client, "PRIVATE_endpoint_settings", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "PRIVATE_deploy_firmware", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "PRIVATE_deploy_ai_model", SYS_RESULT_OK);

    // Exec test target
    ret = SysAppCfgInitialize(expect_evp_client);

    // Check return value and global variable
    assert_int_equal(ret, kRetOk);
    assert_int_equal(s_sys_client, expect_evp_client);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgInitialize_ErrorSysClientNull(void **state)
{
    RetCode ret;

    // Exec test target
    ret = SysAppCfgInitialize(NULL);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgInitialize_ErrorSysSetConfigurationCbSystemSettings(void **state)
{
    RetCode ret;
    struct SYS_client *expect_evp_client = (struct SYS_client *)0x23456789;

    // For SYS_set_configuration_cb()
    ForSysSetConfigurationCb(expect_evp_client, "system_settings",
                             SYS_RESULT_ERROR_ALREADY_REGISTERED);

    // Exec test target
    ret = SysAppCfgInitialize(expect_evp_client);

    // Check return value and global variable
    assert_int_equal(ret, kRetFailed);
    assert_int_equal(s_sys_client, expect_evp_client);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgInitialize_ErrorSysSetConfigurationCbNetworkSettings(void **state)
{
    RetCode ret;
    struct SYS_client *expect_evp_client = (struct SYS_client *)0x34567890;

    // For SYS_set_configuration_cb()
    ForSysSetConfigurationCb(expect_evp_client, "system_settings", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "network_settings",
                             SYS_RESULT_ERROR_ALREADY_REGISTERED);

    // Exec test target
    ret = SysAppCfgInitialize(expect_evp_client);

    // Check return value and global variable
    assert_int_equal(ret, kRetFailed);
    assert_int_equal(s_sys_client, expect_evp_client);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgInitialize_ErrorSysSetConfigurationCbPeriodicSetting(void **state)
{
    RetCode ret;
    struct SYS_client *expect_evp_client = (struct SYS_client *)0x45678901;

    // For SYS_set_configuration_cb()
    ForSysSetConfigurationCb(expect_evp_client, "system_settings", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "network_settings", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "periodic_setting",
                             SYS_RESULT_ERROR_ALREADY_REGISTERED);

    // Exec test target
    ret = SysAppCfgInitialize(expect_evp_client);

    // Check return value and global variable
    assert_int_equal(ret, kRetFailed);
    assert_int_equal(s_sys_client, expect_evp_client);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgInitialize_ErrorSysSetConfigurationCbWirelessSetting(void **state)
{
    RetCode ret;
    struct SYS_client *expect_evp_client = (struct SYS_client *)0x56789012;

    // For SYS_set_configuration_cb()
    ForSysSetConfigurationCb(expect_evp_client, "system_settings", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "network_settings", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "periodic_setting", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "wireless_setting",
                             SYS_RESULT_ERROR_ALREADY_REGISTERED);

    // Exec test target
    ret = SysAppCfgInitialize(expect_evp_client);

    // Check return value and global variable
    assert_int_equal(ret, kRetFailed);
    assert_int_equal(s_sys_client, expect_evp_client);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgInitialize_ErrorSysSetConfigurationCbPrivateEndpointSettings(void **state)
{
    RetCode ret;
    struct SYS_client *expect_evp_client = (struct SYS_client *)0x67890123;

    // For SYS_set_configuration_cb()
    ForSysSetConfigurationCb(expect_evp_client, "system_settings", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "network_settings", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "periodic_setting", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "wireless_setting", SYS_RESULT_OK);
#if defined(CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING)
    ForSysSetConfigurationCb(expect_evp_client, "streaming_settings", SYS_RESULT_OK);
#endif /* CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING */
    ForSysSetConfigurationCb(expect_evp_client, "PRIVATE_endpoint_settings",
                             SYS_RESULT_ERROR_ALREADY_REGISTERED);

    // Exec test target
    ret = SysAppCfgInitialize(expect_evp_client);

    // Check return value and global variable
    assert_int_equal(ret, kRetFailed);
    assert_int_equal(s_sys_client, expect_evp_client);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgInitialize_ErrorSysSetConfigurationCbPrivateDeployFirmware(void **state)
{
    RetCode ret;
    struct SYS_client *expect_evp_client = (struct SYS_client *)0x78901234;

    // For SYS_set_configuration_cb()
    ForSysSetConfigurationCb(expect_evp_client, "system_settings", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "network_settings", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "periodic_setting", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "wireless_setting", SYS_RESULT_OK);
#if defined(CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING)
    ForSysSetConfigurationCb(expect_evp_client, "streaming_settings", SYS_RESULT_OK);
#endif /* CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING */
    ForSysSetConfigurationCb(expect_evp_client, "PRIVATE_endpoint_settings", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "PRIVATE_deploy_firmware",
                             SYS_RESULT_ERROR_ALREADY_REGISTERED);

    // Exec test target
    ret = SysAppCfgInitialize(expect_evp_client);

    // Check return value and global variable
    assert_int_equal(ret, kRetFailed);
    assert_int_equal(s_sys_client, expect_evp_client);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgInitialize_ErrorSysSetConfigurationCbPrivateDeployAiModel(void **state)
{
    RetCode ret;
    struct SYS_client *expect_evp_client = (struct SYS_client *)0x89012345;

    // For SYS_set_configuration_cb()
    ForSysSetConfigurationCb(expect_evp_client, "system_settings", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "network_settings", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "periodic_setting", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "wireless_setting", SYS_RESULT_OK);
#if defined(CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING)
    ForSysSetConfigurationCb(expect_evp_client, "streaming_settings", SYS_RESULT_OK);
#endif /* CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING */
    ForSysSetConfigurationCb(expect_evp_client, "PRIVATE_endpoint_settings", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "PRIVATE_deploy_firmware", SYS_RESULT_OK);
    ForSysSetConfigurationCb(expect_evp_client, "PRIVATE_deploy_ai_model",
                             SYS_RESULT_ERROR_ALREADY_REGISTERED);

    // Exec test target
    ret = SysAppCfgInitialize(expect_evp_client);

    // Check return value and global variable
    assert_int_equal(ret, kRetFailed);
    assert_int_equal(s_sys_client, expect_evp_client);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCfgFinalize()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgFinalize(void **state)
{
    RetCode ret;

    // Exec test target
    ret = SysAppCfgFinalize();

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/

//
// ConfigurationCallback()
//

/*----------------------------------------------------------------------------*/
static void test_ConfigurationCallback_TopicNull(void **state)
{
    struct SYS_client *expect_evp_client = (struct SYS_client *)0x98765432;
    const char *config = "Topic is null";

    // Exec test target
    ConfigurationCallback(expect_evp_client, NULL, config, SYS_CONFIG_ANY, SYS_REASON_FINISHED,
                          NULL);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConfigurationCallback_ConfigNull(void **state)
{
    struct SYS_client *expect_evp_client = (struct SYS_client *)0x98765432;
    const char *topic = "system_settings";

    // Exec test target
    ConfigurationCallback(expect_evp_client, topic, NULL, SYS_CONFIG_ANY, SYS_REASON_FINISHED,
                          NULL);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConfigurationCallback_SystemSettings(void **state)
{
    struct SYS_client *evp_client = (struct SYS_client *)0x98765432;
    const char *topic = "system_settings";
    const char *config = "system_settings configuration";

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    CheckSysAppCfgEProcessUnimplementedConfigurationSuccess(config);
#else
    // For SysAppCfgSystemSettings()
    CheckSysAppCfgSystemSettingsSuccess(config);
#endif

    // Exec test target
    ConfigurationCallback(evp_client, topic, config, SYS_CONFIG_ANY, SYS_REASON_FINISHED, NULL);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConfigurationCallback_NetworkSettings(void **state)
{
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    struct SYS_client *evp_client = (struct SYS_client *)0x98765432;
    const char *topic = "network_settings";
    const char *config = "network_settings configuration";

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    CheckSysAppCfgEProcessUnimplementedConfigurationSuccess(config);
#else
    // For SysAppCfgNetworkSettings()

    CheckJsonOpen(esfj_handle, json_value, config);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    // For SysAppStateSendState()
    expect_value(__wrap_SysAppStateSendState, req, ST_TOPIC_NETWORK_SETTINGS);
    will_return(__wrap_SysAppStateSendState, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
#endif // CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    ConfigurationCallback(evp_client, topic, config, SYS_CONFIG_ANY, SYS_REASON_FINISHED, NULL);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConfigurationCallback_PeriodicSetting(void **state)
{
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    struct SYS_client *evp_client = (struct SYS_client *)0x98765432;
    const char *topic = "periodic_setting";
    const char *config = "periodic_setting configuration";

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    CheckSysAppCfgEProcessUnimplementedConfigurationSuccess(config);
#else
    CheckJsonOpen(esfj_handle, json_value, config);

    CheckSysAppCfgPeriodicSettingReqId(esfj_handle, json_value);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    CheckSysAppCfgPeriodicSettingIntervalSettings(esfj_handle, json_value, interval_settings);
    CheckSysAppCfgIntervalSetting(interval_settings, 0);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
#endif
    ConfigurationCallback(evp_client, topic, config, SYS_CONFIG_ANY, SYS_REASON_FINISHED, NULL);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConfigurationCallback_WirelessSetting(void **state)
{
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    uint32_t req = ST_TOPIC_WIRELESS_SETTING;
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};
    struct SYS_client *evp_client = (struct SYS_client *)0x98765432;
    const char *topic = "wireless_setting";
    const char *config = "wireless_setting configuration";

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    CheckSysAppCfgEProcessUnimplementedConfigurationSuccess(config);
#else
    CheckJsonOpen(esfj_handle, val, config);

    CheckSysAppCfgWirelessSettingReqId(esfj_handle, val);

    CheckSysAppCfgWirelessSettingPropertyStaModeSetting(esfj_handle, val, sta_mode_setting);

    CheckSysAppCfgWirelessSettingSysAppCfgStaModeSetting(sta_mode_setting, &ssid_mask, &ssid_param,
                                                         &password_mask, &password_param,
                                                         &encryption_mask, &encryption_param);

    CheckJsonClose(esfj_handle, req);
#endif
    ConfigurationCallback(evp_client, topic, config, SYS_CONFIG_ANY, SYS_REASON_FINISHED, NULL);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConfigurationCallback_PrivateEndpointSettings(void **state)
{
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";

    struct SYS_client *evp_client = (struct SYS_client *)0x98765432;
    const char *topic = "PRIVATE_endpoint_settings";
    const char *config = "PRIVATE_endpoint_settings configuration";

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    CheckSysAppCfgEProcessUnimplementedConfigurationSuccess(config);
#else
    CheckJsonOpen(esfj_handle, json_value, config);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);
    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    // For SysAppStateSendState()
    expect_value(__wrap_SysAppStateSendState, req, ST_TOPIC_ENDPOINT_SETTINGS);
    will_return(__wrap_SysAppStateSendState, kRetOk);

    ForFree();
    ForFree();

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
#endif
    // Exec test target
    ConfigurationCallback(evp_client, topic, config, SYS_CONFIG_ANY, SYS_REASON_FINISHED, NULL);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConfigurationCallback_PrivateDeployFirmware(void **state)
{
    struct SYS_client *evp_client = (struct SYS_client *)0x98765432;
    const char *topic = "PRIVATE_deploy_firmware";
    const char *config = "PRIVATE_deploy_firmware configuration";

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    CheckSysAppCfgEProcessUnimplementedConfigurationSuccess(config);
#else
    // For SysAppDeploy()
    expect_string(__wrap_SysAppDeploy, topic, topic);
    expect_string(__wrap_SysAppDeploy, config, config);
    expect_value(__wrap_SysAppDeploy, len, strlen(config));
    will_return(__wrap_SysAppDeploy, kRetOk);
#endif
    // Exec test target
    ConfigurationCallback(evp_client, topic, config, SYS_CONFIG_ANY, SYS_REASON_FINISHED, NULL);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConfigurationCallback_PrivateDeployAiModel(void **state)
{
    struct SYS_client *evp_client = (struct SYS_client *)0x98765432;
    const char *topic = "PRIVATE_deploy_ai_model";
    const char *config = "PRIVATE_deploy_ai_model configuration";

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    CheckSysAppCfgEProcessUnimplementedConfigurationSuccess(config);
#else

    // For SysAppDeploy()
    expect_string(__wrap_SysAppDeploy, topic, topic);
    expect_string(__wrap_SysAppDeploy, config, config);
    expect_value(__wrap_SysAppDeploy, len, strlen(config));
    will_return(__wrap_SysAppDeploy, kRetOk);
#endif
    // Exec test target
    ConfigurationCallback(evp_client, topic, config, SYS_CONFIG_ANY, SYS_REASON_FINISHED, NULL);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConfigurationCallback_PrivateDeploySensorCalibrationParam(void **state)
{
    struct SYS_client *evp_client = (struct SYS_client *)0x98765432;
    const char *topic = "PRIVATE_deploy_sensor_calibration_param";
    const char *config = "PRIVATE_deploy_sensor_calibration_param configuration";

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    CheckSysAppCfgEProcessUnimplementedConfigurationSuccess(config);
#else

    // For SysAppDeploy()
    expect_string(__wrap_SysAppDeploy, topic, topic);
    expect_string(__wrap_SysAppDeploy, config, config);
    expect_value(__wrap_SysAppDeploy, len, strlen(config));
    will_return(__wrap_SysAppDeploy, kRetOk);
#endif
    // Exec test target
    ConfigurationCallback(evp_client, topic, config, SYS_CONFIG_ANY, SYS_REASON_FINISHED, NULL);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConfigurationCallback_OtherTopic(void **state)
{
    struct SYS_client *evp_client = (struct SYS_client *)0x98765432;
    const char *topic = "PRIVATE_DEPLOY_AI_MODEL";
    const char *config = "Not support configuration";

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    will_return(__wrap_SysAppStateIsUnimplementedTopic, false);
#endif

    // Exec test target
    ConfigurationCallback(evp_client, topic, config, SYS_CONFIG_ANY, SYS_REASON_FINISHED, NULL);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCfgLog()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_FullySuccess(void **state)
{
    RetCode ret;
    CheckSysAppCfgSystemSettingsSysAppCfgLog(log_settings);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorEsfJsonOpen(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;

    // CASE: EsfJsonOpen fails.
    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorEsfJsonDeserialize(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // CASE: EsfJsonDeserialize fails.
    // For EsfJsonDeserialize()
    expect_value(__wrap_EsfJsonDeserialize, handle, esfj_handle);
    expect_string(__wrap_EsfJsonDeserialize, str, log_settings);
    will_return(__wrap_EsfJsonDeserialize, json_value);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonInternalError);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorCmnExtractStrFilter(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // CASE: SysAppCmnExtractStringValue fails.
    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, -1);

    // For SysAppStateSetInvalidArgErrorWithIdx()
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, LogFilter, AllLog, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorCmnExtractStrInvalidFilter(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // CASE: SysAppCmnExtractStringValue retrieves zero.
    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 0);

    // For SysAppStateSetInvalidArgErrorWithIdx()
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, LogFilter, AllLog, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorInvalidFilter(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // CASE: SysAppCmnExtractStringValue retrieves an empty string.
    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateSetInvalidArgErrorWithIdx()
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, LogFilter, AllLog, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_FilterAll(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "all";
    uint32_t filter_num = 0U;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // CASE: SysAppCmnExtractStringValue retrieves "all".
    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogIndexZero(esfj_handle, json_value);
    for (uint32_t index = 1U; index < 5U; index++) {
        CheckSysAppCfgLogEach(esfj_handle, json_value, index);
    }

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_FilterSensor(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "sensor";
    uint32_t filter_num = 2U;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // CASE: SysAppCmnExtractStringValue retrieves "sensor".
    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogEach(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_FilterCompanionFirmware(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "companion_fw";
    uint32_t filter_num = 3U;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // CASE: SysAppCmnExtractStringValue retrieves "companion_fw".
    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogEach(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_FilterCompanionApp(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "companion_app";
    uint32_t filter_num = 4U;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // CASE: SysAppCmnExtractStringValue retrieves "companion_app".
    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogEach(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorCmnExtractNumLevel(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t level = CriticalLv;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    // CASE: SysAppCmnExtractNumberValue fails.
    // For SysAppCmnExtractNumberValue() about level
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "level", level, -1);

    CheckSysAppCfgLogDestination(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogStorageName(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogPath(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorCmnExtractNumInvalidLevel(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogLevel;
    uint32_t level = CriticalLv;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    // CASE: SysAppCmnExtractNumberValue retrieves zero.
    // For SysAppCmnExtractNumberValue() about level
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "level", level, 0);

    // For SysAppStateSetInvalidArgErrorWithIdx() about level
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, type, filter_num, kRetOk);

    CheckSysAppCfgLogDestination(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogStorageName(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogPath(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorLevelTooSmall(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogLevel;
    uint32_t level = -1;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid level.
    // For SysAppCmnExtractNumberValue() about level
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "level", level, 1);

    // For SysAppStateSetInvalidArgErrorWithIdx() about level
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, type, filter_num, kRetOk);

    CheckSysAppCfgLogDestination(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogStorageName(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogPath(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorLevelTooLarge(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogLevel;
    uint32_t level = LogLevelNum;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid level.
    // For SysAppCmnExtractNumberValue() about level
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "level", level, 1);

    // For SysAppStateSetInvalidArgErrorWithIdx() about level
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, type, filter_num, kRetOk);

    CheckSysAppCfgLogDestination(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogStorageName(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogPath(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorLogGetParamNumLevel(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogLevel;
    uint32_t level = CriticalLv;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    // For SysAppCmnExtractNumberValue() about level
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "level", level, 1);

    // CASE: SysAppLogGetParameterNumber fails.
    // For SysAppLogGetParameterNumber() about level in CheckUpdateNumberWithIdx
    ForSysAppLogGetParameterNumber(filter_num, type, ErrorLv, kRetFailed);

    CheckSysAppCfgLogDestination(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogStorageName(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogPath(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_LevelNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogLevel;
    uint32_t level = CriticalLv;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    // For SysAppCmnExtractNumberValue() about level
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "level", level, 1);

    // CASE: SysAppLogGetParameterNumber retrieves the same level.
    // For SysAppLogGetParameterNumber() about level in CheckUpdateNumberWithIdx
    ForSysAppLogGetParameterNumber(filter_num, type, level, kRetOk);

    CheckSysAppCfgLogDestination(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogStorageName(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogPath(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorLogSetParamNumLevel(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogLevel;
    uint32_t level = CriticalLv;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    // For SysAppCmnExtractNumberValue() about level
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "level", level, 1);

    // For SysAppLogGetParameterNumber() about level in CheckUpdateNumberWithIdx
    ForSysAppLogGetParameterNumber(filter_num, type, ErrorLv, kRetOk);

    // CASE: SysAppLogSetParameterNumber fails.
    // For SysAppLogSetParameterNumber() about level
    ForSysAppLogSetParameterNumber(filter_num, type, level, kRetFailed);

    // For SysAppStateSetInternalErrorWithIdx() about level in SysAppCfg
    ForSysAppStateSetInternalErrorWithIdx(topic, type, filter_num, kRetOk);

    CheckSysAppCfgLogDestination(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogStorageName(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogPath(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorCmnExtractNumDestination(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t destination = DestUart;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogLevel(esfj_handle, json_value, filter_num);

    // CASE: SysAppCmnExtractNumberValue fails.
    // For SysAppCmnExtractNumberValue() about destination
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "destination", destination, -1);

    CheckSysAppCfgLogStorageName(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogPath(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorCmnExtractNumInvalidDestination(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogDestination;
    uint32_t destination = DestUart;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogLevel(esfj_handle, json_value, filter_num);

    // CASE: SysAppCmnExtractNumberValue retrieves zero.
    // For SysAppCmnExtractNumberValue() about destination
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "destination", destination, 0);

    // For SysAppStateSetInvalidArgErrorWithIdx() about destination
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, type, filter_num, kRetOk);

    CheckSysAppCfgLogStorageName(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogPath(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorDestinationTooSmall(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogDestination;
    uint32_t destination = -1;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogLevel(esfj_handle, json_value, filter_num);

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid destination.
    // For SysAppCmnExtractNumberValue() about destination
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "destination", destination, 1);

    // For SysAppStateSetInvalidArgErrorWithIdx() about destination
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, type, filter_num, kRetOk);

    CheckSysAppCfgLogStorageName(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogPath(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorDestinationTooLarge(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogDestination;
    uint32_t destination = LogDestinationNum;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogLevel(esfj_handle, json_value, filter_num);

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid destination.
    // For SysAppCmnExtractNumberValue() about destination
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "destination", destination, 1);

    // For SysAppStateSetInvalidArgErrorWithIdx() about destination
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, type, filter_num, kRetOk);

    CheckSysAppCfgLogStorageName(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogPath(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorLogGetParamNumDestination(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogDestination;
    uint32_t destination = DestUart;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogLevel(esfj_handle, json_value, filter_num);

    // For SysAppCmnExtractNumberValue() about destination
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "destination", destination, 1);

    // CASE: SysAppLogGetParameterNumber fails.
    // For SysAppLogGetParameterNumber() about destination in CheckUpdateNumberWithIdx
    ForSysAppLogGetParameterNumber(filter_num, type, DestCloudStorage, kRetFailed);

    CheckSysAppCfgLogStorageName(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogPath(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_DestinationNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogDestination;
    uint32_t destination = DestUart;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogLevel(esfj_handle, json_value, filter_num);

    // For SysAppCmnExtractNumberValue() about destination
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "destination", destination, 1);

    // CASE: SysAppLogGetParameterNumber retrieves the same destination.
    // For SysAppLogGetParameterNumber() about destination in CheckUpdateNumberWithIdx
    ForSysAppLogGetParameterNumber(filter_num, type, destination, kRetOk);

    CheckSysAppCfgLogStorageName(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogPath(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorLogSetParamNumDestination(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogDestination;
    uint32_t destination = DestUart;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogLevel(esfj_handle, json_value, filter_num);

    // For SysAppCmnExtractNumberValue() about destination
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "destination", destination, 1);

    // For SysAppLogGetParameterNumber() about destination in CheckUpdateNumberWithIdx
    ForSysAppLogGetParameterNumber(filter_num, type, DestCloudStorage, kRetOk);

    // CASE: SysAppLogSetParameterNumber fails.
    // For SysAppLogSetParameterNumber() about destination
    ForSysAppLogSetParameterNumber(filter_num, type, destination, kRetFailed);

    // For SysAppStateSetInternalErrorWithIdx() about destination in SysAppCfg
    ForSysAppStateSetInternalErrorWithIdx(topic, type, filter_num, kRetOk);

    CheckSysAppCfgLogStorageName(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogPath(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorCmnExtractStrStorageName(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    const char *storage_name = "storage_name";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogLevel(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogDestination(esfj_handle, json_value, filter_num);

    // CASE: SysAppCmnExtractStringValue fails.
    // For SysAppCmnExtractStringValue() about storage_name
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "storage_name", storage_name, -1);

    CheckSysAppCfgLogPath(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorCmnExtractStrInvalidStorageName(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogStorageName;
    const char *storage_name = "storage_name";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogLevel(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogDestination(esfj_handle, json_value, filter_num);

    // CASE: SysAppCmnExtractStringValue retrieves zero.
    // For SysAppCmnExtractStringValue() about storage_name
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "storage_name", storage_name, 0);

    // For SysAppStateSetInvalidArgErrorWithIdx() about storage_name
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, type, filter_num, kRetOk);

    CheckSysAppCfgLogPath(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorStorageNameTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogStorageName;
    const char *storage_name = "storage_nameeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogLevel(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogDestination(esfj_handle, json_value, filter_num);

    // CASE: SysAppCmnExtractStringValue retrieves a long storage_name.
    // For SysAppCmnExtractStringValue() about storage_name
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "storage_name", storage_name, 1);

    // For SysAppStateSetInvalidArgErrorWithIdx() about storage_name
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, type, filter_num, kRetOk);

    CheckSysAppCfgLogPath(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorLogGetParamStrStorageName(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogStorageName;
    const char *storage_name = "storage_name";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogLevel(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogDestination(esfj_handle, json_value, filter_num);

    // For SysAppCmnExtractStringValue() about storage_name
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "storage_name", storage_name, 1);

    // CASE: SysAppLogGetParameterString fails.
    // For SysAppLogGetParameterString() about storage_name in CheckUpdateStringWithIdx
    ForSysAppLogGetParameterString(filter_num, type, CFGST_LOG_STORAGE_NAME_LEN + 1U, "",
                                   kRetFailed);

    CheckSysAppCfgLogPath(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_StorageNameNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogStorageName;
    const char *storage_name = "storage_name";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogLevel(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogDestination(esfj_handle, json_value, filter_num);

    // For SysAppCmnExtractStringValue() about storage_name
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "storage_name", storage_name, 1);

    // CASE: SysAppLogGetParameterString retrieves the same storage_name.
    // For SysAppLogGetParameterString() about storage_name in CheckUpdateStringWithIdx
    ForSysAppLogGetParameterString(filter_num, type, CFGST_LOG_STORAGE_NAME_LEN + 1U, storage_name,
                                   kRetOk);

    CheckSysAppCfgLogPath(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorLogSetParamStrStorageName(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogStorageName;
    const char *storage_name = "storage-name.";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogLevel(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogDestination(esfj_handle, json_value, filter_num);

    // For SysAppCmnExtractStringValue() about storage_name
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "storage_name", storage_name, 1);

    // For SysAppLogGetParameterString() about storage_name in CheckUpdateStringWithIdx
    ForSysAppLogGetParameterString(filter_num, type, CFGST_LOG_STORAGE_NAME_LEN + 1U, "", kRetOk);

    // CASE: SysAppLogSetParameterString fails.
    // For SysAppLogSetParameterString() about storage_name
    ForSysAppLogSetParameterString(filter_num, type, storage_name, CFGST_LOG_STORAGE_NAME_LEN + 1U,
                                   kRetParamError);

    // For SysAppStateSetInvalidArgErrorWithIdx() about storage_name in SysAppCfg
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, type, filter_num, kRetOk);

    CheckSysAppCfgLogPath(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorLogSetParamStrStorageNameIO(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogStorageName;
    const char *storage_name = "storage-name";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogLevel(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogDestination(esfj_handle, json_value, filter_num);

    // For SysAppCmnExtractStringValue() about storage_name
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "storage_name", storage_name, 1);

    // For SysAppLogGetParameterString() about storage_name in CheckUpdateStringWithIdx
    ForSysAppLogGetParameterString(filter_num, type, CFGST_LOG_STORAGE_NAME_LEN + 1U, "", kRetOk);

    // CASE: SysAppLogSetParameterString fails.
    // For SysAppLogSetParameterString() about storage_name
    ForSysAppLogSetParameterString(filter_num, type, storage_name, CFGST_LOG_STORAGE_NAME_LEN + 1U,
                                   kRetFailed);

    // For SysAppStateSetInternalErrorWithIdx() about storage_name in SysAppCfg
    ForSysAppStateSetInternalErrorWithIdx(topic, type, filter_num, kRetOk);

    CheckSysAppCfgLogPath(esfj_handle, json_value, filter_num);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorCmnExtractStrPath(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    const char *path = "path";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogLevel(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogDestination(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogStorageName(esfj_handle, json_value, filter_num);

    // CASE: SysAppCmnExtractStringValue fails.
    // For SysAppCmnExtractStringValue() about path
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "path", path, -1);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorCmnExtractStrInvalidPath(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogPath;
    const char *path = "path";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogLevel(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogDestination(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogStorageName(esfj_handle, json_value, filter_num);

    // CASE: SysAppCmnExtractStringValue retrieves zero.
    // For SysAppCmnExtractStringValue() about path
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "path", path, 0);

    // For SysAppStateSetInvalidArgErrorWithIdx() about path
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, type, filter_num, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorPathTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogPath;
    const char *path =
        "pathhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh"
        "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh"
        "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogLevel(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogDestination(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogStorageName(esfj_handle, json_value, filter_num);

    // CASE: SysAppCmnExtractStringValue retrieves a long path.
    // For SysAppCmnExtractStringValue() about path
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "path", path, 1);

    // For SysAppStateSetInvalidArgErrorWithIdx() about path
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, type, filter_num, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorLogGetParamStrPath(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogPath;
    const char *path = "path";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogLevel(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogDestination(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogStorageName(esfj_handle, json_value, filter_num);

    // For SysAppCmnExtractStringValue() about path
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "path", path, 1);

    // CASE: SysAppLogGetParameterString fails.
    // For SysAppLogGetParameterString() about path in CheckUpdateStringWithIdx
    ForSysAppLogGetParameterString(filter_num, type, CFGST_LOG_PATH_LEN + 1U, "", kRetFailed);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_PathNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogPath;
    const char *path = "path";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogLevel(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogDestination(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogStorageName(esfj_handle, json_value, filter_num);

    // For SysAppCmnExtractStringValue() about path
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "path", path, 1);

    // CASE: SysAppLogGetParameterString retrieves the same path.
    // For SysAppLogGetParameterString() about path in CheckUpdateStringWithIdx
    ForSysAppLogGetParameterString(filter_num, type, CFGST_LOG_PATH_LEN + 1U, path, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorLogSetParamStrPath(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogPath;
    const char *path = "path.";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogLevel(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogDestination(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogStorageName(esfj_handle, json_value, filter_num);

    // For SysAppCmnExtractStringValue() about path
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "path", path, 1);

    // For SysAppLogGetParameterString() about path in CheckUpdateStringWithIdx
    ForSysAppLogGetParameterString(filter_num, type, CFGST_LOG_PATH_LEN + 1U, "", kRetOk);

    // CASE: SysAppLogSetParameterString fails.
    // For SysAppLogSetParameterString() about path
    ForSysAppLogSetParameterString(filter_num, type, path, CFGST_LOG_PATH_LEN + 1U, kRetParamError);

    // For SysAppStateSetInvalidArgErrorWithIdx() about path in SysAppCfg
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, type, filter_num, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorLogSetParamStrPathIO(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t type = LogPath;
    const char *path = "path";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogLevel(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogDestination(esfj_handle, json_value, filter_num);
    CheckSysAppCfgLogStorageName(esfj_handle, json_value, filter_num);

    // For SysAppCmnExtractStringValue() about path
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "path", path, 1);

    // For SysAppLogGetParameterString() about path in CheckUpdateStringWithIdx
    ForSysAppLogGetParameterString(filter_num, type, CFGST_LOG_PATH_LEN + 1U, "", kRetOk);

    // CASE: SysAppLogSetParameterString fails.
    // For SysAppLogSetParameterString() about path
    ForSysAppLogSetParameterString(filter_num, type, path, CFGST_LOG_PATH_LEN + 1U, kRetFailed);

    // For SysAppStateSetInternalErrorWithIdx() about path in SysAppCfg
    ForSysAppStateSetInternalErrorWithIdx(topic, type, filter_num, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgLog_ErrorEsfJsonClose(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *filter = "main";
    uint32_t filter_num = 1U;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, log_settings);

    // For SysAppCmnExtractStringValue() about filter
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "filter", filter, 1);

    // For SysAppStateUpdateNumberWithIdx()
    ForSysAppStateUpdateNumberWithIdx(topic, LogFilter, filter_num, filter_num, kRetOk);

    CheckSysAppCfgLogEach(esfj_handle, json_value, filter_num);

    // CASE: EsfJsonClose fails.
    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonInternalError);

    // Exec test target
    ret = SysAppCfgLog(log_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCfgSystemSettings()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_FullySuccess(void **state)
{
    RetCode ret;

    CheckSysAppCfgSystemSettingsSuccess(system_settings);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ErrorEsfJsonOpen(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;

    // CASE: EsfJsonOpen fails.
    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ErrorEsfJsonDeserialize(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // CASE: EsfJsonDeserialize fails.
    // For EsfJsonDeserialize()
    expect_value(__wrap_EsfJsonDeserialize, handle, esfj_handle);
    expect_string(__wrap_EsfJsonDeserialize, str, system_settings);
    will_return(__wrap_EsfJsonDeserialize, json_value);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonInternalError);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ErrorSysAppCmnGetId(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *req_id = "1";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    // CASE: EsfJsonDeserialize fails.
    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetFailed);

    // For SysAppStateUpdateString() about req_id
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, Id);
    expect_string(__wrap_SysAppStateUpdateString, string, "0");
    will_return(__wrap_SysAppStateUpdateString, kRetOk);

    // For SysAppStateSetInvalidArgError() about req_id
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, Id);
    will_return(__wrap_SysAppStateSetInvalidArgError, kEsfJsonSuccess);

    CheckSysAppCfgSystemSettingsLedEnabled(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLogSettings(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsTempUpdateInterval(esfj_handle, json_value);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_NotFoundSysAppCmnGetId(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *req_id = "1";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    // CASE: EsfJsonDeserialize fails.
    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetNotFound);

    // For SysAppStateUpdateString() about req_id
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, Id);
    expect_string(__wrap_SysAppStateUpdateString, string, "0");
    will_return(__wrap_SysAppStateUpdateString, kRetOk);

    CheckSysAppCfgSystemSettingsLedEnabled(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLogSettings(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsTempUpdateInterval(esfj_handle, json_value);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ErrorReqIdTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *req_id =
        "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "111111111111111111111111111111111111111";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    // CASE: SysAppCmnGetReqId retrieves a long req_id.
    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // For SysAppStateUpdateString() about req_id
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, Id);
    expect_string(__wrap_SysAppStateUpdateString, string, "0");
    will_return(__wrap_SysAppStateUpdateString, kRetOk);

    // For SysAppStateSetInvalidArgError() about req_id
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, Id);
    will_return(__wrap_SysAppStateSetInvalidArgError, kEsfJsonSuccess);

    CheckSysAppCfgSystemSettingsLedEnabled(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLogSettings(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsTempUpdateInterval(esfj_handle, json_value);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ErrorSysAppStateGetReqIdNullPtr(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *req_id = "1";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // CASE: SysAppStateGetReqId retrieves a null pointer.
    // For SysAppStateGetReqId() about req_id in CheckUpdateString
    expect_value(__wrap_SysAppStateGetReqId, topic, topic);
    will_return(__wrap_SysAppStateGetReqId, NULL);

    CheckSysAppCfgSystemSettingsLedEnabled(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLogSettings(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsTempUpdateInterval(esfj_handle, json_value);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ReqIdNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *req_id = "1";
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // CASE: SysAppStateGetReqId retrieves the same req_id.
    // For SysAppStateGetReqId() about req_id in CheckUpdateString
    expect_value(__wrap_SysAppStateGetReqId, topic, topic);
    will_return(__wrap_SysAppStateGetReqId, "1");

    CheckSysAppCfgSystemSettingsLedEnabled(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLogSettings(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsTempUpdateInterval(esfj_handle, json_value);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ErrorCmnExtractBool(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    bool led_enabled = false;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    CheckSysAppCfgSystemSettingsReqId(esfj_handle, json_value);

    // CASE: SysAppCmnExtractBooleanValue fails.
    // For SysAppCmnExtractBooleanValue() in SysAppCfgSystemSettings
    ForSysAppCmnExtractBooleanValue(esfj_handle, json_value, "led_enabled", led_enabled, -1);

    CheckSysAppCfgSystemSettingsLogSettings(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsTempUpdateInterval(esfj_handle, json_value);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ErrorInvalidLedEnabled(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    bool led_enabled = false;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    CheckSysAppCfgSystemSettingsReqId(esfj_handle, json_value);

    // CASE: SysAppCmnExtractBooleanValue retrieve zero.
    // For SysAppCmnExtractBooleanValue() in SysAppCfgSystemSettings
    ForSysAppCmnExtractBooleanValue(esfj_handle, json_value, "led_enabled", led_enabled, 0);

    // For SysAppStateSetInvalidArgError() in SysAppCfgSystemSettings
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, LedEnabled);
    will_return(__wrap_SysAppStateSetInvalidArgError, kEsfJsonSuccess);

    CheckSysAppCfgSystemSettingsLogSettings(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsTempUpdateInterval(esfj_handle, json_value);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ErrorSysAppLedGetEnable(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    bool led_enabled = false;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    CheckSysAppCfgSystemSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractBooleanValue() in SysAppCfgSystemSettings
    ForSysAppCmnExtractBooleanValue(esfj_handle, json_value, "led_enabled", led_enabled, 1);

    // CASE: SysAppLedGetEnable fails.
    // For SysAppLedGetEnable() in CheckUpdateBoolean
    will_return(__wrap_SysAppLedGetEnable, !led_enabled);
    will_return(__wrap_SysAppLedGetEnable, kRetFailed);

    CheckSysAppCfgSystemSettingsLogSettings(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsTempUpdateInterval(esfj_handle, json_value);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_LedEnabledNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    bool led_enabled = false;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    CheckSysAppCfgSystemSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractBooleanValue() in SysAppCfgSystemSettings
    ForSysAppCmnExtractBooleanValue(esfj_handle, json_value, "led_enabled", led_enabled, 1);

    // CASE: SysAppLedGetEnable retrieves the same led_enabled.
    // For SysAppLedGetEnable() in CheckUpdateBoolean
    will_return(__wrap_SysAppLedGetEnable, led_enabled);
    will_return(__wrap_SysAppLedGetEnable, kRetOk);

    CheckSysAppCfgSystemSettingsLogSettings(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsTempUpdateInterval(esfj_handle, json_value);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ErrorSysAppLedSetEnable(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    bool led_enabled = false;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    CheckSysAppCfgSystemSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractBooleanValue() in SysAppCfgSystemSettings
    ForSysAppCmnExtractBooleanValue(esfj_handle, json_value, "led_enabled", led_enabled, 1);

    // For SysAppLedGetEnable() in CheckUpdateBoolean
    will_return(__wrap_SysAppLedGetEnable, !led_enabled);
    will_return(__wrap_SysAppLedGetEnable, kRetOk);

    // CASE: SysAppLedSetEnable fails.
    // For SysAppLedSetEnable() in SysAppCfgSystemSettings
    expect_value(__wrap_SysAppLedSetEnable, led_enable, led_enabled);
    will_return(__wrap_SysAppLedSetEnable, kRetFailed);

    // For SysAppStateSetInternalError() in SysAppCfgSystemSettings
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, LedEnabled);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    CheckSysAppCfgSystemSettingsLogSettings(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsTempUpdateInterval(esfj_handle, json_value);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ErrorEsfJsonObjectGet(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    CheckSysAppCfgSystemSettingsReqId(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLedEnabled(esfj_handle, json_value);

    // CASE: EsfJsonObjectGet fails.
    // For EsfJsonObjectGet() in SysAppCfgSystemSettings
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "log_settings");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonInternalError);

    CheckSysAppCfgSystemSettingsTempUpdateInterval(esfj_handle, json_value);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ErrorEsfJsonValueTypeGet(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    CheckSysAppCfgSystemSettingsReqId(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLedEnabled(esfj_handle, json_value);

    // For EsfJsonObjectGet() in SysAppCfgSystemSettings
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "log_settings");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // CASE: EsfJsonValueTypeGet fails.
    // For EsfJsonValueTypeGet() in SysAppCfgSystemSettings
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeArray);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonInternalError);

    CheckSysAppCfgSystemSettingsTempUpdateInterval(esfj_handle, json_value);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ErrorEsfJsonValueTypeGetNotArray(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    CheckSysAppCfgSystemSettingsReqId(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLedEnabled(esfj_handle, json_value);

    // For EsfJsonObjectGet() in SysAppCfgSystemSettings
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "log_settings");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // CASE: EsfJsonValueTypeGet retrieves kEsfJsonValueTypeNull.
    // For EsfJsonValueTypeGet() in SysAppCfgSystemSettings
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeNull);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    CheckSysAppCfgSystemSettingsTempUpdateInterval(esfj_handle, json_value);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ArrayHasNoElements(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    CheckSysAppCfgSystemSettingsReqId(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLedEnabled(esfj_handle, json_value);

    // For EsfJsonObjectGet() in SysAppCfgSystemSettings
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "log_settings");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // For EsfJsonValueTypeGet() in SysAppCfgSystemSettings
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeArray);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // CASE: EsfJsonArrayCount retrieves zero.
    // For EsfJsonArrayCount() in SysAppCfgSystemSettings
    expect_value(__wrap_EsfJsonArrayCount, handle, esfj_handle);
    expect_value(__wrap_EsfJsonArrayCount, parent, json_value);
    will_return(__wrap_EsfJsonArrayCount, 0U);

    CheckSysAppCfgSystemSettingsTempUpdateInterval(esfj_handle, json_value);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ErrorEsfJsonArrayGet(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    CheckSysAppCfgSystemSettingsReqId(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLedEnabled(esfj_handle, json_value);

    // For EsfJsonObjectGet() in SysAppCfgSystemSettings
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "log_settings");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // For EsfJsonValueTypeGet() in SysAppCfgSystemSettings
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeArray);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // For EsfJsonArrayCount() in SysAppCfgSystemSettings
    expect_value(__wrap_EsfJsonArrayCount, handle, esfj_handle);
    expect_value(__wrap_EsfJsonArrayCount, parent, json_value);
    will_return(__wrap_EsfJsonArrayCount, 1U);

    // CASE: EsfJsonArrayGet fails.
    ForEsfJsonArrayGet(esfj_handle, json_value, 0U, json_value, kEsfJsonInternalError);

    CheckSysAppCfgSystemSettingsTempUpdateInterval(esfj_handle, json_value);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ErrorEsfJsonSerialize(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    CheckSysAppCfgSystemSettingsReqId(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLedEnabled(esfj_handle, json_value);

    // For EsfJsonObjectGet() in SysAppCfgSystemSettings
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "log_settings");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // For EsfJsonValueTypeGet() in SysAppCfgSystemSettings
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeArray);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // For EsfJsonArrayCount() in SysAppCfgSystemSettings
    expect_value(__wrap_EsfJsonArrayCount, handle, esfj_handle);
    expect_value(__wrap_EsfJsonArrayCount, parent, json_value);
    will_return(__wrap_EsfJsonArrayCount, 1U);

    ForEsfJsonArrayGet(esfj_handle, json_value, 0U, json_value, kEsfJsonSuccess);

    // CASE: EsfJsonSerialize fails.
    ForEsfJsonSerialize(esfj_handle, json_value, log_settings, kEsfJsonInternalError);

    CheckSysAppCfgSystemSettingsTempUpdateInterval(esfj_handle, json_value);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ErrorEsfJsonSerializeNullPtr(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    CheckSysAppCfgSystemSettingsReqId(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLedEnabled(esfj_handle, json_value);

    // For EsfJsonObjectGet() in SysAppCfgSystemSettings
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "log_settings");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // For EsfJsonValueTypeGet() in SysAppCfgSystemSettings
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeArray);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // For EsfJsonArrayCount() in SysAppCfgSystemSettings
    expect_value(__wrap_EsfJsonArrayCount, handle, esfj_handle);
    expect_value(__wrap_EsfJsonArrayCount, parent, json_value);
    will_return(__wrap_EsfJsonArrayCount, 1U);

    ForEsfJsonArrayGet(esfj_handle, json_value, 0U, json_value, kEsfJsonSuccess);

    // CASE: EsfJsonSerialize retrieves a null pointer.
    ForEsfJsonSerialize(esfj_handle, json_value, NULL, kEsfJsonSuccess);

    CheckSysAppCfgSystemSettingsTempUpdateInterval(esfj_handle, json_value);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ErrorCmnExtractNumTempInterval(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int temperature_interval = 1234;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    CheckSysAppCfgSystemSettingsReqId(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLedEnabled(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLogSettings(esfj_handle, json_value);

    // CASE: SysAppCmnExtractNumberValue fails.
    // For SysAppCmnExtractNumberValue() in SysAppCfgSystemSettings
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "temperature_update_interval",
                                   temperature_interval, -1);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ErrorInvalidTempInterval(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int temperature_interval = 1234;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    CheckSysAppCfgSystemSettingsReqId(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLedEnabled(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLogSettings(esfj_handle, json_value);

    // CASE: SysAppCmnExtractNumberValue retrieves zero.
    // For SysAppCmnExtractNumberValue() in SysAppCfgSystemSettings
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "temperature_update_interval",
                                   temperature_interval, 0);

    // For SysAppStateSetInvalidArgError() in SysAppCfgSystemSettings
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, TemperatureUpdateInterval);
    will_return(__wrap_SysAppStateSetInvalidArgError, kEsfJsonSuccess);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ErrorTempIntervalTooSmall(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int temperature_interval = 9;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    CheckSysAppCfgSystemSettingsReqId(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLedEnabled(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLogSettings(esfj_handle, json_value);

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid temperature_update_interval.
    // For SysAppCmnExtractNumberValue() in SysAppCfgSystemSettings
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "temperature_update_interval",
                                   temperature_interval, 1);

    // For SysAppStateSetInvalidArgError() in SysAppCfgSystemSettings
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, TemperatureUpdateInterval);
    will_return(__wrap_SysAppStateSetInvalidArgError, kEsfJsonSuccess);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ErrorTempIntervalTooLarge(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int temperature_interval = 3601;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    CheckSysAppCfgSystemSettingsReqId(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLedEnabled(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLogSettings(esfj_handle, json_value);

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid temperature_update_interval.
    // For SysAppCmnExtractNumberValue() in SysAppCfgSystemSettings
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "temperature_update_interval",
                                   temperature_interval, 1);

    // For SysAppStateSetInvalidArgError() in SysAppCfgSystemSettings
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, TemperatureUpdateInterval);
    will_return(__wrap_SysAppStateSetInvalidArgError, kEsfJsonSuccess);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_TempIntervalNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int temperature_interval = 1234;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    CheckSysAppCfgSystemSettingsReqId(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLedEnabled(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLogSettings(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue() in SysAppCfgSystemSettings
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "temperature_update_interval",
                                   temperature_interval, 1);

    // CASE: SysAppStateGetTemperatureUpdateInterval retrieves the same temperature_update_interval.
    // For SysAppStateGetTemperatureUpdateInterval() in CheckUpdateNumber
    will_return(__wrap_SysAppStateGetTemperatureUpdateInterval, 1234);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ErrorSysAppTimerUpdateTimer(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int temperature_interval = 1234;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    CheckSysAppCfgSystemSettingsReqId(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLedEnabled(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLogSettings(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue() in SysAppCfgSystemSettings
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "temperature_update_interval",
                                   temperature_interval, 1);

    // For SysAppStateGetTemperatureUpdateInterval() in CheckUpdateNumber
    will_return(__wrap_SysAppStateGetTemperatureUpdateInterval, 0);

    // CASE: SysAppTimerUpdateTimer fails.
    // For SysAppTimerUpdateTimer() in SysAppCfgSystemSettings
    expect_value(__wrap_SysAppTimerUpdateTimer, type, SensorTempIntervalTimer);
    expect_value(__wrap_SysAppTimerUpdateTimer, time, temperature_interval);
    will_return(__wrap_SysAppTimerUpdateTimer, kRetFailed);

    // For SysAppStateSetInternalError() in SysAppCfgSystemSettings
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, TemperatureUpdateInterval);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ErrorSysAppStateSendState(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    CheckSysAppCfgSystemSettingsReqId(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLedEnabled(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLogSettings(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsTempUpdateInterval(esfj_handle, json_value);

    // CASE: SysAppStateSendState fails.
    // For SysAppStateSendState()
    expect_value(__wrap_SysAppStateSendState, req, topic);
    will_return(__wrap_SysAppStateSendState, kRetFailed);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgSystemSettings_ErrorEsfJsonClose(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_SYSTEM_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, system_settings);

    CheckSysAppCfgSystemSettingsReqId(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLedEnabled(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsLogSettings(esfj_handle, json_value);

    CheckSysAppCfgSystemSettingsTempUpdateInterval(esfj_handle, json_value);

    // For SysAppStateSendState()
    expect_value(__wrap_SysAppStateSendState, req, topic);
    will_return(__wrap_SysAppStateSendState, kRetOk);

    // CASE: EsfJsonClose fails.
    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonInternalError);

    // Exec test target
    ret = SysAppCfgSystemSettings(system_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCfgStaticSettings()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_FullySuccess(void **state)
{
    RetCode ret;

    CheckSysAppCfgStaticSettingsIpv6(static_settings);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6EsfJsonOpen(void **state)
{
    RetCode ret;

    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;

    // CASE: EsfJsonOpen fails.
    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6EsfJsonDeserialize(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // CASE: EsfJsonDeserialize fails.
    // For EsfJsonDeserialize()
    expect_value(__wrap_EsfJsonDeserialize, handle, esfj_handle);
    expect_string(__wrap_EsfJsonDeserialize, str, static_settings);
    will_return(__wrap_EsfJsonDeserialize, json_value);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonInternalError);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6LoadNetworkAddressIpAddress(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *ip_addr = "::1";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    // For SysAppCmnExtractStringValue() about ip_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ip_address", ip_addr, -1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // about ip_address
    CheckLoadAddressFromEsf(kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInvalidArgError() about ip_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, IpAddressV6);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv6, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6CheckIpAddressTypeIpAddress(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *ip_addr = "::1:";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    // CASE: SysAppCmnExtractStringValue fails.
    // For SysAppCmnExtractStringValue() about ip_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ip_address", ip_addr, 1);

    // For SysAppStateSetInvalidArgError() about ip_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, IpAddressV6);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv6, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6InvalidIpAddress(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *ip_addr = "0000:0000:0000:0000:0000:0000:0000:0000:0001";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    // CASE: SysAppCmnExtractStringValue retrieves zero.
    // For SysAppCmnExtractStringValue() about ip_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ip_address", ip_addr, 0);

    // For SysAppStateSetInvalidArgError() about ip_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, IpAddressV6);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv6, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6IpAddressTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *ip_addr = "0000:0000:0000:0000:0000:0000:0000:0000:0001";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    // CASE: SysAppCmnExtractStringValue retrieves a long ip_address.
    // For SysAppCmnExtractStringValue() about ip_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ip_address", ip_addr, 1);

    // For SysAppStateSetInvalidArgError() about ip_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, IpAddressV6);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv6, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6EsfNMLoadParamIpAddress(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *ip_addr = "::1";

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    // For SysAppCmnExtractStringValue() about ip_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ip_address", ip_addr, 1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // For EsfNetworkManagerLoadParameter() about ip_address in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultInternalError);

    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv6, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}
/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_IPv6IpAddressNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *ip_addr = "::1";

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    // For SysAppCmnExtractStringValue() about ip_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ip_address", ip_addr, 1);

    // CASE: EsfNetworkManagerLoadParameter retrieve the same ip_address.
    // For EsfNetworkManagerLoadParameter() about ip_address in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, ip_addr);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv6, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6EsfNMSaveParamIpAddress(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *ip_addr = "::1";
    EsfNetworkManagerParameterMask mask_ipv6 = {};
    EsfNetworkManagerParameter param_ipv6 = {};
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    // For SysAppCmnExtractStringValue() about ip_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ip_address", ip_addr, 1);

    // For EsfNetworkManagerLoadParameter() about ip_address in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // CASE: EsfNetworkManagerSaveParameter fails.
    // For EsfNetworkManagerSaveParameter() about ip_address
    memset(&mask_ipv6, 0, sizeof mask_ipv6);
    memset(&param_ipv6, 0, sizeof param_ipv6);
    mask_ipv6.normal_mode.dev_ip_v6.ip = 1;
    snprintf(param_ipv6.normal_mode.dev_ip_v6.ip, sizeof param_ipv6.normal_mode.dev_ip_v6.ip, "%s",
             ip_addr);
    CheckEsfNetworkManagerSaveParameter(&mask_ipv6, &param_ipv6,
                                        kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInternalError() about ip_address
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, IpAddressV6);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv6, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6LoadNetworkAddressSubnetMask(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *subnet_mask = "::1";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv6, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about subnet_mask
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "subnet_mask", subnet_mask, -1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // about subnet_mask
    CheckLoadAddressFromEsf(kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInvalidArgError() about subnet_mask
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, SubnetMaskV6);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv6, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6CheckIpAddressTypeSubnetMask(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *subnet_mask = "::1:";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv6, esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue fails.
    // For SysAppCmnExtractStringValue() about subnet_mask
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "subnet_mask", subnet_mask, 1);

    // For SysAppStateSetInvalidArgError() about subnet_mask
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, SubnetMaskV6);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv6, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6InvalidSubnetMask(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *subnet_mask = "0000:0000:0000:0000:0000:0000:0000:0000:0001";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv6, esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue retrieves zero.
    // For SysAppCmnExtractStringValue() about subnet_mask
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "subnet_mask", subnet_mask, 0);

    // For SysAppStateSetInvalidArgError() about subnet_mask
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, SubnetMaskV6);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv6, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6SubnetMaskTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *subnet_mask = "0000:0000:0000:0000:0000:0000:0000:0000:0001";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv6, esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue retrieves a long subnet_mask.
    // For SysAppCmnExtractStringValue() about subnet_mask
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "subnet_mask", subnet_mask, 1);

    // For SysAppStateSetInvalidArgError() about subnet_mask
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, SubnetMaskV6);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv6, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6EsfNMLoadParamSubnetMask(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *subnet_mask = "::1";

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv6, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about subnet_mask
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "subnet_mask", subnet_mask, 1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // For EsfNetworkManagerLoadParameter() about subnet_mask in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultInternalError);

    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv6, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}
/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_IPv6SubnetMaskNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *subnet_mask = "::1";

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv6, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about subnet_mask
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "subnet_mask", subnet_mask, 1);

    // CASE: EsfNetworkManagerLoadParameter retrieves the same subnet_mask.
    // For EsfNetworkManagerLoadParameter() about subnet_mask in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "::1");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv6, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6EsfNMSaveParamSubnetMask(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *subnet_mask = "::1";
    EsfNetworkManagerParameterMask mask_ipv6 = {};
    EsfNetworkManagerParameter param_ipv6 = {};
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv6, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about subnet_mask
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "subnet_mask", subnet_mask, 1);

    // For EsfNetworkManagerLoadParameter() about subnet_mask in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // CASE: EsfNetworkManagerSaveParameter fails.
    // For EsfNetworkManagerSaveParameter() about subnet_mask
    memset(&mask_ipv6, 0, sizeof mask_ipv6);
    memset(&param_ipv6, 0, sizeof param_ipv6);
    mask_ipv6.normal_mode.dev_ip_v6.subnet_mask = 1;
    snprintf(param_ipv6.normal_mode.dev_ip_v6.subnet_mask,
             sizeof param_ipv6.normal_mode.dev_ip_v6.subnet_mask, "%s", subnet_mask);
    CheckEsfNetworkManagerSaveParameter(&mask_ipv6, &param_ipv6,
                                        kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInternalError() about subnet_mask
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, SubnetMaskV6);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv6, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6LoadNetworkAddressGateway(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *gateway = "::1";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv6, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about gateway_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "gateway_address", gateway, -1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // about gateway_address
    CheckLoadAddressFromEsf(kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInvalidArgError() about gateway_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, GatewayAddressV6);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsDns(UnitTestIPv6, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6CheckIpAddressTypeGateway(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *gateway = "::1:";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv6, esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue fails.
    // For SysAppCmnExtractStringValue() about gateway_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "gateway_address", gateway, 1);

    // For SysAppStateSetInvalidArgError() about gateway_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, GatewayAddressV6);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsDns(UnitTestIPv6, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6InvalidGateway(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *gateway = "0000:0000:0000:0000:0000:0000:0000:0000:0001";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv6, esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue retrieves zero.
    // For SysAppCmnExtractStringValue() about gateway_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "gateway_address", gateway, 0);

    // For SysAppStateSetInvalidArgError() about gateway_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, GatewayAddressV6);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsDns(UnitTestIPv6, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6GatewayTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *gateway = "0000:0000:0000:0000:0000:0000:0000:0000:0001";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv6, esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue retrieves a long gateway_address.
    // For SysAppCmnExtractStringValue() about gateway_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "gateway_address", gateway, 1);

    // For SysAppStateSetInvalidArgError() about gateway_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, GatewayAddressV6);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsDns(UnitTestIPv6, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6EsfNMLoadParamGateway(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *gateway = "::1";

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv6, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about gateway_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "gateway_address", gateway, 1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // For EsfNetworkManagerLoadParameter() about gateway_address in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultInternalError);

    CheckSysAppCfgStaticSettingsDns(UnitTestIPv6, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_IPv6GatewayNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *gateway = "::1";

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv6, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about gateway_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "gateway_address", gateway, 1);

    // CASE: EsfNetworkManagerLoadParameter retrieves the same gateway_address.
    // For EsfNetworkManagerLoadParameter() about gateway_address in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "::1");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    CheckSysAppCfgStaticSettingsDns(UnitTestIPv6, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6EsfNMSaveParamGateway(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *gateway = "::1";
    EsfNetworkManagerParameterMask mask_ipv6 = {};
    EsfNetworkManagerParameter param_ipv6 = {};
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv6, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about gateway_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "gateway_address", gateway, 1);

    // For EsfNetworkManagerLoadParameter() about gateway_address in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // CASE: EsfNetworkManagerSaveParameter fails.
    // For EsfNetworkManagerSaveParameter() about gateway_address
    memset(&mask_ipv6, 0, sizeof mask_ipv6);
    memset(&param_ipv6, 0, sizeof param_ipv6);
    mask_ipv6.normal_mode.dev_ip_v6.gateway = 1;
    snprintf(param_ipv6.normal_mode.dev_ip_v6.gateway,
             sizeof param_ipv6.normal_mode.dev_ip_v6.gateway, "%s", gateway);
    CheckEsfNetworkManagerSaveParameter(&mask_ipv6, &param_ipv6,
                                        kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInternalError() about gateway_address
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, GatewayAddressV6);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    CheckSysAppCfgStaticSettingsDns(UnitTestIPv6, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6LoadNetworkAddressDns(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *dns = "::1";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv6, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about dns_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "dns_address", dns, -1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // about dns_address
    CheckLoadAddressFromEsf(kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInvalidArgError() about dns_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, DnsAddressV6);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6CheckIpAddressTypeDns(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *dns = "::1:";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv6, esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue fails.
    // For SysAppCmnExtractStringValue() about dns_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "dns_address", dns, 1);

    // For SysAppStateSetInvalidArgError() about dns_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, DnsAddressV6);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6InvalidDns(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *dns = "0000:0000:0000:0000:0000:0000:0000:0000:0001";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv6, esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue retrieves zero.
    // For SysAppCmnExtractStringValue() about dns_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "dns_address", dns, 0);

    // For SysAppStateSetInvalidArgError() about dns_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, DnsAddressV6);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6DnsTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *dns = "0000:0000:0000:0000:0000:0000:0000:0000:0001";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv6, esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue retrieves a long dns_address.
    // For SysAppCmnExtractStringValue() about dns_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "dns_address", dns, 1);

    // For SysAppStateSetInvalidArgError() about dns_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, DnsAddressV6);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6EsfNMLoadParamDns(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *dns = "::1";

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv6, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about dns_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "dns_address", dns, 1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // For EsfNetworkManagerLoadParameter() about dns_address in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultInternalError);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_IPv6DnsNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *dns = "::1";

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv6, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about dns_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "dns_address", dns, 1);

    // CASE: EsfNetworkManagerLoadParameter retrieves the same dns_address.
    // For EsfNetworkManagerLoadParameter() about dns_address in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "::1");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6EsfNMSaveParamDns(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *dns = "::1";
    EsfNetworkManagerParameterMask mask_ipv6 = {};
    EsfNetworkManagerParameter param_ipv6 = {};
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv6, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about dns_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "dns_address", dns, 1);

    // For EsfNetworkManagerLoadParameter() about dns_address in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // CASE: EsfNetworkManagerSaveParameter fails.
    // For EsfNetworkManagerSaveParameter() about dns_address
    memset(&mask_ipv6, 0, sizeof mask_ipv6);
    memset(&param_ipv6, 0, sizeof param_ipv6);
    mask_ipv6.normal_mode.dev_ip_v6.dns = 1;
    snprintf(param_ipv6.normal_mode.dev_ip_v6.dns, sizeof param_ipv6.normal_mode.dev_ip_v6.dns,
             "%s", dns);
    CheckEsfNetworkManagerSaveParameter(&mask_ipv6, &param_ipv6,
                                        kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInternalError() about dns_address
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, DnsAddressV6);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv6EsfJsonClose(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv6, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv6, esfj_handle, json_value);

    // CASE: EsfJsonClose fails.
    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonInternalError);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv6);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_IPv4(void **state)
{
    RetCode ret;
    CheckSysAppCfgStaticSettingsIpv4(static_settings);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4EsfJsonOpen(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;

    // CASE: EsfJsonOpen fails.
    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4EsfJsonDeserialize(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // CASE: EsfJsonDeserialize fails.
    // For EsfJsonDeserialize()
    expect_value(__wrap_EsfJsonDeserialize, handle, esfj_handle);
    expect_string(__wrap_EsfJsonDeserialize, str, static_settings);
    will_return(__wrap_EsfJsonDeserialize, json_value);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonInternalError);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4LoadNetworkAddressIpAddress(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *ip_addr = "127.0.0.1";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    // For SysAppCmnExtractStringValue() about ip_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ip_address", ip_addr, -1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // about ip_address
    CheckLoadAddressFromEsf(kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInvalidArgError() about ip_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, IpAddress);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv4, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4CheckIpAddressTypeIpAddress(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *ip_addr = "127.0.0.1.";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    // CASE: SysAppCmnExtractStringValue fails.
    // For SysAppCmnExtractStringValue() about ip_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ip_address", ip_addr, 1);

    // For SysAppStateSetInvalidArgError() about ip_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, IpAddress);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv4, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4InvalidIpAddress(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *ip_addr = "127.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    // CASE: SysAppCmnExtractStringValue retrieves zero.
    // For SysAppCmnExtractStringValue() about ip_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ip_address", ip_addr, 0);

    // For SysAppStateSetInvalidArgError() about ip_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, IpAddress);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv4, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4IpAddressTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *ip_addr = "127.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    // CASE: SysAppCmnExtractStringValue retrieves a long ip_address.
    // For SysAppCmnExtractStringValue() about ip_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ip_address", ip_addr, 1);

    // For SysAppStateSetInvalidArgError() about ip_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, IpAddress);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv4, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4EsfNMLoadParamIpAddress(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *ip_addr = "127.0.0.1";

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    // For SysAppCmnExtractStringValue() about ip_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ip_address", ip_addr, 1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // For EsfNetworkManagerLoadParameter() about ip_address in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultInternalError);

    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv4, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_IPv4IpAddressNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *ip_addr = "127.0.0.1";

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    // For SysAppCmnExtractStringValue() about ip_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ip_address", ip_addr, 1);

    // CASE: EsfNetworkManagerLoadParameter retrieves the same ip_address.
    // For EsfNetworkManagerLoadParameter() about ip_address in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "127.0.0.1");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv4, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4EsfNMSaveParamIpAddress(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *ip_addr = "127.0.0.1";
    EsfNetworkManagerParameterMask mask_ipv4 = {};
    EsfNetworkManagerParameter param_ipv4 = {};
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    // For SysAppCmnExtractStringValue() about ip_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ip_address", ip_addr, 1);

    // For EsfNetworkManagerLoadParameter() about ip_address in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // CASE: EsfNetworkManagerSaveParameter fails.
    // For EsfNetworkManagerSaveParameter() about ip_address
    memset(&mask_ipv4, 0, sizeof mask_ipv4);
    memset(&param_ipv4, 0, sizeof param_ipv4);
    mask_ipv4.normal_mode.dev_ip.ip = 1;
    snprintf(param_ipv4.normal_mode.dev_ip.ip, sizeof param_ipv4.normal_mode.dev_ip.ip, "%s",
             ip_addr);
    CheckEsfNetworkManagerSaveParameter(&mask_ipv4, &param_ipv4,
                                        kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInternalError() about ip_address
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, IpAddress);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv4, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4LoadNetworkAddressSubnetMask(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *subnet_mask = "127.0.0.1";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv4, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about subnet_mask
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "subnet_mask", subnet_mask, -1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // about subnet_mask
    CheckLoadAddressFromEsf(kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInvalidArgError() about subnet_mask
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, SubnetMask);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv4, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4CheckIpAddressTypeSubnetMask(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *subnet_mask = "127.0.0.1.";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv4, esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue fails.
    // For SysAppCmnExtractStringValue() about subnet_mask
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "subnet_mask", subnet_mask, 1);

    // For SysAppStateSetInvalidArgError() about subnet_mask
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, SubnetMask);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv4, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4InvalidSubnetMask(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *subnet_mask = "127.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv4, esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue retrieves zero.
    // For SysAppCmnExtractStringValue() about subnet_mask
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "subnet_mask", subnet_mask, 0);

    // For SysAppStateSetInvalidArgError() about subnet_mask
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, SubnetMask);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv4, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4SubnetMaskTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *subnet_mask = "127.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv4, esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue retrieves a long subnet_mask.
    // For SysAppCmnExtractStringValue() about subnet_mask
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "subnet_mask", subnet_mask, 1);

    // For SysAppStateSetInvalidArgError() about subnet_mask
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, SubnetMask);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv4, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4EsfNMLoadParamSubnetMask(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *subnet_mask = "127.0.0.1";

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv4, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about subnet_mask
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "subnet_mask", subnet_mask, 1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // For EsfNetworkManagerLoadParameter() about subnet_mask in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultInternalError);

    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv4, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_IPv4SubnetMaskNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *subnet_mask = "127.0.0.1";

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv4, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about subnet_mask
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "subnet_mask", subnet_mask, 1);

    // CASE: EsfNetworkManagerLoadParameter retrieves the same subnet_mask.
    // For EsfNetworkManagerLoadParameter() about subnet_mask in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "127.0.0.1");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv4, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4EsfNMSaveParamSubnetMask(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *subnet_mask = "127.0.0.1";
    EsfNetworkManagerParameterMask mask_ipv4 = {};
    EsfNetworkManagerParameter param_ipv4 = {};
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv4, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about subnet_mask
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "subnet_mask", subnet_mask, 1);

    // For EsfNetworkManagerLoadParameter() about subnet_mask in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // CASE: EsfNetworkManagerSaveParameter fails.
    // For EsfNetworkManagerSaveParameter() about subnet_mask
    memset(&mask_ipv4, 0, sizeof mask_ipv4);
    memset(&param_ipv4, 0, sizeof param_ipv4);
    mask_ipv4.normal_mode.dev_ip.subnet_mask = 1;
    snprintf(param_ipv4.normal_mode.dev_ip.subnet_mask,
             sizeof param_ipv4.normal_mode.dev_ip.subnet_mask, "%s", subnet_mask);
    CheckEsfNetworkManagerSaveParameter(&mask_ipv4, &param_ipv4,
                                        kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInternalError() about subnet_mask
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, SubnetMask);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv4, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4LoadNetworkAddressGateway(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *gateway = "127.0.0.1";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv4, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about gateway_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "gateway_address", gateway, -1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // about gateway_address
    CheckLoadAddressFromEsf(kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInvalidArgError() about gateway_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, GatewayAddress);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsDns(UnitTestIPv4, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4CheckIpAddressTypeGateway(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *gateway = "127.0.0.1.";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv4, esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue fails.
    // For SysAppCmnExtractStringValue() about gateway_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "gateway_address", gateway, 1);

    // For SysAppStateSetInvalidArgError() about gateway_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, GatewayAddress);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsDns(UnitTestIPv4, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4InvalidGateway(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *gateway = "127.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv4, esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue retrieves zero.
    // For SysAppCmnExtractStringValue() about gateway_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "gateway_address", gateway, 0);

    // For SysAppStateSetInvalidArgError() about gateway_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, GatewayAddress);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsDns(UnitTestIPv4, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4GatewayTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *gateway = "127.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv4, esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue retrieves a long gateway_address.
    // For SysAppCmnExtractStringValue() about gateway_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "gateway_address", gateway, 1);

    // For SysAppStateSetInvalidArgError() about gateway_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, GatewayAddress);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgStaticSettingsDns(UnitTestIPv4, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4EsfNMLoadParamGateway(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *gateway = "127.0.0.1";

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv4, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about gateway_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "gateway_address", gateway, 1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // For EsfNetworkManagerLoadParameter() about gateway_address in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultInternalError);

    CheckSysAppCfgStaticSettingsDns(UnitTestIPv4, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_IPv4GatewayNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *gateway = "127.0.0.1";

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv4, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about gateway_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "gateway_address", gateway, 1);

    // CASE: EsfNetworkManagerLoadParameter retrieves the same gateway_address.
    // For EsfNetworkManagerLoadParameter() about gateway_address in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "127.0.0.1");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    CheckSysAppCfgStaticSettingsDns(UnitTestIPv4, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4EsfNMSaveParamGateway(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *gateway = "127.0.0.1";
    EsfNetworkManagerParameterMask mask_ipv4 = {};
    EsfNetworkManagerParameter param_ipv4 = {};
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv4, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about gateway_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "gateway_address", gateway, 1);

    // For EsfNetworkManagerLoadParameter() about gateway_address in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // CASE: EsfNetworkManagerSaveParameter fails.
    // For EsfNetworkManagerSaveParameter() about gateway_address
    memset(&mask_ipv4, 0, sizeof mask_ipv4);
    memset(&param_ipv4, 0, sizeof param_ipv4);
    mask_ipv4.normal_mode.dev_ip.gateway = 1;
    snprintf(param_ipv4.normal_mode.dev_ip.gateway, sizeof param_ipv4.normal_mode.dev_ip.gateway,
             "%s", gateway);
    CheckEsfNetworkManagerSaveParameter(&mask_ipv4, &param_ipv4,
                                        kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInternalError() about gateway_address
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, GatewayAddress);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    CheckSysAppCfgStaticSettingsDns(UnitTestIPv4, esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4LoadNetworkAddressDns(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *dns = "127.0.0.1";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv4, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about dns_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "dns_address", dns, -1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // about dns_address
    CheckLoadAddressFromEsf(kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInvalidArgError() about dns_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, DnsAddress);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4CheckIpAddressTypeDns(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *dns = "127.0.0.1.";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv4, esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue fails.
    // For SysAppCmnExtractStringValue() about dns_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "dns_address", dns, 1);

    // For SysAppStateSetInvalidArgError() about dns_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, DnsAddress);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4InvalidDns(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *dns = "127.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv4, esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue retrieves zero.
    // For SysAppCmnExtractStringValue() about dns_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "dns_address", dns, 0);

    // For SysAppStateSetInvalidArgError() about dns_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, DnsAddress);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4DnsTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *dns = "127.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv4, esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue retrieves a long dns_address.
    // For SysAppCmnExtractStringValue() about dns_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "dns_address", dns, 1);

    // For SysAppStateSetInvalidArgError() about dns_address
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, DnsAddress);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4EsfNMLoadParamDns(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *dns = "127.0.0.1";

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv4, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about dns_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "dns_address", dns, 1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // For EsfNetworkManagerLoadParameter() about dns_address in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultInternalError);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_IPv4DnsNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *dns = "127.0.0.1";

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv4, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about dns_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "dns_address", dns, 1);

    // CASE: EsfNetworkManagerLoadParameter retrieves the same dns_address.
    // For EsfNetworkManagerLoadParameter() about dns_address in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "127.0.0.1");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4EsfNMSaveParamDns(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *dns = "127.0.0.1";
    EsfNetworkManagerParameterMask mask_ipv4 = {};
    EsfNetworkManagerParameter param_ipv4 = {};
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv4, esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about dns_address
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "dns_address", dns, 1);

    // For EsfNetworkManagerLoadParameter() about dns_address in CheckUpdateIpAddress
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // CASE: EsfNetworkManagerSaveParameter fails.
    // For EsfNetworkManagerSaveParameter() about dns_address
    memset(&mask_ipv4, 0, sizeof mask_ipv4);
    memset(&param_ipv4, 0, sizeof param_ipv4);
    mask_ipv4.normal_mode.dev_ip.dns = 1;
    snprintf(param_ipv4.normal_mode.dev_ip.dns, sizeof param_ipv4.normal_mode.dev_ip.dns, "%s",
             dns);
    CheckEsfNetworkManagerSaveParameter(&mask_ipv4, &param_ipv4,
                                        kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInternalError() about dns_address
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, DnsAddress);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaticSettings_ErrorIPv4EsfJsonClose(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    CheckJsonOpen(esfj_handle, json_value, static_settings);

    CheckSysAppCfgStaticSettingsIpAddress(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsSubnetMask(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsGateway(UnitTestIPv4, esfj_handle, json_value);
    CheckSysAppCfgStaticSettingsDns(UnitTestIPv4, esfj_handle, json_value);

    // CASE: EsfJsonClose fails.
    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonInternalError);

    // Exec test target
    ret = SysAppCfgStaticSettings(static_settings, UnitTestIPv4);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCfgProxySettings()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_FullySuccess(void **state)
{
    RetCode ret;

    CheckSysAppCfgProxySettings(proxy_settings);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorEsfJsonOpen(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;

    // CASE: EsfJsonOpen fails.
    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorEsfJsonDeserialize(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // CASE: EsfJsonDeserialize fails.
    // For EsfJsonDeserialize()
    expect_value(__wrap_EsfJsonDeserialize, handle, esfj_handle);
    expect_string(__wrap_EsfJsonDeserialize, str, proxy_settings);
    will_return(__wrap_EsfJsonDeserialize, json_value);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonInternalError);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorCmnExtractStrProxyUrl(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *proxy_url = "192.168.0.202";

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    // CASE: SysAppCmnExtractStringValue fails.
    // For SysAppCmnExtractStringValue() about proxy_url
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "proxy_url", proxy_url, -1);

    CheckSysAppCfgProxySettingsProxyPort(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyUserName(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPassword(esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorInvalidProxyUrl(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *proxy_url = "192.168.0.203";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    // CASE: SysAppCmnExtractStringValue retrieves zero.
    // For SysAppCmnExtractStringValue() about proxy_url
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "proxy_url", proxy_url, 0);

    // For SysAppStateSetInvalidArgError() about proxy_url in SysAppCfgStaModeSetting
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, ProxyUrl);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgProxySettingsProxyPort(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyUserName(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPassword(esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorProxyUrlTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *proxy_url =
        "proxy_domain_"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    // CASE: SysAppCmnExtractStringValue retrieves a long proxy_url.
    // For SysAppCmnExtractStringValue() about proxy_url
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "proxy_url", proxy_url, 1);

    // For SysAppStateSetInvalidArgError() about proxy_url in SysAppCfgStaModeSetting
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, ProxyUrl);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgProxySettingsProxyPort(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyUserName(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPassword(esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorEsfNMLoadParamProxyUrl(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *proxy_url = "192.168.0.204";

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    // For SysAppCmnExtractStringValue() about proxy_url
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "proxy_url", proxy_url, 1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // For EsfNetworkManagerLoadParameter() about proxy_url in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultInternalError);

    CheckSysAppCfgProxySettingsProxyPort(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyUserName(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPassword(esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ProxyUrlNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *proxy_url = "192.168.1.1";

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    // For SysAppCmnExtractStringValue() about proxy_url
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "proxy_url", proxy_url, 1);

    // CASE: EsfNetworkManagerLoadParameter retrieves the same proxy_url.
    // For EsfNetworkManagerLoadParameter() about proxy_url in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, proxy_url);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    CheckSysAppCfgProxySettingsProxyPort(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyUserName(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPassword(esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorEsfNMSaveParamProxyUrl(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *proxy_url = "192.168.0.206";
    EsfNetworkManagerParameterMask esfnm_mask = {};
    EsfNetworkManagerParameter esfnm_param = {};
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    // For SysAppCmnExtractStringValue() about proxy_url
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "proxy_url", proxy_url, 1);

    // For EsfNetworkManagerLoadParameter() about proxy_url in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // CASE: EsfNetworkManagerSaveParameter fails.
    // For EsfNetworkManagerSaveParameter() about proxy_url
    memset(&esfnm_mask, 0, sizeof esfnm_mask);
    memset(&esfnm_param, 0, sizeof esfnm_param);
    esfnm_mask.proxy.url = 1;
    snprintf(esfnm_param.proxy.url, sizeof esfnm_param.proxy.url, "%s", proxy_url);
    CheckEsfNetworkManagerSaveParameter(&esfnm_mask, &esfnm_param,
                                        kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInternalError() about proxy_url
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, ProxyUrl);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    CheckSysAppCfgProxySettingsProxyPort(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyUserName(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPassword(esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorCmnExtractStrProxyPort(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int proxy_port = 65535;

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    CheckSysAppCfgProxySettingsProxyUrl(esfj_handle, json_value);

    // CASE: SysAppCmnExtractNumberValue fails.
    // For SysAppCmnExtractNumberValue() about proxy_port
    expect_value(__wrap_SysAppCmnExtractNumberValue, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnExtractNumberValue, parent_val, json_value);
    expect_string(__wrap_SysAppCmnExtractNumberValue, jsonkey, "proxy_port");
    will_return(__wrap_SysAppCmnExtractNumberValue, proxy_port);
    will_return(__wrap_SysAppCmnExtractNumberValue, -1);

    CheckSysAppCfgProxySettingsProxyUserName(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPassword(esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorInvalidProxyPort(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int proxy_port = 65535;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    CheckSysAppCfgProxySettingsProxyUrl(esfj_handle, json_value);

    // CASE: SysAppCmnExtractNumberValue retrieves zero.
    // For SysAppCmnExtractNumberValue() about proxy_port
    expect_value(__wrap_SysAppCmnExtractNumberValue, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnExtractNumberValue, parent_val, json_value);
    expect_string(__wrap_SysAppCmnExtractNumberValue, jsonkey, "proxy_port");
    will_return(__wrap_SysAppCmnExtractNumberValue, proxy_port);
    will_return(__wrap_SysAppCmnExtractNumberValue, 0);

    // For SysAppStateSetInvalidArgError() about proxy_port in SysAppCfgStaModeSetting
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, ProxyPort);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgProxySettingsProxyUserName(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPassword(esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorProxyPortTooSmall(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int proxy_port = -1;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    CheckSysAppCfgProxySettingsProxyUrl(esfj_handle, json_value);

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid proxy_port.
    // For SysAppCmnExtractNumberValue() about proxy_port
    expect_value(__wrap_SysAppCmnExtractNumberValue, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnExtractNumberValue, parent_val, json_value);
    expect_string(__wrap_SysAppCmnExtractNumberValue, jsonkey, "proxy_port");
    will_return(__wrap_SysAppCmnExtractNumberValue, proxy_port);
    will_return(__wrap_SysAppCmnExtractNumberValue, 1);

    // For SysAppStateSetInvalidArgError() about proxy_port in SysAppCfgStaModeSetting
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, ProxyPort);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgProxySettingsProxyUserName(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPassword(esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorProxyPortTooLarge(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int proxy_port = 65536;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    CheckSysAppCfgProxySettingsProxyUrl(esfj_handle, json_value);

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid proxy_port.
    // For SysAppCmnExtractNumberValue() about proxy_port
    expect_value(__wrap_SysAppCmnExtractNumberValue, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnExtractNumberValue, parent_val, json_value);
    expect_string(__wrap_SysAppCmnExtractNumberValue, jsonkey, "proxy_port");
    will_return(__wrap_SysAppCmnExtractNumberValue, proxy_port);
    will_return(__wrap_SysAppCmnExtractNumberValue, 1);

    // For SysAppStateSetInvalidArgError() about proxy_port in SysAppCfgStaModeSetting
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, ProxyPort);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgProxySettingsProxyUserName(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPassword(esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorEsfNMLoadParamProxyPort(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int proxy_port = 65535;

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    CheckSysAppCfgProxySettingsProxyUrl(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue() about proxy_port
    expect_value(__wrap_SysAppCmnExtractNumberValue, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnExtractNumberValue, parent_val, json_value);
    expect_string(__wrap_SysAppCmnExtractNumberValue, jsonkey, "proxy_port");
    will_return(__wrap_SysAppCmnExtractNumberValue, proxy_port);
    will_return(__wrap_SysAppCmnExtractNumberValue, 1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // For EsfNetworkManagerLoadParameter() about proxy_port in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, 0);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultInternalError);

    CheckSysAppCfgProxySettingsProxyUserName(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPassword(esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ProxyPortNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int proxy_port = 65535;

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    CheckSysAppCfgProxySettingsProxyUrl(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue() about proxy_port
    expect_value(__wrap_SysAppCmnExtractNumberValue, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnExtractNumberValue, parent_val, json_value);
    expect_string(__wrap_SysAppCmnExtractNumberValue, jsonkey, "proxy_port");
    will_return(__wrap_SysAppCmnExtractNumberValue, proxy_port);
    will_return(__wrap_SysAppCmnExtractNumberValue, 1);

    // CASE: EsfNetworkManagerLoadParameter retrieves the same proxy_port.
    // For EsfNetworkManagerLoadParameter() about proxy_port in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, 65535);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    CheckSysAppCfgProxySettingsProxyUserName(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPassword(esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorEsfNMSaveParamProxyPort(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int proxy_port = 65535;
    EsfNetworkManagerParameterMask esfnm_mask = {};
    EsfNetworkManagerParameter esfnm_param = {};
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    CheckSysAppCfgProxySettingsProxyUrl(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue() about proxy_port
    expect_value(__wrap_SysAppCmnExtractNumberValue, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnExtractNumberValue, parent_val, json_value);
    expect_string(__wrap_SysAppCmnExtractNumberValue, jsonkey, "proxy_port");
    will_return(__wrap_SysAppCmnExtractNumberValue, proxy_port);
    will_return(__wrap_SysAppCmnExtractNumberValue, 1);

    // For EsfNetworkManagerLoadParameter() about proxy_port in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, 0);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // CASE: EsfNetworkManagerSaveParameter fails.
    // For EsfNetworkManagerSaveParameter() about proxy_port
    memset(&esfnm_mask, 0, sizeof esfnm_mask);
    memset(&esfnm_param, 0, sizeof esfnm_param);
    esfnm_mask.proxy.port = 1;
    esfnm_param.proxy.port = proxy_port;
    CheckEsfNetworkManagerSaveParameter(&esfnm_mask, &esfnm_param,
                                        kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInternalError() about proxy_port
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, ProxyPort);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    CheckSysAppCfgProxySettingsProxyUserName(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPassword(esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorCmnExtractStrProxyUserName(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *proxy_user_name = "0123456789";

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    CheckSysAppCfgProxySettingsProxyUrl(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPort(esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue fails.
    // For SysAppCmnExtractStringValue() about proxy_user_name
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "proxy_user_name", proxy_user_name, -1);

    CheckSysAppCfgProxySettingsProxyPassword(esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorInvalidProxyUserName(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *proxy_user_name = "0123456789";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    CheckSysAppCfgProxySettingsProxyUrl(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPort(esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue retrieves zero.
    // For SysAppCmnExtractStringValue() about proxy_user_name
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "proxy_user_name", proxy_user_name, 0);

    // For SysAppStateSetInvalidArgError() about proxy_user_name in SysAppCfgStaModeSetting
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, ProxyUserName);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgProxySettingsProxyPassword(esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorProxyUserNameTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *proxy_user_name = "012345678901234567890123456789012";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    CheckSysAppCfgProxySettingsProxyUrl(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPort(esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue retrieves a long proxy_user_name.
    // For SysAppCmnExtractStringValue() about proxy_user_name
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "proxy_user_name", proxy_user_name, 1);

    // For SysAppStateSetInvalidArgError() about proxy_user_name in SysAppCfgStaModeSetting
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, ProxyUserName);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgProxySettingsProxyPassword(esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorEsfNMLoadParamProxyUserName(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *proxy_user_name = "0123456789";

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    CheckSysAppCfgProxySettingsProxyUrl(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPort(esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about proxy_user_name
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "proxy_user_name", proxy_user_name, 1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // For EsfNetworkManagerLoadParameter() about proxy_user_name in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultInternalError);

    CheckSysAppCfgProxySettingsProxyPassword(esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ProxyUserNameNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *proxy_user_name = "0123456789";

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    CheckSysAppCfgProxySettingsProxyUrl(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPort(esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about proxy_user_name
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "proxy_user_name", proxy_user_name, 1);

    // CASE: EsfNetworkManagerLoadParameter retrieves the same proxy_user_name.
    // For EsfNetworkManagerLoadParameter() about proxy_user_name in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, "0123456789");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    CheckSysAppCfgProxySettingsProxyPassword(esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorEsfNMSaveParamProxyUserName(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *proxy_user_name = "0123456789";
    EsfNetworkManagerParameterMask esfnm_mask = {};
    EsfNetworkManagerParameter esfnm_param = {};
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    CheckSysAppCfgProxySettingsProxyUrl(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPort(esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about proxy_user_name
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "proxy_user_name", proxy_user_name, 1);

    // For EsfNetworkManagerLoadParameter() about proxy_user_name in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // CASE: EsfNetworkManagerSaveParameter fails.
    // For EsfNetworkManagerSaveParameter() about proxy_user_name
    memset(&esfnm_mask, 0, sizeof esfnm_mask);
    memset(&esfnm_param, 0, sizeof esfnm_param);
    esfnm_mask.proxy.username = 1;
    snprintf(esfnm_param.proxy.username, sizeof esfnm_param.proxy.username, "%s", proxy_user_name);
    CheckEsfNetworkManagerSaveParameter(&esfnm_mask, &esfnm_param,
                                        kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInternalError() about proxy_user_name
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, ProxyUserName);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    CheckSysAppCfgProxySettingsProxyPassword(esfj_handle, json_value);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorCmnExtractStrProxyPassword(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *proxy_password = "0123456789";

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    CheckSysAppCfgProxySettingsProxyUrl(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPort(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyUserName(esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue fails.
    // For SysAppCmnExtractStringValue() about proxy_password
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "proxy_password", proxy_password, -1);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorInvalidProxyPassword(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *proxy_password = "0123456789";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    CheckSysAppCfgProxySettingsProxyUrl(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPort(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyUserName(esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue retrieves zero.
    // For SysAppCmnExtractStringValue() about proxy_password
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "proxy_password", proxy_password, 0);

    // For SysAppStateSetInvalidArgError() about proxy_password in SysAppCfgStaModeSetting
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, ProxyPassword);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorProxyPasswordTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *proxy_password = "012345678901234567890123456789012";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    CheckSysAppCfgProxySettingsProxyUrl(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPort(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyUserName(esfj_handle, json_value);

    // CASE: SysAppCmnExtractStringValue retrieves a long proxy_password.
    // For SysAppCmnExtractStringValue() about proxy_password
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "proxy_password", proxy_password, 1);

    // For SysAppStateSetInvalidArgError() about proxy_password in SysAppCfgStaModeSetting
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, ProxyPassword);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorEsfNMLoadParamProxyPassword(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *proxy_password = "0123456789";

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    CheckSysAppCfgProxySettingsProxyUrl(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPort(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyUserName(esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about proxy_password
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "proxy_password", proxy_password, 1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // For EsfNetworkManagerLoadParameter() about proxy_password in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultInternalError);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ProxyPasswordNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *proxy_password = "0123456789";

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    CheckSysAppCfgProxySettingsProxyUrl(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPort(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyUserName(esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about proxy_password
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "proxy_password", proxy_password, 1);

    // CASE: EsfNetworkManagerLoadParameter retrieves the same proxy_password.
    // For EsfNetworkManagerLoadParameter() about proxy_password in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, "0123456789");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorEsfNMSaveParamProxyPassword(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *proxy_password = "0123456789";
    EsfNetworkManagerParameterMask esfnm_mask = {};
    EsfNetworkManagerParameter esfnm_param = {};
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    CheckSysAppCfgProxySettingsProxyUrl(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPort(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyUserName(esfj_handle, json_value);

    // For SysAppCmnExtractStringValue() about proxy_password
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "proxy_password", proxy_password, 1);

    // For EsfNetworkManagerLoadParameter() about proxy_password in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // CASE: EsfNetworkManagerSaveParameter fails.
    // For EsfNetworkManagerSaveParameter() about proxy_password
    memset(&esfnm_mask, 0, sizeof esfnm_mask);
    memset(&esfnm_param, 0, sizeof esfnm_param);
    esfnm_mask.proxy.password = 1;
    snprintf(esfnm_param.proxy.password, sizeof esfnm_param.proxy.password, "%s", proxy_password);
    CheckEsfNetworkManagerSaveParameter(&esfnm_mask, &esfnm_param,
                                        kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInternalError() about proxy_password
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, ProxyPassword);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgProxySettings_ErrorEsfJsonClose(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    CheckJsonOpen(esfj_handle, json_value, proxy_settings);

    CheckSysAppCfgProxySettingsProxyUrl(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPort(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyUserName(esfj_handle, json_value);
    CheckSysAppCfgProxySettingsProxyPassword(esfj_handle, json_value);

    // CASE: EsfJsonClose fails.
    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonInternalError);

    // Exec test target
    ret = SysAppCfgProxySettings(proxy_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/

//
// IsValidUrlOrIpAddress()
//

/*----------------------------------------------------------------------------*/
static void test_IsValidUrlOrIpAddress_SuccessDomain(void **state)
{
    char *url = "pool.ntp.org";
    bool ret = IsValidUrlOrIpAddress(url, 256);
    assert_int_equal(ret, true);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidUrlOrIpAddress_SuccessIPv4(void **state)
{
    char *url = "192.168.255.2";
    bool ret = IsValidUrlOrIpAddress(url, 256);
    assert_int_equal(ret, true);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidUrlOrIpAddress_ErrorDomain(void **state)
{
    char *url = "pool.ntp.org.";
    bool ret = IsValidUrlOrIpAddress(url, 256);
    assert_int_equal(ret, false);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidUrlOrIpAddress_ErrorIPv6(void **state)
{
    char *url = "2001:0db8:bd05:01d2:288a:1fc0:0001:10ee";
    bool ret = IsValidUrlOrIpAddress(url, 256);
    assert_int_equal(ret, false);
    return;
}

/*----------------------------------------------------------------------------*/

//
// IsValidUrlOrNullString()
//

/*----------------------------------------------------------------------------*/
static void test_IsValidUrlOrNullString_SuccessDomainSubdomain(void **state)
{
    bool ret_flag = true;
    for (uint32_t index = 0U; index < SUCCESS_SUBDOMAIN_TBL_BLOCK_LEN; index++) {
        bool ret = IsValidUrlOrNullString(SuccessSubdomainTbl[index], 256);
        if (ret != true) {
            print_message("[Success NG]   %s\n", SuccessSubdomainTbl[index]);
            ret_flag = false;
        }
        else {
            print_message("[       OK ]   %s\n", SuccessSubdomainTbl[index]);
        }
    }
    assert_int_equal(ret_flag, true);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidUrlOrNullString_ErrorDomainSubdomain(void **state)
{
    bool ret_flag = false;
    for (uint32_t index = 0U; index < ERROR_SUBDOMAIN_TBL_BLOCK_LEN; index++) {
        bool ret = IsValidUrlOrNullString(ErrorSubdomainTbl[index], 256);
        if (ret != false) {
            print_message("[invalid NG]   %s\n", ErrorSubdomainTbl[index]);
            ret_flag = true;
        }
        else {
            print_message("[       OK ]   %s\n", ErrorSubdomainTbl[index]);
        }
    }
    assert_int_equal(ret_flag, false);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidUrlOrNullString_ErrorUrlLength254(void **state)
{
    char *url =
        "o123456789abcde.o123456789abcde.o123456789abcde.o123456789abcde."
        "o123456789abcde.o123456789abcde.o123456789abcde.o123456789abcde."
        "o123456789abcde.o123456789abcde.o123456789abcde.o123456789abcde."
        "o123456789abcde.o123456789abcde.o123456789abcde.o1234567abc.jp";
    bool ret = IsValidUrlOrNullString(url, 256);
    assert_int_equal(ret, false);
    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCfgNetworkSettings()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_FullySuccess(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash_ErrorMalloc();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorEsfJsonOpen(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonErrorCode esfj_open_err_ret = kEsfJsonInternalError;

    // CASE: EsfJsonOpen fails.
    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, esfj_open_err_ret);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorEsfJsonDeserialize(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonErrorCode esfj_open_ret = kEsfJsonSuccess;
    EsfJsonErrorCode esfj_close_ret = kEsfJsonSuccess;
    EsfJsonErrorCode esfj_deser_err_ret = kEsfJsonInternalError;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, esfj_open_ret);

    // CASE: EsfJsonDeserialize fails.
    // For EsfJsonDeserialize()
    expect_value(__wrap_EsfJsonDeserialize, handle, esfj_handle);
    expect_string(__wrap_EsfJsonDeserialize, str, network_settings);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, esfj_deser_err_ret);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, esfj_close_ret);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorSysAppCmnGetReqId(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *req_id = "1";
    int ip_method = DhcpIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    // CASE: SysAppCmnGetReqId fails.
    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetFailed);

    // For SysAppStateUpdateString() about req_id
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, Id);
    expect_string(__wrap_SysAppStateUpdateString, string, "0");
    will_return(__wrap_SysAppStateUpdateString, kRetOk);

    // For SysAppStateSetInvalidArgError() about req_id
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, Id);
    will_return(__wrap_SysAppStateSetInvalidArgError, kEsfJsonSuccess);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash_NotIP();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_NotFoundSysAppCmnGetReqId(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *req_id = "1";
    int ip_method = DhcpIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    // CASE: SysAppCmnGetReqId fails.
    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetNotFound);

    // For SysAppStateUpdateString() about req_id
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, Id);
    expect_string(__wrap_SysAppStateUpdateString, string, "0");
    will_return(__wrap_SysAppStateUpdateString, kRetOk);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash_ErrorEsfNetworkManagerLoadParameter();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorCmnGetReqIdReqIdTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *req_id =
        "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "111111111111111111111111111111111111111";
    int ip_method = DhcpIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    // CASE: SysAppCmnGetReqId retrieves a long req_id
    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // For SysAppStateUpdateString() about req_id
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, Id);
    expect_string(__wrap_SysAppStateUpdateString, string, "0");
    will_return(__wrap_SysAppStateUpdateString, kRetOk);

    // For SysAppStateSetInvalidArgError() about req_id
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, Id);
    will_return(__wrap_SysAppStateSetInvalidArgError, kEsfJsonSuccess);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash_NotSubnetmask();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorCmnGetReqIdReqIdNullPtr(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *req_id = "1";
    int ip_method = DhcpIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // CASE: SysAppStateGetReqId retrieves a null pointer.
    // For SysAppStateGetReqId() about req_id in CheckUpdateString
    expect_value(__wrap_SysAppStateGetReqId, topic, topic);
    will_return(__wrap_SysAppStateGetReqId, NULL);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash_NotGateway();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_CmnGetReqIdReqIdNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *req_id = "1";
    int ip_method = DhcpIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    // CASE: SysAppCmnGetReqId retrieves the same req_id.
    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // For SysAppStateGetReqId() about req_id in CheckUpdateString
    expect_value(__wrap_SysAppStateGetReqId, topic, topic);
    will_return(__wrap_SysAppStateGetReqId, "1");

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash_NotDNS();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorLoadIpMethodFromEsf(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, -1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // For EsfNetworkManagerLoadParameter() about ip_mathod in LoadIpMethodFromEsf
    will_return(__wrap_EsfNetworkManagerLoadParameter, StaticIp);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultInternalError);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorSysAppCmnExtractNumberValue(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // CASE: SysAppCmnExtractNumberValue fails.
    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, -1);

    // For EsfNetworkManagerLoadParameter() about ip_mathod in LoadIpMethodFromEsf
    will_return(__wrap_EsfNetworkManagerLoadParameter, DhcpIp);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorCmnExtractNumInvalidIpMethod(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // CASE: SysAppCmnExtractNumberValue retrieves zero.
    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 0);

    // For SysAppStateSetInvalidArgError() about ip_method
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, IpMethod);
    will_return(__wrap_SysAppStateSetInvalidArgError, kEsfJsonSuccess);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorCmnExtractNumIpMethodOutOfRangeSmall(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = -1;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid ip_method.
    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    // For SysAppStateSetInvalidArgError() about ip_method
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, IpMethod);
    will_return(__wrap_SysAppStateSetInvalidArgError, kEsfJsonSuccess);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    // For EsfNetworkManagerLoadParameter() in CheckUpdateNumber
    will_return(__wrap_EsfNetworkManagerLoadParameter, StaticIp);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    ForEsfNetworkManagerSaveParameterIpMethod(ip_method, kEsfNetworkManagerResultInvalidParameter);

    // For EsfNetworkManagerLoadParameter()
    will_return(__wrap_EsfNetworkManagerLoadParameter, ip_method);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For SysAppStateSetInternalError() about ip_method
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, IpMethod);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorCmnExtractNumIpMethodOutOfRangeLarge(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = IpMethodNum;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid ip_method.
    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    // For SysAppStateSetInvalidArgError() about ip_method
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, IpMethod);
    will_return(__wrap_SysAppStateSetInvalidArgError, kEsfJsonSuccess);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    // For EsfNetworkManagerLoadParameter() in CheckUpdateNumber
    will_return(__wrap_EsfNetworkManagerLoadParameter, StaticIp);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    ForEsfNetworkManagerSaveParameterIpMethod(ip_method, kEsfNetworkManagerResultInvalidParameter);

    // For EsfNetworkManagerLoadParameter()
    will_return(__wrap_EsfNetworkManagerLoadParameter, ip_method);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For SysAppStateSetInternalError() about ip_method
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, IpMethod);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorSysAppCmnExtractStringValue(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    const char *ntp_url = "ntp-domain.jp";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    // CASE: SysAppCmnExtractStringValue fails.
    // For SysAppCmnExtractStringValue()
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ntp_url", ntp_url, -1);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorCmnExtractStrInvalidNtpUrl(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    const char *ntp_url = "ntp-domain.jp";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    // CASE: SysAppCmnExtractStringValue retrieves zero.
    // For SysAppCmnExtractStringValue()
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ntp_url", ntp_url, 0);

    // For SysAppStateSetInvalidArgError() about ntp_url
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, NtpUrl);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorCmnExtractStrNtpUrlTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    const char *ntp_url =
        "ntp-domain-"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    // CASE: SysAppCmnExtractStringValue retrieves an invalid ntp_url.
    // For SysAppCmnExtractStringValue()
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ntp_url", ntp_url, 1);

    // For SysAppStateSetInvalidArgError() about ntp_url
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, NtpUrl);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorCmnExtractStrNtpUrlLen254(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    const char *ntp_url =
        "ntp-domain-"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    // CASE: SysAppCmnExtractStringValue retrieves an invalid ntp_url.
    // For SysAppCmnExtractStringValue()
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ntp_url", ntp_url, 1);

    // For SysAppStateSetInvalidArgError() about ntp_url
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, NtpUrl);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorEsfCMGetParamsNtpUrl(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    const char *ntp_url = "ntp-domain.jp";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    // For SysAppCmnExtractStringValue()
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ntp_url", ntp_url, 1);

    // CASE: EsfClockManagerGetParams fails.
    // For EsfClockManagerGetParams() about ntp_url in CheckUpdateString
    ForEsfClockManagerGetParams("old-ntp-domain.jp", kClockManagerInternalError);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_CmnExtractStrNtpUrlNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    const char *ntp_url = "ntp-domain.jp";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    // For SysAppCmnExtractStringValue()
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ntp_url", ntp_url, 1);

    // CASE: EsfClockManagerGetParams retrieves the same ntp_url.
    // For EsfClockManagerGetParams() about ntp_url in CheckUpdateString
    ForEsfClockManagerGetParams("ntp-domain.jp", kClockManagerSuccess);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorEsfClockManagerSetParamsForcibly(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    const char *ntp_url = "ntp-domain.jp";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    // For SysAppCmnExtractStringValue()
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ntp_url", ntp_url, 1);

    // For EsfClockManagerGetParams() about ntp_url in CheckUpdateString
    ForEsfClockManagerGetParams("old-ntp-domain.jp", kClockManagerSuccess);

    // CASE: EsfClockManagerSetParamsForcibly fails.
    // For EsfClockManagerSetParamsForcibly()
    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, ntp_url);
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerInternalError);

    // For SysAppStateSetInternalError() about ntp_url
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, NtpUrl);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorEsfClockManagerGetParams(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    const char *ntp_url = "ntp-domain.jp";
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    // For SysAppCmnExtractStringValue()
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ntp_url", ntp_url, 1);

    // For EsfClockManagerGetParams() about ntp_url in CheckUpdateString
    ForEsfClockManagerGetParams("old-ntp-domain.jp", kClockManagerSuccess);

    // For EsfClockManagerSetParamsForcibly()
    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, ntp_url);
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    // For EsfClockManagerGetParams() about ntp_url in Reread after write
    ForEsfClockManagerGetParams("default.domain.jp", kClockManagerInternalError);

    // For SysAppStateSetInternalError() about ntp_url
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, NtpUrl);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorEsfJsonObjectGetIpv6(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = StaticIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // CASE: EsfJsonObjectGet fails.
    // For EsfJsonObjectGet() about ipv6
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "static_settings_ipv6");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonInternalError);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsIpv4(esfj_handle, json_value, ipv4_serialized);
    CheckSysAppCfgStaticSettingsIpv4(ipv4_serialized);

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(DhcpIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorEsfJsonValueTypeGetIpv6(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = StaticIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For EsfJsonObjectGet() about ipv6
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "static_settings_ipv6");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // CASE: EsfJsonValueTypeGet fails.
    // For EsfJsonValueTypeGet() about ipv6
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeObject);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonInternalError);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsIpv4(esfj_handle, json_value, ipv4_serialized);
    CheckSysAppCfgStaticSettingsIpv4(ipv4_serialized);

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(DhcpIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorEsfJsonTypeGetIpv6NotObject(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = StaticIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For EsfJsonObjectGet() about ipv6
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "static_settings_ipv6");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // CASE: EsfJsonValueTypeGet retrieves kEsfJsonValueTypeNull.
    // For EsfJsonValueTypeGet() about ipv6
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeNull);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsIpv4(esfj_handle, json_value, ipv4_serialized);
    CheckSysAppCfgStaticSettingsIpv4(ipv4_serialized);

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(DhcpIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorEsfJsonSerializeIpv6(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = StaticIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For EsfJsonObjectGet() about ipv6
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "static_settings_ipv6");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // For EsfJsonValueTypeGet() about ipv6
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeObject);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // CASE: EsfJsonSerialize fails.
    // For EsfJsonSerialize() about ipv6
    ForEsfJsonSerialize(esfj_handle, json_value, ipv6_serialized, kEsfJsonInternalError);

    // For EsfJsonSerializeFree() about ipv6
    ForEsfJsonSerializeFree(esfj_handle, kEsfJsonSuccess);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsIpv4(esfj_handle, json_value, ipv4_serialized);
    CheckSysAppCfgStaticSettingsIpv4(ipv4_serialized);

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(DhcpIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorEsfJsonSerializeIpv6NullPtr(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = StaticIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For EsfJsonObjectGet() about ipv6
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "static_settings_ipv6");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // For EsfJsonValueTypeGet() about ipv6
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeObject);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // CASE: EsfJsonSerialize retrieves a null pointer.
    // For EsfJsonSerialize() about ipv6
    ForEsfJsonSerialize(esfj_handle, json_value, NULL, kEsfJsonSuccess);

    // For EsfJsonSerializeFree() about ipv6
    ForEsfJsonSerializeFree(esfj_handle, kEsfJsonSuccess);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsIpv4(esfj_handle, json_value, ipv4_serialized);
    CheckSysAppCfgStaticSettingsIpv4(ipv4_serialized);

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(DhcpIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorEsfJsonObjectGetIpv4(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = StaticIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    CheckSysAppCfgNetworkSettingsIpv6(esfj_handle, json_value, ipv6_serialized);
    CheckSysAppCfgStaticSettingsIpv6(ipv6_serialized);

    // CASE: EsfJsonObjectGet fails.
    // For EsfJsonObjectGet() about ipv4
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "static_settings_ipv4");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonInternalError);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(DhcpIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorEsfJsonValueTypeGetIpv4(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = StaticIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    CheckSysAppCfgNetworkSettingsIpv6(esfj_handle, json_value, ipv6_serialized);
    CheckSysAppCfgStaticSettingsIpv6(ipv6_serialized);

    // For EsfJsonObjectGet() about ipv4
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "static_settings_ipv4");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // CASE: EsfJsonValueTypeGet fails.
    // For EsfJsonValueTypeGet() about ipv4
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeObject);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonInternalError);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(DhcpIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorEsfJsonTypeGetIpv4NotObject(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = StaticIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    CheckSysAppCfgNetworkSettingsIpv6(esfj_handle, json_value, ipv6_serialized);
    CheckSysAppCfgStaticSettingsIpv6(ipv6_serialized);

    // For EsfJsonObjectGet() about ipv4
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "static_settings_ipv4");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // CASE: EsfJsonValueTypeGet retrieves kEsfJsonValueTypeNull.
    // For EsfJsonValueTypeGet() about ipv4
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeNull);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(DhcpIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorEsfJsonSerializeIpv4(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = StaticIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    CheckSysAppCfgNetworkSettingsIpv6(esfj_handle, json_value, ipv6_serialized);
    CheckSysAppCfgStaticSettingsIpv6(ipv6_serialized);

    // For EsfJsonObjectGet() about ipv4
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "static_settings_ipv4");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // For EsfJsonValueTypeGet() about ipv4
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeObject);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // CASE: EsfJsonSerialize fails.
    // For EsfJsonSerialize() about ipv4
    ForEsfJsonSerialize(esfj_handle, json_value, ipv4_serialized, kEsfJsonInternalError);

    // For EsfJsonSerializeFree() about ipv4
    ForEsfJsonSerializeFree(esfj_handle, kEsfJsonSuccess);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(DhcpIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorEsfJsonSerializeIpv4NullPtr(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = StaticIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    CheckSysAppCfgNetworkSettingsIpv6(esfj_handle, json_value, ipv6_serialized);
    CheckSysAppCfgStaticSettingsIpv6(ipv6_serialized);

    // For EsfJsonObjectGet() about ipv4
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "static_settings_ipv4");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // For EsfJsonValueTypeGet() about ipv4
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeObject);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // CASE: EsfJsonSerialize retrieves a null pointer.
    // For EsfJsonSerialize() about ipv4
    ForEsfJsonSerialize(esfj_handle, json_value, NULL, kEsfJsonSuccess);

    // For EsfJsonSerializeFree() about ipv4
    ForEsfJsonSerializeFree(esfj_handle, kEsfJsonSuccess);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(DhcpIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorStaticSettingsIPv4EsfJsonOpen(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = StaticIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    CheckSysAppCfgNetworkSettingsIpv6(esfj_handle, json_value, ipv6_serialized);
    CheckSysAppCfgStaticSettingsIpv6(ipv6_serialized);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    // For EsfJsonObjectGet() about ipv4
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "static_settings_ipv4");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // For EsfJsonValueTypeGet() about ipv4
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeObject);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // For EsfJsonSerialize() about ipv4
    ForEsfJsonSerialize(esfj_handle, json_value, ipv4_serialized, kEsfJsonSuccess);

    // For EsfJsonSerializeFree() about ipv4
    ForEsfJsonSerializeFree(esfj_handle, kEsfJsonSuccess);

    // CASE: EsfJsonOpen fails.
    // For EsfJsonOpen() in SysAppCfgStaticSettingsIPv4
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    // For EsfNetworkManagerLoadParameter()
    will_return(__wrap_EsfNetworkManagerLoadParameter, ip_method);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorEsfJsonObjectGetProxySettings(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // CASE: EsfJsonObjectGet fails.
    // For EsfJsonObjectGet() about proxy_settings
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "proxy_settings");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonInternalError);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorEsfJsonValueTypeGetProxySettings(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For EsfJsonObjectGet() about proxy_settings
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "proxy_settings");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // CASE: EsfJsonValueTypeGet fails.
    // For EsfJsonValueTypeGet() about proxy_settings
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeObject);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonInternalError);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorEsfJsonTypeGetProxySettingsNotObject(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For EsfJsonObjectGet() about proxy_settings
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "proxy_settings");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // CASE: EsfJsonValueTypeGet retrieves kEsfJsonValueTypeNull.
    // For EsfJsonValueTypeGet() about proxy_settings
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeNull);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorEsfJsonSerializeProxySettings(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For EsfJsonObjectGet() about proxy_settings
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "proxy_settings");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // For EsfJsonValueTypeGet() about proxy_settings
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeObject);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // CASE: EsfJsonSerialize fails.
    // For EsfJsonSerialize() about proxy_settings
    ForEsfJsonSerialize(esfj_handle, json_value, proxy_settings, kEsfJsonInternalError);

    // For EsfJsonSerializeFree() about proxy_settings
    ForEsfJsonSerializeFree(esfj_handle, kEsfJsonSuccess);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorEsfJsonSerializeProxySettingsNullPtr(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For EsfJsonObjectGet() about proxy_settings
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "proxy_settings");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // For EsfJsonValueTypeGet() about proxy_settings
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeObject);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // CASE: EsfJsonSerialize retrieves a null pointer.
    // For EsfJsonSerialize() about proxy_settings
    ForEsfJsonSerialize(esfj_handle, json_value, NULL, kEsfJsonSuccess);

    // For EsfJsonSerializeFree() about proxy_settings
    ForEsfJsonSerializeFree(esfj_handle, kEsfJsonSuccess);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorNMLoadParamIpMethod(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // For EsfNetworkManagerLoadParameter() about ip_method in CheckUpdateNumber
    will_return(__wrap_EsfNetworkManagerLoadParameter, ip_method);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultInternalError);

    // For EsfNetworkManagerLoadParameter()
    will_return(__wrap_EsfNetworkManagerLoadParameter, ip_method);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}
/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_IpMethodNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    // CASE: EsfNetworkManagerLoadParameter retrieves the same ip_method.
    // For EsfNetworkManagerLoadParameter() about ip_method in CheckUpdateNumber
    will_return(__wrap_EsfNetworkManagerLoadParameter, ip_method);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For EsfNetworkManagerLoadParameter()
    will_return(__wrap_EsfNetworkManagerLoadParameter, StaticIp);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For SysAppStateSetInvalidArgError() about ip_method
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, IpMethod);
    will_return(__wrap_SysAppStateSetInvalidArgError, kEsfJsonSuccess);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorEsfNMSaveParam(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    // For EsfNetworkManagerLoadParameter() about ip_method in CheckUpdateNumber
    will_return(__wrap_EsfNetworkManagerLoadParameter, StaticIp);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // CASE: EsfNetworkManagerSaveParameter fails.
    ForEsfNetworkManagerSaveParameterIpMethod(ip_method, kEsfNetworkManagerResultInternalError);

    // For EsfNetworkManagerLoadParameter()
    will_return(__wrap_EsfNetworkManagerLoadParameter, ip_method);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For SysAppStateSetInternalError() about ip_method
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, IpMethod);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorSysAppStateSendState(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    // CASE: SysAppStateSendState fails.
    // For SysAppStateSendState()
    expect_value(__wrap_SysAppStateSendState, req, topic);
    will_return(__wrap_SysAppStateSendState, kRetFailed);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgNetworkSettings_ErrorEsfJsonClose(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int ip_method = DhcpIp;
    uint32_t topic = ST_TOPIC_NETWORK_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, network_settings);

    CheckSysAppCfgNetworkSettingsReqId(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue()
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "ip_method", ip_method, 1);

    CheckSysAppCfgNetworkSettingsNtpUrl(esfj_handle, json_value);

    // For ExistStaticIPv4InFlash()
    ForExistStaticIPv4InFlash();

    CheckSysAppCfgNetworkSettingsProxySettings(esfj_handle, json_value, proxy_settings);
    CheckSysAppCfgProxySettings(proxy_settings);

    CheckSysAppCfgNetworkSettingsUpdateIpMethod(StaticIp, ip_method);

    // For SysAppStateSendState()
    expect_value(__wrap_SysAppStateSendState, req, topic);
    will_return(__wrap_SysAppStateSendState, kRetOk);

    // CASE: EsfJsonClose fails.
    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonInternalError);

    // Exec test target
    ret = SysAppCfgNetworkSettings(network_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCfgIntervalSetting()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgIntervalSetting_FullySuccess(void **state)
{
    RetCode ret;
    int index = 0;

    CheckSysAppCfgIntervalSetting(interval_settings, index);

    // Exec test target
    ret = SysAppCfgIntervalSetting(interval_settings, index);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgIntervalSetting_ErrorEsfJsonOpen(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    int index = 0;

    // CASE: EsfJsonOpen fails.
    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);

    // Exec test target
    ret = SysAppCfgIntervalSetting(interval_settings, index);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgIntervalSetting_ErrorEsfJsonDeserialize(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int index = 0;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // CASE: EsfJsonDeserialize fails.
    // For EsfJsonDeserialize()
    expect_value(__wrap_EsfJsonDeserialize, handle, esfj_handle);
    expect_string(__wrap_EsfJsonDeserialize, str, interval_settings);
    will_return(__wrap_EsfJsonDeserialize, json_value);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonInternalError);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgIntervalSetting(interval_settings, index);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgIntervalSetting_ErrorEsfJsonClose(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int index = 0;

    CheckJsonOpen(esfj_handle, json_value, interval_settings);

    CheckIntervalStrProperty(esfj_handle, json_value, index, "base_time", BaseTime, "00:00", "");

    CheckIntervalNumProperty(esfj_handle, json_value, index, "capture_interval", CaptureInterval, 3,
                             4);

    CheckIntervalNumProperty(esfj_handle, json_value, index, "config_interval", ConfigInterval, 5,
                             6);

    // CASE: EsfJsonClose fails.
    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonInternalError);

    // Exec test target
    ret = SysAppCfgIntervalSetting(interval_settings, index);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgIntervalSetting_ErrorCmnExtractStrBaseTime(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int index = 0;

    CheckJsonOpen(esfj_handle, json_value, interval_settings);

    // CASE: SysAppCmnExtractStringValue fails.
    // For SysAppCmnExtractStringValue()
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "base_time", "00:00", -1);

    CheckIntervalNumProperty(esfj_handle, json_value, index, "capture_interval", CaptureInterval, 3,
                             4);

    CheckIntervalNumProperty(esfj_handle, json_value, index, "config_interval", ConfigInterval, 5,
                             6);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgIntervalSetting(interval_settings, index);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgIntervalSetting_ErrorInvalidBaseTime(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int index = 0;
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, interval_settings);

    // CASE: SysAppCmnExtractStringValue retrieves zero.
    // For SysAppCmnExtractStringValue()
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "base_time", "00:00", 0);

    // For SysAppStateSetInvalidArgErrorWithIdx() about base_time
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, BaseTime, index, kRetOk);

    CheckIntervalNumProperty(esfj_handle, json_value, index, "capture_interval", CaptureInterval, 3,
                             4);

    CheckIntervalNumProperty(esfj_handle, json_value, index, "config_interval", ConfigInterval, 5,
                             6);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgIntervalSetting(interval_settings, index);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgIntervalSetting_ErrorBaseTimeTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int index = 0;
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, interval_settings);

    // CASE: SysAppCmnExtractStringValue retrieves an invalid base_time.
    // For SysAppCmnExtractStringValue()
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "base_time", "00:000", 0);

    // For SysAppStateSetInvalidArgErrorWithIdx() about base_time
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, BaseTime, index, kRetOk);

    CheckIntervalNumProperty(esfj_handle, json_value, index, "capture_interval", CaptureInterval, 3,
                             4);

    CheckIntervalNumProperty(esfj_handle, json_value, index, "config_interval", ConfigInterval, 5,
                             6);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgIntervalSetting(interval_settings, index);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgIntervalSetting_ErrorCmnExtractNumCaptureInterval(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int index = 0;

    CheckJsonOpen(esfj_handle, json_value, interval_settings);

    CheckIntervalStrProperty(esfj_handle, json_value, index, "base_time", BaseTime, "00:00", "");

    // CASE: SysAppCmnExtractNumberValue fails.
    // For SysAppCmnExtractNumberValue() about capture_interval
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "capture_interval", 3, -1);

    CheckIntervalNumProperty(esfj_handle, json_value, index, "config_interval", ConfigInterval, 5,
                             6);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgIntervalSetting(interval_settings, index);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgIntervalSetting_ErrorInvalidCaptureInterval(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int index = 0;
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, interval_settings);

    CheckIntervalStrProperty(esfj_handle, json_value, index, "base_time", BaseTime, "00:00", "");

    // CASE: SysAppCmnExtractNumberValue retrieves zero.
    // For SysAppCmnExtractNumberValue() about capture_interval
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "capture_interval", 3, 0);

    // For SysAppStateSetInvalidArgErrorWithIdx() about capture_interval
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, CaptureInterval, index, kRetOk);

    CheckIntervalNumProperty(esfj_handle, json_value, index, "config_interval", ConfigInterval, 5,
                             6);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgIntervalSetting(interval_settings, index);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgIntervalSetting_ErrorCaptureIntervalTooSmall(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int index = 0;
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, interval_settings);

    CheckIntervalStrProperty(esfj_handle, json_value, index, "base_time", BaseTime, "00:00", "");

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid capture_interval.
    // For SysAppCmnExtractNumberValue() about capture_interval
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "capture_interval", -1, 1);

    // For SysAppStateSetInvalidArgErrorWithIdx() about capture_interval
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, CaptureInterval, index, kRetOk);

    CheckIntervalNumProperty(esfj_handle, json_value, index, "config_interval", ConfigInterval, 5,
                             6);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgIntervalSetting(interval_settings, index);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgIntervalSetting_ErrorCaptureIntervalOutOfRange(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int index = 0;
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, interval_settings);

    CheckIntervalStrProperty(esfj_handle, json_value, index, "base_time", BaseTime, "00:00", "");

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid capture_interval.
    // For SysAppCmnExtractNumberValue() about capture_interval
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "capture_interval", 1, 1);

    // For SysAppStateSetInvalidArgErrorWithIdx() about capture_interval
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, CaptureInterval, index, kRetOk);

    CheckIntervalNumProperty(esfj_handle, json_value, index, "config_interval", ConfigInterval, 5,
                             6);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgIntervalSetting(interval_settings, index);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgIntervalSetting_ErrorCaptureIntervalTooLarge(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int index = 0;
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, interval_settings);

    CheckIntervalStrProperty(esfj_handle, json_value, index, "base_time", BaseTime, "00:00", "");

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid capture_interval.
    // For SysAppCmnExtractNumberValue() about capture_interval
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "capture_interval", 1441, 1);

    // For SysAppStateSetInvalidArgErrorWithIdx() about capture_interval
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, CaptureInterval, index, kRetOk);

    CheckIntervalNumProperty(esfj_handle, json_value, index, "config_interval", ConfigInterval, 5,
                             6);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgIntervalSetting(interval_settings, index);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgIntervalSetting_CaptureIntervalZero(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int index = 0;

    CheckJsonOpen(esfj_handle, json_value, interval_settings);

    CheckIntervalStrProperty(esfj_handle, json_value, index, "base_time", BaseTime, "00:00", "");

    // CASE: AppCmnExtractNumberValue retrieves zero as capture_interval.
    CheckIntervalNumProperty(esfj_handle, json_value, index, "capture_interval", CaptureInterval, 0,
                             4);

    CheckIntervalNumProperty(esfj_handle, json_value, index, "config_interval", ConfigInterval, 5,
                             6);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgIntervalSetting(interval_settings, index);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgIntervalSetting_ErrorCmnExtractNumConfigInterval(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int index = 0;

    CheckJsonOpen(esfj_handle, json_value, interval_settings);

    CheckIntervalStrProperty(esfj_handle, json_value, index, "base_time", BaseTime, "00:00", "");

    CheckIntervalNumProperty(esfj_handle, json_value, index, "capture_interval", CaptureInterval, 3,
                             4);

    // CASE: SysAppCmnExtractNumberValue fails.
    // For SysAppCmnExtractNumberValue() about config_interval
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "config_interval", 5, -1);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgIntervalSetting(interval_settings, index);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgIntervalSetting_ErrorInvalidConfigInterval(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int index = 0;
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, interval_settings);

    CheckIntervalStrProperty(esfj_handle, json_value, index, "base_time", BaseTime, "00:00", "");

    CheckIntervalNumProperty(esfj_handle, json_value, index, "capture_interval", CaptureInterval, 3,
                             4);

    // CASE: SysAppCmnExtractNumberValue retrieves zero.
    // For SysAppCmnExtractNumberValue() about config_interval
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "config_interval", 5, 0);

    // For SysAppStateSetInvalidArgErrorWithIdx() about config_interval
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, ConfigInterval, index, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgIntervalSetting(interval_settings, index);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgIntervalSetting_ErrorConfigIntervalTooSmall(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int index = 0;
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, interval_settings);

    CheckIntervalStrProperty(esfj_handle, json_value, index, "base_time", BaseTime, "00:00", "");

    CheckIntervalNumProperty(esfj_handle, json_value, index, "capture_interval", CaptureInterval, 3,
                             4);

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid config_interval.
    // For SysAppCmnExtractNumberValue() about config_interval
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "config_interval", -1, 1);

    // For SysAppStateSetInvalidArgErrorWithIdx() about config_interval
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, ConfigInterval, index, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgIntervalSetting(interval_settings, index);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgIntervalSetting_ErrorConfigIntervalOutOfRange(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int index = 0;
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, interval_settings);

    CheckIntervalStrProperty(esfj_handle, json_value, index, "base_time", BaseTime, "00:00", "");

    CheckIntervalNumProperty(esfj_handle, json_value, index, "capture_interval", CaptureInterval, 3,
                             4);

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid config_interval.
    // For SysAppCmnExtractNumberValue() about config_interval
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "config_interval", 1, 1);

    // For SysAppStateSetInvalidArgErrorWithIdx() about config_interval
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, ConfigInterval, index, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgIntervalSetting(interval_settings, index);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgIntervalSetting_ErrorConfigIntervalTooLarge(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int index = 0;
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, interval_settings);

    CheckIntervalStrProperty(esfj_handle, json_value, index, "base_time", BaseTime, "00:00", "");

    CheckIntervalNumProperty(esfj_handle, json_value, index, "capture_interval", CaptureInterval, 3,
                             4);

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid config_interval.
    // For SysAppCmnExtractNumberValue() about config_interval
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "config_interval", 1441, 1);

    // For SysAppStateSetInvalidArgErrorWithIdx() about config_interval
    ForSysAppStateSetInvalidArgErrorWithIdx(topic, ConfigInterval, index, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgIntervalSetting(interval_settings, index);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgIntervalSetting_ConfigIntervalZero(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    int index = 0;

    CheckJsonOpen(esfj_handle, json_value, interval_settings);

    CheckIntervalStrProperty(esfj_handle, json_value, index, "base_time", BaseTime, "00:00", "");

    CheckIntervalNumProperty(esfj_handle, json_value, index, "capture_interval", CaptureInterval, 3,
                             4);

    // CASE: SysAppCmnExtractNumberValue retrieves zero as config_interval.
    CheckIntervalNumProperty(esfj_handle, json_value, index, "config_interval", ConfigInterval, 0,
                             6);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgIntervalSetting(interval_settings, index);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCfgPeriodicSetting()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_FullySuccess(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    CheckSysAppCfgPeriodicSettingReqId(esfj_handle, json_value);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    CheckSysAppCfgPeriodicSettingIntervalSettings(esfj_handle, json_value, interval_settings);
    CheckSysAppCfgIntervalSetting(interval_settings, 0);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorEsfJsonOpen(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;

    // CASE: EsfJsonOpen fails.
    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorEsfJsonDeserialize(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // CASE: EsfJsonDeserialize fails.
    // For EsfJsonDeserialize()
    expect_value(__wrap_EsfJsonDeserialize, handle, esfj_handle);
    expect_string(__wrap_EsfJsonDeserialize, str, periodic_setting);
    will_return(__wrap_EsfJsonDeserialize, json_value);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonInternalError);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorSysAppCmnGetReqId(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *req_id = "1";
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    // CASE: SysAppCmnGetReqId fails.
    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetFailed);

    // For SysAppStateUpdateString() about req_id
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, Id);
    expect_string(__wrap_SysAppStateUpdateString, string, "0");
    will_return(__wrap_SysAppStateUpdateString, kRetOk);

    // For SysAppStateSetInvalidArgError() about req_id
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, Id);
    will_return(__wrap_SysAppStateSetInvalidArgError, kEsfJsonSuccess);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    CheckSysAppCfgPeriodicSettingIntervalSettings(esfj_handle, json_value, interval_settings);
    CheckSysAppCfgIntervalSetting(interval_settings, 0);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_NotFoundSysAppCmnGetReqId(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *req_id = "1";
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    // CASE: SysAppCmnGetReqId fails.
    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetNotFound);

    // For SysAppStateUpdateString() about req_id
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, Id);
    expect_string(__wrap_SysAppStateUpdateString, string, "0");
    will_return(__wrap_SysAppStateUpdateString, kRetOk);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    CheckSysAppCfgPeriodicSettingIntervalSettings(esfj_handle, json_value, interval_settings);
    CheckSysAppCfgIntervalSetting(interval_settings, 0);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetNotFound);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorReqIdTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *req_id =
        "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "111111111111111111111111111111111111111";
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    // CASE: SysAppCmnGetReqId retrieves a long req_id.
    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // For SysAppStateUpdateString() about req_id
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, Id);
    expect_string(__wrap_SysAppStateUpdateString, string, "0");
    will_return(__wrap_SysAppStateUpdateString, kRetOk);

    // For SysAppStateSetInvalidArgError() about req_id
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, Id);
    will_return(__wrap_SysAppStateSetInvalidArgError, kEsfJsonSuccess);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    CheckSysAppCfgPeriodicSettingIntervalSettings(esfj_handle, json_value, interval_settings);
    CheckSysAppCfgIntervalSetting(interval_settings, 0);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorSysAppStateGetReqId(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *req_id = "1";
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // CASE: SysAppStateGetReqId retrieves a null pointer.
    // For SysAppStateGetReqId() about req_id in CheckUpdateString
    expect_value(__wrap_SysAppStateGetReqId, topic, topic);
    will_return(__wrap_SysAppStateGetReqId, NULL);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    CheckSysAppCfgPeriodicSettingIntervalSettings(esfj_handle, json_value, interval_settings);
    CheckSysAppCfgIntervalSetting(interval_settings, 0);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ReqIdNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *req_id = "1";
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // CASE: SysAppStateGetReqId retrieves the same req_id.
    // For SysAppStateGetReqId() about req_id in CheckUpdateString
    expect_value(__wrap_SysAppStateGetReqId, topic, topic);
    will_return(__wrap_SysAppStateGetReqId, req_id);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    CheckSysAppCfgPeriodicSettingIntervalSettings(esfj_handle, json_value, interval_settings);
    CheckSysAppCfgIntervalSetting(interval_settings, 0);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorCmnExtractNumOperationMode(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    CheckSysAppCfgPeriodicSettingReqId(esfj_handle, json_value);

    // CASE: SysAppCmnExtractNumberValue fails.
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "operation_mode", ContinuoutMode, -1);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    CheckSysAppCfgPeriodicSettingIntervalSettings(esfj_handle, json_value, interval_settings);
    CheckSysAppCfgIntervalSetting(interval_settings, 0);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorCmnExtractNumInvalidOperationMode(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    CheckSysAppCfgPeriodicSettingReqId(esfj_handle, json_value);

    // CASE: SysAppCmnExtractNumberValue retrieves zero.
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "operation_mode", ContinuoutMode, 0);

    // For SysAppStateSetInvalidArgError() about operation_mode
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, OperationMode);
    will_return(__wrap_SysAppStateSetInvalidArgError, kEsfJsonSuccess);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    CheckSysAppCfgPeriodicSettingIntervalSettings(esfj_handle, json_value, interval_settings);
    CheckSysAppCfgIntervalSetting(interval_settings, 0);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorOperationModeTooSmall(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    CheckSysAppCfgPeriodicSettingReqId(esfj_handle, json_value);

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid operation_mode.
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "operation_mode", -1, 1);

    // For SysAppStateSetInvalidArgError() about operation_mode
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, OperationMode);
    will_return(__wrap_SysAppStateSetInvalidArgError, kEsfJsonSuccess);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    CheckSysAppCfgPeriodicSettingIntervalSettings(esfj_handle, json_value, interval_settings);
    CheckSysAppCfgIntervalSetting(interval_settings, 0);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorOperationModeTooLarge(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    CheckSysAppCfgPeriodicSettingReqId(esfj_handle, json_value);

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid operation_mode.
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "operation_mode", OperationModeNum, 1);

    // For SysAppStateSetInvalidArgError() about operation_mode
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, OperationMode);
    will_return(__wrap_SysAppStateSetInvalidArgError, kEsfJsonSuccess);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    CheckSysAppCfgPeriodicSettingIntervalSettings(esfj_handle, json_value, interval_settings);
    CheckSysAppCfgIntervalSetting(interval_settings, 0);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorCmnExtractNumRecoveryMethod(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    CheckSysAppCfgPeriodicSettingReqId(esfj_handle, json_value);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    // CASE: SysAppCmnExtractNumberValue fails.
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "recovery_method", ManualReset, -1);

    CheckSysAppCfgPeriodicSettingIntervalSettings(esfj_handle, json_value, interval_settings);
    CheckSysAppCfgIntervalSetting(interval_settings, 0);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorCmnExtractNumInvalidRecoveryMethod(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    CheckSysAppCfgPeriodicSettingReqId(esfj_handle, json_value);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    // CASE: SysAppCmnExtractNumberValue retrieves zero.
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "recovery_method", ManualReset, 0);

    // For SysAppStateSetInvalidArgError() about recovery_method
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, RecoveryMethod);
    will_return(__wrap_SysAppStateSetInvalidArgError, kEsfJsonSuccess);

    CheckSysAppCfgPeriodicSettingIntervalSettings(esfj_handle, json_value, interval_settings);
    CheckSysAppCfgIntervalSetting(interval_settings, 0);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorRecoveryMethodTooSmall(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    CheckSysAppCfgPeriodicSettingReqId(esfj_handle, json_value);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid recovery_method.
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "recovery_method", -1, 1);

    // For SysAppStateSetInvalidArgError() about recovery_method
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, RecoveryMethod);
    will_return(__wrap_SysAppStateSetInvalidArgError, kEsfJsonSuccess);

    CheckSysAppCfgPeriodicSettingIntervalSettings(esfj_handle, json_value, interval_settings);
    CheckSysAppCfgIntervalSetting(interval_settings, 0);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorRecoveryMethodTooLarge(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    CheckSysAppCfgPeriodicSettingReqId(esfj_handle, json_value);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid recovery_method.
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "recovery_method", RecoveryMethodNum,
                                   1);

    // For SysAppStateSetInvalidArgError() about recovery_method
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, RecoveryMethod);
    will_return(__wrap_SysAppStateSetInvalidArgError, kEsfJsonSuccess);

    CheckSysAppCfgPeriodicSettingIntervalSettings(esfj_handle, json_value, interval_settings);
    CheckSysAppCfgIntervalSetting(interval_settings, 0);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorEsfJsonObjectGet(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    CheckSysAppCfgPeriodicSettingReqId(esfj_handle, json_value);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    // CASE: EsfJsonObjectGet fails.
    // For EsfJsonObjectGet()
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "interval_settings");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonInternalError);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorEsfJsonValueTypeGet(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    CheckSysAppCfgPeriodicSettingReqId(esfj_handle, json_value);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    // For EsfJsonObjectGet()
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "interval_settings");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // CASE: EsfJsonValueTypeGet fails.
    // For EsfJsonValueTypeGet()
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeArray);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonInternalError);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorEsfJsonValueTypeGetNotArray(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    CheckSysAppCfgPeriodicSettingReqId(esfj_handle, json_value);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    // For EsfJsonObjectGet()
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "interval_settings");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // CASE: EsfJsonValueTypeGet retrieves kEsfJsonValueTypeNull.
    // For EsfJsonValueTypeGet()
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeNull);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ArrayHasNoElements(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    CheckSysAppCfgPeriodicSettingReqId(esfj_handle, json_value);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    // For EsfJsonObjectGet()
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "interval_settings");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // For EsfJsonValueTypeGet()
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeArray);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // CASE: EsfJsonArrayCount retrieves zero.
    // For EsfJsonArrayCount()
    expect_value(__wrap_EsfJsonArrayCount, handle, esfj_handle);
    expect_value(__wrap_EsfJsonArrayCount, parent, json_value);
    will_return(__wrap_EsfJsonArrayCount, 0U);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorEsfJsonArrayGet(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    CheckSysAppCfgPeriodicSettingReqId(esfj_handle, json_value);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    // For EsfJsonObjectGet()
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "interval_settings");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // For EsfJsonValueTypeGet()
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeArray);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // For EsfJsonArrayCount()
    expect_value(__wrap_EsfJsonArrayCount, handle, esfj_handle);
    expect_value(__wrap_EsfJsonArrayCount, parent, json_value);
    will_return(__wrap_EsfJsonArrayCount, 1U);

    // CASE: EsfJsonArrayGet fails.
    ForEsfJsonArrayGet(esfj_handle, json_value, 0U, json_value, kEsfJsonInternalError);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorEsfJsonSerialize(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    CheckSysAppCfgPeriodicSettingReqId(esfj_handle, json_value);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    // For EsfJsonObjectGet()
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "interval_settings");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // For EsfJsonValueTypeGet()
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeArray);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // For EsfJsonArrayCount()
    expect_value(__wrap_EsfJsonArrayCount, handle, esfj_handle);
    expect_value(__wrap_EsfJsonArrayCount, parent, json_value);
    will_return(__wrap_EsfJsonArrayCount, 1U);

    ForEsfJsonArrayGet(esfj_handle, json_value, 0U, json_value, kEsfJsonSuccess);

    // CASE: EsfJsonSerialize fails.
    // For EsfJsonSerialize()
    ForEsfJsonSerialize(esfj_handle, json_value, interval_settings, kEsfJsonInternalError);

    // For EsfJsonSerializeFree()
    ForEsfJsonSerializeFree(esfj_handle, kEsfJsonSuccess);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorEsfJsonSerializeNullPtr(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    CheckSysAppCfgPeriodicSettingReqId(esfj_handle, json_value);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    // For EsfJsonObjectGet()
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_value);
    expect_string(__wrap_EsfJsonObjectGet, key, "interval_settings");
    will_return(__wrap_EsfJsonObjectGet, json_value);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // For EsfJsonValueTypeGet()
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, json_value);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeArray);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // For EsfJsonArrayCount()
    expect_value(__wrap_EsfJsonArrayCount, handle, esfj_handle);
    expect_value(__wrap_EsfJsonArrayCount, parent, json_value);
    will_return(__wrap_EsfJsonArrayCount, 1U);

    ForEsfJsonArrayGet(esfj_handle, json_value, 0U, json_value, kEsfJsonSuccess);

    // CASE: EsfJsonSerialize retrieves a null pointer.
    // For EsfJsonSerialize()
    ForEsfJsonSerialize(esfj_handle, json_value, NULL, kEsfJsonSuccess);

    // For EsfJsonSerializeFree()
    ForEsfJsonSerializeFree(esfj_handle, kEsfJsonSuccess);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorCmnExtractStrIpAddrSetting(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    CheckSysAppCfgPeriodicSettingReqId(esfj_handle, json_value);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    CheckSysAppCfgPeriodicSettingIntervalSettings(esfj_handle, json_value, interval_settings);
    CheckSysAppCfgIntervalSetting(interval_settings, 0);

    // CASE: SysAppCmnExtractStringValue fails.
    // For SysAppCmnExtractStringValue()
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ip_addr_setting", "save", -1);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorCmnExtractStrInvalidIpAddrSetting(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    CheckSysAppCfgPeriodicSettingReqId(esfj_handle, json_value);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    CheckSysAppCfgPeriodicSettingIntervalSettings(esfj_handle, json_value, interval_settings);
    CheckSysAppCfgIntervalSetting(interval_settings, 0);

    // CASE: SysAppCmnExtractStringValue retrieves zero.
    // For SysAppCmnExtractStringValue()
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ip_addr_setting", "save", 0);

    // For SysAppStateSetInvalidArgError() about ip_addr_setting
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, IpAddrSetting);
    will_return(__wrap_SysAppStateSetInvalidArgError, kEsfJsonSuccess);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorInvalidIpAddrSetting(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_PERIODIC_SETTING;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    CheckSysAppCfgPeriodicSettingReqId(esfj_handle, json_value);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    CheckSysAppCfgPeriodicSettingIntervalSettings(esfj_handle, json_value, interval_settings);
    CheckSysAppCfgIntervalSetting(interval_settings, 0);

    // CASE: SysAppCmnExtractStringValue retrieves an invalid ip_addr_setting.
    // For SysAppCmnExtractStringValue()
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "ip_addr_setting", "", 1);

    // For SysAppStateSetInvalidArgError() about ip_addr_setting
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, IpAddrSetting);
    will_return(__wrap_SysAppStateSetInvalidArgError, kEsfJsonSuccess);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_IpAddrSettingDhcp(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    CheckSysAppCfgPeriodicSettingReqId(esfj_handle, json_value);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    CheckSysAppCfgPeriodicSettingIntervalSettings(esfj_handle, json_value, interval_settings);
    CheckSysAppCfgIntervalSetting(interval_settings, 0);

    // CASE: SysAppCmnExtractStringValue retrieves "dhcp".
    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "dhcp", "");

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgPeriodicSetting_ErrorEsfJsonClose(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    CheckJsonOpen(esfj_handle, json_value, periodic_setting);

    CheckSysAppCfgPeriodicSettingReqId(esfj_handle, json_value);

    CheckPeriodicNumProperty(esfj_handle, json_value, "operation_mode", OperationMode,
                             ContinuoutMode, PeriodicMode);

    CheckPeriodicNumProperty(esfj_handle, json_value, "recovery_method", RecoveryMethod,
                             ManualReset, AutoReboot);

    CheckSysAppCfgPeriodicSettingIntervalSettings(esfj_handle, json_value, interval_settings);
    CheckSysAppCfgIntervalSetting(interval_settings, 0);

    CheckPeriodicStrProperty(esfj_handle, json_value, "ip_addr_setting", IpAddrSetting, "save", "");

    // CASE: EsfJsonClose fails.
    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonInternalError);

    // Exec test target
    ret = SysAppCfgPeriodicSetting(periodic_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCfgStaModeSetting()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_FullySuccess(void **state)
{
    RetCode ret;
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckSysAppCfgWirelessSettingSysAppCfgStaModeSetting(sta_mode_setting, &ssid_mask, &ssid_param,
                                                         &password_mask, &password_param,
                                                         &encryption_mask, &encryption_param);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}
/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_ErrorEsfJsonOpen(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;

    // CASE: EsfJsonOpen fails.
    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_ErrorEsfDeserialize(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // CASE: EsfJsonDeserialize fails.
    // For EsfJsonDeserialize()
    expect_value(__wrap_EsfJsonDeserialize, handle, esfj_handle);
    expect_string(__wrap_EsfJsonDeserialize, str, sta_mode_setting);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonInternalError);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_ErrorCmnExtractStrSsid(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "WIRELESS SETTING PASSWORD";
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    // CASE: SysAppCmnExtractStringValue fails.
    // For SysAppCmnExtractStringValue() about ssid
    ForSysAppCmnExtractStringValue(esfj_handle, val, "ssid", ssid, -1);

    CheckWirelessSettingStaModeSettingPassword(esfj_handle, val, &password_mask, &password_param,
                                               password);

    CheckWirelessSettingStaModeSettingEncryption(esfj_handle, val, &encryption_mask,
                                                 &encryption_param);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_ErrorCmnExtractStrInvalidSsid(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_WIRELESS_SETTING;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "WIRELESS SETTING PASSWORD";
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    // CASE: SysAppCmnExtractStringValue retrieves zero.
    // For SysAppCmnExtractStringValue() about ssid
    ForSysAppCmnExtractStringValue(esfj_handle, val, "ssid", ssid, 0);

    // For SysAppStateSetInvalidArgError() about ssid
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, StaSsid);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckWirelessSettingStaModeSettingPassword(esfj_handle, val, &password_mask, &password_param,
                                               password);

    CheckWirelessSettingStaModeSettingEncryption(esfj_handle, val, &encryption_mask,
                                                 &encryption_param);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_ErrorCmnExtractStrSsidTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_WIRELESS_SETTING;
    const char *ssid = "SYSTEM APP CONFIGURATION WIRELESS SETTING SSID";
    const char *password = "WIRELESS SETTING PASSWORD";
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    // CASE: SysAppCmnExtractStringValue retrieves a long ssid.
    // For SysAppCmnExtractStringValue() about ssid
    ForSysAppCmnExtractStringValue(esfj_handle, val, "ssid", ssid, 1);

    // For SysAppStateSetInvalidArgError() about ssid
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, StaSsid);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckWirelessSettingStaModeSettingPassword(esfj_handle, val, &password_mask, &password_param,
                                               password);

    CheckWirelessSettingStaModeSettingEncryption(esfj_handle, val, &encryption_mask,
                                                 &encryption_param);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_ErrorCheckUpdateStringSsid(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "WIRELESS SETTING PASSWORD";
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    // For SysAppCmnExtractStringValue() about ssid
    ForSysAppCmnExtractStringValue(esfj_handle, val, "ssid", ssid, 1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // For EsfNetworkManagerLoadParameter() about ssid in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, "SSID");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultInternalError);

    CheckWirelessSettingStaModeSettingPassword(esfj_handle, val, &password_mask, &password_param,
                                               password);

    CheckWirelessSettingStaModeSettingEncryption(esfj_handle, val, &encryption_mask,
                                                 &encryption_param);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_CheckUpdateStringSsidNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "WIRELESS SETTING PASSWORD";
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    // For SysAppCmnExtractStringValue() about ssid
    ForSysAppCmnExtractStringValue(esfj_handle, val, "ssid", ssid, 1);

    // CASE: EsfNetworkManagerLoadParameter retrieves the same ssid.
    // For EsfNetworkManagerLoadParameter() about ssid in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, "WIRELESS SETTING SSID");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    CheckWirelessSettingStaModeSettingPassword(esfj_handle, val, &password_mask, &password_param,
                                               password);

    CheckWirelessSettingStaModeSettingEncryption(esfj_handle, val, &encryption_mask,
                                                 &encryption_param);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_ErrorEsfNMSaveParameterSsid(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_WIRELESS_SETTING;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "WIRELESS SETTING PASSWORD";
    EsfNetworkManagerParameterMask esfnm_mask = {0};
    EsfNetworkManagerParameter esfnm_param = {0};
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    // For SysAppCmnExtractStringValue() about ssid
    ForSysAppCmnExtractStringValue(esfj_handle, val, "ssid", ssid, 1);

    // For EsfNetworkManagerLoadParameter() about ssid in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, "SSID");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // CASE: EsfNetworkManagerSaveParameter fails.
    // For EsfNetworkManagerSaveParameter() about ssid
    memset(&esfnm_mask, 0, sizeof esfnm_mask);
    esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memset(&esfnm_param, 0, sizeof esfnm_param);
    snprintf(esfnm_param.normal_mode.wifi_sta.ssid, sizeof esfnm_param.normal_mode.wifi_sta.ssid,
             "%s", ssid);
    CheckEsfNetworkManagerSaveParameter(&esfnm_mask, &esfnm_param,
                                        kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInternalError() about ssid
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, StaSsid);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    CheckWirelessSettingStaModeSettingPassword(esfj_handle, val, &password_mask, &password_param,
                                               password);

    CheckWirelessSettingStaModeSettingEncryption(esfj_handle, val, &encryption_mask,
                                                 &encryption_param);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_ErrorCmnExtractStrPassword(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "WIRELESS SETTING PASSWORD";
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    CheckWirelessSettingStaModeSettingSsid(esfj_handle, val, &ssid_mask, &ssid_param, ssid);

    // CASE: SysAppCmnExtractStringValue fails.
    // For SysAppCmnExtractStringValue() about password
    ForSysAppCmnExtractStringValue(esfj_handle, val, "password", password, -1);

    CheckWirelessSettingStaModeSettingEncryption(esfj_handle, val, &encryption_mask,
                                                 &encryption_param);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_ErrorCmnExtractStrInvalidPassword(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_WIRELESS_SETTING;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "WIRELESS SETTING PASSWORD";
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    CheckWirelessSettingStaModeSettingSsid(esfj_handle, val, &ssid_mask, &ssid_param, ssid);

    // CASE: SysAppCmnExtractStringValue retrieves zero.
    // For SysAppCmnExtractStringValue() about password
    ForSysAppCmnExtractStringValue(esfj_handle, val, "password", password, 0);

    // For SysAppStateSetInvalidArgError() about password
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, StaPassword);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckWirelessSettingStaModeSettingEncryption(esfj_handle, val, &encryption_mask,
                                                 &encryption_param);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_ErrorCmnExtractStrPasswordTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_WIRELESS_SETTING;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "SYSTEM APP CONFIGURATION WIRELESS SETTING PASSWORD";
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    CheckWirelessSettingStaModeSettingSsid(esfj_handle, val, &ssid_mask, &ssid_param, ssid);

    // CASE: SysAppCmnExtractStringValue retrieves a long password.
    // For SysAppCmnExtractStringValue() about password
    ForSysAppCmnExtractStringValue(esfj_handle, val, "password", password, 1);

    // For SysAppStateSetInvalidArgError() about password
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, StaPassword);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckWirelessSettingStaModeSettingEncryption(esfj_handle, val, &encryption_mask,
                                                 &encryption_param);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_ErrorPasswordLength1Char(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_WIRELESS_SETTING;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "1"; // 1 character password (invalid)
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    CheckWirelessSettingStaModeSettingSsid(esfj_handle, val, &ssid_mask, &ssid_param, ssid);

    // CASE: SysAppCmnExtractStringValue retrieves 1 character (invalid length).
    // For SysAppCmnExtractStringValue() about password
    ForSysAppCmnExtractStringValue(esfj_handle, val, "password", password, 1);

    // For SysAppStateSetInvalidArgError() about password
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, StaPassword);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckWirelessSettingStaModeSettingEncryption(esfj_handle, val, &encryption_mask,
                                                 &encryption_param);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_ErrorPasswordLength7Chars(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_WIRELESS_SETTING;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "1234567"; // 7 character password (invalid)
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    CheckWirelessSettingStaModeSettingSsid(esfj_handle, val, &ssid_mask, &ssid_param, ssid);

    // CASE: SysAppCmnExtractStringValue retrieves 7 characters (invalid length).
    // For SysAppCmnExtractStringValue() about password
    ForSysAppCmnExtractStringValue(esfj_handle, val, "password", password, 1);

    // For SysAppStateSetInvalidArgError() about password
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, StaPassword);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckWirelessSettingStaModeSettingEncryption(esfj_handle, val, &encryption_mask,
                                                 &encryption_param);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_SuccessPassword8Chars(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "12345678"; // 8 character password (valid)
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    CheckWirelessSettingStaModeSettingSsid(esfj_handle, val, &ssid_mask, &ssid_param, ssid);

    CheckWirelessSettingStaModeSettingPassword(esfj_handle, val, &password_mask, &password_param,
                                               password);

    CheckWirelessSettingStaModeSettingEncryption(esfj_handle, val, &encryption_mask,
                                                 &encryption_param);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_SuccessEmptyPassword(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = ""; // Empty password (valid for open networks)
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    CheckWirelessSettingStaModeSettingSsid(esfj_handle, val, &ssid_mask, &ssid_param, ssid);

    CheckWirelessSettingStaModeSettingPassword(esfj_handle, val, &password_mask, &password_param,
                                               password);

    CheckWirelessSettingStaModeSettingEncryption(esfj_handle, val, &encryption_mask,
                                                 &encryption_param);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_ErrorCheckUpdateStringPassword(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "WIRELESS SETTING PASSWORD";
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    CheckWirelessSettingStaModeSettingSsid(esfj_handle, val, &ssid_mask, &ssid_param, ssid);

    // For SysAppCmnExtractStringValue() about password
    ForSysAppCmnExtractStringValue(esfj_handle, val, "password", password, 1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // For EsfNetworkManagerLoadParameter() about ssid in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, "SSID");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultInternalError);

    CheckWirelessSettingStaModeSettingEncryption(esfj_handle, val, &encryption_mask,
                                                 &encryption_param);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_CheckUpdateStringPasswordNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "WIRELESS SETTING PASSWORD";
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    CheckWirelessSettingStaModeSettingSsid(esfj_handle, val, &ssid_mask, &ssid_param, ssid);

    // For SysAppCmnExtractStringValue() about password
    ForSysAppCmnExtractStringValue(esfj_handle, val, "password", password, 1);

    // CASE: EsfNetworkManagerLoadParameter retrieves the same password.
    // For EsfNetworkManagerLoadParameter() about password in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, "WIRELESS SETTING PASSWORD");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    CheckWirelessSettingStaModeSettingEncryption(esfj_handle, val, &encryption_mask,
                                                 &encryption_param);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_ErrorEsfNMSaveParameterPassword(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_WIRELESS_SETTING;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "WIRELESS SETTING PASSWORD";
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask esfnm_mask = {0};
    EsfNetworkManagerParameter esfnm_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    CheckWirelessSettingStaModeSettingSsid(esfj_handle, val, &ssid_mask, &ssid_param, ssid);

    // For SysAppCmnExtractStringValue() about password
    ForSysAppCmnExtractStringValue(esfj_handle, val, "password", password, 1);

    // For EsfNetworkManagerLoadParameter() about password in CheckUpdateString
    will_return(__wrap_EsfNetworkManagerLoadParameter, "PASSWORD");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // CASE: EsfNetworkManagerSaveParameter fails.
    // For EsfNetworkManagerSaveParameter() about password
    memset(&esfnm_mask, 0, sizeof esfnm_mask);
    esfnm_mask.normal_mode.wifi_sta.password = 1;
    memset(&esfnm_param, 0, sizeof esfnm_param);
    snprintf(esfnm_param.normal_mode.wifi_sta.password,
             sizeof esfnm_param.normal_mode.wifi_sta.password, "%s", password);
    CheckEsfNetworkManagerSaveParameter(&esfnm_mask, &esfnm_param,
                                        kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInternalError() about password
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, StaPassword);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    CheckWirelessSettingStaModeSettingEncryption(esfj_handle, val, &encryption_mask,
                                                 &encryption_param);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_ErrorSysAppCmnExtractNumberValueEncryption(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "WIRELESS SETTING PASSWORD";
    int encryption = EncWpa2Psk;
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    CheckWirelessSettingStaModeSettingSsid(esfj_handle, val, &ssid_mask, &ssid_param, ssid);

    CheckWirelessSettingStaModeSettingPassword(esfj_handle, val, &password_mask, &password_param,
                                               password);

    // CASE: SysAppCmnExtractNumberValue fails.
    // For SysAppCmnExtractNumberValue() about encryption
    ForSysAppCmnExtractNumberValue(esfj_handle, val, "encryption", encryption, -1);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_ErrorCmnExtractNumInvalidEncryption(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_WIRELESS_SETTING;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "WIRELESS SETTING PASSWORD";
    int encryption = EncWpa2Psk;
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    CheckWirelessSettingStaModeSettingSsid(esfj_handle, val, &ssid_mask, &ssid_param, ssid);

    CheckWirelessSettingStaModeSettingPassword(esfj_handle, val, &password_mask, &password_param,
                                               password);

    // CASE: SysAppCmnExtractNumberValue retrieves zero.
    // For SysAppCmnExtractNumberValue() about encryption
    ForSysAppCmnExtractNumberValue(esfj_handle, val, "encryption", encryption, 0);

    // For SysAppStateSetInvalidArgError() about encryption
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, StaEncryption);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_ErrorCmnExtractNumEncryptionOutOfRangeSmall(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_WIRELESS_SETTING;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "WIRELESS SETTING PASSWORD";
    int encryption = -1;
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    CheckWirelessSettingStaModeSettingSsid(esfj_handle, val, &ssid_mask, &ssid_param, ssid);

    CheckWirelessSettingStaModeSettingPassword(esfj_handle, val, &password_mask, &password_param,
                                               password);

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid encryption.
    // For SysAppCmnExtractNumberValue() about encryption
    ForSysAppCmnExtractNumberValue(esfj_handle, val, "encryption", encryption, 1);

    // For SysAppStateSetInvalidArgError() about encryption
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, StaEncryption);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_ErrorCmnExtractNumEncryptionOutOfRangeLarge(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_WIRELESS_SETTING;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "WIRELESS SETTING PASSWORD";
    int encryption = WirelessEncryptionNum;
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    CheckWirelessSettingStaModeSettingSsid(esfj_handle, val, &ssid_mask, &ssid_param, ssid);

    CheckWirelessSettingStaModeSettingPassword(esfj_handle, val, &password_mask, &password_param,
                                               password);

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid encryption.
    // For SysAppCmnExtractNumberValue() about encryption
    ForSysAppCmnExtractNumberValue(esfj_handle, val, "encryption", encryption, 1);

    // For SysAppStateSetInvalidArgError() about encryption
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, StaEncryption);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_ErrorCheckUpdateNumberEncryption(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "WIRELESS SETTING PASSWORD";
    int encryption = EncWpa2Psk;
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    CheckWirelessSettingStaModeSettingSsid(esfj_handle, val, &ssid_mask, &ssid_param, ssid);

    CheckWirelessSettingStaModeSettingPassword(esfj_handle, val, &password_mask, &password_param,
                                               password);

    // For SysAppCmnExtractNumberValue() about encryption
    ForSysAppCmnExtractNumberValue(esfj_handle, val, "encryption", encryption, 1);

    // CASE: EsfNetworkManagerLoadParameter fails.
    // For EsfNetworkManagerLoadParameter() about encryption in CheckUpdateNumber
    will_return(__wrap_EsfNetworkManagerLoadParameter, EncWpa3Psk);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultInternalError);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_CheckUpdateNumberEncryptionNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "WIRELESS SETTING PASSWORD";
    int encryption = EncWpa2Psk;
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    CheckWirelessSettingStaModeSettingSsid(esfj_handle, val, &ssid_mask, &ssid_param, ssid);

    CheckWirelessSettingStaModeSettingPassword(esfj_handle, val, &password_mask, &password_param,
                                               password);

    // For SysAppCmnExtractNumberValue() about encryption
    ForSysAppCmnExtractNumberValue(esfj_handle, val, "encryption", encryption, 1);

    // CASE: EsfNetworkManagerLoadParameter retrieves the same encryption.
    // For EsfNetworkManagerLoadParameter() about encryption in CheckUpdateNumber
    will_return(__wrap_EsfNetworkManagerLoadParameter, EncWpa2Psk);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_ErrorEsfNMSaveParameterEncryption(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_WIRELESS_SETTING;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "WIRELESS SETTING PASSWORD";
    int encryption = EncWpa2Psk;
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};
    EsfNetworkManagerParameterMask esfnm_mask = {0};
    EsfNetworkManagerParameter esfnm_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    CheckWirelessSettingStaModeSettingSsid(esfj_handle, val, &ssid_mask, &ssid_param, ssid);

    CheckWirelessSettingStaModeSettingPassword(esfj_handle, val, &password_mask, &password_param,
                                               password);

    // For SysAppCmnExtractNumberValue() about encryption
    ForSysAppCmnExtractNumberValue(esfj_handle, val, "encryption", encryption, 1);

    // For EsfNetworkManagerLoadParameter() about encryption in CheckUpdateNumber
    will_return(__wrap_EsfNetworkManagerLoadParameter, EncWpa3Psk);
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    // CASE: EsfNetworkManagerSaveParameter fails.
    // For EsfNetworkManagerSaveParameter() about encryption
    memset(&esfnm_mask, 0, sizeof esfnm_mask);
    esfnm_mask.normal_mode.wifi_sta.encryption = 1;
    memset(&esfnm_param, 0, sizeof esfnm_param);
    esfnm_param.normal_mode.wifi_sta.encryption = encryption;
    CheckEsfNetworkManagerSaveParameter(&esfnm_mask, &esfnm_param,
                                        kEsfNetworkManagerResultInternalError);

    // For SysAppStateSetInternalError() about encryption
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, StaEncryption);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgStaModeSetting_ErrorEsfJsonClose(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    const char *ssid = "WIRELESS SETTING SSID";
    const char *password = "WIRELESS SETTING PASSWORD";
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, sta_mode_setting);

    CheckWirelessSettingStaModeSettingSsid(esfj_handle, val, &ssid_mask, &ssid_param, ssid);

    CheckWirelessSettingStaModeSettingPassword(esfj_handle, val, &password_mask, &password_param,
                                               password);

    CheckWirelessSettingStaModeSettingEncryption(esfj_handle, val, &encryption_mask,
                                                 &encryption_param);

    // CASE: EsfJsonClose fails.
    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonInternalError);

    // Exec test target
    ret = SysAppCfgStaModeSetting(sta_mode_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCfgWirelessSetting()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgWirelessSetting_FullySuccess(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    uint32_t req = ST_TOPIC_WIRELESS_SETTING;
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, wireless_setting);

    CheckSysAppCfgWirelessSettingReqId(esfj_handle, val);

    CheckSysAppCfgWirelessSettingPropertyStaModeSetting(esfj_handle, val, sta_mode_setting);

    CheckSysAppCfgWirelessSettingSysAppCfgStaModeSetting(sta_mode_setting, &ssid_mask, &ssid_param,
                                                         &password_mask, &password_param,
                                                         &encryption_mask, &encryption_param);

    CheckJsonClose(esfj_handle, req);

    // Exec test target
    ret = SysAppCfgWirelessSetting(wireless_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgWirelessSetting_ErrorEsfJsonOpen(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonErrorCode esfj_err_ret = kEsfJsonInternalError;

    // CASE: EsfJsonOpen fails.
    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, esfj_err_ret);

    // Exec test target
    ret = SysAppCfgWirelessSetting(wireless_setting);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgWirelessSetting_ErrorEsfJsonDeserialize(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonErrorCode esfj_open_ret = kEsfJsonSuccess;
    EsfJsonErrorCode esfj_close_ret = kEsfJsonSuccess;
    EsfJsonErrorCode esfj_err_ret = kEsfJsonInternalError;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, esfj_open_ret);

    // CASE: EsfJsonDeserialize fails.
    // For EsfJsonDeserialize()
    expect_value(__wrap_EsfJsonDeserialize, handle, esfj_handle);
    expect_string(__wrap_EsfJsonDeserialize, str, wireless_setting);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, esfj_err_ret);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, esfj_close_ret);

    // Exec test target
    ret = SysAppCfgWirelessSetting(wireless_setting);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgWirelessSetting_ErrorSysAppCmnGetReqId(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    const char *req_id = "1";
    uint32_t req = ST_TOPIC_WIRELESS_SETTING;
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, wireless_setting);

    // CASE: SysAppCmnGetReqId fails.
    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetFailed);

    // For SysAppStateUpdateString()
    expect_value(__wrap_SysAppStateUpdateString, topic, req);
    expect_value(__wrap_SysAppStateUpdateString, type, Id);
    expect_string(__wrap_SysAppStateUpdateString, string, "0");
    will_return(__wrap_SysAppStateUpdateString, kRetOk);

    // For SysAppStateSetInvalidArgError()
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, req);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, Id);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgWirelessSettingPropertyStaModeSetting(esfj_handle, val, sta_mode_setting);

    CheckSysAppCfgWirelessSettingSysAppCfgStaModeSetting(sta_mode_setting, &ssid_mask, &ssid_param,
                                                         &password_mask, &password_param,
                                                         &encryption_mask, &encryption_param);

    CheckJsonClose(esfj_handle, req);

    // Exec test target
    ret = SysAppCfgWirelessSetting(wireless_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgWirelessSetting_NotFoundSysAppCmnGetReqId(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    const char *req_id = "1";
    uint32_t req = ST_TOPIC_WIRELESS_SETTING;
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, wireless_setting);

    // CASE: SysAppCmnGetReqId fails.
    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetNotFound);

    // For SysAppStateUpdateString()
    expect_value(__wrap_SysAppStateUpdateString, topic, req);
    expect_value(__wrap_SysAppStateUpdateString, type, Id);
    expect_string(__wrap_SysAppStateUpdateString, string, "0");
    will_return(__wrap_SysAppStateUpdateString, kRetOk);

    CheckSysAppCfgWirelessSettingPropertyStaModeSetting(esfj_handle, val, sta_mode_setting);

    CheckSysAppCfgWirelessSettingSysAppCfgStaModeSetting(sta_mode_setting, &ssid_mask, &ssid_param,
                                                         &password_mask, &password_param,
                                                         &encryption_mask, &encryption_param);

    CheckJsonClose(esfj_handle, req);

    // Exec test target
    ret = SysAppCfgWirelessSetting(wireless_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgWirelessSetting_ErrorReqIdTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    const char *req_id =
        "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "111111111111111111111111111111111111111";
    uint32_t req = ST_TOPIC_WIRELESS_SETTING;
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, wireless_setting);

    // CASE: SysAppCmnGetReqId retrieves a long req_id.
    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // For SysAppStateUpdateString()
    expect_value(__wrap_SysAppStateUpdateString, topic, req);
    expect_value(__wrap_SysAppStateUpdateString, type, Id);
    expect_string(__wrap_SysAppStateUpdateString, string, "0");
    will_return(__wrap_SysAppStateUpdateString, kRetOk);

    // For SysAppStateSetInvalidArgError()
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, req);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, Id);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgWirelessSettingPropertyStaModeSetting(esfj_handle, val, sta_mode_setting);

    CheckSysAppCfgWirelessSettingSysAppCfgStaModeSetting(sta_mode_setting, &ssid_mask, &ssid_param,
                                                         &password_mask, &password_param,
                                                         &encryption_mask, &encryption_param);

    CheckJsonClose(esfj_handle, req);

    // Exec test target
    ret = SysAppCfgWirelessSetting(wireless_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgWirelessSetting_ErrorSysAppStateGetReqIdNullPtr(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    const char *req_id = "1";
    uint32_t req = ST_TOPIC_WIRELESS_SETTING;
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, wireless_setting);

    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // CASE: SysAppStateGetReqId retrieves a null pointer.
    // For SysAppStateGetReqId()
    expect_value(__wrap_SysAppStateGetReqId, topic, req);
    will_return(__wrap_SysAppStateGetReqId, NULL);

    CheckSysAppCfgWirelessSettingPropertyStaModeSetting(esfj_handle, val, sta_mode_setting);

    CheckSysAppCfgWirelessSettingSysAppCfgStaModeSetting(sta_mode_setting, &ssid_mask, &ssid_param,
                                                         &password_mask, &password_param,
                                                         &encryption_mask, &encryption_param);

    CheckJsonClose(esfj_handle, req);

    // Exec test target
    ret = SysAppCfgWirelessSetting(wireless_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgWirelessSetting_ReqIdNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    const char *req_id = "1";
    uint32_t req = ST_TOPIC_WIRELESS_SETTING;
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, wireless_setting);

    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // CASE: SysAppStateGetReqId retrieves the same req_id.
    // For SysAppStateGetReqId()
    expect_value(__wrap_SysAppStateGetReqId, topic, req);
    will_return(__wrap_SysAppStateGetReqId, "1");

    CheckSysAppCfgWirelessSettingPropertyStaModeSetting(esfj_handle, val, sta_mode_setting);

    CheckSysAppCfgWirelessSettingSysAppCfgStaModeSetting(sta_mode_setting, &ssid_mask, &ssid_param,
                                                         &password_mask, &password_param,
                                                         &encryption_mask, &encryption_param);

    CheckJsonClose(esfj_handle, req);

    // Exec test target
    ret = SysAppCfgWirelessSetting(wireless_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgWirelessSetting_ErrorEsfJsonObjectGet(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonErrorCode esfj_err_ret = kEsfJsonInternalError;
    uint32_t req = ST_TOPIC_WIRELESS_SETTING;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;

    CheckJsonOpen(esfj_handle, val, wireless_setting);

    CheckSysAppCfgWirelessSettingReqId(esfj_handle, val);

    // CASE: EsfJsonObjectGet fails.
    // For EsfJsonObjectGet()
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, val);
    expect_string(__wrap_EsfJsonObjectGet, key, "sta_mode_setting");
    will_return(__wrap_EsfJsonObjectGet, val);
    will_return(__wrap_EsfJsonObjectGet, esfj_err_ret);

    CheckJsonClose(esfj_handle, req);

    // Exec test target
    ret = SysAppCfgWirelessSetting(wireless_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgWirelessSetting_ErrorEsfJsonValueTypeGet(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonErrorCode esfj_objget_ret = kEsfJsonSuccess;
    EsfJsonErrorCode esfj_err_ret = kEsfJsonInternalError;
    uint32_t req = ST_TOPIC_WIRELESS_SETTING;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    EsfJsonValueType val_type = kEsfJsonValueTypeObject;

    CheckJsonOpen(esfj_handle, val, wireless_setting);

    CheckSysAppCfgWirelessSettingReqId(esfj_handle, val);

    // For EsfJsonObjectGet()
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, val);
    expect_string(__wrap_EsfJsonObjectGet, key, "sta_mode_setting");
    will_return(__wrap_EsfJsonObjectGet, val);
    will_return(__wrap_EsfJsonObjectGet, esfj_objget_ret);

    // CASE: EsfJsonValueTypeGet fails.
    // For EsfJsonValueTypeGet()
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, val);
    will_return(__wrap_EsfJsonValueTypeGet, val_type);
    will_return(__wrap_EsfJsonValueTypeGet, esfj_err_ret);

    CheckJsonClose(esfj_handle, req);

    // Exec test target
    ret = SysAppCfgWirelessSetting(wireless_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgWirelessSetting_ErrorEsfJsonTypeGetNotObject(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonErrorCode esfj_objget_ret = kEsfJsonSuccess;
    EsfJsonErrorCode esfj_typeget_ret = kEsfJsonSuccess;
    uint32_t req = ST_TOPIC_WIRELESS_SETTING;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    EsfJsonValueType val_type = kEsfJsonValueTypeNull;

    CheckJsonOpen(esfj_handle, val, wireless_setting);

    CheckSysAppCfgWirelessSettingReqId(esfj_handle, val);

    // For EsfJsonObjectGet()
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, val);
    expect_string(__wrap_EsfJsonObjectGet, key, "sta_mode_setting");
    will_return(__wrap_EsfJsonObjectGet, val);
    will_return(__wrap_EsfJsonObjectGet, esfj_objget_ret);

    // CASE: EsfJsonValueTypeGet retrieves kEsfJsonValueTypeNull.
    // For EsfJsonValueTypeGet()
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, val);
    will_return(__wrap_EsfJsonValueTypeGet, val_type);
    will_return(__wrap_EsfJsonValueTypeGet, esfj_typeget_ret);

    CheckJsonClose(esfj_handle, req);

    // Exec test target
    ret = SysAppCfgWirelessSetting(wireless_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgWirelessSetting_ErrorEsfJsonSerialize(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonErrorCode esfj_objget_ret = kEsfJsonSuccess;
    EsfJsonErrorCode esfj_typeget_ret = kEsfJsonSuccess;
    EsfJsonErrorCode esfj_serfree_ret = kEsfJsonSuccess;
    EsfJsonErrorCode esfj_err_ret = kEsfJsonInternalError;
    uint32_t req = ST_TOPIC_WIRELESS_SETTING;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    EsfJsonValueType val_type = kEsfJsonValueTypeObject;

    CheckJsonOpen(esfj_handle, val, wireless_setting);

    CheckSysAppCfgWirelessSettingReqId(esfj_handle, val);

    // For EsfJsonObjectGet()
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, val);
    expect_string(__wrap_EsfJsonObjectGet, key, "sta_mode_setting");
    will_return(__wrap_EsfJsonObjectGet, val);
    will_return(__wrap_EsfJsonObjectGet, esfj_objget_ret);

    // For EsfJsonValueTypeGet()
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, val);
    will_return(__wrap_EsfJsonValueTypeGet, val_type);
    will_return(__wrap_EsfJsonValueTypeGet, esfj_typeget_ret);

    // CASE: EsfJsonSerialize fails.
    ForEsfJsonSerialize(esfj_handle, val, sta_mode_setting, esfj_err_ret);

    ForEsfJsonSerializeFree(esfj_handle, esfj_serfree_ret);

    CheckJsonClose(esfj_handle, req);

    // Exec test target
    ret = SysAppCfgWirelessSetting(wireless_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgWirelessSetting_ErrorEsfJsonSerializeNullPtr(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonErrorCode esfj_objget_ret = kEsfJsonSuccess;
    EsfJsonErrorCode esfj_typeget_ret = kEsfJsonSuccess;
    EsfJsonErrorCode esfj_ser_ret = kEsfJsonSuccess;
    EsfJsonErrorCode esfj_serfree_ret = kEsfJsonSuccess;
    uint32_t req = ST_TOPIC_WIRELESS_SETTING;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    EsfJsonValueType val_type = kEsfJsonValueTypeObject;

    CheckJsonOpen(esfj_handle, val, wireless_setting);

    CheckSysAppCfgWirelessSettingReqId(esfj_handle, val);

    // For EsfJsonObjectGet()
    expect_value(__wrap_EsfJsonObjectGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, val);
    expect_string(__wrap_EsfJsonObjectGet, key, "sta_mode_setting");
    will_return(__wrap_EsfJsonObjectGet, val);
    will_return(__wrap_EsfJsonObjectGet, esfj_objget_ret);

    // For EsfJsonValueTypeGet()
    expect_value(__wrap_EsfJsonValueTypeGet, handle, esfj_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, val);
    will_return(__wrap_EsfJsonValueTypeGet, val_type);
    will_return(__wrap_EsfJsonValueTypeGet, esfj_typeget_ret);

    // CASE: EsfJsonSerialize retrieves a null pointer.
    ForEsfJsonSerialize(esfj_handle, val, NULL, esfj_ser_ret);

    ForEsfJsonSerializeFree(esfj_handle, esfj_serfree_ret);

    CheckJsonClose(esfj_handle, req);

    // Exec test target
    ret = SysAppCfgWirelessSetting(wireless_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgWirelessSetting_ErrorSysAppStateSendState(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    uint32_t req = ST_TOPIC_WIRELESS_SETTING;
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, wireless_setting);

    CheckSysAppCfgWirelessSettingReqId(esfj_handle, val);

    CheckSysAppCfgWirelessSettingPropertyStaModeSetting(esfj_handle, val, sta_mode_setting);

    CheckSysAppCfgWirelessSettingSysAppCfgStaModeSetting(sta_mode_setting, &ssid_mask, &ssid_param,
                                                         &password_mask, &password_param,
                                                         &encryption_mask, &encryption_param);

    // For SysAppStateSendState()
    expect_value(__wrap_SysAppStateSendState, req, req);
    will_return(__wrap_SysAppStateSendState, kRetFailed);

    // CASE: EsfJsonClose success.
    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgWirelessSetting(wireless_setting);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgWirelessSetting_ErrorEsfJsonClose(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    uint32_t req = ST_TOPIC_WIRELESS_SETTING;
    EsfNetworkManagerParameterMask ssid_mask = {0};
    EsfNetworkManagerParameter ssid_param = {0};
    EsfNetworkManagerParameterMask password_mask = {0};
    EsfNetworkManagerParameter password_param = {0};
    EsfNetworkManagerParameterMask encryption_mask = {0};
    EsfNetworkManagerParameter encryption_param = {0};

    CheckJsonOpen(esfj_handle, val, wireless_setting);

    CheckSysAppCfgWirelessSettingReqId(esfj_handle, val);

    CheckSysAppCfgWirelessSettingPropertyStaModeSetting(esfj_handle, val, sta_mode_setting);

    CheckSysAppCfgWirelessSettingSysAppCfgStaModeSetting(sta_mode_setting, &ssid_mask, &ssid_param,
                                                         &password_mask, &password_param,
                                                         &encryption_mask, &encryption_param);

    // For SysAppStateSendState()
    expect_value(__wrap_SysAppStateSendState, req, req);
    will_return(__wrap_SysAppStateSendState, kRetOk);

    // CASE: EsfJsonClose fails.
    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonInternalError);

    // Exec test target
    ret = SysAppCfgWirelessSetting(wireless_setting);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCfgEndpointSettings()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_FullySuccess(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);
    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorEsfJsonOpen(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;

    // CASE: EsfJsonOpen fails.
    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorEsfJsonDeserialize(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // CASE: EsfJsonDeserialize fails.
    // For EsfJsonDeserialize()
    expect_value(__wrap_EsfJsonDeserialize, handle, esfj_handle);
    expect_string(__wrap_EsfJsonDeserialize, str, endpoint_settings);
    will_return(__wrap_EsfJsonDeserialize, json_value);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonInternalError);

    ForFree();
    ForFree();

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorSysAppCmnGetReqId(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *req_id = "1";
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    // CASE: SysAppCmnGetReqId fails.
    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetFailed);

    // For SysAppStateUpdateString() about req_id
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, Id);
    expect_string(__wrap_SysAppStateUpdateString, string, "0");
    will_return(__wrap_SysAppStateUpdateString, kRetOk);

    // For SysAppStateSetInvalidArgError() about req_id
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, Id);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);
    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_NotFoundSysAppCmnGetReqId(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *req_id = "1";
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    // CASE: SysAppCmnGetReqId fails.
    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetNotFound);

    // For SysAppStateUpdateString() about req_id
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, Id);
    expect_string(__wrap_SysAppStateUpdateString, string, "0");
    will_return(__wrap_SysAppStateUpdateString, kRetOk);

    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);
    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorReqIdTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *req_id =
        "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "111111111111111111111111111111111111111";
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    // CASE: SysAppCmnGetReqId retrieves a long req_id.
    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // For SysAppStateUpdateString() about req_id
    expect_value(__wrap_SysAppStateUpdateString, topic, topic);
    expect_value(__wrap_SysAppStateUpdateString, type, Id);
    expect_string(__wrap_SysAppStateUpdateString, string, "0");
    will_return(__wrap_SysAppStateUpdateString, kRetOk);

    // For SysAppStateSetInvalidArgError() about req_id
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, Id);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);
    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorSysAppStateGetReqId(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *req_id = "1";
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // CASE: SysAppStateGetReqId retrieves a null pointer.
    // For SysAppStateGetReqId() in CheckUpdateString
    expect_value(__wrap_SysAppStateGetReqId, topic, topic);
    will_return(__wrap_SysAppStateGetReqId, NULL);

    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);
    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ReqIdNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *req_id = "1";
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, req_id);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // CASE: SysAppStateGetReqId retrieves the same req_id.
    // For SysAppStateGetReqId() in CheckUpdateString
    expect_value(__wrap_SysAppStateGetReqId, topic, topic);
    will_return(__wrap_SysAppStateGetReqId, req_id);

    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);
    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorMAllocUrlBackup(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);

    // CASE: malloc fails.
    // For malloc() of SysAppCfgEndpointSetting
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);
    will_return(mock_malloc, true);
    will_return(mock_malloc, false);

    // For SysAppStateSetInternalError() about endpoint url
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, EndpointUrl);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorEsfSMGetEvpHubUrlBackup(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);

    ForMalloc(ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // CASE: EsfSystemManagerGetEvpHubUrl fails.
    ForEsfSystemManagerGetEvpHubUrl(url_backup, kEsfSystemManagerResultInternalError);

    // For SysAppStateSetInternalError() about endpoint url
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, EndpointUrl);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorMAllocPortBackup(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);

    // CASE: malloc fails.
    // For malloc() of SysAppCfgEndpointSetting
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);
    will_return(mock_malloc, true);
    will_return(mock_malloc, false);

    // For SysAppStateSetInternalError() about endpoint port
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, EndpointPort);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorEsfSMGetEvpHubPortBackup(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);

    ForMalloc(ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // CASE: EsfSystemManagerGetEvpHubPort fails.
    ForEsfSystemManagerGetEvpHubPort(port_backup, kEsfSystemManagerResultInternalError);

    // For SysAppStateSetInternalError() about endpoint port
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, EndpointPort);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorCmnExtractStrEndpointUrl(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    const char *endpoint_url = "endpoint-url.com";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);

    // CASE: SysAppCmnExtractStringValue fails.
    // For SysAppCmnExtractStringValue() about endpoint_url
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "endpoint_url", endpoint_url, -1);

    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);
    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorInvalidEndpointUrl(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    const char *endpoint_url = "endpoint-url.com";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);

    // CASE: SysAppCmnExtractStringValue retrives zero.
    // For SysAppCmnExtractStringValue() about endpoint_url
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "endpoint_url", endpoint_url, 0);

    // For SysAppStateSetInvalidArgError() about endpoint_url
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, EndpointUrl);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);
    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorEndpointUrlTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    const char *endpoint_url =
        "endpoint_"
        "urllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll"
        "llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll"
        "llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);

    // CASE: SysAppCmnExtractStringValue retrives a long url.
    // For SysAppCmnExtractStringValue() about endpoint_url
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "endpoint_url", endpoint_url, 1);

    // For SysAppStateSetInvalidArgError() about endpoint_url
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, EndpointUrl);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);
    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorCheckUpdateStrMAllocEndpointUrl(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    const char *endpoint_url = "endpoint-url.com";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);

    // For SysAppCmnExtractStringValue() about endpoint_url
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "endpoint_url", endpoint_url, 1);

    // CASE: malloc fails.
    // For malloc() of CheckUpdateString
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);
    will_return(mock_malloc, true);
    will_return(mock_malloc, false);

    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);
    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorCheckUpdateStrEsfSMGetEvpHubUrl(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    const char *endpoint_url = "endpoint-url.com";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);

    // For SysAppCmnExtractStringValue() about endpoint_url
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "endpoint_url", endpoint_url, 1);

    // For malloc() of CheckUpdateString
    ForMalloc(ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // CASE: EsfSystemManagerGetEvpHubUrl fails.
    // For EsfSystemManagerGetEvpHubUrl() in CheckUpdateString
    ForEsfSystemManagerGetEvpHubUrl("", kEsfSystemManagerResultInternalError);

    // For free() of CheckUpdateString
    ForFree();

    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);
    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_EndpointUrlNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    const char *endpoint_url = "endpoint-url.com";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);

    // For SysAppCmnExtractStringValue() about endpoint_url
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "endpoint_url", endpoint_url, 1);

    // For malloc() of CheckUpdateString
    ForMalloc(ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // CASE: EsfSystemManagerGetEvpHubUrl retrieves the same endpoint_url.
    // For EsfSystemManagerGetEvpHubUrl() in CheckUpdateString
    ForEsfSystemManagerGetEvpHubUrl(endpoint_url, kEsfSystemManagerResultOk);

    // For free() of CheckUpdateString
    ForFree();

    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);
    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorEsfSMSetEvpHubUrl(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    const char *endpoint_url = "endpoint-url.com";
    size_t url_len = strlen(endpoint_url) + 1U;
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);

    // For SysAppCmnExtractStringValue() about endpoint_url
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "endpoint_url", endpoint_url, 1);

    // For malloc() of CheckUpdateString
    ForMalloc(ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // For EsfSystemManagerGetEvpHubUrl() in CheckUpdateString
    ForEsfSystemManagerGetEvpHubUrl("", kEsfSystemManagerResultOk);

    // For free() of CheckUpdateString
    ForFree();

    // CASE: EsfSystemManagerSetEvpHubUrl fails.
    // For EsfSystemManagerSetEvpHubUrl()
    expect_string(__wrap_EsfSystemManagerSetEvpHubUrl, data, endpoint_url);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size, url_len);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultInternalError);

    // For SysAppStateSetInternalError() about endpoint_url
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, EndpointUrl);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsRevert(url_backup, port_backup);
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorCmnExtractStrEndpointPort(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    int endpoint_port = 1;
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);

    // CASE: SysAppCmnExtractNumberValue fails.
    // For SysAppCmnExtractNumberValue() about endpoint_port
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "endpoint_port", endpoint_port, -1);

    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorInvalidEndpointPort(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    int endpoint_port = 1;
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);

    // CASE: SysAppCmnExtractNumberValue retrieves zero.
    // For SysAppCmnExtractNumberValue() about endpoint_port
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "endpoint_port", endpoint_port, 0);

    // For SysAppStateSetInvalidArgError() about endpoint_url
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, EndpointPort);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorEndpointPortTooSmall(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    int endpoint_port = -1;
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid endpoint_port.
    // For SysAppCmnExtractNumberValue() about endpoint_port
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "endpoint_port", endpoint_port, 1);

    // For SysAppStateSetInvalidArgError() about endpoint_url
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, EndpointPort);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorEndpointPortTooLarge(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    int endpoint_port = 65536;
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);

    // CASE: SysAppCmnExtractNumberValue retrieves an invalid endpoint_port.
    // For SysAppCmnExtractNumberValue() about endpoint_port
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "endpoint_port", endpoint_port, 1);

    // For SysAppStateSetInvalidArgError() about endpoint_url
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, EndpointPort);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorMAllocEndpointPort(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    int endpoint_port = 1;
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue() about endpoint_port
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "endpoint_port", endpoint_port, 1);

    // CASE: malloc fails.
    // For malloc() of SysAppCfgEndpointSetting
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);
    will_return(mock_malloc, true);
    will_return(mock_malloc, false);

    // For SysAppStateSetInternalError() about endpoint_port
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, EndpointPort);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorCheckUpdateStrMAllocEndpointPort(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    int endpoint_port = 1;
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue() about endpoint_port
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "endpoint_port", endpoint_port, 1);

    ForMalloc(ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // CASE: malloc fails.
    // For malloc() of CheckUpdateString
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);
    will_return(mock_malloc, true);
    will_return(mock_malloc, false);

    // For free() of SysAppCfgEndpointSettings
    ForFree();

    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorCheckUpdateStrEsfSMGetEvpHubPort(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    int endpoint_port = 1;
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue() about endpoint_port
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "endpoint_port", endpoint_port, 1);

    ForMalloc(ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // For malloc() of CheckUpdateString
    ForMalloc(ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // CASE: EsfSystemManagerGetEvpHubPort fails.
    // For EsfSystemManagerGetEvpHubPort() in CheckUpdateString
    ForEsfSystemManagerGetEvpHubPort("0", kEsfSystemManagerResultInternalError);

    // For free() of CheckUpdateString
    ForFree();

    // For free() of SysAppCfgEndpointSettings
    ForFree();

    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_EndpointPortNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    int endpoint_port = 1;
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue() about endpoint_port
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "endpoint_port", endpoint_port, 1);

    ForMalloc(ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // For malloc() of CheckUpdateString
    ForMalloc(ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // CASE: EsfSystemManagerGetEvpHubPort retrieves the same endpoint_port.
    // For EsfSystemManagerGetEvpHubPort() in CheckUpdateString
    ForEsfSystemManagerGetEvpHubPort("1", kEsfSystemManagerResultOk);

    // For free() of CheckUpdateString
    ForFree();

    // For free() of SysAppCfgEndpointSettings
    ForFree();

    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorEsfSMSetEvpHubPort(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    int endpoint_port = 1;
    const char *endpoint_port_str = "1";
    size_t port_str_len = strlen(endpoint_port_str) + 1U;
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue() about endpoint_port
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "endpoint_port", endpoint_port, 1);

    ForMalloc(ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // For malloc() of CheckUpdateString
    ForMalloc(ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // For EsfSystemManagerGetEvpHubPort() in CheckUpdateString
    ForEsfSystemManagerGetEvpHubPort("0", kEsfSystemManagerResultOk);

    // For free() of CheckUpdateString
    ForFree();

    // CASE: EsfSystemManagerSetEvpHubPort fails.
    // For EsfSystemManagerSetEvpHubPort()
    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, endpoint_port_str);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size, port_str_len);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultInternalError);

    // For SysAppStateSetInternalError() about endpoint_port
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, EndpointPort);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    // For free() of SysAppCfgEndpointSettings
    ForFree();

    CheckSysAppCfgEndpointSettingsRevert(url_backup, port_backup);
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorEsfSMSetEvpHubUrlRevert(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    int endpoint_port = 1;
    const char *endpoint_port_str = "1";
    size_t port_str_len = strlen(endpoint_port_str) + 1U;
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue() about endpoint_port
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "endpoint_port", endpoint_port, 1);

    ForMalloc(ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // For malloc() of CheckUpdateString
    ForMalloc(ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // For EsfSystemManagerGetEvpHubPort() in CheckUpdateString
    ForEsfSystemManagerGetEvpHubPort("0", kEsfSystemManagerResultOk);

    // For free() of CheckUpdateString
    ForFree();

    // CASE: EsfSystemManagerSetEvpHubPort fails.
    // For EsfSystemManagerSetEvpHubPort()
    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, endpoint_port_str);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size, port_str_len);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultInternalError);

    // For SysAppStateSetInternalError() about endpoint_port
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, EndpointPort);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    // For free() of SysAppCfgEndpointSettings
    ForFree();

    // For EsfSystemManagerSetEvpHubUrl() about endpoint_url
    expect_string(__wrap_EsfSystemManagerSetEvpHubUrl, data, url_backup);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size, strlen(url_backup));
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultInternalError);

    // For EsfSystemManagerSetEvpHubPort() about endpoint_port
    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, port_backup);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size, strlen(port_backup));
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorEsfSMSetEvpHubPortRevert(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    int endpoint_port = 1;
    const char *endpoint_port_str = "1";
    size_t port_str_len = strlen(endpoint_port_str) + 1U;
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);

    // For SysAppCmnExtractNumberValue() about endpoint_port
    ForSysAppCmnExtractNumberValue(esfj_handle, json_value, "endpoint_port", endpoint_port, 1);

    ForMalloc(ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // For malloc() of CheckUpdateString
    ForMalloc(ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // For EsfSystemManagerGetEvpHubPort() in CheckUpdateString
    ForEsfSystemManagerGetEvpHubPort("0", kEsfSystemManagerResultOk);

    // For free() of CheckUpdateString
    ForFree();

    // For EsfSystemManagerSetEvpHubPort()
    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, endpoint_port_str);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size, port_str_len);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultInternalError);

    // For SysAppStateSetInternalError() about endpoint_port
    expect_value(__wrap_SysAppStateSetInternalError, topic, topic);
    expect_value(__wrap_SysAppStateSetInternalError, property, EndpointPort);
    will_return(__wrap_SysAppStateSetInternalError, kRetOk);

    // For free() of SysAppCfgEndpointSettings
    ForFree();

    // For EsfSystemManagerSetEvpHubUrl() about endpoint_url
    expect_string(__wrap_EsfSystemManagerSetEvpHubUrl, data, url_backup);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size, strlen(url_backup));
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    // CASE: EsfSystemManagerSetEvpHubPort fails.
    // For EsfSystemManagerSetEvpHubPort() about endpoint_port
    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, port_backup);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size, strlen(port_backup));
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultInternalError);

    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorClearEnrollmentDataEsfSMSetProjectId(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);

    // CASE: EsfSystemManagerSetProjectId fails.
    // For EsfSystemManagerSetProjectId()
    expect_string(__wrap_EsfSystemManagerSetProjectId, data, "");
    expect_value(__wrap_EsfSystemManagerSetProjectId, data_size, 1U);
    will_return(__wrap_EsfSystemManagerSetProjectId, kEsfSystemManagerResultInternalError);

    // For EsfSystemManagerSetRegisterToken()
    expect_string(__wrap_EsfSystemManagerSetRegisterToken, data, "");
    expect_value(__wrap_EsfSystemManagerSetRegisterToken, data_size, 1U);
    will_return(__wrap_EsfSystemManagerSetRegisterToken, kEsfSystemManagerResultOk);

    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorClearEnrollmentDataEsfSMSetRegisterToken(
    void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);

    // For EsfSystemManagerSetProjectId()
    expect_string(__wrap_EsfSystemManagerSetProjectId, data, "");
    expect_value(__wrap_EsfSystemManagerSetProjectId, data_size, 1U);
    will_return(__wrap_EsfSystemManagerSetProjectId, kEsfSystemManagerResultOk);

    // CASE: EsfSystemManagerSetRegisterToken fails.
    // For EsfSystemManagerSetRegisterToken()
    expect_string(__wrap_EsfSystemManagerSetRegisterToken, data, "");
    expect_value(__wrap_EsfSystemManagerSetRegisterToken, data_size, 1U);
    will_return(__wrap_EsfSystemManagerSetRegisterToken, kEsfSystemManagerResultInternalError);

    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorCmnExtractStrProtocolVersion(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    const char *protocol_version = "TB";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);
    CheckClearEnrollmentData();

    // CASE: SysAppCmnExtractStringValue fails.
    // For SysAppCmnExtractStringValue() about protocol_version
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "protocol_version", protocol_version,
                                   -1);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorInvalidProtocolVersion(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    const char *protocol_version = "TB";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);
    CheckClearEnrollmentData();

    // CASE: SysAppCmnExtractStringValue retrieves zero.
    // For SysAppCmnExtractStringValue() about protocol_version
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "protocol_version", protocol_version,
                                   0);

    // For SysAppStateSetInvalidArgError() about protocol_version
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, ProtocolVersion);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorProtocolVersionTooLong(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    const char *protocol_version = "TBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);
    CheckClearEnrollmentData();

    // CASE: SysAppCmnExtractStringValue retrieves a long protocol_version.
    // For SysAppCmnExtractStringValue() about protocol_version
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "protocol_version", protocol_version,
                                   1);

    // For SysAppStateSetInvalidArgError() about protocol_version
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, ProtocolVersion);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorProtocolVersionNotEqToTB(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    const char *protocol_version = "T";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);
    CheckClearEnrollmentData();

    // CASE: SysAppCmnExtractStringValue retrieves an invlid protocol_version.
    // For SysAppCmnExtractStringValue() about protocol_version
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "protocol_version", protocol_version,
                                   1);

    // For SysAppStateSetInvalidArgError() about protocol_version
    expect_value(__wrap_SysAppStateSetInvalidArgError, topic, topic);
    expect_value(__wrap_SysAppStateSetInvalidArgError, property, ProtocolVersion);
    will_return(__wrap_SysAppStateSetInvalidArgError, kRetOk);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ProtocolVersionNotUpdated(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    const char *protocol_version = "TB";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);
    CheckClearEnrollmentData();

    // For SysAppCmnExtractStringValue() about protocol_version
    ForSysAppCmnExtractStringValue(esfj_handle, json_value, "protocol_version", protocol_version,
                                   1);

    // CASE: SysAppStateGetProtocolVersion retrieves the same protocol_version.
    // For SysAppStateGetProtocolVersion() in CheckUpdateString
    will_return(__wrap_SysAppStateGetProtocolVersion, protocol_version);

    ForFree();
    ForFree();

    CheckJsonClose(esfj_handle, topic);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorSysAppStateSendState(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);
    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    // CASE: SysAppStateSendState fails.
    // For SysAppStateSendState()
    expect_value(__wrap_SysAppStateSendState, req, topic);
    will_return(__wrap_SysAppStateSendState, kRetFailed);

    ForFree();
    ForFree();

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCfgEndpointSettings_ErrorEsfJsonClose(void **state)
{
    RetCode ret;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;
    const char *url_backup = "old_url";
    const char *port_backup = "old_port";
    uint32_t topic = ST_TOPIC_ENDPOINT_SETTINGS;

    CheckJsonOpen(esfj_handle, json_value, endpoint_settings);

    CheckSysAppCfgEndpointSettingsReqId(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsUrlBackup(url_backup);
    CheckSysAppCfgEndpointSettingsPortBackup(port_backup);
    CheckSysAppCfgEndpointSettingsEndpointUrl(esfj_handle, json_value);
    CheckSysAppCfgEndpointSettingsEndpointPort(esfj_handle, json_value);
    CheckClearEnrollmentData();
    CheckSysAppCfgEndpointSettingsProtocolVersion(esfj_handle, json_value);

    // For SysAppStateSendState()
    expect_value(__wrap_SysAppStateSendState, req, topic);
    will_return(__wrap_SysAppStateSendState, kRetOk);

    ForFree();
    ForFree();

    // CASE: EsfJsonClose fails.
    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonInternalError);

    // Exec test target
    ret = SysAppCfgEndpointSettings(endpoint_settings);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
/*----------------------------------------------------------------------------*/
static void test_ProcessUnimplementedConfiguration_EsfJsonOpenError(void **state)
{
    struct SYS_client *evp_client = (struct SYS_client *)0x98765432;
    const char *topic = "system_settings";
    const char *config = "system_settings configuration";
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;

    // SysAppStateIsUnimplementedTopic
    will_return(__wrap_SysAppStateIsUnimplementedTopic, true);

    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);
    // Exec test target
    ConfigurationCallback(evp_client, topic, config, SYS_CONFIG_ANY, SYS_REASON_FINISHED, NULL);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ProcessUnimplementedConfiguration_EsfJsonDeserializeError(void **state)
{
    struct SYS_client *evp_client = (struct SYS_client *)0x98765432;
    const char *topic = "system_settings";
    const char *config = "system_settings configuration";
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    // SysAppStateIsUnimplementedTopic
    will_return(__wrap_SysAppStateIsUnimplementedTopic, true);

    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonDeserialize()
    expect_value(__wrap_EsfJsonDeserialize, handle, esfj_handle);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, json_value);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonInternalError);

    // EsfJsonClose
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
    // Exec test target
    ConfigurationCallback(evp_client, topic, config, SYS_CONFIG_ANY, SYS_REASON_FINISHED, NULL);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ProcessUnimplementedConfiguration_SysAppCmnGetReqIdError(void **state)
{
    struct SYS_client *evp_client = (struct SYS_client *)0x98765432;
    const char *topic = "system_settings";
    const char *config = "system_settings configuration";
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    // SysAppStateIsUnimplementedTopic
    will_return(__wrap_SysAppStateIsUnimplementedTopic, true);

    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonDeserialize()
    expect_value(__wrap_EsfJsonDeserialize, handle, esfj_handle);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, json_value);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, config);
    will_return(__wrap_SysAppCmnGetReqId, kRetFailed);

    // SysAppStateSendUnimplementedState
    will_return(__wrap_SysAppStateSendUnimplementedState, kRetOk);

    // EsfJsonClose
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
    // Exec test target
    ConfigurationCallback(evp_client, topic, config, SYS_CONFIG_ANY, SYS_REASON_FINISHED, NULL);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ProcessUnimplementedConfiguration_EsfJsonCloseError(void **state)
{
    struct SYS_client *evp_client = (struct SYS_client *)0x98765432;
    const char *topic = "system_settings";
    const char *config = "system_settings configuration";
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    // SysAppStateIsUnimplementedTopic
    will_return(__wrap_SysAppStateIsUnimplementedTopic, true);

    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonDeserialize
    expect_value(__wrap_EsfJsonDeserialize, handle, esfj_handle);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, json_value);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // SysAppCmnGetReqId
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, config);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // SysAppStateSendUnimplementedState
    will_return(__wrap_SysAppStateSendUnimplementedState, kRetOk);

    // EsfJsonClose
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonInternalError);
    // Exec test target
    ConfigurationCallback(evp_client, topic, config, SYS_CONFIG_ANY, SYS_REASON_FINISHED, NULL);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ProcessUnimplementedConfiguration_SysAppStateSendUnimplementedStateError(
    void **state)
{
    struct SYS_client *evp_client = (struct SYS_client *)0x98765432;
    const char *topic = "system_settings";
    const char *config = "system_settings configuration";
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue json_value = ESF_JSON_VALUE_INVALID;

    // SysAppStateIsUnimplementedTopic
    will_return(__wrap_SysAppStateIsUnimplementedTopic, true);

    will_return(__wrap_EsfJsonOpen, esfj_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonDeserialize()
    expect_value(__wrap_EsfJsonDeserialize, handle, esfj_handle);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, json_value);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, esfj_handle);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, json_value);
    will_return(__wrap_SysAppCmnGetReqId, config);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // SysAppStateSendUnimplementedState
    will_return(__wrap_SysAppStateSendUnimplementedState, kRetFailed);

    // EsfJsonClose
    expect_value(__wrap_EsfJsonClose, handle, esfj_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
    // Exec test target
    ConfigurationCallback(evp_client, topic, config, SYS_CONFIG_ANY, SYS_REASON_FINISHED, NULL);

    return;
}
#endif // !CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION

/*----------------------------------------------------------------------------*/

//
// main()
//

/*----------------------------------------------------------------------------*/
int main(void)
{
    const struct CMUnitTest tests[] = {
        // Initial value check for static global variable
        cmocka_unit_test(test_SysAppCfg_InitialValueOfGlobalVariable),

        // SysAppCfgInitialize()
        cmocka_unit_test(test_SysAppCfgInitialize_FullySuccess),
        cmocka_unit_test(test_SysAppCfgInitialize_ErrorSysClientNull),
        cmocka_unit_test(test_SysAppCfgInitialize_ErrorSysSetConfigurationCbSystemSettings),
        cmocka_unit_test(test_SysAppCfgInitialize_ErrorSysSetConfigurationCbNetworkSettings),
        cmocka_unit_test(test_SysAppCfgInitialize_ErrorSysSetConfigurationCbPeriodicSetting),
        cmocka_unit_test(test_SysAppCfgInitialize_ErrorSysSetConfigurationCbWirelessSetting),
        cmocka_unit_test(
            test_SysAppCfgInitialize_ErrorSysSetConfigurationCbPrivateEndpointSettings),
        cmocka_unit_test(test_SysAppCfgInitialize_ErrorSysSetConfigurationCbPrivateDeployFirmware),
        cmocka_unit_test(test_SysAppCfgInitialize_ErrorSysSetConfigurationCbPrivateDeployAiModel),

        // SysAppCfgFinalize()
        cmocka_unit_test(test_SysAppCfgFinalize),

        // ConfigurationCallback()
        cmocka_unit_test(test_ConfigurationCallback_TopicNull),
        cmocka_unit_test(test_ConfigurationCallback_ConfigNull),
        cmocka_unit_test(test_ConfigurationCallback_SystemSettings),
        cmocka_unit_test(test_ConfigurationCallback_NetworkSettings),
        cmocka_unit_test(test_ConfigurationCallback_PeriodicSetting),
        cmocka_unit_test(test_ConfigurationCallback_WirelessSetting),
        cmocka_unit_test(test_ConfigurationCallback_PrivateEndpointSettings),
        cmocka_unit_test(test_ConfigurationCallback_PrivateDeployFirmware),
        cmocka_unit_test(test_ConfigurationCallback_PrivateDeployAiModel),
        cmocka_unit_test(test_ConfigurationCallback_PrivateDeploySensorCalibrationParam),
        cmocka_unit_test(test_ConfigurationCallback_OtherTopic),

        // SysAppCfgLog()
        cmocka_unit_test(test_SysAppCfgLog_FullySuccess),
        cmocka_unit_test(test_SysAppCfgLog_ErrorEsfJsonOpen),
        cmocka_unit_test(test_SysAppCfgLog_ErrorEsfJsonDeserialize),
        cmocka_unit_test(test_SysAppCfgLog_ErrorCmnExtractStrFilter),
        cmocka_unit_test(test_SysAppCfgLog_ErrorCmnExtractStrFilter),
        cmocka_unit_test(test_SysAppCfgLog_ErrorCmnExtractStrInvalidFilter),
        cmocka_unit_test(test_SysAppCfgLog_ErrorInvalidFilter),
        cmocka_unit_test(test_SysAppCfgLog_FilterAll),
        cmocka_unit_test(test_SysAppCfgLog_FilterSensor),
        cmocka_unit_test(test_SysAppCfgLog_FilterCompanionFirmware),
        cmocka_unit_test(test_SysAppCfgLog_FilterCompanionApp),
        cmocka_unit_test(test_SysAppCfgLog_ErrorCmnExtractNumLevel),
        cmocka_unit_test(test_SysAppCfgLog_ErrorCmnExtractNumInvalidLevel),
        cmocka_unit_test(test_SysAppCfgLog_ErrorLevelTooSmall),
        cmocka_unit_test(test_SysAppCfgLog_ErrorLevelTooLarge),
        cmocka_unit_test(test_SysAppCfgLog_ErrorLogGetParamNumLevel),
        cmocka_unit_test(test_SysAppCfgLog_LevelNotUpdated),
        cmocka_unit_test(test_SysAppCfgLog_ErrorLogSetParamNumLevel),
        cmocka_unit_test(test_SysAppCfgLog_ErrorCmnExtractNumDestination),
        cmocka_unit_test(test_SysAppCfgLog_ErrorCmnExtractNumInvalidDestination),
        cmocka_unit_test(test_SysAppCfgLog_ErrorDestinationTooSmall),
        cmocka_unit_test(test_SysAppCfgLog_ErrorDestinationTooLarge),
        cmocka_unit_test(test_SysAppCfgLog_ErrorLogGetParamNumDestination),
        cmocka_unit_test(test_SysAppCfgLog_DestinationNotUpdated),
        cmocka_unit_test(test_SysAppCfgLog_ErrorLogSetParamNumDestination),
        cmocka_unit_test(test_SysAppCfgLog_ErrorCmnExtractStrStorageName),
        cmocka_unit_test(test_SysAppCfgLog_ErrorCmnExtractStrInvalidStorageName),
        cmocka_unit_test(test_SysAppCfgLog_ErrorStorageNameTooLong),
        cmocka_unit_test(test_SysAppCfgLog_ErrorLogGetParamStrStorageName),
        cmocka_unit_test(test_SysAppCfgLog_StorageNameNotUpdated),
        cmocka_unit_test(test_SysAppCfgLog_ErrorLogSetParamStrStorageName),
        cmocka_unit_test(test_SysAppCfgLog_ErrorLogSetParamStrStorageNameIO),
        cmocka_unit_test(test_SysAppCfgLog_ErrorCmnExtractStrPath),
        cmocka_unit_test(test_SysAppCfgLog_ErrorCmnExtractStrInvalidPath),
        cmocka_unit_test(test_SysAppCfgLog_ErrorPathTooLong),
        cmocka_unit_test(test_SysAppCfgLog_ErrorLogGetParamStrPath),
        cmocka_unit_test(test_SysAppCfgLog_PathNotUpdated),
        cmocka_unit_test(test_SysAppCfgLog_ErrorLogSetParamStrPath),
        cmocka_unit_test(test_SysAppCfgLog_ErrorLogSetParamStrPathIO),
        cmocka_unit_test(test_SysAppCfgLog_ErrorEsfJsonClose),

        // SysAppCfgSystemSettings()
        cmocka_unit_test(test_SysAppCfgSystemSettings_FullySuccess),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ErrorEsfJsonOpen),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ErrorEsfJsonDeserialize),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ErrorSysAppCmnGetId),
        cmocka_unit_test(test_SysAppCfgSystemSettings_NotFoundSysAppCmnGetId),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ErrorReqIdTooLong),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ErrorSysAppStateGetReqIdNullPtr),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ReqIdNotUpdated),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ErrorCmnExtractBool),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ErrorInvalidLedEnabled),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ErrorSysAppLedGetEnable),
        cmocka_unit_test(test_SysAppCfgSystemSettings_LedEnabledNotUpdated),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ErrorSysAppLedSetEnable),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ErrorEsfJsonObjectGet),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ErrorEsfJsonValueTypeGet),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ErrorEsfJsonValueTypeGetNotArray),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ArrayHasNoElements),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ErrorEsfJsonArrayGet),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ErrorEsfJsonSerialize),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ErrorEsfJsonSerializeNullPtr),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ErrorCmnExtractNumTempInterval),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ErrorInvalidTempInterval),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ErrorTempIntervalTooSmall),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ErrorTempIntervalTooLarge),
        cmocka_unit_test(test_SysAppCfgSystemSettings_TempIntervalNotUpdated),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ErrorSysAppTimerUpdateTimer),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ErrorSysAppStateSendState),
        cmocka_unit_test(test_SysAppCfgSystemSettings_ErrorEsfJsonClose),

        // SysAppCfgStaticSettings
        cmocka_unit_test(test_SysAppCfgStaticSettings_FullySuccess),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6EsfJsonOpen),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6EsfJsonDeserialize),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6LoadNetworkAddressIpAddress),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6CheckIpAddressTypeIpAddress),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6InvalidIpAddress),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6IpAddressTooLong),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6EsfNMLoadParamIpAddress),
        cmocka_unit_test(test_SysAppCfgStaticSettings_IPv6IpAddressNotUpdated),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6EsfNMSaveParamIpAddress),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6LoadNetworkAddressSubnetMask),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6CheckIpAddressTypeSubnetMask),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6InvalidSubnetMask),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6SubnetMaskTooLong),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6EsfNMLoadParamSubnetMask),
        cmocka_unit_test(test_SysAppCfgStaticSettings_IPv6SubnetMaskNotUpdated),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6EsfNMSaveParamSubnetMask),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6LoadNetworkAddressGateway),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6CheckIpAddressTypeGateway),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6InvalidGateway),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6GatewayTooLong),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6EsfNMLoadParamGateway),
        cmocka_unit_test(test_SysAppCfgStaticSettings_IPv6GatewayNotUpdated),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6EsfNMSaveParamGateway),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6LoadNetworkAddressDns),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6CheckIpAddressTypeDns),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6InvalidDns),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6DnsTooLong),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6EsfNMLoadParamDns),
        cmocka_unit_test(test_SysAppCfgStaticSettings_IPv6DnsNotUpdated),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6EsfNMSaveParamDns),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv6EsfJsonClose),
        cmocka_unit_test(test_SysAppCfgStaticSettings_IPv4),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4EsfJsonOpen),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4EsfJsonDeserialize),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4LoadNetworkAddressIpAddress),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4CheckIpAddressTypeIpAddress),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4InvalidIpAddress),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4IpAddressTooLong),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4EsfNMLoadParamIpAddress),
        cmocka_unit_test(test_SysAppCfgStaticSettings_IPv4IpAddressNotUpdated),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4EsfNMSaveParamIpAddress),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4LoadNetworkAddressSubnetMask),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4CheckIpAddressTypeSubnetMask),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4InvalidSubnetMask),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4SubnetMaskTooLong),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4EsfNMLoadParamSubnetMask),
        cmocka_unit_test(test_SysAppCfgStaticSettings_IPv4SubnetMaskNotUpdated),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4EsfNMSaveParamSubnetMask),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4LoadNetworkAddressGateway),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4CheckIpAddressTypeGateway),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4InvalidGateway),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4GatewayTooLong),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4EsfNMLoadParamGateway),
        cmocka_unit_test(test_SysAppCfgStaticSettings_IPv4GatewayNotUpdated),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4EsfNMSaveParamGateway),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4LoadNetworkAddressDns),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4CheckIpAddressTypeDns),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4InvalidDns),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4DnsTooLong),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4EsfNMLoadParamDns),
        cmocka_unit_test(test_SysAppCfgStaticSettings_IPv4DnsNotUpdated),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4EsfNMSaveParamDns),
        cmocka_unit_test(test_SysAppCfgStaticSettings_ErrorIPv4EsfJsonClose),

        // SysAppCfgProxySettings()
        cmocka_unit_test(test_SysAppCfgProxySettings_FullySuccess),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorEsfJsonOpen),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorEsfJsonDeserialize),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorCmnExtractStrProxyUrl),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorInvalidProxyUrl),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorProxyUrlTooLong),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorEsfNMLoadParamProxyUrl),
        cmocka_unit_test(test_SysAppCfgProxySettings_ProxyUrlNotUpdated),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorEsfNMSaveParamProxyUrl),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorCmnExtractStrProxyPort),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorInvalidProxyPort),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorProxyPortTooSmall),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorProxyPortTooLarge),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorEsfNMLoadParamProxyPort),
        cmocka_unit_test(test_SysAppCfgProxySettings_ProxyPortNotUpdated),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorEsfNMSaveParamProxyPort),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorCmnExtractStrProxyUserName),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorInvalidProxyUserName),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorProxyUserNameTooLong),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorEsfNMLoadParamProxyUserName),
        cmocka_unit_test(test_SysAppCfgProxySettings_ProxyUserNameNotUpdated),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorEsfNMSaveParamProxyUserName),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorCmnExtractStrProxyPassword),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorInvalidProxyPassword),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorProxyPasswordTooLong),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorEsfNMLoadParamProxyPassword),
        cmocka_unit_test(test_SysAppCfgProxySettings_ProxyPasswordNotUpdated),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorEsfNMSaveParamProxyPassword),
        cmocka_unit_test(test_SysAppCfgProxySettings_ErrorEsfJsonClose),

        // IsValidUrlOrIpAddress()
        cmocka_unit_test(test_IsValidUrlOrIpAddress_SuccessDomain),
        cmocka_unit_test(test_IsValidUrlOrIpAddress_SuccessIPv4),
        cmocka_unit_test(test_IsValidUrlOrIpAddress_ErrorDomain),
        cmocka_unit_test(test_IsValidUrlOrIpAddress_ErrorIPv6),

        // IsValidUrlOrNullString()
        cmocka_unit_test(test_IsValidUrlOrNullString_SuccessDomainSubdomain),
        cmocka_unit_test(test_IsValidUrlOrNullString_ErrorDomainSubdomain),
        cmocka_unit_test(test_IsValidUrlOrNullString_ErrorUrlLength254),

        // SysAppCfgNetworkSettings()
        cmocka_unit_test(test_SysAppCfgNetworkSettings_FullySuccess),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorEsfJsonOpen),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorEsfJsonDeserialize),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorSysAppCmnGetReqId),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_NotFoundSysAppCmnGetReqId),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorCmnGetReqIdReqIdTooLong),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorCmnGetReqIdReqIdNullPtr),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_CmnGetReqIdReqIdNotUpdated),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorLoadIpMethodFromEsf),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorSysAppCmnExtractNumberValue),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorCmnExtractNumInvalidIpMethod),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorCmnExtractNumIpMethodOutOfRangeSmall),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorCmnExtractNumIpMethodOutOfRangeLarge),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorSysAppCmnExtractStringValue),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorCmnExtractStrInvalidNtpUrl),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorCmnExtractStrNtpUrlTooLong),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorCmnExtractStrNtpUrlLen254),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorEsfCMGetParamsNtpUrl),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_CmnExtractStrNtpUrlNotUpdated),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorEsfClockManagerSetParamsForcibly),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorEsfClockManagerGetParams),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorEsfJsonObjectGetIpv6),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorEsfJsonValueTypeGetIpv6),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorEsfJsonTypeGetIpv6NotObject),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorEsfJsonSerializeIpv6),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorEsfJsonSerializeIpv6NullPtr),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorEsfJsonObjectGetIpv4),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorEsfJsonValueTypeGetIpv4),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorEsfJsonTypeGetIpv4NotObject),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorEsfJsonSerializeIpv4),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorEsfJsonSerializeIpv4NullPtr),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorStaticSettingsIPv4EsfJsonOpen),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorEsfJsonObjectGetProxySettings),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorEsfJsonValueTypeGetProxySettings),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorEsfJsonTypeGetProxySettingsNotObject),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorEsfJsonSerializeProxySettings),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorEsfJsonSerializeProxySettingsNullPtr),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorNMLoadParamIpMethod),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_IpMethodNotUpdated),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorEsfNMSaveParam),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorSysAppStateSendState),
        cmocka_unit_test(test_SysAppCfgNetworkSettings_ErrorEsfJsonClose),

        // SysAppCfgIntervalSetting()
        cmocka_unit_test(test_SysAppCfgIntervalSetting_FullySuccess),
        cmocka_unit_test(test_SysAppCfgIntervalSetting_ErrorEsfJsonOpen),
        cmocka_unit_test(test_SysAppCfgIntervalSetting_ErrorEsfJsonDeserialize),
        cmocka_unit_test(test_SysAppCfgIntervalSetting_ErrorEsfJsonClose),
        cmocka_unit_test(test_SysAppCfgIntervalSetting_ErrorCmnExtractStrBaseTime),
        cmocka_unit_test(test_SysAppCfgIntervalSetting_ErrorInvalidBaseTime),
        cmocka_unit_test(test_SysAppCfgIntervalSetting_ErrorBaseTimeTooLong),
        cmocka_unit_test(test_SysAppCfgIntervalSetting_ErrorCmnExtractNumCaptureInterval),
        cmocka_unit_test(test_SysAppCfgIntervalSetting_ErrorInvalidCaptureInterval),
        cmocka_unit_test(test_SysAppCfgIntervalSetting_ErrorCaptureIntervalTooSmall),
        cmocka_unit_test(test_SysAppCfgIntervalSetting_ErrorCaptureIntervalOutOfRange),
        cmocka_unit_test(test_SysAppCfgIntervalSetting_ErrorCaptureIntervalTooLarge),
        cmocka_unit_test(test_SysAppCfgIntervalSetting_CaptureIntervalZero),
        cmocka_unit_test(test_SysAppCfgIntervalSetting_ErrorCmnExtractNumConfigInterval),
        cmocka_unit_test(test_SysAppCfgIntervalSetting_ErrorInvalidConfigInterval),
        cmocka_unit_test(test_SysAppCfgIntervalSetting_ErrorConfigIntervalTooSmall),
        cmocka_unit_test(test_SysAppCfgIntervalSetting_ErrorConfigIntervalOutOfRange),
        cmocka_unit_test(test_SysAppCfgIntervalSetting_ErrorConfigIntervalTooLarge),
        cmocka_unit_test(test_SysAppCfgIntervalSetting_ConfigIntervalZero),

        // SysAppCfgPeriodicSetting()
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_FullySuccess),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorEsfJsonOpen),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorEsfJsonDeserialize),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorSysAppCmnGetReqId),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_NotFoundSysAppCmnGetReqId),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorReqIdTooLong),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorSysAppStateGetReqId),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ReqIdNotUpdated),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorCmnExtractNumOperationMode),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorCmnExtractNumInvalidOperationMode),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorOperationModeTooSmall),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorOperationModeTooLarge),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorCmnExtractNumRecoveryMethod),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorCmnExtractNumInvalidRecoveryMethod),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorRecoveryMethodTooSmall),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorRecoveryMethodTooLarge),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorEsfJsonObjectGet),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorEsfJsonValueTypeGet),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorEsfJsonValueTypeGetNotArray),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ArrayHasNoElements),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorEsfJsonArrayGet),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorEsfJsonSerialize),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorEsfJsonSerializeNullPtr),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorCmnExtractStrIpAddrSetting),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorCmnExtractStrInvalidIpAddrSetting),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorInvalidIpAddrSetting),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_IpAddrSettingDhcp),
        cmocka_unit_test(test_SysAppCfgPeriodicSetting_ErrorEsfJsonClose),

        // SysAppCfgStaModeSetting()
        cmocka_unit_test(test_SysAppCfgStaModeSetting_FullySuccess),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_ErrorEsfJsonOpen),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_ErrorEsfDeserialize),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_ErrorCmnExtractStrSsid),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_ErrorCmnExtractStrInvalidSsid),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_ErrorCmnExtractStrSsidTooLong),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_ErrorCheckUpdateStringSsid),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_CheckUpdateStringSsidNotUpdated),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_ErrorEsfNMSaveParameterSsid),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_ErrorCmnExtractStrPassword),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_ErrorCmnExtractStrInvalidPassword),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_ErrorCmnExtractStrPasswordTooLong),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_ErrorPasswordLength1Char),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_ErrorPasswordLength7Chars),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_SuccessPassword8Chars),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_SuccessEmptyPassword),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_ErrorCheckUpdateStringPassword),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_CheckUpdateStringPasswordNotUpdated),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_ErrorEsfNMSaveParameterPassword),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_ErrorSysAppCmnExtractNumberValueEncryption),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_ErrorCmnExtractNumInvalidEncryption),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_ErrorCmnExtractNumEncryptionOutOfRangeSmall),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_ErrorCmnExtractNumEncryptionOutOfRangeLarge),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_ErrorCheckUpdateNumberEncryption),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_CheckUpdateNumberEncryptionNotUpdated),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_ErrorEsfNMSaveParameterEncryption),
        cmocka_unit_test(test_SysAppCfgStaModeSetting_ErrorEsfJsonClose),

        // SysAppCfgWirelessSetting()
        cmocka_unit_test(test_SysAppCfgWirelessSetting_FullySuccess),
        cmocka_unit_test(test_SysAppCfgWirelessSetting_ErrorEsfJsonOpen),
        cmocka_unit_test(test_SysAppCfgWirelessSetting_ErrorEsfJsonDeserialize),
        cmocka_unit_test(test_SysAppCfgWirelessSetting_ErrorSysAppCmnGetReqId),
        cmocka_unit_test(test_SysAppCfgWirelessSetting_NotFoundSysAppCmnGetReqId),
        cmocka_unit_test(test_SysAppCfgWirelessSetting_ErrorReqIdTooLong),
        cmocka_unit_test(test_SysAppCfgWirelessSetting_ErrorSysAppStateGetReqIdNullPtr),
        cmocka_unit_test(test_SysAppCfgWirelessSetting_ReqIdNotUpdated),
        cmocka_unit_test(test_SysAppCfgWirelessSetting_ErrorEsfJsonObjectGet),
        cmocka_unit_test(test_SysAppCfgWirelessSetting_ErrorEsfJsonValueTypeGet),
        cmocka_unit_test(test_SysAppCfgWirelessSetting_ErrorEsfJsonTypeGetNotObject),
        cmocka_unit_test(test_SysAppCfgWirelessSetting_ErrorEsfJsonSerialize),
        cmocka_unit_test(test_SysAppCfgWirelessSetting_ErrorEsfJsonSerializeNullPtr),
        cmocka_unit_test(test_SysAppCfgWirelessSetting_ErrorSysAppStateSendState),
        cmocka_unit_test(test_SysAppCfgWirelessSetting_ErrorEsfJsonClose),

        // SysAppCfgEndpointSettings()
        cmocka_unit_test(test_SysAppCfgEndpointSettings_FullySuccess),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorEsfJsonOpen),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorEsfJsonDeserialize),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorSysAppCmnGetReqId),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_NotFoundSysAppCmnGetReqId),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorReqIdTooLong),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorSysAppStateGetReqId),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ReqIdNotUpdated),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorMAllocUrlBackup),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorEsfSMGetEvpHubUrlBackup),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorMAllocPortBackup),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorEsfSMGetEvpHubPortBackup),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorCmnExtractStrEndpointUrl),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorInvalidEndpointUrl),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorEndpointUrlTooLong),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorCheckUpdateStrMAllocEndpointUrl),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorCheckUpdateStrEsfSMGetEvpHubUrl),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_EndpointUrlNotUpdated),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorEsfSMSetEvpHubUrl),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorCmnExtractStrEndpointPort),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorInvalidEndpointPort),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorEndpointPortTooSmall),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorEndpointPortTooLarge),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorMAllocEndpointPort),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorCheckUpdateStrMAllocEndpointPort),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorCheckUpdateStrEsfSMGetEvpHubPort),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_EndpointPortNotUpdated),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorEsfSMSetEvpHubPort),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorEsfSMSetEvpHubUrlRevert),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorEsfSMSetEvpHubPortRevert),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorClearEnrollmentDataEsfSMSetProjectId),
        cmocka_unit_test(
            test_SysAppCfgEndpointSettings_ErrorClearEnrollmentDataEsfSMSetRegisterToken),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorCmnExtractStrProtocolVersion),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorInvalidProtocolVersion),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorProtocolVersionTooLong),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorProtocolVersionNotEqToTB),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ProtocolVersionNotUpdated),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorSysAppStateSendState),
        cmocka_unit_test(test_SysAppCfgEndpointSettings_ErrorEsfJsonClose),

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
        // ProcessUnimplementedConfiguration()
        cmocka_unit_test(test_ProcessUnimplementedConfiguration_EsfJsonOpenError),
        cmocka_unit_test(test_ProcessUnimplementedConfiguration_EsfJsonDeserializeError),
        cmocka_unit_test(test_ProcessUnimplementedConfiguration_SysAppCmnGetReqIdError),
        cmocka_unit_test(test_ProcessUnimplementedConfiguration_EsfJsonCloseError),
        cmocka_unit_test(
            test_ProcessUnimplementedConfiguration_SysAppStateSendUnimplementedStateError),
#endif // !CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    };

    return (((cmocka_run_group_tests(tests, NULL, NULL)) == 0) ? 0 : 1);
}
