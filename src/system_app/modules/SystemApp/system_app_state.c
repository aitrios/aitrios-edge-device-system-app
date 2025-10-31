/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

#if defined(__NuttX__)
#include <nuttx/config.h>
#endif

#if defined(CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING)
#include "system_app_vsc_manager.h"
#endif /* CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING */

#include "evp/sdk_sys.h"
#include "sensor_main.h"
#include "senscord/c_api/senscord_c_api.h"
#include "senscord/inference_stream/c_api/property_c_types.h"
#include "firmware_manager.h"
#include "network_manager.h"
#include "system_manager.h"
#include "clock_manager.h"
#include "clock_manager_setting.h"
#include "power_manager.h"
#include "led_manager.h"
#include "json/include/json.h"
#include "system_manager.h"
#include "base64/include/base64.h"

#include "system_app_common.h"
#include "system_app_log.h"
#include "system_app_deploy.h"
#include "system_app_state.h"
#include "system_app_led.h"
#include "system_app_timer.h"
#include "system_app_util.h"

//
// Macros.
//

#define TEMPERATURE_UPPER_THRESHOLD CONFIG_EXTERNAL_SYSTEMAPP_TEMPERATURE_UPPER_THRESHOLD
#define TEMPERATURE_LOWER_THRESHOLD CONFIG_EXTERNAL_SYSTEMAPP_TEMPERATURE_LOWER_THRESHOLD

#define TEMPERATURE_UPPER_APPROACHING_THRESHOLD (TEMPERATURE_UPPER_THRESHOLD - 10)
#define TEMPERATURE_LOWER_APPROACHING_THRESHOLD (TEMPERATURE_LOWER_THRESHOLD + 10)

#define TEMPERATURE_INVALID_VAL (-300) /*T.B.D*/
#define TRUNCATION_SUFFIX "..."
#define TRUNCATION_SUFFIX_LEN (sizeof(TRUNCATION_SUFFIX) - 1)
#define DEFAULT_UPDATE_INTERVAL_SEC (10)

// TODO:
// Temporary solution for not being able to get name from FirmwareManager

#define MAIN_CHIP_NAME "main_chip"
#define SENSOR_CHIP_NAME "sensor_chip"
#define COMPANION_CHIP_NAME "companion_chip"

#ifdef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
#define POWER_LEVEL (100)
#define BOOTUP_REASON (0)
#else // !CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
#define POWER_LEVEL (-1)
#define BOOTUP_REASON (-1)
#endif // CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION

//
// File private structure.
//

typedef struct {
    int flag_value;
    const char *message;
} ErrorFlag;

//
// File static variables.
//

STATIC struct SYS_client *s_sys_client = NULL;

STATIC StDeviceInfoParams s_device_info;
STATIC StDeviceCapabilitiesParams s_device_capabilities;
STATIC StDeviceStatesParams s_device_states;
STATIC StPowerStatesParams s_power_states;
STATIC StSensorParams s_chips[ST_CHIPS_NUM];
STATIC StAIModelParams s_ai_model[ST_AIMODELS_NUM];
STATIC CfgStSystemSettingsParam s_system_settings;
STATIC CfgStLogParam s_log[LogFilterNum];
STATIC CfgStNetworkSettingsParam s_network_settings;
STATIC CfgStStaticSettingsParam s_static_settings_ipv4;
STATIC CfgStStaticSettingsParam s_static_settings_ipv6;
STATIC CfgStProxySettingsParam s_proxy_settings;
STATIC CfgStWirelessSettingsParam s_wireless_setting;
STATIC CfgStWirelessStaModeParam s_sta_mode_setting;
STATIC CfgStIntervalSettingParam s_interval_setting[2];
STATIC CfgStPeriodicSettingParam s_periodic_setting;
STATIC CfgStEndpointSettingsParam s_endpoint_settings;
#if defined(CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING)
STATIC CfgStStreamingSettingsParam s_streaming_settings;
#endif /* CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING */

STATIC senscord_core_t s_sccore = 0;
STATIC senscord_stream_t s_scstream = 0;

static pthread_mutex_t s_senscord_access_mutex = PTHREAD_MUTEX_INITIALIZER;

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
STATIC struct {
    uint32_t topic;
    const char *topic_str;
    char id[CFG_RES_ID_LEN + 1];
} s_unimplemented_list[] = {
    {.topic = ST_TOPIC_SYSTEM_SETTINGS, .topic_str = "system_settings"},
    {.topic = ST_TOPIC_NETWORK_SETTINGS, .topic_str = "network_settings"},
    {.topic = ST_TOPIC_WIRELESS_SETTING, .topic_str = "wireless_setting"},
    {.topic = ST_TOPIC_ENDPOINT_SETTINGS, .topic_str = "PRIVATE_endpoint_settings"},
};
#endif // !CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION

//
// File static private functions.
//

STATIC RetCode SendState(uint32_t next_req);
STATIC RetCode SendDeviceInfo(void);
STATIC RetCode SendDeviceCapabilities(void);
STATIC RetCode SendDeviceStates(void);
STATIC RetCode SendReserved(void);
STATIC RetCode SendSystemSettings(void);
STATIC RetCode SendNetworkSettings(void);
STATIC RetCode SendWirelessSetting(void);
#if defined(CONFIG_BOARD_WIFI_SMALL_ES) //T3Ws
STATIC RetCode SendPeriodicSetting(void);
#else
#endif
STATIC RetCode SendEndpointSettings(void);

#if defined(CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING)
STATIC RetCode SendStreamingSettings(void);
STATIC void UpdateStreamingStatusFromVsc(void);
STATIC void UpdateInternalStateFromVscStatus(const vsclient_server_status_t *vsc_status);
STATIC void UpdateRtspConfigFromVsc(const vsclient_server_status_t *vsc_status);
STATIC void UpdateNfsConfigFromVsc(const vsclient_server_status_t *vsc_status);
#endif /* CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING */

STATIC RetCode SendDeploy(uint32_t topic_bits);

STATIC void RequestConfigStateUpdate(uint32_t topic);

STATIC bool AppendErrorDetail(const char *msg, char *error_detail_msg,
                              size_t error_detail_msg_size);

STATIC void CheckErrorFlagAndAppendMessage(const ErrorFlag *error_flags, size_t flag_count,
                                           char *error_detail_msg, size_t error_detail_msg_size,
                                           bool *error_exist);

STATIC void CheckErrorFlagAndAppendMessageWithField(const char *base_prefix, const char *field_name,
                                                    size_t index, char *error_detail_msg,
                                                    size_t error_detail_msg_size,
                                                    bool *error_exist);

/*----------------------------------------------------------------------------*/
STATIC char *ConvertFilterValueToString(CfgStLogFilter filter, char *filter_name)
{
    if (filter == AllLog) {
    }
    else if (filter == MainFwLog) {
        strncpy(filter_name, "main", CFGST_LOG_FILTER_LEN);
    }
    else if (filter == SensorLog) {
        strncpy(filter_name, "sensor", CFGST_LOG_FILTER_LEN);
    }
    else if (filter == CompanionFwLog) {
        strncpy(filter_name, "companion_fw", CFGST_LOG_FILTER_LEN);
    }
    else if (filter == CompanionAppLog) {
        strncpy(filter_name, "companion_app", CFGST_LOG_FILTER_LEN);
    }
    else {
        filter_name[0] = '\0';
    }

    return filter_name;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode ReadOutLogByFilterNo(CfgStLogFilter filter)
{
    RetCode ret = kRetOk;
    RetCode stat = kRetOk;

    /* Read all log setting parameters, for each filter(Apps). */

    if ((filter >= MainFwLog) && (filter < LogFilterNum)) {
        s_log[filter].filter = (CfgStLogFilter)filter;

        /* Get information for level */
        CfgStLogLevel level;
        stat = SysAppLogGetParameterNumber(filter, LogLevel, (int *)&level);

        if (stat == kRetOk) {
            /* Save readed parameters. */
            s_log[filter].level = level;
            SYSAPP_DBG("SysAppLogGetParameterNumber(f:%d, p:level) value %d", filter, level);
        }
        else {
            /* Save defult setting parameters, for read error. */
            s_log[filter].level = InfoLv;
            SYSAPP_WARN("SysAppLogGetParameterNumber(f:%d, p:level) faild %d", filter, stat);
            ret = kRetFailed;
        }

        /* Get information for destination */
        CfgStLogDestination destination;
        stat = SysAppLogGetParameterNumber(filter, LogDestination, (int *)&destination);

        if (stat == kRetOk) {
            /* Save readed parameters. */
            s_log[filter].destination = destination;
            SYSAPP_DBG("SysAppLogGetParameterNumber(f:%d, p:destination) value %d", filter,
                       destination);
        }
        else {
            /* Save defult setting parameters, for read error. */
            s_log[filter].destination = DestUart;
            SYSAPP_WARN("SysAppLogGetParameterNumber(f:%d, p:destination) faild %d", filter, stat);
            ret = kRetFailed;
        }

        /* Get information for storage_name */
        char buff_name[sizeof(s_log[0].storage_name)];
        stat = SysAppLogGetParameterString(filter, LogStorageName, buff_name, sizeof(buff_name));

        if (stat == kRetOk) {
            /* Save readed parameters. */
            snprintf(s_log[filter].storage_name, sizeof(s_log[filter].storage_name), "%s",
                     buff_name);
            SYSAPP_DBG("SysAppLogGetParameterString(f:%d, p:storage_name) value %s", filter,
                       buff_name);
        }
        else {
            /* Save defult setting parameters, for read error. */
            s_log[filter].storage_name[0] = '\0';
            SYSAPP_WARN("SysAppLogGetParameterString(f:%d, p:storage_name) faild %d", filter, stat);
            ret = kRetFailed;
        }

        /* Get information for path */
        char buff_path[sizeof(s_log[0].path)];
        stat = SysAppLogGetParameterString(filter, LogPath, buff_path, sizeof(buff_path));

        if (stat == kRetOk) {
            /* Save readed parameters. */
            snprintf(s_log[filter].path, sizeof(s_log[filter].path), "%s", buff_path);
            SYSAPP_DBG("SysAppLogGetParameterString(f:%d, p:path) value %s", filter, buff_path);
        }
        else {
            /* Save defult setting parameters, for read error. */
            s_log[filter].storage_name[0] = '\0';
            SYSAPP_WARN("SysAppLogGetParameterString(f:%d, p:path) faild %d", filter, stat);
            ret = kRetFailed;
        }
    }
    else {
        SYSAPP_ERR("ReadOutLogByFilterNo(f:%d) : invalid filter.", filter);
        ret = kRetFailed;
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode ReadOutLogSystemApp(void)
{
    return ReadOutLogByFilterNo(MainFwLog);
}

/*----------------------------------------------------------------------------*/
STATIC RetCode ReadOutLogSensor(void)
{
    return ReadOutLogByFilterNo(SensorLog);
}

/*----------------------------------------------------------------------------*/
STATIC RetCode ReadOutLogCompanionFw(void)
{
    return ReadOutLogByFilterNo(CompanionFwLog);
}

/*----------------------------------------------------------------------------*/
STATIC RetCode ReadOutLogCompanionApp(void)
{
    return ReadOutLogByFilterNo(CompanionAppLog);
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonReqInfoCore(EsfJsonHandle handle, EsfJsonValue root, const char *req_id)
{
    RetCode ret = kRetOk;

    // Set req_id.

    SysAppCmnSetStringValue(handle, root, "req_id", req_id);

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonReqInfoSystemSettings(EsfJsonHandle handle, EsfJsonValue root, void *ctx)
{
    (void)ctx;
    return MakeJsonReqInfoCore(handle, root, s_system_settings.id);
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonReqInfoNetworkSettings(EsfJsonHandle handle, EsfJsonValue root, void *ctx)
{
    (void)ctx;
    return MakeJsonReqInfoCore(handle, root, s_network_settings.id);
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonReqInfoWirelessSetting(EsfJsonHandle handle, EsfJsonValue root, void *ctx)
{
    (void)ctx;
    return MakeJsonReqInfoCore(handle, root, s_wireless_setting.id);
}

#if defined(CONFIG_BOARD_WIFI_SMALL_ES) //T3Ws
/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonReqInfoPeriodicSetting(EsfJsonHandle handle, EsfJsonValue root, void *ctx)
{
    (void)ctx;
    return MakeJsonReqInfoCore(handle, root, "");
}
#else
#endif

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonReqInfoEndpointSettings(EsfJsonHandle handle, EsfJsonValue root, void *ctx)
{
    (void)ctx;
    return MakeJsonReqInfoCore(handle, root, s_endpoint_settings.id);
}

#if defined(CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING)
/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonReqInfoStreamingSettings(EsfJsonHandle handle, EsfJsonValue root, void *ctx)
{
    (void)ctx;
    return MakeJsonReqInfoCore(handle, root, s_streaming_settings.id);
}
#endif /* CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING */

/*----------------------------------------------------------------------------*/
STATIC RetCode GetErrorInfo(CfgStUpdateInfo *update, int *code, char *detail_msg, int len)
{
    RetCode ret = kRetOk;

    // Check and set invalid_argument.

    if (update->invalid_arg_flag != 0) {
        *code = RESULT_CODE_INVALID_ARGUMENT;
        snprintf(detail_msg, len, "invalid_argument");
        return ret;
    }

    // Check and set internal.

    if (update->internal_error_flag != 0) {
        *code = RESULT_CODE_INTERNAL;
        snprintf(detail_msg, len, "internal");
        return ret;
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonResInfoSystemSettings(EsfJsonHandle handle, EsfJsonValue root, void *ctx)
{
    (void)ctx;
    int code = 0;
    char detail_msg[256] = "ok";
    bool error_exist = false;
    char error_detail_msg[256] = "";

    ErrorFlag error_flags[] = {
        {s_system_settings.invalid_led_enabled_flag, "led enabled is invalid"},
        {s_system_settings.invalid_temperature_update_interval_flag,
         "invalid temperature update interval"},
    };

    if (s_system_settings.update.invalid_arg_flag != 0) {
        error_exist = true;
    }

    CheckErrorFlagAndAppendMessage(error_flags, sizeof(error_flags) / sizeof(error_flags[0]),
                                   error_detail_msg, sizeof(error_detail_msg), &error_exist);

    for (uint32_t idx = AllLog; idx < LogFilterNum; idx++) {
        size_t i = idx - AllLog;
        if (s_log[idx].invalid_filter_flag)
            CheckErrorFlagAndAppendMessageWithField("invalid filter", NULL, 0, error_detail_msg,
                                                    sizeof(error_detail_msg), &error_exist);

        ErrorFlag log_fields[] = {{s_log[idx].invalid_level_flag, "level"},
                                  {s_log[idx].invalid_destination_flag, "destination"},
                                  {s_log[idx].invalid_storage_name_flag, "storage name"},
                                  {s_log[idx].invalid_path_flag, "path"}};

        for (size_t j = 0; j < sizeof(log_fields) / sizeof(log_fields[0]); j++) {
            if (log_fields[j].flag_value) {
                CheckErrorFlagAndAppendMessageWithField("invalid", log_fields[j].message, i,
                                                        error_detail_msg, sizeof(error_detail_msg),
                                                        &error_exist);
            }
        }
    }

    if (error_exist) {
        code = RESULT_CODE_INVALID_ARGUMENT;
        if (strlen(error_detail_msg) > 0) {
            snprintf(detail_msg, sizeof(detail_msg), "%s", error_detail_msg);
        }
        else {
            snprintf(detail_msg, sizeof(detail_msg), "invalid_argument");
        }
        goto call_core;
    }

    // Check and set internal.

    if (s_system_settings.update.internal_error_flag != 0) {
        error_exist = true;
    }

    for (uint32_t idx = AllLog; idx < LogFilterNum; idx++) {
        if (s_log[idx].update.internal_error_flag != 0) {
            error_exist = true;
            break;
        }
    }

    if (error_exist) {
        code = RESULT_CODE_INTERNAL;
        snprintf(detail_msg, sizeof(detail_msg), "internal");
        goto call_core;
    }

call_core:

    return SysAppCmnMakeJsonResInfo(handle, root, s_system_settings.id, code, detail_msg);
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonResInfoNetworkSettings(EsfJsonHandle handle, EsfJsonValue root, void *ctx)
{
    (void)ctx;
    int code = 0;
    char detail_msg[256] = "ok";
    bool error_exist = false;
    char error_detail_msg[256] = "";

    ErrorFlag error_flags[] = {
        {s_network_settings.invalid_ip_method_flag, "can't change ip method"},
        {s_network_settings.invalid_ntp_url_flag, "invalid ntp url"},
        {s_network_settings.invalid_ntp2_url_flag, "invalid ntp2 url"},

        // IPv4
        {s_static_settings_ipv4.invalid_ip_address_flag, "invalid ip address(ipv4)"},
        {s_static_settings_ipv4.invalid_subnet_mask_flag, "invalid subnet mask(ipv4)"},
        {s_static_settings_ipv4.invalid_gateway_address_flag, "invalid gateway address(ipv4)"},
        {s_static_settings_ipv4.invalid_dns_address_flag, "invalid dns address(ipv4)"},
        {s_static_settings_ipv4.invalid_dns2_address_flag, "invalid dns2 address(ipv4)"},

#if 0 // TODO: IPv6 could be save but not effective.
    // IPv6
    { s_static_settings_ipv6.invalid_ip_address_flag,      "invalid ip address(ipv6)" },
    { s_static_settings_ipv6.invalid_subnet_mask_flag,     "invalid subnet mask(ipv6)" },
    { s_static_settings_ipv6.invalid_gateway_address_flag, "invalid gateway address(ipv6)" },
    { s_static_settings_ipv6.invalid_dns_address_flag,     "invalid dns address(ipv6)" },
#endif

        // Proxy
        {s_proxy_settings.invalid_proxy_url_flag, "invalid proxy url"},
        {s_proxy_settings.invalid_proxy_port_flag, "invalid proxy port"},
        {s_proxy_settings.invalid_proxy_user_name_flag, "invalid proxy user name"},
        {s_proxy_settings.invalid_proxy_password_flag, "invalid proxy password"},
    };

    // Check and set invalid_argument.

    if (s_network_settings.update.invalid_arg_flag != 0) {
        error_exist = true;
    }

    if ((s_static_settings_ipv4.update.invalid_arg_flag != 0)
#if 0 // TODO:IPv6 could be save but not effective.
   || (s_static_settings_ipv6.update.invalid_arg_flag != 0)
#endif
    ) {
        // If either of IPv4 or IPv6 is valid, treat result as valid.

        error_exist = true;
    }

    if (s_proxy_settings.update.invalid_arg_flag != 0) {
        error_exist = true;
    }

    CheckErrorFlagAndAppendMessage(error_flags, sizeof(error_flags) / sizeof(error_flags[0]),
                                   error_detail_msg, sizeof(error_detail_msg), &error_exist);

    if (error_exist) {
        code = RESULT_CODE_INVALID_ARGUMENT;
        if (strlen(error_detail_msg) > 0) {
            snprintf(detail_msg, sizeof(detail_msg), "%s", error_detail_msg);
        }
        else {
            snprintf(detail_msg, sizeof(detail_msg), "invalid_argument");
        }
        goto call_core;
    }

    // Check and set internal.

    if (s_network_settings.update.internal_error_flag != 0) {
        error_exist = true;
    }

    if ((s_static_settings_ipv4.update.internal_error_flag != 0) ||
        (s_static_settings_ipv6.update.internal_error_flag != 0)) {
        // If either of IPv4 or IPv6 is valid, treat result as valid.

        error_exist = true;
    }

    if (s_proxy_settings.update.internal_error_flag != 0) {
        error_exist = true;
    }

    if (error_exist) {
        code = RESULT_CODE_INTERNAL;
        snprintf(detail_msg, sizeof(detail_msg), "internal");
        goto call_core;
    }

call_core:

    // Check and set internal.

    return SysAppCmnMakeJsonResInfo(handle, root, s_network_settings.id, code, detail_msg);
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonResInfoWirelessSetting(EsfJsonHandle handle, EsfJsonValue root, void *ctx)
{
    (void)ctx;
    int code = 0;
    char detail_msg[256] = "ok";
    bool error_exist = false;
    char error_detail_msg[256] = "";

    ErrorFlag error_flags[] = {
        {s_sta_mode_setting.invalid_ssid_flag, "invalid ssid"},
        {s_sta_mode_setting.invalid_password_flag, "invalid password"},
        {s_sta_mode_setting.invalid_encryption_flag, "invalid encryption"},
    };

    // Check and set invalid_argument.

    if (s_wireless_setting.update.invalid_arg_flag != 0) {
        error_exist = true;
    }

    // Check specific error flags and append messages.

    CheckErrorFlagAndAppendMessage(error_flags, sizeof(error_flags) / sizeof(error_flags[0]),
                                   error_detail_msg, sizeof(error_detail_msg), &error_exist);

    if (error_exist) {
        code = RESULT_CODE_INVALID_ARGUMENT;
        if (strlen(error_detail_msg) > 0) {
            snprintf(detail_msg, sizeof(detail_msg), "%s", error_detail_msg);
        }
        else {
            snprintf(detail_msg, sizeof(detail_msg), "invalid_argument");
        }
        goto call_core;
    }

    // Check and set internal.

    if (s_sta_mode_setting.update.internal_error_flag != 0) {
        error_exist = true;
    }

    if (error_exist) {
        code = RESULT_CODE_INTERNAL;
        snprintf(detail_msg, sizeof(detail_msg), "internal");
        goto call_core;
    }

call_core:

    return SysAppCmnMakeJsonResInfo(handle, root, s_wireless_setting.id, code, detail_msg);
}

#if defined(CONFIG_BOARD_WIFI_SMALL_ES) //T3Ws
/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonResInfoPeriodicSetting(EsfJsonHandle handle, EsfJsonValue root, void *ctx)
{
    (void)ctx;
    int code = 0;
    char detail_msg[256] = "ok";

    return SysAppCmnMakeJsonResInfo(handle, root, s_periodic_setting.id, code, detail_msg);
}
#else
#endif

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonResInfoEndpointSettings(EsfJsonHandle handle, EsfJsonValue root, void *ctx)
{
    (void)ctx;
    int code = 0;
    char detail_msg[256] = "ok";

    GetErrorInfo(&(s_endpoint_settings.update), &code, detail_msg, sizeof(detail_msg));

    return SysAppCmnMakeJsonResInfo(handle, root, s_endpoint_settings.id, code, detail_msg);
}

#if defined(CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING)
/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonResInfoStreamingSettings(EsfJsonHandle handle, EsfJsonValue root, void *ctx)
{
    (void)ctx;
    int code = 0;
    char detail_msg[256] = "ok";

    // Check if there is error information from VSC Manager

    bool vsc_has_error = SysAppVscManagerHasError();

    if (vsc_has_error) {
        int vsc_code = SysAppVscManagerGetErrorResponseCode();
        const char *vsc_error_msg = SysAppVscManagerGetErrorMessage();
        code = vsc_code;
        strncpy(detail_msg, vsc_error_msg, sizeof(detail_msg) - 1);
        detail_msg[sizeof(detail_msg) - 1] = '\0';
        SysAppVscManagerClearError();
    }

    return SysAppCmnMakeJsonResInfo(handle, root, s_streaming_settings.id, code, detail_msg);
}
#endif /* CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING */

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonAiModel(EsfJsonHandle handle, EsfJsonValue root, uint32_t no, void *ctx)
{
    (void)ctx;
    RetCode ret = kRetOk;

    // Set version.

    SysAppCmnSetStringValue(handle, root, "version", s_ai_model[no].version);

    // Set hash.

    SysAppCmnSetStringValue(handle, root, "hash", s_ai_model[no].hash);

    // Set update_date.
    SysAppCmnSetStringValue(handle, root, "update_date", s_ai_model[no].update_date);

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonChips(EsfJsonHandle handle, EsfJsonValue root, uint32_t no, void *ctx)
{
    (void)ctx;
    RetCode ret = kRetOk;

    // Set name.

    SysAppCmnSetStringValue(handle, root, "name", s_chips[no].name);

    // Set id.

    SysAppCmnSetStringValue(handle, root, "id", s_chips[no].id);

    // Set hardware_version.

    SysAppCmnSetStringValue(handle, root, "hardware_version", s_chips[no].hardware_version);

    // Set current_temperature.

    SysAppCmnSetNumberValue(handle, root, "temperature", s_chips[no].current_temperature);

    // Set loader_version.

    SysAppCmnSetStringValue(handle, root, "loader_version", s_chips[no].loader_version);

    // Set loader_hash.

    SysAppCmnSetStringValue(handle, root, "loader_hash", s_chips[no].loader_hash);

    // Set update_date_loader.

    SysAppCmnSetStringValue(handle, root, "update_date_loader", s_chips[no].update_date_loader);

    // Set firmware_version.

    SysAppCmnSetStringValue(handle, root, "firmware_version", s_chips[no].firmware_version);

    // Set firmware_hash.

    SysAppCmnSetStringValue(handle, root, "firmware_hash", s_chips[no].firmware_hash);

    // Set update_date_firmware.

    SysAppCmnSetStringValue(handle, root, "update_date_firmware", s_chips[no].update_date_firmware);

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
    if (no == CHIPS_IDX_SENSOR_CHIP) {
#else  // Use #else for build: CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
    if (no == CHIPS_IDX_COMPANION_CHIP) {
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

        // Set ai_models.

        SysAppCmnSetArrayValue(handle, root, "ai_models", ST_AIMODELS_NUM, MakeJsonAiModel, NULL);
    }
    else {
        // Set ai_models Dummy.

        SysAppCmnSetArrayValue(handle, root, "ai_models", ST_AIMODELS_DUMMY_NUM, MakeJsonAiModel,
                               NULL);
    }
    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonDeviceInfo(EsfJsonHandle handle, EsfJsonValue root)
{
    RetCode ret = kRetOk;

    // Set device_manifest.

    SysAppCmnSetStringValue(handle, root, "device_manifest", s_device_info.device_manifest);

    // Set chips.

    SysAppCmnSetArrayValue(handle, root, "chips", ST_CHIPS_NUM, MakeJsonChips, NULL);

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonDeviceCapabilities(EsfJsonHandle handle, EsfJsonValue root)
{
    RetCode ret = kRetOk;

#ifdef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    // Set is_battery_supported.

    SysAppCmnSetBooleanValue(handle, root, "is_battery_supported",
                             s_device_capabilities.is_battery_supported);

    // Set supported_wireless_mode.

    SysAppCmnSetNumberValue(handle, root, "supported_wireless_mode",
                            s_device_capabilities.supported_wireless_mode);

    // Set is_periodic_supported.

    SysAppCmnSetBooleanValue(handle, root, "is_periodic_supported",
                             s_device_capabilities.is_periodic_supported);

    // Set is_sensor_postprocess_supported.

    SysAppCmnSetBooleanValue(handle, root, "is_sensor_postprocess_supported",
                             s_device_capabilities.is_sensor_postprocess_supported);
#endif // CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonPowerSource(EsfJsonHandle handle, EsfJsonValue root, uint32_t no, void *ctx)
{
    (void)ctx;
    RetCode ret = kRetOk;

    // Set type.

    SysAppCmnSetNumberValue(handle, root, "type", s_power_states.source[no].type);

    // Set level.

    SysAppCmnSetNumberValue(handle, root, "level", s_power_states.source[no].level);
    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonPowerStates(EsfJsonHandle handle, EsfJsonValue root, void *ctx)
{
    (void)ctx;
    RetCode ret = kRetOk;

    SysAppCmnSetArrayValue(handle, root, "source", 1, MakeJsonPowerSource, NULL);

    // Set in_use.

    SysAppCmnSetNumberValue(handle, root, "in_use", s_power_states.in_use);

    // Set is_battery_low.

    SysAppCmnSetBooleanValue(handle, root, "is_battery_low", s_power_states.is_battery_low);

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonDeviceStates(EsfJsonHandle handle, EsfJsonValue root)
{
    RetCode ret = kRetOk;

    // Set power_states.

    SysAppCmnSetObjectValue(handle, root, "power_states", MakeJsonPowerStates, NULL);

    // Set process_state.

    SysAppCmnSetStringValue(handle, root, "process_state", s_device_states.process_state);

    // Set hours_meter.

    SysAppCmnSetNumberValue(handle, root, "hours_meter", s_device_states.hours_meter);

    // Set bootup_reason.

    SysAppCmnSetNumberValue(handle, root, "bootup_reason", s_device_states.bootup_reason);

    // Set last_bootup_time.

    SysAppCmnSetStringValue(handle, root, "last_bootup_time", s_device_states.last_bootup_time);

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonReserved(EsfJsonHandle handle, EsfJsonValue root)
{
    RetCode ret = kRetOk;

    // Set process_state.

    SysAppCmnSetStringValue(handle, root, "schema", CONFIG_EXTERNAL_SYSTEMAPP_SCHEMA);

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonLog(EsfJsonHandle handle, EsfJsonValue root, uint32_t idx, void *ctx)
{
    (void)ctx;
    RetCode ret = kRetOk;

    // Log filter:0 items do not output to State.

    if (idx == 0) {
        return kRetNotFound;
    }

    // Set filter.

    char filter_name[CFGST_LOG_FILTER_LEN + 1] = "";

    SysAppCmnSetStringValue(handle, root, "filter",
                            ConvertFilterValueToString(s_log[idx].filter, filter_name));

    // Set level.

    SysAppCmnSetNumberValue(handle, root, "level", s_log[idx].level);

    // Set destination.

    SysAppCmnSetNumberValue(handle, root, "destination", s_log[idx].destination);

    // Set storage_name.

    SysAppCmnSetStringValue(handle, root, "storage_name", s_log[idx].storage_name);

    // Set path.

    SysAppCmnSetStringValue(handle, root, "path", s_log[idx].path);

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonSystemSettings(EsfJsonHandle handle, EsfJsonValue root)
{
    RetCode ret = kRetOk;

    // Set req_info.

    SysAppCmnSetObjectValue(handle, root, "req_info", MakeJsonReqInfoSystemSettings, NULL);

    // Set led_enabled.

    SysAppCmnSetBooleanValue(handle, root, "led_enabled", s_system_settings.led_enabled);

    // Set temperature_update_interval.

    SysAppCmnSetNumberValue(handle, root, "temperature_update_interval",
                            s_system_settings.temperature_update_interval);

    // Set log_settings.

    SysAppCmnSetArrayValue(handle, root, "log_settings", LogFilterNum, MakeJsonLog, NULL);

    // Set res_info.

    SysAppCmnSetObjectValue(handle, root, "res_info", MakeJsonResInfoSystemSettings, NULL);

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonStaticSettingsIPv6(EsfJsonHandle handle, EsfJsonValue root, void *ctx)
{
    (void)ctx;
    RetCode ret = kRetOk;

    // Set ip_address.

    SysAppCmnSetStringValue(handle, root, "ip_address", s_static_settings_ipv6.ip_address);

    // Set subnet_mask.

    SysAppCmnSetStringValue(handle, root, "subnet_mask", s_static_settings_ipv6.subnet_mask);

    // Set gateway_address.

    SysAppCmnSetStringValue(handle, root, "gateway_address",
                            s_static_settings_ipv6.gateway_address);

    // Set dns_address.

    SysAppCmnSetStringValue(handle, root, "dns_address", s_static_settings_ipv6.dns_address);

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonStaticSettingsIPv4(EsfJsonHandle handle, EsfJsonValue root, void *ctx)
{
    (void)ctx;
    RetCode ret = kRetOk;

    // Set ip_address.

    SysAppCmnSetStringValue(handle, root, "ip_address", s_static_settings_ipv4.ip_address);

    // Set subnet_mask.

    SysAppCmnSetStringValue(handle, root, "subnet_mask", s_static_settings_ipv4.subnet_mask);

    // Set gateway_address.

    SysAppCmnSetStringValue(handle, root, "gateway_address",
                            s_static_settings_ipv4.gateway_address);

    // Set dns_address.

    SysAppCmnSetStringValue(handle, root, "dns_address", s_static_settings_ipv4.dns_address);

    // Set dns2_address.
    // dns2_address is optional. so set only when it is not empty.

    if (s_static_settings_ipv4.dns2_address[0] != '\0') {
        SysAppCmnSetStringValue(handle, root, "dns2_address", s_static_settings_ipv4.dns2_address);
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonProxySettings(EsfJsonHandle handle, EsfJsonValue root, void *ctx)
{
    (void)ctx;
    RetCode ret = kRetOk;

    // Set proxy_url.

    SysAppCmnSetStringValue(handle, root, "proxy_url", s_proxy_settings.proxy_url);

    // Set proxy_port.

    SysAppCmnSetNumberValue(handle, root, "proxy_port", s_proxy_settings.proxy_port);

    // Set proxy_user_name.

    SysAppCmnSetStringValue(handle, root, "proxy_user_name", s_proxy_settings.proxy_user_name);

    // Set proxy_password.

    SysAppCmnSetStringValue(handle, root, "proxy_password", s_proxy_settings.proxy_password);

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonNetworkSettings(EsfJsonHandle handle, EsfJsonValue root)
{
    RetCode ret = kRetOk;

    // Set req_info.

    SysAppCmnSetObjectValue(handle, root, "req_info", MakeJsonReqInfoNetworkSettings, NULL);

    // Set ip_method.

    SysAppCmnSetNumberValue(handle, root, "ip_method", s_network_settings.ip_method);

    // Set ntp_url.

    SysAppCmnSetStringValue(handle, root, "ntp_url", s_network_settings.ntp_url);

    // Set ntp2_url.
    // ntp2_url is optional. so set only when it is not empty.

    if (s_network_settings.ntp2_url[0] != '\0') {
        SysAppCmnSetStringValue(handle, root, "ntp2_url", s_network_settings.ntp2_url);
    }

    // Set static_settings_ipv6.

    SysAppCmnSetObjectValue(handle, root, "static_settings_ipv6", MakeJsonStaticSettingsIPv6, NULL);

    // Set static_settings_ipv4.

    SysAppCmnSetObjectValue(handle, root, "static_settings_ipv4", MakeJsonStaticSettingsIPv4, NULL);

    // Set proxy_settings.

    SysAppCmnSetObjectValue(handle, root, "proxy_settings", MakeJsonProxySettings, NULL);

    // Set res_info.

    SysAppCmnSetObjectValue(handle, root, "res_info", MakeJsonResInfoNetworkSettings, NULL);

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonStaModeSetting(EsfJsonHandle handle, EsfJsonValue root, void *ctx)
{
    (void)ctx;
    RetCode ret = kRetOk;

    // Set ssid.

    SysAppCmnSetStringValue(handle, root, "ssid", s_sta_mode_setting.ssid);

    // Set password.

    SysAppCmnSetStringValue(handle, root, "password", s_sta_mode_setting.password);

    // Set encryption.

    SysAppCmnSetNumberValue(handle, root, "encryption", s_sta_mode_setting.encryption);

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonWirelessSetting(EsfJsonHandle handle, EsfJsonValue root)
{
    RetCode ret = kRetOk;

    // Set req_info.

    SysAppCmnSetObjectValue(handle, root, "req_info", MakeJsonReqInfoWirelessSetting, NULL);

    // Set sta_mode_setting.

    SysAppCmnSetObjectValue(handle, root, "sta_mode_setting", MakeJsonStaModeSetting, NULL);

    // Set res_info.

    SysAppCmnSetObjectValue(handle, root, "res_info", MakeJsonResInfoWirelessSetting, NULL);

    return ret;
}

#if defined(CONFIG_BOARD_WIFI_SMALL_ES) //T3Ws
/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonIntervalSettings(EsfJsonHandle handle, EsfJsonValue root, uint32_t idx,
                                        void *ctx)
{
    (void)idx;
    (void)ctx;
    RetCode ret = kRetOk;

    // Set base_time.

    SysAppCmnSetStringValue(handle, root, "base_time", "00.00");

    // Set capture_interval.

    SysAppCmnSetNumberValue(handle, root, "capture_interval", 120);

    // Set config_interval.

    SysAppCmnSetNumberValue(handle, root, "config_interval", 240);

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonPeriodicSetting(EsfJsonHandle handle, EsfJsonValue root)
{
    RetCode ret = kRetOk;

    // Set req_info.

    SysAppCmnSetObjectValue(handle, root, "req_info", MakeJsonReqInfoPeriodicSetting, NULL);

    // Set operation_mode.

    SysAppCmnSetNumberValue(handle, root, "operation_mode", 0);

    // Set recovery_method.

    SysAppCmnSetNumberValue(handle, root, "recovery_method", 0);

    // Set interval_settings.

    SysAppCmnSetArrayValue(handle, root, "interval_settings", 2, MakeJsonIntervalSettings, NULL);

    // Set ip_addr_setting.

    SysAppCmnSetStringValue(handle, root, "ip_addr_setting", "dhcp");

    // Set res_info.

    SysAppCmnSetObjectValue(handle, root, "res_info", MakeJsonResInfoPeriodicSetting, NULL);

    return ret;
}
#else
#endif

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonEndpointSettings(EsfJsonHandle handle, EsfJsonValue root)
{
    RetCode ret = kRetOk;

    // Set req_info.

    SysAppCmnSetObjectValue(handle, root, "req_info", MakeJsonReqInfoEndpointSettings, NULL);

    // Set endpoint_url.

    SysAppCmnSetStringValue(handle, root, "endpoint_url", s_endpoint_settings.endpoint_url);

    // Set endpoint_port.

    SysAppCmnSetNumberValue(handle, root, "endpoint_port", s_endpoint_settings.endpoint_port);

    // Set protocol_version.

    SysAppCmnSetStringValue(handle, root, "protocol_version", s_endpoint_settings.protocol_version);

    // Set res_info.

    SysAppCmnSetObjectValue(handle, root, "res_info", MakeJsonResInfoEndpointSettings, NULL);

    return ret;
}

#if defined(CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING)
/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonRtspConfig(EsfJsonHandle handle, EsfJsonValue root)
{
    RetCode ret = kRetOk;

    // Set server_ip.

    SysAppCmnSetStringValue(handle, root, "server_ip", s_streaming_settings.rtsp_config.server_ip);

    // Set stream_name.

    SysAppCmnSetStringValue(handle, root, "stream_name",
                            s_streaming_settings.rtsp_config.stream_name);

    // Set user_name.

    SysAppCmnSetStringValue(handle, root, "user_name", s_streaming_settings.rtsp_config.user_name);

    // Set password.

    SysAppCmnSetStringValue(handle, root, "password", s_streaming_settings.rtsp_config.password);

    // Set is_rtsp_server_running.

    SysAppCmnSetBooleanValue(handle, root, "is_rtsp_server_running",
                             s_streaming_settings.rtsp_config.is_rtsp_server_running);

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonNfsConfig(EsfJsonHandle handle, EsfJsonValue root)
{
    RetCode ret = kRetOk;

    // Set server_ip.

    SysAppCmnSetStringValue(handle, root, "server_ip", s_streaming_settings.nfs_config.server_ip);

    // Set mount_path.

    SysAppCmnSetStringValue(handle, root, "mount_path", s_streaming_settings.nfs_config.mount_path);

    // Set nfs_version.

    SysAppCmnSetNumberValue(handle, root, "nfs_version",
                            s_streaming_settings.nfs_config.nfs_version);

    // Set use_tcp.

    SysAppCmnSetBooleanValue(handle, root, "use_tcp", s_streaming_settings.nfs_config.use_tcp);

    // Set max_record_time.

    SysAppCmnSetNumberValue(handle, root, "max_record_time",
                            s_streaming_settings.nfs_config.max_record_time);

    // Set record_filename.

    SysAppCmnSetStringValue(handle, root, "record_filename",
                            s_streaming_settings.nfs_config.record_filename);

    // Set file_recording_time.

    SysAppCmnSetStringValue(handle, root, "file_recording_time",
                            s_streaming_settings.nfs_config.file_recording_time);

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonStreamingSettings(EsfJsonHandle handle, EsfJsonValue root)
{
    RetCode ret = kRetOk;

    // Set req_info.

    SysAppCmnSetObjectValue(handle, root, "req_info", MakeJsonReqInfoStreamingSettings, NULL);

    // Set process_state.

    SysAppCmnSetNumberValue(handle, root, "process_state", s_streaming_settings.process_state);

    // Set operating_mode.

    SysAppCmnSetNumberValue(handle, root, "operating_mode", s_streaming_settings.operating_mode);

    // Set rtsp_config.

    SysAppCmnSetObjectValue(handle, root, "rtsp_config", MakeJsonRtspConfig, NULL);

    // Set nfs_config.

    SysAppCmnSetObjectValue(handle, root, "nfs_config", MakeJsonNfsConfig, NULL);

    // Set res_info.

    SysAppCmnSetObjectValue(handle, root, "res_info", MakeJsonResInfoStreamingSettings, NULL);

    return ret;
}
#endif /* CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING */

/*----------------------------------------------------------------------------*/
STATIC RetCode SendStateCore(const char *topic, const char *state_org, uint32_t state_len)
{
    (void)state_len;
    RetCode ret = kRetOk;
    enum SYS_result sys_ret;

    SYSAPP_INFO("Send %s", topic);

    for (size_t i = 0; i < state_len; i += 78) {
        SYSAPP_INFO("%.78s", state_org + i);
    }

    // Send state.

    sys_ret = SYS_set_state(s_sys_client, topic, state_org);

    if (sys_ret != SYS_RESULT_OK) {
        SYSAPP_ERR("SYS_set_state() ret %d", sys_ret);
        ret = kRetFailed;
    }

    return ret;
}

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonReqInfoUnimplemented(EsfJsonHandle handle, EsfJsonValue root, void *ctx)
{
    const char *req_id = (const char *)ctx;
    return MakeJsonReqInfoCore(handle, root, req_id);
}

/*----------------------------------------------------------------------------*/
STATIC RetCode MakeJsonResInfoUnimplemented(EsfJsonHandle handle, EsfJsonValue root, void *ctx)
{
    const char *res_id = (const char *)ctx;
    return SysAppCmnMakeJsonResInfo(handle, root, res_id, 12, "unimplemented");
}

/*----------------------------------------------------------------------------*/
STATIC void MakeJsonUnimplemented(EsfJsonHandle handle, EsfJsonValue root, char *id)
{
    // Set req_info.

    SysAppCmnSetObjectValue(handle, root, "req_info", MakeJsonReqInfoUnimplemented, id);

    // Set res_info.

    SysAppCmnSetObjectValue(handle, root, "res_info", MakeJsonResInfoUnimplemented, id);
}

/*----------------------------------------------------------------------------*/
STATIC RetCode SendUnimplementedState(const char *topic, char *id)
{
    RetCode ret = kRetOk;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    EsfJsonErrorCode esfj_ret = kEsfJsonSuccess;

    // Make json string.

    esfj_ret = EsfJsonOpen(&esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonOpen() failed %d", esfj_ret);
        return kRetFailed;
    }

    esfj_ret = EsfJsonObjectInit(esfj_handle, &val);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectInit() failed %d", esfj_ret);
        ret = kRetFailed;
        goto close_json_handle;
    }

    MakeJsonUnimplemented(esfj_handle, val, id);

    // Send state.

    const char *state_org = NULL;
    esfj_ret = EsfJsonSerialize(esfj_handle, val, &state_org);

    if ((state_org != NULL) && (esfj_ret == kEsfJsonSuccess)) {
        ret = SendStateCore(topic, state_org, strlen(state_org));
    }

close_json_handle:

    // Close handle.

    esfj_ret = EsfJsonClose(esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_WARN("EsfJsonClose() failed %d", esfj_ret);
    }

    return ret;
}
#endif // !CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION

/*----------------------------------------------------------------------------*/
STATIC RetCode SendState(uint32_t next_req)
{
    RetCode ret = kRetOk;

    // Send state.

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    for (size_t i = 0; i < ARRAY_SIZE(s_unimplemented_list); i++) {
        if (next_req & s_unimplemented_list[i].topic) {
            return SendUnimplementedState(s_unimplemented_list[i].topic_str,
                                          s_unimplemented_list[i].id);
        }
    }
#endif // !CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION

    if (next_req & ST_TOPIC_DEVICE_INFO) {
        ret = SendDeviceInfo();
    }
    else if (next_req & ST_TOPIC_DEVICE_CAPABILITIES) {
        ret = SendDeviceCapabilities();
    }
    else if (next_req & ST_TOPIC_DEVICE_STATES) {
        ret = SendDeviceStates();
    }
    else if (next_req & ST_TOPIC_RESERVED) {
        ret = SendReserved();
    }
    else if (next_req & ST_TOPIC_SYSTEM_SETTINGS) {
        ret = SendSystemSettings();
    }
    else if (next_req & ST_TOPIC_NETWORK_SETTINGS) {
        ret = SendNetworkSettings();
    }
    else if (next_req & ST_TOPIC_WIRELESS_SETTING) {
        ret = SendWirelessSetting();
    }
    else if (next_req & ST_TOPIC_PERIODIC_SETTING) {
#if defined(CONFIG_BOARD_WIFI_SMALL_ES) //T3Ws
        ret = SendPeriodicSetting();
#else
#endif
    }
    else if (next_req & ST_TOPIC_ENDPOINT_SETTINGS) {
        ret = SendEndpointSettings();
    }
#if defined(CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING)
    else if (next_req & ST_TOPIC_STREAMING_SETTINGS) {
        ret = SendStreamingSettings();
    }
#endif /* CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING */
    else if (next_req & ST_TOPIC_DEPLOY_FIRMWARE) {
        ret = SendDeploy(ST_TOPIC_DEPLOY_FIRMWARE);
    }
    else if (next_req & ST_TOPIC_DEPLOY_AI_MODEL) {
        ret = SendDeploy(ST_TOPIC_DEPLOY_AI_MODEL);
    }
    else if (next_req & ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM) {
        ret = SendDeploy(ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM);
    }
    else if (next_req & ST_TOPIC_UPDATE_DEVICE_INFO) {
        SysAppStateReadoutDeviceInfo();
        ret = SendDeviceInfo();
    }
    else {
        SYSAPP_ERR("Unknown request %x.", next_req);
        ret = kRetFailed;
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode SendDeviceInfo(void)
{
    RetCode ret = kRetOk;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    EsfJsonErrorCode esfj_ret = kEsfJsonSuccess;

    // Make json string for state::device_info.

    esfj_ret = EsfJsonOpen(&esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonOpen(%p) ret %d", &esfj_handle, esfj_ret);
    }

    esfj_ret = EsfJsonObjectInit(esfj_handle, &val);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectInit(%p) ret %d", esfj_handle, esfj_ret);
    }

    MakeJsonDeviceInfo(esfj_handle, val);

    // Send state.

    const char *state_org = NULL;
    esfj_ret = EsfJsonSerialize(esfj_handle, val, &state_org);

    if ((state_org != NULL) && (esfj_ret == kEsfJsonSuccess)) {
        uint32_t state_len = strlen(state_org);

        ret = SendStateCore("device_info", state_org, state_len);
    }

    // Clean up.

    esfj_ret = EsfJsonClose(esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_WARN("EsfJsonClose(%p) ret %d", esfj_handle, esfj_ret);
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode SendDeviceCapabilities(void)
{
    RetCode ret = kRetOk;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    EsfJsonErrorCode esfj_ret = kEsfJsonSuccess;

    // Make json string for state::device_capabilities.

    esfj_ret = EsfJsonOpen(&esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonOpen(%p) ret %d", &esfj_handle, esfj_ret);
    }

    esfj_ret = EsfJsonObjectInit(esfj_handle, &val);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectInit(%p) ret %d", esfj_handle, esfj_ret);
    }

    MakeJsonDeviceCapabilities(esfj_handle, val);

    // Send state.

    const char *state_org = NULL;
    esfj_ret = EsfJsonSerialize(esfj_handle, val, &state_org);

    if ((state_org != NULL) && (esfj_ret == kEsfJsonSuccess)) {
        uint32_t state_len = strlen(state_org);

        ret = SendStateCore("device_capabilities", state_org, state_len);
    }

    // Clean up.

    esfj_ret = EsfJsonClose(esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_WARN("EsfJsonClose(%p) ret %d", esfj_handle, esfj_ret);
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode SendDeviceStates(void)
{
    RetCode ret = kRetOk;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    EsfJsonErrorCode esfj_ret = kEsfJsonSuccess;

    // Make json string for state::device_states.

    esfj_ret = EsfJsonOpen(&esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonOpen(%p) ret %d", &esfj_handle, esfj_ret);
    }

    esfj_ret = EsfJsonObjectInit(esfj_handle, &val);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectInit(%p) ret %d", esfj_handle, esfj_ret);
    }

    MakeJsonDeviceStates(esfj_handle, val);

    // Send state.

    const char *state_org = NULL;
    esfj_ret = EsfJsonSerialize(esfj_handle, val, &state_org);

    if ((state_org != NULL) && (esfj_ret == kEsfJsonSuccess)) {
        uint32_t state_len = strlen(state_org);

        ret = SendStateCore("device_states", state_org, state_len);
    }

    // Clean up.

    esfj_ret = EsfJsonClose(esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_WARN("EsfJsonClose(%p) ret %d", esfj_handle, esfj_ret);
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode SendReserved(void)
{
    RetCode ret = kRetOk;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    EsfJsonErrorCode esfj_ret = kEsfJsonSuccess;

    // Make json string for state::device_states.

    esfj_ret = EsfJsonOpen(&esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonOpen(%p) ret %d", &esfj_handle, esfj_ret);
    }

    esfj_ret = EsfJsonObjectInit(esfj_handle, &val);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectInit(%p) ret %d", esfj_handle, esfj_ret);
    }

    MakeJsonReserved(esfj_handle, val);

    // Send state.

    const char *state_org = NULL;
    esfj_ret = EsfJsonSerialize(esfj_handle, val, &state_org);

    if ((state_org != NULL) && (esfj_ret == kEsfJsonSuccess)) {
        uint32_t state_len = strlen(state_org);

        ret = SendStateCore("PRIVATE_reserved", state_org, state_len);
    }

    // Clean up.

    esfj_ret = EsfJsonClose(esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_WARN("EsfJsonClose(%p) ret %d", esfj_handle, esfj_ret);
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode SendSystemSettings(void)
{
    RetCode ret = kRetOk;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    EsfJsonErrorCode esfj_ret = kEsfJsonSuccess;

    // Make json string for state::system_settings.

    esfj_ret = EsfJsonOpen(&esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonOpen(%p) ret %d", esfj_handle, esfj_ret);
    }

    esfj_ret = EsfJsonObjectInit(esfj_handle, &val);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectInit(%p) ret %d", esfj_handle, esfj_ret);
    }

    MakeJsonSystemSettings(esfj_handle, val);

    // Send state.

    const char *state_org = NULL;
    esfj_ret = EsfJsonSerialize(esfj_handle, val, &state_org);

    if ((state_org != NULL) && (esfj_ret == kEsfJsonSuccess)) {
        uint32_t state_len = strlen(state_org);

        ret = SendStateCore("system_settings", state_org, state_len);
    }

    // Clean up.

    esfj_ret = EsfJsonClose(esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_WARN("EsfJsonClose(%p) ret %d", esfj_handle, esfj_ret);
    }

    // Clear error info.

    s_system_settings.update.invalid_arg_flag = 0;
    s_system_settings.update.internal_error_flag = 0;
    s_system_settings.invalid_led_enabled_flag = 0;
    s_system_settings.invalid_temperature_update_interval_flag = 0;

    for (int idx = 0; idx < LogFilterNum; idx++) {
        s_log[idx].update.invalid_arg_flag = 0;
        s_log[idx].update.internal_error_flag = 0;
        s_log[idx].invalid_filter_flag = 0;
        s_log[idx].invalid_level_flag = 0;
        s_log[idx].invalid_destination_flag = 0;
        s_log[idx].invalid_storage_name_flag = 0;
        s_log[idx].invalid_path_flag = 0;
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode SendNetworkSettings(void)
{
    RetCode ret = kRetOk;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    EsfJsonErrorCode esfj_ret = kEsfJsonSuccess;

    // Make json string for state::system_settings.

    esfj_ret = EsfJsonOpen(&esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonOpen(%p) ret %d", &esfj_handle, esfj_ret);
    }

    esfj_ret = EsfJsonObjectInit(esfj_handle, &val);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectInit(%p) ret %d", esfj_handle, esfj_ret);
    }

    MakeJsonNetworkSettings(esfj_handle, val);

    // Send state.

    const char *state_org = NULL;
    esfj_ret = EsfJsonSerialize(esfj_handle, val, &state_org);

    if ((state_org != NULL) && (esfj_ret == kEsfJsonSuccess)) {
        uint32_t state_len = strlen(state_org);

        ret = SendStateCore("network_settings", state_org, state_len);
    }

    // Clean up.

    esfj_ret = EsfJsonClose(esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_WARN("EsfJsonClose(%p) ret %d", esfj_handle, esfj_ret);
    }

    // Clear error info.

    s_network_settings.update.invalid_arg_flag = 0;
    s_network_settings.update.internal_error_flag = 0;
    s_network_settings.invalid_ip_method_flag = 0;
    s_network_settings.invalid_ntp_url_flag = 0;
    s_network_settings.invalid_ntp2_url_flag = 0;
    s_static_settings_ipv4.update.invalid_arg_flag = 0;
    s_static_settings_ipv4.update.internal_error_flag = 0;
    s_static_settings_ipv6.update.invalid_arg_flag = 0;
    s_static_settings_ipv6.update.internal_error_flag = 0;
    s_static_settings_ipv4.invalid_ip_address_flag = 0;
    s_static_settings_ipv4.invalid_subnet_mask_flag = 0;
    s_static_settings_ipv4.invalid_gateway_address_flag = 0;
    s_static_settings_ipv4.invalid_dns_address_flag = 0;
    s_static_settings_ipv4.invalid_dns2_address_flag = 0;
    s_static_settings_ipv6.invalid_ip_address_flag = 0;
    s_static_settings_ipv6.invalid_subnet_mask_flag = 0;
    s_static_settings_ipv6.invalid_gateway_address_flag = 0;
    s_static_settings_ipv6.invalid_dns_address_flag = 0;
    s_proxy_settings.update.invalid_arg_flag = 0;
    s_proxy_settings.update.internal_error_flag = 0;
    s_proxy_settings.invalid_proxy_url_flag = 0;
    s_proxy_settings.invalid_proxy_port_flag = 0;
    s_proxy_settings.invalid_proxy_user_name_flag = 0;
    s_proxy_settings.invalid_proxy_password_flag = 0;

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode SendWirelessSetting(void)
{
    RetCode ret = kRetOk;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    EsfJsonErrorCode esfj_ret = kEsfJsonSuccess;

    // Make json string for state::system_settings.

    esfj_ret = EsfJsonOpen(&esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonOpen(%p) ret %d", &esfj_handle, esfj_ret);
    }

    esfj_ret = EsfJsonObjectInit(esfj_handle, &val);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectInit(%p) ret %d", esfj_handle, esfj_ret);
    }

    MakeJsonWirelessSetting(esfj_handle, val);

    // Send state.

    const char *state_org = NULL;
    esfj_ret = EsfJsonSerialize(esfj_handle, val, &state_org);

    if ((state_org != NULL) && (esfj_ret == kEsfJsonSuccess)) {
        uint32_t state_len = strlen(state_org);

        ret = SendStateCore("wireless_setting", state_org, state_len);
    }

    // Clean up.

    esfj_ret = EsfJsonClose(esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_WARN("EsfJsonClose(%p) ret %d", esfj_handle, esfj_ret);
    }

    // Clear error info.

    s_wireless_setting.update.invalid_arg_flag = 0;
    s_wireless_setting.update.internal_error_flag = 0;
    s_sta_mode_setting.update.invalid_arg_flag = 0;
    s_sta_mode_setting.update.internal_error_flag = 0;
    s_sta_mode_setting.invalid_ssid_flag = 0;
    s_sta_mode_setting.invalid_password_flag = 0;
    s_sta_mode_setting.invalid_encryption_flag = 0;

    return ret;
}

/*----------------------------------------------------------------------------*/
#if defined(CONFIG_BOARD_WIFI_SMALL_ES) //T3Ws
STATIC RetCode SendPeriodicSetting(void)
{
    RetCode ret = kRetOk;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    EsfJsonErrorCode esfj_ret = kEsfJsonSuccess;

    // Make json string for state::system_settings.

    esfj_ret = EsfJsonOpen(&esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonOpen(%p) ret %d", &esfj_handle, esfj_ret);
    }

    esfj_ret = EsfJsonObjectInit(esfj_handle, &val);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectInit(%p) ret %d", esfj_handle, esfj_ret);
    }

    MakeJsonPeriodicSetting(esfj_handle, val);

    // Send state.

    const char *state_org = NULL;
    esfj_ret = EsfJsonSerialize(esfj_handle, val, &state_org);

    if ((state_org != NULL) && (esfj_ret == kEsfJsonSuccess)) {
        uint32_t state_len = strlen(state_org);

        ret = SendStateCore("periodic_setting", state_org, state_len);
    }

    // Clean up.

    esfj_ret = EsfJsonClose(esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_WARN("EsfJsonClose(%p) ret %d", esfj_handle, esfj_ret);
    }

    // Clear error info.

    s_periodic_setting.update.invalid_arg_flag = 0;
    s_periodic_setting.update.internal_error_flag = 0;

    for (int idx = 0; idx < 2; idx++) {
        s_interval_setting[idx].update.invalid_arg_flag = 0;
        s_interval_setting[idx].update.internal_error_flag = 0;
    }

    return ret;
}
#else
#endif

/*----------------------------------------------------------------------------*/
STATIC RetCode SendEndpointSettings(void)
{
    RetCode ret = kRetOk;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    EsfJsonErrorCode esfj_ret = kEsfJsonSuccess;

    // Make json string for state::system_settings.

    esfj_ret = EsfJsonOpen(&esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonOpen(%p) ret %d", &esfj_handle, esfj_ret);
    }

    esfj_ret = EsfJsonObjectInit(esfj_handle, &val);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectInit(%p) ret %d", esfj_handle, esfj_ret);
    }

    MakeJsonEndpointSettings(esfj_handle, val);

    // Send state.

    const char *state_org = NULL;
    esfj_ret = EsfJsonSerialize(esfj_handle, val, &state_org);

    if ((state_org != NULL) && (esfj_ret == kEsfJsonSuccess)) {
        uint32_t state_len = strlen(state_org);

        ret = SendStateCore("PRIVATE_endpoint_settings", state_org, state_len);
    }

    // Clean up.

    esfj_ret = EsfJsonClose(esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_WARN("EsfJsonClose(%p) ret %d", esfj_handle, esfj_ret);
    }

    // Clear error info.

    s_endpoint_settings.update.invalid_arg_flag = 0;
    s_endpoint_settings.update.internal_error_flag = 0;

    return ret;
}

#if defined(CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING)
/*----------------------------------------------------------------------------*/
STATIC RetCode SendStreamingSettings(void)
{
    RetCode ret = kRetOk;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;
    EsfJsonErrorCode esfj_ret = kEsfJsonSuccess;

    // Update streaming status before sending state

    UpdateStreamingStatusFromVsc();

    // Make json string for state::streaming_settings.

    esfj_ret = EsfJsonOpen(&esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonOpen(%p) ret %d", &esfj_handle, esfj_ret);
    }

    esfj_ret = EsfJsonObjectInit(esfj_handle, &val);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectInit(%p) ret %d", esfj_handle, esfj_ret);
    }

    MakeJsonStreamingSettings(esfj_handle, val);

    // Send state.

    const char *state_org = NULL;
    esfj_ret = EsfJsonSerialize(esfj_handle, val, &state_org);

    if ((state_org != NULL) && (esfj_ret == kEsfJsonSuccess)) {
        uint32_t state_len = strlen(state_org);
        ret = SendStateCore("streaming_settings", state_org, state_len);
    }

    // Clean up.

    esfj_ret = EsfJsonClose(esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_WARN("EsfJsonClose(%p) ret %d", esfj_handle, esfj_ret);
    }

    // Clear streaming settings error flags.

    s_streaming_settings.update.invalid_arg_flag = 0;
    s_streaming_settings.update.internal_error_flag = 0;

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC void UpdateRtspConfigFromVsc(const vsclient_server_status_t *vsc_status)
{
    // RTSP configuration update

    if (strlen(vsc_status->rtsp_config.server_ip) > 0) {
        strncpy(s_streaming_settings.rtsp_config.server_ip, vsc_status->rtsp_config.server_ip,
                sizeof(s_streaming_settings.rtsp_config.server_ip) - 1);
        s_streaming_settings.rtsp_config
            .server_ip[sizeof(s_streaming_settings.rtsp_config.server_ip) - 1] = '\0';
    }
    if (strlen(vsc_status->rtsp_config.stream_name) > 0) {
        strncpy(s_streaming_settings.rtsp_config.stream_name, vsc_status->rtsp_config.stream_name,
                sizeof(s_streaming_settings.rtsp_config.stream_name) - 1);
        s_streaming_settings.rtsp_config
            .stream_name[sizeof(s_streaming_settings.rtsp_config.stream_name) - 1] = '\0';
    }
    if (strlen(vsc_status->rtsp_config.username) > 0) {
        strncpy(s_streaming_settings.rtsp_config.user_name, vsc_status->rtsp_config.username,
                sizeof(s_streaming_settings.rtsp_config.user_name) - 1);
        s_streaming_settings.rtsp_config
            .user_name[sizeof(s_streaming_settings.rtsp_config.user_name) - 1] = '\0';
    }
    s_streaming_settings.rtsp_config.is_rtsp_server_running =
        (vsc_status->rtsp_config.server_running == 1);
}

/*----------------------------------------------------------------------------*/
STATIC void UpdateNfsConfigFromVsc(const vsclient_server_status_t *vsc_status)
{
    // NFS configuration update

    if (strlen(vsc_status->nfs_config.server_ip) > 0) {
        strncpy(s_streaming_settings.nfs_config.server_ip, vsc_status->nfs_config.server_ip,
                sizeof(s_streaming_settings.nfs_config.server_ip) - 1);
        s_streaming_settings.nfs_config
            .server_ip[sizeof(s_streaming_settings.nfs_config.server_ip) - 1] = '\0';
    }
    if (strlen(vsc_status->nfs_config.mount_point) > 0) {
        strncpy(s_streaming_settings.nfs_config.mount_path, vsc_status->nfs_config.mount_point,
                sizeof(s_streaming_settings.nfs_config.mount_path) - 1);
        s_streaming_settings.nfs_config
            .mount_path[sizeof(s_streaming_settings.nfs_config.mount_path) - 1] = '\0';
    }
    s_streaming_settings.nfs_config.nfs_version = vsc_status->nfs_config.nfs_version;
    s_streaming_settings.nfs_config.use_tcp = vsc_status->nfs_config.use_tcp;
    s_streaming_settings.nfs_config.max_record_time = vsc_status->nfs_config.file_duration_minutes;
    if (strlen(vsc_status->nfs_config.record_filename) > 0) {
        strncpy(s_streaming_settings.nfs_config.record_filename,
                vsc_status->nfs_config.record_filename,
                sizeof(s_streaming_settings.nfs_config.record_filename) - 1);
        s_streaming_settings.nfs_config
            .record_filename[sizeof(s_streaming_settings.nfs_config.record_filename) - 1] = '\0';
    }
    uint32_t total_seconds = vsc_status->nfs_config.record_time;
    uint32_t hours = total_seconds / 3600;
    uint32_t minutes = (total_seconds % 3600) / 60;
    uint32_t seconds = total_seconds % 60;
    snprintf(s_streaming_settings.nfs_config.file_recording_time,
             sizeof(s_streaming_settings.nfs_config.file_recording_time), "%02u:%02u:%02u", hours,
             minutes, seconds);
}

/*----------------------------------------------------------------------------*/
STATIC void UpdateStreamingStatusFromVsc(void)
{
    // Skip VSC status update if VSC errors already exist

    if (SysAppVscManagerHasError()) {
        SYSAPP_INFO(
            "VSC error detected - skipping status update to avoid additional VSC operations");
        return;
    }

    // Get status from VSC using VSC Manager

    vsclient_result_t vsc_ret;
    vsclient_server_status_t vsc_status = {0};

    // Get status

    vsc_ret = SysAppVscGetServerStatus(&vsc_status);

    if (vsc_ret == VSCLIENT_SUCCESS) {
        // reflect status information to internal state

        UpdateInternalStateFromVscStatus(&vsc_status);
        SYSAPP_INFO("VSC status updated successfully");
    }
    else {
        // log error information only

        SYSAPP_WARN("VSC get_status failed: %s", SysAppVscGetErrorString(vsc_ret));
        SysAppVscHandleCreateError(vsc_ret, "VSC status update", ST_TOPIC_STREAMING_SETTINGS);
    }
}

/*----------------------------------------------------------------------------*/
STATIC void UpdateInternalStateFromVscStatus(const vsclient_server_status_t *vsc_status)
{
    // Process state mapping

    switch (vsc_status->stream_status) {
        case 0: // VSC stopped
            s_streaming_settings.process_state = StreamOff;
            break;
        case 1: // VSC streaming
            s_streaming_settings.process_state = StreamOn;
            break;
        default:
            SYSAPP_WARN("Unknown VSC stream_status: %d", vsc_status->stream_status);
            break;
    }

    // Operating mode update

    s_streaming_settings.operating_mode = (CfgStStreamOperatingMode)vsc_status->operating_mode;

    // Update RTSP configuration

    UpdateRtspConfigFromVsc(vsc_status);

    // Update NFS configuration

    UpdateNfsConfigFromVsc(vsc_status);
}
#endif /* CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING */

/*----------------------------------------------------------------------------*/
STATIC RetCode SendDeploy(uint32_t topic_bits)
{
    // Send deploy state.

    RetCode ret = kRetOk;
    char *state = NULL;
    const char *topic;
    uint32_t state_len;

    /* Get state json string by topic */

    if (topic_bits == ST_TOPIC_DEPLOY_FIRMWARE) {
        ret = SysAppDeployGetFirmwareState(&state, &state_len);
        topic = "PRIVATE_deploy_firmware";
    }
    else if (topic_bits == ST_TOPIC_DEPLOY_AI_MODEL) {
        ret = SysAppDeployGetAiModelState(&state, &state_len);
        topic = "PRIVATE_deploy_ai_model";
    }
    else if (topic_bits == ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM) {
        ret = SysAppDeployGetSensorCalibrationParamState(&state, &state_len);
        topic = "PRIVATE_deploy_sensor_calibration_param";
    }
    else {
        SYSAPP_ERR("Invalid topic");
        return kRetFailed;
    }

    if (ret != kRetOk) {
        return ret;
    }

    ret = SendStateCore(topic, state, state_len);

    /* SysAppDeployGet* allocate memory internally for string,
   * so must free after use */

    SysAppDeployFreeState(state);

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode GetSensorInfo(SensorInfoCategory target, char *buf, int bufsize)
{
    RetCode ret = kRetOk;
    const uint32_t category_table[SensorInfoCategoryNum] = {
        SENSCORD_INFO_STRING_SENSOR_NAME, SENSCORD_INFO_STRING_SENSOR_ID,
        SENSCORD_INFO_STRING_KEY_GENERATION, SENSCORD_INFO_STRING_AIISP_DEVICE_ID};

    if (s_scstream == 0) {
        SYSAPP_ERR("GetSensorInfo(%d)", target);
        ret = kRetFailed;
        goto senscord_start_stream_failed;
    }

    // Get sensor string info.

    struct senscord_info_string_property_t strinfo = {0};
    strinfo.category = category_table[target];

    int sc_ret = senscord_stream_get_property(s_scstream, SENSCORD_INFO_STRING_PROPERTY_KEY,
                                              (void *)&strinfo, sizeof(strinfo));

    if (sc_ret < 0) {
        SYSAPP_ERR("senscord_stream_get_property(INFO_STRING=%d) ret %d", category_table[target],
                   sc_ret);
        ret = kRetFailed;
        goto senscord_stream_get_property_failed;
    }

    int len = snprintf(buf, bufsize, "%.32s", strinfo.info);

    if ((len < 0) || (len > bufsize)) {
        SYSAPP_ERR("Too short buf. %d", len);
        ret = kRetFailed;
    }

senscord_stream_get_property_failed:
senscord_start_stream_failed:

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC bool GetSensorPostProcessSupported(void)
{
    bool ret = false;

    if (s_scstream == 0) {
        SYSAPP_ERR("GetSensorPostProcessSupported");
        ret = kRetFailed;
        goto senscord_start_stream_failed;
    }

    // Get sensor post process availability.

    struct senscord_post_process_available_property_t postproc = {0};

    int sc_ret = senscord_stream_get_property(s_scstream,
                                              SENSCORD_POST_PROCESS_AVAILABLE_PROPERTY_KEY,
                                              (void *)&postproc, sizeof(postproc));

    if (sc_ret < 0) {
        SYSAPP_ERR("senscord_stream_get_property(POST_PROCESS_AVAILABLE) ret %d", sc_ret);
        goto senscord_stream_get_property_failed;
    }

    ret = postproc.is_aveilable;

senscord_stream_get_property_failed:
senscord_start_stream_failed:

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC int GetSensorTemperature(int prev_temperature)
{
    int current_temperature = TEMPERATURE_INVALID_VAL;

    // Lock.

    int lock_ret = pthread_mutex_lock(&s_senscord_access_mutex);

    if (lock_ret != 0) {
        SYSAPP_ERR("pthread_mutex_lock");
        return prev_temperature;
    }

    // Get sensor temperature.

    if (s_scstream == 0) {
        SYSAPP_WARN("GetSensorTemperature");
        current_temperature = prev_temperature;
        goto senscord_start_stream_failed;
    }

    struct senscord_temperature_property_t temperature_prop = {0};

    int sc_ret = senscord_stream_get_property(s_scstream, SENSCORD_TEMPERATURE_PROPERTY_KEY,
                                              (void *)&temperature_prop, sizeof(temperature_prop));

    if (sc_ret < 0) {
        SYSAPP_ELOG_ERR(SYSAPP_EVT_FAILED_TO_RETRIEVE_TEMP);
        SYSAPP_ERR("senscord_core_get_property(TEMPERATURE_PROPERTY) ret %d", sc_ret);
        goto senscord_stream_get_property_failed;
    }
    else {
        // Use temperatures[0] as the current temperature temporally
        current_temperature = (int)temperature_prop.temperatures[0].temperature;

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
        if (current_temperature > TEMPERATURE_UPPER_THRESHOLD) {
            SYSAPP_ELOG_ERR(SYSAPP_EVT_SENSOR_EXCEEDED_HIGH_TEMP);
        }
        else if (current_temperature > TEMPERATURE_UPPER_APPROACHING_THRESHOLD) {
            SYSAPP_ELOG_WARN(SYSAPP_EVT_SENSOR_APPROACHING_HIGH_TEMP);
        }
        else {
            if (current_temperature < TEMPERATURE_LOWER_THRESHOLD) {
                SYSAPP_ELOG_ERR(SYSAPP_EVT_SENSOR_EXCEEDED_LOW_TEMP);
            }
            else if (current_temperature < TEMPERATURE_LOWER_APPROACHING_THRESHOLD) {
                SYSAPP_ELOG_WARN(SYSAPP_EVT_SENSOR_APPROACHING_LOW_TEMP);
            }
            else {
                // Nop.
            }
        }
#endif
    }

senscord_stream_get_property_failed:
senscord_start_stream_failed:

    // Unlock.

    pthread_mutex_unlock(&s_senscord_access_mutex);

    return current_temperature;
}

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
/*----------------------------------------------------------------------------*/
STATIC int GetAiIspTemperature(int prev_temperature)
{
    int maximum_temperature = TEMPERATURE_INVALID_VAL;

    // Lock.

    int lock_ret = pthread_mutex_lock(&s_senscord_access_mutex);

    if (lock_ret != 0) {
        SYSAPP_ERR("pthread_mutex_lock");
        return prev_temperature;
    }

    // Get AI-ISP temperature.

    if (s_scstream == 0) {
        SYSAPP_WARN("GetAiIspTemperature");
        maximum_temperature = prev_temperature;
        goto senscord_start_stream_failed;
    }

    struct senscord_temperature_property_t temperature_prop = {0};

    int sc_ret = senscord_stream_get_property(s_scstream, SENSCORD_TEMPERATURE_PROPERTY_KEY,
                                              (void *)&temperature_prop, sizeof(temperature_prop));

    if (sc_ret < 0) {
        SYSAPP_ELOG_ERR(SYSAPP_EVT_FAILED_TO_RETRIEVE_TEMP);
        SYSAPP_ERR("senscord_core_get_property(TEMPERATURE_PROPERTY) ret %d", sc_ret);
        goto senscord_stream_get_property_failed;
    }
    else {
        // We can get temperature of AI-ISP internal 5 modules, and we use highest one.
        for (int i = 1; i <= 5; i++) {
            if (maximum_temperature <= (int)temperature_prop.temperatures[i].temperature) {
                maximum_temperature = (int)temperature_prop.temperatures[i].temperature;
            }
        }

        if (maximum_temperature > TEMPERATURE_UPPER_THRESHOLD) {
            SYSAPP_ELOG_ERR(SYSAPP_EVT_SENSOR_EXCEEDED_HIGH_TEMP);
            SsfSensorPowerOFF();
            SysAppStateUpdateString(ST_TOPIC_DEVICE_STATES, ProcessState, "EmergencyStop");
            SysAppStateSendState(ST_TOPIC_DEVICE_STATES);
        }
        else if (maximum_temperature > TEMPERATURE_UPPER_APPROACHING_THRESHOLD) {
            SYSAPP_ELOG_WARN(SYSAPP_EVT_SENSOR_APPROACHING_HIGH_TEMP);
        }
        else {
            // Nop.
        }
    }

senscord_stream_get_property_failed:
senscord_start_stream_failed:

    // Unlock.

    pthread_mutex_unlock(&s_senscord_access_mutex);

    return maximum_temperature;
}
#endif
/*----------------------------------------------------------------------------*/
STATIC long GetSensorHoursMeter(void)
{
    EsfPwrMgrError esfpm_ret = kEsfPwrMgrOk;
    int32_t hours = 0;

    esfpm_ret = EsfPwrMgrHoursMeterGetValue(&hours);

    if (esfpm_ret != kEsfPwrMgrOk) {
        SYSAPP_WARN("EsfPwrMgrHoursMeterGetValue() failed %d", esfpm_ret);
        hours = 0;
    }

    return (long)hours;
}

/*----------------------------------------------------------------------------*/
STATIC void SensorTempUpdateIntervalCallback(void)
{
    SYSAPP_DBG("SensorTempUpdateIntervalCallback()");

    // Update sensor temperature.

    RetCode ret = SysAppStateUpdateSensorTemperature();

    if (ret != kRetOk) {
        SYSAPP_WARN("SysAppStateUpdateSensorTemperature() ret %d", ret);
    }

    // Send device_info.

    SysAppStateSendState(ST_TOPIC_DEVICE_INFO);

    return;
}

/*----------------------------------------------------------------------------*/
STATIC void HoursMeterUpdateIntervalCallback(void)
{
    SYSAPP_DBG("HoursMeterUpdateIntervalCallback()");

    // Update hours meter.

    RetCode ret = SysAppStateUpdateHoursMeter();

    if (ret != kRetOk) {
        SYSAPP_ERR("SysAppStateUpdateHoursMeter() ret %d", ret);
    }

    SysAppStateSendState(ST_TOPIC_DEVICE_STATES);

    return;
}

#if defined(CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING)
/*----------------------------------------------------------------------------*/
STATIC void StreamingSettingsUpdateIntervalCallback(void)
{
    SYSAPP_DBG("StreamingSettingsUpdateIntervalCallback()");

    // Send streaming_settings.

    SysAppStateSendState(ST_TOPIC_STREAMING_SETTINGS);

    return;
}
#endif /* CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING */

/*----------------------------------------------------------------------------*/
STATIC CfgStUpdateInfo *GetConfigStateUpdateInfo(uint32_t topic)
{
    CfgStUpdateInfo *ret = NULL;

    if (topic == ST_TOPIC_DEVICE_STATES) {
    }
    else if (topic == ST_TOPIC_SYSTEM_SETTINGS) {
        ret = &(s_system_settings.update);
    }
    else if (topic == ST_TOPIC_NETWORK_SETTINGS) {
        ret = &(s_network_settings.update);
    }
    else if (topic == ST_TOPIC_WIRELESS_SETTING) {
        ret = &(s_wireless_setting.update);
    }
    else if (topic == ST_TOPIC_PERIODIC_SETTING) {
        ret = &(s_periodic_setting.update);
    }
    else if (topic == ST_TOPIC_ENDPOINT_SETTINGS) {
        ret = &(s_endpoint_settings.update);
    }
#if defined(CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING)
    else if (topic == ST_TOPIC_STREAMING_SETTINGS) {
        ret = &(s_streaming_settings.update);
    }
#endif /* CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING */
    else if (topic == ST_TOPIC_UPLOAD_SENSOR_CALIBRATION_PARAM) {
    }
    else if (topic == ST_TOPIC_DEPLOY_FIRMWARE) {
    }
    else if (topic == ST_TOPIC_DEPLOY_AI_MODEL) {
    }
    else if (topic == ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM) {
    }
    else {
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC void RequestConfigStateUpdate(uint32_t topic)
{
    CfgStUpdateInfo *info = GetConfigStateUpdateInfo(topic);

    if (info == NULL) {
        SYSAPP_ERR("RequestConfigStateUpdate(%u) Unknown topic.", topic);
        return;
    }

    // Note:
    //   Not all members of the "CfgStUpdateInfo" structure are used.
    //   Only "request_flag" is used.
    //   But the "request_flag" bitmap is not used, only the LSB is used.

    info->request_flag = 1U;

    SYSAPP_DBG("RequestConfigStateUpdate(%u)", topic);
}

/*----------------------------------------------------------------------------*/
STATIC bool AppendErrorDetail(const char *msg, char *error_detail_msg, size_t error_detail_msg_size)
{
    if (strstr(error_detail_msg, TRUNCATION_SUFFIX) != NULL) {
        return false;
    }

    size_t current_len = strlen(error_detail_msg);
    size_t msg_len = strlen(msg);
    size_t separator_len = (current_len > 0) ? 2 : 0;
    size_t required_len = current_len + separator_len + msg_len + 1;

    if (required_len > error_detail_msg_size) {
        if (current_len + TRUNCATION_SUFFIX_LEN <= error_detail_msg_size - 1) {
            strncat(error_detail_msg, TRUNCATION_SUFFIX, error_detail_msg_size - current_len - 1);
        }
        return false;
    }

    if (separator_len) {
        strncat(error_detail_msg, ", ", error_detail_msg_size - current_len - 1);
        current_len = strlen(error_detail_msg);
    }

    strncat(error_detail_msg, msg, error_detail_msg_size - current_len - 1);
    return true;
}

/*----------------------------------------------------------------------------*/
STATIC void CheckErrorFlagAndAppendMessage(const ErrorFlag *error_flags, size_t flag_count,
                                           char *error_detail_msg, size_t error_detail_msg_size,
                                           bool *error_exist)
{
    for (size_t i = 0; i < flag_count; i++) {
        if (error_flags[i].flag_value != 0) {
            if (AppendErrorDetail(error_flags[i].message, error_detail_msg,
                                  error_detail_msg_size)) {
                *error_exist = true;
            }
            else {
                break;
            }
        }
    }
}

/*----------------------------------------------------------------------------*/
STATIC void CheckErrorFlagAndAppendMessageWithField(const char *base_prefix, const char *field_name,
                                                    size_t index, char *error_detail_msg,
                                                    size_t error_detail_msg_size, bool *error_exist)
{
    char buf[32];
    if (field_name == NULL) {
        snprintf(buf, sizeof(buf), "%s", base_prefix);
    }
    else {
        snprintf(buf, sizeof(buf), "%s %s[%zu]", base_prefix, field_name, index);
    }

    if (AppendErrorDetail(buf, error_detail_msg, error_detail_msg_size)) {
        *error_exist = true;
    }
}

/*----------------------------------------------------------------------------*/
STATIC char *ConvB64EncErrToString(EsfCodecBase64ResultEnum err_code)
{
    if (err_code == kEsfCodecBase64ResultNullParam) {
        return "Parameter is NULL";
    }
    else if (err_code == kEsfCodecBase64ResultOutOfRange) {
        return "Parameter is out of range";
    }
    else if (err_code == kEsfCodecBase64ResultExceedsOutBuffer) {
        return "Data size after processing exceeds";
    }
    else if (err_code == kEsfCodecBase64ResultIllegalInSize) {
        return "Parameter is illegal size";
    }
    else if (err_code == kEsfCodecBase64ResultIllegalInData) {
        return "Parameter is illegal data";
    }
    else if (err_code == kEsfCodecBase64ResultInternalError) {
        return "Internal processing error";
    }
    else if (err_code == kEsfCodecBase64ResultExternalError) {
        return "External processing error";
    }
    else if (err_code == kEsfCodecBase64NotSupported) {
        return "This API is not supported on this device";
    }
    else {
        return "";
    }
}

/*----------------------------------------------------------------------------*/
STATIC RetCode SetHashWithB64Encode(uint8_t *in, size_t in_size, char *out, size_t *out_size)
{
    /* Checks whether all data is 0 */

    size_t i;

    for (i = 0; i < in_size; i++) {
        if (*(in + i) != 0) {
            break;
        }
    }

    /* If all data is 0, returns an error */

    if (i == in_size) {
        return kRetFailed;
    }

    /* Encode the hash value into Base64 */
    EsfCodecBase64ResultEnum ret_b64encode = EsfCodecBase64Encode((const uint8_t *)in, in_size, out,
                                                                  out_size);

    if (ret_b64encode != kEsfCodecBase64ResultSuccess) {
        SYSAPP_ERR("EsfCodecBase64Encode() code:%d, error:%s", ret_b64encode,
                   ConvB64EncErrToString(ret_b64encode));
        return kRetFailed;
    }

    return kRetOk;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode GetSensorLoaderVersion(char *buf, int bufsize)
{
    RetCode ret = kRetOk;

    if (s_scstream == 0) {
        SYSAPP_ERR("GetSensorLoaderVersion");
        ret = kRetFailed;
        return ret;
    }

    struct senscord_info_string_property_t strinfo = {0};
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
    strinfo.category = 0x00020000; // kSsfSensorLibInfoCategoryLoaderVersion
#endif
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
    strinfo.category = SENSCORD_INFO_STRING_LOADER_VERSION;
#endif

    // Get loader version

    int sc_ret = senscord_stream_get_property(s_scstream, SENSCORD_INFO_STRING_PROPERTY_KEY,
                                              (void *)&strinfo, sizeof(strinfo));

    if (sc_ret < 0) {
        SYSAPP_ERR("senscord_stream_get_property(Loader Version) ret %d", sc_ret);
        ret = kRetFailed;
        return ret;
    }

    int len = snprintf(buf, bufsize, "%.32s", strinfo.info);

    if ((len < 0) || (len > bufsize)) {
        SYSAPP_ERR("Too short buf. %d", len);
        ret = kRetFailed;
    }

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
    SYSAPP_INFO("AP-ISP Loader Version:%s", strinfo.info);
#endif
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
    SYSAPP_INFO("Sensor Loader Version:%s", strinfo.info);
#endif

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode GetSensorFirmwareVersion(char *buf, int bufsize)
{
    RetCode ret = kRetOk;

    if (s_scstream == 0) {
        SYSAPP_ERR("GetSensorFirmwareVersion");
        ret = kRetFailed;
        return ret;
    }

    struct senscord_info_string_property_t strinfo = {0};
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
    strinfo.category = 0x00020001; // kSsfSensorLibInfoCategoryFirmwareVersion
#endif
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
    strinfo.category = SENSCORD_INFO_STRING_FIRMWARE_VERSION;
#endif

    // Get firmware version

    int sc_ret = senscord_stream_get_property(s_scstream, SENSCORD_INFO_STRING_PROPERTY_KEY,
                                              (void *)&strinfo, sizeof(strinfo));

    if (sc_ret < 0) {
        SYSAPP_ERR("senscord_stream_get_property(Firmware Version) ret %d", sc_ret);
        ret = kRetFailed;
        return ret;
    }

    int len = snprintf(buf, bufsize, "%.32s", strinfo.info);

    if ((len < 0) || (len > bufsize)) {
        SYSAPP_ERR("Too short buf. %d", len);
        ret = kRetFailed;
    }

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
    SYSAPP_INFO("AP-ISP Firmware Version:%s", strinfo.info);
#endif
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
    SYSAPP_INFO("Sensor Firmware Version:%s", strinfo.info);
#endif

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC CfgStPowerSupplyType GetPowerSupplyType(void)
{
    CfgStPowerSupplyType power_supply_type = UnknownSupply;
    EsfPwrMgrSupplyType esfpm_supply_type = kEsfPwrMgrSupplyTypeUnknown;

    // Get supply type.

    EsfPwrMgrError esfpm_ret = EsfPwrMgrGetSupplyType(&esfpm_supply_type);

    // Convert definition.

    if (esfpm_ret == kEsfPwrMgrOk) {
        switch (esfpm_supply_type) {
            case kEsfPwrMgrSupplyTypeUnknown:
                power_supply_type = UnknownSupply;
                break;

            case kEsfPwrMgrSupplyTypePoE:
                power_supply_type = PoESupply;
                break;

            case kEsfPwrMgrSupplyTypeUsb:
                power_supply_type = UsbSupply;
                break;

            case kEsfPwrMgrSupplyTypeDcPlug:
                power_supply_type = DcPlugSupply;
                break;

            case kEsfPwrMgrSupplyTypePrimaryBattery:
                power_supply_type = PrimaryBattery;
                break;

            case kEsfPwrMgrSupplyTypeSecondaryBattery:
                power_supply_type = SecondaryBattery;
                break;

            default:
                power_supply_type = UnknownSupply;
                break;
        }
    }
    else {
        SYSAPP_ERR("EsfPwrMgrGetSupplyType() ret %d", esfpm_ret);
    }

    return power_supply_type;
}

//
// Public functions.
//

/*----------------------------------------------------------------------------*/
RetCode SysAppStaInitialize(struct SYS_client *sys_client)
{
    SYSAPP_INFO("Initialize State block.");
    RetCode ret = kRetOk;

    // Check and save sys_client.

    if (sys_client == NULL) {
        return kRetFailed;
    }

    s_sys_client = sys_client;

    // Init stream.

    int32_t sc_ret = senscord_core_init(&s_sccore);

    if (sc_ret < 0) {
        SYSAPP_CRIT("senscord_core_init() ret %d", sc_ret);
        s_sccore = 0;
        s_scstream = 0;
        ret = kRetFailed;
        goto ssfds_open_failed;
    }

    // Open stream.

    sc_ret = senscord_core_open_stream(s_sccore, "inference_stream", &s_scstream);

    if (sc_ret < 0) {
        SYSAPP_ERR("senscord_core_open_stream() ret %d", sc_ret);
        senscord_core_exit(s_sccore);
        s_sccore = 0;
        s_scstream = 0;
        ret = kRetOk; /*T.B.D senscord_core_open_stream()_always_fails_but_not_treat_it_as_fail.*/
                      //ret = kRetFailed;
                      //goto ssfds_open_failed;
    }

    // Init senscord access mutex.

    int mtx_ret = pthread_mutex_init(&s_senscord_access_mutex, NULL);

    if (mtx_ret != 0) {
        SYSAPP_CRIT("pthread_mutex_init. mtx_ret=%d", mtx_ret);
        goto mtx_init_failed;
    }

    // Readout and send device_info.

    SysAppStateReadoutDeviceInfo();
    SysAppStateSendState(ST_TOPIC_DEVICE_INFO);

    // Readout and send device_capabilities.

    SysAppStateReadoutDeviceCapabilities();
    SysAppStateSendState(ST_TOPIC_DEVICE_CAPABILITIES);

    // Readout and send device_states.

    SysAppStateReadoutDeviceStates();
    SysAppStateSendState(ST_TOPIC_DEVICE_STATES);

    // Readout and send reserved.
#if 0 // For_Coverity_Disable_SysAppStateReadoutReserved
  SysAppStateReadoutReserved();
#endif
    SysAppStateSendState(ST_TOPIC_RESERVED);

    // Readout and send system_settings.

    SysAppStateReadoutSystemSettings();
    SysAppStateSendState(ST_TOPIC_SYSTEM_SETTINGS);

    // Readout and send network_settings.

    SysAppStateReadoutNetworkSettings();
    SysAppStateSendState(ST_TOPIC_NETWORK_SETTINGS);

    // Readout and send wireless_setting.

    SysAppStateReadoutWirelessSetting();
    SysAppStateSendState(ST_TOPIC_WIRELESS_SETTING);

    // Readout and send periodic_setting.

    SysAppStateReadoutPeriodicSetting();
    SysAppStateSendState(ST_TOPIC_PERIODIC_SETTING);

    // Readout and send endpoint_settings.

    SysAppStateReadoutEndpointSettings();
    SysAppStateSendState(ST_TOPIC_ENDPOINT_SETTINGS);

#if defined(CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING)
    // Readout and send streaming_settings.

    SysAppStateReadoutStreamingSettings();
    SysAppStateSendState(ST_TOPIC_STREAMING_SETTINGS);
#endif /* CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING */

mtx_init_failed:
ssfds_open_failed:

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateGetSensCordId(void *core_id)
{
    if (s_sccore == 0) {
        return kRetFailed;
    }

    *(senscord_core_t *)core_id = s_sccore;

    return kRetOk;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateGetSensCordStream(void *stream)
{
    if (s_scstream == 0) {
        return kRetFailed;
    }

    *(senscord_stream_t *)stream = s_scstream;

    return kRetOk;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStaFinalize(void)
{
    SYSAPP_INFO("Finalize State block.");

    RetCode ret = kRetOk;

    // Stop timer.

    for (TimerType type = SensorTempIntervalTimer; type < TimerTypeNum; type++) {
        SysAppTimerStopTimer(type);
    }

    // Destroy mutex.

    pthread_mutex_destroy(&s_senscord_access_mutex);

    // Close senscord

    if (s_sccore && s_scstream) {
        senscord_core_close_stream(s_sccore, s_scstream);
    }

    if (s_sccore) {
        senscord_core_exit(s_sccore);
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateUpdateNumber(uint32_t topic, uint32_t type, int number)
{
    RetCode ret = kRetOk;

    SYSAPP_INFO("SysAppStateUpdateNumber topic:%u  prop:%d.", topic, type);

    if (topic == ST_TOPIC_DEVICE_STATES) {
        if (type == HoursMeter) {
            s_device_states.hours_meter = number;
        }
        else {
        }
    }
    else if (topic == ST_TOPIC_SYSTEM_SETTINGS) {
        if (type == TemperatureUpdateInterval) {
            s_system_settings.temperature_update_interval = number;
        }
        else {
        }
    }
    else if (topic == ST_TOPIC_NETWORK_SETTINGS) {
        if (type == IpMethod) {
            s_network_settings.ip_method = number;
        }
        else if (type == ProxyPort) {
            s_proxy_settings.proxy_port = number;
        }
        else {
        }
    }
    else if (topic == ST_TOPIC_WIRELESS_SETTING) {
        if (type == StaEncryption) {
            s_sta_mode_setting.encryption = number;
        }
        else {
        }
    }
    else if (topic == ST_TOPIC_PERIODIC_SETTING) {
        if (type == OperationMode) {
            s_periodic_setting.operation_mode = number;
        }
        else if (type == RecoveryMethod) {
            s_periodic_setting.recovery_method = number;
        }
        else {
        }
    }
    else if (topic == ST_TOPIC_ENDPOINT_SETTINGS) {
        if (type == EndpointPort) {
            s_endpoint_settings.endpoint_port = number;
        }
        else {
        }
    }
#if defined(CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING)
    else if (topic == ST_TOPIC_STREAMING_SETTINGS) {
        if (type == StreamingProcessState) {
            s_streaming_settings.process_state = (CfgStStreamProcessState)number;
        }
        else if (type == OperatingMode) {
            s_streaming_settings.operating_mode = (CfgStStreamOperatingMode)number;
        }
        else if (type == NfsVersion) {
            s_streaming_settings.nfs_config.nfs_version = (CfgStNfsVersion)number;
        }
        else if (type == UseTcp) {
            s_streaming_settings.nfs_config.use_tcp = number;
        }
        else if (type == MaxRecordTime) {
            s_streaming_settings.nfs_config.max_record_time = number;
        }
        else {
        }
    }
#endif /* CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING */
    else if (topic == ST_TOPIC_UPLOAD_SENSOR_CALIBRATION_PARAM) {
    }
    else if (topic == ST_TOPIC_DEPLOY_FIRMWARE) {
    }
    else if (topic == ST_TOPIC_DEPLOY_AI_MODEL) {
    }
    else if (topic == ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM) {
    }
    else {
    }

    // Set state update flag. Cause update number data.

    RequestConfigStateUpdate(topic);

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateUpdateNumberWithIdx(uint32_t topic, uint32_t type, int number, uint32_t idx)
{
    RetCode ret = kRetOk;

    SYSAPP_INFO("SysAppStateUpdateNumberWithIdx topic:%u  prop:%d.", topic, type);

    if (topic == ST_TOPIC_SYSTEM_SETTINGS) {
        if (type == LogFilter) {
            s_log[idx].filter = number;
        }
        else if (type == LogLevel) {
            s_log[idx].level = number;
        }
        else if (type == LogDestination) {
            s_log[idx].destination = number;
        }
        else {
        }
    }
    else if (topic == ST_TOPIC_PERIODIC_SETTING) {
        if (type == CaptureInterval) {
            s_interval_setting[idx].capture_interval = number;
        }
        else if (type == ConfigInterval) {
            s_interval_setting[idx].config_interval = number;
        }
    }
    else {
    }

    // Set state update flag. Cause update number data.

    RequestConfigStateUpdate(topic);

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateUpdateBoolean(uint32_t topic, uint32_t type, bool boolean)
{
    RetCode ret = kRetOk;

    SYSAPP_INFO("SysAppStateUpdateBoolian topic:%u  prop:%d.", topic, type);

    if (topic == ST_TOPIC_DEVICE_CAPABILITIES) {
        if (type == SensorPostProcessSupported) {
            s_device_capabilities.is_sensor_postprocess_supported = boolean;
        }
        else {
        }
    }
    else if (topic == ST_TOPIC_SYSTEM_SETTINGS) {
        if (type == LedEnabled) {
            s_system_settings.led_enabled = boolean;
        }
        else {
        }
    }
    else {
    }

    // Set state update flag. Cause update boolian data.

    RequestConfigStateUpdate(topic);

    return ret;
}

/*----------------------------------------------------------------------------*/
void SysAppStateUpdateString(uint32_t topic, uint32_t type, const char *string)
{
    SYSAPP_INFO("SysAppStateUpdateString topic:%u  prop:%d.", topic, type);

    if (topic == ST_TOPIC_DEVICE_STATES) {
        if (type == ProcessState) {
            snprintf(s_device_states.process_state, 32, "%s", string);
        }
        else {
        }
    }
    else if (topic == ST_TOPIC_SYSTEM_SETTINGS) {
        if (type == Id) {
            snprintf(s_system_settings.id, sizeof(s_system_settings.id), "%s", string);
        }
        else {
        }
    }
    else if (topic == ST_TOPIC_NETWORK_SETTINGS) {
        if (type == Id) {
            snprintf(s_network_settings.id, sizeof(s_network_settings.id), "%s", string);
        }
        else if (type == ProxyUrl) {
            snprintf(s_proxy_settings.proxy_url, sizeof(s_proxy_settings.proxy_url), "%s", string);
        }
        else if (type == ProxyUserName) {
            snprintf(s_proxy_settings.proxy_user_name, sizeof(s_proxy_settings.proxy_user_name),
                     "%s", string);
        }
        else if (type == ProxyPassword) {
            snprintf(s_proxy_settings.proxy_password, sizeof(s_proxy_settings.proxy_password), "%s",
                     string);
        }
        else if (type == IpAddressV6) {
            snprintf(s_static_settings_ipv6.ip_address, sizeof(s_static_settings_ipv6.ip_address),
                     "%s", string);
        }
        else if (type == SubnetMaskV6) {
            snprintf(s_static_settings_ipv6.subnet_mask, sizeof(s_static_settings_ipv6.subnet_mask),
                     "%s", string);
        }
        else if (type == GatewayAddressV6) {
            snprintf(s_static_settings_ipv6.gateway_address,
                     sizeof(s_static_settings_ipv6.gateway_address), "%s", string);
        }
        else if (type == DnsAddressV6) {
            snprintf(s_static_settings_ipv6.dns_address, sizeof(s_static_settings_ipv6.dns_address),
                     "%s", string);
        }
        else if (type == IpAddress) {
            snprintf(s_static_settings_ipv4.ip_address, sizeof(s_static_settings_ipv4.ip_address),
                     "%s", string);
        }
        else if (type == SubnetMask) {
            snprintf(s_static_settings_ipv4.subnet_mask, sizeof(s_static_settings_ipv4.subnet_mask),
                     "%s", string);
        }
        else if (type == GatewayAddress) {
            snprintf(s_static_settings_ipv4.gateway_address,
                     sizeof(s_static_settings_ipv4.gateway_address), "%s", string);
        }
        else if (type == DnsAddress) {
            snprintf(s_static_settings_ipv4.dns_address, sizeof(s_static_settings_ipv4.dns_address),
                     "%s", string);
        }
        else if (type == Dns2Address) {
            snprintf(s_static_settings_ipv4.dns2_address,
                     sizeof(s_static_settings_ipv4.dns2_address), "%s", string);
        }
        else if (type == NtpUrl) {
            snprintf(s_network_settings.ntp_url, sizeof(s_network_settings.ntp_url), "%s", string);
        }
        else if (type == Ntp2Url) {
            snprintf(s_network_settings.ntp2_url, sizeof(s_network_settings.ntp2_url), "%s",
                     string);
        }
        else {
        }
    }
    else if (topic == ST_TOPIC_WIRELESS_SETTING) {
        if (type == Id) {
            snprintf(s_wireless_setting.id, sizeof(s_wireless_setting.id), "%s", string);
        }
        else if (type == StaSsid) {
            snprintf(s_sta_mode_setting.ssid, sizeof(s_sta_mode_setting.ssid), "%s", string);
        }
        else if (type == StaPassword) {
            snprintf(s_sta_mode_setting.password, sizeof(s_sta_mode_setting.password), "%s",
                     string);
        }
        else {
        }
    }
    else if (topic == ST_TOPIC_PERIODIC_SETTING) {
        if (type == Id) {
            snprintf(s_periodic_setting.id, sizeof(s_periodic_setting.id), "%s", string);
        }
    }
    else if (topic == ST_TOPIC_ENDPOINT_SETTINGS) {
        if (type == Id) {
            snprintf(s_endpoint_settings.id, sizeof(s_endpoint_settings.id), "%s", string);
        }
        else if (type == EndpointUrl) {
            snprintf(s_endpoint_settings.endpoint_url, sizeof(s_endpoint_settings.endpoint_url),
                     "%s", string);
        }
        else if (type == ProtocolVersion) {
            snprintf(s_endpoint_settings.protocol_version,
                     sizeof(s_endpoint_settings.protocol_version), "%s", string);
        }
        else {
        }
    }
#if defined(CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING)
    else if (topic == ST_TOPIC_STREAMING_SETTINGS) {
        if (type == Id) {
            snprintf(s_streaming_settings.id, sizeof(s_streaming_settings.id), "%s", string);
        }
        else if (type == ServerIp) {
            snprintf(s_streaming_settings.rtsp_config.server_ip,
                     sizeof(s_streaming_settings.rtsp_config.server_ip), "%s", string);
        }
        else if (type == StreamName) {
            snprintf(s_streaming_settings.rtsp_config.stream_name,
                     sizeof(s_streaming_settings.rtsp_config.stream_name), "%s",
                     string ? string : DEFAULT_STREAM_NAME);
        }
        else if (type == UserName) {
            snprintf(s_streaming_settings.rtsp_config.user_name,
                     sizeof(s_streaming_settings.rtsp_config.user_name), "%s",
                     string ? string : "");
        }
        else if (type == Password) {
            snprintf(s_streaming_settings.rtsp_config.password,
                     sizeof(s_streaming_settings.rtsp_config.password), "%s", string ? string : "");
        }
        else if (type == NfsServerIp) {
            snprintf(s_streaming_settings.nfs_config.server_ip,
                     sizeof(s_streaming_settings.nfs_config.server_ip), "%s", string);
        }
        else if (type == MountPath) {
            snprintf(s_streaming_settings.nfs_config.mount_path,
                     sizeof(s_streaming_settings.nfs_config.mount_path), "%s", string);
        }
        else {
        }
    }
#endif /* CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING */
    else if (topic == ST_TOPIC_UPLOAD_SENSOR_CALIBRATION_PARAM) {
    }
    else if (topic == ST_TOPIC_DEPLOY_FIRMWARE) {
    }
    else if (topic == ST_TOPIC_DEPLOY_AI_MODEL) {
    }
    else if (topic == ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM) {
    }
    else {
    }

    // Set state update flag. Cause update string data.

    RequestConfigStateUpdate(topic);
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateUpdateStringWithIdx(uint32_t topic, uint32_t type, const char *string,
                                       uint32_t idx)
{
    RetCode ret = kRetOk;

    SYSAPP_INFO("SysAppStateUpdateStringWithIdx topic:%u  prop:%d.", topic, type);

    if (topic == ST_TOPIC_SYSTEM_SETTINGS) {
        if (type == LogStorageName) {
            snprintf(s_log[idx].storage_name, sizeof(s_log[0].storage_name), "%s", string);
        }
        else if (type == LogPath) {
            snprintf(s_log[idx].path, sizeof(s_log[0].path), "%s", string);
        }
        else {
        }
    }
    else if (topic == ST_TOPIC_PERIODIC_SETTING) {
        if (type == BaseTime) {
            snprintf(s_interval_setting[idx].base_time, 5, "%s", string);
        }
        else {
        }
    }
    else {
    }

    // Set state update flag. Cause update string data.

    RequestConfigStateUpdate(topic);

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateUpdateSensorTemperature(void)
{
    RetCode ret = kRetOk;

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
    // Get information for temperature(AI-ISP).

    s_chips[CHIPS_IDX_COMPANION_CHIP].current_temperature =
        GetAiIspTemperature(s_chips[CHIPS_IDX_COMPANION_CHIP].current_temperature);

    if (s_chips[CHIPS_IDX_COMPANION_CHIP].current_temperature == TEMPERATURE_INVALID_VAL) {
        SYSAPP_WARN("GetAiIspTemperature() failed");
        ret = kRetFailed;
    }
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP

    // Get information for temperature(Sensor).

    s_chips[CHIPS_IDX_SENSOR_CHIP].current_temperature =
        GetSensorTemperature(s_chips[CHIPS_IDX_SENSOR_CHIP].current_temperature);

    if (s_chips[CHIPS_IDX_SENSOR_CHIP].current_temperature == TEMPERATURE_INVALID_VAL) {
        SYSAPP_WARN("GetSensorTemperature() failed");
        ret = kRetFailed;
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateUpdateHoursMeter(void)
{
    RetCode ret = kRetOk;

    // Get information for hours_meter.

    s_device_states.hours_meter = GetSensorHoursMeter();

    return ret;
}

#if 0
/*----------------------------------------------------------------------------*/
RetCode SysAppStateUpdate(uint32_t topic, uint32_t type, CfgStData* data) {
  RetCode ret = kRetOk;

  if ((type & CFGST_DATATYPE_NUMBER) == CFGST_DATATYPE_NUMBER) {
    SysAppStateUpdateNumber(topic, type, data->number);
  } else if ((type & CFGST_DATATYPE_BOOLEAN) == CFGST_DATATYPE_BOOLEAN) {
    SysAppStateUpdateBoolean(topic, type, data->boolean);
  } else if ((type & CFGST_DATATYPE_STRING) == CFGST_DATATYPE_STRING) {
    SysAppStateUpdateString(topic, type, data->string);
  } else {
  }

  return ret;
}
#endif

/*----------------------------------------------------------------------------*/
RetCode SysAppStateSetInvalidArgError(uint32_t topic, uint32_t property)
{
    RetCode ret = kRetOk;

    SYSAPP_DBG("SysAppStateSetInvalidArgError topic:%u  prop:%d.", topic, property);

    if (topic == ST_TOPIC_SYSTEM_SETTINGS) {
        if (property == Id) {
            s_system_settings.update.invalid_arg_flag = (1 << property);
        }
        if (property == LedEnabled) {
            s_system_settings.invalid_led_enabled_flag = (1 << property);
        }
        if (property == TemperatureUpdateInterval) {
            s_system_settings.invalid_temperature_update_interval_flag = (1 << property);
        }
    }
    else if (topic == ST_TOPIC_NETWORK_SETTINGS) {
        if (property == Id) {
            s_network_settings.update.invalid_arg_flag = (1 << property);
        }
        if (property == IpMethod) {
            s_network_settings.invalid_ip_method_flag = (1 << property);
        }
        if (property == NtpUrl) {
            s_network_settings.invalid_ntp_url_flag = (1 << property);
        }
        if (property == Ntp2Url) {
            s_network_settings.invalid_ntp2_url_flag = (1 << property);
        }
        if (property == IpAddress) {
            s_static_settings_ipv4.invalid_ip_address_flag = (1 << property);
        }
        if (property == SubnetMask) {
            s_static_settings_ipv4.invalid_subnet_mask_flag = (1 << property);
        }
        if (property == GatewayAddress) {
            s_static_settings_ipv4.invalid_gateway_address_flag = (1 << property);
        }
        if (property == DnsAddress) {
            s_static_settings_ipv4.invalid_dns_address_flag = (1 << property);
        }
        if (property == Dns2Address) {
            s_static_settings_ipv4.invalid_dns2_address_flag = (1 << property);
        }
        if (property == IpAddressV6) {
            s_static_settings_ipv6.invalid_ip_address_flag = (1 << property);
        }
        if (property == SubnetMaskV6) {
            s_static_settings_ipv6.invalid_subnet_mask_flag = (1 << property);
        }
        if (property == GatewayAddressV6) {
            s_static_settings_ipv6.invalid_gateway_address_flag = (1 << property);
        }
        if (property == DnsAddressV6) {
            s_static_settings_ipv6.invalid_dns_address_flag = (1 << property);
        }
        if (property == ProxyPort) {
            s_proxy_settings.invalid_proxy_port_flag = (1 << property);
        }
        if (property == ProxyUrl) {
            s_proxy_settings.invalid_proxy_url_flag = (1 << property);
        }
        if (property == ProxyUserName) {
            s_proxy_settings.invalid_proxy_user_name_flag = (1 << property);
        }
        if (property == ProxyPassword) {
            s_proxy_settings.invalid_proxy_password_flag = (1 << property);
        }
    }
    else if (topic == ST_TOPIC_WIRELESS_SETTING) {
        if (property == Id) {
            s_wireless_setting.update.invalid_arg_flag = (1 << property);
        }
        if (property == StaSsid) {
            s_sta_mode_setting.invalid_ssid_flag = (1 << property);
        }
        if (property == StaPassword) {
            s_sta_mode_setting.invalid_password_flag = (1 << property);
        }
        if (property == StaEncryption) {
            s_sta_mode_setting.invalid_encryption_flag = (1 << property);
        }
    }
    else if (topic == ST_TOPIC_PERIODIC_SETTING) {
        s_periodic_setting.update.invalid_arg_flag = (1 << property);
    }
    else if (topic == ST_TOPIC_ENDPOINT_SETTINGS) {
        s_endpoint_settings.update.invalid_arg_flag = (1 << property);
    }
#if defined(CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING)
    else if (topic == ST_TOPIC_STREAMING_SETTINGS) {
        s_streaming_settings.update.invalid_arg_flag = (1 << property);
    }
#endif /* CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING */
    else {
    }

    // Set state update flag. Cause InvalidArg error.

    RequestConfigStateUpdate(topic);

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateSetInvalidArgErrorWithIdx(uint32_t topic, uint32_t property, uint32_t idx)
{
    RetCode ret = kRetOk;

    SYSAPP_DBG("SysAppStateSetInvalidArgErrorWithIdx topic:%u  prop:%d.", topic, property);

    if (topic == ST_TOPIC_SYSTEM_SETTINGS) {
        if (property == LogFilter) {
            s_log[idx].invalid_filter_flag = (1 << property);
        }
        if (property == LogLevel) {
            s_log[idx].invalid_level_flag = (1 << property);
        }
        if (property == LogDestination) {
            s_log[idx].invalid_destination_flag = (1 << property);
        }
        if (property == LogStorageName) {
            s_log[idx].invalid_storage_name_flag = (1 << property);
        }
        if (property == LogPath) {
            s_log[idx].invalid_path_flag = (1 << property);
        }
    }
    else if (topic == ST_TOPIC_PERIODIC_SETTING) {
        if ((property == BaseTime) || (property == CaptureInterval) ||
            (property == ConfigInterval)) {
            s_interval_setting[idx].update.invalid_arg_flag = (1 << property);
        }
    }
    else {
    }

    // Set state update flag. Cause InvalidArg error.

    RequestConfigStateUpdate(topic);

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateSetInternalError(uint32_t topic, uint32_t property)
{
    RetCode ret = kRetOk;

    SYSAPP_DBG("SysAppStateSetInternalError topic:%u  prop:%d.", topic, property);

    if (topic == ST_TOPIC_SYSTEM_SETTINGS) {
        s_system_settings.update.internal_error_flag = (1 << property);
    }
    else if (topic == ST_TOPIC_NETWORK_SETTINGS) {
        if ((property == IpMethod) || (property == NtpUrl) || (property == Ntp2Url)) {
            s_network_settings.update.internal_error_flag = (1 << property);
        }
        if ((property == IpAddress) || (property == SubnetMask) || (property == GatewayAddress) ||
            (property == DnsAddress) || (property == Dns2Address)) {
            s_static_settings_ipv4.update.internal_error_flag = (1 << property);
        }
        if ((property == IpAddressV6) || (property == SubnetMaskV6) ||
            (property == GatewayAddressV6) || (property == DnsAddressV6)) {
            s_static_settings_ipv6.update.internal_error_flag = (1 << property);
        }
        if ((property == ProxyPort) || (property == ProxyUrl) || (property == ProxyUserName) ||
            (property == ProxyPassword)) {
            s_proxy_settings.update.internal_error_flag = (1 << property);
        }
    }
    else if (topic == ST_TOPIC_WIRELESS_SETTING) {
        if ((property == StaSsid) || (property == StaPassword) || (property == StaEncryption)) {
            s_sta_mode_setting.update.internal_error_flag = (1 << property);
        }
        else {
        }
    }
    else if (topic == ST_TOPIC_PERIODIC_SETTING) {
        s_periodic_setting.update.internal_error_flag = (1 << property);
    }
    else if (topic == ST_TOPIC_ENDPOINT_SETTINGS) {
        s_endpoint_settings.update.internal_error_flag = (1 << property);
    }
#if defined(CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING)
    else if (topic == ST_TOPIC_STREAMING_SETTINGS) {
        s_streaming_settings.update.internal_error_flag = (1 << property);
    }
#endif /* CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING */
    else {
    }

    // Set state update flag. Cause Internal error.

    RequestConfigStateUpdate(topic);

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateSetInternalErrorWithIdx(uint32_t topic, uint32_t property, uint32_t idx)
{
    RetCode ret = kRetOk;

    SYSAPP_DBG("SysAppStateSetInternalErrorWithIdx topic:%u  prop:%d.", topic, property);

    if (topic == ST_TOPIC_SYSTEM_SETTINGS) {
        if ((property == LogFilter) || (property == LogLevel) || (property == LogDestination) ||
            (property == LogStorageName) || (property == LogPath)) {
            s_log[idx].update.internal_error_flag = (1 << property);
        }
    }
    else if (topic == ST_TOPIC_PERIODIC_SETTING) {
        if ((property == BaseTime) || (property == CaptureInterval) ||
            (property == ConfigInterval)) {
            s_interval_setting[idx].update.internal_error_flag = (1 << property);
        }
    }
    else {
    }

    // Set state update flag. Cause Internal error.

    RequestConfigStateUpdate(topic);

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateReadoutMainChip(void)
{
    RetCode ret = kRetOk;
    int len = 0;

    // Get information for name.
    // TODO:
    // Since ESF is not supported, the current value is fixed.

    // Set "ApFw" for name.

    strncpy(s_chips[CHIPS_IDX_MAIN_CHIP].name, MAIN_CHIP_NAME,
            sizeof(s_chips[CHIPS_IDX_MAIN_CHIP].name));

    // Get information for hardware_version.

    s_chips[CHIPS_IDX_MAIN_CHIP].hardware_version[0] = '\0'; /*T.B.D*/

    // Get information for current_temperature.

    s_chips[CHIPS_IDX_MAIN_CHIP].current_temperature = 0; /*T.B.D*/

    // Get information for processor.

    EsfFwMgrGetInfoData info;
    EsfFwMgrGetInfoResponse response;
    EsfFwMgrResult res;

    memset(&info, 0, sizeof(info));
    memset(&response, 0, sizeof(response));

    // Get processor loader info.

    info.target = kEsfFwMgrTargetProcessorLoader;
    info.in_length = 1;
    info.response = &response;
    info.out_length = 0;

    res = EsfFwMgrGetInfo(&info);

    if (res != kEsfFwMgrResultOk) {
        s_chips[CHIPS_IDX_MAIN_CHIP].loader_version[0] = '\0';
        s_chips[CHIPS_IDX_MAIN_CHIP].loader_hash[0] = '\0';
        s_chips[CHIPS_IDX_MAIN_CHIP].update_date_loader[0] = '\0';
        if (res == kEsfFwMgrResultUnimplemented) {
            SYSAPP_WARN("Unimplemented");
        }
        else {
            SYSAPP_ERR("EsfFwMgrGetInfo=%d", res);
            ret = kRetFailed;
        }
    }
    else {
        len = snprintf(s_chips[CHIPS_IDX_MAIN_CHIP].loader_version,
                       sizeof(s_chips[CHIPS_IDX_MAIN_CHIP].loader_version), "%.32s",
                       response.version);

        if ((len < 0) || (len > ST_PROCESSOR_LOADER_VERSION_LEN)) {
            SYSAPP_ERR("Num of char in processor.loader_version is incorrect=%d", len);
            s_chips[CHIPS_IDX_MAIN_CHIP].loader_version[0] = '\0';
            ret = kRetFailed;
        }

        size_t outsize = ST_PROCESSOR_HASH_LEN + 1;

        if (kRetOk != SetHashWithB64Encode(response.hash, sizeof(response.hash),
                                           s_chips[CHIPS_IDX_MAIN_CHIP].loader_hash, &outsize)) {
            SYSAPP_ERR("processor.loader_hash invalid outsize=%zu", outsize);
            s_chips[CHIPS_IDX_MAIN_CHIP].loader_hash[0] = '\0';
            ret = kRetFailed;
        }

        len = snprintf(s_chips[CHIPS_IDX_MAIN_CHIP].update_date_loader,
                       sizeof(s_chips[CHIPS_IDX_MAIN_CHIP].update_date_loader), "%s",
                       response.last_update);

        if ((len < 0) || (len > ST_PROCESSOR_LOADER_UPDATE_DATE_LEN)) {
            SYSAPP_ERR("Num of char in processor.update_date_loader is incorrect=%d", len);
            s_chips[CHIPS_IDX_MAIN_CHIP].update_date_loader[0] = '\0';
            ret = kRetFailed;
        }
    }

    // Get processor firmware info

    info.target = kEsfFwMgrTargetProcessorFirmware;
    info.out_length = 0;
    memset(&response, 0, sizeof(response));

    res = EsfFwMgrGetInfo(&info);

    if (res != kEsfFwMgrResultOk) {
        s_chips[CHIPS_IDX_MAIN_CHIP].firmware_version[0] = '\0';
        s_chips[CHIPS_IDX_MAIN_CHIP].firmware_hash[0] = '\0';
        s_chips[CHIPS_IDX_MAIN_CHIP].update_date_firmware[0] = '\0';
        if (res == kEsfFwMgrResultUnimplemented) {
            SYSAPP_WARN("Unimplemented");
        }
        else {
            SYSAPP_ERR("EsfFwMgrGetInfo=%d", res);
            ret = kRetFailed;
        }
    }
    else {
        len = snprintf(s_chips[CHIPS_IDX_MAIN_CHIP].firmware_version,
                       sizeof(s_chips[CHIPS_IDX_MAIN_CHIP].firmware_version), "%.32s",
                       response.version);

        if ((len < 0) || (len > ST_PROCESSOR_FIRMWARE_VERSION_LEN)) {
            SYSAPP_ERR("Num of char in processor.firmware_version is incorrect=%d", len);
            s_chips[CHIPS_IDX_MAIN_CHIP].firmware_version[0] = '\0';
            ret = kRetFailed;
        }

        size_t outsize = ST_PROCESSOR_HASH_LEN + 1;

        if (kRetOk != SetHashWithB64Encode(response.hash, sizeof(response.hash),
                                           s_chips[CHIPS_IDX_MAIN_CHIP].firmware_hash, &outsize)) {
            SYSAPP_ERR("processor.firmware_hash invalid outsize=%zu", outsize);
            s_chips[CHIPS_IDX_MAIN_CHIP].firmware_hash[0] = '\0';
            ret = kRetFailed;
        }

        len = snprintf(s_chips[CHIPS_IDX_MAIN_CHIP].update_date_firmware,
                       sizeof(s_chips[CHIPS_IDX_MAIN_CHIP].update_date_firmware), "%s",
                       response.last_update);

        if ((len < 0) || (len > ST_PROCESSOR_LOADER_UPDATE_DATE_LEN)) {
            SYSAPP_ERR("Num of char in processor.update_date_firmware is incorrect=%d", len);
            s_chips[CHIPS_IDX_MAIN_CHIP].update_date_firmware[0] = '\0';
            ret = kRetFailed;
        }
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateReadoutChips(void)
{
    RetCode ret = kRetOk;
    RetCode chips_ret = kRetOk;
    int len = 0;

    chips_ret = SysAppStateReadoutMainChip();

    if (chips_ret != kRetOk) {
        SYSAPP_WARN("SysAppStateReadoutMainChip() ret %d", ret);
        ret = kRetFailed;
    }

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
    // Get information for id.

    chips_ret = GetSensorInfo(SensorId, s_chips[CHIPS_IDX_SENSOR_CHIP].id,
                              sizeof(s_chips[CHIPS_IDX_SENSOR_CHIP].id));

    if (chips_ret != kRetOk) {
        s_chips[CHIPS_IDX_SENSOR_CHIP].id[0] = '\0';
    }

#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP

    // Set "Companion Chip(AI-ISP)" for name.

    strncpy(s_chips[CHIPS_IDX_COMPANION_CHIP].name, COMPANION_CHIP_NAME,
            sizeof(s_chips[CHIPS_IDX_COMPANION_CHIP].name));

    // Get information for id.

    chips_ret = GetSensorInfo(AiIspDeviceId, s_chips[CHIPS_IDX_COMPANION_CHIP].id,
                              sizeof(s_chips[CHIPS_IDX_COMPANION_CHIP].id));

    if (chips_ret != kRetOk) {
        s_chips[CHIPS_IDX_COMPANION_CHIP].id[0] = '\0';
    }

    // Get information for temperature(AI-ISP).

    s_chips[CHIPS_IDX_COMPANION_CHIP].current_temperature =
        GetAiIspTemperature(s_chips[CHIPS_IDX_COMPANION_CHIP].current_temperature);

    if (s_chips[CHIPS_IDX_COMPANION_CHIP].current_temperature == TEMPERATURE_INVALID_VAL) {
        SYSAPP_WARN("GetAiIspTemperature() failed");
        ret = kRetFailed;
    }
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP

    // Set "Sensor Chip(IMX500)" for name.

    strncpy(s_chips[CHIPS_IDX_SENSOR_CHIP].name, SENSOR_CHIP_NAME,
            sizeof(s_chips[CHIPS_IDX_SENSOR_CHIP].name));

    // Get information for hardware_version.

    chips_ret = GetSensorInfo(SensorHwVer, s_chips[CHIPS_IDX_SENSOR_CHIP].hardware_version,
                              sizeof(s_chips[CHIPS_IDX_SENSOR_CHIP].hardware_version));

    if (chips_ret != kRetOk) {
        s_chips[CHIPS_IDX_SENSOR_CHIP].hardware_version[0] = '\0';
    }

    // Get information for temperature(Sensor).

    s_chips[CHIPS_IDX_SENSOR_CHIP].current_temperature =
        GetSensorTemperature(s_chips[CHIPS_IDX_SENSOR_CHIP].current_temperature);

    if (s_chips[CHIPS_IDX_SENSOR_CHIP].current_temperature == TEMPERATURE_INVALID_VAL) {
        SYSAPP_WARN("GetSensorTemperature() failed");
        ret = kRetFailed;
    }

    // Get information for sensor.

    EsfFwMgrGetInfoData info;
    EsfFwMgrGetInfoResponse response;
    EsfFwMgrResult res;
    bool loader_error = false;
    bool firmware_error = false;

    // Use index for T3(Sensor) or T5(AI-ISP)
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
    uint32_t no = CHIPS_IDX_SENSOR_CHIP;
#else // Use #else for build: CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
    uint32_t no = CHIPS_IDX_COMPANION_CHIP;
#endif

    memset(&info, 0, sizeof(info));
    memset(&response, 0, sizeof(response));

    // Get sensor loader info.

    info.target = kEsfFwMgrTargetSensorLoader;
    info.in_length = 1;
    info.response = &response;
    info.out_length = 0;

    res = EsfFwMgrGetInfo(&info);

    if (res != kEsfFwMgrResultOk) {
        s_chips[no].loader_version[0] = '\0';
        s_chips[no].loader_hash[0] = '\0';
        s_chips[no].update_date_loader[0] = '\0';
        if (res == kEsfFwMgrResultUnimplemented) {
            SYSAPP_WARN("Unimplemented");
        }
        else {
            SYSAPP_ERR("EsfFwMgrGetInfo=%d", res);
            ret = kRetFailed;
        }
        loader_error = true;
    }
    else {
        len = snprintf(s_chips[no].loader_version, sizeof(s_chips[no].loader_version), "%.32s",
                       response.version);

        if ((len < 0) || (len > ST_SENSOR_LOADER_VERSION_LEN)) {
            SYSAPP_ERR("Num of char in sensor.loader_version is incorrect=%d", len);
            s_chips[no].loader_version[0] = '\0';
            ret = kRetFailed;
            loader_error = true;
        }

        size_t outsize = ST_SENSOR_HASH_LEN + 1;

        if (kRetOk != SetHashWithB64Encode(response.hash, sizeof(response.hash),
                                           s_chips[no].loader_hash, &outsize)) {
            SYSAPP_ERR("sensor.loader_hash invalid outsize=%zu", outsize);
            s_chips[no].loader_hash[0] = '\0';
            ret = kRetFailed;
            loader_error = true;
        }

        len = snprintf(s_chips[no].update_date_loader, sizeof(s_chips[no].update_date_loader), "%s",
                       response.last_update);

        if ((len < 0) || (len > ST_PROCESSOR_LOADER_UPDATE_DATE_LEN)) {
            SYSAPP_ERR("Num of char in sensor.update_date_loader is incorrect=%d", len);
            s_chips[no].update_date_loader[0] = '\0';
            ret = kRetFailed;
            loader_error = true;
        }
    }

    // Update "AI-ISP" for loader version only when failed to get from FwManager.

    if (loader_error) {
        ret = GetSensorLoaderVersion(s_chips[no].loader_version,
                                     sizeof(s_chips[no].loader_version));

        if (ret != kRetOk) {
            s_chips[no].loader_version[0] = '\0';
        }
    }

    // Get sensor firmware info

    info.target = kEsfFwMgrTargetSensorFirmware;
    info.out_length = 0;
    memset(&response, 0, sizeof(response));

    res = EsfFwMgrGetInfo(&info);

    if (res != kEsfFwMgrResultOk) {
        s_chips[no].firmware_version[0] = '\0';
        s_chips[no].firmware_hash[0] = '\0';
        s_chips[no].update_date_firmware[0] = '\0';
        if (res == kEsfFwMgrResultUnimplemented) {
            SYSAPP_WARN("Unimplemented");
        }
        else {
            SYSAPP_ERR("EsfFwMgrGetInfo=%d", res);
            ret = kRetFailed;
        }
        firmware_error = true;
    }
    else {
        len = snprintf(s_chips[no].firmware_version, sizeof(s_chips[no].firmware_version), "%.32s",
                       response.version);

        if ((len < 0) || (len > ST_SENSOR_FIRMWARE_VERSION_LEN)) {
            SYSAPP_ERR("Num of char in s_sensor.firmware_version is incorrect=%d", len);
            s_chips[no].firmware_version[0] = '\0';
            ret = kRetFailed;
            firmware_error = true;
        }

        size_t outsize = ST_SENSOR_HASH_LEN + 1;

        if (kRetOk != SetHashWithB64Encode(response.hash, sizeof(response.hash),
                                           s_chips[no].firmware_hash, &outsize)) {
            SYSAPP_ERR("s_sensor.firmware_hash invalid outsize=%zu", outsize);
            s_chips[no].firmware_hash[0] = '\0';
            ret = kRetFailed;
            firmware_error = true;
        }

        len = snprintf(s_chips[no].update_date_firmware, sizeof(s_chips[no].update_date_firmware),
                       "%s", response.last_update);

        if ((len < 0) || (len > ST_PROCESSOR_LOADER_UPDATE_DATE_LEN)) {
            SYSAPP_ERR("Num of char in sensor.update_date_firmware is incorrect=%d", len);
            s_chips[no].update_date_firmware[0] = '\0';
            ret = kRetFailed;
            firmware_error = true;
        }
    }

    // Update "AI-ISP" for firmware version from senscord only when failed to get from FwManager.

    if (firmware_error) {
        ret = GetSensorFirmwareVersion(s_chips[no].firmware_version,
                                       sizeof(s_chips[no].firmware_version));

        if (ret != kRetOk) {
            s_chips[no].firmware_version[0] = '\0';
        }
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateReadoutAiModels(void)
{
    RetCode ret = kRetOk;
    int len = 0;

    // Get information for sensor.

    EsfFwMgrGetInfoData info;
    EsfFwMgrGetInfoResponse *response = NULL;
    EsfFwMgrResult res;

    size_t bsize = sizeof(EsfFwMgrGetInfoResponse) * ST_AIMODELS_NUM;

    response = (EsfFwMgrGetInfoResponse *)malloc(bsize);

    if (response == NULL) {
        SYSAPP_ERR("malloc");
        ret = kRetMemoryError;
        goto exit;
    }

    // Clear

    memset(&info, 0, sizeof(info));
    memset(response, 0, bsize);

    for (uint32_t slot = 0; slot < ST_AIMODELS_NUM; slot++) {
        s_ai_model[slot].version[0] = '\0';
        s_ai_model[slot].hash[0] = '\0';
        s_ai_model[slot].update_date[0] = '\0';
    }

    // Get sensor loader info.

    info.target = kEsfFwMgrTargetAIModel;
    info.in_length = ST_AIMODELS_NUM;
    info.response = response;
    info.out_length = 0;

    res = EsfFwMgrGetInfo(&info);

    if (res != kEsfFwMgrResultOk) {
        SYSAPP_ERR("EsfFwMgrGetInfo=%d", res);
        ret = kRetFailed;
        goto exit;
    }

    for (uint32_t slot = 0; slot < ST_AIMODELS_NUM; slot++) {
        // Get information for name.
        // TODO:
        // Since ESF is not supported, the current value is fixed.

        if (response[slot].version[0] == '\0') {
            /* Due to the specifications of FirmwareManager,
       * if there is no version, there is no AI model. */

            continue;
        }

        // Get information for version.

        len = snprintf(s_ai_model[slot].version, sizeof(s_ai_model[slot].version), "%s",
                       response[slot].version);

        if ((len < 0) || (len > ST_AIMODEL_VERSION_LEN)) {
            SYSAPP_ERR("Num of char in ai_model.version is incorrect=%d", len);
            s_ai_model[slot].version[0] = '\0';
            ret = kRetFailed;
        }

        // Get information for hash.

        size_t outsize = ST_AIMODEL_HASH_LEN + 1;

        if (kRetOk != SetHashWithB64Encode(response[slot].hash, sizeof(response[slot].hash),
                                           s_ai_model[slot].hash, &outsize)) {
            SYSAPP_ERR("ai_model.hash invalid outsize=%zu", outsize);
            s_ai_model[slot].hash[0] = '\0';
            ret = kRetFailed;
        }

        // Get information for update_date.

        len = snprintf(s_ai_model[slot].update_date, sizeof(s_ai_model[slot].update_date), "%s",
                       response[slot].last_update);

        if ((len < 0) || (len > ST_AIMODEL_UPDATE_DATE_LEN)) {
            SYSAPP_ERR("Num of char in ai_model.update_date is incorrect=%d", len);
            s_ai_model[slot].update_date[0] = '\0';
            ret = kRetFailed;
        }
    }

exit:
    /* Clean up */

    if (response) {
        free(response);
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateReadoutDeviceInfo(void)
{
    RetCode ret = kRetOk;

    // Get information for device manifest.

    EsfSystemManagerResult sysmng_ret;
    size_t md_size = sizeof(s_device_info.device_manifest);

    sysmng_ret = EsfSystemManagerGetDeviceManifest(s_device_info.device_manifest, &md_size);
    if (sysmng_ret != kEsfSystemManagerResultOk) {
        s_device_info.device_manifest[0] = '\0';
    }

    // Get information for chips[].

    ret = SysAppStateReadoutChips();

    if (ret != kRetOk) {
        SYSAPP_WARN("SysAppStateReadoutChips() ret %d", ret);
    }

    // Get information for ai_models[].

    ret = SysAppStateReadoutAiModels();

    if (ret != kRetOk) {
        SYSAPP_WARN("SysAppStateReadoutAiModels() ret %d", ret);
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateReadoutDeviceCapabilities(void)
{
    RetCode ret = kRetOk;

#if 1 /** T5 24/8/E release, fixed value. */
    s_device_capabilities.is_battery_supported = false;
    s_device_capabilities.supported_wireless_mode = WirelessModeStaAp;
    s_device_capabilities.is_periodic_supported = false;
#else
    // Get information for is_battery_supported.

#if defined(CONFIG_ESP32_BATTERY_INFO)
    s_device_capabilities.is_battery_supported = true;
#else  /* defined(CONFIG_ESP32_BATTERY_INFO) */
    s_device_capabilities.is_battery_supported = false;
#endif /* defined(CONFIG_ESP32_BATTERY_INFO) */

    // Get information for supported_wireless_mode.

#if defined(CONFIG_BOARD_POE_ES)          /** Case T3P. */
    s_device_capabilities.supported_wireless_mode = WirelessModeAp;
#elif defined(CONFIG_BOARD_WIFI_SMALL_ES) /** Case T3Ws. */
    s_device_capabilities.supported_wireless_mode = WirelessModeStaAp;
#else                                     /** There is no case which builds this code. */
    s_device_capabilities.supported_wireless_mode = WirelessModeNone;
#endif

    // Get information for is_periodic_supported.

#if defined(CONFIG_INTERMITTENT_ENABLE)
    s_device_capabilities.is_periodic_supported = true;
#else  /* defined(CONFIG_INTERMITTENT_ENABLE) */
    s_device_capabilities.is_periodic_supported = false;
#endif /* defined(CONFIG_INTERMITTENT_ENABLE) */
#endif

    // Get information for is_sensor_postprocess_supported.

    s_device_capabilities.is_sensor_postprocess_supported = GetSensorPostProcessSupported();

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateReadoutPowerStates(void)
{
    RetCode ret = kRetOk;

    // Get information for power_source.

    s_power_states.source[0].type =
        GetPowerSupplyType(); //TODO: Array should be list of power supply.

    // Get information for power_level.

    s_power_states.source[0].level = POWER_LEVEL;

    // Get information for in_use.

    s_power_states.in_use = GetPowerSupplyType();

    // Get information for is_battery_low.

    s_power_states.is_battery_low = false;

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateReadoutDeviceStates(void)
{
    RetCode ret = kRetOk;

    // Get information for power_states.

    ret = SysAppStateReadoutPowerStates();

    if (ret != kRetOk) {
        SYSAPP_WARN("SysAppStateReadoutDeviceStates() ret %d", ret);
    }

    // Get information for process_state.T.B.D

    snprintf(s_device_states.process_state, sizeof(s_device_states.process_state), "Idle");

    // Get information for hours_meter.

    s_device_states.hours_meter = GetSensorHoursMeter();

    ret = SysAppTimerStartTimer(HoursMeterIntervalTimer, 3600, HoursMeterUpdateIntervalCallback);

    if (ret != kRetOk) {
        SYSAPP_WARN("SysAppTimerStartTimer() failed %d", ret);
    }

    // Get information for bootup_reason. T.B.D

#if 0
  SsfPwrMgrError ssfpm_ret = kSsfPwrMgrOk;
  SsfPwrMgrBootCause boot_cause;

  ssfpm_ret = SsfPwrMgrGetBootCause(&boot_cause);

  if (ssfpm_ret == kSsfPwrMgrOk) {
    s_device_states.bootup_reason = boot_cause;
  } else {
    s_device_states.bootup_reason = 0;
  }
#else
    s_device_states.bootup_reason = BOOTUP_REASON;
#endif

    // Get information for last_bootup_time.

#ifdef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    struct timespec ts = {0};

    int cgret = clock_gettime(CLOCK_REALTIME, &ts);

    if (cgret == 0) {
        struct tm ctime = {0};
        localtime_r(&ts.tv_sec, &ctime);

        snprintf(s_device_states.last_bootup_time, sizeof(s_device_states.last_bootup_time),
                 "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ", ctime.tm_year + 1900, ctime.tm_mon + 1,
                 ctime.tm_mday, ctime.tm_hour, ctime.tm_min, ctime.tm_sec, ts.tv_nsec / 1000000);
    }
    else {
        SYSAPP_ERR("clock_gettime() failed %d", cgret);

        snprintf(s_device_states.last_bootup_time, sizeof(s_device_states.last_bootup_time),
                 "1970-01-01T00:00:00.000Z");
    }
#else  // !CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    snprintf(s_device_states.last_bootup_time, sizeof(s_device_states.last_bootup_time),
             "0000-00-00T00:00:00.000Z");
#endif // CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION

    return ret;
}

#if 0 // For_Coverity_Disable_SysAppStateReadoutReserved
/*----------------------------------------------------------------------------*/
RetCode SysAppStateReadoutReserved(void) {
  RetCode ret = kRetOk;

  return ret;
}
#endif

/*----------------------------------------------------------------------------*/
RetCode SysAppStateReadoutLog(void)
{
    RetCode ret = kRetOk;

    // SystemApp log.

    ReadOutLogSystemApp();

    // Sensor log.

    ReadOutLogSensor();

    // CompanionFw log.

    ReadOutLogCompanionFw();

    // CompanionApp log.

    ReadOutLogCompanionApp();

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateReadoutSystemSettings(void)
{
    RetCode ret = kRetOk;

    // Get information for led_enabled.

    bool led_val = true;

    RetCode ledret = SysAppLedGetEnable(&led_val);

    if (ledret == kRetOk) {
        s_system_settings.led_enabled = led_val;
    }
    else {
        SYSAPP_WARN("SysAppLedGetEnable() failed %d", ledret);
        s_system_settings.led_enabled = true;
    }

    // Get information for temperature_update_interval.

    s_system_settings.temperature_update_interval = DEFAULT_UPDATE_INTERVAL_SEC;

    ret = SysAppTimerStartTimer(SensorTempIntervalTimer,
                                s_system_settings.temperature_update_interval,
                                SensorTempUpdateIntervalCallback);

    if (ret != kRetOk) {
        SYSAPP_WARN("SysAppTimerStartTimer() failed %d", ret);
    }

    // Get information for log_settings.

    SysAppStateReadoutLog();

    // Set send request.

    RequestConfigStateUpdate(ST_TOPIC_SYSTEM_SETTINGS);

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateReadoutStaticSettingsIPv6(void)
{
    RetCode ret = kRetOk;
    EsfNetworkManagerResult esfnm_ret = kEsfNetworkManagerResultSuccess;
    EsfNetworkManagerParameterMask esfnm_mask = {0};
    EsfNetworkManagerParameter esfnm_param = {0};
    int len = 0;

    // Get information for ip_address.

    memset(&esfnm_mask, 0, sizeof(esfnm_mask));
    esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    esfnm_ret = EsfNetworkManagerLoadParameter(&esfnm_mask, &esfnm_param);

    if (esfnm_ret == kEsfNetworkManagerResultSuccess) {
        len = snprintf(s_static_settings_ipv6.ip_address, sizeof(s_static_settings_ipv6.ip_address),
                       "%s", esfnm_param.normal_mode.dev_ip_v6.ip);

        if ((len < 0) || (len > CFGST_NETOWRK_IP_ADDRESS_LEN)) {
            s_static_settings_ipv6.ip_address[0] = '\0';
            ret = kRetFailed;
        }
    }
    else {
        SYSAPP_WARN("EsfNetworkManagerLoadParameter(ip_address) failed %d", esfnm_ret);
        s_static_settings_ipv6.ip_address[0] = '\0';
        ret = kRetFailed;
    }

    // Get information for subnet_mask.

    memset(&esfnm_mask, 0, sizeof(esfnm_mask));
    esfnm_mask.normal_mode.dev_ip_v6.subnet_mask = 1;
    esfnm_ret = EsfNetworkManagerLoadParameter(&esfnm_mask, &esfnm_param);

    if (esfnm_ret == kEsfNetworkManagerResultSuccess) {
        len = snprintf(s_static_settings_ipv6.subnet_mask,
                       sizeof(s_static_settings_ipv6.subnet_mask), "%s",
                       esfnm_param.normal_mode.dev_ip_v6.subnet_mask);

        if ((len < 0) || (len > CFGST_NETOWRK_SUBNET_MASK_LEN)) {
            s_static_settings_ipv6.subnet_mask[0] = '\0';
            ret = kRetFailed;
        }
    }
    else {
        SYSAPP_WARN("EsfNetworkManagerLoadParameter(subnet_mask) failed %d", esfnm_ret);
        s_static_settings_ipv6.subnet_mask[0] = '\0';
        ret = kRetFailed;
    }

    // Get information for gateway_address.

    memset(&esfnm_mask, 0, sizeof(esfnm_mask));
    esfnm_mask.normal_mode.dev_ip_v6.gateway = 1;
    esfnm_ret = EsfNetworkManagerLoadParameter(&esfnm_mask, &esfnm_param);

    if (esfnm_ret == kEsfNetworkManagerResultSuccess) {
        len = snprintf(s_static_settings_ipv6.gateway_address,
                       sizeof(s_static_settings_ipv6.gateway_address), "%s",
                       esfnm_param.normal_mode.dev_ip_v6.gateway);

        if ((len < 0) || (len > CFGST_NETOWRK_GATEWAY_ADDRESS_LEN)) {
            s_static_settings_ipv6.gateway_address[0] = '\0';
            ret = kRetFailed;
        }
    }
    else {
        SYSAPP_WARN("EsfNetworkManagerLoadParameter(gateway_address) failed %d", esfnm_ret);
        s_static_settings_ipv6.gateway_address[0] = '\0';
        ret = kRetFailed;
    }

    // Get information for dns_address.

    memset(&esfnm_mask, 0, sizeof(esfnm_mask));
    esfnm_mask.normal_mode.dev_ip_v6.dns = 1;
    esfnm_ret = EsfNetworkManagerLoadParameter(&esfnm_mask, &esfnm_param);

    if (esfnm_ret == kEsfNetworkManagerResultSuccess) {
        len = snprintf(s_static_settings_ipv6.dns_address,
                       sizeof(s_static_settings_ipv6.dns_address), "%s",
                       esfnm_param.normal_mode.dev_ip_v6.dns);

        if ((len < 0) || (len > CFGST_NETOWRK_DNS_ADDRESS_LEN)) {
            s_static_settings_ipv6.dns_address[0] = '\0';
            ret = kRetFailed;
        }
    }
    else {
        SYSAPP_WARN("EsfNetworkManagerLoadParameter(dns_address) failed %d", esfnm_ret);
        s_static_settings_ipv6.dns_address[0] = '\0';
        ret = kRetFailed;
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateReadoutStaticSettingsIPv4(void)
{
    RetCode ret = kRetOk;
    EsfNetworkManagerResult esfnm_ret = kEsfNetworkManagerResultSuccess;
    EsfNetworkManagerParameterMask esfnm_mask = {0};
    EsfNetworkManagerParameter esfnm_param = {0};
    int len = 0;

    // Get information for ip_address.

    memset(&esfnm_mask, 0, sizeof(esfnm_mask));
    esfnm_mask.normal_mode.dev_ip.ip = 1;
    esfnm_ret = EsfNetworkManagerLoadParameter(&esfnm_mask, &esfnm_param);

    if (esfnm_ret == kEsfNetworkManagerResultSuccess) {
        len = snprintf(s_static_settings_ipv4.ip_address, sizeof(s_static_settings_ipv4.ip_address),
                       "%s", esfnm_param.normal_mode.dev_ip.ip);

        if ((len < 0) || (len > CFGST_NETOWRK_IP_ADDRESS_LEN)) {
            s_static_settings_ipv4.ip_address[0] = '\0';
            ret = kRetFailed;
        }
    }
    else {
        SYSAPP_WARN("EsfNetworkManagerLoadParameter(ip_address) failed %d", esfnm_ret);
        s_static_settings_ipv4.ip_address[0] = '\0';
        ret = kRetFailed;
    }

    // Get information for subnet_mask.

    memset(&esfnm_mask, 0, sizeof(esfnm_mask));
    esfnm_mask.normal_mode.dev_ip.subnet_mask = 1;
    esfnm_ret = EsfNetworkManagerLoadParameter(&esfnm_mask, &esfnm_param);

    if (esfnm_ret == kEsfNetworkManagerResultSuccess) {
        len = snprintf(s_static_settings_ipv4.subnet_mask,
                       sizeof(s_static_settings_ipv4.subnet_mask), "%s",
                       esfnm_param.normal_mode.dev_ip.subnet_mask);

        if ((len < 0) || (len > CFGST_NETOWRK_SUBNET_MASK_LEN)) {
            s_static_settings_ipv4.subnet_mask[0] = '\0';
            ret = kRetFailed;
        }
    }
    else {
        SYSAPP_WARN("EsfNetworkManagerLoadParameter(subnet_mask) failed %d", esfnm_ret);
        s_static_settings_ipv4.subnet_mask[0] = '\0';
        ret = kRetFailed;
    }

    // Get information for gateway_address.

    memset(&esfnm_mask, 0, sizeof(esfnm_mask));
    esfnm_mask.normal_mode.dev_ip.gateway = 1;
    esfnm_ret = EsfNetworkManagerLoadParameter(&esfnm_mask, &esfnm_param);

    if (esfnm_ret == kEsfNetworkManagerResultSuccess) {
        len = snprintf(s_static_settings_ipv4.gateway_address,
                       sizeof(s_static_settings_ipv4.gateway_address), "%s",
                       esfnm_param.normal_mode.dev_ip.gateway);

        if ((len < 0) || (len > CFGST_NETOWRK_GATEWAY_ADDRESS_LEN)) {
            s_static_settings_ipv4.gateway_address[0] = '\0';
            ret = kRetFailed;
        }
    }
    else {
        SYSAPP_WARN("EsfNetworkManagerLoadParameter(gateway_address) failed %d", esfnm_ret);
        s_static_settings_ipv4.gateway_address[0] = '\0';
        ret = kRetFailed;
    }

    // Get information for dns_address.

    memset(&esfnm_mask, 0, sizeof(esfnm_mask));
    esfnm_mask.normal_mode.dev_ip.dns = 1;
    esfnm_ret = EsfNetworkManagerLoadParameter(&esfnm_mask, &esfnm_param);

    if (esfnm_ret == kEsfNetworkManagerResultSuccess) {
        len = snprintf(s_static_settings_ipv4.dns_address,
                       sizeof(s_static_settings_ipv4.dns_address), "%s",
                       esfnm_param.normal_mode.dev_ip.dns);

        if ((len < 0) || (len > CFGST_NETOWRK_DNS_ADDRESS_LEN)) {
            s_static_settings_ipv4.dns_address[0] = '\0';
            ret = kRetFailed;
        }
    }
    else {
        SYSAPP_WARN("EsfNetworkManagerLoadParameter(dns_address) failed %d", esfnm_ret);
        s_static_settings_ipv4.dns_address[0] = '\0';
        ret = kRetFailed;
    }

    // Get information for dns2_address.

    memset(&esfnm_mask, 0, sizeof(esfnm_mask));
    esfnm_mask.normal_mode.dev_ip.dns2 = 1;
    esfnm_ret = EsfNetworkManagerLoadParameter(&esfnm_mask, &esfnm_param);

    if (esfnm_ret == kEsfNetworkManagerResultSuccess) {
        len = snprintf(s_static_settings_ipv4.dns2_address,
                       sizeof(s_static_settings_ipv4.dns2_address), "%.*s",
                       CFGST_NETOWRK_DNS2_ADDRESS_LEN, esfnm_param.normal_mode.dev_ip.dns2);

        if ((len < 0) || (len > CFGST_NETOWRK_DNS2_ADDRESS_LEN)) {
            s_static_settings_ipv4.dns2_address[0] = '\0';
            ret = kRetFailed;
        }
    }
    else {
        SYSAPP_WARN("EsfNetworkManagerLoadParameter(dns2_address) failed %d", esfnm_ret);
        s_static_settings_ipv4.dns2_address[0] = '\0';
        ret = kRetFailed;
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateReadoutProxySettings(void)
{
    RetCode ret = kRetOk;
    EsfNetworkManagerResult esfnm_ret = kEsfNetworkManagerResultSuccess;
    EsfNetworkManagerParameterMask esfnm_mask = {0};
    EsfNetworkManagerParameter esfnm_param = {0};
    int len = 0;

    // Get information for proxy_url.

    memset(&esfnm_mask, 0, sizeof(esfnm_mask));
    esfnm_mask.proxy.url = 1;
    esfnm_ret = EsfNetworkManagerLoadParameter(&esfnm_mask, &esfnm_param);

    if (esfnm_ret == kEsfNetworkManagerResultSuccess) {
        len = snprintf(s_proxy_settings.proxy_url, sizeof(s_proxy_settings.proxy_url), "%s",
                       esfnm_param.proxy.url);

        if ((len < 0) || (len > CFGST_NETWORK_PROXY_URL_LEN)) {
            s_proxy_settings.proxy_url[0] = '\0';
            ret = kRetFailed;
        }
    }
    else {
        SYSAPP_WARN("EsfNetworkManagerLoadParameter(proxy_url) failed %d", esfnm_ret);
        s_proxy_settings.proxy_url[0] = '\0';
        ret = kRetFailed;
    }

    // Get information for proxy_port.

    memset(&esfnm_mask, 0, sizeof(esfnm_mask));
    esfnm_mask.proxy.port = 1;
    esfnm_ret = EsfNetworkManagerLoadParameter(&esfnm_mask, &esfnm_param);

    if (esfnm_ret == kEsfNetworkManagerResultSuccess) {
        s_proxy_settings.proxy_port = esfnm_param.proxy.port;

        if ((s_proxy_settings.proxy_port < 0) || (s_proxy_settings.proxy_port > 65535)) {
            s_proxy_settings.proxy_port = 0;
            ret = kRetFailed;
        }
    }
    else {
        SYSAPP_WARN("EsfNetworkManagerLoadParameter(proxy_port) failed %d", esfnm_ret);
        s_proxy_settings.proxy_port = 0;
        ret = kRetFailed;
    }

    // Get information for proxy_user_name.

    memset(&esfnm_mask, 0, sizeof(esfnm_mask));
    esfnm_mask.proxy.username = 1;
    esfnm_ret = EsfNetworkManagerLoadParameter(&esfnm_mask, &esfnm_param);

    if (esfnm_ret == kEsfNetworkManagerResultSuccess) {
        len = snprintf(s_proxy_settings.proxy_user_name, sizeof(s_proxy_settings.proxy_user_name),
                       "%s", esfnm_param.proxy.username);

        if ((len < 0) || (len > CFGST_NETWORK_PROXY_USER_NAME_LEN)) {
            s_proxy_settings.proxy_user_name[0] = '\0';
            ret = kRetFailed;
        }
    }
    else {
        SYSAPP_WARN("EsfNetworkManagerLoadParameter(proxy_user_name) failed %d", esfnm_ret);
        s_proxy_settings.proxy_user_name[0] = '\0';
        ret = kRetFailed;
    }

    // Get information for proxy_password.

    memset(&esfnm_mask, 0, sizeof(esfnm_mask));
    esfnm_mask.proxy.password = 1;
    esfnm_ret = EsfNetworkManagerLoadParameter(&esfnm_mask, &esfnm_param);

    if (esfnm_ret == kEsfNetworkManagerResultSuccess) {
        len = snprintf(s_proxy_settings.proxy_password, sizeof(s_proxy_settings.proxy_password),
                       "%s", esfnm_param.proxy.password);

        if ((len < 0) || (len > CFGST_NETWORK_PROXY_PASSWORD_LEN)) {
            s_proxy_settings.proxy_password[0] = '\0';
            ret = kRetFailed;
        }
    }
    else {
        SYSAPP_WARN("EsfNetworkManagerLoadParameter(proxy_password) failed %d", esfnm_ret);
        s_proxy_settings.proxy_password[0] = '\0';
        ret = kRetFailed;
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateReadoutNetworkSettings(void)
{
    RetCode ret = kRetOk;
    EsfNetworkManagerResult esfnm_ret = kEsfNetworkManagerResultSuccess;
    EsfNetworkManagerParameterMask esfnm_mask = {0};
    EsfNetworkManagerParameter esfnm_param = {0};
    int len = 0;

    // Get information for ip_method.

    memset(&esfnm_mask, 0, sizeof(esfnm_mask));
    esfnm_mask.normal_mode.ip_method = 1;
    esfnm_ret = EsfNetworkManagerLoadParameter(&esfnm_mask, &esfnm_param);

    if (esfnm_ret == kEsfNetworkManagerResultSuccess) {
        s_network_settings.ip_method = esfnm_param.normal_mode.ip_method;

        if ((esfnm_param.normal_mode.ip_method < 0) || (esfnm_param.normal_mode.ip_method > 1)) {
            s_network_settings.ip_method = 0;
            ret = kRetFailed;
        }
    }
    else {
        SYSAPP_WARN("EsfNetworkManagerLoadParameter(ip_method) failed %d", esfnm_ret);
        s_network_settings.ip_method = 0;
        ret = kRetFailed;
    }

    // Get information for ntp_url.

    EsfClockManagerParams cm_param = {0};

    EsfClockManagerReturnValue esfcm_ret = EsfClockManagerGetParams(&cm_param);

    if (esfcm_ret == kClockManagerSuccess) {
        len = snprintf(s_network_settings.ntp_url, sizeof(s_network_settings.ntp_url), "%.253s",
                       cm_param.connect.hostname);

        if ((len < 0) || (len > CFGST_NETOWRK_NTP_URL_LEN)) {
            s_network_settings.ntp_url[0] = '\0';
            ret = kRetFailed;
        }

        len = snprintf(s_network_settings.ntp2_url, sizeof(s_network_settings.ntp2_url), "%.253s",
                       cm_param.connect.hostname2);

        if ((len < 0) || (len > CFGST_NETOWRK_NTP_URL_LEN)) {
            s_network_settings.ntp2_url[0] = '\0';
            ret = kRetFailed;
        }
    }
    else {
        SYSAPP_WARN("EsfClockManagerGetParams() failed %d", esfcm_ret);
        s_network_settings.ntp_url[0] = '\0';
        s_network_settings.ntp2_url[0] = '\0';
        ret = kRetFailed;
    }

    // Get information for static_settings_ipv6.

    SysAppStateReadoutStaticSettingsIPv6();

    // Get information for static_settings_ipv4.

    SysAppStateReadoutStaticSettingsIPv4();

    // Get information for proxy_settings.

    SysAppStateReadoutProxySettings();

    // Set send request.

    RequestConfigStateUpdate(ST_TOPIC_NETWORK_SETTINGS);

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateReadoutStaModeSetting(void)
{
    RetCode ret = kRetOk;
    EsfNetworkManagerResult esfnm_ret = kEsfNetworkManagerResultSuccess;
    EsfNetworkManagerParameterMask esfnm_mask = {0};
    EsfNetworkManagerParameter esfnm_param = {0};
    int len = 0;

    // Get information for ssid.

    memset(&esfnm_mask, 0, sizeof(esfnm_mask));
    esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    esfnm_ret = EsfNetworkManagerLoadParameter(&esfnm_mask, &esfnm_param);

    if (esfnm_ret == kEsfNetworkManagerResultSuccess) {
        len = snprintf(s_sta_mode_setting.ssid, sizeof(s_sta_mode_setting.ssid), "%s",
                       esfnm_param.normal_mode.wifi_sta.ssid);

        if ((len < 0) || (len > CFGST_WIRELESS_STA_SSID_LEN)) {
            s_sta_mode_setting.ssid[0] = '\0';
            ret = kRetFailed;
        }
    }
    else {
        SYSAPP_WARN("EsfNetworkManagerLoadParameter(wifi_sta.ssid) failed %d", esfnm_ret);
        s_sta_mode_setting.ssid[0] = '\0';
        ret = kRetFailed;
    }

    // Get information for password.

    memset(&esfnm_mask, 0, sizeof(esfnm_mask));
    esfnm_mask.normal_mode.wifi_sta.password = 1;
    esfnm_ret = EsfNetworkManagerLoadParameter(&esfnm_mask, &esfnm_param);

    if (esfnm_ret == kEsfNetworkManagerResultSuccess) {
        len = snprintf(s_sta_mode_setting.password, sizeof(s_sta_mode_setting.password), "%.32s",
                       esfnm_param.normal_mode.wifi_sta.password);

        if ((len < 0) || (len > CFGST_WIRELESS_STA_PASSWORD_LEN)) {
            s_sta_mode_setting.password[0] = '\0';
            ret = kRetFailed;
        }
    }
    else {
        SYSAPP_WARN("EsfNetworkManagerLoadParameter(wifi_sta.password) failed %d", esfnm_ret);
        s_sta_mode_setting.password[0] = '\0';
        ret = kRetFailed;
    }

    // Get information for encryption;

    memset(&esfnm_mask, 0, sizeof(esfnm_mask));
    esfnm_mask.normal_mode.wifi_sta.encryption = 1;
    esfnm_ret = EsfNetworkManagerLoadParameter(&esfnm_mask, &esfnm_param);

    if (esfnm_ret == kEsfNetworkManagerResultSuccess) {
        s_sta_mode_setting.encryption = esfnm_param.normal_mode.wifi_sta.encryption;

        if ((esfnm_param.normal_mode.wifi_sta.encryption < EncWpa2Psk) ||
            (esfnm_param.normal_mode.wifi_sta.encryption >= WirelessEncryptionNum)) {
            s_sta_mode_setting.encryption = EncWpa2Psk;
            ret = kRetFailed;
        }
    }
    else {
        SYSAPP_WARN("EsfNetworkManagerLoadParameter(wifi_sta.encryption) failed %d", esfnm_ret);
        s_sta_mode_setting.encryption = EncWpa2Psk;
        ret = kRetFailed;
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateReadoutWirelessSetting(void)
{
    RetCode ret = kRetOk;

    // Get information for sta_mode_setting.

    SysAppStateReadoutStaModeSetting();

    // Set send request.

    RequestConfigStateUpdate(ST_TOPIC_WIRELESS_SETTING);

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateReadoutPeriodicSetting(void)
{
    RetCode ret = kRetOk;

    // Set send request.

    RequestConfigStateUpdate(ST_TOPIC_PERIODIC_SETTING);

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateReadoutEndpointSettings(void)
{
    RetCode ret = kRetOk;
    EsfSystemManagerResult esfsm_ret;
    int len = 0;

    // Allocate working memory

    size_t endp_host_buf_size = ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE;
    size_t endp_port_buf_size = ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE;

    char *endpoint_url = (char *)malloc(endp_host_buf_size);
    char *endpoint_port = (char *)malloc(endp_port_buf_size);

    if ((endpoint_url == NULL) || (endpoint_port == NULL)) {
        SYSAPP_ERR("malloc");
        free(endpoint_url);
        free(endpoint_port);
        s_endpoint_settings.endpoint_url[0] = '\0';
        s_endpoint_settings.endpoint_port = 0;
        return kRetMemoryError;
    }

    // Get information for endpoint_url.

    esfsm_ret = EsfSystemManagerGetEvpHubUrl(endpoint_url, &endp_host_buf_size);

    if (esfsm_ret == kEsfSystemManagerResultOk) {
        len = snprintf(s_endpoint_settings.endpoint_url, sizeof(s_endpoint_settings.endpoint_url),
                       "%s", endpoint_url);

        if ((len < 0) || (len > CFGST_ENDPOINT_DOMAIN_LEN_MAX)) {
            s_endpoint_settings.endpoint_url[0] = '\0';
            ret = kRetFailed;
        }
    }
    else {
        SYSAPP_WARN("EsfSystemManagerGetEvpHubUrl failed %d", esfsm_ret);
        s_endpoint_settings.endpoint_url[0] = '\0';
        ret = kRetFailed;
    }

    // Get information for endpoint_port.
    esfsm_ret = EsfSystemManagerGetEvpHubPort(endpoint_port, &endp_port_buf_size);

    if (esfsm_ret == kEsfSystemManagerResultOk) {
        s_endpoint_settings.endpoint_port = (int)strtol(endpoint_port, NULL, 10);
    }
    else {
        SYSAPP_WARN("EsfSystemManagerGetEvpHubPort failed %d", esfsm_ret);
        s_endpoint_settings.endpoint_port = 0;
        ret = kRetFailed;
    }

    free(endpoint_url);
    free(endpoint_port);

    // Get information for protocol_version.
    // This field has a fixed value of "TB".

    snprintf(s_endpoint_settings.protocol_version, sizeof(s_endpoint_settings.protocol_version),
             "TB");

    // Set send request.

    RequestConfigStateUpdate(ST_TOPIC_ENDPOINT_SETTINGS);

    return ret;
}

#if defined(CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING)
/*----------------------------------------------------------------------------*/
RetCode SysAppStateReadoutStreamingSettings(void)
{
    RetCode ret = kRetOk;

    // Start streaming settings update interval timer

    ret = SysAppTimerStartTimer(StreamingSettingsIntervalTimer, DEFAULT_UPDATE_INTERVAL_SEC,
                                StreamingSettingsUpdateIntervalCallback);

    if (ret != kRetOk) {
        SYSAPP_WARN("SysAppTimerStartTimer() failed %d", ret);
    }

    // Set send request.

    RequestConfigStateUpdate(ST_TOPIC_STREAMING_SETTINGS);

    return ret;
}
#endif /* CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING */

/*----------------------------------------------------------------------*/
char *SysAppStateGetReqId(uint32_t topic)
{
    char *ret = NULL;

    if (topic == ST_TOPIC_DEVICE_STATES) {
    }
    else if (topic == ST_TOPIC_SYSTEM_SETTINGS) {
        ret = &(s_system_settings.id[0]);
    }
    else if (topic == ST_TOPIC_NETWORK_SETTINGS) {
        ret = &(s_network_settings.id[0]);
    }
    else if (topic == ST_TOPIC_WIRELESS_SETTING) {
        ret = &(s_wireless_setting.id[0]);
    }
    else if (topic == ST_TOPIC_PERIODIC_SETTING) {
        ret = &(s_periodic_setting.id[0]);
    }
    else if (topic == ST_TOPIC_ENDPOINT_SETTINGS) {
        ret = &(s_endpoint_settings.id[0]);
    }
    else if (topic == ST_TOPIC_UPLOAD_SENSOR_CALIBRATION_PARAM) {
    }
    else if (topic == ST_TOPIC_DEPLOY_FIRMWARE) {
    }
    else if (topic == ST_TOPIC_DEPLOY_AI_MODEL) {
    }
    else if (topic == ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM) {
    }
    else {
    }

    return ret;
}

/*----------------------------------------------------------------------*/
void SysAppStateGetTemperatureUpdateInterval(int *temperature_update_interval)
{
    *temperature_update_interval = s_system_settings.temperature_update_interval;
}

/*----------------------------------------------------------------------*/
char *SysAppStateGetProtocolVersion(void)
{
    return &(s_endpoint_settings.protocol_version[0]);
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateSendState(uint32_t req)
{
    RetCode ret = kRetOk;

    ret = SendState(req);

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStaReopenIfClose(void)
{
    if (s_sccore == 0) {
        SYSAPP_ERR("Not senscord_core_init");
        return kRetFailed;
    }

    if (s_scstream) {
        SYSAPP_ERR("Now open");
        return kRetOk;
    }

    SYSAPP_INFO("senscord_core_open_stream");

    int32_t sc_ret = senscord_core_open_stream(s_sccore, "inference_stream", &s_scstream);
    if (sc_ret < 0) {
        SYSAPP_ERR("senscord_core_open_stream() ret %d", sc_ret);
        s_scstream = 0;
        return kRetFailed;
    }

    return kRetOk;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStaClose(void)
{
    // Lock.

    RetCode ret = kRetOk;
    int lock_ret = pthread_mutex_lock(&s_senscord_access_mutex);

    if (lock_ret != 0) {
        SYSAPP_ERR("pthread_mutex_lock");
        return kRetFailed;
    }

    // Close sescord stream.

    if (s_sccore == 0) {
        SYSAPP_ERR("Not senscord_core_init");
        ret = kRetFailed;
        goto func_exit;
    }

    if (s_scstream == 0) {
        SYSAPP_WARN("Now close");
        ret = kRetFailed;
        goto func_exit;
    }

    SYSAPP_INFO("senscord_core_close_stream");

    int32_t sc_ret = senscord_core_close_stream(s_sccore, s_scstream);

    if (sc_ret < 0) {
        SYSAPP_ERR("senscord_core_open_stream() ret %d", sc_ret);
        ret = kRetFailed;
        goto func_exit;
    }

    s_scstream = 0;

func_exit:

    // Unlock.

    pthread_mutex_unlock(&s_senscord_access_mutex);

    return ret;
}

/*----------------------------------------------------------------------------*/
bool SysAppStaIsStateQueueEmpty(void)
{
    // T.B.D DCS does not have a CB func, so Can't do same chack.
    SYSAPP_INFO("Wait for state queue empty");
    return true;
}

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
/*----------------------------------------------------------------------------*/
bool SysAppStateIsUnimplementedTopic(const char *topic)
{
    bool ret = false;

    for (size_t i = 0; i < ARRAY_SIZE(s_unimplemented_list); i++) {
        if (strcmp(s_unimplemented_list[i].topic_str, topic) == 0) {
            ret = true;
            break;
        }
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppStateSendUnimplementedState(const char *topic, const char *id)
{
    RetCode ret = kRetOk;

    for (size_t i = 0; i < ARRAY_SIZE(s_unimplemented_list); i++) {
        if (strcmp(s_unimplemented_list[i].topic_str, topic) == 0) {
            // Save last req_id/res_id.
            snprintf(s_unimplemented_list[i].id, sizeof(s_unimplemented_list[i].id), "%s", id);

            // Send "unimplemented" error state.
            ret = SendUnimplementedState(s_unimplemented_list[i].topic_str,
                                         s_unimplemented_list[i].id);
            break;
        }
    }

    return ret;
}
#endif // !CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
