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

#if defined(__NuttX__)
#include <nuttx/config.h>
#endif

#include "evp/sdk_sys.h"
#include "led_manager.h"
#include "power_manager.h"
#include "system_manager.h"
#include "clock_manager.h"
#include "clock_manager_setting.h"
#include "firmware_manager.h"
#include "senscord/c_api/senscord_c_api.h"
#include "senscord/inference_stream/c_api/property_c_types.h"
#include "system_app_common.h"
#include "system_app_state.h"
#include "system_app_log.h"
#include "base64/include/base64.h"
#include "system_app_timer.h"
#include "sensor_main.h"

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

typedef struct {
    int flag_value;
    const char *message;
} ErrorFlag;

extern struct SYS_client *s_sys_client;

extern SsfDeviceSettingHandle s_ssfds_handle;

extern StDeviceInfoParams s_device_info;
extern StDeviceCapabilitiesParams s_device_capabilities;
extern StDeviceStatesParams s_device_states;
extern StPowerStatesParams s_power_states;
extern StSensorParams s_chips[ST_CHIPS_NUM];
extern StAIModelParams s_ai_model[ST_AIMODELS_NUM];
extern CfgStSystemSettingsParam s_system_settings;
extern CfgStLogParam s_log[LogFilterNum];
extern CfgStNetworkSettingsParam s_network_settings;
extern CfgStStaticSettingsParam s_static_settings_ipv4;
extern CfgStStaticSettingsParam s_static_settings_ipv6;
extern CfgStProxySettingsParam s_proxy_settings;
extern CfgStWirelessSettingsParam s_wireless_setting;
extern CfgStWirelessStaModeParam s_sta_mode_setting;
extern CfgStIntervalSettingParam s_interval_setting[2];
extern CfgStPeriodicSettingParam s_periodic_setting;
extern CfgStEndpointSettingsParam s_endpoint_settings;

extern senscord_core_t s_sccore;
extern senscord_stream_t s_scstream;

extern RetCode SysAppStateReadoutAiModels(void);
extern RetCode SysAppStateReadoutMainChip(void);
extern RetCode SysAppStateReadoutChips(void);
extern RetCode MakeJsonPowerStates(EsfJsonHandle handle, EsfJsonValue root, void *ctx);
extern RetCode MakeJsonReqInfoSystemSettings(EsfJsonHandle handle, EsfJsonValue root, void *ctx);
extern RetCode MakeJsonResInfoSystemSettings(EsfJsonHandle handle, EsfJsonValue root, void *ctx);
extern RetCode MakeJsonReqInfoNetworkSettings(EsfJsonHandle handle, EsfJsonValue root, void *ctx);
extern RetCode MakeJsonReqInfoWirelessSetting(EsfJsonHandle handle, EsfJsonValue root, void *ctx);
extern RetCode MakeJsonReqInfoEndpointSettings(EsfJsonHandle handle, EsfJsonValue root, void *ctx);
extern RetCode MakeJsonStaticSettingsIPv6(EsfJsonHandle handle, EsfJsonValue root, void *ctx);
extern RetCode MakeJsonStaticSettingsIPv4(EsfJsonHandle handle, EsfJsonValue root, void *ctx);
extern RetCode MakeJsonProxySettings(EsfJsonHandle handle, EsfJsonValue root, void *ctx);
extern RetCode MakeJsonResInfoNetworkSettings(EsfJsonHandle handle, EsfJsonValue root, void *ctx);
extern RetCode MakeJsonStaModeSetting(EsfJsonHandle handle, EsfJsonValue root, void *ctx);
extern RetCode MakeJsonResInfoWirelessSetting(EsfJsonHandle handle, EsfJsonValue root, void *ctx);
extern RetCode MakeJsonResInfoEndpointSettings(EsfJsonHandle handle, EsfJsonValue root, void *ctx);
extern RetCode MakeJsonAiModel(EsfJsonHandle handle, EsfJsonValue root, uint32_t no, void *ctx);
extern RetCode MakeJsonChips(EsfJsonHandle handle, EsfJsonValue root, uint32_t no, void *ctx);
extern RetCode MakeJsonDeviceInfo(EsfJsonHandle handle, EsfJsonValue root);
extern RetCode MakeJsonDeviceCapabilities(EsfJsonHandle handle, EsfJsonValue root);
extern RetCode MakeJsonPowerSource(EsfJsonHandle handle, EsfJsonValue root, uint32_t no, void *ctx);
extern RetCode MakeJsonDeviceStates(EsfJsonHandle handle, EsfJsonValue root);
extern RetCode MakeJsonReserved(EsfJsonHandle handle, EsfJsonValue root);
extern RetCode MakeJsonLog(EsfJsonHandle handle, EsfJsonValue root, uint32_t idx, void *ctx);
extern RetCode MakeJsonSystemSettings(EsfJsonHandle handle, EsfJsonValue root);
extern RetCode MakeJsonNetworkSettings(EsfJsonHandle handle, EsfJsonValue root);
extern RetCode MakeJsonWirelessSetting(EsfJsonHandle handle, EsfJsonValue root);
extern RetCode MakeJsonEndpointSettings(EsfJsonHandle handle, EsfJsonValue root);
extern RetCode ReadOutLogByFilterNo(CfgStLogFilter filter);
extern RetCode MakeJsonReqInfoCore(EsfJsonHandle handle, EsfJsonValue root, const char *req_id);
extern char *ConvertFilterValueToString(CfgStLogFilter filter, char *filter_name);
extern RetCode GetErrorInfo(CfgStUpdateInfo *update, int *code, char *detail_msg, int len);
extern int GetAiIspTemperature(int prev_temperature);
extern int GetSensorTemperature(int prev_temperature);
extern bool GetSensorPostProcessSupported(void);
extern RetCode SysAppStateReadoutPowerStates(void);
extern RetCode SysAppStateReadoutLog(void);
extern RetCode SysAppStateReadoutStaticSettingsIPv6(void);
extern RetCode SysAppStateReadoutStaticSettingsIPv4(void);
extern RetCode SysAppStateReadoutProxySettings(void);
extern RetCode SysAppStateReadoutNetworkSettings(void);
extern RetCode SysAppStateReadoutStaModeSetting(void);
extern RetCode SysAppStateReadoutWirelessSetting(void);
extern void SensorTempUpdateIntervalCallback(void);
extern CfgStUpdateInfo *GetConfigStateUpdateInfo(uint32_t topic);
extern void RequestConfigStateUpdate(uint32_t topic);
extern bool AppendErrorDetail(const char *msg, char *error_detail_msg,
                              size_t error_detail_msg_size);
extern void CheckErrorFlagAndAppendMessage(const ErrorFlag *error_flags, size_t flag_count,
                                           char *error_detail_msg, size_t error_detail_msg_size,
                                           bool *error_exist);
extern void CheckErrorFlagAndAppendMessageWithField(const char *base_prefix, const char *field_name,
                                                    size_t index, char *error_detail_msg,
                                                    size_t error_detail_msg_size,
                                                    bool *error_exist);
extern void HoursMeterUpdateIntervalCallback(void);
extern RetCode GetSensorInfo(SensorInfoCategory target, char *buf, int bufsize);
extern RetCode SendDeploy(uint32_t topic_bits);
extern CfgStPowerSupplyType GetPowerSupplyType(void);
extern RetCode GetSensorLoaderVersion(char *buf, int bufsize);
extern RetCode GetSensorFirmwareVersion(char *buf, int bufsize);
extern RetCode SetHashWithB64Encode(uint8_t *in, size_t in_size, char *out, size_t *out_size);
extern char *ConvB64EncErrToString(EsfCodecBase64ResultEnum err_code);
#if defined(CONFIG_BOARD_WIFI_SMALL_ES) //T3Ws
extern RetCode MakeJsonReqInfoPeriodicSetting(EsfJsonHandle handle, EsfJsonValue root, void *ctx);
extern RetCode MakeJsonResInfoPeriodicSetting(EsfJsonHandle handle, EsfJsonValue root, void *ctx);
extern RetCode MakeJsonIntervalSettings(EsfJsonHandle handle, EsfJsonValue root, uint32_t idx,
                                        void *ctx);
extern RetCode MakeJsonPeriodicSetting(EsfJsonHandle handle, EsfJsonValue root);
#else
#endif

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
extern RetCode MakeJsonReqInfoUnimplemented(EsfJsonHandle handle, EsfJsonValue root, void *ctx);
extern RetCode MakeJsonResInfoUnimplemented(EsfJsonHandle handle, EsfJsonValue root, void *ctx);
extern RetCode SendUnimplementedState(const char *topic, char *id);
#endif // CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
static void common_set_SendDeviceStates(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                        const char *string_expect, EsfJsonErrorCode ret_val);

static EsfFwMgrGetInfoResponse s_fm_gir_ai_model[4] = {
    {.version = "ai_model_version_1",
     .last_update = "ai_model_last_update_1",
     .hash = "ai_model_hash_1"},
    {.version = "ai_model_version_2",
     .last_update = "ai_model_last_update_2",
     .hash = "ai_model_hash_2"},
    {.version = "ai_model_version_3",
     .last_update = "ai_model_last_update_3",
     .hash = "ai_model_hash_3"},
    {.version = "sensor_fw_version_4",
     .last_update = "sensor_fw_last_update_4",
     .hash = "sensor_fw_hash_4"},
};

static EsfFwMgrGetInfoResponse s_fm_gir_ai_model_not[4] = {
    {.version = "", .last_update = "", .hash = ""},
    {.version = "", .last_update = "", .hash = ""},
    {.version = "", .last_update = "", .hash = ""},
    {.version = "", .last_update = "", .hash = ""},
};

static const char *s_evp_hub_url = {"evp/hub/url"};
static const char *s_evp_hub_port = {"8888"};

static struct senscord_temperature_property_t s_temperature_prop = {0};
static struct senscord_image_property_t s_expect_img_prop = {0};

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
/*----------------------------------------------------------------------------*/
static void common_set_SendUnimplementedState(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                              const char *string_expect, EsfJsonErrorCode ret_val,
                                              const char *topic_str)
{
    // EsfJsonOpen
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonUnimplemented - req_info
    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "req_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonReqInfoUnimplemented);
    expect_string(__wrap_SysAppCmnSetObjectValue, ctx, "");
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    // MakeJsonUnimplemented - res_info
    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfoUnimplemented);
    expect_string(__wrap_SysAppCmnSetObjectValue, ctx, "");
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    // EsfJsonSerialize
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SYS_set_state
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // EsfJsonClose
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, ret_val);
}

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonResInfoUnimplemented(EsfJsonHandle handle_val,
                                                    EsfJsonValue parent_val,
                                                    EsfJsonErrorCode ret_val)
{
    // MakeJsonUnimplemented - req_info
    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "req_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonReqInfoUnimplemented);
    expect_string(__wrap_SysAppCmnSetObjectValue, ctx, "");
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    // MakeJsonUnimplemented - res_info
    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfoUnimplemented);
    expect_string(__wrap_SysAppCmnSetObjectValue, ctx, "");
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);
}
#endif // CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
/*----------------------------------------------------------------------------*/
static void common_set_EsfNetworkManagerLoadParameter(int port_val, int ip_method_val,
                                                      int encryption_val,
                                                      EsfNetworkManagerResult ret_val)
{
    will_return(__wrap_EsfNetworkManagerLoadParameter, port_val);
    will_return(__wrap_EsfNetworkManagerLoadParameter, ip_method_val);
    will_return(__wrap_EsfNetworkManagerLoadParameter, encryption_val);
    will_return(__wrap_EsfNetworkManagerLoadParameter, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_EsfNetworkManagerLoadParameterSSID(int port_val, int ip_method_val,
                                                          int encryption_val, char *string_val,
                                                          EsfNetworkManagerResult ret_val)
{
    will_return(__wrap_EsfNetworkManagerLoadParameter, port_val);
    will_return(__wrap_EsfNetworkManagerLoadParameter, ip_method_val);
    will_return(__wrap_EsfNetworkManagerLoadParameter, encryption_val);
    will_return(__wrap_EsfNetworkManagerLoadParameter, string_val);
    will_return(__wrap_EsfNetworkManagerLoadParameter, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_GetSensorFirmwareVersion(senscord_stream_t scstream,
                                                struct senscord_image_property_t *expect_img_prop,
                                                int32_t ret_val)
{
    // senscord_stream_get_property
    expect_value(__wrap_senscord_stream_get_property, stream, scstream);
    expect_string(__wrap_senscord_stream_get_property, property_key,
                  SENSCORD_INFO_STRING_PROPERTY_KEY);
    expect_value(__wrap_senscord_stream_get_property, value_size, 0x84);
    will_return(__wrap_senscord_stream_get_property, expect_img_prop);
    will_return(__wrap_senscord_stream_get_property, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_GetSensorPostProcessSupported(
    senscord_stream_t scstream, struct senscord_image_property_t *expect_img_prop, int32_t ret_val)
{
    if (scstream > 0) {
        // senscord_stream_get_property
        expect_value(__wrap_senscord_stream_get_property, stream, scstream);
        expect_string(__wrap_senscord_stream_get_property, property_key,
                      "post_process_available_property");
        expect_value(__wrap_senscord_stream_get_property, value_size, 0x01);
        will_return(__wrap_senscord_stream_get_property, expect_img_prop);
        will_return(__wrap_senscord_stream_get_property, ret_val);
    }
    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_GetSensorInfo(senscord_stream_t scstream,
                                     struct senscord_image_property_t *expect_img_prop,
                                     int32_t ret_val)
{
    if (s_scstream) {
        // senscord_stream_get_property
        expect_value(__wrap_senscord_stream_get_property, stream, scstream);
        expect_string(__wrap_senscord_stream_get_property, property_key,
                      SENSCORD_INFO_STRING_PROPERTY_KEY);
        expect_value(__wrap_senscord_stream_get_property, value_size, 0x84);
        will_return(__wrap_senscord_stream_get_property, expect_img_prop);
        will_return(__wrap_senscord_stream_get_property, ret_val);
    }
    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_ReadOutLogByFilterNo()
{
    const char *storage_name_1st = "storage_name_1st";

    // SysAppLogGetParameterNumber
    will_return(__wrap_SysAppLogGetParameterNumber, LogLevel);
    will_return(__wrap_SysAppLogGetParameterNumber, ErrorLv);
    will_return(__wrap_SysAppLogGetParameterNumber, kRetOk);

    // SysAppLogGetParameterNumber
    will_return(__wrap_SysAppLogGetParameterNumber, LogLevel);
    will_return(__wrap_SysAppLogGetParameterNumber, ErrorLv);
    will_return(__wrap_SysAppLogGetParameterNumber, kRetOk);

    // SysAppLogGetParameterString
    will_return(__wrap_SysAppLogGetParameterString, storage_name_1st);
    will_return(__wrap_SysAppLogGetParameterString, kRetOk);

    // SysAppLogGetParameterString
    will_return(__wrap_SysAppLogGetParameterString, storage_name_1st);
    will_return(__wrap_SysAppLogGetParameterString, kRetOk);

    return;
}

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
/*----------------------------------------------------------------------------*/
static void common_set_GetAiIspTemperature(senscord_stream_t scstream, float temperature_val,
                                           int32_t ret_mutex_lock, int32_t ret_val)
{
    // pthread_mutex_lock
    will_return(__wrap_pthread_mutex_lock, ret_mutex_lock);
    s_temperature_prop.temperatures[1].temperature = temperature_val;

    if (ret_mutex_lock == 0) {
        if (scstream != 0) {
            // senscord_stream_get_property
            expect_value(__wrap_senscord_stream_get_property, stream, scstream);
            expect_string(__wrap_senscord_stream_get_property, property_key,
                          SENSCORD_TEMPERATURE_PROPERTY_KEY);
            expect_value(__wrap_senscord_stream_get_property, value_size,
                         sizeof(struct senscord_temperature_property_t));
            will_return(__wrap_senscord_stream_get_property, &s_temperature_prop);
            will_return(__wrap_senscord_stream_get_property, ret_val);

            if (ret_val < 0) {
                // SYSAPP_ELOG_ERR
                expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
                expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelError);
                expect_value(__wrap_UtilityLogWriteELog, event_id, 0xb0b0);
                will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);
            }
        }

        // pthread_mutex_unlock
        will_return(__wrap_pthread_mutex_unlock, 0);
    }
    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_GetAiIspTemperature_Upper(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                                 const char *string_expect,
                                                 senscord_stream_t scstream, float temperature_val,
                                                 int32_t ret_mutex_lock, int32_t ret_val)
{
    // pthread_mutex_lock
    will_return(__wrap_pthread_mutex_lock, ret_mutex_lock);
    s_temperature_prop.temperatures[1].temperature = temperature_val;

    if (scstream != 0) {
        // senscord_stream_get_property
        expect_value(__wrap_senscord_stream_get_property, stream, scstream);
        expect_string(__wrap_senscord_stream_get_property, property_key,
                      SENSCORD_TEMPERATURE_PROPERTY_KEY);
        expect_value(__wrap_senscord_stream_get_property, value_size,
                     sizeof(struct senscord_temperature_property_t));
        will_return(__wrap_senscord_stream_get_property, &s_temperature_prop);
        will_return(__wrap_senscord_stream_get_property, ret_val);

        if (ret_val < 0) {
            // SYSAPP_ELOG_ERR
            expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
            expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelError);
            expect_value(__wrap_UtilityLogWriteELog, event_id, 0xb0b0);
            will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);
        }
        else {
            if (temperature_val > TEMPERATURE_UPPER_THRESHOLD) {
                expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
                expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelError);
                expect_value(__wrap_UtilityLogWriteELog, event_id,
                             SYSAPP_EVT_SENSOR_EXCEEDED_HIGH_TEMP);
                will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);

                common_set_SendDeviceStates(handle_val, parent_val, string_expect, kEsfJsonSuccess);
            }
            else if (temperature_val > TEMPERATURE_UPPER_APPROACHING_THRESHOLD) {
                expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
                expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelWarn);
                expect_value(__wrap_UtilityLogWriteELog, event_id,
                             SYSAPP_EVT_SENSOR_APPROACHING_HIGH_TEMP);
                will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);
            }
            else {
                // Nop.
            }
        }

        // pthread_mutex_unlock
        will_return(__wrap_pthread_mutex_unlock, 0);
    }
    return;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP

/*----------------------------------------------------------------------------*/
static void common_set_GetSensorTemperature(senscord_stream_t scstream, float temperature_val,
                                            int32_t ret_mutex_lock, int32_t ret_val)
{
    s_temperature_prop.temperatures[0].temperature = temperature_val;

    // pthread_mutex_lock
    will_return(__wrap_pthread_mutex_lock, ret_mutex_lock);
    if (ret_mutex_lock == 0) {
        if (s_scstream) {
            // senscord_stream_get_property
            expect_value(__wrap_senscord_stream_get_property, stream, scstream);
            expect_string(__wrap_senscord_stream_get_property, property_key,
                          SENSCORD_TEMPERATURE_PROPERTY_KEY);
            expect_value(__wrap_senscord_stream_get_property, value_size,
                         sizeof(struct senscord_temperature_property_t));
            will_return(__wrap_senscord_stream_get_property, &s_temperature_prop);
            will_return(__wrap_senscord_stream_get_property, ret_val);
            if (ret_val < 0) {
                // SYSAPP_ELOG_ERR
                expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
                expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelError);
                expect_value(__wrap_UtilityLogWriteELog, event_id,
                             SYSAPP_EVT_FAILED_TO_RETRIEVE_TEMP);
                will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);
            }
            else {
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
                if (temperature_val > TEMPERATURE_UPPER_THRESHOLD) {
                    // SYSAPP_ELOG_ERR
                    expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
                    expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelError);
                    expect_value(__wrap_UtilityLogWriteELog, event_id,
                                 SYSAPP_EVT_SENSOR_EXCEEDED_HIGH_TEMP);
                    will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);
                }
                else if (temperature_val > TEMPERATURE_UPPER_APPROACHING_THRESHOLD) {
                    // SYSAPP_ELOG_ERR
                    expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
                    expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelWarn);
                    expect_value(__wrap_UtilityLogWriteELog, event_id,
                                 SYSAPP_EVT_SENSOR_APPROACHING_HIGH_TEMP);
                    will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);
                }
                else {
                    if (temperature_val < TEMPERATURE_LOWER_THRESHOLD) {
                        // SYSAPP_ELOG_ERR
                        expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
                        expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelError);
                        expect_value(__wrap_UtilityLogWriteELog, event_id,
                                     SYSAPP_EVT_SENSOR_EXCEEDED_LOW_TEMP);
                        will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);
                    }
                    else if (temperature_val < TEMPERATURE_LOWER_APPROACHING_THRESHOLD) {
                        // SYSAPP_ELOG_ERR
                        expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
                        expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelWarn);
                        expect_value(__wrap_UtilityLogWriteELog, event_id,
                                     SYSAPP_EVT_SENSOR_APPROACHING_LOW_TEMP);
                        will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);
                    }
                    else {
                        // Nop.
                    }
                }
#endif
            }
        }
        // pthread_mutex_unlock
        will_return(__wrap_pthread_mutex_unlock, 0);
    }
    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SysAppStateReadoutMainChip_Fully(char *b64_buf, uint32_t expect_b64_size,
                                                        EsfFwMgrGetInfoResponse *response,
                                                        EsfCodecBase64ResultEnum ret_Loaer,
                                                        EsfCodecBase64ResultEnum ret_Firmware)
{
    // EsfFwMgrGetInfo
    will_return(__wrap_EsfFwMgrGetInfo, (EsfFwMgrGetInfoData *)&response[0]);
    will_return(__wrap_EsfFwMgrGetInfo, kEsfFwMgrResultOk);

    // Execute_EncodeToBase64
    expect_not_value(__wrap_EsfCodecBase64Encode, in, NULL);
    expect_value(__wrap_EsfCodecBase64Encode, in_size, sizeof(response[0].hash));
    will_return(__wrap_EsfCodecBase64Encode, b64_buf);
    will_return(__wrap_EsfCodecBase64Encode, expect_b64_size);
    will_return(__wrap_EsfCodecBase64Encode, ret_Loaer);

    // EsfFwMgrGetInfo
    will_return(__wrap_EsfFwMgrGetInfo, (EsfFwMgrGetInfoData *)&response[0]);
    will_return(__wrap_EsfFwMgrGetInfo, kEsfFwMgrResultOk);

    // Execute_EncodeToBase64
    expect_not_value(__wrap_EsfCodecBase64Encode, in, NULL);
    expect_value(__wrap_EsfCodecBase64Encode, in_size, sizeof(response[0].hash));
    will_return(__wrap_EsfCodecBase64Encode, b64_buf);
    will_return(__wrap_EsfCodecBase64Encode, expect_b64_size);
    will_return(__wrap_EsfCodecBase64Encode, ret_Firmware);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SysAppStateReadoutAiModels_Fully(char *b64_buf, uint32_t expect_b64_size,
                                                        size_t bsize,
                                                        EsfFwMgrGetInfoResponse *response,
                                                        EsfCodecBase64ResultEnum ret_ai_models)
{
    expect_value(mock_malloc, __size, bsize);
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);

    // EsfFwMgrGetInfo
    will_return(__wrap_EsfFwMgrGetInfo, (EsfFwMgrGetInfoData *)&response[0]);
    will_return(__wrap_EsfFwMgrGetInfo, kEsfFwMgrResultOk); // SetHashWithB64Encode()

    for (uint32_t i = 0; i < ST_AIMODELS_NUM; i++) {
        // Execute_EncodeToBase64
        expect_not_value(__wrap_EsfCodecBase64Encode, in, NULL);
        expect_value(__wrap_EsfCodecBase64Encode, in_size, sizeof(response[i].hash));
        will_return(__wrap_EsfCodecBase64Encode, b64_buf);
        will_return(__wrap_EsfCodecBase64Encode, expect_b64_size);
        will_return(__wrap_EsfCodecBase64Encode, ret_ai_models);
    }

    // For free()
    will_return(mock_free, false);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SysAppStateReadoutChips_FullySuccess(char *b64_buf, uint32_t expect_b64_size)
{
    common_set_SysAppStateReadoutMainChip_Fully(b64_buf, expect_b64_size, s_fm_gir_ai_model,
                                                kEsfCodecBase64ResultSuccess,
                                                kEsfCodecBase64ResultSuccess);

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
    common_set_GetSensorInfo(s_scstream, &s_expect_img_prop, 0); // GetSensorInfo()
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
    common_set_GetSensorInfo(s_scstream, &s_expect_img_prop, 0); // GetSensorInfo()
    common_set_GetAiIspTemperature(s_scstream, TEMPERATURE_UPPER_APPROACHING_THRESHOLD, 0,
                                   0); // GetAiIspTemperature()
#endif                                 // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
    common_set_GetSensorInfo(s_scstream, &s_expect_img_prop, 0); // GetSensorInfo()
    common_set_GetSensorTemperature(s_scstream, TEMPERATURE_LOWER_APPROACHING_THRESHOLD, 0,
                                    0); // GetSensorTemperature()

    // EsfFwMgrGetInfo
    will_return(__wrap_EsfFwMgrGetInfo, (EsfFwMgrGetInfoData *)&s_fm_gir_ai_model[0]);
    will_return(__wrap_EsfFwMgrGetInfo, kEsfFwMgrResultOk); // SetHashWithB64Encode()

    // Execute_EncodeToBase64
    expect_not_value(__wrap_EsfCodecBase64Encode, in, NULL);
    expect_value(__wrap_EsfCodecBase64Encode, in_size, sizeof(s_fm_gir_ai_model[0].hash));
    will_return(__wrap_EsfCodecBase64Encode, b64_buf);
    will_return(__wrap_EsfCodecBase64Encode, expect_b64_size);
    will_return(__wrap_EsfCodecBase64Encode, kRetOk);

    // EsfFwMgrGetInfo
    will_return(__wrap_EsfFwMgrGetInfo, (EsfFwMgrGetInfoData *)&s_fm_gir_ai_model[0]);
    will_return(__wrap_EsfFwMgrGetInfo, kEsfFwMgrResultOk); // SetHashWithB64Encode()

    // Execute_EncodeToBase64
    expect_not_value(__wrap_EsfCodecBase64Encode, in, NULL);
    expect_value(__wrap_EsfCodecBase64Encode, in_size, sizeof(s_fm_gir_ai_model[0].hash));
    will_return(__wrap_EsfCodecBase64Encode, b64_buf);
    will_return(__wrap_EsfCodecBase64Encode, expect_b64_size);
    will_return(__wrap_EsfCodecBase64Encode, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SysAppStateReadoutChips_Failed(char *b64_buf, uint32_t expect_b64_size)
{
    common_set_SysAppStateReadoutMainChip_Fully(b64_buf, expect_b64_size, s_fm_gir_ai_model,
                                                kEsfCodecBase64ResultSuccess,
                                                kEsfCodecBase64ResultNullParam);

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
    common_set_GetSensorInfo(s_scstream, &s_expect_img_prop, -1); // GetSensorInfo()
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
    common_set_GetSensorInfo(s_scstream, &s_expect_img_prop, -1); // GetSensorInfo()
    common_set_GetAiIspTemperature(s_scstream, TEMPERATURE_UPPER_APPROACHING_THRESHOLD, 0,
                                   -1); // GetAiIspTemperature()
#endif                                  // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
    common_set_GetSensorInfo(s_scstream, &s_expect_img_prop, -1); // GetSensorInfo()
    common_set_GetSensorTemperature(s_scstream, TEMPERATURE_LOWER_APPROACHING_THRESHOLD, 0,
                                    -1); // GetSensorTemperature()

    // EsfFwMgrGetInfo
    will_return(__wrap_EsfFwMgrGetInfo, (EsfFwMgrGetInfoData *)&s_fm_gir_ai_model[0]);
    will_return(__wrap_EsfFwMgrGetInfo, kEsfFwMgrResultOk);

    // Execute_EncodeToBase64
    expect_not_value(__wrap_EsfCodecBase64Encode, in, NULL);
    expect_value(__wrap_EsfCodecBase64Encode, in_size, sizeof(s_fm_gir_ai_model[0].hash));
    will_return(__wrap_EsfCodecBase64Encode, b64_buf);
    will_return(__wrap_EsfCodecBase64Encode, expect_b64_size);
    will_return(__wrap_EsfCodecBase64Encode, kRetFailed);

    common_set_GetSensorFirmwareVersion(s_scstream, &s_expect_img_prop,
                                        -1); // GetSensorFirmwareVersion()

    // EsfFwMgrGetInfo
    will_return(__wrap_EsfFwMgrGetInfo, (EsfFwMgrGetInfoData *)&s_fm_gir_ai_model[0]);
    will_return(__wrap_EsfFwMgrGetInfo, kEsfFwMgrResultOk);

    // Execute_EncodeToBase64
    expect_not_value(__wrap_EsfCodecBase64Encode, in, NULL);
    expect_value(__wrap_EsfCodecBase64Encode, in_size, sizeof(s_fm_gir_ai_model[0].hash));
    will_return(__wrap_EsfCodecBase64Encode, b64_buf);
    will_return(__wrap_EsfCodecBase64Encode, expect_b64_size);
    will_return(__wrap_EsfCodecBase64Encode, kRetFailed);

    common_set_GetSensorFirmwareVersion(s_scstream, &s_expect_img_prop,
                                        -1); // GetSensorFirmwareVersion()

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SysAppStateReadoutDeviceInfo(char *b64_buf, uint32_t expect_b64_size,
                                                    size_t bsize,
                                                    EsfSystemManagerResult ret_manifest,
                                                    EsfCodecBase64ResultEnum ret_aimodels)
{
    will_return(__wrap_EsfSystemManagerGetDeviceManifest, "manifest");
    will_return(__wrap_EsfSystemManagerGetDeviceManifest, ret_manifest);

    if (ret_manifest == kEsfSystemManagerResultOk) {
        common_set_SysAppStateReadoutChips_FullySuccess(b64_buf, expect_b64_size);
    }
    else {
        common_set_SysAppStateReadoutChips_Failed(b64_buf, expect_b64_size);
    }

    common_set_SysAppStateReadoutAiModels_Fully(b64_buf, expect_b64_size, bsize, s_fm_gir_ai_model,
                                                ret_aimodels);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SysAppStaClose(senscord_core_t core, senscord_stream_t stream,
                                      int32_t ret_mutex_lock, int32_t ret_close_stream)
{
    s_sccore = core;
    s_scstream = stream;

    // pthread_mutex_lock
    will_return(__wrap_pthread_mutex_lock, 0);

    if (s_sccore > 0 && s_scstream > 0) {
        // SensCoreCoreCloseStream
        expect_value(__wrap_senscord_core_close_stream, core, s_sccore);
        expect_value(__wrap_senscord_core_close_stream, stream, s_scstream);
        will_return(__wrap_senscord_core_close_stream, ret_close_stream);
    }
    if (ret_mutex_lock == 0) {
        // pthread_mutex_unlock
        will_return(__wrap_pthread_mutex_unlock, 0);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SendDeviceInfo(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                      const char *string_expect, char *SysAppCmnSetStringValue)
{
    s_device_info.device_manifest[0] = '\0';

    // EsfJsonOpen
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonHandleError);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "device_manifest");
    expect_string(__wrap_SysAppCmnSetStringValue, string, SysAppCmnSetStringValue);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetArrayValue
    will_return(__wrap_SysAppCmnSetArrayValue, kRetOk);

    // EsfJsonSerialize
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // EsfJsonClose
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonResInfoSystemSettings(EsfJsonHandle handle_val,
                                                     EsfJsonValue parent_val, int code_val,
                                                     const char *detail_msg_val, RetCode ret_val)
{
    // SysAppCmnMakeJsonResInfo
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, parent_val);
    expect_not_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, "");
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, code_val);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, detail_msg_val);
    will_return(__wrap_SysAppCmnMakeJsonResInfo, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonResInfoNetworkSettings(EsfJsonHandle handle_val,
                                                      EsfJsonValue parent_val, int code_val,
                                                      const char *detail_msg_val, RetCode ret_val)
{
    // SysAppCmnMakeJsonResInfo
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, parent_val);
    expect_not_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, "");
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, code_val);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, detail_msg_val);
    will_return(__wrap_SysAppCmnMakeJsonResInfo, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonResInfoWirelessSetting(EsfJsonHandle handle_val,
                                                      EsfJsonValue parent_val, int code_val,
                                                      const char *detail_msg_val, RetCode ret_val)
{
    // SysAppCmnMakeJsonResInfo
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, parent_val);
    expect_not_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, "");
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, code_val);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, detail_msg_val);
    will_return(__wrap_SysAppCmnMakeJsonResInfo, ret_val);
    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonChips(EsfJsonHandle handle_val, EsfJsonValue parent_val, uint32_t no,
                                     RetCode ret_val)
{
    snprintf(s_chips[no].name, sizeof(s_chips[0].name), "NAME%d", no);
    snprintf(s_chips[no].id, sizeof(s_chips[0].id), "ID%d", no);
    snprintf(s_chips[no].hardware_version, sizeof(s_chips[0].hardware_version), "HW_VER%d", no);
    s_chips[no].current_temperature = 25;
    snprintf(s_chips[no].loader_version, sizeof(s_chips[0].loader_version), "LD_VER%d", no);
    snprintf(s_chips[no].loader_hash, sizeof(s_chips[0].loader_hash), "LD_HASH%d", no);
    snprintf(s_chips[no].update_date_loader, sizeof(s_chips[0].update_date_loader), "LD_DATE%d",
             no);
    snprintf(s_chips[no].firmware_version, sizeof(s_chips[0].firmware_version), "FW_VER%d", no);
    snprintf(s_chips[no].firmware_hash, sizeof(s_chips[0].firmware_hash), "FW_HASH%d", no);
    snprintf(s_chips[no].update_date_firmware, sizeof(s_chips[0].update_date_firmware), "FW_DATE%d",
             no);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "name");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_chips[no].name);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "id");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_chips[no].id);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "hardware_version");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_chips[no].hardware_version);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetNumberValue
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "temperature");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, s_chips[no].current_temperature);
    will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "loader_version");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_chips[no].loader_version);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "loader_hash");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_chips[no].loader_hash);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "update_date_loader");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_chips[no].update_date_loader);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "firmware_version");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_chips[no].firmware_version);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "firmware_hash");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_chips[no].firmware_hash);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "update_date_firmware");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_chips[no].update_date_firmware);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);
    will_return(__wrap_SysAppCmnSetArrayValue, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonAiModel(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                       uint32_t no, RetCode ret_val)
{
    snprintf(s_ai_model[no].version, sizeof(s_ai_model[0].version), "VERSION%d", no);
    snprintf(s_ai_model[no].hash, sizeof(s_ai_model[0].hash), "HASH%d", no);
    snprintf(s_ai_model[no].update_date, sizeof(s_ai_model[0].update_date), "UPDATE_DATE%d", no);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "version");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_ai_model[no].version);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "hash");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_ai_model[no].hash);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "update_date");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_ai_model[no].update_date);
    will_return(__wrap_SysAppCmnSetStringValue, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonDeviceInfo(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                          RetCode ret_val)
{
    snprintf(s_device_info.device_manifest, sizeof(s_device_info.device_manifest), "MANIFEST");

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "device_manifest");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_device_info.device_manifest);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetArrayValue
    will_return(__wrap_SysAppCmnSetArrayValue, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonDeviceCapabilities(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                                  RetCode ret_val)
{
    s_device_capabilities.is_battery_supported = false;
    s_device_capabilities.is_periodic_supported = false;
    s_device_capabilities.is_sensor_postprocess_supported = false;

#ifdef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    // SysAppCmnSetBooleanValue
    will_return(__wrap_SysAppCmnSetBooleanValue, kRetOk);

    // SysAppCmnSetNumberValue
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "supported_wireless_mode");
    expect_value(__wrap_SysAppCmnSetNumberValue, number,
                 s_device_capabilities.supported_wireless_mode);
    will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);

    // SysAppCmnSetBooleanValue
    will_return(__wrap_SysAppCmnSetBooleanValue, kRetOk);

    // SysAppCmnSetBooleanValue
    will_return(__wrap_SysAppCmnSetBooleanValue, ret_val);
#endif
    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonPowerSource(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                           uint32_t no, RetCode ret_val)
{
    s_power_states.source[no].type = no;
    s_power_states.source[no].level = no;

    // SysAppCmnSetNumberValue
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "type");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, s_power_states.source[no].type);
    will_return(__wrap_SysAppCmnSetNumberValue, ret_val);

    // SysAppCmnSetNumberValue
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "level");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, s_power_states.source[no].level);
    will_return(__wrap_SysAppCmnSetNumberValue, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonPowerStates(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                           RetCode ret_val)
{
    // SysAppCmnSetArrayValue
    will_return(__wrap_SysAppCmnSetArrayValue, kRetOk);

    // SysAppCmnSetNumberValue
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "in_use");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, s_power_states.in_use);
    will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);

    // SysAppCmnSetBooleanValue
    will_return(__wrap_SysAppCmnSetBooleanValue, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonDeviceStates(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                            RetCode ret_val)
{
    // _SysAppCmnSetObjectValue
    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "power_states");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonPowerStates);
    expect_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "process_state");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_device_states.process_state);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetNumberValue
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "hours_meter");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, s_device_states.hours_meter);
    will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);

    // SysAppCmnSetNumberValue
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "bootup_reason");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, s_device_states.bootup_reason);
    will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "last_bootup_time");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_device_states.last_bootup_time);
    will_return(__wrap_SysAppCmnSetStringValue, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonReserved(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                        RetCode ret_val)
{
    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "schema");
#if defined(CONFIG_ARCH_CHIP_ESP32S3) // T5
    expect_string(__wrap_SysAppCmnSetStringValue, string,
                  "dtmi:com:sony_semicon:aitrios:sss:edge:system:t5;2");
#elif defined(CONFIG_BOARD_POE_ES) || defined(__linux__) //T3P or Raspi
    expect_string(__wrap_SysAppCmnSetStringValue, string,
                  "dtmi:com:sony_semicon:aitrios:sss:edge:system:t3p;2");
#elif defined(CONFIG_BOARD_WIFI_SMALL_ES)                //T3Ws
    expect_string(__wrap_SysAppCmnSetStringValue, string,
                  "dtmi:com:sony_semicon:aitrios:sss:edge:system:t3w;2");
#else
    expect_string(__wrap_SysAppCmnSetStringValue, string,
                  "dtmi:com:sony_semicon:aitrios:sss:edge:system:t3w;2");
#endif
    will_return(__wrap_SysAppCmnSetStringValue, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonLog(EsfJsonHandle handle_val, EsfJsonValue parent_val, uint32_t idx,
                                   RetCode ret_val)
{
    memset(s_log, 0, sizeof(s_log));

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "filter");
    expect_string(__wrap_SysAppCmnSetStringValue, string, "");
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetNumberValue
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "level");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, s_log[idx].level);
    will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);

    // SysAppCmnSetNumberValue
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "destination");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, s_log[idx].destination);
    will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "storage_name");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_log[idx].storage_name);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "path");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_log[idx].path);
    will_return(__wrap_SysAppCmnSetStringValue, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonSystemSettings(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                              RetCode ret_val)
{
    // _SysAppCmnSetObjectValue
    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "req_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonReqInfoSystemSettings);
    expect_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    // SysAppCmnSetBooleanValue
    will_return(__wrap_SysAppCmnSetBooleanValue, kRetOk);

    // SysAppCmnSetNumberValue
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "temperature_update_interval");
    expect_value(__wrap_SysAppCmnSetNumberValue, number,
                 s_system_settings.temperature_update_interval);
    will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);

    // SysAppCmnSetArrayValue
    will_return(__wrap_SysAppCmnSetArrayValue, kRetOk);

    // _SysAppCmnSetObjectValue
    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfoSystemSettings);
    expect_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonStaticSettingsIPv6(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                                  RetCode ret_val)
{
    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "ip_address");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_static_settings_ipv6.ip_address);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "subnet_mask");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_static_settings_ipv6.subnet_mask);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "gateway_address");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_static_settings_ipv6.gateway_address);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "dns_address");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_static_settings_ipv6.dns_address);
    will_return(__wrap_SysAppCmnSetStringValue, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonStaticSettingsIPv4(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                                  RetCode ret_val)
{
    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "ip_address");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_static_settings_ipv4.ip_address);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "subnet_mask");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_static_settings_ipv4.subnet_mask);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "gateway_address");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_static_settings_ipv4.gateway_address);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "dns_address");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_static_settings_ipv4.dns_address);
    will_return(__wrap_SysAppCmnSetStringValue, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonProxySettings(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                             RetCode ret_val)
{
    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "proxy_url");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_proxy_settings.proxy_url);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetNumberValue
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "proxy_port");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, s_proxy_settings.proxy_port);
    will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "proxy_user_name");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_proxy_settings.proxy_user_name);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "proxy_password");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_proxy_settings.proxy_password);
    will_return(__wrap_SysAppCmnSetStringValue, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonNetworkSettings(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                               RetCode ret_val)
{
    // _SysAppCmnSetObjectValue
    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "req_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonReqInfoNetworkSettings);
    expect_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    // SysAppCmnSetNumberValue
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "ip_method");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, s_network_settings.ip_method);
    will_return(__wrap_SysAppCmnSetNumberValue, ret_val);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "ntp_url");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_network_settings.ntp_url);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // _SysAppCmnSetObjectValue
    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "static_settings_ipv6");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonStaticSettingsIPv6);
    expect_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    // _SysAppCmnSetObjectValue
    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "static_settings_ipv4");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonStaticSettingsIPv4);
    expect_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    // _SysAppCmnSetObjectValue
    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "proxy_settings");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonProxySettings);
    expect_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    // _SysAppCmnSetObjectValue
    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfoNetworkSettings);
    expect_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonStaModeSetting(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                              RetCode ret_val)
{
    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "ssid");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_sta_mode_setting.ssid);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "password");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_sta_mode_setting.password);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetNumberValue
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "encryption");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, s_sta_mode_setting.encryption);
    will_return(__wrap_SysAppCmnSetNumberValue, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonWirelessSetting(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                               RetCode ret_val)
{
    // _SysAppCmnSetObjectValue
    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "req_info");
    expect_any(__wrap_SysAppCmnSetObjectValue, make_json);
    expect_any(__wrap_SysAppCmnSetObjectValue, ctx);
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    // _SysAppCmnSetObjectValue
    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "sta_mode_setting");
    expect_any(__wrap_SysAppCmnSetObjectValue, make_json);
    expect_any(__wrap_SysAppCmnSetObjectValue, ctx);
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    // _SysAppCmnSetObjectValue
    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_any(__wrap_SysAppCmnSetObjectValue, make_json);
    expect_any(__wrap_SysAppCmnSetObjectValue, ctx);
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, ret_val);

    return;
}

#if defined(CONFIG_BOARD_WIFI_SMALL_ES) //T3Ws
/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonIntervalSettings(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                                RetCode ret_val)
{
    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "base_time");
    expect_string(__wrap_SysAppCmnSetStringValue, string, "00.00");
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetNumberValue
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "capture_interval");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, 120);
    will_return(__wrap_SysAppCmnSetNumberValue, ret_val);

    // SysAppCmnSetNumberValue
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "config_interval");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, 240);
    will_return(__wrap_SysAppCmnSetNumberValue, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonPeriodicSetting(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                               RetCode ret_val)
{
    // _SysAppCmnSetObjectValue
    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "req_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonReqInfoPeriodicSetting);
    expect_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    // SysAppCmnSetNumberValue
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "operation_mode");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, 0);
    will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);

    // SysAppCmnSetNumberValue
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "recovery_method");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, 0);
    will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);

    // SysAppCmnSetArrayValue
    will_return(__wrap_SysAppCmnSetArrayValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "ip_addr_setting");
    expect_string(__wrap_SysAppCmnSetStringValue, string, "dhcp");
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // _SysAppCmnSetObjectValue
    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfoPeriodicSetting);
    expect_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, ret_val);

    return;
}
#else
#endif

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonEndpointSettings(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                                RetCode ret_val)
{
    // _SysAppCmnSetObjectValue
    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "req_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonReqInfoEndpointSettings);
    expect_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "endpoint_url");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_endpoint_settings.endpoint_url);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetNumberValue
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "endpoint_port");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, s_endpoint_settings.endpoint_port);
    will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "protocol_version");
    expect_string(__wrap_SysAppCmnSetStringValue, string, s_endpoint_settings.protocol_version);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // _SysAppCmnSetObjectValue
    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfoEndpointSettings);
    expect_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SysAppStateUpdateSensorTemperature(bool log_flag,
                                                          UtilityLogElogLevel log_level,
                                                          uint16_t event_id, int32_t ret_val1,
                                                          int32_t ret_val2)
{
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP

    common_set_GetAiIspTemperature(s_scstream, TEMPERATURE_UPPER_APPROACHING_THRESHOLD, 0,
                                   ret_val1);

#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP

    common_set_GetSensorTemperature(s_scstream, TEMPERATURE_UPPER_APPROACHING_THRESHOLD, 0,
                                    ret_val2); // GetSensorTemperature()

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_MakeJsonReqInfoCore(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                           char *key_val, char *string_val, RetCode ret_val)
{
    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, key_val);
    expect_string(__wrap_SysAppCmnSetStringValue, string, string_val);
    will_return(__wrap_SysAppCmnSetStringValue, ret_val);
}

/*----------------------------------------------------------------------------*/
static void common_set_ReadOutLogSystemApp()
{
    common_set_ReadOutLogByFilterNo();
    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_ReadOutLogSensor()
{
    common_set_ReadOutLogByFilterNo();

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_ReadOutLogCompanionFw()
{
    common_set_ReadOutLogByFilterNo();

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_ReadOutLogCompanionApp()
{
    common_set_ReadOutLogByFilterNo();

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SysAppStateReadoutLog()
{
    common_set_ReadOutLogSystemApp();
    common_set_ReadOutLogSensor();
    common_set_ReadOutLogCompanionFw();
    common_set_ReadOutLogCompanionApp();

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SysAppStateReadoutSystemSettings(RetCode ret_val1, RetCode ret_val2)
{
    // SysAppLedGetEnable
    bool led_enabled = true;
    will_return(__wrap_SysAppLedGetEnable, led_enabled);
    will_return(__wrap_SysAppLedGetEnable, ret_val1);

    // SysAppTimerStartTimer
    will_return(__wrap_SysAppTimerStartTimer, ret_val2);

    common_set_SysAppStateReadoutLog();

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SendDeviceCapabilities(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                              const char *string_expect, EsfJsonErrorCode ret_val)
{
    // SendDeviceCapabilities
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonDeviceCapabilities
    common_set_MakeJsonDeviceCapabilities(handle_val, parent_val, kRetOk);

    // SendDeviceCapabilities
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SendDeviceCapabilities
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, ret_val);
    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SendDeviceStates(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                        const char *string_expect, EsfJsonErrorCode ret_val)
{
    // SendDeviceStates
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonDeviceStates
    common_set_MakeJsonDeviceStates(handle_val, parent_val, kRetOk);

    // SendDeviceStates
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, ret_val);

    // SendDeviceStates
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, SYS_RESULT_OK);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SendReserved(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                    const char *string_expect, EsfJsonErrorCode ret_val)
{
    // SendReserved
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonDeviceStates
    common_set_MakeJsonReserved(handle_val, parent_val, kRetOk);

    // SendReserved
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SendReserved
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SendSystemSettings(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                          const char *string_expect, EsfJsonErrorCode ret_val)
{
    // SendSystemSettings
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonSystemSettings
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    common_set_MakeJsonResInfoUnimplemented(handle_val, parent_val, kRetOk);
#else
    common_set_MakeJsonSystemSettings(handle_val, parent_val, kRetOk);
#endif

    // SendSystemSettings
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SendSystemSettings
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SendNetworkSettings(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                           const char *string_expect, EsfJsonErrorCode ret_val)
{
    // SendNetworkSettings
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonSystemSettings
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    common_set_MakeJsonResInfoUnimplemented(handle_val, parent_val, kRetOk);
#else
    common_set_MakeJsonNetworkSettings(handle_val, parent_val, kRetOk);
#endif

    // SendNetworkSettings
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SendNetworkSettings
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SendWirelessSetting(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                           const char *string_expect, EsfJsonErrorCode ret_val)
{
    // SendWirelessSetting
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonSystemSettings
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    common_set_MakeJsonResInfoUnimplemented(handle_val, parent_val, kRetOk);
#else
    common_set_MakeJsonWirelessSetting(handle_val, parent_val, kRetOk);
#endif

    // SendWirelessSetting
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SendWirelessSetting
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, ret_val);

    return;
}

#if defined(CONFIG_BOARD_WIFI_SMALL_ES) //T3Ws
/*----------------------------------------------------------------------------*/
static void common_set_SendPeriodicSetting(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                           const char *string_expect, EsfJsonErrorCode ret_val)
{
    // EsfJsonOpen
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonPeriodicSetting
    common_set_MakeJsonPeriodicSetting(handle_val, parent_val, kRetOk);

    // EsfJsonSerialize
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // EsfJsonClose
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, ret_val);
    return;
}
#else
#endif
/*----------------------------------------------------------------------------*/
static void common_set_SendEndpointSettings(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                            const char *string_expect, EsfJsonErrorCode ret_val)
{
    // SendEndpointSettings
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonEndpointSettings
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    common_set_MakeJsonResInfoUnimplemented(handle_val, parent_val, kRetOk);
#else
    common_set_MakeJsonEndpointSettings(handle_val, parent_val, kRetOk);
#endif

    // SendEndpointSettings
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SendEndpointSettings
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_GetPowerSupplyType(EsfPwrMgrSupplyType type_val, EsfPwrMgrError ret_val)
{
    // Set_EsfPwrMgrGetSupplyType
    will_return(__wrap_EsfPwrMgrGetSupplyType, type_val);
    will_return(__wrap_EsfPwrMgrGetSupplyType, ret_val);
    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SysAppStateReadoutPowerStates()
{
    common_set_GetPowerSupplyType(kEsfPwrMgrSupplyTypePoE, kEsfPwrMgrOk);
    common_set_GetPowerSupplyType(kEsfPwrMgrSupplyTypePoE, kEsfPwrMgrOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SysAppStateReadoutDeviceStates(RetCode start_timer_ret_val,
                                                      int clock_gettime_ret_val)
{
    common_set_SysAppStateReadoutPowerStates();

    // GetSensorHoursMeter
    will_return(__wrap_EsfPwrMgrHoursMeterGetValue, 123);
    will_return(__wrap_EsfPwrMgrHoursMeterGetValue, kEsfPwrMgrOk);

    // SysAppTimerStartTimer
    will_return(__wrap_SysAppTimerStartTimer, start_timer_ret_val);

    // clock_gettime() 1.return 2.tv_sec 3.tv_nsec
#if defined(__NuttX__)
    will_return(__wrap_clock_gettime, clock_gettime_ret_val);
    will_return(__wrap_clock_gettime, 2000); // tv_sec:0 (sec)
    will_return(__wrap_clock_gettime, 0L);   // tv_nsec:0L (ns)
#endif
    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SysAppStateReadoutNetworkSettings(int ip_method_val,
                                                         EsfClockManagerReturnValue clock_val,
                                                         EsfNetworkManagerResult ret_val)
{
    // ip_method
    common_set_EsfNetworkManagerLoadParameter(0, ip_method_val, EncWpa2Psk, ret_val);

    // ntp_url
    will_return(__wrap_EsfClockManagerGetParams, "old_ntp_domain");
    will_return(__wrap_EsfClockManagerGetParams, 0);
    will_return(__wrap_EsfClockManagerGetParams, 0);
    will_return(__wrap_EsfClockManagerGetParams, kClockManagerParamTypeOff);
    will_return(__wrap_EsfClockManagerGetParams, 0);
    will_return(__wrap_EsfClockManagerGetParams, 0);
    will_return(__wrap_EsfClockManagerGetParams, 0);
    will_return(__wrap_EsfClockManagerGetParams, kClockManagerParamTypeOff);
    will_return(__wrap_EsfClockManagerGetParams, 0);
    will_return(__wrap_EsfClockManagerGetParams, 0);
    will_return(__wrap_EsfClockManagerGetParams, clock_val);

    // SysAppStateReadoutStaticSettingsIPv6()
    // ip_address
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, ret_val);

    // subnet_mask
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, ret_val);

    // gateway_address
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, ret_val);

    // dns_address
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, ret_val);

    // SysAppStateReadoutStaticSettingsIPv4()
    // ip_address
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, ret_val);

    // subnet_mask
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, ret_val);

    // gateway_address
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, ret_val);

    // dns_address
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, ret_val);

    // SysAppStateReadoutProxySettings()
    // proxy_url
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, ret_val);

    // proxy_port
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, ret_val);

    // Proxy_user_name
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, ret_val);

    // proxy_password
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SysAppStateReadoutWirelessSetting(EsfNetworkManagerResult ret_val)
{
    // SysAppStateReadoutStaModeSetting();
    // ssid
    common_set_EsfNetworkManagerLoadParameterSSID(0, 0, EncWpa2Psk, "ssid", ret_val);

    // password
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, ret_val);

    // encription
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SysAppStateReadoutEndpointSettings(EsfSystemManagerResult ret_val1,
                                                          EsfSystemManagerResult ret_val2)
{
    // malloc(endp_host_buf_size);
    will_return(mock_malloc, false); /* no check size */
    will_return(mock_malloc, true);  /* execute malloc */
    // malloc(endp_port_buf_size);
    will_return(mock_malloc, false); /* no check size */
    will_return(mock_malloc, true);  /* execute malloc */

    // endpoint_url EsfSystemManagerGetEvpHubUrl();
    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, s_evp_hub_url);
    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, ret_val1);

    // endpoint_port EsfSystemManagerGetEvpHubPort();
    will_return(__wrap_EsfSystemManagerGetEvpHubPort, s_evp_hub_port);
    will_return(__wrap_EsfSystemManagerGetEvpHubPort, ret_val2);

    // free(endpoint_url);
    will_return(mock_free, false); /* no check pointer */
    // free(endpoint_port);
    will_return(mock_free, false); /* no check pointer */

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SysAppStateReadoutDeviceCapabilities(RetCode ret_val)
{
    s_scstream = 1;

    common_set_GetSensorPostProcessSupported(s_scstream, &s_expect_img_prop, ret_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SendDeploy(uint32_t topic_bits)
{
    if (topic_bits == ST_TOPIC_DEPLOY_FIRMWARE) {
        // SysAppDeployGetFirmwareState
        will_return(__wrap_SysAppDeployGetFirmwareState, kRetOk);
    }
    else if (topic_bits == ST_TOPIC_DEPLOY_AI_MODEL) {
        // SysAppDeployGetAiModelState
        will_return(__wrap_SysAppDeployGetAiModelState, kRetOk);
    }
    else if (topic_bits == ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM) {
        // SysAppDeployGetSensorCalibrationParamState
        will_return(__wrap_SysAppDeployGetSensorCalibrationParamState, kRetOk);
    }
    else {
        return;
    }

    //  SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SysAppDeployFreeState
    will_return(__wrap_SysAppDeployFreeState, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SendState(EsfJsonHandle handle_val, EsfJsonValue parent_val, size_t bsize,
                                 char *b64_buf, uint32_t expect_b64_size, const char *string_expect,
                                 uint32_t req, char *SendDeviceInfoValue)
{
    if (req & ST_TOPIC_DEVICE_INFO) {
        // SendDeviceInfo();
        common_set_SendDeviceInfo(handle_val, parent_val, string_expect, SendDeviceInfoValue);
    }
    else if (req & ST_TOPIC_DEVICE_CAPABILITIES) {
        // SendDeviceCapabilities();
        common_set_SendDeviceCapabilities(handle_val, parent_val, string_expect, kEsfJsonSuccess);
    }
    else if (req & ST_TOPIC_DEVICE_STATES) {
        // SendDeviceStates();
        common_set_SendDeviceStates(handle_val, parent_val, string_expect, kEsfJsonSuccess);
    }
    else if (req & ST_TOPIC_RESERVED) {
        // SendReserved();
        common_set_SendReserved(handle_val, parent_val, string_expect, kEsfJsonSuccess);
    }
    else if (req & ST_TOPIC_SYSTEM_SETTINGS) {
        // SendSystemSettings();
        common_set_SendSystemSettings(handle_val, parent_val, string_expect, kEsfJsonSuccess);
    }
    else if (req & ST_TOPIC_NETWORK_SETTINGS) {
        // SendNetworkSettings();
        common_set_SendNetworkSettings(handle_val, parent_val, string_expect, kEsfJsonSuccess);
    }
    else if (req & ST_TOPIC_WIRELESS_SETTING) {
        // SendWirelessSetting();
        common_set_SendWirelessSetting(handle_val, parent_val, string_expect, kEsfJsonSuccess);
    }
    else if (req & ST_TOPIC_PERIODIC_SETTING) {
#if defined(CONFIG_BOARD_WIFI_SMALL_ES) //T3Ws
        // SendPeriodicSetting();
        common_set_SendPeriodicSetting(handle_val, parent_val, string_expect, kEsfJsonSuccess);
#else
#endif
    }
    else if (req & ST_TOPIC_ENDPOINT_SETTINGS) {
        // SendEndpointSettings();
        common_set_SendEndpointSettings(handle_val, parent_val, string_expect, kEsfJsonSuccess);
    }
    else if (req & ST_TOPIC_DEPLOY_FIRMWARE) {
        // SendDeploy(ST_TOPIC_DEPLOY_FIRMWARE);
        common_set_SendDeploy(ST_TOPIC_DEPLOY_FIRMWARE);
    }
    else if (req & ST_TOPIC_DEPLOY_AI_MODEL) {
        // SendDeploy(ST_TOPIC_DEPLOY_AI_MODEL);
        common_set_SendDeploy(ST_TOPIC_DEPLOY_AI_MODEL);
    }
    else if (req & ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM) {
        // SendDeploy(ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM);
        common_set_SendDeploy(ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM);
    }
    else if (req & ST_TOPIC_UPDATE_DEVICE_INFO) {
        // SysAppStateReadoutDeviceInfo();
        common_set_SysAppStateReadoutDeviceInfo(b64_buf, expect_b64_size, bsize,
                                                kEsfSystemManagerResultOk,
                                                kEsfCodecBase64ResultSuccess);
        //   ret = SendDeviceInfo();
        common_set_SendDeviceInfo(handle_val, parent_val, string_expect, SendDeviceInfoValue);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void common_set_SysAppStateSendState(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                            size_t bsize, char *b64_buf, uint32_t expect_b64_size,
                                            const char *string_expect, uint32_t req,
                                            char *SendDeviceInfoValue)
{
    common_set_SendState(handle_val, parent_val, bsize, b64_buf, expect_b64_size, string_expect,
                         req, SendDeviceInfoValue);

    return;
}

/*----------------------------------------------------------------------------*/
static RetCode common_Set_GetErrorInfo(CfgStUpdateInfo *update, int *code, char *detail_msg,
                                       int len)
{
    RetCode ret;

    ret = GetErrorInfo(update, code, detail_msg, len);

    return ret;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppState_InitialValueOfGlobalVariable(void **state)
{
    s_sccore = 0;
    s_scstream = 0;
    assert_null(s_sys_client);
    assert_int_equal(s_sccore, 0);
    assert_int_equal(s_scstream, 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_Deploy_FullySuccess()
{
    // SYS_set_state
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SysAppDeployFreeState
    will_return(__wrap_SysAppDeployFreeState, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_RequestConfigStateUpdate_Failed(void **)
{
    RequestConfigStateUpdate(ST_TOPIC_DEVICE_STATES);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_AppendErrorDetail_FullySuccess(void **state)
{
    char buf[32] = "";
    assert_true(AppendErrorDetail("error_1", buf, sizeof(buf)));
    assert_string_equal(buf, "error_1");
    assert_true(AppendErrorDetail("error_2", buf, sizeof(buf)));
    assert_string_equal(buf, "error_1, error_2");
}

/*----------------------------------------------------------------------------*/
static void test_AppendErrorDetail_Truncate(void **state)
{
    char buf[16] = "error_1";
    bool ret = AppendErrorDetail("error_2", buf, sizeof(buf));
    assert_false(ret);
    assert_non_null(strstr(buf, "..."));
}

static void test_AppendErrorDetail_Too_Small_Buffer(void **state)
{
    char buf[TRUNCATION_SUFFIX_LEN] = "";
    bool ret = AppendErrorDetail("error1", buf, sizeof(buf));
    assert_false(ret);
    assert_string_equal(buf, "");
}

/*----------------------------------------------------------------------------*/
static void test_CheckErrorFlagAndAppendMessage_FullySuccess(void **state)
{
    ErrorFlag flags[3] = {{0, "none"}, {1, "err1"}, {2, "err2"}};
    char buf[64] = "";
    bool error_exist = false;
    CheckErrorFlagAndAppendMessage(flags, 3, buf, sizeof(buf), &error_exist);
    assert_true(error_exist);
    assert_string_equal(buf, "err1, err2");
}

/*----------------------------------------------------------------------------*/
static void test_CheckErrorFlagAndAppendMessage_Truncate(void **state)
{
    ErrorFlag flags[3] = {
        {1, "verylongerrormessage1"}, {2, "verylongerrormessage2"}, {3, "verylongerrormessage3"}};
    char buf[32] = "";
    bool error_exist = false;
    CheckErrorFlagAndAppendMessage(flags, 3, buf, sizeof(buf), &error_exist);
    assert_true(error_exist);
    assert_non_null(strstr(buf, "..."));
}

/*----------------------------------------------------------------------------*/
static void test_CheckErrorFlagAndAppendMessageWithField_FullySuccess(void **state)
{
    char buf[64] = "";
    bool error_exist = false;
    CheckErrorFlagAndAppendMessageWithField("prefix", "field", 2, buf, sizeof(buf), &error_exist);
    assert_true(error_exist);
    assert_string_equal(buf, "prefix field[2]");

    char buf2[64] = "";
    bool error_exist2 = false;
    CheckErrorFlagAndAppendMessageWithField("prefix2", NULL, 0, buf2, sizeof(buf2), &error_exist2);
    assert_true(error_exist2);
    assert_string_equal(buf2, "prefix2");
}

/*----------------------------------------------------------------------------*/
static void common_set_GetSensorLoaderVersion(senscord_stream_t scstream, int32_t ret_val)
{
    struct senscord_info_string_property_t strinfo = {0};

    if (s_scstream) {
        // senscord_stream_get_property
        expect_value(__wrap_senscord_stream_get_property, stream, scstream);
        expect_string(__wrap_senscord_stream_get_property, property_key,
                      SENSCORD_INFO_STRING_PROPERTY_KEY);
        expect_value(__wrap_senscord_stream_get_property, value_size,
                     sizeof(struct senscord_info_string_property_t));
        will_return(__wrap_senscord_stream_get_property, &strinfo);
        will_return(__wrap_senscord_stream_get_property, ret_val);
    }
    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetSensorLoaderVersion_FullySuccess(void **)
{
    RetCode ret;
    char buf[10];

    s_scstream = 1;

    common_set_GetSensorLoaderVersion(s_scstream, kRetOk);

    ret = GetSensorLoaderVersion(buf, sizeof(buf));

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetSensorLoaderVersion_Faild(void **)
{
    RetCode ret;
    char buf[10];

    s_scstream = 0;

    ret = GetSensorLoaderVersion(buf, sizeof(buf));

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetSensorFirmwareVersion_Faild(void **)
{
    RetCode ret;
    char buf[10];

    s_scstream = 0;

    ret = GetSensorFirmwareVersion(buf, sizeof(buf));

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
// STATIC RetCode MakeJsonAiModel(EsfJsonHandle handle, EsfJsonValue root)
/*----------------------------------------------------------------------------*/
static void test_MakeJsonAiModel_fully_success(void **)
{
    EsfJsonHandle handle = 0;
    EsfJsonValue root = 0;
    uint32_t ctx;
    RetCode ret;

    for (uint32_t no = 0; no < ST_AIMODELS_NUM; no++) {
        common_set_MakeJsonAiModel(handle, root, no, kRetOk);

        ret = MakeJsonAiModel(handle, root, no, &ctx);

        assert_int_equal(ret, kRetOk);
    }
}

/*----------------------------------------------------------------------------*/
// STATIC RetCode MakeJsonChips(EsfJsonHandle handle, EsfJsonValue root)
/*----------------------------------------------------------------------------*/
static void test_MakeJsonChips_fully_success(void **)
{
    EsfJsonHandle handle = 0;
    EsfJsonValue root = 0;
    uint32_t ctx;
    RetCode ret;

    for (uint32_t no = 0; no < ST_CHIPS_NUM; no++) {
        common_set_MakeJsonChips(handle, root, no, kRetOk);

        ret = MakeJsonChips(handle, root, no, (void *)&ctx);

        assert_int_equal(ret, kRetOk);
    }
}

/*----------------------------------------------------------------------------*/
// STATIC RetCode MakeJsonDeviceInfo(EsfJsonHandle handle, EsfJsonValue root)
/*----------------------------------------------------------------------------*/
static void test_MakeJsonDeviceInfo_fully_success(void **)
{
    EsfJsonHandle handle = 0;
    EsfJsonValue root = 0;

    common_set_MakeJsonDeviceInfo(handle, root, kRetOk);

    RetCode ret = MakeJsonDeviceInfo(handle, root);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
// STATIC RetCode MakeJsonDeviceCapabilities(EsfJsonHandle handle, EsfJsonValue root)
/*----------------------------------------------------------------------------*/
static void test_MakeJsonDeviceCapabilities_fully_success(void **)
{
    EsfJsonHandle handle = 0;
    EsfJsonValue root = 0;

    common_set_MakeJsonDeviceCapabilities(handle, root, kRetOk);

    RetCode ret = MakeJsonDeviceCapabilities(handle, root);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
// STATIC RetCode MakeJsonPowerSource(EsfJsonHandle handle, EsfJsonValue root, uint32_t no, void* ctx)
/*----------------------------------------------------------------------------*/
static void test_MakeJsonPowerSource_fully_success(void **)
{
    EsfJsonHandle handle = 0;
    EsfJsonValue root = 0;
    uint32_t ctx;

    for (uint32_t no = 0; no < PowerSourceNum; no++) {
        common_set_MakeJsonPowerSource(handle, root, no, kRetOk);

        RetCode ret = MakeJsonPowerSource(handle, root, no, &ctx);

        assert_int_equal(ret, kRetOk);
    }
    return;
}

/*----------------------------------------------------------------------------*/
// STATIC RetCode MakeJsonPowerStates(EsfJsonHandle handle, EsfJsonValue root, void* ctx)
/*----------------------------------------------------------------------------*/
static void test_MakeJsonPowerStates(void **)
{
    RetCode ret;
    EsfJsonHandle handle = 0;
    EsfJsonValue parent = 0;

    common_set_MakeJsonPowerStates(handle, parent, kRetOk);

    ret = MakeJsonPowerStates(handle, parent, "");

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
// STATIC RetCode MakeJsonDeviceStates(EsfJsonHandle handle, EsfJsonValue root)
/*----------------------------------------------------------------------------*/
static void test_MakeJsonDeviceStates(void **)
{
    RetCode ret;
    EsfJsonHandle handle = 0;
    EsfJsonValue parent = 0;

    common_set_MakeJsonDeviceStates(handle, parent, kRetOk);

    ret = MakeJsonDeviceStates(handle, parent);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
// STATIC RetCode MakeJsonReserved(EsfJsonHandle handle, EsfJsonValue root)
/*----------------------------------------------------------------------------*/
static void test_MakeJsonReserved(void **)
{
    RetCode ret;
    EsfJsonHandle handle = 0;
    EsfJsonValue parent = 0;

    common_set_MakeJsonReserved(handle, parent, kRetOk);

    ret = MakeJsonReserved(handle, parent);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
// STATIC RetCode MakeJsonLog(EsfJsonHandle handle, EsfJsonValue root, uint32_t idx, void* ctx)
/*----------------------------------------------------------------------------*/
static void test_MakeJsonLog(void **)
{
    RetCode ret;
    EsfJsonHandle handle = 0;
    EsfJsonValue parent = 0;
    uint32_t idx = 1;

    common_set_MakeJsonLog(handle, parent, idx, kRetOk);

    ret = MakeJsonLog(handle, parent, idx, NULL);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonLog_FailedNotFound(void **)
{
    RetCode ret;
    EsfJsonHandle handle = 0;
    EsfJsonValue parent = 0;
    uint32_t idx = 0;

    ret = MakeJsonLog(handle, parent, idx, NULL);

    assert_int_equal(ret, kRetNotFound);

    return;
}

/*----------------------------------------------------------------------------*/
// STATIC RetCode MakeJsonSystemSettings(EsfJsonHandle handle, EsfJsonValue root)
/*----------------------------------------------------------------------------*/
static void test_MakeJsonSystemSettings(void **)
{
    RetCode ret;
    EsfJsonHandle handle = 0;
    EsfJsonValue parent = 0;

    common_set_MakeJsonSystemSettings(handle, parent, kRetOk);

    ret = MakeJsonSystemSettings(handle, parent);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
// STATIC RetCode MakeJsonStaticSettingsIPv6(EsfJsonHandle handle, EsfJsonValue root, void* ctx)
/*----------------------------------------------------------------------------*/
static void test_MakeJsonStaticSettingsIPv6(void **)
{
    RetCode ret;
    EsfJsonHandle handle = 0;
    EsfJsonValue parent = 0;

    common_set_MakeJsonStaticSettingsIPv6(handle, parent, kRetOk);

    ret = MakeJsonStaticSettingsIPv6(handle, parent, "");

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
// STATIC RetCode MakeJsonStaticSettingsIPv4(EsfJsonHandle handle, EsfJsonValue root, void* ctx)
/*----------------------------------------------------------------------------*/
static void test_MakeJsonStaticSettingsIPv4(void **)
{
    RetCode ret;
    EsfJsonHandle handle = 0;
    EsfJsonValue parent = 0;

    common_set_MakeJsonStaticSettingsIPv4(handle, parent, kRetOk);

    ret = MakeJsonStaticSettingsIPv4(handle, parent, "");

    assert_int_equal(ret, kRetOk);

    return;
}
/*----------------------------------------------------------------------------*/
// STATIC RetCode MakeJsonProxySettings(EsfJsonHandle handle, EsfJsonValue root, void* ctx)
/*----------------------------------------------------------------------------*/
static void test_MakeJsonProxySettings(void **)
{
    RetCode ret;
    EsfJsonHandle handle = 0;
    EsfJsonValue parent = 0;

    common_set_MakeJsonProxySettings(handle, parent, kRetOk);

    ret = MakeJsonProxySettings(handle, parent, "");

    assert_int_equal(ret, kRetOk);

    return;
}
/*----------------------------------------------------------------------------*/
// STATIC RetCode MakeJsonNetworkSettings(EsfJsonHandle handle, EsfJsonValue root)
/*----------------------------------------------------------------------------*/
static void test_MakeJsonNetworkSettings(void **)
{
    RetCode ret;
    EsfJsonHandle handle = 0;
    EsfJsonValue parent = 0;

    common_set_MakeJsonNetworkSettings(handle, parent, kRetOk);

    ret = MakeJsonNetworkSettings(handle, parent);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
// STATIC RetCode MakeJsonStaModeSetting(EsfJsonHandle handle, EsfJsonValue root, void* ctx)
/*----------------------------------------------------------------------------*/
static void test_MakeJsonStaModeSetting(void **)
{
    RetCode ret;
    EsfJsonHandle handle = 0;
    EsfJsonValue parent = 0;

    common_set_MakeJsonStaModeSetting(handle, parent, kRetOk);

    ret = MakeJsonStaModeSetting(handle, parent, "");

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
// STATIC RetCode MakeJsonWirelessSetting(EsfJsonHandle handle, EsfJsonValue root)
/*----------------------------------------------------------------------------*/
static void test_MakeJsonWirelessSetting(void **)
{
    RetCode ret;
    EsfJsonHandle handle = 0;
    EsfJsonValue parent = 0;

    common_set_MakeJsonWirelessSetting(handle, parent, kRetOk);

    ret = MakeJsonWirelessSetting(handle, parent);

    assert_int_equal(ret, kRetOk);

    return;
}

#if defined(CONFIG_BOARD_WIFI_SMALL_ES) //T3Ws
/*----------------------------------------------------------------------------*/
// STATIC RetCode MakeJsonIntervalSettings(EsfJsonHandle handle, EsfJsonValue root, uint32_t idx, void* ctx)
/*----------------------------------------------------------------------------*/
static void test_MakeJsonIntervalSettings(void **)
{
    RetCode ret;
    EsfJsonHandle handle = 0;
    EsfJsonValue parent = 0;

    common_set_MakeJsonIntervalSettings(handle, parent, kRetOk);

    ret = MakeJsonIntervalSettings(handle, parent, 0, "");

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
// STATIC RetCode MakeJsonPeriodicSetting(EsfJsonHandle handle, EsfJsonValue root)
/*----------------------------------------------------------------------------*/
static void test_MakeJsonPeriodicSetting(void **)
{
    RetCode ret;
    EsfJsonHandle handle = 0;
    EsfJsonValue parent = 0;

    common_set_MakeJsonPeriodicSetting(handle, parent, kRetOk);

    ret = MakeJsonPeriodicSetting(handle, parent);

    assert_int_equal(ret, kRetOk);

    return;
}
#else
#endif

/*----------------------------------------------------------------------------*/
// STATIC RetCode MakeJsonEndpointSettings(EsfJsonHandle handle, EsfJsonValue root)
/*----------------------------------------------------------------------------*/
static void test_MakeJsonEndpointSettings(void **)
{
    RetCode ret;
    EsfJsonHandle handle = 0;
    EsfJsonValue parent = 0;

    common_set_MakeJsonEndpointSettings(handle, parent, kRetOk);

    ret = MakeJsonEndpointSettings(handle, parent);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetSensorInfo_stream_Failed(void **)
{
    RetCode ret;

    s_scstream = 0;

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
    ret = GetSensorInfo(AiIspDeviceId, s_chips[CHIPS_IDX_COMPANION_CHIP].id,
                        sizeof(s_chips[CHIPS_IDX_COMPANION_CHIP].id));
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
    ret = GetSensorInfo(SensorId, s_chips[CHIPS_IDX_SENSOR_CHIP].id,
                        sizeof(s_chips[CHIPS_IDX_SENSOR_CHIP].id));
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConvertFilterValueToString(void **)
{
    char filter_name[CFGST_LOG_FILTER_LEN + 1] = "";

    ConvertFilterValueToString(AllLog, filter_name);
    ConvertFilterValueToString(MainFwLog, filter_name);
    ConvertFilterValueToString(SensorLog, filter_name);
    ConvertFilterValueToString(CompanionFwLog, filter_name);
    ConvertFilterValueToString(CompanionAppLog, filter_name);
    ConvertFilterValueToString(LogFilterNum, filter_name);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ReadOutLogByFilterNo_Failed(void **)
{
    const char *storage_name_1st = "";

    // SysAppLogGetParameterNumber
    will_return(__wrap_SysAppLogGetParameterNumber, LogLevel);
    will_return(__wrap_SysAppLogGetParameterNumber, ErrorLv);
    will_return(__wrap_SysAppLogGetParameterNumber, kRetFailed);

    // SysAppLogGetParameterNumber
    will_return(__wrap_SysAppLogGetParameterNumber, LogLevel);
    will_return(__wrap_SysAppLogGetParameterNumber, ErrorLv);
    will_return(__wrap_SysAppLogGetParameterNumber, kRetFailed);

    // SysAppLogGetParameterString
    will_return(__wrap_SysAppLogGetParameterString, storage_name_1st);
    will_return(__wrap_SysAppLogGetParameterString, kRetFailed);

    // SysAppLogGetParameterString
    will_return(__wrap_SysAppLogGetParameterString, storage_name_1st);
    will_return(__wrap_SysAppLogGetParameterString, kRetFailed);
    ReadOutLogByFilterNo(MainFwLog);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ReadOutLogByFilterNo_filter_Failed(void **)
{
    ReadOutLogByFilterNo(LogFilterNum);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonReqInfoCore(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    common_set_MakeJsonReqInfoCore(handle_val, parent_val, "req_id", "req_id", kRetOk);

    ret = MakeJsonReqInfoCore(handle_val, parent_val, "req_id");

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonReqInfoSystemSettings()
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    common_set_MakeJsonReqInfoCore(handle_val, parent_val, "req_id", "", kRetOk);

    ret = MakeJsonReqInfoSystemSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonReqInfoNetworkSettings()
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    common_set_MakeJsonReqInfoCore(handle_val, parent_val, "req_id", "", kRetOk);

    ret = MakeJsonReqInfoNetworkSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonReqInfoWirelessSetting()
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    common_set_MakeJsonReqInfoCore(handle_val, parent_val, "req_id", "", kRetOk);

    ret = MakeJsonReqInfoWirelessSetting(handle_val, parent_val, "");

    assert_int_equal(ret, kRetOk);

    return;
}

#if defined(CONFIG_BOARD_WIFI_SMALL_ES) //T3Ws
/*----------------------------------------------------------------------------*/
static void test_MakeJsonReqInfoPeriodicSetting()
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    common_set_MakeJsonReqInfoCore(handle_val, parent_val, "req_id", "", kRetOk);

    ret = MakeJsonReqInfoPeriodicSetting(handle_val, parent_val, "");

    assert_int_equal(ret, kRetOk);

    return;
}
#else
#endif

/*----------------------------------------------------------------------------*/
static void test_MakeJsonReqInfoEndpointSettings()
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    common_set_MakeJsonReqInfoCore(handle_val, parent_val, "req_id", "", kRetOk);

    ret = MakeJsonReqInfoEndpointSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetErrorInfo_FullySuccess(void **)
{
    RetCode ret;
    CfgStUpdateInfo update;
    int code = 0;
    char detail_msg[256] = "ok";

    memset(&update, 0, sizeof(update));

    ret = common_Set_GetErrorInfo(&update, &code, detail_msg, sizeof(detail_msg));

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetErrorInfo_arg_flag(void **)
{
    RetCode ret;
    CfgStUpdateInfo update;
    int code = 0;
    char detail_msg[256] = "ok";

    memset(&update, 0, sizeof(update));
    update.invalid_arg_flag = 1;
    update.internal_error_flag = 0;

    ret = common_Set_GetErrorInfo(&update, &code, detail_msg, sizeof(detail_msg));

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetErrorInfo_error_flag(void **)
{
    RetCode ret;
    CfgStUpdateInfo update;
    int code = 0;
    char detail_msg[256] = "ok";

    memset(&update, 0, sizeof(update));
    update.invalid_arg_flag = 0;
    update.internal_error_flag = 1;

    ret = common_Set_GetErrorInfo(&update, &code, detail_msg, sizeof(detail_msg));

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoSystemSettings_FullySuccess(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_system_settings, 0, sizeof(s_system_settings));
    memset(s_log, 0, sizeof(s_log));

    common_set_MakeJsonResInfoSystemSettings(handle_val, parent_val, 0, "ok", kRetOk);

    ret = MakeJsonResInfoSystemSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoSystemSettings_invalid_arg_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_system_settings, 0, sizeof(s_system_settings));
    memset(s_log, 0, sizeof(s_log));

    s_system_settings.update.invalid_arg_flag = 1;
    s_log[AllLog].update.invalid_arg_flag = 1;

    common_set_MakeJsonResInfoSystemSettings(handle_val, parent_val, 0x03, "invalid_argument",
                                             kRetFailed);

    ret = MakeJsonResInfoSystemSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoSystemSettings_invalid_led_enabled_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_system_settings, 0, sizeof(s_system_settings));
    memset(s_log, 0, sizeof(s_log));

    s_system_settings.invalid_led_enabled_flag = 1;

    common_set_MakeJsonResInfoSystemSettings(handle_val, parent_val, 0x03, "led enabled is invalid",
                                             kRetFailed);

    ret = MakeJsonResInfoSystemSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoSystemSettings_invalid_temperature_update_interval_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_system_settings, 0, sizeof(s_system_settings));
    memset(s_log, 0, sizeof(s_log));

    s_system_settings.invalid_temperature_update_interval_flag = 1;

    common_set_MakeJsonResInfoSystemSettings(handle_val, parent_val, 0x03,
                                             "invalid temperature update interval", kRetFailed);

    ret = MakeJsonResInfoSystemSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoSystemSettings_invalid_filter_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_system_settings, 0, sizeof(s_system_settings));
    memset(s_log, 0, sizeof(s_log));

    s_log[AllLog].invalid_filter_flag = 1;

    common_set_MakeJsonResInfoSystemSettings(handle_val, parent_val, 0x03, "invalid filter",
                                             kRetFailed);

    ret = MakeJsonResInfoSystemSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoSystemSettings_invalid_level_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_system_settings, 0, sizeof(s_system_settings));
    memset(s_log, 0, sizeof(s_log));

    s_log[MainFwLog].invalid_level_flag = 1;

    common_set_MakeJsonResInfoSystemSettings(handle_val, parent_val, 0x03, "invalid level[1]",
                                             kRetFailed);

    ret = MakeJsonResInfoSystemSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoSystemSettings_invalid_destination_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_system_settings, 0, sizeof(s_system_settings));
    memset(s_log, 0, sizeof(s_log));

    s_log[MainFwLog].invalid_destination_flag = 1;

    common_set_MakeJsonResInfoSystemSettings(handle_val, parent_val, 0x03, "invalid destination[1]",
                                             kRetFailed);

    ret = MakeJsonResInfoSystemSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoSystemSettings_invalid_storage_name_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_system_settings, 0, sizeof(s_system_settings));
    memset(s_log, 0, sizeof(s_log));

    s_log[MainFwLog].invalid_storage_name_flag = 1;

    common_set_MakeJsonResInfoSystemSettings(handle_val, parent_val, 0x03,
                                             "invalid storage name[1]", kRetFailed);

    ret = MakeJsonResInfoSystemSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoSystemSettings_invalid_path_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_system_settings, 0, sizeof(s_system_settings));
    memset(s_log, 0, sizeof(s_log));

    s_log[MainFwLog].invalid_path_flag = 1;

    common_set_MakeJsonResInfoSystemSettings(handle_val, parent_val, 0x03, "invalid path[1]",
                                             kRetFailed);

    ret = MakeJsonResInfoSystemSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoSystemSettings_too_long_detail_msg(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_system_settings, 0, sizeof(s_system_settings));
    memset(s_log, 0, sizeof(s_log));

    s_system_settings.invalid_led_enabled_flag = 1;
    s_system_settings.invalid_temperature_update_interval_flag = 1;
    s_log[MainFwLog].invalid_level_flag = 1;
    s_log[MainFwLog].invalid_destination_flag = 1;
    s_log[MainFwLog].invalid_storage_name_flag = 1;
    s_log[MainFwLog].invalid_path_flag = 1;
    s_log[SensorLog].invalid_level_flag = 1;
    s_log[SensorLog].invalid_destination_flag = 1;
    s_log[SensorLog].invalid_storage_name_flag = 1;
    s_log[SensorLog].invalid_path_flag = 1;
    s_log[CompanionFwLog].invalid_level_flag = 1;
    s_log[CompanionFwLog].invalid_destination_flag = 1;
    s_log[CompanionFwLog].invalid_storage_name_flag = 1;
    s_log[CompanionFwLog].invalid_path_flag = 1;

    common_set_MakeJsonResInfoSystemSettings(
        handle_val, parent_val, 0x03,
        "led enabled is invalid, invalid temperature update interval, invalid level[1], invalid "
        "destination[1], invalid storage name[1], invalid path[1], invalid level[2], invalid "
        "destination[2], invalid storage name[2], invalid path[2], invalid level[3]...",
        kRetFailed);

    ret = MakeJsonResInfoSystemSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoSystemSettings_internal_error_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_system_settings, 0, sizeof(s_system_settings));
    memset(s_log, 0, sizeof(s_log));

    s_system_settings.update.internal_error_flag = 1;
    s_log[AllLog].update.internal_error_flag = 1;

    common_set_MakeJsonResInfoSystemSettings(handle_val, parent_val, 0x0d, "internal", kRetFailed);

    ret = MakeJsonResInfoSystemSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoNetworkSettings_FullySuccess(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_network_settings, 0, sizeof(s_network_settings));
    memset(&s_static_settings_ipv4, 0, sizeof(s_static_settings_ipv4));
    memset(&s_static_settings_ipv6, 0, sizeof(s_static_settings_ipv6));
    memset(&s_proxy_settings, 0, sizeof(s_proxy_settings));

    common_set_MakeJsonResInfoNetworkSettings(handle_val, parent_val, 0, "ok", kRetOk);

    ret = MakeJsonResInfoNetworkSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoNetworkSettings_invalid_arg_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_network_settings, 0, sizeof(s_network_settings));
    memset(&s_static_settings_ipv4, 0, sizeof(s_static_settings_ipv4));
    memset(&s_static_settings_ipv6, 0, sizeof(s_static_settings_ipv6));
    memset(&s_proxy_settings, 0, sizeof(s_proxy_settings));

    s_network_settings.update.invalid_arg_flag = 1;
    s_static_settings_ipv4.update.invalid_arg_flag = 1;
    s_proxy_settings.update.invalid_arg_flag = 1;

    common_set_MakeJsonResInfoNetworkSettings(handle_val, parent_val, 0x03, "invalid_argument",
                                              kRetFailed);

    ret = MakeJsonResInfoNetworkSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoNetworkSettings_invalid_ip_method_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_network_settings, 0, sizeof(s_network_settings));
    memset(&s_static_settings_ipv4, 0, sizeof(s_static_settings_ipv4));
    memset(&s_static_settings_ipv6, 0, sizeof(s_static_settings_ipv6));
    memset(&s_proxy_settings, 0, sizeof(s_proxy_settings));

    s_network_settings.invalid_ip_method_flag = 1;

    common_set_MakeJsonResInfoNetworkSettings(handle_val, parent_val, 0x03,
                                              "can't change ip method", kRetFailed);

    ret = MakeJsonResInfoNetworkSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoNetworkSettings_invalid_ip_address_ipv4_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_network_settings, 0, sizeof(s_network_settings));
    memset(&s_static_settings_ipv4, 0, sizeof(s_static_settings_ipv4));
    memset(&s_static_settings_ipv6, 0, sizeof(s_static_settings_ipv6));
    memset(&s_proxy_settings, 0, sizeof(s_proxy_settings));

    s_static_settings_ipv4.invalid_ip_address_flag = 1;

    common_set_MakeJsonResInfoNetworkSettings(handle_val, parent_val, 0x03,
                                              "invalid ip address(ipv4)", kRetFailed);

    ret = MakeJsonResInfoNetworkSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoNetworkSettings_invalid_subnet_mask_ipv4_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_network_settings, 0, sizeof(s_network_settings));
    memset(&s_static_settings_ipv4, 0, sizeof(s_static_settings_ipv4));
    memset(&s_static_settings_ipv6, 0, sizeof(s_static_settings_ipv6));
    memset(&s_proxy_settings, 0, sizeof(s_proxy_settings));

    s_static_settings_ipv4.invalid_subnet_mask_flag = 1;

    common_set_MakeJsonResInfoNetworkSettings(handle_val, parent_val, 0x03,
                                              "invalid subnet mask(ipv4)", kRetFailed);

    ret = MakeJsonResInfoNetworkSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoNetworkSettings_invalid_gateway_address_ipv4_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_network_settings, 0, sizeof(s_network_settings));
    memset(&s_static_settings_ipv4, 0, sizeof(s_static_settings_ipv4));
    memset(&s_static_settings_ipv6, 0, sizeof(s_static_settings_ipv6));
    memset(&s_proxy_settings, 0, sizeof(s_proxy_settings));

    s_static_settings_ipv4.invalid_gateway_address_flag = 1;

    common_set_MakeJsonResInfoNetworkSettings(handle_val, parent_val, 0x03,
                                              "invalid gateway address(ipv4)", kRetFailed);

    ret = MakeJsonResInfoNetworkSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoNetworkSettings_invalid_dns_address_ipv4_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_network_settings, 0, sizeof(s_network_settings));
    memset(&s_static_settings_ipv4, 0, sizeof(s_static_settings_ipv4));
    memset(&s_static_settings_ipv6, 0, sizeof(s_static_settings_ipv6));
    memset(&s_proxy_settings, 0, sizeof(s_proxy_settings));

    s_static_settings_ipv4.invalid_dns_address_flag = 1;

    common_set_MakeJsonResInfoNetworkSettings(handle_val, parent_val, 0x03,
                                              "invalid dns address(ipv4)", kRetFailed);

    ret = MakeJsonResInfoNetworkSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoNetworkSettings_invalid_proxy_url_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_network_settings, 0, sizeof(s_network_settings));
    memset(&s_static_settings_ipv4, 0, sizeof(s_static_settings_ipv4));
    memset(&s_static_settings_ipv6, 0, sizeof(s_static_settings_ipv6));
    memset(&s_proxy_settings, 0, sizeof(s_proxy_settings));

    s_proxy_settings.invalid_proxy_url_flag = 1;

    common_set_MakeJsonResInfoNetworkSettings(handle_val, parent_val, 0x03, "invalid proxy url",
                                              kRetFailed);

    ret = MakeJsonResInfoNetworkSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoNetworkSettings_invalid_proxy_port_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_network_settings, 0, sizeof(s_network_settings));
    memset(&s_static_settings_ipv4, 0, sizeof(s_static_settings_ipv4));
    memset(&s_static_settings_ipv6, 0, sizeof(s_static_settings_ipv6));
    memset(&s_proxy_settings, 0, sizeof(s_proxy_settings));

    s_proxy_settings.invalid_proxy_port_flag = 1;

    common_set_MakeJsonResInfoNetworkSettings(handle_val, parent_val, 0x03, "invalid proxy port",
                                              kRetFailed);

    ret = MakeJsonResInfoNetworkSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoNetworkSettings_invalid_proxy_user_name_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_network_settings, 0, sizeof(s_network_settings));
    memset(&s_static_settings_ipv4, 0, sizeof(s_static_settings_ipv4));
    memset(&s_static_settings_ipv6, 0, sizeof(s_static_settings_ipv6));
    memset(&s_proxy_settings, 0, sizeof(s_proxy_settings));

    s_proxy_settings.invalid_proxy_user_name_flag = 1;

    common_set_MakeJsonResInfoNetworkSettings(handle_val, parent_val, 0x03,
                                              "invalid proxy user name", kRetFailed);

    ret = MakeJsonResInfoNetworkSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoNetworkSettings_invalid_proxy_password_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_network_settings, 0, sizeof(s_network_settings));
    memset(&s_static_settings_ipv4, 0, sizeof(s_static_settings_ipv4));
    memset(&s_static_settings_ipv6, 0, sizeof(s_static_settings_ipv6));
    memset(&s_proxy_settings, 0, sizeof(s_proxy_settings));

    s_proxy_settings.invalid_proxy_password_flag = 1;

    common_set_MakeJsonResInfoNetworkSettings(handle_val, parent_val, 0x03,
                                              "invalid proxy password", kRetFailed);

    ret = MakeJsonResInfoNetworkSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoNetworkSettings_invalid_ntp_url_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_network_settings, 0, sizeof(s_network_settings));
    memset(&s_static_settings_ipv4, 0, sizeof(s_static_settings_ipv4));
    memset(&s_static_settings_ipv6, 0, sizeof(s_static_settings_ipv6));
    memset(&s_proxy_settings, 0, sizeof(s_proxy_settings));

    s_network_settings.invalid_ntp_url_flag = 1;

    common_set_MakeJsonResInfoNetworkSettings(handle_val, parent_val, 0x03, "invalid ntp url",
                                              kRetFailed);

    ret = MakeJsonResInfoNetworkSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoNetworkSettings_internal_error_flag1(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_network_settings, 0, sizeof(s_network_settings));
    memset(&s_static_settings_ipv4, 0, sizeof(s_static_settings_ipv4));
    memset(&s_static_settings_ipv6, 0, sizeof(s_static_settings_ipv6));
    memset(&s_proxy_settings, 0, sizeof(s_proxy_settings));

    s_network_settings.update.internal_error_flag = 1;
    s_static_settings_ipv4.update.internal_error_flag = 1;
    s_proxy_settings.update.internal_error_flag = 1;

    common_set_MakeJsonResInfoNetworkSettings(handle_val, parent_val, 13, "internal", kRetFailed);

    ret = MakeJsonResInfoNetworkSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoNetworkSettings_internal_error_flag2(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_network_settings, 0, sizeof(s_network_settings));
    memset(&s_static_settings_ipv4, 0, sizeof(s_static_settings_ipv4));
    memset(&s_static_settings_ipv6, 0, sizeof(s_static_settings_ipv6));
    memset(&s_proxy_settings, 0, sizeof(s_proxy_settings));

    s_network_settings.update.internal_error_flag = 1;
    s_static_settings_ipv6.update.internal_error_flag = 1;
    s_proxy_settings.update.internal_error_flag = 1;

    common_set_MakeJsonResInfoNetworkSettings(handle_val, parent_val, 13, "internal", kRetFailed);

    ret = MakeJsonResInfoNetworkSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoWirelessSetting_FullySuccess(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_wireless_setting, 0, sizeof(s_wireless_setting));
    memset(&s_sta_mode_setting, 0, sizeof(s_sta_mode_setting));

    common_set_MakeJsonResInfoWirelessSetting(handle_val, parent_val, 0, "ok", kRetOk);

    ret = MakeJsonResInfoWirelessSetting(handle_val, parent_val, "");

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoWirelessSetting_invalid_arg_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_wireless_setting, 0, sizeof(s_wireless_setting));
    memset(&s_sta_mode_setting, 0, sizeof(s_sta_mode_setting));
    memset(s_log, 0, sizeof(s_log));
    s_wireless_setting.update.invalid_arg_flag = 1;
    s_sta_mode_setting.update.invalid_arg_flag = 1;

    common_set_MakeJsonResInfoWirelessSetting(handle_val, parent_val, 0x03, "invalid_argument",
                                              kRetFailed);

    ret = MakeJsonResInfoWirelessSetting(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoWirelessSetting_invalid_ssid_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_sta_mode_setting, 0, sizeof(s_sta_mode_setting));
    s_sta_mode_setting.invalid_ssid_flag = 1;

    common_set_MakeJsonResInfoWirelessSetting(handle_val, parent_val, 0x03, "invalid ssid",
                                              kRetFailed);

    ret = MakeJsonResInfoWirelessSetting(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoWirelessSetting_invalid_password_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_sta_mode_setting, 0, sizeof(s_sta_mode_setting));
    s_sta_mode_setting.invalid_password_flag = 1;

    common_set_MakeJsonResInfoWirelessSetting(handle_val, parent_val, 0x03, "invalid password",
                                              kRetFailed);

    ret = MakeJsonResInfoWirelessSetting(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoWirelessSetting_invalid_encryption_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_sta_mode_setting, 0, sizeof(s_sta_mode_setting));
    s_sta_mode_setting.invalid_encryption_flag = 1;

    common_set_MakeJsonResInfoWirelessSetting(handle_val, parent_val, 0x03, "invalid encryption",
                                              kRetFailed);

    ret = MakeJsonResInfoWirelessSetting(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoWirelessSetting_invalid_ssid_password_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_sta_mode_setting, 0, sizeof(s_sta_mode_setting));
    s_sta_mode_setting.invalid_ssid_flag = 1;
    s_sta_mode_setting.invalid_password_flag = 1;

    common_set_MakeJsonResInfoWirelessSetting(handle_val, parent_val, 0x03,
                                              "invalid ssid, invalid password", kRetFailed);

    ret = MakeJsonResInfoWirelessSetting(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoWirelessSetting_invalid_ssid_encryption_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_sta_mode_setting, 0, sizeof(s_sta_mode_setting));
    s_sta_mode_setting.invalid_ssid_flag = 1;
    s_sta_mode_setting.invalid_encryption_flag = 1;

    common_set_MakeJsonResInfoWirelessSetting(handle_val, parent_val, 0x03,
                                              "invalid ssid, invalid encryption", kRetFailed);

    ret = MakeJsonResInfoWirelessSetting(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoWirelessSetting_invalid_password_encryption_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_sta_mode_setting, 0, sizeof(s_sta_mode_setting));
    s_sta_mode_setting.invalid_password_flag = 1;
    s_sta_mode_setting.invalid_encryption_flag = 1;

    common_set_MakeJsonResInfoWirelessSetting(handle_val, parent_val, 0x03,
                                              "invalid password, invalid encryption", kRetFailed);

    ret = MakeJsonResInfoWirelessSetting(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoWirelessSetting_invalid_ssid_password_encryption_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_sta_mode_setting, 0, sizeof(s_sta_mode_setting));
    s_sta_mode_setting.invalid_ssid_flag = 1;
    s_sta_mode_setting.invalid_password_flag = 1;
    s_sta_mode_setting.invalid_encryption_flag = 1;

    common_set_MakeJsonResInfoWirelessSetting(handle_val, parent_val, 0x03,
                                              "invalid ssid, invalid password, invalid encryption",
                                              kRetFailed);

    ret = MakeJsonResInfoWirelessSetting(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoWirelessSetting_internal_error_flag(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_wireless_setting, 0, sizeof(s_wireless_setting));
    memset(&s_sta_mode_setting, 0, sizeof(s_sta_mode_setting));
    s_sta_mode_setting.update.internal_error_flag = 1;

    common_set_MakeJsonResInfoWirelessSetting(handle_val, parent_val, 0x0d, "internal", kRetFailed);

    ret = MakeJsonResInfoWirelessSetting(handle_val, parent_val, "");

    assert_int_equal(ret, kRetFailed);

    return;
}

#if defined(CONFIG_BOARD_WIFI_SMALL_ES) //T3Ws
/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoPeriodicSetting_FullySuccess(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_wireless_setting, 0, sizeof(s_wireless_setting));
    memset(&s_sta_mode_setting, 0, sizeof(s_sta_mode_setting));

    // SysAppCmnMakeJsonResInfo
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, parent_val);
    expect_not_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, "");
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    //  common_set_MakeJsonResInfoWirelessSetting(handle_val,parent_val, 0, "ok", kRetOk);

    ret = MakeJsonResInfoPeriodicSetting(handle_val, parent_val, "");

    assert_int_equal(ret, kRetOk);

    return;
}
#else
#endif

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoEndpointSettings_FullySuccess(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;

    memset(&s_wireless_setting, 0, sizeof(s_wireless_setting));
    memset(&s_sta_mode_setting, 0, sizeof(s_sta_mode_setting));

    // SysAppCmnMakeJsonResInfo
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, parent_val);
    expect_not_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, "");
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    //  common_set_MakeJsonResInfoWirelessSetting(handle_val,parent_val, 0, "ok", kRetOk);

    ret = MakeJsonResInfoEndpointSettings(handle_val, parent_val, "");

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetSensorTemperature_Success(void **)
{
    RetCode ret;
    int temperature = TEMPERATURE_UPPER_APPROACHING_THRESHOLD;

    s_scstream = 1;

    common_set_GetSensorTemperature(s_scstream, (float)temperature, 0, 0);

    ret = GetSensorTemperature(0);

    assert_int_equal(ret, temperature);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetSensorTemperature_Upper(void **)
{
    RetCode ret;
    int temperature = TEMPERATURE_UPPER_THRESHOLD + 1;

    s_scstream = 1;

    common_set_GetSensorTemperature(s_scstream, (float)temperature, 0, 0);

    ret = GetSensorTemperature(0);

    assert_int_equal(ret, temperature);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetSensorTemperature_UpperApproaching(void **)
{
    RetCode ret;
    int temperature = TEMPERATURE_UPPER_APPROACHING_THRESHOLD + 1;

    s_scstream = 1;

    common_set_GetSensorTemperature(s_scstream, (float)temperature, 0, 0);

    ret = GetSensorTemperature(0);

    assert_int_equal(ret, temperature);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetSensorTemperature_Lower(void **)
{
    int ret;
    int temperature = (TEMPERATURE_LOWER_THRESHOLD - 1);

    s_scstream = 1;

    common_set_GetSensorTemperature(s_scstream, (float)temperature, 0, 0);

    ret = GetSensorTemperature(0);

    assert_int_equal(ret, temperature);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetSensorTemperature_LowerApproaching(void **)
{
    int ret;
    int temperature = (TEMPERATURE_LOWER_APPROACHING_THRESHOLD - 1);

    s_scstream = 1;

    common_set_GetSensorTemperature(s_scstream, (float)temperature, 0, 0);

    ret = GetSensorTemperature(0);

    assert_int_equal(ret, temperature);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetSensorTemperature_Stream_Failed(void **)
{
    RetCode ret = kRetOk;

    s_scstream = 0;
    // pthread_mutex_lock
    will_return(__wrap_pthread_mutex_lock, 0);

    // pthread_mutex_unlock
    will_return(__wrap_pthread_mutex_unlock, 0);

    ret = GetSensorTemperature(100);

    assert_int_equal(ret, 100);

    return;
}

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
/*----------------------------------------------------------------------------*/
static void test_GetAiIspTemperature_Mutex_Failed(void **)
{
    RetCode ret;
    s_scstream = 1;

    common_set_GetAiIspTemperature(s_scstream, TEMPERATURE_UPPER_APPROACHING_THRESHOLD, -1, 0);

    ret = GetAiIspTemperature(0);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetAiIspTemperature_Stream_Failed(void **)
{
    RetCode ret;
    s_scstream = 0;

    common_set_GetAiIspTemperature(s_scstream, TEMPERATURE_UPPER_APPROACHING_THRESHOLD, 0, 0);

    ret = GetAiIspTemperature(0);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetAiIspTemperature_Stream_Property_Failed(void **)
{
    RetCode ret;
    s_scstream = 0;

    common_set_GetAiIspTemperature(s_scstream, TEMPERATURE_UPPER_APPROACHING_THRESHOLD, 0, -1);

    ret = GetAiIspTemperature(0);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetAiIspTemperature_Upper(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";
    int temperature = TEMPERATURE_UPPER_THRESHOLD + 1;

    s_scstream = 1;

    common_set_GetAiIspTemperature_Upper(handle_val, parent_val, string_expect, s_scstream,
                                         temperature, 0, 0);

    ret = GetAiIspTemperature(0);

    assert_int_equal(ret, temperature);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetAiIspTemperature_UpperApproaching(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";
    int temperature = TEMPERATURE_UPPER_APPROACHING_THRESHOLD + 1;

    s_scstream = 1;

    common_set_GetAiIspTemperature_Upper(handle_val, parent_val, string_expect, s_scstream,
                                         temperature, 0, 0);

    ret = GetAiIspTemperature(0);

    assert_int_equal(ret, temperature);

    return;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP

/*----------------------------------------------------------------------------*/
static void test_GetSensorTemperature_Mutex_Failed(void **)
{
    RetCode ret;
    s_scstream = 1;

    common_set_GetSensorTemperature(s_scstream, TEMPERATURE_LOWER_APPROACHING_THRESHOLD, -1, 0);

    ret = GetSensorTemperature(0);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetSensorTemperature_Property_Failed(void **)
{
    int ret;
    s_scstream = 1;
    int temperature = 0;

    common_set_GetSensorTemperature(s_scstream, temperature, 0, -1);

    ret = GetSensorTemperature(0);

    assert_int_equal(ret, TEMPERATURE_INVALID_VAL);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_test_GetPowerSupplyType(EsfPwrMgrSupplyType type_val)
{
    CfgStPowerSupplyType ret;
    common_set_GetPowerSupplyType(type_val, kEsfPwrMgrOk);

    ret = GetPowerSupplyType();

    assert_int_equal(ret, type_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetPowerSupplyType_FullySuccess(void **)
{
    common_test_GetPowerSupplyType(kEsfPwrMgrSupplyTypePoE);
    common_test_GetPowerSupplyType(kEsfPwrMgrSupplyTypeUsb);
    common_test_GetPowerSupplyType(kEsfPwrMgrSupplyTypeDcPlug);
    common_test_GetPowerSupplyType(kEsfPwrMgrSupplyTypePrimaryBattery);
    common_test_GetPowerSupplyType(kEsfPwrMgrSupplyTypeSecondaryBattery);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetPowerSupplyType_Failed(void **)
{
    CfgStPowerSupplyType ret;

    common_set_GetPowerSupplyType(kEsfPwrMgrSupplyTypePoE, kEsfPwrMgrErrorInvalidArgument);

    ret = GetPowerSupplyType();

    assert_int_equal(ret, kEsfPwrMgrSupplyTypeUnknown);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_test_GetPowerSupplyType_Unknown_Type_Failed(EsfPwrMgrSupplyType type_val)
{
    CfgStPowerSupplyType ret;

    common_set_GetPowerSupplyType(type_val, kEsfPwrMgrOk);

    ret = GetPowerSupplyType();

    assert_int_equal(ret, kEsfPwrMgrSupplyTypeUnknown);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetPowerSupplyType_Type_Failed(void **)
{
    common_test_GetPowerSupplyType_Unknown_Type_Failed(kEsfPwrMgrSupplyTypeMax);
    common_test_GetPowerSupplyType_Unknown_Type_Failed(kEsfPwrMgrSupplyTypeUnknown);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetSensorPostProcessSupported_Failed(void **)
{
    RetCode ret = kRetOk;

    s_scstream = 1;

    common_set_GetSensorPostProcessSupported(s_scstream, &s_expect_img_prop, -1);

    ret = GetSensorPostProcessSupported();

    assert_int_equal(ret, false);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetSensorPostProcessSupported_StreamFailed(void **)
{
    RetCode ret = kRetOk;

    s_scstream = 0;

    common_set_GetSensorPostProcessSupported(s_scstream, &s_expect_img_prop, kRetOk);

    ret = GetSensorPostProcessSupported();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_test_SysAppStateSendState(uint32_t req, char *SendDeviceInfoValue)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    size_t bsize = sizeof(EsfFwMgrGetInfoResponse) * ST_AIMODELS_NUM;
    char *b64_buf = "0x64646464";
    uint32_t expect_b64_size = 4646;
    const char *string_expect = "string_serialize_value";

    //  SysAppStateSendState(req);
    common_set_SysAppStateSendState(handle_val, parent_val, bsize, b64_buf, expect_b64_size,
                                    string_expect, req, SendDeviceInfoValue);

    SysAppStateSendState(req);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_ST_TOPIC_DEVICE_INFO()
{
    //  SysAppStateSendState(ST_TOPIC_DEVICE_INFO);
    common_test_SysAppStateSendState(ST_TOPIC_DEVICE_INFO, "");

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_ST_TOPIC_DEVICE_CAPABILITIES()
{
    //  SysAppStateSendState(ST_TOPIC_DEVICE_CAPABILITIES);

    common_test_SysAppStateSendState(ST_TOPIC_DEVICE_CAPABILITIES, "");

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_ST_TOPIC_DEVICE_STATES()
{
    //  SysAppStateSendState(ST_TOPIC_DEVICE_STATES);
    common_test_SysAppStateSendState(ST_TOPIC_DEVICE_STATES, "");

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_ST_TOPIC_RESERVED()
{
    //  SysAppStateSendState(ST_TOPIC_RESERVED);
    common_test_SysAppStateSendState(ST_TOPIC_RESERVED, "");

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_ST_TOPIC_SYSTEM_SETTINGS(void **state)
{
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = (EsfJsonValue)0x87654321;
    const char *string_expect = "test_string";

    common_set_SendUnimplementedState(handle_val, parent_val, string_expect, kEsfJsonSuccess, "");

    SysAppStateSendState(ST_TOPIC_SYSTEM_SETTINGS);
#else
    common_test_SysAppStateSendState(ST_TOPIC_SYSTEM_SETTINGS, "");
#endif

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_ST_TOPIC_NETWORK_SETTINGS(void **state)
{
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = (EsfJsonValue)0x87654321;
    const char *string_expect = "test_string";

    common_set_SendUnimplementedState(handle_val, parent_val, string_expect, kEsfJsonSuccess, "");
    SysAppStateSendState(ST_TOPIC_NETWORK_SETTINGS);
#else
    common_test_SysAppStateSendState(ST_TOPIC_NETWORK_SETTINGS, "");
#endif

    return;
}
/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_ST_TOPIC_WIRELESS_SETTING(void **state)
{
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = (EsfJsonValue)0x87654321;
    const char *string_expect = "test_string";

    common_set_SendUnimplementedState(handle_val, parent_val, string_expect, kEsfJsonSuccess, "");
    SysAppStateSendState(ST_TOPIC_WIRELESS_SETTING);
#else
    //  SysAppStateSendState(ST_TOPIC_WIRELESS_SETTING);
    common_test_SysAppStateSendState(ST_TOPIC_WIRELESS_SETTING, "");
#endif

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_ST_TOPIC_PERIODIC_SETTING()
{
    //  SysAppStateSendState(ST_TOPIC_PERIODIC_SETTING);
    common_test_SysAppStateSendState(ST_TOPIC_PERIODIC_SETTING, "");

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_ST_TOPIC_ENDPOINT_SETTINGS(void **state)
{
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = (EsfJsonValue)0x87654321;
    const char *string_expect = "test_string";

    common_set_SendUnimplementedState(handle_val, parent_val, string_expect, kEsfJsonSuccess, "");
    SysAppStateSendState(ST_TOPIC_ENDPOINT_SETTINGS);
#else
    common_test_SysAppStateSendState(ST_TOPIC_ENDPOINT_SETTINGS, "");
#endif

    return;
}
/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_ST_TOPIC_DEPLOY_FIRMWARE(void **state)
{
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = (EsfJsonValue)0x87654321;
    const char *string_expect = "test_string";

    common_set_SendUnimplementedState(handle_val, parent_val, string_expect, kEsfJsonSuccess, "");
    SysAppStateSendState(ST_TOPIC_DEPLOY_FIRMWARE);
#else
    common_test_SysAppStateSendState(ST_TOPIC_DEPLOY_FIRMWARE, "");
#endif

    return;
}
/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_ST_TOPIC_DEPLOY_AI_MODEL()
{
    // SendDeploy(ST_TOPIC_DEPLOY_AI_MODEL);
    common_test_SysAppStateSendState(ST_TOPIC_DEPLOY_AI_MODEL, "");

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM()
{
    // SendDeploy(ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM);
    common_test_SysAppStateSendState(ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM, "");

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_ST_TOPIC_UPDATE_DEVICE_INFO()
{
    common_test_SysAppStateSendState(ST_TOPIC_UPDATE_DEVICE_INFO, "manifest");

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_Other()
{
    common_test_SysAppStateSendState(1 << 14, "");

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStaInitialize_FullySuccess(void **)
{
    RetCode ret;
    struct SYS_client Client;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    size_t bsize = sizeof(EsfFwMgrGetInfoResponse) * ST_AIMODELS_NUM;
    char *b64_buf = "0x64646464";
    uint32_t expect_b64_size = 4646;
    const char *string_expect = "string_serialize_value";

    s_scstream = 1;
    s_device_capabilities.supported_wireless_mode = 0x03;
    s_device_states.hours_meter = 0x7b;
    s_system_settings.temperature_update_interval = 0x0a;
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    s_device_states.bootup_reason = -1;
#endif
    // SensCoreCoreOpenStream
    expect_value(__wrap_senscord_core_open_stream, core, s_sccore);
    expect_string(__wrap_senscord_core_open_stream, stream_key, "inference_stream");
    expect_value(__wrap_senscord_core_open_stream, stream, &s_scstream);
    will_return(__wrap_senscord_core_open_stream, 0);

    // SensCordCoreInit
    expect_value(__wrap_senscord_core_init, core, &s_sccore);
    will_return(__wrap_senscord_core_init, 0);

    // pthread_mutex_init(0);
    will_return(__wrap_pthread_mutex_init, 0);

    //  SysAppStateReadoutDeviceInfo();
    common_set_SysAppStateReadoutDeviceInfo(
        b64_buf, expect_b64_size, bsize, kEsfSystemManagerResultOk, kEsfCodecBase64ResultSuccess);
    //  SysAppStateSendState(ST_TOPIC_DEVICE_INFO);
    common_set_SysAppStateSendState(handle_val, parent_val, bsize, b64_buf, expect_b64_size,
                                    string_expect, ST_TOPIC_DEVICE_INFO, "manifest");

    //  SysAppStateReadoutDeviceCapabilities();
    common_set_SysAppStateReadoutDeviceCapabilities(kRetOk);

    //  SysAppStateSendState(ST_TOPIC_DEVICE_CAPABILITIES);
    common_set_SysAppStateSendState(handle_val, parent_val, bsize, b64_buf, expect_b64_size,
                                    string_expect, ST_TOPIC_DEVICE_CAPABILITIES, "");

    //  SysAppStateReadoutDeviceStates();
    common_set_SysAppStateReadoutDeviceStates(kRetOk, 0);

    //  SysAppStateSendState(ST_TOPIC_DEVICE_STATES);
    common_set_SysAppStateSendState(handle_val, parent_val, bsize, b64_buf, expect_b64_size,
                                    string_expect, ST_TOPIC_DEVICE_STATES, "");

    //  SysAppStateSendState(ST_TOPIC_RESERVED);
    common_set_SysAppStateSendState(handle_val, parent_val, bsize, b64_buf, expect_b64_size,
                                    string_expect, ST_TOPIC_RESERVED, "");

    //  SysAppStateReadoutSystemSettings();
    common_set_SysAppStateReadoutSystemSettings(kRetOk, kRetOk);

    //  SysAppStateSendState(ST_TOPIC_SYSTEM_SETTINGS);
    common_set_SysAppStateSendState(handle_val, parent_val, bsize, b64_buf, expect_b64_size,
                                    string_expect, ST_TOPIC_SYSTEM_SETTINGS, "");

    //  SysAppStateReadoutNetworkSettings();
    common_set_SysAppStateReadoutNetworkSettings(0, kClockManagerSuccess,
                                                 kEsfNetworkManagerResultSuccess);

    //  SysAppStateSendState(ST_TOPIC_NETWORK_SETTINGS);
    common_set_SysAppStateSendState(handle_val, parent_val, bsize, b64_buf, expect_b64_size,
                                    string_expect, ST_TOPIC_NETWORK_SETTINGS, "");

    //  SysAppStateReadoutWirelessSetting();
    common_set_SysAppStateReadoutWirelessSetting(kEsfNetworkManagerResultSuccess);

    //  SysAppStateSendState(ST_TOPIC_WIRELESS_SETTING);
    common_set_SysAppStateSendState(handle_val, parent_val, bsize, b64_buf, expect_b64_size,
                                    string_expect, ST_TOPIC_WIRELESS_SETTING, "");

    //  SysAppStateReadoutPeriodicSetting();
    SysAppStateReadoutPeriodicSetting();

    //  SysAppStateSendState(ST_TOPIC_PERIODIC_SETTING);
    common_set_SysAppStateSendState(handle_val, parent_val, bsize, b64_buf, expect_b64_size,
                                    string_expect, ST_TOPIC_PERIODIC_SETTING, "");

    //  SysAppStateReadoutEndpointSettings();
    common_set_SysAppStateReadoutEndpointSettings(kEsfSystemManagerResultInternalError,
                                                  kEsfSystemManagerResultInternalError);

    //  SysAppStateSendState(ST_TOPIC_ENDPOINT_SETTINGS);
    common_set_SysAppStateSendState(handle_val, parent_val, bsize, b64_buf, expect_b64_size,
                                    string_expect, ST_TOPIC_ENDPOINT_SETTINGS, "");

    // senscord_core_exit
    //  expect_value(__wrap_senscord_core_exit, core, s_sccore);
    //  will_return(__wrap_senscord_core_exit, 0);

    ret = SysAppStaInitialize(&Client);

    assert_int_equal(ret, kRetOk);

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    s_device_states.bootup_reason = 0;
#endif
    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStaInitialize_Client_Failed(void **)
{
    RetCode ret;
    struct SYS_client *Client = NULL;

    ret = SysAppStaInitialize(Client);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStaInitialize_SensCordCoreInit_Failed(void **)
{
    RetCode ret;
    struct SYS_client Client;

    // SensCordCoreInit
    expect_value(__wrap_senscord_core_init, core, &s_sccore);
    will_return(__wrap_senscord_core_init, -1);

    ret = SysAppStaInitialize(&Client);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStaInitialize_SensCordCoreOpen_Failed(void **)
{
    RetCode ret;
    struct SYS_client Client;

    // SensCordCoreInit
    expect_value(__wrap_senscord_core_init, core, &s_sccore);
    will_return(__wrap_senscord_core_init, 1);

    // SensCoreCoreOpenStream
    expect_value(__wrap_senscord_core_open_stream, core, s_sccore);
    expect_string(__wrap_senscord_core_open_stream, stream_key, "inference_stream");
    expect_value(__wrap_senscord_core_open_stream, stream, &s_scstream);
    will_return(__wrap_senscord_core_open_stream, -1);

    // senscord_core_exit
    expect_value(__wrap_senscord_core_exit, core, s_sccore);
    will_return(__wrap_senscord_core_exit, 0);

    // pthread_mutex_init(-1);
    will_return(__wrap_pthread_mutex_init, -1);

    ret = SysAppStaInitialize(&Client);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateGetSensCordId_FullySuccess(void **)
{
    RetCode ret;

    s_sccore = 1234;
    senscord_core_t core_id = 0;
    ret = SysAppStateGetSensCordId(&core_id);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
void test_SysAppStateGetSensCordId_Failed(void **)
{
    RetCode ret;

    senscord_core_t core_id = 0;
    s_sccore = 0;

    ret = SysAppStateGetSensCordId(&core_id);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
void test_SysAppStateGetSensCordStream_FullySuccess(void **)
{
    RetCode ret;
    s_scstream = 12345;
    senscord_stream_t stream = 0;

    ret = SysAppStateGetSensCordStream(&stream);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
void test_SysAppStateGetSensCordStream_Failed(void **)
{
    RetCode ret;

    s_scstream = 0;
    senscord_stream_t stream = 0;

    ret = SysAppStateGetSensCordStream(&stream);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SensorTempUpdateIntervalCallback_FullySuccess(void **)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    s_scstream = 1;

    common_set_SysAppStateUpdateSensorTemperature(false, kUtilityLogElogLevelError, 0, 0, 0);
    common_set_SendDeviceInfo(handle_val, parent_val, string_expect, "");

    SensorTempUpdateIntervalCallback();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SensorTempUpdateIntervalCallback_Failed(void **)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    s_scstream = 1;

    common_set_SysAppStateUpdateSensorTemperature(true, kUtilityLogElogLevelError,
                                                  SYSAPP_EVT_FAILED_TO_RETRIEVE_TEMP, 0, -1);
    common_set_SendDeviceInfo(handle_val, parent_val, string_expect, "");

    SensorTempUpdateIntervalCallback();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateUpdateSensorTemperature_FullySuccess(void **)
{
    RetCode ret;

    s_scstream = 1;

    common_set_SysAppStateUpdateSensorTemperature(false, kUtilityLogElogLevelError, 0, 0, 0);

    ret = SysAppStateUpdateSensorTemperature();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateUpdateHoursMeter_FullySuccess(void **)
{
    RetCode ret;

    // GetSensorHoursMeter
    will_return(__wrap_EsfPwrMgrHoursMeterGetValue, 123);
    will_return(__wrap_EsfPwrMgrHoursMeterGetValue, kEsfPwrMgrOk);

    ret = SysAppStateUpdateHoursMeter();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSetInvalidArgError_FullySuccess(void **)
{
    RetCode ret;

    ret = SysAppStateSetInvalidArgError(ST_TOPIC_SYSTEM_SETTINGS, Id);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInvalidArgError(ST_TOPIC_SYSTEM_SETTINGS, LedEnabled);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInvalidArgError(ST_TOPIC_SYSTEM_SETTINGS, TemperatureUpdateInterval);
    assert_int_equal(ret, kRetOk);

    ret = SysAppStateSetInvalidArgError(ST_TOPIC_NETWORK_SETTINGS, Id);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInvalidArgError(ST_TOPIC_NETWORK_SETTINGS, IpMethod);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInvalidArgError(ST_TOPIC_NETWORK_SETTINGS, NtpUrl);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInvalidArgError(ST_TOPIC_NETWORK_SETTINGS, IpAddress);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInvalidArgError(ST_TOPIC_NETWORK_SETTINGS, SubnetMask);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInvalidArgError(ST_TOPIC_NETWORK_SETTINGS, GatewayAddress);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInvalidArgError(ST_TOPIC_NETWORK_SETTINGS, DnsAddress);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInvalidArgError(ST_TOPIC_NETWORK_SETTINGS, IpAddressV6);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInvalidArgError(ST_TOPIC_NETWORK_SETTINGS, SubnetMaskV6);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInvalidArgError(ST_TOPIC_NETWORK_SETTINGS, GatewayAddressV6);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInvalidArgError(ST_TOPIC_NETWORK_SETTINGS, DnsAddressV6);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInvalidArgError(ST_TOPIC_NETWORK_SETTINGS, ProxyPort);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInvalidArgError(ST_TOPIC_NETWORK_SETTINGS, ProxyUrl);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInvalidArgError(ST_TOPIC_NETWORK_SETTINGS, ProxyUserName);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInvalidArgError(ST_TOPIC_NETWORK_SETTINGS, ProxyPassword);
    assert_int_equal(ret, kRetOk);

    ret = SysAppStateSetInvalidArgError(ST_TOPIC_WIRELESS_SETTING, Id);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInvalidArgError(ST_TOPIC_WIRELESS_SETTING, StaSsid);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInvalidArgError(ST_TOPIC_WIRELESS_SETTING, StaPassword);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInvalidArgError(ST_TOPIC_WIRELESS_SETTING, StaEncryption);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInvalidArgError(ST_TOPIC_WIRELESS_SETTING, -1);
    assert_int_equal(ret, kRetOk);

    ret = SysAppStateSetInvalidArgError(ST_TOPIC_PERIODIC_SETTING, 0);
    assert_int_equal(ret, kRetOk);

    ret = SysAppStateSetInvalidArgError(ST_TOPIC_ENDPOINT_SETTINGS, Id);
    assert_int_equal(ret, kRetOk);

    ret = SysAppStateSetInvalidArgError(-1, -1);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSetInvalidArgErrorWithIdx_FullySuccess(void **)
{
    RetCode ret;

    for (uint32_t idx = 0; idx < 2; idx++) {
        ret = SysAppStateSetInvalidArgErrorWithIdx(ST_TOPIC_SYSTEM_SETTINGS, LogFilter, idx);
        assert_int_equal(ret, kRetOk);
        ret = SysAppStateSetInvalidArgErrorWithIdx(ST_TOPIC_SYSTEM_SETTINGS, LogLevel, idx);
        assert_int_equal(ret, kRetOk);
        ret = SysAppStateSetInvalidArgErrorWithIdx(ST_TOPIC_SYSTEM_SETTINGS, LogDestination, idx);
        assert_int_equal(ret, kRetOk);
        ret = SysAppStateSetInvalidArgErrorWithIdx(ST_TOPIC_SYSTEM_SETTINGS, LogStorageName, idx);
        assert_int_equal(ret, kRetOk);
        ret = SysAppStateSetInvalidArgErrorWithIdx(ST_TOPIC_SYSTEM_SETTINGS, LogPath, idx);
        assert_int_equal(ret, kRetOk);
        ret = SysAppStateSetInvalidArgErrorWithIdx(ST_TOPIC_SYSTEM_SETTINGS, -1, idx);
        assert_int_equal(ret, kRetOk);

        ret = SysAppStateSetInvalidArgErrorWithIdx(ST_TOPIC_PERIODIC_SETTING, BaseTime, idx);
        assert_int_equal(ret, kRetOk);
        ret = SysAppStateSetInvalidArgErrorWithIdx(ST_TOPIC_PERIODIC_SETTING, CaptureInterval, idx);
        assert_int_equal(ret, kRetOk);
        ret = SysAppStateSetInvalidArgErrorWithIdx(ST_TOPIC_PERIODIC_SETTING, ConfigInterval, idx);
        assert_int_equal(ret, kRetOk);
        ret = SysAppStateSetInvalidArgErrorWithIdx(ST_TOPIC_PERIODIC_SETTING, -1, idx);
        assert_int_equal(ret, kRetOk);

        ret = SysAppStateSetInvalidArgErrorWithIdx(-1, -1, idx);
        assert_int_equal(ret, kRetOk);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSetInternalError_FullySuccess(void **)
{
    RetCode ret;

    ret = SysAppStateSetInternalError(ST_TOPIC_SYSTEM_SETTINGS, 0);
    assert_int_equal(ret, kRetOk);

    ret = SysAppStateSetInternalError(ST_TOPIC_NETWORK_SETTINGS, Id);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInternalError(ST_TOPIC_NETWORK_SETTINGS, IpMethod);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInternalError(ST_TOPIC_NETWORK_SETTINGS, NtpUrl);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInternalError(ST_TOPIC_NETWORK_SETTINGS, IpAddress);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInternalError(ST_TOPIC_NETWORK_SETTINGS, SubnetMask);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInternalError(ST_TOPIC_NETWORK_SETTINGS, GatewayAddress);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInternalError(ST_TOPIC_NETWORK_SETTINGS, DnsAddress);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInternalError(ST_TOPIC_NETWORK_SETTINGS, IpAddressV6);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInternalError(ST_TOPIC_NETWORK_SETTINGS, SubnetMaskV6);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInternalError(ST_TOPIC_NETWORK_SETTINGS, GatewayAddressV6);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInternalError(ST_TOPIC_NETWORK_SETTINGS, DnsAddressV6);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInternalError(ST_TOPIC_NETWORK_SETTINGS, ProxyPort);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInternalError(ST_TOPIC_NETWORK_SETTINGS, ProxyUrl);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInternalError(ST_TOPIC_NETWORK_SETTINGS, ProxyUserName);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInternalError(ST_TOPIC_NETWORK_SETTINGS, ProxyPassword);
    assert_int_equal(ret, kRetOk);

    ret = SysAppStateSetInternalError(ST_TOPIC_WIRELESS_SETTING, StaSsid);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInternalError(ST_TOPIC_WIRELESS_SETTING, StaPassword);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInternalError(ST_TOPIC_WIRELESS_SETTING, StaEncryption);
    assert_int_equal(ret, kRetOk);
    ret = SysAppStateSetInternalError(ST_TOPIC_WIRELESS_SETTING, -1);
    assert_int_equal(ret, kRetOk);

    ret = SysAppStateSetInternalError(ST_TOPIC_PERIODIC_SETTING, 0);
    assert_int_equal(ret, kRetOk);

    ret = SysAppStateSetInternalError(ST_TOPIC_ENDPOINT_SETTINGS, Id);
    assert_int_equal(ret, kRetOk);

    ret = SysAppStateSetInternalError(-1, -1);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSetInternalErrorWithIdx_FullySuccess(void **)
{
    RetCode ret;

    for (uint32_t idx = 0; idx < 2; idx++) {
        ret = SysAppStateSetInternalErrorWithIdx(ST_TOPIC_SYSTEM_SETTINGS, LogFilter, idx);
        assert_int_equal(ret, kRetOk);
        ret = SysAppStateSetInternalErrorWithIdx(ST_TOPIC_SYSTEM_SETTINGS, LogLevel, idx);
        assert_int_equal(ret, kRetOk);
        ret = SysAppStateSetInternalErrorWithIdx(ST_TOPIC_SYSTEM_SETTINGS, LogDestination, idx);
        assert_int_equal(ret, kRetOk);
        ret = SysAppStateSetInternalErrorWithIdx(ST_TOPIC_SYSTEM_SETTINGS, LogStorageName, idx);
        assert_int_equal(ret, kRetOk);
        ret = SysAppStateSetInternalErrorWithIdx(ST_TOPIC_SYSTEM_SETTINGS, LogPath, idx);
        assert_int_equal(ret, kRetOk);
        ret = SysAppStateSetInternalErrorWithIdx(ST_TOPIC_SYSTEM_SETTINGS, -1, idx);
        assert_int_equal(ret, kRetOk);

        ret = SysAppStateSetInternalErrorWithIdx(ST_TOPIC_PERIODIC_SETTING, BaseTime, idx);
        assert_int_equal(ret, kRetOk);
        ret = SysAppStateSetInternalErrorWithIdx(ST_TOPIC_PERIODIC_SETTING, CaptureInterval, idx);
        assert_int_equal(ret, kRetOk);
        ret = SysAppStateSetInternalErrorWithIdx(ST_TOPIC_PERIODIC_SETTING, ConfigInterval, idx);
        assert_int_equal(ret, kRetOk);
        ret = SysAppStateSetInternalErrorWithIdx(ST_TOPIC_PERIODIC_SETTING, -1, idx);
        assert_int_equal(ret, kRetOk);

        ret = SysAppStateSetInternalErrorWithIdx(-1, -1, idx);
        assert_int_equal(ret, kRetOk);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigStateUpdateInfo_FullySuccess(void **)
{
    GetConfigStateUpdateInfo(ST_TOPIC_DEVICE_STATES);
    GetConfigStateUpdateInfo(ST_TOPIC_SYSTEM_SETTINGS);
    GetConfigStateUpdateInfo(ST_TOPIC_NETWORK_SETTINGS);
    GetConfigStateUpdateInfo(ST_TOPIC_WIRELESS_SETTING);
    GetConfigStateUpdateInfo(ST_TOPIC_PERIODIC_SETTING);
    GetConfigStateUpdateInfo(ST_TOPIC_ENDPOINT_SETTINGS);
    GetConfigStateUpdateInfo(ST_TOPIC_UPLOAD_SENSOR_CALIBRATION_PARAM);
    GetConfigStateUpdateInfo(ST_TOPIC_DEPLOY_FIRMWARE);
    GetConfigStateUpdateInfo(ST_TOPIC_DEPLOY_AI_MODEL);
    GetConfigStateUpdateInfo(ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_RequestConfigStateUpdate_FullySuccess(void **)
{
    RequestConfigStateUpdate(ST_TOPIC_SYSTEM_SETTINGS);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStaFinalize_FullySuccess(void **)
{
    RetCode ret;
    s_sccore = 1;
    s_scstream = 1;

    for (TimerType type = SensorTempIntervalTimer; type < TimerTypeNum; type++) {
        // SysAppTimerStopTimer
        will_return(__wrap_SysAppTimerStopTimer, type);
    }

    // pthread_mutex_destroy
    will_return(__wrap_pthread_mutex_destroy, 0);

    // SensCoreCoreCloseStream
    expect_value(__wrap_senscord_core_close_stream, core, s_sccore);
    expect_value(__wrap_senscord_core_close_stream, stream, s_scstream);
    will_return(__wrap_senscord_core_close_stream, 0);

    // senscord_core_exit
    expect_value(__wrap_senscord_core_exit, core, s_sccore);
    will_return(__wrap_senscord_core_exit, 0);

    ret = SysAppStaFinalize();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateUpdateNumber_FullySuccess(void **)
{
    SysAppStateUpdateNumber(ST_TOPIC_DEVICE_STATES, HoursMeter, 1);
    SysAppStateUpdateNumber(ST_TOPIC_DEVICE_STATES, ProcessState, 1);
    SysAppStateUpdateNumber(ST_TOPIC_SYSTEM_SETTINGS, TemperatureUpdateInterval, 1);
    SysAppStateUpdateNumber(ST_TOPIC_SYSTEM_SETTINGS, LedEnabled, 1);
    SysAppStateUpdateNumber(ST_TOPIC_NETWORK_SETTINGS, IpMethod, 1);
    SysAppStateUpdateNumber(ST_TOPIC_NETWORK_SETTINGS, ProxyPort, 1);
    SysAppStateUpdateNumber(ST_TOPIC_NETWORK_SETTINGS, ProxyUrl, 1);
    SysAppStateUpdateNumber(ST_TOPIC_WIRELESS_SETTING, StaEncryption, 1);
    SysAppStateUpdateNumber(ST_TOPIC_WIRELESS_SETTING, StaPassword, 1);
    SysAppStateUpdateNumber(ST_TOPIC_PERIODIC_SETTING, OperationMode, 1);
    SysAppStateUpdateNumber(ST_TOPIC_PERIODIC_SETTING, RecoveryMethod, 1);
    SysAppStateUpdateNumber(ST_TOPIC_PERIODIC_SETTING, IpAddrSetting, 1);
    SysAppStateUpdateNumber(ST_TOPIC_ENDPOINT_SETTINGS, EndpointPort, 1);
    SysAppStateUpdateNumber(ST_TOPIC_ENDPOINT_SETTINGS, EndpointUrl, 1);
    SysAppStateUpdateNumber(ST_TOPIC_UPLOAD_SENSOR_CALIBRATION_PARAM, EndpointUrl, 1);
    SysAppStateUpdateNumber(ST_TOPIC_DEPLOY_AI_MODEL, EndpointUrl, 1);
    SysAppStateUpdateNumber(ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM, EndpointUrl, 1);
    SysAppStateUpdateNumber(ST_TOPIC_RESERVED, EndpointUrl, 1);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateUpdateNumberWithIdx_FullySuccess(void **)
{
    SysAppStateUpdateNumberWithIdx(ST_TOPIC_SYSTEM_SETTINGS, LogFilter, 1, 0);
    SysAppStateUpdateNumberWithIdx(ST_TOPIC_SYSTEM_SETTINGS, LogLevel, 1, 0);
    SysAppStateUpdateNumberWithIdx(ST_TOPIC_SYSTEM_SETTINGS, LogDestination, 1, 0);
    SysAppStateUpdateNumberWithIdx(ST_TOPIC_SYSTEM_SETTINGS, LogDestination, 1, 0);
    SysAppStateUpdateNumberWithIdx(ST_TOPIC_SYSTEM_SETTINGS, LogStorageName, 1, 0);
    SysAppStateUpdateNumberWithIdx(ST_TOPIC_PERIODIC_SETTING, CaptureInterval, 1, 0);
    SysAppStateUpdateNumberWithIdx(ST_TOPIC_PERIODIC_SETTING, ConfigInterval, 1, 0);
    SysAppStateUpdateNumberWithIdx(ST_TOPIC_PERIODIC_SETTING, BaseTime, 1, 0);
    SysAppStateUpdateNumberWithIdx(ST_TOPIC_UPLOAD_SENSOR_CALIBRATION_PARAM, BaseTime, 1, 0);
    SysAppStateUpdateNumberWithIdx(ST_TOPIC_DEPLOY_FIRMWARE, BaseTime, 1, 0);
    SysAppStateUpdateNumberWithIdx(ST_TOPIC_DEPLOY_AI_MODEL, BaseTime, 1, 0);
    SysAppStateUpdateNumberWithIdx(ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM, BaseTime, 1, 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateUpdateBoolean_FullySuccess(void **)
{
    SysAppStateUpdateBoolean(ST_TOPIC_DEVICE_CAPABILITIES, SensorPostProcessSupported, true);
    SysAppStateUpdateBoolean(ST_TOPIC_DEVICE_CAPABILITIES, SensorPostProcessSupported + 1, true);
    SysAppStateUpdateBoolean(ST_TOPIC_SYSTEM_SETTINGS, LedEnabled, true);
    SysAppStateUpdateBoolean(ST_TOPIC_SYSTEM_SETTINGS, LogFilter, true);
    SysAppStateUpdateBoolean(ST_TOPIC_DEVICE_INFO, LedEnabled, true);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateUpdateString_FullySuccess(void **)
{
    SysAppStateUpdateString(ST_TOPIC_DEVICE_STATES, ProcessState, "PROCESS_STATE");
    SysAppStateUpdateString(ST_TOPIC_DEVICE_STATES, -1, NULL);
    SysAppStateUpdateString(ST_TOPIC_SYSTEM_SETTINGS, Id, "SYSTEM-ID");
    SysAppStateUpdateString(ST_TOPIC_SYSTEM_SETTINGS, -1, NULL);
    SysAppStateUpdateString(ST_TOPIC_NETWORK_SETTINGS, Id, "NETWORK-ID");
    SysAppStateUpdateString(ST_TOPIC_NETWORK_SETTINGS, ProxyUrl, "PROXY-URL");
    SysAppStateUpdateString(ST_TOPIC_NETWORK_SETTINGS, ProxyUserName, "PROXY-USER");
    SysAppStateUpdateString(ST_TOPIC_NETWORK_SETTINGS, ProxyPassword, "PROXY-PASS");
    SysAppStateUpdateString(ST_TOPIC_NETWORK_SETTINGS, IpAddressV6, "ADDR-V6");
    SysAppStateUpdateString(ST_TOPIC_NETWORK_SETTINGS, SubnetMaskV6, "MASK-V6");
    SysAppStateUpdateString(ST_TOPIC_NETWORK_SETTINGS, GatewayAddressV6, "GATEWAY-V6");
    SysAppStateUpdateString(ST_TOPIC_NETWORK_SETTINGS, DnsAddressV6, "DNS-V6");
    SysAppStateUpdateString(ST_TOPIC_NETWORK_SETTINGS, IpAddress, "ADDR-V4");
    SysAppStateUpdateString(ST_TOPIC_NETWORK_SETTINGS, SubnetMask, "MASK-V4");
    SysAppStateUpdateString(ST_TOPIC_NETWORK_SETTINGS, GatewayAddress, "GATEWAY-V4");
    SysAppStateUpdateString(ST_TOPIC_NETWORK_SETTINGS, DnsAddress, "DNS-V4");
    SysAppStateUpdateString(ST_TOPIC_NETWORK_SETTINGS, NtpUrl, "NTP-URL");
    SysAppStateUpdateString(ST_TOPIC_NETWORK_SETTINGS, -1, NULL);
    SysAppStateUpdateString(ST_TOPIC_WIRELESS_SETTING, Id, "WIRELESS-ID");
    SysAppStateUpdateString(ST_TOPIC_WIRELESS_SETTING, StaSsid, "STA-SSID");
    SysAppStateUpdateString(ST_TOPIC_WIRELESS_SETTING, StaPassword, "STA-PASS");
    SysAppStateUpdateString(ST_TOPIC_WIRELESS_SETTING, -1, NULL);
    SysAppStateUpdateString(ST_TOPIC_PERIODIC_SETTING, Id, "PERIODIC-ID");
    SysAppStateUpdateString(ST_TOPIC_PERIODIC_SETTING, -1, NULL);
    SysAppStateUpdateString(ST_TOPIC_ENDPOINT_SETTINGS, Id, "ENDPOINT-ID");
    SysAppStateUpdateString(ST_TOPIC_ENDPOINT_SETTINGS, EndpointUrl, "ENDPOINT-URL");
    SysAppStateUpdateString(ST_TOPIC_ENDPOINT_SETTINGS, ProtocolVersion, "PROTOL-VER");
    SysAppStateUpdateString(ST_TOPIC_ENDPOINT_SETTINGS, -1, NULL);
    SysAppStateUpdateString(ST_TOPIC_UPLOAD_SENSOR_CALIBRATION_PARAM, -1, NULL);
    SysAppStateUpdateString(ST_TOPIC_DEPLOY_FIRMWARE, -1, NULL);
    SysAppStateUpdateString(ST_TOPIC_DEPLOY_AI_MODEL, -1, NULL);
    SysAppStateUpdateString(ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM, -1, NULL);
    SysAppStateUpdateString(-1, -1, NULL);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateUpdateStringWithIdx_FullySuccess(void **)
{
    for (uint32_t idx = 0; idx < 2U; idx++) {
        SysAppStateUpdateStringWithIdx(ST_TOPIC_SYSTEM_SETTINGS, LogStorageName, "STORAGE-NAME",
                                       idx);
        SysAppStateUpdateStringWithIdx(ST_TOPIC_SYSTEM_SETTINGS, LogPath, "LOG-PATH", idx);
        SysAppStateUpdateStringWithIdx(ST_TOPIC_SYSTEM_SETTINGS, -1, NULL, idx);
        SysAppStateUpdateStringWithIdx(ST_TOPIC_PERIODIC_SETTING, BaseTime, "12:00", idx);
        SysAppStateUpdateStringWithIdx(ST_TOPIC_PERIODIC_SETTING, -1, NULL, idx);
        SysAppStateUpdateStringWithIdx(-1, -1, NULL, idx);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateUpdateSensorTemperature_Failed(void **)
{
    RetCode ret;

    s_scstream = 1;

    common_set_SysAppStateUpdateSensorTemperature(true, kUtilityLogElogLevelError,
                                                  SYSAPP_EVT_FAILED_TO_RETRIEVE_TEMP, -1, -1);

    ret = SysAppStateUpdateSensorTemperature();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutMainChip_FullySuccess(void **)
{
    RetCode ret;
    char *b64_buf = "0x64646464";
    uint32_t expect_b64_size = 4646;

    common_set_SysAppStateReadoutMainChip_Fully(b64_buf, expect_b64_size, s_fm_gir_ai_model,
                                                kEsfCodecBase64ResultSuccess,
                                                kEsfCodecBase64ResultSuccess);

    ret = SysAppStateReadoutMainChip();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutMainChip_Loder_Failed(void **)
{
    RetCode ret;
    char *b64_buf = "0x64646464";
    uint32_t expect_b64_size = 4646;

    common_set_SysAppStateReadoutMainChip_Fully(b64_buf, expect_b64_size, s_fm_gir_ai_model,
                                                kEsfCodecBase64ResultNullParam,
                                                kEsfCodecBase64ResultSuccess);

    ret = SysAppStateReadoutMainChip();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutMainChip_Firmware_Failed(void **)
{
    RetCode ret;
    char *b64_buf = "0x64646464";
    uint32_t expect_b64_size = 4646;

    common_set_SysAppStateReadoutMainChip_Fully(b64_buf, expect_b64_size, s_fm_gir_ai_model,
                                                kEsfCodecBase64ResultSuccess,
                                                kEsfCodecBase64ResultNullParam);

    ret = SysAppStateReadoutMainChip();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutMainChip_GetInfo_Failed(void **)
{
    RetCode ret;

    // EsfFwMgrGetInfo
    will_return(__wrap_EsfFwMgrGetInfo, (EsfFwMgrGetInfoData *)&s_fm_gir_ai_model[0]);
    will_return(__wrap_EsfFwMgrGetInfo, kEsfFwMgrResultInvalidArgument);

    // EsfFwMgrGetInfo
    will_return(__wrap_EsfFwMgrGetInfo, (EsfFwMgrGetInfoData *)&s_fm_gir_ai_model[0]);
    will_return(__wrap_EsfFwMgrGetInfo, kEsfFwMgrResultInvalidArgument);

    ret = SysAppStateReadoutMainChip();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutMainChip_GetInfo_Unimplemented(void **)
{
    RetCode ret;

    // EsfFwMgrGetInfo
    will_return(__wrap_EsfFwMgrGetInfo, (EsfFwMgrGetInfoData *)&s_fm_gir_ai_model[0]);
    will_return(__wrap_EsfFwMgrGetInfo, kEsfFwMgrResultUnimplemented);

    // EsfFwMgrGetInfo
    will_return(__wrap_EsfFwMgrGetInfo, (EsfFwMgrGetInfoData *)&s_fm_gir_ai_model[0]);
    will_return(__wrap_EsfFwMgrGetInfo, kEsfFwMgrResultUnimplemented);

    ret = SysAppStateReadoutMainChip();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutChips_FullySuccess(void **)
{
    RetCode ret;
    char *b64_buf = "0x64646464";
    uint32_t expect_b64_size = 4646;

    s_scstream = 1;

    common_set_SysAppStateReadoutChips_FullySuccess(b64_buf, expect_b64_size);

    ret = SysAppStateReadoutChips();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutChips_Failed(void **)
{
    RetCode ret;
    char *b64_buf = "0x64646464";
    uint32_t expect_b64_size = 4646;

    s_scstream = 1;

    common_set_SysAppStateReadoutChips_Failed(b64_buf, expect_b64_size);

    ret = SysAppStateReadoutChips();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void common_test_SysAppStateReadoutChips_GetInfo_Failed(EsfFwMgrResult error_val)
{
    RetCode ret;
    char *b64_buf = "0x64646464";
    uint32_t expect_b64_size = 4646;

    s_scstream = 1;

    common_set_SysAppStateReadoutMainChip_Fully(
        b64_buf, expect_b64_size, s_fm_gir_ai_model, kEsfCodecBase64ResultSuccess,
        kEsfCodecBase64ResultNullParam); // SysAppStateReadoutMainChip()

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
    common_set_GetSensorInfo(s_scstream, &s_expect_img_prop, 0); // GetSensorInfo()
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
    common_set_GetSensorInfo(s_scstream, &s_expect_img_prop, 0); // GetSensorInfo()
    common_set_GetAiIspTemperature(s_scstream, TEMPERATURE_UPPER_APPROACHING_THRESHOLD, 0,
                                   0); // GetAiIspTemperature()
#endif                                 // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
    common_set_GetSensorInfo(s_scstream, &s_expect_img_prop, 0); // GetSensorInfo()
    common_set_GetSensorTemperature(s_scstream, TEMPERATURE_LOWER_APPROACHING_THRESHOLD, 0,
                                    0); // GetSensorTemperature()

    // EsfFwMgrGetInfo
    will_return(__wrap_EsfFwMgrGetInfo, (EsfFwMgrGetInfoData *)&s_fm_gir_ai_model[0]);
    will_return(__wrap_EsfFwMgrGetInfo, error_val); // EsfFwMgrGetInfo()

    common_set_GetSensorFirmwareVersion(s_scstream, &s_expect_img_prop,
                                        0); // GetSensorFirmwareVersion()

    // EsfFwMgrGetInfo
    will_return(__wrap_EsfFwMgrGetInfo, (EsfFwMgrGetInfoData *)&s_fm_gir_ai_model[0]);
    will_return(__wrap_EsfFwMgrGetInfo, error_val); // EsfFwMgrGetInfo()

    common_set_GetSensorFirmwareVersion(s_scstream, &s_expect_img_prop,
                                        0); // GetSensorFirmwareVersion()

    ret = SysAppStateReadoutChips();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutChips_GetInfo_Failed(void **)
{
    common_test_SysAppStateReadoutChips_GetInfo_Failed(kEsfFwMgrResultInvalidArgument);
    common_test_SysAppStateReadoutChips_GetInfo_Failed(kEsfFwMgrResultUnimplemented);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutAiModels_FullySuccess(void **)
{
    RetCode ret = kRetFailed;
    size_t bsize = sizeof(EsfFwMgrGetInfoResponse) * ST_AIMODELS_NUM;
    char *b64_buf = "0x64646464";
    uint32_t expect_b64_size = 4646;

    common_set_SysAppStateReadoutAiModels_Fully(b64_buf, expect_b64_size, bsize, s_fm_gir_ai_model,
                                                kEsfCodecBase64ResultSuccess);

    ret = SysAppStateReadoutAiModels();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutAiModels_Encode_Failed(void **)
{
    RetCode ret = kRetOk;
    size_t bsize = sizeof(EsfFwMgrGetInfoResponse) * ST_AIMODELS_NUM;
    char *b64_buf = "0x64646464";
    uint32_t expect_b64_size = 4646;

    common_set_SysAppStateReadoutAiModels_Fully(b64_buf, expect_b64_size, bsize, s_fm_gir_ai_model,
                                                kEsfCodecBase64ResultNullParam);

    ret = SysAppStateReadoutAiModels();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutAiModels_Malloc_Failed(void **)
{
    RetCode ret = kRetOk;
    will_return(mock_malloc, false);
    will_return(mock_malloc, false);

    ret = SysAppStateReadoutAiModels();

    assert_int_equal(ret, kRetMemoryError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutAiModels_GetInfo_Failed(void **)
{
    RetCode ret = kRetOk;
    size_t bsize = sizeof(EsfFwMgrGetInfoResponse) * ST_AIMODELS_NUM;

    expect_value(mock_malloc, __size, bsize);
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);

    // EsfFwMgrGetInfo
    will_return(__wrap_EsfFwMgrGetInfo, (EsfFwMgrGetInfoData *)&s_fm_gir_ai_model[0]);
    will_return(__wrap_EsfFwMgrGetInfo, kEsfFwMgrResultInvalidArgument);

    // For free() of ctx
    will_return(mock_free, false);

    ret = SysAppStateReadoutAiModels();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutAiModels_Version_Failed(void **)
{
    RetCode ret = kRetFailed;
    size_t bsize = sizeof(EsfFwMgrGetInfoResponse) * ST_AIMODELS_NUM;

    expect_value(mock_malloc, __size, bsize);
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);

    // EsfFwMgrGetInfo
    will_return(__wrap_EsfFwMgrGetInfo, (EsfFwMgrGetInfoData *)&s_fm_gir_ai_model_not[0]);
    will_return(__wrap_EsfFwMgrGetInfo, kEsfFwMgrResultOk); // SetHashWithB64Encode()

    // For free()
    will_return(mock_free, false);

    ret = SysAppStateReadoutAiModels();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutDeviceInfo_FullySuccess(void **)
{
    RetCode ret = kRetOk;
    size_t bsize = sizeof(EsfFwMgrGetInfoResponse) * ST_AIMODELS_NUM;
    char *b64_buf = "0x64646464";
    uint32_t expect_b64_size = 4646;

    s_scstream = 1;

    common_set_SysAppStateReadoutDeviceInfo(
        b64_buf, expect_b64_size, bsize, kEsfSystemManagerResultOk, kEsfCodecBase64ResultSuccess);

    ret = SysAppStateReadoutDeviceInfo();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutDeviceInfo_Failed(void **)
{
    RetCode ret = kRetOk;
    size_t bsize = sizeof(EsfFwMgrGetInfoResponse) * ST_AIMODELS_NUM;
    char *b64_buf = "0x64646464";
    uint32_t expect_b64_size = 4646;

    s_scstream = 1;

    common_set_SysAppStateReadoutDeviceInfo(b64_buf, expect_b64_size, bsize,
                                            kEsfSystemManagerResultParamError,
                                            kEsfCodecBase64ResultNullParam);

    ret = SysAppStateReadoutDeviceInfo();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutDeviceCapabilities_FullySuccess(void **)
{
    RetCode ret = kRetOk;

    common_set_SysAppStateReadoutDeviceCapabilities(kRetOk);

    ret = SysAppStateReadoutDeviceCapabilities();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutPowerStates_FullySuccess(void **)
{
    RetCode ret = kRetOk;

    common_set_SysAppStateReadoutPowerStates();

    ret = SysAppStateReadoutPowerStates();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutDeviceStates_fully_success(void **)
{
    RetCode ret = kRetOk;

    common_set_SysAppStateReadoutDeviceStates(kRetOk, 0);

    ret = SysAppStateReadoutDeviceStates();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutDeviceStates_StartTimer_Failed(void **)
{
    RetCode ret = kRetOk;

    common_set_SysAppStateReadoutDeviceStates(kRetFailed, 0);

    ret = SysAppStateReadoutDeviceStates();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutDeviceStates_clock_gettime_Failed(void **)
{
    RetCode ret = kRetOk;

    common_set_SysAppStateReadoutDeviceStates(kRetOk, 1);

    ret = SysAppStateReadoutDeviceStates();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutLog_fully_success(void **)
{
    RetCode ret = kRetOk;

    common_set_SysAppStateReadoutLog();

    ret = SysAppStateReadoutLog();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutStaticSettingsIPv6_fully_success(void **)
{
    RetCode ret = kRetOk;

    // ip_address
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, kEsfNetworkManagerResultSuccess);

    // subnet_mask
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, kEsfNetworkManagerResultSuccess);

    // gateway_address
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, kEsfNetworkManagerResultSuccess);

    // dns_address
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, kEsfNetworkManagerResultSuccess);

    ret = SysAppStateReadoutStaticSettingsIPv6();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutStaticSettingsIPv6_fully_errors(void **)
{
    RetCode ret = kRetOk;

    // ip_address
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, 1);

    // subnet_mask
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, 2);

    // gateway_address
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, 3);

    // dns_address
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, 4);

    ret = SysAppStateReadoutStaticSettingsIPv6();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutStaticSettingsIPv4_fully_success(void **)
{
    RetCode ret = kRetOk;

    // ip_address
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, kEsfNetworkManagerResultSuccess);

    // subnet_mask
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, kEsfNetworkManagerResultSuccess);

    // gateway_address
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, kEsfNetworkManagerResultSuccess);

    // dns_address
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, kEsfNetworkManagerResultSuccess);

    ret = SysAppStateReadoutStaticSettingsIPv4();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutStaticSettingsIPv4_fully_errors(void **)
{
    RetCode ret = kRetOk;

    // ip_address
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, 1);

    // subnet_mask
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, 2);

    // gateway_address
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, 3);

    // dns_address
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, 4);

    ret = SysAppStateReadoutStaticSettingsIPv4();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutSystemSettings_fully_success(void **)
{
    RetCode ret = kRetOk;

    common_set_SysAppStateReadoutSystemSettings(kRetOk, kRetOk);

    ret = SysAppStateReadoutSystemSettings();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutSystemSettings_Failed(void **)
{
    RetCode ret = kRetOk;

    common_set_SysAppStateReadoutSystemSettings(kRetFailed, kRetFailed);

    ret = SysAppStateReadoutSystemSettings();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutProxySettings_fully_success(void **)
{
    RetCode ret = kRetOk;

    // proxy_url
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, kEsfNetworkManagerResultSuccess);

    // proxy_port
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, kEsfNetworkManagerResultSuccess);

    // Proxy_user_name
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, kEsfNetworkManagerResultSuccess);

    // proxy_password
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, kEsfNetworkManagerResultSuccess);

    ret = SysAppStateReadoutProxySettings();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutProxySettings_fully_port_errors(void **)
{
    RetCode ret = kRetOk;

    memset(&s_proxy_settings, 0, sizeof(s_proxy_settings));
    s_proxy_settings.proxy_port = -1;

    // proxy_url
    common_set_EsfNetworkManagerLoadParameter(-1, 0, EncWpa2Psk, kEsfNetworkManagerResultSuccess);

    // proxy_port
    common_set_EsfNetworkManagerLoadParameter(-1, 0, EncWpa2Psk, kEsfNetworkManagerResultSuccess);

    // Proxy_user_name
    common_set_EsfNetworkManagerLoadParameter(-1, 0, EncWpa2Psk, kEsfNetworkManagerResultSuccess);

    // proxy_password
    common_set_EsfNetworkManagerLoadParameter(-1, 0, EncWpa2Psk, kEsfNetworkManagerResultSuccess);

    ret = SysAppStateReadoutProxySettings();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutNetworkSettings_fully_success(void **)
{
    RetCode ret = kRetOk;

    common_set_SysAppStateReadoutNetworkSettings(0, kClockManagerSuccess,
                                                 kEsfNetworkManagerResultSuccess);

    ret = SysAppStateReadoutNetworkSettings();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutNetworkSettings_fully_ClockManager_errors(void **)
{
    RetCode ret = kRetOk;

    common_set_SysAppStateReadoutNetworkSettings(0, kClockManagerParamError,
                                                 kEsfNetworkManagerResultSuccess);

    ret = SysAppStateReadoutNetworkSettings();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutNetworkSettings_fully_errors(void **)
{
    RetCode ret = kRetOk;

    common_set_SysAppStateReadoutNetworkSettings(0, kClockManagerSuccess,
                                                 kEsfNetworkManagerResultHWIFError);

    ret = SysAppStateReadoutNetworkSettings();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutNetworkSettings_fully_ip_method_errors(void **)
{
    RetCode ret = kRetOk;

    common_set_SysAppStateReadoutNetworkSettings(-1, kClockManagerSuccess,
                                                 kEsfNetworkManagerResultSuccess);

    ret = SysAppStateReadoutNetworkSettings();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutProxySettings_fully_errors(void **)
{
    RetCode ret = kRetOk;

    // proxy_url
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, 1);

    // proxy_port
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, 2);

    // Proxy_user_name
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, 3);

    // proxy_passwor
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, 4);

    ret = SysAppStateReadoutProxySettings();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutStaModeSetting_fully_success(void **)
{
    RetCode ret = kRetOk;

    // ssid
    common_set_EsfNetworkManagerLoadParameterSSID(0, 0, EncWpa2Psk, "ssid",
                                                  kEsfNetworkManagerResultSuccess);

    // password
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, kEsfNetworkManagerResultSuccess);

    // encryption
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, kEsfNetworkManagerResultSuccess);

    ret = SysAppStateReadoutStaModeSetting();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutStaModeSetting_fully_errors(void **)
{
    RetCode ret = kRetOk;

    // ssid
    common_set_EsfNetworkManagerLoadParameterSSID(0, 0, EncWpa2Psk, "ssid", 1);

    // password
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, 2);

    // encription
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, 3);

    ret = SysAppStateReadoutStaModeSetting();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutStaModeSetting_fully_encryption_errors(void **)
{
    RetCode ret = kRetOk;

    // ssid
    common_set_EsfNetworkManagerLoadParameterSSID(0, 0, EncWpa2Psk, "ssid",
                                                  kEsfNetworkManagerResultSuccess);

    // password
    common_set_EsfNetworkManagerLoadParameter(0, 0, EncWpa2Psk, kEsfNetworkManagerResultSuccess);

    // encryption
    common_set_EsfNetworkManagerLoadParameter(0, 0, WirelessEncryptionNum,
                                              kEsfNetworkManagerResultSuccess);

    ret = SysAppStateReadoutStaModeSetting();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutWirelessSetting_fully_success(void **)
{
    RetCode ret = kRetOk;

    common_set_SysAppStateReadoutWirelessSetting(kEsfNetworkManagerResultSuccess);

    ret = SysAppStateReadoutWirelessSetting();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutPeriodicSetting_fully_success(void **)
{
    SysAppStateReadoutPeriodicSetting();
    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutEndpointSettings_fully_success(void **)
{
    RetCode ret = kRetOk;

    common_set_SysAppStateReadoutEndpointSettings(kEsfSystemManagerResultOk,
                                                  kEsfSystemManagerResultOk);

    ret = SysAppStateReadoutEndpointSettings();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutEndpointSettings_fully_errors(void **)
{
    RetCode ret = kRetOk;

    common_set_SysAppStateReadoutEndpointSettings(kEsfSystemManagerResultInternalError,
                                                  kEsfSystemManagerResultInternalError);

    ret = SysAppStateReadoutEndpointSettings();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateReadoutEndpointSettings_memory_errors(void **)
{
    RetCode ret = kRetOk;

    // malloc(endp_host_buf_size);
    will_return(mock_malloc, false); /* no check size */
    will_return(mock_malloc, false); /* return NULL */
    // malloc(endp_port_buf_size);
    will_return(mock_malloc, false); /* no check size */
    will_return(mock_malloc, false); /* return NULL */

    // free(endpoint_url);
    will_return(mock_free, false); /* no check pointer */
    // free(endpoint_port);
    will_return(mock_free, false); /* no check pointer */

    ret = SysAppStateReadoutEndpointSettings();

    assert_int_equal(ret, kRetMemoryError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateGetReqId_DeviceStates(void **)
{
    SysAppStateGetReqId(ST_TOPIC_DEVICE_STATES);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateGetReqId_SystemSetting(void **)
{
    char *req_id = 0;
    strncpy(s_system_settings.id, "12345", CFG_RES_ID_LEN + 1);

    req_id = SysAppStateGetReqId(ST_TOPIC_SYSTEM_SETTINGS);

    assert_string_equal(req_id, s_system_settings.id);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateGetReqId_NetworkSetting(void **)
{
    char *req_id = NULL;
    strncpy(s_network_settings.id, "6789", CFG_RES_ID_LEN + 1);

    req_id = SysAppStateGetReqId(ST_TOPIC_NETWORK_SETTINGS);

    assert_string_equal(req_id, s_network_settings.id);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateGetReqId_WirelessSetting(void **)
{
    char *req_id = NULL;
    strncpy(s_wireless_setting.id, "abcdef", CFG_RES_ID_LEN + 1);

    req_id = SysAppStateGetReqId(ST_TOPIC_WIRELESS_SETTING);

    assert_string_equal(req_id, s_wireless_setting.id);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateGetReqId_PeropdicSetting(void **)
{
    char *req_id = NULL;
    strncpy(s_periodic_setting.id, "hijkl", CFG_RES_ID_LEN + 1);

    req_id = SysAppStateGetReqId(ST_TOPIC_PERIODIC_SETTING);

    assert_string_equal(req_id, s_periodic_setting.id);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateGetReqId_EndpointSetting(void **)
{
    char *req_id = NULL;
    strncpy(s_endpoint_settings.id, "mnopq", CFG_RES_ID_LEN + 1);

    req_id = SysAppStateGetReqId(ST_TOPIC_ENDPOINT_SETTINGS);

    assert_string_equal(req_id, s_endpoint_settings.id);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateGetReqId_UploadSensorCalibrationParam(void **)
{
    SysAppStateGetReqId(ST_TOPIC_UPLOAD_SENSOR_CALIBRATION_PARAM);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateGetReqId_DeployFireware(void **)
{
    SysAppStateGetReqId(ST_TOPIC_DEPLOY_FIRMWARE);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateGetReqId_DeployAiModel(void **)
{
    SysAppStateGetReqId(ST_TOPIC_DEPLOY_AI_MODEL);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateGetReqId_DeploySensorCalibrationParam(void **)
{
    SysAppStateGetReqId(ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateGetReqId_Reserved(void **)
{
    SysAppStateGetReqId(ST_TOPIC_RESERVED);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateGetProtocolVersion(void **)
{
    char *protocol_version = NULL;
    strncpy(s_endpoint_settings.protocol_version, "1234567890",
            CFGST_ENDPOINT_PROTOCOL_VERSION_LEN + 1);

    protocol_version = SysAppStateGetProtocolVersion();

    assert_string_equal(protocol_version, s_endpoint_settings.protocol_version);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateGetTemperatureUpdateInterval(void **)
{
    int temperature_update_interval = 0;

    s_system_settings.temperature_update_interval = 12345;

    SysAppStateGetTemperatureUpdateInterval(&temperature_update_interval);

    assert_int_equal(temperature_update_interval, s_system_settings.temperature_update_interval);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_DeviceInfo_FullySuccess(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    common_set_SendDeviceInfo(handle_val, parent_val, string_expect, "");

    ret = SysAppStateSendState(ST_TOPIC_DEVICE_INFO);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_DeviceInfo_Open_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";
    s_device_info.device_manifest[0] = '\0';

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonHandleError);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "device_manifest");
    expect_string(__wrap_SysAppCmnSetStringValue, string, "");
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetArrayValue
    will_return(__wrap_SysAppCmnSetArrayValue, kRetOk);

    // EsfJsonSerialize
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SYS_set_state
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // EsfJsonClose
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_DEVICE_INFO);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_DeviceInfo_ObjectInit_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";
    s_device_info.device_manifest[0] = '\0';

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonHandleError);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "device_manifest");
    expect_string(__wrap_SysAppCmnSetStringValue, string, "");
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetArrayValue
    will_return(__wrap_SysAppCmnSetArrayValue, kRetOk);

    // EsfJsonSerialize
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SYS_set_state
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // EsfJsonClose
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_DEVICE_INFO);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_DeviceInfo_Serialize_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";
    s_device_info.device_manifest[0] = '\0';

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "device_manifest");
    expect_string(__wrap_SysAppCmnSetStringValue, string, "");
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetArrayValue
    will_return(__wrap_SysAppCmnSetArrayValue, kRetOk);

    // EsfJsonSerialize
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonHandleError);

    // EsfJsonClose
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_DEVICE_INFO);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_DeviceInfo_Close_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";
    s_device_info.device_manifest[0] = '\0';

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // SysAppCmnSetStringValue
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "device_manifest");
    expect_string(__wrap_SysAppCmnSetStringValue, string, "");
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // SysAppCmnSetArrayValue
    will_return(__wrap_SysAppCmnSetArrayValue, kRetOk);

    // EsfJsonSerialize
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    //EsfJsonClose(handle_val
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonHandleError);

    ret = SysAppStateSendState(ST_TOPIC_DEVICE_INFO);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_DeviceCapabilities_FullySuccess(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    common_set_SendDeviceCapabilities(handle_val, parent_val, string_expect, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_DEVICE_CAPABILITIES);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_DeviceCapabilities_Open_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendDeviceCapabilities
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonHandleError);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonDeviceCapabilities
    common_set_MakeJsonDeviceCapabilities(handle_val, parent_val, kRetOk);

    // SendDeviceCapabilities
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SendDeviceCapabilities
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_DEVICE_CAPABILITIES);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_DeviceCapabilities_ObjectInit_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendDeviceCapabilities
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonHandleError);

    // MakeJsonDeviceCapabilities
    common_set_MakeJsonDeviceCapabilities(handle_val, parent_val, kRetOk);

    // SendDeviceCapabilities
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SendDeviceCapabilities
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_DEVICE_CAPABILITIES);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_DeviceCapabilities_Serialize_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendDeviceCapabilities
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonDeviceCapabilities
    common_set_MakeJsonDeviceCapabilities(handle_val, parent_val, kRetOk);

    // SendDeviceCapabilities
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonHandleError);

    // EsfJsonClose
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_DEVICE_CAPABILITIES);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_DeviceCapabilities_Close_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendDeviceCapabilities
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonDeviceCapabilities
    common_set_MakeJsonDeviceCapabilities(handle_val, parent_val, kRetOk);

    // SendDeviceCapabilities
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SendDeviceCapabilities
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonHandleError);

    ret = SysAppStateSendState(ST_TOPIC_DEVICE_CAPABILITIES);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_DeviceStates_FullySuccess(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    common_set_SendDeviceStates(handle_val, parent_val, string_expect, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_DEVICE_STATES);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_DeviceStates_Open_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendDeviceStates
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonHandleError);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonDeviceStates
    common_set_MakeJsonDeviceStates(handle_val, parent_val, kRetOk);

    // SendDeviceStates
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SendDeviceStates
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_DEVICE_STATES);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_HoursMeterUpdateIntervalCallback_FullySuccess(void **)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // GetSensorHoursMeter
    will_return(__wrap_EsfPwrMgrHoursMeterGetValue, 0);
    will_return(__wrap_EsfPwrMgrHoursMeterGetValue, kRetOk);

    common_set_SendDeviceStates(handle_val, parent_val, string_expect, kEsfJsonSuccess);

    HoursMeterUpdateIntervalCallback();
    return;
}

/*----------------------------------------------------------------------------*/
static void test_HoursMeterUpdateIntervalCallback_Failed(void **)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // The SysAppStateUpdateHoursMeter() function called by SendDeviceStates() does not return an error, so it does not enter error handling

    // GetSensorHoursMeter
    will_return(__wrap_EsfPwrMgrHoursMeterGetValue, 0);
    will_return(__wrap_EsfPwrMgrHoursMeterGetValue, kRetFailed);

    common_set_SendDeviceStates(handle_val, parent_val, string_expect, kEsfJsonInternalError);

    HoursMeterUpdateIntervalCallback();
    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetHashWithB64Encode_Failed(void **)
{
    RetCode ret = kRetFailed;
    EsfFwMgrGetInfoData info;
    EsfFwMgrGetInfoResponse response;
    size_t outsize = ST_PROCESSOR_HASH_LEN + 1;

    memset(&info, 0, sizeof(info));
    memset(&response, 0, sizeof(response));

    ret = SetHashWithB64Encode(response.hash, sizeof(response.hash),
                               s_chips[CHIPS_IDX_MAIN_CHIP].loader_hash, &outsize);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendDeploy_SysAppDeployGetAiModelState(void **)
{
    RetCode ret;

    // SysAppDeployGetAiModelState
    will_return(__wrap_SysAppDeployGetAiModelState, kRetOk);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SysAppDeployFreeState
    will_return(__wrap_SysAppDeployFreeState, kRetOk);

    ret = SendDeploy(ST_TOPIC_DEPLOY_AI_MODEL);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendDeploy_Failed(void **)
{
    RetCode ret;

    ret = SendDeploy(ST_TOPIC_RESERVED);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_DeviceStates_ObjectInit_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendDeviceStates
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonHandleError);

    // MakeJsonDeviceStates
    common_set_MakeJsonDeviceStates(handle_val, parent_val, kRetOk);

    // SendDeviceStates
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SendDeviceStates
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_DEVICE_STATES);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_DeviceStates_Serialize_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendDeviceStates
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonDeviceStates
    common_set_MakeJsonDeviceStates(handle_val, parent_val, kRetOk);

    // SendDeviceStates
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonHandleError);

    // EsfJsonClose
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_DEVICE_STATES);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_DeviceStates_Close_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendDeviceStates
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonDeviceStates
    common_set_MakeJsonDeviceStates(handle_val, parent_val, kRetOk);

    // SendDeviceStates
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SendDeviceStates
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonHandleError);

    ret = SysAppStateSendState(ST_TOPIC_DEVICE_STATES);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_Reserved_FullySuccess(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    common_set_SendReserved(handle_val, parent_val, string_expect, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_RESERVED);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_Reserved_Open_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendReserved
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonHandleError);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);
    // MakeJsonReserved
    common_set_MakeJsonReserved(handle_val, parent_val, kRetOk);

    // SendReserved
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SendReserved
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_RESERVED);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_Reserved_ObjectInit_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendReserved
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonHandleError);

    // MakeJsonReserved
    common_set_MakeJsonReserved(handle_val, parent_val, kRetOk);

    // SendReserved
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SendReserved
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_RESERVED);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_Reserved_Serialize_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendReserved
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonReserved
    common_set_MakeJsonReserved(handle_val, parent_val, kRetOk);

    // SendReserved
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonHandleError);

    // EsfJsonClose
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_RESERVED);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_Reserved_Close_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendReserved
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonReserved
    common_set_MakeJsonReserved(handle_val, parent_val, kRetOk);

    // SendReserved
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SendReserved
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonHandleError);

    ret = SysAppStateSendState(ST_TOPIC_RESERVED);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_SystemSettings_FullySuccess(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    common_set_SendSystemSettings(handle_val, parent_val, string_expect, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_SYSTEM_SETTINGS);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_SystemSettings_Open_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendSystemSettings
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonHandleError);

#ifdef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonSystemSettings
    common_set_MakeJsonSystemSettings(handle_val, parent_val, kRetOk);

    // SendSystemSettings
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SendSystemSettings
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
#endif
    ret = SysAppStateSendState(ST_TOPIC_SYSTEM_SETTINGS);

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    assert_int_equal(ret, kRetFailed);
#else
    assert_int_equal(ret, kRetOk);
#endif
    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_SystemSettings_ObjectInit_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendSystemSettings
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonHandleError);

#ifdef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    // MakeJsonSystemSettings
    common_set_MakeJsonSystemSettings(handle_val, parent_val, kRetOk);

    // SendSystemSettings
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);
#endif
    // SendSystemSettings
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_SYSTEM_SETTINGS);

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    assert_int_equal(ret, kRetFailed);
#else
    assert_int_equal(ret, kRetOk);
#endif

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_SystemSettings_Serialize_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendSystemSettings
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonSystemSettings
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    common_set_MakeJsonResInfoUnimplemented(handle_val, parent_val, kRetOk);
#else
    common_set_MakeJsonSystemSettings(handle_val, parent_val, kRetOk);
#endif

    // SendSystemSettings
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonHandleError);

    // EsfJsonClose
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_SYSTEM_SETTINGS);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_SystemSettings_Close_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendSystemSettings
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonSystemSettings
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    common_set_MakeJsonResInfoUnimplemented(handle_val, parent_val, kRetOk);
#else
    common_set_MakeJsonSystemSettings(handle_val, parent_val, kRetOk);
#endif

    // SendSystemSettings
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SendSystemSettings
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonHandleError);

    ret = SysAppStateSendState(ST_TOPIC_SYSTEM_SETTINGS);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_NetworkSettings_FullySuccess(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    common_set_SendUnimplementedState(handle_val, parent_val, string_expect, kEsfJsonSuccess, "");
#else

    common_set_SendNetworkSettings(handle_val, parent_val, string_expect, kEsfJsonSuccess);
#endif
    ret = SysAppStateSendState(ST_TOPIC_NETWORK_SETTINGS);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_NetworkSettings_Open_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendNetworkSettings
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonHandleError);

#ifdef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonNetworkSettings
    common_set_MakeJsonNetworkSettings(handle_val, parent_val, kRetOk);

    // SendNetworkSettings
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SendNetworkSettings
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

#endif
    ret = SysAppStateSendState(ST_TOPIC_NETWORK_SETTINGS);

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    assert_int_equal(ret, kRetFailed);
#else
    assert_int_equal(ret, kRetOk);
#endif

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_NetworkSettings_ObjectInit_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendNetworkSettings
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonHandleError);
#ifdef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    // MakeJsonNetworkSettings
    common_set_MakeJsonNetworkSettings(handle_val, parent_val, kRetOk);

    // SendNetworkSettings
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);
#endif
    // SendNetworkSettings
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_NETWORK_SETTINGS);

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    assert_int_equal(ret, kRetFailed);
#else
    assert_int_equal(ret, kRetOk);
#endif

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_NetworkSettings_Serialize_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendNetworkSettings
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonNetworkSettings
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    common_set_MakeJsonResInfoUnimplemented(handle_val, parent_val, kRetOk);
#else
    common_set_MakeJsonNetworkSettings(handle_val, parent_val, kRetOk);
#endif

    // SendNetworkSettings
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonHandleError);

    // EsfJsonClose
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_NETWORK_SETTINGS);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_NetworkSettings_Close_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendNetworkSettings
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonNetworkSettings
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    common_set_MakeJsonResInfoUnimplemented(handle_val, parent_val, kRetOk);
#else
    common_set_MakeJsonNetworkSettings(handle_val, parent_val, kRetOk);
#endif

    // SendNetworkSettings
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);
    // SendNetworkSettings
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonHandleError);

    ret = SysAppStateSendState(ST_TOPIC_NETWORK_SETTINGS);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_WirelessSetting_FullySuccess(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    common_set_SendWirelessSetting(handle_val, parent_val, string_expect, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_WIRELESS_SETTING);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_WirelessSetting_Open_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendWirelessSetting
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonHandleError);

#ifdef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonWirelessSetting
    common_set_MakeJsonWirelessSetting(handle_val, parent_val, kRetOk);

    // SendWirelessSetting
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SendWirelessSetting
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
#endif

    ret = SysAppStateSendState(ST_TOPIC_WIRELESS_SETTING);

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    assert_int_equal(ret, kRetFailed);
#else
    assert_int_equal(ret, kRetOk);
#endif

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_WirelessSetting_ObjectInit_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendWirelessSetting
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonHandleError);

#ifdef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    // MakeJsonWirelessSetting
    common_set_MakeJsonWirelessSetting(handle_val, parent_val, kRetOk);

    // SendWirelessSetting
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);
#endif
    // SendWirelessSetting
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_WIRELESS_SETTING);

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    assert_int_equal(ret, kRetFailed);
#else
    assert_int_equal(ret, kRetOk);
#endif

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_WirelessSetting_Serialize_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendWirelessSetting
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonWirelessSetting
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    common_set_MakeJsonResInfoUnimplemented(handle_val, parent_val, kRetOk);
#else
    common_set_MakeJsonWirelessSetting(handle_val, parent_val, kRetOk);
#endif

    // SendWirelessSetting
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonHandleError);

    // EsfJsonClose
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_WIRELESS_SETTING);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_WirelessSetting_Close_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendWirelessSetting
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonWirelessSetting
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    common_set_MakeJsonResInfoUnimplemented(handle_val, parent_val, kRetOk);
#else
    common_set_MakeJsonWirelessSetting(handle_val, parent_val, kRetOk);
#endif

    // SendWirelessSetting
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);
    // SendWirelessSetting
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonHandleError);

    ret = SysAppStateSendState(ST_TOPIC_WIRELESS_SETTING);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
#if defined(CONFIG_BOARD_WIFI_SMALL_ES) //T3Ws
static void test_SysAppStateSendState_PeriodicSetting_FullySuccess(void **)
{
    RetCode ret;

    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    common_set_SendPeriodicSetting(handle_val, parent_val, string_expect, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_PERIODIC_SETTING);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_PeriodicSetting_Close_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    common_set_SendPeriodicSetting(handle_val, parent_val, string_expect, kEsfJsonInternalError);

    ret = SysAppStateSendState(ST_TOPIC_PERIODIC_SETTING);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_PeriodicSetting_Open_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // EsfJsonOpen
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonHandleError);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonPeriodicSetting
    common_set_MakeJsonPeriodicSetting(handle_val, parent_val, kRetOk);

    // EsfJsonSerialize
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // EsfJsonClose
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_PERIODIC_SETTING);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_PeriodicSetting_ObjectInit_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // EsfJsonOpen
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonHandleError);

    // MakeJsonPeriodicSetting
    common_set_MakeJsonPeriodicSetting(handle_val, parent_val, kRetOk);

    // EsfJsonSerialize
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // EsfJsonClose
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_PERIODIC_SETTING);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_PeriodicSetting_Serialize_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // EsfJsonOpen
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonPeriodicSetting
    common_set_MakeJsonPeriodicSetting(handle_val, parent_val, kRetOk);

    // EsfJsonSerialize
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonHandleError);

    // EsfJsonClose
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_PERIODIC_SETTING);

    assert_int_equal(ret, kRetOk);

    return;
}
#else
#endif

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_EndpointSettings_FullySuccess(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    common_set_SendEndpointSettings(handle_val, parent_val, string_expect, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_ENDPOINT_SETTINGS);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_EndpointSettings_Open_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendEndpointSettings
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonHandleError);
#ifdef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonEndpointSettings
    common_set_MakeJsonEndpointSettings(handle_val, parent_val, kRetOk);

    // SendEndpointSettings
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SendEndpointSettings
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
#endif
    ret = SysAppStateSendState(ST_TOPIC_ENDPOINT_SETTINGS);

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    assert_int_equal(ret, kRetFailed);
#else
    assert_int_equal(ret, kRetOk);
#endif

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_EndpointSettings_ObjectInit_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendEndpointSettings
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonHandleError);
#ifdef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    // MakeJsonEndpointSettings
    common_set_MakeJsonEndpointSettings(handle_val, parent_val, kRetOk);

    // SendEndpointSettings
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);
#endif
    // SendEndpointSettings
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_ENDPOINT_SETTINGS);

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    assert_int_equal(ret, kRetFailed);
#else
    assert_int_equal(ret, kRetOk);
#endif

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_EndpointSettings_Serialize_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendEndpointSettings
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonEndpointSettings
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    common_set_MakeJsonResInfoUnimplemented(handle_val, parent_val, kRetOk);
#else
    common_set_MakeJsonEndpointSettings(handle_val, parent_val, kRetOk);
#endif

    // SendEndpointSettings
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonHandleError);

    // EsfJsonClose
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SysAppStateSendState(ST_TOPIC_ENDPOINT_SETTINGS);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_EndpointSettings_Close_Failed(void **)
{
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";

    // SendEndpointSettings
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // EsfJsonObjectInit
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // MakeJsonEndpointSettings
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    common_set_MakeJsonResInfoUnimplemented(handle_val, parent_val, kRetOk);
#else
    common_set_MakeJsonEndpointSettings(handle_val, parent_val, kRetOk);
#endif

    // SendEndpointSettings
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    // SendEndpointSettings
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonHandleError);

    ret = SysAppStateSendState(ST_TOPIC_ENDPOINT_SETTINGS);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_DeployFirmware_FullySuccess(void **)
{
    RetCode ret;

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";
    // SendUnimplementedState
    common_set_SendUnimplementedState(handle_val, parent_val, string_expect, kEsfJsonSuccess, "");
#else
    // SysAppDeployGetFirmwareState
    will_return(__wrap_SysAppDeployGetFirmwareState, kRetOk);

    test_SysAppStateSendState_Deploy_FullySuccess();
#endif
    ret = SysAppStateSendState(ST_TOPIC_DEPLOY_FIRMWARE);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_DeployFirmware_Failed(void **)
{
    RetCode ret;

    // SysAppDeployGetFirmwareState
    will_return(__wrap_SysAppDeployGetFirmwareState, kRetFailed);

    ret = SysAppStateSendState(ST_TOPIC_DEPLOY_FIRMWARE);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_DeployAimodel_FullySuccess(void **)
{
    RetCode ret;
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_serialize_value";
    // Mock configuration for SendUnimplementedState only
    common_set_SendUnimplementedState(handle_val, parent_val, string_expect, kEsfJsonSuccess, "");
#else
    // SysAppDeployGetFirmwareState
    will_return(__wrap_SysAppDeployGetFirmwareState, kRetOk);

    test_SysAppStateSendState_Deploy_FullySuccess();
#endif

    ret = SysAppStateSendState(ST_TOPIC_DEPLOY_FIRMWARE);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_DeployAimodel_Failed(void **)
{
    RetCode ret;

    // SysAppDeployGetFirmwareState
    will_return(__wrap_SysAppDeployGetFirmwareState, kRetFailed);

    ret = SysAppStateSendState(ST_TOPIC_DEPLOY_FIRMWARE);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_DeploySensorCalibrationParam_FullySuccess(void **)
{
    RetCode ret;

    // SysAppDeployGetSensorCalibrationParamState
    will_return(__wrap_SysAppDeployGetSensorCalibrationParamState, kRetOk);

    test_SysAppStateSendState_Deploy_FullySuccess();

    ret = SysAppStateSendState(ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_DeploySensorCalibrationParam_Failed(void **)
{
    RetCode ret;

    // SysAppDeployGetSensorCalibrationParamState
    will_return(__wrap_SysAppDeployGetSensorCalibrationParamState, kRetFailed);

    ret = SysAppStateSendState(ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendState_Deploy_Failed(void **)
{
    RetCode ret;

    // SysAppDeployGetFirmwareState
    will_return(__wrap_SysAppDeployGetFirmwareState, kRetOk);

    // SYS_set_state
    will_return(__wrap_SYS_set_state, kRetFailed);

    // SysAppDeployFreeState
    will_return(__wrap_SysAppDeployFreeState, kRetOk);

    ret = SysAppStateSendState(ST_TOPIC_DEPLOY_FIRMWARE);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStaReopenIfClose_FullySuccess(void **)
{
    RetCode ret;

    s_sccore = 1;
    s_scstream = 0;

    // SensCoreCoreOpenStream
    expect_value(__wrap_senscord_core_open_stream, core, s_sccore);
    expect_string(__wrap_senscord_core_open_stream, stream_key, "inference_stream");
    expect_value(__wrap_senscord_core_open_stream, stream, &s_scstream);
    will_return(__wrap_senscord_core_open_stream, 0);

    ret = SysAppStaReopenIfClose();

    assert_int_equal(ret, kRetOk);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStaReopenIfClose_Failed(void **)
{
    RetCode ret;
    s_sccore = 1;
    s_scstream = 0;

    // SensCoreCoreOpenStream
    expect_value(__wrap_senscord_core_open_stream, core, s_sccore);
    expect_string(__wrap_senscord_core_open_stream, stream_key, "inference_stream");
    expect_value(__wrap_senscord_core_open_stream, stream, &s_scstream);
    will_return(__wrap_senscord_core_open_stream, -1);

    ret = SysAppStaReopenIfClose();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStaReopenIfClose_Sccore_Failed(void **)
{
    RetCode ret;

    s_sccore = 0;

    ret = SysAppStaReopenIfClose();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStaReopenIfClose_Scstream_Success(void **)
{
    RetCode ret;

    s_sccore = 1;
    s_scstream = 1;

    ret = SysAppStaReopenIfClose();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStaClose_FullySuccess(void **)
{
    RetCode ret;

    common_set_SysAppStaClose(1, 1, 0, 0);

    ret = SysAppStaClose();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStaClose_Failed(void **)
{
    RetCode ret;

    common_set_SysAppStaClose(1, 1, 0, -1);

    ret = SysAppStaClose();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStaClose_Sccore_Failed(void **)
{
    RetCode ret;

    common_set_SysAppStaClose(0, 1, 0, 0);

    ret = SysAppStaClose();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStaClose_Scstream_Failed(void **)
{
    RetCode ret;

    common_set_SysAppStaClose(1, 0, 0, 0);

    ret = SysAppStaClose();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStaClose_Mutex_Failed(void **)
{
    RetCode ret;

    // pthread_mutex_lock
    will_return(__wrap_pthread_mutex_lock, -1);

    ret = SysAppStaClose();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStaIsStateQueueEmpty(void **)
{
    bool ret;

    ret = SysAppStaIsStateQueueEmpty();

    assert_true(ret);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConvB64EncErrToString(void **)
{
    for (EsfCodecBase64ResultEnum code = kEsfCodecBase64ResultSuccess;
         code <= kEsfCodecBase64NotSupported; code++) {
        print_message("[  MESSAGE ] %s\n", ConvB64EncErrToString(code));
    }
}

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
/*----------------------------------------------------------------------------*/
static void test_SysAppStateIsUnimplementedTopic_Found(void **state)
{
    (void)state;

    // Test with a topic that exists in s_unimplemented_list
    bool ret = SysAppStateIsUnimplementedTopic("system_settings");

    assert_true(ret);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateIsUnimplementedTopic_NotFound(void **state)
{
    (void)state;

    // Test with a topic that does not exist in s_unimplemented_list
    bool ret = SysAppStateIsUnimplementedTopic("non_existent_topic");

    assert_false(ret);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppStateSendUnimplementedState_Found(void **state)
{
    (void)state;

    // Set up mock for one call
    common_set_SendUnimplementedState((EsfJsonHandle)0x12345678, 1357, "string_serialize_value",
                                      kEsfJsonSuccess, "");

    // Test with a topic that exists in s_unimplemented_list
    RetCode ret = SysAppStateSendUnimplementedState("system_settings", "");

    assert_int_equal(ret, kRetOk);
}

/*----------------------------------------------------------------------------*/

static void test_SysAppStateSendUnimplementedState_NotFound(void **state)
{
    (void)state;

    // Test with a topic that does not exist in s_unimplemented_list
    RetCode ret = SysAppStateSendUnimplementedState("non_existent_topic", "test_id");

    assert_int_equal(ret, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonReqInfoUnimplemented(void **state)
{
    (void)state;

    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;
    const char *test_req_id = "test_req_id_123";

    // MakeJsonReqInfoCore
    common_set_MakeJsonReqInfoCore(handle_val, parent_val, "req_id", test_req_id, kRetOk);

    RetCode ret = MakeJsonReqInfoUnimplemented(handle_val, parent_val, (void *)test_req_id);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoUnimplemented(void **state)
{
    (void)state;

    EsfJsonHandle handle_val = (EsfJsonHandle)0x01;
    EsfJsonValue parent_val = 1357;
    const char *test_req_id = "test_req_id_123";

    // MakeJsonReqInfoCore
    common_set_MakeJsonResInfoSystemSettings(handle_val, parent_val, 12, "unimplemented", kRetOk);

    RetCode ret = MakeJsonResInfoUnimplemented(handle_val, parent_val, (void *)test_req_id);

    assert_int_equal(ret, kRetOk);

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
        // Static function
        cmocka_unit_test(test_ConvertFilterValueToString),
        cmocka_unit_test(test_ReadOutLogByFilterNo_Failed),
        cmocka_unit_test(test_ReadOutLogByFilterNo_filter_Failed),
        cmocka_unit_test(test_MakeJsonReqInfoCore),
        cmocka_unit_test(test_MakeJsonReqInfoSystemSettings),
        cmocka_unit_test(test_MakeJsonReqInfoNetworkSettings),
        cmocka_unit_test(test_MakeJsonReqInfoWirelessSetting),
#if defined(CONFIG_BOARD_WIFI_SMALL_ES) //T3Ws
        cmocka_unit_test(test_MakeJsonReqInfoPeriodicSetting),
#else
#endif
        cmocka_unit_test(test_MakeJsonReqInfoEndpointSettings),
        cmocka_unit_test(test_GetErrorInfo_FullySuccess),
        cmocka_unit_test(test_GetErrorInfo_arg_flag),
        cmocka_unit_test(test_GetErrorInfo_error_flag),
        cmocka_unit_test(test_MakeJsonResInfoSystemSettings_FullySuccess),
        cmocka_unit_test(test_MakeJsonResInfoSystemSettings_invalid_arg_flag),
        cmocka_unit_test(test_MakeJsonResInfoSystemSettings_invalid_led_enabled_flag),
        cmocka_unit_test(
            test_MakeJsonResInfoSystemSettings_invalid_temperature_update_interval_flag),
        cmocka_unit_test(test_MakeJsonResInfoSystemSettings_invalid_filter_flag),
        cmocka_unit_test(test_MakeJsonResInfoSystemSettings_invalid_level_flag),
        cmocka_unit_test(test_MakeJsonResInfoSystemSettings_invalid_destination_flag),
        cmocka_unit_test(test_MakeJsonResInfoSystemSettings_invalid_storage_name_flag),
        cmocka_unit_test(test_MakeJsonResInfoSystemSettings_invalid_path_flag),
        cmocka_unit_test(test_MakeJsonResInfoSystemSettings_too_long_detail_msg),
        cmocka_unit_test(test_MakeJsonResInfoSystemSettings_internal_error_flag),
        cmocka_unit_test(test_MakeJsonResInfoNetworkSettings_FullySuccess),
        cmocka_unit_test(test_MakeJsonResInfoNetworkSettings_invalid_arg_flag),
        cmocka_unit_test(test_MakeJsonResInfoNetworkSettings_invalid_ip_method_flag),
        cmocka_unit_test(test_MakeJsonResInfoNetworkSettings_invalid_ip_address_ipv4_flag),
        cmocka_unit_test(test_MakeJsonResInfoNetworkSettings_invalid_subnet_mask_ipv4_flag),
        cmocka_unit_test(test_MakeJsonResInfoNetworkSettings_invalid_gateway_address_ipv4_flag),
        cmocka_unit_test(test_MakeJsonResInfoNetworkSettings_invalid_dns_address_ipv4_flag),
        cmocka_unit_test(test_MakeJsonResInfoNetworkSettings_invalid_proxy_url_flag),
        cmocka_unit_test(test_MakeJsonResInfoNetworkSettings_invalid_proxy_port_flag),
        cmocka_unit_test(test_MakeJsonResInfoNetworkSettings_invalid_proxy_user_name_flag),
        cmocka_unit_test(test_MakeJsonResInfoNetworkSettings_invalid_proxy_password_flag),
        cmocka_unit_test(test_MakeJsonResInfoNetworkSettings_invalid_ntp_url_flag),
        cmocka_unit_test(test_MakeJsonResInfoNetworkSettings_internal_error_flag1),
        cmocka_unit_test(test_MakeJsonResInfoNetworkSettings_internal_error_flag2),
        cmocka_unit_test(test_MakeJsonResInfoWirelessSetting_FullySuccess),
        cmocka_unit_test(test_MakeJsonResInfoWirelessSetting_invalid_arg_flag),
        cmocka_unit_test(test_MakeJsonResInfoWirelessSetting_invalid_ssid_flag),
        cmocka_unit_test(test_MakeJsonResInfoWirelessSetting_invalid_password_flag),
        cmocka_unit_test(test_MakeJsonResInfoWirelessSetting_invalid_encryption_flag),
        cmocka_unit_test(test_MakeJsonResInfoWirelessSetting_invalid_ssid_password_flag),
        cmocka_unit_test(test_MakeJsonResInfoWirelessSetting_invalid_ssid_encryption_flag),
        cmocka_unit_test(test_MakeJsonResInfoWirelessSetting_invalid_password_encryption_flag),
        cmocka_unit_test(test_MakeJsonResInfoWirelessSetting_invalid_ssid_password_encryption_flag),
        cmocka_unit_test(test_MakeJsonResInfoWirelessSetting_internal_error_flag),
#if defined(CONFIG_BOARD_WIFI_SMALL_ES) //T3Ws
        cmocka_unit_test(test_MakeJsonResInfoPeriodicSetting_FullySuccess),
#else
#endif
        cmocka_unit_test(test_MakeJsonResInfoEndpointSettings_FullySuccess),
        cmocka_unit_test(test_GetSensorTemperature_Success),
        cmocka_unit_test(test_GetSensorTemperature_Upper),
        cmocka_unit_test(test_GetSensorTemperature_UpperApproaching),
        cmocka_unit_test(test_GetSensorTemperature_Lower),
        cmocka_unit_test(test_GetSensorTemperature_LowerApproaching),
        cmocka_unit_test(test_GetSensorTemperature_Stream_Failed),
        cmocka_unit_test(test_GetSensorTemperature_Mutex_Failed),
        cmocka_unit_test(test_GetSensorTemperature_Property_Failed),
        cmocka_unit_test(test_GetPowerSupplyType_FullySuccess),
        cmocka_unit_test(test_GetPowerSupplyType_Failed),
        cmocka_unit_test(test_GetPowerSupplyType_Type_Failed),
        cmocka_unit_test(test_GetSensorPostProcessSupported_Failed),
        cmocka_unit_test(test_GetSensorPostProcessSupported_StreamFailed),
        cmocka_unit_test(test_GetConfigStateUpdateInfo_FullySuccess),
        cmocka_unit_test(test_RequestConfigStateUpdate_FullySuccess),
        cmocka_unit_test(test_RequestConfigStateUpdate_Failed),
        cmocka_unit_test(test_AppendErrorDetail_FullySuccess),
        cmocka_unit_test(test_AppendErrorDetail_Truncate),
        cmocka_unit_test(test_AppendErrorDetail_Too_Small_Buffer),
        cmocka_unit_test(test_CheckErrorFlagAndAppendMessage_FullySuccess),
        cmocka_unit_test(test_CheckErrorFlagAndAppendMessage_Truncate),
        cmocka_unit_test(test_CheckErrorFlagAndAppendMessageWithField_FullySuccess),
        cmocka_unit_test(test_GetSensorLoaderVersion_FullySuccess),
        cmocka_unit_test(test_GetSensorLoaderVersion_Faild),
        cmocka_unit_test(test_GetSensorFirmwareVersion_Faild),
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
        cmocka_unit_test(test_GetAiIspTemperature_Mutex_Failed),
        cmocka_unit_test(test_GetAiIspTemperature_Stream_Failed),
        cmocka_unit_test(test_GetAiIspTemperature_Stream_Property_Failed),
        cmocka_unit_test(test_GetAiIspTemperature_Upper),
        cmocka_unit_test(test_GetAiIspTemperature_UpperApproaching),
#endif
        cmocka_unit_test(test_SensorTempUpdateIntervalCallback_FullySuccess),
        cmocka_unit_test(test_SensorTempUpdateIntervalCallback_Failed),
        cmocka_unit_test(test_HoursMeterUpdateIntervalCallback_FullySuccess),
        cmocka_unit_test(test_HoursMeterUpdateIntervalCallback_Failed),

        cmocka_unit_test(test_SetHashWithB64Encode_Failed),

        cmocka_unit_test(test_SendDeploy_SysAppDeployGetAiModelState),
        cmocka_unit_test(test_SendDeploy_Failed),
        cmocka_unit_test(test_SysAppStateSendState_ST_TOPIC_DEVICE_INFO),
        cmocka_unit_test(test_SysAppStateSendState_ST_TOPIC_DEVICE_CAPABILITIES),
        cmocka_unit_test(test_SysAppStateSendState_ST_TOPIC_DEVICE_STATES),
        cmocka_unit_test(test_SysAppStateSendState_ST_TOPIC_RESERVED),
        cmocka_unit_test(test_SysAppStateSendState_ST_TOPIC_SYSTEM_SETTINGS),
        cmocka_unit_test(test_SysAppStateSendState_ST_TOPIC_NETWORK_SETTINGS),
        cmocka_unit_test(test_SysAppStateSendState_ST_TOPIC_WIRELESS_SETTING),
        cmocka_unit_test(test_SysAppStateSendState_ST_TOPIC_PERIODIC_SETTING),
        cmocka_unit_test(test_SysAppStateSendState_ST_TOPIC_ENDPOINT_SETTINGS),
        cmocka_unit_test(test_SysAppStateSendState_ST_TOPIC_DEPLOY_FIRMWARE),
        cmocka_unit_test(test_SysAppStateSendState_ST_TOPIC_DEPLOY_AI_MODEL),
        cmocka_unit_test(test_SysAppStateSendState_ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM),
        cmocka_unit_test(test_SysAppStateSendState_ST_TOPIC_UPDATE_DEVICE_INFO),
        cmocka_unit_test(test_SysAppStateSendState_Other),

        // STATIC RetCode MakeJsonAiModel(EsfJsonHandle handle, EsfJsonValue root, uint32_t no, void* ctx)
        cmocka_unit_test(test_MakeJsonAiModel_fully_success),

        // STATIC RetCode MakeJsonChips(EsfJsonHandle handle, EsfJsonValue root, uint32_t no, void* ctx)
        cmocka_unit_test(test_MakeJsonChips_fully_success),

        // STATIC RetCode MakeJsonDeviceInfo(EsfJsonHandle handle, EsfJsonValue root)
        cmocka_unit_test(test_MakeJsonDeviceInfo_fully_success),

        // STATIC RetCode MakeJsonDeviceCapabilities(EsfJsonHandle handle, EsfJsonValue root)
        cmocka_unit_test(test_MakeJsonDeviceCapabilities_fully_success),

        // STATIC RetCode MakeJsonPowerSource(EsfJsonHandle handle, EsfJsonValue root, uint32_t no, void* ctx)
        cmocka_unit_test(test_MakeJsonPowerSource_fully_success),
        cmocka_unit_test(test_MakeJsonPowerStates),
        cmocka_unit_test(test_MakeJsonDeviceStates),
        cmocka_unit_test(test_MakeJsonReserved),
        cmocka_unit_test(test_MakeJsonLog),
        cmocka_unit_test(test_MakeJsonLog_FailedNotFound),
        cmocka_unit_test(test_MakeJsonSystemSettings),
        cmocka_unit_test(test_MakeJsonStaticSettingsIPv6),
        cmocka_unit_test(test_MakeJsonStaticSettingsIPv4),
        cmocka_unit_test(test_MakeJsonProxySettings),
        cmocka_unit_test(test_MakeJsonNetworkSettings),
        cmocka_unit_test(test_MakeJsonStaModeSetting),
        cmocka_unit_test(test_MakeJsonWirelessSetting),
#if defined(CONFIG_BOARD_WIFI_SMALL_ES) //T3Ws
        cmocka_unit_test(test_MakeJsonIntervalSettings),
        cmocka_unit_test(test_MakeJsonPeriodicSetting),
#else
#endif
        cmocka_unit_test(test_MakeJsonEndpointSettings),
        cmocka_unit_test(test_GetSensorInfo_stream_Failed),

        // Global function

        // Initial value check for static global variable
        cmocka_unit_test(test_SysAppState_InitialValueOfGlobalVariable),

        // SysAppStaInitialize()
        cmocka_unit_test(test_SysAppStaInitialize_FullySuccess),
        cmocka_unit_test(test_SysAppStaInitialize_Client_Failed),
        cmocka_unit_test(test_SysAppStaInitialize_SensCordCoreInit_Failed),
        cmocka_unit_test(test_SysAppStaInitialize_SensCordCoreOpen_Failed),

        // SysAppStateGetSensCordId()
        cmocka_unit_test(test_SysAppStateGetSensCordId_FullySuccess),
        cmocka_unit_test(test_SysAppStateGetSensCordId_Failed),

        // SysAppStateGetSensCordStream()
        cmocka_unit_test(test_SysAppStateGetSensCordStream_FullySuccess),
        cmocka_unit_test(test_SysAppStateGetSensCordStream_Failed),

        // SysAppStaFinalize()
        cmocka_unit_test(test_SysAppStaFinalize_FullySuccess),
        // SysAppStateUpdateNumber()
        cmocka_unit_test(test_SysAppStateUpdateNumber_FullySuccess),
        // SysAppStateUpdateNumberWithIdx()
        cmocka_unit_test(test_SysAppStateUpdateNumberWithIdx_FullySuccess),
        // SysAppStateUpdateBoolean()
        cmocka_unit_test(test_SysAppStateUpdateBoolean_FullySuccess),
        // SysAppStateUpdateString()
        cmocka_unit_test(test_SysAppStateUpdateString_FullySuccess),
        // SysAppStateUpdateStringWithIdx()
        cmocka_unit_test(test_SysAppStateUpdateStringWithIdx_FullySuccess),
        // SysAppStateUpdateSensorTemperature()
        cmocka_unit_test(test_SysAppStateUpdateSensorTemperature_FullySuccess),
        cmocka_unit_test(test_SysAppStateUpdateSensorTemperature_Failed),

        // SysAppStateUpdateHoursMeter()
        cmocka_unit_test(test_SysAppStateUpdateHoursMeter_FullySuccess),
        // SysAppStateSetInvalidArgError()
        cmocka_unit_test(test_SysAppStateSetInvalidArgError_FullySuccess),
        // SysAppStateSetInvalidArgErrorWithIdx()
        cmocka_unit_test(test_SysAppStateSetInvalidArgErrorWithIdx_FullySuccess),
        // SysAppStateSetInternalError()
        cmocka_unit_test(test_SysAppStateSetInternalError_FullySuccess),
        // SysAppStateSetInternalErrorWithIdx()
        cmocka_unit_test(test_SysAppStateSetInternalErrorWithIdx_FullySuccess),
        // SysAppStateReadoutMainChip()
        cmocka_unit_test(test_SysAppStateReadoutMainChip_FullySuccess),
        cmocka_unit_test(test_SysAppStateReadoutMainChip_Loder_Failed),
        cmocka_unit_test(test_SysAppStateReadoutMainChip_Firmware_Failed),
        cmocka_unit_test(test_SysAppStateReadoutMainChip_GetInfo_Failed),
        cmocka_unit_test(test_SysAppStateReadoutMainChip_GetInfo_Unimplemented),

        // SysAppStateReadoutChips()
        cmocka_unit_test(test_SysAppStateReadoutChips_FullySuccess),
        cmocka_unit_test(test_SysAppStateReadoutChips_Failed),
        cmocka_unit_test(test_SysAppStateReadoutChips_GetInfo_Failed),

        // SysAppStateReadoutAiModels()
        cmocka_unit_test(test_SysAppStateReadoutAiModels_FullySuccess),
        cmocka_unit_test(test_SysAppStateReadoutAiModels_Encode_Failed),
        cmocka_unit_test(test_SysAppStateReadoutAiModels_Malloc_Failed),
        cmocka_unit_test(test_SysAppStateReadoutAiModels_GetInfo_Failed),
        cmocka_unit_test(test_SysAppStateReadoutAiModels_Version_Failed),

        // SysAppStateReadoutDeviceInfo()
        cmocka_unit_test(test_SysAppStateReadoutDeviceInfo_FullySuccess),
        cmocka_unit_test(test_SysAppStateReadoutDeviceInfo_Failed),

        // SysAppStateReadoutDeviceCapabilities()
        cmocka_unit_test(test_SysAppStateReadoutDeviceCapabilities_FullySuccess),

        // SysAppStateReadoutPowerStates()
        cmocka_unit_test(test_SysAppStateReadoutPowerStates_FullySuccess),

        // SysAppStateReadoutDeviceStates()
        cmocka_unit_test(test_SysAppStateReadoutDeviceStates_fully_success),
        cmocka_unit_test(test_SysAppStateReadoutDeviceStates_StartTimer_Failed),
        cmocka_unit_test(test_SysAppStateReadoutDeviceStates_clock_gettime_Failed),

        // SysAppStateReadoutLog()
        cmocka_unit_test(test_SysAppStateReadoutLog_fully_success),

        // SysAppStateReadoutSystemSettings
        cmocka_unit_test(test_SysAppStateReadoutSystemSettings_fully_success),
        cmocka_unit_test(test_SysAppStateReadoutSystemSettings_Failed),

        // SysAppStateReadoutStaticSettingsIPv6
        cmocka_unit_test(test_SysAppStateReadoutStaticSettingsIPv6_fully_success),
        cmocka_unit_test(test_SysAppStateReadoutStaticSettingsIPv6_fully_errors),

        // SysAppStateReadoutStaticSettingsIPv4
        cmocka_unit_test(test_SysAppStateReadoutStaticSettingsIPv4_fully_success),
        cmocka_unit_test(test_SysAppStateReadoutStaticSettingsIPv4_fully_errors),

        // SysAppStateReadoutProxySettings
        cmocka_unit_test(test_SysAppStateReadoutProxySettings_fully_success),
        cmocka_unit_test(test_SysAppStateReadoutProxySettings_fully_errors),
        cmocka_unit_test(test_SysAppStateReadoutProxySettings_fully_port_errors),

        // SysAppStateReadoutNetworkSettings
        cmocka_unit_test(test_SysAppStateReadoutNetworkSettings_fully_success),
        cmocka_unit_test(test_SysAppStateReadoutNetworkSettings_fully_ClockManager_errors),
        cmocka_unit_test(test_SysAppStateReadoutNetworkSettings_fully_errors),
        cmocka_unit_test(test_SysAppStateReadoutNetworkSettings_fully_ip_method_errors),

        // SysAppStateReadoutStaModeSetting
        cmocka_unit_test(test_SysAppStateReadoutStaModeSetting_fully_success),
        cmocka_unit_test(test_SysAppStateReadoutStaModeSetting_fully_errors),
        cmocka_unit_test(test_SysAppStateReadoutStaModeSetting_fully_encryption_errors),

        // SysAppStateReadoutWirelessSetting()
        cmocka_unit_test(test_SysAppStateReadoutWirelessSetting_fully_success),

        // SysAppStateReadoutPeriodicSetting()
        cmocka_unit_test(test_SysAppStateReadoutPeriodicSetting_fully_success),

        // SysAppStateReadoutEndpointSettings()
        cmocka_unit_test(test_SysAppStateReadoutEndpointSettings_fully_success),
        cmocka_unit_test(test_SysAppStateReadoutEndpointSettings_fully_errors),
        cmocka_unit_test(test_SysAppStateReadoutEndpointSettings_memory_errors),

        // SysAppStateGetReqId()
        cmocka_unit_test(test_SysAppStateGetReqId_DeviceStates),
        cmocka_unit_test(test_SysAppStateGetReqId_SystemSetting),
        cmocka_unit_test(test_SysAppStateGetReqId_NetworkSetting),
        cmocka_unit_test(test_SysAppStateGetReqId_WirelessSetting),
        cmocka_unit_test(test_SysAppStateGetReqId_PeropdicSetting),
        cmocka_unit_test(test_SysAppStateGetReqId_EndpointSetting),
        cmocka_unit_test(test_SysAppStateGetReqId_UploadSensorCalibrationParam),
        cmocka_unit_test(test_SysAppStateGetReqId_DeployFireware),
        cmocka_unit_test(test_SysAppStateGetReqId_DeployAiModel),
        cmocka_unit_test(test_SysAppStateGetReqId_DeploySensorCalibrationParam),
        cmocka_unit_test(test_SysAppStateGetReqId_Reserved),

        // SysAppStateGetTemperatureUpdateInterval()
        cmocka_unit_test(test_SysAppStateGetTemperatureUpdateInterval),

        // SysAppStateGetProtocolVersion()
        cmocka_unit_test(test_SysAppStateGetProtocolVersion),

        // SysAppStateSendState() - DeviceInfo
        cmocka_unit_test(test_SysAppStateSendState_DeviceInfo_FullySuccess),
        cmocka_unit_test(test_SysAppStateSendState_DeviceInfo_Open_Failed),
        cmocka_unit_test(test_SysAppStateSendState_DeviceInfo_ObjectInit_Failed),
        cmocka_unit_test(test_SysAppStateSendState_DeviceInfo_Serialize_Failed),
        cmocka_unit_test(test_SysAppStateSendState_DeviceInfo_Close_Failed),

    // SysAppStateSendState() - DeviceCapabilities
#ifdef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
        cmocka_unit_test(test_SysAppStateSendState_DeviceCapabilities_FullySuccess),
        cmocka_unit_test(test_SysAppStateSendState_DeviceCapabilities_Open_Failed),
        cmocka_unit_test(test_SysAppStateSendState_DeviceCapabilities_ObjectInit_Failed),
        cmocka_unit_test(test_SysAppStateSendState_DeviceCapabilities_Serialize_Failed),
        cmocka_unit_test(test_SysAppStateSendState_DeviceCapabilities_Close_Failed),
#endif
        // SysAppStateSendState() - DeviceStates
        cmocka_unit_test(test_SysAppStateSendState_DeviceStates_FullySuccess),
        cmocka_unit_test(test_SysAppStateSendState_DeviceStates_Open_Failed),
        cmocka_unit_test(test_SysAppStateSendState_DeviceStates_ObjectInit_Failed),
        cmocka_unit_test(test_SysAppStateSendState_DeviceStates_Serialize_Failed),
        cmocka_unit_test(test_SysAppStateSendState_DeviceStates_Close_Failed),

        // SysAppStateSendState() - Reserved
        cmocka_unit_test(test_SysAppStateSendState_Reserved_FullySuccess),
        cmocka_unit_test(test_SysAppStateSendState_Reserved_Open_Failed),
        cmocka_unit_test(test_SysAppStateSendState_Reserved_ObjectInit_Failed),
        cmocka_unit_test(test_SysAppStateSendState_Reserved_Serialize_Failed),
        cmocka_unit_test(test_SysAppStateSendState_Reserved_Close_Failed),

        // SysAppStateSendState() - SystemSettings
        cmocka_unit_test(test_SysAppStateSendState_SystemSettings_FullySuccess),
        cmocka_unit_test(test_SysAppStateSendState_SystemSettings_Open_Failed),
        cmocka_unit_test(test_SysAppStateSendState_SystemSettings_ObjectInit_Failed),
        cmocka_unit_test(test_SysAppStateSendState_SystemSettings_Serialize_Failed),
        cmocka_unit_test(test_SysAppStateSendState_SystemSettings_Close_Failed),

        // SysAppStateSendState() - NetworkSettings
        cmocka_unit_test(test_SysAppStateSendState_NetworkSettings_FullySuccess),
        cmocka_unit_test(test_SysAppStateSendState_NetworkSettings_Open_Failed),
        cmocka_unit_test(test_SysAppStateSendState_NetworkSettings_ObjectInit_Failed),
        cmocka_unit_test(test_SysAppStateSendState_NetworkSettings_Serialize_Failed),
        cmocka_unit_test(test_SysAppStateSendState_NetworkSettings_Close_Failed),

        // SysAppStateSendState() - WirelessSetting
        cmocka_unit_test(test_SysAppStateSendState_WirelessSetting_FullySuccess),
        cmocka_unit_test(test_SysAppStateSendState_WirelessSetting_Open_Failed),
        cmocka_unit_test(test_SysAppStateSendState_WirelessSetting_ObjectInit_Failed),
        cmocka_unit_test(test_SysAppStateSendState_WirelessSetting_Serialize_Failed),
        cmocka_unit_test(test_SysAppStateSendState_WirelessSetting_Close_Failed),

#if defined(CONFIG_BOARD_WIFI_SMALL_ES) //T3Ws
        // SysAppStateSendState() - PeriodicSetting
        cmocka_unit_test(test_SysAppStateSendState_PeriodicSetting_FullySuccess),
        cmocka_unit_test(test_SysAppStateSendState_PeriodicSetting_Close_Failed),
        cmocka_unit_test(test_SysAppStateSendState_PeriodicSetting_Open_Failed),
        cmocka_unit_test(test_SysAppStateSendState_PeriodicSetting_ObjectInit_Failed),
        cmocka_unit_test(test_SysAppStateSendState_PeriodicSetting_Serialize_Failed),
#else
#endif

        // SysAppStateSendState() - EndpointSettings
        cmocka_unit_test(test_SysAppStateSendState_EndpointSettings_FullySuccess),
        cmocka_unit_test(test_SysAppStateSendState_EndpointSettings_Open_Failed),
        cmocka_unit_test(test_SysAppStateSendState_EndpointSettings_ObjectInit_Failed),
        cmocka_unit_test(test_SysAppStateSendState_EndpointSettings_Serialize_Failed),
        cmocka_unit_test(test_SysAppStateSendState_EndpointSettings_Close_Failed),

        cmocka_unit_test(test_SysAppStateSendState_DeployFirmware_FullySuccess),
        cmocka_unit_test(test_SysAppStateSendState_DeployAimodel_FullySuccess),
        cmocka_unit_test(test_SysAppStateSendState_DeploySensorCalibrationParam_FullySuccess),
#ifdef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
        cmocka_unit_test(test_SysAppStateSendState_DeployFirmware_Failed),
        cmocka_unit_test(test_SysAppStateSendState_DeployAimodel_Failed),
        cmocka_unit_test(test_SysAppStateSendState_DeploySensorCalibrationParam_Failed),

        cmocka_unit_test(test_SysAppStateSendState_Deploy_Failed),
#endif

        // SysAppStaReopenIfClose()
        cmocka_unit_test(test_SysAppStaReopenIfClose_FullySuccess),
        cmocka_unit_test(test_SysAppStaReopenIfClose_Failed),
        cmocka_unit_test(test_SysAppStaReopenIfClose_Sccore_Failed),
        cmocka_unit_test(test_SysAppStaReopenIfClose_Scstream_Success),

        // SysAppStaClose()
        cmocka_unit_test(test_SysAppStaClose_FullySuccess),
        cmocka_unit_test(test_SysAppStaClose_Failed),
        cmocka_unit_test(test_SysAppStaClose_Sccore_Failed),
        cmocka_unit_test(test_SysAppStaClose_Scstream_Failed),
        cmocka_unit_test(test_SysAppStaClose_Mutex_Failed),

        // SysAppStaIsStateQueueEmpty()
        cmocka_unit_test(test_SysAppStaIsStateQueueEmpty),
        cmocka_unit_test(test_ConvB64EncErrToString),

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
        // MakeJsonReqInfoUnimplemented()
        cmocka_unit_test(test_MakeJsonReqInfoUnimplemented),

        // MakeJsonResInfoUnimplemented()
        cmocka_unit_test(test_MakeJsonResInfoUnimplemented),

        // SysAppStateIsUnimplementedTopic()
        cmocka_unit_test(test_SysAppStateIsUnimplementedTopic_Found),
        cmocka_unit_test(test_SysAppStateIsUnimplementedTopic_NotFound),

        // SysAppStateSendUnimplementedState()
        cmocka_unit_test(test_SysAppStateSendUnimplementedState_Found),
        cmocka_unit_test(test_SysAppStateSendUnimplementedState_NotFound),
#endif // !CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    };

    return (((cmocka_run_group_tests(tests, NULL, NULL)) == 0) ? 0 : 1);
}
