/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _SYSTEM_APP_COMMON_H_
#define _SYSTEM_APP_COMMON_H_

#include "memory_manager.h"
#include "json/include/json.h"

// Result code of directcommand and configuration.

#define RESULT_CODE_OK (0)
#define RESULT_CODE_UNKNOWN (2)
#define RESULT_CODE_INVALID_ARGUMENT (3)
#define RESULT_CODE_RESOURCE_EXHAUSTED (8)
#define RESULT_CODE_FAILED_PRECONDITION (9)
#define RESULT_CODE_ABORTED (10)
#define RESULT_CODE_UNIMPLEMENTED (12)
#define RESULT_CODE_INTERNAL (13)
#define RESULT_CODE_UNAVAILABLE (14)
#define RESULT_CODE_UNAUTHENTICATED (16)

// String length for req/res_id..

#define CFG_RES_ID_LEN (128)
#define CFG_RES_DETAIL_MSG_LEN (256) /*T.B.D*/

// String length for device_info.

#define ST_DEVICE_INFO_DEVICE_MANIFEST_LEN (1024)

// String length for processor.

#define ST_MAIN_CHIP_NAME_LEN (32)
#define ST_PROCESSOR_HARDWARE_VERSION_LEN (32)
#define ST_PROCESSOR_LOADER_VERSION_LEN (32)
#define ST_PROCESSOR_LOADER_UPDATE_DATE_LEN (32)
#define ST_PROCESSOR_FIRMWARE_VERSION_LEN (32)
#define ST_PROCESSOR_FIRMWARE_UPDATE_DATE_LEN (32)
#define ST_PROCESSOR_HASH_LEN (44)

// String length for sensor.

#define ST_SENSOR_NAME_LEN (32)
#define ST_SENSOR_ID_LEN (32)
#define ST_SENSOR_HARDWARE_VERSION_LEN (32)
#define ST_SENSOR_LOADER_VERSION_LEN (32)
#define ST_SENSOR_LOADER_UPDATE_DATE_LEN (32)
#define ST_SENSOR_FIRMWARE_VERSION_LEN (32)
#define ST_SENSOR_FIRMWARE_UPDATE_DATE_LEN (32)
#define ST_SENSOR_HASH_LEN (44)

// String length for ai_model

#define ST_AIMODEL_VERSION_LEN (32)
#define ST_AIMODEL_UPDATE_DATE_LEN (32)
#define ST_AIMODEL_HASH_LEN (44)

// String length for log.

#define CFGST_LOG_FILTER_LEN (32)
#define CFGST_LOG_STORAGE_NAME_LEN (64)
#define CFGST_LOG_PATH_LEN (256)

// String length for network_settings.

#define CFGST_NETWORK_PROXY_URL_LEN (256)
#define CFGST_NETWORK_PROXY_USER_NAME_LEN (32)
#define CFGST_NETWORK_PROXY_PASSWORD_LEN (32)
#define CFGST_NETOWRK_IP_ADDRESS_LEN (39)
#define CFGST_NETOWRK_SUBNET_MASK_LEN (39)
#define CFGST_NETOWRK_GATEWAY_ADDRESS_LEN (39)
#define CFGST_NETOWRK_DNS_ADDRESS_LEN (39)
#define CFGST_NETOWRK_NTP_URL_LEN (256)

// String length for wireless_setting.

#define CFGST_WIRELESS_STA_SSID_LEN (32)
#define CFGST_WIRELESS_STA_PASSWORD_LEN (32)
#define CFGST_WIRELESS_AP_SSID_LEN (32)
#define CFGST_WIRELESS_AP_PASSWORD_LEN (32)

// String length for periodic_settings.
#define CFGST_PERIODIC_INTERVAL_BASETIME_LEN (5)

// String length for endpoint_settings.

#define CFGST_ENDPOINT_DOMAIN_LEN_MIN (3)
// Limiting the total size of a domain to 64 instead of the standard 253(details in issues1053)
#define CFGST_ENDPOINT_DOMAIN_LEN_MAX (64)

#define CFGST_ENDPOINT_LABEL_LEN_MIN (1)
#define CFGST_ENDPOINT_LABEL_LEN_MAX (63)
#define CFGST_ENDPOINT_PORT_MAX (65535)
#define CFGST_ENDPOINT_PROTOCOL_VERSION_LEN (32)

// Topics.

#define ST_TOPIC_DEVICE_INFO (1 << 0)
#define ST_TOPIC_DEVICE_CAPABILITIES (1 << 1)
#define ST_TOPIC_DEVICE_STATES (1 << 2)
#define ST_TOPIC_SYSTEM_SETTINGS (1 << 3)
#define ST_TOPIC_NETWORK_SETTINGS (1 << 4)
#define ST_TOPIC_WIRELESS_SETTING (1 << 5)
#define ST_TOPIC_PERIODIC_SETTING (1 << 6)
#define ST_TOPIC_ENDPOINT_SETTINGS (1 << 7)
#define ST_TOPIC_UPLOAD_SENSOR_CALIBRATION_PARAM (1 << 8)
#define ST_TOPIC_DEPLOY_FIRMWARE (1 << 9)
#define ST_TOPIC_DEPLOY_AI_MODEL (1 << 10)
#define ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM (1 << 11)
#define ST_TOPIC_RESERVED (1 << 12)
#define ST_TOPIC_UPDATE_DEVICE_INFO (1 << 13)

// Data type group.

#define CFGST_DATATYPE_NUMBER (0x80000000)
#define CFGST_DATATYPE_BOOLEAN (0x40000000)
#define CFGST_DATATYPE_STRING (0x20000000)

// Return code.

typedef enum {
    kRetOk = 0,
    kRetFailed,
    kRetBusy,
    kRetStateViolate,
    kRetMemoryError,
    kRetApiCallError,
    kRetNotFound,
    kRetAbort,
    kRetParamError,

} RetCode;

// Tremination reason.

typedef enum {
    UnDefined = 0,
    RebootRequested,
    FactoryResetDeployRequested,
    FactoryResetRequested,
    FactoryResetButtonRequested,

    TerminationReasonNum
} TerminationReason;

// Property type.

typedef enum {
    Id = 0,
} ReqInfoProperty;

typedef enum {
    SensorPostProcessSupported = 1,
} DeviceCapabilitiesProperty;

typedef enum { ProcessState = 1, HoursMeter } DeviceStatesProperty;

typedef enum {
    PowerSourceUnknown = -1,
    PowerSourcePoe = 0,
    PowerSourceUsb,
    PowerSourceDcPlug,
    PowerSourcePrimaryBattery,
    PowerSourceSecondaryBattery,
    PowerSourceNum
} DeviceStatesPowerSourceProperty;

typedef enum {
    LedEnabled = 1,
    LogFilter,
    LogLevel,
    LogDestination,
    LogStorageName,
    LogPath,
    TemperatureUpdateInterval
} SystemSettingsProperty;

typedef enum {
    IpMethod = 1,
    ProxyPort,
    ProxyUrl,
    ProxyUserName,
    ProxyPassword,
    IpAddressV6,
    SubnetMaskV6,
    GatewayAddressV6,
    DnsAddressV6,
    IpAddress,
    SubnetMask,
    GatewayAddress,
    DnsAddress,
    NtpUrl
} NetworkSettingsProperty;

typedef enum { StaSsid = 1, StaPassword, StaEncryption } WirelessSettingProperty;

typedef enum {
    OperationMode = 1,
    RecoveryMethod,
    IpAddrSetting,
    BaseTime,
    CaptureInterval,
    ConfigInterval
} PeriodicSettingProperty;

typedef enum { EndpointPort = 1, EndpointUrl, ProtocolVersion } EndpointSettingsProperty;

// Log filter.

typedef enum {
    AllLog = 0,
    MainFwLog,
    SensorLog,
    CompanionFwLog,
    CompanionAppLog,

    LogFilterNum
} CfgStLogFilter;

// Log level.

typedef enum {
    CriticalLv = 0,
    ErrorLv,
    WarningLv,
    InfoLv,
    DebugLv,
    VerboseLv,

    LogLevelNum
} CfgStLogLevel;

// Log desitination.

typedef enum {
    DestUart = 0,
    DestCloudStorage,

    LogDestinationNum
} CfgStLogDestination;

// IP method.

typedef enum {
    DhcpIp = 0,
    StaticIp,

    IpMethodNum
} CfgStIpMethod;

// Wireless encryption.

typedef enum {
    EncWpa2Psk = 0,
    EncWpa3Psk,
    EncWpa2Wpa3Psk,

    WirelessEncryptionNum
} CfgStWirelessEncryption;

// Operation mode.

typedef enum {
    ContinuoutMode = 0,
    PeriodicMode,

    OperationModeNum
} CfgStOperationMode;

// Recovery method.

typedef enum {
    ManualReset = 0,
    AutoReboot,

    RecoveryMethodNum
} CfgStRecoveryMethod;

// Power supply type.

typedef enum {
    UnknownSupply = -1,
    PoESupply = 0,
    UsbSupply,
    DcPlugSupply,
    PrimaryBattery,
    SecondaryBattery,

    PowerSupplyTypeNum

} CfgStPowerSupplyType;

// Union for some data type.

typedef union {
    int number;
    bool boolean;
    const char* string;
} CfgStData;

// Struct for device_info.

typedef struct {
    char device_manifest[ST_DEVICE_INFO_DEVICE_MANIFEST_LEN + 1];
} StDeviceInfoParams;

// Struct for device_capablities.

typedef struct {
    bool is_battery_supported;
    int supported_wireless_mode;
    bool is_periodic_supported;
    bool is_sensor_postprocess_supported;
} StDeviceCapabilitiesParams;

// Struct for device_states.

typedef struct {
    //power_states;
    char process_state[32];
    long hours_meter;
    int bootup_reason;
    char last_bootup_time[80];
} StDeviceStatesParams;

// Struct for power_states.source.

typedef struct {
    int type;
    int level;
} StPowerStatesSourceParams;

// Struct for power_states.

typedef struct {
    StPowerStatesSourceParams source[PowerSourceNum];
    int in_use;
    bool is_battery_low;
} StPowerStatesParams;

// Struct for processor.

typedef struct {
    char name[ST_MAIN_CHIP_NAME_LEN + 1];
    char hardware_version[ST_PROCESSOR_HARDWARE_VERSION_LEN + 1];
    int current_temperature;
    char loader_version[ST_PROCESSOR_LOADER_VERSION_LEN + 1];
    char loader_hash[ST_PROCESSOR_HASH_LEN + 1];
    char update_date_loader[ST_PROCESSOR_LOADER_UPDATE_DATE_LEN + 1];
    char firmware_version[ST_PROCESSOR_FIRMWARE_VERSION_LEN + 1];
    char firmware_hash[ST_PROCESSOR_HASH_LEN + 1];
    char update_date_firmware[ST_PROCESSOR_FIRMWARE_UPDATE_DATE_LEN + 1];
} StProcessorParams;

// Struct for sensor.

typedef struct {
    char name[ST_SENSOR_NAME_LEN + 1];
    char id[ST_SENSOR_ID_LEN + 1];
    char hardware_version[ST_SENSOR_HARDWARE_VERSION_LEN + 1];
    int current_temperature;
    char loader_version[ST_SENSOR_LOADER_VERSION_LEN + 1];
    char loader_hash[ST_SENSOR_HASH_LEN + 1];
    char update_date_loader[ST_SENSOR_LOADER_UPDATE_DATE_LEN + 1];
    char firmware_version[ST_SENSOR_FIRMWARE_VERSION_LEN + 1];
    char firmware_hash[ST_SENSOR_HASH_LEN + 1];
    char update_date_firmware[ST_SENSOR_FIRMWARE_UPDATE_DATE_LEN + 1];
    //calibration_params;
} StSensorParams;

// Struct for ai_model.

typedef struct {
    char version[ST_AIMODEL_VERSION_LEN + 1];
    char hash[ST_AIMODEL_HASH_LEN + 1];
    char update_date[ST_AIMODEL_UPDATE_DATE_LEN + 1];
    //char location[];
} StAIModelParams;

// Struct for update_info.
//
// Note 1:
//   Not all members of the "CfgStUpdateInfo" structure are used.
//   Only "request_flag" is used. But the "request_flag" bitmap
//   is not used, only the LSB is used.
//
// Note 2:
//   Only the "CfgStUpdateInfo" structure contained in the PARENT
//   topic structure is used.  The "CfgStUpdateInfo" structure
//   contained in the child structure is not used.
//

typedef struct {
    char req_id;
    uint32_t request_flag;
    uint32_t invalid_arg_flag;
    uint32_t internal_error_flag;
} CfgStUpdateInfo;

// Struct for system_settings.

typedef struct {
    char id[CFG_RES_ID_LEN + 1];
    bool led_enabled;
    int temperature_update_interval;
    //int heartbeat_interval;
    CfgStUpdateInfo update;
    uint32_t invalid_led_enabled_flag;
    uint32_t invalid_temperature_update_interval_flag;
} CfgStSystemSettingsParam;

// Struct for log.

typedef struct {
    int filter;
    int level;
    int destination;
    char storage_name[CFGST_LOG_STORAGE_NAME_LEN + 1];
    char path[CFGST_LOG_PATH_LEN + 1];
    CfgStUpdateInfo update;
    uint32_t invalid_filter_flag;
    uint32_t invalid_level_flag;
    uint32_t invalid_destination_flag;
    uint32_t invalid_storage_name_flag;
    uint32_t invalid_path_flag;
} CfgStLogParam;

// Struct for network_settings.

typedef struct {
    char id[CFG_RES_ID_LEN + 1];
    int ip_method;
    char ntp_url[CFGST_NETOWRK_NTP_URL_LEN + 1];
    CfgStUpdateInfo update;
    uint32_t invalid_ip_method_flag;
    uint32_t invalid_ntp_url_flag;
} CfgStNetworkSettingsParam;

// Struct for static_settings.

typedef struct {
    char ip_address[CFGST_NETOWRK_IP_ADDRESS_LEN + 1];
    char subnet_mask[CFGST_NETOWRK_SUBNET_MASK_LEN + 1];
    char gateway_address[CFGST_NETOWRK_GATEWAY_ADDRESS_LEN + 1];
    char dns_address[CFGST_NETOWRK_DNS_ADDRESS_LEN + 1];
    CfgStUpdateInfo update;
    uint32_t invalid_ip_address_flag;
    uint32_t invalid_subnet_mask_flag;
    uint32_t invalid_gateway_address_flag;
    uint32_t invalid_dns_address_flag;
} CfgStStaticSettingsParam;

// Struct for proxy_settings.

typedef struct {
    char proxy_url[CFGST_NETWORK_PROXY_URL_LEN + 1];
    int proxy_port;
    char proxy_user_name[CFGST_NETWORK_PROXY_USER_NAME_LEN + 1];
    char proxy_password[CFGST_NETWORK_PROXY_PASSWORD_LEN + 1];
    CfgStUpdateInfo update;
    uint32_t invalid_proxy_url_flag;
    uint32_t invalid_proxy_port_flag;
    uint32_t invalid_proxy_user_name_flag;
    uint32_t invalid_proxy_password_flag;
} CfgStProxySettingsParam;

// Struct for wiress_setting.

typedef struct {
    char id[CFG_RES_ID_LEN + 1];
    CfgStUpdateInfo update;
} CfgStWirelessSettingsParam;

// Struct for sta_mode_setting.

typedef struct {
    char ssid[CFGST_WIRELESS_STA_SSID_LEN + 1];
    char password[CFGST_WIRELESS_STA_PASSWORD_LEN + 1];
    int encryption;
    CfgStUpdateInfo update;
    uint32_t invalid_ssid_flag;
    uint32_t invalid_password_flag;
    uint32_t invalid_encryption_flag;
} CfgStWirelessStaModeParam;

// Struct for interval_setting.

typedef struct {
    char base_time[CFGST_PERIODIC_INTERVAL_BASETIME_LEN + 1];
    int capture_interval;
    int config_interval;
    CfgStUpdateInfo update;
} CfgStIntervalSettingParam;

// Struct for periodic_setting.

typedef struct {
    char id[CFG_RES_ID_LEN + 1];
    int operation_mode;
    int recovery_method;
    char ip_addr_setting[16];
    CfgStUpdateInfo update;
} CfgStPeriodicSettingParam;

// Struct for endpoint_settings.

typedef struct {
    char id[CFG_RES_ID_LEN + 1];
    char endpoint_url[CFGST_ENDPOINT_DOMAIN_LEN_MAX + 1];
    int endpoint_port;
    char protocol_version[CFGST_ENDPOINT_PROTOCOL_VERSION_LEN + 1];
    CfgStUpdateInfo update;
} CfgStEndpointSettingsParam;

int SysAppCmnExtractStringValue(EsfJsonHandle handle, EsfJsonValue parent_val, const char* jsonkey,
                                const char** string);
int SysAppCmnExtractNumberValue(EsfJsonHandle handle, EsfJsonValue parent_val, const char* jsonkey,
                                int* number);
int SysAppCmnExtractRealNumberValue(EsfJsonHandle handle, EsfJsonValue parent_val,
                                    const char* jsonkey, double* number);
int SysAppCmnExtractBooleanValue(EsfJsonHandle handle, EsfJsonValue parent_val, const char* jsonkey,
                                 bool* boolean);
int SysAppCmnExtractObjectValue(EsfJsonHandle handle, EsfJsonValue parent_val, const char* jsonkey,
                                EsfJsonValue* object);
RetCode SysAppCmnGetReqId(EsfJsonHandle handle, EsfJsonValue parent_val, const char** req_id);
RetCode SysAppCmnSetStringValue(EsfJsonHandle handle, EsfJsonValue parent, const char* key,
                                const char* string);
RetCode SysAppCmnSetStringValueHandle(EsfJsonHandle handle, EsfJsonValue parent, const char* key,
                                      EsfMemoryManagerHandle mm_handle, size_t size);
RetCode SysAppCmnSetNumberValue(EsfJsonHandle handle, EsfJsonValue parent, const char* key,
                                int number);
RetCode SysAppCmnSetRealNumberValue(EsfJsonHandle handle, EsfJsonValue parent, const char* key,
                                    double number);
RetCode SysAppCmnSetBooleanValue(EsfJsonHandle handle, EsfJsonValue parent, const char* key,
                                 bool boolean);
RetCode SysAppCmnSetObjectValue(EsfJsonHandle handle, EsfJsonValue parent, const char* key,
                                RetCode (*make_json)(EsfJsonHandle, EsfJsonValue, void*),
                                void* ctx);
RetCode SysAppCmnSetArrayValue(EsfJsonHandle handle, EsfJsonValue parent, const char* key,
                               uint32_t array_num,
                               RetCode (*make_json)(EsfJsonHandle, EsfJsonValue, uint32_t, void*),
                               void* ctx);
RetCode SysAppCmnMakeJsonResInfo(EsfJsonHandle handle, EsfJsonValue root, const char* res_id,
                                 int code, const char* detail_msg);

#if 1 /* TENTATIVE_STUB : These functions are stub for avoid build error. Must be deleted after API replace. */
#include "network_manager.h"

#define SSF_DEVICE_SETTING_LED_ON_SIZE (32)
#define SSF_DEVICE_SETTING_HARDWARE_APPLICATION_PROCESSOR_SIZE (64 + 1)
#define SSF_DEVICE_SETTING_TEMPERATURE_SENSOR_SIZE (16)
#define SSF_DEVICE_SETTING_APP_FW_VERSION_SIZE (32 + 1)
#define SSF_DEVICE_SETTING_APP_FW_LOADER_VERSION_SIZE (32 + 1)
#define SSF_DEVICE_SETTING_APP_FW_LAST_UPDATE_SIZE (32 + 1)
#define SSF_DEVICE_SETTING_SENSOR_VERSION_SIZE (32 + 1)
#define SSF_DEVICE_SETTING_SENSOR_LOADER_VERSION_SIZE (64 + 1)
#define SSF_DEVICE_SETTING_SENSOR_FW_LOADER_LAST_UPDATE_SIZE (32 + 1)
#define SSF_DEVICE_SETTING_SENSOR_FW_LAST_UPDATE_SIZE (32 + 1)
#define SSF_DEVICE_SETTING_AI_MODEL_VERSION_SIZE (64 + 1)
#define SSF_DEVICE_SETTING_AI_MODEL_LAST_UPDATE_SIZE (32 + 1)
#define SSF_DEVICE_SETTING_CAMERA_SETUP_HASH_SIZE (32)

typedef int32_t SsfDeviceSettingHandle;
#define SSF_DEVICE_SETTING_INVALID_HANDLE (-1)

typedef enum SSFStatus { kSSFStatusOk, kSSFStatusOutOfRange } SSFStatus;

typedef struct {
    struct __mask_per {
        int factory_reset_enable;
    } mask;
    int factory_reset_enable;
} SsfDeviceSettingPermission;

typedef struct {
    struct __mask_sensfw {
        int loader_version;
        int version;
        int loader_last_update;
        int last_update;
    } mask;

    char loader_version[SSF_DEVICE_SETTING_SENSOR_LOADER_VERSION_SIZE];
    char version[SSF_DEVICE_SETTING_SENSOR_VERSION_SIZE];
    char loader_last_update[SSF_DEVICE_SETTING_SENSOR_FW_LOADER_LAST_UPDATE_SIZE];
    char last_update[SSF_DEVICE_SETTING_SENSOR_FW_LAST_UPDATE_SIZE];
} SsfDeviceSettingSensorFw;

typedef struct {
    struct __mask_appfw {
        int loader_version;
        int version;
        int last_update;
    } mask;

    char loader_version[SSF_DEVICE_SETTING_APP_FW_LOADER_VERSION_SIZE];
    char version[SSF_DEVICE_SETTING_APP_FW_VERSION_SIZE];
    char last_update[SSF_DEVICE_SETTING_APP_FW_LAST_UPDATE_SIZE];
} SsfDeviceSettingAppFw;

typedef struct {
    struct __mask_aimodel {
        int version;
        int last_update;
    } mask;

    char version[SSF_DEVICE_SETTING_AI_MODEL_VERSION_SIZE];
    char last_update[SSF_DEVICE_SETTING_AI_MODEL_LAST_UPDATE_SIZE];
} SsfDeviceSettingAIModel;

typedef struct {
    struct __mask_camsetup {
        struct __mask_version {
            int version;
        } version;

        struct __mask_quality {
            int lmt_hash;
            int pre_wb_hash;
            int gamma_hash;
            int lsc_hash;
            int dewarp_hash;
        } quality;
    } mask;

    struct __quality {
        uint8_t lmt_hash[SSF_DEVICE_SETTING_CAMERA_SETUP_HASH_SIZE];
        uint8_t pre_wb_hash[SSF_DEVICE_SETTING_CAMERA_SETUP_HASH_SIZE];
        uint8_t gamma_hash[SSF_DEVICE_SETTING_CAMERA_SETUP_HASH_SIZE];
        uint8_t lsc_hash[SSF_DEVICE_SETTING_CAMERA_SETUP_HASH_SIZE];
        uint8_t dewarp_hash[SSF_DEVICE_SETTING_CAMERA_SETUP_HASH_SIZE];
    } quality;
} SsfDeviceSettingCameraSetup;

#endif /* TENTATIVE_STUB : These functions are stub for avoid build error. Must be deleted after API replace. */

#ifdef ARRAY_SIZE
#undef ARRAY_SIZE
#endif
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#endif // _SYSTEM_APP_COMMON_H_
