/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>

#if defined(__linux__)
#include <unistd.h>
#endif

#include "evp/sdk_sys.h"
#include "sdk_backdoor.h"
#include "senscord/c_api/senscord_c_api.h"
#include "senscord/inference_stream/c_api/property_c_types.h"
#include "hal_i2c.h"
#include "hal_driver.h"
#include "hal_ioexp.h"
#include "system_manager.h"
#include "button_manager.h"
#include "clock_manager.h"
#include "clock_manager_setting.h"
#include "firmware_manager.h"
#include "memory_manager.h"
#include "parameter_storage_manager.h"
#include "power_manager.h"
#include "led_manager.h"
#include "system_app_common.h"
#include "initial_setting_app_timer.h"
#include "initial_setting_app_button.h"
#include "initial_setting_app_log.h"
#include "initial_setting_app_ps.h"
#include "initial_setting_app_util.h"
#include "utility_msg.h"
#include "utility_timer.h"

/****************************************************************************
 * Pre-processor definitions
 ****************************************************************************/

// Define debug log

// Maximum number of telemetry retries

#define TELEMETRY_RETRY_MAX (10)

// Maximum length of the send string

#define MAX_LENGTH_OF_STRING (1024)

// Send enrolldata interval seconds

#define SEND_ENROLLDATA_INTERVAL_SEC (5)

#define SEND_ENROLLDATA_INTERVAL_CNT \
    ((SEND_ENROLLDATA_INTERVAL_SEC * 1000 * 1000) / EVP_PROCESS_EVENT_INTERVAL_US)

// EVP process event interval milliseconds

#define EVP_PROCESS_EVENT_INTERVAL_US (100 * 1000)

// Camera firmware initial startup access URL

/****************************************************************************
 * Private type definitions
 ****************************************************************************/

// Provisioning Mode

typedef enum {
    IsaPsMode_Idle = 0,
    IsaPsMode_Operation,
    IsaPsMode_Enrollment,
    IsaPsMode_QrCode, /* Currently unused. Not set anywhere */
    IsaPsMode_Reboot,
    IsaPsMode_FactoryReset,
    IsaPsModeNum
} IsaPsMode;

// DirectCommand res_info.

typedef struct {
    char res_id[CFG_RES_ID_LEN + 1];
    int code;
    char detail_msg[CFG_RES_DETAIL_MSG_LEN + 1];
} ResInfoContext;

// DirectCommand response context.

typedef struct {
    SYS_response_id cmd_id;
    const char *response;
    bool send_complete;
} ResponseContext;

// Define DCS struct a little shorter

typedef struct SYS_client SYS_client;

// Telemetry information

typedef struct {
    bool complete;
    enum SYS_callback_reason result;
} TelemetryInfo;

// PS information

typedef struct {
    pid_t pid;
    SYS_client *client;
    IsaPsMode mode;
    bool is_ps_mode_force_entory;
    char mqtt_host[ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE];
    char mqtt_port[ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE];
    size_t mqtt_host_len;
    size_t mqtt_port_len;
    bool is_auto_enrollment;
    int retry_count;
} PsInfo;

/****************************************************************************
 * Private Data
 ****************************************************************************/

// Camera firmware initial startup access URL

static const char *s_str_evp_ps_mqtt_host = "provision.aitrios.sony-semicon.com";
static const char *s_str_evp_ps_mqtt_port = "8883";

/****************************************************************************
 * Private Functions
 ****************************************************************************/

// --> TENTATIVE!! SHOULD BE DELETED.

#include "initial_setting_app_ps_stub.c"

// <-- TENTATIVE!! SHOULD BE DELETED.

/*--------------------------------------------------------------------------*/
STATIC EsfJsonErrorCode JsonOpenAndInit(EsfJsonHandle *handle, EsfJsonValue *val)
{
    /* Open and Initialize of Json */

    EsfJsonErrorCode esfj_ret;

    if ((esfj_ret = EsfJsonOpen(handle)) == kEsfJsonSuccess) {
        if ((esfj_ret = EsfJsonObjectInit(*handle, val)) == kEsfJsonSuccess) {
            return esfj_ret;
        }
        EsfJsonClose(*handle);
    }

    ISA_ERR("EsfJsonOpen or Init ret %d", esfj_ret);

    return esfj_ret;
}
/*--------------------------------------------------------------------------*/
STATIC EsfJsonErrorCode JsonOpenAndDeserialize(EsfJsonHandle *handle, EsfJsonValue *val,
                                               const char *param)
{
    /* Open and Deserialize of Json */

    EsfJsonErrorCode esfj_ret;

    if ((esfj_ret = EsfJsonOpen(handle)) == kEsfJsonSuccess) {
        if ((esfj_ret = EsfJsonDeserialize(*handle, param, val)) == kEsfJsonSuccess) {
            return esfj_ret;
        }
        EsfJsonClose(*handle);
    }

    ISA_ERR("EsfJsonOpen or Deserialize ret %d", esfj_ret);

    return esfj_ret;
}

/*--------------------------------------------------------------------------*/
STATIC void ResponseToDetailmsg(ResInfoContext *ctx, const char *req_id, int code)
{
    /* Set rec_info properities */

    ctx->code = code;

    if (req_id) {
        snprintf(ctx->res_id, sizeof(ctx->res_id), "%s", req_id);
    }

    const char *detail_msg = "unknown";

    switch (code) {
        case RESULT_CODE_OK:
            detail_msg = "ok";
            break;

        case RESULT_CODE_UNIMPLEMENTED:
            detail_msg = "unimplemented";
            break;

        case RESULT_CODE_INVALID_ARGUMENT:
            detail_msg = "invalid_argument";
            break;

        case RESULT_CODE_INTERNAL:
            detail_msg = "internal";
            break;

        default:
            ctx->code = RESULT_CODE_UNKNOWN;
            ISA_WARN("Unknown response code:%d", code);
            break;
    }

    snprintf(ctx->detail_msg, sizeof(ctx->detail_msg), "%s", detail_msg);
}

/*--------------------------------------------------------------------------*/
STATIC RetCode MakeJsonResInfo(EsfJsonHandle handle, EsfJsonValue root, void *ctx)
{
    /* Callback of SysAppCmnSetObjectValue */

    ResInfoContext *res_info = (ResInfoContext *)ctx;

    return SysAppCmnMakeJsonResInfo(handle, root, res_info->res_id, res_info->code,
                                    res_info->detail_msg);
}

/*--------------------------------------------------------------------------*/
STATIC RetCode GetDeviceManifest(bool *is_device_manifest, char *p_manifest,
                                 size_t *p_manifest_size)
{
    /* Gets the DeviceManifest.
   * If the DeviceManifest cannot be obtained, the SensorID is returned instead. */

    size_t manifest_size = *p_manifest_size;
    *is_device_manifest = false;

    EsfSystemManagerResult sm_res;

    sm_res = EsfSystemManagerGetDeviceManifest(p_manifest, p_manifest_size);

    if (sm_res == kEsfSystemManagerResultOk) {
        ISA_INFO("EsfSystemManagerGetDeviceManifest:%d", sm_res);
        *is_device_manifest = true;
        return kRetOk;
    }

#ifdef CONFIG_ARCH_CHIP_ESP32S3
    ISA_DBG("Get sensor id");

    senscord_core_t sccore = 0;
    senscord_stream_t scstream = 0;

    /* Init stream */

    int32_t sc_ret = senscord_core_init(&sccore);

    if (sc_ret < 0) {
        ISA_ERR("senscord_core_init() ret %d", sc_ret);
        return kRetFailed;
    }

    RetCode res = kRetFailed;

    /* Open stream */

    sc_ret = senscord_core_open_stream(sccore, "inference_stream", &scstream);
    if (sc_ret < 0) {
        ISA_ERR("senscord_core_open_stream() ret %d", sc_ret);
        goto exit;
    }

    /* Get sensor string info */

    struct senscord_info_string_property_t strinfo = {0};

    strinfo.category = SENSCORD_INFO_STRING_AIISP_DEVICE_ID;

    sc_ret = senscord_stream_get_property(scstream, SENSCORD_INFO_STRING_PROPERTY_KEY,
                                          (void *)&strinfo, sizeof(strinfo));
    if (sc_ret < 0) {
        ISA_ERR("senscord_stream_get_property ret %d", sc_ret);
        goto exit;
    }

    int len = snprintf(p_manifest, manifest_size, "%s", strinfo.info);

    if ((len < 0) || (len >= (int)manifest_size)) {
        ISA_ERR("Too short buf. %d", len);
        goto exit;
    }

    /* Succeed */

    res = kRetOk;

exit:
    // Clena up

    if (sccore && scstream) {
        senscord_core_close_stream(sccore, scstream);
    }

    if (sccore) {
        senscord_core_exit(sccore);
    }
#else  // CONFIG_ARCH_CHIP_ESP32S3
    ISA_DBG("Get product serial id");

    RetCode res = kRetOk;
    EsfSystemManagerHwInfo hwinfo;

    EsfSystemManagerResult esfsm_ret = EsfSystemManagerGetHwInfo(&hwinfo);

    if (esfsm_ret == kEsfSystemManagerResultOk) {
        int len = snprintf(p_manifest, manifest_size, "%s", hwinfo.serial_number);

        if ((len < 0) || (len >= (int)manifest_size)) {
            ISA_ERR("Too short buf. %d", len);
            res = kRetFailed;
        }
    }
    else {
        ISA_ERR("EsfSystemManagerGetHwInfo() failed. %d", esfsm_ret);
        res = kRetFailed;
    }
#endif // CONFIG_ARCH_CHIP_ESP32S3

    return res;
}

/*--------------------------------------------------------------------------*/
STATIC RetCode SendStateCore(SYS_client *sys_client, const char *topic, const char *state)
{
    /* Send state */

    enum SYS_result sys_ret = SYS_RESULT_OK;
    const int show_str_len = 255;

    ISA_INFO("Send state(show %dchars max) %.*s%s", show_str_len, show_str_len, state,
             strnlen(state, show_str_len + 1) > show_str_len ? "...(truncated)" : "");

    sys_ret = SYS_set_state(sys_client, topic, state);
    if (sys_ret != SYS_RESULT_OK) {
        ISA_ERR("SYS_set_state() ret %d", sys_ret);
        return kRetFailed;
    }

    return kRetOk;
}

/*--------------------------------------------------------------------------*/
STATIC RetCode GetReqInfoToSetResInfo(EsfJsonHandle esfj_handle, EsfJsonValue esfj_val,
                                      ResInfoContext *res_info)
{
    /* Get req_info to set res_info */

    ResponseToDetailmsg(res_info, "0", RESULT_CODE_INVALID_ARGUMENT);

    const char *req_id_ptr = NULL;

    RetCode ret = SysAppCmnGetReqId(esfj_handle, esfj_val, &req_id_ptr);

    switch (ret) {
        case kRetOk:
            if (strnlen(req_id_ptr, CFG_RES_ID_LEN + 1) <= CFG_RES_ID_LEN) {
                ResponseToDetailmsg(res_info, req_id_ptr, RESULT_CODE_OK);
            }
            else {
                ret = kRetFailed;
            }
            break;
        case kRetNotFound:
            ResponseToDetailmsg(res_info, NULL, RESULT_CODE_OK);
            ret = kRetOk;
            break;
        default:
            break;
    }

    return ret;
}
/*--------------------------------------------------------------------------*/
STATIC RetCode EndpointSettings(SYS_client *sys_client, const char *topic, const char *config,
                                PsInfo *info)
{
    RetCode ret = kRetOk;

    /* Parse configuration and wait */

    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue esfj_val = ESF_JSON_VALUE_INVALID;

    /* Open SSF(Json) and create JsonValue from param */

    EsfJsonErrorCode esfj_ret = JsonOpenAndDeserialize(&esfj_handle, &esfj_val, config);

    if (esfj_ret != kEsfJsonSuccess) {
        return kRetFailed;
    }

    /* Allocate buffer */

    char *endpoint_port_buf = malloc(ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    if (endpoint_port_buf == NULL) {
        ISA_ERR("malloc");
        ret = kRetMemoryError;
        goto clean_up_exit;
    }

    /* Set res_info */

    ResInfoContext res_info = {0};

    ret = GetReqInfoToSetResInfo(esfj_handle, esfj_val, &res_info);

    if (ret == kRetOk && info->mode == IsaPsMode_Enrollment) {
        /* Backup endpoint */

        EsfSystemManagerResult res;

        /* Get endpoint_url property */

        bool writeback_request = false;
        const char *endpoint_url = NULL;
        int extret = SysAppCmnExtractStringValue(esfj_handle, esfj_val, "endpoint_url",
                                                 &endpoint_url);

        if (extret >= 0) {
            ISA_INFO("Set endpoint_host: %s", endpoint_url);

            if ((extret >= 1) && (strnlen(endpoint_url, CFGST_ENDPOINT_DOMAIN_LEN_MAX + 1) <=
                                  CFGST_ENDPOINT_DOMAIN_LEN_MAX)) {
                res = EsfSystemManagerSetEvpHubUrl(endpoint_url,
                                                   ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);
                if (res != kEsfSystemManagerResultOk) {
                    ISA_ERR("EsfSystemManagerSetEvpHubUrl:%d", res);
                    ResponseToDetailmsg(&res_info, NULL, RESULT_CODE_INTERNAL);
                    writeback_request = true;
                }
            }
            else {
                ISA_WARN("Invalid endpoint_url %s", endpoint_url);
                ResponseToDetailmsg(&res_info, NULL, RESULT_CODE_INVALID_ARGUMENT);
            }
        }

        /* Get endpoint_port property */

        int endpoint_port = 0;
        extret = SysAppCmnExtractNumberValue(esfj_handle, esfj_val, "endpoint_port",
                                             &endpoint_port);

        if (extret >= 0) {
            ISA_INFO("Set endpoint_port: %d", endpoint_port);

            if (extret >= 1 && (endpoint_port >= 0 && endpoint_port <= CFGST_ENDPOINT_PORT_MAX)) {
                snprintf(endpoint_port_buf, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE, "%d",
                         endpoint_port);

                res = EsfSystemManagerSetEvpHubPort(endpoint_port_buf,
                                                    ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);
                if (res != kEsfSystemManagerResultOk) {
                    ISA_ERR("EsfSystemManagerSetEvpHubPort:%d", res);
                    ResponseToDetailmsg(&res_info, NULL, RESULT_CODE_INTERNAL);
                    writeback_request = true;
                }
            }
            else {
                ISA_WARN("Invalid endpoint_port %d", endpoint_port);
                ResponseToDetailmsg(&res_info, NULL, RESULT_CODE_INVALID_ARGUMENT);
            }
        }

        /* Check both of url and port are successfully written? */

        if (writeback_request) {
            ISA_ERR("Write error! Reverting");

            /* If the URL or port is partially set due to an error, set the backup URL and Port. */

            EsfSystemManagerSetEvpHubUrl(info->mqtt_host, info->mqtt_host_len);
            EsfSystemManagerSetEvpHubPort(info->mqtt_port, info->mqtt_port_len);
        }
    }

    /* Set res_info */

    ret = SysAppCmnSetObjectValue(esfj_handle, esfj_val, "res_info", MakeJsonResInfo, &res_info);

    /* Serialize json string and send it */

    const char *state = NULL;

    esfj_ret = EsfJsonSerialize(esfj_handle, esfj_val, &state);

    if (esfj_ret == kEsfJsonSuccess && state != NULL) {
        /* Send state and wait */

        SendStateCore(sys_client, topic, state);

        EsfJsonSerializeFree(esfj_handle);
    }

clean_up_exit:
    /* Clean up */

    free(endpoint_port_buf);

    esfj_ret = EsfJsonClose(esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        ISA_ERR("EsfJsonClose(%p) ret %d", esfj_handle, esfj_ret);
    }

    return ret;
}

/*--------------------------------------------------------------------------*/
STATIC bool GetEnrollmentData(bool *is_device_manifest, char **buf_manifest, char **buf_project_id,
                              char **buf_token)
{
    /* Get manifest, project_id,  token */

    size_t size_manifest_size = ESF_SYSTEM_MANAGER_DEVICE_MANIFEST_MAX_SIZE;
    size_t size_project_id_size = ESF_SYSTEM_MANAGER_PROJECT_ID_MAX_SIZE;
    size_t size_token_size = ESF_SYSTEM_MANAGER_REGISTER_TOKEN_MAX_SIZE;

    char *p_manifest = (char *)malloc(size_manifest_size);
    char *p_project_id = (char *)malloc(size_project_id_size);
    char *p_token = (char *)malloc(size_token_size);

    if (p_manifest == NULL || p_project_id == NULL || p_token == NULL) {
        ISA_ERR("malloc");
        goto errout;
    }

    /* Device manifest */

    if (GetDeviceManifest(is_device_manifest, p_manifest, &size_manifest_size) != kRetOk) {
        goto errout;
    }

    /* Project ID */

    EsfSystemManagerResult res;

    res = EsfSystemManagerGetProjectId(p_project_id, &size_project_id_size);

    if (res != kEsfSystemManagerResultOk) {
        ISA_ERR("EsfSystemManagerGetProjectId");
        goto errout;
    }

    /* Token */

    res = EsfSystemManagerGetRegisterToken(p_token, &size_token_size);

    if (res != kEsfSystemManagerResultOk) {
        ISA_ERR("EsfSystemManagerGetRegisterToken");
        goto errout;
    }

    *buf_manifest = p_manifest;
    *buf_project_id = p_project_id;
    *buf_token = p_token;

    return true;

errout:
    if (p_manifest) {
        free(p_manifest);
    }

    if (p_project_id) {
        free(p_project_id);
    }

    if (p_token) {
        free(p_token);
    }

    *buf_manifest = NULL;
    *buf_project_id = NULL;
    *buf_token = NULL;

    return false;
}

/*--------------------------------------------------------------------------*/
STATIC void SendTelemetryEnrollmentCallback(SYS_client *client, enum SYS_callback_reason result,
                                            void *usr_data)
{
    /* Callback of SYS_send_telemetry */
    (void)client;
    TelemetryInfo *info = (TelemetryInfo *)usr_data;

    /* Log output */

    switch (result) {
        case SYS_REASON_FINISHED:
            ISA_INFO("Succeeded to send enrollment");
            break;

        case SYS_REASON_ERROR:
            ISA_ERR("Failed to send enrollment");
            break;

        case SYS_REASON_TIMEOUT:
            ISA_ERR("Timeout send enrollment");
            break;

        default:
            /* Do nothing */

            ISA_ERR("Do nothing %d", result);
            break;
    }

    info->result = result;
    info->complete = true;
}

/*--------------------------------------------------------------------------*/
STATIC RetCode MakeJsonOfTelemetry(EsfJsonHandle *handle, char *device_manifest,
                                   char *device_manifest_key_name, char *project_id, char *token,
                                   int retry_count, const char **response)
{
    /* Make Json Of Telemetry */

    EsfJsonValue val = ESF_JSON_VALUE_INVALID;

    if (JsonOpenAndInit(handle, &val) != kEsfJsonSuccess) {
        return kRetFailed;
    }

    SysAppCmnSetStringValue(*handle, val, "project_id", project_id);

    SysAppCmnSetStringValue(*handle, val, "token", token);

    SysAppCmnSetStringValue(*handle, val, device_manifest_key_name, device_manifest);

    SysAppCmnSetNumberValue(*handle, val, "retry_count", retry_count);

    if (EsfJsonSerialize(*handle, val, response) == kEsfJsonSuccess) {
        if (*response != NULL) {
            return kRetOk;
        }
    }

    /* Clean up */

    EsfJsonSerializeFree(*handle);

    if (EsfJsonClose(*handle) != kEsfJsonSuccess) {
        ISA_ERR("EsfJsonClose");
    }

    return kRetFailed;
}

/*--------------------------------------------------------------------------*/
STATIC void SendEnrollmentData(PsInfo *p_info)
{
    /* Send enrollment */

    bool is_device_manifest = true;
    char device_manifest_key_name[16];
    char *device_manifest;
    char *project_id;
    char *token;

    if (!GetEnrollmentData(&is_device_manifest, &device_manifest, &project_id, &token)) {
        return;
    }

    /* Send telemetry */

    for (int retry_count = 0; retry_count < TELEMETRY_RETRY_MAX; retry_count++) {
        /* Make json string for telemetry */

        ISA_INFO("Send telemetry");

        EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
        const char *response_org = NULL;

        if (is_device_manifest) {
            strncpy(device_manifest_key_name, "device_manifest", sizeof(device_manifest_key_name));
        }
        else {
            strncpy(device_manifest_key_name, "sensor_id", sizeof(device_manifest_key_name));
        }

        if (MakeJsonOfTelemetry(&esfj_handle, device_manifest, device_manifest_key_name, project_id,
                                token, p_info->retry_count++, &response_org) != kRetOk) {
            break;
        }

        size_t len = strnlen(response_org, MAX_LENGTH_OF_STRING);

        for (size_t i = 0; i < len; i += 78) {
            ISA_INFO("%.78s", response_org + i);
        }

        /* Send telemetry */
        TelemetryInfo info = {.complete = false, .result = SYS_REASON_FINISHED};

        if (SYS_send_telemetry(p_info->client, "auto_enrollment", response_org,
                               SendTelemetryEnrollmentCallback, &info) != SYS_RESULT_OK) {
            ISA_ERR("SYS_send_telemetry");
        }
        else {
            /* Wait for telemetry transmission to finish */

            ISA_INFO("Wait telemetry");

            for (;;) {
                if (SYS_process_event(p_info->client, 0) == SYS_RESULT_SHOULD_EXIT) {
                    break;
                }

                if (info.complete) {
                    break;
                }

                usleep(100 * 1000);
            }

            ISA_INFO("Send telemetry OK");
        }

        /* Free the serialized json string */

        EsfJsonSerializeFree(esfj_handle);

        /* Clean up json */

        if (EsfJsonClose(esfj_handle) != kEsfJsonSuccess) {
            ISA_ERR("EsfJsonClose(%p)", esfj_handle);
        }

        if (info.result != SYS_REASON_TIMEOUT) {
            break;
        }

        ISA_INFO("Telemetry callback timeout...retry(%d/%d)", retry_count + 1, TELEMETRY_RETRY_MAX);
    }

    /* Clean up */

    if (device_manifest) {
        free(device_manifest);
    }

    if (project_id) {
        free(project_id);
    }

    if (token) {
        free(token);
    }
}

/*--------------------------------------------------------------------------*/
STATIC RetCode SetResId(const char *param, ResInfoContext *info)
{
    /* Get req_id */

    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue esfj_val = ESF_JSON_VALUE_INVALID;

    /* Open SSF(Json) and create JsonValue from param */

    EsfJsonErrorCode esfj_ret = JsonOpenAndDeserialize(&esfj_handle, &esfj_val, param);

    if (esfj_ret != kEsfJsonSuccess) {
        ResponseToDetailmsg(info, "0", RESULT_CODE_INTERNAL);
        return kRetFailed;
    }

    /* Set res_info */

    RetCode ret = GetReqInfoToSetResInfo(esfj_handle, esfj_val, info);

    /* Clean up */

    esfj_ret = EsfJsonClose(esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        ISA_ERR("EsfJsonClose(%p) ret %d", esfj_handle, esfj_ret);
    }

    return ret;
}

/*--------------------------------------------------------------------------*/
STATIC IsaPsErrorCode ReleaseEvpAgent(PsInfo *ps_info)
{
    /* Clean up of EvpAgent */

    ISA_INFO("Release EvpAgent");

    if (ps_info->client != NULL) {
        int sys_ret = EVP_Agent_unregister_sys_client(ps_info->client);
        if (sys_ret != 0) {
            ISA_ERR("EVP_Agent_unregister_sys_client() ret %d", sys_ret);
        }
    }

#if defined(__NuttX__)
    if (ps_info->pid != (pid_t)-1) {
        task_delete(ps_info->pid);
    }
#else
    extern void evp_agent_shutdown();
    evp_agent_shutdown();
#endif

    ps_info->client = NULL;
    ps_info->pid = -1;

    return kIsaPsSuccess;
}

/*--------------------------------------------------------------------------*/
STATIC void ConfigurationCallback(SYS_client *, const char *topic, const char *config,
                                  enum SYS_type_configuration, enum SYS_callback_reason reason,
                                  void *usr_data)
{
    /* Callback of Configuration */
    if (reason != SYS_REASON_FINISHED) {
        ISA_ERR("Conf receive(%d)", reason);
        return;
    }

    if (strcmp(topic, "PRIVATE_endpoint_settings") == 0) {
        ISA_INFO("Conf: %s", topic);
        EndpointSettings(((PsInfo *)usr_data)->client, topic, config, usr_data);
    }
    else {
        ISA_WARN("Skip: %s", topic);
    }

    /* Set enrollment settings when initial configuration is received */

    PsInfo *ps_info = (PsInfo *)usr_data;

    if (ps_info->mode != IsaPsMode_Enrollment) {
        ISA_INFO("1st configuration received");
        ps_info->mode = IsaPsMode_Enrollment;
    }
}

/*--------------------------------------------------------------------------*/
STATIC void ResponseSendCompleteCallback(SYS_client *, enum SYS_callback_reason reason,
                                         void *context)
{
    /* Callback of SYS_set_response_cb */
    ISA_INFO("Callback of SYS_set_response_cb");

    if (context == NULL) {
        ISA_ERR("ResponseSendCompleteCallback(%d, %p)", reason, context);
        return;
    }

    ResponseContext *ctx = (ResponseContext *)context;

    ctx->send_complete = true;
}

/*--------------------------------------------------------------------------*/
STATIC RetCode SendDirectCommandResponseCore(SYS_client *sys_handle, SYS_response_id cmd_id,
                                             const char *response)
{
    RetCode ret = kRetOk;
    enum SYS_result sys_ret = SYS_RESULT_OK;
    ResponseContext dcres_ctx;

    // Set context parameter to give send-complete-callback.

    dcres_ctx.cmd_id = cmd_id;
    dcres_ctx.response = response;
    dcres_ctx.send_complete = false;

    // Send direct command response.

    const int show_str_len = 127;

    ISA_INFO("Send command response(show %dchars max): cmd_id %ju, %.*s%s", show_str_len, cmd_id,
             show_str_len, response,
             strnlen(response, show_str_len + 1) > show_str_len ? "...(truncated)" : "");

    sys_ret = SYS_set_response_cb(sys_handle, cmd_id, response, SYS_RESPONSE_STATUS_OK,
                                  ResponseSendCompleteCallback, &dcres_ctx);
    if (sys_ret != SYS_RESULT_OK) {
        ISA_ERR("SYS_set_response_cb() ret %d", sys_ret);
        return kRetFailed;
    }

    // If sync is specified, call SYS_process_event() until send complete.
    // When call SYS_process_event(), ResponseSendCompleteCallback() is called internally.
    // ResponseSendCompleteCallback() notifies send completion to send_complete flag.

    for (;;) {
        if (SYS_process_event(sys_handle, 0) == SYS_RESULT_SHOULD_EXIT) {
            break;
        }

        if (dcres_ctx.send_complete) {
            break;
        }

        ISA_INFO("Wait...");
        usleep(100 * 1000);
    }

    return ret;
}

/*--------------------------------------------------------------------------*/
STATIC RetCode SendDirectCommandResponse(SYS_client *sys_handle, SYS_response_id cmd_id,
                                         ResInfoContext *res_info)
{
    /* Send response of DirectCommand */

    RetCode ret = kRetOk;
    EsfJsonErrorCode esfj_ret = kEsfJsonSuccess;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue esfj_val = ESF_JSON_VALUE_INVALID;

    /* Set res_info parameter */

    esfj_ret = JsonOpenAndInit(&esfj_handle, &esfj_val);

    if (esfj_ret != kEsfJsonSuccess) {
        return kRetFailed;
    }

    ret = SysAppCmnSetObjectValue(esfj_handle, esfj_val, "res_info", MakeJsonResInfo, res_info);

    /* Serialize json string and send it */

    const char *response = NULL;

    esfj_ret = EsfJsonSerialize(esfj_handle, esfj_val, &response);

    /* Send DirectCommand response and wait for completion */

    if (esfj_ret == kEsfJsonSuccess && response != NULL) {
        ret = SendDirectCommandResponseCore(sys_handle, cmd_id, response);
        EsfJsonSerializeFree(esfj_handle);
    }
    else {
        ret = kRetFailed;
    }

    /* Clean up */

    esfj_ret = EsfJsonClose(esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        ISA_ERR("EsfJsonClose(%p) ret %d", esfj_handle, esfj_ret);
    }

    return ret;
}

/*--------------------------------------------------------------------------*/
STATIC void DirectCommandRebootCallback(SYS_client *, SYS_response_id cmd_id, const char *params,
                                        void *user_context)
{
    /* Callback of DirectCommand */

    if (params == NULL) {
        ISA_ERR("DirectCommandRebootCallback(%d, %p, %p)", (int)cmd_id, params, user_context);
        return;
    }

    ISA_INFO("DirectCommand callback (cmd_id %ju, %s)", cmd_id, "reboot");
    ISA_DBG("Params %s", params);

    PsInfo *ps_info = (PsInfo *)user_context;

    /* Set result info */
    ResInfoContext res_info;
    SetResId(params, &res_info);

    /* Perform a reboot */
    ps_info->mode = IsaPsMode_Reboot;

    /* Send DirectCommand response and wait for completion */

    SendDirectCommandResponse(ps_info->client, cmd_id, &res_info);
}

/*----------------------------------------------------------------------------*/
STATIC RetCode CheckProjectIdAndRegisterToken(void)
{
    RetCode ret = kRetNotFound;

    size_t project_id_size = ESF_SYSTEM_MANAGER_PROJECT_ID_MAX_SIZE;
    size_t register_token_size = ESF_SYSTEM_MANAGER_REGISTER_TOKEN_MAX_SIZE;

    char *project_id = (char *)malloc(project_id_size);
    char *register_token = (char *)malloc(register_token_size);

    if (project_id == NULL || register_token == NULL) {
        ISA_ERR("malloc");
        ret = kRetMemoryError;
        goto exit;
    }

    EsfSystemManagerResult res;

    res = EsfSystemManagerGetProjectId(project_id, &project_id_size);

    if (res != kEsfSystemManagerResultOk) {
        ISA_ERR("EsfSystemManagerGetProjectId:%d", res);
        goto exit;
    }

    res = EsfSystemManagerGetRegisterToken(register_token, &register_token_size);

    if (res != kEsfSystemManagerResultOk) {
        ISA_ERR("EsfSystemManagerGetProjectId:%d", res);
        goto exit;
    }

    ISA_INFO("ProjectId:%s", project_id);
    ISA_INFO("RegiToken:%s", register_token);

    /* Check if ProjectId and RegisterToken are set */

    if (project_id[0] != '\0' && register_token[0] != '\0') {
        ret = kRetOk;
    }

exit:
    /* Clean up */

    if (project_id) {
        free(project_id);
    }

    if (register_token) {
        free(register_token);
    }

    return ret;
}

/*--------------------------------------------------------------------------*/
STATIC RetCode SetDefaultEndpoint(PsInfo *ps_info)
{
    /* Set default url and port */

    RetCode ret = kRetOk;

    size_t mqtt_host_size = ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE;
    size_t mqtt_port_size = ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE;

    char *mqtt_host = (char *)malloc(mqtt_host_size);
    char *mqtt_port = (char *)malloc(mqtt_port_size);

    if (mqtt_host == NULL || mqtt_port == NULL) {
        ISA_CRIT(
            "mqtt_host or mqtt_port malloc failed. "
            "mqtt_host=%p, mqtt_port=%p, mqtt_host_size=%zu, mqtt_port_size=%zu",
            mqtt_host, mqtt_port, mqtt_host_size, mqtt_port_size);
        ret = kRetMemoryError;
        goto exit;
    }

    /* Set default endpoint */

    EsfSystemManagerResult res;

    ps_info->is_auto_enrollment = (CheckProjectIdAndRegisterToken() == kRetOk);

    if (!ps_info->is_ps_mode_force_entory && !ps_info->is_auto_enrollment) {
        /* In PS mode, endpoint URL and port are set to fixed values */

        snprintf(mqtt_host, mqtt_host_size, "%s", s_str_evp_ps_mqtt_host);
        snprintf(mqtt_port, mqtt_port_size, "%s", s_str_evp_ps_mqtt_port);

        res = EsfSystemManagerSetEvpHubUrl(mqtt_host, mqtt_host_size);

        if (res != kEsfSystemManagerResultOk) {
            ISA_WARN("EsfSystemManagerSetEvpHubUrl:%d", res);
        }

        res = EsfSystemManagerSetEvpHubPort(mqtt_port, mqtt_port_size);

        if (res != kEsfSystemManagerResultOk) {
            ISA_WARN("EsfSystemManagerSetEvpHubPort:%d", res);
        }
    }

    /* Set the mode to force enter PS mode.
   * Reason:
   * This is to allow the device to start in PS mode again
   * if the power is turned off/on while connected to EVP. */

    EsfSystemManagerSetQrModeTimeoutValue(ISAPP_PS_MODE_FORCE_ENTRY);

    /* Check if the settings are correct */

    res = EsfSystemManagerGetEvpHubUrl(mqtt_host, &mqtt_host_size);

    if (res != kEsfSystemManagerResultOk) {
        ISA_WARN("EsfSystemManagerGetEvpHubUrl:%d", res);
    }

    res = EsfSystemManagerGetEvpHubPort(mqtt_port, &mqtt_port_size);

    if (res != kEsfSystemManagerResultOk) {
        ISA_WARN("EsfSystemManagerGetEvpHubPort:%d", res);
    }

    ISA_INFO("Host: %s", mqtt_host);
    ISA_INFO("Port: %s", mqtt_port);

    /* Backup endpoint
   * Use when there is error during ESF configuration or when the port is not set */

    ps_info->mqtt_host_len =
        snprintf(ps_info->mqtt_host, sizeof(ps_info->mqtt_host), "%s", mqtt_host) + 1;
    ps_info->mqtt_port_len =
        snprintf(ps_info->mqtt_port, sizeof(ps_info->mqtt_port), "%s", mqtt_port) + 1;

    ISA_INFO("Host_bk: %s(%zu)", ps_info->mqtt_host, ps_info->mqtt_host_len);
    ISA_INFO("Port_bk: %s(%zu)", ps_info->mqtt_port, ps_info->mqtt_port_len);

exit:
    /* Clean up */

    if (mqtt_host) {
        free(mqtt_host);
    }

    if (mqtt_port) {
        free(mqtt_port);
    }

    return ret;
}

/*--------------------------------------------------------------------------*/
STATIC RetCode SetupEvpAgent(PsInfo *ps_info)
{
    /* Setting up EvpAgent */

    ISA_INFO("Setting up EvpAgent");

    ps_info->pid = -1;
    ps_info->client = NULL;

    /* Set default EvpHUb url and port */

    if (SetDefaultEndpoint(ps_info) != kRetOk) {
        return kRetFailed;
    }

    /* Start EvpAgent */
#if defined(__NuttX__)
    extern int evp_agent_main(int, FAR char **);

    ps_info->pid = task_create("EVP Agent", 101, CONFIG_DEFAULT_TASK_STACKSIZE, evp_agent_main,
                               NULL);
    if (ps_info->pid == (pid_t)-1) {
        ISA_CRIT("Failed to create EVP Agent task. errno=%d", errno);
        return kRetFailed;
    }
#else
    extern int evp_agent_startup();

    int ret = evp_agent_startup();
    if (ret) {
        ISA_CRIT("Failed to create EVP Agent\n");
        return kRetFailed;
    }
#endif
    /* Setup EvpAgent and get a handle */

    while (ps_info->client == NULL) {
        ps_info->client = EVP_Agent_register_sys_client();
        if (ps_info->client == NULL) {
            ISA_WARN("Sys Client registration failed, retrying in 100ms...");
            usleep(100 * 1000); // 100ms wait
        }
    }

    /*FIXME: Register configuration callback */

    enum SYS_result sys_ret = SYS_set_configuration_cb(
        ps_info->client, "system_settings", ConfigurationCallback, SYS_CONFIG_ANY, ps_info);
    if (sys_ret != SYS_RESULT_OK) {
        ISA_CRIT("SYS_set_configuration_cb() for system_settings ret %d", sys_ret);
        goto errout;
    }

    sys_ret = SYS_set_configuration_cb(ps_info->client, "PRIVATE_endpoint_settings",
                                       ConfigurationCallback, SYS_CONFIG_ANY, ps_info);
    if (sys_ret != SYS_RESULT_OK) {
        ISA_CRIT("SYS_set_configuration_cb() for PRIVATE_endpoint_settings ret %d", sys_ret);
        goto errout;
    }

    /* Register direct command callback */

    sys_ret = SYS_register_command_cb(ps_info->client, "reboot", DirectCommandRebootCallback,
                                      ps_info);

    if (sys_ret != SYS_RESULT_OK) {
        ISA_CRIT("SYS_register_command_cb(reboot) ret %d", sys_ret);
        goto errout;
    }

    ISA_INFO("Setting up EvpAgent OK");

    /* Once connected to EVP,
   * If not auto enrollment mode, delete the URL.
   * This will allow you to start in PS mode even if you reset,
   * for example if the settings fail. */

    EsfSystemManagerSetQrModeTimeoutValue(0);

    if (!ps_info->is_auto_enrollment) {
        EsfSystemManagerSetEvpHubUrl("", 1);
    }

    return kRetOk;

errout:
    /* Clean up */

    ReleaseEvpAgent(ps_info);

    return kRetFailed;
}

/*--------------------------------------------------------------------------*/
STATIC void SetLedStatusForProvisioningService(void)
{
    // Set LED status when entering ProvisioningService.

    EsfLedManagerResult ret_ledmgr = kEsfLedManagerInternalError;
    EsfLedManagerLedStatusInfo status;

    status.led = kEsfLedManagerTargetLedPower;
    status.enabled = true;
    status.status = kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner;

    ret_ledmgr = EsfLedManagerSetStatus(&status);

    if (ret_ledmgr != kEsfLedManagerSuccess) {
        ISA_ERR("EsfLedManagerSetStatus failed : ret=%d", ret_ledmgr);
    }
}

/*--------------------------------------------------------------------------*/
STATIC void UnsetLedStatusForProvisioningService(void)
{
    // Unset PS mode led status.

    EsfLedManagerResult ret_ledmgr = kEsfLedManagerInternalError;
    EsfLedManagerLedStatusInfo status;

    status.led = kEsfLedManagerTargetLedPower;
    status.enabled = false;
    status.status = kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner;

    ret_ledmgr = EsfLedManagerSetStatus(&status);

    if (ret_ledmgr != kEsfLedManagerSuccess) {
        ISA_ERR("EsfLedManagerSetStatus failed : ret=%d", ret_ledmgr);
    }
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/*--------------------------------------------------------------------------*/
IsaPsErrorCode IsaRunProvisioningService(bool is_ps_mode_force_entory)
{
    /* Run the provisioning service */

    RetCode ret;
    PsInfo *ps_info;

    ps_info = (PsInfo *)malloc(sizeof(PsInfo));

    if (ps_info == NULL) {
        ISA_CRIT("PsInfo malloc failed. size=%zu", sizeof(PsInfo));
        return kIsaPsDoesntRun;
    }

    memset(ps_info, 0, sizeof(PsInfo));

    ps_info->pid = -1;

    // Set LED status when entering ProvisioningService.

    SetLedStatusForProvisioningService();

    if (is_ps_mode_force_entory == true) {
        /* Debug mode setting.
     * Get EvpHub connection destination from EsfSystemManagerSetEvpHubUrl. */

        ISA_INFO("### Force entory mode ###");

        ps_info->is_ps_mode_force_entory = true;
    }

    /* Start PS... */

    ISA_INFO("Start Provisioning Services...");

    // Connect network. Keep retyr until connect will be succeeded.

    ISA_INFO("Setting up network");

    do {
        ret = ConnectNetwork();

        if (ret == kRetAbort) {
            if (IsaBtnCheckFactoryResetRequest()) {
                ISA_INFO("Network connect abort for factory_reset.");
                ps_info->mode = IsaPsMode_FactoryReset;
            }
            else {
                ISA_INFO("Network connect abort for reboot.");
                ps_info->mode = IsaPsMode_Reboot;
            }
            goto network_abort;
        }

        if (ret != kRetOk) {
            ISA_WARN("ConnectNetwork() ret %d, retry.", ret);
        }

        // Check reboot request.

        if (IsaBtnCheckRebootRequest()) {
            ps_info->mode = IsaPsMode_Reboot;
            goto network_abort;
        }

        // Check factory_reset request.

        if (IsaBtnCheckFactoryResetRequest()) {
            ps_info->mode = IsaPsMode_FactoryReset;
            goto network_abort;
        }

        sleep(1);
    } while (ret != kRetOk);

    if ((ret = StartSyncNtp()) != kRetOk) {
        if (IsaBtnCheckFactoryResetRequest()) {
            ISA_INFO("StartSyncNtp() ret %d for factory_reset.", ret);
            ps_info->mode = IsaPsMode_FactoryReset;
        }
        else {
            ISA_INFO("StartSyncNtp() ret %d for reboot.", ret);
            ps_info->mode = IsaPsMode_Reboot;
        }
        goto ntpsync_abort;
    }

    /* Setup EvpAgent */

    if ((ret = SetupEvpAgent(ps_info)) != kRetOk) {
        goto errout;
    }

    /*
   * main loop
   */

    ISA_INFO("Main loop...");

    ps_info->mode = IsaPsMode_Idle;

    int interval = SEND_ENROLLDATA_INTERVAL_CNT;

    bool is_evp_connect_checked = false;

    for (;;) {
        /* Check EVP Connection and control LED */

        if (!is_evp_connect_checked) {
            is_evp_connect_checked = true;
        }

        if (SYS_process_event(ps_info->client, 0) == SYS_RESULT_SHOULD_EXIT) {
            ISA_CRIT("SYS_process_event() == SYS_RESULT_SHOULD_EXIT");
            break;
        }

        if (ps_info->mode == IsaPsMode_Reboot) {
            ISA_INFO("Exit(%d)", ps_info->mode);
            break;
        }

        if (IsaBtnCheckFactoryResetRequest()) {
            ISA_INFO("Exit PS mode for factory_reset");
            ps_info->mode = IsaPsMode_FactoryReset;
            break;
        }

        if (IsaBtnCheckRebootRequest()) {
            ISA_INFO("Exit PS mode to QR code mode");

            // Set QR mode timeout value to enter QR mode at next reboot.

            EsfSystemManagerResult esfss_ret = EsfSystemManagerSetQrModeTimeoutValue(-1);

            if (esfss_ret != kEsfSystemManagerResultOk) {
                ISA_ERR("EsfSystemManagerSetQrModeTimeoutValue() ret %d", esfss_ret);
            }

            ps_info->mode = IsaPsMode_Reboot;
            break;
        }

        /* Send telemetry every x seconds */

        if (ps_info->mode == IsaPsMode_Enrollment) {
            if (interval < SEND_ENROLLDATA_INTERVAL_CNT) {
                interval++;
            }
            else {
                interval = 0;
                SendEnrollmentData(ps_info);
            }
        }

        usleep(EVP_PROCESS_EVENT_INTERVAL_US);
    }

ntpsync_abort:
network_abort:
errout:
    /* Clean up */

    // Stop Keep Alive of WDT

    ISA_INFO("Stop Keep Alive of WDT");

    EsfPwrMgrWdtTerminate();

    ReleaseEvpAgent(ps_info);

#if 0 /*T.B.D EsfClockManagerDeinit_often_causes_crash.*/
  /* Release ClockManager */

  EsfClockManagerDeinit();
#endif

    /* Delete RegisterToken and ProjectId
   * when there is no reset request via the button (when the endpoint is set). */

    if (!IsaBtnCheckRebootRequest()) {
        if (EsfSystemManagerSetProjectId("", 1) != kEsfSystemManagerResultOk) {
            ISA_ERR("EsfSystemManagerGetProjectId");
        }

        if (EsfSystemManagerSetRegisterToken("", 1) != kEsfSystemManagerResultOk) {
            ISA_ERR("EsfSystemManagerGetRegisterToken");
        }
    }

    EsfClockManagerStop();

    /* Perform a factory_reset or reboot or not*/

    IsaPsErrorCode ercd = kIsaPsSuccess;

    if (ps_info->mode == IsaPsMode_FactoryReset) {
        ISA_INFO("Run factory_reset");
        UnsetLedStatusForProvisioningService();
        IsaBtnExecuteFactoryResetCore();
        ercd = kIsaPsFactoryReset;
    }
    else if (ps_info->mode == IsaPsMode_Reboot) {
        ISA_INFO("PrepareReboot");

        EsfPwrMgrError ret_pm;

        ret_pm = EsfPwrMgrPrepareReboot();

        if (ret_pm != kEsfPwrMgrOk) {
            ISA_ERR("EsfPwrMgrPrepareReboot() ret %d", ret_pm);
        }

        ercd = kIsaPsReboot;
    }
    else {
        ISA_INFO("Not perform reboot in mode(%d)", ps_info->mode);
    }

    free(ps_info);

    return ercd;
}
