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
#include <string.h>
#if defined(__linux__)
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>
#endif
#include <mbedtls/sha256.h>

#if defined(__NuttX__)
#include <nuttx/config.h>
#endif

#include "evp/sdk_sys.h"
#include "json/include/json.h"
#include "base64/include/base64.h"
#include "firmware_manager.h"
#include "utility_msg.h"
#include "system_app_common.h"
#include "system_app_state.h"
#include "system_app_ud_main.h"
#include "system_app_led.h"
#include "system_app_log.h"
#include "system_app_util.h"
#include "system_app_deploy_private.h"
#include "system_app_deploy.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

// Define of result::code

#define RESULT_CODE_OK (0)
#define RESULT_CODE_INVALID_ARGUMENT (3)
#define RESULT_CODE_DEADLINE_EXCEEDED (4)
#define RESULT_CODE_PERMISSION_DENIED (7)
#define RESULT_CODE_RESOURCE_EXHAUSTED (8)
#define RESULT_CODE_FAILED_PRECONDITION (9)
#define RESULT_CODE_UNIMPLEMENTED (12)
#define RESULT_CODE_INTERNAL (13)
#define RESULT_CODE_UNAVAILABLE (14)

// String of result::detail

static const char *const s_p_result_desc_str_ok = "ok";
static const char *const s_p_result_desc_str_invalid_argument = "invalid_argument";
static const char *const s_p_result_desc_str_internal = "internal";
static const char *const s_p_result_desc_str_permission_denied = "permission_denied";
static const char *const s_p_result_desc_str_deadline_exceeded = "deadline_exceeded";
static const char *const s_p_result_desc_str_unavailable = "unavailable";

/* Stack size for deploy threads
 * We set it to 8k because the default 4k is not enough when using FirmwareManager */

#define DEPLOY_THREAD_STACKSIZE (8 * 1024)

// Max size that can be downloaded at one time

#define DEPLOY_SIZE_OF_DOWNLOAD_AT_ONE_TIME CONFIG_EXTERNAL_FIRMWARE_MANAGER_MAX_MEMORY_SIZE

// Max size of topic string

#define DEPLOY_TOPIC_STRING_SIZE (48)

// Deploy taget name

#define DEPLOY_TARGET_NAME_IMX500 "IMX500"
#define DEPLOY_TARGET_NAME_AI_ISP "AI-ISP"

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
#define DEPLOY_TARGET_NAME DEPLOY_TARGET_NAME_IMX500
#else // Use #else for build: CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
#define DEPLOY_TARGET_NAME DEPLOY_TARGET_NAME_AI_ISP
#endif

/* HTTP Error Response Code 403 Forbidden */

#define HTTP_STATUS_403_FORBIDDEN (403)

/****************************************************************************
 * Public Type Definitions
 ****************************************************************************/

// For chip name and component conversion

typedef struct {
    int deploy_id;                  /* [INP] Deploying to a topic */
    char *chip;                     /* [INP] Chip name */
    DeployComponent_e component;    /* [INP] Component */
    char *to_name;                  /* [OUT] Name to set in FwMgr */
    DeployComponent_e to_component; /* [OUT] Component to set in FwMgr */
} DeployChipToComponent_t;

/****************************************************************************
 * Private Data
 ****************************************************************************/

// string definition of deploy state

// The array `sc_str_deploy_state` maps each `DeployState_e` enum value to its corresponding string representation.
// For example, `DeployStateFailed` corresponds to "failed".
// Note: The `DeployStateFailedUnavailable` is also represented as "failed".
static const char *const sc_str_deploy_state[DeployStateNum] = {
    "request_received",               // DeployStateRequestReceived
    "downloading",                    // DeployStateDownloading
    "installing",                     // DeployStateInstalling
    "done",                           // DeployStateDone
    "failed",                         // DeployStateFailed
    "failed_invalid_argument",        // DeployStateFailedInvalidArgument
    "failed_token_expired",           // DeployStateFailedTokenExpired
    "failed_download_retry_exceeded", // DeployStateFailedDownloadRetryExceeded
    "failed",                         // DeployStateFailedUnavailable
};

// string definition of deploy topic

static const char *const sc_topics[DeployTopicNum] = {
    "PRIVATE_deploy_firmware",
    "PRIVATE_deploy_ai_model",
    "PRIVATE_deploy_sensor_calibration_param",
};

// string definition of sensor name

static const char *const sc_name_of_target_sensor[] = {"IMX500", "AI-ISP", NULL};

// string definition of processor name

static const char *const sc_name_of_target_processor[] = {"ESP32-S3", "ESP32", "ApFw", NULL};

// definition of convert chip to component

static DeployChipToComponent_t sc_chip_to_component[] = {
    {DeployTopicFirmware, "main_chip", DeployComponentLoader, "ApFw",
     DeployComponentProcessorLoader},

    {DeployTopicFirmware, "main_chip", DeployComponentFirmware, "ApFw",
     DeployComponentProcessorFirmware},

    {DeployTopicFirmware, "sensor_chip", DeployComponentLoader, DEPLOY_TARGET_NAME_IMX500,
     DeployComponentSensorLoader},

    {DeployTopicFirmware, "sensor_chip", DeployComponentFirmware, DEPLOY_TARGET_NAME_IMX500,
     DeployComponentSensorFirmware},

    {DeployTopicFirmware, "companion_chip", DeployComponentLoader, DEPLOY_TARGET_NAME_AI_ISP,
     DeployComponentSensorLoader},

    {DeployTopicFirmware, "companion_chip", DeployComponentFirmware, DEPLOY_TARGET_NAME_AI_ISP,
     DeployComponentSensorFirmware},

    {DeployTopicAiModel, "sensor_chip", DeployComponentAiModel, DEPLOY_TARGET_NAME_IMX500,
     DeployComponentAiModel},

    {DeployTopicAiModel, "companion_chip", DeployComponentAiModel, DEPLOY_TARGET_NAME_AI_ISP,
     DeployComponentAiModel},

    {0, NULL, 0, NULL, 0}, /* Terminate */
};

// string definition of camera setup name

static const char *const sc_name_of_target_camera_setup[] = {"ColorMatrix", "Gamma",  "LSCISP",
                                                             "PreWB",       "Dewarp", NULL};

// deploy handle

STATIC SysAppDeployHandle s_handle = NULL;

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/*--------------------------------------------------------------------------*/
STATIC void *InitSha256(void)
{
    mbedtls_sha256_context *p_ctx = malloc(sizeof(mbedtls_sha256_context));

    if (p_ctx == NULL) {
        return NULL;
    }

    mbedtls_sha256_init(p_ctx);

    mbedtls_sha256_starts(p_ctx, 0);

    return p_ctx;
}

/*--------------------------------------------------------------------------*/
STATIC int UpdateSha256(void *handle, size_t length, const uint8_t *p_input)
{
    mbedtls_sha256_context *p_ctx = (mbedtls_sha256_context *)handle;

    if (p_ctx == NULL || p_input == NULL) {
        return -1;
    }

    mbedtls_sha256_update(p_ctx, p_input, length);

    return 0;
}

/*--------------------------------------------------------------------------*/
STATIC int FinishSha256(void *handle, uint8_t *p_output)
{
    mbedtls_sha256_context *p_ctx = (mbedtls_sha256_context *)handle;
    int ret = -1;

    if (p_ctx == NULL) {
        goto errout;
    }

    if (p_output == NULL) {
        goto errout;
    }

    mbedtls_sha256_finish(p_ctx, p_output);

    ret = 0;

errout:
    if (p_ctx) {
        mbedtls_sha256_free(p_ctx);
        free(p_ctx);
    }

    return ret;
}

/*--------------------------------------------------------------------------*/
STATIC bool GetCancel(DeployInitParams_t *initp)
{
    /* Cancel deploy */

    bool is_cancel = false;

    /* Lock */

    if (pthread_mutex_lock(&initp->state_mutex) == 0) {
        is_cancel = initp->is_cancels[initp->deploy.topic_id];

        /* Unlock */

        pthread_mutex_unlock(&initp->state_mutex);
    }
    else {
        SYSAPP_ERR("pthread_mutex_lock");
    }

    return is_cancel;
}

/*--------------------------------------------------------------------------*/
STATIC void ClearCancelFlag(DeployInitParams_t *initp, int topic_id)
{
    /* Cancel deploy */

    /* Lock */

    if (pthread_mutex_lock(&initp->state_mutex) == 0) {
        initp->is_cancels[topic_id] = false;

        /* Unlock */

        pthread_mutex_unlock(&initp->state_mutex);
    }
    else {
        SYSAPP_ERR("pthread_mutex_lock");
    }
}

/*--------------------------------------------------------------------------*/
STATIC int SetTargetState(DeployTarget_t *p_target, int progress, DeployState_e state)
{
    /* Set progress and state for target */

    p_target->progress = progress;
    p_target->process_state = state;

    return progress;
}

/*--------------------------------------------------------------------------*/
STATIC int ExtractStringValue(EsfJsonHandle handle, EsfJsonValue parent_val, const char *jsonkey,
                              char *buf, uint32_t buflen, int32_t extraced_len)
{
    /* Extract string value */

    const char *string = NULL;

    int res = SysAppCmnExtractStringValue(handle, parent_val, jsonkey, &string);

    if (res <= 0) {
        return res;
    }

    if (string == NULL || string[0] == '\0') {
        return 0;
    }

    if (strnlen(string, buflen) >= buflen) {
        return 0;
    }

    ssize_t len = snprintf(buf, buflen, "%s", string);

    if (len > extraced_len) {
        buf[0] = '\0';
        return 0;
    }

    return 1;
}

/*--------------------------------------------------------------------------*/
STATIC void MakeJsonStateReqInfo(char *req_id, EsfJsonHandle handle, EsfJsonValue parent_val)
{
    EsfJsonValue val_req_info;
    EsfJsonErrorCode esfj_ret = kEsfJsonSuccess;
    RetCode ret = kRetOk;

    /* Set object for req_info */

    esfj_ret = EsfJsonObjectInit(handle, &val_req_info);
    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectInit ret %d", esfj_ret);
        return;
    }

    /* Set req_id */

    ret = SysAppCmnSetStringValue(handle, val_req_info, "req_id", req_id);
    if (ret != kRetOk) {
        SYSAPP_ERR("SysAppCmnSetStringValue ret %d", ret);
        return;
    }

    /* Set req_info on parent object */

    esfj_ret = EsfJsonObjectSet(handle, parent_val, "req_info", val_req_info);
    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectSet ret %d", esfj_ret);
        return;
    }
}

/*--------------------------------------------------------------------------*/
STATIC void SetResInfo(ResInfo_t *res_info, DeployState_e state)
{
    /* Rewrite contents of res_info depending on state */

    if (state == DeployStateDone) {
        res_info->code = RESULT_CODE_OK; /* OK */

        snprintf(res_info->detail_msg, sizeof(res_info->detail_msg), "%s", s_p_result_desc_str_ok);
    }
    else if (state == DeployStateFailed) {
        res_info->code = RESULT_CODE_INTERNAL; /* INTERNAL */

        snprintf(res_info->detail_msg, sizeof(res_info->detail_msg), "%s",
                 s_p_result_desc_str_internal);
    }
    else if (state == DeployStateFailedTokenExpired) {
        res_info->code = RESULT_CODE_PERMISSION_DENIED; /* PERMISSION_DENIED */

        snprintf(res_info->detail_msg, sizeof(res_info->detail_msg), "%s",
                 s_p_result_desc_str_permission_denied);
    }
    else if (state == DeployStateFailedDownloadRetryExceeded) {
        res_info->code = RESULT_CODE_DEADLINE_EXCEEDED; /* DEADLINE_EXCEEDED */

        snprintf(res_info->detail_msg, sizeof(res_info->detail_msg), "%s",
                 s_p_result_desc_str_deadline_exceeded);
    }
    else if (state == DeployStateFailedInvalidRequest) {
        res_info->code = RESULT_CODE_INVALID_ARGUMENT; /* INVALID_ARGUMENT */

        snprintf(res_info->detail_msg, sizeof(res_info->detail_msg), "%s",
                 s_p_result_desc_str_invalid_argument);
    }
    else if (state == DeployStateFailedUnavailable) {
        res_info->code = RESULT_CODE_UNAVAILABLE; /* UNAVAILABLE */

        snprintf(res_info->detail_msg, sizeof(res_info->detail_msg), "%s",
                 s_p_result_desc_str_unavailable);
    }
    else {
        /* We will do nothing for ineligible result_codes */
    }
}

/*--------------------------------------------------------------------------*/
STATIC DeployComponent_e ConvertComponentToState(DeployComponent_e component)
{
    /* Convert component value notified to FwMgr into  component value to be notified to state */

    switch (component) {
        case DeployComponentSensorLoader:
            component = DeployComponentLoader;
            break;
        case DeployComponentSensorFirmware:
            component = DeployComponentFirmware;
            break;
        case DeployComponentProcessorLoader:
            component = DeployComponentLoader;
            break;
        case DeployComponentProcessorFirmware:
            component = DeployComponentFirmware;
            break;
        case DeployComponentSensorCalibrationParam:
            component = DeployComponentNum;
            break;
        case DeployComponentAiModel:
            component = DeployComponentNum;
            break;
        default:
            component = DeployComponentNum;
            break;
    }

    return component;
}

/*--------------------------------------------------------------------------*/
STATIC void MakeJsonStateDeployTarget(DeployTarget_t *p_target, EsfJsonHandle handle,
                                      EsfJsonValue parent_val, ResInfo_t *p_res_info)
{
    /* Set component property */

    DeployComponent_e component = ConvertComponentToState(p_target->component);

    if (component < DeployComponentNum) {
        if (SysAppCmnSetNumberValue(handle, parent_val, "component", component) != kRetOk) {
            SYSAPP_ERR("component");
        }
    }

    /* Set chip property */

    if (p_target->chip[0] != '\0') {
        if (SysAppCmnSetStringValue(handle, parent_val, "chip", p_target->chip) != kRetOk) {
            SYSAPP_ERR("chip");
        }
    }

    /* Set package_url property */

    if (SysAppCmnSetStringValue(handle, parent_val, "package_url", p_target->package_url) !=
        kRetOk) {
        SYSAPP_ERR("package_url");
    }

    /* Set version property */

    if (SysAppCmnSetStringValue(handle, parent_val, "version", p_target->version) != kRetOk) {
        SYSAPP_ERR("version");
    }

    /* Set hash property */

    if (SysAppCmnSetStringValue(handle, parent_val, "hash", p_target->hash) != kRetOk) {
        SYSAPP_ERR("hash");
    }

    /* Set size property */

    if (SysAppCmnSetNumberValue(handle, parent_val, "size", p_target->size) != kRetOk) {
        SYSAPP_ERR("size");
    }

    /* Set progress property */

    if (SysAppCmnSetNumberValue(handle, parent_val, "progress", p_target->progress) != kRetOk) {
        SYSAPP_ERR("progress");
    }

    /* Set result parameter */

    SetResInfo(p_res_info, p_target->process_state);

    /* Set process_state property */

    if (SysAppCmnSetStringValue(handle, parent_val, "process_state",
                                sc_str_deploy_state[p_target->process_state]) != kRetOk) {
        SYSAPP_ERR("process_state %d", p_target->process_state);
    }
}

/*--------------------------------------------------------------------------*/
STATIC int ConvertChipToComponent(int deploy_id, DeployTarget_t *target)
{
    /* Convert chip name to components */

    int ret = -1;

    DeployChipToComponent_t *p_list = sc_chip_to_component;

    while (p_list->chip != NULL) {
        if ((strncmp(target->chip, p_list->chip, DEPLOY_STR_CHIP_LEN) == 0) &&
            (p_list->deploy_id == deploy_id) && (p_list->component == target->component)) {
            /* Set name and component to be set to ESF from  specified chip name and component */

            target->component = p_list->to_component;
            snprintf(target->name, sizeof(target->name), "%s", p_list->to_name);

            SYSAPP_INFO("Set Name:%s", target->name);
            SYSAPP_INFO("Set Comp:%d", target->component);
            ret = 0;
            break;
        }
        p_list++;
    }

    return ret;
}

/*--------------------------------------------------------------------------*/
STATIC int CmpTargetNameProperty(int deploy_id, DeployComponent_e component, const char *target)
{
    /* Target name validity check */

    static const char *const *p_list;

    if (deploy_id == DeployTopicCameraSetup) {
        p_list = sc_name_of_target_camera_setup;
    }
    else if (deploy_id == DeployTopicFirmware) {
        if (component == DeployComponentSensorLoader ||
            component == DeployComponentSensorFirmware) {
            p_list = sc_name_of_target_sensor;
        }
        else {
            p_list = sc_name_of_target_processor;
        }
    }
    else if (deploy_id == DeployTopicAiModel) {
        p_list = sc_name_of_target_sensor;
    }
    else {
        return -1;
    }

    int ret = -1;

    while (*p_list != NULL) {
        ret = strncmp(target, *p_list, DEPLOY_STR_NAME_BUF_LEN);

        if (ret == 0) {
            break;
        }

        p_list++;
    }

    return ret;
}

/*--------------------------------------------------------------------------*/
STATIC RetCode GetConfigurationDeployTargetProperty(DeployTarget_t *p_target, EsfJsonHandle handle,
                                                    EsfJsonValue parent_val, int deploy_id)
{
    /* Parse deploy configuration */

    RetCode ret = kRetOk;

    /* Parse deployment target property */

    EsfJsonValue val;
    int extret = -1;

    /* Initialize */

    SetTargetState(p_target, 0, DeployStateIdle);

    /* Get component property */

    p_target->component = 0;

    if (deploy_id != DeployTopicAiModel) {
        if (EsfJsonObjectGet(handle, parent_val, "component", &val) == kEsfJsonSuccess) {
            if (EsfJsonIntegerGet(handle, val, (int *)&p_target->component) != kEsfJsonSuccess) {
                /* Key is invalid. */

                SYSAPP_ERR("Invalid key component");
                p_target->parse_state = DeployStateFailedInvalidRequest;
            }
        }
        else {
            /* Key is required */

            SYSAPP_ERR("Not key component");
            p_target->parse_state = DeployStateFailedInvalidRequest;
        }
    }
    else {
        p_target->component = DeployComponentAiModel;
    }

    /* Get name property */

    extret = ExtractStringValue(handle, parent_val, "chip", p_target->chip, sizeof(p_target->chip),
                                DEPLOY_STR_CHIP_LEN);
    if (0 >= extret) {
        /* If chip property does not exist, an error is returned */

        SYSAPP_INFO("Not key chip");

        p_target->parse_state = DeployStateFailedInvalidRequest;
    }
    else {
        /* Check chip of target */

        if (ConvertChipToComponent(deploy_id, p_target)) {
            /* Invalid chip */

            SYSAPP_ERR("chip");
            p_target->parse_state = DeployStateFailedInvalidRequest;
        }
    }

    /* Get name property */

    extret = ExtractStringValue(handle, parent_val, "name", p_target->name, sizeof(p_target->name),
                                DEPLOY_STR_NAME_LEN);
    if (0 >= extret) {
        /* ignore */
    }
    else {
        /* Check name of target */

        if (CmpTargetNameProperty(deploy_id, p_target->component, p_target->name)) {
            /* Invalid name */

            SYSAPP_ERR("name: %s", p_target->name);
            p_target->parse_state = DeployStateFailedInvalidRequest;
        }
    }

    /* Get version property */

    p_target->version[0] = '\0';

    extret = ExtractStringValue(handle, parent_val, "version", p_target->version,
                                sizeof(p_target->version), DEPLOY_STR_VERSION_LEN);
    if (0 >= extret) {
        /* Key is required */

        SYSAPP_ERR("varsion");
        p_target->parse_state = DeployStateFailedInvalidRequest;
    }

    /* Get package_url property */

    extret = ExtractStringValue(handle, parent_val, "package_url", p_target->package_url,
                                sizeof(p_target->package_url), DEPLOY_STR_PACKAGE_URL_LEN);
    if (0 >= extret) {
        /* Key is required */

        SYSAPP_ERR("package_url");
        p_target->parse_state = DeployStateFailedInvalidRequest;
    }

    /* Get hash property */

    extret = ExtractStringValue(handle, parent_val, "hash", p_target->hash, sizeof(p_target->hash),
                                DEPLOY_STR_HASH_LEN);
    if (0 >= extret) {
        /* Key is required */

        SYSAPP_ERR("hash");
        p_target->parse_state = DeployStateFailedInvalidRequest;
    }

    /* Get size property */

    p_target->size = 0;

    if (EsfJsonObjectGet(handle, parent_val, "size", &val) == kEsfJsonSuccess) {
        EsfJsonIntegerGet(handle, val, (int *)&p_target->size);
    }

    if (p_target->size < 0) {
        /* If the value is invalid, clear it */

        p_target->size = 0;
    }

    return ret;
}

/*--------------------------------------------------------------------------*/
STATIC int GetResCodePriority(int res_code)
{
    /* res_code priority:
   * RESULT_CODE_UNIMPLEMENTED        hight 5
   * RESULT_CODE_INVALID_ARGUMENT           ^
   * RESULT_CODE_FAILED_PRECONDITION        |
   * RESULT_CODE_UNAVAILABLE                |
   * RESULT_CODE_RESOURCE_EXHAUSTED         |
   * RESULT_CODE_PERMISSION_DENIED          |
   * RESULT_CODE_DEADLINE_EXCEEDED          |
   * RESULT_CODE_INTERNAL                   v
   * RESULT_CODE_OK                     low 0
   */

    int priority = 0;

    switch (res_code) {
        case RESULT_CODE_UNIMPLEMENTED:
            priority = 8;
            break;
        case RESULT_CODE_INVALID_ARGUMENT:
            priority = 7;
            break;
        case RESULT_CODE_FAILED_PRECONDITION:
            priority = 6;
            break;
        case RESULT_CODE_UNAVAILABLE:
            priority = 5;
            break;
        case RESULT_CODE_RESOURCE_EXHAUSTED:
            priority = 4;
            break;
        case RESULT_CODE_PERMISSION_DENIED:
            priority = 3;
            break;
        case RESULT_CODE_DEADLINE_EXCEEDED:
            priority = 2;
            break;
        case RESULT_CODE_INTERNAL:
            priority = 1;
            break;
        case RESULT_CODE_OK:
            priority = 0;
            break;
        default:
            break;
    }

    return priority;
}

/*--------------------------------------------------------------------------*/
STATIC RetCode MakeJsonResInfoDeployConfiguration(EsfJsonHandle handle, EsfJsonValue root,
                                                  void *ctx)
{
    RetCode ret = kRetOk;
    ResInfo_t *res_info = (ResInfo_t *)ctx;

    ret = SysAppCmnMakeJsonResInfo(handle, root, res_info->res_id, res_info->code,
                                   res_info->detail_msg);
    return ret;
}

/*--------------------------------------------------------------------------*/
STATIC void MakeJsonStateDeployConfiguration(Deploy_t *p_deploy, EsfJsonHandle handle,
                                             EsfJsonValue parent_val)
{
    /* Make Json for state */

    /* Set req_info property */

    MakeJsonStateReqInfo(p_deploy->id, handle, parent_val);

    /* Set version property */

    if (p_deploy->topic_id == DeployTopicFirmware) {
        if (SysAppCmnSetStringValue(handle, parent_val, "version", p_deploy->version) != kRetOk) {
            SYSAPP_ERR("SysAppCmnSetStringValue : version");
        }
    }

    /* Initialize result parameters */

    ResInfo_t res_info;

    SetResInfo(&res_info, p_deploy->parse_state);

    snprintf(res_info.res_id, sizeof(res_info.res_id), "%s", p_deploy->id);

    /* Set targets property */

    EsfJsonValue ary;

    if (EsfJsonArrayInit(handle, &ary) == kEsfJsonSuccess) {
        /* Add deploy target to array */

        for (size_t index = 0; index < p_deploy->deploy_target_num; index++) {
            EsfJsonValue val;

            if (EsfJsonObjectInit(handle, &val) != kEsfJsonSuccess) {
                SYSAPP_ERR("JsonObjectInit");
                break;
            }

            DeployTarget_t *p_target = p_deploy->deploy_targets + index;

            MakeJsonStateDeployTarget(p_target, handle, val, &res_info);

            if (EsfJsonArrayAppend(handle, ary, val) != kEsfJsonSuccess) {
                SYSAPP_ERR("JsonArrayAppend");
                break;
            }
        }

        if (EsfJsonObjectSet(handle, parent_val, "targets", ary) != kEsfJsonSuccess) {
            SYSAPP_ERR("targets");
        }
    }

    /* Keep first error that occurred */

    if (GetResCodePriority(res_info.code) >= GetResCodePriority(p_deploy->res_info.code)) {
        p_deploy->res_info = res_info;
    }

    /* Make json res_info */

    SysAppCmnSetObjectValue(handle, parent_val, "res_info", MakeJsonResInfoDeployConfiguration,
                            &p_deploy->res_info);
}

/*--------------------------------------------------------------------------*/
STATIC bool GetConfigurationReqInfoProperty(char *req_id, size_t size, EsfJsonHandle handle,
                                            EsfJsonValue parent_val)
{
    /* Parse res_info */

    const char *p_req_id = NULL;

    switch (SysAppCmnGetReqId(handle, parent_val, &p_req_id)) {
        case kRetOk:
            break;
        case kRetNotFound:
            snprintf(req_id, size, "0");
            return true;
        default:
            snprintf(req_id, size, "0");
            return false;
    }

    if (strnlen(p_req_id, size) >= size) {
        SYSAPP_ERR("Max string length exceed");
        snprintf(req_id, size, "0");
        return false;
    }

    snprintf(req_id, size, "%s", p_req_id);

    return true;
}

/*--------------------------------------------------------------------------*/
STATIC void StartLED(void)
{
    /* Set no access LED during deploy */

    SysAppLedSetAppStatus(LedTypePower, LedAppStatusUnableToAcceptInput);

    /* Cancel lighting patterns with high priority */

    SysAppLedUnsetAppStatus(LedTypePower, LedAppStatusAbleToAcceptInput);
    SysAppLedUnsetAppStatus(LedTypePower, LedAppStatusErrorDownloadFailed);
    SysAppLedUnsetAppStatus(LedTypePower, LedAppStatusErrorUpdateMemoryAllocateFailed);
}

/*--------------------------------------------------------------------------*/
STATIC void SetLedForFatalError(void)
{
    /* Set LED for fatal error */

    SysAppLedSetAppStatus(LedTypePower, LedAppStatusErrorUpdateMemoryAllocateFailed);
}

/*--------------------------------------------------------------------------*/
STATIC void SetLedForUnavailable(void)
{
    /* Set LED to prompt you to redo the operation */

    SysAppLedSetAppStatus(LedTypePower, LedAppStatusErrorDownloadFailed);
}

/*--------------------------------------------------------------------------*/
STATIC void UnsetLedForUnavailable(void)
{
    /* Unset LED to prompt you to redo the operation */

    SysAppLedUnsetAppStatus(LedTypePower, LedAppStatusErrorDownloadFailed);
}

/*--------------------------------------------------------------------------*/
STATIC void StopLED(DeployInitParams_t *initp)
{
    /* Set LED according to deploy result */

    if (initp->deploy.res_info.code != RESULT_CODE_OK) {
        SysAppLedSetAppStatus(LedTypePower, LedAppStatusErrorDownloadFailed);
    }

    if (!initp->is_pre_reboot) {
        /* Unset lighting pattern */

        SysAppLedUnsetAppStatus(LedTypePower, LedAppStatusUnableToAcceptInput);
        SysAppLedSetAppStatus(LedTypePower, LedAppStatusAbleToAcceptInput);
    }
    else {
        /* Keep LED settings to contine flashing if reboot is required */
    }
}

/*--------------------------------------------------------------------------*/
void SetEvpStateReportOtaUpdateStatus(DeployInitParams_t *initp)
{
    /* Get handle to JSON module */

    EsfJsonHandle handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;

    if (EsfJsonOpen(&handle) != kEsfJsonSuccess) {
        SYSAPP_ERR("JsonOpen");
        goto errout;
    }

    /* Get parent value */

    if (EsfJsonObjectInit(handle, &val) != kEsfJsonSuccess) {
        SYSAPP_ERR("JsonObjectInit");
        goto errout;
    }

    /* Make json string. */

    MakeJsonStateDeployConfiguration(&initp->deploy, handle, val);

    /* Save the state string */

    const char *pstr = NULL;

    if (kEsfJsonSuccess != EsfJsonSerialize(handle, val, &pstr) || *pstr == '\0') {
        SYSAPP_ERR("JsonSerialize");
        goto errout;
    }

    /* Send state of json string */

    SYSAPP_DBG("state[%d] = %s", initp->deploy.topic_id, pstr);

    size_t max_len = DEPLOY_TARGET_MAX_NUM * sizeof(DeployTarget_t) + sizeof(Deploy_t);
    size_t len = strnlen(pstr, max_len) + 1;
    int id = initp->deploy.topic_id;
    int req_id;

    /* topic_id to state req_bit */

    if (id == DeployTopicFirmware) {
        req_id = ST_TOPIC_DEPLOY_FIRMWARE;
    }
    else if (id == DeployTopicAiModel) {
        req_id = ST_TOPIC_DEPLOY_AI_MODEL;
    }
    else if (id == DeployTopicCameraSetup) {
        req_id = ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM;
    }
    else {
        SYSAPP_ERR("Invalid id=%d", id);
        goto errout;
    }

    if (len > max_len) {
        SYSAPP_ERR("Serialized state string is too long");
        goto errout;
    }

    /* Lock */

    if (pthread_mutex_lock(&initp->state_mutex) != 0) {
        SYSAPP_ERR("pthread_mutex_lock");
        goto errout;
    }

    char *temp = realloc(initp->state_str[id], len);

    if (temp) {
        /* Save the state string */

        initp->state_str[id] = temp;
        initp->state_str_len[id] = snprintf(initp->state_str[id], len, "%s", pstr);
    }
    else {
        SYSAPP_ERR("realloc");

        /* Allocate failed */

        if (initp->state_str[id]) {
            free(initp->state_str[id]);
        }

        initp->state_str[id] = NULL;
        initp->state_str_len[id] = 0;
    }

    /* Unlock */

    pthread_mutex_unlock(&initp->state_mutex);

    if (initp->state_str[id]) {
        if (SysAppStateSendState(req_id) != kRetOk) {
            SYSAPP_ERR("SysAppStateSendState");
        }
    }

errout:
    /* Cleanup */

    if (handle != ESF_JSON_HANDLE_INITIALIZER) {
        EsfJsonSerializeFree(handle);
        EsfJsonClose(handle);
    }
}

/*--------------------------------------------------------------------------*/
STATIC RetCode GetConfigurationDeployConfigurationProperty(EsfJsonHandle handle,
                                                           EsfJsonValue parent_val,
                                                           Deploy_t *p_deploy, int topic_id)
{
    /* Parse deployment target property */

    RetCode ret = kRetFailed;
    int extret = 0;

    /* Initialize parameters */

    memset(p_deploy, 0, sizeof(Deploy_t));

    p_deploy->topic_id = topic_id;
    p_deploy->res_info.code = RESULT_CODE_OK;
    p_deploy->parse_state = DeployStateDone;

    /* Get req_info property */

    if (!GetConfigurationReqInfoProperty(p_deploy->id, sizeof(p_deploy->id), handle, parent_val)) {
        SYSAPP_ERR("req_info");
        p_deploy->parse_state = DeployStateFailedInvalidRequest;
    }

    /* Get version property */

    p_deploy->version[0] = '\0';

    if (p_deploy->topic_id == DeployTopicFirmware) {
        extret = ExtractStringValue(handle, parent_val, "version", p_deploy->version,
                                    sizeof(p_deploy->version), DEPLOY_STR_FIRMWARE_VERSION_LEN);
        if (extret == 0) {
            SYSAPP_ERR("version");
            p_deploy->parse_state = DeployStateFailedInvalidRequest;
        }
    }

    /* Get targets property */

    EsfJsonValue val;
    ssize_t cnt = 0;

    if (EsfJsonObjectGet(handle, parent_val, "targets", &val) == kEsfJsonSuccess) {
        EsfJsonValueType val_type;

        if (EsfJsonValueTypeGet(handle, val, &val_type) == kEsfJsonSuccess) {
            /* Check array */

            if (val_type == kEsfJsonValueTypeArray) {
                cnt = EsfJsonArrayCount(handle, val);

                /* Check maximum value of DeployTargt */

                if (cnt < 0) {
                    SYSAPP_ERR("Number of array is invalid!");
                    p_deploy->parse_state = DeployStateFailedInvalidRequest;
                }
                else if (cnt > DEPLOY_TARGET_MAX_NUM) {
                    cnt = DEPLOY_TARGET_MAX_NUM;
                }
            }
            else {
                SYSAPP_ERR("targets is not array!");
                p_deploy->parse_state = DeployStateFailedInvalidRequest;
            }
        }
        else {
            SYSAPP_ERR("EsfJsonValueTypeGet");
            p_deploy->parse_state = DeployStateFailedInvalidRequest;
        }
    }
    else {
        /* There is no targets property */

        SYSAPP_INFO("Not targets!");
        p_deploy->parse_state = DeployStateFailedInvalidRequest;
    }

    /* Initialize deploy information */

    p_deploy->deploy_target_num = 0;
    p_deploy->deploy_target_cnt = 0;
    p_deploy->deploy_targets = NULL;

    /* Allocate memory for deploy targets */

    if (cnt > 0) {
        DeployTarget_t *target;

        target = (DeployTarget_t *)malloc(sizeof(DeployTarget_t) * cnt);

        if (target) {
            memset(target, 0, sizeof(DeployTarget_t) * cnt);

            p_deploy->deploy_targets = target;

            p_deploy->deploy_target_num = (uint8_t)cnt;

            /* Get deploy target property */

            for (ssize_t index = 0; index < cnt; index++) {
                EsfJsonValue subval;

                if (EsfJsonArrayGet(handle, val, index, &subval) != kEsfJsonSuccess) {
                    SYSAPP_ERR("get deploy target!");
                    p_deploy->parse_state = DeployStateFailed;
                    break;
                }

                GetConfigurationDeployTargetProperty(target + index, handle, subval, topic_id);
            }
        }
        else {
            SYSAPP_ERR("Allocate memory");
            p_deploy->parse_state = DeployStateFailed;
            SetLedForFatalError(); /* Set LED to prompt reset */
        }
    }

    if (p_deploy->parse_state == DeployStateDone) {
        /* Set parameter for next DelpoyTarget */

        ret = kRetOk;
    }
    else {
        /* Invalid request! */

        SYSAPP_ERR("Invalid deploy properties!");
    }

    return ret;
}

/*--------------------------------------------------------------------------*/
STATIC EsfFwMgrHandle FirmwareUpdateOpen(DeployInitParams_t *initp, DeployTarget_t *target,
                                         size_t size, EsfFwMgrPrepareWriteResponse *p_res)
{
    /* Open firmware update */

    EsfFwMgrOpenRequest req;

    memset(&req, 0, sizeof(req));

    /* Set update parameters */

    req.target = (EsfFwMgrTarget)target->component;

    snprintf(req.name, sizeof(req.name), "%.*s", (int)sizeof(req.name) - 1, target->name);

    snprintf(req.version, sizeof(req.version), "%.*s", (int)sizeof(req.version) - 1,
             target->version);

    /* Decode base64 string */

    if (target->hash[0] != '\0') {
        uint8_t hash[sizeof(req.hash) + 1];
        size_t out_size = sizeof(hash);

        if (kEsfCodecBase64ResultSuccess !=
            EsfCodecBase64Decode(target->hash, DEPLOY_STR_HASH_LEN, hash, &out_size)) {
            SYSAPP_ERR("CodecBase64Decode");
            return NULL;
        }

        memcpy(req.hash, hash, sizeof(req.hash));
    }

    /* Get update parameters */

    EsfFwMgrResult status;
    EsfFwMgrHandle handle = NULL;
    EsfFwMgrOpenResponse res;
    EsfFwMgrPrepareWriteRequest pre_req;

    pre_req.total_size = size;
    pre_req.memory_size = DEPLOY_SIZE_OF_DOWNLOAD_AT_ONE_TIME;

    SYSAPP_INFO("target =%d", req.target);
    SYSAPP_INFO("name   =%s", req.name);
    SYSAPP_INFO("version=%s", req.version);
    SYSAPP_INFO("hash=%02X %02X...%02X", req.hash[0], req.hash[1], req.hash[31]);
    SYSAPP_INFO("total_size =%d", pre_req.total_size);
    SYSAPP_INFO("memory_size=%d", pre_req.memory_size);

    int retry_cnt;

    /* Save previous state */

    ResInfo_t res_info_bk = initp->deploy.res_info;

    DeployState_e e_state = target->process_state;

    for (retry_cnt = 0; retry_cnt < MAX_NUMBER_OF_UPDATE_OPEN_RETRY; retry_cnt++) {
        if (SysAppUdIsThisRequestToStopForDownload()) {
            SYSAPP_INFO("Stop the download by a request.");
            break;
        }

        SYSAPP_INFO("EsfFwMgrOpen(%d)...", retry_cnt);

        status = EsfFwMgrOpen(&req, &pre_req, &res);

        if (status == kEsfFwMgrResultUnavailable) {
            /* Sensor close */

            SysAppStaClose();

            /* Sleeps for 1 second before next open */

            SYSAPP_INFO("Waiting for streaming to stop...");

            if (retry_cnt == 1) {
                /* Execute SysAppStaClose to request the sensor to stop,
         * and update the state if an error occurs in the next FwMgrOpen */

                SetTargetState(target, 0, DeployStateFailedUnavailable);

                SetEvpStateReportOtaUpdateStatus(initp);

                /* Set open Waiting LED */

                SetLedForUnavailable();
            }

            sleep(1);

            continue;
        }

        if (status == kEsfFwMgrResultOk) {
            handle = res.handle;

            if (p_res) {
                *p_res = res.prepare_write;
            }

            SYSAPP_INFO("EsfFwMgrOpen OK");
            SYSAPP_INFO("memory:%d", res.prepare_write.memory_size);
            SYSAPP_INFO("writab:%d", res.prepare_write.writable_size);

            break;
        }

        /* Open error */

        SYSAPP_ELOG_ERR(SYSAPP_EVT_OTA_FAILED);

        SYSAPP_ERR("EsfFwMgrOpen=%d", status);

        break;
    }

    /* Updates the progress state */

    if (e_state != target->process_state) {
        initp->deploy.res_info = res_info_bk;

        if (retry_cnt < MAX_NUMBER_OF_UPDATE_OPEN_RETRY) {
            SetTargetState(target, 0, e_state);
        }
        else {
            SetTargetState(target, 0, DeployStateFailedUnavailable);
        }

        SetEvpStateReportOtaUpdateStatus(initp);

        /* If open is successful, clear LED indicating that open is complete */

        UnsetLedForUnavailable();
    }

    return handle;
}

/*--------------------------------------------------------------------------*/
static void PrintHash(char *name, uint8_t *h)
{
    SYSAPP_INFO(
        "%s:"
        "%02X%02X%02X%02X%02X%02X%02X%02X"
        "%02X%02X%02X%02X%02X%02X%02X%02X"
        "%02X%02X%02X%02X%02X%02X%02X%02X"
        "%02X%02X%02X%02X%02X%02X%02X%02X",
        name, h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12],
        h[13], h[14], h[15], h[16], h[17], h[18], h[19], h[20], h[21], h[22], h[23], h[24], h[25],
        h[26], h[27], h[28], h[29], h[30], h[31]);
}

/*--------------------------------------------------------------------------*/
static bool IsSameHash(void *hash1, void *hash2)
{
    /* Compares hash1 and hash2 and returns true if same. Size is fixed at 32 bytes */

    return (memcmp(hash1, hash2, ESF_FIRMWARE_MANAGER_TARGET_HASH_SIZE) == 0);
}

/*--------------------------------------------------------------------------*/
STATIC int CompareDeployingVersionWithDeployedOneTarget(DeployTarget_t *p_target,
                                                        DeployState_e *state)
{
    /* Compare version of deployed with version of one target to be deployed */

    SYSAPP_INFO("Check version:comp=%d", p_target->component);

    *state = DeployStateFailed;

    EsfFwMgrGetInfoResponse response;
    EsfFwMgrGetInfoData info;

    memset(&response, 0, sizeof(response));
    memset(&info, 0, sizeof(info));

    info.target = (EsfFwMgrTarget)p_target->component;
    info.in_length = 1;
    info.response = &response;
    info.out_length = 0;

    snprintf(info.name, sizeof(info.name), "%.*s", (int)sizeof(info.name) - 1, p_target->name);

    /* Get firmware info */

    SYSAPP_INFO("target   :%d", info.target);
    SYSAPP_INFO("in_length:%d", info.in_length);
    SYSAPP_INFO("name     :%s", info.name);

    EsfFwMgrResult res = EsfFwMgrGetInfo(&info);

    if (res != kEsfFwMgrResultOk) {
        SYSAPP_ELOG_ERR(SYSAPP_EVT_OTA_FAILED);
        SYSAPP_ERR("EsfFwMgrGetInfo=%d", res);
        return -1;
    }

    /* Check version */

    SYSAPP_INFO("ou_length:%d", info.out_length);
    SYSAPP_INFO("version  :%s", response.version);
    SYSAPP_INFO("lasupdate:%s", response.last_update);

    /* Decode base64 */

    uint8_t hash[DEPLOY_STR_HASH_LEN + 1];
    size_t out_size = sizeof(hash);

    if (kEsfCodecBase64ResultSuccess !=
        EsfCodecBase64Decode(p_target->hash, DEPLOY_STR_HASH_LEN, hash, &out_size)) {
        SYSAPP_ERR("CodecBase64Decode");
        *state = DeployStateFailedInvalidRequest;
        return -1;
    }

    /* Compare hash value that has already been OTA with hash value that will be OTA,
   * and if different, OTA. */

    PrintHash("DeployedHash", (uint8_t *)response.hash);
    PrintHash("TargetedHash", hash);

    return !IsSameHash(response.hash, hash);
}

/*--------------------------------------------------------------------------*/
STATIC int CompareDeployingVersionWithDeployedAiModel(DeployTarget_t *p_target,
                                                      DeployState_e *state)
{
    /* Compare version of AI model deployed with version to be deployed */

    SYSAPP_INFO("Check ai-model version");

    *state = DeployStateFailed;

    /* Allocate ai model version */

    EsfFwMgrGetInfoResponse *response;

    response = malloc(sizeof(EsfFwMgrGetInfoResponse) * ESF_FIRMWARE_MANAGER_AI_MODEL_SLOT_NUM);

    if (response == NULL) {
        SYSAPP_ERR("malloc");
        SetLedForFatalError(); /* Set LED to prompt reset */
        return -1;
    }

    /* Set target for AI model */

    EsfFwMgrGetInfoData info;
    int res = 1;

    memset(&info, 0, sizeof(info));

    info.target = kEsfFwMgrTargetAIModel;
    info.in_length = ESF_FIRMWARE_MANAGER_AI_MODEL_SLOT_NUM;
    info.response = response;
    info.out_length = 0;

    snprintf(info.name, sizeof(info.name), "%.*s", (int)sizeof(info.name) - 1, p_target->name);

    SYSAPP_INFO("target   :%d", info.target);
    SYSAPP_INFO("in_length:%d", info.in_length);
    SYSAPP_INFO("name     :%s", info.name);

    /* Get firmware info */

    EsfFwMgrResult fwres;

    if ((fwres = EsfFwMgrGetInfo(&info)) != kEsfFwMgrResultOk) {
        SYSAPP_ELOG_ERR(SYSAPP_EVT_OTA_FAILED);
        SYSAPP_ERR("EsfFwMgrGetInfo:%d", fwres);
        res = -1;
        goto errout;
    }

    SYSAPP_INFO("ou_length: %d", info.out_length);

    for (int i = 0; i < info.out_length; i++) {
        SYSAPP_INFO("(%d/%d)version:   %s", i + 1, info.out_length, response[i].version);
        SYSAPP_INFO("(%d/%d)lasupdate: %s", i + 1, info.out_length, response[i].last_update);
        PrintHash("DeployedHash", (uint8_t *)response[i].hash);
    }

    /* Decode base64 */

    uint8_t hash[ESF_FIRMWARE_MANAGER_TARGET_HASH_SIZE + 1];
    size_t out_size = sizeof(hash);

    if (kEsfCodecBase64ResultSuccess !=
        EsfCodecBase64Decode(p_target->hash, DEPLOY_STR_HASH_LEN, hash, &out_size)) {
        SYSAPP_ERR("CodecBase64Decode");
        *state = DeployStateFailedInvalidRequest;
        res = -1;
        goto errout;
    }

    PrintHash("TargetedHash", hash);

    /* Perform a version check.
   * Search all slots for an AI model matching the specified version.
   * If a matching version is found, set res=0 and return (no OTA will be performed).
   * If no matching version is found, set res=1 and perform the OTA */

    for (int slot = 0; slot < info.out_length; slot++) {
#if 0 // Use version to judge whether to do OTA for AI Module Bundle
    if (!IsSameHash(hash, response[slot].hash)) {
      continue;
    }
#else
        if (strncmp(response[slot].version, p_target->version, sizeof(response[slot].version))) {
            continue;
        }
#endif

        /* Already loaded */

        res = 0;
        break;
    }

    /* Search to see if there are any available slots.
   * If no slots are available, set an error and return */

    if (res) {
        int slot;

        /* Check all slots to see if they are available.
     * If version is an empty string, the slot is available */

        for (slot = 0; slot < info.out_length; res++, slot++) {
            if (response[slot].version[0] == '\0') {
                break;
            }
        }

        /* Check all slots and if there are no free slots, an error occurs */

        if (slot == info.out_length) {
            SYSAPP_WARN("No free slot");
            res = -1;
        }
    }

errout:
    /* Clean up */

    free(response);

    return res;
}

/*--------------------------------------------------------------------------*/
STATIC int CheckVersion(DeployTarget_t *p_target, DeployState_e *state)
{
    /* Version check */

    int res = -1;

    *state = DeployStateFailed;

    switch (p_target->component) {
        case DeployComponentSensorLoader:
        case DeployComponentSensorFirmware:
        case DeployComponentProcessorLoader:
        case DeployComponentProcessorFirmware:
        case DeployComponentSensorCalibrationParam:
            /* Check version for one target */

            res = CompareDeployingVersionWithDeployedOneTarget(p_target, state);
            break;

        case DeployComponentAiModel:
            /* Check AI model version */

            res = CompareDeployingVersionWithDeployedAiModel(p_target, state);
            break;

        default:
            SYSAPP_ERR("Invalid component");
            break;
    }

    return res;
}

/*--------------------------------------------------------------------------*/
STATIC int DownloadCallback(uint8_t *data, size_t dl_size, void *p_usr_data)
{
    /* Update */

    DeployFwWrite_t *ctx = (DeployFwWrite_t *)p_usr_data;

    EsfFwMgrCopyToInternalBufferRequest ireq;

    ireq.offset = ctx->offset;
    ireq.size = dl_size;
    ireq.data = data;

    EsfFwMgrCopyToInternalBuffer(ctx->fwmgr_handle, &ireq);

    /* Calculating the hash value */

    UpdateSha256(ctx->sha256_handle, dl_size, data);

    ctx->offset += dl_size;

    /* Download abort request check */

    if (SysAppUdIsThisRequestToStopForDownload()) {
        return -1;
    }

    return 0;
}

/*--------------------------------------------------------------------------*/
STATIC RetCode WaitingForRetry(int retry_count)
{
    /* If the connection fails, it will retry after 1000 ms.
   * Then it will retry after (1000 << 1) ms = 2 seconds
   * Then it will retry after (1000 << 2) ms = 4 seconds
   * Then it will retry after (1000 << 3) ms = 8 seconds
   * And so on,
   * double the retry interval as long as download failures continue,
   * eventually reaching (1000 << 8) ms = 256 seconds. */

    int wait_interval = (1 << retry_count);
    int i;

    if (wait_interval > MAX_NUMBER_OF_UPDATE_RETRY_INTERVAL_TIME_SEC) {
        wait_interval = MAX_NUMBER_OF_UPDATE_RETRY_INTERVAL_TIME_SEC;
    }

    SYSAPP_WARN("Wait for %d second(s)", wait_interval);

    for (i = 0; i < wait_interval; i++) {
        if (SysAppUdIsThisRequestToStopForDownload()) {
            SYSAPP_INFO("!!!A request was made to stop the download!!!");
            break;
        }

        sleep(1);
    }

    if (i != wait_interval) {
        SYSAPP_WARN("The retry wait interrupted");
        return kRetAbort;
    }

    return kRetOk;
}

/*--------------------------------------------------------------------------*/
STATIC RetCode FirmwareUpdate(DeployInitParams_t *initp, DeployTarget_t *p_target)
{
    /* Update */

    RetCode ret = kRetFailed;

    EsfFwMgrHandle handle = ESF_FIRMWARE_MANAGER_HANDLE_INVALID;
    EsfFwMgrResult result;

    DeployState_e e_state = DeployStateFailed;

    /* Start updating state */

    int progress = SetTargetState(p_target, 0, DeployStateIdle);

    SetEvpStateReportOtaUpdateStatus(initp);

    SYSAPP_INFO("Start get image size");

    /* Get data size of download image */

    size_t image_size = 0;
    int http_status = 0;

    /* Workaround for case where the size property of
   * configuration is not available (previous version) */

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
    if (p_target->component == DeployComponentProcessorLoader ||
        p_target->component == DeployComponentProcessorFirmware) {
#endif
        /* For ApFw and ApLoader,
     * get the size of the data to download (from FwMgr) */

        if (p_target->size > 0) {
            /* Use size property when available */

            image_size = p_target->size;
        }
        else {
            /* Download and get file size */

            image_size = SysAppUdGetImageSize(p_target->package_url, &http_status);

            if (image_size == 0) {
                if (http_status == HTTP_STATUS_403_FORBIDDEN) {
                    e_state = DeployStateFailedTokenExpired;
                }
                else if (http_status < 0) {
                    /* If download not start, http_status is set to -1. Stop  download without retry. */

                    e_state = DeployStateFailedInvalidRequest;
                }
                else {
                    e_state = DeployStateFailedDownloadRetryExceeded;
                }

                SYSAPP_ERR("SysAppUdGetImageSize(%d)", http_status);
                goto errout;
            }
        }
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
    }
    else {
        /* For SensorFw, SensorLoader, and AI-Model,
     * it is not necessary to specify the size (from FwMgr) */
    }
#endif

    /* Start updating device */

    EsfFwMgrPrepareWriteResponse res_prepare;

    handle = FirmwareUpdateOpen(initp, p_target, image_size, &res_prepare);

    if (handle == NULL) {
        goto errout;
    }

    if (res_prepare.memory_size == 0) {
        SYSAPP_ERR("Update memory");
        goto errout;
    }

    /* Start download image */

    progress = SetTargetState(p_target, 25, DeployStateDownloading);

    SetEvpStateReportOtaUpdateStatus(initp);

    SYSAPP_INFO("Start get image data");

    /* Get data of download image */

    DeployFwWrite_t write;

    write.sha256_handle = InitSha256();
    write.fwmgr_handle = handle;
    write.offset = 0;
    write.memory_size = res_prepare.memory_size;

    size_t offset = 0; /* Download start position */
    int retry = 0;     /* Number of retries when download fails */

    mbedtls_sha256_context ctx = {0}; /* sha256_context backup */

    for (;;) {
        /* The hash data may be discarded due to retries, so make a backup now. */

        if (write.sha256_handle) {
            ctx = *(mbedtls_sha256_context *)write.sha256_handle;
        }

        write.offset = 0;

        ssize_t bsize = SysAppUdGetImageData(p_target->package_url,
                                             offset,            /* Download start position*/
                                             write.memory_size, /* Download size */
                                             DownloadCallback, &write, &http_status);
        if (bsize == 0) {
            /* Download complete */

            /* There may be garbage at the end, so discard it and calculate the hash. */

            if (write.sha256_handle) {
                *(mbedtls_sha256_context *)write.sha256_handle = ctx;
            }

            /* Calculating the hash value */

            if (FinishSha256(write.sha256_handle, write.hash) == 0) {
                char b64output[DEPLOY_STR_HASH_LEN + 1];
                size_t outsize = sizeof(b64output);

                memset(b64output, 0, sizeof(b64output));

                EsfCodecBase64Encode(write.hash, sizeof(write.hash), b64output, &outsize);

                SYSAPP_INFO("Hash(B64) %s", b64output);

                if (strncmp(b64output, p_target->hash, DEPLOY_STR_HASH_LEN) != 0) {
                    SYSAPP_ERR("Hash");
                    e_state = DeployStateFailedInvalidRequest;
                    goto errout;
                }
            }

            SYSAPP_INFO("DL: total_size %zu END", offset);

            /* Post process */

            SYSAPP_INFO("Post-processing");

            /* Update status */

            progress = SetTargetState(p_target, 75, DeployStateInstalling);

            SetEvpStateReportOtaUpdateStatus(initp);

            if ((result = EsfFwMgrPostProcess(handle)) != kEsfFwMgrResultOk) {
                SYSAPP_ELOG_ERR(SYSAPP_EVT_OTA_FAILED);
                SYSAPP_ERR("EsfFwMgrPostProcess:%d", result);
                goto errout;
            }

            /* Update successful */

            ret = kRetOk;

            break;
        }
        else if (bsize < 0) {
            /* Download error, will retry */

            if (http_status == HTTP_STATUS_403_FORBIDDEN) {
                e_state = DeployStateFailedTokenExpired;
                SYSAPP_ERR("Forbidden");
                break;
            }

            /* If download not start, http_status is set to -1. Stop  download without retry. */

            if (http_status < 0) {
                e_state = DeployStateFailedInvalidRequest;
                SYSAPP_ERR("URL is not http:// or https://");
                break;
            }

            if ((retry >= MAX_NUMBER_OF_UPDATE_RETRY) ||
                (SysAppUdIsThisRequestToStopForDownload())) {
                /* If the retry limit is reached, the program will terminate with an error. */

                SYSAPP_ELOG_ERR(SYSAPP_EVT_FAILED_TO_DOWNLOAD_FILE);

                SYSAPP_ERR("SysAppUdGetImage");
                FinishSha256(write.sha256_handle, write.hash);

                e_state = DeployStateFailedDownloadRetryExceeded;
                break;
            }

            /* Restore data and retry the download.
       * so we will discard the data we have updated so far for the hash. */

            if (write.sha256_handle) {
                *(mbedtls_sha256_context *)write.sha256_handle = ctx;
            }

            SYSAPP_WARN("FirmwareUpdate retry(%d/%d)", retry + 1, MAX_NUMBER_OF_UPDATE_RETRY);

            /* Waiting for retry */

            if (WaitingForRetry(retry++) == kRetAbort) {
                break;
            }
        }
        else {
            /* One block downloaded */

            retry = 0; /* Clear the retry count */

            offset += bsize;

            SYSAPP_INFO("DL: total_size %zu, len %zu", offset, bsize);

            /* Firmware data write */

            EsfFwMgrWriteRequest req;

            req.offset = 0;
            req.size = write.offset;

            if (EsfFwMgrWrite(handle, &req) != kEsfFwMgrResultOk) {
                SYSAPP_ELOG_ERR(SYSAPP_EVT_OTA_FAILED);
                SYSAPP_ERR("EsfFwMgrWrite");
                break;
            }

            /* Update status */

            progress = SetTargetState(p_target, 50, DeployStateDownloading);

            SetEvpStateReportOtaUpdateStatus(initp);
        }
    }

    /* Get arch version */

    EsfFwMgrBinaryHeaderInfo arch = {.sw_arch_version = kEsfFwMgrSwArchVersionUnknown};

    if ((result = EsfFwMgrGetBinaryHeaderInfo(handle, &arch)) == kEsfFwMgrResultOk) {
        SYSAPP_INFO("EsfFwMgrGetBinaryHeaderInfo:arch=%d", arch.sw_arch_version);
        initp->arch_version = arch.sw_arch_version;
    }
    else {
        SYSAPP_WARN("EsfFwMgrGetBinaryHeaderInfo:%d", result);
        initp->arch_version = kEsfFwMgrSwArchVersionUnknown;
    }

errout:
    /* Cleanup */

    if (handle != ESF_FIRMWARE_MANAGER_HANDLE_INVALID) {
        if ((result = EsfFwMgrClose(handle)) == kEsfFwMgrResultOk) {
            SYSAPP_INFO("EsfFwMgrClose");
        }
        else {
            SYSAPP_ELOG_ERR(SYSAPP_EVT_OTA_FAILED);
            SYSAPP_ERR("EsfFwMgrClose:%d", result);
            ret = kRetFailed;
        }
    }

    /* Set upload result */

    if (ret == kRetOk) {
        SYSAPP_INFO("Update successful");

        if (p_target->component == DeployComponentProcessorLoader ||
            p_target->component == DeployComponentProcessorFirmware) {
            /* Force reboot */

            SYSAPP_INFO("Force reboot");
            initp->is_pre_reboot = true;
        }

        SetTargetState(p_target, 100, DeployStateDone);
    }
    else {
        SYSAPP_INFO("Update %s", sc_str_deploy_state[e_state]);

        SetTargetState(p_target, progress, e_state);
    }

    return ret;
}

/*--------------------------------------------------------------------------*/
RetCode ParseConfiguration(Deploy_t *p_deploy, int topic_id, const char *param)
{
    /* Deploy process will start */

    SYSAPP_INFO("Parse configuration");

    RetCode ret = kRetFailed;
    EsfJsonHandle handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;

    /* Get handle to JSON module */

    if (EsfJsonOpen(&handle) != kEsfJsonSuccess) {
        SYSAPP_ERR("JsonOpen");
        goto errout;
    }

    /* Convert string to JSON Value */

    if (EsfJsonDeserialize(handle, param, &val) != kEsfJsonSuccess) {
        SYSAPP_ERR("JsonDeserialize");
        goto errout;
    }

    /* Parse deploy configuration */

    ret = GetConfigurationDeployConfigurationProperty(handle, val, p_deploy, topic_id);

    SYSAPP_INFO("===TOP(topic:%d)", p_deploy->topic_id);
    SYSAPP_INFO("id  :%s", p_deploy->id);
    SYSAPP_INFO("ver :%s", p_deploy->version);
    SYSAPP_INFO("targ:%d/%d", p_deploy->deploy_target_cnt, p_deploy->deploy_target_num);
    SYSAPP_INFO("stat:%d", p_deploy->parse_state);

errout:
    /* Close handle */

    if (handle != ESF_JSON_HANDLE_INITIALIZER) {
        EsfJsonClose(handle);
    }

    return ret;
}

/*--------------------------------------------------------------------------*/
STATIC RetCode DeleteAiModel(DeployInitParams_t *initp, Deploy_t *p_deploy)
{
    /* Delete ai model */

    RetCode ret = kRetOk;

    if (p_deploy->topic_id != DeployTopicAiModel) {
        return ret;
    }

    SYSAPP_INFO("Delete AI models Start");

    EsfFwMgrGetInfoResponse *response;
    EsfFwMgrOpenRequest *req;

    response = malloc(sizeof(EsfFwMgrGetInfoResponse) * ESF_FIRMWARE_MANAGER_AI_MODEL_SLOT_NUM +
                      sizeof(EsfFwMgrOpenRequest));
    req = (EsfFwMgrOpenRequest *)(response + ESF_FIRMWARE_MANAGER_AI_MODEL_SLOT_NUM);

    if (response == NULL) {
        SYSAPP_ERR("malloc");
        p_deploy->parse_state = DeployStateFailed;
        SetEvpStateReportOtaUpdateStatus(initp);
        SetLedForFatalError(); /* Set LED to prompt reset */
        return kRetMemoryError;
    }

    /* Set target for AI model */

    EsfFwMgrGetInfoData info;

    memset(&info, 0, sizeof(info));

    info.target = kEsfFwMgrTargetAIModel;
    info.in_length = ESF_FIRMWARE_MANAGER_AI_MODEL_SLOT_NUM;
    info.response = response;
    info.out_length = 0;
    snprintf(info.name, ESF_FIRMWARE_MANAGER_TARGET_NAME_SIZE, DEPLOY_TARGET_NAME);

    /* Get firmware info */

    SYSAPP_INFO("target   :%d", info.target);
    SYSAPP_INFO("in_length:%d", info.in_length);
    SYSAPP_INFO("name     :%s", info.name);

    EsfFwMgrResult res = EsfFwMgrGetInfo(&info);

    if (res != kEsfFwMgrResultOk) {
        SYSAPP_ELOG_ERR(SYSAPP_EVT_OTA_FAILED);
        SYSAPP_ERR("EsfFwMgrGetInfo=%d", res);
        p_deploy->parse_state = DeployStateFailed;
        goto errout;
    }

    DeployTarget_t *p_target = p_deploy->deploy_targets;

    for (int slot = 0; slot < info.out_length; slot++) {
        if (response[slot].version[0] == '\0') {
            /* Due to the specifications of FirmwareManager,
       * if there is no version, there is no AI model. */

            continue;
        }

        char b64output[DEPLOY_STR_HASH_LEN + 1];
        size_t outsize = sizeof(b64output);

        memset(b64output, 0, sizeof(b64output));

        if (kEsfCodecBase64ResultSuccess != EsfCodecBase64Encode((uint8_t *)response[slot].hash,
                                                                 sizeof(response[slot].hash),
                                                                 b64output, &outsize)) {
            SYSAPP_ERR("EsfCodecBase64Encode");
            continue;
        }

        SYSAPP_INFO("TargetedHash :%s", b64output);

        int idx;

        for (idx = 0; idx < p_deploy->deploy_target_num; idx++) {
            SYSAPP_INFO("DeployedHash%d:%s", idx + 1, p_target[idx].hash);

#if 0 // Use version to judge whether to do OTA for AI Module Bundle
      if (strncmp(b64output, p_target[idx].hash, DEPLOY_STR_HASH_LEN) == 0) {
        break;
      }
#else
            if (strncmp(response[slot].version, p_target[idx].version,
                        sizeof(response[slot].version)) == 0) {
                break;
            }
#endif
        }

        /* If there is no version to update to for loaded version,
     * the AI model of that loaded version delete. */

        if (idx < p_deploy->deploy_target_num) {
            continue;
        }

        /* Set open request info of delete AI model */

        EsfFwMgrOpenResponse o_res;

        memset(req, 0, sizeof(EsfFwMgrOpenRequest));
        memset(&o_res, 0, sizeof(o_res));

        req->target = kEsfFwMgrTargetAIModel;

        snprintf(req->name, sizeof(req->name), "%s", info.name);
        snprintf(req->version, sizeof(req->version), "%s", response[slot].version);
        memcpy(req->hash, response[slot].hash, sizeof(req->hash));

        SYSAPP_INFO("Delete AI model hash[%d]:%s", slot, b64output);

        int retry_cnt = 0;

        /* Save previous state */

        ResInfo_t res_info_bk = p_deploy->res_info;

        DeployState_e e_state = p_deploy->parse_state;

        for (retry_cnt = 0; retry_cnt < MAX_NUMBER_OF_UPDATE_OPEN_RETRY; retry_cnt++) {
            if (SysAppUdIsThisRequestToStopForDownload()) {
                SYSAPP_INFO("Stop the download by a request.");
                goto stop_download;
            }

            res = EsfFwMgrOpen(req, NULL, &o_res);

            if (res != kEsfFwMgrResultUnavailable) {
                SYSAPP_INFO("EsfFwMgrOpen(retry_cnt:%d)...", retry_cnt);
                if (e_state != p_deploy->parse_state) {
                    /* If the state has changed, return it to its original state */

                    p_deploy->res_info = res_info_bk;

                    p_deploy->parse_state = e_state;

                    SetEvpStateReportOtaUpdateStatus(initp);

                    /* If open is successful, clear LED indicating that open is complete */

                    UnsetLedForUnavailable();
                }
                break;
            }

            /* Sensor close */

            SysAppStaClose();

            /* Sleeps for 1 second before next open */

            SYSAPP_INFO("Waiting for streaming to stop...");

            if (retry_cnt == 1) {
                p_deploy->parse_state = DeployStateFailedUnavailable;

                SetEvpStateReportOtaUpdateStatus(initp);

                /* Set open Waiting LED */

                SetLedForUnavailable();
            }

            sleep(1);
        }

        if (retry_cnt >= MAX_NUMBER_OF_UPDATE_OPEN_RETRY) {
            /* EsfFwMgrOpen timeout */

            p_deploy->parse_state = DeployStateFailedUnavailable;
            ret = kRetFailed;
            break;
        }

        if (res != kEsfFwMgrResultOk) {
            SYSAPP_ERR("EsfFwMgrOpen=%d slot:%d", res, slot);
            SYSAPP_ELOG_ERR(SYSAPP_EVT_OTA_FAILED);
            continue;
        }

        /* Delete AI model */

        res = EsfFwMgrErase(o_res.handle);

        if (res != kEsfFwMgrResultOk) {
            SYSAPP_ELOG_ERR(SYSAPP_EVT_OTA_FAILED);
            SYSAPP_ERR("EsfFwMgrErase=%d", res);
            p_deploy->parse_state = DeployStateFailed;
        }

        res = EsfFwMgrClose(o_res.handle);

        if (res != kEsfFwMgrResultOk) {
            SYSAPP_ELOG_ERR(SYSAPP_EVT_OTA_FAILED);
            SYSAPP_ERR("EsfFwMgrClose=%d", res);
            p_deploy->parse_state = DeployStateFailed;
        }
    }

stop_download:
errout:

    /* Clean up */

    free(response);

    if (p_deploy->parse_state != DeployStateIdle) {
        SetEvpStateReportOtaUpdateStatus(initp);
    }

    SYSAPP_INFO("Delete AI model end");

    return ret;
}

/*--------------------------------------------------------------------------*/
STATIC void StartDeploy(DeployInitParams_t *initp)
{
    /* Start Deploy */

    SYSAPP_ELOG_INFO(SYSAPP_EVT_OTA_STARTED);

    Deploy_t *p_deploy = &initp->deploy;

    /* Delete ai model */

    if (DeleteAiModel(initp, p_deploy) != kRetOk) {
        goto errout;
    }

    /* Process for each deploy target */

    for (int i = 0; i < p_deploy->deploy_target_num; i++) {
        DeployTarget_t *p_target = p_deploy->deploy_targets + i;

        SYSAPP_INFO("===%d/%d %p", i + 1, p_deploy->deploy_target_num, p_target);
        SYSAPP_INFO("comp:%d", p_target->component);
        SYSAPP_INFO("chip:%s", p_target->chip);
        SYSAPP_INFO("name:%s", p_target->name);
        SYSAPP_INFO("ver: %s", p_target->version);
        SYSAPP_INFO("url: %s", p_target->package_url);
        SYSAPP_INFO("hash:%s", p_target->hash);
        SYSAPP_INFO("prog:%d", p_target->progress);
        SYSAPP_INFO("stat:%d/%d", p_target->process_state, p_target->parse_state);

        if (p_target->parse_state != DeployStateIdle) {
            /* Target is already errord */

            SYSAPP_INFO("Parse error(%d)", p_target->parse_state);

            SetTargetState(p_target, 0, p_target->parse_state);

            SetEvpStateReportOtaUpdateStatus(initp);
            continue;
        }

        /* Check version */

        DeployState_e state = DeployStateFailed;

        int res = CheckVersion(p_target, &state);

        if (res == 0) {
            /* Target is already deployed */

            SYSAPP_INFO("Already deployed");

            SetTargetState(p_target, 100, DeployStateDone);

            SetEvpStateReportOtaUpdateStatus(initp);
            continue;
        }
        else if (res < 0) {
            /* Target is errord */

            SYSAPP_ERR("errord");

            SetTargetState(p_target, 0, state);

            SetEvpStateReportOtaUpdateStatus(initp);
            continue;
        }

        /* Start update */

        FirmwareUpdate(initp, p_target);
    }

errout:
    /* Sensor reopen */

    if (SysAppStaReopenIfClose() == kRetOk) {
        // Update device_info.
        SysAppStateSendState(ST_TOPIC_UPDATE_DEVICE_INFO);
    }
}

/*--------------------------------------------------------------------------*/
STATIC void RetryProcessWhenFirmwareManagerIsUnavailable(DeployInitParams_t *initp)
{
    /* Retry process when FirmwareManager is unavailable */

    if (initp->deploy.res_info.code != RESULT_CODE_UNAVAILABLE) {
        /* Retry only if FirmwareManager is not available */

        return;
    }

    /* Wait until retry */

    for (int i = 0; i < MAX_NUMBER_OF_UPDATE_RETRY; i++) {
        if (SysAppUdIsThisRequestToStopForDownload()) {
            return;
        }
        SYSAPP_INFO("Wait retry process(%d)", i);
        sleep(1);
    }

    /* Send retry message */

    EsfJsonHandle handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue parent = ESF_JSON_VALUE_INVALID;

    if (EsfJsonOpen(&handle) != kEsfJsonSuccess) {
        SYSAPP_ERR("JsonOpen");
        return;
    }

    /* Get parent value */

    if (EsfJsonObjectInit(handle, &parent) != kEsfJsonSuccess) {
        SYSAPP_ERR("JsonObjectInit");
        goto errout;
    }

    Deploy_t *p_deploy = &initp->deploy;

    /* Set req_info property */

    MakeJsonStateReqInfo(p_deploy->id, handle, parent);

    /* Set targets property */

    EsfJsonValue ary;

    if (EsfJsonArrayInit(handle, &ary) != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonArrayInit");
        goto errout;
    }

    /* Add deploy target to array */

    for (size_t index = 0; index < p_deploy->deploy_target_num; index++) {
        EsfJsonValue val;

        if (EsfJsonObjectInit(handle, &val) != kEsfJsonSuccess) {
            SYSAPP_ERR("JsonObjectInit");
            goto errout;
        }

        DeployTarget_t *p_target = p_deploy->deploy_targets + index;
        ResInfo_t res_info;

        memset(&res_info, 0, sizeof(res_info));

        MakeJsonStateDeployTarget(p_target, handle, val, &res_info);

        if (EsfJsonArrayAppend(handle, ary, val) != kEsfJsonSuccess) {
            SYSAPP_ERR("JsonArrayAppend");
            goto errout;
        }
    }

    if (EsfJsonObjectSet(handle, parent, "targets", ary) != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectSet");
        goto errout;
    }

    /* Save the state string */

    const char *pstr = NULL;

    if (kEsfJsonSuccess != EsfJsonSerialize(handle, parent, &pstr) || *pstr == '\0') {
        SYSAPP_ERR("JsonSerialize");
        goto errout;
    }

    size_t len = strnlen(pstr, MAX_NUMBER_OF_CHARACTERS_IN_CONFIGURATION);

    /* Send state of json string */

    RetCode ret = SysAppDeploy(sc_topics[p_deploy->topic_id], pstr, len);

    if (ret != kRetOk) {
        SYSAPP_ERR("SysAppDeploy");
    }

    EsfJsonSerializeFree(handle);

errout:
    EsfJsonClose(handle);
}

/*--------------------------------------------------------------------------*/
STATIC void *DeployMain(void *p)
{
    /* Deploy main proc */

    DeployInitParams_t *initp = (DeployInitParams_t *)p;

    /* Main loop */

    SYSAPP_INFO("DeployMain() enter event loop...");

    for (;;) {
        UtilityMsgErrCode msg_ercd;
        RetCode res = kRetFailed;
        DeployMessage_t *msg = NULL;
        bool is_finish = false;
        Deploy_t *p_deploy = (Deploy_t *)&initp->deploy;

        int32_t recv_size;

        msg_ercd = UtilityMsgRecv(initp->msg_handle_dp, &msg, sizeof(DeployMessage_t *), -1,
                                  &recv_size);

        /* Deploy process will start */

        if (msg_ercd == kUtilityMsgOk) {
            if (msg) {
                /* Disable cancel flag  */

                ClearCancelFlag(initp, msg->topic_id);

                /* Start controlling Deploy's LED */

                StartLED();

                /* Parse configuration */

                SYSAPP_INFO("RECV:%d", msg->topic_id);
                SYSAPP_INFO("RECV:%s", msg->config);

                res = ParseConfiguration(p_deploy, msg->topic_id, msg->config);

                /* Free used memory */

                free(msg);
            }
            else {
                SYSAPP_INFO("Thread stop request received");
                is_finish = true;
            }
        }

        /* When thread stop request is received, This loop is exit */

        if (is_finish) {
            SYSAPP_INFO("Termination");
            break;
        }

        /* Discard all messages when forced to reboot */

        if (initp->is_pre_reboot) {
            SYSAPP_INFO("Force termination");
            continue;
        }

        /* Message error check */

        if (msg_ercd == kUtilityMsgErrTimedout) {
            sleep(1);
            continue;
        }
        else if (msg_ercd != kUtilityMsgOk) {
            SYSAPP_ERR("UtilityMsgRecv(%d)", msg_ercd);
            continue;
        }

        SYSAPP_INFO("Deploy..Start");

        clock_t cstart, cend;

        cstart = clock();

        if (res == kRetOk) {
            StartDeploy(initp);
        }

        cend = clock();

        /* Deploy is complete, so update state */

        SetEvpStateReportOtaUpdateStatus(initp);

        /* Stop controlling Deploy's LED */

        StopLED(initp);

        /* Retry process when FirmwareManager is unavailable */

        RetryProcessWhenFirmwareManagerIsUnavailable(initp);

        /* Clear deproy parameters */

        SYSAPP_INFO("Deploy..End - Clear deproy parameter:%g(sec)\n",
                    (double)(cend - cstart) / CLOCKS_PER_SEC);

        if (p_deploy->deploy_targets) {
            free(p_deploy->deploy_targets);
        }

        memset(p_deploy, 0, sizeof(Deploy_t));

        /* Once OTA is complete for one message, set the reboot flag */

        initp->is_reboot = initp->is_pre_reboot;
    }

    /* Thread termination process */

    SysAppUdCancelDownloadStopRequest();

    return NULL;
}

/*--------------------------------------------------------------------------*/
static RetCode GetState(SysAppDeployHandle handle, int id, char **state, uint32_t *p_size)
{
    /* Get state for PRIVATE_deploy_firmware topic */

    DeployInitParams_t *initp = (DeployInitParams_t *)handle;

    if (initp == NULL || state == NULL || p_size == NULL) {
        return kRetStateViolate;
    }

    *state = NULL;
    *p_size = 0;

    if (pthread_mutex_lock(&initp->state_mutex) != 0) {
        SYSAPP_ERR("pthread_mutex_lock");
        return kRetFailed;
    }

    /* Lock */

    RetCode ret = kRetFailed;
    uint32_t len = initp->state_str_len[id] + 1;
    char *str;

    if (initp->state_str[id]) {
        str = (char *)malloc(len);

        /* Copy state */

        if (str) {
            snprintf(str, len, "%s", initp->state_str[id]);

            *p_size = initp->state_str_len[id];
            *state = str;

            ret = kRetOk;
        }
    }

    /* Unlock */

    pthread_mutex_unlock(&initp->state_mutex);

    return ret;
}

#ifdef CONFIG_EXTERNAL_SYSTEMAPP_SYSTEM_UPDATE_SUPPORT
/*--------------------------------------------------------------------------*/
STATIC RetCode ParseSystemUpdateConfiguration(const char *param)
{
    /* Parse and validate system update configuration */

    SYSAPP_INFO("Parse system update configuration");

    RetCode ret = kRetFailed;
    EsfJsonHandle handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;

    /* Get handle to JSON module */
    if (EsfJsonOpen(&handle) != kEsfJsonSuccess) {
        SYSAPP_ERR("ParseSystemUpdateConfiguration JsonOpen failed");
        goto errout;
    }

    /* Convert string to JSON Value */
    if (EsfJsonDeserialize(handle, param, &val) != kEsfJsonSuccess) {
        SYSAPP_ERR("ParseSystemUpdateConfiguration JsonDeserialize failed");
        goto errout;
    }

    /* Parse and validate system update specific configuration */
    /* Get targets array */
    EsfJsonValue targets_val;
    if (EsfJsonObjectGet(handle, val, "targets", &targets_val) != kEsfJsonSuccess) {
        SYSAPP_ERR("Missing targets array in system update configuration");
        goto errout;
    }

    /* Get first target from array */
    EsfJsonValue target_val;
    if (EsfJsonArrayGet(handle, targets_val, 0, &target_val) != kEsfJsonSuccess) {
        SYSAPP_ERR("No target found in targets array");
        goto errout;
    }

    /* Extract and validate component from first target */
    int component_value = 0;
    int extract_ret = SysAppCmnExtractNumberValue(handle, target_val, "component",
                                                  &component_value);
    if (extract_ret <= 0 || component_value != 1) {
        SYSAPP_ERR("Invalid or missing component value. Expected: 1, Got: %d", component_value);
        goto errout;
    }

    /* Extract and validate chip from first target */
    const char *chip_value = NULL;
    extract_ret = SysAppCmnExtractStringValue(handle, target_val, "chip", &chip_value);
    if (extract_ret <= 0 || !chip_value || strcmp(chip_value, "main_chip") != 0) {
        SYSAPP_ERR("Invalid or missing chip value. Expected: main_chip, Got: %s",
                   chip_value ? chip_value : "NULL");
        goto errout;
    }

    SYSAPP_INFO("System Update configuration validation successful:");
    SYSAPP_DBG("  component: %d", component_value);
    SYSAPP_DBG("  chip: %s", chip_value);

    ret = kRetOk;

errout:
    /* Close handle */
    if (handle != ESF_JSON_HANDLE_INITIALIZER) {
        EsfJsonClose(handle);
    }

    return ret;
}

/*--------------------------------------------------------------------------*/
STATIC DeployState_e ExecuteSystemUpdateScript(void)
{
    /* Execute /sbin/edc_system_update.sh script */

    const char *script_path = "/sbin/edc_system_update.sh";

    SYSAPP_INFO("Starting system update script: %s", script_path);

    /* Check if script exists */
    if (access(script_path, F_OK) != 0) {
        SYSAPP_ERR("System update script not found: %s", script_path);
        return DeployStateFailed;
    }

    /* Check if script is executable */
    if (access(script_path, X_OK) != 0) {
        SYSAPP_ERR("System update script is not executable: %s", script_path);
        return DeployStateFailed;
    }

    /* Set up environment with proper PATH for script execution */
    const char *current_path = getenv("PATH");
    const char *standard_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    char *full_command = NULL;
    int ret = -1;

    /* Create command with proper PATH environment */
    if (current_path != NULL) {
        /* Prepend standard paths to existing PATH */
        size_t cmd_len = strlen("PATH=") + strlen(standard_path) + strlen(":") +
                         strlen(current_path) + strlen(" ") + strlen(script_path) + 1;
        full_command = malloc(cmd_len);
        if (full_command != NULL) {
            snprintf(full_command, cmd_len, "PATH=%s:%s %s", standard_path, current_path,
                     script_path);
        }
    }
    else {
        /* Use only standard paths */
        size_t cmd_len = strlen("PATH=") + strlen(standard_path) + strlen(" ") +
                         strlen(script_path) + 1;
        full_command = malloc(cmd_len);
        if (full_command != NULL) {
            snprintf(full_command, cmd_len, "PATH=%s %s", standard_path, script_path);
        }
    }

    if (full_command == NULL) {
        SYSAPP_ERR("Failed to allocate memory for command string");
        return DeployStateFailed;
    }

    SYSAPP_INFO("Executing command: %s", full_command);

    /* Execute the script with proper environment */
    ret = system(full_command);

    free(full_command);

    if (ret == -1) {
        SYSAPP_ERR("Failed to execute system update script");
        return DeployStateFailed;
    }

    /* Get the actual exit status */
    if (WIFEXITED(ret)) {
        int exit_status = WEXITSTATUS(ret);
        SYSAPP_INFO("System update script completed with exit status: %d", exit_status);
        return (exit_status == 0) ? DeployStateDone : DeployStateFailed;
    }
    else {
        SYSAPP_ERR("System update script terminated abnormally");
        return DeployStateFailed;
    }
}

/*--------------------------------------------------------------------------*/
STATIC void SendReportSystemUpdateStatus(DeployInitParams_t *initp, DeployState_e state)
{
    /* Send system update status report to cloud using existing state management */

    SYSAPP_INFO("Sending system update status report: state=%d", state);

    EsfJsonHandle handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue parent = ESF_JSON_VALUE_INVALID;

    /* Get handle to JSON module */
    if (EsfJsonOpen(&handle) != kEsfJsonSuccess) {
        SYSAPP_ERR("SendReportSystemUpdateStatus JsonOpen failed");
        return;
    }

    /* Create parent object */
    if (EsfJsonObjectInit(handle, &parent) != kEsfJsonSuccess) {
        SYSAPP_ERR("SendReportSystemUpdateStatus JsonObjectInit failed");
        goto errout;
    }

    /* Set component (fixed value: 1) */
    if (SysAppCmnSetNumberValue(handle, parent, "component", 1) != kRetOk) {
        SYSAPP_ERR("Failed to set component");
        goto errout;
    }

    /* Set chip (fixed value: "main_chip") */
    if (SysAppCmnSetStringValue(handle, parent, "chip", "main_chip") != kRetOk) {
        SYSAPP_ERR("Failed to set chip");
        goto errout;
    }

    /* Set process_state based on script result */
    const char *process_state_str = (state == DeployStateDone) ? "done" : "failed";
    if (SysAppCmnSetStringValue(handle, parent, "process_state", process_state_str) != kRetOk) {
        SYSAPP_ERR("Failed to set process_state");
        goto errout;
    }

    /* Serialize JSON to string */
    const char *json_str = NULL;
    if (EsfJsonSerialize(handle, parent, &json_str) != kEsfJsonSuccess || json_str == NULL) {
        SYSAPP_ERR("JsonSerialize failed");
        goto errout;
    }

    /* Calculate string length */
    size_t json_len = strnlen(json_str, MAX_NUMBER_OF_CHARACTERS_IN_CONFIGURATION);

    SYSAPP_DBG("System update status JSON: %s", json_str);

    int topic_id = DeployTopicFirmware; // Use firmware topic for system update

    /* Lock state mutex */
    if (pthread_mutex_lock(&initp->state_mutex) == 0) {
        /* Free existing state string */
        if (initp->state_str[topic_id]) {
            free(initp->state_str[topic_id]);
            initp->state_str[topic_id] = NULL;
            initp->state_str_len[topic_id] = 0;
        }

        /* Allocate and store new state string */
        initp->state_str[topic_id] = (char *)malloc(json_len + 1);
        if (initp->state_str[topic_id]) {
            snprintf(initp->state_str[topic_id], json_len + 1, "%s", json_str);
            initp->state_str_len[topic_id] = json_len;

            SYSAPP_DBG("System update state stored successfully");
        }
        else {
            SYSAPP_ERR("Failed to allocate memory for state string");
        }
        /* Unlock state mutex */
        pthread_mutex_unlock(&initp->state_mutex);
    }
    else {
        SYSAPP_ERR("pthread_mutex_lock failed");
    }

    /* Send state using the existing state management system */
    if (SysAppStateSendState(ST_TOPIC_DEPLOY_FIRMWARE) != kRetOk) {
        SYSAPP_ERR("Failed to send system update status via SysAppStateSendState");
    }
    else {
        SYSAPP_INFO("System update status sent successfully via state management");
    }

    /* Free serialized string */
    EsfJsonSerializeFree(handle);

errout:
    /* Close JSON handle */
    if (handle != ESF_JSON_HANDLE_INITIALIZER) {
        EsfJsonClose(handle);
    }
}

/*--------------------------------------------------------------------------*/
STATIC RetCode UpdateSystemFirmware(SysAppDeployHandle handle, const char *config)
{
    /* Update system firmware */

    RetCode ret = kRetFailed;
    DeployState_e state = DeployStateFailed;
    DeployInitParams_t *initp = (DeployInitParams_t *)handle;

    if (initp == NULL) {
        SYSAPP_ERR("Deploy handle is NULL");
        return kRetFailed;
    }

    SYSAPP_INFO("Starting system update");

    /* Parse and validate configuration */
    RetCode parse_ret = ParseSystemUpdateConfiguration(config);
    SYSAPP_INFO("Configuration validation result: %d", parse_ret);

    if (parse_ret == kRetOk) {
        /* Execute system update script */
        state = ExecuteSystemUpdateScript();
        SYSAPP_INFO("System update script execution returned: %d", state);
        ret = kRetOk;
    }
    else {
        SYSAPP_ERR("Failed to parse system update configuration - invalid format or values");
    }

    /* Send state report */
    SendReportSystemUpdateStatus(initp, state);

    if (ret == kRetOk) {
        SYSAPP_INFO("System update process completed successfully");
    }
    else {
        SYSAPP_ERR("System update process failed");
    }

    return ret;
}
#endif // CONFIG_EXTERNAL_SYSTEMAPP_SYSTEM_UPDATE_SUPPORT

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/*--------------------------------------------------------------------------*/
RetCode SysAppDeployInitializeWithHandle(SysAppDeployHandle *handle)
{
#if !defined(__NuttX__)
    size_t size = DEPLOY_THREAD_STACKSIZE > PTHREAD_STACK_MIN ? DEPLOY_THREAD_STACKSIZE
                                                              : PTHREAD_STACK_MIN;
#endif

    /* Initialize */

    SYSAPP_INFO("DeployInitialize");

    RetCode ret = kRetFailed;

    DeployInitParams_t *initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));

    if (initp == NULL) {
        SYSAPP_CRIT("DeployInitParams malloc failed. size=%zu", sizeof(DeployInitParams_t));
        ret = kRetMemoryError;
        goto errout;
    }

    memset(initp, 0, sizeof(DeployInitParams_t));

    initp->max_msg_size_dp = sizeof(DeployMessage_t *);

    if (kUtilityMsgOk !=
        UtilityMsgOpen(&initp->msg_handle_dp, MSG_QUEUE_SIZE_FOR_DEPLOY, initp->max_msg_size_dp)) {
        SYSAPP_CRIT("UtilityMsgOpen failed. handle=%" PRId32
                    ", queue_size=%d, max_msg_size=%" PRIu32,
                    initp->msg_handle_dp, MSG_QUEUE_SIZE_FOR_DEPLOY, initp->max_msg_size_dp);
        goto errout;
    }

    /* Initialize mutex */

    if (pthread_mutex_init(&initp->state_mutex, NULL) != 0) {
        SYSAPP_CRIT("pthread_mutex_init");
        goto errout;
    }

    /* Create deploy thread */

    pthread_attr_t ota_attr;
    int ercd;

    if ((ercd = pthread_attr_init(&ota_attr)) == 0) {
#if defined(__NuttX__)
        if ((ercd = pthread_attr_setstacksize(&ota_attr, DEPLOY_THREAD_STACKSIZE)) == 0) {
#else
        if ((ercd = pthread_attr_setstacksize(&ota_attr, size)) == 0) {
#endif
            if ((ercd = pthread_create(&initp->pid, &ota_attr, DeployMain, initp)) == 0) {
                /* Thread creation successful */

                SYSAPP_INFO("DeployInitialize successful");
                ret = kRetOk;
            }
            else {
                SYSAPP_CRIT("pthread_create(%d)!", ercd);
            }
        }
        else {
            SYSAPP_CRIT("pthread_attr_setstacksize(%d)!", ercd);
        }

        /* Destroy pthread_attr_t */

        pthread_attr_destroy(&ota_attr);
    }
    else {
        SYSAPP_CRIT("pthread_attr_init(%d)!", ercd);
    }

    if (ret == kRetOk) {
        *handle = initp;
        return kRetOk;
    }

errout:
    /* Cleanup */

    if (initp) {
        if (initp->msg_handle_dp) {
            UtilityMsgErrCode MsgClose_ret = UtilityMsgClose(initp->msg_handle_dp);
            if (MsgClose_ret != kUtilityMsgOk) {
                SYSAPP_ERR("UtilityMsgClose(%d)!", MsgClose_ret);
            }
        }

        pthread_mutex_destroy(&initp->state_mutex);

        free(initp);
    }

    *handle = NULL;

    SYSAPP_ERR("DeployInitialize:%d", ret);

    return ret;
}

/*--------------------------------------------------------------------------*/
RetCode SysAppDeployFinalizeWithHandle(SysAppDeployHandle handle)
{
    /* Finalize */

    SYSAPP_INFO("DeployFinalize - Send message for thread finish");

    DeployInitParams_t *initp = (DeployInitParams_t *)handle;

    if (initp == NULL) {
        SYSAPP_ERR("Invalid handle");
        return kRetStateViolate;
    }

    /* Request to stop download */

    SysAppUdRequestToStopDownload();

    /* Message recombination */

    UtilityMsgErrCode ret;
    int32_t recv_size;
    int32_t send_size;
    DeployMessage_t *msgs = NULL;

    for (int i = 0; i < MSG_QUEUE_SIZE_FOR_DEPLOY; i++) {
        ret = UtilityMsgRecv(initp->msg_handle_dp, &msgs, initp->max_msg_size_dp, 0, &recv_size);

        if (ret == kUtilityMsgOk) {
            if (msgs) {
                SYSAPP_INFO("Delete msg[%d]", i);
                free(msgs);
                msgs = NULL;
            }
        }
    }

    /* Send message that the thread is finished */

    DeployMessage_t *msg = NULL;

    SYSAPP_INFO("Send message for thread finish");

    ret = UtilityMsgSend(initp->msg_handle_dp, &msg, initp->max_msg_size_dp, 0, &send_size);

    if (ret != kUtilityMsgOk) {
        SYSAPP_ERR("UtilityMsgSend");
    }

    /* Wait for a download to finish */

    SysAppUdWaitForDownloadToStop();

    /* Wait for a thread to finish */

    SYSAPP_INFO("Wait for thread to finish");

    if (pthread_join(initp->pid, NULL) != 0) {
        SYSAPP_ERR("pthread_join");
    }

    /* Cleanup */

    if (initp->msg_handle_dp) {
        UtilityMsgErrCode MsgClose_ret = UtilityMsgClose(initp->msg_handle_dp);
        if (MsgClose_ret != kUtilityMsgOk) {
            SYSAPP_ERR("UtilityMsgClose(%d)!", MsgClose_ret);
        }
    }

    pthread_mutex_destroy(&initp->state_mutex);

    /* Clear state strings */

    for (int i = 0; i < DeployTopicNum; i++) {
        if (initp->state_str[i]) {
            free(initp->state_str[i]);
        }
    }

    free(initp);

    SYSAPP_INFO("The thread has ended");

    /* Cancel LED status used in deploy */

    SysAppLedUnsetAppStatus(LedTypePower, LedAppStatusErrorDownloadFailed);
    SysAppLedUnsetAppStatus(LedTypePower, LedAppStatusErrorUpdateMemoryAllocateFailed);

    return kRetOk;
}

/*--------------------------------------------------------------------------*/
RetCode SysAppDeployWithHandle(SysAppDeployHandle handle, const char *topic, const char *config,
                               size_t len)
{
    /* Deploy process will start */

    SYSAPP_INFO("Set deploy");

    if (handle == NULL) {
        SYSAPP_ERR("handle");
        return kRetFailed;
    }

    /* topic to topic_id */

    int topic_id = -1;

    for (int i = 0; i < DeployTopicNum; i++) {
        if (strncmp(sc_topics[i], topic, DEPLOY_TOPIC_STRING_SIZE) == 0) {
            topic_id = i;
            break;
        }
    }

    if (topic_id < 0) {
        SYSAPP_ERR("topic_id");
        return kRetFailed;
    }

    DeployInitParams_t *initp = (DeployInitParams_t *)handle;

    UtilityMsgErrCode ret;
    int32_t recv_size;
    int32_t send_size;

    /* Message recombination */

    DeployMessage_t *msgs[MSG_QUEUE_SIZE_FOR_DEPLOY];

    memset(msgs, 0, sizeof(msgs));

    for (int i = 0; i < MSG_QUEUE_SIZE_FOR_DEPLOY; i++) {
        ret = UtilityMsgRecv(initp->msg_handle_dp, &msgs[i], initp->max_msg_size_dp, 0, &recv_size);

        if (ret != kUtilityMsgOk) {
            SYSAPP_INFO("Number of items=%d", i);
            break;
        }
    }

    /* Request to stop deploy */

    initp->is_cancels[topic_id] = true;

    /* If send topic_id is same, message is delete */

    for (int i = 0; i < MSG_QUEUE_SIZE_FOR_DEPLOY; i++) {
        if (msgs[i] == NULL) {
            continue;
        }

        if (msgs[i]->topic_id == topic_id) {
            SYSAPP_INFO("Remove msg:%d/%d", msgs[i]->topic_id, topic_id);
            free(msgs[i]);
            msgs[i] = NULL;
            continue;
        }

        /* Reload the message */

        ret = UtilityMsgSend(initp->msg_handle_dp, &msgs[i], initp->max_msg_size_dp, 0, &send_size);

        if (ret != kUtilityMsgOk) {
            SYSAPP_ERR("UtilityMsgSend");
        }
        else {
            SYSAPP_INFO("Resend msg:%d", msgs[i]->topic_id);
        }
    }

    /* Send new message */

    DeployMessage_t *msg = (DeployMessage_t *)malloc(sizeof(DeployMessage_t) + len);

    if (msg == NULL) {
        SYSAPP_ERR("Memory allocation");
        return kRetFailed;
    }

    msg->topic_id = topic_id;
    msg->len = len;
    snprintf(msg->config, len + 1, "%s", config);

    SYSAPP_INFO("CONF:%d, %zu", msg->topic_id, msg->len);
    SYSAPP_INFO("CONF:%s", msg->config);

    ret = UtilityMsgSend(initp->msg_handle_dp, &msg, initp->max_msg_size_dp, 0, &send_size);

    if (ret != kUtilityMsgOk) {
        SYSAPP_ERR("UtilityMsgSend");
        free(msg);
    }
    else {
        SYSAPP_INFO("SEND:%p", msg);
    }

    return kRetOk;
}

/*--------------------------------------------------------------------------*/
RetCode SysAppDeployInitialize(void)
{
    /* Initialize */

    if (s_handle != NULL) {
        SYSAPP_CRIT("DeployInitialize invalid state");
        return kRetStateViolate;
    }

    return SysAppDeployInitializeWithHandle(&s_handle);
}

/*--------------------------------------------------------------------------*/
RetCode SysAppDeployFinalize(void)
{
    /* Finalize */

    RetCode ret = SysAppDeployFinalizeWithHandle(s_handle);

    s_handle = NULL;

    return ret;
}

/*--------------------------------------------------------------------------*/
RetCode SysAppDeploy(const char *topic, const char *config, size_t len)
{
    /* Deploy process will start */

#ifdef CONFIG_EXTERNAL_SYSTEMAPP_SYSTEM_UPDATE_SUPPORT
    if (strcmp(topic, "PRIVATE_deploy_firmware") == 0) {
        return UpdateSystemFirmware(s_handle, config);
    }
#endif

    RetCode ret = kRetFailed;

    DeployInitParams_t *initp = (DeployInitParams_t *)s_handle;

    /* Lock */

    if (pthread_mutex_lock(&initp->state_mutex) == 0) {
        ret = SysAppDeployWithHandle(s_handle, topic, config, len);

        /* Unlock */

        pthread_mutex_unlock(&initp->state_mutex);
    }

    return ret;
}

/*--------------------------------------------------------------------------*/
RetCode SysAppDeployGetFirmwareState(char **state, uint32_t *p_size)
{
    /* Get state for PRIVATE_deploy_firmware topic */

    return GetState(s_handle, DeployTopicFirmware, state, p_size);
}

/*--------------------------------------------------------------------------*/
RetCode SysAppDeployGetAiModelState(char **state, uint32_t *p_size)
{
    /* Get state for PRIVATE_deploy_ai_model topic */

    return GetState(s_handle, DeployTopicAiModel, state, p_size);
}

/*--------------------------------------------------------------------------*/
RetCode SysAppDeployGetSensorCalibrationParamState(char **state, uint32_t *p_size)
{
    /* Get state for PRIVATE_deploy_sensor_calibration_param topic */

    return GetState(s_handle, DeployTopicCameraSetup, state, p_size);
}

/*--------------------------------------------------------------------------*/
RetCode SysAppDeployFreeState(char *state)
{
    if (state) {
        free(state);
    }
    return kRetOk;
}

/*--------------------------------------------------------------------------*/
bool SysAppDeployCheckResetRequest(bool *is_downgrade)
{
    /* Check if a reboot is required */

    if (s_handle == NULL) {
        SYSAPP_ERR("DeployInitialize invalid state");
        return false;
    }

    if (is_downgrade == NULL) {
        SYSAPP_ERR("DeployInitialize invalid argument");
        return false;
    }

    DeployInitParams_t *initp = (DeployInitParams_t *)s_handle;

    *is_downgrade = false;

    if (initp->is_reboot) {
        if (initp->arch_version == kEsfFwMgrSwArchVersion1) {
            *is_downgrade = true;
        }
    }

    return initp->is_reboot;
}

/*--------------------------------------------------------------------------*/
void SysAppDeployFactoryReset(void)
{
    /* Factory Reset when downgrad */

    SYSAPP_INFO("SysAppDeployFactoryReset");

    EsfFwMgrResult res = EsfFwMgrStartFactoryReset(kEsfFwMgrResetCauseDowngrade);

    if (res != kEsfFwMgrResultOk) {
        SYSAPP_ELOG_ERR(SYSAPP_EVT_OTA_FAILED);
        SYSAPP_ERR("EsfFwMgrClose=%d", res);
    }
}

/*--------------------------------------------------------------------------*/
bool SysAppDeployGetCancel(void)
{
    /* Get cancel */

    return GetCancel((DeployInitParams_t *)s_handle);
}
