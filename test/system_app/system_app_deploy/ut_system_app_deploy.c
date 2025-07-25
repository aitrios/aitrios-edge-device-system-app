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
#include <mbedtls/sha256.h>
#if defined(__NuttX__)
#include <nuttx/config.h>
#endif
#include "ut_mock_utility_msg.h"
#include "utility_msg.h"
#include "utility_log.h"
#include "utility_log_module_id.h"
#include "firmware_manager.h"
#include "base64/include/base64.h"
#include "system_app_common.h"
#include "system_app_deploy_private.h"
#include "system_app_led.h"
#include "system_app_deploy.h"

#define ELOG_EVENT_ID_OTA_FAILED (0xb0b3)
#define ELOG_EVENT_ID_DOWNLOAD_FAILED (0xb0b2)
#define ELOG_EVENT_ID_START_OTA (0xb000)

static const char *dtdl_deploy_target_chip_main_chip = "main_chip";
static const char *dtdl_deploy_target_chip_sensor_chip = "sensor_chip";
static const char *dtdl_deploy_target_chip_companion_chip = "companion_chip";

static const char *esf_fw_mgr_open_param_name_ap_fw = "ApFw";
static const char *esf_fw_mgr_open_param_name_sensor = "IMX500";
static const char *esf_fw_mgr_open_param_name_companion = "AI-ISP";

extern SysAppDeployHandle s_handle;

extern void *InitSha256(void);
extern int UpdateSha256(void *handle, size_t length, const uint8_t *p_input);
extern int FinishSha256(void *handle, uint8_t *p_output);
extern int SetTargetState(DeployTarget_t *p_target, int progress, DeployState_e state);
extern int ExtractStringValue(EsfJsonHandle handle, EsfJsonValue parent_val, const char *jsonkey,
                              char *buf, uint32_t buflen, int32_t extraced_len);
extern void MakeJsonStateReqInfo(char *req_id, EsfJsonHandle handle, EsfJsonValue parent_val);
extern void SetResInfo(ResInfo_t *res_info, DeployState_e state);
extern DeployComponent_e ConvertComponentToState(DeployComponent_e component);
extern void MakeJsonStateDeployTarget(DeployTarget_t *p_target, EsfJsonHandle handle,
                                      EsfJsonValue parent_val, ResInfo_t *p_res_info);
extern int ConvertChipToComponent(int deploy_id, DeployTarget_t *target);
extern int CmpTargetNameProperty(int deploy_id, DeployComponent_e component, const char *target);
extern RetCode GetConfigurationDeployTargetProperty(DeployTarget_t *p_target, EsfJsonHandle handle,
                                                    EsfJsonValue parent_val, int deploy_id);
extern int GetResCodePriority(int res_code);
extern RetCode MakeJsonResInfoDeployConfiguration(EsfJsonHandle handle, EsfJsonValue root,
                                                  void *ctx);
extern void MakeJsonStateDeployConfiguration(Deploy_t *p_deploy, EsfJsonHandle handle,
                                             EsfJsonValue parent_val);
extern bool GetConfigurationReqInfoProperty(char *req_id, size_t size, EsfJsonHandle handle,
                                            EsfJsonValue parent_val);
extern void SetEvpStateReportOtaUpdateStatus(DeployInitParams_t *initp);
extern RetCode GetConfigurationDeployConfigurationProperty(EsfJsonHandle handle,
                                                           EsfJsonValue parent_val,
                                                           Deploy_t *p_deploy, int topic_id);
extern EsfFwMgrHandle FirmwareUpdateOpen(DeployInitParams_t *initp, DeployTarget_t *target,
                                         size_t size, EsfFwMgrPrepareWriteResponse *p_res);
extern int CompareDeployingVersionWithDeployedOneTarget(DeployTarget_t *p_target,
                                                        DeployState_e *state);
extern int CompareDeployingVersionWithDeployedAiModel(DeployTarget_t *p_target,
                                                      DeployState_e *state);
extern int CheckVersion(DeployTarget_t *p_target, DeployState_e *state);
extern int DownloadCallback(uint8_t *data, size_t dl_size, void *p_usr_data);
extern RetCode FirmwareUpdate(DeployInitParams_t *initp, DeployTarget_t *p_target);
extern RetCode ParseConfiguration(Deploy_t *p_deploy, int topic_id, const char *param);
extern void StartDeploy(DeployInitParams_t *initp);
extern void *DeployMain(void *p);
extern void DeleteAiModel(DeployInitParams_t *initp, Deploy_t *p_deploy);
extern void StopLED(DeployInitParams_t *initp);
extern void ClearCancelFlag(DeployInitParams_t *initp, int topic_id);
extern void RetryProcessWhenFirmwareManagerIsUnavailable(DeployInitParams_t *initp);

/*----------------------------------------------------------------------------*/

//
// Common
//

/*----------------------------------------------------------------------------*/
static void DeployMain_FinishLoop(UtilityMsgErrCode ret_msg_ercd, int32_t exp_msg_handle_dp)
{
    expect_value(__wrap_UtilityMsgRecv, handle, exp_msg_handle_dp);
    expect_value(__wrap_UtilityMsgRecv, size, sizeof(DeployMessage_t *));
    expect_value(__wrap_UtilityMsgRecv, timeout_ms, -1);

    will_return(__wrap_UtilityMsgRecv, (int32_t)sizeof(DeployMessage_t *));
    will_return(__wrap_UtilityMsgRecv, NULL);
    will_return(__wrap_UtilityMsgRecv, ret_msg_ercd);
}

/*----------------------------------------------------------------------------*/
static DeployTopic_e ConvertTopicStr2TopicId(const char *topic)
{
    DeployTopic_e topic_id;

    if (strcmp("PRIVATE_deploy_firmware", topic) == 0) {
        topic_id = DeployTopicFirmware;
    }
    else if (strcmp("PRIVATE_deploy_ai_model", topic) == 0) {
        topic_id = DeployTopicAiModel;
    }
    else if (strcmp("PRIVATE_deploy_sensor_calibration_param", topic) == 0) {
        topic_id = DeployTopicCameraSetup;
    }
    else {
        topic_id = DeployTopicNum;
    }

    return topic_id;
}

/*----------------------------------------------------------------------------*/
static bool InitGlobalVariableForFinalize(bool is_allocate_state_str)
{
    bool ret = false;
    DeployInitParams_t *init_param;
    int i;

    s_handle = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (s_handle == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    init_param = (DeployInitParams_t *)s_handle;

    init_param->msg_handle_dp = 0x12345678;
    init_param->max_msg_size_dp = 2468;
    init_param->pid = 1357;

    memset(init_param->state_str, 0, sizeof(init_param->state_str));
    if (is_allocate_state_str == true) {
        for (i = 0; i < DeployTopicNum; i++) {
            init_param->state_str[i] = malloc(10);
            if (init_param->state_str[i] == NULL) {
                assert_non_null(init_param->state_str[i]);
                goto exit;
            }
        }
    }

    ret = true;

exit:
    return ret;
}

/*----------------------------------------------------------------------------*/
static void FinGlobalVariableForFinalize(void)
{
    DeployInitParams_t *init_param = (DeployInitParams_t *)s_handle;
    int i;

    if (init_param != NULL) {
        for (i = 0; i < DeployTopicNum; i++) {
            if (init_param->state_str[i] != NULL) {
                free(init_param->state_str[i]);
            }
        }

        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void UtilityMsgSendForFinalize(UtilityMsgErrCode ercd)
{
    DeployInitParams_t *init_param = (DeployInitParams_t *)s_handle;

    will_return(__wrap_UtilityMsgSend, ercd);
    will_return(__wrap_UtilityMsgSend, UtilityMsgSendTypeDeployMessage);
    will_return(__wrap_UtilityMsgSend, 10);

    expect_value(__wrap_UtilityMsgSend, handle, init_param->msg_handle_dp);
    expect_value(__wrap_UtilityMsgSend, deploy_msg, NULL);
    expect_value(__wrap_UtilityMsgSend, msg_size, init_param->max_msg_size_dp);
    expect_value(__wrap_UtilityMsgSend, msg_prio, 0);
}

/*----------------------------------------------------------------------------*/
static bool UtilityMsgRecvForFinalize(UtilityMsgErrCode ercd, void **rcv_msg, size_t rcv_msg_num,
                                      bool is_allocate)
{
    bool ret = false;
    int i;
    DeployInitParams_t *init_param = (DeployInitParams_t *)s_handle;

    memset(rcv_msg, 0, sizeof(void *) * rcv_msg_num);

    for (i = 0; i < rcv_msg_num; i++) {
        if (is_allocate == true) {
            rcv_msg[i] = malloc(sizeof(DeployMessage_t));
            if (rcv_msg[i] == NULL) {
                assert_non_null(rcv_msg[i]);
                goto exit;
            }
        }

        will_return(__wrap_UtilityMsgRecv, sizeof(DeployMessage_t *));
        will_return(__wrap_UtilityMsgRecv, &rcv_msg[i]);
        will_return(__wrap_UtilityMsgRecv, ercd);

        expect_value(__wrap_UtilityMsgRecv, handle, init_param->msg_handle_dp);
        expect_value(__wrap_UtilityMsgRecv, size, init_param->max_msg_size_dp);
        expect_value(__wrap_UtilityMsgRecv, timeout_ms, 0);
    }

    ret = true;

exit:
    return ret;
}

/*----------------------------------------------------------------------------*/
static bool InitGlobalVariableForDeploy(void)
{
    bool ret = false;
    DeployInitParams_t *init_param;

    s_handle = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (s_handle == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    init_param = (DeployInitParams_t *)s_handle;

    init_param->msg_handle_dp = 0x12345678;
    init_param->max_msg_size_dp = 2468;

    ret = true;

exit:
    return ret;
}

/*----------------------------------------------------------------------------*/
static void FinGlobalVariableForDeploy(void)
{
    DeployInitParams_t *init_param = (DeployInitParams_t *)s_handle;

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static bool UtilityMsgRecvForDeploy(UtilityMsgErrCode ercd, void **rcv_msg, size_t rcv_msg_num,
                                    bool is_allocate)
{
    bool ret = false;
    int i;
    uint32_t config_len = 16;
    DeployInitParams_t *init_param = (DeployInitParams_t *)s_handle;

    memset(rcv_msg, 0, sizeof(void *) * rcv_msg_num);

    for (i = 0; i < rcv_msg_num; i++) {
        if (is_allocate == true) {
            rcv_msg[i] = malloc(sizeof(DeployMessage_t) + config_len);
            if (rcv_msg[i] == NULL) {
                assert_non_null(rcv_msg[i]);
                goto exit;
            }

            {
                DeployMessage_t *deploy_msg = (DeployMessage_t *)rcv_msg[i];

                deploy_msg->topic_id = i;
                snprintf(deploy_msg->config, config_len, "test-%d", i);
                deploy_msg->len = strlen(deploy_msg->config) + 1;
            }
        }

        will_return(__wrap_UtilityMsgRecv, sizeof(DeployMessage_t *));
        will_return(__wrap_UtilityMsgRecv, &rcv_msg[i]);
        will_return(__wrap_UtilityMsgRecv, ercd);

        expect_value(__wrap_UtilityMsgRecv, handle, init_param->msg_handle_dp);
        expect_value(__wrap_UtilityMsgRecv, size, init_param->max_msg_size_dp);
        expect_value(__wrap_UtilityMsgRecv, timeout_ms, 0);
    }

    ret = true;

exit:
    return ret;
}

/*----------------------------------------------------------------------------*/
static void UtilityMsgSendForDeployReload(UtilityMsgErrCode ercd, void **rcv_msg,
                                          size_t rcv_msg_num, const char *except_topic)
{
    DeployInitParams_t *init_param = (DeployInitParams_t *)s_handle;
    DeployTopic_e except_topic_id;
    int i;

    except_topic_id = ConvertTopicStr2TopicId(except_topic);

    for (i = 0; i < rcv_msg_num; i++) {
        DeployMessage_t *deploy_msg = (DeployMessage_t *)rcv_msg[i];

        if (i == except_topic_id) {
            // For free()
            will_return(mock_free, true); // Exec parameter check
            expect_value(mock_free, __ptr, deploy_msg);
            continue;
        }

        // For UtilityMsgSend()
        will_return(__wrap_UtilityMsgSend, ercd);
        will_return(__wrap_UtilityMsgSend, UtilityMsgSendTypeDeployMessage);
        will_return(__wrap_UtilityMsgSend, 10);

        expect_value(__wrap_UtilityMsgSend, handle, init_param->msg_handle_dp);
        expect_value(__wrap_UtilityMsgSend, deploy_msg->topic_id, i);
        expect_value(__wrap_UtilityMsgSend, deploy_msg->len, deploy_msg->len);
        expect_string(__wrap_UtilityMsgSend, deploy_msg->config, deploy_msg->config);
        expect_value(__wrap_UtilityMsgSend, msg_size, init_param->max_msg_size_dp);
        expect_value(__wrap_UtilityMsgSend, msg_prio, 0);
    }
}

/*----------------------------------------------------------------------------*/
static void UtilityMsgSendForDeployNew(UtilityMsgErrCode ercd, const char *topic,
                                       const char *config)
{
    DeployInitParams_t *init_param = (DeployInitParams_t *)s_handle;
    DeployTopic_e topic_id;

    topic_id = ConvertTopicStr2TopicId(topic);

    if (strcmp("PRIVATE_deploy_firmware", topic) == 0) {
        topic_id = DeployTopicFirmware;
    }
    else if (strcmp("PRIVATE_deploy_ai_model", topic) == 0) {
        topic_id = DeployTopicAiModel;
    }
    else if (strcmp("PRIVATE_deploy_sensor_calibration_param", topic) == 0) {
        topic_id = DeployTopicCameraSetup;
    }
    else {
        topic_id = DeployTopicNum;
    }

    will_return(__wrap_UtilityMsgSend, ercd);
    will_return(__wrap_UtilityMsgSend, UtilityMsgSendTypeDeployMessage);
    will_return(__wrap_UtilityMsgSend, 10);

    expect_value(__wrap_UtilityMsgSend, handle, init_param->msg_handle_dp);
    expect_value(__wrap_UtilityMsgSend, deploy_msg->topic_id, topic_id);
    expect_value(__wrap_UtilityMsgSend, deploy_msg->len, strlen(config));
    expect_string(__wrap_UtilityMsgSend, deploy_msg->config, config);
    expect_value(__wrap_UtilityMsgSend, msg_size, init_param->max_msg_size_dp);
    expect_value(__wrap_UtilityMsgSend, msg_prio, 0);
}

/*----------------------------------------------------------------------------*/
static bool InitGlobalVariableForGetState(void)
{
    bool ret = false;
    DeployInitParams_t *init_param;
    uint32_t state_str_len = 16;
    int i;

    s_handle = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (s_handle == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    init_param = (DeployInitParams_t *)s_handle;

    memset(init_param->state_str, 0, sizeof(init_param->state_str));
    for (i = 0; i < DeployTopicNum; i++) {
        init_param->state_str[i] = malloc(state_str_len);
        if (init_param->state_str[i] == NULL) {
            assert_non_null(init_param->state_str[i]);
            goto exit;
        }

        snprintf(init_param->state_str[i], state_str_len, "test-%d", i);
        init_param->state_str_len[i] = state_str_len + i;
    }

    ret = true;

exit:
    return ret;
}

/*----------------------------------------------------------------------------*/
static void FinGlobalVariableForGetState(void)
{
    DeployInitParams_t *init_param = (DeployInitParams_t *)s_handle;
    int i;

    if (init_param != NULL) {
        for (i = 0; i < DeployTopicNum; i++) {
            if (init_param->state_str[i] != NULL) {
                free(init_param->state_str[i]);
            }
        }

        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static bool InitGlobalVariableForSysAppDeployCheckResetRequest(bool is_reboot)
{
    bool ret = false;
    DeployInitParams_t *init_param;

    s_handle = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (s_handle == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    init_param = (DeployInitParams_t *)s_handle;

    init_param->is_reboot = is_reboot;

    ret = true;

exit:
    return ret;
}

/*----------------------------------------------------------------------------*/
static void FinGlobalVariableForSysAppDeployCheckResetRequest(void)
{
    DeployInitParams_t *init_param = (DeployInitParams_t *)s_handle;

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void InitMbedtlsSha256Context(mbedtls_sha256_context *ctx)
{
    int i;

    memset(ctx, 0x00, sizeof(mbedtls_sha256_context));

    for (i = 0; i < sizeof(ctx->MBEDTLS_PRIVATE(buffer)) / sizeof(unsigned char); i++) {
        ctx->MBEDTLS_PRIVATE(buffer)[i] = i % 0x100;
    }

    for (i = 0; i < sizeof(ctx->MBEDTLS_PRIVATE(total)) / sizeof(uint32_t); i++) {
        ctx->MBEDTLS_PRIVATE(total)[i] = (i * 2) % 0x100;
    }

    for (i = 0; i < sizeof(ctx->MBEDTLS_PRIVATE(state)) / sizeof(uint32_t); i++) {
        ctx->MBEDTLS_PRIVATE(state)[i] = (i * 3) % 0x100;
    }
}

/*----------------------------------------------------------------------------*/
static void InitSha256Common(mbedtls_sha256_context *ctx, bool is_err_malloc)
{
    // Prepare mbedtls paramter
    InitMbedtlsSha256Context(ctx);

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    expect_value(mock_malloc, __size, sizeof(mbedtls_sha256_context));

    if (is_err_malloc == true) {
        will_return(mock_malloc, false); // Get NULL
        goto exit;
    }
    else {
        will_return(mock_malloc, true); // Get allocate memory
    }

    // For mbedtls_sha256_init()
    will_return(__wrap_mbedtls_sha256_init, ctx);

    // For mbedtls_sha256_starts()
    expect_memory(__wrap_mbedtls_sha256_starts, ctx, ctx, sizeof(mbedtls_sha256_context));
    expect_value(__wrap_mbedtls_sha256_starts, is224, 0);
    will_return(__wrap_mbedtls_sha256_starts, 0);

exit:
}

/*----------------------------------------------------------------------------*/
static void UpdateSha256FullySuccess(mbedtls_sha256_context *ctx, const char *input)
{
    size_t input_len = strlen(input) + 1;

    // Prepare mbedtls paramter
    InitMbedtlsSha256Context(ctx);

    // For mbedtls_sha256_update()
    will_return(__wrap_mbedtls_sha256_update, 0);
    expect_memory(__wrap_mbedtls_sha256_update, ctx, ctx, sizeof(mbedtls_sha256_context));
    expect_memory(__wrap_mbedtls_sha256_update, input, input, input_len);
    expect_value(__wrap_mbedtls_sha256_update, ilen, input_len);
}

/*----------------------------------------------------------------------------*/
static void FinishSha256FullySuccess(mbedtls_sha256_context *ctx, const char *checksum_result)
{
    // Prepare mbedtls paramter
    InitMbedtlsSha256Context(ctx);

    // For mbedtls_sha256_finish()
    will_return(__wrap_mbedtls_sha256_finish, checksum_result);
    will_return(__wrap_mbedtls_sha256_finish, 0);
    expect_memory(__wrap_mbedtls_sha256_finish, ctx, ctx, sizeof(mbedtls_sha256_context));

    // For mbedtls_sha256_free()
    expect_memory(__wrap_mbedtls_sha256_free, ctx, ctx, sizeof(mbedtls_sha256_context));

    // For free()
    will_return(mock_free, false);
}

/*----------------------------------------------------------------------------*/
static void ExtractStringValueCommon(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                     const char *jsonkey, const char *extra_string, int ret)
{
    expect_value(__wrap_SysAppCmnExtractStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractStringValue, parent_val, parent_val);
    expect_string(__wrap_SysAppCmnExtractStringValue, jsonkey, jsonkey);
    will_return(__wrap_SysAppCmnExtractStringValue, extra_string);
    will_return(__wrap_SysAppCmnExtractStringValue, ret);
}

/*----------------------------------------------------------------------------*/
static void MakeJsonStateReqInfoFullySuccess(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                             const char *req_id_val)
{
    EsfJsonValue child_val = 2468;

    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, child_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "req_id");
    expect_string(__wrap_SysAppCmnSetStringValue, string, req_id_val);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, "req_info");
    expect_value(__wrap_EsfJsonObjectSet, value, child_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
typedef enum {
    MakeJsonStateDeployTargetError_None = 0,
    MakeJsonStateDeployTargetError_Component,
    MakeJsonStateDeployTargetError_Chip,
    MakeJsonStateDeployTargetError_PackageUrl,
    MakeJsonStateDeployTargetError_Version,
    MakeJsonStateDeployTargetError_Hash,
    MakeJsonStateDeployTargetError_Size,
    MakeJsonStateDeployTargetError_Progress,
    MakeJsonStateDeployTargetError_ProcessState,
} MakeJsonStateDeployTargetErrorFlag;

static void MakeJsonStateDeployTargetCommon(DeployTarget_t *p_target, EsfJsonHandle handle_val,
                                            EsfJsonValue parent_val,
                                            MakeJsonStateDeployTargetErrorFlag err_flag)
{
    DeployComponent_e component;

    // component proterty
    switch (p_target->component) {
        case DeployComponentSensorLoader:
        case DeployComponentProcessorLoader:
            component = DeployComponentLoader;
            break;
        case DeployComponentSensorFirmware:
        case DeployComponentProcessorFirmware:
            component = DeployComponentSensorFirmware;
            break;
        default:
            component = DeployComponentNum;
            break;
    }

    if (component != DeployComponentNum) {
        expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
        expect_value(__wrap_SysAppCmnSetNumberValue, parent, parent_val);
        expect_string(__wrap_SysAppCmnSetNumberValue, key, "component");
        expect_value(__wrap_SysAppCmnSetNumberValue, number, component);

        if (err_flag == MakeJsonStateDeployTargetError_Component) {
            will_return(__wrap_SysAppCmnSetNumberValue, kRetFailed);
        }
        else {
            will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);
        }
    }

    // chip proterty
    if (p_target->chip[0] != '\0') {
        expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
        expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
        expect_string(__wrap_SysAppCmnSetStringValue, key, "chip");
        expect_string(__wrap_SysAppCmnSetStringValue, string, p_target->chip);

        if (err_flag == MakeJsonStateDeployTargetError_Chip) {
            will_return(__wrap_SysAppCmnSetStringValue, kRetFailed);
        }
        else {
            will_return(__wrap_SysAppCmnSetStringValue, kRetOk);
        }
    }

    // package_url proterty
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "package_url");
    expect_string(__wrap_SysAppCmnSetStringValue, string, p_target->package_url);

    if (err_flag == MakeJsonStateDeployTargetError_PackageUrl) {
        will_return(__wrap_SysAppCmnSetStringValue, kRetFailed);
    }
    else {
        will_return(__wrap_SysAppCmnSetStringValue, kRetOk);
    }

    // version proterty
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "version");
    expect_string(__wrap_SysAppCmnSetStringValue, string, p_target->version);

    if (err_flag == MakeJsonStateDeployTargetError_Version) {
        will_return(__wrap_SysAppCmnSetStringValue, kRetFailed);
    }
    else {
        will_return(__wrap_SysAppCmnSetStringValue, kRetOk);
    }

    // hash proterty
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "hash");
    expect_string(__wrap_SysAppCmnSetStringValue, string, p_target->hash);

    if (err_flag == MakeJsonStateDeployTargetError_Hash) {
        will_return(__wrap_SysAppCmnSetStringValue, kRetFailed);
    }
    else {
        will_return(__wrap_SysAppCmnSetStringValue, kRetOk);
    }

    // size proterty
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "size");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, p_target->size);

    if (err_flag == MakeJsonStateDeployTargetError_Size) {
        will_return(__wrap_SysAppCmnSetNumberValue, kRetFailed);
    }
    else {
        will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);
    }

    // progress proterty
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "progress");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, p_target->progress);

    if (err_flag == MakeJsonStateDeployTargetError_Progress) {
        will_return(__wrap_SysAppCmnSetNumberValue, kRetFailed);
    }
    else {
        will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);
    }

    // process_state proterty
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "process_state");

    if (err_flag == MakeJsonStateDeployTargetError_ProcessState) {
        will_return(__wrap_SysAppCmnSetStringValue, kRetFailed);
    }
    else {
        will_return(__wrap_SysAppCmnSetStringValue, kRetOk);
    }

    switch (p_target->process_state) {
        case DeployStateIdle: // included DeployStateRequestReceived which is same value as DeployStateIdle
            expect_string(__wrap_SysAppCmnSetStringValue, string, "request_received");
            break;
        case DeployStateDownloading:
            expect_string(__wrap_SysAppCmnSetStringValue, string, "downloading");
            break;
        case DeployStateInstalling:
            expect_string(__wrap_SysAppCmnSetStringValue, string, "installing");
            break;
        case DeployStateDone:
            expect_string(__wrap_SysAppCmnSetStringValue, string, "done");
            break;
        case DeployStateFailed:
        case DeployStateFailedUnavailable:
            expect_string(__wrap_SysAppCmnSetStringValue, string, "failed");
            break;
        case DeployStateFailedInvalidRequest:
            expect_string(__wrap_SysAppCmnSetStringValue, string, "failed_invalid_argument");
            break;
        case DeployStateFailedTokenExpired:
            expect_string(__wrap_SysAppCmnSetStringValue, string, "failed_token_expired");
            break;
        case DeployStateFailedDownloadRetryExceeded:
            expect_string(__wrap_SysAppCmnSetStringValue, string, "failed_download_retry_exceeded");
            break;
        default:
            // Do nothing(That is, test NG)
    }
}

/*----------------------------------------------------------------------------*/
static DeployTarget_t *SetMakeJsonStateDeployTargetParam(void)
{
    DeployTarget_t *target = NULL;

    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));

    target->component = DeployComponentSensorLoader;
    snprintf(target->chip, sizeof(target->chip), "%s", "chip test");
    snprintf(target->package_url, sizeof(target->package_url), "%s", "package_url test");
    snprintf(target->version, sizeof(target->version), "%s", "version test");
    snprintf(target->hash, sizeof(target->hash), "%s", "hash test");
    target->size = 2467;
    target->progress = 75;
    target->process_state = DeployStateDone;

exit:
    return target;
}

/*----------------------------------------------------------------------------*/
static void SetGetConfigurationDeployTargetPropertyExpectValue(DeployTarget_t *expect_value,
                                                               DeployComponent_e component,
                                                               const char *chip, const char *name)
{
    expect_value->component = component;
    snprintf(expect_value->chip, sizeof(expect_value->chip), "%s", chip);
    snprintf(expect_value->name, sizeof(expect_value->name), "%s", name);
    snprintf(expect_value->version, sizeof(expect_value->version), "%s", "123456");
    snprintf(expect_value->package_url, sizeof(expect_value->package_url), "%s",
             "https://test.pkg");
    snprintf(expect_value->hash, sizeof(expect_value->hash), "%s",
             "U34mQ9K5kQSRs25pQKwsiS+qK3uNWGvgorqSsZkM/vI=");
    expect_value->size = 1234;
}

/*----------------------------------------------------------------------------*/
static void GetConfigurationDeployTargetPropertyCommonLib(DeployTarget_t *expect_value,
                                                          EsfJsonHandle handle_val,
                                                          EsfJsonValue parent_val, int deploy_id,
                                                          EsfJsonErrorCode ret_val)
{
    EsfJsonValue child_val = 9876;

    // component property
    if (deploy_id != DeployTopicAiModel) {
        expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
        expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
        expect_string(__wrap_EsfJsonObjectGet, key, "component");
        will_return(__wrap_EsfJsonObjectGet, child_val);

        if (expect_value->component != DeployComponentNum) {
            will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

            expect_value(__wrap_EsfJsonIntegerGet, handle, handle_val);
            expect_value(__wrap_EsfJsonIntegerGet, value, child_val);
            will_return(__wrap_EsfJsonIntegerGet, expect_value->component);
            will_return(__wrap_EsfJsonIntegerGet, ret_val);
        }
        else {
            will_return(__wrap_EsfJsonObjectGet, kEsfJsonInternalError);
        }
    }

    // chip property
    ExtractStringValueCommon(handle_val, parent_val, "chip", expect_value->chip,
                             (strlen(expect_value->chip) == 0) ? 0 : 1);

    // name property
    ExtractStringValueCommon(handle_val, parent_val, "name", expect_value->name,
                             (strlen(expect_value->name) == 0) ? 0 : 1);

    // version property
    ExtractStringValueCommon(handle_val, parent_val, "version", expect_value->version,
                             (strlen(expect_value->version) == 0) ? 0 : 1);

    // package_url property
    ExtractStringValueCommon(handle_val, parent_val, "package_url", expect_value->package_url,
                             (strlen(expect_value->package_url) == 0) ? 0 : 1);

    // hash property
    ExtractStringValueCommon(handle_val, parent_val, "hash", expect_value->hash,
                             (strlen(expect_value->hash) == 0) ? 0 : 1);

    // size property
    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, "size");
    will_return(__wrap_EsfJsonObjectGet, child_val);

    if (expect_value->size >= -1) {
        will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

        expect_value(__wrap_EsfJsonIntegerGet, handle, handle_val);
        expect_value(__wrap_EsfJsonIntegerGet, value, child_val);
        will_return(__wrap_EsfJsonIntegerGet, expect_value->size);
        will_return(__wrap_EsfJsonIntegerGet, kEsfJsonSuccess);
    }
    else {
        will_return(__wrap_EsfJsonObjectGet, kEsfJsonInternalError);
    }
}

/*----------------------------------------------------------------------------*/
static void GetConfigurationDeployTargetPropertyCommon(DeployTarget_t *expect_value,
                                                       EsfJsonHandle handle_val,
                                                       EsfJsonValue parent_val, int deploy_id)
{
    GetConfigurationDeployTargetPropertyCommonLib(expect_value, handle_val, parent_val, deploy_id,
                                                  kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
typedef enum {
    MakeJsonStateDeployConfiguration_None = 0,
    MakeJsonStateDeployConfiguration_SetStringValue,
    MakeJsonStateDeployConfiguration_ArrayInit,
    MakeJsonStateDeployConfiguration_ObjectInit,
    MakeJsonStateDeployConfiguration_ArrayAppend,
    MakeJsonStateDeployConfiguration_ObjectSet,
} MakeJsonStateDeployConfigurationErrorFlag;

static void MakeJsonStateDeployConfigurationCommon(
    Deploy_t *deploy, EsfJsonHandle handle_val, EsfJsonValue parent_val,
    MakeJsonStateDeployConfigurationErrorFlag err_flag)
{
    EsfJsonValue array_val = 2468;
    EsfJsonValue child_val = 3579;
    int i;

    // mock operation for MakeJsonStateReqInfo()
    MakeJsonStateReqInfoFullySuccess(handle_val, parent_val, deploy->id);

    if (deploy->topic_id == DeployTopicFirmware) {
        // For SysAppCmnSetStringValue()
        expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
        expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
        expect_string(__wrap_SysAppCmnSetStringValue, key, "version");
        expect_string(__wrap_SysAppCmnSetStringValue, string, deploy->version);

        if (err_flag == MakeJsonStateDeployConfiguration_SetStringValue) {
            will_return(__wrap_SysAppCmnSetStringValue, kRetFailed);
        }
        else {
            will_return(__wrap_SysAppCmnSetStringValue, kRetOk);
        }
    }

    // For EsfJsonArrayInit()
    expect_value(__wrap_EsfJsonArrayInit, handle, handle_val);
    will_return(__wrap_EsfJsonArrayInit, array_val);

    if (err_flag == MakeJsonStateDeployConfiguration_ArrayInit) {
        will_return(__wrap_EsfJsonArrayInit, kEsfJsonInternalError);
    }
    else {
        will_return(__wrap_EsfJsonArrayInit, kEsfJsonSuccess);

        for (i = 0; i < deploy->deploy_target_num; i++) {
            DeployTarget_t *p_target = deploy->deploy_targets + i;

            // For EsfJsonObjectInit()
            expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
            will_return(__wrap_EsfJsonObjectInit, child_val + i);

            if (err_flag == MakeJsonStateDeployConfiguration_ObjectInit) {
                will_return(__wrap_EsfJsonObjectInit, kEsfJsonInternalError);
                break;
            }
            else {
                will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);
            }

            // mock operation for MakeJsonStateDeployTarget()
            MakeJsonStateDeployTargetCommon(p_target, handle_val, child_val + i,
                                            MakeJsonStateDeployTargetError_None);

            // For EsfJsonArrayAppend()
            expect_value(__wrap_EsfJsonArrayAppend, handle, handle_val);
            expect_value(__wrap_EsfJsonArrayAppend, parent, array_val);
            expect_value(__wrap_EsfJsonArrayAppend, value, child_val + i);

            if (err_flag == MakeJsonStateDeployConfiguration_ArrayAppend) {
                will_return(__wrap_EsfJsonArrayAppend, kEsfJsonInternalError);
                break;
            }
            else {
                will_return(__wrap_EsfJsonArrayAppend, kEsfJsonSuccess);
            }
        }

        // For EsfJsonObjectSet()
        expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
        expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
        expect_string(__wrap_EsfJsonObjectSet, key, "targets");
        expect_value(__wrap_EsfJsonObjectSet, value, array_val);

        if (err_flag == MakeJsonStateDeployConfiguration_ObjectSet) {
            will_return(__wrap_EsfJsonObjectSet, kEsfJsonInternalError);
        }
        else {
            will_return(__wrap_EsfJsonObjectSet, kEsfJsonSuccess);
        }
    }

    // For SysAppCmnSetObjectValue()
    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfoDeployConfiguration);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void CheckGetConfigurationReqInfoProperty(const char *expect_req_id,
                                                 EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                                 RetCode expect_ret_code)
{
    // For SysAppCmnGetReqId()
    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, parent_val);
    will_return(__wrap_SysAppCmnGetReqId, expect_req_id);
    will_return(__wrap_SysAppCmnGetReqId, expect_ret_code);
}

/*----------------------------------------------------------------------------*/
// Max length is DEPLOY_TARGET_MAX_NUM * sizeof(DeployTarget_t) + sizeof(Deploy_t) - 1
#define SET_EVP_STATE_REPORT_OTA_UPDATE_STATUS_MAX_OVER_STR \
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234"

#define SET_EVP_STATE_REPORT_OTA_UPDATE_STATUS_MAX_STR \
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
123"

#define ESF_JSON_SERIALIZE_OUTPUT_STR "EsfJsonSerialize Output"

typedef enum {
    SetEvpStateReportOtaUpdateStatus_None = 0,
    SetEvpStateReportOtaUpdateStatus_JsonOpen,
    SetEvpStateReportOtaUpdateStatus_ObjectInit,
    SetEvpStateReportOtaUpdateStatus_JsonSerializeNullStr,
    SetEvpStateReportOtaUpdateStatus_JsonSerializeMaxOverStr,
    SetEvpStateReportOtaUpdateStatus_JsonSerializeMaxStr,
    SetEvpStateReportOtaUpdateStatus_JsonSerializeReturn,
    SetEvpStateReportOtaUpdateStatus_PthreadMutexLock,
    SetEvpStateReportOtaUpdateStatus_Realloc,
    SetEvpStateReportOtaUpdateStatus_SendState,
} SetEvpStateReportOtaUpdateStatusErrorFlag;

static void SetEvpStateReportOtaUpdateStatusCommon(
    DeployInitParams_t *init_param, SetEvpStateReportOtaUpdateStatusErrorFlag err_flag)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    int req_id;

    // For EsfJsonOpen()
    if (err_flag == SetEvpStateReportOtaUpdateStatus_JsonOpen) {
        will_return(__wrap_EsfJsonOpen, ESF_JSON_HANDLE_INITIALIZER);
        will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);
        goto exit;
    }
    else {
        will_return(__wrap_EsfJsonOpen, handle_val);
        will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);
    }

    // For EsfJsonObjectInit()
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    if (err_flag == SetEvpStateReportOtaUpdateStatus_ObjectInit) {
        will_return(__wrap_EsfJsonObjectInit, kEsfJsonInternalError);
        goto exit;
    }
    else {
        will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);
    }

    // mock operation for MakeJsonStateDeployConfiguration()
    MakeJsonStateDeployConfigurationCommon(&init_param->deploy, handle_val, parent_val,
                                           MakeJsonStateDeployConfiguration_None);

    // For EsfJsonSerialize()
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    if (err_flag == SetEvpStateReportOtaUpdateStatus_JsonSerializeNullStr) {
        will_return(__wrap_EsfJsonSerialize, "");
    }
    else if (err_flag == SetEvpStateReportOtaUpdateStatus_JsonSerializeMaxOverStr) {
        will_return(__wrap_EsfJsonSerialize, SET_EVP_STATE_REPORT_OTA_UPDATE_STATUS_MAX_OVER_STR);
    }
    else if (err_flag == SetEvpStateReportOtaUpdateStatus_JsonSerializeMaxStr) {
        will_return(__wrap_EsfJsonSerialize, SET_EVP_STATE_REPORT_OTA_UPDATE_STATUS_MAX_STR);
    }
    else {
        will_return(__wrap_EsfJsonSerialize, ESF_JSON_SERIALIZE_OUTPUT_STR);
    }
    if (err_flag == SetEvpStateReportOtaUpdateStatus_JsonSerializeReturn) {
        will_return(__wrap_EsfJsonSerialize, kEsfJsonInternalError);
    }
    else {
        will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);
    }

    if ((err_flag == SetEvpStateReportOtaUpdateStatus_JsonSerializeNullStr) ||
        (err_flag == SetEvpStateReportOtaUpdateStatus_JsonSerializeReturn)) {
        goto exit;
    }

    // Select req_id
    switch (init_param->deploy.topic_id) {
        case DeployTopicFirmware:
            req_id = ST_TOPIC_DEPLOY_FIRMWARE;
            break;
        case DeployTopicAiModel:
            req_id = ST_TOPIC_DEPLOY_AI_MODEL;
            break;
        case DeployTopicCameraSetup:
            req_id = ST_TOPIC_DEPLOY_SENSOR_CALIBRATION_PARAM;
            break;
        default:
            goto exit;
    }

    // For max length
    if (err_flag == SetEvpStateReportOtaUpdateStatus_JsonSerializeMaxOverStr ||
        err_flag == SetEvpStateReportOtaUpdateStatus_JsonSerializeMaxStr) {
        goto exit;
    }

    // For pthread_mutex_lock()
    // expect_value(__wrap_pthread_mutex_lock, mutex, &init_param->state_mutex);
    if (err_flag == SetEvpStateReportOtaUpdateStatus_PthreadMutexLock) {
        will_return(__wrap_pthread_mutex_lock, -1);
        goto exit;
    }
    else {
        will_return(__wrap_pthread_mutex_lock, 0);
    }

    // For realloc()
    will_return(mock_realloc, false); // Not exec parameter check
    if (err_flag == SetEvpStateReportOtaUpdateStatus_Realloc) {
        will_return(mock_realloc, false); // Get NULL

        if (init_param->state_str[init_param->deploy.topic_id] != NULL) {
            // For free()
            will_return(mock_free, true); // Exec parameter check
            expect_value(mock_free, __ptr, init_param->state_str[init_param->deploy.topic_id]);
        }
    }
    else {
        will_return(mock_realloc, true); // Get allocate memory
    }

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);
    // expect_value(__wrap_pthread_mutex_unlock, mutex, &init_param->state_mutex);

    // For SysAppStateSendState()
    if (err_flag != SetEvpStateReportOtaUpdateStatus_Realloc) {
        expect_value(__wrap_SysAppStateSendState, req, req_id);
        if (err_flag == SetEvpStateReportOtaUpdateStatus_SendState) {
            will_return(__wrap_SysAppStateSendState, kRetFailed);
        }
        else {
            will_return(__wrap_SysAppStateSendState, kRetOk);
        }
    }

exit:
    if (err_flag != SetEvpStateReportOtaUpdateStatus_JsonOpen) {
        // For EsfJsonSerializeFree()
        expect_value(__wrap_EsfJsonSerializeFree, handle, handle_val);
        will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

        // For EsfJsonClose()
        expect_value(__wrap_EsfJsonClose, handle, handle_val);
        will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
    }
}

/*----------------------------------------------------------------------------*/
static const char *firmware_update_open_base64_decoded_data = "hash decoded test";

typedef enum {
    FirmwareUpdateOpenCommon_None = 0,
    FirmwareUpdateOpenCommon_Base64Decode,
    FirmwareUpdateOpenCommon_EsfFwMgrOpen,
} FirmwareUpdateOpenCommonErrorFlag;

static void FirmwareUpdateOpenCommon(DeployInitParams_t *init_param, DeployTarget_t *target,
                                     size_t size, bool is_exec_open,
                                     EsfFwMgrOpenResponse *fw_mgr_open_res, int retry_cnt,
                                     FirmwareUpdateOpenCommonErrorFlag err_flag)
{
    int i;
    bool is_need_send_state_2nd = false;
    DeployState_e currect_state = target->process_state;

    if (target->hash[0] != '\0') {
        // For EsfCodecBase64Decode()
        expect_string(__wrap_EsfCodecBase64Decode, in, target->hash);
        expect_value(__wrap_EsfCodecBase64Decode, in_size, DEPLOY_STR_HASH_LEN);
        will_return(__wrap_EsfCodecBase64Decode, true);
        will_return(__wrap_EsfCodecBase64Decode, firmware_update_open_base64_decoded_data);
        will_return(__wrap_EsfCodecBase64Decode,
                    strlen(firmware_update_open_base64_decoded_data) + 1);

        if (err_flag == FirmwareUpdateOpenCommon_Base64Decode) {
            will_return(__wrap_EsfCodecBase64Decode, kEsfCodecBase64ResultInternalError);
            goto exit;
        }
        else {
            will_return(__wrap_EsfCodecBase64Decode, kEsfCodecBase64ResultSuccess);
        }
    }

    for (i = 0; (i <= retry_cnt) && (i < MAX_NUMBER_OF_UPDATE_OPEN_RETRY); i++) {
        // For SysAppUdIsThisRequestToStopForDownload()
        will_return(__wrap_SysAppUdIsThisRequestToStopForDownload,
                    (is_exec_open == true) ? false : true);

        if (is_exec_open == false) {
            break;
        }
        else {
            // For EsfFwMgrOpen()
            will_return(__wrap_EsfFwMgrOpen, fw_mgr_open_res->handle);
            will_return(__wrap_EsfFwMgrOpen, fw_mgr_open_res->prepare_write.memory_size);
            will_return(__wrap_EsfFwMgrOpen, fw_mgr_open_res->prepare_write.writable_size);
            if ((retry_cnt == 0) || (i == retry_cnt)) {
                if (err_flag == FirmwareUpdateOpenCommon_EsfFwMgrOpen) {
                    will_return(__wrap_EsfFwMgrOpen, kEsfFwMgrResultInternal);

                    // For UtilityLogWriteELog()
                    expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
                    expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelError);
                    expect_value(__wrap_UtilityLogWriteELog, event_id, ELOG_EVENT_ID_OTA_FAILED);
                    will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);
                }
                else {
                    will_return(__wrap_EsfFwMgrOpen, kEsfFwMgrResultOk);
                }
            }
            else {
                will_return(__wrap_EsfFwMgrOpen, kEsfFwMgrResultUnavailable);

                // For SysAppStaClose()
                will_return(__wrap_SysAppStaClose, kRetOk);

                if (i == 1) {
                    // mock operation for SetEvpStateReportOtaUpdateStatus()
                    target->progress = 0;
                    target->process_state = DeployStateFailedUnavailable;
                    SetEvpStateReportOtaUpdateStatusCommon(init_param,
                                                           SetEvpStateReportOtaUpdateStatus_None);

                    is_need_send_state_2nd = true;

                    // For SysAppLedSetAppStatus()
                    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
                    expect_value(__wrap_SysAppLedSetAppStatus, app_state,
                                 LedAppStatusErrorDownloadFailed);
                }
            }
        }
    }

    if (is_need_send_state_2nd == true) {
        // mock operation for SetEvpStateReportOtaUpdateStatus()
        target->progress = 0;
        if (retry_cnt >= MAX_NUMBER_OF_UPDATE_OPEN_RETRY) {
            target->process_state = DeployStateFailed;
        }
        else {
            target->process_state = currect_state;
        }
        SetEvpStateReportOtaUpdateStatusCommon(init_param, SetEvpStateReportOtaUpdateStatus_None);

        // For SysAppLedSetAppStatus()
        expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
        expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDownloadFailed);
    }

exit:
}

/*----------------------------------------------------------------------------*/
static const EsfFwMgrGetInfoResponse comp_one_target_esf_fw_mgr_get_info_res = {
    .version = "version test",
    .last_update = "20240115",
    .hash = "1234567890123456789012345678901",
};
static const char *comp_one_target_not_match_hash = "2345678901234567890123456789012";

typedef enum {
    CompareDeployingVersionWithDeployedOneTarget_None = 0,
    CompareDeployingVersionWithDeployedOneTarget_GetInfo,
    CompareDeployingVersionWithDeployedOneTarget_Base64Decode,
} CompareDeployingVersionWithDeployedOneTargetErrorFlag;

static void CompareDeployingVersionWithDeployedOneTargetCommon(
    DeployTarget_t *target, bool is_same_hash,
    CompareDeployingVersionWithDeployedOneTargetErrorFlag err_flag)
{
    char *output_hash;

    if (is_same_hash == true) {
        output_hash = (char *)comp_one_target_esf_fw_mgr_get_info_res.hash;
    }
    else {
        output_hash = (char *)comp_one_target_not_match_hash;
    }

    // For EsfFwMgrGetInfo()
    will_return(__wrap_EsfFwMgrGetInfo, &comp_one_target_esf_fw_mgr_get_info_res);
    if (err_flag == CompareDeployingVersionWithDeployedOneTarget_GetInfo) {
        will_return(__wrap_EsfFwMgrGetInfo, kEsfFwMgrResultInternal);

        // For UtilityLogWriteELog()
        expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
        expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelError);
        expect_value(__wrap_UtilityLogWriteELog, event_id, ELOG_EVENT_ID_OTA_FAILED);
        will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);

        goto exit;
    }
    else {
        will_return(__wrap_EsfFwMgrGetInfo, kEsfFwMgrResultOk);
    }

    // For EsfCodecBase64Decode()
    expect_string(__wrap_EsfCodecBase64Decode, in, target->hash);
    expect_value(__wrap_EsfCodecBase64Decode, in_size, DEPLOY_STR_HASH_LEN);
    will_return(__wrap_EsfCodecBase64Decode, true);
    will_return(__wrap_EsfCodecBase64Decode, output_hash);
    will_return(__wrap_EsfCodecBase64Decode, sizeof(comp_one_target_esf_fw_mgr_get_info_res.hash));
    if (err_flag == CompareDeployingVersionWithDeployedOneTarget_Base64Decode) {
        will_return(__wrap_EsfCodecBase64Decode, kEsfCodecBase64ResultInternalError);
        goto exit;
    }
    else {
        will_return(__wrap_EsfCodecBase64Decode, kEsfCodecBase64ResultSuccess);
    }

exit:
}

/*----------------------------------------------------------------------------*/
static const EsfFwMgrGetInfoResponse comp_ai_model_esf_fw_mgr_get_info_res = {
    .version = "version test",
    .last_update = "20240115",
    .hash = "1234567890123456789012345678901",
};

static const EsfFwMgrGetInfoResponse comp_ai_model_diff_esf_fw_mgr_get_info_res = {
    .version = "version test2",
    .last_update = "20240115",
    .hash = "1234567890123456789012345678901",
};

static const EsfFwMgrGetInfoResponse comp_ai_model_diff_full_slot_esf_fw_mgr_get_info_res[4] = {
    {.version = "version test2",
     .last_update = "20240115",
     .hash = "1234567890123456789012345678901"},
    {.version = "version test2",
     .last_update = "20240115",
     .hash = "1234567890123456789012345678901"},
    {.version = "version test2",
     .last_update = "20240115",
     .hash = "1234567890123456789012345678901"},
    {.version = "version test2",
     .last_update = "20240115",
     .hash = "1234567890123456789012345678901"},
};

typedef enum {
    CompareDeployingVersionWithDeployedAiModel_None = 0,
    CompareDeployingVersionWithDeployedAiModel_MallocNull,
    CompareDeployingVersionWithDeployedAiModel_GetInfo,
    CompareDeployingVersionWithDeployedAiModel_Base64Decode,
    CompareDeployingVersionWithDeployedAiModel_DiffVersion,
    CompareDeployingVersionWithDeployedAiModel_SlotFull,
} CompareDeployingVersionWithDeployedAiModelErrorFlag;

static void CompareDeployingVersionWithDeployedAiModelCommon(
    DeployTarget_t *target, CompareDeployingVersionWithDeployedAiModelErrorFlag err_flag)
{
    char *output_hash;

    // Fixed value for Test only
    output_hash = (char *)comp_ai_model_esf_fw_mgr_get_info_res.hash;

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    expect_value(mock_malloc, __size,
                 sizeof(EsfFwMgrGetInfoResponse) * ESF_FIRMWARE_MANAGER_AI_MODEL_SLOT_NUM);
    if (err_flag == CompareDeployingVersionWithDeployedAiModel_MallocNull) {
        will_return(mock_malloc, false); // Get NULL
        goto exit;
    }
    else {
        will_return(mock_malloc, true); // Get allocate memory
    }

    // For EsfFwMgrGetInfo()
    if (err_flag == CompareDeployingVersionWithDeployedAiModel_DiffVersion) {
        will_return(__wrap_EsfFwMgrGetInfo, &comp_ai_model_diff_esf_fw_mgr_get_info_res);
    }
    else if (err_flag == CompareDeployingVersionWithDeployedAiModel_SlotFull) {
        will_return(__wrap_EsfFwMgrGetInfo, &comp_ai_model_diff_full_slot_esf_fw_mgr_get_info_res);
    }
    else {
        will_return(__wrap_EsfFwMgrGetInfo, &comp_ai_model_esf_fw_mgr_get_info_res);
    }

    if (err_flag == CompareDeployingVersionWithDeployedAiModel_GetInfo) {
        will_return(__wrap_EsfFwMgrGetInfo, kEsfFwMgrResultInternal);

        // For UtilityLogWriteELog()
        expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
        expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelError);
        expect_value(__wrap_UtilityLogWriteELog, event_id, ELOG_EVENT_ID_OTA_FAILED);
        will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);

        goto free;
    }
    else {
        will_return(__wrap_EsfFwMgrGetInfo, kEsfFwMgrResultOk);
    }

    // For EsfCodecBase64Decode()
    expect_string(__wrap_EsfCodecBase64Decode, in, target->hash);
    expect_value(__wrap_EsfCodecBase64Decode, in_size, DEPLOY_STR_HASH_LEN);
    will_return(__wrap_EsfCodecBase64Decode, true);
    will_return(__wrap_EsfCodecBase64Decode, output_hash);
    will_return(__wrap_EsfCodecBase64Decode,
                sizeof(comp_ai_model_esf_fw_mgr_get_info_res.hash) + 1);
    if (err_flag == CompareDeployingVersionWithDeployedAiModel_Base64Decode) {
        will_return(__wrap_EsfCodecBase64Decode, kEsfCodecBase64ResultInternalError);
        goto free;
    }
    else {
        will_return(__wrap_EsfCodecBase64Decode, kEsfCodecBase64ResultSuccess);
    }

free:
    // For free()
    will_return(mock_free, false); // Not exec parameter check

exit:
}

/*----------------------------------------------------------------------------*/
typedef enum {
    CheckVersion_NeedDeploy = 0,
    CheckVersion_NotNeedDeploy,
    CheckVersion_Error,
} CheckVersionReturnType;

static void CheckVersionCommon(DeployTarget_t *target, CheckVersionReturnType return_type)
{
    bool is_same_hash;
    CompareDeployingVersionWithDeployedOneTargetErrorFlag other_err_flag;
    CompareDeployingVersionWithDeployedAiModelErrorFlag ai_model_err_flag;

    switch (target->component) {
        case DeployComponentSensorLoader:
        case DeployComponentSensorFirmware:
        case DeployComponentProcessorLoader:
        case DeployComponentProcessorFirmware:
        case DeployComponentSensorCalibrationParam:
            switch (return_type) {
                case CheckVersion_NeedDeploy:
                    is_same_hash = false;
                    other_err_flag = CompareDeployingVersionWithDeployedOneTarget_None;
                    break;
                case CheckVersion_NotNeedDeploy:
                    is_same_hash = true;
                    other_err_flag = CompareDeployingVersionWithDeployedOneTarget_None;
                    break;
                case CheckVersion_Error:
                default:
                    is_same_hash = true;
                    other_err_flag = CompareDeployingVersionWithDeployedOneTarget_GetInfo;
                    break;
            }
            CompareDeployingVersionWithDeployedOneTargetCommon(target, is_same_hash,
                                                               other_err_flag);
            break;

        case DeployComponentAiModel:
            switch (return_type) {
                case CheckVersion_NeedDeploy:
                    ai_model_err_flag = CompareDeployingVersionWithDeployedAiModel_DiffVersion;
                    break;
                case CheckVersion_NotNeedDeploy:
                    ai_model_err_flag = CompareDeployingVersionWithDeployedAiModel_None;
                    break;
                case CheckVersion_Error:
                default:
                    ai_model_err_flag = CompareDeployingVersionWithDeployedAiModel_GetInfo;
                    break;
            }
            CompareDeployingVersionWithDeployedAiModelCommon(target, ai_model_err_flag);
            break;

        default:
            // Do Nothing
            break;
    }
}

/*----------------------------------------------------------------------------*/
static const char *not_match_hash_strings = "Not Match Hash";

typedef enum {
    FirmwareUpdateCommon_None = 0,
    FirmwareUpdateCommon_GetImageSize403,
    FirmwareUpdateCommon_GetImageSizeOther,
    FirmwareUpdateCommon_GetImageSizeBadParams,
    FirmwareUpdateCommon_FirmwareUpdateOpen,
    FirmwareUpdateCommon_UpdateMemorySize,
    FirmwareUpdateCommon_FinishSha256,
    FirmwareUpdateCommon_NotMatchHash,
    FirmwareUpdateCommon_FwMgrPostProcess,
    FirmwareUpdateCommon_GetImage403,
    FirmwareUpdateCommon_GetImageBadParams,
    FirmwareUpdateCommon_GetImageRetryOver,
    FirmwareUpdateCommon_RequestStop,
    FirmwareUpdateCommon_RequestStopInWaitingForRetry,
    FirmwareUpdateCommon_FwMgrWrite,
    FirmwareUpdateCommon_FwMgrClose,
    FirmwareUpdateCommon_FwMgrGetBinaryHeaderInfo,
    FirmwareUpdateCommon_GetImageRetryAndSha256Null,
} FirmwareUpdateErrorFlag;

static void FirmwareUpdateCommon(DeployInitParams_t *init_param, DeployTarget_t *target,
                                 int download_cnt, mbedtls_sha256_context *sha256_ctx,
                                 FirmwareUpdateErrorFlag err_flag)
{
    EsfFwMgrOpenResponse fw_mgr_open_res = {.handle = (EsfFwMgrHandle)1234,
                                            .prepare_write.memory_size = 2345,
                                            .prepare_write.writable_size = 3456};
    size_t download_size = 4567;
    size_t target_size;
    FirmwareUpdateOpenCommonErrorFlag firmware_update_open_err_flag = FirmwareUpdateOpenCommon_None;
    int i;
    EsfFwMgrSwArchVersion sw_arch_version = kEsfFwMgrSwArchVersion2;

    // mock operation for SetEvpStateReportOtaUpdateStatus()
    target->progress = 0;
    target->process_state = DeployStateIdle;
    SetEvpStateReportOtaUpdateStatusCommon(init_param, SetEvpStateReportOtaUpdateStatus_None);

    if ((target->component == DeployComponentProcessorLoader) ||
        (target->component == DeployComponentProcessorFirmware)) {
        if (target->size <= 0) {
            // For SysAppUdGetImageSize()
            if (err_flag == FirmwareUpdateCommon_GetImageSize403) {
                will_return(__wrap_SysAppUdGetImageSize, 403);
                will_return(__wrap_SysAppUdGetImageSize, 0);
                goto exit;
            }
            else if (err_flag == FirmwareUpdateCommon_GetImageSizeOther) {
                will_return(__wrap_SysAppUdGetImageSize, 500);
                will_return(__wrap_SysAppUdGetImageSize, 0);
                goto exit;
            }
            else if (err_flag == FirmwareUpdateCommon_GetImageSizeBadParams) {
                will_return(__wrap_SysAppUdGetImageSize, -1);
                will_return(__wrap_SysAppUdGetImageSize, 0);
                goto exit;
            }
            else {
                will_return(__wrap_SysAppUdGetImageSize, 0);
                will_return(__wrap_SysAppUdGetImageSize, download_size);
            }
            target_size = download_size;
        }
        else {
            target_size = target->size;
        }
    }

    // mock operation for FirmwareUpdateOpen()
    if (err_flag == FirmwareUpdateCommon_FirmwareUpdateOpen) {
        firmware_update_open_err_flag = FirmwareUpdateOpenCommon_Base64Decode;
    }
    else if (err_flag == FirmwareUpdateCommon_UpdateMemorySize) {
        fw_mgr_open_res.prepare_write.memory_size = 0;
    }

    FirmwareUpdateOpenCommon(init_param, target, target_size, true, &fw_mgr_open_res, 0,
                             firmware_update_open_err_flag);

    if (err_flag == FirmwareUpdateCommon_FirmwareUpdateOpen) {
        goto exit;
    }
    else if (err_flag == FirmwareUpdateCommon_UpdateMemorySize) {
        goto close_exit;
    }

    // mock operation for SetEvpStateReportOtaUpdateStatus()
    target->progress = 25;
    target->process_state = DeployStateDownloading;
    SetEvpStateReportOtaUpdateStatusCommon(init_param, SetEvpStateReportOtaUpdateStatus_None);

    // mock operation for InitSha256()
    if (err_flag == FirmwareUpdateCommon_FinishSha256 ||
        err_flag == FirmwareUpdateCommon_GetImageRetryAndSha256Null) {
        InitSha256Common(sha256_ctx, true);
    }
    else {
        InitSha256Common(sha256_ctx, false);
    }

    if (err_flag == FirmwareUpdateCommon_GetImage403) {
        // For SysAppUdGetImageData()
        will_return(__wrap_SysAppUdGetImageData, 403);
        will_return(__wrap_SysAppUdGetImageData, -1);
        goto header_info_exit;
    }
    else if (err_flag == FirmwareUpdateCommon_GetImageBadParams) {
        // For SysAppUdGetImageData()
        will_return(__wrap_SysAppUdGetImageData, -1);
        will_return(__wrap_SysAppUdGetImageData, -1);
        goto header_info_exit;
    }
    else if (err_flag == FirmwareUpdateCommon_GetImageRetryOver ||
             err_flag == FirmwareUpdateCommon_GetImageRetryAndSha256Null) {
        for (i = 1; i <= (MAX_NUMBER_OF_UPDATE_RETRY + 1); i++) {
            // For SysAppUdGetImageData()
            will_return(__wrap_SysAppUdGetImageData, 500);
            will_return(__wrap_SysAppUdGetImageData, -1);

            if (i != (MAX_NUMBER_OF_UPDATE_RETRY + 1)) {
                // For SysAppUdIsThisRequestToStopForDownload()
                will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, false);

                int wait_interval = (1 << (i - 1));

                if (wait_interval > MAX_NUMBER_OF_UPDATE_RETRY_INTERVAL_TIME_SEC) {
                    wait_interval = MAX_NUMBER_OF_UPDATE_RETRY_INTERVAL_TIME_SEC;
                }

                for (int j = 0; j < wait_interval; j++) {
                    // For SysAppUdIsThisRequestToStopForDownload()
                    will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, false);
                }
            }
        }

        // For UtilityLogWriteELog()
        expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
        expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelError);
        expect_value(__wrap_UtilityLogWriteELog, event_id, ELOG_EVENT_ID_DOWNLOAD_FAILED);
        will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);

        if (err_flag == FirmwareUpdateCommon_GetImageRetryOver) {
            // mock operation for FinishSha256()
            FinishSha256FullySuccess(sha256_ctx, target->hash);
        }

        goto header_info_exit;
    }
    else if (err_flag == FirmwareUpdateCommon_RequestStop) {
        // For SysAppUdGetImageData()
        will_return(__wrap_SysAppUdGetImageData, 500);
        will_return(__wrap_SysAppUdGetImageData, -1);

        // For SysAppUdIsThisRequestToStopForDownload()
        will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, true);

        // For UtilityLogWriteELog()
        expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
        expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelError);
        expect_value(__wrap_UtilityLogWriteELog, event_id, ELOG_EVENT_ID_DOWNLOAD_FAILED);
        will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);

        // mock operation for FinishSha256
        FinishSha256FullySuccess(sha256_ctx, target->hash);

        goto header_info_exit;
    }
    else if (err_flag == FirmwareUpdateCommon_RequestStopInWaitingForRetry) {
        // For SysAppUdGetImageData()
        will_return(__wrap_SysAppUdGetImageData, 500);
        will_return(__wrap_SysAppUdGetImageData, -1);

        // For SysAppUdIsThisRequestToStopForDownload()
        will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, false);

        // For SysAppUdIsThisRequestToStopForDownload()
        will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, true);

        goto header_info_exit;
    }
    else {
        for (i = 1; i <= download_cnt; i++) {
            // For SysAppUdGetImageData()
            will_return(__wrap_SysAppUdGetImageData, 0);
            if (i == download_cnt) {
                will_return(__wrap_SysAppUdGetImageData, 0);

                if (err_flag != FirmwareUpdateCommon_FinishSha256) {
                    // mock operation for FinishSha256
                    FinishSha256FullySuccess(sha256_ctx, target->hash);

                    // For EsfCodecBase64Encode()
                    expect_not_value(__wrap_EsfCodecBase64Encode, in, NULL);
                    expect_value(__wrap_EsfCodecBase64Encode, in_size,
                                 64 / 2); // "64" means number of SHA-256 digits
                                          // "2" means number of uint8_t hex digits
                    if (err_flag == FirmwareUpdateCommon_NotMatchHash) {
                        will_return(__wrap_EsfCodecBase64Encode, not_match_hash_strings);
                    }
                    else {
                        will_return(__wrap_EsfCodecBase64Encode, target->hash);
                    }
                    will_return(__wrap_EsfCodecBase64Encode, sizeof(target->hash));
                    will_return(__wrap_EsfCodecBase64Encode, kEsfCodecBase64ResultSuccess);
                    if (err_flag == FirmwareUpdateCommon_NotMatchHash) {
                        goto close_exit;
                    }
                }

                // mock operation for SetEvpStateReportOtaUpdateStatus()
                target->progress = 75;
                target->process_state = DeployStateInstalling;
                SetEvpStateReportOtaUpdateStatusCommon(init_param,
                                                       SetEvpStateReportOtaUpdateStatus_None);

                // For EsfFwMgrPostProcess()
                if (err_flag == FirmwareUpdateCommon_FwMgrPostProcess) {
                    will_return(__wrap_EsfFwMgrPostProcess, kEsfFwMgrResultInternal);

                    // For UtilityLogWriteELog()
                    expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
                    expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelError);
                    expect_value(__wrap_UtilityLogWriteELog, event_id, ELOG_EVENT_ID_OTA_FAILED);
                    will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);

                    goto close_exit;
                }
                else {
                    will_return(__wrap_EsfFwMgrPostProcess, kEsfFwMgrResultOk);
                }
            }
            else {
                will_return(__wrap_SysAppUdGetImageData, 1);

                // For EsfFwMgrWrite()
                if (err_flag == FirmwareUpdateCommon_FwMgrWrite) {
                    will_return(__wrap_EsfFwMgrWrite, kEsfFwMgrResultInternal);

                    // For UtilityLogWriteELog()
                    expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
                    expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelError);
                    expect_value(__wrap_UtilityLogWriteELog, event_id, ELOG_EVENT_ID_OTA_FAILED);
                    will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);

                    break;
                }
                else {
                    will_return(__wrap_EsfFwMgrWrite, kEsfFwMgrResultOk);
                }

                // mock operation for SetEvpStateReportOtaUpdateStatus()
                target->progress = 50;
                target->process_state = DeployStateDownloading;
                SetEvpStateReportOtaUpdateStatusCommon(init_param,
                                                       SetEvpStateReportOtaUpdateStatus_None);
            }
        }
    }

header_info_exit:
    // For EsfFwMgrGetBinaryHeaderInfo()
    will_return(__wrap_EsfFwMgrGetBinaryHeaderInfo, sw_arch_version);
    if (err_flag == FirmwareUpdateCommon_FwMgrGetBinaryHeaderInfo) {
        will_return(__wrap_EsfFwMgrGetBinaryHeaderInfo, kEsfFwMgrResultInternal);
    }
    else {
        will_return(__wrap_EsfFwMgrGetBinaryHeaderInfo, kEsfFwMgrResultOk);
    }

close_exit:
    // For EsfFwMgrClose()
    if (err_flag == FirmwareUpdateCommon_FwMgrClose) {
        will_return(__wrap_EsfFwMgrClose, kEsfFwMgrResultInternal);

        // For UtilityLogWriteELog()
        expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
        expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelError);
        expect_value(__wrap_UtilityLogWriteELog, event_id, ELOG_EVENT_ID_OTA_FAILED);
        will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);
    }
    else {
        will_return(__wrap_EsfFwMgrClose, kEsfFwMgrResultOk);
    }

exit:
}

/*----------------------------------------------------------------------------*/
static const char *chk_config_deploy_version = "V00112233";
static const char *system_app_cmn_get_req_id = "No.555";

static void CheckGetConfigurationDeployConfigurationProperty(
    Deploy_t *deploy, EsfJsonHandle expect_esf_handle, EsfJsonValue expect_esf_pare_val,
    int topic_id, DeployTarget_t *expect_value, ssize_t array_cnt)
{
    RetCode expect_ret_code = kRetOk;
    EsfJsonValue expect_esf_child_val = 2468;
    EsfJsonValueType expect_val_type = kEsfJsonValueTypeArray;
    EsfJsonValue expect_subval = 1122;

    CheckGetConfigurationReqInfoProperty(system_app_cmn_get_req_id, expect_esf_handle,
                                         expect_esf_pare_val, expect_ret_code);

    ExtractStringValueCommon(expect_esf_handle, expect_esf_pare_val, "version",
                             chk_config_deploy_version, 1);

    // targets property
    expect_value(__wrap_EsfJsonObjectGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, expect_esf_pare_val);
    expect_string(__wrap_EsfJsonObjectGet, key, "targets");
    will_return(__wrap_EsfJsonObjectGet, expect_esf_child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // value type
    expect_value(__wrap_EsfJsonValueTypeGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, expect_esf_child_val);
    will_return(__wrap_EsfJsonValueTypeGet, expect_val_type);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // array count
    expect_value(__wrap_EsfJsonArrayCount, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonArrayCount, parent, expect_esf_child_val);
    will_return(__wrap_EsfJsonArrayCount, array_cnt);

    // Reset array_cnt for test
    if (array_cnt > DEPLOY_TARGET_MAX_NUM) {
        array_cnt = DEPLOY_TARGET_MAX_NUM;
    }

    if (array_cnt > 0) {
        // For malloc()
        will_return(mock_malloc, true); // Exec parameter check
        will_return(mock_malloc, true); // Get allocate memory
        expect_value(mock_malloc, __size, sizeof(DeployTarget_t) * array_cnt);

        for (int i = 0; i < array_cnt; i++) {
            // get array
            expect_value(__wrap_EsfJsonArrayGet, handle, expect_esf_handle);
            expect_value(__wrap_EsfJsonArrayGet, parent, expect_esf_child_val);
            expect_value(__wrap_EsfJsonArrayGet, index, i);
            will_return(__wrap_EsfJsonArrayGet, expect_subval);
            will_return(__wrap_EsfJsonArrayGet, kEsfJsonSuccess);

            // mock operation for GetConfigurationDeployTargetProperty()
            GetConfigurationDeployTargetPropertyCommon(expect_value, expect_esf_handle,
                                                       expect_subval, topic_id);
        }
    }
}

/*----------------------------------------------------------------------------*/
static void CheckParseConfiguration(Deploy_t *deploy, DeployTarget_t *expect_value,
                                    ssize_t array_cnt, int topic_id, const char *expect_param)
{
    EsfJsonHandle expect_esf_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue expect_esf_pare_val = 1357;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, expect_esf_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // For EsfJsonDeserialize()
    expect_value(__wrap_EsfJsonDeserialize, handle, expect_esf_handle);
    expect_string(__wrap_EsfJsonDeserialize, str, expect_param);
    will_return(__wrap_EsfJsonDeserialize, expect_esf_pare_val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // Check GetConfigurationDeployConfigurationProperty()
    CheckGetConfigurationDeployConfigurationProperty(deploy, expect_esf_handle, expect_esf_pare_val,
                                                     topic_id, expect_value, array_cnt);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, expect_esf_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
typedef enum {
    StartDeploy_AlreadyDeploy = 0,
    StartDeploy_ExecDeploy,
    StartDeploy_ErrorCheckVersion,
    StartDeploy_Other,
} StartDeployDeployBehavior;

static void StartDeployCommon(DeployInitParams_t *init_param, mbedtls_sha256_context *sha256_ctx,
                              StartDeployDeployBehavior behavior)
{
    Deploy_t *deploy = &init_param->deploy;
    DeployTarget_t *target;

    // For UtilityLogWriteELog()
    expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
    expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelInfo);
    expect_value(__wrap_UtilityLogWriteELog, event_id, ELOG_EVENT_ID_START_OTA);
    will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);

    for (int i = 0; i < deploy->deploy_target_num; i++) {
        target = deploy->deploy_targets + i;

        if (target->parse_state != DeployStateIdle) {
            // mock operation for SetEvpStateReportOtaUpdateStatus()
            target->progress = 0;
            target->process_state = target->parse_state;
            SetEvpStateReportOtaUpdateStatusCommon(init_param,
                                                   SetEvpStateReportOtaUpdateStatus_None);
        }
        else {
            if (behavior == StartDeploy_AlreadyDeploy) {
                // mock operation for CheckVersion()
                CheckVersionCommon(target, CheckVersion_NotNeedDeploy);

                // mock operation for SetEvpStateReportOtaUpdateStatus()
                target->progress = 100;
                target->process_state = DeployStateDone;
                SetEvpStateReportOtaUpdateStatusCommon(init_param,
                                                       SetEvpStateReportOtaUpdateStatus_None);
            }
            else if (behavior == StartDeploy_ExecDeploy) {
                // mock operation for CheckVersion()
                CheckVersionCommon(target, CheckVersion_NeedDeploy);

                // mock operation for CheckVersion()
                FirmwareUpdateCommon(init_param, target, 1, sha256_ctx, FirmwareUpdateCommon_None);
            }
            else if (behavior == StartDeploy_ErrorCheckVersion) {
                // mock operation for CheckVersion()
                CheckVersionCommon(target, CheckVersion_Error);

                // mock operation for SetEvpStateReportOtaUpdateStatus()
                target->progress = 0;
                target->process_state = DeployStateFailed;
                SetEvpStateReportOtaUpdateStatusCommon(init_param,
                                                       SetEvpStateReportOtaUpdateStatus_None);
            }
            else {
                // Do Nothing
            }
        }
    }

    // For SysAppStaReopenIfClose()
    will_return(__wrap_SysAppStaReopenIfClose, kRetOk);

    // For SysAppStateSendState()
    expect_value(__wrap_SysAppStateSendState, req, ST_TOPIC_UPDATE_DEVICE_INFO);
    will_return(__wrap_SysAppStateSendState, kRetOk);
}

/*----------------------------------------------------------------------------*/

//
// Initial value check for static global variable
//

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployInitialValueOfGlobalVariable(void **state)
{
    assert_null(s_handle);
}

/*----------------------------------------------------------------------------*/

//
// SysAppDeployInitialize()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployInitialize_FullySuccess(void **state)
{
    RetCode ret;
    int32_t util_msg_handle = 0x12345678;
    // pthread_t pid = 0x13572468;
    // pthread_mutex_t mutex;

    // Initialize global variable
    s_handle = (SysAppDeployHandle)NULL;

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, sizeof(DeployInitParams_t));

    // For UtilityMsgOpen()
    will_return(__wrap_UtilityMsgOpen, util_msg_handle);
    will_return(__wrap_UtilityMsgOpen, kUtilityMsgOk);
    expect_value(__wrap_UtilityMsgOpen, queue_size, MSG_QUEUE_SIZE_FOR_DEPLOY);
    expect_value(__wrap_UtilityMsgOpen, max_msg_size, sizeof(DeployMessage_t *));

    // For pthread_mutex_init()
    // will_return(__wrap_pthread_mutex_init, &mutex);
    will_return(__wrap_pthread_mutex_init, 0);

    // For pthread_attr_init()
    // will_return(__wrap_pthread_attr_init, );  // For output argument
    will_return(__wrap_pthread_attr_init, 0);

    // For pthread_attr_setstacksize()
    will_return(__wrap_pthread_attr_setstacksize, 0);
    // expect_value(__wrap_pthread_attr_setstacksize, attr, XXX);
    // expect_value(__wrap_pthread_attr_setstacksize, stacksize, XXX);

    // For pthread_create()
    // will_return(__wrap_pthread_create, pid);
    will_return(__wrap_pthread_create, 0);
    will_return(__wrap_pthread_create, 0);
    // expect_value(__wrap_pthread_create, attr, XXX);
    // expect_value(__wrap_pthread_create, start_routine, DeployMain);
    // expect_not_value(__wrap_pthread_create, arg, NULL);

    // For pthread_attr_destroy()
    will_return(__wrap_pthread_attr_destroy, 0);
    // expect_value(__wrap_pthread_attr_destroy, attr, XXX);

    // Exec test target
    ret = SysAppDeployInitialize();

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_non_null(s_handle);

    // Free memory allocated by test target
    if (s_handle != NULL) {
        free(s_handle);
    }
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployInitialize_ErrorStateViolate(void **state)
{
    s_handle = (SysAppDeployHandle)0x12345678;

    RetCode ret = SysAppDeployInitialize();

    assert_int_equal(ret, kRetStateViolate);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployInitialize_ErrorMalloc(void **state)
{
    RetCode ret;

    // Initialize global variable
    s_handle = (SysAppDeployHandle)NULL;

    // For malloc()
    will_return(mock_malloc, true);  // Exec parameter check
    will_return(mock_malloc, false); // Get NULL
    expect_value(mock_malloc, __size, sizeof(DeployInitParams_t));

    // Exec test target
    ret = SysAppDeployInitialize();

    // Check output
    assert_int_equal(ret, kRetMemoryError);
    assert_null(s_handle);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployInitialize_ErrorUtilityMsgOpen(void **state)
{
    RetCode ret;
    int32_t util_msg_handle = 0;

    // Initialize global variable
    s_handle = (SysAppDeployHandle)NULL;

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, sizeof(DeployInitParams_t));

    // For UtilityMsgOpen()
    will_return(__wrap_UtilityMsgOpen, util_msg_handle);
    will_return(__wrap_UtilityMsgOpen, kUtilityMsgError);
    expect_value(__wrap_UtilityMsgOpen, queue_size, MSG_QUEUE_SIZE_FOR_DEPLOY);
    expect_value(__wrap_UtilityMsgOpen, max_msg_size, sizeof(DeployMessage_t *));

    // For pthread_mutex_destroy()
    // expect_value(__wrap_pthread_mutex_destroy, mutex, XXX);
    will_return(__wrap_pthread_mutex_destroy, 0);

    // For free()
    will_return(mock_free, false); // Not exec parameter check

    // Exec test target
    ret = SysAppDeployInitialize();

    // Check output
    assert_int_equal(ret, kRetFailed);
    assert_null(s_handle);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployInitialize_ErrorPthreadMutexInit(void **state)
{
    RetCode ret;
    int32_t util_msg_handle = 0x12345678;
    // pthread_mutex_t mutex;

    // Initialize global variable
    s_handle = (SysAppDeployHandle)NULL;

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, sizeof(DeployInitParams_t));

    // For UtilityMsgOpen()
    will_return(__wrap_UtilityMsgOpen, util_msg_handle);
    will_return(__wrap_UtilityMsgOpen, kUtilityMsgOk);
    expect_value(__wrap_UtilityMsgOpen, queue_size, MSG_QUEUE_SIZE_FOR_DEPLOY);
    expect_value(__wrap_UtilityMsgOpen, max_msg_size, sizeof(DeployMessage_t *));

    // For pthread_mutex_init()
    // will_return(__wrap_pthread_mutex_init, &mutex);
    will_return(__wrap_pthread_mutex_init, -1);

    // For UtilityMsgClose()
    will_return(__wrap_UtilityMsgClose, kUtilityMsgOk);
    expect_value(__wrap_UtilityMsgClose, handle, util_msg_handle);

    // For pthread_mutex_destroy()
    // expect_value(__wrap_pthread_mutex_destroy, mutex, XXX);
    will_return(__wrap_pthread_mutex_destroy, 0);

    // For free()
    will_return(mock_free, false); // Not exec parameter check

    // Exec test target
    ret = SysAppDeployInitialize();

    // Check output
    assert_int_equal(ret, kRetFailed);
    assert_null(s_handle);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployInitialize_ErrorPthreadAttrInit(void **state)
{
    RetCode ret;
    int32_t util_msg_handle = 0x12345678;
    // pthread_t pid = 0x13572468;
    // pthread_mutex_t mutex;

    // Initialize global variable
    s_handle = (SysAppDeployHandle)NULL;

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, sizeof(DeployInitParams_t));

    // For UtilityMsgOpen()
    will_return(__wrap_UtilityMsgOpen, util_msg_handle);
    will_return(__wrap_UtilityMsgOpen, kUtilityMsgOk);
    expect_value(__wrap_UtilityMsgOpen, queue_size, MSG_QUEUE_SIZE_FOR_DEPLOY);
    expect_value(__wrap_UtilityMsgOpen, max_msg_size, sizeof(DeployMessage_t *));

    // For pthread_mutex_init()
    // will_return(__wrap_pthread_mutex_init, &mutex);
    will_return(__wrap_pthread_mutex_init, 0);

    // For pthread_attr_init()
    // will_return(__wrap_pthread_attr_init, );  // For output argument
    will_return(__wrap_pthread_attr_init, -1);

    // For UtilityMsgClose()
    will_return(__wrap_UtilityMsgClose, kUtilityMsgOk);
    expect_value(__wrap_UtilityMsgClose, handle, util_msg_handle);

    // For pthread_mutex_destroy()
    // expect_value(__wrap_pthread_mutex_destroy, mutex, XXX);
    will_return(__wrap_pthread_mutex_destroy, 0);

    // For free()
    will_return(mock_free, false); // Not exec parameter check

    // Exec test target
    ret = SysAppDeployInitialize();

    // Check output
    assert_int_equal(ret, kRetFailed);
    assert_null(s_handle);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployInitialize_ErrorPthreadAttrsSetstacksize(void **state)
{
    RetCode ret;
    int32_t util_msg_handle = 0x12345678;
    // pthread_t pid = 0x13572468;
    // pthread_mutex_t mutex;

    // Initialize global variable
    s_handle = (SysAppDeployHandle)NULL;

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, sizeof(DeployInitParams_t));

    // For UtilityMsgOpen()
    will_return(__wrap_UtilityMsgOpen, util_msg_handle);
    will_return(__wrap_UtilityMsgOpen, kUtilityMsgOk);
    expect_value(__wrap_UtilityMsgOpen, queue_size, MSG_QUEUE_SIZE_FOR_DEPLOY);
    expect_value(__wrap_UtilityMsgOpen, max_msg_size, sizeof(DeployMessage_t *));

    // For pthread_mutex_init()
    // will_return(__wrap_pthread_mutex_init, &mutex);
    will_return(__wrap_pthread_mutex_init, 0);

    // For pthread_attr_init()
    // will_return(__wrap_pthread_attr_init, );  // For output argument
    will_return(__wrap_pthread_attr_init, 0);

    // For pthread_attr_setstacksize()
    will_return(__wrap_pthread_attr_setstacksize, -1);
    // expect_value(__wrap_pthread_attr_setstacksize, attr, XXX);
    // expect_value(__wrap_pthread_attr_setstacksize, stacksize, XXX);

    // For pthread_attr_destroy()
    will_return(__wrap_pthread_attr_destroy, 0);
    // expect_value(__wrap_pthread_attr_destroy, attr, XXX);

    // For UtilityMsgClose()
    will_return(__wrap_UtilityMsgClose, kUtilityMsgOk);
    expect_value(__wrap_UtilityMsgClose, handle, util_msg_handle);

    // For pthread_mutex_destroy()
    // expect_value(__wrap_pthread_mutex_destroy, mutex, XXX);
    will_return(__wrap_pthread_mutex_destroy, 0);

    // For free()
    will_return(mock_free, false); // Not exec parameter check

    // Exec test target
    ret = SysAppDeployInitialize();

    // Check output
    assert_int_equal(ret, kRetFailed);
    assert_null(s_handle);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployInitialize_ErrorPthreadCreate(void **state)
{
    RetCode ret;
    int32_t util_msg_handle = 0x12345678;
    // pthread_t pid = 0x13572468;
    // pthread_mutex_t mutex;

    // Initialize global variable
    s_handle = (SysAppDeployHandle)NULL;

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, sizeof(DeployInitParams_t));

    // For UtilityMsgOpen()
    will_return(__wrap_UtilityMsgOpen, util_msg_handle);
    will_return(__wrap_UtilityMsgOpen, kUtilityMsgOk);
    expect_value(__wrap_UtilityMsgOpen, queue_size, MSG_QUEUE_SIZE_FOR_DEPLOY);
    expect_value(__wrap_UtilityMsgOpen, max_msg_size, sizeof(DeployMessage_t *));

    // For pthread_mutex_init()
    // will_return(__wrap_pthread_mutex_init, &mutex);
    will_return(__wrap_pthread_mutex_init, 0);

    // For pthread_attr_init()
    // will_return(__wrap_pthread_attr_init, );  // For output argument
    will_return(__wrap_pthread_attr_init, 0);

    // For pthread_attr_setstacksize()
    will_return(__wrap_pthread_attr_setstacksize, 0);
    // expect_value(__wrap_pthread_attr_setstacksize, attr, XXX);
    // expect_value(__wrap_pthread_attr_setstacksize, stacksize, XXX);

    // For pthread_create()
    // will_return(__wrap_pthread_create, pid);
    will_return(__wrap_pthread_create, 0);
    will_return(__wrap_pthread_create, -1);
    // expect_value(__wrap_pthread_create, attr, XXX);
    // expect_value(__wrap_pthread_create, start_routine, DeployMain);
    // expect_not_value(__wrap_pthread_create, arg, NULL);

    // For pthread_attr_destroy()
    will_return(__wrap_pthread_attr_destroy, 0);
    // expect_value(__wrap_pthread_attr_destroy, attr, XXX);

    // For UtilityMsgClose()
    will_return(__wrap_UtilityMsgClose, kUtilityMsgOk);
    expect_value(__wrap_UtilityMsgClose, handle, util_msg_handle);

    // For pthread_mutex_destroy()
    // expect_value(__wrap_pthread_mutex_destroy, mutex, XXX);
    will_return(__wrap_pthread_mutex_destroy, 0);

    // For free()
    will_return(mock_free, false); // Not exec parameter check

    // Exec test target
    ret = SysAppDeployInitialize();

    // Check output
    assert_int_equal(ret, kRetFailed);
    assert_null(s_handle);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployInitialize_MsgCloseError(void **state)
{
    RetCode ret;
    int32_t util_msg_handle = 0x12345678;
    // pthread_t pid = 0x13572468;
    // pthread_mutex_t mutex;

    // Initialize global variable
    s_handle = (SysAppDeployHandle)NULL;

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, sizeof(DeployInitParams_t));

    // For UtilityMsgOpen()
    will_return(__wrap_UtilityMsgOpen, util_msg_handle);
    will_return(__wrap_UtilityMsgOpen, kUtilityMsgOk);
    expect_value(__wrap_UtilityMsgOpen, queue_size, MSG_QUEUE_SIZE_FOR_DEPLOY);
    expect_value(__wrap_UtilityMsgOpen, max_msg_size, sizeof(DeployMessage_t *));

    // For pthread_mutex_init()
    // will_return(__wrap_pthread_mutex_init, &mutex);
    will_return(__wrap_pthread_mutex_init, 0);

    // For pthread_attr_init()
    // will_return(__wrap_pthread_attr_init, );  // For output argument
    will_return(__wrap_pthread_attr_init, 0);

    // For pthread_attr_setstacksize()
    will_return(__wrap_pthread_attr_setstacksize, 0);
    // expect_value(__wrap_pthread_attr_setstacksize, attr, XXX);
    // expect_value(__wrap_pthread_attr_setstacksize, stacksize, XXX);

    // For pthread_create()
    // will_return(__wrap_pthread_create, pid);
    will_return(__wrap_pthread_create, 0);
    will_return(__wrap_pthread_create, -1);
    // expect_value(__wrap_pthread_create, attr, XXX);
    // expect_value(__wrap_pthread_create, start_routine, DeployMain);
    // expect_not_value(__wrap_pthread_create, arg, NULL);

    // For pthread_attr_destroy()
    will_return(__wrap_pthread_attr_destroy, 0);
    // expect_value(__wrap_pthread_attr_destroy, attr, XXX);

    // For UtilityMsgClose()
    will_return(__wrap_UtilityMsgClose, kUtilityMsgError);
    expect_value(__wrap_UtilityMsgClose, handle, util_msg_handle);

    // For pthread_mutex_destroy()
    // expect_value(__wrap_pthread_mutex_destroy, mutex, XXX);
    will_return(__wrap_pthread_mutex_destroy, 0);

    // For free()
    will_return(mock_free, false); // Not exec parameter check

    // Exec test target
    ret = SysAppDeployInitialize();

    // Check output
    assert_int_equal(ret, kRetFailed);
    assert_null(s_handle);
}

/*----------------------------------------------------------------------------*/

//
// SysAppDeployFinalize()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployFinalize_FullySuccess(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param;
    void *rcv_msg[MSG_QUEUE_SIZE_FOR_DEPLOY];
    int i;

    // Initialize global variable
    if (InitGlobalVariableForFinalize(true) == false) {
        goto err_exit;
    }
    init_param = (DeployInitParams_t *)s_handle;

    // For SysAppUdRequestToStopDownload()
    expect_function_call(__wrap_SysAppUdRequestToStopDownload);

    // For UtilityMsgRecv()
    if (UtilityMsgRecvForFinalize(kUtilityMsgOk, rcv_msg, MSG_QUEUE_SIZE_FOR_DEPLOY, true) ==
        false) {
        goto err_exit;
    }

    // For free() of UtilityMsgRecv() receive msg
    for (i = 0; i < MSG_QUEUE_SIZE_FOR_DEPLOY; i++) {
        will_return(mock_free, true); // Exec parameter check
        expect_value(mock_free, __ptr, rcv_msg[i]);
    }

    // For UtilityMsgSend()
    UtilityMsgSendForFinalize(kUtilityMsgOk);

    // For SysAppUdWaitForDownloadToStop()
    expect_function_call(__wrap_SysAppUdWaitForDownloadToStop);

    // For pthread_join()
    will_return(__wrap_pthread_join, 0);
    // expect_value(__wrap_pthread_join, thread, init_param->pid);
    // expect_value(__wrap_pthread_join, retval, NULL);

    // For UtilityMsgClose()
    will_return(__wrap_UtilityMsgClose, kUtilityMsgOk);
    expect_value(__wrap_UtilityMsgClose, handle, init_param->msg_handle_dp);

    // For pthread_mutex_destroy()
    // expect_value(__wrap_pthread_mutex_destroy, mutex, XXX);
    will_return(__wrap_pthread_mutex_destroy, 0);

    // For free() of initp->state_str
    for (i = 0; i < DeployTopicNum; i++) {
        will_return(mock_free, true); // Exec parameter check
        expect_value(mock_free, __ptr, init_param->state_str[i]);
    }

    // For free() of initp
    will_return(mock_free, true); // Exec parameter check
    expect_value(mock_free, __ptr, s_handle);

    // For SysAppLedUnsetAppStatus()
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDownloadFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state,
                 LedAppStatusErrorUpdateMemoryAllocateFailed);

    // Exec test target
    ret = SysAppDeployFinalize();

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_null(s_handle);

    return;

err_exit:
    for (i = 0; i < MSG_QUEUE_SIZE_FOR_DEPLOY; i++) {
        if (rcv_msg[i] != NULL) {
            free(rcv_msg[i]);
        }
    }

    FinGlobalVariableForFinalize();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployFinalize_ErrorStateViolate(void **state)
{
    s_handle = (SysAppDeployHandle)NULL;

    RetCode ret = SysAppDeployFinalize();

    assert_int_equal(ret, kRetStateViolate);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployFinalize_ErrorUtilityMsgRecv(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param;
    void *rcv_msg[MSG_QUEUE_SIZE_FOR_DEPLOY];
    int i;

    // Initialize global variable
    if (InitGlobalVariableForFinalize(true) == false) {
        goto err_exit;
    }
    init_param = (DeployInitParams_t *)s_handle;

    // For SysAppUdRequestToStopDownload()
    expect_function_call(__wrap_SysAppUdRequestToStopDownload);

    // For UtilityMsgRecv()
    if (UtilityMsgRecvForFinalize(kUtilityMsgError, rcv_msg, MSG_QUEUE_SIZE_FOR_DEPLOY, true) ==
        false) {
        goto err_exit;
    }

    // For UtilityMsgSend()
    UtilityMsgSendForFinalize(kUtilityMsgOk);

    // For SysAppUdWaitForDownloadToStop()
    expect_function_call(__wrap_SysAppUdWaitForDownloadToStop);

    // For pthread_join()
    will_return(__wrap_pthread_join, 0);
    // expect_value(__wrap_pthread_join, thread, init_param->pid);
    // expect_value(__wrap_pthread_join, retval, NULL);

    // For UtilityMsgClose()
    will_return(__wrap_UtilityMsgClose, kUtilityMsgOk);
    expect_value(__wrap_UtilityMsgClose, handle, init_param->msg_handle_dp);

    // For pthread_mutex_destroy()
    // expect_value(__wrap_pthread_mutex_destroy, mutex, XXX);
    will_return(__wrap_pthread_mutex_destroy, 0);

    // For free() of initp->state_str
    for (i = 0; i < DeployTopicNum; i++) {
        will_return(mock_free, true); // Exec parameter check
        expect_value(mock_free, __ptr, init_param->state_str[i]);
    }

    // For free() of initp
    will_return(mock_free, true); // Exec parameter check
    expect_value(mock_free, __ptr, s_handle);

    // For SysAppLedUnsetAppStatus()
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDownloadFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state,
                 LedAppStatusErrorUpdateMemoryAllocateFailed);

    // Exec test target
    ret = SysAppDeployFinalize();

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_null(s_handle);

    // Free memory
    for (i = 0; i < MSG_QUEUE_SIZE_FOR_DEPLOY; i++) {
        if (rcv_msg[i] != NULL) {
            free(rcv_msg[i]);
        }
    }

    return;

err_exit:
    for (i = 0; i < MSG_QUEUE_SIZE_FOR_DEPLOY; i++) {
        if (rcv_msg[i] != NULL) {
            free(rcv_msg[i]);
        }
    }

    FinGlobalVariableForFinalize();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployFinalize_NullUtilityMsgRecv(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param;
    void *rcv_msg[MSG_QUEUE_SIZE_FOR_DEPLOY];
    int i;

    // Initialize global variable
    if (InitGlobalVariableForFinalize(true) == false) {
        goto err_exit;
    }
    init_param = (DeployInitParams_t *)s_handle;

    // For SysAppUdRequestToStopDownload()
    expect_function_call(__wrap_SysAppUdRequestToStopDownload);

    // For UtilityMsgRecv()
    if (UtilityMsgRecvForFinalize(kUtilityMsgOk, rcv_msg, MSG_QUEUE_SIZE_FOR_DEPLOY, false) ==
        false) {
        goto err_exit;
    }

    // For UtilityMsgSend()
    UtilityMsgSendForFinalize(kUtilityMsgOk);

    // For SysAppUdWaitForDownloadToStop()
    expect_function_call(__wrap_SysAppUdWaitForDownloadToStop);

    // For pthread_join()
    will_return(__wrap_pthread_join, 0);
    // expect_value(__wrap_pthread_join, thread, init_param->pid);
    // expect_value(__wrap_pthread_join, retval, NULL);

    // For UtilityMsgClose()
    will_return(__wrap_UtilityMsgClose, kUtilityMsgOk);
    expect_value(__wrap_UtilityMsgClose, handle, init_param->msg_handle_dp);

    // For pthread_mutex_destroy()
    // expect_value(__wrap_pthread_mutex_destroy, mutex, XXX);
    will_return(__wrap_pthread_mutex_destroy, 0);

    // For free() of initp->state_str
    for (i = 0; i < DeployTopicNum; i++) {
        will_return(mock_free, true); // Exec parameter check
        expect_value(mock_free, __ptr, init_param->state_str[i]);
    }

    // For free() of initp
    will_return(mock_free, true); // Exec parameter check
    expect_value(mock_free, __ptr, s_handle);

    // For SysAppLedUnsetAppStatus()
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDownloadFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state,
                 LedAppStatusErrorUpdateMemoryAllocateFailed);

    // Exec test target
    ret = SysAppDeployFinalize();

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_null(s_handle);

    return;

err_exit:
    FinGlobalVariableForFinalize();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployFinalize_ErrorUtilityMsgSend(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param;
    void *rcv_msg[MSG_QUEUE_SIZE_FOR_DEPLOY];
    int i;

    // Initialize global variable
    if (InitGlobalVariableForFinalize(true) == false) {
        goto err_exit;
    }
    init_param = (DeployInitParams_t *)s_handle;

    // For SysAppUdRequestToStopDownload()
    expect_function_call(__wrap_SysAppUdRequestToStopDownload);

    // For UtilityMsgRecv()
    if (UtilityMsgRecvForFinalize(kUtilityMsgOk, rcv_msg, MSG_QUEUE_SIZE_FOR_DEPLOY, true) ==
        false) {
        goto err_exit;
    }

    // For free() of UtilityMsgRecv() receive msg
    for (i = 0; i < MSG_QUEUE_SIZE_FOR_DEPLOY; i++) {
        will_return(mock_free, true); // Exec parameter check
        expect_value(mock_free, __ptr, rcv_msg[i]);
    }

    // For UtilityMsgSend()
    UtilityMsgSendForFinalize(kUtilityMsgError);

    // For SysAppUdWaitForDownloadToStop()
    expect_function_call(__wrap_SysAppUdWaitForDownloadToStop);

    // For pthread_join()
    will_return(__wrap_pthread_join, 0);
    // expect_value(__wrap_pthread_join, thread, init_param->pid);
    // expect_value(__wrap_pthread_join, retval, NULL);

    // For UtilityMsgClose()
    will_return(__wrap_UtilityMsgClose, kUtilityMsgOk);
    expect_value(__wrap_UtilityMsgClose, handle, init_param->msg_handle_dp);

    // For pthread_mutex_destroy()
    // expect_value(__wrap_pthread_mutex_destroy, mutex, XXX);
    will_return(__wrap_pthread_mutex_destroy, 0);

    // For free() of initp->state_str
    for (i = 0; i < DeployTopicNum; i++) {
        will_return(mock_free, true); // Exec parameter check
        expect_value(mock_free, __ptr, init_param->state_str[i]);
    }

    // For free() of initp
    will_return(mock_free, true); // Exec parameter check
    expect_value(mock_free, __ptr, s_handle);

    // For SysAppLedUnsetAppStatus()
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDownloadFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state,
                 LedAppStatusErrorUpdateMemoryAllocateFailed);

    // Exec test target
    ret = SysAppDeployFinalize();

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_null(s_handle);

    return;

err_exit:
    for (i = 0; i < MSG_QUEUE_SIZE_FOR_DEPLOY; i++) {
        if (rcv_msg[i] != NULL) {
            free(rcv_msg[i]);
        }
    }

    FinGlobalVariableForFinalize();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployFinalize_ErrorPthreadJoin(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param;
    void *rcv_msg[MSG_QUEUE_SIZE_FOR_DEPLOY];
    int i;

    // Initialize global variable
    if (InitGlobalVariableForFinalize(true) == false) {
        goto err_exit;
    }
    init_param = (DeployInitParams_t *)s_handle;

    // For SysAppUdRequestToStopDownload()
    expect_function_call(__wrap_SysAppUdRequestToStopDownload);

    // For UtilityMsgRecv()
    if (UtilityMsgRecvForFinalize(kUtilityMsgOk, rcv_msg, MSG_QUEUE_SIZE_FOR_DEPLOY, true) ==
        false) {
        goto err_exit;
    }

    // For free() of UtilityMsgRecv() receive msg
    for (i = 0; i < MSG_QUEUE_SIZE_FOR_DEPLOY; i++) {
        will_return(mock_free, true); // Exec parameter check
        expect_value(mock_free, __ptr, rcv_msg[i]);
    }

    // For UtilityMsgSend()
    UtilityMsgSendForFinalize(kUtilityMsgOk);

    // For SysAppUdWaitForDownloadToStop()
    expect_function_call(__wrap_SysAppUdWaitForDownloadToStop);

    // For pthread_join()
    will_return(__wrap_pthread_join, -1);
    // expect_value(__wrap_pthread_join, thread, init_param->pid);
    // expect_value(__wrap_pthread_join, retval, NULL);

    // For UtilityMsgClose()
    will_return(__wrap_UtilityMsgClose, kUtilityMsgOk);
    expect_value(__wrap_UtilityMsgClose, handle, init_param->msg_handle_dp);

    // For pthread_mutex_destroy()
    // expect_value(__wrap_pthread_mutex_destroy, mutex, XXX);
    will_return(__wrap_pthread_mutex_destroy, 0);

    // For free() of initp->state_str
    for (i = 0; i < DeployTopicNum; i++) {
        will_return(mock_free, true); // Exec parameter check
        expect_value(mock_free, __ptr, init_param->state_str[i]);
    }

    // For free() of initp
    will_return(mock_free, true); // Exec parameter check
    expect_value(mock_free, __ptr, s_handle);

    // For SysAppLedUnsetAppStatus()
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDownloadFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state,
                 LedAppStatusErrorUpdateMemoryAllocateFailed);

    // Exec test target
    ret = SysAppDeployFinalize();

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_null(s_handle);

    return;

err_exit:
    for (i = 0; i < MSG_QUEUE_SIZE_FOR_DEPLOY; i++) {
        if (rcv_msg[i] != NULL) {
            free(rcv_msg[i]);
        }
    }

    FinGlobalVariableForFinalize();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployFinalize_NullMsgHandle(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param;
    void *rcv_msg[MSG_QUEUE_SIZE_FOR_DEPLOY];
    int i;

    // Initialize global variable
    if (InitGlobalVariableForFinalize(true) == false) {
        goto err_exit;
    }
    init_param = (DeployInitParams_t *)s_handle;
    init_param->msg_handle_dp = 0;

    // For SysAppUdRequestToStopDownload()
    expect_function_call(__wrap_SysAppUdRequestToStopDownload);

    // For UtilityMsgRecv()
    if (UtilityMsgRecvForFinalize(kUtilityMsgOk, rcv_msg, MSG_QUEUE_SIZE_FOR_DEPLOY, true) ==
        false) {
        goto err_exit;
    }

    // For free() of UtilityMsgRecv() receive msg
    for (i = 0; i < MSG_QUEUE_SIZE_FOR_DEPLOY; i++) {
        will_return(mock_free, true); // Exec parameter check
        expect_value(mock_free, __ptr, rcv_msg[i]);
    }

    // For UtilityMsgSend()
    UtilityMsgSendForFinalize(kUtilityMsgOk);

    // For SysAppUdWaitForDownloadToStop()
    expect_function_call(__wrap_SysAppUdWaitForDownloadToStop);

    // For pthread_join()
    will_return(__wrap_pthread_join, 0);
    // expect_value(__wrap_pthread_join, thread, init_param->pid);
    // expect_value(__wrap_pthread_join, retval, NULL);

    // For pthread_mutex_destroy()
    // expect_value(__wrap_pthread_mutex_destroy, mutex, XXX);
    will_return(__wrap_pthread_mutex_destroy, 0);

    // For free() of initp->state_str
    for (i = 0; i < DeployTopicNum; i++) {
        will_return(mock_free, true); // Exec parameter check
        expect_value(mock_free, __ptr, init_param->state_str[i]);
    }

    // For free() of initp
    will_return(mock_free, true); // Exec parameter check
    expect_value(mock_free, __ptr, s_handle);

    // For SysAppLedUnsetAppStatus()
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDownloadFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state,
                 LedAppStatusErrorUpdateMemoryAllocateFailed);

    // Exec test target
    ret = SysAppDeployFinalize();

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_null(s_handle);

    return;

err_exit:
    for (i = 0; i < MSG_QUEUE_SIZE_FOR_DEPLOY; i++) {
        if (rcv_msg[i] != NULL) {
            free(rcv_msg[i]);
        }
    }

    FinGlobalVariableForFinalize();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployFinalize_NullStateStr(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param;
    void *rcv_msg[MSG_QUEUE_SIZE_FOR_DEPLOY];
    int i;

    // Initialize global variable
    if (InitGlobalVariableForFinalize(false) == false) {
        goto err_exit;
    }
    init_param = (DeployInitParams_t *)s_handle;

    // For SysAppUdRequestToStopDownload()
    expect_function_call(__wrap_SysAppUdRequestToStopDownload);

    // For UtilityMsgRecv()
    if (UtilityMsgRecvForFinalize(kUtilityMsgOk, rcv_msg, MSG_QUEUE_SIZE_FOR_DEPLOY, true) ==
        false) {
        goto err_exit;
    }

    // For free() of UtilityMsgRecv() receive msg
    for (i = 0; i < MSG_QUEUE_SIZE_FOR_DEPLOY; i++) {
        will_return(mock_free, true); // Exec parameter check
        expect_value(mock_free, __ptr, rcv_msg[i]);
    }

    // For UtilityMsgSend()
    UtilityMsgSendForFinalize(kUtilityMsgOk);

    // For SysAppUdWaitForDownloadToStop()
    expect_function_call(__wrap_SysAppUdWaitForDownloadToStop);

    // For pthread_join()
    will_return(__wrap_pthread_join, 0);
    // expect_value(__wrap_pthread_join, thread, init_param->pid);
    // expect_value(__wrap_pthread_join, retval, NULL);

    // For UtilityMsgClose()
    will_return(__wrap_UtilityMsgClose, kUtilityMsgOk);
    expect_value(__wrap_UtilityMsgClose, handle, init_param->msg_handle_dp);

    // For pthread_mutex_destroy()
    // expect_value(__wrap_pthread_mutex_destroy, mutex, XXX);
    will_return(__wrap_pthread_mutex_destroy, 0);

    // For free() of initp
    will_return(mock_free, true); // Exec parameter check
    expect_value(mock_free, __ptr, s_handle);

    // For SysAppLedUnsetAppStatus()
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDownloadFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state,
                 LedAppStatusErrorUpdateMemoryAllocateFailed);

    // Exec test target
    ret = SysAppDeployFinalize();

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_null(s_handle);

    return;

err_exit:
    for (i = 0; i < MSG_QUEUE_SIZE_FOR_DEPLOY; i++) {
        if (rcv_msg[i] != NULL) {
            free(rcv_msg[i]);
        }
    }

    FinGlobalVariableForFinalize();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployFinalize_MsgCloseError(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param;
    void *rcv_msg[MSG_QUEUE_SIZE_FOR_DEPLOY];
    int i;

    // Initialize global variable
    if (InitGlobalVariableForFinalize(false) == false) {
        goto err_exit;
    }
    init_param = (DeployInitParams_t *)s_handle;

    // For SysAppUdRequestToStopDownload()
    expect_function_call(__wrap_SysAppUdRequestToStopDownload);

    // For UtilityMsgRecv()
    if (UtilityMsgRecvForFinalize(kUtilityMsgOk, rcv_msg, MSG_QUEUE_SIZE_FOR_DEPLOY, true) ==
        false) {
        goto err_exit;
    }

    // For free() of UtilityMsgRecv() receive msg
    for (i = 0; i < MSG_QUEUE_SIZE_FOR_DEPLOY; i++) {
        will_return(mock_free, true); // Exec parameter check
        expect_value(mock_free, __ptr, rcv_msg[i]);
    }

    // For UtilityMsgSend()
    UtilityMsgSendForFinalize(kUtilityMsgOk);

    // For SysAppUdWaitForDownloadToStop()
    expect_function_call(__wrap_SysAppUdWaitForDownloadToStop);

    // For pthread_join()
    will_return(__wrap_pthread_join, 0);
    // expect_value(__wrap_pthread_join, thread, init_param->pid);
    // expect_value(__wrap_pthread_join, retval, NULL);

    // For UtilityMsgClose()
    will_return(__wrap_UtilityMsgClose, kUtilityMsgError);
    expect_value(__wrap_UtilityMsgClose, handle, init_param->msg_handle_dp);

    // For pthread_mutex_destroy()
    // expect_value(__wrap_pthread_mutex_destroy, mutex, XXX);
    will_return(__wrap_pthread_mutex_destroy, 0);

    // For free() of initp
    will_return(mock_free, true); // Exec parameter check
    expect_value(mock_free, __ptr, s_handle);

    // For SysAppLedUnsetAppStatus()
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDownloadFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state,
                 LedAppStatusErrorUpdateMemoryAllocateFailed);

    // Exec test target
    ret = SysAppDeployFinalize();

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_null(s_handle);

    return;

err_exit:
    for (i = 0; i < MSG_QUEUE_SIZE_FOR_DEPLOY; i++) {
        if (rcv_msg[i] != NULL) {
            free(rcv_msg[i]);
        }
    }

    FinGlobalVariableForFinalize();

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppDeploy()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppDeploy_FullySuccessFirmware(void **state)
{
    RetCode ret;
    const char *topic = "PRIVATE_deploy_firmware";
    const char *config = "test";
    void *rcv_msg[MSG_QUEUE_SIZE_FOR_DEPLOY];

    // Initialize global variable
    if (InitGlobalVariableForDeploy() == false) {
        goto exit;
    }

    // For UtilityMsgRecv() -No receive-
    if (UtilityMsgRecvForDeploy(kUtilityMsgOk, rcv_msg, MSG_QUEUE_SIZE_FOR_DEPLOY, false) ==
        false) {
        goto exit;
    }

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, sizeof(DeployMessage_t) + strlen(config));

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, 0);

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);

    // For UtilityMsgSend()
    UtilityMsgSendForDeployNew(kUtilityMsgOk, topic, config);

    // Exet test target
    ret = SysAppDeploy(topic, config, strlen(config));

    // Check output
    assert_int_equal(ret, kRetOk);

exit:
    FinGlobalVariableForDeploy();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeploy_FullySuccessAiModel(void **state)
{
    RetCode ret;
    const char *topic = "PRIVATE_deploy_ai_model";
    const char *config = "test";
    void *rcv_msg[MSG_QUEUE_SIZE_FOR_DEPLOY];

    // Initialize global variable
    if (InitGlobalVariableForDeploy() == false) {
        goto exit;
    }

    // For UtilityMsgRecv() -No receive-
    if (UtilityMsgRecvForDeploy(kUtilityMsgOk, rcv_msg, MSG_QUEUE_SIZE_FOR_DEPLOY, false) ==
        false) {
        goto exit;
    }

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, sizeof(DeployMessage_t) + strlen(config));

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, 0);

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);

    // For UtilityMsgSend()
    UtilityMsgSendForDeployNew(kUtilityMsgOk, topic, config);

    // Exet test target
    ret = SysAppDeploy(topic, config, strlen(config));

    // Check output
    assert_int_equal(ret, kRetOk);

exit:
    FinGlobalVariableForDeploy();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeploy_FullySuccessSensorCalibrationParam(void **state)
{
    RetCode ret;
    const char *topic = "PRIVATE_deploy_sensor_calibration_param";
    const char *config = "test";
    void *rcv_msg[MSG_QUEUE_SIZE_FOR_DEPLOY];

    // Initialize global variable
    if (InitGlobalVariableForDeploy() == false) {
        goto exit;
    }

    // For UtilityMsgRecv() -No receive-
    if (UtilityMsgRecvForDeploy(kUtilityMsgOk, rcv_msg, MSG_QUEUE_SIZE_FOR_DEPLOY, false) ==
        false) {
        goto exit;
    }

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, sizeof(DeployMessage_t) + strlen(config));

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, 0);

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);

    // For UtilityMsgSend()
    UtilityMsgSendForDeployNew(kUtilityMsgOk, topic, config);

    // Exet test target
    ret = SysAppDeploy(topic, config, strlen(config));

    // Check output
    assert_int_equal(ret, kRetOk);

exit:
    FinGlobalVariableForDeploy();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeploy_FullySuccessFirmwareReload(void **state)
{
    RetCode ret;
    const char *topic = "PRIVATE_deploy_firmware";
    const char *config = "test";
    void *rcv_msg[MSG_QUEUE_SIZE_FOR_DEPLOY];

    // Initialize global variable
    if (InitGlobalVariableForDeploy() == false) {
        goto exit;
    }

    // For UtilityMsgRecv() -Receive-
    if (UtilityMsgRecvForDeploy(kUtilityMsgOk, rcv_msg, MSG_QUEUE_SIZE_FOR_DEPLOY, true) == false) {
        goto exit;
    }

    // For UtilityMsgSend()
    UtilityMsgSendForDeployReload(kUtilityMsgOk, rcv_msg, MSG_QUEUE_SIZE_FOR_DEPLOY, topic);

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, sizeof(DeployMessage_t) + strlen(config));

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, 0);

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);

    // For UtilityMsgSend()
    UtilityMsgSendForDeployNew(kUtilityMsgOk, topic, config);

    // Exet test target
    ret = SysAppDeploy(topic, config, strlen(config));

    // Check output
    assert_int_equal(ret, kRetOk);

exit:
    FinGlobalVariableForDeploy();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeploy_FullySuccessAiModelReload(void **state)
{
    RetCode ret;
    const char *topic = "PRIVATE_deploy_ai_model";
    const char *config = "test";
    void *rcv_msg[MSG_QUEUE_SIZE_FOR_DEPLOY];

    // Initialize global variable
    if (InitGlobalVariableForDeploy() == false) {
        goto exit;
    }

    // For UtilityMsgRecv() -Receive-
    if (UtilityMsgRecvForDeploy(kUtilityMsgOk, rcv_msg, MSG_QUEUE_SIZE_FOR_DEPLOY, true) == false) {
        goto exit;
    }

    // For UtilityMsgSend()
    UtilityMsgSendForDeployReload(kUtilityMsgOk, rcv_msg, MSG_QUEUE_SIZE_FOR_DEPLOY, topic);

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, sizeof(DeployMessage_t) + strlen(config));

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, 0);

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);

    // For UtilityMsgSend()
    UtilityMsgSendForDeployNew(kUtilityMsgOk, topic, config);

    // Exet test target
    ret = SysAppDeploy(topic, config, strlen(config));

    // Check output
    assert_int_equal(ret, kRetOk);

exit:
    FinGlobalVariableForDeploy();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeploy_FullySuccessSensorCalibrationParamReload(void **state)
{
    RetCode ret;
    const char *topic = "PRIVATE_deploy_sensor_calibration_param";
    const char *config = "test";
    void *rcv_msg[MSG_QUEUE_SIZE_FOR_DEPLOY];

    // Initialize global variable
    if (InitGlobalVariableForDeploy() == false) {
        goto exit;
    }

    // For UtilityMsgRecv() -Receive-
    if (UtilityMsgRecvForDeploy(kUtilityMsgOk, rcv_msg, MSG_QUEUE_SIZE_FOR_DEPLOY, true) == false) {
        goto exit;
    }

    // For UtilityMsgSend()
    UtilityMsgSendForDeployReload(kUtilityMsgOk, rcv_msg, MSG_QUEUE_SIZE_FOR_DEPLOY, topic);

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, sizeof(DeployMessage_t) + strlen(config));

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, 0);

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);

    // For UtilityMsgSend()
    UtilityMsgSendForDeployNew(kUtilityMsgOk, topic, config);

    // Exet test target
    ret = SysAppDeploy(topic, config, strlen(config));

    // Check output
    assert_int_equal(ret, kRetOk);

exit:
    FinGlobalVariableForDeploy();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeploy_NullHandle(void **state)
{
    RetCode ret;
    const char *topic = "PRIVATE_deploy_firmware";
    const char *config = "test";

    // Initialize global variable
    s_handle = (SysAppDeployHandle)NULL;

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, 0);

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);

    // Exet test target
    ret = SysAppDeploy(topic, config, strlen(config));

    // Check output
    assert_int_equal(ret, kRetFailed);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeploy_UndefinedTopic(void **state)
{
    RetCode ret;
    const char *topic = "PRIVATE_deploy_undefined";
    const char *config = "test";

    // Initialize global variable
    if (InitGlobalVariableForDeploy() == false) {
        goto exit;
    }

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, 0);

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);

    // Exet test target
    ret = SysAppDeploy(topic, config, strlen(config));

    // Check output
    assert_int_equal(ret, kRetFailed);

exit:
    FinGlobalVariableForDeploy();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeploy_ErrorUtilityMsgRecv(void **state)
{
    RetCode ret;
    const char *topic = "PRIVATE_deploy_firmware";
    const char *config = "test";
    void *rcv_msg;

    // Initialize global variable
    if (InitGlobalVariableForDeploy() == false) {
        goto exit;
    }

    // For UtilityMsgRecv() -No receive-
    if (UtilityMsgRecvForDeploy(kUtilityMsgError, &rcv_msg, 1, false) == false) {
        goto exit;
    }

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, sizeof(DeployMessage_t) + strlen(config));

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, 0);

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);

    // For UtilityMsgSend()
    UtilityMsgSendForDeployNew(kUtilityMsgOk, topic, config);

    // Exet test target
    ret = SysAppDeploy(topic, config, strlen(config));

    // Check output
    assert_int_equal(ret, kRetOk);

exit:
    FinGlobalVariableForDeploy();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeploy_ErrorUtilityMsgSendForReload(void **state)
{
    RetCode ret;
    const char *topic = "PRIVATE_deploy_firmware";
    const char *config = "test";
    void *rcv_msg[MSG_QUEUE_SIZE_FOR_DEPLOY];

    // Initialize global variable
    if (InitGlobalVariableForDeploy() == false) {
        goto exit;
    }

    // For UtilityMsgRecv() -Receive-
    if (UtilityMsgRecvForDeploy(kUtilityMsgOk, rcv_msg, MSG_QUEUE_SIZE_FOR_DEPLOY, true) == false) {
        goto exit;
    }

    // For UtilityMsgSend()
    UtilityMsgSendForDeployReload(kUtilityMsgError, rcv_msg, MSG_QUEUE_SIZE_FOR_DEPLOY, topic);

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, sizeof(DeployMessage_t) + strlen(config));

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, 0);

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);

    // For UtilityMsgSend()
    UtilityMsgSendForDeployNew(kUtilityMsgOk, topic, config);

    // Exet test target
    ret = SysAppDeploy(topic, config, strlen(config));

    // Check output
    assert_int_equal(ret, kRetOk);

exit:
    FinGlobalVariableForDeploy();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeploy_ErrorMalloc(void **state)
{
    RetCode ret;
    const char *topic = "PRIVATE_deploy_firmware";
    const char *config = "test";
    void *rcv_msg[MSG_QUEUE_SIZE_FOR_DEPLOY];

    // Initialize global variable
    if (InitGlobalVariableForDeploy() == false) {
        goto exit;
    }

    // For UtilityMsgRecv() -No receive-
    if (UtilityMsgRecvForDeploy(kUtilityMsgOk, rcv_msg, MSG_QUEUE_SIZE_FOR_DEPLOY, false) ==
        false) {
        goto exit;
    }

    // For malloc()
    will_return(mock_malloc, true);  // Exec parameter check
    will_return(mock_malloc, false); // Get NULL
    expect_value(mock_malloc, __size, sizeof(DeployMessage_t) + strlen(config));

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, 0);

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);

    // Exet test target
    ret = SysAppDeploy(topic, config, strlen(config));

    // Check output
    assert_int_equal(ret, kRetFailed);

exit:
    FinGlobalVariableForDeploy();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeploy_ErrorUtilityMsgSendForNew(void **state)
{
    RetCode ret;
    const char *topic = "PRIVATE_deploy_firmware";
    const char *config = "test";
    void *rcv_msg[MSG_QUEUE_SIZE_FOR_DEPLOY];

    // Initialize global variable
    if (InitGlobalVariableForDeploy() == false) {
        goto exit;
    }

    // For UtilityMsgRecv() -No receive-
    if (UtilityMsgRecvForDeploy(kUtilityMsgOk, rcv_msg, MSG_QUEUE_SIZE_FOR_DEPLOY, false) ==
        false) {
        goto exit;
    }

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, sizeof(DeployMessage_t) + strlen(config));

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, 0);

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);

    // For UtilityMsgSend()
    UtilityMsgSendForDeployNew(kUtilityMsgError, topic, config);

    // For free()
    will_return(mock_free, false);

    // Exet test target
    ret = SysAppDeploy(topic, config, strlen(config));

    // Check output
    assert_int_equal(ret, kRetOk);

exit:
    FinGlobalVariableForDeploy();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeploy_ErrorMutex(void **state)
{
    RetCode ret;
    const char *topic = "PRIVATE_deploy_firmware";
    const char *config = "test";

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, -1);

    // Exet test target
    ret = SysAppDeploy(topic, config, strlen(config));

    // Check output
    assert_int_equal(ret, kRetFailed);
}

/*----------------------------------------------------------------------------*/

//
// SysAppDeployGetFirmwareState()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployGetFirmwareState_FullySuccess(void **state)
{
    RetCode ret;
    char *state_str = NULL;
    uint32_t size;
    DeployInitParams_t *init_param;

    // Initialize global variable
    if (InitGlobalVariableForGetState() == false) {
        goto exit;
    }
    init_param = (DeployInitParams_t *)s_handle;

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, 0);
    // expect_value(__wrap_pthread_mutex_lock, mutex, &init_param->state_mutex);

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, init_param->state_str_len[DeployTopicFirmware] + 1);

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);
    // expect_value(__wrap_pthread_mutex_unlock, mutex, &init_param->state_mutex);

    // Exet test target
    ret = SysAppDeployGetFirmwareState(&state_str, &size);

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_string_equal(state_str, init_param->state_str[DeployTopicFirmware]);
    assert_int_equal(size, init_param->state_str_len[DeployTopicFirmware]);

exit:
    if (state_str != NULL) {
        free(state_str);
    }

    FinGlobalVariableForGetState();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployGetFirmwareState_NullHandle(void **state)
{
    RetCode ret;
    char *state_str = NULL;
    uint32_t size;

    // Initialize global variable
    s_handle = (SysAppDeployHandle)NULL;

    // Exet test target
    ret = SysAppDeployGetFirmwareState(&state_str, &size);

    // Check output
    assert_int_equal(ret, kRetStateViolate);

    if (state_str != NULL) {
        free(state_str);
    }
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployGetFirmwareState_NullState(void **state)
{
    RetCode ret;
    uint32_t size;

    // Initialize global variable
    if (InitGlobalVariableForGetState() == false) {
        goto exit;
    }

    // Exet test target
    ret = SysAppDeployGetFirmwareState(NULL, &size);

    // Check output
    assert_int_equal(ret, kRetStateViolate);

exit:
    FinGlobalVariableForGetState();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployGetFirmwareState_NullSize(void **state)
{
    RetCode ret;
    char *state_str = NULL;

    // Initialize global variable
    if (InitGlobalVariableForGetState() == false) {
        goto exit;
    }

    // Exet test target
    ret = SysAppDeployGetFirmwareState(&state_str, NULL);

    // Check output
    assert_int_equal(ret, kRetStateViolate);

exit:
    if (state_str != NULL) {
        free(state_str);
    }

    FinGlobalVariableForGetState();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployGetFirmwareState_ErrorPthreadMutexLock(void **state)
{
    RetCode ret;
    char *state_str = NULL;
    uint32_t size;
    // DeployInitParams_t *init_param;

    // Initialize global variable
    if (InitGlobalVariableForGetState() == false) {
        goto exit;
    }
    // init_param = (DeployInitParams_t *)s_handle;

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, -1);
    // expect_value(__wrap_pthread_mutex_lock, mutex, &init_param->state_mutex);

    // Exet test target
    ret = SysAppDeployGetFirmwareState(&state_str, &size);

    // Check output
    assert_int_equal(ret, kRetFailed);
    assert_null(state_str);
    assert_int_equal(size, 0);

exit:
    if (state_str != NULL) {
        free(state_str);
    }

    FinGlobalVariableForGetState();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployGetFirmwareState_StateStrNothing(void **state)
{
    RetCode ret;
    char *state_str = NULL;
    uint32_t size;
    DeployInitParams_t *init_param;

    // Initialize global variable
    if (InitGlobalVariableForGetState() == false) {
        goto exit;
    }
    init_param = (DeployInitParams_t *)s_handle;

    free(init_param->state_str[DeployTopicFirmware]);
    init_param->state_str[DeployTopicFirmware] = NULL;

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, 0);
    // expect_value(__wrap_pthread_mutex_lock, mutex, &init_param->state_mutex);

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);
    // expect_value(__wrap_pthread_mutex_unlock, mutex, &init_param->state_mutex);

    // Exet test target
    ret = SysAppDeployGetFirmwareState(&state_str, &size);

    // Check output
    assert_int_equal(ret, kRetFailed);
    assert_null(state_str);
    assert_int_equal(size, 0);

exit:
    if (state_str != NULL) {
        free(state_str);
    }

    FinGlobalVariableForGetState();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployGetFirmwareState_ErrorMalloc(void **state)
{
    RetCode ret;
    char *state_str = NULL;
    uint32_t size;
    DeployInitParams_t *init_param;

    // Initialize global variable
    if (InitGlobalVariableForGetState() == false) {
        goto exit;
    }
    init_param = (DeployInitParams_t *)s_handle;

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, 0);
    // expect_value(__wrap_pthread_mutex_lock, mutex, &init_param->state_mutex);

    // For malloc()
    will_return(mock_malloc, true);  // Exec parameter check
    will_return(mock_malloc, false); // Get NULL
    expect_value(mock_malloc, __size, init_param->state_str_len[DeployTopicFirmware] + 1);

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);
    // expect_value(__wrap_pthread_mutex_unlock, mutex, &init_param->state_mutex);

    // Exet test target
    ret = SysAppDeployGetFirmwareState(&state_str, &size);

    // Check output
    assert_int_equal(ret, kRetFailed);
    assert_null(state_str);
    assert_int_equal(size, 0);

exit:
    if (state_str != NULL) {
        free(state_str);
    }

    FinGlobalVariableForGetState();
}

/*----------------------------------------------------------------------------*/

//
// SysAppDeployGetAiModelState()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployGetAiModelState_FullySuccess(void **state)
{
    RetCode ret;
    char *state_str = NULL;
    uint32_t size;
    DeployInitParams_t *init_param;

    // Initialize global variable
    if (InitGlobalVariableForGetState() == false) {
        goto exit;
    }
    init_param = (DeployInitParams_t *)s_handle;

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, 0);
    // expect_value(__wrap_pthread_mutex_lock, mutex, &init_param->state_mutex);

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, init_param->state_str_len[DeployTopicAiModel] + 1);

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);
    // expect_value(__wrap_pthread_mutex_unlock, mutex, &init_param->state_mutex);

    // Exet test target
    ret = SysAppDeployGetAiModelState(&state_str, &size);

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_string_equal(state_str, init_param->state_str[DeployTopicAiModel]);
    assert_int_equal(size, init_param->state_str_len[DeployTopicAiModel]);

exit:
    if (state_str != NULL) {
        free(state_str);
    }

    FinGlobalVariableForGetState();
}

/*----------------------------------------------------------------------------*/

//
// SysAppDeployGetSensorCalibrationParamState()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployGetSensorCalibrationParamState_FullySuccess(void **state)
{
    RetCode ret;
    char *state_str = NULL;
    uint32_t size;
    DeployInitParams_t *init_param;

    // Initialize global variable
    if (InitGlobalVariableForGetState() == false) {
        goto exit;
    }
    init_param = (DeployInitParams_t *)s_handle;

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, 0);
    // expect_value(__wrap_pthread_mutex_lock, mutex, &init_param->state_mutex);

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, init_param->state_str_len[DeployTopicCameraSetup] + 1);

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);
    // expect_value(__wrap_pthread_mutex_unlock, mutex, &init_param->state_mutex);

    // Exet test target
    ret = SysAppDeployGetSensorCalibrationParamState(&state_str, &size);

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_string_equal(state_str, init_param->state_str[DeployTopicCameraSetup]);
    assert_int_equal(size, init_param->state_str_len[DeployTopicCameraSetup]);

exit:
    if (state_str != NULL) {
        free(state_str);
    }

    FinGlobalVariableForGetState();
}

/*----------------------------------------------------------------------------*/

//
// SysAppDeployFreeState()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployFreeState_NotNullState(void **state)
{
    RetCode ret;
    char *state_str_buff;

    // Prepare test target argument
    state_str_buff = malloc(10);
    if (state_str_buff == NULL) {
        assert_non_null(state_str_buff);
        goto exit;
    }

    // For free()
    will_return(mock_free, true); // Exec parameter check
    expect_value(mock_free, __ptr, state_str_buff);

    // Exec test target
    ret = SysAppDeployFreeState(state_str_buff);

    // Check output
    assert_int_equal(ret, kRetOk);

exit:
    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployFreeState_NullState(void **state)
{
    RetCode ret;

    // Exec test target
    ret = SysAppDeployFreeState(NULL);

    // Check output
    assert_int_equal(ret, kRetOk);
}

/*----------------------------------------------------------------------------*/

//
// SysAppDeployCheckResetRequest()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployCheckResetRequest_FullySuccessRequest(void **state)
{
    bool ret;
    bool is_downgrade = false;

    // Initialize global variable
    if (InitGlobalVariableForSysAppDeployCheckResetRequest(true) == false) {
        goto exit;
    }

    // Exec test target
    ret = SysAppDeployCheckResetRequest(&is_downgrade);

    // Check output
    assert_true(ret);

exit:
    FinGlobalVariableForSysAppDeployCheckResetRequest();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployCheckResetRequest_FullySuccessNotRequest(void **state)
{
    bool ret;
    bool is_downgrade = false;

    // Initialize global variable
    if (InitGlobalVariableForSysAppDeployCheckResetRequest(false) == false) {
        goto exit;
    }

    // Exec test target
    ret = SysAppDeployCheckResetRequest(&is_downgrade);

    // Check output
    assert_false(ret);

exit:
    FinGlobalVariableForSysAppDeployCheckResetRequest();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployCheckResetRequest_ErrorStateViolate(void **state)
{
    bool ret;
    bool is_downgrade = false;

    // Initialize global variable
    s_handle = (SysAppDeployHandle)NULL;

    // Exec test target
    ret = SysAppDeployCheckResetRequest(&is_downgrade);

    // Check output
    assert_false(ret);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployCheckResetRequest_InvalidArgument(void **state)
{
    bool ret;

    // Initialize global variable
    if (InitGlobalVariableForSysAppDeployCheckResetRequest(true) == false) {
        goto exit;
    }

    // Exec test target
    ret = SysAppDeployCheckResetRequest(NULL);

    // Check output
    assert_false(ret);

exit:
    FinGlobalVariableForSysAppDeployCheckResetRequest();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployCheckResetRequest_SwArchVersion1(void **state)
{
    bool ret;
    bool is_downgrade = false;

    // Initialize global variable
    if (InitGlobalVariableForSysAppDeployCheckResetRequest(true) == false) {
        goto exit;
    }

    DeployInitParams_t *init_param = (DeployInitParams_t *)s_handle;

    init_param->arch_version = kEsfFwMgrSwArchVersion1;

    // Exec test target
    ret = SysAppDeployCheckResetRequest(&is_downgrade);

    // Check output
    assert_true(ret);
    assert_true(is_downgrade);

exit:
    FinGlobalVariableForSysAppDeployCheckResetRequest();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployCheckResetRequest_SwArchVersion2(void **state)
{
    bool ret;
    bool is_downgrade = false;

    // Initialize global variable
    if (InitGlobalVariableForSysAppDeployCheckResetRequest(true) == false) {
        goto exit;
    }

    DeployInitParams_t *init_param = (DeployInitParams_t *)s_handle;

    init_param->arch_version = kEsfFwMgrSwArchVersion2;

    // Exec test target
    ret = SysAppDeployCheckResetRequest(&is_downgrade);

    // Check output
    assert_true(ret);
    assert_false(is_downgrade);

exit:
    FinGlobalVariableForSysAppDeployCheckResetRequest();
}

/*----------------------------------------------------------------------------*/

//
// SysAppDeployFactoryReset()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployFactoryReset_FullySuccessRequest(void **state)
{
    // Exec test target

    expect_value(__wrap_EsfFwMgrStartFactoryReset, cause, kEsfFwMgrResetCauseDowngrade);
    will_return(__wrap_EsfFwMgrStartFactoryReset, kEsfFwMgrResultOk);

    SysAppDeployFactoryReset();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployFactoryReset_ErrorCause(void **state)
{
    // Exec test target

    expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
    expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelError);
    expect_value(__wrap_UtilityLogWriteELog, event_id, ELOG_EVENT_ID_OTA_FAILED);
    will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);
    expect_value(__wrap_EsfFwMgrStartFactoryReset, cause, kEsfFwMgrResetCauseDowngrade);
    will_return(__wrap_EsfFwMgrStartFactoryReset, kEsfFwMgrResultInternal);

    SysAppDeployFactoryReset();
}

/*----------------------------------------------------------------------------*/

//
// InitSha256()
//

/*----------------------------------------------------------------------------*/
static void test_InitSha256_FullySuccess(void **state)
{
    void *ret;
    mbedtls_sha256_context *ctx = NULL;

    // mock operation for InitSha256()
    ctx = malloc(sizeof(mbedtls_sha256_context));
    if (ctx == NULL) {
        assert_non_null(ctx);
        goto exit;
    }
    InitSha256Common(ctx, false);

    // Exec test target
    ret = InitSha256();

    // Check output
    assert_non_null(ret);

    // Free memory allocated by test target
    if (ret != NULL) {
        free(ret);
    }

exit:
    if (ctx != NULL) {
        free(ctx);
    }
}

/*----------------------------------------------------------------------------*/
static void test_InitSha256_ErrorMalloc(void **state)
{
    void *ret;

    // For malloc()
    will_return(mock_malloc, true);  // Exec parameter check
    will_return(mock_malloc, false); // Get NULL
    expect_value(mock_malloc, __size, sizeof(mbedtls_sha256_context));

    // Exec test target
    ret = InitSha256();

    // Check output
    assert_null(ret);

    // Free memory allocated by test target
    if (ret != NULL) {
        free(ret);
    }
}

/*----------------------------------------------------------------------------*/

//
// UpdateSha256()
//

/*----------------------------------------------------------------------------*/
static void test_UpdateSha256_FullySuccess(void **state)
{
    int ret;
    mbedtls_sha256_context *ctx;
    const char *input = "UpdateSha256Test";
    size_t input_len = strlen(input) + 1;

    // mock operation for UpdateSha256()
    ctx = malloc(sizeof(mbedtls_sha256_context));
    if (ctx == NULL) {
        assert_non_null(ctx);
        goto exit;
    }
    UpdateSha256FullySuccess(ctx, input);

    // Exec test target
    ret = UpdateSha256(ctx, input_len, (const uint8_t *)input);

    // Check output
    assert_int_equal(ret, 0);

exit:
    if (ctx != NULL) {
        free(ctx);
    }
}

/*----------------------------------------------------------------------------*/
static void test_UpdateSha256_NullHandle(void **state)
{
    int ret;
    const char *input = "UpdateSha256Test";
    size_t input_len = strlen(input) + 1;

    // Exec test target
    ret = UpdateSha256(NULL, input_len, (const uint8_t *)input);

    // Check output
    assert_int_equal(ret, -1);
}

/*----------------------------------------------------------------------------*/
static void test_UpdateSha256_NullInput(void **state)
{
    int ret;
    mbedtls_sha256_context ctx;

    // Exec test target
    ret = UpdateSha256(&ctx, 0, NULL);

    // Check output
    assert_int_equal(ret, -1);
}

/*----------------------------------------------------------------------------*/

//
// FinishSha256()
//

/*----------------------------------------------------------------------------*/
static void test_FinishSha256_FullySuccess(void **state)
{
    int ret;
    mbedtls_sha256_context *ctx;
    uint8_t output[32];
    const char *checksum_result = "1234";

    // mock operation for FinishSha256()
    ctx = malloc(sizeof(mbedtls_sha256_context));
    if (ctx == NULL) {
        assert_non_null(ctx);
        goto exit;
    }
    FinishSha256FullySuccess(ctx, checksum_result);

    // Exec test target
    ret = FinishSha256(ctx, (uint8_t *)&output);

    // Check output
    assert_int_equal(ret, 0);
    assert_string_equal((char *)output, checksum_result);

exit:
    return;
}

/*----------------------------------------------------------------------------*/
static void test_FinishSha256_NullHandle(void **state)
{
    int ret;
    uint8_t output[32];

    // Exec test target
    ret = FinishSha256(NULL, (uint8_t *)&output);

    // Check output
    assert_int_equal(ret, -1);
}

/*----------------------------------------------------------------------------*/
static void test_FinishSha256_NullOutput(void **state)
{
    int ret;
    mbedtls_sha256_context *ctx;

    // Prepare mbedtls paramter
    ctx = malloc(sizeof(mbedtls_sha256_context));
    if (ctx == NULL) {
        assert_non_null(ctx);
        goto exit;
    }
    InitMbedtlsSha256Context(ctx);

    // For mbedtls_sha256_free()
    expect_memory(__wrap_mbedtls_sha256_free, ctx, ctx, sizeof(mbedtls_sha256_context));

    // For free()
    will_return(mock_free, true); // Exec parameter check
    expect_value(mock_free, __ptr, ctx);

    // Exec test target
    ret = FinishSha256(ctx, NULL);

    // Check output
    assert_int_equal(ret, -1);

exit:
    return;
}

/*----------------------------------------------------------------------------*/

//
// SetTargetState()
//

/*----------------------------------------------------------------------------*/
static void test_SetTargetState(void **state)
{
    int ret;
    DeployTarget_t *target;
    int progress = 75;
    DeployState_e deploy_state = DeployStateInstalling;

    // Initialize test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    target->progress = 0;
    target->process_state = DeployStateIdle;

    // Exec test target
    ret = SetTargetState(target, progress, deploy_state);

    // Check output
    assert_int_equal(ret, progress);
    assert_int_equal(target->progress, progress);
    assert_int_equal(target->process_state, deploy_state);

exit:
    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/

//
// ExtractStringValue()
//

/*----------------------------------------------------------------------------*/
static void test_ExtractStringValue_FullySuccess(void **state)
{
    int ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *jsonkey = "json_key";
    const char *extra_string = "extra_string";
    char output_buff[16] = {0};

    // mock operation for ExtractStringValue()
    ExtractStringValueCommon(handle_val, parent_val, jsonkey, extra_string, 1);

    // Exec test target
    ret = ExtractStringValue(handle_val, parent_val, jsonkey, output_buff, sizeof(output_buff),
                             sizeof(output_buff) - 1);

    // Check output
    assert_int_equal(ret, 1);
    assert_string_equal(output_buff, extra_string);
}

/*----------------------------------------------------------------------------*/
static void test_ExtractStringValue_ErrorSysAppCmnExtractStringValue(void **state)
{
    int ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *jsonkey = "json_key";
    const char *extra_string = "extra_string";
    char output_buff[16] = {0};

    // mock operation for ExtractStringValue()
    ExtractStringValueCommon(handle_val, parent_val, jsonkey, extra_string, 0);

    // Exec test target
    ret = ExtractStringValue(handle_val, parent_val, jsonkey, output_buff, sizeof(output_buff),
                             sizeof(output_buff) - 1);

    // Check output
    assert_int_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_ExtractStringValue_NullPointerSysAppCmnExtractStringValue(void **state)
{
    int ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *jsonkey = "json_key";
    char output_buff[16] = {0};

    // mock operation for ExtractStringValue()
    ExtractStringValueCommon(handle_val, parent_val, jsonkey, NULL, 1);

    // Exec test target
    ret = ExtractStringValue(handle_val, parent_val, jsonkey, output_buff, sizeof(output_buff),
                             sizeof(output_buff) - 1);

    // Check output
    assert_int_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_ExtractStringValue_NullStrSysAppCmnExtractStringValue(void **state)
{
    int ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *jsonkey = "json_key";
    const char *extra_string = "";
    char output_buff[16] = {0};

    // mock operation for ExtractStringValue()
    ExtractStringValueCommon(handle_val, parent_val, jsonkey, extra_string, 1);

    // Exec test target
    ret = ExtractStringValue(handle_val, parent_val, jsonkey, output_buff, sizeof(output_buff),
                             sizeof(output_buff) - 1);

    // Check output
    assert_int_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_ExtractStringValue_MaxOverBuffExtraString(void **state)
{
    int ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *jsonkey = "json_key";
    const char *extra_string = "1234567890123456";
    char output_buff[16] = {0};

    // mock operation for ExtractStringValue()
    ExtractStringValueCommon(handle_val, parent_val, jsonkey, extra_string, 1);

    // Exec test target
    ret = ExtractStringValue(handle_val, parent_val, jsonkey, output_buff, sizeof(output_buff),
                             sizeof(output_buff) - 1);

    // Check output
    assert_int_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_ExtractStringValue_MaxBuffExtraString(void **state)
{
    int ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *jsonkey = "json_key";
    const char *extra_string = "123456789012345";
    char output_buff[16] = {0};

    // mock operation for ExtractStringValue()
    ExtractStringValueCommon(handle_val, parent_val, jsonkey, extra_string, 1);

    // Exec test target
    ret = ExtractStringValue(handle_val, parent_val, jsonkey, output_buff, sizeof(output_buff),
                             sizeof(output_buff) - 1);

    // Check output
    assert_int_equal(ret, 1);
    assert_string_equal(output_buff, extra_string);
}

/*----------------------------------------------------------------------------*/
static void test_ExtractStringValue_MaxOverExtracedLenExtraString(void **state)
{
    int ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *jsonkey = "json_key";
    const char *extra_string = "1234567890";
    char output_buff[16] = {0};

    // mock operation for ExtractStringValue()
    ExtractStringValueCommon(handle_val, parent_val, jsonkey, extra_string, 1);

    // Exec test target
    ret = ExtractStringValue(handle_val, parent_val, jsonkey, output_buff, sizeof(output_buff),
                             strlen(extra_string) - 1);

    // Check output
    assert_int_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_ExtractStringValue_MaxExtracedLenExtraString(void **state)
{
    int ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *jsonkey = "json_key";
    const char *extra_string = "1234567890";
    char output_buff[16] = {0};

    // mock operation for ExtractStringValue()
    ExtractStringValueCommon(handle_val, parent_val, jsonkey, extra_string, 1);

    // Exec test target
    ret = ExtractStringValue(handle_val, parent_val, jsonkey, output_buff, sizeof(output_buff),
                             strlen(extra_string));

    // Check output
    assert_int_equal(ret, 1);
    assert_string_equal(output_buff, extra_string);
}

/*----------------------------------------------------------------------------*/

//
// MakeJsonStateReqInfo()
//

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateReqInfo_FullySuccess(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *req_id_val = "No.1234";

    // mock operation for MakeJsonStateReqInfoFullySuccess()
    MakeJsonStateReqInfoFullySuccess(handle_val, parent_val, req_id_val);

    // Exec test target
    MakeJsonStateReqInfo((char *)req_id_val, handle_val, parent_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateReqInfo_ErrorEsfJsonObjectInit(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *req_id_val = "No.1234";

    // For EsfJsonObjectInit()
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonInternalError);

    // Exec test target
    MakeJsonStateReqInfo((char *)req_id_val, handle_val, parent_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateReqInfo_ErrorSysAppCmnSetStringValue(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *req_id_val = "No.1234";

    // For EsfJsonObjectInit()
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // For SysAppCmnSetStringValue()
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, child_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "req_id");
    expect_string(__wrap_SysAppCmnSetStringValue, string, req_id_val);
    will_return(__wrap_SysAppCmnSetStringValue, kRetFailed);

    // Exec test target
    MakeJsonStateReqInfo((char *)req_id_val, handle_val, parent_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateReqInfo_ErrorEsfJsonObjectSet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *req_id_val = "No.1234";

    // For EsfJsonObjectInit()
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // For SysAppCmnSetStringValue()
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, child_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "req_id");
    expect_string(__wrap_SysAppCmnSetStringValue, string, req_id_val);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // For EsfJsonObjectSet()
    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, "req_info");
    expect_value(__wrap_EsfJsonObjectSet, value, child_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonInternalError);

    // Exec test target
    MakeJsonStateReqInfo((char *)req_id_val, handle_val, parent_val);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SetResInfo()
//

/*----------------------------------------------------------------------------*/
static void test_SetResInfo_Done(void **state)
{
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // Exec test target
    SetResInfo(res_info, DeployStateDone);

    // Check output
    assert_int_equal(res_info->code, 0);
    assert_string_equal(res_info->detail_msg, "ok");

exit:
    if (res_info != NULL) {
        free(res_info);
    }
}

/*----------------------------------------------------------------------------*/
static void test_SetResInfo_Failed(void **state)
{
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // Exec test target
    SetResInfo(res_info, DeployStateFailed);

    // Check output
    assert_int_equal(res_info->code, 13);
    assert_string_equal(res_info->detail_msg, "internal");

exit:
    if (res_info != NULL) {
        free(res_info);
    }
}

/*----------------------------------------------------------------------------*/
static void test_SetResInfo_FailedTokenExpired(void **state)
{
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // Exec test target
    SetResInfo(res_info, DeployStateFailedTokenExpired);

    // Check output
    assert_int_equal(res_info->code, 7);
    assert_string_equal(res_info->detail_msg, "permission_denied");

exit:
    if (res_info != NULL) {
        free(res_info);
    }
}

/*----------------------------------------------------------------------------*/
static void test_SetResInfo_FailedDownloadRetryExceeded(void **state)
{
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // Exec test target
    SetResInfo(res_info, DeployStateFailedDownloadRetryExceeded);

    // Check output
    assert_int_equal(res_info->code, 4);
    assert_string_equal(res_info->detail_msg, "deadline_exceeded");

exit:
    if (res_info != NULL) {
        free(res_info);
    }
}

/*----------------------------------------------------------------------------*/
static void test_SetResInfo_FailedInvalidRequest(void **state)
{
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // Exec test target
    SetResInfo(res_info, DeployStateFailedInvalidRequest);

    // Check output
    assert_int_equal(res_info->code, 3);
    assert_string_equal(res_info->detail_msg, "invalid_argument");

exit:
    if (res_info != NULL) {
        free(res_info);
    }
}

/*----------------------------------------------------------------------------*/
static void test_SetResInfo_FailedUnavailable(void **state)
{
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // Exec test target
    SetResInfo(res_info, DeployStateFailedUnavailable);

    // Check output
    assert_int_equal(res_info->code, 14);
    assert_string_equal(res_info->detail_msg, "unavailable");

exit:
    if (res_info != NULL) {
        free(res_info);
    }
}

/*----------------------------------------------------------------------------*/
static void test_SetResInfo_FailedCancelled(void **state)
{
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // Exec test target
    SetResInfo(res_info, DeployStateFailed);

    // Check output
    assert_int_equal(res_info->code, 13);
    assert_string_equal(res_info->detail_msg, "internal");

exit:
    if (res_info != NULL) {
        free(res_info);
    }
}

/*----------------------------------------------------------------------------*/
static void test_SetResInfo_Other(void **state)
{
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // Exec test target
    SetResInfo(res_info, DeployStateInstalling);

    // Check output
    assert_int_equal(res_info->code, -1);
    assert_string_equal(res_info->detail_msg, "");

exit:
    if (res_info != NULL) {
        free(res_info);
    }
}

/*----------------------------------------------------------------------------*/

//
// ConvertComponentToState()
//

/*----------------------------------------------------------------------------*/
static void test_ConvertComponentToState_SensorLoader(void **state)
{
    DeployComponent_e ret;

    // Exec test target
    ret = ConvertComponentToState(DeployComponentSensorLoader);

    // Check output
    assert_int_equal(ret, DeployComponentLoader);
}

/*----------------------------------------------------------------------------*/
static void test_ConvertComponentToState_SensorFirmware(void **state)
{
    DeployComponent_e ret;

    // Exec test target
    ret = ConvertComponentToState(DeployComponentSensorFirmware);

    // Check output
    assert_int_equal(ret, DeployComponentFirmware);
}

/*----------------------------------------------------------------------------*/
static void test_ConvertComponentToState_ProcessorLoader(void **state)
{
    DeployComponent_e ret;

    // Exec test target
    ret = ConvertComponentToState(DeployComponentProcessorLoader);

    // Check output
    assert_int_equal(ret, DeployComponentLoader);
}

/*----------------------------------------------------------------------------*/
static void test_ConvertComponentToState_ProcessorFirmware(void **state)
{
    DeployComponent_e ret;

    // Exec test target
    ret = ConvertComponentToState(DeployComponentProcessorFirmware);

    // Check output
    assert_int_equal(ret, DeployComponentFirmware);
}

/*----------------------------------------------------------------------------*/
static void test_ConvertComponentToState_SensorCalibrationParam(void **state)
{
    DeployComponent_e ret;

    // Exec test target
    ret = ConvertComponentToState(DeployComponentSensorCalibrationParam);

    // Check output
    assert_int_equal(ret, DeployComponentNum);
}

/*----------------------------------------------------------------------------*/
static void test_ConvertComponentToState_AiModel(void **state)
{
    DeployComponent_e ret;

    // Exec test target
    ret = ConvertComponentToState(DeployComponentAiModel);

    // Check output
    assert_int_equal(ret, DeployComponentNum);
}

/*----------------------------------------------------------------------------*/
static void test_ConvertComponentToState_Other(void **state)
{
    DeployComponent_e ret;

    // Exec test target
    ret = ConvertComponentToState(6);

    // Check output
    assert_int_equal(ret, DeployComponentNum);
}

/*----------------------------------------------------------------------------*/

//
// MakeJsonStateDeployTarget()
//

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployTarget_FullySuccessBase(void **state)
{
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // mock operation for MakeJsonStateDeployTarget()
    MakeJsonStateDeployTargetCommon(target, handle_val, parent_val,
                                    MakeJsonStateDeployTargetError_None);

    // Exec test target
    MakeJsonStateDeployTarget(target, handle_val, parent_val, res_info);

    // Check output
    assert_int_equal(res_info->code, 0);
    assert_string_equal(res_info->detail_msg, "ok");

exit:
    if (res_info != NULL) {
        free(res_info);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployTarget_FullySuccessNothingComponent(void **state)
{
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    target->component = DeployComponentAiModel;

    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // mock operation for ExtractStringValue()
    MakeJsonStateDeployTargetCommon(target, handle_val, parent_val,
                                    MakeJsonStateDeployTargetError_None);

    // Exec test target
    MakeJsonStateDeployTarget(target, handle_val, parent_val, res_info);

    // Check output
    assert_int_equal(res_info->code, 0);
    assert_string_equal(res_info->detail_msg, "ok");

exit:
    if (res_info != NULL) {
        free(res_info);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployTarget_FullySuccessNothingChip(void **state)
{
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    target->chip[0] = '\0';

    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // mock operation for ExtractStringValue()
    MakeJsonStateDeployTargetCommon(target, handle_val, parent_val,
                                    MakeJsonStateDeployTargetError_None);

    // Exec test target
    MakeJsonStateDeployTarget(target, handle_val, parent_val, res_info);

    // Check output
    assert_int_equal(res_info->code, 0);
    assert_string_equal(res_info->detail_msg, "ok");

exit:
    if (res_info != NULL) {
        free(res_info);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployTarget_FullySuccessProcessStateIdle(void **state)
{
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    target->process_state = DeployStateIdle;

    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // mock operation for ExtractStringValue()
    MakeJsonStateDeployTargetCommon(target, handle_val, parent_val,
                                    MakeJsonStateDeployTargetError_None);

    // Exec test target
    MakeJsonStateDeployTarget(target, handle_val, parent_val, res_info);

    // Check output
    assert_int_equal(res_info->code, -1);
    assert_string_equal(res_info->detail_msg, "");

exit:
    if (res_info != NULL) {
        free(res_info);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployTarget_FullySuccessProcessStateRequestReceived(void **state)
{
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    target->process_state = DeployStateRequestReceived;

    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // mock operation for ExtractStringValue()
    MakeJsonStateDeployTargetCommon(target, handle_val, parent_val,
                                    MakeJsonStateDeployTargetError_None);

    // Exec test target
    MakeJsonStateDeployTarget(target, handle_val, parent_val, res_info);

    // Check output
    assert_int_equal(res_info->code, -1);
    assert_string_equal(res_info->detail_msg, "");

exit:
    if (res_info != NULL) {
        free(res_info);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployTarget_FullySuccessProcessStateDownloading(void **state)
{
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    target->process_state = DeployStateDownloading;

    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // mock operation for ExtractStringValue()
    MakeJsonStateDeployTargetCommon(target, handle_val, parent_val,
                                    MakeJsonStateDeployTargetError_None);

    // Exec test target
    MakeJsonStateDeployTarget(target, handle_val, parent_val, res_info);

    // Check output
    assert_int_equal(res_info->code, -1);
    assert_string_equal(res_info->detail_msg, "");

exit:
    if (res_info != NULL) {
        free(res_info);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployTarget_FullySuccessProcessStateInstalling(void **state)
{
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    target->process_state = DeployStateInstalling;

    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // mock operation for ExtractStringValue()
    MakeJsonStateDeployTargetCommon(target, handle_val, parent_val,
                                    MakeJsonStateDeployTargetError_None);

    // Exec test target
    MakeJsonStateDeployTarget(target, handle_val, parent_val, res_info);

    // Check output
    assert_int_equal(res_info->code, -1);
    assert_string_equal(res_info->detail_msg, "");

exit:
    if (res_info != NULL) {
        free(res_info);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployTarget_FullySuccessProcessStateFailed(void **state)
{
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    target->process_state = DeployStateFailed;

    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // mock operation for ExtractStringValue()
    MakeJsonStateDeployTargetCommon(target, handle_val, parent_val,
                                    MakeJsonStateDeployTargetError_None);

    // Exec test target
    MakeJsonStateDeployTarget(target, handle_val, parent_val, res_info);

    // Check output
    assert_int_equal(res_info->code, 13);
    assert_string_equal(res_info->detail_msg, "internal");

exit:
    if (res_info != NULL) {
        free(res_info);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployTarget_FullySuccessProcessStateFailedInvalidRequest(
    void **state)
{
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    target->process_state = DeployStateFailedInvalidRequest;

    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // mock operation for ExtractStringValue()
    MakeJsonStateDeployTargetCommon(target, handle_val, parent_val,
                                    MakeJsonStateDeployTargetError_None);

    // Exec test target
    MakeJsonStateDeployTarget(target, handle_val, parent_val, res_info);

    // Check output
    assert_int_equal(res_info->code, 3);
    assert_string_equal(res_info->detail_msg, "invalid_argument");

exit:
    if (res_info != NULL) {
        free(res_info);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployTarget_FullySuccessProcessStateFailedTokenExpired(void **state)
{
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    target->process_state = DeployStateFailedTokenExpired;

    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // mock operation for ExtractStringValue()
    MakeJsonStateDeployTargetCommon(target, handle_val, parent_val,
                                    MakeJsonStateDeployTargetError_None);

    // Exec test target
    MakeJsonStateDeployTarget(target, handle_val, parent_val, res_info);

    // Check output
    assert_int_equal(res_info->code, 7);
    assert_string_equal(res_info->detail_msg, "permission_denied");

exit:
    if (res_info != NULL) {
        free(res_info);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployTarget_FullySuccessProcessStateFailedDownloadRetryExceeded(
    void **state)
{
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    target->process_state = DeployStateFailedDownloadRetryExceeded;

    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // mock operation for ExtractStringValue()
    MakeJsonStateDeployTargetCommon(target, handle_val, parent_val,
                                    MakeJsonStateDeployTargetError_None);

    // Exec test target
    MakeJsonStateDeployTarget(target, handle_val, parent_val, res_info);

    // Check output
    assert_int_equal(res_info->code, 4);
    assert_string_equal(res_info->detail_msg, "deadline_exceeded");

exit:
    if (res_info != NULL) {
        free(res_info);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployTarget_FullySuccessProcessStateFailedUnavailable(void **state)
{
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    target->process_state = DeployStateFailedUnavailable;

    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // mock operation for ExtractStringValue()
    MakeJsonStateDeployTargetCommon(target, handle_val, parent_val,
                                    MakeJsonStateDeployTargetError_None);

    // Exec test target
    MakeJsonStateDeployTarget(target, handle_val, parent_val, res_info);

    // Check output
    assert_int_equal(res_info->code, 14);
    assert_string_equal(res_info->detail_msg, "unavailable");

exit:
    if (res_info != NULL) {
        free(res_info);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployTarget_ErrorSysAppCmnSetNumberValueComponent(void **state)
{
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // mock operation for ExtractStringValue()
    MakeJsonStateDeployTargetCommon(target, handle_val, parent_val,
                                    MakeJsonStateDeployTargetError_Component);

    // Exec test target
    MakeJsonStateDeployTarget(target, handle_val, parent_val, res_info);

    // Check output
    assert_int_equal(res_info->code, 0);
    assert_string_equal(res_info->detail_msg, "ok");

exit:
    if (res_info != NULL) {
        free(res_info);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployTarget_ErrorSysAppCmnSetStringValueChip(void **state)
{
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // mock operation for ExtractStringValue()
    MakeJsonStateDeployTargetCommon(target, handle_val, parent_val,
                                    MakeJsonStateDeployTargetError_Chip);

    // Exec test target
    MakeJsonStateDeployTarget(target, handle_val, parent_val, res_info);

    // Check output
    assert_int_equal(res_info->code, 0);
    assert_string_equal(res_info->detail_msg, "ok");

exit:
    if (res_info != NULL) {
        free(res_info);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployTarget_ErrorSysAppCmnSetStringValuePackageUrl(void **state)
{
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // mock operation for ExtractStringValue()
    MakeJsonStateDeployTargetCommon(target, handle_val, parent_val,
                                    MakeJsonStateDeployTargetError_PackageUrl);

    // Exec test target
    MakeJsonStateDeployTarget(target, handle_val, parent_val, res_info);

    // Check output
    assert_int_equal(res_info->code, 0);
    assert_string_equal(res_info->detail_msg, "ok");

exit:
    if (res_info != NULL) {
        free(res_info);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployTarget_ErrorSysAppCmnSetStringValueVersion(void **state)
{
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // mock operation for ExtractStringValue()
    MakeJsonStateDeployTargetCommon(target, handle_val, parent_val,
                                    MakeJsonStateDeployTargetError_Version);

    // Exec test target
    MakeJsonStateDeployTarget(target, handle_val, parent_val, res_info);

    // Check output
    assert_int_equal(res_info->code, 0);
    assert_string_equal(res_info->detail_msg, "ok");

exit:
    if (res_info != NULL) {
        free(res_info);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployTarget_ErrorSysAppCmnSetStringValueHash(void **state)
{
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // mock operation for ExtractStringValue()
    MakeJsonStateDeployTargetCommon(target, handle_val, parent_val,
                                    MakeJsonStateDeployTargetError_Hash);

    // Exec test target
    MakeJsonStateDeployTarget(target, handle_val, parent_val, res_info);

    // Check output
    assert_int_equal(res_info->code, 0);
    assert_string_equal(res_info->detail_msg, "ok");

exit:
    if (res_info != NULL) {
        free(res_info);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployTarget_ErrorSysAppCmnSetNumberValueSize(void **state)
{
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // mock operation for ExtractStringValue()
    MakeJsonStateDeployTargetCommon(target, handle_val, parent_val,
                                    MakeJsonStateDeployTargetError_Size);

    // Exec test target
    MakeJsonStateDeployTarget(target, handle_val, parent_val, res_info);

    // Check output
    assert_int_equal(res_info->code, 0);
    assert_string_equal(res_info->detail_msg, "ok");

exit:
    if (res_info != NULL) {
        free(res_info);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployTarget_ErrorSysAppCmnSetNumberValueProgress(void **state)
{
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // mock operation for ExtractStringValue()
    MakeJsonStateDeployTargetCommon(target, handle_val, parent_val,
                                    MakeJsonStateDeployTargetError_Progress);

    // Exec test target
    MakeJsonStateDeployTarget(target, handle_val, parent_val, res_info);

    // Check output
    assert_int_equal(res_info->code, 0);
    assert_string_equal(res_info->detail_msg, "ok");

exit:
    if (res_info != NULL) {
        free(res_info);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployTarget_ErrorSysAppCmnSetNumberValueProcessState(void **state)
{
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    ResInfo_t *res_info = NULL;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    res_info->code = -1;
    memset(res_info->detail_msg, 0x00, sizeof(res_info->detail_msg));

    // mock operation for ExtractStringValue()
    MakeJsonStateDeployTargetCommon(target, handle_val, parent_val,
                                    MakeJsonStateDeployTargetError_ProcessState);

    // Exec test target
    MakeJsonStateDeployTarget(target, handle_val, parent_val, res_info);

    // Check output
    assert_int_equal(res_info->code, 0);
    assert_string_equal(res_info->detail_msg, "ok");

exit:
    if (res_info != NULL) {
        free(res_info);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/

//
// ConvertChipToComponent()
//

/*----------------------------------------------------------------------------*/
static void test_ConvertChipToComponent_MainLoader(void **state)
{
    int ret;
    DeployTarget_t *target;

    // Prepare test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));
    snprintf(target->chip, sizeof(target->chip), "%s", dtdl_deploy_target_chip_main_chip);
    target->component = DeployComponentLoader;

    // Exec test target
    ret = ConvertChipToComponent(DeployTopicFirmware, target);

    // Check output
    assert_int_equal(ret, 0);
    assert_int_equal(target->component, DeployComponentProcessorLoader);
    assert_string_equal(target->name, esf_fw_mgr_open_param_name_ap_fw);

exit:
    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_ConvertChipToComponent_MainFirmware(void **state)
{
    int ret;
    DeployTarget_t *target;

    // Prepare test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));
    snprintf(target->chip, sizeof(target->chip), "%s", dtdl_deploy_target_chip_main_chip);
    target->component = DeployComponentFirmware;

    // Exec test target
    ret = ConvertChipToComponent(DeployTopicFirmware, target);

    // Check output
    assert_int_equal(ret, 0);
    assert_int_equal(target->component, DeployComponentProcessorFirmware);
    assert_string_equal(target->name, esf_fw_mgr_open_param_name_ap_fw);

exit:
    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_ConvertChipToComponent_SensorLoader(void **state)
{
    int ret;
    DeployTarget_t *target;

    // Prepare test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));
    snprintf(target->chip, sizeof(target->chip), "%s", dtdl_deploy_target_chip_sensor_chip);
    target->component = DeployComponentLoader;

    // Exec test target
    ret = ConvertChipToComponent(DeployTopicFirmware, target);

    // Check output
    assert_int_equal(ret, 0);
    assert_int_equal(target->component, DeployComponentSensorLoader);
    assert_string_equal(target->name, esf_fw_mgr_open_param_name_sensor);

exit:
    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_ConvertChipToComponent_SensorFirmware(void **state)
{
    int ret;
    DeployTarget_t *target;

    // Prepare test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));
    snprintf(target->chip, sizeof(target->chip), "%s", dtdl_deploy_target_chip_sensor_chip);
    target->component = DeployComponentFirmware;

    // Exec test target
    ret = ConvertChipToComponent(DeployTopicFirmware, target);

    // Check output
    assert_int_equal(ret, 0);
    assert_int_equal(target->component, DeployComponentSensorFirmware);
    assert_string_equal(target->name, esf_fw_mgr_open_param_name_sensor);

exit:
    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_ConvertChipToComponent_SensorAiModel(void **state)
{
    int ret;
    DeployTarget_t *target;

    // Prepare test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));
    snprintf(target->chip, sizeof(target->chip), "%s", dtdl_deploy_target_chip_sensor_chip);
    target->component = DeployComponentAiModel;

    // Exec test target
    ret = ConvertChipToComponent(DeployTopicAiModel, target);

    // Check output
    assert_int_equal(ret, 0);
    assert_int_equal(target->component, DeployComponentAiModel);
    assert_string_equal(target->name, esf_fw_mgr_open_param_name_sensor);

exit:
    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_ConvertChipToComponent_CompanionLoader(void **state)
{
    int ret;
    DeployTarget_t *target;

    // Prepare test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));
    snprintf(target->chip, sizeof(target->chip), "%s", dtdl_deploy_target_chip_companion_chip);
    target->component = DeployComponentLoader;

    // Exec test target
    ret = ConvertChipToComponent(DeployTopicFirmware, target);

    // Check output
    assert_int_equal(ret, 0);
    assert_int_equal(target->component, DeployComponentSensorLoader);
    assert_string_equal(target->name, esf_fw_mgr_open_param_name_companion);

exit:
    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_ConvertChipToComponent_CompanionFirmware(void **state)
{
    int ret;
    DeployTarget_t *target;

    // Prepare test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));
    snprintf(target->chip, sizeof(target->chip), "%s", dtdl_deploy_target_chip_companion_chip);
    target->component = DeployComponentFirmware;

    // Exec test target
    ret = ConvertChipToComponent(DeployTopicFirmware, target);

    // Check output
    assert_int_equal(ret, 0);
    assert_int_equal(target->component, DeployComponentSensorFirmware);
    assert_string_equal(target->name, esf_fw_mgr_open_param_name_companion);

exit:
    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_ConvertChipToComponent_CompanionAiModel(void **state)
{
    int ret;
    DeployTarget_t *target;

    // Prepare test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));
    snprintf(target->chip, sizeof(target->chip), "%s", dtdl_deploy_target_chip_companion_chip);
    target->component = DeployComponentAiModel;

    // Exec test target
    ret = ConvertChipToComponent(DeployTopicAiModel, target);

    // Check output
    assert_int_equal(ret, 0);
    assert_int_equal(target->component, DeployComponentAiModel);
    assert_string_equal(target->name, esf_fw_mgr_open_param_name_companion);

exit:
    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_ConvertChipToComponent_Invalid(void **state)
{
    int ret;
    DeployTarget_t *target;

    // Prepare test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));
    snprintf(target->chip, sizeof(target->chip), "%s", dtdl_deploy_target_chip_sensor_chip);
    target->component = DeployComponentAiModel;

    // Exec test target
    ret = ConvertChipToComponent(DeployTopicFirmware, target);

    // Check output
    assert_int_equal(ret, -1);

exit:
    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/

//
// CmpTargetNameProperty()
//

/*----------------------------------------------------------------------------*/
static void test_CmpTargetNameProperty_CameraSetupColorMatrix(void **state)
{
    int ret;

    // Exec test target
    ret = CmpTargetNameProperty(DeployTopicCameraSetup, DeployComponentSensorCalibrationParam,
                                "ColorMatrix");

    // Check output
    assert_int_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_CmpTargetNameProperty_CameraSetupGamma(void **state)
{
    int ret;

    // Exec test target
    ret = CmpTargetNameProperty(DeployTopicCameraSetup, DeployComponentSensorCalibrationParam,
                                "Gamma");

    // Check output
    assert_int_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_CmpTargetNameProperty_CameraSetupLscIsp(void **state)
{
    int ret;

    // Exec test target
    ret = CmpTargetNameProperty(DeployTopicCameraSetup, DeployComponentSensorCalibrationParam,
                                "LSCISP");

    // Check output
    assert_int_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_CmpTargetNameProperty_CameraSetupPreWB(void **state)
{
    int ret;

    // Exec test target
    ret = CmpTargetNameProperty(DeployTopicCameraSetup, DeployComponentSensorCalibrationParam,
                                "PreWB");

    // Check output
    assert_int_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_CmpTargetNameProperty_CameraSetupDewarp(void **state)
{
    int ret;

    // Exec test target
    ret = CmpTargetNameProperty(DeployTopicCameraSetup, DeployComponentSensorCalibrationParam,
                                "Dewarp");

    // Check output
    assert_int_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_CmpTargetNameProperty_CameraSetupOther(void **state)
{
    int ret;

    // Exec test target
    ret = CmpTargetNameProperty(DeployTopicCameraSetup, DeployComponentSensorCalibrationParam,
                                "DEWARP");

    // Check output
    assert_int_not_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_CmpTargetNameProperty_FirmwareSensorLoaderImx500(void **state)
{
    int ret;

    // Exec test target
    ret = CmpTargetNameProperty(DeployTopicFirmware, DeployComponentSensorLoader, "IMX500");

    // Check output
    assert_int_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_CmpTargetNameProperty_FirmwareSensorLoaderAiIsp(void **state)
{
    int ret;

    // Exec test target
    ret = CmpTargetNameProperty(DeployTopicFirmware, DeployComponentSensorLoader, "AI-ISP");

    // Check output
    assert_int_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_CmpTargetNameProperty_FirmwareSensorLoaderOther(void **state)
{
    int ret;

    // Exec test target
    ret = CmpTargetNameProperty(DeployTopicFirmware, DeployComponentSensorLoader, "other");

    // Check output
    assert_int_not_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_CmpTargetNameProperty_FirmwareSensorFirmwareImx500(void **state)
{
    int ret;

    // Exec test target
    ret = CmpTargetNameProperty(DeployTopicFirmware, DeployComponentSensorFirmware, "IMX500");

    // Check output
    assert_int_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_CmpTargetNameProperty_FirmwareSensorFirmwareAiIsp(void **state)
{
    int ret;

    // Exec test target
    ret = CmpTargetNameProperty(DeployTopicFirmware, DeployComponentSensorFirmware, "AI-ISP");

    // Check output
    assert_int_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_CmpTargetNameProperty_FirmwareSensorFirmwareOther(void **state)
{
    int ret;

    // Exec test target
    ret = CmpTargetNameProperty(DeployTopicFirmware, DeployComponentSensorFirmware, "other");

    // Check output
    assert_int_not_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_CmpTargetNameProperty_FirmwareOtherEsp32S3(void **state)
{
    int ret;

    // Exec test target
    ret = CmpTargetNameProperty(DeployTopicFirmware, DeployComponentProcessorFirmware, "ESP32-S3");

    // Check output
    assert_int_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_CmpTargetNameProperty_FirmwareOtherEsp32(void **state)
{
    int ret;

    // Exec test target
    ret = CmpTargetNameProperty(DeployTopicFirmware, DeployComponentProcessorFirmware, "ESP32");

    // Check output
    assert_int_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_CmpTargetNameProperty_FirmwareOtherApFw(void **state)
{
    int ret;

    // Exec test target
    ret = CmpTargetNameProperty(DeployTopicFirmware, DeployComponentProcessorFirmware, "ApFw");

    // Check output
    assert_int_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_CmpTargetNameProperty_FirmwareOtherOther(void **state)
{
    int ret;

    // Exec test target
    ret = CmpTargetNameProperty(DeployTopicFirmware, DeployComponentProcessorFirmware, "other");

    // Check output
    assert_int_not_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_CmpTargetNameProperty_AiModelImx500(void **state)
{
    int ret;

    // Exec test target
    ret = CmpTargetNameProperty(DeployTopicAiModel, DeployComponentAiModel, "IMX500");

    // Check output
    assert_int_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_CmpTargetNameProperty_AiModelAiIsp(void **state)
{
    int ret;

    // Exec test target
    ret = CmpTargetNameProperty(DeployTopicAiModel, DeployComponentAiModel, "AI-ISP");

    // Check output
    assert_int_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_CmpTargetNameProperty_AiModelOther(void **state)
{
    int ret;

    // Exec test target
    ret = CmpTargetNameProperty(DeployTopicAiModel, DeployComponentAiModel, "other");

    // Check output
    assert_int_not_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_CmpTargetNameProperty_OtherTopic(void **state)
{
    int ret;

    // Exec test target
    ret = CmpTargetNameProperty(DeployTopicNum, DeployComponentAiModel, "other");

    // Check output
    assert_int_equal(ret, -1);
}

/*----------------------------------------------------------------------------*/

//
// GetConfigurationDeployTargetProperty()
//

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployTargetProperty_FullySuccessAiModel(void **state)
{
    RetCode ret;
    DeployTarget_t *target = NULL;
    DeployTarget_t *expect_value = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    int deploy_id;

    // Prepare test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));
    target->progress = 99;
    target->process_state = DeployStateNum;
    target->parse_state = DeployStateNum;

    deploy_id = DeployTopicAiModel;

    // Create expect value
    expect_value = malloc(sizeof(DeployTarget_t));
    if (expect_value == NULL) {
        assert_non_null(expect_value);
        goto exit;
    }
    SetGetConfigurationDeployTargetPropertyExpectValue(expect_value, -1,
                                                       dtdl_deploy_target_chip_sensor_chip, "");

    // mock operation for GetConfigurationDeployTargetProperty()
    GetConfigurationDeployTargetPropertyCommon(expect_value, handle_val, parent_val, deploy_id);

    // Exec test target
    ret = GetConfigurationDeployTargetProperty(target, handle_val, parent_val, deploy_id);

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_int_equal(target->progress, 0);
    assert_int_equal(target->process_state, DeployStateIdle);
    assert_int_equal(target->component, DeployComponentAiModel);
    assert_int_equal(target->parse_state, DeployStateNum);
    assert_string_equal(target->chip, expect_value->chip);
    assert_string_equal(target->name, esf_fw_mgr_open_param_name_sensor);
    assert_string_equal(target->version, expect_value->version);
    assert_string_equal(target->package_url, expect_value->package_url);
    assert_string_equal(target->hash, expect_value->hash);
    assert_int_equal(target->size, expect_value->size);

exit:
    if (expect_value != NULL) {
        free(expect_value);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployTargetProperty_FullySuccessOther(void **state)
{
    RetCode ret;
    DeployTarget_t *target = NULL;
    DeployTarget_t *expect_value = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    int deploy_id;

    // Prepare test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));
    target->progress = 99;
    target->process_state = DeployStateNum;
    target->parse_state = DeployStateNum;

    deploy_id = DeployTopicFirmware;

    // Create expect value
    expect_value = malloc(sizeof(DeployTarget_t));
    if (expect_value == NULL) {
        assert_non_null(expect_value);
        goto exit;
    }
    SetGetConfigurationDeployTargetPropertyExpectValue(expect_value, DeployComponentLoader,
                                                       dtdl_deploy_target_chip_sensor_chip, "");

    // mock operation for GetConfigurationDeployTargetProperty()
    GetConfigurationDeployTargetPropertyCommon(expect_value, handle_val, parent_val, deploy_id);

    // Exec test target
    ret = GetConfigurationDeployTargetProperty(target, handle_val, parent_val, deploy_id);

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_int_equal(target->progress, 0);
    assert_int_equal(target->process_state, DeployStateIdle);
    assert_int_equal(target->component, DeployComponentSensorLoader);
    assert_int_equal(target->parse_state, DeployStateNum);
    assert_string_equal(target->chip, expect_value->chip);
    assert_string_equal(target->name, esf_fw_mgr_open_param_name_sensor);
    assert_string_equal(target->version, expect_value->version);
    assert_string_equal(target->package_url, expect_value->package_url);
    assert_string_equal(target->hash, expect_value->hash);
    assert_int_equal(target->size, expect_value->size);

exit:
    if (expect_value != NULL) {
        free(expect_value);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployTargetProperty_NotSpecifyChip(void **state)
{
    RetCode ret;
    DeployTarget_t *target = NULL;
    DeployTarget_t *expect_value = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    int deploy_id;

    // Prepare test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));
    target->progress = 99;
    target->process_state = DeployStateNum;
    target->parse_state = DeployStateNum;

    deploy_id = DeployTopicAiModel;

    // Create expect value
    expect_value = malloc(sizeof(DeployTarget_t));
    if (expect_value == NULL) {
        assert_non_null(expect_value);
        goto exit;
    }
    SetGetConfigurationDeployTargetPropertyExpectValue(expect_value, DeployComponentAiModel, "",
                                                       "");

    // mock operation for GetConfigurationDeployTargetProperty()
    GetConfigurationDeployTargetPropertyCommon(expect_value, handle_val, parent_val, deploy_id);

    // Exec test target
    ret = GetConfigurationDeployTargetProperty(target, handle_val, parent_val, deploy_id);

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_int_equal(target->progress, 0);
    assert_int_equal(target->process_state, DeployStateIdle);
    assert_int_equal(target->parse_state, DeployStateFailedInvalidRequest);

exit:
    if (expect_value != NULL) {
        free(expect_value);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployTargetProperty_FullySuccessSpecifyName(void **state)
{
    RetCode ret;
    DeployTarget_t *target = NULL;
    DeployTarget_t *expect_value = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    int deploy_id;

    // Prepare test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));
    target->progress = 99;
    target->process_state = DeployStateNum;
    target->parse_state = DeployStateNum;

    deploy_id = DeployTopicAiModel;

    // Create expect value
    expect_value = malloc(sizeof(DeployTarget_t));
    if (expect_value == NULL) {
        assert_non_null(expect_value);
        goto exit;
    }
    SetGetConfigurationDeployTargetPropertyExpectValue(
        expect_value, DeployComponentNum, dtdl_deploy_target_chip_sensor_chip, "IMX500");

    // mock operation for GetConfigurationDeployTargetProperty()
    GetConfigurationDeployTargetPropertyCommon(expect_value, handle_val, parent_val, deploy_id);

    // Exec test target
    ret = GetConfigurationDeployTargetProperty(target, handle_val, parent_val, deploy_id);

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_int_equal(target->progress, 0);
    assert_int_equal(target->process_state, DeployStateIdle);
    assert_int_equal(target->component, DeployComponentAiModel);
    assert_int_equal(target->parse_state, DeployStateNum);
    assert_string_equal(target->chip, expect_value->chip);
    assert_string_equal(target->name, esf_fw_mgr_open_param_name_sensor);
    assert_string_equal(target->version, expect_value->version);
    assert_string_equal(target->package_url, expect_value->package_url);
    assert_string_equal(target->hash, expect_value->hash);
    assert_int_equal(target->size, expect_value->size);

exit:
    if (expect_value != NULL) {
        free(expect_value);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployTargetProperty_InvalidComponent(void **state)
{
    RetCode ret;
    DeployTarget_t *target = NULL;
    DeployTarget_t *expect_value = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    int deploy_id;

    // Prepare test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));
    target->progress = 99;
    target->process_state = DeployStateNum;
    target->parse_state = DeployStateNum;

    deploy_id = DeployTopicFirmware;

    // Create expect value
    expect_value = malloc(sizeof(DeployTarget_t));
    if (expect_value == NULL) {
        assert_non_null(expect_value);
        goto exit;
    }
    SetGetConfigurationDeployTargetPropertyExpectValue(
        expect_value, DeployComponentV2Num, dtdl_deploy_target_chip_sensor_chip, "IMX500");

    // mock operation for GetConfigurationDeployTargetProperty()
    GetConfigurationDeployTargetPropertyCommonLib(expect_value, handle_val, parent_val, deploy_id,
                                                  kEsfJsonInvalidArgument);

    // Exec test target
    ret = GetConfigurationDeployTargetProperty(target, handle_val, parent_val, deploy_id);

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_int_equal(target->progress, 0);
    assert_int_equal(target->process_state, DeployStateIdle);
    assert_int_equal(target->component, DeployComponentV2Num);
    assert_string_equal(target->chip, expect_value->chip);
    assert_string_equal(target->name, esf_fw_mgr_open_param_name_sensor);
    assert_string_equal(target->version, expect_value->version);
    assert_string_equal(target->package_url, expect_value->package_url);
    assert_string_equal(target->hash, expect_value->hash);
    assert_int_equal(target->size, expect_value->size);

exit:
    if (expect_value != NULL) {
        free(expect_value);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployTargetProperty_NotSpecifyComponent(void **state)
{
    RetCode ret;
    DeployTarget_t *target = NULL;
    DeployTarget_t *expect_value = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    int deploy_id;

    // Prepare test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));
    target->progress = 99;
    target->process_state = DeployStateNum;
    target->parse_state = DeployStateNum;

    deploy_id = DeployTopicFirmware;

    // Create expect value
    expect_value = malloc(sizeof(DeployTarget_t));
    if (expect_value == NULL) {
        assert_non_null(expect_value);
        goto exit;
    }
    SetGetConfigurationDeployTargetPropertyExpectValue(expect_value, DeployComponentNum,
                                                       dtdl_deploy_target_chip_sensor_chip, "");

    // mock operation for GetConfigurationDeployTargetProperty()
    GetConfigurationDeployTargetPropertyCommon(expect_value, handle_val, parent_val, deploy_id);

    // Exec test target
    ret = GetConfigurationDeployTargetProperty(target, handle_val, parent_val, deploy_id);

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_int_equal(target->progress, 0);
    assert_int_equal(target->process_state, DeployStateIdle);
    assert_int_equal(target->parse_state, DeployStateFailedInvalidRequest);

exit:
    if (expect_value != NULL) {
        free(expect_value);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployTargetProperty_NotSpecifyChipAndInvaliComponent(void **state)
{
    RetCode ret;
    DeployTarget_t *target = NULL;
    DeployTarget_t *expect_value = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    int deploy_id;

    // Prepare test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));
    target->progress = 99;
    target->process_state = DeployStateNum;
    target->parse_state = DeployStateNum;

    deploy_id = DeployTopicFirmware;

    // Create expect value
    expect_value = malloc(sizeof(DeployTarget_t));
    if (expect_value == NULL) {
        assert_non_null(expect_value);
        goto exit;
    }
    SetGetConfigurationDeployTargetPropertyExpectValue(expect_value, DeployComponentAiModel, "",
                                                       "");

    // mock operation for GetConfigurationDeployTargetProperty()
    GetConfigurationDeployTargetPropertyCommon(expect_value, handle_val, parent_val, deploy_id);

    // Exec test target
    ret = GetConfigurationDeployTargetProperty(target, handle_val, parent_val, deploy_id);

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_int_equal(target->progress, 0);
    assert_int_equal(target->process_state, DeployStateIdle);
    assert_int_equal(target->parse_state, DeployStateFailedInvalidRequest);

exit:
    if (expect_value != NULL) {
        free(expect_value);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployTargetProperty_InvalidName(void **state)
{
    RetCode ret;
    DeployTarget_t *target = NULL;
    DeployTarget_t *expect_value = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    int deploy_id;

    // Prepare test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));
    target->progress = 99;
    target->process_state = DeployStateNum;
    target->parse_state = DeployStateNum;

    deploy_id = DeployTopicAiModel;

    // Create expect value
    expect_value = malloc(sizeof(DeployTarget_t));
    if (expect_value == NULL) {
        assert_non_null(expect_value);
        goto exit;
    }
    SetGetConfigurationDeployTargetPropertyExpectValue(
        expect_value, DeployComponentNum, dtdl_deploy_target_chip_sensor_chip, "invalid name");

    // mock operation for GetConfigurationDeployTargetProperty()
    GetConfigurationDeployTargetPropertyCommon(expect_value, handle_val, parent_val, deploy_id);

    // Exec test target
    ret = GetConfigurationDeployTargetProperty(target, handle_val, parent_val, deploy_id);

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_int_equal(target->progress, 0);
    assert_int_equal(target->process_state, DeployStateIdle);
    assert_int_equal(target->parse_state, DeployStateFailedInvalidRequest);

exit:
    if (expect_value != NULL) {
        free(expect_value);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployTargetProperty_NotSpecifyVersion(void **state)
{
    RetCode ret;
    DeployTarget_t *target = NULL;
    DeployTarget_t *expect_value = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    int deploy_id;

    // Prepare test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));
    target->progress = 99;
    target->process_state = DeployStateNum;
    target->parse_state = DeployStateNum;

    deploy_id = DeployTopicAiModel;

    // Create expect value
    expect_value = malloc(sizeof(DeployTarget_t));
    if (expect_value == NULL) {
        assert_non_null(expect_value);
        goto exit;
    }
    SetGetConfigurationDeployTargetPropertyExpectValue(expect_value, -1,
                                                       dtdl_deploy_target_chip_sensor_chip, "");
    expect_value->version[0] = '\0';

    // mock operation for GetConfigurationDeployTargetProperty()
    GetConfigurationDeployTargetPropertyCommon(expect_value, handle_val, parent_val, deploy_id);

    // Exec test target
    ret = GetConfigurationDeployTargetProperty(target, handle_val, parent_val, deploy_id);

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_int_equal(target->progress, 0);
    assert_int_equal(target->process_state, DeployStateIdle);
    assert_int_equal(target->parse_state, DeployStateFailedInvalidRequest);

exit:
    if (expect_value != NULL) {
        free(expect_value);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployTargetProperty_NotSpecifyPackageUri(void **state)
{
    RetCode ret;
    DeployTarget_t *target = NULL;
    DeployTarget_t *expect_value = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    int deploy_id;

    // Prepare test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));
    target->progress = 99;
    target->process_state = DeployStateNum;
    target->parse_state = DeployStateNum;

    deploy_id = DeployTopicAiModel;

    // Create expect value
    expect_value = malloc(sizeof(DeployTarget_t));
    if (expect_value == NULL) {
        assert_non_null(expect_value);
        goto exit;
    }
    SetGetConfigurationDeployTargetPropertyExpectValue(expect_value, -1,
                                                       dtdl_deploy_target_chip_sensor_chip, "");
    expect_value->package_url[0] = '\0';

    // mock operation for GetConfigurationDeployTargetProperty()
    GetConfigurationDeployTargetPropertyCommon(expect_value, handle_val, parent_val, deploy_id);

    // Exec test target
    ret = GetConfigurationDeployTargetProperty(target, handle_val, parent_val, deploy_id);

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_int_equal(target->progress, 0);
    assert_int_equal(target->process_state, DeployStateIdle);
    assert_int_equal(target->parse_state, DeployStateFailedInvalidRequest);

exit:
    if (expect_value != NULL) {
        free(expect_value);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployTargetProperty_NotSpecifyHash(void **state)
{
    RetCode ret;
    DeployTarget_t *target = NULL;
    DeployTarget_t *expect_value = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    int deploy_id;

    // Prepare test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));
    target->progress = 99;
    target->process_state = DeployStateNum;
    target->parse_state = DeployStateNum;

    deploy_id = DeployTopicAiModel;

    // Create expect value
    expect_value = malloc(sizeof(DeployTarget_t));
    if (expect_value == NULL) {
        assert_non_null(expect_value);
        goto exit;
    }
    SetGetConfigurationDeployTargetPropertyExpectValue(expect_value, -1,
                                                       dtdl_deploy_target_chip_sensor_chip, "");
    expect_value->hash[0] = '\0';

    // mock operation for GetConfigurationDeployTargetProperty()
    GetConfigurationDeployTargetPropertyCommon(expect_value, handle_val, parent_val, deploy_id);

    // Exec test target
    ret = GetConfigurationDeployTargetProperty(target, handle_val, parent_val, deploy_id);

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_int_equal(target->progress, 0);
    assert_int_equal(target->process_state, DeployStateIdle);
    assert_int_equal(target->parse_state, DeployStateFailedInvalidRequest);

exit:
    if (expect_value != NULL) {
        free(expect_value);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployTargetProperty_NotSpecifySize(void **state)
{
    RetCode ret;
    DeployTarget_t *target = NULL;
    DeployTarget_t *expect_value = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    int deploy_id;

    // Prepare test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));
    target->progress = 99;
    target->process_state = DeployStateNum;
    target->parse_state = DeployStateNum;

    deploy_id = DeployTopicAiModel;

    // Create expect value
    expect_value = malloc(sizeof(DeployTarget_t));
    if (expect_value == NULL) {
        assert_non_null(expect_value);
        goto exit;
    }
    SetGetConfigurationDeployTargetPropertyExpectValue(expect_value, -1,
                                                       dtdl_deploy_target_chip_sensor_chip, "");
    expect_value->size = -2; /* This value means size property doesn't specify */

    // mock operation for GetConfigurationDeployTargetProperty()
    GetConfigurationDeployTargetPropertyCommon(expect_value, handle_val, parent_val, deploy_id);

    // Exec test target
    ret = GetConfigurationDeployTargetProperty(target, handle_val, parent_val, deploy_id);

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_int_equal(target->progress, 0);
    assert_int_equal(target->process_state, DeployStateIdle);
    assert_int_equal(target->component, DeployComponentAiModel);
    assert_int_equal(target->parse_state, DeployStateNum);
    assert_string_equal(target->chip, expect_value->chip);
    assert_string_equal(target->name, esf_fw_mgr_open_param_name_sensor);
    assert_string_equal(target->version, expect_value->version);
    assert_string_equal(target->package_url, expect_value->package_url);
    assert_string_equal(target->hash, expect_value->hash);
    assert_int_equal(target->size, 0);

exit:
    if (expect_value != NULL) {
        free(expect_value);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployTargetProperty_NegativeSize(void **state)
{
    RetCode ret;
    DeployTarget_t *target = NULL;
    DeployTarget_t *expect_value = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    int deploy_id;

    // Prepare test target argument
    target = malloc(sizeof(DeployTarget_t));
    if (target == NULL) {
        assert_non_null(target);
        goto exit;
    }
    memset(target, 0x00, sizeof(DeployTarget_t));
    target->progress = 99;
    target->process_state = DeployStateNum;
    target->parse_state = DeployStateNum;

    deploy_id = DeployTopicAiModel;

    // Create expect value
    expect_value = malloc(sizeof(DeployTarget_t));
    if (expect_value == NULL) {
        assert_non_null(expect_value);
        goto exit;
    }
    SetGetConfigurationDeployTargetPropertyExpectValue(expect_value, -1,
                                                       dtdl_deploy_target_chip_sensor_chip, "");
    expect_value->size = -1;

    // mock operation for GetConfigurationDeployTargetProperty()
    GetConfigurationDeployTargetPropertyCommon(expect_value, handle_val, parent_val, deploy_id);

    // Exec test target
    ret = GetConfigurationDeployTargetProperty(target, handle_val, parent_val, deploy_id);

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_int_equal(target->progress, 0);
    assert_int_equal(target->process_state, DeployStateIdle);
    assert_int_equal(target->component, DeployComponentAiModel);
    assert_int_equal(target->parse_state, DeployStateNum);
    assert_string_equal(target->chip, expect_value->chip);
    assert_string_equal(target->name, esf_fw_mgr_open_param_name_sensor);
    assert_string_equal(target->version, expect_value->version);
    assert_string_equal(target->package_url, expect_value->package_url);
    assert_string_equal(target->hash, expect_value->hash);
    assert_int_equal(target->size, 0);

exit:
    if (expect_value != NULL) {
        free(expect_value);
    }

    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/

//
// GetResCodePriority()
//

/*----------------------------------------------------------------------------*/
static void test_GetResCodePriority_Unimplemented(void **state)
{
    int ret;

    // Exec test target
    ret = GetResCodePriority(12);

    // Check output
    assert_int_equal(ret, 8);
}

/*----------------------------------------------------------------------------*/
static void test_GetResCodePriority_InvalidArgument(void **state)
{
    int ret;

    // Exec test target
    ret = GetResCodePriority(3);

    // Check output
    assert_int_equal(ret, 7);
}

/*----------------------------------------------------------------------------*/
static void test_GetResCodePriority_FailedPrecondition(void **state)
{
    int ret;

    // Exec test target
    ret = GetResCodePriority(9);

    // Check output
    assert_int_equal(ret, 6);
}

/*----------------------------------------------------------------------------*/
static void test_GetResCodePriority_Unavailable(void **state)
{
    int ret;

    // Exec test target
    ret = GetResCodePriority(14);

    // Check output
    assert_int_equal(ret, 5);
}

/*----------------------------------------------------------------------------*/
static void test_GetResCodePriority_ResourceExhausted(void **state)
{
    int ret;

    // Exec test target
    ret = GetResCodePriority(8);

    // Check output
    assert_int_equal(ret, 4);
}

/*----------------------------------------------------------------------------*/
static void test_GetResCodePriority_PermissionDenied(void **state)
{
    int ret;

    // Exec test target
    ret = GetResCodePriority(7);

    // Check output
    assert_int_equal(ret, 3);
}

/*----------------------------------------------------------------------------*/
static void test_GetResCodePriority_DeadlineExceeded(void **state)
{
    int ret;

    // Exec test target
    ret = GetResCodePriority(4);

    // Check output
    assert_int_equal(ret, 2);
}

/*----------------------------------------------------------------------------*/
static void test_GetResCodePriority_Internal(void **state)
{
    int ret;

    // Exec test target
    ret = GetResCodePriority(13);

    // Check output
    assert_int_equal(ret, 1);
}

/*----------------------------------------------------------------------------*/
static void test_GetResCodePriority_Ok(void **state)
{
    int ret;

    // Exec test target
    ret = GetResCodePriority(0);

    // Check output
    assert_int_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/
static void test_GetResCodePriority_Other(void **state)
{
    int ret;

    // Exec test target
    ret = GetResCodePriority(1);

    // Check output
    assert_int_equal(ret, 0);
}

/*----------------------------------------------------------------------------*/

//
// MakeJsonResInfoDeployConfiguration()
//

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfoDeployConfiguration(void **state)
{
    RetCode ret;
    ResInfo_t *res_info = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;

    // Prepare test target argument
    res_info = malloc(sizeof(ResInfo_t));
    if (res_info == NULL) {
        assert_non_null(res_info);
        goto exit;
    }
    snprintf(res_info->res_id, sizeof(res_info->res_id), "res_id test");
    res_info->code = 3;
    snprintf(res_info->detail_msg, sizeof(res_info->detail_msg), "invalid_argument");

    // For SysAppCmnMakeJsonResInfo()
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, parent_val);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, res_id, res_info->res_id);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, res_info->code);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, res_info->detail_msg);
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    // Exec test target
    ret = MakeJsonResInfoDeployConfiguration(handle_val, parent_val, (void *)res_info);

    // Check output
    assert_int_equal(ret, kRetOk);

exit:
    if (res_info != NULL) {
        free(res_info);
    }
}

/*----------------------------------------------------------------------------*/

//
// MakeJsonStateDeployConfiguration()
//

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployConfiguration_FullySuccessFirmware(void **state)
{
    Deploy_t *deploy = NULL;
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(deploy, 0x00, sizeof(Deploy_t));
    snprintf(deploy->id, sizeof(deploy->id), "%s", "res_id_test");
    snprintf(deploy->version, sizeof(deploy->version), "%s", "12345");
    deploy->topic_id = DeployTopicFirmware;
    deploy->parse_state = DeployStateDone;
    deploy->deploy_target_num = 1;
    deploy->deploy_targets = target;
    deploy->res_info.code = 0;

    // mock operation for MakeJsonStateDeployConfiguration()
    MakeJsonStateDeployConfigurationCommon(deploy, handle_val, parent_val,
                                           MakeJsonStateDeployConfiguration_None);

    // Exec test target
    MakeJsonStateDeployConfiguration(deploy, handle_val, parent_val);

    // Check output
    assert_int_equal(deploy->res_info.code, 0);
    assert_string_equal(deploy->res_info.detail_msg, "ok");
    assert_string_equal(deploy->res_info.res_id, deploy->id);

exit:
    if (target != NULL) {
        free(target);
    }
    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployConfiguration_FullySuccessAiModel(void **state)
{
    Deploy_t *deploy = NULL;
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(deploy, 0x00, sizeof(Deploy_t));
    snprintf(deploy->id, sizeof(deploy->id), "%s", "res_id_test");
    snprintf(deploy->version, sizeof(deploy->version), "%s", "12345");
    deploy->topic_id = DeployTopicAiModel;
    deploy->parse_state = DeployStateDone;
    deploy->deploy_target_num = 1;
    deploy->deploy_targets = target;
    deploy->res_info.code = 0;

    // mock operation for MakeJsonStateDeployConfiguration()
    MakeJsonStateDeployConfigurationCommon(deploy, handle_val, parent_val,
                                           MakeJsonStateDeployConfiguration_None);

    // Exec test target
    MakeJsonStateDeployConfiguration(deploy, handle_val, parent_val);

    // Check output
    assert_int_equal(deploy->res_info.code, 0);
    assert_string_equal(deploy->res_info.detail_msg, "ok");
    assert_string_equal(deploy->res_info.res_id, deploy->id);

exit:
    if (target != NULL) {
        free(target);
    }
    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployConfiguration_FullySuccessKeepErrorCode(void **state)
{
    Deploy_t *deploy = NULL;
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    static const char *keep_test_msg = "Keep Test Msg";
    static const char *keep_test_id = "Keep Test Id";

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(deploy, 0x00, sizeof(Deploy_t));
    snprintf(deploy->id, sizeof(deploy->id), "%s", "res_id_test");
    snprintf(deploy->version, sizeof(deploy->version), "%s", "12345");
    deploy->topic_id = DeployTopicFirmware;
    deploy->parse_state = DeployStateDone;
    deploy->deploy_target_num = 1;
    deploy->deploy_targets = target;
    deploy->res_info.code = 12;
    snprintf(deploy->res_info.detail_msg, sizeof(deploy->res_info.detail_msg), "%s", keep_test_msg);
    snprintf(deploy->res_info.res_id, sizeof(deploy->res_info.res_id), "%s", keep_test_id);

    // mock operation for MakeJsonStateDeployConfiguration()
    MakeJsonStateDeployConfigurationCommon(deploy, handle_val, parent_val,
                                           MakeJsonStateDeployConfiguration_None);

    // Exec test target
    MakeJsonStateDeployConfiguration(deploy, handle_val, parent_val);

    // Check output
    assert_int_equal(deploy->res_info.code, 12);
    assert_string_equal(deploy->res_info.detail_msg, keep_test_msg);
    assert_string_equal(deploy->res_info.res_id, keep_test_id);

exit:
    if (target != NULL) {
        free(target);
    }
    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployConfiguration_ErrorSysAppCmnSetStringValue(void **state)
{
    Deploy_t *deploy = NULL;
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(deploy, 0x00, sizeof(Deploy_t));
    snprintf(deploy->id, sizeof(deploy->id), "%s", "res_id_test");
    snprintf(deploy->version, sizeof(deploy->version), "%s", "12345");
    deploy->topic_id = DeployTopicFirmware;
    deploy->parse_state = DeployStateDone;
    deploy->deploy_target_num = 1;
    deploy->deploy_targets = target;
    deploy->res_info.code = 0;

    // mock operation for MakeJsonStateDeployConfiguration()
    MakeJsonStateDeployConfigurationCommon(deploy, handle_val, parent_val,
                                           MakeJsonStateDeployConfiguration_SetStringValue);

    // Exec test target
    MakeJsonStateDeployConfiguration(deploy, handle_val, parent_val);

    // Check output
    assert_int_equal(deploy->res_info.code, 0);
    assert_string_equal(deploy->res_info.detail_msg, "ok");
    assert_string_equal(deploy->res_info.res_id, deploy->id);

exit:
    if (target != NULL) {
        free(target);
    }
    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployConfiguration_ErrorEsfJsonArrayInit(void **state)
{
    Deploy_t *deploy = NULL;
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(deploy, 0x00, sizeof(Deploy_t));
    snprintf(deploy->id, sizeof(deploy->id), "%s", "res_id_test");
    snprintf(deploy->version, sizeof(deploy->version), "%s", "12345");
    deploy->topic_id = DeployTopicFirmware;
    deploy->parse_state = DeployStateDone;
    deploy->deploy_target_num = 1;
    deploy->deploy_targets = target;
    deploy->res_info.code = 0;

    // mock operation for MakeJsonStateDeployConfiguration()
    MakeJsonStateDeployConfigurationCommon(deploy, handle_val, parent_val,
                                           MakeJsonStateDeployConfiguration_ArrayInit);

    // Exec test target
    MakeJsonStateDeployConfiguration(deploy, handle_val, parent_val);

    // Check output
    assert_int_equal(deploy->res_info.code, 0);
    assert_string_equal(deploy->res_info.detail_msg, "ok");
    assert_string_equal(deploy->res_info.res_id, deploy->id);

exit:
    if (target != NULL) {
        free(target);
    }
    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployConfiguration_ErrorEsfJsonObjectInit(void **state)
{
    Deploy_t *deploy = NULL;
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(deploy, 0x00, sizeof(Deploy_t));
    snprintf(deploy->id, sizeof(deploy->id), "%s", "res_id_test");
    snprintf(deploy->version, sizeof(deploy->version), "%s", "12345");
    deploy->topic_id = DeployTopicFirmware;
    deploy->parse_state = DeployStateDone;
    deploy->deploy_target_num = 1;
    deploy->deploy_targets = target;
    deploy->res_info.code = 0;

    // mock operation for MakeJsonStateDeployConfiguration()
    MakeJsonStateDeployConfigurationCommon(deploy, handle_val, parent_val,
                                           MakeJsonStateDeployConfiguration_ObjectInit);

    // Exec test target
    MakeJsonStateDeployConfiguration(deploy, handle_val, parent_val);

    // Check output
    assert_int_equal(deploy->res_info.code, 0);
    assert_string_equal(deploy->res_info.detail_msg, "ok");
    assert_string_equal(deploy->res_info.res_id, deploy->id);

exit:
    if (target != NULL) {
        free(target);
    }
    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployConfiguration_ErrorEsfJsonArrayAppend(void **state)
{
    Deploy_t *deploy = NULL;
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(deploy, 0x00, sizeof(Deploy_t));
    snprintf(deploy->id, sizeof(deploy->id), "%s", "res_id_test");
    snprintf(deploy->version, sizeof(deploy->version), "%s", "12345");
    deploy->topic_id = DeployTopicFirmware;
    deploy->parse_state = DeployStateDone;
    deploy->deploy_target_num = 1;
    deploy->deploy_targets = target;
    deploy->res_info.code = 0;

    // mock operation for MakeJsonStateDeployConfiguration()
    MakeJsonStateDeployConfigurationCommon(deploy, handle_val, parent_val,
                                           MakeJsonStateDeployConfiguration_ArrayAppend);

    // Exec test target
    MakeJsonStateDeployConfiguration(deploy, handle_val, parent_val);

    // Check output
    assert_int_equal(deploy->res_info.code, 0);
    assert_string_equal(deploy->res_info.detail_msg, "ok");
    assert_string_equal(deploy->res_info.res_id, deploy->id);

exit:
    if (target != NULL) {
        free(target);
    }
    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonStateDeployConfiguration_ErrorEsfJsonObjectSet(void **state)
{
    Deploy_t *deploy = NULL;
    DeployTarget_t *target = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(deploy, 0x00, sizeof(Deploy_t));
    snprintf(deploy->id, sizeof(deploy->id), "%s", "res_id_test");
    snprintf(deploy->version, sizeof(deploy->version), "%s", "12345");
    deploy->topic_id = DeployTopicFirmware;
    deploy->parse_state = DeployStateDone;
    deploy->deploy_target_num = 1;
    deploy->deploy_targets = target;
    deploy->res_info.code = 0;

    // mock operation for MakeJsonStateDeployConfiguration()
    MakeJsonStateDeployConfigurationCommon(deploy, handle_val, parent_val,
                                           MakeJsonStateDeployConfiguration_ObjectSet);

    // Exec test target
    MakeJsonStateDeployConfiguration(deploy, handle_val, parent_val);

    // Check output
    assert_int_equal(deploy->res_info.code, 0);
    assert_string_equal(deploy->res_info.detail_msg, "ok");
    assert_string_equal(deploy->res_info.res_id, deploy->id);

exit:
    if (target != NULL) {
        free(target);
    }
    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/

//
// GetConfigurationReqInfoProperty()
//

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationReqInfoProperty_FullySuccess(void **state)
{
    char *expect_req_id = "No.777";
    size_t expect_size = RES_INFO_RES_ID_LEN + 1;
    char *req_id = malloc(expect_size);
    EsfJsonHandle expect_esf_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue expect_esf_pare_val = 1357;
    RetCode expect_ret_code = kRetOk;
    bool ret;

    // mock operation for GetConfigurationReqInfoProperty()
    CheckGetConfigurationReqInfoProperty(expect_req_id, expect_esf_handle, expect_esf_pare_val,
                                         expect_ret_code);

    // Exec test target
    ret = GetConfigurationReqInfoProperty(req_id, expect_size, expect_esf_handle,
                                          expect_esf_pare_val);

    // Check output
    assert_true(ret);
    assert_string_equal(req_id, expect_req_id);

    free(req_id);
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationReqInfoProperty_NotFoundSysAppCmnGetReqId(void **state)
{
    char *expect_req_id = "No.777";
    size_t expect_size = RES_INFO_RES_ID_LEN + 1;
    char *req_id = malloc(expect_size);
    EsfJsonHandle expect_esf_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue expect_esf_pare_val = 1357;
    RetCode expect_ret_code = kRetNotFound;
    bool ret;

    // mock operation for GetConfigurationReqInfoProperty()
    CheckGetConfigurationReqInfoProperty(expect_req_id, expect_esf_handle, expect_esf_pare_val,
                                         expect_ret_code);

    // Exec test target
    ret = GetConfigurationReqInfoProperty(req_id, expect_size, expect_esf_handle,
                                          expect_esf_pare_val);

    // Check output
    assert_true(ret);
    assert_string_equal(req_id, "0");

    free(req_id);
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationReqInfoProperty_DefaultSysAppCmnGetReqId(void **state)
{
    char *expect_req_id = "No.777";
    size_t expect_size = RES_INFO_RES_ID_LEN + 1;
    char *req_id = malloc(expect_size);
    EsfJsonHandle expect_esf_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue expect_esf_pare_val = 1357;
    RetCode expect_ret_code = kRetMemoryError;
    bool ret;

    // mock operation for GetConfigurationReqInfoProperty()
    CheckGetConfigurationReqInfoProperty(expect_req_id, expect_esf_handle, expect_esf_pare_val,
                                         expect_ret_code);

    // Exec test target
    ret = GetConfigurationReqInfoProperty(req_id, expect_size, expect_esf_handle,
                                          expect_esf_pare_val);

    // Check output
    assert_false(ret);
    assert_string_equal(req_id, "0");

    free(req_id);
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationReqInfoProperty_MaxStrnlen(void **state)
{
    char *expect_req_id =
        "No."
        "777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777"
        "77777777777777777777777777777777777";
    size_t expect_size = RES_INFO_RES_ID_LEN + 1;
    char *req_id = malloc(expect_size);
    EsfJsonHandle expect_esf_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue expect_esf_pare_val = 1357;
    RetCode expect_ret_code = kRetOk;
    bool ret;

    // mock operation for GetConfigurationReqInfoProperty()
    CheckGetConfigurationReqInfoProperty(expect_req_id, expect_esf_handle, expect_esf_pare_val,
                                         expect_ret_code);

    // Exec test target
    ret = GetConfigurationReqInfoProperty(req_id, expect_size, expect_esf_handle,
                                          expect_esf_pare_val);

    // Check output
    assert_true(ret);
    assert_string_equal(req_id, expect_req_id);

    free(req_id);
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationReqInfoProperty_MaxOverStrnlen(void **state)
{
    char *expect_req_id =
        "No."
        "777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777"
        "777777777777777777777777777777777777";
    size_t expect_size = RES_INFO_RES_ID_LEN + 1;
    char *req_id = malloc(expect_size);
    EsfJsonHandle expect_esf_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue expect_esf_pare_val = 1357;
    RetCode expect_ret_code = kRetOk;
    bool ret;

    // mock operation for GetConfigurationReqInfoProperty()
    CheckGetConfigurationReqInfoProperty(expect_req_id, expect_esf_handle, expect_esf_pare_val,
                                         expect_ret_code);

    // Exec test target
    ret = GetConfigurationReqInfoProperty(req_id, expect_size, expect_esf_handle,
                                          expect_esf_pare_val);

    // Check output
    assert_false(ret);
    assert_string_equal(req_id, "0");

    free(req_id);
}

/*----------------------------------------------------------------------------*/

//
// SetEvpStateReportOtaUpdateStatus()
//

/*----------------------------------------------------------------------------*/
static void test_SetEvpStateReportOtaUpdateStatus_FullySuccessFirmware(void **state)
{
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    // mock operation for SetEvpStateReportOtaUpdateStatus()
    SetEvpStateReportOtaUpdateStatusCommon(init_param, SetEvpStateReportOtaUpdateStatus_None);

    // Exec test target
    SetEvpStateReportOtaUpdateStatus(init_param);

    // Check output
    assert_int_equal(init_param->deploy.res_info.code, 0);
    assert_string_equal(init_param->deploy.res_info.detail_msg, "ok");
    assert_string_equal(init_param->deploy.res_info.res_id, init_param->deploy.id);
    assert_string_equal(init_param->state_str[init_param->deploy.topic_id],
                        ESF_JSON_SERIALIZE_OUTPUT_STR);
    assert_int_equal(init_param->state_str_len[init_param->deploy.topic_id],
                     strlen(ESF_JSON_SERIALIZE_OUTPUT_STR));

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_SetEvpStateReportOtaUpdateStatus_FullySuccessAiModel(void **state)
{
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicAiModel;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    // mock operation for SetEvpStateReportOtaUpdateStatus()
    SetEvpStateReportOtaUpdateStatusCommon(init_param, SetEvpStateReportOtaUpdateStatus_None);

    // Exec test target
    SetEvpStateReportOtaUpdateStatus(init_param);

    // Check output
    assert_int_equal(init_param->deploy.res_info.code, 0);
    assert_string_equal(init_param->deploy.res_info.detail_msg, "ok");
    assert_string_equal(init_param->deploy.res_info.res_id, init_param->deploy.id);
    assert_string_equal(init_param->state_str[init_param->deploy.topic_id],
                        ESF_JSON_SERIALIZE_OUTPUT_STR);
    assert_int_equal(init_param->state_str_len[init_param->deploy.topic_id],
                     strlen(ESF_JSON_SERIALIZE_OUTPUT_STR));

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_SetEvpStateReportOtaUpdateStatus_FullySuccessCameraSetup(void **state)
{
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicCameraSetup;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    // mock operation for SetEvpStateReportOtaUpdateStatus()
    SetEvpStateReportOtaUpdateStatusCommon(init_param, SetEvpStateReportOtaUpdateStatus_None);

    // Exec test target
    SetEvpStateReportOtaUpdateStatus(init_param);

    // Check output
    assert_int_equal(init_param->deploy.res_info.code, 0);
    assert_string_equal(init_param->deploy.res_info.detail_msg, "ok");
    assert_string_equal(init_param->deploy.res_info.res_id, init_param->deploy.id);
    assert_string_equal(init_param->state_str[init_param->deploy.topic_id],
                        ESF_JSON_SERIALIZE_OUTPUT_STR);
    assert_int_equal(init_param->state_str_len[init_param->deploy.topic_id],
                     strlen(ESF_JSON_SERIALIZE_OUTPUT_STR));

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_SetEvpStateReportOtaUpdateStatus_ErrorEsfJsonOpen(void **state)
{
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    // mock operation for SetEvpStateReportOtaUpdateStatus()
    SetEvpStateReportOtaUpdateStatusCommon(init_param, SetEvpStateReportOtaUpdateStatus_JsonOpen);

    // Exec test target
    SetEvpStateReportOtaUpdateStatus(init_param);

    // Check output
    // There are no outputs. So, it is not necessary to check.

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_SetEvpStateReportOtaUpdateStatus_ErrorEsfJsonObjectInit(void **state)
{
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    // mock operation for SetEvpStateReportOtaUpdateStatus()
    SetEvpStateReportOtaUpdateStatusCommon(init_param, SetEvpStateReportOtaUpdateStatus_ObjectInit);

    // Exec test target
    SetEvpStateReportOtaUpdateStatus(init_param);

    // Check output
    // There are no outputs. So, it is not necessary to check.

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_SetEvpStateReportOtaUpdateStatus_ErrorEsfJsonSerialize(void **state)
{
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    // mock operation for SetEvpStateReportOtaUpdateStatus()
    SetEvpStateReportOtaUpdateStatusCommon(init_param,
                                           SetEvpStateReportOtaUpdateStatus_JsonSerializeReturn);

    // Exec test target
    SetEvpStateReportOtaUpdateStatus(init_param);

    // Check output
    assert_int_equal(init_param->deploy.res_info.code, 0);
    assert_string_equal(init_param->deploy.res_info.detail_msg, "ok");
    assert_string_equal(init_param->deploy.res_info.res_id, init_param->deploy.id);

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_SetEvpStateReportOtaUpdateStatus_NullEsfJsonSerialize(void **state)
{
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    // mock operation for SetEvpStateReportOtaUpdateStatus()
    SetEvpStateReportOtaUpdateStatusCommon(init_param,
                                           SetEvpStateReportOtaUpdateStatus_JsonSerializeNullStr);

    // Exec test target
    SetEvpStateReportOtaUpdateStatus(init_param);

    // Check output
    assert_int_equal(init_param->deploy.res_info.code, 0);
    assert_string_equal(init_param->deploy.res_info.detail_msg, "ok");
    assert_string_equal(init_param->deploy.res_info.res_id, init_param->deploy.id);

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_SetEvpStateReportOtaUpdateStatus_InvalidId(void **state)
{
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicNum;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    // mock operation for SetEvpStateReportOtaUpdateStatus()
    SetEvpStateReportOtaUpdateStatusCommon(init_param, SetEvpStateReportOtaUpdateStatus_None);

    // Exec test target
    SetEvpStateReportOtaUpdateStatus(init_param);

    // Check output
    assert_int_equal(init_param->deploy.res_info.code, 0);
    assert_string_equal(init_param->deploy.res_info.detail_msg, "ok");
    assert_string_equal(init_param->deploy.res_info.res_id, init_param->deploy.id);

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_SetEvpStateReportOtaUpdateStatus_MaxOverLenSerializedJson(void **state)
{
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    // mock operation for SetEvpStateReportOtaUpdateStatus()
    SetEvpStateReportOtaUpdateStatusCommon(
        init_param, SetEvpStateReportOtaUpdateStatus_JsonSerializeMaxOverStr);

    // Exec test target
    SetEvpStateReportOtaUpdateStatus(init_param);

    // Check output
    assert_int_equal(init_param->deploy.res_info.code, 0);
    assert_string_equal(init_param->deploy.res_info.detail_msg, "ok");
    assert_string_equal(init_param->deploy.res_info.res_id, init_param->deploy.id);

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_SetEvpStateReportOtaUpdateStatus_MaxLenSerializedJson(void **state)
{
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    // mock operation for SetEvpStateReportOtaUpdateStatus()
    SetEvpStateReportOtaUpdateStatusCommon(init_param,
                                           SetEvpStateReportOtaUpdateStatus_JsonSerializeMaxStr);

    // Exec test target
    SetEvpStateReportOtaUpdateStatus(init_param);

    // Check output
    assert_int_equal(init_param->deploy.res_info.code, 0);
    assert_string_equal(init_param->deploy.res_info.detail_msg, "ok");
    assert_string_equal(init_param->deploy.res_info.res_id, init_param->deploy.id);
    assert_null(init_param->state_str[init_param->deploy.topic_id]);
    assert_int_equal(init_param->state_str_len[init_param->deploy.topic_id], 0);

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_SetEvpStateReportOtaUpdateStatus_ErrorPthreadMutexLock(void **state)
{
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    // mock operation for SetEvpStateReportOtaUpdateStatus()
    SetEvpStateReportOtaUpdateStatusCommon(init_param,
                                           SetEvpStateReportOtaUpdateStatus_PthreadMutexLock);

    // Exec test target
    SetEvpStateReportOtaUpdateStatus(init_param);

    // Check output
    assert_int_equal(init_param->deploy.res_info.code, 0);
    assert_string_equal(init_param->deploy.res_info.detail_msg, "ok");
    assert_string_equal(init_param->deploy.res_info.res_id, init_param->deploy.id);

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_SetEvpStateReportOtaUpdateStatus_ErrorReallocNotAllocated(void **state)
{
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    // mock operation for SetEvpStateReportOtaUpdateStatus()
    SetEvpStateReportOtaUpdateStatusCommon(init_param, SetEvpStateReportOtaUpdateStatus_Realloc);

    // Exec test target
    SetEvpStateReportOtaUpdateStatus(init_param);

    // Check output
    assert_int_equal(init_param->deploy.res_info.code, 0);
    assert_string_equal(init_param->deploy.res_info.detail_msg, "ok");
    assert_string_equal(init_param->deploy.res_info.res_id, init_param->deploy.id);
    assert_null(init_param->state_str[init_param->deploy.topic_id]);
    assert_int_equal(init_param->state_str_len[init_param->deploy.topic_id], 0);

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_SetEvpStateReportOtaUpdateStatus_ErrorReallocAllocated(void **state)
{
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    char *allocated_mem = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    allocated_mem = malloc(10);
    if (allocated_mem == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;
    init_param->state_str[init_param->deploy.topic_id] = allocated_mem;

    // mock operation for SetEvpStateReportOtaUpdateStatus()
    SetEvpStateReportOtaUpdateStatusCommon(init_param, SetEvpStateReportOtaUpdateStatus_Realloc);

    // Exec test target
    SetEvpStateReportOtaUpdateStatus(init_param);

    // Check output
    assert_int_equal(init_param->deploy.res_info.code, 0);
    assert_string_equal(init_param->deploy.res_info.detail_msg, "ok");
    assert_string_equal(init_param->deploy.res_info.res_id, init_param->deploy.id);
    assert_null(init_param->state_str[init_param->deploy.topic_id]);
    assert_int_equal(init_param->state_str_len[init_param->deploy.topic_id], 0);

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_SetEvpStateReportOtaUpdateStatus_ErrorSysAppStateSendState(void **state)
{
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    // mock operation for SetEvpStateReportOtaUpdateStatus()
    SetEvpStateReportOtaUpdateStatusCommon(init_param, SetEvpStateReportOtaUpdateStatus_SendState);

    // Exec test target
    SetEvpStateReportOtaUpdateStatus(init_param);

    // Check output
    assert_int_equal(init_param->deploy.res_info.code, 0);
    assert_string_equal(init_param->deploy.res_info.detail_msg, "ok");
    assert_string_equal(init_param->deploy.res_info.res_id, init_param->deploy.id);
    assert_string_equal(init_param->state_str[init_param->deploy.topic_id],
                        ESF_JSON_SERIALIZE_OUTPUT_STR);
    assert_int_equal(init_param->state_str_len[init_param->deploy.topic_id],
                     strlen(ESF_JSON_SERIALIZE_OUTPUT_STR));

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/

//
// GetConfigurationDeployConfigurationProperty()
//

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployConfigurationProperty_FullySuccess(void **state)
{
    Deploy_t *deploy = NULL;
    DeployTarget_t *expect_value = NULL;
    EsfJsonHandle expect_esf_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue expect_esf_pare_val = 1357;
    ssize_t array_cnt = 1;
    int topic_id = 0; // DeployTopicFirmware
    RetCode ret;

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }
    // Create expect value
    expect_value = malloc(sizeof(DeployTarget_t));
    if (expect_value == NULL) {
        assert_non_null(expect_value);
        goto exit;
    }
    memset(deploy, 0x00, sizeof(Deploy_t));

    SetGetConfigurationDeployTargetPropertyExpectValue(expect_value, DeployComponentSensorLoader,
                                                       dtdl_deploy_target_chip_sensor_chip, "");

    // Check GetConfigurationDeployConfigurationProperty()
    CheckGetConfigurationDeployConfigurationProperty(deploy, expect_esf_handle, expect_esf_pare_val,
                                                     topic_id, expect_value, array_cnt);

    // Exec test target
    ret = GetConfigurationDeployConfigurationProperty(expect_esf_handle, expect_esf_pare_val,
                                                      deploy, topic_id);

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_string_equal(deploy->id, system_app_cmn_get_req_id);
    assert_int_equal(deploy->topic_id, topic_id);
    assert_string_equal(deploy->version, chk_config_deploy_version);
    assert_int_equal(deploy->deploy_target_num, array_cnt);
    assert_int_equal(deploy->deploy_target_cnt, 0);
    assert_non_null(deploy->deploy_targets);
    assert_int_equal(deploy->deploy_targets->component, expect_value->component);
    assert_string_equal(deploy->deploy_targets->name, esf_fw_mgr_open_param_name_sensor);
    assert_string_equal(deploy->deploy_targets->chip, expect_value->chip);
    assert_string_equal(deploy->deploy_targets->version, expect_value->version);
    assert_string_equal(deploy->deploy_targets->package_url, expect_value->package_url);
    assert_string_equal(deploy->deploy_targets->hash, expect_value->hash);
    assert_int_equal(deploy->deploy_targets->size, expect_value->size);
    assert_int_equal(deploy->deploy_targets->progress, 0);
    assert_int_equal(deploy->deploy_targets->process_state, DeployStateIdle);
    assert_int_equal(deploy->deploy_targets->parse_state, DeployStateIdle);
    assert_string_equal(deploy->res_info.res_id, "");
    assert_int_equal(deploy->res_info.code, 0);
    assert_string_equal(deploy->res_info.detail_msg, "");
    assert_int_equal(deploy->parse_state, DeployStateDone);

exit:
    if (expect_value != NULL) {
        free(expect_value);
    }

    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployConfigurationProperty_ErrorGetConfigurationReqInfoProperty(
    void **state)
{
    Deploy_t *deploy = NULL;
    DeployTarget_t *expect_value = NULL;
    EsfJsonHandle expect_esf_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue expect_esf_pare_val = 1357;
    EsfJsonValue expect_esf_child_val = 2468;
    EsfJsonValueType expect_val_type = kEsfJsonValueTypeArray;
    ssize_t array_cnt = 1;
    EsfJsonValue expect_subval = 1122;
    int topic_id = 0; // DeployTopicFirmware
    const char *deploy_version = "V00112233";
    RetCode expect_ret_code = kRetMemoryError;
    RetCode ret;

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }
    // Create expect value
    expect_value = malloc(sizeof(DeployTarget_t));
    if (expect_value == NULL) {
        assert_non_null(expect_value);
        goto exit;
    }
    memset(deploy, 0x00, sizeof(Deploy_t));

    SetGetConfigurationDeployTargetPropertyExpectValue(expect_value, DeployComponentSensorLoader,
                                                       dtdl_deploy_target_chip_sensor_chip, "");

    CheckGetConfigurationReqInfoProperty(system_app_cmn_get_req_id, expect_esf_handle,
                                         expect_esf_pare_val, expect_ret_code);

    ExtractStringValueCommon(expect_esf_handle, expect_esf_pare_val, "version", deploy_version, 1);

    // targets property
    expect_value(__wrap_EsfJsonObjectGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, expect_esf_pare_val);
    expect_string(__wrap_EsfJsonObjectGet, key, "targets");
    will_return(__wrap_EsfJsonObjectGet, expect_esf_child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // value type
    expect_value(__wrap_EsfJsonValueTypeGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, expect_esf_child_val);
    will_return(__wrap_EsfJsonValueTypeGet, expect_val_type);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // array count
    expect_value(__wrap_EsfJsonArrayCount, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonArrayCount, parent, expect_esf_child_val);
    will_return(__wrap_EsfJsonArrayCount, array_cnt);

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, sizeof(DeployTarget_t) * array_cnt);

    // get array
    expect_value(__wrap_EsfJsonArrayGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonArrayGet, parent, expect_esf_child_val);
    expect_value(__wrap_EsfJsonArrayGet, index, 0);
    will_return(__wrap_EsfJsonArrayGet, expect_subval);
    will_return(__wrap_EsfJsonArrayGet, kEsfJsonSuccess);

    // mock operation for GetConfigurationDeployTargetProperty()
    GetConfigurationDeployTargetPropertyCommon(expect_value, expect_esf_handle, expect_subval,
                                               topic_id);

    // Exec test target
    ret = GetConfigurationDeployConfigurationProperty(expect_esf_handle, expect_esf_pare_val,
                                                      deploy, topic_id);

    // Check output
    assert_int_equal(ret, kRetFailed);
    assert_string_equal(deploy->id, "0");
    assert_int_equal(deploy->topic_id, topic_id);
    assert_string_equal(deploy->version, deploy_version);
    assert_int_equal(deploy->deploy_target_num, array_cnt);
    assert_int_equal(deploy->deploy_target_cnt, 0);
    assert_non_null(deploy->deploy_targets);
    assert_int_equal(deploy->deploy_targets->component, expect_value->component);
    assert_string_equal(deploy->deploy_targets->name, esf_fw_mgr_open_param_name_sensor);
    assert_string_equal(deploy->deploy_targets->chip, expect_value->chip);
    assert_string_equal(deploy->deploy_targets->version, expect_value->version);
    assert_string_equal(deploy->deploy_targets->package_url, expect_value->package_url);
    assert_string_equal(deploy->deploy_targets->hash, expect_value->hash);
    assert_int_equal(deploy->deploy_targets->size, expect_value->size);
    assert_int_equal(deploy->deploy_targets->progress, 0);
    assert_int_equal(deploy->deploy_targets->process_state, DeployStateIdle);
    assert_int_equal(deploy->deploy_targets->parse_state, DeployStateIdle);
    assert_string_equal(deploy->res_info.res_id, "");
    assert_int_equal(deploy->res_info.code, 0);
    assert_string_equal(deploy->res_info.detail_msg, "");
    assert_int_equal(deploy->parse_state, DeployStateFailedInvalidRequest);

exit:
    if (expect_value != NULL) {
        free(expect_value);
    }

    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployConfigurationProperty_FullySuccessTopicCameraSetup(
    void **state)
{
    Deploy_t *deploy = NULL;
    DeployTarget_t *expect_value = NULL;
    EsfJsonHandle expect_esf_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue expect_esf_pare_val = 1357;
    EsfJsonValue expect_esf_child_val = 2468;
    EsfJsonValueType expect_val_type = kEsfJsonValueTypeArray;
    ssize_t array_cnt = 1;
    EsfJsonValue expect_subval = 1122;
    int topic_id = 2; // DeployTopicCameraSetup
    RetCode expect_ret_code = kRetOk;
    RetCode ret;

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }
    // Create expect value
    expect_value = malloc(sizeof(DeployTarget_t));
    if (expect_value == NULL) {
        assert_non_null(expect_value);
        goto exit;
    }
    memset(deploy, 0x00, sizeof(Deploy_t));

    SetGetConfigurationDeployTargetPropertyExpectValue(expect_value, DeployComponentSensorLoader,
                                                       dtdl_deploy_target_chip_sensor_chip, "");

    CheckGetConfigurationReqInfoProperty(system_app_cmn_get_req_id, expect_esf_handle,
                                         expect_esf_pare_val, expect_ret_code);

    // targets property
    expect_value(__wrap_EsfJsonObjectGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, expect_esf_pare_val);
    expect_string(__wrap_EsfJsonObjectGet, key, "targets");
    will_return(__wrap_EsfJsonObjectGet, expect_esf_child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // value type
    expect_value(__wrap_EsfJsonValueTypeGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, expect_esf_child_val);
    will_return(__wrap_EsfJsonValueTypeGet, expect_val_type);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // array count
    expect_value(__wrap_EsfJsonArrayCount, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonArrayCount, parent, expect_esf_child_val);
    will_return(__wrap_EsfJsonArrayCount, array_cnt);

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, sizeof(DeployTarget_t) * array_cnt);

    // get array
    expect_value(__wrap_EsfJsonArrayGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonArrayGet, parent, expect_esf_child_val);
    expect_value(__wrap_EsfJsonArrayGet, index, (array_cnt - 1));
    will_return(__wrap_EsfJsonArrayGet, expect_subval);
    will_return(__wrap_EsfJsonArrayGet, kEsfJsonSuccess);

    // mock operation for GetConfigurationDeployTargetProperty()
    GetConfigurationDeployTargetPropertyCommon(expect_value, expect_esf_handle, expect_subval,
                                               topic_id);

    // Exec test target
    ret = GetConfigurationDeployConfigurationProperty(expect_esf_handle, expect_esf_pare_val,
                                                      deploy, topic_id);

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_string_equal(deploy->id, system_app_cmn_get_req_id);
    assert_int_equal(deploy->topic_id, topic_id);
    assert_string_equal(deploy->version, "");
    assert_int_equal(deploy->deploy_target_num, array_cnt);
    assert_int_equal(deploy->deploy_target_cnt, 0);
    assert_non_null(deploy->deploy_targets);
    assert_int_equal(deploy->deploy_targets->component, expect_value->component);
    assert_string_equal(deploy->deploy_targets->name, "");
    assert_string_equal(deploy->deploy_targets->chip, expect_value->chip);
    assert_string_equal(deploy->deploy_targets->version, expect_value->version);
    assert_string_equal(deploy->deploy_targets->package_url, expect_value->package_url);
    assert_string_equal(deploy->deploy_targets->hash, expect_value->hash);
    assert_int_equal(deploy->deploy_targets->size, expect_value->size);
    assert_int_equal(deploy->deploy_targets->progress, 0);
    assert_int_equal(deploy->deploy_targets->process_state, DeployStateIdle);
    assert_int_equal(deploy->deploy_targets->parse_state, DeployStateFailedInvalidRequest);
    assert_string_equal(deploy->res_info.res_id, "");
    assert_int_equal(deploy->res_info.code, 0);
    assert_string_equal(deploy->res_info.detail_msg, "");
    assert_int_equal(deploy->parse_state, DeployStateDone);

exit:
    if (expect_value != NULL) {
        free(expect_value);
    }

    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployConfigurationProperty_ErrorExtractStringValue(void **state)
{
    Deploy_t *deploy = NULL;
    DeployTarget_t *expect_value = NULL;
    EsfJsonHandle expect_esf_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue expect_esf_pare_val = 1357;
    EsfJsonValue expect_esf_child_val = 2468;
    EsfJsonValueType expect_val_type = kEsfJsonValueTypeArray;
    ssize_t array_cnt = 1;
    EsfJsonValue expect_subval = 1122;
    int topic_id = 0; // DeployTopicFirmware
    const char *deploy_version = NULL;
    RetCode expect_ret_code = kRetOk;
    RetCode ret;

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }
    // Create expect value
    expect_value = malloc(sizeof(DeployTarget_t));
    if (expect_value == NULL) {
        assert_non_null(expect_value);
        goto exit;
    }
    memset(deploy, 0x00, sizeof(Deploy_t));

    SetGetConfigurationDeployTargetPropertyExpectValue(expect_value, DeployComponentSensorLoader,
                                                       dtdl_deploy_target_chip_sensor_chip, "");

    CheckGetConfigurationReqInfoProperty(system_app_cmn_get_req_id, expect_esf_handle,
                                         expect_esf_pare_val, expect_ret_code);

    ExtractStringValueCommon(expect_esf_handle, expect_esf_pare_val, "version", deploy_version, 1);

    // targets property
    expect_value(__wrap_EsfJsonObjectGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, expect_esf_pare_val);
    expect_string(__wrap_EsfJsonObjectGet, key, "targets");
    will_return(__wrap_EsfJsonObjectGet, expect_esf_child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // value type
    expect_value(__wrap_EsfJsonValueTypeGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, expect_esf_child_val);
    will_return(__wrap_EsfJsonValueTypeGet, expect_val_type);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // array count
    expect_value(__wrap_EsfJsonArrayCount, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonArrayCount, parent, expect_esf_child_val);
    will_return(__wrap_EsfJsonArrayCount, array_cnt);

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, sizeof(DeployTarget_t) * array_cnt);

    // get array
    expect_value(__wrap_EsfJsonArrayGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonArrayGet, parent, expect_esf_child_val);
    expect_value(__wrap_EsfJsonArrayGet, index, 0);
    will_return(__wrap_EsfJsonArrayGet, expect_subval);
    will_return(__wrap_EsfJsonArrayGet, kEsfJsonSuccess);

    // mock operation for GetConfigurationDeployTargetProperty()
    GetConfigurationDeployTargetPropertyCommon(expect_value, expect_esf_handle, expect_subval,
                                               topic_id);

    // Exec test target
    ret = GetConfigurationDeployConfigurationProperty(expect_esf_handle, expect_esf_pare_val,
                                                      deploy, topic_id);

    // Check output
    assert_int_equal(ret, kRetFailed);
    assert_string_equal(deploy->id, system_app_cmn_get_req_id);
    assert_int_equal(deploy->topic_id, topic_id);
    assert_string_equal(deploy->version, "");
    assert_int_equal(deploy->deploy_target_num, array_cnt);
    assert_int_equal(deploy->deploy_target_cnt, 0);
    assert_non_null(deploy->deploy_targets);
    assert_int_equal(deploy->deploy_targets->component, expect_value->component);
    assert_string_equal(deploy->deploy_targets->name, esf_fw_mgr_open_param_name_sensor);
    assert_string_equal(deploy->deploy_targets->chip, expect_value->chip);
    assert_string_equal(deploy->deploy_targets->version, expect_value->version);
    assert_string_equal(deploy->deploy_targets->package_url, expect_value->package_url);
    assert_string_equal(deploy->deploy_targets->hash, expect_value->hash);
    assert_int_equal(deploy->deploy_targets->size, expect_value->size);
    assert_int_equal(deploy->deploy_targets->progress, 0);
    assert_int_equal(deploy->deploy_targets->process_state, DeployStateIdle);
    assert_int_equal(deploy->deploy_targets->parse_state, DeployStateIdle);
    assert_string_equal(deploy->res_info.res_id, "");
    assert_int_equal(deploy->res_info.code, 0);
    assert_string_equal(deploy->res_info.detail_msg, "");
    assert_int_equal(deploy->parse_state, DeployStateFailedInvalidRequest);

exit:
    if (expect_value != NULL) {
        free(expect_value);
    }

    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployConfigurationProperty_ErrorEsfJsonObjectGet(void **state)
{
    Deploy_t *deploy = NULL;
    EsfJsonHandle expect_esf_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue expect_esf_pare_val = 1357;
    EsfJsonValue expect_esf_child_val = 2468;
    int topic_id = 0; // DeployTopicFirmware
    const char *deploy_version = "V00112233";
    RetCode expect_ret_code = kRetOk;
    RetCode ret;

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }

    memset(deploy, 0x00, sizeof(Deploy_t));

    CheckGetConfigurationReqInfoProperty(system_app_cmn_get_req_id, expect_esf_handle,
                                         expect_esf_pare_val, expect_ret_code);

    ExtractStringValueCommon(expect_esf_handle, expect_esf_pare_val, "version", deploy_version, 1);

    // targets property
    expect_value(__wrap_EsfJsonObjectGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, expect_esf_pare_val);
    expect_string(__wrap_EsfJsonObjectGet, key, "targets");
    will_return(__wrap_EsfJsonObjectGet, expect_esf_child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonInternalError);

    // Exec test target
    ret = GetConfigurationDeployConfigurationProperty(expect_esf_handle, expect_esf_pare_val,
                                                      deploy, topic_id);

    // Check output
    assert_int_equal(ret, kRetFailed);
    assert_string_equal(deploy->id, system_app_cmn_get_req_id);
    assert_int_equal(deploy->topic_id, topic_id);
    assert_string_equal(deploy->version, chk_config_deploy_version);
    assert_int_equal(deploy->deploy_target_num, 0);
    assert_int_equal(deploy->deploy_target_cnt, 0);
    assert_null(deploy->deploy_targets);
    assert_string_equal(deploy->res_info.res_id, "");
    assert_int_equal(deploy->res_info.code, 0);
    assert_string_equal(deploy->res_info.detail_msg, "");
    assert_int_equal(deploy->parse_state, DeployStateFailedInvalidRequest);

exit:
    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployConfigurationProperty_ErrorEsfJsonValueTypeGet(void **state)
{
    Deploy_t *deploy = NULL;
    EsfJsonHandle expect_esf_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue expect_esf_pare_val = 1357;
    EsfJsonValue expect_esf_child_val = 2468;
    EsfJsonValueType expect_val_type = kEsfJsonValueTypeArray;
    int topic_id = 0; // DeployTopicFirmware
    const char *deploy_version = "V00112233";
    RetCode expect_ret_code = kRetOk;
    RetCode ret;

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }

    memset(deploy, 0x00, sizeof(Deploy_t));

    CheckGetConfigurationReqInfoProperty(system_app_cmn_get_req_id, expect_esf_handle,
                                         expect_esf_pare_val, expect_ret_code);

    ExtractStringValueCommon(expect_esf_handle, expect_esf_pare_val, "version", deploy_version, 1);

    // targets property
    expect_value(__wrap_EsfJsonObjectGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, expect_esf_pare_val);
    expect_string(__wrap_EsfJsonObjectGet, key, "targets");
    will_return(__wrap_EsfJsonObjectGet, expect_esf_child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // value type
    expect_value(__wrap_EsfJsonValueTypeGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, expect_esf_child_val);
    will_return(__wrap_EsfJsonValueTypeGet, expect_val_type);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonInternalError);

    // Exec test target
    ret = GetConfigurationDeployConfigurationProperty(expect_esf_handle, expect_esf_pare_val,
                                                      deploy, topic_id);

    // Check output
    assert_int_equal(ret, kRetFailed);
    assert_string_equal(deploy->id, system_app_cmn_get_req_id);
    assert_int_equal(deploy->topic_id, topic_id);
    assert_string_equal(deploy->version, chk_config_deploy_version);
    assert_int_equal(deploy->deploy_target_num, 0);
    assert_int_equal(deploy->deploy_target_cnt, 0);
    assert_null(deploy->deploy_targets);
    assert_string_equal(deploy->res_info.res_id, "");
    assert_int_equal(deploy->res_info.code, 0);
    assert_string_equal(deploy->res_info.detail_msg, "");
    assert_int_equal(deploy->parse_state, DeployStateFailedInvalidRequest);

exit:
    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployConfigurationProperty_ErrorTypeEsfJsonValueTypeGet(
    void **state)
{
    Deploy_t *deploy = NULL;
    EsfJsonHandle expect_esf_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue expect_esf_pare_val = 1357;
    EsfJsonValue expect_esf_child_val = 2468;
    EsfJsonValueType expect_val_type = kEsfJsonValueTypeBoolean;
    int topic_id = 0; // DeployTopicFirmware
    const char *deploy_version = "V00112233";
    RetCode expect_ret_code = kRetOk;
    RetCode ret;

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }

    memset(deploy, 0x00, sizeof(Deploy_t));

    CheckGetConfigurationReqInfoProperty(system_app_cmn_get_req_id, expect_esf_handle,
                                         expect_esf_pare_val, expect_ret_code);

    ExtractStringValueCommon(expect_esf_handle, expect_esf_pare_val, "version", deploy_version, 1);

    // targets property
    expect_value(__wrap_EsfJsonObjectGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, expect_esf_pare_val);
    expect_string(__wrap_EsfJsonObjectGet, key, "targets");
    will_return(__wrap_EsfJsonObjectGet, expect_esf_child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // value type
    expect_value(__wrap_EsfJsonValueTypeGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, expect_esf_child_val);
    will_return(__wrap_EsfJsonValueTypeGet, expect_val_type);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // Exec test target
    ret = GetConfigurationDeployConfigurationProperty(expect_esf_handle, expect_esf_pare_val,
                                                      deploy, topic_id);

    // Check output
    assert_int_equal(ret, kRetFailed);
    assert_string_equal(deploy->id, system_app_cmn_get_req_id);
    assert_int_equal(deploy->topic_id, topic_id);
    assert_string_equal(deploy->version, chk_config_deploy_version);
    assert_int_equal(deploy->deploy_target_num, 0);
    assert_int_equal(deploy->deploy_target_cnt, 0);
    assert_null(deploy->deploy_targets);
    assert_string_equal(deploy->res_info.res_id, "");
    assert_int_equal(deploy->res_info.code, 0);
    assert_string_equal(deploy->res_info.detail_msg, "");
    assert_int_equal(deploy->parse_state, DeployStateFailedInvalidRequest);

exit:
    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployConfigurationProperty_ErrorCntEsfJsonArrayCount(void **state)
{
    Deploy_t *deploy = NULL;
    EsfJsonHandle expect_esf_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue expect_esf_pare_val = 1357;
    EsfJsonValue expect_esf_child_val = 2468;
    EsfJsonValueType expect_val_type = kEsfJsonValueTypeArray;
    ssize_t array_cnt = -1;
    int topic_id = 0; // DeployTopicFirmware
    const char *deploy_version = "V00112233";
    RetCode expect_ret_code = kRetOk;
    RetCode ret;

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }

    memset(deploy, 0x00, sizeof(Deploy_t));

    CheckGetConfigurationReqInfoProperty(system_app_cmn_get_req_id, expect_esf_handle,
                                         expect_esf_pare_val, expect_ret_code);

    ExtractStringValueCommon(expect_esf_handle, expect_esf_pare_val, "version", deploy_version, 1);

    // targets property
    expect_value(__wrap_EsfJsonObjectGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, expect_esf_pare_val);
    expect_string(__wrap_EsfJsonObjectGet, key, "targets");
    will_return(__wrap_EsfJsonObjectGet, expect_esf_child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // value type
    expect_value(__wrap_EsfJsonValueTypeGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, expect_esf_child_val);
    will_return(__wrap_EsfJsonValueTypeGet, expect_val_type);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // array count
    expect_value(__wrap_EsfJsonArrayCount, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonArrayCount, parent, expect_esf_child_val);
    will_return(__wrap_EsfJsonArrayCount, array_cnt);

    // Exec test target
    ret = GetConfigurationDeployConfigurationProperty(expect_esf_handle, expect_esf_pare_val,
                                                      deploy, topic_id);

    // Check output
    assert_int_equal(ret, kRetFailed);
    assert_string_equal(deploy->id, system_app_cmn_get_req_id);
    assert_int_equal(deploy->topic_id, topic_id);
    assert_string_equal(deploy->version, chk_config_deploy_version);
    assert_int_equal(deploy->deploy_target_num, 0);
    assert_int_equal(deploy->deploy_target_cnt, 0);
    assert_null(deploy->deploy_targets);
    assert_string_equal(deploy->res_info.res_id, "");
    assert_int_equal(deploy->res_info.code, 0);
    assert_string_equal(deploy->res_info.detail_msg, "");
    assert_int_equal(deploy->parse_state, DeployStateFailedInvalidRequest);

exit:
    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployConfigurationProperty_OverCntEsfJsonArrayCount(void **state)
{
    Deploy_t *deploy = NULL;
    DeployTarget_t *expect_value = NULL;
    EsfJsonHandle expect_esf_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue expect_esf_pare_val = 1357;
    ssize_t array_cnt = DEPLOY_TARGET_MAX_NUM + 1;
    int topic_id = 0; // DeployTopicFirmware
    RetCode ret;

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }
    // Create expect value
    expect_value = malloc(sizeof(DeployTarget_t));
    if (expect_value == NULL) {
        assert_non_null(expect_value);
        goto exit;
    }
    memset(deploy, 0x00, sizeof(Deploy_t));

    SetGetConfigurationDeployTargetPropertyExpectValue(expect_value, DeployComponentSensorLoader,
                                                       dtdl_deploy_target_chip_sensor_chip, "");

    // Check GetConfigurationDeployConfigurationProperty()
    CheckGetConfigurationDeployConfigurationProperty(deploy, expect_esf_handle, expect_esf_pare_val,
                                                     topic_id, expect_value, array_cnt);

    // Exec test target
    ret = GetConfigurationDeployConfigurationProperty(expect_esf_handle, expect_esf_pare_val,
                                                      deploy, topic_id);

    // Check output
    assert_int_equal(ret, kRetOk);
    assert_string_equal(deploy->id, system_app_cmn_get_req_id);
    assert_int_equal(deploy->topic_id, topic_id);
    assert_string_equal(deploy->version, chk_config_deploy_version);
    assert_int_equal(deploy->deploy_target_num, DEPLOY_TARGET_MAX_NUM);
    assert_int_equal(deploy->deploy_target_cnt, 0);
    assert_non_null(deploy->deploy_targets);
    assert_int_equal(deploy->deploy_targets->component, expect_value->component);
    assert_string_equal(deploy->deploy_targets->name, esf_fw_mgr_open_param_name_sensor);
    assert_string_equal(deploy->deploy_targets->chip, expect_value->chip);
    assert_string_equal(deploy->deploy_targets->version, expect_value->version);
    assert_string_equal(deploy->deploy_targets->package_url, expect_value->package_url);
    assert_string_equal(deploy->deploy_targets->hash, expect_value->hash);
    assert_int_equal(deploy->deploy_targets->size, expect_value->size);
    assert_int_equal(deploy->deploy_targets->progress, 0);
    assert_int_equal(deploy->deploy_targets->process_state, DeployStateIdle);
    assert_int_equal(deploy->deploy_targets->parse_state, DeployStateIdle);
    assert_string_equal(deploy->res_info.res_id, "");
    assert_int_equal(deploy->res_info.code, 0);
    assert_string_equal(deploy->res_info.detail_msg, "");
    assert_int_equal(deploy->parse_state, DeployStateDone);

exit:
    if (expect_value != NULL) {
        free(expect_value);
    }

    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployConfigurationProperty_ErrorMalloc(void **state)
{
    Deploy_t *deploy = NULL;
    EsfJsonHandle expect_esf_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue expect_esf_pare_val = 1357;
    EsfJsonValue expect_esf_child_val = 2468;
    EsfJsonValueType expect_val_type = kEsfJsonValueTypeArray;
    ssize_t array_cnt = 1;
    int topic_id = 0; // DeployTopicFirmware
    const char *deploy_version = "V00112233";
    RetCode expect_ret_code = kRetOk;
    RetCode ret;

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }

    memset(deploy, 0x00, sizeof(Deploy_t));

    CheckGetConfigurationReqInfoProperty(system_app_cmn_get_req_id, expect_esf_handle,
                                         expect_esf_pare_val, expect_ret_code);

    ExtractStringValueCommon(expect_esf_handle, expect_esf_pare_val, "version", deploy_version, 1);

    // targets property
    expect_value(__wrap_EsfJsonObjectGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, expect_esf_pare_val);
    expect_string(__wrap_EsfJsonObjectGet, key, "targets");
    will_return(__wrap_EsfJsonObjectGet, expect_esf_child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // value type
    expect_value(__wrap_EsfJsonValueTypeGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, expect_esf_child_val);
    will_return(__wrap_EsfJsonValueTypeGet, expect_val_type);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // array count
    expect_value(__wrap_EsfJsonArrayCount, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonArrayCount, parent, expect_esf_child_val);
    will_return(__wrap_EsfJsonArrayCount, array_cnt);

    // For malloc()
    will_return(mock_malloc, true);  // Exec parameter check
    will_return(mock_malloc, false); // Get allocate memory
    expect_value(mock_malloc, __size, sizeof(DeployTarget_t) * array_cnt);

    // For SysAppLedSetAppStatus()
    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state,
                 LedAppStatusErrorUpdateMemoryAllocateFailed);

    // Exec test target
    ret = GetConfigurationDeployConfigurationProperty(expect_esf_handle, expect_esf_pare_val,
                                                      deploy, topic_id);

    // Check output
    assert_int_equal(ret, kRetFailed);
    assert_string_equal(deploy->id, system_app_cmn_get_req_id);
    assert_int_equal(deploy->topic_id, topic_id);
    assert_string_equal(deploy->version, chk_config_deploy_version);
    assert_int_equal(deploy->deploy_target_num, 0);
    assert_int_equal(deploy->deploy_target_cnt, 0);
    assert_null(deploy->deploy_targets);
    assert_string_equal(deploy->res_info.res_id, "");
    assert_int_equal(deploy->res_info.code, 0);
    assert_string_equal(deploy->res_info.detail_msg, "");
    assert_int_equal(deploy->parse_state, DeployStateFailed);

exit:
    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/
static void test_GetConfigurationDeployConfigurationProperty_ErrorEsfJsonArrayGet(void **state)
{
    Deploy_t *deploy = NULL;
    EsfJsonHandle expect_esf_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue expect_esf_pare_val = 1357;
    EsfJsonValue expect_esf_child_val = 2468;
    EsfJsonValueType expect_val_type = kEsfJsonValueTypeArray;
    ssize_t array_cnt = 1;
    EsfJsonValue expect_subval = 1122;
    int topic_id = 0; // DeployTopicFirmware
    const char *deploy_version = "V00112233";
    RetCode expect_ret_code = kRetOk;
    RetCode ret;

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }

    memset(deploy, 0x00, sizeof(Deploy_t));

    CheckGetConfigurationReqInfoProperty(system_app_cmn_get_req_id, expect_esf_handle,
                                         expect_esf_pare_val, expect_ret_code);

    ExtractStringValueCommon(expect_esf_handle, expect_esf_pare_val, "version", deploy_version, 1);

    // targets property
    expect_value(__wrap_EsfJsonObjectGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, expect_esf_pare_val);
    expect_string(__wrap_EsfJsonObjectGet, key, "targets");
    will_return(__wrap_EsfJsonObjectGet, expect_esf_child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    // value type
    expect_value(__wrap_EsfJsonValueTypeGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, expect_esf_child_val);
    will_return(__wrap_EsfJsonValueTypeGet, expect_val_type);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // array count
    expect_value(__wrap_EsfJsonArrayCount, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonArrayCount, parent, expect_esf_child_val);
    will_return(__wrap_EsfJsonArrayCount, array_cnt);

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, sizeof(DeployTarget_t) * array_cnt);

    // get array
    expect_value(__wrap_EsfJsonArrayGet, handle, expect_esf_handle);
    expect_value(__wrap_EsfJsonArrayGet, parent, expect_esf_child_val);
    expect_value(__wrap_EsfJsonArrayGet, index, (array_cnt - 1));
    will_return(__wrap_EsfJsonArrayGet, expect_subval);
    will_return(__wrap_EsfJsonArrayGet, kEsfJsonInternalError);

    // Exec test target
    ret = GetConfigurationDeployConfigurationProperty(expect_esf_handle, expect_esf_pare_val,
                                                      deploy, topic_id);

    // Check output
    assert_int_equal(ret, kRetFailed);
    assert_string_equal(deploy->id, system_app_cmn_get_req_id);
    assert_int_equal(deploy->topic_id, topic_id);
    assert_string_equal(deploy->version, chk_config_deploy_version);
    assert_int_equal(deploy->deploy_target_num, array_cnt);
    assert_int_equal(deploy->deploy_target_cnt, 0);
    assert_non_null(deploy->deploy_targets);
    assert_int_equal(deploy->deploy_targets->component, 0);
    assert_string_equal(deploy->deploy_targets->name, "");
    assert_string_equal(deploy->deploy_targets->chip, "");
    assert_string_equal(deploy->deploy_targets->version, "");
    assert_string_equal(deploy->deploy_targets->package_url, "");
    assert_string_equal(deploy->deploy_targets->hash, "");
    assert_int_equal(deploy->deploy_targets->size, 0);
    assert_int_equal(deploy->deploy_targets->progress, 0);
    assert_int_equal(deploy->deploy_targets->process_state, DeployStateIdle);
    assert_int_equal(deploy->deploy_targets->parse_state, DeployStateIdle);
    assert_string_equal(deploy->res_info.res_id, "");
    assert_int_equal(deploy->res_info.code, 0);
    assert_string_equal(deploy->res_info.detail_msg, "");
    assert_int_equal(deploy->parse_state, DeployStateFailed);

exit:
    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/

//
// FirmwareUpdateOpen()
//

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdateOpen_RequestToStopForDownload(void **state)
{
    EsfFwMgrHandle ret;
    EsfFwMgrPrepareWriteResponse res_prepare;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    size_t size;
    DeployState_e curret_state = DeployStateRequestReceived;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->process_state = curret_state;

    size = 1234;

    // mock operation for FirmwareUpdateOpen()
    FirmwareUpdateOpenCommon(init_param, target, size, false, NULL, 0,
                             FirmwareUpdateOpenCommon_None);
    target->process_state =
        curret_state; // set again because FirmwareUpdateOpenCommon() may have been updated

    // Exec test target
    ret = FirmwareUpdateOpen(init_param, target, size, &res_prepare);

    // Check output
    assert_null(ret);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdateOpen_Cancelled(void **state)
{
    EsfFwMgrHandle ret;
    EsfFwMgrPrepareWriteResponse res_prepare;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    size_t size;
    DeployState_e curret_state = DeployStateRequestReceived;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->process_state = curret_state;

    size = 1234;

    for (int i = 0; i < DeployTopicNum; i++) {
        init_param->is_cancels[i] = true;
    }

    // mock operation for FirmwareUpdateOpen()
    FirmwareUpdateOpenCommon(init_param, target, size, false, NULL, 0,
                             FirmwareUpdateOpenCommon_None);
    target->process_state =
        curret_state; // set again because FirmwareUpdateOpenCommon() may have been updated

    // Exec test target
    ret = FirmwareUpdateOpen(init_param, target, size, &res_prepare);

    // Check output
    assert_null(ret);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdateOpen_FullySuccessNormal(void **state)
{
    EsfFwMgrHandle ret;
    EsfFwMgrPrepareWriteResponse res_prepare;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    size_t size;
    EsfFwMgrOpenResponse fw_mgr_open_res = {.handle = (EsfFwMgrHandle)1234,
                                            .prepare_write.memory_size = 2345,
                                            .prepare_write.writable_size = 3456};
    DeployState_e curret_state = DeployStateRequestReceived;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->process_state = curret_state;

    size = 1234;

    // mock operation for FirmwareUpdateOpen()
    FirmwareUpdateOpenCommon(init_param, target, size, true, &fw_mgr_open_res, 0,
                             FirmwareUpdateOpenCommon_None);
    target->process_state =
        curret_state; // set again because FirmwareUpdateOpenCommon() may have been updated

    // Exec test target
    ret = FirmwareUpdateOpen(init_param, target, size, &res_prepare);

    // Check output
    assert_int_equal(ret, fw_mgr_open_res.handle);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdateOpen_FullySuccessHashNullOnly(void **state)
{
    EsfFwMgrHandle ret;
    EsfFwMgrPrepareWriteResponse res_prepare;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    size_t size;
    EsfFwMgrOpenResponse fw_mgr_open_res = {.handle = (EsfFwMgrHandle)1234,
                                            .prepare_write.memory_size = 2345,
                                            .prepare_write.writable_size = 3456};
    DeployState_e curret_state = DeployStateRequestReceived;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->hash[0] = '\0';
    target->process_state = curret_state;

    size = 1234;

    // mock operation for FirmwareUpdateOpen()
    FirmwareUpdateOpenCommon(init_param, target, size, true, &fw_mgr_open_res, 0,
                             FirmwareUpdateOpenCommon_None);
    target->process_state =
        curret_state; // set again because FirmwareUpdateOpenCommon() may have been updated

    // Exec test target
    ret = FirmwareUpdateOpen(init_param, target, size, &res_prepare);

    // Check output
    assert_int_equal(ret, fw_mgr_open_res.handle);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdateOpen_ErrorEsfCodecBase64Decode(void **state)
{
    EsfFwMgrHandle ret;
    EsfFwMgrPrepareWriteResponse res_prepare;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    size_t size;
    DeployState_e curret_state = DeployStateRequestReceived;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->process_state = curret_state;

    size = 1234;

    // mock operation for FirmwareUpdateOpen()
    FirmwareUpdateOpenCommon(init_param, target, size, false, NULL, 0,
                             FirmwareUpdateOpenCommon_Base64Decode);
    target->process_state =
        curret_state; // set again because FirmwareUpdateOpenCommon() may have been updated

    // Exec test target
    ret = FirmwareUpdateOpen(init_param, target, size, &res_prepare);

    // Check output
    assert_null(ret);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdateOpen_FullySuccessOpenRetry(void **state)
{
    EsfFwMgrHandle ret;
    EsfFwMgrPrepareWriteResponse res_prepare;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    size_t size;
    EsfFwMgrOpenResponse fw_mgr_open_res = {.handle = (EsfFwMgrHandle)1234,
                                            .prepare_write.memory_size = 2345,
                                            .prepare_write.writable_size = 3456};
    DeployState_e curret_state = DeployStateRequestReceived;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->process_state = curret_state;

    size = 1234;

    // mock operation for FirmwareUpdateOpen()
    FirmwareUpdateOpenCommon(init_param, target, size, true, &fw_mgr_open_res, 2,
                             FirmwareUpdateOpenCommon_None);
    target->process_state =
        curret_state; // set again because FirmwareUpdateOpenCommon() may have been updated

    // Exec test target
    ret = FirmwareUpdateOpen(init_param, target, size, &res_prepare);

    // Check output
    assert_int_equal(ret, fw_mgr_open_res.handle);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdateOpen_ErrorEsfFwMgrOpenRetryOver(void **state)
{
    EsfFwMgrHandle ret;
    EsfFwMgrPrepareWriteResponse res_prepare;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    size_t size;
    EsfFwMgrOpenResponse fw_mgr_open_res = {.handle = (EsfFwMgrHandle)1234,
                                            .prepare_write.memory_size = 2345,
                                            .prepare_write.writable_size = 3456};
    DeployState_e curret_state = DeployStateRequestReceived;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->process_state = curret_state;

    size = 1234;

    // mock operation for FirmwareUpdateOpen()
    FirmwareUpdateOpenCommon(init_param, target, size, true, &fw_mgr_open_res,
                             MAX_NUMBER_OF_UPDATE_OPEN_RETRY + 1, FirmwareUpdateOpenCommon_None);
    target->process_state =
        curret_state; // set again because FirmwareUpdateOpenCommon() may have been updated

    // Exec test target
    ret = FirmwareUpdateOpen(init_param, target, size, &res_prepare);

    // Check output
    assert_null(ret);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdateOpen_ErrorEsfFwMgrOpenOther(void **state)
{
    EsfFwMgrHandle ret;
    EsfFwMgrPrepareWriteResponse res_prepare;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    size_t size;
    EsfFwMgrOpenResponse fw_mgr_open_res = {.handle = (EsfFwMgrHandle)1234,
                                            .prepare_write.memory_size = 2345,
                                            .prepare_write.writable_size = 3456};
    DeployState_e curret_state = DeployStateRequestReceived;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->process_state = curret_state;

    size = 1234;

    // mock operation for FirmwareUpdateOpen()
    FirmwareUpdateOpenCommon(init_param, target, size, true, &fw_mgr_open_res, 0,
                             FirmwareUpdateOpenCommon_EsfFwMgrOpen);
    target->process_state =
        curret_state; // set again because FirmwareUpdateOpenCommon() may have been updated

    // Exec test target
    ret = FirmwareUpdateOpen(init_param, target, size, &res_prepare);

    // Check output
    assert_null(ret);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdateOpen_NullPRes(void **state)
{
    EsfFwMgrHandle ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    size_t size;
    EsfFwMgrOpenResponse fw_mgr_open_res = {.handle = (EsfFwMgrHandle)1234,
                                            .prepare_write.memory_size = 2345,
                                            .prepare_write.writable_size = 3456};
    DeployState_e curret_state = DeployStateRequestReceived;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->process_state = curret_state;

    size = 1234;

    // mock operation for FirmwareUpdateOpen()
    FirmwareUpdateOpenCommon(init_param, target, size, true, &fw_mgr_open_res, 0,
                             FirmwareUpdateOpenCommon_None);
    target->process_state =
        curret_state; // set again because FirmwareUpdateOpenCommon() may have been updated

    // Exec test target
    ret = FirmwareUpdateOpen(init_param, target, size, NULL);

    // Check output
    assert_int_equal(ret, fw_mgr_open_res.handle);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/

//
// CompareDeployingVersionWithDeployedOneTarget()
//

/*----------------------------------------------------------------------------*/
static void test_CompareDeployingVersionWithDeployedOneTarget_FullySuccess(void **state)
{
    int ret;
    DeployTarget_t *target = NULL;
    DeployState_e deploy_state;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    // mock operation for CompareDeployingVersionWithDeployedOneTarget()
    CompareDeployingVersionWithDeployedOneTargetCommon(
        target, true, CompareDeployingVersionWithDeployedOneTarget_None);

    // Exec test target
    ret = CompareDeployingVersionWithDeployedOneTarget(target, &deploy_state);

    // Check output
    assert_int_equal(ret, 0);
    assert_int_equal(deploy_state, DeployStateFailed);

exit:
    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_CompareDeployingVersionWithDeployedOneTarget_ErrorEsfFwMgrGetInfo(void **state)
{
    int ret;
    DeployTarget_t *target = NULL;
    DeployState_e deploy_state;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    // mock operation for CompareDeployingVersionWithDeployedOneTarget()
    CompareDeployingVersionWithDeployedOneTargetCommon(
        target, true, CompareDeployingVersionWithDeployedOneTarget_GetInfo);

    // Exec test target
    ret = CompareDeployingVersionWithDeployedOneTarget(target, &deploy_state);

    // Check output
    assert_int_equal(ret, -1);
    assert_int_equal(deploy_state, DeployStateFailed);

exit:
    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_CompareDeployingVersionWithDeployedOneTarget_ErrorEsfCodecBase64Decode(
    void **state)
{
    int ret;
    DeployTarget_t *target = NULL;
    DeployState_e deploy_state;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    // mock operation for CompareDeployingVersionWithDeployedOneTarget()
    CompareDeployingVersionWithDeployedOneTargetCommon(
        target, true, CompareDeployingVersionWithDeployedOneTarget_Base64Decode);

    // Exec test target
    ret = CompareDeployingVersionWithDeployedOneTarget(target, &deploy_state);

    // Check output
    assert_int_equal(ret, -1);
    assert_int_equal(deploy_state, DeployStateFailedInvalidRequest);

exit:
    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/

//
// CompareDeployingVersionWithDeployedAiModel()
//

/*----------------------------------------------------------------------------*/
static void test_CompareDeployingVersionWithDeployedAiModel_FullySuccessSameVersion(void **state)
{
    int ret;
    DeployTarget_t *target = NULL;
    DeployState_e deploy_state;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    // mock operation for CompareDeployingVersionWithDeployedAiModel()
    CompareDeployingVersionWithDeployedAiModelCommon(
        target, CompareDeployingVersionWithDeployedAiModel_None);

    // Exec test target
    ret = CompareDeployingVersionWithDeployedAiModel(target, &deploy_state);

    // Check output
    assert_int_equal(ret, 0);
    assert_int_equal(deploy_state, DeployStateFailed);

exit:
    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_CompareDeployingVersionWithDeployedAiModel_ErrorMalloc(void **state)
{
    int ret;
    DeployTarget_t *target = NULL;
    DeployState_e deploy_state;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    // mock operation for CompareDeployingVersionWithDeployedAiModel()
    CompareDeployingVersionWithDeployedAiModelCommon(
        target, CompareDeployingVersionWithDeployedAiModel_MallocNull);

    // For SysAppLedSetAppStatus()
    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state,
                 LedAppStatusErrorUpdateMemoryAllocateFailed);

    // Exec test target
    ret = CompareDeployingVersionWithDeployedAiModel(target, &deploy_state);

    // Check output
    assert_int_equal(ret, -1);
    assert_int_equal(deploy_state, DeployStateFailed);

exit:
    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_CompareDeployingVersionWithDeployedAiModel_ErrorEsfFwMgrGetInfo(void **state)
{
    int ret;
    DeployTarget_t *target = NULL;
    DeployState_e deploy_state;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    // mock operation for CompareDeployingVersionWithDeployedAiModel()
    CompareDeployingVersionWithDeployedAiModelCommon(
        target, CompareDeployingVersionWithDeployedAiModel_GetInfo);

    // Exec test target
    ret = CompareDeployingVersionWithDeployedAiModel(target, &deploy_state);

    // Check output
    assert_int_equal(ret, -1);
    assert_int_equal(deploy_state, DeployStateFailed);

exit:
    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_CompareDeployingVersionWithDeployedAiModel_ErrorEsfCodecBase64Decode(void **state)
{
    int ret;
    DeployTarget_t *target = NULL;
    DeployState_e deploy_state;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    // mock operation for CompareDeployingVersionWithDeployedAiModel()
    CompareDeployingVersionWithDeployedAiModelCommon(
        target, CompareDeployingVersionWithDeployedAiModel_Base64Decode);

    // Exec test target
    ret = CompareDeployingVersionWithDeployedAiModel(target, &deploy_state);

    // Check output
    assert_int_equal(ret, -1);
    assert_int_equal(deploy_state, DeployStateFailedInvalidRequest);

exit:
    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_CompareDeployingVersionWithDeployedAiModel_FullySuccessDiffVersion(void **state)
{
    int ret;
    DeployTarget_t *target = NULL;
    DeployState_e deploy_state;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    // mock operation for CompareDeployingVersionWithDeployedAiModel()
    CompareDeployingVersionWithDeployedAiModelCommon(
        target, CompareDeployingVersionWithDeployedAiModel_DiffVersion);

    // Exec test target
    ret = CompareDeployingVersionWithDeployedAiModel(target, &deploy_state);

    // Check output
    assert_int_equal(ret, 2);
    assert_int_equal(deploy_state, DeployStateFailed);

exit:
    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_CompareDeployingVersionWithDeployedAiModel_ErrorDiffVersionSlotFull(void **state)
{
    int ret;
    DeployTarget_t *target = NULL;
    DeployState_e deploy_state;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    // mock operation for CompareDeployingVersionWithDeployedAiModel()
    CompareDeployingVersionWithDeployedAiModelCommon(
        target, CompareDeployingVersionWithDeployedAiModel_SlotFull);

    // Exec test target
    ret = CompareDeployingVersionWithDeployedAiModel(target, &deploy_state);

    // Check output
    assert_int_equal(ret, -1);
    assert_int_equal(deploy_state, DeployStateFailed);

exit:
    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/

//
// CheckVersion()
//

/*----------------------------------------------------------------------------*/
static void test_CheckVersion_SensorLoader(void **state)
{
    int ret;
    DeployTarget_t *target = NULL;
    DeployState_e deploy_state;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    target->component = DeployComponentSensorLoader;

    // mock operation for CompareDeployingVersionWithDeployedOneTarget()
    CheckVersionCommon(target, CheckVersion_NeedDeploy);

    // Exec test target
    ret = CheckVersion(target, &deploy_state);

    // Check output
    assert_int_equal(ret, 1);
    assert_int_equal(deploy_state, DeployStateFailed);

exit:
    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_CheckVersion_AiModel(void **state)
{
    int ret;
    DeployTarget_t *target = NULL;
    DeployState_e deploy_state;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    target->component = DeployComponentAiModel;

    // mock operation for CompareDeployingVersionWithDeployedOneTarget()
    CheckVersionCommon(target, CheckVersion_NeedDeploy);

    // Exec test target
    ret = CheckVersion(target, &deploy_state);

    // Check output
    assert_int_equal(ret, 2);
    assert_int_equal(deploy_state, DeployStateFailed);

exit:
    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/
static void test_CheckVersion_Other(void **state)
{
    int ret;
    DeployTarget_t *target = NULL;
    DeployState_e deploy_state;

    // Prepare test target argument
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    target->component = DeployComponentNum;

    // Exec test target
    ret = CheckVersion(target, &deploy_state);

    // Check output
    assert_int_equal(ret, -1);
    assert_int_equal(deploy_state, DeployStateFailed);

exit:
    if (target != NULL) {
        free(target);
    }
}

/*----------------------------------------------------------------------------*/

//
// DownloadCallback()
//

/*----------------------------------------------------------------------------*/
static void test_DownloadCallback_FullySuccess(void **state)
{
    int ret;
    DeployFwWrite_t *expect_deploy_fw_write = NULL;
    size_t expect_dl_size = 2468;
    size_t expect_offset = 999;
    uint8_t expect_data = 0x01;

    // Prepare test target argument
    expect_deploy_fw_write = (DeployFwWrite_t *)malloc(sizeof(DeployFwWrite_t));
    if (expect_deploy_fw_write == NULL) {
        assert_non_null(expect_deploy_fw_write);
        goto exit;
    }

    memset(expect_deploy_fw_write, 0x00, sizeof(DeployFwWrite_t));
    expect_deploy_fw_write->fwmgr_handle = (EsfFwMgrHandle)1234;
    expect_deploy_fw_write->offset = expect_offset;

    // Prepare handle for mbedtls_sha256_update()
    expect_deploy_fw_write->sha256_handle =
        (mbedtls_sha256_context *)malloc(sizeof(mbedtls_sha256_context));
    if (expect_deploy_fw_write->sha256_handle == NULL) {
        assert_non_null(expect_deploy_fw_write->sha256_handle);
        goto exit;
    }

    memset(expect_deploy_fw_write->sha256_handle, 0x00, sizeof(mbedtls_sha256_context));

    expect_value(__wrap_EsfFwMgrCopyToInternalBuffer, handle, expect_deploy_fw_write->fwmgr_handle);
    expect_value(__wrap_EsfFwMgrCopyToInternalBuffer, request->offset,
                 expect_deploy_fw_write->offset);
    expect_value(__wrap_EsfFwMgrCopyToInternalBuffer, request->size, expect_dl_size);
    expect_value(__wrap_EsfFwMgrCopyToInternalBuffer, request->data, &expect_data);
    will_return(__wrap_EsfFwMgrCopyToInternalBuffer, kEsfFwMgrResultOk);

    // For mbedtls_sha256_update()
    will_return(__wrap_mbedtls_sha256_update, 0);
    expect_value(__wrap_mbedtls_sha256_update, ctx, expect_deploy_fw_write->sha256_handle);
    expect_value(__wrap_mbedtls_sha256_update, input, &expect_data);
    expect_value(__wrap_mbedtls_sha256_update, ilen, expect_dl_size);

    // For SysAppUdIsThisRequestToStopForDownload()
    will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, false);

    // Exec test target
    ret = DownloadCallback(&expect_data, expect_dl_size, (void *)expect_deploy_fw_write);

    // Check output
    assert_int_equal(ret, 0);
    assert_int_equal(expect_deploy_fw_write->offset, expect_dl_size + expect_offset);

exit:
    if (expect_deploy_fw_write->sha256_handle != NULL) {
        free(expect_deploy_fw_write->sha256_handle);
    }

    if (expect_deploy_fw_write != NULL) {
        free(expect_deploy_fw_write);
    }
}

/*----------------------------------------------------------------------------*/
static void test_DownloadCallback_Cancelled(void **state)
{
    int ret;
    DeployFwWrite_t *expect_deploy_fw_write = NULL;
    size_t expect_dl_size = 2468;
    size_t expect_offset = 999;
    uint8_t expect_data = 0x01;

    // Prepare test target argument
    expect_deploy_fw_write = (DeployFwWrite_t *)malloc(sizeof(DeployFwWrite_t));
    if (expect_deploy_fw_write == NULL) {
        assert_non_null(expect_deploy_fw_write);
        goto exit;
    }

    memset(expect_deploy_fw_write, 0x00, sizeof(DeployFwWrite_t));
    expect_deploy_fw_write->fwmgr_handle = (EsfFwMgrHandle)1234;
    expect_deploy_fw_write->offset = expect_offset;

    // Prepare handle for mbedtls_sha256_update()
    expect_deploy_fw_write->sha256_handle =
        (mbedtls_sha256_context *)malloc(sizeof(mbedtls_sha256_context));
    if (expect_deploy_fw_write->sha256_handle == NULL) {
        assert_non_null(expect_deploy_fw_write->sha256_handle);
        goto exit;
    }

    memset(expect_deploy_fw_write->sha256_handle, 0x00, sizeof(mbedtls_sha256_context));

    expect_value(__wrap_EsfFwMgrCopyToInternalBuffer, handle, expect_deploy_fw_write->fwmgr_handle);
    expect_value(__wrap_EsfFwMgrCopyToInternalBuffer, request->offset,
                 expect_deploy_fw_write->offset);
    expect_value(__wrap_EsfFwMgrCopyToInternalBuffer, request->size, expect_dl_size);
    expect_value(__wrap_EsfFwMgrCopyToInternalBuffer, request->data, &expect_data);
    will_return(__wrap_EsfFwMgrCopyToInternalBuffer, kEsfFwMgrResultOk);

    // For mbedtls_sha256_update()
    will_return(__wrap_mbedtls_sha256_update, 0);
    expect_value(__wrap_mbedtls_sha256_update, ctx, expect_deploy_fw_write->sha256_handle);
    expect_value(__wrap_mbedtls_sha256_update, input, &expect_data);
    expect_value(__wrap_mbedtls_sha256_update, ilen, expect_dl_size);

    // For SysAppUdIsThisRequestToStopForDownload()
    will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, true);

    // Exec test target
    ret = DownloadCallback(&expect_data, expect_dl_size, (void *)expect_deploy_fw_write);

    // Check output
    assert_int_equal(ret, -1);
    assert_int_equal(expect_deploy_fw_write->offset, expect_dl_size + expect_offset);

exit:
    if (expect_deploy_fw_write->sha256_handle != NULL) {
        free(expect_deploy_fw_write->sha256_handle);
    }

    if (expect_deploy_fw_write != NULL) {
        free(expect_deploy_fw_write);
    }
}

/*----------------------------------------------------------------------------*/
static void test_DownloadCallback_SucessRequestToStopForDownloadIsTrue(void **state)
{
    int ret;
    DeployFwWrite_t *expect_deploy_fw_write = NULL;
    size_t expect_dl_size = 2468;
    size_t expect_offset = 999;
    uint8_t expect_data = 0x01;

    // Prepare test target argument
    expect_deploy_fw_write = (DeployFwWrite_t *)malloc(sizeof(DeployFwWrite_t));
    if (expect_deploy_fw_write == NULL) {
        assert_non_null(expect_deploy_fw_write);
        goto exit;
    }

    memset(expect_deploy_fw_write, 0x00, sizeof(DeployFwWrite_t));
    expect_deploy_fw_write->fwmgr_handle = (EsfFwMgrHandle)1234;
    expect_deploy_fw_write->offset = expect_offset;

    // Prepare handle for mbedtls_sha256_update()
    expect_deploy_fw_write->sha256_handle =
        (mbedtls_sha256_context *)malloc(sizeof(mbedtls_sha256_context));
    if (expect_deploy_fw_write->sha256_handle == NULL) {
        assert_non_null(expect_deploy_fw_write->sha256_handle);
        goto exit;
    }

    memset(expect_deploy_fw_write->sha256_handle, 0x00, sizeof(mbedtls_sha256_context));

    expect_value(__wrap_EsfFwMgrCopyToInternalBuffer, handle, expect_deploy_fw_write->fwmgr_handle);
    expect_value(__wrap_EsfFwMgrCopyToInternalBuffer, request->offset,
                 expect_deploy_fw_write->offset);
    expect_value(__wrap_EsfFwMgrCopyToInternalBuffer, request->size, expect_dl_size);
    expect_value(__wrap_EsfFwMgrCopyToInternalBuffer, request->data, &expect_data);
    will_return(__wrap_EsfFwMgrCopyToInternalBuffer, kEsfFwMgrResultOk);

    // For mbedtls_sha256_update()
    will_return(__wrap_mbedtls_sha256_update, 0);
    expect_value(__wrap_mbedtls_sha256_update, ctx, expect_deploy_fw_write->sha256_handle);
    expect_value(__wrap_mbedtls_sha256_update, input, &expect_data);
    expect_value(__wrap_mbedtls_sha256_update, ilen, expect_dl_size);

    // For SysAppUdIsThisRequestToStopForDownload()
    will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, true);

    // Exec test target
    ret = DownloadCallback(&expect_data, expect_dl_size, (void *)expect_deploy_fw_write);

    // Check output
    assert_int_equal(ret, -1);
    assert_int_equal(expect_deploy_fw_write->offset, expect_dl_size + expect_offset);

exit:
    if (expect_deploy_fw_write->sha256_handle != NULL) {
        free(expect_deploy_fw_write->sha256_handle);
    }

    if (expect_deploy_fw_write != NULL) {
        free(expect_deploy_fw_write);
    }
}

/*----------------------------------------------------------------------------*/

//
// FirmwareUpdate()
//

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdate_FullySuccessProcessorLoader(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;

    // mock operation for FirmwareUpdateCommon()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    FirmwareUpdateCommon(init_param, target, 1, sha256_ctx, FirmwareUpdateCommon_None);

    // Exec test target
    ret = FirmwareUpdate(init_param, target);

    // Check output
    assert_int_equal(ret, kRetOk);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdate_FullySuccessProcessorFirmware(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorFirmware;

    // mock operation for FirmwareUpdateCommon()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    FirmwareUpdateCommon(init_param, target, 1, sha256_ctx, FirmwareUpdateCommon_None);

    // Exec test target
    ret = FirmwareUpdate(init_param, target);

    // Check output
    assert_int_equal(ret, kRetOk);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdate_FullySuccessAiModel(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicAiModel;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentAiModel;

    // mock operation for FirmwareUpdateCommon()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    FirmwareUpdateCommon(init_param, target, 1, sha256_ctx, FirmwareUpdateCommon_None);

    // Exec test target
    ret = FirmwareUpdate(init_param, target);

    // Check output
    assert_int_equal(ret, kRetOk);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdate_FullySuccessGetSize(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;
    target->size = 0;

    // mock operation for FirmwareUpdateCommon()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    FirmwareUpdateCommon(init_param, target, 1, sha256_ctx, FirmwareUpdateCommon_None);

    // Exec test target
    ret = FirmwareUpdate(init_param, target);

    // Check output
    assert_int_equal(ret, kRetOk);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdate_FullySuccessDownload2Times(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;

    // mock operation for FirmwareUpdateCommon()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    FirmwareUpdateCommon(init_param, target, 2, sha256_ctx, FirmwareUpdateCommon_None);

    // Exec test target
    ret = FirmwareUpdate(init_param, target);

    // Check output
    assert_int_equal(ret, kRetOk);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdate_ErrorGetSize403(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;
    target->size = 0;

    // mock operation for FirmwareUpdateCommon()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    FirmwareUpdateCommon(init_param, target, 1, sha256_ctx, FirmwareUpdateCommon_GetImageSize403);

    // Exec test target
    ret = FirmwareUpdate(init_param, target);

    // Check output
    assert_int_equal(ret, kRetFailed);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdate_ErrorGetSizeOther(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;
    target->size = 0;

    // mock operation for FirmwareUpdateCommon()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    FirmwareUpdateCommon(init_param, target, 1, sha256_ctx, FirmwareUpdateCommon_GetImageSizeOther);

    // Exec test target
    ret = FirmwareUpdate(init_param, target);

    // Check output
    assert_int_equal(ret, kRetFailed);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdate_ErrorGetSizeBadParams(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;
    target->size = 0;

    // mock operation for FirmwareUpdateCommon()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    FirmwareUpdateCommon(init_param, target, 1, sha256_ctx,
                         FirmwareUpdateCommon_GetImageSizeBadParams);

    // Exec test target
    ret = FirmwareUpdate(init_param, target);

    // Check output
    assert_int_equal(ret, kRetFailed);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdate_ErrorFirmwareUpdateOpen(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;

    // mock operation for FirmwareUpdateCommon()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    FirmwareUpdateCommon(init_param, target, 1, sha256_ctx,
                         FirmwareUpdateCommon_FirmwareUpdateOpen);

    // Exec test target
    ret = FirmwareUpdate(init_param, target);

    // Check output
    assert_int_equal(ret, kRetFailed);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdate_ErrorUpdateMemoriSize(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;

    // mock operation for FirmwareUpdateCommon()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    FirmwareUpdateCommon(init_param, target, 1, sha256_ctx, FirmwareUpdateCommon_UpdateMemorySize);

    // Exec test target
    ret = FirmwareUpdate(init_param, target);

    // Check output
    assert_int_equal(ret, kRetFailed);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdate_ErrorFinishSha256(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;

    // mock operation for FirmwareUpdateCommon()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    FirmwareUpdateCommon(init_param, target, 1, sha256_ctx, FirmwareUpdateCommon_FinishSha256);

    // Exec test target
    ret = FirmwareUpdate(init_param, target);

    // Check output
    assert_int_equal(ret, kRetOk);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdate_ErrorNotMatchHash(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;

    // mock operation for FirmwareUpdateCommon()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    FirmwareUpdateCommon(init_param, target, 1, sha256_ctx, FirmwareUpdateCommon_NotMatchHash);

    // Exec test target
    ret = FirmwareUpdate(init_param, target);

    // Check output
    assert_int_equal(ret, kRetFailed);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdate_ErrorFwMgrPostProcess(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;

    // mock operation for FirmwareUpdateCommon()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    FirmwareUpdateCommon(init_param, target, 1, sha256_ctx, FirmwareUpdateCommon_FwMgrPostProcess);

    // Exec test target
    ret = FirmwareUpdate(init_param, target);

    // Check output
    assert_int_equal(ret, kRetFailed);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdate_ErrorGetImage403(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;

    // mock operation for FirmwareUpdateCommon()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    FirmwareUpdateCommon(init_param, target, 1, sha256_ctx, FirmwareUpdateCommon_GetImage403);

    // Exec test target
    ret = FirmwareUpdate(init_param, target);

    // Check output
    assert_int_equal(ret, kRetFailed);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdate_ErrorGetImageBadParams(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;

    // mock operation for FirmwareUpdateCommon()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    FirmwareUpdateCommon(init_param, target, 1, sha256_ctx, FirmwareUpdateCommon_GetImageBadParams);

    // Exec test target
    ret = FirmwareUpdate(init_param, target);

    // Check output
    assert_int_equal(ret, kRetFailed);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdate_ErrorGetImageReteyOver(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;

    // mock operation for FirmwareUpdateCommon()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    FirmwareUpdateCommon(init_param, target, 1, sha256_ctx, FirmwareUpdateCommon_GetImageRetryOver);

    // Exec test target
    ret = FirmwareUpdate(init_param, target);

    // Check output
    assert_int_equal(ret, kRetFailed);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdate_ErrorGetImageRetry(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;

    // mock operation for FirmwareUpdateCommon()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    FirmwareUpdateCommon(init_param, target, 1, sha256_ctx,
                         FirmwareUpdateCommon_GetImageRetryAndSha256Null);

    // Exec test target
    ret = FirmwareUpdate(init_param, target);

    // Check output
    assert_int_equal(ret, kRetFailed);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdate_ErrorGetImageReteyOverRequestStop(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;

    // mock operation for FirmwareUpdateCommon()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    FirmwareUpdateCommon(init_param, target, 1, sha256_ctx, FirmwareUpdateCommon_RequestStop);

    // Exec test target
    ret = FirmwareUpdate(init_param, target);

    // Check output
    assert_int_equal(ret, kRetFailed);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdate_ErrorGetImageReteyOverRequestStopInWaitingForRetry(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;

    // mock operation for FirmwareUpdateCommon()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    FirmwareUpdateCommon(init_param, target, 1, sha256_ctx,
                         FirmwareUpdateCommon_RequestStopInWaitingForRetry);

    // Exec test target
    ret = FirmwareUpdate(init_param, target);

    assert_int_equal(init_param->arch_version, kEsfFwMgrSwArchVersion2);
    assert_int_equal(target->process_state, DeployStateFailed);
    assert_int_equal(ret, kRetFailed);

    // Check output
    assert_int_equal(ret, kRetFailed);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdate_ErrorEsfFwMgrWrite(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;

    // mock operation for FirmwareUpdateCommon()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    FirmwareUpdateCommon(init_param, target, 2, sha256_ctx, FirmwareUpdateCommon_FwMgrWrite);

    // Exec test target
    ret = FirmwareUpdate(init_param, target);

    // Check output
    assert_int_equal(ret, kRetFailed);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdate_ErrorEsfFwMgrClose(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;

    // mock operation for FirmwareUpdateCommon()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    FirmwareUpdateCommon(init_param, target, 2, sha256_ctx, FirmwareUpdateCommon_FwMgrClose);

    // Exec test target
    ret = FirmwareUpdate(init_param, target);

    // Check output
    assert_int_equal(ret, kRetFailed);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_FirmwareUpdate_ErrorEsfFwMgrGetBinaryHeaderInfo(void **state)
{
    RetCode ret;
    DeployInitParams_t *init_param = NULL;
    DeployTarget_t *target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;
    int i;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }
    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;

    // mock operation for FirmwareUpdateCommon()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    FirmwareUpdateCommon(init_param, target, 2, sha256_ctx,
                         FirmwareUpdateCommon_FwMgrGetBinaryHeaderInfo);

    // Exec test target
    ret = FirmwareUpdate(init_param, target);

    // Check output
    assert_int_equal(ret, kRetOk);
    // to be added more...

exit:
    for (i = 0; i < DeployTopicNum; i++) {
        if (init_param->state_str[i] != NULL) {
            free(init_param->state_str[i]);
        }
    }

    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param != NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/

//
// ParseConfiguration()
//

/*----------------------------------------------------------------------------*/
static void test_ParseConfiguration_FullySuccess(void **state)
{
    Deploy_t *deploy = NULL;
    DeployTarget_t *expect_value = NULL;
    const char *expect_param = "expect_deserialize";
    ssize_t array_cnt = 1;
    int topic_id = 0; // DeployTopicFirmware
    RetCode ret;

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }
    // Create expect value
    expect_value = malloc(sizeof(DeployTarget_t));
    if (expect_value == NULL) {
        assert_non_null(expect_value);
        goto exit;
    }
    memset(deploy, 0x00, sizeof(Deploy_t));
    snprintf(deploy->id, sizeof(deploy->id), "%s", "No.777");

    SetGetConfigurationDeployTargetPropertyExpectValue(expect_value, DeployComponentSensorLoader,
                                                       dtdl_deploy_target_chip_sensor_chip, "");

    // Check ParseConfiguration()
    CheckParseConfiguration(deploy, expect_value, array_cnt, topic_id, expect_param);

    // Exec test target
    ret = ParseConfiguration(deploy, topic_id, expect_param);

    // Check output
    assert_int_equal(ret, kRetOk);
    // to be added more...

exit:
    if (expect_value != NULL) {
        free(expect_value);
    }

    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/
static void test_ParseConfiguration_ErrorEsfJsonOpen(void **state)
{
    Deploy_t *deploy = NULL;
    const char *expect_param = "expect_deserialize";
    EsfJsonHandle expect_esf_handle = ESF_JSON_HANDLE_INITIALIZER;
    int topic_id = 0; // DeployTopicFirmware

    RetCode ret;

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }

    memset(deploy, 0x00, sizeof(Deploy_t));
    snprintf(deploy->id, sizeof(deploy->id), "%s", "No.777");

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, expect_esf_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);

    // Exec test target
    ret = ParseConfiguration(deploy, topic_id, expect_param);

    // Check output
    assert_int_equal(ret, kRetFailed);
    // to be added more...

exit:
    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/
static void test_ParseConfiguration_ErrorEsfJsonDeserialize(void **state)
{
    Deploy_t *deploy = NULL;
    const char *expect_param = "expect_deserialize";
    EsfJsonHandle expect_esf_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue expect_esf_pare_val = 1357;
    int topic_id = 0; // DeployTopicFirmware

    RetCode ret;

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }

    memset(deploy, 0x00, sizeof(Deploy_t));
    snprintf(deploy->id, sizeof(deploy->id), "%s", "No.777");

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, expect_esf_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // For EsfJsonDeserialize()
    expect_value(__wrap_EsfJsonDeserialize, handle, expect_esf_handle);
    expect_string(__wrap_EsfJsonDeserialize, str, expect_param);
    will_return(__wrap_EsfJsonDeserialize, expect_esf_pare_val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonInternalError);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, expect_esf_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = ParseConfiguration(deploy, topic_id, expect_param);

    // Check output
    assert_int_equal(ret, kRetFailed);
    // to be added more...

exit:
    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/
static void test_ParseConfiguration_ErrorGetConfigurationDeployConfigurationProperty(void **state)
{
    Deploy_t *deploy = NULL;
    DeployTarget_t *expect_value = NULL;
    const char *expect_param = "expect_deserialize";
    ssize_t array_cnt = -1;
    int topic_id = 0; // DeployTopicFirmware
    RetCode ret;

    // Prepare test target argument
    deploy = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deploy == NULL) {
        assert_non_null(deploy);
        goto exit;
    }
    // Create expect value
    expect_value = malloc(sizeof(DeployTarget_t));
    if (expect_value == NULL) {
        assert_non_null(expect_value);
        goto exit;
    }
    memset(deploy, 0x00, sizeof(Deploy_t));
    snprintf(deploy->id, sizeof(deploy->id), "%s", "No.777");

    SetGetConfigurationDeployTargetPropertyExpectValue(expect_value, DeployComponentSensorLoader,
                                                       dtdl_deploy_target_chip_sensor_chip, "");

    // Check ParseConfiguration()
    CheckParseConfiguration(deploy, expect_value, array_cnt, topic_id, expect_param);

    // Exec test target
    ret = ParseConfiguration(deploy, topic_id, expect_param);

    // Check output
    assert_int_equal(ret, kRetFailed);
    // to be added more...

exit:
    if (expect_value != NULL) {
        free(expect_value);
    }

    if (deploy != NULL) {
        free(deploy);
    }
}

/*----------------------------------------------------------------------------*/

//
// StartDeploy()
//

/*----------------------------------------------------------------------------*/
static void test_StartDeploy_ErrorParse(void **state)
{
    DeployInitParams_t *init_param = NULL;
    DeployInitParams_t *mock_init_param = NULL;
    DeployTarget_t *target = NULL;
    DeployTarget_t *mock_target = NULL;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    // Prepare mock argument
    mock_init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (mock_init_param == NULL) {
        assert_non_null(mock_init_param);
        goto exit;
    }
    mock_target = (DeployTarget_t *)malloc(sizeof(DeployTarget_t));
    if (mock_target == NULL) {
        assert_non_null(mock_target);
        goto exit;
    }

    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;
    target->parse_state = DeployStateFailedInvalidRequest;

    // Copy test parameter to mock argument
    memcpy(mock_init_param, init_param, sizeof(DeployInitParams_t));
    memcpy(mock_target, target, sizeof(DeployTarget_t));

    // Change target for mock operation
    mock_init_param->deploy.deploy_targets = mock_target;

    // mock operation for StartDeploy()
    StartDeployCommon(mock_init_param, NULL, StartDeploy_Other);

    // Exec test target
    StartDeploy(init_param);

    // Check output
    assert_int_equal(init_param->deploy.res_info.code, 3); // Invalid argument
    assert_string_equal(init_param->deploy.res_info.detail_msg, "invalid_argument");
    assert_string_equal(init_param->deploy.res_info.res_id, init_param->deploy.id);
    assert_int_equal(init_param->deploy.deploy_targets->progress, 0);
    assert_int_equal(init_param->deploy.deploy_targets->process_state,
                     mock_init_param->deploy.deploy_targets->parse_state);
    assert_string_equal(init_param->state_str[init_param->deploy.topic_id],
                        ESF_JSON_SERIALIZE_OUTPUT_STR);
    assert_int_equal(init_param->state_str_len[init_param->deploy.topic_id],
                     strlen(ESF_JSON_SERIALIZE_OUTPUT_STR));

exit:
    if (mock_target != NULL) {
        free(mock_target);
    }

    if (mock_init_param != NULL) {
        free(mock_init_param);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param == NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_StartDeploy_AlreadyDeployed(void **state)
{
    DeployInitParams_t *init_param = NULL;
    DeployInitParams_t *mock_init_param = NULL;
    DeployTarget_t *target = NULL;
    DeployTarget_t *mock_target = NULL;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    // Prepare mock argument
    mock_init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (mock_init_param == NULL) {
        assert_non_null(mock_init_param);
        goto exit;
    }
    mock_target = (DeployTarget_t *)malloc(sizeof(DeployTarget_t));
    if (mock_target == NULL) {
        assert_non_null(mock_target);
        goto exit;
    }

    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;
    target->parse_state = DeployStateIdle;

    // Copy test parameter to mock argument
    memcpy(mock_init_param, init_param, sizeof(DeployInitParams_t));
    memcpy(mock_target, target, sizeof(DeployTarget_t));

    // Change target for mock operation
    mock_init_param->deploy.deploy_targets = mock_target;

    // mock operation for StartDeploy()
    StartDeployCommon(mock_init_param, NULL, StartDeploy_AlreadyDeploy);

    // Exec test target
    StartDeploy(init_param);

    // Check output
    assert_int_equal(init_param->deploy.res_info.code, 0); // Ok
    assert_string_equal(init_param->deploy.res_info.detail_msg, "ok");
    assert_string_equal(init_param->deploy.res_info.res_id, init_param->deploy.id);
    assert_int_equal(init_param->deploy.deploy_targets->progress, 100);
    assert_int_equal(init_param->deploy.deploy_targets->process_state, DeployStateDone);
    assert_string_equal(init_param->state_str[init_param->deploy.topic_id],
                        ESF_JSON_SERIALIZE_OUTPUT_STR);
    assert_int_equal(init_param->state_str_len[init_param->deploy.topic_id],
                     strlen(ESF_JSON_SERIALIZE_OUTPUT_STR));

exit:
    if (mock_target != NULL) {
        free(mock_target);
    }

    if (mock_init_param != NULL) {
        free(mock_init_param);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param == NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_StartDeploy_ExecDeploy(void **state)
{
    DeployInitParams_t *init_param = NULL;
    DeployInitParams_t *mock_init_param = NULL;
    DeployTarget_t *target = NULL;
    DeployTarget_t *mock_target = NULL;
    mbedtls_sha256_context *sha256_ctx = NULL;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    // Prepare mock argument
    mock_init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (mock_init_param == NULL) {
        assert_non_null(mock_init_param);
        goto exit;
    }
    mock_target = (DeployTarget_t *)malloc(sizeof(DeployTarget_t));
    if (mock_target == NULL) {
        assert_non_null(mock_target);
        goto exit;
    }

    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;
    target->parse_state = DeployStateIdle;

    // Copy test parameter to mock argument
    memcpy(mock_init_param, init_param, sizeof(DeployInitParams_t));
    memcpy(mock_target, target, sizeof(DeployTarget_t));

    // Change target for mock operation
    mock_init_param->deploy.deploy_targets = mock_target;

    // mock operation for StartDeploy()
    sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    if (sha256_ctx == NULL) {
        assert_non_null(sha256_ctx);
        goto exit;
    }
    StartDeployCommon(mock_init_param, sha256_ctx, StartDeploy_ExecDeploy);

    // Exec test target
    StartDeploy(init_param);

    // Check output
    assert_int_equal(init_param->deploy.res_info.code, 0); // Ok
    assert_string_equal(init_param->deploy.res_info.detail_msg, "ok");
    assert_string_equal(init_param->deploy.res_info.res_id, init_param->deploy.id);
    assert_int_equal(init_param->deploy.deploy_targets->progress, 100);
    assert_int_equal(init_param->deploy.deploy_targets->process_state, DeployStateDone);
    assert_string_equal(init_param->state_str[init_param->deploy.topic_id],
                        ESF_JSON_SERIALIZE_OUTPUT_STR);
    assert_int_equal(init_param->state_str_len[init_param->deploy.topic_id],
                     strlen(ESF_JSON_SERIALIZE_OUTPUT_STR));
    assert_int_equal(init_param->arch_version, kEsfFwMgrSwArchVersion2);
    assert_true(init_param->is_pre_reboot);

exit:
    if (sha256_ctx != NULL) {
        free(sha256_ctx);
    }

    if (mock_target != NULL) {
        free(mock_target);
    }

    if (mock_init_param != NULL) {
        free(mock_init_param);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param == NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_StartDeploy_ErrorCheckVersion(void **state)
{
    DeployInitParams_t *init_param = NULL;
    DeployInitParams_t *mock_init_param = NULL;
    DeployTarget_t *target = NULL;
    DeployTarget_t *mock_target = NULL;

    // Prepare test target argument
    init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (init_param == NULL) {
        assert_non_null(init_param);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    // Prepare mock argument
    mock_init_param = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (mock_init_param == NULL) {
        assert_non_null(mock_init_param);
        goto exit;
    }
    mock_target = (DeployTarget_t *)malloc(sizeof(DeployTarget_t));
    if (mock_target == NULL) {
        assert_non_null(mock_target);
        goto exit;
    }

    memset(init_param, 0x00, sizeof(DeployInitParams_t));
    snprintf(init_param->deploy.id, sizeof(init_param->deploy.id), "%s", "res_id_test");
    snprintf(init_param->deploy.version, sizeof(init_param->deploy.version), "%s", "12345");
    init_param->deploy.topic_id = DeployTopicFirmware;
    init_param->deploy.parse_state = DeployStateDone;
    init_param->deploy.deploy_target_num = 1;
    init_param->deploy.deploy_targets = target;
    init_param->deploy.res_info.code = 0;

    snprintf(target->name, sizeof(target->name), "%s", "name test");
    target->component = DeployComponentProcessorLoader;
    target->parse_state = DeployStateIdle;

    // Copy test parameter to mock argument
    memcpy(mock_init_param, init_param, sizeof(DeployInitParams_t));
    memcpy(mock_target, target, sizeof(DeployTarget_t));

    // Change target for mock operation
    mock_init_param->deploy.deploy_targets = mock_target;

    // mock operation for StartDeploy()
    StartDeployCommon(mock_init_param, NULL, StartDeploy_ErrorCheckVersion);

    // Exec test target
    StartDeploy(init_param);

    // Check output
    assert_int_equal(init_param->deploy.res_info.code, 13); // Internal
    assert_string_equal(init_param->deploy.res_info.detail_msg, "internal");
    assert_string_equal(init_param->deploy.res_info.res_id, init_param->deploy.id);
    assert_int_equal(init_param->deploy.deploy_targets->progress, 0);
    assert_int_equal(init_param->deploy.deploy_targets->process_state, DeployStateFailed);
    assert_string_equal(init_param->state_str[init_param->deploy.topic_id],
                        ESF_JSON_SERIALIZE_OUTPUT_STR);
    assert_int_equal(init_param->state_str_len[init_param->deploy.topic_id],
                     strlen(ESF_JSON_SERIALIZE_OUTPUT_STR));

exit:
    if (mock_target != NULL) {
        free(mock_target);
    }

    if (mock_init_param != NULL) {
        free(mock_init_param);
    }

    if (target != NULL) {
        free(target);
    }

    if (init_param == NULL) {
        free(init_param);
    }
}

/*----------------------------------------------------------------------------*/
static void test_StartDeploy_ErrorDeleteAiModel(void **state)
{
    DeployInitParams_t init;

    memset(&init, 0, sizeof(DeployInitParams_t));

    init.deploy.topic_id = DeployTopicAiModel;
    init.deploy.parse_state = DeployStateIdle;
    init.deploy.res_info.code = 0;

    // For UtilityLogWriteELog()
    expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
    expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelInfo);
    expect_value(__wrap_UtilityLogWriteELog, event_id, ELOG_EVENT_ID_START_OTA);
    will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);

    // For malloc()
    will_return(mock_malloc, true);  // Exec parameter check
    will_return(mock_malloc, false); // Failed allocate memory
    expect_value(mock_malloc, __size,
                 sizeof(EsfFwMgrGetInfoResponse) * 4 + sizeof(EsfFwMgrOpenRequest));

    // SetEvpStateReportOtaUpdateStatus()
    SetEvpStateReportOtaUpdateStatusCommon(&init, SetEvpStateReportOtaUpdateStatus_None);

    // For SysAppLedSetAppStatus()
    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state,
                 LedAppStatusErrorUpdateMemoryAllocateFailed);

    // For SysAppStaReopenIfClose()
    will_return(__wrap_SysAppStaReopenIfClose, kRetOk);

    // For SysAppStateSendState()
    expect_value(__wrap_SysAppStateSendState, req, ST_TOPIC_UPDATE_DEVICE_INFO);
    will_return(__wrap_SysAppStateSendState, kRetOk);

    // Exec test target
    StartDeploy(&init);

    // Check output
    assert_int_equal(init.deploy.parse_state, DeployStateFailed);
    assert_int_equal(init.deploy.res_info.code, RESULT_CODE_INTERNAL);
}

/*----------------------------------------------------------------------------*/

//
// DeployMain()
//

/*----------------------------------------------------------------------------*/
static void test_DeployMain_ErrorMsgNULL(void **state)
{
    int *ret = NULL;
    DeployInitParams_t *initp = NULL;
    initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    initp->msg_handle_dp = 0x12345678;
    initp->is_pre_reboot = false;

    //set expected value
    int32_t exp_msg_handle_dp = 0x12345678;

    //for UtilityMsgRecv()
    expect_value(__wrap_UtilityMsgRecv, handle, exp_msg_handle_dp);
    expect_value(__wrap_UtilityMsgRecv, size, sizeof(DeployMessage_t *));
    expect_value(__wrap_UtilityMsgRecv, timeout_ms, -1);

    UtilityMsgErrCode ret_msg_ercd = kUtilityMsgOk;

    will_return(__wrap_UtilityMsgRecv, (int32_t)sizeof(DeployMessage_t *));
    will_return(__wrap_UtilityMsgRecv, NULL);
    will_return(__wrap_UtilityMsgRecv, ret_msg_ercd);

    ret = DeployMain(initp);

    assert_null(ret);

    free(initp);
}

/*----------------------------------------------------------------------------*/
static void test_DeployMain_ErrorMsgTimedout(void **state)
{
    int *ret = NULL;
    DeployInitParams_t *initp = NULL;
    initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    initp->msg_handle_dp = 0x12345678;
    initp->is_pre_reboot = false;

    //set expected value
    int32_t exp_msg_handle_dp = 0x12345678;

    //for UtilityMsgRecv() first
    expect_value(__wrap_UtilityMsgRecv, handle, exp_msg_handle_dp);
    expect_value(__wrap_UtilityMsgRecv, size, sizeof(DeployMessage_t *));
    expect_value(__wrap_UtilityMsgRecv, timeout_ms, -1);

    UtilityMsgErrCode ret_msg_ercd = kUtilityMsgErrTimedout;

    will_return(__wrap_UtilityMsgRecv, (int32_t)sizeof(DeployMessage_t *));
    will_return(__wrap_UtilityMsgRecv, NULL);
    will_return(__wrap_UtilityMsgRecv, ret_msg_ercd);

    // Finish loop
    DeployMain_FinishLoop(kUtilityMsgOk, exp_msg_handle_dp);

    ret = DeployMain(initp);

    assert_null(ret);

    free(initp);
}

/*----------------------------------------------------------------------------*/
static void test_DeployMain_ErrorMsgError(void **state)
{
    int *ret = NULL;
    DeployInitParams_t *initp = NULL;
    initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    initp->msg_handle_dp = 0x12345678;
    initp->is_pre_reboot = false;

    //set expected value
    int32_t exp_msg_handle_dp = 0x12345678;

    //for UtilityMsgRecv()
    expect_value(__wrap_UtilityMsgRecv, handle, exp_msg_handle_dp);
    expect_value(__wrap_UtilityMsgRecv, size, sizeof(DeployMessage_t *));
    expect_value(__wrap_UtilityMsgRecv, timeout_ms, -1);

    UtilityMsgErrCode ret_msg_ercd = kUtilityMsgErrInternal;

    will_return(__wrap_UtilityMsgRecv, (int32_t)sizeof(DeployMessage_t *));
    will_return(__wrap_UtilityMsgRecv, NULL);
    will_return(__wrap_UtilityMsgRecv, ret_msg_ercd);

    // Finish loop
    DeployMain_FinishLoop(kUtilityMsgOk, exp_msg_handle_dp);

    ret = DeployMain(initp);

    assert_null(ret);

    free(initp);
}

/*----------------------------------------------------------------------------*/
static void test_DeployMain_ErrorPreReboot(void **state)
{
    int *ret = NULL;
    DeployInitParams_t *initp = NULL;
    initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    initp->msg_handle_dp = 0x12345678;
    initp->is_pre_reboot = true;

    //set expected value
    int32_t exp_msg_handle_dp = 0x12345678;

    //for UtilityMsgRecv()
    expect_value(__wrap_UtilityMsgRecv, handle, exp_msg_handle_dp);
    expect_value(__wrap_UtilityMsgRecv, size, sizeof(DeployMessage_t *));
    expect_value(__wrap_UtilityMsgRecv, timeout_ms, -1);

    UtilityMsgErrCode ret_msg_ercd = kUtilityMsgError;

    will_return(__wrap_UtilityMsgRecv, (int32_t)sizeof(DeployMessage_t *));
    will_return(__wrap_UtilityMsgRecv, NULL);
    will_return(__wrap_UtilityMsgRecv, ret_msg_ercd);

    // Finish loop
    DeployMain_FinishLoop(kUtilityMsgOk, exp_msg_handle_dp);

    ret = DeployMain(initp);

    assert_null(ret);

    free(initp);
}

/*----------------------------------------------------------------------------*/
static void test_DeployMain_ReceiveDeployMsgNotExecDeploy(void **state)
{
    int *ret = NULL;
    DeployInitParams_t *initp = NULL;
    DeployTarget_t *config_value = NULL;
    DeployMessage_t *msg = NULL;
    const char *config_str = "expect_deserialize";

    initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    initp->msg_handle_dp = 0x12345678;
    initp->is_pre_reboot = false;

    //for UtilityMsgRecv()
    expect_value(__wrap_UtilityMsgRecv, handle, initp->msg_handle_dp);
    expect_value(__wrap_UtilityMsgRecv, size, sizeof(DeployMessage_t *));
    expect_value(__wrap_UtilityMsgRecv, timeout_ms, -1);

    will_return(__wrap_UtilityMsgRecv, (int32_t)sizeof(DeployMessage_t *));
    msg = malloc(sizeof(DeployMessage_t) + strlen(config_str));
    msg->topic_id = DeployTopicFirmware;
    msg->len = strlen(config_str);
    snprintf(msg->config, msg->len + 1, "%s", config_str);
    will_return(__wrap_UtilityMsgRecv, &msg);
    will_return(__wrap_UtilityMsgRecv, kUtilityMsgOk);

    // For SysAppLedSetAppStatus()
    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusUnableToAcceptInput);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusAbleToAcceptInput);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDownloadFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state,
                 LedAppStatusErrorUpdateMemoryAllocateFailed);

    // for ParseConfiguration()
    memset(&initp->deploy, 0x00, sizeof(Deploy_t));
    config_value = malloc(sizeof(DeployTarget_t));
    SetGetConfigurationDeployTargetPropertyExpectValue(config_value, DeployComponentSensorLoader,
                                                       dtdl_deploy_target_chip_sensor_chip, "");
    CheckParseConfiguration(&initp->deploy, config_value, 0, msg->topic_id, config_str);

    // for free() of receive message by UtilityMsgRecv()
    will_return(mock_free, true); // Exec parameter check
    expect_value(mock_free, __ptr, msg);

    // for StartDeploy()
    StartDeployCommon(initp, NULL, StartDeploy_Other);

    // for SetEvpStateReportOtaUpdateStatus()
    SetEvpStateReportOtaUpdateStatusCommon(initp, SetEvpStateReportOtaUpdateStatus_None);

    // For SysAppLedSetAppStatus()
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusUnableToAcceptInput);
    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusAbleToAcceptInput);

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, 0);

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);

    // Finish loop
    DeployMain_FinishLoop(kUtilityMsgOk, initp->msg_handle_dp);

    ret = DeployMain(initp);

    assert_null(ret);

    free(config_value);
    free(initp);
}

/*----------------------------------------------------------------------------*/
static void test_DeployMain_ReceiveDeployMsgConfigErr(void **state)
{
    int *ret = NULL;
    DeployInitParams_t *initp = NULL;
    DeployTarget_t *config_value = NULL;
    DeployMessage_t *msg = NULL;
    const char *config_str = "expect_deserialize";

    initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    initp->msg_handle_dp = 0x12345678;
    initp->is_pre_reboot = false;

    //for UtilityMsgRecv()
    expect_value(__wrap_UtilityMsgRecv, handle, initp->msg_handle_dp);
    expect_value(__wrap_UtilityMsgRecv, size, sizeof(DeployMessage_t *));
    expect_value(__wrap_UtilityMsgRecv, timeout_ms, -1);

    will_return(__wrap_UtilityMsgRecv, (int32_t)sizeof(DeployMessage_t *));
    msg = malloc(sizeof(DeployMessage_t) + strlen(config_str));
    msg->topic_id = DeployTopicFirmware;
    msg->len = strlen(config_str);
    snprintf(msg->config, msg->len + 1, "%s", config_str);
    will_return(__wrap_UtilityMsgRecv, &msg);
    will_return(__wrap_UtilityMsgRecv, kUtilityMsgOk);

    // For SysAppLedSetAppStatus()
    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusUnableToAcceptInput);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusAbleToAcceptInput);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDownloadFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state,
                 LedAppStatusErrorUpdateMemoryAllocateFailed);

    // for ParseConfiguration()
    memset(&initp->deploy, 0x00, sizeof(Deploy_t));
    config_value = malloc(sizeof(DeployTarget_t));
    SetGetConfigurationDeployTargetPropertyExpectValue(config_value, DeployComponentSensorLoader,
                                                       dtdl_deploy_target_chip_sensor_chip, "");
    CheckParseConfiguration(&initp->deploy, config_value, -1, msg->topic_id, config_str);

    // for free() of receive message by UtilityMsgRecv()
    will_return(mock_free, true); // Exec parameter check
    expect_value(mock_free, __ptr, msg);

    // for SetEvpStateReportOtaUpdateStatus()
    SetEvpStateReportOtaUpdateStatusCommon(initp, SetEvpStateReportOtaUpdateStatus_None);

    // For SysAppLedSetAppStatus()
    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusErrorDownloadFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusUnableToAcceptInput);
    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusAbleToAcceptInput);

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, 0);

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);

    // Finish loop
    DeployMain_FinishLoop(kUtilityMsgOk, initp->msg_handle_dp);

    ret = DeployMain(initp);

    assert_null(ret);

    free(config_value);
    free(initp);
}

/*----------------------------------------------------------------------------*/
static void test_DeployMain_ReceiveDeployMsgFreeMemory(void **state)
{
    int *ret = NULL;
    DeployInitParams_t *initp = NULL;
    DeployTarget_t *config_value = NULL;
    DeployMessage_t *msg = NULL;
    const char *config_str = "expect_deserialize";

    initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    initp->msg_handle_dp = 0x12345678;
    initp->is_pre_reboot = false;

    //for UtilityMsgRecv()
    expect_value(__wrap_UtilityMsgRecv, handle, initp->msg_handle_dp);
    expect_value(__wrap_UtilityMsgRecv, size, sizeof(DeployMessage_t *));
    expect_value(__wrap_UtilityMsgRecv, timeout_ms, -1);

    will_return(__wrap_UtilityMsgRecv, (int32_t)sizeof(DeployMessage_t *));
    msg = malloc(sizeof(DeployMessage_t) + strlen(config_str));
    msg->topic_id = DeployTopicFirmware;
    msg->len = strlen(config_str);
    snprintf(msg->config, msg->len + 1, "%s", config_str);
    will_return(__wrap_UtilityMsgRecv, &msg);
    will_return(__wrap_UtilityMsgRecv, kUtilityMsgOk);

    // For SysAppLedSetAppStatus()
    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusUnableToAcceptInput);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusAbleToAcceptInput);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDownloadFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state,
                 LedAppStatusErrorUpdateMemoryAllocateFailed);

    // for ParseConfiguration()
    memset(&initp->deploy, 0x00, sizeof(Deploy_t));
    initp->deploy.deploy_target_num = 1;
    config_value = malloc(sizeof(DeployTarget_t) * initp->deploy.deploy_target_num);
    SetGetConfigurationDeployTargetPropertyExpectValue(config_value, DeployComponentSensorLoader,
                                                       dtdl_deploy_target_chip_sensor_chip, "");
    CheckParseConfiguration(&initp->deploy, config_value, initp->deploy.deploy_target_num,
                            msg->topic_id, config_str);

    // for free() of receive message by UtilityMsgRecv()
    will_return(mock_free, true); // Exec parameter check
    expect_value(mock_free, __ptr, msg);

    // for StartDeploy()
    initp->deploy.deploy_targets = config_value;
    StartDeployCommon(initp, NULL, StartDeploy_AlreadyDeploy);

    // for SetEvpStateReportOtaUpdateStatus()
    SetEvpStateReportOtaUpdateStatusCommon(initp, SetEvpStateReportOtaUpdateStatus_None);

    // for free() of p_deploy->deploy_targets
    initp->deploy.deploy_targets = malloc(sizeof(DeployTarget_t));
    will_return(mock_free, false); // Not exec parameter check

    // For SysAppLedSetAppStatus()
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusUnableToAcceptInput);
    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusAbleToAcceptInput);

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, 0);

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);

    // Finish loop
    DeployMain_FinishLoop(kUtilityMsgOk, initp->msg_handle_dp);

    ret = DeployMain(initp);

    assert_null(ret);

    free(config_value);
    free(initp);
}

/*----------------------------------------------------------------------------*/

//
// DeleteAiModel()
//

/*----------------------------------------------------------------------------*/
static void test_DeleteAiModel_FullySuccess(void **state)
{
    DeployInitParams_t *initp = NULL;
    Deploy_t *deployp = NULL;
    DeployTarget_t *target = NULL;
    EsfFwMgrGetInfoResponse *InfoResponse = NULL;

    // Prepare test target argument
    initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (initp == NULL) {
        assert_non_null(initp);
        goto exit;
    }

    memset(initp, 0, sizeof(DeployInitParams_t));

    deployp = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deployp == NULL) {
        assert_non_null(deployp);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    memset(deployp, 0, sizeof(Deploy_t));
    deployp->topic_id = DeployTopicAiModel;
    deployp->parse_state = DeployStateIdle;
    deployp->res_info.code = 1;
    deployp->deploy_target_num = 1;

    target->component = DeployComponentAiModel;
    deployp->deploy_targets = target;

    // Prepare mock
    // ESF_FIRMWARE_MANAGER_AI_MODEL_SLOT_NUM = 4
    uint32_t slot_num = 4;

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size,
                 sizeof(EsfFwMgrGetInfoResponse) * slot_num + sizeof(EsfFwMgrOpenRequest));

    // For EsfFwMgrGetInfo()
    InfoResponse =
        malloc((slot_num * sizeof(EsfFwMgrGetInfoResponse)) + sizeof(EsfFwMgrOpenRequest));
    if (InfoResponse == NULL) {
        goto exit;
    }
    else {
        strcpy(InfoResponse[0].version, "ai_model_version_1");
        strcpy(InfoResponse[0].last_update, "ai_model_last_update_1");
        strcpy((char *)InfoResponse[0].hash, "ai_model_hash_1");

        strcpy(InfoResponse[1].version, "ai_model_version_2");
        strcpy(InfoResponse[1].last_update, "ai_model_last_update_2");
        strcpy((char *)InfoResponse[1].hash, "ai_model_hash_2");

        strcpy(InfoResponse[2].version, "ai_model_version_3");
        strcpy(InfoResponse[2].last_update, "ai_model_last_update_3");
        strcpy((char *)InfoResponse[2].hash, "ai_model_hash_3");

        strcpy(InfoResponse[3].version, "sensor_fw_version_4");
        strcpy(InfoResponse[3].last_update, "sensor_fw_last_update_4");
        strcpy((char *)InfoResponse[3].hash, "sensor_fw_hash_4");
    }

    EsfFwMgrResult EsfFwMgrGetInfo_ret = kEsfFwMgrResultOk;
    will_return(__wrap_EsfFwMgrGetInfo, InfoResponse);
    will_return(__wrap_EsfFwMgrGetInfo, EsfFwMgrGetInfo_ret);

    // For EsfCodecBase64Encode()
    char b64output[DEPLOY_STR_HASH_LEN + 1];

    memset(b64output, 'f', sizeof(b64output));
    b64output[DEPLOY_STR_HASH_LEN] = '\0';
    EsfCodecBase64ResultEnum Base64Enc_ret = kEsfCodecBase64ResultSuccess;

    for (int slot = 0; slot < slot_num; slot++) {
        expect_not_value(__wrap_EsfCodecBase64Encode, in, NULL);
        expect_value(__wrap_EsfCodecBase64Encode, in_size, sizeof(InfoResponse[slot].hash));
        will_return(__wrap_EsfCodecBase64Encode, b64output);
        will_return(__wrap_EsfCodecBase64Encode, sizeof(b64output));
        will_return(__wrap_EsfCodecBase64Encode, Base64Enc_ret);

        // For SysAppUdIsThisRequestToStopForDownload()
        bool StopForDownload = false;
        will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, StopForDownload);

        // For EsfFwMgrOpen()
        EsfFwMgrHandle Handle_ret = (EsfFwMgrHandle)1234;
        int32_t MemorySize = 2345;
        int32_t WritableSize = 3456;
        EsfFwMgrResult FwMgr_ret = kEsfFwMgrResultOk;
        will_return(__wrap_EsfFwMgrOpen, Handle_ret);
        will_return(__wrap_EsfFwMgrOpen, MemorySize);
        will_return(__wrap_EsfFwMgrOpen, WritableSize);
        will_return(__wrap_EsfFwMgrOpen, FwMgr_ret);

        // For EsfFwMgrErase()
        will_return(__wrap_EsfFwMgrErase, kEsfFwMgrResultOk);

        // For EsfFwMgrClose()
        will_return(__wrap_EsfFwMgrClose, kEsfFwMgrResultOk);
    }

    // For free()
    will_return(mock_free, false); // Not check parameter

    // Exec test target
    DeleteAiModel(initp, deployp);

    // Check output
    assert_int_equal(deployp->parse_state, DeployStateIdle);
    assert_int_equal(deployp->res_info.code, 1); // not changed

exit:
    // cleanup
    free(initp);
    free(target);
    free(deployp);
    free(InfoResponse);
}

/*----------------------------------------------------------------------------*/
static void test_DeleteAiModel_SucessSameVersion(void **state)
{
    DeployInitParams_t *initp = NULL;
    Deploy_t *deployp = NULL;
    DeployTarget_t *target = NULL;
    EsfFwMgrGetInfoResponse *InfoResponse = NULL;

    // Prepare test target argument
    initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (initp == NULL) {
        assert_non_null(initp);
        goto exit;
    }

    memset(initp, 0, sizeof(DeployInitParams_t));

    deployp = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deployp == NULL) {
        assert_non_null(deployp);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    memset(deployp, 0, sizeof(Deploy_t));
    deployp->topic_id = DeployTopicAiModel;
    deployp->parse_state = DeployStateIdle;
    deployp->res_info.code = 1;
    deployp->deploy_target_num = 1;

    target->component = DeployComponentAiModel;
    deployp->deploy_targets = target;

    // Prepare mock
    // ESF_FIRMWARE_MANAGER_AI_MODEL_SLOT_NUM = 4
    uint32_t slot_num = 4;

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size,
                 sizeof(EsfFwMgrGetInfoResponse) * slot_num + sizeof(EsfFwMgrOpenRequest));

    // For EsfFwMgrGetInfo()
    InfoResponse = malloc(slot_num * sizeof(EsfFwMgrGetInfoResponse) + sizeof(EsfFwMgrOpenRequest));
    if (InfoResponse == NULL) {
        goto exit;
    }
    else {
        strcpy(InfoResponse[0].version, "version test");
        strcpy(InfoResponse[0].last_update, "ai_model_last_update_1");
        strcpy((char *)InfoResponse[0].hash, "ai_model_hash_1");

        strcpy(InfoResponse[1].version, "version test");
        strcpy(InfoResponse[1].last_update, "ai_model_last_update_2");
        strcpy((char *)InfoResponse[1].hash, "ai_model_hash_2");

        strcpy(InfoResponse[2].version, "version test");
        strcpy(InfoResponse[2].last_update, "ai_model_last_update_3");
        strcpy((char *)InfoResponse[2].hash, "ai_model_hash_3");

        strcpy(InfoResponse[3].version, "version test");
        strcpy(InfoResponse[3].last_update, "sensor_fw_last_update_4");
        strcpy((char *)InfoResponse[3].hash, "sensor_fw_hash_4");
    }

    EsfFwMgrResult EsfFwMgrGetInfo_ret = kEsfFwMgrResultOk;
    will_return(__wrap_EsfFwMgrGetInfo, InfoResponse);
    will_return(__wrap_EsfFwMgrGetInfo, EsfFwMgrGetInfo_ret);

    // For EsfCodecBase64Encode()
    char b64output[DEPLOY_STR_HASH_LEN + 1];

    memset(b64output, 'f', sizeof(b64output));
    b64output[DEPLOY_STR_HASH_LEN] = '\0';
    EsfCodecBase64ResultEnum Base64Enc_ret = kEsfCodecBase64ResultSuccess;

    for (int slot = 0; slot < slot_num; slot++) {
        expect_not_value(__wrap_EsfCodecBase64Encode, in, NULL);
        expect_value(__wrap_EsfCodecBase64Encode, in_size, sizeof(InfoResponse[slot].hash));
        will_return(__wrap_EsfCodecBase64Encode, b64output);
        will_return(__wrap_EsfCodecBase64Encode, sizeof(b64output));
        will_return(__wrap_EsfCodecBase64Encode, Base64Enc_ret);
    }

    // For free()
    will_return(mock_free, false); // Not check parameter

    // Exec test target
    DeleteAiModel(initp, deployp);

    // Check output
    assert_int_equal(deployp->parse_state, DeployStateIdle);
    assert_int_equal(deployp->res_info.code, 1); // not changed

exit:
    // cleanup
    free(initp);
    free(target);
    free(deployp);
    free(InfoResponse);
}

/*----------------------------------------------------------------------------*/
static void test_DeleteAiModel_SuccessNonAimodel(void **state)
{
    DeployInitParams_t *initp = NULL;
    Deploy_t *deployp = NULL;
    DeployTarget_t *target = NULL;
    EsfFwMgrGetInfoResponse *InfoResponse = NULL;

    // Prepare test target argument
    initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (initp == NULL) {
        assert_non_null(initp);
        goto exit;
    }

    memset(initp, 0, sizeof(DeployInitParams_t));

    deployp = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deployp == NULL) {
        assert_non_null(deployp);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    memset(deployp, 0, sizeof(Deploy_t));
    deployp->topic_id = DeployTopicAiModel;
    deployp->parse_state = DeployStateIdle;
    deployp->res_info.code = 1;
    deployp->deploy_target_num = 1;

    target->component = DeployComponentAiModel;
    deployp->deploy_targets = target;

    // Prepare mock
    // ESF_FIRMWARE_MANAGER_AI_MODEL_SLOT_NUM = 4
    uint32_t slot_num = 4;

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size,
                 sizeof(EsfFwMgrGetInfoResponse) * slot_num + sizeof(EsfFwMgrOpenRequest));

    // For EsfFwMgrGetInfo()
    InfoResponse = malloc(slot_num * sizeof(EsfFwMgrGetInfoResponse) + sizeof(EsfFwMgrOpenRequest));
    if (InfoResponse == NULL) {
        goto exit;
    }
    else {
        // Set Version is \0 for test
        strcpy(InfoResponse[0].version, "\0");
        strcpy(InfoResponse[0].last_update, "ai_model_last_update_1");
        strcpy((char *)InfoResponse[0].hash, "ai_model_hash_1");

        strcpy(InfoResponse[1].version, "\0");
        strcpy(InfoResponse[1].last_update, "ai_model_last_update_2");
        strcpy((char *)InfoResponse[1].hash, "ai_model_hash_2");

        strcpy(InfoResponse[2].version, "\0");
        strcpy(InfoResponse[2].last_update, "ai_model_last_update_3");
        strcpy((char *)InfoResponse[2].hash, "ai_model_hash_3");

        strcpy(InfoResponse[3].version, "\0");
        strcpy(InfoResponse[3].last_update, "sensor_fw_last_update_4");
        strcpy((char *)InfoResponse[3].hash, "sensor_fw_hash_4");
    }

    EsfFwMgrResult EsfFwMgrGetInfo_ret = kEsfFwMgrResultOk;
    will_return(__wrap_EsfFwMgrGetInfo, InfoResponse);
    will_return(__wrap_EsfFwMgrGetInfo, EsfFwMgrGetInfo_ret);

    // For free()
    will_return(mock_free, false); // Not check parameter

    // Exec test target
    DeleteAiModel(initp, deployp);

    // Check output
    assert_int_equal(deployp->parse_state, DeployStateIdle);
    assert_int_equal(deployp->res_info.code, 1); // not changed

exit:
    // cleanup
    free(initp);
    free(target);
    free(deployp);
    free(InfoResponse);
}

/*----------------------------------------------------------------------------*/
static void test_DeleteAiModel_SucessRequestToStopForDownloadIsTrue(void **state)
{
    DeployInitParams_t *initp = NULL;
    Deploy_t *deployp = NULL;
    DeployTarget_t *target = NULL;
    EsfFwMgrGetInfoResponse *InfoResponse = NULL;

    // Prepare test target argument
    initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (initp == NULL) {
        assert_non_null(initp);
        goto exit;
    }

    memset(initp, 0, sizeof(DeployInitParams_t));

    deployp = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deployp == NULL) {
        assert_non_null(deployp);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    memset(deployp, 0, sizeof(Deploy_t));
    deployp->topic_id = DeployTopicAiModel;
    deployp->parse_state = DeployStateIdle;
    deployp->res_info.code = 1;
    deployp->deploy_target_num = 1;

    target->component = DeployComponentAiModel;
    deployp->deploy_targets = target;

    // Prepare mock
    // ESF_FIRMWARE_MANAGER_AI_MODEL_SLOT_NUM = 4
    uint32_t slot_num = 4;

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size,
                 sizeof(EsfFwMgrGetInfoResponse) * slot_num + sizeof(EsfFwMgrOpenRequest));

    // For EsfFwMgrGetInfo()
    InfoResponse = malloc(slot_num * sizeof(EsfFwMgrGetInfoResponse) + sizeof(EsfFwMgrOpenRequest));
    if (InfoResponse == NULL) {
        goto exit;
    }
    else {
        strcpy(InfoResponse[0].version, "ai_model_version_1");
        strcpy(InfoResponse[0].last_update, "ai_model_last_update_1");
        strcpy((char *)InfoResponse[0].hash, "ai_model_hash_1");

        strcpy(InfoResponse[1].version, "ai_model_version_2");
        strcpy(InfoResponse[1].last_update, "ai_model_last_update_2");
        strcpy((char *)InfoResponse[1].hash, "ai_model_hash_2");

        strcpy(InfoResponse[2].version, "ai_model_version_3");
        strcpy(InfoResponse[2].last_update, "ai_model_last_update_3");
        strcpy((char *)InfoResponse[2].hash, "ai_model_hash_3");

        strcpy(InfoResponse[3].version, "sensor_fw_version_4");
        strcpy(InfoResponse[3].last_update, "sensor_fw_last_update_4");
        strcpy((char *)InfoResponse[3].hash, "sensor_fw_hash_4");
    }

    EsfFwMgrResult EsfFwMgrGetInfo_ret = kEsfFwMgrResultOk;
    will_return(__wrap_EsfFwMgrGetInfo, InfoResponse);
    will_return(__wrap_EsfFwMgrGetInfo, EsfFwMgrGetInfo_ret);

    // For EsfCodecBase64Encode()
    char b64output[DEPLOY_STR_HASH_LEN + 1];

    memset(b64output, 'f', sizeof(b64output));
    b64output[DEPLOY_STR_HASH_LEN] = '\0';
    EsfCodecBase64ResultEnum Base64Enc_ret = kEsfCodecBase64ResultSuccess;

    expect_not_value(__wrap_EsfCodecBase64Encode, in, NULL);
    expect_value(__wrap_EsfCodecBase64Encode, in_size, sizeof(InfoResponse[0].hash));
    will_return(__wrap_EsfCodecBase64Encode, b64output);
    will_return(__wrap_EsfCodecBase64Encode, sizeof(b64output));
    will_return(__wrap_EsfCodecBase64Encode, Base64Enc_ret);

    // For SysAppUdIsThisRequestToStopForDownload()
    // Set true for test
    bool StopForDownload = true;
    will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, StopForDownload);

    // For free()
    will_return(mock_free, false); // Not check parameter

    // Exec test target
    DeleteAiModel(initp, deployp);

    // Check output
    assert_int_equal(deployp->parse_state, DeployStateIdle);
    assert_int_equal(deployp->res_info.code, 1); // not changed

exit:
    // cleanup
    free(initp);
    free(target);
    free(deployp);
    free(InfoResponse);
}

/*----------------------------------------------------------------------------*/
static void test_DeleteAiModel_Cancel(void **state)
{
    DeployInitParams_t *initp = NULL;
    Deploy_t *deployp = NULL;
    DeployTarget_t *target = NULL;
    EsfFwMgrGetInfoResponse *InfoResponse = NULL;

    // Prepare test target argument
    initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (initp == NULL) {
        assert_non_null(initp);
        goto exit;
    }

    memset(initp, 0, sizeof(DeployInitParams_t));

    deployp = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deployp == NULL) {
        assert_non_null(deployp);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    memset(deployp, 0, sizeof(Deploy_t));
    deployp->topic_id = DeployTopicAiModel;
    deployp->parse_state = DeployStateIdle;
    deployp->res_info.code = 1;
    deployp->deploy_target_num = 1;

    target->component = DeployComponentAiModel;
    deployp->deploy_targets = target;

    for (int i = 0; i < DeployTopicNum; i++) {
        initp->is_cancels[i] = true;
    }

    // Prepare mock
    // ESF_FIRMWARE_MANAGER_AI_MODEL_SLOT_NUM = 4
    uint32_t slot_num = 4;

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size,
                 sizeof(EsfFwMgrGetInfoResponse) * slot_num + sizeof(EsfFwMgrOpenRequest));

    // For EsfFwMgrGetInfo()
    InfoResponse = malloc(slot_num * sizeof(EsfFwMgrGetInfoResponse) + sizeof(EsfFwMgrOpenRequest));
    if (InfoResponse == NULL) {
        goto exit;
    }
    else {
        strcpy(InfoResponse[0].version, "ai_model_version_1");
        strcpy(InfoResponse[0].last_update, "ai_model_last_update_1");
        strcpy((char *)InfoResponse[0].hash, "ai_model_hash_1");

        strcpy(InfoResponse[1].version, "ai_model_version_2");
        strcpy(InfoResponse[1].last_update, "ai_model_last_update_2");
        strcpy((char *)InfoResponse[1].hash, "ai_model_hash_2");

        strcpy(InfoResponse[2].version, "ai_model_version_3");
        strcpy(InfoResponse[2].last_update, "ai_model_last_update_3");
        strcpy((char *)InfoResponse[2].hash, "ai_model_hash_3");

        strcpy(InfoResponse[3].version, "sensor_fw_version_4");
        strcpy(InfoResponse[3].last_update, "sensor_fw_last_update_4");
        strcpy((char *)InfoResponse[3].hash, "sensor_fw_hash_4");
    }

    EsfFwMgrResult EsfFwMgrGetInfo_ret = kEsfFwMgrResultOk;
    will_return(__wrap_EsfFwMgrGetInfo, InfoResponse);
    will_return(__wrap_EsfFwMgrGetInfo, EsfFwMgrGetInfo_ret);

    // For EsfCodecBase64Encode()
    char b64output[DEPLOY_STR_HASH_LEN + 1];

    memset(b64output, 'f', sizeof(b64output));
    b64output[DEPLOY_STR_HASH_LEN] = '\0';
    EsfCodecBase64ResultEnum Base64Enc_ret = kEsfCodecBase64ResultSuccess;

    expect_not_value(__wrap_EsfCodecBase64Encode, in, NULL);
    expect_value(__wrap_EsfCodecBase64Encode, in_size, sizeof(InfoResponse[0].hash));
    will_return(__wrap_EsfCodecBase64Encode, b64output);
    will_return(__wrap_EsfCodecBase64Encode, sizeof(b64output));
    will_return(__wrap_EsfCodecBase64Encode, Base64Enc_ret);

    // For SysAppUdIsThisRequestToStopForDownload()
    will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, true);

    // For free()
    will_return(mock_free, false); // Not check parameter

    // Exec test target
    DeleteAiModel(initp, deployp);

    // Check output
    assert_int_equal(deployp->parse_state, DeployStateIdle);
    assert_int_equal(deployp->res_info.code, 1); // not changed

exit:
    // cleanup
    free(initp);
    free(target);
    free(deployp);
    free(InfoResponse);
}

/*----------------------------------------------------------------------------*/
static void test_DeleteAiModel_Timedout(void **state)
{
    DeployInitParams_t *initp = NULL;
    Deploy_t *deployp = NULL;
    DeployTarget_t *target = NULL;
    EsfFwMgrGetInfoResponse *InfoResponse = NULL;

    // Prepare test target argument
    initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (initp == NULL) {
        assert_non_null(initp);
        goto exit;
    }

    memset(initp, 0, sizeof(DeployInitParams_t));

    deployp = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deployp == NULL) {
        assert_non_null(deployp);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    memset(deployp, 0, sizeof(Deploy_t));
    deployp->topic_id = DeployTopicAiModel;
    deployp->parse_state = DeployStateIdle;
    deployp->res_info.code = 1;
    deployp->deploy_target_num = 1;

    target->component = DeployComponentAiModel;
    deployp->deploy_targets = target;

    // Prepare mock
    // ESF_FIRMWARE_MANAGER_AI_MODEL_SLOT_NUM = 4
    uint32_t slot_num = 4;

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size,
                 sizeof(EsfFwMgrGetInfoResponse) * slot_num + sizeof(EsfFwMgrOpenRequest));

    // For EsfFwMgrGetInfo()
    InfoResponse = malloc(slot_num * sizeof(EsfFwMgrGetInfoResponse) + sizeof(EsfFwMgrOpenRequest));
    if (InfoResponse == NULL) {
        goto exit;
    }
    else {
        strcpy(InfoResponse[0].version, "ai_model_version_1");
        strcpy(InfoResponse[0].last_update, "ai_model_last_update_1");
        strcpy((char *)InfoResponse[0].hash, "ai_model_hash_1");

        strcpy(InfoResponse[1].version, "ai_model_version_2");
        strcpy(InfoResponse[1].last_update, "ai_model_last_update_2");
        strcpy((char *)InfoResponse[1].hash, "ai_model_hash_2");

        strcpy(InfoResponse[2].version, "ai_model_version_3");
        strcpy(InfoResponse[2].last_update, "ai_model_last_update_3");
        strcpy((char *)InfoResponse[2].hash, "ai_model_hash_3");

        strcpy(InfoResponse[3].version, "sensor_fw_version_4");
        strcpy(InfoResponse[3].last_update, "sensor_fw_last_update_4");
        strcpy((char *)InfoResponse[3].hash, "sensor_fw_hash_4");
    }

    EsfFwMgrResult EsfFwMgrGetInfo_ret = kEsfFwMgrResultOk;
    will_return(__wrap_EsfFwMgrGetInfo, InfoResponse);
    will_return(__wrap_EsfFwMgrGetInfo, EsfFwMgrGetInfo_ret);

    // For EsfCodecBase64Encode()
    char b64output[DEPLOY_STR_HASH_LEN + 1];

    memset(b64output, 'f', sizeof(b64output));
    b64output[DEPLOY_STR_HASH_LEN] = '\0';
    EsfCodecBase64ResultEnum Base64Enc_ret = kEsfCodecBase64ResultSuccess;

    expect_not_value(__wrap_EsfCodecBase64Encode, in, NULL);
    expect_value(__wrap_EsfCodecBase64Encode, in_size, sizeof(InfoResponse[0].hash));
    will_return(__wrap_EsfCodecBase64Encode, b64output);
    will_return(__wrap_EsfCodecBase64Encode, sizeof(b64output));
    will_return(__wrap_EsfCodecBase64Encode, Base64Enc_ret);

    for (int retry_cnt = 0; retry_cnt < MAX_NUMBER_OF_UPDATE_OPEN_RETRY; retry_cnt++) {
        // For SysAppUdIsThisRequestToStopForDownload()
        will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, false);

        // For EsfFwMgrOpen()
        will_return(__wrap_EsfFwMgrOpen, 0);
        will_return(__wrap_EsfFwMgrOpen, 0);
        will_return(__wrap_EsfFwMgrOpen, 0);
        will_return(__wrap_EsfFwMgrOpen, kEsfFwMgrResultUnavailable);

        // For SysAppStaClose()
        will_return(__wrap_SysAppStaClose, kRetOk);

        if (retry_cnt == 1) {
            // mock operation for SetEvpStateReportOtaUpdateStatus()
            target->progress = 0;
            target->process_state = DeployStateFailedUnavailable;
            SetEvpStateReportOtaUpdateStatusCommon(initp, SetEvpStateReportOtaUpdateStatus_None);

            // For SysAppLedSetAppStatus()
            expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
            expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusErrorDownloadFailed);
        }
    }

    target->process_state = DeployStateFailedUnavailable;
    SetEvpStateReportOtaUpdateStatusCommon(initp, SetEvpStateReportOtaUpdateStatus_None);

    // For free()
    will_return(mock_free, false); // Not check parameter

    // Exec test target
    DeleteAiModel(initp, deployp);

    // Check output
    assert_int_equal(deployp->parse_state, DeployStateFailedUnavailable);
    assert_int_equal(deployp->res_info.code, 1); // not changed

exit:
    // cleanup
    free(initp);
    free(target);
    free(deployp);
    free(InfoResponse);
}

/*----------------------------------------------------------------------------*/
static void test_DeleteAiModel_SuccessFwMgrUnavilable(void **state)
{
    DeployInitParams_t *initp = NULL;
    Deploy_t *deployp = NULL;
    DeployTarget_t *target = NULL;
    EsfFwMgrGetInfoResponse *InfoResponse = NULL;

    // Prepare test target argument
    initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (initp == NULL) {
        assert_non_null(initp);
        goto exit;
    }

    memset(initp, 0, sizeof(DeployInitParams_t));

    deployp = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deployp == NULL) {
        assert_non_null(deployp);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    memset(deployp, 0, sizeof(Deploy_t));
    deployp->topic_id = DeployTopicAiModel;
    deployp->parse_state = DeployStateIdle;
    deployp->res_info.code = 1;
    deployp->deploy_target_num = 1;

    target->component = DeployComponentAiModel;
    deployp->deploy_targets = target;

    // Prepare mock
    // ESF_FIRMWARE_MANAGER_AI_MODEL_SLOT_NUM = 4
    uint32_t slot_num = 4;

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size,
                 sizeof(EsfFwMgrGetInfoResponse) * slot_num + sizeof(EsfFwMgrOpenRequest));

    // For EsfFwMgrGetInfo()
    InfoResponse = malloc(slot_num * sizeof(EsfFwMgrGetInfoResponse) + sizeof(EsfFwMgrOpenRequest));
    if (InfoResponse == NULL) {
        goto exit;
    }
    else {
        strcpy(InfoResponse[0].version, "ai_model_version_1");
        strcpy(InfoResponse[0].last_update, "ai_model_last_update_1");
        strcpy((char *)InfoResponse[0].hash, "ai_model_hash_1");

        strcpy(InfoResponse[1].version, "ai_model_version_2");
        strcpy(InfoResponse[1].last_update, "ai_model_last_update_2");
        strcpy((char *)InfoResponse[1].hash, "ai_model_hash_2");

        strcpy(InfoResponse[2].version, "ai_model_version_3");
        strcpy(InfoResponse[2].last_update, "ai_model_last_update_3");
        strcpy((char *)InfoResponse[2].hash, "ai_model_hash_3");

        strcpy(InfoResponse[3].version, "sensor_fw_version_4");
        strcpy(InfoResponse[3].last_update, "sensor_fw_last_update_4");
        strcpy((char *)InfoResponse[3].hash, "sensor_fw_hash_4");
    }

    EsfFwMgrResult EsfFwMgrGetInfo_ret = kEsfFwMgrResultOk;
    will_return(__wrap_EsfFwMgrGetInfo, InfoResponse);
    will_return(__wrap_EsfFwMgrGetInfo, EsfFwMgrGetInfo_ret);

    // For EsfCodecBase64Encode()
    char b64output[DEPLOY_STR_HASH_LEN + 1];

    memset(b64output, 'f', sizeof(b64output));
    b64output[DEPLOY_STR_HASH_LEN] = '\0';
    EsfCodecBase64ResultEnum Base64Enc_ret = kEsfCodecBase64ResultSuccess;

    for (int slot = 0; slot < slot_num; slot++) {
        expect_not_value(__wrap_EsfCodecBase64Encode, in, NULL);
        expect_value(__wrap_EsfCodecBase64Encode, in_size, sizeof(InfoResponse[slot].hash));
        will_return(__wrap_EsfCodecBase64Encode, b64output);
        will_return(__wrap_EsfCodecBase64Encode, sizeof(b64output));
        will_return(__wrap_EsfCodecBase64Encode, Base64Enc_ret);

        // For SysAppUdIsThisRequestToStopForDownload()
        bool StopForDownload = false;
        will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, StopForDownload);

        // For EsfFwMgrOpen()
        EsfFwMgrHandle Handle_ret = (EsfFwMgrHandle)1234;
        int32_t MemorySize = 2345;
        int32_t WritableSize = 3456;
        // Set kEsfFwMgrResultUnavailable for test
        EsfFwMgrResult FwMgr_ret = kEsfFwMgrResultUnavailable;
        will_return(__wrap_EsfFwMgrOpen, Handle_ret);
        will_return(__wrap_EsfFwMgrOpen, MemorySize);
        will_return(__wrap_EsfFwMgrOpen, WritableSize);
        will_return(__wrap_EsfFwMgrOpen, FwMgr_ret);

        // For SysAppStaClose()
        will_return(__wrap_SysAppStaClose, kRetOk);

        // For SysAppUdIsThisRequestToStopForDownload() at second
        will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, StopForDownload);

        // For EsfFwMgrOpen() at second
        will_return(__wrap_EsfFwMgrOpen, Handle_ret);
        will_return(__wrap_EsfFwMgrOpen, MemorySize);
        will_return(__wrap_EsfFwMgrOpen, WritableSize);
        will_return(__wrap_EsfFwMgrOpen, FwMgr_ret);

        // For SysAppStaClose() at second
        will_return(__wrap_SysAppStaClose, kRetOk);

        // SetEvpStateReportOtaUpdateStatus()
        SetEvpStateReportOtaUpdateStatusCommon(initp, SetEvpStateReportOtaUpdateStatus_None);

        // For SysAppLedSetAppStatus()
        expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
        expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusErrorDownloadFailed);

        // For SysAppUdIsThisRequestToStopForDownload() at third
        will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, StopForDownload);

        // For EsfFwMgrOpen() at third
        FwMgr_ret = kEsfFwMgrResultOk;
        will_return(__wrap_EsfFwMgrOpen, Handle_ret);
        will_return(__wrap_EsfFwMgrOpen, MemorySize);
        will_return(__wrap_EsfFwMgrOpen, WritableSize);
        will_return(__wrap_EsfFwMgrOpen, FwMgr_ret);

        // For SysAppLedSetAppStatus()
        expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
        expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDownloadFailed);

        // SetEvpStateReportOtaUpdateStatus() at second
        SetEvpStateReportOtaUpdateStatusCommon(initp, SetEvpStateReportOtaUpdateStatus_None);

        // For EsfFwMgrErase()
        will_return(__wrap_EsfFwMgrErase, kEsfFwMgrResultOk);

        // For EsfFwMgrClose()
        will_return(__wrap_EsfFwMgrClose, kEsfFwMgrResultOk);
    }

    // For free()
    will_return(mock_free, false); // Not check parameter

    // Exec test target
    DeleteAiModel(initp, deployp);

    // Check output
    assert_int_equal(deployp->parse_state, DeployStateIdle);
    assert_int_equal(deployp->res_info.code, 1); // not changed

exit:
    // cleanup
    free(initp);
    free(target);
    free(deployp);
    free(InfoResponse);
}

/*----------------------------------------------------------------------------*/
static void test_DeleteAiModel_ErrorTopicID(void **state)
{
    DeployInitParams_t *initp = NULL;
    Deploy_t *deployp = NULL;
    DeployTarget_t *target = NULL;

    // Prepare test target argument
    initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (initp == NULL) {
        assert_non_null(initp);
        goto exit;
    }

    memset(initp, 0, sizeof(DeployInitParams_t));

    deployp = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deployp == NULL) {
        assert_non_null(deployp);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    memset(deployp, 0, sizeof(Deploy_t));
    deployp->topic_id = DeployTopicAiModel;
    deployp->parse_state = DeployStateIdle;
    deployp->res_info.code = 1;
    deployp->deploy_target_num = 1;

    target->component = DeployComponentAiModel;
    deployp->deploy_targets = target;

    // Prepare mock

    // Set invalid value
    deployp->topic_id = DeployTopicNum;

    // Exec test target
    DeleteAiModel(initp, deployp);

    // Check output
    assert_int_equal(deployp->parse_state, DeployStateIdle);
    assert_int_equal(deployp->res_info.code, 1); // not changed

exit:
    // cleanup
    free(initp);
    free(target);
    free(deployp);
}

/*----------------------------------------------------------------------------*/
static void test_DeleteAiModel_ErrorResponseMalloc(void **state)
{
    DeployInitParams_t *initp = NULL;
    Deploy_t *deployp = NULL;
    DeployTarget_t *target = NULL;

    // Prepare test target argument
    initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (initp == NULL) {
        assert_non_null(initp);
        goto exit;
    }

    memset(initp, 0, sizeof(DeployInitParams_t));

    deployp = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deployp == NULL) {
        assert_non_null(deployp);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    memset(deployp, 0, sizeof(Deploy_t));
    deployp->topic_id = DeployTopicAiModel;
    deployp->parse_state = DeployStateIdle;
    deployp->res_info.code = 1;
    deployp->deploy_target_num = 1;

    target->component = DeployComponentAiModel;
    deployp->deploy_targets = target;

    // Prepare mock
    // ESF_FIRMWARE_MANAGER_AI_MODEL_SLOT_NUM = 4
    uint32_t slot_num = 4;

    // For malloc()
    will_return(mock_malloc, true);  // Exec parameter check
    will_return(mock_malloc, false); // Failed allocate memory
    expect_value(mock_malloc, __size,
                 sizeof(EsfFwMgrGetInfoResponse) * slot_num + sizeof(EsfFwMgrOpenRequest));

    // SetEvpStateReportOtaUpdateStatus()
    SetEvpStateReportOtaUpdateStatusCommon(initp, SetEvpStateReportOtaUpdateStatus_None);

    // For SysAppLedSetAppStatus()
    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state,
                 LedAppStatusErrorUpdateMemoryAllocateFailed);

    // Exec test target
    DeleteAiModel(initp, deployp);

    // Check output
    assert_int_equal(deployp->parse_state, DeployStateFailed);
    assert_int_equal(deployp->res_info.code, 1); // not changed

exit:
    // cleanup
    free(initp);
    free(target);
    free(deployp);
}

/*----------------------------------------------------------------------------*/
static void test_DeleteAiModel_ErrorEsfFwMgrGetInfo(void **state)
{
    DeployInitParams_t *initp = NULL;
    Deploy_t *deployp = NULL;
    DeployTarget_t *target = NULL;
    EsfFwMgrGetInfoResponse *InfoResponse = NULL;

    // Prepare test target argument
    initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (initp == NULL) {
        assert_non_null(initp);
        goto exit;
    }

    memset(initp, 0, sizeof(DeployInitParams_t));

    deployp = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deployp == NULL) {
        assert_non_null(deployp);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    memset(deployp, 0, sizeof(Deploy_t));
    deployp->topic_id = DeployTopicAiModel;
    deployp->parse_state = DeployStateIdle;
    deployp->res_info.code = 1;
    deployp->deploy_target_num = 1;

    target->component = DeployComponentAiModel;
    deployp->deploy_targets = target;

    // Prepare mock
    // ESF_FIRMWARE_MANAGER_AI_MODEL_SLOT_NUM = 4
    uint32_t slot_num = 4;

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size,
                 sizeof(EsfFwMgrGetInfoResponse) * slot_num + sizeof(EsfFwMgrOpenRequest));

    // For EsfFwMgrGetInfo()
    InfoResponse = malloc(slot_num * sizeof(EsfFwMgrGetInfoResponse) + sizeof(EsfFwMgrOpenRequest));
    if (InfoResponse == NULL) {
        goto exit;
    }
    else {
        strcpy(InfoResponse[0].version, "ai_model_version_1");
        strcpy(InfoResponse[0].last_update, "ai_model_last_update_1");
        strcpy((char *)InfoResponse[0].hash, "ai_model_hash_1");

        strcpy(InfoResponse[1].version, "ai_model_version_2");
        strcpy(InfoResponse[1].last_update, "ai_model_last_update_2");
        strcpy((char *)InfoResponse[1].hash, "ai_model_hash_2");

        strcpy(InfoResponse[2].version, "ai_model_version_3");
        strcpy(InfoResponse[2].last_update, "ai_model_last_update_3");
        strcpy((char *)InfoResponse[2].hash, "ai_model_hash_3");

        strcpy(InfoResponse[3].version, "sensor_fw_version_4");
        strcpy(InfoResponse[3].last_update, "sensor_fw_last_update_4");
        strcpy((char *)InfoResponse[3].hash, "sensor_fw_hash_4");
    }

    // Set invalid value
    EsfFwMgrResult EsfFwMgrGetInfo_ret = kEsfFwMgrResultInvalidArgument;
    will_return(__wrap_EsfFwMgrGetInfo, InfoResponse);
    will_return(__wrap_EsfFwMgrGetInfo, EsfFwMgrGetInfo_ret);

    // For UtilityLogWriteELog() SYSAPP_ELOG_ERR(SYSAPP_EVT_OTA_FAILED)
    expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
    expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelError);
    expect_value(__wrap_UtilityLogWriteELog, event_id, ELOG_EVENT_ID_OTA_FAILED);
    will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);

    // SetEvpStateReportOtaUpdateStatus()
    SetEvpStateReportOtaUpdateStatusCommon(initp, SetEvpStateReportOtaUpdateStatus_None);

    // For free()
    will_return(mock_free, false); // Not check parameter

    // Exec test target
    DeleteAiModel(initp, deployp);

    // Check output
    assert_int_equal(deployp->parse_state, DeployStateFailed);
    assert_int_equal(deployp->res_info.code, 1); // not changed

exit:
    // cleanup
    free(initp);
    free(target);
    free(deployp);
    free(InfoResponse);
}

/*----------------------------------------------------------------------------*/
static void test_DeleteAiModel_ErrorEsfBase64Encode(void **state)
{
    DeployInitParams_t *initp = NULL;
    Deploy_t *deployp = NULL;
    DeployTarget_t *target = NULL;
    EsfFwMgrGetInfoResponse *InfoResponse = NULL;

    // Prepare test target argument
    initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (initp == NULL) {
        assert_non_null(initp);
        goto exit;
    }

    memset(initp, 0, sizeof(DeployInitParams_t));

    deployp = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deployp == NULL) {
        assert_non_null(deployp);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    memset(deployp, 0, sizeof(Deploy_t));
    deployp->topic_id = DeployTopicAiModel;
    deployp->parse_state = DeployStateIdle;
    deployp->res_info.code = 1;
    deployp->deploy_target_num = 1;

    target->component = DeployComponentAiModel;
    deployp->deploy_targets = target;

    // Prepare mock
    // ESF_FIRMWARE_MANAGER_AI_MODEL_SLOT_NUM = 4
    uint32_t slot_num = 4;

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size,
                 sizeof(EsfFwMgrGetInfoResponse) * slot_num + sizeof(EsfFwMgrOpenRequest));

    // For EsfFwMgrGetInfo()
    InfoResponse = malloc(slot_num * sizeof(EsfFwMgrGetInfoResponse) + sizeof(EsfFwMgrOpenRequest));
    if (InfoResponse == NULL) {
        goto exit;
    }
    else {
        strcpy(InfoResponse[0].version, "ai_model_version_1");
        strcpy(InfoResponse[0].last_update, "ai_model_last_update_1");
        strcpy((char *)InfoResponse[0].hash, "ai_model_hash_1");

        strcpy(InfoResponse[1].version, "ai_model_version_2");
        strcpy(InfoResponse[1].last_update, "ai_model_last_update_2");
        strcpy((char *)InfoResponse[1].hash, "ai_model_hash_2");

        strcpy(InfoResponse[2].version, "ai_model_version_3");
        strcpy(InfoResponse[2].last_update, "ai_model_last_update_3");
        strcpy((char *)InfoResponse[2].hash, "ai_model_hash_3");

        strcpy(InfoResponse[3].version, "sensor_fw_version_4");
        strcpy(InfoResponse[3].last_update, "sensor_fw_last_update_4");
        strcpy((char *)InfoResponse[3].hash, "sensor_fw_hash_4");
    }

    EsfFwMgrResult EsfFwMgrGetInfo_ret = kEsfFwMgrResultOk;
    will_return(__wrap_EsfFwMgrGetInfo, InfoResponse);
    will_return(__wrap_EsfFwMgrGetInfo, EsfFwMgrGetInfo_ret);

    // For EsfCodecBase64Encode()
    char b64output[DEPLOY_STR_HASH_LEN + 1];

    memset(b64output, 'f', sizeof(b64output));
    b64output[DEPLOY_STR_HASH_LEN] = '\0';
    // Set Invalid Value
    EsfCodecBase64ResultEnum Base64Enc_ret = kEsfCodecBase64ResultInternalError;

    for (int slot = 0; slot < slot_num; slot++) {
        expect_not_value(__wrap_EsfCodecBase64Encode, in, NULL);
        expect_value(__wrap_EsfCodecBase64Encode, in_size, sizeof(InfoResponse[slot].hash));
        will_return(__wrap_EsfCodecBase64Encode, b64output);
        will_return(__wrap_EsfCodecBase64Encode, sizeof(b64output));
        will_return(__wrap_EsfCodecBase64Encode, Base64Enc_ret);
    }

    // For free()
    will_return(mock_free, false); // Not check parameter

    // Exec test target
    DeleteAiModel(initp, deployp);

    // Check output
    assert_int_equal(deployp->parse_state, DeployStateIdle);
    assert_int_equal(deployp->res_info.code, 1); // not changed

exit:
    // cleanup
    free(initp);
    free(target);
    free(deployp);
    free(InfoResponse);
}

/*----------------------------------------------------------------------------*/
static void test_DeleteAiModel_ErrorEsfMgrOpen(void **state)
{
    DeployInitParams_t *initp = NULL;
    Deploy_t *deployp = NULL;
    DeployTarget_t *target = NULL;
    EsfFwMgrGetInfoResponse *InfoResponse = NULL;

    // Prepare test target argument
    initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (initp == NULL) {
        assert_non_null(initp);
        goto exit;
    }

    memset(initp, 0, sizeof(DeployInitParams_t));

    deployp = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deployp == NULL) {
        assert_non_null(deployp);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    memset(deployp, 0, sizeof(Deploy_t));
    deployp->topic_id = DeployTopicAiModel;
    deployp->parse_state = DeployStateIdle;
    deployp->res_info.code = 1;
    deployp->deploy_target_num = 1;

    target->component = DeployComponentAiModel;
    deployp->deploy_targets = target;

    // Prepare mock
    // ESF_FIRMWARE_MANAGER_AI_MODEL_SLOT_NUM = 4
    uint32_t slot_num = 4;

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size,
                 sizeof(EsfFwMgrGetInfoResponse) * slot_num + sizeof(EsfFwMgrOpenRequest));

    // For EsfFwMgrGetInfo()
    InfoResponse = malloc(slot_num * sizeof(EsfFwMgrGetInfoResponse) + sizeof(EsfFwMgrOpenRequest));
    if (InfoResponse == NULL) {
        goto exit;
    }
    else {
        strcpy(InfoResponse[0].version, "ai_model_version_1");
        strcpy(InfoResponse[0].last_update, "ai_model_last_update_1");
        strcpy((char *)InfoResponse[0].hash, "ai_model_hash_1");

        strcpy(InfoResponse[1].version, "ai_model_version_2");
        strcpy(InfoResponse[1].last_update, "ai_model_last_update_2");
        strcpy((char *)InfoResponse[1].hash, "ai_model_hash_2");

        strcpy(InfoResponse[2].version, "ai_model_version_3");
        strcpy(InfoResponse[2].last_update, "ai_model_last_update_3");
        strcpy((char *)InfoResponse[2].hash, "ai_model_hash_3");

        strcpy(InfoResponse[3].version, "sensor_fw_version_4");
        strcpy(InfoResponse[3].last_update, "sensor_fw_last_update_4");
        strcpy((char *)InfoResponse[3].hash, "sensor_fw_hash_4");
    }

    EsfFwMgrResult EsfFwMgrGetInfo_ret = kEsfFwMgrResultOk;
    will_return(__wrap_EsfFwMgrGetInfo, InfoResponse);
    will_return(__wrap_EsfFwMgrGetInfo, EsfFwMgrGetInfo_ret);

    // For EsfCodecBase64Encode()
    char b64output[DEPLOY_STR_HASH_LEN + 1];

    memset(b64output, 'f', sizeof(b64output));
    b64output[DEPLOY_STR_HASH_LEN] = '\0';
    EsfCodecBase64ResultEnum Base64Enc_ret = kEsfCodecBase64ResultSuccess;

    for (int slot = 0; slot < slot_num; slot++) {
        expect_not_value(__wrap_EsfCodecBase64Encode, in, NULL);
        expect_value(__wrap_EsfCodecBase64Encode, in_size, sizeof(InfoResponse[slot].hash));
        will_return(__wrap_EsfCodecBase64Encode, b64output);
        will_return(__wrap_EsfCodecBase64Encode, sizeof(b64output));
        will_return(__wrap_EsfCodecBase64Encode, Base64Enc_ret);

        // For SysAppUdIsThisRequestToStopForDownload()
        bool StopForDownload = false;
        will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, StopForDownload);

        // For EsfFwMgrOpen()
        EsfFwMgrHandle Handle_ret = (EsfFwMgrHandle)1234;
        int32_t MemorySize = 2345;
        int32_t WritableSize = 3456;
        EsfFwMgrResult FwMgr_ret = kEsfFwMgrResultAborted;
        will_return(__wrap_EsfFwMgrOpen, Handle_ret);
        will_return(__wrap_EsfFwMgrOpen, MemorySize);
        will_return(__wrap_EsfFwMgrOpen, WritableSize);
        will_return(__wrap_EsfFwMgrOpen, FwMgr_ret);

        // For UtilityLogWriteELog() SYSAPP_ELOG_ERR(SYSAPP_EVT_OTA_FAILED)
        expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
        expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelError);
        expect_value(__wrap_UtilityLogWriteELog, event_id, ELOG_EVENT_ID_OTA_FAILED);
        will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);
    }

    // For free()
    will_return(mock_free, false); // Not check parameter

    // Exec test target
    DeleteAiModel(initp, deployp);

    // Check output
    assert_int_equal(deployp->parse_state, DeployStateIdle);
    assert_int_equal(deployp->res_info.code, 1); // not changed

exit:
    // cleanup
    free(initp);
    free(target);
    free(deployp);
    free(InfoResponse);
}

/*----------------------------------------------------------------------------*/
static void test_DeleteAiModel_ErrorEsfMgrErase(void **state)
{
    DeployInitParams_t *initp = NULL;
    Deploy_t *deployp = NULL;
    DeployTarget_t *target = NULL;
    EsfFwMgrGetInfoResponse *InfoResponse = NULL;

    // Prepare test target argument
    initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (initp == NULL) {
        assert_non_null(initp);
        goto exit;
    }

    memset(initp, 0, sizeof(DeployInitParams_t));

    deployp = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deployp == NULL) {
        assert_non_null(deployp);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    memset(deployp, 0, sizeof(Deploy_t));
    deployp->topic_id = DeployTopicAiModel;
    deployp->parse_state = DeployStateIdle;
    deployp->res_info.code = 1;
    deployp->deploy_target_num = 1;

    target->component = DeployComponentAiModel;
    deployp->deploy_targets = target;

    // Prepare mock
    // ESF_FIRMWARE_MANAGER_AI_MODEL_SLOT_NUM = 4
    uint32_t slot_num = 4;

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size,
                 sizeof(EsfFwMgrGetInfoResponse) * slot_num + sizeof(EsfFwMgrOpenRequest));

    // For EsfFwMgrGetInfo()
    InfoResponse = malloc(slot_num * sizeof(EsfFwMgrGetInfoResponse) + sizeof(EsfFwMgrOpenRequest));
    if (InfoResponse == NULL) {
        goto exit;
    }
    else {
        strcpy(InfoResponse[0].version, "ai_model_version_1");
        strcpy(InfoResponse[0].last_update, "ai_model_last_update_1");
        strcpy((char *)InfoResponse[0].hash, "ai_model_hash_1");

        strcpy(InfoResponse[1].version, "ai_model_version_2");
        strcpy(InfoResponse[1].last_update, "ai_model_last_update_2");
        strcpy((char *)InfoResponse[1].hash, "ai_model_hash_2");

        strcpy(InfoResponse[2].version, "ai_model_version_3");
        strcpy(InfoResponse[2].last_update, "ai_model_last_update_3");
        strcpy((char *)InfoResponse[2].hash, "ai_model_hash_3");

        strcpy(InfoResponse[3].version, "sensor_fw_version_4");
        strcpy(InfoResponse[3].last_update, "sensor_fw_last_update_4");
        strcpy((char *)InfoResponse[3].hash, "sensor_fw_hash_4");
    }

    EsfFwMgrResult EsfFwMgrGetInfo_ret = kEsfFwMgrResultOk;
    will_return(__wrap_EsfFwMgrGetInfo, InfoResponse);
    will_return(__wrap_EsfFwMgrGetInfo, EsfFwMgrGetInfo_ret);

    // For EsfCodecBase64Encode()
    char b64output[DEPLOY_STR_HASH_LEN + 1];

    memset(b64output, 'f', sizeof(b64output));
    b64output[DEPLOY_STR_HASH_LEN] = '\0';
    EsfCodecBase64ResultEnum Base64Enc_ret = kEsfCodecBase64ResultSuccess;

    for (int slot = 0; slot < slot_num; slot++) {
        expect_not_value(__wrap_EsfCodecBase64Encode, in, NULL);
        expect_value(__wrap_EsfCodecBase64Encode, in_size, sizeof(InfoResponse[slot].hash));
        will_return(__wrap_EsfCodecBase64Encode, b64output);
        will_return(__wrap_EsfCodecBase64Encode, sizeof(b64output));
        will_return(__wrap_EsfCodecBase64Encode, Base64Enc_ret);

        // For SysAppUdIsThisRequestToStopForDownload()
        bool StopForDownload = false;
        will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, StopForDownload);

        // For EsfFwMgrOpen()
        EsfFwMgrHandle Handle_ret = (EsfFwMgrHandle)1234;
        int32_t MemorySize = 2345;
        int32_t WritableSize = 3456;
        EsfFwMgrResult FwMgr_ret = kEsfFwMgrResultOk;
        will_return(__wrap_EsfFwMgrOpen, Handle_ret);
        will_return(__wrap_EsfFwMgrOpen, MemorySize);
        will_return(__wrap_EsfFwMgrOpen, WritableSize);
        will_return(__wrap_EsfFwMgrOpen, FwMgr_ret);

        // For EsfFwMgrErase()
        // Set invalied for test
        will_return(__wrap_EsfFwMgrErase, kEsfFwMgrResultInternal);

        // For UtilityLogWriteELog() SYSAPP_ELOG_ERR(SYSAPP_EVT_OTA_FAILED)
        expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
        expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelError);
        expect_value(__wrap_UtilityLogWriteELog, event_id, ELOG_EVENT_ID_OTA_FAILED);
        will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);

        // For EsfFwMgrClose()
        will_return(__wrap_EsfFwMgrClose, kEsfFwMgrResultOk);
    }

    // For free()
    will_return(mock_free, false); // Not check parameter

    // SetEvpStateReportOtaUpdateStatus()
    SetEvpStateReportOtaUpdateStatusCommon(initp, SetEvpStateReportOtaUpdateStatus_None);

    // Exec test target
    DeleteAiModel(initp, deployp);

    // Check output
    assert_int_equal(deployp->parse_state, DeployStateFailed);
    assert_int_equal(deployp->res_info.code, 1); // not changed

exit:
    // cleanup
    free(initp);
    free(target);
    free(deployp);
    free(InfoResponse);
}

/*----------------------------------------------------------------------------*/
static void test_DeleteAiModel_ErrorEsfMgrClose(void **state)
{
    DeployInitParams_t *initp = NULL;
    Deploy_t *deployp = NULL;
    DeployTarget_t *target = NULL;
    EsfFwMgrGetInfoResponse *InfoResponse = NULL;

    // Prepare test target argument
    initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));
    if (initp == NULL) {
        assert_non_null(initp);
        goto exit;
    }

    memset(initp, 0, sizeof(DeployInitParams_t));

    deployp = (Deploy_t *)malloc(sizeof(Deploy_t));
    if (deployp == NULL) {
        assert_non_null(deployp);
        goto exit;
    }
    target = SetMakeJsonStateDeployTargetParam();
    if (target == NULL) {
        goto exit;
    }

    memset(deployp, 0, sizeof(Deploy_t));
    deployp->topic_id = DeployTopicAiModel;
    deployp->parse_state = DeployStateIdle;
    deployp->res_info.code = 1;
    deployp->deploy_target_num = 1;

    target->component = DeployComponentAiModel;
    deployp->deploy_targets = target;

    // Prepare mock
    // ESF_FIRMWARE_MANAGER_AI_MODEL_SLOT_NUM = 4
    uint32_t slot_num = 4;

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size,
                 sizeof(EsfFwMgrGetInfoResponse) * slot_num + sizeof(EsfFwMgrOpenRequest));

    // For EsfFwMgrGetInfo()
    InfoResponse = malloc(slot_num * sizeof(EsfFwMgrGetInfoResponse) + sizeof(EsfFwMgrOpenRequest));
    if (InfoResponse == NULL) {
        goto exit;
    }
    else {
        strcpy(InfoResponse[0].version, "ai_model_version_1");
        strcpy(InfoResponse[0].last_update, "ai_model_last_update_1");
        strcpy((char *)InfoResponse[0].hash, "ai_model_hash_1");

        strcpy(InfoResponse[1].version, "ai_model_version_2");
        strcpy(InfoResponse[1].last_update, "ai_model_last_update_2");
        strcpy((char *)InfoResponse[1].hash, "ai_model_hash_2");

        strcpy(InfoResponse[2].version, "ai_model_version_3");
        strcpy(InfoResponse[2].last_update, "ai_model_last_update_3");
        strcpy((char *)InfoResponse[2].hash, "ai_model_hash_3");

        strcpy(InfoResponse[3].version, "sensor_fw_version_4");
        strcpy(InfoResponse[3].last_update, "sensor_fw_last_update_4");
        strcpy((char *)InfoResponse[3].hash, "sensor_fw_hash_4");
    }

    EsfFwMgrResult EsfFwMgrGetInfo_ret = kEsfFwMgrResultOk;
    will_return(__wrap_EsfFwMgrGetInfo, InfoResponse);
    will_return(__wrap_EsfFwMgrGetInfo, EsfFwMgrGetInfo_ret);

    // For EsfCodecBase64Encode()
    char b64output[DEPLOY_STR_HASH_LEN + 1];

    memset(b64output, 'f', sizeof(b64output));
    b64output[DEPLOY_STR_HASH_LEN] = '\0';
    EsfCodecBase64ResultEnum Base64Enc_ret = kEsfCodecBase64ResultSuccess;

    for (int slot = 0; slot < slot_num; slot++) {
        expect_not_value(__wrap_EsfCodecBase64Encode, in, NULL);
        expect_value(__wrap_EsfCodecBase64Encode, in_size, sizeof(InfoResponse[slot].hash));
        will_return(__wrap_EsfCodecBase64Encode, b64output);
        will_return(__wrap_EsfCodecBase64Encode, sizeof(b64output));
        will_return(__wrap_EsfCodecBase64Encode, Base64Enc_ret);

        // For SysAppUdIsThisRequestToStopForDownload()
        bool StopForDownload = false;
        will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, StopForDownload);

        // For EsfFwMgrOpen()
        EsfFwMgrHandle Handle_ret = (EsfFwMgrHandle)1234;
        int32_t MemorySize = 2345;
        int32_t WritableSize = 3456;
        EsfFwMgrResult FwMgr_ret = kEsfFwMgrResultOk;
        will_return(__wrap_EsfFwMgrOpen, Handle_ret);
        will_return(__wrap_EsfFwMgrOpen, MemorySize);
        will_return(__wrap_EsfFwMgrOpen, WritableSize);
        will_return(__wrap_EsfFwMgrOpen, FwMgr_ret);

        // For EsfFwMgrErase()
        will_return(__wrap_EsfFwMgrErase, kEsfFwMgrResultOk);

        // For EsfFwMgrClose()
        // Set invalied for test
        will_return(__wrap_EsfFwMgrClose, kEsfFwMgrResultInternal);

        // For UtilityLogWriteELog() SYSAPP_ELOG_ERR(SYSAPP_EVT_OTA_FAILED)
        expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
        expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelError);
        expect_value(__wrap_UtilityLogWriteELog, event_id, ELOG_EVENT_ID_OTA_FAILED);
        will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);
    }

    // For free()
    will_return(mock_free, false); // Not check parameter

    // SetEvpStateReportOtaUpdateStatus()
    SetEvpStateReportOtaUpdateStatusCommon(initp, SetEvpStateReportOtaUpdateStatus_None);

    // Exec test target
    DeleteAiModel(initp, deployp);

    // Check output
    assert_int_equal(deployp->parse_state, DeployStateFailed);
    assert_int_equal(deployp->res_info.code, 1); // not changed

exit:
    // cleanup
    free(initp);
    free(target);
    free(deployp);
    free(InfoResponse);
}

/*----------------------------------------------------------------------------*/

//
// StopLED
//

/*----------------------------------------------------------------------------*/
static void test_StopLED_FullySuccess(void **state)
{
    DeployInitParams_t *initp = (DeployInitParams_t *)malloc(sizeof(DeployInitParams_t));

    if (initp == NULL) {
        assert_non_null(initp);
        return;
    }

    memset(initp, 0, sizeof(DeployInitParams_t));

    initp->is_pre_reboot = true;

    StopLED(initp);
}

/*----------------------------------------------------------------------------*/

//
// SysAppDeployGetCancel
//

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployGetCancel_FullySuccess(void **state)
{
    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, 0);

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);

    SysAppDeployGetCancel();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDeployGetCancel_ErrorMutex(void **state)
{
    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, -1);

    SysAppDeployGetCancel();
}

/*----------------------------------------------------------------------------*/

//
// ClearCancelFlag
//

/*----------------------------------------------------------------------------*/
static void test_ClearCancelFlag_ErrorMutex(void **state)
{
    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, -1);

    ClearCancelFlag(NULL, 0);
}

/*----------------------------------------------------------------------------*/

//
// RetryProcessWhenFirmwareManagerIsUnavailable
//

/*----------------------------------------------------------------------------*/
static void RetryProcessWhenFirmwareManagerIsUnavailable_MakeJsonStateReqInfo(void)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue child_val = 2468;

    // For EsfJsonObjectInit()
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // For SysAppCmnSetStringValue()
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, child_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "req_id");
    expect_string(__wrap_SysAppCmnSetStringValue, string, "");
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // For EsfJsonObjectSet()
    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, child_val);
    expect_string(__wrap_EsfJsonObjectSet, key, "req_info");
    expect_value(__wrap_EsfJsonObjectSet, value, child_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
static void RetryProcessWhenFirmwareManagerIsUnavailable_MakeJsonStateDeployTarget(void)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue child_val = 2468;

    // For SysAppCmnSetStringValue()
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, child_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "package_url");
    expect_string(__wrap_SysAppCmnSetStringValue, string, "");
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // component proterty
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, child_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "component");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, 1);
    will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);

    // For SysAppCmnSetStringValue()
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, child_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "version");
    expect_string(__wrap_SysAppCmnSetStringValue, string, "");
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // For SysAppCmnSetStringValue()
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, child_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "hash");
    expect_string(__wrap_SysAppCmnSetStringValue, string, "");
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // For SysAppCmnSetStringValue()
    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, child_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "process_state");
    expect_string(__wrap_SysAppCmnSetStringValue, string, "request_received");
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // size proterty
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, child_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "size");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, 0);
    will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);

    // progress proterty
    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, child_val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "progress");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, 0);
    will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void RetryProcessWhenFirmwareManagerIsUnavailable_SysAppDeploy(DeployInitParams_t *initp)
{
    expect_value(__wrap_UtilityMsgRecv, handle, initp->msg_handle_dp);
    expect_value(__wrap_UtilityMsgRecv, size, initp->max_msg_size_dp);
    expect_value(__wrap_UtilityMsgRecv, timeout_ms, 0);

    will_return(__wrap_UtilityMsgRecv, (int32_t)sizeof(DeployMessage_t *));
    will_return(__wrap_UtilityMsgRecv, NULL);
    will_return(__wrap_UtilityMsgRecv, kUtilityMsgErrState);

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    will_return(mock_malloc, true); // Get allocate memory
    expect_value(mock_malloc, __size, 0x1b);

    // For UtilityMsgSend()
    will_return(__wrap_UtilityMsgSend, kUtilityMsgOk);
    will_return(__wrap_UtilityMsgSend, UtilityMsgSendTypeNum);
    will_return(__wrap_UtilityMsgSend, 10);

    expect_value(__wrap_UtilityMsgSend, handle, initp->msg_handle_dp);
    expect_value(__wrap_UtilityMsgSend, msg_size, initp->max_msg_size_dp);
    expect_value(__wrap_UtilityMsgSend, msg_prio, 0);
}

/*----------------------------------------------------------------------------*/
static void test_RetryProcessWhenFirmwareManagerIsUnavailable_FullySuccess(void **state)
{
    DeployInitParams_t init;
    DeployTarget_t targets[1];

    memset(&init, 0, sizeof(init));
    memset(targets, 0, sizeof(DeployTarget_t));

    init.msg_handle_dp = 0x12345678;
    init.max_msg_size_dp = 2468;
    init.deploy.res_info.code = RESULT_CODE_UNAVAILABLE;
    init.deploy.deploy_target_num = 1;
    init.deploy.deploy_targets = targets;

    s_handle = (SysAppDeployHandle)&init;

    targets[0].component = DeployComponentSensorFirmware;

    for (int i = 0; i < MAX_NUMBER_OF_UPDATE_RETRY; i++) {
        will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, false);
    }

    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue child_val = 2468;
    EsfJsonValue array_val = 2468;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // For EsfJsonObjectInit()
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // For MakeJsonStateReqInfo()
    RetryProcessWhenFirmwareManagerIsUnavailable_MakeJsonStateReqInfo();

    expect_value(__wrap_EsfJsonArrayInit, handle, handle_val);
    will_return(__wrap_EsfJsonArrayInit, array_val);
    will_return(__wrap_EsfJsonArrayInit, kEsfJsonSuccess);

    // For EsfJsonObjectInit()
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // For MakeJsonStateDeployTarget()
    RetryProcessWhenFirmwareManagerIsUnavailable_MakeJsonStateDeployTarget();

    // For EsfJsonArrayAppend()
    expect_value(__wrap_EsfJsonArrayAppend, handle, handle_val);
    expect_value(__wrap_EsfJsonArrayAppend, parent, array_val);
    expect_value(__wrap_EsfJsonArrayAppend, value, child_val);
    will_return(__wrap_EsfJsonArrayAppend, kEsfJsonSuccess);

    // For EsfJsonObjectSet()
    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, child_val);
    expect_string(__wrap_EsfJsonObjectSet, key, "targets");
    expect_value(__wrap_EsfJsonObjectSet, value, child_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonSuccess);

    // For EsfJsonSerialize()
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, child_val);
    will_return(__wrap_EsfJsonSerialize, "aaa");
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, 0);

    // For pthread_mutex_unlock()
    will_return(__wrap_pthread_mutex_unlock, 0);

    // For SysAppDeploy
    RetryProcessWhenFirmwareManagerIsUnavailable_SysAppDeploy(&init);

    // For EsfJsonSerializeFree()
    expect_value(__wrap_EsfJsonSerializeFree, handle, handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    RetryProcessWhenFirmwareManagerIsUnavailable(&init);
}

/*----------------------------------------------------------------------------*/
static void test_RetryProcessWhenFirmwareManagerIsUnavailable_ErrorSysAppDeploy(void **state)
{
    DeployInitParams_t init;
    DeployTarget_t targets[1];

    memset(&init, 0, sizeof(init));
    memset(targets, 0, sizeof(DeployTarget_t));

    init.msg_handle_dp = 0x12345678;
    init.max_msg_size_dp = 2468;
    init.deploy.res_info.code = RESULT_CODE_UNAVAILABLE;
    init.deploy.deploy_target_num = 1;
    init.deploy.deploy_targets = targets;

    s_handle = (SysAppDeployHandle)&init;

    targets[0].component = DeployComponentSensorFirmware;

    for (int i = 0; i < MAX_NUMBER_OF_UPDATE_RETRY; i++) {
        will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, false);
    }

    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue child_val = 2468;
    EsfJsonValue array_val = 2468;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // For EsfJsonObjectInit()
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // For MakeJsonStateReqInfo()
    RetryProcessWhenFirmwareManagerIsUnavailable_MakeJsonStateReqInfo();

    expect_value(__wrap_EsfJsonArrayInit, handle, handle_val);
    will_return(__wrap_EsfJsonArrayInit, array_val);
    will_return(__wrap_EsfJsonArrayInit, kEsfJsonSuccess);

    // For EsfJsonObjectInit()
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // For MakeJsonStateDeployTarget()
    RetryProcessWhenFirmwareManagerIsUnavailable_MakeJsonStateDeployTarget();

    // For EsfJsonArrayAppend()
    expect_value(__wrap_EsfJsonArrayAppend, handle, handle_val);
    expect_value(__wrap_EsfJsonArrayAppend, parent, array_val);
    expect_value(__wrap_EsfJsonArrayAppend, value, child_val);
    will_return(__wrap_EsfJsonArrayAppend, kEsfJsonSuccess);

    // For EsfJsonObjectSet()
    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, child_val);
    expect_string(__wrap_EsfJsonObjectSet, key, "targets");
    expect_value(__wrap_EsfJsonObjectSet, value, child_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonSuccess);

    // For EsfJsonSerialize()
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, child_val);
    will_return(__wrap_EsfJsonSerialize, "aaa");
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // For pthread_mutex_lock()
    will_return(__wrap_pthread_mutex_lock, -1);

    // For EsfJsonSerializeFree()
    expect_value(__wrap_EsfJsonSerializeFree, handle, handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    RetryProcessWhenFirmwareManagerIsUnavailable(&init);
}

/*----------------------------------------------------------------------------*/
static void
    test_RetryProcessWhenFirmwareManagerIsUnavailable_SysAppUdIsThisRequestToStopForDownload(
        void **state)
{
    DeployInitParams_t init;
    DeployTarget_t targets[1];

    memset(&init, 0, sizeof(init));
    memset(targets, 0, sizeof(DeployTarget_t));

    init.deploy.res_info.code = RESULT_CODE_UNAVAILABLE;
    init.deploy.deploy_target_num = 1;
    init.deploy.deploy_targets = targets;

    targets[0].component = DeployComponentSensorFirmware;

    will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, true);

    RetryProcessWhenFirmwareManagerIsUnavailable(&init);
}

/*----------------------------------------------------------------------------*/
static void test_RetryProcessWhenFirmwareManagerIsUnavailable_Error_EsfJsonOpen(void **state)
{
    DeployInitParams_t init;
    DeployTarget_t targets[1];

    memset(&init, 0, sizeof(init));
    memset(targets, 0, sizeof(DeployTarget_t));

    init.deploy.res_info.code = RESULT_CODE_UNAVAILABLE;
    init.deploy.deploy_target_num = 1;
    init.deploy.deploy_targets = targets;

    targets[0].component = DeployComponentSensorFirmware;

    for (int i = 0; i < MAX_NUMBER_OF_UPDATE_RETRY; i++) {
        will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, false);
    }

    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);

    RetryProcessWhenFirmwareManagerIsUnavailable(&init);
}

/*----------------------------------------------------------------------------*/
static void test_RetryProcessWhenFirmwareManagerIsUnavailable_Error_EsfJsonObjectInit1(void **state)
{
    DeployInitParams_t init;
    DeployTarget_t targets[1];

    memset(&init, 0, sizeof(init));
    memset(targets, 0, sizeof(DeployTarget_t));

    init.deploy.res_info.code = RESULT_CODE_UNAVAILABLE;
    init.deploy.deploy_target_num = 1;
    init.deploy.deploy_targets = targets;

    targets[0].component = DeployComponentSensorFirmware;

    for (int i = 0; i < MAX_NUMBER_OF_UPDATE_RETRY; i++) {
        will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, false);
    }

    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue child_val = 2468;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // For EsfJsonObjectInit()
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonInternalError);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    RetryProcessWhenFirmwareManagerIsUnavailable(&init);
}

/*----------------------------------------------------------------------------*/
static void test_RetryProcessWhenFirmwareManagerIsUnavailable_Error_EsfJsonArrayInit(void **state)
{
    DeployInitParams_t init;
    DeployTarget_t targets[1];

    memset(&init, 0, sizeof(init));
    memset(targets, 0, sizeof(DeployTarget_t));

    init.deploy.res_info.code = RESULT_CODE_UNAVAILABLE;
    init.deploy.deploy_target_num = 1;
    init.deploy.deploy_targets = targets;

    targets[0].component = DeployComponentSensorFirmware;

    for (int i = 0; i < MAX_NUMBER_OF_UPDATE_RETRY; i++) {
        will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, false);
    }

    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue child_val = 2468;
    EsfJsonValue array_val = 2468;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // For EsfJsonObjectInit()
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // For MakeJsonStateReqInfo()
    RetryProcessWhenFirmwareManagerIsUnavailable_MakeJsonStateReqInfo();

    expect_value(__wrap_EsfJsonArrayInit, handle, handle_val);
    will_return(__wrap_EsfJsonArrayInit, array_val);
    will_return(__wrap_EsfJsonArrayInit, kEsfJsonInternalError);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    RetryProcessWhenFirmwareManagerIsUnavailable(&init);
}

/*----------------------------------------------------------------------------*/
static void test_RetryProcessWhenFirmwareManagerIsUnavailable_Error_EsfJsonObjectInit2(void **state)
{
    DeployInitParams_t init;
    DeployTarget_t targets[1];

    memset(&init, 0, sizeof(init));
    memset(targets, 0, sizeof(DeployTarget_t));

    init.deploy.res_info.code = RESULT_CODE_UNAVAILABLE;
    init.deploy.deploy_target_num = 1;
    init.deploy.deploy_targets = targets;

    targets[0].component = DeployComponentSensorFirmware;

    for (int i = 0; i < MAX_NUMBER_OF_UPDATE_RETRY; i++) {
        will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, false);
    }

    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue child_val = 2468;
    EsfJsonValue array_val = 2468;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // For EsfJsonObjectInit()
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // For MakeJsonStateReqInfo()
    RetryProcessWhenFirmwareManagerIsUnavailable_MakeJsonStateReqInfo();

    // For EsfJsonArrayInit
    expect_value(__wrap_EsfJsonArrayInit, handle, handle_val);
    will_return(__wrap_EsfJsonArrayInit, array_val);
    will_return(__wrap_EsfJsonArrayInit, kEsfJsonSuccess);

    // For EsfJsonObjectInit()
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonInternalError);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    RetryProcessWhenFirmwareManagerIsUnavailable(&init);
}

/*----------------------------------------------------------------------------*/
static void test_RetryProcessWhenFirmwareManagerIsUnavailable_Error_EsfJsonArrayAppend(void **state)
{
    DeployInitParams_t init;
    DeployTarget_t targets[1];

    memset(&init, 0, sizeof(init));
    memset(targets, 0, sizeof(DeployTarget_t));

    init.deploy.res_info.code = RESULT_CODE_UNAVAILABLE;
    init.deploy.deploy_target_num = 1;
    init.deploy.deploy_targets = targets;

    targets[0].component = DeployComponentSensorFirmware;

    for (int i = 0; i < MAX_NUMBER_OF_UPDATE_RETRY; i++) {
        will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, false);
    }

    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue child_val = 2468;
    EsfJsonValue array_val = 2468;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // For EsfJsonObjectInit()
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // For MakeJsonStateReqInfo()
    RetryProcessWhenFirmwareManagerIsUnavailable_MakeJsonStateReqInfo();

    // For EsfJsonArrayInit
    expect_value(__wrap_EsfJsonArrayInit, handle, handle_val);
    will_return(__wrap_EsfJsonArrayInit, array_val);
    will_return(__wrap_EsfJsonArrayInit, kEsfJsonSuccess);

    // For EsfJsonObjectInit()
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // For MakeJsonStateDeployTarget()
    RetryProcessWhenFirmwareManagerIsUnavailable_MakeJsonStateDeployTarget();

    // For EsfJsonArrayAppend()
    expect_value(__wrap_EsfJsonArrayAppend, handle, handle_val);
    expect_value(__wrap_EsfJsonArrayAppend, parent, array_val);
    expect_value(__wrap_EsfJsonArrayAppend, value, child_val);
    will_return(__wrap_EsfJsonArrayAppend, kEsfJsonInternalError);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    RetryProcessWhenFirmwareManagerIsUnavailable(&init);
}

/*----------------------------------------------------------------------------*/
static void test_RetryProcessWhenFirmwareManagerIsUnavailable_Error_EsfJsonObjectSet(void **state)
{
    DeployInitParams_t init;
    DeployTarget_t targets[1];

    memset(&init, 0, sizeof(init));
    memset(targets, 0, sizeof(DeployTarget_t));

    init.deploy.res_info.code = RESULT_CODE_UNAVAILABLE;
    init.deploy.deploy_target_num = 1;
    init.deploy.deploy_targets = targets;

    targets[0].component = DeployComponentSensorFirmware;

    for (int i = 0; i < MAX_NUMBER_OF_UPDATE_RETRY; i++) {
        will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, false);
    }

    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue child_val = 2468;
    EsfJsonValue array_val = 2468;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // For EsfJsonObjectInit()
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // For MakeJsonStateReqInfo()
    RetryProcessWhenFirmwareManagerIsUnavailable_MakeJsonStateReqInfo();

    // For EsfJsonArrayInit
    expect_value(__wrap_EsfJsonArrayInit, handle, handle_val);
    will_return(__wrap_EsfJsonArrayInit, array_val);
    will_return(__wrap_EsfJsonArrayInit, kEsfJsonSuccess);

    // For EsfJsonObjectInit()
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // For MakeJsonStateDeployTarget()
    RetryProcessWhenFirmwareManagerIsUnavailable_MakeJsonStateDeployTarget();

    // For EsfJsonArrayAppend()
    expect_value(__wrap_EsfJsonArrayAppend, handle, handle_val);
    expect_value(__wrap_EsfJsonArrayAppend, parent, array_val);
    expect_value(__wrap_EsfJsonArrayAppend, value, child_val);
    will_return(__wrap_EsfJsonArrayAppend, kEsfJsonSuccess);

    // For EsfJsonObjectSet()
    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, child_val);
    expect_string(__wrap_EsfJsonObjectSet, key, "targets");
    expect_value(__wrap_EsfJsonObjectSet, value, child_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonInternalError);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    RetryProcessWhenFirmwareManagerIsUnavailable(&init);
}

/*----------------------------------------------------------------------------*/
static void test_RetryProcessWhenFirmwareManagerIsUnavailable_Error_EsfJsonSerialize(void **state)
{
    DeployInitParams_t init;
    DeployTarget_t targets[1];

    memset(&init, 0, sizeof(init));
    memset(targets, 0, sizeof(DeployTarget_t));

    init.deploy.res_info.code = RESULT_CODE_UNAVAILABLE;
    init.deploy.deploy_target_num = 1;
    init.deploy.deploy_targets = targets;

    targets[0].component = DeployComponentSensorFirmware;

    for (int i = 0; i < MAX_NUMBER_OF_UPDATE_RETRY; i++) {
        will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, false);
    }

    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue child_val = 2468;
    EsfJsonValue array_val = 2468;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // For EsfJsonObjectInit()
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // For MakeJsonStateReqInfo()
    RetryProcessWhenFirmwareManagerIsUnavailable_MakeJsonStateReqInfo();

    // For EsfJsonArrayInit
    expect_value(__wrap_EsfJsonArrayInit, handle, handle_val);
    will_return(__wrap_EsfJsonArrayInit, array_val);
    will_return(__wrap_EsfJsonArrayInit, kEsfJsonSuccess);

    // For EsfJsonObjectInit()
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // For MakeJsonStateDeployTarget()
    RetryProcessWhenFirmwareManagerIsUnavailable_MakeJsonStateDeployTarget();

    // For EsfJsonArrayAppend()
    expect_value(__wrap_EsfJsonArrayAppend, handle, handle_val);
    expect_value(__wrap_EsfJsonArrayAppend, parent, array_val);
    expect_value(__wrap_EsfJsonArrayAppend, value, child_val);
    will_return(__wrap_EsfJsonArrayAppend, kEsfJsonSuccess);

    // For EsfJsonObjectSet()
    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, child_val);
    expect_string(__wrap_EsfJsonObjectSet, key, "targets");
    expect_value(__wrap_EsfJsonObjectSet, value, child_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonSuccess);

    // For EsfJsonSerialize()
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, child_val);
    will_return(__wrap_EsfJsonSerialize, "aaa");
    will_return(__wrap_EsfJsonSerialize, kEsfJsonInternalError);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    RetryProcessWhenFirmwareManagerIsUnavailable(&init);
}

/*----------------------------------------------------------------------------*/
static void test_RetryProcessWhenFirmwareManagerIsUnavailable_Error_EsfJsonSerializeStrNull(
    void **state)
{
    DeployInitParams_t init;
    DeployTarget_t targets[1];

    memset(&init, 0, sizeof(init));
    memset(targets, 0, sizeof(DeployTarget_t));

    init.deploy.res_info.code = RESULT_CODE_UNAVAILABLE;
    init.deploy.deploy_target_num = 1;
    init.deploy.deploy_targets = targets;

    targets[0].component = DeployComponentSensorFirmware;

    for (int i = 0; i < MAX_NUMBER_OF_UPDATE_RETRY; i++) {
        will_return(__wrap_SysAppUdIsThisRequestToStopForDownload, false);
    }

    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue child_val = 2468;
    EsfJsonValue array_val = 2468;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    // For EsfJsonObjectInit()
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // For MakeJsonStateReqInfo()
    RetryProcessWhenFirmwareManagerIsUnavailable_MakeJsonStateReqInfo();

    // For EsfJsonArrayInit
    expect_value(__wrap_EsfJsonArrayInit, handle, handle_val);
    will_return(__wrap_EsfJsonArrayInit, array_val);
    will_return(__wrap_EsfJsonArrayInit, kEsfJsonSuccess);

    // For EsfJsonObjectInit()
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    // For MakeJsonStateDeployTarget()
    RetryProcessWhenFirmwareManagerIsUnavailable_MakeJsonStateDeployTarget();

    // For EsfJsonArrayAppend()
    expect_value(__wrap_EsfJsonArrayAppend, handle, handle_val);
    expect_value(__wrap_EsfJsonArrayAppend, parent, array_val);
    expect_value(__wrap_EsfJsonArrayAppend, value, child_val);
    will_return(__wrap_EsfJsonArrayAppend, kEsfJsonSuccess);

    // For EsfJsonObjectSet()
    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, child_val);
    expect_string(__wrap_EsfJsonObjectSet, key, "targets");
    expect_value(__wrap_EsfJsonObjectSet, value, child_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonSuccess);

    // For EsfJsonSerialize()
    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, child_val);
    will_return(__wrap_EsfJsonSerialize, "");
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    RetryProcessWhenFirmwareManagerIsUnavailable(&init);
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

        cmocka_unit_test(test_SysAppDeployInitialValueOfGlobalVariable),

        // SysAppDeployInitialize()
        cmocka_unit_test(test_SysAppDeployInitialize_FullySuccess),
        cmocka_unit_test(test_SysAppDeployInitialize_ErrorStateViolate),
        cmocka_unit_test(test_SysAppDeployInitialize_ErrorMalloc),
        cmocka_unit_test(test_SysAppDeployInitialize_ErrorUtilityMsgOpen),
        cmocka_unit_test(test_SysAppDeployInitialize_ErrorPthreadMutexInit),
        cmocka_unit_test(test_SysAppDeployInitialize_ErrorPthreadAttrInit),
        cmocka_unit_test(test_SysAppDeployInitialize_ErrorPthreadAttrsSetstacksize),
        cmocka_unit_test(test_SysAppDeployInitialize_ErrorPthreadCreate),
        cmocka_unit_test(test_SysAppDeployInitialize_MsgCloseError),

        // SysAppDeployFinalize()
        cmocka_unit_test(test_SysAppDeployFinalize_FullySuccess),
        cmocka_unit_test(test_SysAppDeployFinalize_ErrorStateViolate),
        cmocka_unit_test(test_SysAppDeployFinalize_ErrorUtilityMsgRecv),
        cmocka_unit_test(test_SysAppDeployFinalize_NullUtilityMsgRecv),
        cmocka_unit_test(test_SysAppDeployFinalize_ErrorUtilityMsgSend),
        cmocka_unit_test(test_SysAppDeployFinalize_ErrorPthreadJoin),
        cmocka_unit_test(test_SysAppDeployFinalize_NullMsgHandle),
        cmocka_unit_test(test_SysAppDeployFinalize_NullStateStr),
        cmocka_unit_test(test_SysAppDeployFinalize_MsgCloseError),

        // SysAppDeploy()
        cmocka_unit_test(test_SysAppDeploy_FullySuccessFirmware),
        cmocka_unit_test(test_SysAppDeploy_FullySuccessAiModel),
        cmocka_unit_test(test_SysAppDeploy_FullySuccessSensorCalibrationParam),
        cmocka_unit_test(test_SysAppDeploy_FullySuccessFirmwareReload),
        cmocka_unit_test(test_SysAppDeploy_FullySuccessAiModelReload),
        cmocka_unit_test(test_SysAppDeploy_FullySuccessSensorCalibrationParamReload),
        cmocka_unit_test(test_SysAppDeploy_NullHandle),
        cmocka_unit_test(test_SysAppDeploy_UndefinedTopic),
        cmocka_unit_test(test_SysAppDeploy_ErrorUtilityMsgRecv),
        cmocka_unit_test(test_SysAppDeploy_ErrorUtilityMsgSendForReload),
        cmocka_unit_test(test_SysAppDeploy_ErrorMalloc),
        cmocka_unit_test(test_SysAppDeploy_ErrorUtilityMsgSendForNew),
        cmocka_unit_test(test_SysAppDeploy_ErrorMutex),

        // SysAppDeployGetFirmwareState()
        cmocka_unit_test(test_SysAppDeployGetFirmwareState_FullySuccess),
        cmocka_unit_test(test_SysAppDeployGetFirmwareState_NullHandle),
        cmocka_unit_test(test_SysAppDeployGetFirmwareState_NullState),
        cmocka_unit_test(test_SysAppDeployGetFirmwareState_NullSize),
        cmocka_unit_test(test_SysAppDeployGetFirmwareState_ErrorPthreadMutexLock),
        cmocka_unit_test(test_SysAppDeployGetFirmwareState_StateStrNothing),
        cmocka_unit_test(test_SysAppDeployGetFirmwareState_ErrorMalloc),

        // SysAppDeployGetAiModelState()
        cmocka_unit_test(test_SysAppDeployGetAiModelState_FullySuccess),

        // SysAppDeployGetSensorCalibrationParamState()
        cmocka_unit_test(test_SysAppDeployGetSensorCalibrationParamState_FullySuccess),

        // SysAppDeployFreeState()
        cmocka_unit_test(test_SysAppDeployFreeState_NotNullState),
        cmocka_unit_test(test_SysAppDeployFreeState_NullState),

        // SysAppDeployCheckResetRequest()
        cmocka_unit_test(test_SysAppDeployCheckResetRequest_FullySuccessRequest),
        cmocka_unit_test(test_SysAppDeployCheckResetRequest_FullySuccessNotRequest),
        cmocka_unit_test(test_SysAppDeployCheckResetRequest_ErrorStateViolate),
        cmocka_unit_test(test_SysAppDeployCheckResetRequest_InvalidArgument),
        cmocka_unit_test(test_SysAppDeployCheckResetRequest_SwArchVersion1),
        cmocka_unit_test(test_SysAppDeployCheckResetRequest_SwArchVersion2),

        // SysAppDeployFactoryReset()
        cmocka_unit_test(test_SysAppDeployFactoryReset_FullySuccessRequest),
        cmocka_unit_test(test_SysAppDeployFactoryReset_ErrorCause),

        // InitSha256()
        cmocka_unit_test(test_InitSha256_FullySuccess),
        cmocka_unit_test(test_InitSha256_ErrorMalloc),

        // UpdateSha256()
        cmocka_unit_test(test_UpdateSha256_FullySuccess),
        cmocka_unit_test(test_UpdateSha256_NullHandle),
        cmocka_unit_test(test_UpdateSha256_NullInput),

        // FinishSha256()
        cmocka_unit_test(test_FinishSha256_FullySuccess),
        cmocka_unit_test(test_FinishSha256_NullHandle),
        cmocka_unit_test(test_FinishSha256_NullOutput),

        // SetTargetState()
        cmocka_unit_test(test_SetTargetState),

        // ExtractStringValue()
        cmocka_unit_test(test_ExtractStringValue_FullySuccess),
        cmocka_unit_test(test_ExtractStringValue_ErrorSysAppCmnExtractStringValue),
        cmocka_unit_test(test_ExtractStringValue_NullPointerSysAppCmnExtractStringValue),
        cmocka_unit_test(test_ExtractStringValue_NullStrSysAppCmnExtractStringValue),
        cmocka_unit_test(test_ExtractStringValue_MaxOverBuffExtraString),
        cmocka_unit_test(test_ExtractStringValue_MaxBuffExtraString),
        cmocka_unit_test(test_ExtractStringValue_MaxOverExtracedLenExtraString),
        cmocka_unit_test(test_ExtractStringValue_MaxExtracedLenExtraString),

        // MakeJsonStateReqInfo()
        cmocka_unit_test(test_MakeJsonStateReqInfo_FullySuccess),
        cmocka_unit_test(test_MakeJsonStateReqInfo_ErrorEsfJsonObjectInit),
        cmocka_unit_test(test_MakeJsonStateReqInfo_ErrorSysAppCmnSetStringValue),
        cmocka_unit_test(test_MakeJsonStateReqInfo_ErrorEsfJsonObjectSet),

        // SetResInfo()
        cmocka_unit_test(test_SetResInfo_Done),
        cmocka_unit_test(test_SetResInfo_Failed),
        cmocka_unit_test(test_SetResInfo_FailedTokenExpired),
        cmocka_unit_test(test_SetResInfo_FailedDownloadRetryExceeded),
        cmocka_unit_test(test_SetResInfo_FailedInvalidRequest),
        cmocka_unit_test(test_SetResInfo_FailedUnavailable),
        cmocka_unit_test(test_SetResInfo_FailedCancelled),
        cmocka_unit_test(test_SetResInfo_Other),

        // ConvertComponentToState()
        cmocka_unit_test(test_ConvertComponentToState_SensorLoader),
        cmocka_unit_test(test_ConvertComponentToState_SensorFirmware),
        cmocka_unit_test(test_ConvertComponentToState_ProcessorLoader),
        cmocka_unit_test(test_ConvertComponentToState_ProcessorFirmware),
        cmocka_unit_test(test_ConvertComponentToState_SensorCalibrationParam),
        cmocka_unit_test(test_ConvertComponentToState_AiModel),
        cmocka_unit_test(test_ConvertComponentToState_Other),

        // MakeJsonStateDeployTarget()
        cmocka_unit_test(test_MakeJsonStateDeployTarget_FullySuccessBase),
        cmocka_unit_test(test_MakeJsonStateDeployTarget_FullySuccessNothingComponent),
        cmocka_unit_test(test_MakeJsonStateDeployTarget_FullySuccessNothingChip),
        cmocka_unit_test(test_MakeJsonStateDeployTarget_FullySuccessProcessStateIdle),
        cmocka_unit_test(test_MakeJsonStateDeployTarget_FullySuccessProcessStateRequestReceived),
        cmocka_unit_test(test_MakeJsonStateDeployTarget_FullySuccessProcessStateDownloading),
        cmocka_unit_test(test_MakeJsonStateDeployTarget_FullySuccessProcessStateInstalling),

        // cmocka_unit_test(test_MakeJsonStateDeployTarget_FullySuccessProcessStateDone), this case is same as FullySuccessBase
        cmocka_unit_test(test_MakeJsonStateDeployTarget_FullySuccessProcessStateFailed),
        cmocka_unit_test(
            test_MakeJsonStateDeployTarget_FullySuccessProcessStateFailedInvalidRequest),
        cmocka_unit_test(test_MakeJsonStateDeployTarget_FullySuccessProcessStateFailedTokenExpired),
        cmocka_unit_test(
            test_MakeJsonStateDeployTarget_FullySuccessProcessStateFailedDownloadRetryExceeded),
        cmocka_unit_test(test_MakeJsonStateDeployTarget_FullySuccessProcessStateFailedUnavailable),
        cmocka_unit_test(test_MakeJsonStateDeployTarget_ErrorSysAppCmnSetNumberValueComponent),
        cmocka_unit_test(test_MakeJsonStateDeployTarget_ErrorSysAppCmnSetStringValueChip),
        cmocka_unit_test(test_MakeJsonStateDeployTarget_ErrorSysAppCmnSetStringValuePackageUrl),
        cmocka_unit_test(test_MakeJsonStateDeployTarget_ErrorSysAppCmnSetStringValueVersion),
        cmocka_unit_test(test_MakeJsonStateDeployTarget_ErrorSysAppCmnSetStringValueHash),
        cmocka_unit_test(test_MakeJsonStateDeployTarget_ErrorSysAppCmnSetNumberValueSize),
        cmocka_unit_test(test_MakeJsonStateDeployTarget_ErrorSysAppCmnSetNumberValueProgress),
        cmocka_unit_test(test_MakeJsonStateDeployTarget_ErrorSysAppCmnSetNumberValueProcessState),

        // ConvertChipToComponent()
        cmocka_unit_test(test_ConvertChipToComponent_MainLoader),
        cmocka_unit_test(test_ConvertChipToComponent_MainFirmware),
        cmocka_unit_test(test_ConvertChipToComponent_SensorLoader),
        cmocka_unit_test(test_ConvertChipToComponent_SensorFirmware),
        cmocka_unit_test(test_ConvertChipToComponent_SensorAiModel),
        cmocka_unit_test(test_ConvertChipToComponent_CompanionLoader),
        cmocka_unit_test(test_ConvertChipToComponent_CompanionFirmware),
        cmocka_unit_test(test_ConvertChipToComponent_CompanionAiModel),
        cmocka_unit_test(test_ConvertChipToComponent_Invalid),

        // CmpTargetNameProperty()
        cmocka_unit_test(test_CmpTargetNameProperty_CameraSetupColorMatrix),
        cmocka_unit_test(test_CmpTargetNameProperty_CameraSetupGamma),
        cmocka_unit_test(test_CmpTargetNameProperty_CameraSetupLscIsp),
        cmocka_unit_test(test_CmpTargetNameProperty_CameraSetupPreWB),
        cmocka_unit_test(test_CmpTargetNameProperty_CameraSetupDewarp),
        cmocka_unit_test(test_CmpTargetNameProperty_CameraSetupOther),
        cmocka_unit_test(test_CmpTargetNameProperty_FirmwareSensorLoaderImx500),
        cmocka_unit_test(test_CmpTargetNameProperty_FirmwareSensorLoaderAiIsp),
        cmocka_unit_test(test_CmpTargetNameProperty_FirmwareSensorLoaderOther),
        cmocka_unit_test(test_CmpTargetNameProperty_FirmwareSensorFirmwareImx500),
        cmocka_unit_test(test_CmpTargetNameProperty_FirmwareSensorFirmwareAiIsp),
        cmocka_unit_test(test_CmpTargetNameProperty_FirmwareSensorFirmwareOther),
        cmocka_unit_test(test_CmpTargetNameProperty_FirmwareOtherEsp32S3),
        cmocka_unit_test(test_CmpTargetNameProperty_FirmwareOtherEsp32),
        cmocka_unit_test(test_CmpTargetNameProperty_FirmwareOtherApFw),
        cmocka_unit_test(test_CmpTargetNameProperty_FirmwareOtherOther),
        cmocka_unit_test(test_CmpTargetNameProperty_AiModelImx500),
        cmocka_unit_test(test_CmpTargetNameProperty_AiModelAiIsp),
        cmocka_unit_test(test_CmpTargetNameProperty_AiModelOther),
        cmocka_unit_test(test_CmpTargetNameProperty_OtherTopic),

        // GetConfigurationDeployTargetProperty()
        cmocka_unit_test(test_GetConfigurationDeployTargetProperty_FullySuccessAiModel),
        cmocka_unit_test(test_GetConfigurationDeployTargetProperty_FullySuccessOther),
        cmocka_unit_test(test_GetConfigurationDeployTargetProperty_NotSpecifyChip),
        cmocka_unit_test(test_GetConfigurationDeployTargetProperty_FullySuccessSpecifyName),
        cmocka_unit_test(test_GetConfigurationDeployTargetProperty_InvalidComponent),
        cmocka_unit_test(test_GetConfigurationDeployTargetProperty_NotSpecifyComponent),
        cmocka_unit_test(
            test_GetConfigurationDeployTargetProperty_NotSpecifyChipAndInvaliComponent),
        cmocka_unit_test(test_GetConfigurationDeployTargetProperty_InvalidName),
        cmocka_unit_test(test_GetConfigurationDeployTargetProperty_NotSpecifyVersion),
        cmocka_unit_test(test_GetConfigurationDeployTargetProperty_NotSpecifyPackageUri),
        cmocka_unit_test(test_GetConfigurationDeployTargetProperty_NotSpecifyHash),
        cmocka_unit_test(test_GetConfigurationDeployTargetProperty_NotSpecifySize),
        cmocka_unit_test(test_GetConfigurationDeployTargetProperty_NegativeSize),

        // GetResCodePriority()
        cmocka_unit_test(test_GetResCodePriority_Unimplemented),
        cmocka_unit_test(test_GetResCodePriority_InvalidArgument),
        cmocka_unit_test(test_GetResCodePriority_FailedPrecondition),
        cmocka_unit_test(test_GetResCodePriority_Unavailable),
        cmocka_unit_test(test_GetResCodePriority_ResourceExhausted),
        cmocka_unit_test(test_GetResCodePriority_PermissionDenied),
        cmocka_unit_test(test_GetResCodePriority_DeadlineExceeded),
        cmocka_unit_test(test_GetResCodePriority_Internal),
        cmocka_unit_test(test_GetResCodePriority_Ok),
        cmocka_unit_test(test_GetResCodePriority_Other),

        // MakeJsonResInfoDeployConfiguration()
        cmocka_unit_test(test_MakeJsonResInfoDeployConfiguration),

        // MakeJsonStateDeployConfiguration()
        cmocka_unit_test(test_MakeJsonStateDeployConfiguration_FullySuccessFirmware),
        cmocka_unit_test(test_MakeJsonStateDeployConfiguration_FullySuccessAiModel),
        cmocka_unit_test(test_MakeJsonStateDeployConfiguration_FullySuccessKeepErrorCode),
        cmocka_unit_test(test_MakeJsonStateDeployConfiguration_ErrorSysAppCmnSetStringValue),
        cmocka_unit_test(test_MakeJsonStateDeployConfiguration_ErrorEsfJsonArrayInit),
        cmocka_unit_test(test_MakeJsonStateDeployConfiguration_ErrorEsfJsonObjectInit),
        cmocka_unit_test(test_MakeJsonStateDeployConfiguration_ErrorEsfJsonArrayAppend),
        cmocka_unit_test(test_MakeJsonStateDeployConfiguration_ErrorEsfJsonObjectSet),

        // GetConfigurationReqInfoProperty()
        cmocka_unit_test(test_GetConfigurationReqInfoProperty_FullySuccess),
        cmocka_unit_test(test_GetConfigurationReqInfoProperty_NotFoundSysAppCmnGetReqId),
        cmocka_unit_test(test_GetConfigurationReqInfoProperty_DefaultSysAppCmnGetReqId),
        cmocka_unit_test(test_GetConfigurationReqInfoProperty_MaxStrnlen),
        cmocka_unit_test(test_GetConfigurationReqInfoProperty_MaxOverStrnlen),

        // SetEvpStateReportOtaUpdateStatus()
        cmocka_unit_test(test_SetEvpStateReportOtaUpdateStatus_FullySuccessFirmware),
        cmocka_unit_test(test_SetEvpStateReportOtaUpdateStatus_FullySuccessAiModel),
        cmocka_unit_test(test_SetEvpStateReportOtaUpdateStatus_FullySuccessCameraSetup),
        cmocka_unit_test(test_SetEvpStateReportOtaUpdateStatus_ErrorEsfJsonOpen),
        cmocka_unit_test(test_SetEvpStateReportOtaUpdateStatus_ErrorEsfJsonObjectInit),
        cmocka_unit_test(test_SetEvpStateReportOtaUpdateStatus_ErrorEsfJsonSerialize),
        cmocka_unit_test(test_SetEvpStateReportOtaUpdateStatus_NullEsfJsonSerialize),
        cmocka_unit_test(test_SetEvpStateReportOtaUpdateStatus_InvalidId),
        cmocka_unit_test(test_SetEvpStateReportOtaUpdateStatus_MaxOverLenSerializedJson),
        cmocka_unit_test(test_SetEvpStateReportOtaUpdateStatus_MaxLenSerializedJson),
        cmocka_unit_test(test_SetEvpStateReportOtaUpdateStatus_ErrorPthreadMutexLock),
        cmocka_unit_test(test_SetEvpStateReportOtaUpdateStatus_ErrorReallocNotAllocated),
        cmocka_unit_test(test_SetEvpStateReportOtaUpdateStatus_ErrorReallocAllocated),
        cmocka_unit_test(test_SetEvpStateReportOtaUpdateStatus_ErrorSysAppStateSendState),

        // GetConfigurationDeployConfigurationProperty()
        cmocka_unit_test(test_GetConfigurationDeployConfigurationProperty_FullySuccess),
        cmocka_unit_test(
            test_GetConfigurationDeployConfigurationProperty_ErrorGetConfigurationReqInfoProperty),
        cmocka_unit_test(
            test_GetConfigurationDeployConfigurationProperty_FullySuccessTopicCameraSetup),
        cmocka_unit_test(test_GetConfigurationDeployConfigurationProperty_ErrorExtractStringValue),
        cmocka_unit_test(test_GetConfigurationDeployConfigurationProperty_ErrorEsfJsonObjectGet),
        cmocka_unit_test(test_GetConfigurationDeployConfigurationProperty_ErrorEsfJsonValueTypeGet),
        cmocka_unit_test(
            test_GetConfigurationDeployConfigurationProperty_ErrorTypeEsfJsonValueTypeGet),
        cmocka_unit_test(
            test_GetConfigurationDeployConfigurationProperty_ErrorCntEsfJsonArrayCount),
        cmocka_unit_test(test_GetConfigurationDeployConfigurationProperty_OverCntEsfJsonArrayCount),
        cmocka_unit_test(test_GetConfigurationDeployConfigurationProperty_ErrorMalloc),
        cmocka_unit_test(test_GetConfigurationDeployConfigurationProperty_ErrorEsfJsonArrayGet),

        // FirmwareUpdateOpen()
        cmocka_unit_test(test_FirmwareUpdateOpen_RequestToStopForDownload),
        cmocka_unit_test(test_FirmwareUpdateOpen_Cancelled),
        cmocka_unit_test(test_FirmwareUpdateOpen_FullySuccessNormal),
        cmocka_unit_test(test_FirmwareUpdateOpen_FullySuccessHashNullOnly),
        cmocka_unit_test(test_FirmwareUpdateOpen_ErrorEsfCodecBase64Decode),
        cmocka_unit_test(test_FirmwareUpdateOpen_FullySuccessOpenRetry),
        cmocka_unit_test(test_FirmwareUpdateOpen_ErrorEsfFwMgrOpenRetryOver),
        cmocka_unit_test(test_FirmwareUpdateOpen_ErrorEsfFwMgrOpenOther),
        cmocka_unit_test(test_FirmwareUpdateOpen_NullPRes),

        // CompareDeployingVersionWithDeployedOneTarget()
        cmocka_unit_test(test_CompareDeployingVersionWithDeployedOneTarget_FullySuccess),
        cmocka_unit_test(test_CompareDeployingVersionWithDeployedOneTarget_ErrorEsfFwMgrGetInfo),
        cmocka_unit_test(
            test_CompareDeployingVersionWithDeployedOneTarget_ErrorEsfCodecBase64Decode),

        // CompareDeployingVersionWithDeployedAiModel()
        cmocka_unit_test(test_CompareDeployingVersionWithDeployedAiModel_FullySuccessSameVersion),
        cmocka_unit_test(test_CompareDeployingVersionWithDeployedAiModel_ErrorMalloc),
        cmocka_unit_test(test_CompareDeployingVersionWithDeployedAiModel_ErrorEsfFwMgrGetInfo),
        cmocka_unit_test(test_CompareDeployingVersionWithDeployedAiModel_ErrorEsfCodecBase64Decode),
        cmocka_unit_test(test_CompareDeployingVersionWithDeployedAiModel_FullySuccessDiffVersion),
        cmocka_unit_test(test_CompareDeployingVersionWithDeployedAiModel_ErrorDiffVersionSlotFull),

        // CheckVersion()
        cmocka_unit_test(test_CheckVersion_SensorLoader),
        cmocka_unit_test(test_CheckVersion_AiModel),
        cmocka_unit_test(test_CheckVersion_Other),

        // DownloadCallback()
        cmocka_unit_test(test_DownloadCallback_FullySuccess),
        cmocka_unit_test(test_DownloadCallback_Cancelled),
        cmocka_unit_test(test_DownloadCallback_SucessRequestToStopForDownloadIsTrue),

        // FirmwareUpdate()
        cmocka_unit_test(test_FirmwareUpdate_FullySuccessProcessorLoader),
        cmocka_unit_test(test_FirmwareUpdate_FullySuccessProcessorFirmware),
        cmocka_unit_test(test_FirmwareUpdate_FullySuccessAiModel),
        cmocka_unit_test(test_FirmwareUpdate_FullySuccessGetSize),
        cmocka_unit_test(test_FirmwareUpdate_FullySuccessDownload2Times),
        cmocka_unit_test(test_FirmwareUpdate_ErrorGetSize403),
        cmocka_unit_test(test_FirmwareUpdate_ErrorGetSizeOther),
        cmocka_unit_test(test_FirmwareUpdate_ErrorGetSizeBadParams),
        cmocka_unit_test(test_FirmwareUpdate_ErrorFirmwareUpdateOpen),
        cmocka_unit_test(test_FirmwareUpdate_ErrorUpdateMemoriSize),
        cmocka_unit_test(test_FirmwareUpdate_ErrorFinishSha256),
        cmocka_unit_test(test_FirmwareUpdate_ErrorNotMatchHash),
        cmocka_unit_test(test_FirmwareUpdate_ErrorFwMgrPostProcess),
        cmocka_unit_test(test_FirmwareUpdate_ErrorGetImage403),
        cmocka_unit_test(test_FirmwareUpdate_ErrorGetImageBadParams),
        cmocka_unit_test(test_FirmwareUpdate_ErrorGetImageReteyOver),
        cmocka_unit_test(test_FirmwareUpdate_ErrorGetImageReteyOverRequestStop),
        cmocka_unit_test(test_FirmwareUpdate_ErrorGetImageReteyOverRequestStopInWaitingForRetry),
        cmocka_unit_test(test_FirmwareUpdate_ErrorEsfFwMgrWrite),
        cmocka_unit_test(test_FirmwareUpdate_ErrorEsfFwMgrClose),
        cmocka_unit_test(test_FirmwareUpdate_ErrorEsfFwMgrGetBinaryHeaderInfo),
        cmocka_unit_test(test_FirmwareUpdate_ErrorGetImageRetry),

        // ParseConfiguration()
        cmocka_unit_test(test_ParseConfiguration_FullySuccess),
        cmocka_unit_test(test_ParseConfiguration_ErrorEsfJsonOpen),
        cmocka_unit_test(test_ParseConfiguration_ErrorEsfJsonDeserialize),
        cmocka_unit_test(test_ParseConfiguration_ErrorGetConfigurationDeployConfigurationProperty),

        // StartDeploy()
        cmocka_unit_test(test_StartDeploy_ErrorParse),
        cmocka_unit_test(test_StartDeploy_AlreadyDeployed),
        cmocka_unit_test(test_StartDeploy_ExecDeploy),
        cmocka_unit_test(test_StartDeploy_ErrorCheckVersion),
        cmocka_unit_test(test_StartDeploy_ErrorDeleteAiModel),

        // DeployMain()
        cmocka_unit_test(test_DeployMain_ErrorMsgNULL),
        cmocka_unit_test(test_DeployMain_ErrorMsgTimedout),
        cmocka_unit_test(test_DeployMain_ErrorMsgError),
        cmocka_unit_test(test_DeployMain_ErrorPreReboot),
        cmocka_unit_test(test_DeployMain_ReceiveDeployMsgNotExecDeploy),
        cmocka_unit_test(test_DeployMain_ReceiveDeployMsgConfigErr),
        cmocka_unit_test(test_DeployMain_ReceiveDeployMsgFreeMemory),

        // DeleteAiModel()
        cmocka_unit_test(test_DeleteAiModel_FullySuccess),
        cmocka_unit_test(test_DeleteAiModel_SuccessNonAimodel),
        cmocka_unit_test(test_DeleteAiModel_SucessSameVersion),
        cmocka_unit_test(test_DeleteAiModel_Cancel),
        cmocka_unit_test(test_DeleteAiModel_Timedout),
        cmocka_unit_test(test_DeleteAiModel_SucessRequestToStopForDownloadIsTrue),
        cmocka_unit_test(test_DeleteAiModel_SuccessFwMgrUnavilable),
        cmocka_unit_test(test_DeleteAiModel_ErrorTopicID),
        cmocka_unit_test(test_DeleteAiModel_ErrorResponseMalloc),
        cmocka_unit_test(test_DeleteAiModel_ErrorEsfFwMgrGetInfo),
        cmocka_unit_test(test_DeleteAiModel_ErrorEsfBase64Encode),
        cmocka_unit_test(test_DeleteAiModel_ErrorEsfMgrOpen),
        cmocka_unit_test(test_DeleteAiModel_ErrorEsfMgrErase),
        cmocka_unit_test(test_DeleteAiModel_ErrorEsfMgrClose),

        // StopLED
        cmocka_unit_test(test_StopLED_FullySuccess),

        // SysAppDeployGetCancel
        cmocka_unit_test(test_SysAppDeployGetCancel_FullySuccess),
        cmocka_unit_test(test_SysAppDeployGetCancel_ErrorMutex),

        // ClearCancelFlag
        cmocka_unit_test(test_ClearCancelFlag_ErrorMutex),

        // RetryProcessWhenFirmwareManagerIsUnavailable
        cmocka_unit_test(test_RetryProcessWhenFirmwareManagerIsUnavailable_FullySuccess),
        cmocka_unit_test(test_RetryProcessWhenFirmwareManagerIsUnavailable_ErrorSysAppDeploy),
        cmocka_unit_test(
            test_RetryProcessWhenFirmwareManagerIsUnavailable_SysAppUdIsThisRequestToStopForDownload),
        cmocka_unit_test(test_RetryProcessWhenFirmwareManagerIsUnavailable_Error_EsfJsonOpen),
        cmocka_unit_test(
            test_RetryProcessWhenFirmwareManagerIsUnavailable_Error_EsfJsonObjectInit1),
        cmocka_unit_test(test_RetryProcessWhenFirmwareManagerIsUnavailable_Error_EsfJsonArrayInit),
        cmocka_unit_test(
            test_RetryProcessWhenFirmwareManagerIsUnavailable_Error_EsfJsonObjectInit2),
        cmocka_unit_test(
            test_RetryProcessWhenFirmwareManagerIsUnavailable_Error_EsfJsonArrayAppend),
        cmocka_unit_test(test_RetryProcessWhenFirmwareManagerIsUnavailable_Error_EsfJsonObjectSet),
        cmocka_unit_test(test_RetryProcessWhenFirmwareManagerIsUnavailable_Error_EsfJsonSerialize),
        cmocka_unit_test(
            test_RetryProcessWhenFirmwareManagerIsUnavailable_Error_EsfJsonSerializeStrNull),
    };

    return (((cmocka_run_group_tests(tests, NULL, NULL)) == 0) ? 0 : 1);
}
