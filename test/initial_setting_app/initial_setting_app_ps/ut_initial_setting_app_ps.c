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
#include <stdlib.h>
#include <string.h>
#if defined(__NuttX__)
#include <nuttx/config.h>
#endif

#include "system_app_common.h"
#include "initial_setting_app_ps.h"
#include "led_manager.h"
#include "log_manager.h"
#include "ut_mock_codec_json.h"
#include "evp/agent.h"
#include "evp/sdk_sys.h"
#include "json/include/json.h"
#include "system_manager.h"
#include "power_manager.h"
#include "network_manager.h"
#include "clock_manager.h"
#include "clock_manager_setting.h"
#include "senscord/c_api/senscord_c_api.h"
#include "senscord/inference_stream/c_api/property_c_types.h"

static const char *telemetry_json_serialize = "TelemetryJsonSerialize";
static const EsfJsonHandle common_handle_val = (EsfJsonHandle)0x12345678;

// Provisioning Mode

typedef enum {
    IsaPsMode_Idle = 0,
    IsaPsMode_Operation,
    IsaPsMode_Enrollment,
    IsaPsMode_QrCode,
    IsaPsMode_Reboot,
    IsaPsModeNum
} IsaPsMode;

// Define DCS struct a little shorter

typedef struct SYS_client SYS_client;

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
} PsInfo;

extern EsfJsonErrorCode JsonOpenAndInit(EsfJsonHandle *handle, EsfJsonValue *val);
extern EsfJsonErrorCode JsonOpenAndDeserialize(EsfJsonHandle *handle, EsfJsonValue *val,
                                               const char *param);
extern void ResponseToDetailmsg(ResInfoContext *ctx, const char *req_id, int code);
extern RetCode MakeJsonResInfo(EsfJsonHandle handle, EsfJsonValue root, void *ctx);
extern RetCode GetDeviceManifest(bool *has_device_manifest, char *p_manifest,
                                 size_t *p_manifest_size);
extern RetCode SendStateCore(SYS_client *sys_client, const char *topic, const char *state);
extern RetCode GetReqInfoToSetResInfo(EsfJsonHandle esfj_handle, EsfJsonValue esfj_val,
                                      ResInfoContext *res_info);
extern RetCode EndpointSettings(SYS_client *sys_client, const char *topic, const char *config,
                                PsInfo *info);
extern bool GetEnrollmentData(bool *has_device_manifest, char **buf_manifest, char **buf_project_id,
                              char **buf_token);
extern void SendTelemetryEnrollmentCallback(SYS_client *client, enum SYS_callback_reason result,
                                            void *usr_data);
extern RetCode MakeJsonOfTelemetry(EsfJsonHandle *handle, char *device_manifest,
                                   char *device_manifest_key_name, char *project_id, char *token,
                                   int retry_count, const char **response);
extern void SendEnrollmentData(PsInfo *p_info);
extern RetCode SetResId(const char *param, ResInfoContext *info);
extern IsaPsErrorCode ReleaseEvpAgent(PsInfo *ps_info);
extern void ConfigurationCallback(SYS_client *, const char *topic, const char *config,
                                  enum SYS_type_configuration, enum SYS_callback_reason reason,
                                  void *usr_data);
extern void ResponseSendCompleteCallback(SYS_client *, enum SYS_callback_reason reason,
                                         void *context);
extern RetCode SendDirectCommandResponseCore(SYS_client *sys_handle, SYS_response_id cmd_id,
                                             const char *response);
extern RetCode SendDirectCommandResponse(SYS_client *sys_handle, SYS_response_id cmd_id,
                                         ResInfoContext *res_info);
extern void DirectCommandRebootCallback(SYS_client *, SYS_response_id cmd_id, const char *params,
                                        void *user_context);
extern RetCode CheckProjectIdAndRegisterToken(void);
extern RetCode SetDefaultEndpoint(PsInfo *ps_info);
extern RetCode SetupEvpAgent(PsInfo *ps_info);
extern void SetLedStatusForProvisioningService(void);

/*----------------------------------------------------------------------------*/
//
// task_create_delete_Success()
//
/*----------------------------------------------------------------------------*/
static void task_create_Success(void)
{
#if defined(__NuttX__)
    will_return(__wrap_task_create, 333);
#elif defined(__linux__)
    // Check evp_agent_startup
    will_return(__wrap_evp_agent_startup, 0);
#endif
    return;
}

/*----------------------------------------------------------------------------*/
//
// JsonOpenAndInit()
//
/*----------------------------------------------------------------------------*/
static void test_JsonOpenAndInit_FullySuccess(void **state)
{
    EsfJsonErrorCode esfj_ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    esfj_ret = JsonOpenAndInit(&handle_val, &val);

    assert_int_equal(esfj_ret, kEsfJsonSuccess);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_JsonOpenAndInit_ErrorEsfJsonOpen(void **state)
{
    EsfJsonErrorCode esfj_ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);

    esfj_ret = JsonOpenAndInit(&handle_val, &val);

    assert_int_equal(esfj_ret, kEsfJsonInternalError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_JsonOpenAndInit_ErrorEsfJsonObjectInit(void **state)
{
    EsfJsonErrorCode esfj_ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonInternalError);
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    esfj_ret = JsonOpenAndInit(&handle_val, &val);

    assert_int_equal(esfj_ret, kEsfJsonInternalError);

    return;
}

/*----------------------------------------------------------------------------*/
//
// JsonOpenAndDeserialize()
//
/*----------------------------------------------------------------------------*/
static void test_JsonOpenAndDeserialize_FullySuccess(void **state)
{
    EsfJsonErrorCode esfj_ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    const char *param = "name";

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, param);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    esfj_ret = JsonOpenAndDeserialize(&handle_val, &val, param);

    assert_int_equal(esfj_ret, kEsfJsonSuccess);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_JsonOpenAndDeserialize_ErrorEsfJsonOpen(void **state)
{
    EsfJsonErrorCode esfj_ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    const char *param = "name";

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);

    esfj_ret = JsonOpenAndDeserialize(&handle_val, &val, param);

    assert_int_equal(esfj_ret, kEsfJsonInternalError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_JsonOpenAndDeserialize_ErrorEsfJsonDeserialize(void **state)
{
    EsfJsonErrorCode esfj_ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    const char *param = "name";

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);
    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, param);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonInternalError);
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    esfj_ret = JsonOpenAndDeserialize(&handle_val, &val, param);

    assert_int_equal(esfj_ret, kEsfJsonInternalError);

    return;
}

/*----------------------------------------------------------------------------*/
//
// ResponseToDetailmsg()
//
/*----------------------------------------------------------------------------*/
static void test_ResponseToDetailmsg_ok(void **state)
{
    ResInfoContext res_info = {0};
    const char *req_id = "00001";
    int code = RESULT_CODE_OK;

    ResponseToDetailmsg(&res_info, req_id, code);

    assert_string_equal(res_info.res_id, "00001");
    assert_string_equal(res_info.detail_msg, "ok");

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ResponseToDetailmsg_unimplemented(void **state)
{
    ResInfoContext res_info = {0};
    const char *req_id = "00001";
    int code = RESULT_CODE_UNIMPLEMENTED;

    ResponseToDetailmsg(&res_info, req_id, code);

    assert_string_equal(res_info.res_id, "00001");
    assert_string_equal(res_info.detail_msg, "unimplemented");

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ResponseToDetailmsg_invalid_argument(void **state)
{
    ResInfoContext res_info = {0};
    const char *req_id = "00001";
    int code = RESULT_CODE_INVALID_ARGUMENT;

    ResponseToDetailmsg(&res_info, req_id, code);

    assert_string_equal(res_info.res_id, "00001");
    assert_string_equal(res_info.detail_msg, "invalid_argument");

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ResponseToDetailmsg_internal(void **state)
{
    ResInfoContext res_info = {0};
    const char *req_id = "00001";
    int code = RESULT_CODE_INTERNAL;

    ResponseToDetailmsg(&res_info, req_id, code);

    assert_string_equal(res_info.res_id, "00001");
    assert_string_equal(res_info.detail_msg, "internal");

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ResponseToDetailmsg_unknown(void **state)
{
    ResInfoContext res_info = {0};
    const char *req_id = "00001";
    int code = RESULT_CODE_UNKNOWN;

    ResponseToDetailmsg(&res_info, req_id, code);

    assert_string_equal(res_info.res_id, "00001");
    assert_string_equal(res_info.detail_msg, "unknown");

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ResponseToDetailmsg_ok_null(void **state)
{
    ResInfoContext res_info = {0};
    const char *req_id = NULL;
    int code = RESULT_CODE_OK;

    ResponseToDetailmsg(&res_info, req_id, code);

    assert_string_equal(res_info.detail_msg, "ok");

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ResponseToDetailmsg_unimplemented_null(void **state)
{
    ResInfoContext res_info = {0};
    const char *req_id = NULL;
    int code = RESULT_CODE_UNIMPLEMENTED;

    ResponseToDetailmsg(&res_info, req_id, code);

    assert_string_equal(res_info.detail_msg, "unimplemented");

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ResponseToDetailmsg_invalid_argument_null(void **state)
{
    ResInfoContext res_info = {0};
    const char *req_id = NULL;
    int code = RESULT_CODE_INVALID_ARGUMENT;

    ResponseToDetailmsg(&res_info, req_id, code);

    assert_string_equal(res_info.detail_msg, "invalid_argument");

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ResponseToDetailmsg_internal_null(void **state)
{
    ResInfoContext res_info = {0};
    const char *req_id = NULL;
    int code = RESULT_CODE_INTERNAL;

    ResponseToDetailmsg(&res_info, req_id, code);

    assert_string_equal(res_info.detail_msg, "internal");

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ResponseToDetailmsg_unknown_null(void **state)
{
    ResInfoContext res_info = {0};
    const char *req_id = NULL;
    int code = RESULT_CODE_UNKNOWN;

    ResponseToDetailmsg(&res_info, req_id, code);

    assert_string_equal(res_info.detail_msg, "unknown");

    return;
}

/*----------------------------------------------------------------------------*/
//
// MakeJsonResInfo()
//
/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfo_FullySuccess(void **state)
{
    ResInfoContext ctx = {.res_id = "Test", .code = 0, .detail_msg = "ok"};
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    RetCode ret;

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, parent_val);
    expect_not_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, NULL);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");

    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    ret = MakeJsonResInfo(handle_val, parent_val, (void *)&ctx);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
//
// GetDeviceManifest()
//
/*----------------------------------------------------------------------------*/
static void test_GetDeviceManifest_FullySuccess(void **state)
{
    RetCode ret;
    char manifest[10];
    char *p_manifest = (char *)manifest;
    size_t size_manifest_size = sizeof(manifest);
    bool has_device_manifest = false;

    will_return(__wrap_EsfSystemManagerGetDeviceManifest, p_manifest);
    will_return(__wrap_EsfSystemManagerGetDeviceManifest, kEsfSystemManagerResultOk);

    ret = GetDeviceManifest(&has_device_manifest, p_manifest, &size_manifest_size);

    assert_int_equal(ret, kRetOk);

    return;
}

#ifdef CONFIG_ARCH_CHIP_ESP32S3
/*----------------------------------------------------------------------------*/
static void test_GetDeviceManifest_Error_senscord_core_init(void **state)
{
    RetCode ret;
    char manifest[10];
    char *p_manifest = (char *)manifest;
    senscord_core_t core = 0;
    size_t size_manifest_size = sizeof(manifest);
    bool has_device_manifest = false;

    will_return(__wrap_EsfSystemManagerGetDeviceManifest, p_manifest);
    will_return(__wrap_EsfSystemManagerGetDeviceManifest, kEsfSystemManagerResultInternalError);

    expect_not_value(__wrap_senscord_core_init, core, NULL);
    will_return(__wrap_senscord_core_init, core);
    will_return(__wrap_senscord_core_init, -1);

    ret = GetDeviceManifest(&has_device_manifest, p_manifest, &size_manifest_size);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetDeviceManifest_Error_senscord_core_open_stream(void **state)
{
    RetCode ret;
    char manifest[10];
    char *p_manifest = (char *)manifest;
    size_t size_manifest_size = sizeof(manifest);
    senscord_core_t core = 0;
    senscord_stream_t scstream = 0;
    bool has_device_manifest = false;

    will_return(__wrap_EsfSystemManagerGetDeviceManifest, p_manifest);
    will_return(__wrap_EsfSystemManagerGetDeviceManifest, kEsfSystemManagerResultInternalError);

    expect_not_value(__wrap_senscord_core_init, core, NULL);
    will_return(__wrap_senscord_core_init, core);
    will_return(__wrap_senscord_core_init, 0);

    expect_value(__wrap_senscord_core_open_stream, core, core);
    expect_string(__wrap_senscord_core_open_stream, stream_key, "inference_stream");
    expect_not_value(__wrap_senscord_core_open_stream, stream, NULL);
    will_return(__wrap_senscord_core_open_stream, scstream);
    will_return(__wrap_senscord_core_open_stream, -1);

    ret = GetDeviceManifest(&has_device_manifest, p_manifest, &size_manifest_size);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetDeviceManifest_Error_senscord_stream_get_property(void **state)
{
    RetCode ret;
    char manifest[10];
    char *p_manifest = (char *)manifest;
    size_t size_manifest_size = sizeof(manifest);
    senscord_core_t core = 0;
    senscord_stream_t scstream = 0;
    struct senscord_info_string_property_t expect_str_prop = {0};
    bool has_device_manifest = false;

    will_return(__wrap_EsfSystemManagerGetDeviceManifest, p_manifest);
    will_return(__wrap_EsfSystemManagerGetDeviceManifest, kEsfSystemManagerResultInternalError);

    expect_not_value(__wrap_senscord_core_init, core, NULL);
    will_return(__wrap_senscord_core_init, core);
    will_return(__wrap_senscord_core_init, 0);

    expect_value(__wrap_senscord_core_open_stream, core, core);
    expect_string(__wrap_senscord_core_open_stream, stream_key, "inference_stream");
    expect_not_value(__wrap_senscord_core_open_stream, stream, NULL);
    will_return(__wrap_senscord_core_open_stream, scstream);
    will_return(__wrap_senscord_core_open_stream, 0);

    expect_value(__wrap_senscord_stream_get_property, stream, scstream);
    expect_string(__wrap_senscord_stream_get_property, property_key,
                  SENSCORD_INFO_STRING_PROPERTY_KEY);
    expect_value(__wrap_senscord_stream_get_property, value_size, sizeof(expect_str_prop));
    will_return(__wrap_senscord_stream_get_property, &expect_str_prop);
    will_return(__wrap_senscord_stream_get_property, -1);

    ret = GetDeviceManifest(&has_device_manifest, p_manifest, &size_manifest_size);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetDeviceManifest_NoError(void **state)
{
    RetCode ret;
    char manifest[10];
    char *p_manifest = (char *)manifest;
    size_t size_manifest_size = sizeof(manifest);
    senscord_core_t core = 0;
    senscord_stream_t scstream = 0;
    struct senscord_info_string_property_t expect_str_prop = {0};
    bool has_device_manifest = false;

    will_return(__wrap_EsfSystemManagerGetDeviceManifest, p_manifest);
    will_return(__wrap_EsfSystemManagerGetDeviceManifest, kEsfSystemManagerResultInternalError);

    expect_not_value(__wrap_senscord_core_init, core, NULL);
    will_return(__wrap_senscord_core_init, core);
    will_return(__wrap_senscord_core_init, 0);

    expect_value(__wrap_senscord_core_open_stream, core, core);
    expect_string(__wrap_senscord_core_open_stream, stream_key, "inference_stream");
    expect_not_value(__wrap_senscord_core_open_stream, stream, NULL);
    will_return(__wrap_senscord_core_open_stream, scstream);
    will_return(__wrap_senscord_core_open_stream, 0);

    expect_value(__wrap_senscord_stream_get_property, stream, scstream);
    expect_string(__wrap_senscord_stream_get_property, property_key,
                  SENSCORD_INFO_STRING_PROPERTY_KEY);
    expect_value(__wrap_senscord_stream_get_property, value_size, sizeof(expect_str_prop));
    will_return(__wrap_senscord_stream_get_property, &expect_str_prop);
    will_return(__wrap_senscord_stream_get_property, 0);

    ret = GetDeviceManifest(&has_device_manifest, p_manifest, &size_manifest_size);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetDeviceManifest_senscord_InitZero_OpenNotZero(void **state)
{
    RetCode ret;
    char manifest[10];
    char *p_manifest = (char *)manifest;
    size_t size_manifest_size = sizeof(manifest);
    senscord_core_t core = 0;
    senscord_stream_t scstream = 4567;
    struct senscord_info_string_property_t expect_str_prop = {0};
    bool has_device_manifest = false;

    will_return(__wrap_EsfSystemManagerGetDeviceManifest, p_manifest);
    will_return(__wrap_EsfSystemManagerGetDeviceManifest, kEsfSystemManagerResultInternalError);

    expect_not_value(__wrap_senscord_core_init, core, NULL);
    will_return(__wrap_senscord_core_init, core);
    will_return(__wrap_senscord_core_init, 0);

    expect_value(__wrap_senscord_core_open_stream, core, core);
    expect_string(__wrap_senscord_core_open_stream, stream_key, "inference_stream");
    expect_not_value(__wrap_senscord_core_open_stream, stream, NULL);
    will_return(__wrap_senscord_core_open_stream, scstream);
    will_return(__wrap_senscord_core_open_stream, 0);

    expect_value(__wrap_senscord_stream_get_property, stream, scstream);
    expect_string(__wrap_senscord_stream_get_property, property_key,
                  SENSCORD_INFO_STRING_PROPERTY_KEY);
    expect_value(__wrap_senscord_stream_get_property, value_size, sizeof(expect_str_prop));
    will_return(__wrap_senscord_stream_get_property, &expect_str_prop);
    will_return(__wrap_senscord_stream_get_property, 0);

    ret = GetDeviceManifest(&has_device_manifest, p_manifest, &size_manifest_size);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetDeviceManifest_senscord_InitNotZero_OpenZero(void **state)
{
    RetCode ret;
    char manifest[10];
    char *p_manifest = (char *)manifest;
    size_t size_manifest_size = sizeof(manifest);
    senscord_core_t core = 1234;
    senscord_stream_t scstream = 0;
    struct senscord_info_string_property_t expect_str_prop = {0};
    bool has_device_manifest = false;

    will_return(__wrap_EsfSystemManagerGetDeviceManifest, p_manifest);
    will_return(__wrap_EsfSystemManagerGetDeviceManifest, kEsfSystemManagerResultInternalError);

    expect_not_value(__wrap_senscord_core_init, core, NULL);
    will_return(__wrap_senscord_core_init, core);
    will_return(__wrap_senscord_core_init, 0);

    expect_value(__wrap_senscord_core_open_stream, core, core);
    expect_string(__wrap_senscord_core_open_stream, stream_key, "inference_stream");
    expect_not_value(__wrap_senscord_core_open_stream, stream, NULL);
    will_return(__wrap_senscord_core_open_stream, scstream);
    will_return(__wrap_senscord_core_open_stream, 0);

    expect_value(__wrap_senscord_stream_get_property, stream, scstream);
    expect_string(__wrap_senscord_stream_get_property, property_key,
                  SENSCORD_INFO_STRING_PROPERTY_KEY);
    expect_value(__wrap_senscord_stream_get_property, value_size, sizeof(expect_str_prop));
    will_return(__wrap_senscord_stream_get_property, &expect_str_prop);
    will_return(__wrap_senscord_stream_get_property, 0);

    expect_value(__wrap_senscord_core_exit, core, core);
    will_return(__wrap_senscord_core_exit, 0);

    ret = GetDeviceManifest(&has_device_manifest, p_manifest, &size_manifest_size);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetDeviceManifest_senscord_InitNotZero_OpenNotZero(void **state)
{
    RetCode ret;
    char manifest[10];
    char *p_manifest = (char *)manifest;
    size_t size_manifest_size = sizeof(manifest);
    senscord_core_t core = 1234;
    senscord_stream_t scstream = 5678;
    struct senscord_info_string_property_t expect_str_prop = {0};
    bool has_device_manifest = false;

    will_return(__wrap_EsfSystemManagerGetDeviceManifest, p_manifest);
    will_return(__wrap_EsfSystemManagerGetDeviceManifest, kEsfSystemManagerResultInternalError);

    expect_not_value(__wrap_senscord_core_init, core, NULL);
    will_return(__wrap_senscord_core_init, core);
    will_return(__wrap_senscord_core_init, 0);

    expect_value(__wrap_senscord_core_open_stream, core, core);
    expect_string(__wrap_senscord_core_open_stream, stream_key, "inference_stream");
    expect_not_value(__wrap_senscord_core_open_stream, stream, NULL);
    will_return(__wrap_senscord_core_open_stream, scstream);
    will_return(__wrap_senscord_core_open_stream, 0);

    expect_value(__wrap_senscord_stream_get_property, stream, scstream);
    expect_string(__wrap_senscord_stream_get_property, property_key,
                  SENSCORD_INFO_STRING_PROPERTY_KEY);
    expect_value(__wrap_senscord_stream_get_property, value_size, sizeof(expect_str_prop));
    will_return(__wrap_senscord_stream_get_property, &expect_str_prop);
    will_return(__wrap_senscord_stream_get_property, 0);

    expect_value(__wrap_senscord_core_close_stream, core, core);
    expect_value(__wrap_senscord_core_close_stream, stream, scstream);
    will_return(__wrap_senscord_core_close_stream, 0);

    expect_value(__wrap_senscord_core_exit, core, core);
    will_return(__wrap_senscord_core_exit, 0);

    ret = GetDeviceManifest(&has_device_manifest, p_manifest, &size_manifest_size);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetDeviceManifest_MaxOverManifest(void **state)
{
    RetCode ret;
    char manifest[10];
    char *p_manifest = (char *)manifest;
    size_t size_manifest_size = sizeof(manifest);
    senscord_core_t core = 0;
    senscord_stream_t scstream = 0;
    struct senscord_info_string_property_t expect_str_prop = {.info = "1234567890"};
    bool has_device_manifest = false;

    will_return(__wrap_EsfSystemManagerGetDeviceManifest, p_manifest);
    will_return(__wrap_EsfSystemManagerGetDeviceManifest, kEsfSystemManagerResultInternalError);

    expect_not_value(__wrap_senscord_core_init, core, NULL);
    will_return(__wrap_senscord_core_init, core);
    will_return(__wrap_senscord_core_init, 0);

    expect_value(__wrap_senscord_core_open_stream, core, core);
    expect_string(__wrap_senscord_core_open_stream, stream_key, "inference_stream");
    expect_not_value(__wrap_senscord_core_open_stream, stream, NULL);
    will_return(__wrap_senscord_core_open_stream, scstream);
    will_return(__wrap_senscord_core_open_stream, 0);

    expect_value(__wrap_senscord_stream_get_property, stream, scstream);
    expect_string(__wrap_senscord_stream_get_property, property_key,
                  SENSCORD_INFO_STRING_PROPERTY_KEY);
    expect_value(__wrap_senscord_stream_get_property, value_size, sizeof(expect_str_prop));
    will_return(__wrap_senscord_stream_get_property, &expect_str_prop);
    will_return(__wrap_senscord_stream_get_property, 0);

    ret = GetDeviceManifest(&has_device_manifest, p_manifest, &size_manifest_size);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetDeviceManifest_MaxManifest(void **state)
{
    RetCode ret;
    char manifest[10];
    char *p_manifest = (char *)manifest;
    size_t size_manifest_size = sizeof(manifest);
    senscord_core_t core = 0;
    senscord_stream_t scstream = 0;
    struct senscord_info_string_property_t expect_str_prop = {.info = "123456789"};
    bool has_device_manifest = false;

    will_return(__wrap_EsfSystemManagerGetDeviceManifest, p_manifest);
    will_return(__wrap_EsfSystemManagerGetDeviceManifest, kEsfSystemManagerResultInternalError);

    expect_not_value(__wrap_senscord_core_init, core, NULL);
    will_return(__wrap_senscord_core_init, core);
    will_return(__wrap_senscord_core_init, 0);

    expect_value(__wrap_senscord_core_open_stream, core, core);
    expect_string(__wrap_senscord_core_open_stream, stream_key, "inference_stream");
    expect_not_value(__wrap_senscord_core_open_stream, stream, NULL);
    will_return(__wrap_senscord_core_open_stream, scstream);
    will_return(__wrap_senscord_core_open_stream, 0);

    expect_value(__wrap_senscord_stream_get_property, stream, scstream);
    expect_string(__wrap_senscord_stream_get_property, property_key,
                  SENSCORD_INFO_STRING_PROPERTY_KEY);
    expect_value(__wrap_senscord_stream_get_property, value_size, sizeof(expect_str_prop));
    will_return(__wrap_senscord_stream_get_property, &expect_str_prop);
    will_return(__wrap_senscord_stream_get_property, 0);

    ret = GetDeviceManifest(&has_device_manifest, p_manifest, &size_manifest_size);

    assert_int_equal(ret, kRetOk);

    return;
}
#else
/*----------------------------------------------------------------------------*/
static void test_GetDeviceManifest_MaxOverSerialNumber(void **state)
{
    RetCode ret;
    char manifest[10];
    char *p_manifest = (char *)manifest;
    size_t size_manifest_size = sizeof(manifest);
    bool has_device_manifest = false;

    will_return(__wrap_EsfSystemManagerGetDeviceManifest, p_manifest);
    will_return(__wrap_EsfSystemManagerGetDeviceManifest, kEsfSystemManagerResultInternalError);

    will_return(__wrap_EsfSystemManagerGetHwInfo, "sensor_id_over");
    will_return(__wrap_EsfSystemManagerGetHwInfo, kEsfSystemManagerResultOk);

    ret = GetDeviceManifest(&has_device_manifest, p_manifest, &size_manifest_size);

    assert_int_equal(ret, kRetFailed);

    return;
}
#endif

/*----------------------------------------------------------------------------*/
//
// SendStateCore()
//
/*----------------------------------------------------------------------------*/
static void test_SendStateCore_FullySuccess(void **state)
{
    RetCode ret;
    SYS_client *sys_client = {0};
    char *topic_val = "topic";
    char *state_val = "state";

    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    ret = SendStateCore(sys_client, topic_val, state_val);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendStateCore_Error_SYS_set_state(void **state)
{
    RetCode ret;
    SYS_client *sys_client = {0};
    char *topic_val = "topic";
    char *state_val = "state";

    will_return(__wrap_SYS_set_state, SYS_RESULT_TIMEDOUT);

    ret = SendStateCore(sys_client, topic_val, state_val);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendStateCore_FullySuccess_StateMaxLen(void **state)
{
    RetCode ret;
    SYS_client *sys_client = {0};
    char *topic_val = "topic";
    char *state_val =
        "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
        "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
        "1234567890123456789012345678901234567890123456789012345678901234567890123456";

    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    ret = SendStateCore(sys_client, topic_val, state_val);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
//
// GetReqInfoToSetResInfo()
//
/*----------------------------------------------------------------------------*/
static void test_GetReqInfoToSetResInfo_FullySuccess(void **state)
{
    RetCode ret;
    ResInfoContext ctx = {0};
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    const char *req_id_ptr = "TEST";

    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    ret = GetReqInfoToSetResInfo(handle_val, val, (void *)&ctx);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetReqInfoToSetResInfo_NotFound(void **state)
{
    RetCode ret;
    ResInfoContext ctx = {0};
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    const char *req_id_ptr = NULL;

    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetNotFound);

    ret = GetReqInfoToSetResInfo(handle_val, val, (void *)&ctx);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetReqInfoToSetResInfo_Other(void **state)
{
    RetCode ret;
    ResInfoContext ctx = {0};
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    const char *req_id_ptr = NULL;

    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetFailed);

    ret = GetReqInfoToSetResInfo(handle_val, val, (void *)&ctx);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetReqInfoToSetResInfo_MaxOverLen(void **state)
{
    RetCode ret;
    ResInfoContext ctx = {0};
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    const char *req_id_ptr =
        "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
        "123456789012345678901234567890123456789";

    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    ret = GetReqInfoToSetResInfo(handle_val, val, (void *)&ctx);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetReqInfoToSetResInfo_MaxLen(void **state)
{
    RetCode ret;
    ResInfoContext ctx = {0};
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    const char *req_id_ptr =
        "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678";

    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    ret = GetReqInfoToSetResInfo(handle_val, val, (void *)&ctx);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
//
// EndpointSettings()
//
/*----------------------------------------------------------------------------*/
static void EndpointSettings_FullySuccess(const char *config)
{
    static const char *state_val = "state";
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    static const char *req_id_ptr = "TEST";

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // malloc()
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // GetReqInfoToSetResInfo()

    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, state_val);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore()
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    expect_value(__wrap_EsfJsonSerializeFree, handle, handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    will_return(mock_free, false);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    return;
}

/*----------------------------------------------------------------------------*/
static void EndpointSettings_FullySuccess_Enrollment(const char *config)
{
    static const char *state_val = "state";
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    static const char *req_id_ptr = "TEST";
    int expect_endpoint_port = 8883;
    static const char *expect_endpoint_port_str = "8883";
    static const char *expect_endpoint_url = "test.jp";

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // malloc()
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // GetReqInfoToSetResInfo()

    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    expect_value(__wrap_SysAppCmnExtractStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractStringValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractStringValue, jsonkey, "endpoint_url");
    will_return(__wrap_SysAppCmnExtractStringValue, expect_endpoint_url);
    will_return(__wrap_SysAppCmnExtractStringValue, 1);

    expect_value(__wrap_SysAppCmnExtractNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractNumberValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractNumberValue, jsonkey, "endpoint_port");
    will_return(__wrap_SysAppCmnExtractNumberValue, expect_endpoint_port);
    will_return(__wrap_SysAppCmnExtractNumberValue, 1);

    expect_string(__wrap_EsfSystemManagerSetEvpHubUrl, data, expect_endpoint_url);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, expect_endpoint_port_str);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, val);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, res_id, req_id_ptr);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, state_val);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore()
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    expect_value(__wrap_EsfJsonSerializeFree, handle, handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    will_return(mock_free, false);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_EndpointSettings_FullySuccess(void **state)
{
    RetCode ret;
    struct SYS_client *sys_client = {0};
    char *topic_val = "topic";
    PsInfo info = {0};
    const char *config = "name";
    info.mode = IsaPsMode_Enrollment;

    EndpointSettings_FullySuccess_Enrollment(config);

    ret = EndpointSettings(sys_client, topic_val, config, &info);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_EndpointSettings_ErrorJsonOpenAndDeserialize(void **state)
{
    RetCode ret;
    struct SYS_client *sys_client = {0};
    char *topic_val = "topic";
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    PsInfo info = {0};
    const char *config = "name";

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);

    ret = EndpointSettings(sys_client, topic_val, config, &info);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_EndpointSettings_endpoint_port_AllocError(void **state)
{
    RetCode ret;
    struct SYS_client *sys_client = {0};
    char *topic_val = "topic";
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    PsInfo info = {0};
    const char *config = "name";

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // malloc()
    will_return(mock_malloc, true);
    will_return(mock_malloc, false);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    will_return(mock_free, false);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = EndpointSettings(sys_client, topic_val, config, &info);

    assert_int_equal(ret, kRetMemoryError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_EndpointSettings_ErrorSysAppCmnGetReqId(void **state)
{
    RetCode ret;
    struct SYS_client *sys_client = {0};
    char *topic_val = "topic";
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    PsInfo info = {0};
    const char *config = "name";
    const char *req_id_ptr = NULL;

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // malloc()
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // GetReqInfoToSetResInfo()

    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetFailed);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, val);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, res_id, "0");
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 3);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "invalid_argument");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, state);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore()
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    expect_value(__wrap_EsfJsonSerializeFree, handle, handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    will_return(mock_free, false);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = EndpointSettings(sys_client, topic_val, config, &info);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_EndpointSettings_ErrorEsfSystemManagerSetEvpHubUrlandPort(void **state)
{
    RetCode ret;
    struct SYS_client *sys_client = {0};
    char *topic_val = "topic";
    char *state_val = "state";
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    const char *req_id_ptr = "TEST";
    int expect_endpoint_port = 8883;
    static const char *expect_endpoint_port_str = "8883";
    const char *expect_endpoint_url = "test.jp";
    PsInfo info = {0};
    const char *config = "name";
    info.mode = IsaPsMode_Enrollment;
    snprintf(info.mqtt_host, sizeof(info.mqtt_host), "%s", "write back mqtt_host");
    info.mqtt_host_len = strlen(info.mqtt_host);
    snprintf(info.mqtt_port, sizeof(info.mqtt_port), "%s", "write back mqtt_port");
    info.mqtt_port_len = strlen(info.mqtt_port);

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // malloc()
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // GetReqInfoToSetResInfo()

    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    expect_value(__wrap_SysAppCmnExtractStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractStringValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractStringValue, jsonkey, "endpoint_url");
    will_return(__wrap_SysAppCmnExtractStringValue, expect_endpoint_url);
    will_return(__wrap_SysAppCmnExtractStringValue, 1);

    expect_value(__wrap_SysAppCmnExtractNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractNumberValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractNumberValue, jsonkey, "endpoint_port");
    will_return(__wrap_SysAppCmnExtractNumberValue, expect_endpoint_port);
    will_return(__wrap_SysAppCmnExtractNumberValue, 1);

    expect_string(__wrap_EsfSystemManagerSetEvpHubUrl, data, expect_endpoint_url);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultInternalError);

    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, expect_endpoint_port_str);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultInternalError);

    // write back
    expect_string(__wrap_EsfSystemManagerSetEvpHubUrl, data, info.mqtt_host);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size, info.mqtt_host_len);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, info.mqtt_port);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size, info.mqtt_port_len);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, val);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, res_id, req_id_ptr);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 13);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "internal");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, state_val);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore()
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    expect_value(__wrap_EsfJsonSerializeFree, handle, handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    will_return(mock_free, false);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = EndpointSettings(sys_client, topic_val, config, &info);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_EndpointSettings_ErrorEsfJsonClose(void **state)
{
    RetCode ret;
    struct SYS_client *sys_client = {0};
    char *topic_val = "topic";
    char *state_val = "state";
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    const char *req_id_ptr = "TEST";
    int expect_endpoint_port = 8883;
    const char *expect_endpoint_url = "test.jp";
    PsInfo info = {0};
    const char *config = "name";
    info.mode = IsaPsMode_Enrollment;

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // malloc()
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // GetReqInfoToSetResInfo()

    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    expect_value(__wrap_SysAppCmnExtractStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractStringValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractStringValue, jsonkey, "endpoint_url");
    will_return(__wrap_SysAppCmnExtractStringValue, expect_endpoint_url);
    will_return(__wrap_SysAppCmnExtractStringValue, 0);

    expect_value(__wrap_SysAppCmnExtractNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractNumberValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractNumberValue, jsonkey, "endpoint_port");
    will_return(__wrap_SysAppCmnExtractNumberValue, expect_endpoint_port);
    will_return(__wrap_SysAppCmnExtractNumberValue, 0);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, state_val);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore()
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    expect_value(__wrap_EsfJsonSerializeFree, handle, handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    will_return(mock_free, false);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonInternalError);

    ret = EndpointSettings(sys_client, topic_val, config, &info);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_EndpointSettings_ErrorSysAppCmnExtractStringValueEndpointUrl(void **state)
{
    RetCode ret;
    struct SYS_client *sys_client = {0};
    char *topic_val = "topic";
    PsInfo info = {0};
    const char *config = "name";
    info.mode = IsaPsMode_Enrollment;
    static const char *state_val = "state";
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    static const char *req_id_ptr = "TEST";
    int expect_endpoint_port = 8883;
    static const char *expect_endpoint_port_str = "8883";
    static const char *expect_endpoint_url = "test.jp";

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // malloc()
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // GetReqInfoToSetResInfo()

    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    expect_value(__wrap_SysAppCmnExtractStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractStringValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractStringValue, jsonkey, "endpoint_url");
    will_return(__wrap_SysAppCmnExtractStringValue, expect_endpoint_url);
    will_return(__wrap_SysAppCmnExtractStringValue, -1);

    expect_value(__wrap_SysAppCmnExtractNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractNumberValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractNumberValue, jsonkey, "endpoint_port");
    will_return(__wrap_SysAppCmnExtractNumberValue, expect_endpoint_port);
    will_return(__wrap_SysAppCmnExtractNumberValue, 1);

    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, expect_endpoint_port_str);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, val);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, res_id, req_id_ptr);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, state_val);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore()
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    expect_value(__wrap_EsfJsonSerializeFree, handle, handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    will_return(mock_free, false);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = EndpointSettings(sys_client, topic_val, config, &info);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_EndpointSettings_MaxOverLenEndpointUrl(void **state)
{
    RetCode ret;
    struct SYS_client *sys_client = {0};
    char *topic_val = "topic";
    PsInfo info = {0};
    const char *config = "name";
    info.mode = IsaPsMode_Enrollment;
    static const char *state_val = "state";
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    static const char *req_id_ptr = "TEST";
    int expect_endpoint_port = 8883;
    static const char *expect_endpoint_port_str = "8883";
    static const char *expect_endpoint_url =
        "12345678901234567890123456789012345678901234567890123456789012345";

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // malloc()
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // GetReqInfoToSetResInfo()

    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    expect_value(__wrap_SysAppCmnExtractStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractStringValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractStringValue, jsonkey, "endpoint_url");
    will_return(__wrap_SysAppCmnExtractStringValue, expect_endpoint_url);
    will_return(__wrap_SysAppCmnExtractStringValue, 1);

    expect_value(__wrap_SysAppCmnExtractNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractNumberValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractNumberValue, jsonkey, "endpoint_port");
    will_return(__wrap_SysAppCmnExtractNumberValue, expect_endpoint_port);
    will_return(__wrap_SysAppCmnExtractNumberValue, 1);

    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, expect_endpoint_port_str);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, val);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, res_id, req_id_ptr);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 3);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "invalid_argument");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, state_val);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore()
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    expect_value(__wrap_EsfJsonSerializeFree, handle, handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    will_return(mock_free, false);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = EndpointSettings(sys_client, topic_val, config, &info);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_EndpointSettings_MaxLenEndpointUrl(void **state)
{
    RetCode ret;
    struct SYS_client *sys_client = {0};
    char *topic_val = "topic";
    PsInfo info = {0};
    const char *config = "name";
    info.mode = IsaPsMode_Enrollment;
    static const char *state_val = "state";
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    static const char *req_id_ptr = "TEST";
    int expect_endpoint_port = 8883;
    static const char *expect_endpoint_port_str = "8883";
    static const char *expect_endpoint_url =
        "1234567890123456789012345678901234567890123456789012345678901234";

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // malloc()
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // GetReqInfoToSetResInfo()

    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    expect_value(__wrap_SysAppCmnExtractStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractStringValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractStringValue, jsonkey, "endpoint_url");
    will_return(__wrap_SysAppCmnExtractStringValue, expect_endpoint_url);
    will_return(__wrap_SysAppCmnExtractStringValue, 1);

    expect_string(__wrap_EsfSystemManagerSetEvpHubUrl, data, expect_endpoint_url);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    expect_value(__wrap_SysAppCmnExtractNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractNumberValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractNumberValue, jsonkey, "endpoint_port");
    will_return(__wrap_SysAppCmnExtractNumberValue, expect_endpoint_port);
    will_return(__wrap_SysAppCmnExtractNumberValue, 1);

    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, expect_endpoint_port_str);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, val);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, res_id, req_id_ptr);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, state_val);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore()
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    expect_value(__wrap_EsfJsonSerializeFree, handle, handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    will_return(mock_free, false);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = EndpointSettings(sys_client, topic_val, config, &info);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_EndpointSettings_ErrorSysAppCmnExtractNumberValueEndpointPort(void **state)
{
    RetCode ret;
    struct SYS_client *sys_client = {0};
    char *topic_val = "topic";
    PsInfo info = {0};
    const char *config = "name";
    info.mode = IsaPsMode_Enrollment;
    static const char *state_val = "state";
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    static const char *req_id_ptr = "TEST";
    int expect_endpoint_port = 8883;
    static const char *expect_endpoint_url = "test.jp";

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // malloc()
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // GetReqInfoToSetResInfo()

    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    expect_value(__wrap_SysAppCmnExtractStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractStringValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractStringValue, jsonkey, "endpoint_url");
    will_return(__wrap_SysAppCmnExtractStringValue, expect_endpoint_url);
    will_return(__wrap_SysAppCmnExtractStringValue, 1);

    expect_string(__wrap_EsfSystemManagerSetEvpHubUrl, data, expect_endpoint_url);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    expect_value(__wrap_SysAppCmnExtractNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractNumberValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractNumberValue, jsonkey, "endpoint_port");
    will_return(__wrap_SysAppCmnExtractNumberValue, expect_endpoint_port);
    will_return(__wrap_SysAppCmnExtractNumberValue, -1);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, val);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, res_id, req_id_ptr);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, state_val);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore()
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    expect_value(__wrap_EsfJsonSerializeFree, handle, handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    will_return(mock_free, false);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = EndpointSettings(sys_client, topic_val, config, &info);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_EndpointSettings_MinOverEndpointPort(void **state)
{
    RetCode ret;
    struct SYS_client *sys_client = {0};
    char *topic_val = "topic";
    PsInfo info = {0};
    const char *config = "name";
    info.mode = IsaPsMode_Enrollment;
    static const char *state_val = "state";
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    static const char *req_id_ptr = "TEST";
    int expect_endpoint_port = -1;
    static const char *expect_endpoint_url = "test.jp";

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // malloc()
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // GetReqInfoToSetResInfo()

    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    expect_value(__wrap_SysAppCmnExtractStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractStringValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractStringValue, jsonkey, "endpoint_url");
    will_return(__wrap_SysAppCmnExtractStringValue, expect_endpoint_url);
    will_return(__wrap_SysAppCmnExtractStringValue, 1);

    expect_string(__wrap_EsfSystemManagerSetEvpHubUrl, data, expect_endpoint_url);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    expect_value(__wrap_SysAppCmnExtractNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractNumberValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractNumberValue, jsonkey, "endpoint_port");
    will_return(__wrap_SysAppCmnExtractNumberValue, expect_endpoint_port);
    will_return(__wrap_SysAppCmnExtractNumberValue, 1);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, val);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, res_id, req_id_ptr);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 3);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "invalid_argument");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, state_val);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore()
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    expect_value(__wrap_EsfJsonSerializeFree, handle, handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    will_return(mock_free, false);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = EndpointSettings(sys_client, topic_val, config, &info);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_EndpointSettings_MinEndpointPort(void **state)
{
    RetCode ret;
    struct SYS_client *sys_client = {0};
    char *topic_val = "topic";
    PsInfo info = {0};
    const char *config = "name";
    info.mode = IsaPsMode_Enrollment;
    static const char *state_val = "state";
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    static const char *req_id_ptr = "TEST";
    int expect_endpoint_port = 0;
    static const char *expect_endpoint_port_str = "0";
    static const char *expect_endpoint_url = "test.jp";

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // malloc()
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // GetReqInfoToSetResInfo()

    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    expect_value(__wrap_SysAppCmnExtractStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractStringValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractStringValue, jsonkey, "endpoint_url");
    will_return(__wrap_SysAppCmnExtractStringValue, expect_endpoint_url);
    will_return(__wrap_SysAppCmnExtractStringValue, 1);

    expect_string(__wrap_EsfSystemManagerSetEvpHubUrl, data, expect_endpoint_url);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    expect_value(__wrap_SysAppCmnExtractNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractNumberValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractNumberValue, jsonkey, "endpoint_port");
    will_return(__wrap_SysAppCmnExtractNumberValue, expect_endpoint_port);
    will_return(__wrap_SysAppCmnExtractNumberValue, 1);

    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, expect_endpoint_port_str);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, val);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, res_id, req_id_ptr);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, state_val);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore()
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    expect_value(__wrap_EsfJsonSerializeFree, handle, handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    will_return(mock_free, false);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = EndpointSettings(sys_client, topic_val, config, &info);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_EndpointSettings_MaxEndpointPort(void **state)
{
    RetCode ret;
    struct SYS_client *sys_client = {0};
    char *topic_val = "topic";
    PsInfo info = {0};
    const char *config = "name";
    info.mode = IsaPsMode_Enrollment;
    static const char *state_val = "state";
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    static const char *req_id_ptr = "TEST";
    int expect_endpoint_port = 65535;
    static const char *expect_endpoint_port_str = "65535";
    static const char *expect_endpoint_url = "test.jp";

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // malloc()
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // GetReqInfoToSetResInfo()

    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    expect_value(__wrap_SysAppCmnExtractStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractStringValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractStringValue, jsonkey, "endpoint_url");
    will_return(__wrap_SysAppCmnExtractStringValue, expect_endpoint_url);
    will_return(__wrap_SysAppCmnExtractStringValue, 1);

    expect_string(__wrap_EsfSystemManagerSetEvpHubUrl, data, expect_endpoint_url);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    expect_value(__wrap_SysAppCmnExtractNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractNumberValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractNumberValue, jsonkey, "endpoint_port");
    will_return(__wrap_SysAppCmnExtractNumberValue, expect_endpoint_port);
    will_return(__wrap_SysAppCmnExtractNumberValue, 1);

    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, expect_endpoint_port_str);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, val);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, res_id, req_id_ptr);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, state_val);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore()
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    expect_value(__wrap_EsfJsonSerializeFree, handle, handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    will_return(mock_free, false);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = EndpointSettings(sys_client, topic_val, config, &info);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_EndpointSettings_MaxOverEndpointPort(void **state)
{
    RetCode ret;
    struct SYS_client *sys_client = {0};
    char *topic_val = "topic";
    PsInfo info = {0};
    const char *config = "name";
    info.mode = IsaPsMode_Enrollment;
    static const char *state_val = "state";
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    static const char *req_id_ptr = "TEST";
    int expect_endpoint_port = 65536;
    static const char *expect_endpoint_url = "test.jp";

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // malloc()
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // GetReqInfoToSetResInfo()

    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    expect_value(__wrap_SysAppCmnExtractStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractStringValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractStringValue, jsonkey, "endpoint_url");
    will_return(__wrap_SysAppCmnExtractStringValue, expect_endpoint_url);
    will_return(__wrap_SysAppCmnExtractStringValue, 1);

    expect_string(__wrap_EsfSystemManagerSetEvpHubUrl, data, expect_endpoint_url);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    expect_value(__wrap_SysAppCmnExtractNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractNumberValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractNumberValue, jsonkey, "endpoint_port");
    will_return(__wrap_SysAppCmnExtractNumberValue, expect_endpoint_port);
    will_return(__wrap_SysAppCmnExtractNumberValue, 1);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, val);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, res_id, req_id_ptr);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 3);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "invalid_argument");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, state_val);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // SendStateCore()
    will_return(__wrap_SYS_set_state, SYS_RESULT_OK);

    expect_value(__wrap_EsfJsonSerializeFree, handle, handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    will_return(mock_free, false);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = EndpointSettings(sys_client, topic_val, config, &info);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_EndpointSettings_ErrorEsfJsonSerialize(void **state)
{
    RetCode ret;
    struct SYS_client *sys_client = {0};
    char *topic_val = "topic";
    PsInfo info = {0};
    const char *config = "name";
    info.mode = IsaPsMode_Enrollment;
    static const char *state_val = "state";
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    static const char *req_id_ptr = "TEST";
    int expect_endpoint_port = 8883;
    static const char *expect_endpoint_port_str = "8883";
    static const char *expect_endpoint_url = "test.jp";

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // malloc()
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // GetReqInfoToSetResInfo()

    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    expect_value(__wrap_SysAppCmnExtractStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractStringValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractStringValue, jsonkey, "endpoint_url");
    will_return(__wrap_SysAppCmnExtractStringValue, expect_endpoint_url);
    will_return(__wrap_SysAppCmnExtractStringValue, 1);

    expect_string(__wrap_EsfSystemManagerSetEvpHubUrl, data, expect_endpoint_url);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    expect_value(__wrap_SysAppCmnExtractNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractNumberValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractNumberValue, jsonkey, "endpoint_port");
    will_return(__wrap_SysAppCmnExtractNumberValue, expect_endpoint_port);
    will_return(__wrap_SysAppCmnExtractNumberValue, 1);

    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, expect_endpoint_port_str);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, state_val);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonInternalError);

    will_return(mock_free, false);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = EndpointSettings(sys_client, topic_val, config, &info);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_EndpointSettings_NullEsfJsonSerialize(void **state)
{
    RetCode ret;
    struct SYS_client *sys_client = {0};
    char *topic_val = "topic";
    PsInfo info = {0};
    const char *config = "name";
    info.mode = IsaPsMode_Enrollment;
    static const char *state_val = NULL;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    static const char *req_id_ptr = "TEST";
    int expect_endpoint_port = 8883;
    static const char *expect_endpoint_port_str = "8883";
    static const char *expect_endpoint_url = "test.jp";

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // malloc()
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // GetReqInfoToSetResInfo()

    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    expect_value(__wrap_SysAppCmnExtractStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractStringValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractStringValue, jsonkey, "endpoint_url");
    will_return(__wrap_SysAppCmnExtractStringValue, expect_endpoint_url);
    will_return(__wrap_SysAppCmnExtractStringValue, 1);

    expect_string(__wrap_EsfSystemManagerSetEvpHubUrl, data, expect_endpoint_url);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    expect_value(__wrap_SysAppCmnExtractNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractNumberValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractNumberValue, jsonkey, "endpoint_port");
    will_return(__wrap_SysAppCmnExtractNumberValue, expect_endpoint_port);
    will_return(__wrap_SysAppCmnExtractNumberValue, 1);

    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, expect_endpoint_port_str);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, false);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, state_val);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    will_return(mock_free, false);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = EndpointSettings(sys_client, topic_val, config, &info);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
//
// GetEnrollmentData()
//
/*----------------------------------------------------------------------------*/
static void GetEnrollmentData_FullySuccess(void)
{
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_DEVICE_MANIFEST_MAX_SIZE);

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_PROJECT_ID_MAX_SIZE);

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_REGISTER_TOKEN_MAX_SIZE);

    will_return(__wrap_EsfSystemManagerGetDeviceManifest, "manifest");
    will_return(__wrap_EsfSystemManagerGetDeviceManifest, kEsfSystemManagerResultOk);

    will_return(__wrap_EsfSystemManagerGetProjectId, "project_id");
    will_return(__wrap_EsfSystemManagerGetProjectId, kEsfSystemManagerResultOk);

    will_return(__wrap_EsfSystemManagerGetRegisterToken, "token");
    will_return(__wrap_EsfSystemManagerGetRegisterToken, kEsfSystemManagerResultOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void GetEnrollmentData_SensorIdInsteadOfDeviceManifest(void)
{
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_DEVICE_MANIFEST_MAX_SIZE);

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_PROJECT_ID_MAX_SIZE);

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_REGISTER_TOKEN_MAX_SIZE);

    /* For test that get SensorID instead of DeviceManifest,
   * set up mock to make EsfSystemManagerGetDeviceManifest() fail. */

    will_return(__wrap_EsfSystemManagerGetDeviceManifest, "manifest");
    will_return(__wrap_EsfSystemManagerGetDeviceManifest, kEsfSystemManagerResultInternalError);

#ifdef CONFIG_ARCH_CHIP_ESP32S3
    senscord_core_t core = 0;
    senscord_stream_t scstream = 0;
    static struct senscord_info_string_property_t expect_str_prop = {.info = "sensor_id"};

    expect_not_value(__wrap_senscord_core_init, core, NULL);
    will_return(__wrap_senscord_core_init, core);
    will_return(__wrap_senscord_core_init, 0);

    expect_value(__wrap_senscord_core_open_stream, core, core);
    expect_string(__wrap_senscord_core_open_stream, stream_key, "inference_stream");
    expect_not_value(__wrap_senscord_core_open_stream, stream, NULL);
    will_return(__wrap_senscord_core_open_stream, scstream);
    will_return(__wrap_senscord_core_open_stream, 0);

    expect_value(__wrap_senscord_stream_get_property, stream, scstream);
    expect_string(__wrap_senscord_stream_get_property, property_key,
                  SENSCORD_INFO_STRING_PROPERTY_KEY);
    expect_value(__wrap_senscord_stream_get_property, value_size, sizeof(expect_str_prop));
    will_return(__wrap_senscord_stream_get_property, &expect_str_prop);
    will_return(__wrap_senscord_stream_get_property, 0);
#else
    will_return(__wrap_EsfSystemManagerGetHwInfo, "sensor_id");
    will_return(__wrap_EsfSystemManagerGetHwInfo, kEsfSystemManagerResultOk);
#endif

    will_return(__wrap_EsfSystemManagerGetProjectId, "project_id");
    will_return(__wrap_EsfSystemManagerGetProjectId, kEsfSystemManagerResultOk);

    will_return(__wrap_EsfSystemManagerGetRegisterToken, "token");
    will_return(__wrap_EsfSystemManagerGetRegisterToken, kEsfSystemManagerResultOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetEnrollmentData_FullySuccess(void **state)
{
    bool ret;
    char *device_manifest;
    char *project_id;
    char *token;
    bool has_device_manifest = false;

    GetEnrollmentData_FullySuccess();

    ret = GetEnrollmentData(&has_device_manifest, &device_manifest, &project_id, &token);

    assert_true(ret);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetEnrollmentData_device_manifest_AllocError(void **state)
{
    bool ret;
    char *device_manifest;
    char *project_id;
    char *token;
    bool has_device_manifest = false;

    will_return(mock_malloc, true);
    will_return(mock_malloc, false);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_DEVICE_MANIFEST_MAX_SIZE);

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_PROJECT_ID_MAX_SIZE);

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_REGISTER_TOKEN_MAX_SIZE);

    will_return(mock_free, false);
    will_return(mock_free, false);

    ret = GetEnrollmentData(&has_device_manifest, &device_manifest, &project_id, &token);

    assert_false(ret);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetEnrollmentData_project_id_AllocError(void **state)
{
    bool ret;
    char *device_manifest;
    char *project_id;
    char *token;
    bool has_device_manifest = false;

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_DEVICE_MANIFEST_MAX_SIZE);

    will_return(mock_malloc, true);
    will_return(mock_malloc, false);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_PROJECT_ID_MAX_SIZE);

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_REGISTER_TOKEN_MAX_SIZE);

    will_return(mock_free, false);
    will_return(mock_free, false);

    ret = GetEnrollmentData(&has_device_manifest, &device_manifest, &project_id, &token);

    assert_false(ret);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetEnrollmentData_register_token_AllocError(void **state)
{
    bool ret;
    char *device_manifest;
    char *project_id;
    char *token;
    bool has_device_manifest = false;

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_DEVICE_MANIFEST_MAX_SIZE);

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_PROJECT_ID_MAX_SIZE);

    will_return(mock_malloc, true);
    will_return(mock_malloc, false);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_REGISTER_TOKEN_MAX_SIZE);

    will_return(mock_free, false);
    will_return(mock_free, false);

    ret = GetEnrollmentData(&has_device_manifest, &device_manifest, &project_id, &token);

    assert_false(ret);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetEnrollmentData_ErrorEsfSystemManagerGetDeviceManifest(void **state)
{
    bool ret;
    char *device_manifest;
    char *project_id;
    char *token;
    char *p_manifest;
    bool has_device_manifest = false;

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_DEVICE_MANIFEST_MAX_SIZE);

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_PROJECT_ID_MAX_SIZE);

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_REGISTER_TOKEN_MAX_SIZE);

    will_return(__wrap_EsfSystemManagerGetDeviceManifest, p_manifest);
    will_return(__wrap_EsfSystemManagerGetDeviceManifest, kEsfSystemManagerResultInternalError);

#ifdef CONFIG_ARCH_CHIP_ESP32S3
    expect_not_value(__wrap_senscord_core_init, core, NULL);
    will_return(__wrap_senscord_core_init, 1234);
    will_return(__wrap_senscord_core_init, -1);
#else
    will_return(__wrap_EsfSystemManagerGetHwInfo, "sensor_id");
    will_return(__wrap_EsfSystemManagerGetHwInfo, kEsfSystemManagerResultInternalError);
#endif

    will_return(mock_free, false);
    will_return(mock_free, false);
    will_return(mock_free, false);

    ret = GetEnrollmentData(&has_device_manifest, &device_manifest, &project_id, &token);

    assert_false(ret);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetEnrollmentData_ErrorEsfSystemManagerGetProjectId(void **state)
{
    bool ret;
    char *device_manifest;
    char *project_id;
    char *token;
    char *p_manifest;
    bool has_device_manifest = false;

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_DEVICE_MANIFEST_MAX_SIZE);

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_PROJECT_ID_MAX_SIZE);

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_REGISTER_TOKEN_MAX_SIZE);

    will_return(__wrap_EsfSystemManagerGetDeviceManifest, p_manifest);
    will_return(__wrap_EsfSystemManagerGetDeviceManifest, kEsfSystemManagerResultOk);

    will_return(__wrap_EsfSystemManagerGetProjectId, "unittest_project_id");
    will_return(__wrap_EsfSystemManagerGetProjectId, kEsfSystemManagerResultInternalError);

    will_return(mock_free, false);
    will_return(mock_free, false);
    will_return(mock_free, false);

    ret = GetEnrollmentData(&has_device_manifest, &device_manifest, &project_id, &token);

    assert_false(ret);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_GetEnrollmentData_ErrorEsfSystemManagerGetRegisterToken(void **state)
{
    bool ret;
    char *device_manifest;
    char *project_id;
    char *token;
    char *p_manifest;
    bool has_device_manifest = false;

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_DEVICE_MANIFEST_MAX_SIZE);

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_PROJECT_ID_MAX_SIZE);

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_REGISTER_TOKEN_MAX_SIZE);

    will_return(__wrap_EsfSystemManagerGetDeviceManifest, p_manifest);
    will_return(__wrap_EsfSystemManagerGetDeviceManifest, kEsfSystemManagerResultOk);

    will_return(__wrap_EsfSystemManagerGetProjectId, "unittest_project_id");
    will_return(__wrap_EsfSystemManagerGetProjectId, kEsfSystemManagerResultOk);

    will_return(__wrap_EsfSystemManagerGetRegisterToken, "unittest_register_token");
    will_return(__wrap_EsfSystemManagerGetRegisterToken, kEsfSystemManagerResultInternalError);

    will_return(mock_free, false);
    will_return(mock_free, false);
    will_return(mock_free, false);

    ret = GetEnrollmentData(&has_device_manifest, &device_manifest, &project_id, &token);

    assert_false(ret);

    return;
}

/*----------------------------------------------------------------------------*/
//
// SendTelemetryEnrollmentCallback()
//
/*----------------------------------------------------------------------------*/
static void test_SendTelemetryEnrollmentCallback_Finished(void **state)
{
    SYS_client *sys_client = {0};
    TelemetryInfo info = {.complete = false, .result = SYS_REASON_FINISHED};

    SendTelemetryEnrollmentCallback(sys_client, SYS_REASON_FINISHED, &info);

    assert_int_equal(info.result, SYS_REASON_FINISHED);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendTelemetryEnrollmentCallback_Error(void **state)
{
    SYS_client *sys_client = {0};
    TelemetryInfo info = {.complete = false, .result = SYS_REASON_ERROR};

    SendTelemetryEnrollmentCallback(sys_client, SYS_REASON_ERROR, &info);

    assert_int_equal(info.result, SYS_REASON_ERROR);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendTelemetryEnrollmentCallback_Timeout(void **state)
{
    SYS_client *sys_client = {0};
    TelemetryInfo info = {.complete = false, .result = SYS_REASON_TIMEOUT};

    SendTelemetryEnrollmentCallback(sys_client, SYS_REASON_TIMEOUT, &info);

    assert_int_equal(info.result, SYS_REASON_TIMEOUT);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendTelemetryEnrollmentCallback_Default(void **state)
{
    SYS_client *sys_client = {0};
    TelemetryInfo info = {.complete = false, .result = SYS_REASON_MORE_DATA};

    SendTelemetryEnrollmentCallback(sys_client, SYS_REASON_MORE_DATA, &info);

    assert_int_equal(info.result, SYS_REASON_MORE_DATA);

    return;
}

/*----------------------------------------------------------------------------*/
//
// MakeJsonOfTelemetry()
//
/*----------------------------------------------------------------------------*/
static void MakeJsonOfTelemetry_FullySuccess(int retry_cnt)
{
    static const char *device_manifest = "manifest";
    static const char *project_id = "project_id";
    static const char *token = "token";
    EsfJsonValue val = 1357;

    will_return(__wrap_EsfJsonOpen, common_handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectInit, handle, common_handle_val);
    will_return(__wrap_EsfJsonObjectInit, val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetStringValue, handle, common_handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "project_id");
    expect_string(__wrap_SysAppCmnSetStringValue, string, project_id);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    expect_value(__wrap_SysAppCmnSetStringValue, handle, common_handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "token");
    expect_string(__wrap_SysAppCmnSetStringValue, string, token);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    expect_value(__wrap_SysAppCmnSetStringValue, handle, common_handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "device_manifest");
    expect_string(__wrap_SysAppCmnSetStringValue, string, device_manifest);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    expect_value(__wrap_SysAppCmnSetNumberValue, handle, common_handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "retry_count");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, retry_cnt);
    will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, common_handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, telemetry_json_serialize);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    return;
}

/*----------------------------------------------------------------------------*/
static void MakeJsonOfTelemetry_SetSensorIdInsteadOfDeviceManifest(int retry_cnt)
{
    static const char *device_manifest = "sensor_id";
    static const char *project_id = "project_id";
    static const char *token = "token";
    EsfJsonValue val = 1357;

    will_return(__wrap_EsfJsonOpen, common_handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectInit, handle, common_handle_val);
    will_return(__wrap_EsfJsonObjectInit, val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetStringValue, handle, common_handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "project_id");
    expect_string(__wrap_SysAppCmnSetStringValue, string, project_id);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    expect_value(__wrap_SysAppCmnSetStringValue, handle, common_handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "token");
    expect_string(__wrap_SysAppCmnSetStringValue, string, token);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    expect_value(__wrap_SysAppCmnSetStringValue, handle, common_handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "sensor_id");
    expect_string(__wrap_SysAppCmnSetStringValue, string, device_manifest);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    expect_value(__wrap_SysAppCmnSetNumberValue, handle, common_handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "retry_count");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, retry_cnt);
    will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, common_handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, telemetry_json_serialize);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonOfTelemetry_FullySuccess(void **state)
{
    EsfJsonHandle esfj_handle;
    char *device_manifest = "manifest";
    char *project_id = "project_id";
    char *token = "token";
    char *device_manifest_key_name = "device_manifest";
    int retry_count = 1;
    const char *response_org;
    RetCode ret;

    MakeJsonOfTelemetry_FullySuccess(retry_count);

    ret = MakeJsonOfTelemetry(&esfj_handle, device_manifest, device_manifest_key_name, project_id,
                              token, retry_count, &response_org);

    assert_int_equal(ret, kRetOk);
    assert_string_equal(response_org, telemetry_json_serialize);
    assert_int_equal(esfj_handle, common_handle_val);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonOfTelemetry_ErrorEsfJsonOpen(void **state)
{
    EsfJsonHandle esfj_handle;
    char *device_manifest = "manifest";
    char *project_id = "project_id";
    char *token = "token";
    char *device_manifest_key_name = "device_manifest";
    int retry_count = 1;
    const char *response_org;
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);

    ret = MakeJsonOfTelemetry(&esfj_handle, device_manifest, device_manifest_key_name, project_id,
                              token, retry_count, &response_org);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonOfTelemetry_ErrorEsfJsonSerialize(void **state)
{
    EsfJsonHandle esfj_handle;
    char *device_manifest = "manifest";
    char *project_id = "project_id";
    char *token = "token";
    char *device_manifest_key_name = "device_manifest";
    int retry_count = 1;
    const char *response_org;
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "project_id");
    expect_string(__wrap_SysAppCmnSetStringValue, string, project_id);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "token");
    expect_string(__wrap_SysAppCmnSetStringValue, string, token);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "device_manifest");
    expect_string(__wrap_SysAppCmnSetStringValue, string, device_manifest);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "retry_count");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, retry_count);
    will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, telemetry_json_serialize);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonInternalError);

    expect_value(__wrap_EsfJsonSerializeFree, handle, handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = MakeJsonOfTelemetry(&esfj_handle, device_manifest, device_manifest_key_name, project_id,
                              token, retry_count, &response_org);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonOfTelemetry_ErrorEsfJsonSerializeAndEsfJsonClose(void **state)
{
    EsfJsonHandle esfj_handle;
    char *device_manifest = "manifest";
    char *project_id = "project_id";
    char *token = "token";
    char *device_manifest_key_name = "device_manifest";
    int retry_count = 1;
    const char *response_org;
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "project_id");
    expect_string(__wrap_SysAppCmnSetStringValue, string, project_id);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "token");
    expect_string(__wrap_SysAppCmnSetStringValue, string, token);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "device_manifest");
    expect_string(__wrap_SysAppCmnSetStringValue, string, device_manifest);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "retry_count");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, retry_count);
    will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, telemetry_json_serialize);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonInternalError);

    expect_value(__wrap_EsfJsonSerializeFree, handle, handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonInternalError);

    ret = MakeJsonOfTelemetry(&esfj_handle, device_manifest, device_manifest_key_name, project_id,
                              token, retry_count, &response_org);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_MakeJsonOfTelemetry_NullEsfJsonSerialize(void **state)
{
    EsfJsonHandle esfj_handle;
    char *device_manifest = "manifest";
    char *project_id = "project_id";
    char *token = "token";
    char *device_manifest_key_name = "device_manifest";
    int retry_count = 1;
    const char *response_org;
    RetCode ret;
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "project_id");
    expect_string(__wrap_SysAppCmnSetStringValue, string, project_id);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "token");
    expect_string(__wrap_SysAppCmnSetStringValue, string, token);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "device_manifest");
    expect_string(__wrap_SysAppCmnSetStringValue, string, device_manifest);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetNumberValue, parent, val);
    expect_string(__wrap_SysAppCmnSetNumberValue, key, "retry_count");
    expect_value(__wrap_SysAppCmnSetNumberValue, number, retry_count);
    will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, NULL);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonSerializeFree, handle, handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = MakeJsonOfTelemetry(&esfj_handle, device_manifest, device_manifest_key_name, project_id,
                              token, retry_count, &response_org);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
//
// SendEnrollmentData()
//
/*----------------------------------------------------------------------------*/
static void SendEnrollmentData_FullySuccess(PsInfo *p_info)
{
    GetEnrollmentData_SensorIdInsteadOfDeviceManifest();

    MakeJsonOfTelemetry_SetSensorIdInsteadOfDeviceManifest(0);

    expect_value(__wrap_SYS_send_telemetry, c, p_info->client);
    expect_string(__wrap_SYS_send_telemetry, topic, "auto_enrollment");
    expect_value(__wrap_SYS_send_telemetry, value, telemetry_json_serialize);
    expect_value(__wrap_SYS_send_telemetry, cb, SendTelemetryEnrollmentCallback);
    expect_not_value(__wrap_SYS_send_telemetry, user, NULL);
    will_return(__wrap_SYS_send_telemetry, SYS_RESULT_OK);
    will_return(__wrap_SYS_send_telemetry, 0);
    will_return(__wrap_SYS_send_telemetry, SYS_REASON_FINISHED);

    expect_value(__wrap_SYS_process_event, c, p_info->client);
    expect_value(__wrap_SYS_process_event, ms, 0);
    will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

    expect_value(__wrap_EsfJsonSerializeFree, handle, common_handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonClose, handle, common_handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // For free of device_manifest.

    will_return(mock_free, false); // Not check parameter

    // For free of project_id.

    will_return(mock_free, false); // Not check parameter

    // For free of register_token.

    will_return(mock_free, false); // Not check parameter

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendEnrollmentData_FullySuccess(void **state)
{
    PsInfo info = {0};

    SendEnrollmentData_FullySuccess(&info);

    SendEnrollmentData(&info);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendEnrollmentData_ErrorEsfJsonClose(void **state)
{
    PsInfo info = {0};

    GetEnrollmentData_FullySuccess();

    MakeJsonOfTelemetry_FullySuccess(0);

    expect_value(__wrap_SYS_send_telemetry, c, info.client);
    expect_string(__wrap_SYS_send_telemetry, topic, "auto_enrollment");
    expect_value(__wrap_SYS_send_telemetry, value, telemetry_json_serialize);
    expect_value(__wrap_SYS_send_telemetry, cb, SendTelemetryEnrollmentCallback);
    expect_not_value(__wrap_SYS_send_telemetry, user, NULL);
    will_return(__wrap_SYS_send_telemetry, SYS_RESULT_OK);
    will_return(__wrap_SYS_send_telemetry, 0);
    will_return(__wrap_SYS_send_telemetry, SYS_REASON_FINISHED);

    expect_value(__wrap_SYS_process_event, c, info.client);
    expect_value(__wrap_SYS_process_event, ms, 0);
    will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

    expect_value(__wrap_EsfJsonSerializeFree, handle, common_handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);
    expect_value(__wrap_EsfJsonClose, handle, common_handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonInternalError);

    // For free of device_manifest.

    will_return(mock_free, false); // Not check parameter

    // For free of project_id.

    will_return(mock_free, false); // Not check parameter

    // For free of register_token.

    will_return(mock_free, false); // Not check parameter

    SendEnrollmentData(&info);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendEnrollmentData_ErrorGetEnrollmentData(void **state)
{
    PsInfo info = {0};

    // GetEnrollmentData()
    will_return(mock_malloc, true);
    will_return(mock_malloc, false);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_DEVICE_MANIFEST_MAX_SIZE);

    will_return(mock_malloc, true);
    will_return(mock_malloc, false);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_PROJECT_ID_MAX_SIZE);

    will_return(mock_malloc, true);
    will_return(mock_malloc, false);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_REGISTER_TOKEN_MAX_SIZE);

    SendEnrollmentData(&info);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendEnrollmentData_RetryMaxOver(void **state)
{
    PsInfo info = {0};
    int i;

    GetEnrollmentData_FullySuccess();

    for (i = 0; i < 10; i++) {
        MakeJsonOfTelemetry_FullySuccess(i);

        expect_value(__wrap_SYS_send_telemetry, c, info.client);
        expect_string(__wrap_SYS_send_telemetry, topic, "auto_enrollment");
        expect_value(__wrap_SYS_send_telemetry, value, telemetry_json_serialize);
        expect_value(__wrap_SYS_send_telemetry, cb, SendTelemetryEnrollmentCallback);
        expect_not_value(__wrap_SYS_send_telemetry, user, NULL);
        will_return(__wrap_SYS_send_telemetry, SYS_RESULT_OK);
        will_return(__wrap_SYS_send_telemetry, 0);
        will_return(__wrap_SYS_send_telemetry, SYS_REASON_TIMEOUT);

        expect_value(__wrap_SYS_process_event, c, info.client);
        expect_value(__wrap_SYS_process_event, ms, 0);
        will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

        expect_value(__wrap_EsfJsonSerializeFree, handle, common_handle_val);
        will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

        expect_value(__wrap_EsfJsonClose, handle, common_handle_val);
        will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
    }

    will_return(mock_free, false); // Not check parameter
    will_return(mock_free, false); // Not check parameter
    will_return(mock_free, false); // Not check parameter

    SendEnrollmentData(&info);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendEnrollmentData_RetryMax(void **state)
{
    PsInfo info = {0};
    int i;

    GetEnrollmentData_FullySuccess();

    for (i = 0; i < 9; i++) {
        MakeJsonOfTelemetry_FullySuccess(i);

        expect_value(__wrap_SYS_send_telemetry, c, info.client);
        expect_string(__wrap_SYS_send_telemetry, topic, "auto_enrollment");
        expect_value(__wrap_SYS_send_telemetry, value, telemetry_json_serialize);
        expect_value(__wrap_SYS_send_telemetry, cb, SendTelemetryEnrollmentCallback);
        expect_not_value(__wrap_SYS_send_telemetry, user, NULL);
        will_return(__wrap_SYS_send_telemetry, SYS_RESULT_OK);
        will_return(__wrap_SYS_send_telemetry, 0);
        if (i == 8) {
            will_return(__wrap_SYS_send_telemetry, SYS_REASON_FINISHED);
        }
        else {
            will_return(__wrap_SYS_send_telemetry, SYS_REASON_TIMEOUT);
        }

        expect_value(__wrap_SYS_process_event, c, info.client);
        expect_value(__wrap_SYS_process_event, ms, 0);
        will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

        expect_value(__wrap_EsfJsonSerializeFree, handle, common_handle_val);
        will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

        expect_value(__wrap_EsfJsonClose, handle, common_handle_val);
        will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
    }

    will_return(mock_free, false); // Not check parameter
    will_return(mock_free, false); // Not check parameter
    will_return(mock_free, false); // Not check parameter

    SendEnrollmentData(&info);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendEnrollmentData_ErrorMakeJsonOfTelemetry(void **state)
{
    PsInfo info = {0};
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;

    GetEnrollmentData_FullySuccess();

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);

    will_return(mock_free, false); // Not check parameter
    will_return(mock_free, false); // Not check parameter
    will_return(mock_free, false); // Not check parameter

    SendEnrollmentData(&info);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendEnrollmentData_ErrorSYS_send_telemetry(void **state)
{
    PsInfo info = {0};

    GetEnrollmentData_FullySuccess();
    MakeJsonOfTelemetry_FullySuccess(0);

    expect_value(__wrap_SYS_send_telemetry, c, info.client);
    expect_string(__wrap_SYS_send_telemetry, topic, "auto_enrollment");
    expect_value(__wrap_SYS_send_telemetry, value, telemetry_json_serialize);
    expect_value(__wrap_SYS_send_telemetry, cb, SendTelemetryEnrollmentCallback);
    expect_not_value(__wrap_SYS_send_telemetry, user, NULL);
    will_return(__wrap_SYS_send_telemetry, SYS_RESULT_ERRNO);

    expect_value(__wrap_EsfJsonSerializeFree, handle, common_handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonClose, handle, common_handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    will_return(mock_free, false); // Not check parameter
    will_return(mock_free, false); // Not check parameter
    will_return(mock_free, false); // Not check parameter

    SendEnrollmentData(&info);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendEnrollmentData_ErrorSYS_process_event(void **state)
{
    PsInfo info = {0};

    GetEnrollmentData_FullySuccess();
    MakeJsonOfTelemetry_FullySuccess(0);

    expect_value(__wrap_SYS_send_telemetry, c, info.client);
    expect_string(__wrap_SYS_send_telemetry, topic, "auto_enrollment");
    expect_value(__wrap_SYS_send_telemetry, value, telemetry_json_serialize);
    expect_value(__wrap_SYS_send_telemetry, cb, SendTelemetryEnrollmentCallback);
    expect_not_value(__wrap_SYS_send_telemetry, user, NULL);
    will_return(__wrap_SYS_send_telemetry, SYS_RESULT_OK);
    will_return(__wrap_SYS_send_telemetry, 0);
    will_return(__wrap_SYS_send_telemetry, SYS_REASON_FINISHED);

    expect_value(__wrap_SYS_process_event, c, info.client);
    expect_value(__wrap_SYS_process_event, ms, 0);
    will_return(__wrap_SYS_process_event, SYS_RESULT_SHOULD_EXIT);

    expect_value(__wrap_EsfJsonSerializeFree, handle, common_handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonClose, handle, common_handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    will_return(mock_free, false); // Not check parameter
    will_return(mock_free, false); // Not check parameter
    will_return(mock_free, false); // Not check parameter

    SendEnrollmentData(&info);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendEnrollmentData_WaitTelemetryCallback(void **state)
{
    PsInfo info = {0};

    GetEnrollmentData_FullySuccess();
    MakeJsonOfTelemetry_FullySuccess(0);

    expect_value(__wrap_SYS_send_telemetry, c, info.client);
    expect_string(__wrap_SYS_send_telemetry, topic, "auto_enrollment");
    expect_value(__wrap_SYS_send_telemetry, value, telemetry_json_serialize);
    expect_value(__wrap_SYS_send_telemetry, cb, SendTelemetryEnrollmentCallback);
    expect_not_value(__wrap_SYS_send_telemetry, user, NULL);
    will_return(__wrap_SYS_send_telemetry, SYS_RESULT_OK);
    will_return(__wrap_SYS_send_telemetry, 1);
    will_return(__wrap_SYS_send_telemetry, SYS_REASON_FINISHED);

    expect_value(__wrap_SYS_process_event, c, info.client);
    expect_value(__wrap_SYS_process_event, ms, 0);
    will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

    expect_value(__wrap_SYS_process_event, c, info.client);
    expect_value(__wrap_SYS_process_event, ms, 0);
    will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

    expect_value(__wrap_EsfJsonSerializeFree, handle, common_handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonClose, handle, common_handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    will_return(mock_free, false); // Not check parameter
    will_return(mock_free, false); // Not check parameter
    will_return(mock_free, false); // Not check parameter

    SendEnrollmentData(&info);

    return;
}

/*----------------------------------------------------------------------------*/
//
// SetResId()
//
/*----------------------------------------------------------------------------*/
static void SetResId_FullySuccess(void)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    const char *req_id_ptr = "TEST";
    const char *config = "name";

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // GetReqInfoToSetResInfo()

    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetResId_FullySuccess(void **state)
{
    RetCode ret;
    ResInfoContext res_info;
    const char *param = "name";

    SetResId_FullySuccess();

    ret = SetResId(param, &res_info);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetResId_JsonOpenAndDeserializeError(void **state)
{
    RetCode ret;
    ResInfoContext res_info;
    const char *param = "name";
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);

    ret = SetResId(param, &res_info);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetResId_ErrorEsfJsonClose(void **state)
{
    RetCode ret;
    ResInfoContext res_info;
    const char *param = "name";

    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    const char *req_id_ptr = "TEST";
    const char *config = "name";

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // GetReqInfoToSetResInfo()

    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonInternalError);

    ret = SetResId(param, &res_info);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
//
// ReleaseEvpAgent()
//
/*----------------------------------------------------------------------------*/
static void test_ReleaseEvpAgent_FullySuccess(void **state)
{
    IsaPsErrorCode ret;
    PsInfo ps_info = {0};

    ps_info.client = (struct SYS_client *)1;
    ps_info.pid = 1;

    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.
#if defined(__linux__)
    // workaround for Nuttx occur issue on FR.
    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);
#endif

#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif
    ret = ReleaseEvpAgent(&ps_info);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ReleaseEvpAgent_ErrorEVP_Agent_unregister_sys_client(void **state)
{
    IsaPsErrorCode ret;
    PsInfo ps_info = {0};

    ps_info.client = (struct SYS_client *)1;
    ps_info.pid = -1;

    will_return(__wrap_EVP_Agent_unregister_sys_client, -1);

    // Check EsfLogManagerDeinit.
#if defined(__linux__)
    // workaround for Nuttx occur issue on FR.
    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);
#endif

    ret = ReleaseEvpAgent(&ps_info);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
//
// ConfigurationCallback()
//
/*----------------------------------------------------------------------------*/
static void test_ConfigurationCallback_PRIVATE_endpoint_settings(void **state)
{
    struct SYS_client *evp_client = (struct SYS_client *)0x98765432;
    const char *topic = "PRIVATE_endpoint_settings";
    const char *config = "PRIVATE_endpoint_settings configuration";
    PsInfo ps_info = {0};

    ps_info.mode = IsaPsMode_Idle;

    EndpointSettings_FullySuccess(config);

    ConfigurationCallback(evp_client, topic, config, SYS_CONFIG_ANY, SYS_REASON_FINISHED, &ps_info);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConfigurationCallback_Other(void **state)
{
    struct SYS_client *evp_client = (struct SYS_client *)0x98765432;
    const char *topic = "Other";
    const char *config = "Other configuration";
    PsInfo ps_info = {0};

    ps_info.mode = IsaPsMode_Enrollment;

    ConfigurationCallback(evp_client, topic, config, SYS_CONFIG_ANY, SYS_REASON_FINISHED, &ps_info);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ConfigurationCallback_SYS_REASON_ERROR(void **state)
{
    struct SYS_client *evp_client = (struct SYS_client *)0x98765432;
    const char *topic = "PRIVATE_endpoint_settings";
    const char *config = "PRIVATE_endpoint_settings configuration";

    ConfigurationCallback(evp_client, topic, config, SYS_CONFIG_ANY, SYS_REASON_ERROR, NULL);

    return;
}

/*----------------------------------------------------------------------------*/
//
// ResponseSendCompleteCallback()
//
/*----------------------------------------------------------------------------*/
static void test_ResponseSendCompleteCallback_FullySuccess(void **state)
{
    SYS_client *sys_client = {0};
    ResponseContext ctx = {0};

    ResponseSendCompleteCallback(sys_client, SYS_REASON_FINISHED, (void *)&ctx);

    assert_true(ctx.send_complete);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ResponseSendCompleteCallback_Null(void **state)
{
    SYS_client *sys_client = {0};

    ResponseSendCompleteCallback(sys_client, SYS_REASON_FINISHED, NULL);

    return;
}

/*----------------------------------------------------------------------------*/
//
// SendDirectCommandResponseCore()
//
/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
static void SendDirectCommandResponseCore_FullySuccess(void)
{
    int process_event_count = 1;

    expect_any(__wrap_SYS_set_response_cb, c);
    expect_any(__wrap_SYS_set_response_cb, id);
    expect_any(__wrap_SYS_set_response_cb, response);
    expect_value(__wrap_SYS_set_response_cb, status, SYS_RESPONSE_STATUS_OK);
    expect_value(__wrap_SYS_set_response_cb, cb, ResponseSendCompleteCallback);
    expect_any(__wrap_SYS_set_response_cb, user);
    will_return(__wrap_SYS_set_response_cb, SYS_RESULT_OK);
    will_return(__wrap_SYS_set_response_cb, process_event_count);

    expect_any(__wrap_SYS_process_event, c);
    expect_value(__wrap_SYS_process_event, ms, 0);
    will_return(__wrap_SYS_process_event, SYS_RESULT_SHOULD_EXIT);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendDirectCommandResponseCore_FullySuccess(void **state)
{
    SYS_client *sys_client = (SYS_client *)0x98765432;
    SYS_response_id cmd_id = 777;
    const char *response = "00000";
    RetCode ret;

    SendDirectCommandResponseCore_FullySuccess();

    ret = SendDirectCommandResponseCore(sys_client, cmd_id, response);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendDirectCommandResponseCore_FullySuccess_SendComplete(void **state)
{
    SYS_client *sys_client = (SYS_client *)0x98765432;
    SYS_response_id cmd_id = 777;
    const char *response =
        "w123456789x123456789y123456789z123456789"
        "w123456789x123456789y123456789z123456789"
        "w123456789x123456789y123456789z123456789"
        "w123456789x123456789y123456789z123456789"
        "w1234567";
    RetCode ret;
    int process_event_count = 0;

    expect_any(__wrap_SYS_set_response_cb, c);
    expect_any(__wrap_SYS_set_response_cb, id);
    expect_any(__wrap_SYS_set_response_cb, response);
    expect_value(__wrap_SYS_set_response_cb, status, SYS_RESPONSE_STATUS_OK);
    expect_value(__wrap_SYS_set_response_cb, cb, ResponseSendCompleteCallback);
    expect_any(__wrap_SYS_set_response_cb, user);
    will_return(__wrap_SYS_set_response_cb, SYS_RESULT_OK);
    will_return(__wrap_SYS_set_response_cb, process_event_count);

    expect_value(__wrap_SYS_process_event, c, sys_client);
    expect_value(__wrap_SYS_process_event, ms, 0);
    will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

    ret = SendDirectCommandResponseCore(sys_client, cmd_id, response);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendDirectCommandResponseCore_2ndloop(void **state)
{
    SYS_client *sys_client = (SYS_client *)0x98765432;
    SYS_response_id cmd_id = 777;
    const char *response = "00000";
    int process_event_count = 2;
    RetCode ret;

    expect_value(__wrap_SYS_set_response_cb, c, sys_client);
    expect_value(__wrap_SYS_set_response_cb, id, cmd_id);
    expect_string(__wrap_SYS_set_response_cb, response, response);
    expect_value(__wrap_SYS_set_response_cb, status, SYS_RESPONSE_STATUS_OK);
    expect_value(__wrap_SYS_set_response_cb, cb, ResponseSendCompleteCallback);
    expect_not_value(__wrap_SYS_set_response_cb, user, NULL);
    will_return(__wrap_SYS_set_response_cb, SYS_RESULT_OK);
    will_return(__wrap_SYS_set_response_cb, process_event_count);

    expect_value(__wrap_SYS_process_event, c, sys_client);
    expect_value(__wrap_SYS_process_event, ms, 0);
    will_return(__wrap_SYS_process_event, SYS_RESULT_TIMEDOUT);
    expect_value(__wrap_SYS_process_event, c, sys_client);
    expect_value(__wrap_SYS_process_event, ms, 0);
    will_return(__wrap_SYS_process_event, SYS_RESULT_SHOULD_EXIT);

    ret = SendDirectCommandResponseCore(sys_client, cmd_id, response);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendDirectCommandResponseCore_ErrorSYS_set_response_cb(void **state)
{
    SYS_client *sys_client = (SYS_client *)0x98765432;
    SYS_response_id cmd_id = 777;
    const char *response = "00000";
    RetCode ret;

    expect_value(__wrap_SYS_set_response_cb, c, sys_client);
    expect_value(__wrap_SYS_set_response_cb, id, cmd_id);
    expect_string(__wrap_SYS_set_response_cb, response, response);
    expect_value(__wrap_SYS_set_response_cb, status, SYS_RESPONSE_STATUS_OK);
    expect_value(__wrap_SYS_set_response_cb, cb, ResponseSendCompleteCallback);
    expect_not_value(__wrap_SYS_set_response_cb, user, NULL);
    will_return(__wrap_SYS_set_response_cb, SYS_RESULT_TIMEDOUT);

    ret = SendDirectCommandResponseCore(sys_client, cmd_id, response);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
//
// SendDirectCommandResponse()
//
/*----------------------------------------------------------------------------*/
static void SendDirectCommandResponse_FullySuccess(void)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    const char *string_expect = "string_serialize_value";
    const char *string_expect_key = "res_info";

    // JsonOpenAndInit()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, string_expect_key);
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, val);
    expect_not_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, NULL);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    SendDirectCommandResponseCore_FullySuccess();

    expect_value(__wrap_EsfJsonSerializeFree, handle, handle_val);
    will_return(__wrap_EsfJsonSerializeFree, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendDirectCommandResponse_FullySuccess(void **state)
{
    SYS_client *sys_client = {0};
    ResInfoContext ctx = {.res_id = "Test", .code = 0, .detail_msg = "ok"};
    RetCode ret;

    SendDirectCommandResponse_FullySuccess();

    ret = SendDirectCommandResponse(sys_client, 0, &ctx);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendDirectCommandResponse_ErrorEsfJsonSerialize(void **state)
{
    SYS_client *sys_client = {0};
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    ResInfoContext ctx = {.res_id = "Test", .code = 0, .detail_msg = "ok"};
    EsfJsonValue val = 1357;
    const char *string_expect = "string_serialize_value";
    const char *string_expect_key = "res_info";
    RetCode ret;

    // JsonOpenAndInit()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, string_expect_key);
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, val);
    expect_not_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, NULL);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonInternalError);
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SendDirectCommandResponse(sys_client, 0, &ctx);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendDirectCommandResponse_EsfJsonSerialize_Null(void **state)
{
    SYS_client *sys_client = {0};
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    ResInfoContext ctx = {.res_id = "Test", .code = 0, .detail_msg = "ok"};
    EsfJsonValue val = 1357;
    const char *string_expect_key = "res_info";
    RetCode ret;

    // JsonOpenAndInit()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, string_expect_key);
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, val);
    expect_not_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, NULL);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, NULL);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    ret = SendDirectCommandResponse(sys_client, 0, &ctx);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendDirectCommandResponse_ErrorEsfJsonSerializeEsfJsonClose(void **state)
{
    SYS_client *sys_client = {0};
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    ResInfoContext ctx = {.res_id = "Test", .code = 0, .detail_msg = "ok"};
    EsfJsonValue val = 1357;
    const char *string_expect = "string_serialize_value";
    const char *string_expect_key = "res_info";
    RetCode ret;

    // JsonOpenAndInit()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, string_expect_key);
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, val);
    expect_not_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, NULL);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonInternalError);
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonInternalError);

    ret = SendDirectCommandResponse(sys_client, 0, &ctx);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SendDirectCommandResponse_ErrorEsfJsonOpen(void **state)
{
    SYS_client *sys_client = {0};
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    ResInfoContext ctx = {.res_id = "Test", .code = 0, .detail_msg = "ok"};
    RetCode ret;

    // JsonOpenAndInit()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);

    ret = SendDirectCommandResponse(sys_client, 0, &ctx);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
//
// DirectCommandRebootCallback()
//
/*----------------------------------------------------------------------------*/
static void test_DirectCommandRebootCallback_FullySuccess(void **state)
{
    SYS_client *sys_client = {0};
    PsInfo ps_info = {0};
    const char *param = "name";

    SetResId_FullySuccess();

    SendDirectCommandResponse_FullySuccess();

    DirectCommandRebootCallback(sys_client, 0, param, (void *)&ps_info);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_DirectCommandRebootCallback_Null(void **state)
{
    SYS_client *sys_client = {0};
    PsInfo ps_info = {0};

    DirectCommandRebootCallback(sys_client, 0, NULL, (void *)&ps_info);

    return;
}

/*----------------------------------------------------------------------------*/
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

    will_return(__wrap_EsfSystemManagerGetProjectId, "project_id");
    will_return(__wrap_EsfSystemManagerGetProjectId, kEsfSystemManagerResultOk);

    // Check EsfSystemManagerGetRegisterToken.

    will_return(__wrap_EsfSystemManagerGetRegisterToken, "token");
    will_return(__wrap_EsfSystemManagerGetRegisterToken, kEsfSystemManagerResultOk);

    // For free of project_id.

    will_return(mock_free, false); // Not check parameter

    // For free of register_token.

    will_return(mock_free, false); // Not check parameter
}

/*----------------------------------------------------------------------------*/
static void CheckProjectIdAndRegisterToken_NotFound(void)
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

    will_return(__wrap_EsfSystemManagerGetProjectId, "project_id");
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
static void test_CheckProjectIdAndRegisterToken_FullySuccess(void **state)
{
    RetCode ret;

    CheckProjectIdAndRegisterToken_FullySuccess();

    ret = CheckProjectIdAndRegisterToken();

    // Check return value.

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_CheckProjectIdAndRegisterToken_ProjectIdAllocError(void **state)
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
static void test_CheckProjectIdAndRegisterToken_RegisterTokenAllocError(void **state)
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
static void test_CheckProjectIdAndRegisterToken_BothAllocError(void **state)
{
    RetCode ret;

    // Check project_id malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, false);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_PROJECT_ID_MAX_SIZE);

    // Check register_token malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, false);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_REGISTER_TOKEN_MAX_SIZE);

    // Execute test target.

    ret = CheckProjectIdAndRegisterToken();

    // Check return value.

    assert_int_equal(ret, kRetMemoryError);
}

/*----------------------------------------------------------------------------*/
static void test_CheckProjectIdAndRegisterToken_GetProjectIdError(void **state)
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

    will_return(__wrap_EsfSystemManagerGetProjectId, "project_id");
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
static void test_CheckProjectIdAndRegisterToken_GetRegisterTokenError(void **state)
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

    will_return(__wrap_EsfSystemManagerGetProjectId, "project_id");
    will_return(__wrap_EsfSystemManagerGetProjectId, kEsfSystemManagerResultOk);

    // Check EsfSystemManagerGetRegisterToken.

    will_return(__wrap_EsfSystemManagerGetRegisterToken, "token");
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
static void test_CheckProjectIdAndRegisterToken_EmptyProjectIdAndRegisterToken(void **state)
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

    will_return(__wrap_EsfSystemManagerGetProjectId, "");
    will_return(__wrap_EsfSystemManagerGetProjectId, kEsfSystemManagerResultOk);

    // Check EsfSystemManagerGetRegisterToken.

    will_return(__wrap_EsfSystemManagerGetRegisterToken, "");
    will_return(__wrap_EsfSystemManagerGetRegisterToken, kEsfSystemManagerResultOk);

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
static void test_CheckProjectIdAndRegisterToken_EmptyRegisterToken(void **state)
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

    will_return(__wrap_EsfSystemManagerGetProjectId, "project_id");
    will_return(__wrap_EsfSystemManagerGetProjectId, kEsfSystemManagerResultOk);

    // Check EsfSystemManagerGetRegisterToken.

    will_return(__wrap_EsfSystemManagerGetRegisterToken, "");
    will_return(__wrap_EsfSystemManagerGetRegisterToken, kEsfSystemManagerResultOk);

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
static void test_CheckProjectIdAndRegisterToken_EmptyProjectId(void **state)
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

    will_return(__wrap_EsfSystemManagerGetProjectId, "");
    will_return(__wrap_EsfSystemManagerGetProjectId, kEsfSystemManagerResultOk);

    // Check EsfSystemManagerGetRegisterToken.

    will_return(__wrap_EsfSystemManagerGetRegisterToken, "token");
    will_return(__wrap_EsfSystemManagerGetRegisterToken, kEsfSystemManagerResultOk);

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
//
// SetDefaultEndpoint()
//
/*----------------------------------------------------------------------------*/
static void SetDefaultEndpoint_FullySuccess(void)
{
    char *expected_mqtt_host = "provision.aitrios.sony-semicon.com";
    char *expected_mqtt_port = "8883";

    // Check mqtt_host malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // Check mqtt_port malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    CheckProjectIdAndRegisterToken_FullySuccess();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, ISAPP_PS_MODE_FORCE_ENTRY);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, expected_mqtt_host);
    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, kEsfSystemManagerResultOk);

    will_return(__wrap_EsfSystemManagerGetEvpHubPort, expected_mqtt_port);
    will_return(__wrap_EsfSystemManagerGetEvpHubPort, kEsfSystemManagerResultOk);

    // Check EsfPwrMgrWdtTerminate

    // For free of mqtt_host.

    will_return(mock_free, false); // Not check parameter

    // For free of mqtt_port.

    will_return(mock_free, false); // Not check parameter

    return;
}

/*----------------------------------------------------------------------------*/
static void SetDefaultEndpoint_FullySuccess_ProvisioningService(void)
{
    char *expected_mqtt_host = "provision.aitrios.sony-semicon.com";
    char *expected_mqtt_port = "8883";

    // Check mqtt_host malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // Check mqtt_port malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    CheckProjectIdAndRegisterToken_NotFound();

    // Check EsfSystemManagerSetEvpHubUrl.

    expect_string(__wrap_EsfSystemManagerSetEvpHubUrl, data, expected_mqtt_host);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    // Check EsfSystemManagerSetEvpHubPort.

    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, expected_mqtt_port);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    // Check EsfSystemManagerSetQrModeTimeoutValue.

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, ISAPP_PS_MODE_FORCE_ENTRY);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    // Check EsfSystemManagerGetEvpHubUrl.

    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, expected_mqtt_host);
    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, kEsfSystemManagerResultOk);

    // Check EsfSystemManagerGetEvpHubPort.

    will_return(__wrap_EsfSystemManagerGetEvpHubPort, expected_mqtt_port);
    will_return(__wrap_EsfSystemManagerGetEvpHubPort, kEsfSystemManagerResultOk);

    // For free of mqtt_host.

    will_return(mock_free, false); // Not check parameter

    // For free of mqtt_port.

    will_return(mock_free, false); // Not check parameter

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetDefaultEndpoint_FullySuccess(void **state)
{
    RetCode ret;
    PsInfo ps_info = {0};
    ps_info.is_ps_mode_force_entory = false;

    SetDefaultEndpoint_FullySuccess();

    ret = SetDefaultEndpoint(&ps_info);

    // Check return value.

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetDefaultEndpoint_MqttHostAllocError(void **state)
{
    RetCode ret;
    PsInfo ps_info = {0};

    // Check mqtt_host malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, false);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // Check mqtt_port malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // For free of mqtt_port.

    will_return(mock_free, false); // Not check parameter

    ret = SetDefaultEndpoint(&ps_info);

    // Check return value.

    assert_int_equal(ret, kRetMemoryError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetDefaultEndpoint_MqttPortAllocError(void **state)
{
    RetCode ret;
    PsInfo ps_info = {0};

    // Check mqtt_host malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // Check mqtt_port malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, false);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // For free of mqtt_host.

    will_return(mock_free, false); // Not check parameter

    ret = SetDefaultEndpoint(&ps_info);

    // Check return value.

    assert_int_equal(ret, kRetMemoryError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetDefaultEndpoint_BothAllocError(void **state)
{
    RetCode ret;
    PsInfo ps_info = {0};

    // Check mqtt_host malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, false);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // Check mqtt_port malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, false);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    ret = SetDefaultEndpoint(&ps_info);

    // Check return value.

    assert_int_equal(ret, kRetMemoryError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetDefaultEndpoint_ErrorCheckProjectIdAndRegisterToken(void **state)
{
    RetCode ret;
    PsInfo ps_info = {0};
    char *expected_mqtt_host = "provision.aitrios.sony-semicon.com";
    char *expected_mqtt_port = "8883";

    ps_info.is_ps_mode_force_entory = false;

    // Check mqtt_host malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // Check mqtt_port malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // Error CheckProjectIdAndRegisterToken()

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_PROJECT_ID_MAX_SIZE);

    will_return(mock_malloc, true);
    will_return(mock_malloc, false);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_REGISTER_TOKEN_MAX_SIZE);

    will_return(mock_free, false); // Not check parameter

    expect_any(__wrap_EsfSystemManagerSetEvpHubUrl, data);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultInternalError);

    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, expected_mqtt_port);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, ISAPP_PS_MODE_FORCE_ENTRY);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, expected_mqtt_host);
    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, kEsfSystemManagerResultOk);

    will_return(__wrap_EsfSystemManagerGetEvpHubPort, expected_mqtt_port);
    will_return(__wrap_EsfSystemManagerGetEvpHubPort, kEsfSystemManagerResultOk);

    // Check EsfPwrMgrWdtTerminate

    // For free of mqtt_host.

    will_return(mock_free, false); // Not check parameter

    // For free of mqtt_port.

    will_return(mock_free, false); // Not check parameter

    ret = SetDefaultEndpoint(&ps_info);

    // Check return value.

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetDefaultEndpoint_TrueForceEntry(void **state)
{
    RetCode ret;
    PsInfo ps_info = {0};
    char *expected_mqtt_host = "provision.aitrios.sony-semicon.com";
    char *expected_mqtt_port = "8883";

    ps_info.is_ps_mode_force_entory = true;

    // Check mqtt_host malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // Check mqtt_port malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    CheckProjectIdAndRegisterToken_FullySuccess();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, ISAPP_PS_MODE_FORCE_ENTRY);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, expected_mqtt_host);
    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, kEsfSystemManagerResultOk);

    will_return(__wrap_EsfSystemManagerGetEvpHubPort, expected_mqtt_port);
    will_return(__wrap_EsfSystemManagerGetEvpHubPort, kEsfSystemManagerResultOk);

    // Check EsfPwrMgrWdtTerminate

    // For free of mqtt_host.

    will_return(mock_free, false); // Not check parameter

    // For free of mqtt_port.

    will_return(mock_free, false); // Not check parameter

    ret = SetDefaultEndpoint(&ps_info);

    // Check return value.

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetDefaultEndpoint_ErrorEsfSystemManagerSetEvpHubUrl(void **state)
{
    RetCode ret;
    PsInfo ps_info = {0};
    char *expected_mqtt_host = "provision.aitrios.sony-semicon.com";
    char *expected_mqtt_port = "8883";

    ps_info.is_ps_mode_force_entory = false;

    // Check mqtt_host malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // Check mqtt_port malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    CheckProjectIdAndRegisterToken_NotFound();

    expect_any(__wrap_EsfSystemManagerSetEvpHubUrl, data);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultInternalError);

    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, expected_mqtt_port);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, ISAPP_PS_MODE_FORCE_ENTRY);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, expected_mqtt_host);
    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, kEsfSystemManagerResultOk);

    will_return(__wrap_EsfSystemManagerGetEvpHubPort, expected_mqtt_port);
    will_return(__wrap_EsfSystemManagerGetEvpHubPort, kEsfSystemManagerResultOk);

    // Check EsfPwrMgrWdtTerminate

    // For free of mqtt_host.

    will_return(mock_free, false); // Not check parameter

    // For free of mqtt_port.

    will_return(mock_free, false); // Not check parameter

    ret = SetDefaultEndpoint(&ps_info);

    // Check return value.

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetDefaultEndpoint_ErrorEsfSystemManagerSetEvpHubPort(void **state)
{
    RetCode ret;
    PsInfo ps_info = {0};
    char *expected_mqtt_host = "provision.aitrios.sony-semicon.com";
    char *expected_mqtt_port = "8883";

    ps_info.is_ps_mode_force_entory = false;

    // Check mqtt_host malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // Check mqtt_port malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    CheckProjectIdAndRegisterToken_NotFound();

    expect_any(__wrap_EsfSystemManagerSetEvpHubUrl, data);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, expected_mqtt_port);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultInternalError);

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, ISAPP_PS_MODE_FORCE_ENTRY);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, expected_mqtt_host);
    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, kEsfSystemManagerResultOk);

    will_return(__wrap_EsfSystemManagerGetEvpHubPort, expected_mqtt_port);
    will_return(__wrap_EsfSystemManagerGetEvpHubPort, kEsfSystemManagerResultOk);

    // Check EsfPwrMgrWdtTerminate

    // For free of mqtt_host.

    will_return(mock_free, false); // Not check parameter

    // For free of mqtt_port.

    will_return(mock_free, false); // Not check parameter

    ret = SetDefaultEndpoint(&ps_info);

    // Check return value.

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetDefaultEndpoint_ErrorEsfSystemManagerGetEvpHubUrl(void **state)
{
    RetCode ret;
    PsInfo ps_info = {0};
    char *expected_mqtt_host = "provision.aitrios.sony-semicon.com";
    char *expected_mqtt_port = "8883";

    ps_info.is_ps_mode_force_entory = false;

    // Check mqtt_host malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // Check mqtt_port malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    CheckProjectIdAndRegisterToken_NotFound();

    expect_any(__wrap_EsfSystemManagerSetEvpHubUrl, data);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, expected_mqtt_port);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, ISAPP_PS_MODE_FORCE_ENTRY);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, expected_mqtt_host);
    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, kEsfSystemManagerResultInternalError);

    will_return(__wrap_EsfSystemManagerGetEvpHubPort, expected_mqtt_port);
    will_return(__wrap_EsfSystemManagerGetEvpHubPort, kEsfSystemManagerResultOk);

    // Check EsfPwrMgrWdtTerminate

    // For free of mqtt_host.

    will_return(mock_free, false); // Not check parameter

    // For free of mqtt_port.

    will_return(mock_free, false); // Not check parameter

    ret = SetDefaultEndpoint(&ps_info);

    // Check return value.

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetDefaultEndpoint_ErrorEsfSystemManagerGetEvpHubPort(void **state)
{
    RetCode ret;
    PsInfo ps_info = {0};
    char *expected_mqtt_host = "provision.aitrios.sony-semicon.com";
    char *expected_mqtt_port = "8883";

    ps_info.is_ps_mode_force_entory = false;

    // Check mqtt_host malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // Check mqtt_port malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    CheckProjectIdAndRegisterToken_NotFound();

    expect_any(__wrap_EsfSystemManagerSetEvpHubUrl, data);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    expect_string(__wrap_EsfSystemManagerSetEvpHubPort, data, expected_mqtt_port);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size,
                 ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, ISAPP_PS_MODE_FORCE_ENTRY);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, expected_mqtt_host);
    will_return(__wrap_EsfSystemManagerGetEvpHubUrl, kEsfSystemManagerResultOk);

    will_return(__wrap_EsfSystemManagerGetEvpHubPort, expected_mqtt_port);
    will_return(__wrap_EsfSystemManagerGetEvpHubPort, kEsfSystemManagerResultInternalError);

    // Check EsfPwrMgrWdtTerminate

    // For free of mqtt_host.

    will_return(mock_free, false); // Not check parameter

    // For free of mqtt_port.

    will_return(mock_free, false); // Not check parameter

    ret = SetDefaultEndpoint(&ps_info);

    // Check return value.

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
//
// SetupEvpAgent()
//
/*----------------------------------------------------------------------------*/
static void SetupEvpAgent_FullySuccess(void)
{
    struct SYS_client *expect_client = (struct SYS_client *)0x98765432;

    SetDefaultEndpoint_FullySuccess();
    task_create_Success();

    will_return(__wrap_EVP_Agent_register_sys_client, expect_client);

    will_return(__wrap_SYS_set_configuration_cb, false); // Don't call cb.
    will_return(__wrap_SYS_set_configuration_cb, SYS_RESULT_OK);
    expect_any(__wrap_SYS_set_configuration_cb, c);
    expect_string(__wrap_SYS_set_configuration_cb, topic, "system_settings");
    expect_value(__wrap_SYS_set_configuration_cb, cb, ConfigurationCallback);
    expect_value(__wrap_SYS_set_configuration_cb, type, SYS_CONFIG_ANY);
    expect_any(__wrap_SYS_set_configuration_cb, user);

    will_return(__wrap_SYS_set_configuration_cb, false); // Don't call cb.
    will_return(__wrap_SYS_set_configuration_cb, SYS_RESULT_OK);
    expect_any(__wrap_SYS_set_configuration_cb, c);
    expect_string(__wrap_SYS_set_configuration_cb, topic, "PRIVATE_endpoint_settings");
    expect_value(__wrap_SYS_set_configuration_cb, cb, ConfigurationCallback);
    expect_value(__wrap_SYS_set_configuration_cb, type, SYS_CONFIG_ANY);
    expect_any(__wrap_SYS_set_configuration_cb, user);

    expect_any(__wrap_SYS_register_command_cb, c);
    expect_string(__wrap_SYS_register_command_cb, command, "reboot");
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandRebootCallback);
    expect_any(__wrap_SYS_register_command_cb, user);
    will_return(__wrap_SYS_register_command_cb, false);
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void SetupEvpAgent_FullySuccess_ProvisioningService(void)
{
    struct SYS_client *expect_client = (struct SYS_client *)0x98765432;

    SetDefaultEndpoint_FullySuccess_ProvisioningService();

    task_create_Success();

    will_return(__wrap_EVP_Agent_register_sys_client, expect_client);

    will_return(__wrap_SYS_set_configuration_cb, false); // Don't call cb.
    will_return(__wrap_SYS_set_configuration_cb, SYS_RESULT_OK);
    expect_any(__wrap_SYS_set_configuration_cb, c);
    expect_string(__wrap_SYS_set_configuration_cb, topic, "system_settings");
    expect_value(__wrap_SYS_set_configuration_cb, cb, ConfigurationCallback);
    expect_value(__wrap_SYS_set_configuration_cb, type, SYS_CONFIG_ANY);
    expect_any(__wrap_SYS_set_configuration_cb, user);

    will_return(__wrap_SYS_set_configuration_cb, false); // Don't call cb.
    will_return(__wrap_SYS_set_configuration_cb, SYS_RESULT_OK);
    expect_any(__wrap_SYS_set_configuration_cb, c);
    expect_string(__wrap_SYS_set_configuration_cb, topic, "PRIVATE_endpoint_settings");
    expect_value(__wrap_SYS_set_configuration_cb, cb, ConfigurationCallback);
    expect_value(__wrap_SYS_set_configuration_cb, type, SYS_CONFIG_ANY);
    expect_any(__wrap_SYS_set_configuration_cb, user);

    expect_any(__wrap_SYS_register_command_cb, c);
    expect_string(__wrap_SYS_register_command_cb, command, "reboot");
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandRebootCallback);
    expect_any(__wrap_SYS_register_command_cb, user);
    will_return(__wrap_SYS_register_command_cb, false);
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    // Check EsfSystemManagerSetEvpHubUrl.

    expect_string(__wrap_EsfSystemManagerSetEvpHubUrl, data, "");
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetupEvpAgent_FullySuccess(void **state)
{
    RetCode ret;
    PsInfo ps_info = {0};

    ps_info.is_auto_enrollment = true;

    SetupEvpAgent_FullySuccess();

    ret = SetupEvpAgent(&ps_info);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetupEvpAgent_FullySuccess_ProvisioningService(void **state)
{
    RetCode ret;
    PsInfo ps_info = {0};

    ps_info.is_ps_mode_force_entory = false;

    SetupEvpAgent_FullySuccess_ProvisioningService();

    ret = SetupEvpAgent(&ps_info);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetupEvpAgent_ErrorSetDefaultEndpoint(void **state)
{
    RetCode ret;
    PsInfo ps_info = {0};

    // Check mqtt_host malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, false);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

    // Check mqtt_port malloc.

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);

    // For free of mqtt_port.

    will_return(mock_free, false); // Not check parameter

    ret = SetupEvpAgent(&ps_info);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetupEvpAgent_Errortask_create(void **state)
{
    RetCode ret;
    PsInfo ps_info = {0};

    SetDefaultEndpoint_FullySuccess();

    will_return(__wrap_task_create, -1);

    ret = SetupEvpAgent(&ps_info);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetupEvpAgent_ErrorSYS_set_configuration_cb_1st(void **state)
{
    RetCode ret;
    PsInfo ps_info = {0};
    struct SYS_client *expect_client = (struct SYS_client *)0x98765432;

    ps_info.is_auto_enrollment = true;

    SetDefaultEndpoint_FullySuccess();

    task_create_Success();

    will_return(__wrap_EVP_Agent_register_sys_client, NULL);
    will_return(__wrap_EVP_Agent_register_sys_client, expect_client);

    will_return(__wrap_SYS_set_configuration_cb, false); // Don't call cb.
    will_return(__wrap_SYS_set_configuration_cb, SYS_RESULT_TIMEDOUT);
    expect_any(__wrap_SYS_set_configuration_cb, c);
    expect_string(__wrap_SYS_set_configuration_cb, topic, "system_settings");
    expect_value(__wrap_SYS_set_configuration_cb, cb, ConfigurationCallback);
    expect_value(__wrap_SYS_set_configuration_cb, type, SYS_CONFIG_ANY);
    expect_any(__wrap_SYS_set_configuration_cb, user);

    // ReleaseEvpAgent()
    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.
#if defined(__linux__)
    // workaround for Nuttx occur issue on FR.
    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);
#endif

#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif

    ret = SetupEvpAgent(&ps_info);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetupEvpAgent_ErrorSYS_set_configuration_cb_2nd(void **state)
{
    RetCode ret;
    PsInfo ps_info = {0};
    struct SYS_client *expect_client = (struct SYS_client *)0x98765432;

    ps_info.is_auto_enrollment = true;

    SetDefaultEndpoint_FullySuccess();

    task_create_Success();

    will_return(__wrap_EVP_Agent_register_sys_client, expect_client);

    will_return(__wrap_SYS_set_configuration_cb, false); // Don't call cb.
    will_return(__wrap_SYS_set_configuration_cb, SYS_RESULT_OK);
    expect_any(__wrap_SYS_set_configuration_cb, c);
    expect_string(__wrap_SYS_set_configuration_cb, topic, "system_settings");
    expect_value(__wrap_SYS_set_configuration_cb, cb, ConfigurationCallback);
    expect_value(__wrap_SYS_set_configuration_cb, type, SYS_CONFIG_ANY);
    expect_any(__wrap_SYS_set_configuration_cb, user);

    will_return(__wrap_SYS_set_configuration_cb, false); // Don't call cb.
    will_return(__wrap_SYS_set_configuration_cb, SYS_RESULT_TIMEDOUT);
    expect_any(__wrap_SYS_set_configuration_cb, c);
    expect_string(__wrap_SYS_set_configuration_cb, topic, "PRIVATE_endpoint_settings");
    expect_value(__wrap_SYS_set_configuration_cb, cb, ConfigurationCallback);
    expect_value(__wrap_SYS_set_configuration_cb, type, SYS_CONFIG_ANY);
    expect_any(__wrap_SYS_set_configuration_cb, user);

    // ReleaseEvpAgent()
    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.
#if defined(__linux__)
    // workaround for Nuttx occur issue on FR.
    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);
#endif

#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif
    ret = SetupEvpAgent(&ps_info);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetupEvpAgent_ErrorSYS_register_command_cb(void **state)
{
    RetCode ret;
    PsInfo ps_info = {0};
    struct SYS_client *expect_client = (struct SYS_client *)0x98765432;

    ps_info.is_auto_enrollment = true;

    SetDefaultEndpoint_FullySuccess();
    task_create_Success();

    will_return(__wrap_EVP_Agent_register_sys_client, expect_client);

    will_return(__wrap_SYS_set_configuration_cb, false); // Don't call cb.
    will_return(__wrap_SYS_set_configuration_cb, SYS_RESULT_OK);
    expect_any(__wrap_SYS_set_configuration_cb, c);
    expect_string(__wrap_SYS_set_configuration_cb, topic, "system_settings");
    expect_value(__wrap_SYS_set_configuration_cb, cb, ConfigurationCallback);
    expect_value(__wrap_SYS_set_configuration_cb, type, SYS_CONFIG_ANY);
    expect_any(__wrap_SYS_set_configuration_cb, user);

    will_return(__wrap_SYS_set_configuration_cb, false); // Don't call cb.
    will_return(__wrap_SYS_set_configuration_cb, SYS_RESULT_OK);
    expect_any(__wrap_SYS_set_configuration_cb, c);
    expect_string(__wrap_SYS_set_configuration_cb, topic, "PRIVATE_endpoint_settings");
    expect_value(__wrap_SYS_set_configuration_cb, cb, ConfigurationCallback);
    expect_value(__wrap_SYS_set_configuration_cb, type, SYS_CONFIG_ANY);
    expect_any(__wrap_SYS_set_configuration_cb, user);

    expect_any(__wrap_SYS_register_command_cb, c);
    expect_string(__wrap_SYS_register_command_cb, command, "reboot");
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandRebootCallback);
    expect_any(__wrap_SYS_register_command_cb, user);
    will_return(__wrap_SYS_register_command_cb, false);
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_TIMEDOUT);

    // ReleaseEvpAgent()
    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.
#if defined(__linux__)
    // workaround for Nuttx occur issue on FR.
    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);
#endif

#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif

    ret = SetupEvpAgent(&ps_info);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
//
// SetLedStatusForProvisioningService()
//
/*----------------------------------------------------------------------------*/
static void test_SetLedStatusForProvisioningService_FullySuccess(void **state)
{
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    SetLedStatusForProvisioningService();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetLedStatusForProvisioningService_ErrorEsfLedManagerSetStatus(void **state)
{
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerInternalError);

    SetLedStatusForProvisioningService();

    return;
}

/*----------------------------------------------------------------------------*/
//
// CheckAllowlist()
//
/*----------------------------------------------------------------------------*/
static void test_CheckAllowlist_AllowlistTrue(void **state)
{
    PsInfo ps_info = {0};
    ps_info.mode = IsaPsMode_Enrollment;
    const char *topic = "system_settings";
    const char *config = "{\"is_allowlisted\": true}";

    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    const char *req_id_ptr = "TEST";
    bool is_allowlisted = true;

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // GetReqInfoToSetResInfo()
    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // SysAppCmnExtractBooleanValue()
    expect_value(__wrap_SysAppCmnExtractBooleanValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractBooleanValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractBooleanValue, jsonkey, "is_allowlisted");
    will_return(__wrap_SysAppCmnExtractBooleanValue, is_allowlisted);
    will_return(__wrap_SysAppCmnExtractBooleanValue, 1);

    // EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    CheckAllowlist(topic, config, &ps_info);

    // Mode should remain IsaPsMode_Enrollment when allowlist is true
    assert_int_equal(ps_info.mode, IsaPsMode_Enrollment);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_CheckAllowlist_AllowlistFalse(void **state)
{
    PsInfo ps_info = {0};
    ps_info.mode = IsaPsMode_Enrollment;
    const char *topic = "system_settings";
    const char *config = "{\"is_allowlisted\": false}";

    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    const char *req_id_ptr = "TEST";
    bool is_allowlisted = false;

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // GetReqInfoToSetResInfo()
    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // SysAppCmnExtractBooleanValue()
    expect_value(__wrap_SysAppCmnExtractBooleanValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractBooleanValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractBooleanValue, jsonkey, "is_allowlisted");
    will_return(__wrap_SysAppCmnExtractBooleanValue, is_allowlisted);
    will_return(__wrap_SysAppCmnExtractBooleanValue, 1);

    // EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    CheckAllowlist(topic, config, &ps_info);

    // Mode should change to IsaPsMode_QrCode when allowlist is false
    assert_int_equal(ps_info.mode, IsaPsMode_QrCode);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_CheckAllowlist_ModeNotEnrollment(void **state)
{
    PsInfo ps_info = {0};
    ps_info.mode = IsaPsMode_Operation; // Not Enrollment mode
    const char *topic = "system_settings";
    const char *config = "{\"is_allowlisted\": false}";

    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    const char *req_id_ptr = "TEST";

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // GetReqInfoToSetResInfo()
    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // SysAppCmnExtractBooleanValue should not be called when mode is not Enrollment

    // EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    CheckAllowlist(topic, config, &ps_info);

    // Mode should remain unchanged when not in Enrollment mode
    assert_int_equal(ps_info.mode, IsaPsMode_Operation);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_CheckAllowlist_JsonDeserializeError(void **state)
{
    PsInfo ps_info = {0};
    ps_info.mode = IsaPsMode_Enrollment;
    const char *topic = "system_settings";
    const char *config = "invalid_json";

    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;

    // JsonOpenAndDeserialize() - failure case
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, ESF_JSON_VALUE_INVALID);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonInternalError);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    CheckAllowlist(topic, config, &ps_info);

    // Mode should remain unchanged when JSON deserialize fails
    assert_int_equal(ps_info.mode, IsaPsMode_Enrollment);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_CheckAllowlist_InvalidExtractBooleanValue(void **state)
{
    PsInfo ps_info = {0};
    ps_info.mode = IsaPsMode_Enrollment;
    const char *topic = "system_settings";
    const char *config = "{\"is_allowlisted\": \"invalid_boolean\"}";

    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    const char *req_id_ptr = "TEST";
    bool is_allowlisted = false;

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // GetReqInfoToSetResInfo()
    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // SysAppCmnExtractBooleanValue() - return invalid value (0 or negative)
    expect_value(__wrap_SysAppCmnExtractBooleanValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractBooleanValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractBooleanValue, jsonkey, "is_allowlisted");
    will_return(__wrap_SysAppCmnExtractBooleanValue, is_allowlisted);
    will_return(__wrap_SysAppCmnExtractBooleanValue, 0); // Invalid return value

    // EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    CheckAllowlist(topic, config, &ps_info);

    // Mode should remain IsaPsMode_Enrollment when extraction fails
    assert_int_equal(ps_info.mode, IsaPsMode_Enrollment);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_CheckAllowlist_EsfJsonCloseError(void **state)
{
    PsInfo ps_info = {0};
    ps_info.mode = IsaPsMode_Enrollment;
    const char *topic = "system_settings";
    const char *config = "{\"is_allowlisted\": true}";

    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    const char *req_id_ptr = "TEST";
    bool is_allowlisted = true;

    // JsonOpenAndDeserialize()
    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    expect_string(__wrap_EsfJsonDeserialize, str, config);
    will_return(__wrap_EsfJsonDeserialize, val);
    will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

    // GetReqInfoToSetResInfo()
    expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
    expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
    will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
    will_return(__wrap_SysAppCmnGetReqId, kRetOk);

    // SysAppCmnExtractBooleanValue()
    expect_value(__wrap_SysAppCmnExtractBooleanValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractBooleanValue, parent_val, val);
    expect_string(__wrap_SysAppCmnExtractBooleanValue, jsonkey, "is_allowlisted");
    will_return(__wrap_SysAppCmnExtractBooleanValue, is_allowlisted);
    will_return(__wrap_SysAppCmnExtractBooleanValue, 1);

    // EsfJsonClose() - return error to trigger error log
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonInternalError);

    CheckAllowlist(topic, config, &ps_info);

    // Mode should remain IsaPsMode_Enrollment when allowlist is true
    assert_int_equal(ps_info.mode, IsaPsMode_Enrollment);

    return;
}

/*----------------------------------------------------------------------------*/
//
// IsaRunProvisioningService()
//
/*----------------------------------------------------------------------------*/
static void test_IsaRunProvisioningService_Should_exit(void **state)
{
    RetCode ret;
    bool is_ps_mode_force_entory = true;

    EsfClockManagerParams cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    EsfClockManagerParamsMask cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    EsfNetworkManagerParameterMask esfnm_mask_expect = {0};
    EsfNetworkManagerParameter esfnm_param_expect = {0};

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(PsInfo));

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // ConnectNetwork()
    memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

    will_return(__wrap_EsfNetworkManagerOpen, 777);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.subnet_mask, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.subnet_mask, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.ssid, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.password, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.encryption, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.ip_method, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.netif_kind,
                 esfnm_mask_expect.normal_mode.netif_kind);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.subnet_mask,
                 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.ssid, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.password, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.encryption,
                 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.channel, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.url, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.port, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.username, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.password, 0);

    expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.netif_kind,
                 esfnm_param_expect.normal_mode.netif_kind);

    will_return(__wrap_EsfNetworkManagerSaveParameter, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultStatusAlreadyRunning);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // StartNTP()
    expect_value(__wrap_EsfClockManagerSetParams, mask->connect.hostname, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->common.sync_interval,
                 cm_mask.common.sync_interval);
    expect_value(__wrap_EsfClockManagerSetParams, mask->common.polling_time,
                 cm_mask.common.polling_time);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.type,
                 cm_mask.skip_and_limit.type);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_packet_time, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_rtc_correction_value,
                 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.sanity_limit, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.type,
                 cm_mask.slew_setting.type);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_rtc_correction_value,
                 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_sync_number, 0);

    expect_value(__wrap_EsfClockManagerSetParams, data->common.sync_interval,
                 cm_param.common.sync_interval);
    expect_value(__wrap_EsfClockManagerSetParams, data->common.polling_time,
                 cm_param.common.polling_time);
    expect_value(__wrap_EsfClockManagerSetParams, data->skip_and_limit.type,
                 cm_param.skip_and_limit.type);
    expect_value(__wrap_EsfClockManagerSetParams, data->slew_setting.type,
                 cm_param.slew_setting.type);

    will_return(__wrap_EsfClockManagerSetParams, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerStart, true);
    will_return(__wrap_EsfClockManagerStart, true);
    will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // SetupEvpAgent
    SetupEvpAgent_FullySuccess();

    // 1st loop.

    {
        // Check EVP_getAgentStatus.
        will_return(__wrap_EVP_getAgentStatus, EVP_AGENT_STATUS_CONNECTED);
        expect_any(__wrap_SYS_process_event, c);
        expect_value(__wrap_SYS_process_event, ms, 0);
        will_return(__wrap_SYS_process_event, SYS_RESULT_SHOULD_EXIT);
    }

    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    expect_any(__wrap_EsfSystemManagerSetEvpHubUrl, data);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetEvpHubPort, data);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetProjectId, data);
    expect_value(__wrap_EsfSystemManagerSetProjectId, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetProjectId, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetRegisterToken, data);
    expect_value(__wrap_EsfSystemManagerSetRegisterToken, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetRegisterToken, kEsfSystemManagerResultOk);

    // Check EsfClockManagerStop.

    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    // Check UnsetLedStatusForProvisioningService.
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    will_return(mock_free, false);

    ret = IsaRunProvisioningService(is_ps_mode_force_entory);

    assert_int_equal(ret, kIsaPsSwitchToQrMode);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaRunProvisioningService_SendTelemetry(void **state)
{
    RetCode ret;
    bool is_ps_mode_force_entory = false;
    EsfNetworkManagerParameterMask esfnm_mask_expect = {0};
    EsfNetworkManagerParameter esfnm_param_expect = {0};
    EsfClockManagerParams cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    EsfClockManagerParamsMask cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(PsInfo));

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // ConnectNetwork() 2nd call, will be aborted.

    {
        memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
        memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
        esfnm_mask_expect.normal_mode.netif_kind = 1;
        esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

        // Check for EsfNetworkManagerOpen.

        will_return(__wrap_EsfNetworkManagerOpen, 777);
        will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerRegisterCallback.

        will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerLoadParameter.

        will_return(__wrap_EsfNetworkManagerLoadParameter, "");
        will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerSaveParameter.

        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.ip, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.subnet_mask,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.gateway, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.dns, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.ip, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.subnet_mask,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.gateway, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.dns, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.ssid, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.password, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.encryption,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.ip_method, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.netif_kind,
                     esfnm_mask_expect.normal_mode.netif_kind);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.ip, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter,
                     mask->accesspoint_mode.dev_ip.subnet_mask, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.gateway,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.dns, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.ssid, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.password,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter,
                     mask->accesspoint_mode.wifi_ap.encryption, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.channel,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.url, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.port, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.username, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.password, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.netif_kind,
                     esfnm_param_expect.normal_mode.netif_kind);
        will_return(__wrap_EsfNetworkManagerSaveParameter, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerStart. Will connect.

        will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
        will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);
    }

    // Check StartSyncNtp. Will sync.

    {
        // Check EsfClockManagerSetParams.

        expect_value(__wrap_EsfClockManagerSetParams, mask->connect.hostname, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->common.sync_interval,
                     cm_mask.common.sync_interval);
        expect_value(__wrap_EsfClockManagerSetParams, mask->common.polling_time,
                     cm_mask.common.polling_time);
        expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.type,
                     cm_mask.skip_and_limit.type);
        expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_packet_time, 0);
        expect_value(__wrap_EsfClockManagerSetParams,
                     mask->skip_and_limit.limit_rtc_correction_value, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.sanity_limit, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.type,
                     cm_mask.slew_setting.type);
        expect_value(__wrap_EsfClockManagerSetParams,
                     mask->slew_setting.stable_rtc_correction_value, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_sync_number, 0);
        expect_value(__wrap_EsfClockManagerSetParams, data->common.sync_interval,
                     cm_param.common.sync_interval);
        expect_value(__wrap_EsfClockManagerSetParams, data->common.polling_time,
                     cm_param.common.polling_time);
        expect_value(__wrap_EsfClockManagerSetParams, data->skip_and_limit.type,
                     cm_param.skip_and_limit.type);
        expect_value(__wrap_EsfClockManagerSetParams, data->slew_setting.type,
                     cm_param.slew_setting.type);
        will_return(__wrap_EsfClockManagerSetParams, kClockManagerSuccess);

        // Check EsfClockManagerRegisterCbOnNtpSyncComplete.

        will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

        // Check EsfClockManagerStart.

        will_return(__wrap_EsfClockManagerStart, true);
        will_return(__wrap_EsfClockManagerStart, true);
        will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

        // Check EsfClockManagerUnregisterCbOnNtpSyncComplete.

        will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);
    }

    // Check SetupEvpAgent.

    {
        struct SYS_client *expect_client = (struct SYS_client *)0x98765432;

        // Check SetDefaultEndpoint. Will success.

        {
            SetDefaultEndpoint_FullySuccess();
        }

        // Check task_create.
        task_create_Success();

        // Check EVP_Agent_register_sys_client.

        will_return(__wrap_EVP_Agent_register_sys_client, expect_client);

        // Check SYS_set_configuration_cb. system_settings.

        will_return(__wrap_SYS_set_configuration_cb, true); // Call cb.
        will_return(__wrap_SYS_set_configuration_cb, SYS_RESULT_OK);
        expect_any(__wrap_SYS_set_configuration_cb, c);
        expect_string(__wrap_SYS_set_configuration_cb, topic, "system_settings");
        expect_value(__wrap_SYS_set_configuration_cb, cb, ConfigurationCallback);
        expect_value(__wrap_SYS_set_configuration_cb, type, SYS_CONFIG_ANY);
        expect_any(__wrap_SYS_set_configuration_cb, user);

        // For CheckAllowlist. Mode is not IsaPsMode_Enrollment, so no operation.
        EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
        EsfJsonValue val = 1357;
        const char *param = "";
        const char *req_id_ptr = "TEST";
        will_return(__wrap_EsfJsonOpen, handle_val);
        will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

        expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
        expect_string(__wrap_EsfJsonDeserialize, str, param);
        will_return(__wrap_EsfJsonDeserialize, val);
        will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

        expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
        expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
        will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
        will_return(__wrap_SysAppCmnGetReqId, kRetOk);

        expect_value(__wrap_EsfJsonClose, handle, handle_val);
        will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

        // Check SYS_set_configuration_cb. endpoint_settings.

        will_return(__wrap_SYS_set_configuration_cb, true); // Don't call cb.
        will_return(__wrap_SYS_set_configuration_cb, SYS_RESULT_OK);
        expect_any(__wrap_SYS_set_configuration_cb, c);
        expect_string(__wrap_SYS_set_configuration_cb, topic, "PRIVATE_endpoint_settings");
        expect_value(__wrap_SYS_set_configuration_cb, cb, ConfigurationCallback);
        expect_value(__wrap_SYS_set_configuration_cb, type, SYS_CONFIG_ANY);
        expect_any(__wrap_SYS_set_configuration_cb, user);

        // Check ConfigurationCallback.

        {
            // Nop.
        }

        // Check SYS_register_command_cb. reboot callback will be called.

        expect_any(__wrap_SYS_register_command_cb, c);
        expect_string(__wrap_SYS_register_command_cb, command, "reboot");
        expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandRebootCallback);
        expect_any(__wrap_SYS_register_command_cb, user);
        will_return(__wrap_SYS_register_command_cb, false); // Don't call cb.
        will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

        // Check EsfSystemManagerSetQrModeTimeoutValue.

        expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
        will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    }

    // 1st loop.

    {
        // Check SYS_process_event.

        will_return(__wrap_EVP_getAgentStatus, EVP_AGENT_STATUS_CONNECTED);
        expect_any(__wrap_SYS_process_event, c);
        expect_value(__wrap_SYS_process_event, ms, 0);
        will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

        // Check IsaBtnCheckFactoryResetRequest.

        will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);

        // Check IsaBtnCheckRebootRequest.

        expect_function_call(__wrap_IsaBtnCheckRebootRequest);
        will_return(__wrap_IsaBtnCheckRebootRequest, false);

        // Check SendEnrollmentData. Will fail.

        {
            // Check GetEnrollmentData. Will fail.

            {
                // Check malloc for manifest.

                will_return(mock_malloc, true);
                will_return(mock_malloc, false);
                expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_DEVICE_MANIFEST_MAX_SIZE);

                // Check malloc for project id.

                will_return(mock_malloc, true);
                will_return(mock_malloc, false);
                expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_PROJECT_ID_MAX_SIZE);

                // Check malloc for register token.

                will_return(mock_malloc, true);
                will_return(mock_malloc, false);
                expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_REGISTER_TOKEN_MAX_SIZE);
            }
        }
    }

    // 2nd loop.

    {
        // Check SYS_process_event.

        will_return(__wrap_EVP_getAgentStatus, EVP_AGENT_STATUS_CONNECTED);
        expect_any(__wrap_SYS_process_event, c);
        expect_value(__wrap_SYS_process_event, ms, 0);
        will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

        // Check IsaBtnCheckFactoryResetRequest.

        will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);

        // Check IsaBtnCheckRebootRequest.

        expect_function_call(__wrap_IsaBtnCheckRebootRequest);
        will_return(__wrap_IsaBtnCheckRebootRequest, false);
    }

    // 3rd loop.

    {
        // Check SYS_process_event.

        will_return(__wrap_EVP_getAgentStatus, EVP_AGENT_STATUS_CONNECTED);
        expect_any(__wrap_SYS_process_event, c);
        expect_value(__wrap_SYS_process_event, ms, 0);
        will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

        // Check IsaBtnCheckFactoryResetRequest.

        will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);

        // Check IsaBtnCheckRebootRequest.

        expect_function_call(__wrap_IsaBtnCheckRebootRequest);
        will_return(__wrap_IsaBtnCheckRebootRequest, true);

        // Check EsfSystemManagerSetQrModeTimeoutValue.

        expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, -1);
        will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    }

    // Check EsfPwrMgrWdtTerminate.

    // ReleaseEvpAgent

    {
        // Check EVP_Agent_unregister_sys_client.

        will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

        // Check EsfLogManagerDeinit.
#if defined(__linux__)
        // workaround for Nuttx occur issue on FR.
        will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);
#endif

        // Check task_delete.
#if defined(__NuttX__)
        will_return(__wrap_task_delete, 0);
#endif
    }

    // Check IsaBtnCheckRebootRequest.

    expect_function_call(__wrap_IsaBtnCheckRebootRequest);
    will_return(__wrap_IsaBtnCheckRebootRequest, true);

    // Check EsfClockManagerStop.

    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    // Check EsfPwrMgrPrepareReboot.

    expect_function_call(__wrap_EsfPwrMgrPrepareReboot);
    will_return(__wrap_EsfPwrMgrPrepareReboot, kEsfPwrMgrOk);

    // Check free.

    will_return(mock_free, false);

    // Execute target.
    ret = IsaRunProvisioningService(is_ps_mode_force_entory);

    // Check return value.

    assert_int_equal(ret, kIsaPsReboot);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaRunProvisioningService_PsInfoAllocError(void **state)
{
    RetCode ret;
    bool is_ps_mode_force_entory = false;

    will_return(mock_malloc, true);
    will_return(mock_malloc, false);
    expect_value(mock_malloc, __size, sizeof(PsInfo));

    ret = IsaRunProvisioningService(is_ps_mode_force_entory);

    assert_int_equal(ret, kIsaPsDoesntRun);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaRunProvisioningService_ConnectNetwork_Abort(void **state)
{
    RetCode ret;
    bool is_ps_mode_force_entory = true;
    EsfNetworkManagerParameterMask esfnm_mask_expect = {0};
    EsfNetworkManagerParameter esfnm_param_expect = {0};

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(PsInfo));

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // ConnectNetwork() call, will be aborted.

    {
        memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
        memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
        esfnm_mask_expect.normal_mode.netif_kind = 1;
        esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

        // Check for EsfNetworkManagerOpen.

        will_return(__wrap_EsfNetworkManagerOpen, 777);
        will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerRegisterCallback.

        will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerLoadParameter.

        will_return(__wrap_EsfNetworkManagerLoadParameter, "");
        will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerSaveParameter.

        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.ip, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.subnet_mask,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.gateway, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.dns, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.ip, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.subnet_mask,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.gateway, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.dns, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.ssid, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.password, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.encryption,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.ip_method, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.netif_kind,
                     esfnm_mask_expect.normal_mode.netif_kind);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.ip, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter,
                     mask->accesspoint_mode.dev_ip.subnet_mask, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.gateway,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.dns, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.ssid, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.password,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter,
                     mask->accesspoint_mode.wifi_ap.encryption, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.channel,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.url, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.port, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.username, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.password, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.netif_kind,
                     esfnm_param_expect.normal_mode.netif_kind);
        will_return(__wrap_EsfNetworkManagerSaveParameter, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerStart. Will not connect.

        will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoDisconnected);
        will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

        // Check IsaBtnCheckFactoryResetRequest.

        will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);

        // Check IsaBtnCheckRebootRequest.

        expect_function_call(__wrap_IsaBtnCheckRebootRequest);
        will_return(__wrap_IsaBtnCheckRebootRequest, true);

        // Check IsaBtnCheckFactoryResetRequest

        will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);

        // Check EsfNetworkManagerStop.

        will_return(__wrap_EsfNetworkManagerStop, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerUnregisterCallback.

        will_return(__wrap_EsfNetworkManagerUnregisterCallback, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerClose.

        will_return(__wrap_EsfNetworkManagerClose, kEsfNetworkManagerResultSuccess);
    }

    // Check EsfPwrMgrWdtTerminate.

    // ReleaseEvpAgent

    {
        // Nop because SetupEvpAgent will not be executed.
    }

    // Check EsfLogManagerDeinit.
#if defined(__linux__)
    // workaround for Nuttx occur issue on FR.
    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);
#endif

    // Check IsaBtnCheckRebootRequest.

    expect_function_call(__wrap_IsaBtnCheckRebootRequest);
    will_return(__wrap_IsaBtnCheckRebootRequest, true);

    // Check EsfClockManagerStop.

    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    // Check EsfPwrMgrPrepareReboot.

    expect_function_call(__wrap_EsfPwrMgrPrepareReboot);
    will_return(__wrap_EsfPwrMgrPrepareReboot, kEsfPwrMgrOk);

    // Check free.

    will_return(mock_free, false);

    // Execute target.

    ret = IsaRunProvisioningService(is_ps_mode_force_entory);

    // Check return value.

    assert_int_equal(ret, kIsaPsReboot);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaRunProvisioningService_ConnectNetwork_Abort_FR(void **state)
{
    RetCode ret;
    bool is_ps_mode_force_entory = true;
    EsfNetworkManagerParameterMask esfnm_mask_expect = {0};
    EsfNetworkManagerParameter esfnm_param_expect = {0};

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(PsInfo));

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // ConnectNetwork() call, will be aborted.

    {
        memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
        memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
        esfnm_mask_expect.normal_mode.netif_kind = 1;
        esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

        // Check for EsfNetworkManagerOpen.

        will_return(__wrap_EsfNetworkManagerOpen, 777);
        will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerRegisterCallback.

        will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerLoadParameter.

        will_return(__wrap_EsfNetworkManagerLoadParameter, "");
        will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerSaveParameter.

        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.ip, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.subnet_mask,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.gateway, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.dns, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.ip, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.subnet_mask,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.gateway, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.dns, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.ssid, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.password, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.encryption,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.ip_method, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.netif_kind,
                     esfnm_mask_expect.normal_mode.netif_kind);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.ip, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter,
                     mask->accesspoint_mode.dev_ip.subnet_mask, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.gateway,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.dns, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.ssid, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.password,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter,
                     mask->accesspoint_mode.wifi_ap.encryption, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.channel,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.url, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.port, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.username, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.password, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.netif_kind,
                     esfnm_param_expect.normal_mode.netif_kind);
        will_return(__wrap_EsfNetworkManagerSaveParameter, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerStart. Will not connect.

        will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoDisconnected);
        will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

        // Check IsaBtnCheckRebootRequest.

        expect_function_call(__wrap_IsaBtnCheckRebootRequest);
        will_return(__wrap_IsaBtnCheckRebootRequest, false);

        // Check IsaBtnCheckFactoryResetRequest.

        will_return(__wrap_IsaBtnCheckFactoryResetRequest, true);

        // Check IsaBtnCheckFactoryResetRequest.

        will_return(__wrap_IsaBtnCheckFactoryResetRequest, true);

        // Check EsfLedManagerSetLightingPersistence.

        will_return(__wrap_EsfLedManagerSetLightingPersistence, kEsfLedManagerSuccess);

        // Check EsfNetworkManagerStop.

        will_return(__wrap_EsfNetworkManagerStop, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerUnregisterCallback.

        will_return(__wrap_EsfNetworkManagerUnregisterCallback, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerClose.

        will_return(__wrap_EsfNetworkManagerClose, kEsfNetworkManagerResultSuccess);
    }
    // Check EsfPwrMgrWdtTerminate.

    // ReleaseEvpAgent

    {
        // Nop because SetupEvpAgent will not be executed.
    }

    // Check EsfLogManagerDeinit.
#if defined(__linux__)
    // workaround for Nuttx occur issue on FR.
    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);
#endif

    // Check IsaBtnCheckFactoryResetRequest.

    will_return(__wrap_IsaBtnCheckFactoryResetRequest, true);

    // Check IsaBtnCheckRebootRequest.

    expect_function_call(__wrap_IsaBtnCheckRebootRequest);
    will_return(__wrap_IsaBtnCheckRebootRequest, false);

    expect_any(__wrap_EsfSystemManagerSetProjectId, data);
    expect_value(__wrap_EsfSystemManagerSetProjectId, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetProjectId, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetRegisterToken, data);
    expect_value(__wrap_EsfSystemManagerSetRegisterToken, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetRegisterToken, kEsfSystemManagerResultOk);

    // Check EsfClockManagerStop.

    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    // UnsetLedStatusForProvisioningService()

    {
        // Check EsfLedManagerSetStatus.

        expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
        expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                     kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
        expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
        will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);
    }

    // Check IsaBtnExecuteFactoryResetCore

    will_return(__wrap_IsaBtnExecuteFactoryResetCore, kRetOk);

    // Check free.

    will_return(mock_free, false);

    // Execute target.

    ret = IsaRunProvisioningService(is_ps_mode_force_entory);

    // Check return value.

    assert_int_equal(ret, kIsaPsFactoryReset);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaRunProvisioningService_ConnectNetwork_Error(void **state)
{
    RetCode ret;
    bool is_ps_mode_force_entory = true;
    EsfNetworkManagerParameterMask esfnm_mask_expect = {0};
    EsfNetworkManagerParameter esfnm_param_expect = {0};

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(PsInfo));

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // ConnectNetwork() 1st call, will be failed.

    {
        memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
        memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
        esfnm_mask_expect.normal_mode.netif_kind = 1;
        esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

        // Check for EsfNetworkManagerOpen.

        will_return(__wrap_EsfNetworkManagerOpen, 777);
        will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultInvalidParameter);
    }

    expect_any(__wrap_EsfSystemManagerSetEvpHubUrl, data);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetEvpHubPort, data);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetProjectId, data);
    expect_value(__wrap_EsfSystemManagerSetProjectId, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetProjectId, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetRegisterToken, data);
    expect_value(__wrap_EsfSystemManagerSetRegisterToken, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetRegisterToken, kEsfSystemManagerResultOk);

    // Check EsfClockManagerStop.

    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    // Check UnsetLedStatusForProvisioningService.
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // Check free.

    will_return(mock_free, false);

    // Execute target.

    ret = IsaRunProvisioningService(is_ps_mode_force_entory);

    // Check return value.

    assert_int_equal(ret, kIsaPsSwitchToQrMode);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaRunProvisioningService_ErrorStartNTP(void **state)
{
    RetCode ret;
    bool is_ps_mode_force_entory = true;

    EsfClockManagerParams cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    EsfClockManagerParamsMask cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    EsfNetworkManagerParameterMask esfnm_mask_expect = {0};
    EsfNetworkManagerParameter esfnm_param_expect = {0};

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(PsInfo));

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // ConnectNetwork()
    memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

    will_return(__wrap_EsfNetworkManagerOpen, 777);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.subnet_mask, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.subnet_mask, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.ssid, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.password, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.encryption, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.ip_method, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.netif_kind,
                 esfnm_mask_expect.normal_mode.netif_kind);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.subnet_mask,
                 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.ssid, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.password, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.encryption,
                 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.channel, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.url, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.port, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.username, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.password, 0);

    expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.netif_kind,
                 esfnm_param_expect.normal_mode.netif_kind);

    will_return(__wrap_EsfNetworkManagerSaveParameter, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultStatusAlreadyRunning);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // StartNTP()
    expect_value(__wrap_EsfClockManagerSetParams, mask->connect.hostname, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->common.sync_interval,
                 cm_mask.common.sync_interval);
    expect_value(__wrap_EsfClockManagerSetParams, mask->common.polling_time,
                 cm_mask.common.polling_time);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.type,
                 cm_mask.skip_and_limit.type);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_packet_time, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_rtc_correction_value,
                 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.sanity_limit, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.type,
                 cm_mask.slew_setting.type);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_rtc_correction_value,
                 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_sync_number, 0);

    expect_value(__wrap_EsfClockManagerSetParams, data->common.sync_interval,
                 cm_param.common.sync_interval);
    expect_value(__wrap_EsfClockManagerSetParams, data->common.polling_time,
                 cm_param.common.polling_time);
    expect_value(__wrap_EsfClockManagerSetParams, data->skip_and_limit.type,
                 cm_param.skip_and_limit.type);
    expect_value(__wrap_EsfClockManagerSetParams, data->slew_setting.type,
                 cm_param.slew_setting.type);

    will_return(__wrap_EsfClockManagerSetParams, kClockManagerInternalError);

    expect_any(__wrap_EsfSystemManagerSetEvpHubUrl, data);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetEvpHubPort, data);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetProjectId, data);
    expect_value(__wrap_EsfSystemManagerSetProjectId, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetProjectId, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetRegisterToken, data);
    expect_value(__wrap_EsfSystemManagerSetRegisterToken, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetRegisterToken, kEsfSystemManagerResultOk);

    // Check EsfClockManagerStop.

    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    // Check UnsetLedStatusForProvisioningService.
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    will_return(mock_free, false);

    ret = IsaRunProvisioningService(is_ps_mode_force_entory);

    assert_int_equal(ret, kIsaPsSwitchToQrMode);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaRunProvisioningService_StartSyncNtp_Abort_FactoryReset(void **state)
{
    RetCode ret;
    bool is_ps_mode_force_entory = false;

    EsfClockManagerParams cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    EsfClockManagerParamsMask cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    EsfNetworkManagerParameterMask esfnm_mask_expect = {0};
    EsfNetworkManagerParameter esfnm_param_expect = {0};

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(PsInfo));

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // ConnectNetwork()
    memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

    will_return(__wrap_EsfNetworkManagerOpen, 777);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.subnet_mask, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.subnet_mask, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.ssid, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.password, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.encryption, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.ip_method, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.netif_kind,
                 esfnm_mask_expect.normal_mode.netif_kind);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.subnet_mask,
                 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.ssid, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.password, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.encryption,
                 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.channel, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.url, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.port, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.username, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.password, 0);

    expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.netif_kind,
                 esfnm_param_expect.normal_mode.netif_kind);

    will_return(__wrap_EsfNetworkManagerSaveParameter, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultStatusAlreadyRunning);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // StartSyncNtp() - SetParams
    {
        // Check EsfClockManagerSetParams.

        expect_value(__wrap_EsfClockManagerSetParams, mask->connect.hostname, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->common.sync_interval,
                     cm_mask.common.sync_interval);
        expect_value(__wrap_EsfClockManagerSetParams, mask->common.polling_time,
                     cm_mask.common.polling_time);
        expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.type,
                     cm_mask.skip_and_limit.type);
        expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_packet_time, 0);
        expect_value(__wrap_EsfClockManagerSetParams,
                     mask->skip_and_limit.limit_rtc_correction_value, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.sanity_limit, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.type,
                     cm_mask.slew_setting.type);
        expect_value(__wrap_EsfClockManagerSetParams,
                     mask->slew_setting.stable_rtc_correction_value, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_sync_number, 0);
        expect_value(__wrap_EsfClockManagerSetParams, data->common.sync_interval,
                     cm_param.common.sync_interval);
        expect_value(__wrap_EsfClockManagerSetParams, data->common.polling_time,
                     cm_param.common.polling_time);
        expect_value(__wrap_EsfClockManagerSetParams, data->skip_and_limit.type,
                     cm_param.skip_and_limit.type);
        expect_value(__wrap_EsfClockManagerSetParams, data->slew_setting.type,
                     cm_param.slew_setting.type);
        will_return(__wrap_EsfClockManagerSetParams, kClockManagerSuccess);

        // Check EsfClockManagerRegisterCbOnNtpSyncComplete.

        will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

        will_return(__wrap_EsfClockManagerStart, false);
        will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

        // Check button calls in while loop (exactly 1 iteration)
        expect_function_call(__wrap_IsaBtnCheckRebootRequest);
        will_return(__wrap_IsaBtnCheckRebootRequest, false);

        will_return(__wrap_IsaBtnCheckFactoryResetRequest, true);

        will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);
        will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);
    }

    will_return(__wrap_IsaBtnCheckFactoryResetRequest, true);

    // Check EsfLogManagerDeinit.
#if defined(__linux__)
    // workaround for Nuttx occur issue on FR.
    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);
#endif

    // Check IsaBtnCheckRebootRequest at cleanup
    expect_function_call(__wrap_IsaBtnCheckRebootRequest);
    will_return(__wrap_IsaBtnCheckRebootRequest, false);

    expect_any(__wrap_EsfSystemManagerSetProjectId, data);
    expect_value(__wrap_EsfSystemManagerSetProjectId, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetProjectId, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetRegisterToken, data);
    expect_value(__wrap_EsfSystemManagerSetRegisterToken, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetRegisterToken, kEsfSystemManagerResultOk);

    // Check EsfClockManagerStop.

    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    // Check UnsetLedStatusForProvisioningService.
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // Check IsaBtnExecuteFactoryResetCore

    will_return(__wrap_IsaBtnExecuteFactoryResetCore, kRetOk);

    will_return(mock_free, false);

    ret = IsaRunProvisioningService(is_ps_mode_force_entory);

    assert_int_equal(ret, kIsaPsFactoryReset);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaRunProvisioningService_StartSyncNtp_Abort_Reboot(void **state)
{
    RetCode ret;
    bool is_ps_mode_force_entory = false;

    EsfClockManagerParams cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    EsfClockManagerParamsMask cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    EsfNetworkManagerParameterMask esfnm_mask_expect = {0};
    EsfNetworkManagerParameter esfnm_param_expect = {0};

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(PsInfo));

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // ConnectNetwork()
    memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

    will_return(__wrap_EsfNetworkManagerOpen, 777);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.subnet_mask, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.subnet_mask, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.ssid, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.password, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.encryption, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.ip_method, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.netif_kind,
                 esfnm_mask_expect.normal_mode.netif_kind);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.subnet_mask,
                 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.ssid, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.password, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.encryption,
                 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.channel, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.url, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.port, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.username, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.password, 0);

    expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.netif_kind,
                 esfnm_param_expect.normal_mode.netif_kind);

    will_return(__wrap_EsfNetworkManagerSaveParameter, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultStatusAlreadyRunning);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // StartSyncNtp() - SetParams
    {
        // Check EsfClockManagerSetParams.

        expect_value(__wrap_EsfClockManagerSetParams, mask->connect.hostname, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->common.sync_interval,
                     cm_mask.common.sync_interval);
        expect_value(__wrap_EsfClockManagerSetParams, mask->common.polling_time,
                     cm_mask.common.polling_time);
        expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.type,
                     cm_mask.skip_and_limit.type);
        expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_packet_time, 0);
        expect_value(__wrap_EsfClockManagerSetParams,
                     mask->skip_and_limit.limit_rtc_correction_value, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.sanity_limit, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.type,
                     cm_mask.slew_setting.type);
        expect_value(__wrap_EsfClockManagerSetParams,
                     mask->slew_setting.stable_rtc_correction_value, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_sync_number, 0);
        expect_value(__wrap_EsfClockManagerSetParams, data->common.sync_interval,
                     cm_param.common.sync_interval);
        expect_value(__wrap_EsfClockManagerSetParams, data->common.polling_time,
                     cm_param.common.polling_time);
        expect_value(__wrap_EsfClockManagerSetParams, data->skip_and_limit.type,
                     cm_param.skip_and_limit.type);
        expect_value(__wrap_EsfClockManagerSetParams, data->slew_setting.type,
                     cm_param.slew_setting.type);
        will_return(__wrap_EsfClockManagerSetParams, kClockManagerSuccess);

        // Check EsfClockManagerRegisterCbOnNtpSyncComplete.

        will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

        will_return(__wrap_EsfClockManagerStart, false);
        will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

        expect_function_call(__wrap_IsaBtnCheckRebootRequest);
        will_return(__wrap_IsaBtnCheckRebootRequest, true);

        will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);
        will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);
    }

    will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);

    // ReleaseEvpAgent
    // Check EsfLogManagerDeinit.
#if defined(__linux__)
    // workaround for Nuttx occur issue on FR.
    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);
#endif

    // Check IsaBtnCheckRebootRequest at cleanup
    expect_function_call(__wrap_IsaBtnCheckRebootRequest);
    will_return(__wrap_IsaBtnCheckRebootRequest, true);

    // Check EsfClockManagerStop.

    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    // Check EsfPwrMgrPrepareReboot.

    expect_function_call(__wrap_EsfPwrMgrPrepareReboot);
    will_return(__wrap_EsfPwrMgrPrepareReboot, kEsfPwrMgrOk);

    will_return(mock_free, false);

    ret = IsaRunProvisioningService(is_ps_mode_force_entory);

    assert_int_equal(ret, kIsaPsReboot);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaRunProvisioningService_Error_SetupEvpAgent(void **state)
{
    RetCode ret;
    bool is_ps_mode_force_entory = false;
    EsfNetworkManagerParameterMask esfnm_mask_expect = {0};
    EsfNetworkManagerParameter esfnm_param_expect = {0};
    EsfClockManagerParams cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    EsfClockManagerParamsMask cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(PsInfo));

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // ConnectNetwork() 2nd call, will be aborted.

    {
        memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
        memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
        esfnm_mask_expect.normal_mode.netif_kind = 1;
        esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

        // Check for EsfNetworkManagerOpen.

        will_return(__wrap_EsfNetworkManagerOpen, 777);
        will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerRegisterCallback.

        will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerLoadParameter.

        will_return(__wrap_EsfNetworkManagerLoadParameter, "");
        will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerSaveParameter.

        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.ip, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.subnet_mask,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.gateway, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.dns, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.ip, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.subnet_mask,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.gateway, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.dns, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.ssid, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.password, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.encryption,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.ip_method, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.netif_kind,
                     esfnm_mask_expect.normal_mode.netif_kind);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.ip, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter,
                     mask->accesspoint_mode.dev_ip.subnet_mask, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.gateway,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.dns, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.ssid, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.password,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter,
                     mask->accesspoint_mode.wifi_ap.encryption, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.channel,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.url, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.port, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.username, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.password, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.netif_kind,
                     esfnm_param_expect.normal_mode.netif_kind);
        will_return(__wrap_EsfNetworkManagerSaveParameter, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerStart. Will connect.

        will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
        will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);
    }

    // Check StartSyncNtp. Will sync.

    {
        // Check EsfClockManagerSetParams.

        expect_value(__wrap_EsfClockManagerSetParams, mask->connect.hostname, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->common.sync_interval,
                     cm_mask.common.sync_interval);
        expect_value(__wrap_EsfClockManagerSetParams, mask->common.polling_time,
                     cm_mask.common.polling_time);
        expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.type,
                     cm_mask.skip_and_limit.type);
        expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_packet_time, 0);
        expect_value(__wrap_EsfClockManagerSetParams,
                     mask->skip_and_limit.limit_rtc_correction_value, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.sanity_limit, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.type,
                     cm_mask.slew_setting.type);
        expect_value(__wrap_EsfClockManagerSetParams,
                     mask->slew_setting.stable_rtc_correction_value, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_sync_number, 0);
        expect_value(__wrap_EsfClockManagerSetParams, data->common.sync_interval,
                     cm_param.common.sync_interval);
        expect_value(__wrap_EsfClockManagerSetParams, data->common.polling_time,
                     cm_param.common.polling_time);
        expect_value(__wrap_EsfClockManagerSetParams, data->skip_and_limit.type,
                     cm_param.skip_and_limit.type);
        expect_value(__wrap_EsfClockManagerSetParams, data->slew_setting.type,
                     cm_param.slew_setting.type);
        will_return(__wrap_EsfClockManagerSetParams, kClockManagerSuccess);

        // Check EsfClockManagerRegisterCbOnNtpSyncComplete.

        will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

        // Check EsfClockManagerStart.

        will_return(__wrap_EsfClockManagerStart, true);
        will_return(__wrap_EsfClockManagerStart, true);
        will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

        // Check EsfClockManagerUnregisterCbOnNtpSyncComplete.

        will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);
    }

    // Check SetupEvpAgent. Will return failed.

    { // Check SetDefaultEndpoint. Will return failed.

        { // Check mqtt_host malloc. Will return NULL.

            will_return(mock_malloc, true);
            will_return(mock_malloc, false);
            expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE);

            // Check mqtt_port malloc. Will return NULL.

            will_return(mock_malloc, true);
            will_return(mock_malloc, false);
            expect_value(mock_malloc, __size, ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE);
        }
    }

    // Check EsfPwrMgrWdtTerminate.

    // ReleaseEvpAgent

    {
        // Nop because SetupEvpAgent returned with NULL client.
    }

    expect_any(__wrap_EsfSystemManagerSetEvpHubUrl, data);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetEvpHubPort, data);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetProjectId, data);
    expect_value(__wrap_EsfSystemManagerSetProjectId, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetProjectId, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetRegisterToken, data);
    expect_value(__wrap_EsfSystemManagerSetRegisterToken, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetRegisterToken, kEsfSystemManagerResultOk);

    // Check EsfClockManagerStop.

    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    // Check UnsetLedStatusForProvisioningService.
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // Check free.

    will_return(mock_free, false);

    // Execute target.

    ret = IsaRunProvisioningService(is_ps_mode_force_entory);

    // Check return value.

    assert_int_equal(ret, kIsaPsSwitchToQrMode);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaRunProvisioningService_EvpConnectWait_FactoryResetRequested(void **state)
{
    RetCode ret;
    bool is_ps_mode_force_entory = true;

    EsfClockManagerParams cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    EsfClockManagerParamsMask cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    EsfNetworkManagerParameterMask esfnm_mask_expect = {0};
    EsfNetworkManagerParameter esfnm_param_expect = {0};

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(PsInfo));

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // ConnectNetwork()
    memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

    will_return(__wrap_EsfNetworkManagerOpen, 777);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.subnet_mask, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.subnet_mask, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.ssid, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.password, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.encryption, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.ip_method, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.netif_kind,
                 esfnm_mask_expect.normal_mode.netif_kind);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.subnet_mask,
                 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.ssid, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.password, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.encryption,
                 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.channel, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.url, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.port, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.username, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.password, 0);

    expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.netif_kind,
                 esfnm_param_expect.normal_mode.netif_kind);

    will_return(__wrap_EsfNetworkManagerSaveParameter, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultStatusAlreadyRunning);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // StartNTP()
    expect_value(__wrap_EsfClockManagerSetParams, mask->connect.hostname, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->common.sync_interval,
                 cm_mask.common.sync_interval);
    expect_value(__wrap_EsfClockManagerSetParams, mask->common.polling_time,
                 cm_mask.common.polling_time);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.type,
                 cm_mask.skip_and_limit.type);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_packet_time, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_rtc_correction_value,
                 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.sanity_limit, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.type,
                 cm_mask.slew_setting.type);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_rtc_correction_value,
                 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_sync_number, 0);

    expect_value(__wrap_EsfClockManagerSetParams, data->common.sync_interval,
                 cm_param.common.sync_interval);
    expect_value(__wrap_EsfClockManagerSetParams, data->common.polling_time,
                 cm_param.common.polling_time);
    expect_value(__wrap_EsfClockManagerSetParams, data->skip_and_limit.type,
                 cm_param.skip_and_limit.type);
    expect_value(__wrap_EsfClockManagerSetParams, data->slew_setting.type,
                 cm_param.slew_setting.type);

    will_return(__wrap_EsfClockManagerSetParams, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerStart, true);
    will_return(__wrap_EsfClockManagerStart, true);
    will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // SetupEvpAgent
    SetupEvpAgent_FullySuccess();

    // Loop to simulate EVP connection wait with factory reset request
    {
        // First call to EVP_getAgentStatus - not connected
        will_return(__wrap_EVP_getAgentStatus, EVP_AGENT_STATUS_DISCONNECTED);

        // Check IsaBtnCheckRebootRequest
        will_return(__wrap_IsaBtnCheckFactoryResetRequest, true);
    }

    // ReleaseEvpAgent

    {
        // Check EVP_Agent_unregister_sys_client.

        will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

        // Check EsfLogManagerDeinit.
#if defined(__linux__)
        // workaround for Nuttx occur issue on FR.
        will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);
#endif

        // Check task_delete.
#if defined(__NuttX__)
        will_return(__wrap_task_delete, 0);
#endif
    }

    // Check IsaBtnCheckRebootRequest at cleanup
    expect_function_call(__wrap_IsaBtnCheckRebootRequest);
    will_return(__wrap_IsaBtnCheckRebootRequest, false);

    expect_any(__wrap_EsfSystemManagerSetProjectId, data);
    expect_value(__wrap_EsfSystemManagerSetProjectId, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetProjectId, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetRegisterToken, data);
    expect_value(__wrap_EsfSystemManagerSetRegisterToken, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetRegisterToken, kEsfSystemManagerResultOk);

    // Check EsfClockManagerStop.

    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    // Check UnsetLedStatusForProvisioningService.
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // Check IsaBtnExecuteFactoryResetCore

    will_return(__wrap_IsaBtnExecuteFactoryResetCore, kRetOk);

    will_return(mock_free, false);

    ret = IsaRunProvisioningService(is_ps_mode_force_entory);

    assert_int_equal(ret, kIsaPsFactoryReset);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaRunProvisioningService_EvpConnectWait_RebootRequested_SetQrModeSuccess(
    void **state)
{
    RetCode ret;
    bool is_ps_mode_force_entory = true;

    EsfClockManagerParams cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    EsfClockManagerParamsMask cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    EsfNetworkManagerParameterMask esfnm_mask_expect = {0};
    EsfNetworkManagerParameter esfnm_param_expect = {0};

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(PsInfo));

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // ConnectNetwork()
    memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

    will_return(__wrap_EsfNetworkManagerOpen, 777);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.subnet_mask, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.subnet_mask, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.ssid, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.password, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.encryption, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.ip_method, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.netif_kind,
                 esfnm_mask_expect.normal_mode.netif_kind);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.subnet_mask,
                 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.ssid, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.password, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.encryption,
                 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.channel, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.url, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.port, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.username, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.password, 0);

    expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.netif_kind,
                 esfnm_param_expect.normal_mode.netif_kind);

    will_return(__wrap_EsfNetworkManagerSaveParameter, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultStatusAlreadyRunning);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // StartNTP()
    expect_value(__wrap_EsfClockManagerSetParams, mask->connect.hostname, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->common.sync_interval,
                 cm_mask.common.sync_interval);
    expect_value(__wrap_EsfClockManagerSetParams, mask->common.polling_time,
                 cm_mask.common.polling_time);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.type,
                 cm_mask.skip_and_limit.type);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_packet_time, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_rtc_correction_value,
                 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.sanity_limit, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.type,
                 cm_mask.slew_setting.type);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_rtc_correction_value,
                 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_sync_number, 0);

    expect_value(__wrap_EsfClockManagerSetParams, data->common.sync_interval,
                 cm_param.common.sync_interval);
    expect_value(__wrap_EsfClockManagerSetParams, data->common.polling_time,
                 cm_param.common.polling_time);
    expect_value(__wrap_EsfClockManagerSetParams, data->skip_and_limit.type,
                 cm_param.skip_and_limit.type);
    expect_value(__wrap_EsfClockManagerSetParams, data->slew_setting.type,
                 cm_param.slew_setting.type);

    will_return(__wrap_EsfClockManagerSetParams, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerStart, true);
    will_return(__wrap_EsfClockManagerStart, true);
    will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // SetupEvpAgent
    SetupEvpAgent_FullySuccess();

    // Loop to simulate EVP connection wait with reboot request
    {
        // First call to EVP_getAgentStatus - not connected
        will_return(__wrap_EVP_getAgentStatus, EVP_AGENT_STATUS_DISCONNECTED);

        // Check IsaBtnCheckFactoryResetRequest - false
        will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);

        // Check IsaBtnCheckRebootRequest - true
        expect_function_call(__wrap_IsaBtnCheckRebootRequest);
        will_return(__wrap_IsaBtnCheckRebootRequest, true);

        // EsfSystemManagerSetQrModeTimeoutValue should be called with -1 and succeed
        expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, -1);
        will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    }

    // ReleaseEvpAgent
    {
        // Check EVP_Agent_unregister_sys_client.
        will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

        // Check EsfLogManagerDeinit.
#if defined(__linux__)
        // workaround for Nuttx occur issue on FR.
        will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);
#endif

        // Check task_delete.
#if defined(__NuttX__)
        will_return(__wrap_task_delete, 0);
#endif
    }

    // Check IsaBtnCheckRebootRequest at cleanup
    expect_function_call(__wrap_IsaBtnCheckRebootRequest);
    will_return(__wrap_IsaBtnCheckRebootRequest, true);

    // Check EsfClockManagerStop.
    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    // Check EsfPwrMgrPrepareReboot.

    expect_function_call(__wrap_EsfPwrMgrPrepareReboot);
    will_return(__wrap_EsfPwrMgrPrepareReboot, kEsfPwrMgrOk);

    will_return(mock_free, false);

    ret = IsaRunProvisioningService(is_ps_mode_force_entory);

    assert_int_equal(ret, kIsaPsReboot);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaRunProvisioningService_EvpConnectWait_RebootRequested_SetQrModeError(
    void **state)
{
    RetCode ret;
    bool is_ps_mode_force_entory = true;

    EsfClockManagerParams cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    EsfClockManagerParamsMask cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    EsfNetworkManagerParameterMask esfnm_mask_expect = {0};
    EsfNetworkManagerParameter esfnm_param_expect = {0};

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(PsInfo));

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // ConnectNetwork()
    memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

    will_return(__wrap_EsfNetworkManagerOpen, 777);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.subnet_mask, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.subnet_mask, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.ssid, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.password, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.encryption, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.ip_method, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.netif_kind,
                 esfnm_mask_expect.normal_mode.netif_kind);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.subnet_mask,
                 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.ssid, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.password, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.encryption,
                 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.channel, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.url, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.port, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.username, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.password, 0);

    expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.netif_kind,
                 esfnm_param_expect.normal_mode.netif_kind);

    will_return(__wrap_EsfNetworkManagerSaveParameter, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultStatusAlreadyRunning);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // StartNTP()
    expect_value(__wrap_EsfClockManagerSetParams, mask->connect.hostname, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->common.sync_interval,
                 cm_mask.common.sync_interval);
    expect_value(__wrap_EsfClockManagerSetParams, mask->common.polling_time,
                 cm_mask.common.polling_time);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.type,
                 cm_mask.skip_and_limit.type);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_packet_time, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_rtc_correction_value,
                 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.sanity_limit, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.type,
                 cm_mask.slew_setting.type);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_rtc_correction_value,
                 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_sync_number, 0);

    expect_value(__wrap_EsfClockManagerSetParams, data->common.sync_interval,
                 cm_param.common.sync_interval);
    expect_value(__wrap_EsfClockManagerSetParams, data->common.polling_time,
                 cm_param.common.polling_time);
    expect_value(__wrap_EsfClockManagerSetParams, data->skip_and_limit.type,
                 cm_param.skip_and_limit.type);
    expect_value(__wrap_EsfClockManagerSetParams, data->slew_setting.type,
                 cm_param.slew_setting.type);

    will_return(__wrap_EsfClockManagerSetParams, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerStart, true);
    will_return(__wrap_EsfClockManagerStart, true);
    will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // SetupEvpAgent
    SetupEvpAgent_FullySuccess();

    // Loop to simulate EVP connection wait with reboot request
    {
        // First call to EVP_getAgentStatus - not connected
        will_return(__wrap_EVP_getAgentStatus, EVP_AGENT_STATUS_DISCONNECTED);

        // Check IsaBtnCheckFactoryResetRequest - false
        will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);

        // Check IsaBtnCheckRebootRequest - true
        expect_function_call(__wrap_IsaBtnCheckRebootRequest);
        will_return(__wrap_IsaBtnCheckRebootRequest, true);

        // EsfSystemManagerSetQrModeTimeoutValue should be called with -1 and fail
        expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, -1);
        will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue,
                    kEsfSystemManagerResultInternalError);
    }

    // ReleaseEvpAgent
    {
        // Check EVP_Agent_unregister_sys_client.
        will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

        // Check EsfLogManagerDeinit.
#if defined(__linux__)
        // workaround for Nuttx occur issue on FR.
        will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);
#endif

        // Check task_delete.
#if defined(__NuttX__)
        will_return(__wrap_task_delete, 0);
#endif
    }

    // Check IsaBtnCheckRebootRequest at cleanup
    expect_function_call(__wrap_IsaBtnCheckRebootRequest);
    will_return(__wrap_IsaBtnCheckRebootRequest, true);

    // Check EsfClockManagerStop.
    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    // Check EsfPwrMgrPrepareReboot.

    expect_function_call(__wrap_EsfPwrMgrPrepareReboot);
    will_return(__wrap_EsfPwrMgrPrepareReboot, kEsfPwrMgrOk);

    will_return(mock_free, false);

    ret = IsaRunProvisioningService(is_ps_mode_force_entory);

    assert_int_equal(ret, kIsaPsReboot);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaRunProvisioningService_EvpConnectTimeout(void **state)
{
    RetCode ret;
    bool is_ps_mode_force_entory = true;

    EsfClockManagerParams cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    EsfClockManagerParamsMask cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    EsfNetworkManagerParameterMask esfnm_mask_expect = {0};
    EsfNetworkManagerParameter esfnm_param_expect = {0};

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(PsInfo));

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // ConnectNetwork()
    memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

    will_return(__wrap_EsfNetworkManagerOpen, 777);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.subnet_mask, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.subnet_mask, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.ssid, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.password, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.encryption, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.ip_method, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.netif_kind,
                 esfnm_mask_expect.normal_mode.netif_kind);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.subnet_mask,
                 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.ssid, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.password, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.encryption,
                 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.channel, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.url, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.port, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.username, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.password, 0);

    expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.netif_kind,
                 esfnm_param_expect.normal_mode.netif_kind);

    will_return(__wrap_EsfNetworkManagerSaveParameter, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultStatusAlreadyRunning);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // StartNTP()
    expect_value(__wrap_EsfClockManagerSetParams, mask->connect.hostname, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->common.sync_interval,
                 cm_mask.common.sync_interval);
    expect_value(__wrap_EsfClockManagerSetParams, mask->common.polling_time,
                 cm_mask.common.polling_time);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.type,
                 cm_mask.skip_and_limit.type);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_packet_time, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_rtc_correction_value,
                 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.sanity_limit, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.type,
                 cm_mask.slew_setting.type);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_rtc_correction_value,
                 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_sync_number, 0);

    expect_value(__wrap_EsfClockManagerSetParams, data->common.sync_interval,
                 cm_param.common.sync_interval);
    expect_value(__wrap_EsfClockManagerSetParams, data->common.polling_time,
                 cm_param.common.polling_time);
    expect_value(__wrap_EsfClockManagerSetParams, data->skip_and_limit.type,
                 cm_param.skip_and_limit.type);
    expect_value(__wrap_EsfClockManagerSetParams, data->slew_setting.type,
                 cm_param.slew_setting.type);

    will_return(__wrap_EsfClockManagerSetParams, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerStart, true);
    will_return(__wrap_EsfClockManagerStart, true);
    will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // SetupEvpAgent
    SetupEvpAgent_FullySuccess();

    // Loop to simulate EVP connection timeout (30 iterations)
    // EVP_CONNECT_WAIT_MAX_SEC = 30
    for (int i = 0; i < 30; i++) {
        will_return(__wrap_EVP_getAgentStatus, EVP_AGENT_STATUS_DISCONNECTED);
        will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);
        expect_function_call(__wrap_IsaBtnCheckRebootRequest);
        will_return(__wrap_IsaBtnCheckRebootRequest, false);
    }

    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    expect_any(__wrap_EsfSystemManagerSetEvpHubUrl, data);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetEvpHubPort, data);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetProjectId, data);
    expect_value(__wrap_EsfSystemManagerSetProjectId, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetProjectId, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetRegisterToken, data);
    expect_value(__wrap_EsfSystemManagerSetRegisterToken, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetRegisterToken, kEsfSystemManagerResultOk);

    // Check EsfClockManagerStop.
    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    // Check UnsetLedStatusForProvisioningService.
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // Check free.
    will_return(mock_free, false);

    // Execute target.
    ret = IsaRunProvisioningService(is_ps_mode_force_entory);

    // Check return value.
    assert_int_equal(ret, kIsaPsSwitchToQrMode);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaRunProvisioningService_DirectCommandRebootRequested(void **state)
{
    RetCode ret;
    bool is_ps_mode_force_entory = false;
    EsfNetworkManagerParameterMask esfnm_mask_expect = {0};
    EsfNetworkManagerParameter esfnm_param_expect = {0};
    EsfClockManagerParams cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    EsfClockManagerParamsMask cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(PsInfo));

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // ConnectNetwork() 2nd call, will be aborted.

    {
        memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
        memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
        esfnm_mask_expect.normal_mode.netif_kind = 1;
        esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

        // Check for EsfNetworkManagerOpen.

        will_return(__wrap_EsfNetworkManagerOpen, 777);
        will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerRegisterCallback.

        will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerLoadParameter.

        will_return(__wrap_EsfNetworkManagerLoadParameter, "");
        will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerSaveParameter.

        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.ip, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.subnet_mask,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.gateway, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.dns, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.ip, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.subnet_mask,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.gateway, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.dns, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.ssid, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.password, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.encryption,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.ip_method, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.netif_kind,
                     esfnm_mask_expect.normal_mode.netif_kind);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.ip, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter,
                     mask->accesspoint_mode.dev_ip.subnet_mask, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.gateway,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.dns, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.ssid, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.password,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter,
                     mask->accesspoint_mode.wifi_ap.encryption, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.channel,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.url, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.port, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.username, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.password, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.netif_kind,
                     esfnm_param_expect.normal_mode.netif_kind);
        will_return(__wrap_EsfNetworkManagerSaveParameter, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerStart. Will connect.

        will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
        will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);
    }

    // Check StartSyncNtp. Will sync.

    {
        // Check EsfClockManagerSetParams.

        expect_value(__wrap_EsfClockManagerSetParams, mask->connect.hostname, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->common.sync_interval,
                     cm_mask.common.sync_interval);
        expect_value(__wrap_EsfClockManagerSetParams, mask->common.polling_time,
                     cm_mask.common.polling_time);
        expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.type,
                     cm_mask.skip_and_limit.type);
        expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_packet_time, 0);
        expect_value(__wrap_EsfClockManagerSetParams,
                     mask->skip_and_limit.limit_rtc_correction_value, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.sanity_limit, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.type,
                     cm_mask.slew_setting.type);
        expect_value(__wrap_EsfClockManagerSetParams,
                     mask->slew_setting.stable_rtc_correction_value, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_sync_number, 0);
        expect_value(__wrap_EsfClockManagerSetParams, data->common.sync_interval,
                     cm_param.common.sync_interval);
        expect_value(__wrap_EsfClockManagerSetParams, data->common.polling_time,
                     cm_param.common.polling_time);
        expect_value(__wrap_EsfClockManagerSetParams, data->skip_and_limit.type,
                     cm_param.skip_and_limit.type);
        expect_value(__wrap_EsfClockManagerSetParams, data->slew_setting.type,
                     cm_param.slew_setting.type);
        will_return(__wrap_EsfClockManagerSetParams, kClockManagerSuccess);

        // Check EsfClockManagerRegisterCbOnNtpSyncComplete.

        will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

        // Check EsfClockManagerStart.

        will_return(__wrap_EsfClockManagerStart, true);
        will_return(__wrap_EsfClockManagerStart, true);
        will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

        // Check EsfClockManagerUnregisterCbOnNtpSyncComplete.

        will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);
    }

    // Check SetupEvpAgent.

    {
        struct SYS_client *expect_client = (struct SYS_client *)0x98765432;

        // Check SetDefaultEndpoint. Will success.

        {
            SetDefaultEndpoint_FullySuccess();
        }

        // Check task_create.
        task_create_Success();

        // Check EVP_Agent_register_sys_client.

        will_return(__wrap_EVP_Agent_register_sys_client, expect_client);

        // Check SYS_set_configuration_cb. system_settings.

        will_return(__wrap_SYS_set_configuration_cb, false); // Don't call cb.
        will_return(__wrap_SYS_set_configuration_cb, SYS_RESULT_OK);
        expect_any(__wrap_SYS_set_configuration_cb, c);
        expect_string(__wrap_SYS_set_configuration_cb, topic, "system_settings");
        expect_value(__wrap_SYS_set_configuration_cb, cb, ConfigurationCallback);
        expect_value(__wrap_SYS_set_configuration_cb, type, SYS_CONFIG_ANY);
        expect_any(__wrap_SYS_set_configuration_cb, user);

        // Check SYS_set_configuration_cb. endpoint_settings.

        will_return(__wrap_SYS_set_configuration_cb, false); // Don't call cb.
        will_return(__wrap_SYS_set_configuration_cb, SYS_RESULT_OK);
        expect_any(__wrap_SYS_set_configuration_cb, c);
        expect_string(__wrap_SYS_set_configuration_cb, topic, "PRIVATE_endpoint_settings");
        expect_value(__wrap_SYS_set_configuration_cb, cb, ConfigurationCallback);
        expect_value(__wrap_SYS_set_configuration_cb, type, SYS_CONFIG_ANY);
        expect_any(__wrap_SYS_set_configuration_cb, user);

        // Check SYS_register_command_cb. reboot callback will be called.

        expect_any(__wrap_SYS_register_command_cb, c);
        expect_string(__wrap_SYS_register_command_cb, command, "reboot");
        expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandRebootCallback);
        expect_any(__wrap_SYS_register_command_cb, user);
        will_return(__wrap_SYS_register_command_cb, true);
        will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

        // Check DirectCommandRebootCallback. Will fail.

        {
            // Check SetResId.

            { // Check JsonOpenAndDeserialize. Will fail.

                {
                    EsfJsonHandle json_handle;
                    will_return(__wrap_EsfJsonOpen, json_handle);
                    will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);
                }
            }

            // Check SendDirectCommandResponse. Will fail.

            {
                // Check JsonOpenAndInit. Will fail.

                {
                    EsfJsonHandle json_handle;
                    will_return(__wrap_EsfJsonOpen, json_handle);
                    will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);
                }
            }
        }

        expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
        will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    }

    // Check SYS_process_event.
    will_return(__wrap_EVP_getAgentStatus, EVP_AGENT_STATUS_CONNECTED);
    expect_any(__wrap_SYS_process_event, c);
    expect_value(__wrap_SYS_process_event, ms, 0);
    will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

    // Check EsfPwrMgrWdtTerminate.

    // ReleaseEvpAgent

    {
        // Check EVP_Agent_unregister_sys_client.

        will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

        // Check EsfLogManagerDeinit.
#if defined(__linux__)
        // workaround for Nuttx occur issue on FR.
        will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);
#endif

        // Check task_delete.
#if defined(__NuttX__)
        will_return(__wrap_task_delete, 0);
#endif
    }

    // Check IsaBtnCheckRebootRequest.

    expect_function_call(__wrap_IsaBtnCheckRebootRequest);
    will_return(__wrap_IsaBtnCheckRebootRequest, true);

    // Check EsfClockManagerStop.

    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    // Check EsfPwrMgrPrepareReboot.

    expect_function_call(__wrap_EsfPwrMgrPrepareReboot);
    will_return(__wrap_EsfPwrMgrPrepareReboot, kEsfPwrMgrOk);

    // Check free.

    will_return(mock_free, false);

    // Execute target.

    ret = IsaRunProvisioningService(is_ps_mode_force_entory);

    // Check return value.

    assert_int_equal(ret, kIsaPsReboot);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaRunProvisioningService_ErrorReboot(void **state)
{
    RetCode ret;
    bool is_ps_mode_force_entory = true;

    EsfClockManagerParams cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    EsfClockManagerParamsMask cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    EsfNetworkManagerParameterMask esfnm_mask_expect = {0};
    EsfNetworkManagerParameter esfnm_param_expect = {0};

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(PsInfo));

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // ConnectNetwork()
    memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

    will_return(__wrap_EsfNetworkManagerOpen, 777);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.subnet_mask, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.subnet_mask, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.ssid, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.password, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.encryption, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.ip_method, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.netif_kind,
                 esfnm_mask_expect.normal_mode.netif_kind);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.subnet_mask,
                 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.ssid, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.password, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.encryption,
                 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.channel, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.url, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.port, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.username, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.password, 0);

    expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.netif_kind,
                 esfnm_param_expect.normal_mode.netif_kind);

    will_return(__wrap_EsfNetworkManagerSaveParameter, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultStatusAlreadyRunning);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // StartNTP()
    expect_value(__wrap_EsfClockManagerSetParams, mask->connect.hostname, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->common.sync_interval,
                 cm_mask.common.sync_interval);
    expect_value(__wrap_EsfClockManagerSetParams, mask->common.polling_time,
                 cm_mask.common.polling_time);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.type,
                 cm_mask.skip_and_limit.type);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_packet_time, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_rtc_correction_value,
                 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.sanity_limit, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.type,
                 cm_mask.slew_setting.type);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_rtc_correction_value,
                 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_sync_number, 0);

    expect_value(__wrap_EsfClockManagerSetParams, data->common.sync_interval,
                 cm_param.common.sync_interval);
    expect_value(__wrap_EsfClockManagerSetParams, data->common.polling_time,
                 cm_param.common.polling_time);
    expect_value(__wrap_EsfClockManagerSetParams, data->skip_and_limit.type,
                 cm_param.skip_and_limit.type);
    expect_value(__wrap_EsfClockManagerSetParams, data->slew_setting.type,
                 cm_param.slew_setting.type);

    will_return(__wrap_EsfClockManagerSetParams, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerStart, true);
    will_return(__wrap_EsfClockManagerStart, true);
    will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // SetupEvpAgent
    SetupEvpAgent_FullySuccess();

    will_return(__wrap_EVP_getAgentStatus, EVP_AGENT_STATUS_CONNECTED);
    expect_any(__wrap_SYS_process_event, c);
    expect_value(__wrap_SYS_process_event, ms, 0);
    will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

    will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);

    expect_function_call(__wrap_IsaBtnCheckRebootRequest);
    will_return(__wrap_IsaBtnCheckRebootRequest, true);

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, -1);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultInternalError);

    // ReleaseEvpAgent()
    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.
#if defined(__linux__)
    // workaround for Nuttx occur issue on FR.
    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);
#endif

#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif
    expect_function_call(__wrap_IsaBtnCheckRebootRequest);
    will_return(__wrap_IsaBtnCheckRebootRequest, false);

    expect_any(__wrap_EsfSystemManagerSetProjectId, data);
    expect_value(__wrap_EsfSystemManagerSetProjectId, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetProjectId, kEsfSystemManagerResultInternalError);

    expect_any(__wrap_EsfSystemManagerSetRegisterToken, data);
    expect_value(__wrap_EsfSystemManagerSetRegisterToken, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetRegisterToken, kEsfSystemManagerResultInternalError);

    // Check EsfClockManagerStop.

    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    expect_function_call(__wrap_EsfPwrMgrPrepareReboot);
    will_return(__wrap_EsfPwrMgrPrepareReboot, kEsfPwrMgrErrorInternal);

    will_return(mock_free, false);

    ret = IsaRunProvisioningService(is_ps_mode_force_entory);

    assert_int_equal(ret, kIsaPsReboot);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaRunProvisioningService_ErrorFactoryReset(void **state)
{
    RetCode ret;
    bool is_ps_mode_force_entory = true;

    EsfClockManagerParams cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    EsfClockManagerParamsMask cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    EsfNetworkManagerParameterMask esfnm_mask_expect = {0};
    EsfNetworkManagerParameter esfnm_param_expect = {0};

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(PsInfo));

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // ConnectNetwork()
    memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

    will_return(__wrap_EsfNetworkManagerOpen, 777);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.subnet_mask, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.subnet_mask, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.ssid, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.password, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.encryption, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.ip_method, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.netif_kind,
                 esfnm_mask_expect.normal_mode.netif_kind);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.subnet_mask,
                 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.ssid, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.password, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.encryption,
                 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.channel, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.url, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.port, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.username, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.password, 0);

    expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.netif_kind,
                 esfnm_param_expect.normal_mode.netif_kind);

    will_return(__wrap_EsfNetworkManagerSaveParameter, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultStatusAlreadyRunning);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // StartNTP()
    expect_value(__wrap_EsfClockManagerSetParams, mask->connect.hostname, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->common.sync_interval,
                 cm_mask.common.sync_interval);
    expect_value(__wrap_EsfClockManagerSetParams, mask->common.polling_time,
                 cm_mask.common.polling_time);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.type,
                 cm_mask.skip_and_limit.type);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_packet_time, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_rtc_correction_value,
                 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.sanity_limit, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.type,
                 cm_mask.slew_setting.type);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_rtc_correction_value,
                 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_sync_number, 0);

    expect_value(__wrap_EsfClockManagerSetParams, data->common.sync_interval,
                 cm_param.common.sync_interval);
    expect_value(__wrap_EsfClockManagerSetParams, data->common.polling_time,
                 cm_param.common.polling_time);
    expect_value(__wrap_EsfClockManagerSetParams, data->skip_and_limit.type,
                 cm_param.skip_and_limit.type);
    expect_value(__wrap_EsfClockManagerSetParams, data->slew_setting.type,
                 cm_param.slew_setting.type);

    will_return(__wrap_EsfClockManagerSetParams, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerStart, true);
    will_return(__wrap_EsfClockManagerStart, true);
    will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // SetupEvpAgent
    SetupEvpAgent_FullySuccess();

    will_return(__wrap_EVP_getAgentStatus, EVP_AGENT_STATUS_CONNECTED);
    expect_any(__wrap_SYS_process_event, c);
    expect_value(__wrap_SYS_process_event, ms, 0);
    will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

    // Check IsaBtnCheckFactoryResetRequest.

    will_return(__wrap_IsaBtnCheckFactoryResetRequest, true);

    // ReleaseEvpAgent()
    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    // Check EsfLogManagerDeinit.
#if defined(__linux__)
    // workaround for Nuttx occur issue on FR.
    will_return(__wrap_EsfLogManagerDeinit, kEsfLogManagerStatusOk);
#endif

#if defined(__NuttX__)
    will_return(__wrap_task_delete, 0);
#endif
    // Check IsaBtnCheckRebootRequest.

    expect_function_call(__wrap_IsaBtnCheckRebootRequest);
    will_return(__wrap_IsaBtnCheckRebootRequest, false);

    expect_any(__wrap_EsfSystemManagerSetProjectId, data);
    expect_value(__wrap_EsfSystemManagerSetProjectId, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetProjectId, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetRegisterToken, data);
    expect_value(__wrap_EsfSystemManagerSetRegisterToken, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetRegisterToken, kEsfSystemManagerResultOk);

    // UnsetLedStatusForProvisioningService()

    {
        // Check EsfLedManagerSetStatus.

        expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
        expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                     kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
        expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
        will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerInternalError);
    }

    // Check EsfClockManagerStop.

    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    // Check IsaBtnExecuteFactoryResetCore

    will_return(__wrap_IsaBtnExecuteFactoryResetCore, kRetFailed);

    will_return(mock_free, false);

    ret = IsaRunProvisioningService(is_ps_mode_force_entory);

    assert_int_equal(ret, kIsaPsFactoryReset);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaRunProvisioningService_Qr_Cleanup_unregister_sys_client_Error(void **state)
{
    RetCode ret;
    bool is_ps_mode_force_entory = true;

    EsfClockManagerParams cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    EsfClockManagerParamsMask cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    EsfNetworkManagerParameterMask esfnm_mask_expect = {0};
    EsfNetworkManagerParameter esfnm_param_expect = {0};

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(PsInfo));

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // ConnectNetwork()
    memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
    esfnm_mask_expect.normal_mode.netif_kind = 1;
    esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

    will_return(__wrap_EsfNetworkManagerOpen, 777);
    will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerLoadParameter, "");
    will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.subnet_mask, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.subnet_mask, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.ssid, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.password, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.encryption, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.ip_method, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.netif_kind,
                 esfnm_mask_expect.normal_mode.netif_kind);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.ip, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.subnet_mask,
                 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.gateway, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.dns, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.ssid, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.password, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.encryption,
                 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.channel, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.url, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.port, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.username, 0);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.password, 0);

    expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.netif_kind,
                 esfnm_param_expect.normal_mode.netif_kind);

    will_return(__wrap_EsfNetworkManagerSaveParameter, kEsfNetworkManagerResultSuccess);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultStatusAlreadyRunning);

    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
    will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);

    // StartNTP()
    expect_value(__wrap_EsfClockManagerSetParams, mask->connect.hostname, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->common.sync_interval,
                 cm_mask.common.sync_interval);
    expect_value(__wrap_EsfClockManagerSetParams, mask->common.polling_time,
                 cm_mask.common.polling_time);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.type,
                 cm_mask.skip_and_limit.type);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_packet_time, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_rtc_correction_value,
                 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.sanity_limit, 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.type,
                 cm_mask.slew_setting.type);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_rtc_correction_value,
                 0);
    expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_sync_number, 0);

    expect_value(__wrap_EsfClockManagerSetParams, data->common.sync_interval,
                 cm_param.common.sync_interval);
    expect_value(__wrap_EsfClockManagerSetParams, data->common.polling_time,
                 cm_param.common.polling_time);
    expect_value(__wrap_EsfClockManagerSetParams, data->skip_and_limit.type,
                 cm_param.skip_and_limit.type);
    expect_value(__wrap_EsfClockManagerSetParams, data->slew_setting.type,
                 cm_param.slew_setting.type);

    will_return(__wrap_EsfClockManagerSetParams, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerStart, true);
    will_return(__wrap_EsfClockManagerStart, true);
    will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

    will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);

    // SetupEvpAgent
    SetupEvpAgent_FullySuccess();

    // Loop to simulate EVP connection timeout (30 iterations)
    // EVP_CONNECT_WAIT_MAX_SEC = 30
    for (int i = 0; i < 30; i++) {
        will_return(__wrap_EVP_getAgentStatus, EVP_AGENT_STATUS_DISCONNECTED);
        will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);
        expect_function_call(__wrap_IsaBtnCheckRebootRequest);
        will_return(__wrap_IsaBtnCheckRebootRequest, false);
    }

    will_return(__wrap_EVP_Agent_unregister_sys_client, -1); //Error

    expect_any(__wrap_EsfSystemManagerSetEvpHubUrl, data);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetEvpHubPort, data);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetProjectId, data);
    expect_value(__wrap_EsfSystemManagerSetProjectId, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetProjectId, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetRegisterToken, data);
    expect_value(__wrap_EsfSystemManagerSetRegisterToken, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetRegisterToken, kEsfSystemManagerResultOk);

    // Check EsfClockManagerStop.
    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    // Check UnsetLedStatusForProvisioningService.
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // Check free.
    will_return(mock_free, false);

    // Execute target.
    ret = IsaRunProvisioningService(is_ps_mode_force_entory);

    // Check return value.
    assert_int_equal(ret, kIsaPsSwitchToQrMode);

    return;
}

/*--------------------------------------------------------------------------*/
static void test_IsaRunProvisioningService_AllowlistFalse(void **state)
{
    RetCode ret;
    bool is_ps_mode_force_entory = false;
    EsfNetworkManagerParameterMask esfnm_mask_expect = {0};
    EsfNetworkManagerParameter esfnm_param_expect = {0};
    EsfClockManagerParams cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    EsfClockManagerParamsMask cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(PsInfo));

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // ConnectNetwork()
    {
        memset(&esfnm_mask_expect, 0, sizeof(EsfNetworkManagerParameterMask));
        memset(&esfnm_param_expect, 0, sizeof(EsfNetworkManagerParameter));
        esfnm_mask_expect.normal_mode.netif_kind = 1;
        esfnm_param_expect.normal_mode.netif_kind = 1; // Ether.

        // Check for EsfNetworkManagerOpen.

        will_return(__wrap_EsfNetworkManagerOpen, 777);
        will_return(__wrap_EsfNetworkManagerOpen, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerRegisterCallback.

        will_return(__wrap_EsfNetworkManagerRegisterCallback, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerLoadParameter.

        will_return(__wrap_EsfNetworkManagerLoadParameter, "");
        will_return(__wrap_EsfNetworkManagerLoadParameter, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerSaveParameter.

        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.ip, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.subnet_mask,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.gateway, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.dns, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.ip, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.subnet_mask,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.gateway, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.dns, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.ssid, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.password, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.encryption,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.ip_method, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.netif_kind,
                     esfnm_mask_expect.normal_mode.netif_kind);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.ip, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter,
                     mask->accesspoint_mode.dev_ip.subnet_mask, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.gateway,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.dns, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.ssid, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.password,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter,
                     mask->accesspoint_mode.wifi_ap.encryption, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.channel,
                     0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.url, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.port, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.username, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.password, 0);
        expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.netif_kind,
                     esfnm_param_expect.normal_mode.netif_kind);
        will_return(__wrap_EsfNetworkManagerSaveParameter, kEsfNetworkManagerResultSuccess);

        // Check EsfNetworkManagerStart. Will connect.

        will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerNotifyInfoConnected);
        will_return(__wrap_EsfNetworkManagerStart, kEsfNetworkManagerResultSuccess);
    }

    // Check StartSyncNtp. Will sync.
    {
        // Check EsfClockManagerSetParams.

        expect_value(__wrap_EsfClockManagerSetParams, mask->connect.hostname, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->common.sync_interval,
                     cm_mask.common.sync_interval);
        expect_value(__wrap_EsfClockManagerSetParams, mask->common.polling_time,
                     cm_mask.common.polling_time);
        expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.type,
                     cm_mask.skip_and_limit.type);
        expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.limit_packet_time, 0);
        expect_value(__wrap_EsfClockManagerSetParams,
                     mask->skip_and_limit.limit_rtc_correction_value, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->skip_and_limit.sanity_limit, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.type,
                     cm_mask.slew_setting.type);
        expect_value(__wrap_EsfClockManagerSetParams,
                     mask->slew_setting.stable_rtc_correction_value, 0);
        expect_value(__wrap_EsfClockManagerSetParams, mask->slew_setting.stable_sync_number, 0);
        expect_value(__wrap_EsfClockManagerSetParams, data->common.sync_interval,
                     cm_param.common.sync_interval);
        expect_value(__wrap_EsfClockManagerSetParams, data->common.polling_time,
                     cm_param.common.polling_time);
        expect_value(__wrap_EsfClockManagerSetParams, data->skip_and_limit.type,
                     cm_param.skip_and_limit.type);
        expect_value(__wrap_EsfClockManagerSetParams, data->slew_setting.type,
                     cm_param.slew_setting.type);
        will_return(__wrap_EsfClockManagerSetParams, kClockManagerSuccess);

        // Check EsfClockManagerRegisterCbOnNtpSyncComplete.

        will_return(__wrap_EsfClockManagerRegisterCbOnNtpSyncComplete, kClockManagerSuccess);

        // Check EsfClockManagerStart.

        will_return(__wrap_EsfClockManagerStart, true);
        will_return(__wrap_EsfClockManagerStart, true);
        will_return(__wrap_EsfClockManagerStart, kClockManagerSuccess);

        // Check EsfClockManagerUnregisterCbOnNtpSyncComplete.

        will_return(__wrap_EsfClockManagerUnregisterCbOnNtpSyncComplete, kClockManagerSuccess);
    }

    // SetupEvpAgent() setup
    {
        SetDefaultEndpoint_FullySuccess();

        // Check task_create.
        task_create_Success();

        will_return(__wrap_EVP_Agent_register_sys_client, (SYS_client *)0x1000);

        will_return(__wrap_SYS_set_configuration_cb, true); // Do call cb.
        will_return(__wrap_SYS_set_configuration_cb, SYS_RESULT_OK);
        expect_any(__wrap_SYS_set_configuration_cb, c);
        expect_string(__wrap_SYS_set_configuration_cb, topic, "system_settings");
        expect_value(__wrap_SYS_set_configuration_cb, cb, ConfigurationCallback);
        expect_value(__wrap_SYS_set_configuration_cb, type, SYS_CONFIG_ANY);
        expect_any(__wrap_SYS_set_configuration_cb, user);

        // Check SYS_set_configuration_cb. endpoint_settings.

        will_return(__wrap_SYS_set_configuration_cb, true); // Don't call cb.
        will_return(__wrap_SYS_set_configuration_cb, SYS_RESULT_OK);
        expect_any(__wrap_SYS_set_configuration_cb, c);
        expect_string(__wrap_SYS_set_configuration_cb, topic, "PRIVATE_endpoint_settings");
        expect_value(__wrap_SYS_set_configuration_cb, cb, ConfigurationCallback);
        expect_value(__wrap_SYS_set_configuration_cb, type, SYS_CONFIG_ANY);
        expect_any(__wrap_SYS_set_configuration_cb, user);

        // Check SYS_register_command_cb. reboot callback will be called.

        expect_any(__wrap_SYS_register_command_cb, c);
        expect_string(__wrap_SYS_register_command_cb, command, "reboot");
        expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandRebootCallback);
        expect_any(__wrap_SYS_register_command_cb, user);
        will_return(__wrap_SYS_register_command_cb, false); // Don't call cb.
        will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

        expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
        will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    }

    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue val = 1357;
    const char *req_id_ptr = "TEST";

    // First configuration callback - empty config "{}"
    {
        will_return(__wrap_EsfJsonOpen, handle_val);
        will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

        expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
        expect_string(__wrap_EsfJsonDeserialize, str, "{}");
        will_return(__wrap_EsfJsonDeserialize, val);
        will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

        // GetReqInfoToSetResInfo() expectations for first call
        expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
        expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
        will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
        will_return(__wrap_SysAppCmnGetReqId, kRetOk);

        // EsfJsonClose() expectations for first call
        expect_value(__wrap_EsfJsonClose, handle, handle_val);
        will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
    }

    // Second configuration callback - allowlist=false config
    {
        will_return(__wrap_EsfJsonOpen, handle_val);
        will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

        expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
        expect_string(__wrap_EsfJsonDeserialize, str, "{\"is_allowlisted\": false}");
        will_return(__wrap_EsfJsonDeserialize, val);
        will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);

        // GetReqInfoToSetResInfo() expectations for second call
        expect_value(__wrap_SysAppCmnGetReqId, handle, handle_val);
        expect_value(__wrap_SysAppCmnGetReqId, parent_val, val);
        will_return(__wrap_SysAppCmnGetReqId, req_id_ptr);
        will_return(__wrap_SysAppCmnGetReqId, kRetOk);

        // SysAppCmnExtractBooleanValue() expectations for second call - allowlist=false
        expect_value(__wrap_SysAppCmnExtractBooleanValue, handle, handle_val);
        expect_value(__wrap_SysAppCmnExtractBooleanValue, parent_val, val);
        expect_string(__wrap_SysAppCmnExtractBooleanValue, jsonkey, "is_allowlisted");
        will_return(__wrap_SysAppCmnExtractBooleanValue, false); // allowlist=false
        will_return(__wrap_SysAppCmnExtractBooleanValue, 1);     // Extraction succeeds

        // EsfJsonClose() expectations for second call
        expect_value(__wrap_EsfJsonClose, handle, handle_val);
        will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
    }

    // SYS_process_event
    will_return(__wrap_EVP_getAgentStatus, EVP_AGENT_STATUS_CONNECTED);
    expect_any(__wrap_SYS_process_event, c);
    expect_value(__wrap_SYS_process_event, ms, 0);
    will_return(__wrap_SYS_process_event, SYS_RESULT_OK);
    will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);
    expect_function_call(__wrap_IsaBtnCheckRebootRequest);
    will_return(__wrap_IsaBtnCheckRebootRequest, false);

    // Cleanup for QR mode
    will_return(__wrap_EVP_Agent_unregister_sys_client, 0);

    expect_any(__wrap_EsfSystemManagerSetEvpHubUrl, data);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetEvpHubPort, data);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetProjectId, data);
    expect_value(__wrap_EsfSystemManagerSetProjectId, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetProjectId, kEsfSystemManagerResultOk);

    expect_any(__wrap_EsfSystemManagerSetRegisterToken, data);
    expect_value(__wrap_EsfSystemManagerSetRegisterToken, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetRegisterToken, kEsfSystemManagerResultOk);

    will_return(__wrap_EsfClockManagerStop, kClockManagerSuccess);

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    will_return(mock_free, false);

    // Trigger allowlist=false scenario before calling the main function
    ut_trigger_allowlist_false_scenario();

    // Execute target - this will trigger the 2-call allowlist=false scenario during SYS_process_event
    IsaPsErrorCode actual_result = IsaRunProvisioningService(is_ps_mode_force_entory);

    // Verify that we switched to QR mode
    assert_int_equal(kIsaPsSwitchToQrMode, actual_result);
}

/*----------------------------------------------------------------------------*/
//
// main()
//
/*----------------------------------------------------------------------------*/
int main(void)
{
    const struct CMUnitTest tests[] = {
        // JsonOpenAndInit()
        cmocka_unit_test(test_JsonOpenAndInit_FullySuccess),
        cmocka_unit_test(test_JsonOpenAndInit_ErrorEsfJsonOpen),
        cmocka_unit_test(test_JsonOpenAndInit_ErrorEsfJsonObjectInit),
        // JsonOpenAndDeserialize()
        cmocka_unit_test(test_JsonOpenAndDeserialize_FullySuccess),
        cmocka_unit_test(test_JsonOpenAndDeserialize_ErrorEsfJsonOpen),
        cmocka_unit_test(test_JsonOpenAndDeserialize_ErrorEsfJsonDeserialize),
        // ResponseToDetailmsg()
        cmocka_unit_test(test_ResponseToDetailmsg_ok),
        cmocka_unit_test(test_ResponseToDetailmsg_unimplemented),
        cmocka_unit_test(test_ResponseToDetailmsg_invalid_argument),
        cmocka_unit_test(test_ResponseToDetailmsg_internal),
        cmocka_unit_test(test_ResponseToDetailmsg_unknown),
        cmocka_unit_test(test_ResponseToDetailmsg_ok_null),
        cmocka_unit_test(test_ResponseToDetailmsg_unimplemented_null),
        cmocka_unit_test(test_ResponseToDetailmsg_invalid_argument_null),
        cmocka_unit_test(test_ResponseToDetailmsg_internal_null),
        cmocka_unit_test(test_ResponseToDetailmsg_unknown_null),
        // MakeJsonResInfo()
        cmocka_unit_test(test_MakeJsonResInfo_FullySuccess),
        // GetDeviceManifest()
        cmocka_unit_test(test_GetDeviceManifest_FullySuccess),
#ifdef CONFIG_ARCH_CHIP_ESP32S3
        cmocka_unit_test(test_GetDeviceManifest_Error_senscord_core_init),
        cmocka_unit_test(test_GetDeviceManifest_Error_senscord_core_open_stream),
        cmocka_unit_test(test_GetDeviceManifest_Error_senscord_core_open_stream),
        cmocka_unit_test(test_GetDeviceManifest_Error_senscord_stream_get_property),
        cmocka_unit_test(test_GetDeviceManifest_NoError),
        cmocka_unit_test(test_GetDeviceManifest_senscord_InitZero_OpenNotZero),
        cmocka_unit_test(test_GetDeviceManifest_senscord_InitNotZero_OpenZero),
        cmocka_unit_test(test_GetDeviceManifest_senscord_InitNotZero_OpenNotZero),
        cmocka_unit_test(test_GetDeviceManifest_MaxOverManifest),
        cmocka_unit_test(test_GetDeviceManifest_MaxManifest),
#else
        cmocka_unit_test(test_GetDeviceManifest_MaxOverSerialNumber),
#endif
        // SendStateCore()
        cmocka_unit_test(test_SendStateCore_FullySuccess),
        cmocka_unit_test(test_SendStateCore_Error_SYS_set_state),
        cmocka_unit_test(test_SendStateCore_FullySuccess_StateMaxLen),
        // GetReqInfoToSetResInfo()
        cmocka_unit_test(test_GetReqInfoToSetResInfo_FullySuccess),
        cmocka_unit_test(test_GetReqInfoToSetResInfo_NotFound),
        cmocka_unit_test(test_GetReqInfoToSetResInfo_Other),
        cmocka_unit_test(test_GetReqInfoToSetResInfo_MaxOverLen),
        cmocka_unit_test(test_GetReqInfoToSetResInfo_MaxLen),
        // EndpointSettings()
        cmocka_unit_test(test_EndpointSettings_FullySuccess),
        cmocka_unit_test(test_EndpointSettings_ErrorJsonOpenAndDeserialize),
        cmocka_unit_test(test_EndpointSettings_endpoint_port_AllocError),
        cmocka_unit_test(test_EndpointSettings_ErrorSysAppCmnGetReqId),
        cmocka_unit_test(test_EndpointSettings_ErrorEsfSystemManagerSetEvpHubUrlandPort),
        cmocka_unit_test(test_EndpointSettings_ErrorEsfJsonClose),
        cmocka_unit_test(test_EndpointSettings_ErrorSysAppCmnExtractStringValueEndpointUrl),
        cmocka_unit_test(test_EndpointSettings_MaxOverLenEndpointUrl),
        cmocka_unit_test(test_EndpointSettings_MaxLenEndpointUrl),
        cmocka_unit_test(test_EndpointSettings_ErrorSysAppCmnExtractNumberValueEndpointPort),
        cmocka_unit_test(test_EndpointSettings_MinOverEndpointPort),
        cmocka_unit_test(test_EndpointSettings_MinEndpointPort),
        cmocka_unit_test(test_EndpointSettings_MaxEndpointPort),
        cmocka_unit_test(test_EndpointSettings_MaxOverEndpointPort),
        cmocka_unit_test(test_EndpointSettings_ErrorEsfJsonSerialize),
        cmocka_unit_test(test_EndpointSettings_NullEsfJsonSerialize),
        // GetEnrollmentData()
        cmocka_unit_test(test_GetEnrollmentData_FullySuccess),
        cmocka_unit_test(test_GetEnrollmentData_device_manifest_AllocError),
        cmocka_unit_test(test_GetEnrollmentData_project_id_AllocError),
        cmocka_unit_test(test_GetEnrollmentData_register_token_AllocError),
        cmocka_unit_test(test_GetEnrollmentData_ErrorEsfSystemManagerGetDeviceManifest),
        cmocka_unit_test(test_GetEnrollmentData_ErrorEsfSystemManagerGetProjectId),
        cmocka_unit_test(test_GetEnrollmentData_ErrorEsfSystemManagerGetRegisterToken),
        // SendTelemetryEnrollmentCallback()
        cmocka_unit_test(test_SendTelemetryEnrollmentCallback_Finished),
        cmocka_unit_test(test_SendTelemetryEnrollmentCallback_Error),
        cmocka_unit_test(test_SendTelemetryEnrollmentCallback_Timeout),
        cmocka_unit_test(test_SendTelemetryEnrollmentCallback_Default),
        // MakeJsonOfTelemetry()
        cmocka_unit_test(test_MakeJsonOfTelemetry_FullySuccess),
        cmocka_unit_test(test_MakeJsonOfTelemetry_ErrorEsfJsonOpen),
        cmocka_unit_test(test_MakeJsonOfTelemetry_ErrorEsfJsonSerialize),
        cmocka_unit_test(test_MakeJsonOfTelemetry_ErrorEsfJsonSerializeAndEsfJsonClose),
        cmocka_unit_test(test_MakeJsonOfTelemetry_NullEsfJsonSerialize),
        // SendEnrollmentData()
        cmocka_unit_test(test_SendEnrollmentData_FullySuccess),
        cmocka_unit_test(test_SendEnrollmentData_ErrorEsfJsonClose),
        cmocka_unit_test(test_SendEnrollmentData_ErrorGetEnrollmentData),
        cmocka_unit_test(test_SendEnrollmentData_RetryMaxOver),
        cmocka_unit_test(test_SendEnrollmentData_RetryMax),
        cmocka_unit_test(test_SendEnrollmentData_ErrorMakeJsonOfTelemetry),
        cmocka_unit_test(test_SendEnrollmentData_ErrorSYS_send_telemetry),
        cmocka_unit_test(test_SendEnrollmentData_ErrorSYS_process_event),
        cmocka_unit_test(test_SendEnrollmentData_WaitTelemetryCallback),
        // SetResId()
        cmocka_unit_test(test_SetResId_FullySuccess),
        cmocka_unit_test(test_SetResId_JsonOpenAndDeserializeError),
        cmocka_unit_test(test_SetResId_ErrorEsfJsonClose),
        // ReleaseEvpAgent()
        cmocka_unit_test(test_ReleaseEvpAgent_FullySuccess),
        cmocka_unit_test(test_ReleaseEvpAgent_ErrorEVP_Agent_unregister_sys_client),
        // ConfigurationCallback()
        cmocka_unit_test(test_ConfigurationCallback_PRIVATE_endpoint_settings),
        cmocka_unit_test(test_ConfigurationCallback_Other),
        cmocka_unit_test(test_ConfigurationCallback_SYS_REASON_ERROR),
        // ResponseSendCompleteCallback()
        cmocka_unit_test(test_ResponseSendCompleteCallback_FullySuccess),
        cmocka_unit_test(test_ResponseSendCompleteCallback_Null),
        // SendDirectCommandResponseCore()
        cmocka_unit_test(test_SendDirectCommandResponseCore_FullySuccess),
        cmocka_unit_test(test_SendDirectCommandResponseCore_FullySuccess_SendComplete),
        cmocka_unit_test(test_SendDirectCommandResponseCore_2ndloop),
        cmocka_unit_test(test_SendDirectCommandResponseCore_ErrorSYS_set_response_cb),
        // SendDirectCommandResponse()
        cmocka_unit_test(test_SendDirectCommandResponse_FullySuccess),
        cmocka_unit_test(test_SendDirectCommandResponse_EsfJsonSerialize_Null),
        cmocka_unit_test(test_SendDirectCommandResponse_ErrorEsfJsonSerialize),
        cmocka_unit_test(test_SendDirectCommandResponse_ErrorEsfJsonSerializeEsfJsonClose),
        cmocka_unit_test(test_SendDirectCommandResponse_ErrorEsfJsonOpen),
        // DirectCommandRebootCallback()
        cmocka_unit_test(test_DirectCommandRebootCallback_FullySuccess),
        cmocka_unit_test(test_DirectCommandRebootCallback_Null),
        // CheckProjectIdAndRegisterToken()
        cmocka_unit_test(test_CheckProjectIdAndRegisterToken_FullySuccess),
        cmocka_unit_test(test_CheckProjectIdAndRegisterToken_ProjectIdAllocError),
        cmocka_unit_test(test_CheckProjectIdAndRegisterToken_RegisterTokenAllocError),
        cmocka_unit_test(test_CheckProjectIdAndRegisterToken_BothAllocError),
        cmocka_unit_test(test_CheckProjectIdAndRegisterToken_GetProjectIdError),
        cmocka_unit_test(test_CheckProjectIdAndRegisterToken_GetRegisterTokenError),
        cmocka_unit_test(test_CheckProjectIdAndRegisterToken_EmptyProjectIdAndRegisterToken),
        cmocka_unit_test(test_CheckProjectIdAndRegisterToken_EmptyRegisterToken),
        cmocka_unit_test(test_CheckProjectIdAndRegisterToken_EmptyProjectId),
        // SetDefaultEndpoint()
        cmocka_unit_test(test_SetDefaultEndpoint_FullySuccess),
        cmocka_unit_test(test_SetDefaultEndpoint_BothAllocError),
        cmocka_unit_test(test_SetDefaultEndpoint_MqttHostAllocError),
        cmocka_unit_test(test_SetDefaultEndpoint_MqttPortAllocError),
        cmocka_unit_test(test_SetDefaultEndpoint_ErrorCheckProjectIdAndRegisterToken),
        cmocka_unit_test(test_SetDefaultEndpoint_TrueForceEntry),
        cmocka_unit_test(test_SetDefaultEndpoint_ErrorEsfSystemManagerSetEvpHubUrl),
        cmocka_unit_test(test_SetDefaultEndpoint_ErrorEsfSystemManagerSetEvpHubPort),
        cmocka_unit_test(test_SetDefaultEndpoint_ErrorEsfSystemManagerGetEvpHubUrl),
        cmocka_unit_test(test_SetDefaultEndpoint_ErrorEsfSystemManagerGetEvpHubPort),
        // SetupEvpAgent()
        cmocka_unit_test(test_SetupEvpAgent_FullySuccess),
        cmocka_unit_test(test_SetupEvpAgent_FullySuccess_ProvisioningService),
        cmocka_unit_test(test_SetupEvpAgent_ErrorSetDefaultEndpoint),
#if defined(__NuttX__)
        cmocka_unit_test(test_SetupEvpAgent_Errortask_create),
#endif
        cmocka_unit_test(test_SetupEvpAgent_ErrorSYS_set_configuration_cb_1st),
        cmocka_unit_test(test_SetupEvpAgent_ErrorSYS_set_configuration_cb_2nd),
        cmocka_unit_test(test_SetupEvpAgent_ErrorSYS_register_command_cb),
        // SetupEvpAgent()
        cmocka_unit_test(test_SetLedStatusForProvisioningService_FullySuccess),
        cmocka_unit_test(test_SetLedStatusForProvisioningService_ErrorEsfLedManagerSetStatus),
        // CheckAllowlist()
        cmocka_unit_test(test_CheckAllowlist_AllowlistTrue),
        cmocka_unit_test(test_CheckAllowlist_AllowlistFalse),
        cmocka_unit_test(test_CheckAllowlist_ModeNotEnrollment),
        cmocka_unit_test(test_CheckAllowlist_JsonDeserializeError),
        cmocka_unit_test(test_CheckAllowlist_InvalidExtractBooleanValue),
        cmocka_unit_test(test_CheckAllowlist_EsfJsonCloseError),
        // IsaRunProvisioningService()
        cmocka_unit_test(test_IsaRunProvisioningService_Should_exit),
        cmocka_unit_test(test_IsaRunProvisioningService_SendTelemetry),
        cmocka_unit_test(test_IsaRunProvisioningService_PsInfoAllocError),
        cmocka_unit_test(test_IsaRunProvisioningService_ConnectNetwork_Abort),
        cmocka_unit_test(test_IsaRunProvisioningService_ConnectNetwork_Abort_FR),
        cmocka_unit_test(test_IsaRunProvisioningService_ConnectNetwork_Error),
        cmocka_unit_test(test_IsaRunProvisioningService_ErrorStartNTP),
        cmocka_unit_test(test_IsaRunProvisioningService_StartSyncNtp_Abort_FactoryReset),
        cmocka_unit_test(test_IsaRunProvisioningService_StartSyncNtp_Abort_Reboot),
        cmocka_unit_test(test_IsaRunProvisioningService_Error_SetupEvpAgent),
        cmocka_unit_test(test_IsaRunProvisioningService_EvpConnectWait_FactoryResetRequested),
        cmocka_unit_test(
            test_IsaRunProvisioningService_EvpConnectWait_RebootRequested_SetQrModeSuccess),
        cmocka_unit_test(
            test_IsaRunProvisioningService_EvpConnectWait_RebootRequested_SetQrModeError),
        cmocka_unit_test(test_IsaRunProvisioningService_EvpConnectTimeout),
        cmocka_unit_test(test_IsaRunProvisioningService_DirectCommandRebootRequested),
        cmocka_unit_test(test_IsaRunProvisioningService_ErrorReboot),
        cmocka_unit_test(test_IsaRunProvisioningService_ErrorFactoryReset),
        cmocka_unit_test(test_IsaRunProvisioningService_Qr_Cleanup_unregister_sys_client_Error),
        cmocka_unit_test(test_IsaRunProvisioningService_AllowlistFalse),
    };

    return (((cmocka_run_group_tests(tests, NULL, NULL)) == 0) ? 0 : 1);
}
