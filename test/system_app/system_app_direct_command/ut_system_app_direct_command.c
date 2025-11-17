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

#if defined(__NuttX__)
#include <nuttx/config.h>
#endif
#include "utility_log.h"
#include "power_manager.h"
#include "firmware_manager.h"
#include "memory_manager.h"
#include "jpeg/include/jpeg.h"
#include "base64/include/base64.h"
#include "senscord/c_api/senscord_c_api.h"
#include "senscord/inference_stream/c_api/property_c_types.h"
#include "system_app_log.h"
#include "system_app_direct_command.h"
#include "system_app_direct_command_private.h"
#include "ut_mock_sysappcmn.h"

#define SENSOR_REGISTER_PARAM_ADDRESS_BASE_VAL (0x98765432)
#define SENSOR_REGISTER_PARAM_SIZE_1BYTE_BASE_VAL (0x12)
#define SENSOR_REGISTER_PARAM_SIZE_2BYTE_BASE_VAL (0x3456)
#define SENSOR_REGISTER_PARAM_SIZE_4BYTE_BASE_VAL (0x78901234)

#define SENSOR_REGISTER_PARAM_REGISTER_ARRAY_NUM_MIN (1)
#define SENSOR_REGISTER_PARAM_REGISTER_ARRAY_NUM_MAX (32)

#define SENSOR_REGISTER_COMMON_ARRAY_NUM (3)

#define SENSCORD_SENSOR_REGISTER_ID_IMX500 (0x00000000)

#define READ_SENSOR_REGISTER_COMMON_SENSCORD_STREAM (0x96385274)
#define WRITE_SENSOR_REGISTER_COMMON_SENSCORD_STREAM (0x74185296)

#define FRAME_INFO_SCCORE (112233)
#define FRAME_INFO_SCSTREAM (445566)
#define FRAME_INFO_SCSCFRAME (666)

#define SENSCORD_IMAGE_PROPERTY_WIDTH (2028)
#define SENSCORD_IMAGE_PROPERTY_HEIGHT (1520)
#define SENSCORD_IMAGE_PROPERTY_STRIDE_BYTE (77)
#define SENSCORD_RAW_DATA_ADDRESS (0x11112222)
#define SENSCORD_RAW_DATA_SIZE (334455)
#define SENSCORD_RAW_DATA_TIMESTAMP (202412051128)

#define MEMORY_MANAGER_MAP_MAP_ADDRESS (0x33334444)

static const char *dgiparam_test_network_id = "expect_network_id";
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
static const char *dgiparam_default_network_id = "99999999999999999999999999999999";
#else  // Use #else for build: CONFIG_APP_EXTERNAL_SENSOR_IMX500_LIB
static const char *dgiparam_default_network_id = "999997";
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
static const char *dgiparam_max_over_network_id = "expect_network_iddddddddddddddddd";
static const char *dgiparam_max_network_id = "expect_network_idddddddddddddddd";

typedef enum {
    FcloseAndFreeMemoryManagerHandle_None = 0,
    FcloseAndFreeMemoryManagerHandle_Fclose,
    FcloseAndFreeMemoryManagerHandle_Free,
} FcloseAndFreeMemoryManagerHandleErrFlag;

typedef enum {
    AllocateAndFopenMemoryManagerHandle_None = 0,
    AllocateAndFopenMemoryManagerHandle_Allocate,
    AllocateAndFopenMemoryManagerHandle_Fopen,
} AllocateAndFopenMemoryManagerHandleErrFlag;

typedef enum {
    JpegEncodeHandle_None = 0,
    JpegEncodeHandle_JpegOutputBufferFull,
    JpegEncodeHandle_JpegOutputOther,
} JpegEncodeHandleErrorFlag;

typedef enum {
    JpegEncode_None = 0,
    JpegEncode_JpegOutputBufferFull,
    JpegEncode_JpegOutputOther,
} JpegEncodeErrorFlag;

typedef enum {
    GetSensorRegisterArrayParam_None = 0,
    GetSensorRegisterArrayParam_EsfJsonArrayGet,
    GetSensorRegisterArrayParam_SysAppCmnExtractRealNumberValueAddress,
    GetSensorRegisterArrayParam_SysAppCmnExtractNumberValueSize,
    GetSensorRegisterArrayParam_InvalidSizeProtertyValue,
    GetSensorRegisterArrayParam_SysAppCmnExtractRealNumberValueValue,
    GetSensorRegisterArrayParam_MaxOverValue1Byte,
    GetSensorRegisterArrayParam_MaxValue1Byte,
    GetSensorRegisterArrayParam_MaxOverValue2Byte,
    GetSensorRegisterArrayParam_MaxValue2Byte,
    GetSensorRegisterArrayParam_MaxOverValue4Byte,
    GetSensorRegisterArrayParam_MaxValue4Byte,
} GetSensorRegisterArrayParamErrFlag;

typedef enum {
    GetSensorRegisterParam_None = 0,
    GetSensorRegisterParam_EsfJsonObjectGet,
    GetSensorRegisterParam_EsfJsonValueTypeGet,
    GetSensorRegisterParam_InvalidTypeRegisterProperty,
    GetSensorRegisterParam_Malloc,
    GetSensorRegisterParam_GetSensorRegisterArrayParam,
} GetSensorRegisterParamErrFlag;

typedef enum {
    GetReadSensorRegisterParam_None = 0,
    GetReadSensorRegisterParam_EsfJsonOpen,
    GetReadSensorRegisterParam_EsfJsonDeserialize,
    GetReadSensorRegisterParam_GetSensorRegisterParam,
    GetReadSensorRegisterParam_EsfJsonClose,
} GetReadSensorRegisterParamErrFlag;

typedef enum {
    GetWriteSensorRegisterParam_None = 0,
    GetWriteSensorRegisterParam_EsfJsonOpen,
    GetWriteSensorRegisterParam_EsfJsonDeserialize,
    GetWriteSensorRegisterParam_GetSensorRegisterParam,
    GetWriteSensorRegisterParam_EsfJsonClose,
} GetWriteSensorRegisterParamErrFlag;

typedef enum {
    ExecReadSensorRegister8bit_None = 0,
    ExecReadSensorRegister8bit_GetProperty,
} ExecReadSensorRegister8bitErrFlag;

typedef enum {
    ExecReadSensorRegister16bit_None = 0,
    ExecReadSensorRegister16bit_GetProperty,
} ExecReadSensorRegister16bitErrFlag;

typedef enum {
    ExecReadSensorRegister32bit_None = 0,
    ExecReadSensorRegister32bit_GetProperty,
} ExecReadSensorRegister32bitErrFlag;

typedef enum {
    ExecWriteSensorRegisterEachBit_None = 0,
    ExecWriteSensorRegisterEachBit_SetProperty,
} ExecWriteSensorRegisterEachBitErrFlag;

typedef enum {
    ExecWriteSensorRegisterBit_8bit = 0,
    ExecWriteSensorRegisterBit_16bit,
    ExecWriteSensorRegisterBit_32bit,
} ExecWriteSensorRegisterBit;

typedef enum {
    ExecReadSensorRegister_None = 0,
    ExecReadSensorRegister_SysAppStateGetSensCordStream,
    ExecReadSensorRegister_ExecReadSensorRegister8bit,
    ExecReadSensorRegister_ExecReadSensorRegister16bit,
    ExecReadSensorRegister_ExecReadSensorRegister32bit,
} ExecReadSensorRegisterErrFlag;

typedef enum {
    ExecWriteSensorRegister_None = 0,
    ExecWriteSensorRegister_SysAppStateGetSensCordStream,
    ExecWriteSensorRegister_ExecWriteSensorRegister8bit,
    ExecWriteSensorRegister_ExecWriteSensorRegister16bit,
    ExecWriteSensorRegister_ExecWriteSensorRegister32bit,
} ExecWriteSensorRegisterErrFlag;

typedef enum {
    ExecEncodePhaseWithRawData_None = 0,
    ExecEncodePhaseWithRawData_MallocJpegEncodeBuffer,
    ExecEncodePhaseWithRawData_MallocBase64EncodeBuffer,
    ExecEncodePhaseWithRawData_EsfCodecJpegEncode,
    ExecEncodePhaseWithRawData_EsfCodecBase64Encode,
} ExecEncodePhaseWithRawDataErrFlag;

typedef enum {
    SysAppDcmdReadSensorRegister_None = 0,
    SysAppDcmdReadSensorRegister_GetReadSensorRegisterParamInvalidParam,
    SysAppDcmdReadSensorRegister_GetReadSensorRegisterParamOther,
    SysAppDcmdReadSensorRegister_ExecReadSensorRegister,
    SysAppDcmdReadSensorRegister_SendDirectCommandResponseAsync,
} SysAppDcmdReadSensorRegisterErrFlag;

typedef enum {
    SysAppDcmdWriteSensorRegister_None = 0,
    SysAppDcmdWriteSensorRegister_GetWriteSensorRegisterParamInvalidParam,
    SysAppDcmdWriteSensorRegister_GetWriteSensorRegisterParamOther,
    SysAppDcmdWriteSensorRegister_ExecWriteSensorRegister,
    SysAppDcmdWriteSensorRegister_SendDirectCommandResponseAsync,
} SysAppDcmdWriteSensorRegisterErrFlag;

typedef enum {
    GetDirectGetImageParams_None = 0,
    GetDirectGetImageParams_EsfJsonOpen,
    GetDirectGetImageParams_EsfJsonDeserialize,
    GetDirectGetImageParams_SysAppCmnExtractStringValueNetworkIdNokey,
    GetDirectGetImageParams_SysAppCmnExtractStringValueNetworkIdNullStr,
    GetDirectGetImageParams_SysAppCmnExtractStringValueNetworkIdMaxOver,
    GetDirectGetImageParams_SysAppCmnExtractStringValueNetworkIdMax,
    GetDirectGetImageParams_SysAppCmnExtractStringValueNetworkIdInvalidKey,
    GetDirectGetImageParams_EsfJsonClose,
} GetDirectGetImageParamsTestFlag;

typedef enum {
    GetOneFrame_None = 0,
    GetOneFrame_SysAppStateGetSensCordId,
    GetOneFrame_SysAppStateGetSensCordStream,
    GetOneFrame_SenscordStreamSetPropertyAiModel,
    GetOneFrame_SenscordStreamSetPropertyAiModelCheckDefault,
    GetOneFrame_SenscordStreamSetPropertyAiModelCheckMax,
    GetOneFrame_SenscordStreamSetPropertyInputData,
    GetOneFrame_SenscordStreamSetPropertyImageProp,
    GetOneFrame_GetFormatOfImage,
    GetOneFrame_SenscordStreamStart,
    GetOneFrame_SenscordStreamGetFrame,
    GetOneFrame_SenscordFrameGetChannelFromChannelId,
    GetOneFrame_SenscordChannelGetRawData,
    GetOneFrame_EsfMemoryManagerGetHandleInfo,
    GetOneFrame_EsfMemoryManagerGetHandleInfoOtherHeap,
} GetOneFrameTestFlag;

typedef enum {
    ReleaseOneFrame_None = 0,
    ReleaseOneFrame_EsfMemoryManagerUnmap,
    ReleaseOneFrame_SenscordStreamReleaseFrame,
    ReleaseOneFrame_SenscordStreamStop,
} ReleaseOneFrameTestFlag;

extern struct SYS_client *s_sys_client;
extern TerminationReason s_terminate_request;

extern void ResponseSendCompleteCallback(struct SYS_client *client, enum SYS_callback_reason reason,
                                         void *context);
extern void ResponseSendCompleteCallbackHandle(struct SYS_client *client,
                                               enum SYS_callback_reason reason, void *context);
extern RetCode MakeJsonResInfo(EsfJsonHandle handle, EsfJsonValue root, void *ctx);
extern RetCode SetImageProperty(EsfJsonHandle handle, EsfJsonValue val, void *param,
                                size_t param_size);
extern RetCode SetImagePropertyHandle(EsfJsonHandle handle, EsfJsonValue val, void *param,
                                      size_t param_size);
#if defined(CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500)
extern DcResult GetSensorRegisterArrayParam(EsfJsonHandle esfj_handle, EsfJsonValue val,
                                            SensorRegisterParam *sensor_register_param,
                                            bool is_get_value_property);
extern DcResult GetSensorRegisterParam(EsfJsonHandle esfj_handle, EsfJsonValue val,
                                       SensorRegisterParam *sensor_register_param,
                                       bool is_get_value_property);
extern DcResult GetReadSensorRegisterParam(const char *param,
                                           SensorRegisterParam *sensor_register_param);
extern DcResult GetWriteSensorRegisterParam(const char *param,
                                            SensorRegisterParam *sensor_register_param);
extern RetCode ExecReadSensorRegister8bit(senscord_stream_t scstream,
                                          SensorRegisterInfo *sensor_register_info);
extern RetCode ExecReadSensorRegister16bit(senscord_stream_t scstream,
                                           SensorRegisterInfo *sensor_register_info);
extern RetCode ExecReadSensorRegister32bit(senscord_stream_t scstream,
                                           SensorRegisterInfo *sensor_register_info);
extern DcResult ExecReadSensorRegister(SensorRegisterParam *sensor_register_param);
extern RetCode ExecWriteSensorRegister8bit(senscord_stream_t scstream,
                                           SensorRegisterInfo *sensor_register_info);
extern RetCode ExecWriteSensorRegister16bit(senscord_stream_t scstream,
                                            SensorRegisterInfo *sensor_register_info);
extern RetCode ExecWriteSensorRegister32bit(senscord_stream_t scstream,
                                            SensorRegisterInfo *sensor_register_info);
extern DcResult ExecWriteSensorRegister(SensorRegisterParam *sensor_register_param);
extern RetCode MakeJsonRegisterParams(EsfJsonHandle handle, EsfJsonValue root, uint32_t no,
                                      void *ctx);
extern RetCode SetRegisterProperty(EsfJsonHandle handle, EsfJsonValue val, void *param,
                                   size_t param_size);
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
extern void Response2CodeAndDetailmsg(DcResult res, int *code, char *desc, uint32_t desc_len);
extern RetCode SendDirectCommandResponse(
    struct SYS_client *evp_handle, SYS_response_id cmd_id, const char *req_id, DcResult dc_result,
    RetCode (*additional)(EsfJsonHandle, EsfJsonValue, void *, size_t), void *additional_param,
    size_t additional_param_size, bool is_additional_param_file_io, bool is_sync);
extern void DirectCommandRebootCallback(struct SYS_client *client, SYS_response_id cmd_id,
                                        const char *params, void *user_context);
extern void DirectCommandShutdownCallback(struct SYS_client *client, SYS_response_id cmd_id,
                                          const char *params, void *user_context);
extern void DirectCommandFactoryResetCallback(struct SYS_client *client, SYS_response_id cmd_id,
                                              const char *params, void *user_context);
extern void DirectCommandDirectGetImageCallback(struct SYS_client *client, SYS_response_id cmd_id,
                                                const char *params, void *user_context);
extern void DirectCommandReadSensorRegisterCallback(struct SYS_client *client,
                                                    SYS_response_id cmd_id, const char *params,
                                                    void *user_context);
extern void DirectCommandWriteSensorRegisterCallback(struct SYS_client *client,
                                                     SYS_response_id cmd_id, const char *params,
                                                     void *user_context);
extern void DirectCommandUnimplementedCallback(struct SYS_client *client, SYS_response_id cmd_id,
                                               const char *params, void *user_context);
extern bool IsUnimplementedMethod(const char *method);

/*----------------------------------------------------------------------------*/

//
// Initial value check for static global variable
//

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmd_InitialValueOfGlobalVariable(void **state)
{
    assert_null(s_sys_client);
    assert_int_equal(s_terminate_request, UnDefined);

    return;
}

/*----------------------------------------------------------------------------*/

//
// Common
//

/*----------------------------------------------------------------------------*/
static void FcloseAndFreeMemoryManagerHandleCommon(EsfMemoryManagerHandle handle,
                                                   FcloseAndFreeMemoryManagerHandleErrFlag err_flag)
{
    // For EsfMemoryManagerFree()
    expect_value(__wrap_EsfMemoryManagerFree, handle, handle);
    expect_value(__wrap_EsfMemoryManagerFree, exec_env, NULL);

    if (err_flag == FcloseAndFreeMemoryManagerHandle_Free) {
        will_return(__wrap_EsfMemoryManagerFree, kEsfMemoryManagerResultOperationError);
    }
    else {
        will_return(__wrap_EsfMemoryManagerFree, kEsfMemoryManagerResultSuccess);
    }
}

/*----------------------------------------------------------------------------*/
static void AllocateAndFopenMemoryManagerHandleCommon(
    EsfMemoryManagerHandle handle, size_t size, AllocateAndFopenMemoryManagerHandleErrFlag err_flag)
{
    // For EsfMemoryManagerAllocate()
    expect_value(__wrap_EsfMemoryManagerAllocate, target_area, kEsfMemoryManagerTargetLargeHeap);
    expect_value(__wrap_EsfMemoryManagerAllocate, exec_env, NULL);
    expect_value(__wrap_EsfMemoryManagerAllocate, size, size);
    will_return(__wrap_EsfMemoryManagerAllocate, handle);
    if (err_flag == AllocateAndFopenMemoryManagerHandle_Allocate) {
        will_return(__wrap_EsfMemoryManagerAllocate, kEsfMemoryManagerResultOperationError);
        goto exit;
    }
    else {
        will_return(__wrap_EsfMemoryManagerAllocate, kEsfMemoryManagerResultSuccess);
    }

exit:
}

/*----------------------------------------------------------------------------*/
static void Response2CodeAndDetailmsgForTest(DcResult dc_result)
{
    switch (dc_result) {
        case DcOk:
            expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
            expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");
            break;

        case DcUnknown:
            expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 2);
            expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "unknown");
            break;

        case DcInvalidArgument:
            expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 3);
            expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "invalid_argument");
            break;

        case DcResourceExhausted:
            expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 8);
            expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "resource_exhausted");
            break;

        case DcFailedPreCondition:
            expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 9);
            expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "failed_precondition");
            break;

        case DcAborted:
            expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 10);
            expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "aborted");
            break;

        case DcUnimplemented:
            expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 12);
            expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "unimplemented");
            break;

        case DcInternal:
            expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 13);
            expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "internal");
            break;

        case DcUnavailable:
            expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 14);
            expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "unavailable");
            break;

        case DcUnauthenticated:
            expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 16);
            expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "unauthenticated");
            break;

        default:
            expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 2);
            expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "unknown");
            break;
    }
}

/*----------------------------------------------------------------------------*/
#if defined(CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500)
static void MakeJsonRegisterParamsCommon(EsfJsonHandle handle_val, EsfJsonValue parent_val,
                                         SensorRegisterParam *sensor_register_param)
{
    int i;

    for (i = 0; i < sensor_register_param->num; i++) {
        // For SysAppCmnSetRealNumberValue() of address property
        expect_value(__wrap_SysAppCmnSetRealNumberValue, handle, handle_val);
        expect_value(__wrap_SysAppCmnSetRealNumberValue, parent, parent_val);
        expect_string(__wrap_SysAppCmnSetRealNumberValue, key, "address");
        SetSysAppCmnSetRealNumberValue(sensor_register_param->info[i].address);
        will_return(__wrap_SysAppCmnSetRealNumberValue, kRetOk);

        // For SysAppCmnSetRealNumberValue() of size property
        expect_value(__wrap_SysAppCmnSetNumberValue, handle, handle_val);
        expect_value(__wrap_SysAppCmnSetNumberValue, parent, parent_val);
        expect_string(__wrap_SysAppCmnSetNumberValue, key, "size");
        expect_value(__wrap_SysAppCmnSetNumberValue, number, sensor_register_param->info[i].size);
        will_return(__wrap_SysAppCmnSetNumberValue, kRetOk);

        // For SysAppCmnSetRealNumberValue() of value property
        expect_value(__wrap_SysAppCmnSetRealNumberValue, handle, handle_val);
        expect_value(__wrap_SysAppCmnSetRealNumberValue, parent, parent_val);
        expect_string(__wrap_SysAppCmnSetRealNumberValue, key, "value");
        SetSysAppCmnSetRealNumberValue(sensor_register_param->info[i].value);
        will_return(__wrap_SysAppCmnSetRealNumberValue, kRetOk);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
static void SendDirectCommandResponse_FullSuccess(
    EsfJsonHandle handle_val, const char *string_expect, DcResult dc_result,
    RetCode (*additional)(EsfJsonHandle, EsfJsonValue, void *, size_t), void *additional_param)
{
    EsfJsonValue parent_val = 1357;

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, parent_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, NULL);

    // Check response code and detail msg based on dc_result
    Response2CodeAndDetailmsgForTest(dc_result);

    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    if (additional != NULL) {
        if (additional == SetImageProperty) {
            if (additional_param != NULL) {
                expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
                expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
                expect_string(__wrap_SysAppCmnSetStringValue, key, "image");
                expect_string(__wrap_SysAppCmnSetStringValue, string, additional_param);
                will_return(__wrap_SysAppCmnSetStringValue, kRetOk);
            }
            else {
                expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
                expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
                expect_string(__wrap_SysAppCmnSetStringValue, key, "image");
                expect_string(__wrap_SysAppCmnSetStringValue, string, "");
                will_return(__wrap_SysAppCmnSetStringValue, kRetOk);
            }
#if defined(CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500)
        }
        else if (additional == SetRegisterProperty) {
            SensorRegisterParam *sensor_register_param = (SensorRegisterParam *)additional_param;

            // For SysAppCmnSetArrayValue()
            expect_value(__wrap_SysAppCmnSetArrayValue, handle, handle_val);
            expect_value(__wrap_SysAppCmnSetArrayValue, parent, parent_val);
            expect_string(__wrap_SysAppCmnSetArrayValue, key, "register");
            expect_value(__wrap_SysAppCmnSetArrayValue, array_num, sensor_register_param->num);
            expect_value(__wrap_SysAppCmnSetArrayValue, make_json, MakeJsonRegisterParams);
            expect_not_value(__wrap_SysAppCmnSetArrayValue, ctx, NULL);
            will_return(__wrap_SysAppCmnSetArrayValue, true);
            will_return(__wrap_SysAppCmnSetArrayValue, kRetOk);

            // For MakeJsonRegisterParams()
            MakeJsonRegisterParamsCommon(handle_val, parent_val, sensor_register_param);
#endif // CONFIG_ARCH_CHIP_ESP32
        }
        else {
            // Do Nothing
        }
    }

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // Check response strdup
    will_return(mock_strdup, true);
    will_return(mock_strdup, true);
    expect_value(mock_strdup, __ptr, string_expect);

    // Check dcres_ctx malloc
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(DcResponseContext));
}

/*----------------------------------------------------------------------------*/
static void SendDirectCommandResponseSync_FullSuccess(
    struct SYS_client *evp_handle, SYS_response_id cmd_id, const char *req_id, DcResult dc_result,
    RetCode (*additional)(EsfJsonHandle, EsfJsonValue, void *, size_t), void *additional_param)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    const char *string_expect = "string_serialize_value";
    int process_event_count = 5;

    SendDirectCommandResponse_FullSuccess(handle_val, string_expect, dc_result, additional,
                                          additional_param);

    expect_value(__wrap_SYS_set_response_cb, c, s_sys_client);
    expect_value(__wrap_SYS_set_response_cb, id, cmd_id);
    expect_string(__wrap_SYS_set_response_cb, response, string_expect);
    expect_value(__wrap_SYS_set_response_cb, status, SYS_RESPONSE_STATUS_OK);
    expect_value(__wrap_SYS_set_response_cb, cb, ResponseSendCompleteCallback);
    expect_not_value(__wrap_SYS_set_response_cb, user, NULL);
    will_return(__wrap_SYS_set_response_cb, SYS_RESULT_OK);
    will_return(__wrap_SYS_set_response_cb, process_event_count);

    for (int i = 0; i <= process_event_count; i++) {
        expect_value(__wrap_SYS_process_event, c, s_sys_client);
        expect_value(__wrap_SYS_process_event, ms, 0);
        will_return(__wrap_SYS_process_event, SYS_RESULT_OK);
    }

    // For free() of response
    will_return(mock_free, false);

    // For free() of struct dcres_ctx
    will_return(mock_free, false);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
static void SendDirectCommandResponseAsync_FullSuccess(
    struct SYS_client *evp_handle, SYS_response_id cmd_id, const char *req_id, DcResult dc_result,
    RetCode (*additional)(EsfJsonHandle, EsfJsonValue, void *, size_t), void *additional_param)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    const char *string_expect = "string_serialize_value";
    int process_event_count = 0;

    SendDirectCommandResponse_FullSuccess(handle_val, string_expect, dc_result, additional,
                                          additional_param);

    expect_value(__wrap_SYS_set_response_cb, c, s_sys_client);
    expect_value(__wrap_SYS_set_response_cb, id, cmd_id);
    expect_string(__wrap_SYS_set_response_cb, response, string_expect);
    expect_value(__wrap_SYS_set_response_cb, status, SYS_RESPONSE_STATUS_OK);
    expect_value(__wrap_SYS_set_response_cb, cb, ResponseSendCompleteCallback);
    expect_not_value(__wrap_SYS_set_response_cb, user, NULL);
    will_return(__wrap_SYS_set_response_cb, SYS_RESULT_OK);
    will_return(__wrap_SYS_set_response_cb, process_event_count);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
static void SendDirectCommandResponse_FullSuccessHandle(
    EsfJsonHandle json_handle, DcResult dc_result,
    RetCode (*additional)(EsfJsonHandle, EsfJsonValue, void *, size_t), void *additional_param,
    size_t additional_param_size, EsfMemoryManagerHandle memmgr_handle)
{
    EsfJsonValue json_val = 1357;
    size_t json_buf_size = 2468;
    size_t json_serialize_size = 3579;

    will_return(__wrap_EsfJsonOpen, json_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectInit, handle, json_handle);
    will_return(__wrap_EsfJsonObjectInit, json_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, json_handle);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, json_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, json_handle);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, json_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, NULL);

    Response2CodeAndDetailmsgForTest(dc_result);

    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    if (additional != NULL) {
        if (additional == SetImagePropertyHandle) {
            expect_value(__wrap_SysAppCmnSetStringValueHandle, handle, json_handle);
            expect_value(__wrap_SysAppCmnSetStringValueHandle, parent, json_val);
            expect_string(__wrap_SysAppCmnSetStringValueHandle, key, "image");
            expect_value(__wrap_SysAppCmnSetStringValueHandle, mm_handle,
                         (EsfMemoryManagerHandle)(uintptr_t)additional_param);
            expect_value(__wrap_SysAppCmnSetStringValueHandle, size,
                         additional_param_size - 1); // "-1" means exclude null char
            will_return(__wrap_SysAppCmnSetStringValueHandle, kRetOk);
        }
    }

    expect_value(__wrap_EsfJsonSerializeSizeGet, handle, json_handle);
    expect_value(__wrap_EsfJsonSerializeSizeGet, value, json_val);
    will_return(__wrap_EsfJsonSerializeSizeGet,
                json_buf_size - 1); // "-1" means terminate null string

    AllocateAndFopenMemoryManagerHandleCommon(memmgr_handle, json_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    expect_value(__wrap_EsfJsonSerializeHandle, handle, json_handle);
    expect_value(__wrap_EsfJsonSerializeHandle, value, json_val);
    expect_value(__wrap_EsfJsonSerializeHandle, mem_handle, memmgr_handle);
    will_return(__wrap_EsfJsonSerializeHandle, json_serialize_size);
    will_return(__wrap_EsfJsonSerializeHandle, kEsfJsonSuccess);

    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(DcResponseContext));
}

/*----------------------------------------------------------------------------*/
static void SendDirectCommandResponseAsync_FullSuccessHandle(
    SYS_response_id cmd_id, DcResult dc_result,
    RetCode (*additional)(EsfJsonHandle, EsfJsonValue, void *, size_t), void *additional_param,
    size_t additional_param_size, EsfMemoryManagerHandle memmgr_handle_json)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    int process_event_count = 0;

    SendDirectCommandResponse_FullSuccessHandle(handle_val, dc_result, additional, additional_param,
                                                additional_param_size, memmgr_handle_json);

    expect_value(__wrap_SYS_set_response_cb, c, s_sys_client);
    expect_value(__wrap_SYS_set_response_cb, id, cmd_id);
    expect_value(__wrap_SYS_set_response_cb, response, memmgr_handle_json);
    expect_value(__wrap_SYS_set_response_cb, status, SYS_RESPONSE_STATUS_OK);
    expect_value(__wrap_SYS_set_response_cb, cb, ResponseSendCompleteCallbackHandle);
    expect_not_value(__wrap_SYS_set_response_cb, user, NULL);
    will_return(__wrap_SYS_set_response_cb, SYS_RESULT_OK);
    will_return(__wrap_SYS_set_response_cb, process_event_count);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    FcloseAndFreeMemoryManagerHandleCommon((EsfMemoryManagerHandle)(uintptr_t)additional_param,
                                           FcloseAndFreeMemoryManagerHandle_None);
}

/*----------------------------------------------------------------------------*/
static void ExecSysProcessEventForMemoryFree(void)
{
    // For free() of response
    will_return(mock_free, false);

    // For free() of struct dcres_ctx
    will_return(mock_free, false);

    // For SYS_process_event()
    expect_value(__wrap_SYS_process_event, c, s_sys_client);
    expect_value(__wrap_SYS_process_event, ms, 0);
    will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

    // Exec SYS_process_event()
    SYS_process_event(s_sys_client, 0);
}

/*----------------------------------------------------------------------------*/
static void ExecSysProcessEventForMemoryFreeHandle(EsfMemoryManagerHandle memmgr_handle_json)
{
    // For MemoryManager mock operatoin
    FcloseAndFreeMemoryManagerHandleCommon(memmgr_handle_json,
                                           FcloseAndFreeMemoryManagerHandle_None);

    // For free() of struct dcres_ctx
    will_return(mock_free, false);

    // For SYS_process_event()
    expect_value(__wrap_SYS_process_event, c, s_sys_client);
    expect_value(__wrap_SYS_process_event, ms, 0);
    will_return(__wrap_SYS_process_event, SYS_RESULT_OK);

    // Exec SYS_process_event()
    SYS_process_event(s_sys_client, 0);
}

/*----------------------------------------------------------------------------*/
static void SendDirectCommandResponseSync_CheckResponseLog(struct SYS_client *evp_handle,
                                                           SYS_response_id cmd_id,
                                                           const char *req_id, DcResult dc_result,
                                                           const char *string_expect)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    int process_event_count = 5;

    SendDirectCommandResponse_FullSuccess(handle_val, string_expect, dc_result, NULL, NULL);

    expect_value(__wrap_SYS_set_response_cb, c, s_sys_client);
    expect_value(__wrap_SYS_set_response_cb, id, cmd_id);
    expect_string(__wrap_SYS_set_response_cb, response, string_expect);
    expect_value(__wrap_SYS_set_response_cb, status, SYS_RESPONSE_STATUS_OK);
    expect_value(__wrap_SYS_set_response_cb, cb, ResponseSendCompleteCallback);
    expect_not_value(__wrap_SYS_set_response_cb, user, NULL);
    will_return(__wrap_SYS_set_response_cb, SYS_RESULT_OK);
    will_return(__wrap_SYS_set_response_cb, process_event_count);

    for (int i = 0; i <= process_event_count; i++) {
        expect_value(__wrap_SYS_process_event, c, s_sys_client);
        expect_value(__wrap_SYS_process_event, ms, 0);
        will_return(__wrap_SYS_process_event, SYS_RESULT_OK);
    }

    // For free() of response
    will_return(mock_free, false); // Not check parameter

    // For free() of struct dcres_ctx
    will_return(mock_free, false); // Not check parameter

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
static void SendDirectCommandResponse_ErrorSysSetResponseCb(
    struct SYS_client *evp_handle, SYS_response_id cmd_id, const char *req_id, DcResult dc_result,
    RetCode (*additional)(EsfJsonHandle, EsfJsonValue, void *, size_t), void *additional_param)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    const char *string_expect = "string_serialize_value";

    SendDirectCommandResponse_FullSuccess(handle_val, string_expect, dc_result, additional,
                                          additional_param);

    expect_value(__wrap_SYS_set_response_cb, c, s_sys_client);
    expect_value(__wrap_SYS_set_response_cb, id, cmd_id);
    expect_string(__wrap_SYS_set_response_cb, response, string_expect);
    expect_value(__wrap_SYS_set_response_cb, status, SYS_RESPONSE_STATUS_OK);
    expect_value(__wrap_SYS_set_response_cb, cb, ResponseSendCompleteCallback);
    expect_not_value(__wrap_SYS_set_response_cb, user, NULL);
    will_return(__wrap_SYS_set_response_cb, SYS_RESULT_ERRNO);

    // For free() of response
    will_return(mock_free, false); // Not check parameter

    // For free() of struct dcres_ctx
    will_return(mock_free, false); // Not check parameter

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
}

/*----------------------------------------------------------------------------*/
static void Execute_GetDirectGetImageParams(const char *param,
                                            GetDirectGetImageParamsTestFlag test_flg)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;

    // Check EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, handle_val);
    if (test_flg == GetDirectGetImageParams_EsfJsonOpen) {
        will_return(__wrap_EsfJsonOpen, kEsfJsonHandleError);
        goto exit;
    }
    else {
        will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);
    }

    // Check EsfJsonDeserialize()
    expect_value(__wrap_EsfJsonDeserialize, handle, handle_val);
    if (param != NULL) {
        expect_string(__wrap_EsfJsonDeserialize, str, param);
    }
    else {
        expect_value(__wrap_EsfJsonDeserialize, str, param);
    }
    will_return(__wrap_EsfJsonDeserialize, parent_val);
    if (test_flg == GetDirectGetImageParams_EsfJsonDeserialize) {
        will_return(__wrap_EsfJsonDeserialize, kEsfJsonHandleError);
        goto close_exit;
    }
    else {
        will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);
    }

    // Check jsonkey(network_id) from SysAppCmnExtractStringValue()
    expect_value(__wrap_SysAppCmnExtractStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnExtractStringValue, parent_val, parent_val);
    expect_string(__wrap_SysAppCmnExtractStringValue, jsonkey, "network_id");
    if (test_flg == GetDirectGetImageParams_SysAppCmnExtractStringValueNetworkIdNullStr) {
        // Return null str
        will_return(__wrap_SysAppCmnExtractStringValue, "");
    }
    else if (test_flg == GetDirectGetImageParams_SysAppCmnExtractStringValueNetworkIdMaxOver) {
        // Return max over str
        will_return(__wrap_SysAppCmnExtractStringValue, dgiparam_max_over_network_id);
    }
    else if (test_flg == GetDirectGetImageParams_SysAppCmnExtractStringValueNetworkIdMax) {
        // Return max str
        will_return(__wrap_SysAppCmnExtractStringValue, dgiparam_max_network_id);
    }
    else {
        // Return test str
        will_return(__wrap_SysAppCmnExtractStringValue, dgiparam_test_network_id);
    }

    if (test_flg == GetDirectGetImageParams_SysAppCmnExtractStringValueNetworkIdNokey) {
        will_return(__wrap_SysAppCmnExtractStringValue, -1);
    }
    else if (test_flg == GetDirectGetImageParams_SysAppCmnExtractStringValueNetworkIdInvalidKey) {
        will_return(__wrap_SysAppCmnExtractStringValue, 0);
    }
    else {
        will_return(__wrap_SysAppCmnExtractStringValue, 1);
    }

close_exit:
    // Check EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    if (test_flg == GetDirectGetImageParams_EsfJsonClose) {
        will_return(__wrap_EsfJsonClose, kEsfJsonHandleError);
    }
    else {
        will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
    }

exit:
    return;
}

/*----------------------------------------------------------------------------*/
static void Execute_GetOneFrame(GetOneFrameTestFlag test_flg)
{
    senscord_channel_t expect_channel = 555;
    uint32_t expect_count = 1;                  // Fixed value
    uint32_t expect_input_channel = 0x00000001; // Fixed value

    // Image Property Test Parameter
    static struct senscord_image_property_t expect_img_prop = {
        .width = SENSCORD_IMAGE_PROPERTY_WIDTH,
        .height = SENSCORD_IMAGE_PROPERTY_HEIGHT,
        .stride_bytes = SENSCORD_IMAGE_PROPERTY_STRIDE_BYTE};

    // Raw Data Test Parameter
    static const struct senscord_raw_data_t expect_raw_data = {
        .address = (void *)(uintptr_t)SENSCORD_RAW_DATA_ADDRESS,
        .size = SENSCORD_RAW_DATA_SIZE,
        .type = "expect_raw_data_type",
        .timestamp = SENSCORD_RAW_DATA_TIMESTAMP};

    // Check table in GetFormatOfImage
    if (test_flg == GetOneFrame_GetFormatOfImage) {
        snprintf(expect_img_prop.pixel_format, sizeof(expect_img_prop.pixel_format), "%s", "test");
    }
    else {
        snprintf(expect_img_prop.pixel_format, sizeof(expect_img_prop.pixel_format), "%s",
                 SENSCORD_PIXEL_FORMAT_RGB8_PLANAR);
    }

    // Check SysAppStateGetSensCordId()
    will_return(__wrap_SysAppStateGetSensCordId, FRAME_INFO_SCCORE);
    if (test_flg == GetOneFrame_SysAppStateGetSensCordId) {
        will_return(__wrap_SysAppStateGetSensCordId, kRetApiCallError);
        goto error_exit;
    }
    else {
        will_return(__wrap_SysAppStateGetSensCordId, kRetOk);
    }

    // Check SysAppStateGetSensCordStream()
    will_return(__wrap_SysAppStateGetSensCordStream, FRAME_INFO_SCSTREAM);
    if (test_flg == GetOneFrame_SysAppStateGetSensCordStream) {
        will_return(__wrap_SysAppStateGetSensCordStream, kRetApiCallError);
        goto error_exit;
    }
    else {
        will_return(__wrap_SysAppStateGetSensCordStream, kRetOk);
    }

    // Check property(ai_model) in senscord_stream_set_property()
    expect_value(__wrap_senscord_stream_set_property, stream, FRAME_INFO_SCSTREAM);
    expect_string(__wrap_senscord_stream_set_property, property_key,
                  SENSCORD_AI_MODEL_BUNDLE_ID_PROPERTY_KEY);
    if (test_flg == GetOneFrame_SenscordStreamSetPropertyAiModelCheckDefault) {
        // Check default network_id
        expect_string(__wrap_senscord_stream_set_property, ai_model->ai_model_bundle_id,
                      dgiparam_default_network_id);
    }
    else if (test_flg == GetOneFrame_SenscordStreamSetPropertyAiModelCheckMax) {
        // Check max network_id str
        expect_string(__wrap_senscord_stream_set_property, ai_model->ai_model_bundle_id,
                      dgiparam_max_network_id);
    }
    else {
        // Check test parameter network_id
        expect_string(__wrap_senscord_stream_set_property, ai_model->ai_model_bundle_id,
                      dgiparam_test_network_id);
    }
    expect_value(__wrap_senscord_stream_set_property, value_size,
                 sizeof(struct senscord_ai_model_bundle_id_property_t));
    if (test_flg == GetOneFrame_SenscordStreamSetPropertyAiModel) {
        will_return(__wrap_senscord_stream_set_property, -1);
        goto error_exit;
    }
    else {
        will_return(__wrap_senscord_stream_set_property, 0);
    }

    // Check property(input_data) in senscord_stream_set_property()
    expect_value(__wrap_senscord_stream_set_property, stream, FRAME_INFO_SCSTREAM);
    expect_string(__wrap_senscord_stream_set_property, property_key,
                  SENSCORD_INPUT_DATA_TYPE_PROPERTY_KEY);
    expect_value(__wrap_senscord_stream_set_property, input_data->count, expect_count);
    expect_value(__wrap_senscord_stream_set_property, input_data->channels[0],
                 expect_input_channel);
    expect_value(__wrap_senscord_stream_set_property, value_size,
                 sizeof(struct senscord_input_data_type_property_t));
    if (test_flg == GetOneFrame_SenscordStreamSetPropertyInputData) {
        will_return(__wrap_senscord_stream_set_property, -1);
        goto error_exit;
    }
    else {
        will_return(__wrap_senscord_stream_set_property, 0);
    }

    // Check senscord_stream_start()
    expect_value(__wrap_senscord_stream_start, stream, FRAME_INFO_SCSTREAM);
    if (test_flg == GetOneFrame_SenscordStreamStart) {
        will_return(__wrap_senscord_stream_start, -1);
        goto error_exit;
    }
    else {
        will_return(__wrap_senscord_stream_start, 0);
    }

    // Check senscord_stream_get_frame()
    expect_value(__wrap_senscord_stream_get_frame, stream, FRAME_INFO_SCSTREAM);
    expect_value(__wrap_senscord_stream_get_frame, timeout_msec, -1);
    will_return(__wrap_senscord_stream_get_frame, FRAME_INFO_SCSCFRAME);
    if (test_flg == GetOneFrame_SenscordStreamGetFrame) {
        will_return(__wrap_senscord_stream_get_frame, -1);
        goto stop_exit;
    }
    else {
        will_return(__wrap_senscord_stream_get_frame, 0);
    }

    // Check senscord_frame_get_channel_from_channel_id()
    expect_value(__wrap_senscord_frame_get_channel_from_channel_id, frame, FRAME_INFO_SCSCFRAME);
    expect_value(__wrap_senscord_frame_get_channel_from_channel_id, channel_id, 0x00000001);
    will_return(__wrap_senscord_frame_get_channel_from_channel_id, expect_channel);
    if (test_flg == GetOneFrame_SenscordFrameGetChannelFromChannelId) {
        will_return(__wrap_senscord_frame_get_channel_from_channel_id, -1);
        goto release_exit;
    }
    else {
        will_return(__wrap_senscord_frame_get_channel_from_channel_id, 0);
    }

    // Check senscord_stream_get_property() and return property(image_property)
    expect_value(__wrap_senscord_stream_get_property, stream, FRAME_INFO_SCSTREAM);
    expect_string(__wrap_senscord_stream_get_property, property_key, SENSCORD_IMAGE_PROPERTY_KEY);
    expect_value(__wrap_senscord_stream_get_property, value_size,
                 sizeof(struct senscord_image_property_t));
    will_return(__wrap_senscord_stream_get_property, &expect_img_prop);
    if (test_flg == GetOneFrame_SenscordStreamSetPropertyImageProp) {
        will_return(__wrap_senscord_stream_get_property, -1);
        goto error_exit;
    }
    else {
        will_return(__wrap_senscord_stream_get_property, 0);
    }

    // Check senscord_channel_get_raw_data()
    expect_value(__wrap_senscord_channel_get_raw_data, channel, expect_channel);
    will_return(__wrap_senscord_channel_get_raw_data, &expect_raw_data);
    if (test_flg == GetOneFrame_SenscordChannelGetRawData) {
        will_return(__wrap_senscord_channel_get_raw_data, -1);
        goto release_exit;
    }
    else {
        will_return(__wrap_senscord_channel_get_raw_data, 0);
    }

    // Check EsfMemoryManagerGetHandleInfo()
    expect_value(__wrap_EsfMemoryManagerGetHandleInfo, handle, expect_raw_data.address);
    if (test_flg == GetOneFrame_EsfMemoryManagerGetHandleInfo) {
        will_return(__wrap_EsfMemoryManagerGetHandleInfo, kEsfMemoryManagerTargetLargeHeap);
        will_return(__wrap_EsfMemoryManagerGetHandleInfo, kEsfMemoryManagerResultParamError);
        goto release_exit;
    }
    else if (test_flg == GetOneFrame_EsfMemoryManagerGetHandleInfoOtherHeap) {
        will_return(__wrap_EsfMemoryManagerGetHandleInfo, kEsfMemoryManagerTargetOtherHeap);
        will_return(__wrap_EsfMemoryManagerGetHandleInfo, kEsfMemoryManagerResultSuccess);
    }
    else {
        will_return(__wrap_EsfMemoryManagerGetHandleInfo, kEsfMemoryManagerTargetLargeHeap);
        will_return(__wrap_EsfMemoryManagerGetHandleInfo, kEsfMemoryManagerResultSuccess);
    }

    return;

    //
    // Error handling.
    //

release_exit:
    // Check senscord_stream_release_frame()
    expect_value(__wrap_senscord_stream_release_frame, stream, FRAME_INFO_SCSTREAM);
    expect_value(__wrap_senscord_stream_release_frame, frame, FRAME_INFO_SCSCFRAME);
    will_return(__wrap_senscord_stream_release_frame, 0);

stop_exit:
    // Check senscord_stream_stop()
    expect_value(__wrap_senscord_stream_stop, stream, FRAME_INFO_SCSTREAM);
    will_return(__wrap_senscord_stream_stop, 0);

error_exit:
    return;
}

/*----------------------------------------------------------------------------*/
static void Execute_ReleaseOneFrame(ReleaseOneFrameTestFlag test_flg)
{
    // Check senscord_stream_release_frame()
    expect_value(__wrap_senscord_stream_release_frame, stream, FRAME_INFO_SCSTREAM);
    expect_value(__wrap_senscord_stream_release_frame, frame, FRAME_INFO_SCSCFRAME);
    if (test_flg == ReleaseOneFrame_SenscordStreamReleaseFrame) {
        will_return(__wrap_senscord_stream_release_frame, -1);
    }
    else {
        will_return(__wrap_senscord_stream_release_frame, 0);
    }

    // Check senscord_stream_stop()
    expect_value(__wrap_senscord_stream_stop, stream, FRAME_INFO_SCSTREAM);
    if (test_flg == ReleaseOneFrame_SenscordStreamStop) {
        will_return(__wrap_senscord_stream_stop, -1);
    }
    else {
        will_return(__wrap_senscord_stream_stop, 0);
    }
}

/*----------------------------------------------------------------------------*/
static void Execute_EsfCodecJpegEncodeHandle(EsfMemoryManagerHandle expect_jpeg_buf_handle,
                                             EsfCodecJpegInputFormat jpeg_input_format,
                                             int expect_quality, int32_t expect_jpeg_size,
                                             JpegEncodeHandleErrorFlag err_flag)
{
    expect_value(__wrap_EsfCodecJpegEncodeHandle, input_file_handle, SENSCORD_RAW_DATA_ADDRESS);
    expect_value(__wrap_EsfCodecJpegEncodeHandle, output_file_handle, expect_jpeg_buf_handle);
    expect_value(__wrap_EsfCodecJpegEncodeHandle, info->input_fmt, jpeg_input_format);
    expect_value(__wrap_EsfCodecJpegEncodeHandle, info->width, SENSCORD_IMAGE_PROPERTY_WIDTH);
    expect_value(__wrap_EsfCodecJpegEncodeHandle, info->height, SENSCORD_IMAGE_PROPERTY_HEIGHT);
    expect_value(__wrap_EsfCodecJpegEncodeHandle, info->stride,
                 SENSCORD_IMAGE_PROPERTY_STRIDE_BYTE);
    expect_value(__wrap_EsfCodecJpegEncodeHandle, info->quality, expect_quality);
    will_return(__wrap_EsfCodecJpegEncodeHandle, expect_jpeg_size);
    if (err_flag == JpegEncodeHandle_JpegOutputOther) {
        will_return(__wrap_EsfCodecJpegEncodeHandle, kJpegOtherError);
        goto exit;
    }
    else if (err_flag == JpegEncodeHandle_JpegOutputBufferFull) {
        will_return(__wrap_EsfCodecJpegEncodeHandle, kJpegOutputBufferFullError);
        goto exit;
    }
    else {
        will_return(__wrap_EsfCodecJpegEncodeHandle, kJpegSuccess);
    }

exit:
}

/*----------------------------------------------------------------------------*/
static void Execute_EsfCodecJpegEncode(uint32_t jpeg_buf_size,
                                       EsfCodecJpegInputFormat jpeg_input_format, int quality,
                                       int32_t jpeg_size, JpegEncodeErrorFlag err_flag)
{
    expect_value(__wrap_EsfCodecJpegEncode, enc_param->input_adr_handle, SENSCORD_RAW_DATA_ADDRESS);
    expect_not_value(__wrap_EsfCodecJpegEncode, enc_param->out_buf.output_adr_handle, NULL);
    expect_value(__wrap_EsfCodecJpegEncode, enc_param->out_buf.output_buf_size, jpeg_buf_size);
    expect_value(__wrap_EsfCodecJpegEncode, enc_param->input_fmt, jpeg_input_format);
    expect_value(__wrap_EsfCodecJpegEncode, enc_param->width, SENSCORD_IMAGE_PROPERTY_WIDTH);
    expect_value(__wrap_EsfCodecJpegEncode, enc_param->height, SENSCORD_IMAGE_PROPERTY_HEIGHT);
    expect_value(__wrap_EsfCodecJpegEncode, enc_param->stride, SENSCORD_IMAGE_PROPERTY_STRIDE_BYTE);
    expect_value(__wrap_EsfCodecJpegEncode, enc_param->quality, quality);
    will_return(__wrap_EsfCodecJpegEncode, jpeg_size);
    if (err_flag == JpegEncode_JpegOutputOther) {
        will_return(__wrap_EsfCodecJpegEncode, kJpegOtherError);
    }
    else if (err_flag == JpegEncode_JpegOutputBufferFull) {
        will_return(__wrap_EsfCodecJpegEncode, kJpegOutputBufferFullError);
    }
    else {
        will_return(__wrap_EsfCodecJpegEncode, kJpegSuccess);
    }
}

/*----------------------------------------------------------------------------*/
static void Execute_EsfCodecBase64EncodeHandle(
    int32_t expect_jpeg_size, EsfCodecBase64ResultEnum ret_esfcodecbase64_encodefileio,
    EsfMemoryManagerHandle expect_jpeg_buf_handle, EsfMemoryManagerHandle expect_b64_buf_size,
    uint32_t expect_b64_size)
{
    expect_value(__wrap_EsfCodecBase64EncodeHandle, in_handle, expect_jpeg_buf_handle);
    expect_value(__wrap_EsfCodecBase64EncodeHandle, in_size, expect_jpeg_size);
    expect_value(__wrap_EsfCodecBase64EncodeHandle, out_handle, expect_b64_buf_size);
    will_return(__wrap_EsfCodecBase64EncodeHandle, expect_b64_size);
    will_return(__wrap_EsfCodecBase64EncodeHandle, ret_esfcodecbase64_encodefileio);
}

/*----------------------------------------------------------------------------*/
static void Execute_EsfCodecBase64Encode(size_t jpeg_size, char *b64_buf, size_t b64_size,
                                         EsfCodecBase64ResultEnum ret)
{
    expect_not_value(__wrap_EsfCodecBase64Encode, in, NULL);
    expect_value(__wrap_EsfCodecBase64Encode, in_size, jpeg_size);
    will_return(__wrap_EsfCodecBase64Encode, b64_buf);
    will_return(__wrap_EsfCodecBase64Encode, b64_size);
    will_return(__wrap_EsfCodecBase64Encode, ret);
}

/*----------------------------------------------------------------------------*/
static void Execute_EncodePhaseWithHandle(EsfMemoryManagerHandle expect_b64_buf_handle,
                                          EsfCodecJpegInputFormat jpeg_input_format,
                                          uint32_t expect_b64_size)
{
    EsfMemoryManagerHandle expect_jpeg_buf_handle = (EsfMemoryManagerHandle)0x24680000;
    int32_t expect_jpeg_size = 5566;
    int expect_quality = 80;
    uint32_t expect_b64_buf_size = 6464;
    const uint32_t jpeg_buf_size = DC_DIRECT_GET_IMAGE_MAX_SIZE * 3 / 4;

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_jpeg_buf_handle, jpeg_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    // Check EsfCodecJpegEncodeHandle function
    Execute_EsfCodecJpegEncodeHandle(expect_jpeg_buf_handle, jpeg_input_format, expect_quality,
                                     expect_jpeg_size, JpegEncodeHandle_None);

    expect_value(__wrap_EsfCodecBase64GetEncodeSize, in_size, expect_jpeg_size);
    will_return(__wrap_EsfCodecBase64GetEncodeSize, expect_b64_buf_size);

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_b64_buf_handle, expect_b64_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    // Check EsfCodecBase64EncodeHandle function
    Execute_EsfCodecBase64EncodeHandle(expect_jpeg_size, kEsfCodecBase64ResultSuccess,
                                       expect_jpeg_buf_handle, expect_b64_buf_handle,
                                       expect_b64_size);

    // FcloseAndFreeMemoryManagerHandle()
    FcloseAndFreeMemoryManagerHandleCommon(expect_jpeg_buf_handle,
                                           FcloseAndFreeMemoryManagerHandle_None);

    // Check ReleaseOneFrame function
    Execute_ReleaseOneFrame(ReleaseOneFrame_None);
}

/*----------------------------------------------------------------------------*/
static void Execute_EncodePhaseWithRawData(char *expect_b64_buf,
                                           EsfCodecJpegInputFormat jpeg_input_format,
                                           uint32_t expect_b64_size,
                                           ExecEncodePhaseWithRawDataErrFlag err_flag)
{
    int32_t expect_jpeg_size = 5566;
    int expect_quality = 80;
    uint32_t expect_b64_buf_size = 6464;
    const uint32_t jpeg_buf_size = DC_DIRECT_GET_IMAGE_MAX_SIZE * 3 / 4;

    // Check malloc()
    will_return(mock_malloc, true); // Exec parameter check
    expect_value(mock_malloc, __size, jpeg_buf_size);
    if (err_flag == ExecEncodePhaseWithRawData_MallocJpegEncodeBuffer) {
        will_return(mock_malloc, false); // Get NULL
        goto release_one_frame;
    }
    else {
        will_return(mock_malloc, true); // Get allocate memory
    }

    // Check EsfCodecJpegEncode function
    if (err_flag == ExecEncodePhaseWithRawData_EsfCodecJpegEncode) {
        Execute_EsfCodecJpegEncode(jpeg_buf_size, jpeg_input_format, expect_quality,
                                   expect_jpeg_size, JpegEncode_JpegOutputOther);
        goto release_one_frame;
    }
    else {
        Execute_EsfCodecJpegEncode(jpeg_buf_size, jpeg_input_format, expect_quality,
                                   expect_jpeg_size, JpegEncode_None);
    }

    expect_value(__wrap_EsfCodecBase64GetEncodeSize, in_size, expect_jpeg_size);
    will_return(__wrap_EsfCodecBase64GetEncodeSize, expect_b64_buf_size);

    // Check malloc()
    will_return(mock_malloc, true); // Exec parameter check
    expect_value(mock_malloc, __size, expect_b64_buf_size);
    if (err_flag == ExecEncodePhaseWithRawData_MallocBase64EncodeBuffer) {
        will_return(mock_malloc, false); // Get NULL
        goto free_jpeg_buffer;
    }
    else {
        will_return(mock_malloc, true); // Get allocate memory
    }

    // Check EsfCodecBase64Encode function
    if (err_flag == ExecEncodePhaseWithRawData_EsfCodecBase64Encode) {
        Execute_EsfCodecBase64Encode(expect_jpeg_size, expect_b64_buf, expect_b64_size,
                                     kEsfCodecBase64ResultInternalError);

        // Check free() - base64 encode buffer
        will_return(mock_free, false); // Not check parameter

        goto free_jpeg_buffer;
    }
    else {
        Execute_EsfCodecBase64Encode(expect_jpeg_size, expect_b64_buf, expect_b64_size,
                                     kEsfCodecBase64ResultSuccess);
    }

free_jpeg_buffer:
    // Check free() - jpeg encode buffer
    will_return(mock_free, false); // Not check parameter

release_one_frame:
    // Check ReleaseOneFrame function
    Execute_ReleaseOneFrame(ReleaseOneFrame_None);
}

/*----------------------------------------------------------------------------*/
static void SendDirectCommandResponseAsync_ErrorSysSetResponseCbHandle(
    SYS_response_id cmd_id, DcResult dc_result,
    RetCode (*additional)(EsfJsonHandle, EsfJsonValue, void *, size_t), void *additional_param,
    size_t additional_param_size, EsfMemoryManagerHandle memmgr_handle_json)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;

    SendDirectCommandResponse_FullSuccessHandle(handle_val, dc_result, additional, additional_param,
                                                additional_param_size, memmgr_handle_json);

    expect_value(__wrap_SYS_set_response_cb, c, s_sys_client);
    expect_value(__wrap_SYS_set_response_cb, id, cmd_id);
    expect_value(__wrap_SYS_set_response_cb, response, memmgr_handle_json);
    expect_value(__wrap_SYS_set_response_cb, status, SYS_RESPONSE_STATUS_OK);
    expect_value(__wrap_SYS_set_response_cb, cb, ResponseSendCompleteCallbackHandle);
    expect_not_value(__wrap_SYS_set_response_cb, user, NULL);
    will_return(__wrap_SYS_set_response_cb, SYS_RESULT_ERRNO);

    // For free() of struct dcres_ctx
    will_return(mock_free, false); // Not check parameter

    FcloseAndFreeMemoryManagerHandleCommon(memmgr_handle_json,
                                           FcloseAndFreeMemoryManagerHandle_None);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    FcloseAndFreeMemoryManagerHandleCommon((EsfMemoryManagerHandle)(uintptr_t)additional_param,
                                           FcloseAndFreeMemoryManagerHandle_None);
}

/*----------------------------------------------------------------------------*/
static void CheckDcmdRebootStartedUtilityLog(void)
{
    expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
    expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelInfo);
    expect_value(__wrap_UtilityLogWriteELog, event_id, 0xb001);
    will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);
}

/*----------------------------------------------------------------------------*/
static void CheckDcmdFactoryResetFromConsoleStartedUtilityLog(void)
{
    expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
    expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelInfo);
    expect_value(__wrap_UtilityLogWriteELog, event_id, 0xb002);
    will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);
}

/*----------------------------------------------------------------------------*/
static void CheckDcmdDirectGetImageRequestStartedUtilityLog(void)
{
    expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
    expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelInfo);
    expect_value(__wrap_UtilityLogWriteELog, event_id, 0xb004);
    will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);
}

/*----------------------------------------------------------------------------*/
static void CheckDcmdDirectGetImageSensorErrorUtilityLog(void)
{
    expect_value(__wrap_UtilityLogWriteELog, module_id, MODULE_ID_SYSTEM);
    expect_value(__wrap_UtilityLogWriteELog, level, kUtilityLogElogLevelError);
    expect_value(__wrap_UtilityLogWriteELog, event_id, 0xb0b1);
    will_return(__wrap_UtilityLogWriteELog, kUtilityLogStatusOk);
}

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static uint64_t GetSensorRegisterArrayAddress(uint32_t array_index)
{
    return (SENSOR_REGISTER_PARAM_ADDRESS_BASE_VAL + array_index);
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static uint32_t GetSensorRegisterArraySize(uint32_t array_index)
{
    uint32_t ret = 0;

    switch (array_index % 3) {
        case 0:
            ret = 4;
            break;
        case 1:
            ret = 1;
            break;
        case 2:
        default:
            ret = 2;
            break;
    }

    return ret;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static uint32_t GetSensorRegisterArrayValue(uint32_t size, uint32_t array_index)
{
    uint32_t ret = 0;

    switch (size) {
        case 1:
            ret = SENSOR_REGISTER_PARAM_SIZE_1BYTE_BASE_VAL + array_index;
            break;
        case 2:
            ret = SENSOR_REGISTER_PARAM_SIZE_2BYTE_BASE_VAL + array_index;
            break;
        case 4:
        default:
            ret = SENSOR_REGISTER_PARAM_SIZE_4BYTE_BASE_VAL + array_index;
            break;
    }

    return ret;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static uint32_t GetSensorRegisterArrayMaxValue(uint32_t size)
{
    uint32_t ret = 0;

    switch (size) {
        case 1:
            ret = 0xFF;
            break;
        case 2:
            ret = 0xFFFF;
            break;
        case 4:
        default:
            ret = 0xFFFFFFFF;
            break;
    }

    return ret;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void GetSensorRegisterArrayParamCommon(EsfJsonHandle json_handle, EsfJsonValue json_val,
                                              int32_t array_num, bool is_get_value_property,
                                              GetSensorRegisterArrayParamErrFlag err_flag)
{
    int i;
    EsfJsonValue json_val_sub = 1122;
    uint32_t size;
    bool is_exit = false;

    for (i = 0; i < array_num; i++) {
        size = GetSensorRegisterArraySize(i);

        // For EsfJsonArrayGet()
        expect_value(__wrap_EsfJsonArrayGet, handle, json_handle);
        expect_value(__wrap_EsfJsonArrayGet, parent, json_val);
        expect_value(__wrap_EsfJsonArrayGet, index, i);
        will_return(__wrap_EsfJsonArrayGet, json_val_sub);
        if (err_flag == GetSensorRegisterArrayParam_EsfJsonArrayGet) {
            will_return(__wrap_EsfJsonArrayGet, kEsfJsonInternalError);
            goto exit;
        }
        else {
            will_return(__wrap_EsfJsonArrayGet, kEsfJsonSuccess);
        }

        // For SysAppCmnExtractRealNumberValue() address property
        expect_value(__wrap_SysAppCmnExtractRealNumberValue, handle, json_handle);
        expect_value(__wrap_SysAppCmnExtractRealNumberValue, parent_val, json_val_sub);
        expect_string(__wrap_SysAppCmnExtractRealNumberValue, jsonkey, "address");
        SetSysAppCmnExtractRealNumberValue(GetSensorRegisterArrayAddress(i));
        if (err_flag == GetSensorRegisterArrayParam_SysAppCmnExtractRealNumberValueAddress) {
            will_return(__wrap_SysAppCmnExtractRealNumberValue, 0);
            goto exit;
        }
        else {
            will_return(__wrap_SysAppCmnExtractRealNumberValue, 1);
        }

        // For SysAppCmnExtractNumberValue() size property
        expect_value(__wrap_SysAppCmnExtractNumberValue, handle, json_handle);
        expect_value(__wrap_SysAppCmnExtractNumberValue, parent_val, json_val_sub);
        expect_string(__wrap_SysAppCmnExtractNumberValue, jsonkey, "size");
        if (err_flag == GetSensorRegisterArrayParam_InvalidSizeProtertyValue) {
            will_return(__wrap_SysAppCmnExtractNumberValue, 3);
            is_exit = true;
        }
        else {
            will_return(__wrap_SysAppCmnExtractNumberValue, size);
        }
        if (err_flag == GetSensorRegisterArrayParam_SysAppCmnExtractNumberValueSize) {
            will_return(__wrap_SysAppCmnExtractNumberValue, 0);
            is_exit = true;
        }
        else {
            will_return(__wrap_SysAppCmnExtractNumberValue, 1);
        }
        if (is_exit == true) {
            goto exit;
        }

        if (is_get_value_property == true) {
            // For SysAppCmnExtractRealNumberValue() value property
            expect_value(__wrap_SysAppCmnExtractRealNumberValue, handle, json_handle);
            expect_value(__wrap_SysAppCmnExtractRealNumberValue, parent_val, json_val_sub);
            expect_string(__wrap_SysAppCmnExtractRealNumberValue, jsonkey, "value");
            if (((size == 1) && (err_flag == GetSensorRegisterArrayParam_MaxOverValue1Byte)) ||
                ((size == 2) && (err_flag == GetSensorRegisterArrayParam_MaxOverValue2Byte)) ||
                ((size == 4) && (err_flag == GetSensorRegisterArrayParam_MaxOverValue4Byte))) {
                SetSysAppCmnExtractRealNumberValue((uint64_t)GetSensorRegisterArrayMaxValue(size) +
                                                   1);
                is_exit = true;
            }
            else if (((size == 1) && (err_flag == GetSensorRegisterArrayParam_MaxValue1Byte)) ||
                     ((size == 2) && (err_flag == GetSensorRegisterArrayParam_MaxValue2Byte)) ||
                     ((size == 4) && (err_flag == GetSensorRegisterArrayParam_MaxValue4Byte))) {
                SetSysAppCmnExtractRealNumberValue(GetSensorRegisterArrayMaxValue(size));
            }
            else {
                SetSysAppCmnExtractRealNumberValue(GetSensorRegisterArrayValue(size, i));
            }
            if (err_flag == GetSensorRegisterArrayParam_SysAppCmnExtractRealNumberValueValue) {
                will_return(__wrap_SysAppCmnExtractRealNumberValue, 0);
                is_exit = true;
            }
            else {
                will_return(__wrap_SysAppCmnExtractRealNumberValue, 1);
            }
            if (is_exit == true) {
                goto exit;
            }
        }
    }

exit:
    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void GetSensorRegisterParamCommon(EsfJsonHandle json_handle, EsfJsonValue json_val,
                                         int32_t array_num, bool is_get_value_property,
                                         GetSensorRegisterParamErrFlag err_flag)
{
    EsfJsonValue child_json_val = json_val * 2;
    bool is_exit = false;
    GetSensorRegisterArrayParamErrFlag get_sensor_register_array_param_err_flag;

    // For EsfJsonObjectGet()
    expect_value(__wrap_EsfJsonObjectGet, handle, json_handle);
    expect_value(__wrap_EsfJsonObjectGet, parent, json_val);
    expect_string(__wrap_EsfJsonObjectGet, key, "register");
    will_return(__wrap_EsfJsonObjectGet, child_json_val);
    if (err_flag == GetSensorRegisterParam_EsfJsonObjectGet) {
        will_return(__wrap_EsfJsonObjectGet, kEsfJsonInternalError);
        goto exit;
    }
    else {
        will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);
    }

    // For EsfJsonValueTypeGet()
    expect_value(__wrap_EsfJsonValueTypeGet, handle, json_handle);
    expect_value(__wrap_EsfJsonValueTypeGet, value, child_json_val);
    if (err_flag == GetSensorRegisterParam_InvalidTypeRegisterProperty) {
        will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeNumber);
        is_exit = true;
    }
    else {
        will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeArray);
    }
    if (err_flag == GetSensorRegisterParam_EsfJsonValueTypeGet) {
        will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonInternalError);
        is_exit = true;
    }
    else {
        will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);
    }
    if (is_exit == true) {
        goto exit;
    }

    // For EsfJsonArrayCount()
    expect_value(__wrap_EsfJsonArrayCount, handle, json_handle);
    expect_value(__wrap_EsfJsonArrayCount, parent, child_json_val);
    will_return(__wrap_EsfJsonArrayCount, array_num);
    if ((array_num < SENSOR_REGISTER_PARAM_REGISTER_ARRAY_NUM_MIN) ||
        (SENSOR_REGISTER_PARAM_REGISTER_ARRAY_NUM_MAX < array_num)) {
        goto exit;
    }

    // For malloc()
    will_return(mock_malloc, true); // Exec parameter check
    expect_value(mock_malloc, __size, sizeof(SensorRegisterInfo) * array_num);
    if (err_flag == GetSensorRegisterParam_Malloc) {
        will_return(mock_malloc, false); // Get NULL
        goto exit;
    }
    else {
        will_return(mock_malloc, true); // Get allocate memory
    }

    // For mock operation of GetSensorRegisterArrayParam()
    if (err_flag == GetSensorRegisterParam_GetSensorRegisterArrayParam) {
        get_sensor_register_array_param_err_flag =
            GetSensorRegisterArrayParam_SysAppCmnExtractRealNumberValueAddress;
    }
    else {
        get_sensor_register_array_param_err_flag = GetSensorRegisterArrayParam_None;
    }
    GetSensorRegisterArrayParamCommon(json_handle, child_json_val, array_num, is_get_value_property,
                                      get_sensor_register_array_param_err_flag);

exit:
    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void GetReadSensorRegisterParamCommon(const char *param,
                                             GetReadSensorRegisterParamErrFlag err_flag)
{
    EsfJsonHandle json_handle = (EsfJsonHandle)0x97538642;
    EsfJsonValue parent_val = 1357;
    GetSensorRegisterParamErrFlag get_sensor_register_param_err_flag;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, json_handle);
    if (err_flag == GetReadSensorRegisterParam_EsfJsonOpen) {
        will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);
        goto exit;
    }
    else {
        will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);
    }

    // For EsfJsonDeserialize
    expect_value(__wrap_EsfJsonDeserialize, handle, json_handle);
    if (param != NULL) {
        expect_string(__wrap_EsfJsonDeserialize, str, param);
    }
    else {
        expect_value(__wrap_EsfJsonDeserialize, str, param);
    }
    will_return(__wrap_EsfJsonDeserialize, parent_val);
    if (err_flag == GetReadSensorRegisterParam_EsfJsonDeserialize) {
        will_return(__wrap_EsfJsonDeserialize, kEsfJsonInternalError);
        goto close_exit;
    }
    else {
        will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);
    }

    // mock oepration for GetSensorRegisterParam()
    if (err_flag == GetReadSensorRegisterParam_GetSensorRegisterParam) {
        get_sensor_register_param_err_flag = GetSensorRegisterParam_GetSensorRegisterArrayParam;
    }
    else {
        get_sensor_register_param_err_flag = GetSensorRegisterParam_None;
    }
    GetSensorRegisterParamCommon(json_handle, parent_val, SENSOR_REGISTER_COMMON_ARRAY_NUM, false,
                                 get_sensor_register_param_err_flag);

close_exit:
    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, json_handle);
    if (err_flag == GetReadSensorRegisterParam_EsfJsonClose) {
        will_return(__wrap_EsfJsonClose, kEsfJsonInternalError);
    }
    else {
        will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
    }

exit:
    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void GetWriteSensorRegisterParamCommon(const char *param,
                                              GetWriteSensorRegisterParamErrFlag err_flag)
{
    EsfJsonHandle json_handle = (EsfJsonHandle)0x97538642;
    EsfJsonValue parent_val = 1357;
    GetSensorRegisterParamErrFlag get_sensor_register_param_err_flag;

    // For EsfJsonOpen()
    will_return(__wrap_EsfJsonOpen, json_handle);
    if (err_flag == GetWriteSensorRegisterParam_EsfJsonOpen) {
        will_return(__wrap_EsfJsonOpen, kEsfJsonInternalError);
        goto exit;
    }
    else {
        will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);
    }

    // For EsfJsonDeserialize
    expect_value(__wrap_EsfJsonDeserialize, handle, json_handle);
    if (param != NULL) {
        expect_string(__wrap_EsfJsonDeserialize, str, param);
    }
    else {
        expect_value(__wrap_EsfJsonDeserialize, str, param);
    }
    will_return(__wrap_EsfJsonDeserialize, parent_val);
    if (err_flag == GetWriteSensorRegisterParam_EsfJsonDeserialize) {
        will_return(__wrap_EsfJsonDeserialize, kEsfJsonInternalError);
        goto close_exit;
    }
    else {
        will_return(__wrap_EsfJsonDeserialize, kEsfJsonSuccess);
    }

    // mock oepration for GetSensorRegisterParam()
    if (err_flag == GetWriteSensorRegisterParam_GetSensorRegisterParam) {
        get_sensor_register_param_err_flag = GetSensorRegisterParam_GetSensorRegisterArrayParam;
    }
    else {
        get_sensor_register_param_err_flag = GetSensorRegisterParam_None;
    }
    GetSensorRegisterParamCommon(json_handle, parent_val, SENSOR_REGISTER_COMMON_ARRAY_NUM, true,
                                 get_sensor_register_param_err_flag);

close_exit:
    // For EsfJsonClose()
    expect_value(__wrap_EsfJsonClose, handle, json_handle);
    if (err_flag == GetWriteSensorRegisterParam_EsfJsonClose) {
        will_return(__wrap_EsfJsonClose, kEsfJsonInternalError);
    }
    else {
        will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);
    }

exit:
    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void ExecReadSensorRegister8bitCommon(SensorRegisterInfo *sensor_register_info,
                                             uint32_t array_index,
                                             ExecReadSensorRegister8bitErrFlag err_flag)
{
    // For senscord_stream_get_property()
    expect_value(__wrap_senscord_stream_get_property, stream,
                 READ_SENSOR_REGISTER_COMMON_SENSCORD_STREAM);
    expect_string(__wrap_senscord_stream_get_property, property_key,
                  SENSCORD_REGISTER_ACCESS_8_PROPERTY_KEY);
    expect_value(__wrap_senscord_stream_get_property, value_size,
                 sizeof(struct senscord_register_access_8_property_t));
    expect_value(__wrap_senscord_stream_get_property, register_access_8->id,
                 SENSCORD_SENSOR_REGISTER_ID_IMX500);
    expect_value(__wrap_senscord_stream_get_property, register_access_8->address,
                 sensor_register_info->address);
    will_return(__wrap_senscord_stream_get_property, GetSensorRegisterArrayValue(1, array_index));
    if (err_flag == ExecReadSensorRegister8bit_GetProperty) {
        will_return(__wrap_senscord_stream_get_property, -1);
    }
    else {
        will_return(__wrap_senscord_stream_get_property, 0);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void ExecReadSensorRegister16bitCommon(SensorRegisterInfo *sensor_register_info,
                                              uint32_t array_index,
                                              ExecReadSensorRegister16bitErrFlag err_flag)
{
    // For senscord_stream_get_property()
    expect_value(__wrap_senscord_stream_get_property, stream,
                 READ_SENSOR_REGISTER_COMMON_SENSCORD_STREAM);
    expect_string(__wrap_senscord_stream_get_property, property_key,
                  SENSCORD_REGISTER_ACCESS_16_PROPERTY_KEY);
    expect_value(__wrap_senscord_stream_get_property, value_size,
                 sizeof(struct senscord_register_access_16_property_t));
    expect_value(__wrap_senscord_stream_get_property, register_access_16->id,
                 SENSCORD_SENSOR_REGISTER_ID_IMX500);
    expect_value(__wrap_senscord_stream_get_property, register_access_16->address,
                 sensor_register_info->address);
    will_return(__wrap_senscord_stream_get_property, GetSensorRegisterArrayValue(2, array_index));
    if (err_flag == ExecReadSensorRegister16bit_GetProperty) {
        will_return(__wrap_senscord_stream_get_property, -1);
    }
    else {
        will_return(__wrap_senscord_stream_get_property, 0);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void ExecReadSensorRegister32bitCommon(SensorRegisterInfo *sensor_register_info,
                                              uint32_t array_index,
                                              ExecReadSensorRegister32bitErrFlag err_flag)
{
    // For senscord_stream_get_property()
    expect_value(__wrap_senscord_stream_get_property, stream,
                 READ_SENSOR_REGISTER_COMMON_SENSCORD_STREAM);
    expect_string(__wrap_senscord_stream_get_property, property_key,
                  SENSCORD_REGISTER_ACCESS_32_PROPERTY_KEY);
    expect_value(__wrap_senscord_stream_get_property, value_size,
                 sizeof(struct senscord_register_access_32_property_t));
    expect_value(__wrap_senscord_stream_get_property, register_access_32->id,
                 SENSCORD_SENSOR_REGISTER_ID_IMX500);
    expect_value(__wrap_senscord_stream_get_property, register_access_32->address,
                 sensor_register_info->address);
    will_return(__wrap_senscord_stream_get_property, GetSensorRegisterArrayValue(4, array_index));
    if (err_flag == ExecReadSensorRegister32bit_GetProperty) {
        will_return(__wrap_senscord_stream_get_property, -1);
    }
    else {
        will_return(__wrap_senscord_stream_get_property, 0);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void SetCommonParamExecReadSensorRegister(SensorRegisterParam *sensor_register_param)
{
    int i;

    for (i = 0; i < sensor_register_param->num; i++) {
        sensor_register_param->info[i].address = GetSensorRegisterArrayAddress(i);
        sensor_register_param->info[i].size = GetSensorRegisterArraySize(i);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void ExecReadSensorRegisterCommon(SensorRegisterParam *sensor_register_param,
                                         ExecReadSensorRegisterErrFlag err_flag)
{
    int i;

    // For SysAppStateGetSensCordStream()
    will_return(__wrap_SysAppStateGetSensCordStream, READ_SENSOR_REGISTER_COMMON_SENSCORD_STREAM);
    if (err_flag == ExecReadSensorRegister_SysAppStateGetSensCordStream) {
        will_return(__wrap_SysAppStateGetSensCordStream, kRetFailed);
        goto exit;
    }
    else {
        will_return(__wrap_SysAppStateGetSensCordStream, kRetOk);
    }

    for (i = 0; i < sensor_register_param->num; i++) {
        switch (sensor_register_param->info[i].size) {
            case 1:
                if (err_flag == ExecReadSensorRegister_ExecReadSensorRegister8bit) {
                    ExecReadSensorRegister8bitCommon(&sensor_register_param->info[i], i,
                                                     ExecReadSensorRegister8bit_GetProperty);
                    goto exit;
                }
                else {
                    ExecReadSensorRegister8bitCommon(&sensor_register_param->info[i], i,
                                                     ExecReadSensorRegister8bit_None);
                }
                break;
            case 2:
                if (err_flag == ExecReadSensorRegister_ExecReadSensorRegister16bit) {
                    ExecReadSensorRegister16bitCommon(&sensor_register_param->info[i], i,
                                                      ExecReadSensorRegister16bit_GetProperty);
                    goto exit;
                }
                else {
                    ExecReadSensorRegister16bitCommon(&sensor_register_param->info[i], i,
                                                      ExecReadSensorRegister16bit_None);
                }
                break;
            case 4:
            default:
                if (err_flag == ExecReadSensorRegister_ExecReadSensorRegister32bit) {
                    ExecReadSensorRegister32bitCommon(&sensor_register_param->info[i], i,
                                                      ExecReadSensorRegister32bit_GetProperty);
                    goto exit;
                }
                else {
                    ExecReadSensorRegister32bitCommon(&sensor_register_param->info[i], i,
                                                      ExecReadSensorRegister32bit_None);
                }
                break;
        }
    }

exit:
    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void ExecWriteSensorRegisterEachBit(uint64_t address, uint32_t value,
                                           ExecWriteSensorRegisterBit write_bit,
                                           ExecWriteSensorRegisterEachBitErrFlag err_flag)
{
    // For senscord_stream_set_property()
    expect_value(__wrap_senscord_stream_set_property, stream,
                 WRITE_SENSOR_REGISTER_COMMON_SENSCORD_STREAM);
    if (write_bit == ExecWriteSensorRegisterBit_8bit) {
        expect_string(__wrap_senscord_stream_set_property, property_key,
                      SENSCORD_REGISTER_ACCESS_8_PROPERTY_KEY);
        expect_value(__wrap_senscord_stream_set_property, value_size,
                     sizeof(struct senscord_register_access_8_property_t));
    }
    else if (write_bit == ExecWriteSensorRegisterBit_16bit) {
        expect_string(__wrap_senscord_stream_set_property, property_key,
                      SENSCORD_REGISTER_ACCESS_16_PROPERTY_KEY);
        expect_value(__wrap_senscord_stream_set_property, value_size,
                     sizeof(struct senscord_register_access_16_property_t));
    }
    else if (write_bit == ExecWriteSensorRegisterBit_32bit) {
        expect_string(__wrap_senscord_stream_set_property, property_key,
                      SENSCORD_REGISTER_ACCESS_32_PROPERTY_KEY);
        expect_value(__wrap_senscord_stream_set_property, value_size,
                     sizeof(struct senscord_register_access_32_property_t));
    }
    else {
        // Do Nothing
    }
    expect_value(__wrap_senscord_stream_set_property, senscord_register->id,
                 SENSCORD_SENSOR_REGISTER_ID_IMX500);
    expect_value(__wrap_senscord_stream_set_property, senscord_register->address, address);
    expect_value(__wrap_senscord_stream_set_property, senscord_register->data, value);
    if (err_flag == ExecWriteSensorRegisterEachBit_SetProperty) {
        will_return(__wrap_senscord_stream_set_property, -1);
    }
    else {
        will_return(__wrap_senscord_stream_set_property, 0);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void SetCommonParamExecWriteSensorRegister(SensorRegisterParam *sensor_register_param)
{
    int i;
    uint32_t size;

    for (i = 0; i < sensor_register_param->num; i++) {
        size = GetSensorRegisterArraySize(i);
        sensor_register_param->info[i].address = GetSensorRegisterArrayAddress(i);
        sensor_register_param->info[i].size = size;
        sensor_register_param->info[i].value = GetSensorRegisterArrayValue(size, i);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void ExecWriteSensorRegisterCommon(SensorRegisterParam *sensor_register_param,
                                          ExecWriteSensorRegisterErrFlag err_flag)
{
    int i;
    ExecWriteSensorRegisterBit bit_flag;
    ExecWriteSensorRegisterEachBitErrFlag bit_err_flag;

    // For SysAppStateGetSensCordStream()
    will_return(__wrap_SysAppStateGetSensCordStream, WRITE_SENSOR_REGISTER_COMMON_SENSCORD_STREAM);
    if (err_flag == ExecWriteSensorRegister_SysAppStateGetSensCordStream) {
        will_return(__wrap_SysAppStateGetSensCordStream, kRetFailed);
        goto exit;
    }
    else {
        will_return(__wrap_SysAppStateGetSensCordStream, kRetOk);
    }

    for (i = 0; i < sensor_register_param->num; i++) {
        bit_err_flag = ExecWriteSensorRegisterEachBit_None;

        switch (sensor_register_param->info[i].size) {
            case 1:
                bit_flag = ExecWriteSensorRegisterBit_8bit;
                if (err_flag == ExecWriteSensorRegister_ExecWriteSensorRegister8bit) {
                    bit_err_flag = ExecWriteSensorRegisterEachBit_SetProperty;
                }
                break;
            case 2:
                bit_flag = ExecWriteSensorRegisterBit_16bit;
                if (err_flag == ExecWriteSensorRegister_ExecWriteSensorRegister16bit) {
                    bit_err_flag = ExecWriteSensorRegisterEachBit_SetProperty;
                }
                break;
            case 4:
            default:
                bit_flag = ExecWriteSensorRegisterBit_32bit;
                if (err_flag == ExecWriteSensorRegister_ExecWriteSensorRegister32bit) {
                    bit_err_flag = ExecWriteSensorRegisterEachBit_SetProperty;
                }
                break;
        }
        // mock oepration for ExecWriteSensorRegister
        ExecWriteSensorRegisterEachBit(sensor_register_param->info[i].address,
                                       sensor_register_param->info[i].value, bit_flag,
                                       bit_err_flag);

        if (bit_err_flag == ExecWriteSensorRegisterEachBit_SetProperty) {
            goto exit;
        }
    }

exit:
    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static bool SysAppDcmdReadSensorRegisterCommon(SYS_response_id cmd_id, const char *req_id,
                                               const char *param,
                                               SysAppDcmdReadSensorRegisterErrFlag err_flag)
{
    bool ret = true;
    DcResult dc_result = DcOk;
    SensorRegisterParam sensor_register_param = {.info = NULL};

    // mock oepration for GetReadSensorRegisterParam()
    if (err_flag == SysAppDcmdReadSensorRegister_GetReadSensorRegisterParamInvalidParam) {
        GetReadSensorRegisterParamCommon(param, GetReadSensorRegisterParam_GetSensorRegisterParam);
        dc_result = DcInvalidArgument;
        goto return_response;
    }
    else if (err_flag == SysAppDcmdReadSensorRegister_GetReadSensorRegisterParamOther) {
        GetReadSensorRegisterParamCommon(param, GetReadSensorRegisterParam_EsfJsonOpen);
        dc_result = DcInternal;
        goto return_response;
    }
    else {
        GetReadSensorRegisterParamCommon(param, GetReadSensorRegisterParam_None);
    }

    // mock oepration for ExecReadSensorRegister()
    sensor_register_param.num = SENSOR_REGISTER_COMMON_ARRAY_NUM;
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        ret = false;
        goto exit;
    }
    SetCommonParamExecReadSensorRegister(&sensor_register_param);

    if (err_flag == SysAppDcmdReadSensorRegister_ExecReadSensorRegister) {
        ExecReadSensorRegisterCommon(&sensor_register_param,
                                     ExecReadSensorRegister_ExecReadSensorRegister8bit);
        dc_result = DcInternal;
        goto return_response;
    }
    else {
        ExecReadSensorRegisterCommon(&sensor_register_param, ExecReadSensorRegister_None);
    }

    // Set read register value
    for (int i = 0; i < sensor_register_param.num; i++) {
        sensor_register_param.info[i].value =
            GetSensorRegisterArrayValue(sensor_register_param.info[i].size, i);
    }

return_response:
    // mock oepration for SendDirectCommandResponseAsync()
    s_sys_client = (struct SYS_client *)0x98765432;
    if ((err_flag != SysAppDcmdReadSensorRegister_None) &&
        (err_flag != SysAppDcmdReadSensorRegister_SendDirectCommandResponseAsync)) {
        sensor_register_param.num = 0;
    }

    if (err_flag == SysAppDcmdReadSensorRegister_SendDirectCommandResponseAsync) {
        SendDirectCommandResponse_ErrorSysSetResponseCb(s_sys_client, cmd_id, req_id, dc_result,
                                                        SetRegisterProperty,
                                                        (void *)&sensor_register_param);
    }
    else {
        SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, dc_result,
                                                   SetRegisterProperty,
                                                   (void *)&sensor_register_param);
    }

    // For free()
    if (err_flag != SysAppDcmdReadSensorRegister_GetReadSensorRegisterParamOther) {
        will_return(mock_free, false);
    }

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return ret;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static bool SysAppDcmdWriteSensorRegisterCommon(SYS_response_id cmd_id, const char *req_id,
                                                const char *param,
                                                SysAppDcmdWriteSensorRegisterErrFlag err_flag)
{
    bool ret = true;
    DcResult dc_result = DcOk;
    SensorRegisterParam sensor_register_param = {.info = NULL};

    // mock oepration for GetWriteSensorRegisterParam()
    if (err_flag == SysAppDcmdWriteSensorRegister_GetWriteSensorRegisterParamInvalidParam) {
        GetWriteSensorRegisterParamCommon(param,
                                          GetWriteSensorRegisterParam_GetSensorRegisterParam);
        dc_result = DcInvalidArgument;
        goto return_response;
    }
    else if (err_flag == SysAppDcmdWriteSensorRegister_GetWriteSensorRegisterParamOther) {
        GetWriteSensorRegisterParamCommon(param, GetWriteSensorRegisterParam_EsfJsonOpen);
        dc_result = DcInternal;
        goto return_response;
    }
    else {
        GetWriteSensorRegisterParamCommon(param, GetWriteSensorRegisterParam_None);
    }

    // mock oepration for ExecWriteSensorRegister()
    sensor_register_param.num = SENSOR_REGISTER_COMMON_ARRAY_NUM;
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        ret = false;
        goto exit;
    }
    SetCommonParamExecWriteSensorRegister(&sensor_register_param);

    if (err_flag == SysAppDcmdWriteSensorRegister_ExecWriteSensorRegister) {
        ExecWriteSensorRegisterCommon(&sensor_register_param,
                                      ExecWriteSensorRegister_ExecWriteSensorRegister8bit);
        dc_result = DcInternal;
        goto return_response;
    }
    else {
        ExecWriteSensorRegisterCommon(&sensor_register_param, ExecWriteSensorRegister_None);
    }

return_response:
    // mock oepration for SendDirectCommandResponseAsync()
    s_sys_client = (struct SYS_client *)0x98765432;
    if (err_flag == SysAppDcmdWriteSensorRegister_SendDirectCommandResponseAsync) {
        SendDirectCommandResponse_ErrorSysSetResponseCb(s_sys_client, cmd_id, req_id, dc_result,
                                                        NULL, NULL);
    }
    else {
        SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, dc_result, NULL,
                                                   NULL);
    }

    // For free()
    if (err_flag != SysAppDcmdWriteSensorRegister_GetWriteSensorRegisterParamOther) {
        will_return(mock_free, false);
    }

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return ret;
}
#endif

/*----------------------------------------------------------------------------*/

//
// SysAppDcmdInitialize()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdInitialize_FullySuccess(void **state)
{
    RetCode ret;
    struct SYS_client *expect_client = (struct SYS_client *)0x98765432;

    // Check RegisterDirectCommandCallback
    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "reboot");
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandUnimplementedCallback);
    expect_any(__wrap_SYS_register_command_cb, user);
#else
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandRebootCallback);
    expect_value(__wrap_SYS_register_command_cb, user, NULL);
#endif
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "shutdown");
    expect_any(__wrap_SYS_register_command_cb, cb);
    expect_any(__wrap_SYS_register_command_cb, user);
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "factory_reset");
    expect_any(__wrap_SYS_register_command_cb, cb);
    expect_any(__wrap_SYS_register_command_cb, user);
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "direct_get_image");
    expect_any(__wrap_SYS_register_command_cb, cb);
    expect_any(__wrap_SYS_register_command_cb, user);
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "read_sensor_register");
    expect_any(__wrap_SYS_register_command_cb, cb);
    expect_any(__wrap_SYS_register_command_cb, user);
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "write_sensor_register");
    expect_any(__wrap_SYS_register_command_cb, cb);
    expect_any(__wrap_SYS_register_command_cb, user);
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    // Exec test target
    ret = SysAppDcmdInitialize(expect_client);

    // Check return and global value
    assert_int_equal(ret, kRetOk);
    assert_int_equal(s_sys_client, expect_client);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdInitialize_ErrorEvpHandleNull(void **state)
{
    RetCode ret;
    struct SYS_client *expect_client = NULL;
    s_sys_client = (struct SYS_client *)0x20241231;

    // Exec test target
    ret = SysAppDcmdInitialize(expect_client);

    // Check return and global value
    assert_int_equal(ret, kRetFailed);
    assert_int_equal(s_sys_client, s_sys_client);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdInitialize_ErrorRegisterDirectCommandRebootCallback(void **state)
{
    RetCode ret;
    struct SYS_client *expect_client = (struct SYS_client *)0x98765432;

    // Check RegisterDirectCommandCallback
    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "reboot");
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandUnimplementedCallback);
    expect_any(__wrap_SYS_register_command_cb, user);
#else
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandRebootCallback);
    expect_value(__wrap_SYS_register_command_cb, user, NULL);
#endif
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_ERRNO);

    // Exec test target
    ret = SysAppDcmdInitialize(expect_client);

    // Check return and global value
    assert_int_equal(ret, kRetFailed);
    assert_int_equal(s_sys_client, expect_client);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdInitialize_ErrorRegisterDirectCommandShutdownCallback(void **state)
{
    RetCode ret;
    struct SYS_client *expect_client = (struct SYS_client *)0x98765432;

    // Check RegisterDirectCommandCallback
    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "reboot");
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandUnimplementedCallback);
    expect_any(__wrap_SYS_register_command_cb, user);
#else
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandRebootCallback);
    expect_value(__wrap_SYS_register_command_cb, user, NULL);
#endif
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "shutdown");
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandUnimplementedCallback);
    expect_any(__wrap_SYS_register_command_cb, user);
#else
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandShutdownCallback);
    expect_value(__wrap_SYS_register_command_cb, user, NULL);
#endif
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_ERRNO);

    // Exec test target
    ret = SysAppDcmdInitialize(expect_client);

    // Check return and global value
    assert_int_equal(ret, kRetFailed);
    assert_int_equal(s_sys_client, expect_client);

    return;
}
/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdInitialize_ErrorRegisterDirectCommandFactoryResetCallback(void **state)
{
    RetCode ret;
    struct SYS_client *expect_client = (struct SYS_client *)0x98765432;

    // Check RegisterDirectCommandCallback
    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "reboot");
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandUnimplementedCallback);
    expect_any(__wrap_SYS_register_command_cb, user);
#else
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandRebootCallback);
    expect_value(__wrap_SYS_register_command_cb, user, NULL);
#endif
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "shutdown");
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandUnimplementedCallback);
    expect_any(__wrap_SYS_register_command_cb, user);
#else
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandShutdownCallback);
    expect_value(__wrap_SYS_register_command_cb, user, NULL);
#endif
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "factory_reset");
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandUnimplementedCallback);
    expect_any(__wrap_SYS_register_command_cb, user);
#else
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandFactoryResetCallback);
    expect_value(__wrap_SYS_register_command_cb, user, NULL);
#endif
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_ERRNO);

    // Exec test target
    ret = SysAppDcmdInitialize(expect_client);

    // Check return and global value
    assert_int_equal(ret, kRetFailed);
    assert_int_equal(s_sys_client, expect_client);

    return;
}
/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdInitialize_ErrorRegisterDirectCommandDirectGetImageCallback(void **state)
{
    RetCode ret;
    struct SYS_client *expect_client = (struct SYS_client *)0x98765432;

    // Check RegisterDirectCommandCallback
    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "reboot");
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandUnimplementedCallback);
    expect_any(__wrap_SYS_register_command_cb, user);
#else
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandRebootCallback);
    expect_value(__wrap_SYS_register_command_cb, user, NULL);
#endif
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "shutdown");
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandUnimplementedCallback);
    expect_any(__wrap_SYS_register_command_cb, user);
#else
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandShutdownCallback);
    expect_value(__wrap_SYS_register_command_cb, user, NULL);
#endif
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "factory_reset");
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandUnimplementedCallback);
    expect_any(__wrap_SYS_register_command_cb, user);
#else
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandFactoryResetCallback);
    expect_value(__wrap_SYS_register_command_cb, user, NULL);
#endif
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "direct_get_image");
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    expect_any(__wrap_SYS_register_command_cb, cb);
    expect_any(__wrap_SYS_register_command_cb, user);
#else
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandDirectGetImageCallback);
    expect_value(__wrap_SYS_register_command_cb, user, NULL);
#endif
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_ERRNO);

    // Exec test target
    ret = SysAppDcmdInitialize(expect_client);

    // Check return and global value
    assert_int_equal(ret, kRetFailed);
    assert_int_equal(s_sys_client, expect_client);

    return;
}
/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdInitialize_ErrorRegisterDirectCommandReadSensorRegisterCallback(
    void **state)
{
    RetCode ret;
    struct SYS_client *expect_client = (struct SYS_client *)0x98765432;

    // Check RegisterDirectCommandCallback
    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "reboot");
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandUnimplementedCallback);
    expect_any(__wrap_SYS_register_command_cb, user);
#else
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandRebootCallback);
    expect_value(__wrap_SYS_register_command_cb, user, NULL);
#endif
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "shutdown");
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandUnimplementedCallback);
    expect_any(__wrap_SYS_register_command_cb, user);
#else
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandShutdownCallback);
    expect_value(__wrap_SYS_register_command_cb, user, NULL);
#endif
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "factory_reset");
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandUnimplementedCallback);
    expect_any(__wrap_SYS_register_command_cb, user);
#else
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandFactoryResetCallback);
    expect_value(__wrap_SYS_register_command_cb, user, NULL);
#endif
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "direct_get_image");
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    expect_any(__wrap_SYS_register_command_cb, cb);
    expect_any(__wrap_SYS_register_command_cb, user);
#else
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandDirectGetImageCallback);
    expect_value(__wrap_SYS_register_command_cb, user, NULL);
#endif
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "read_sensor_register");
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandUnimplementedCallback);
    expect_any(__wrap_SYS_register_command_cb, user);
#else
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandReadSensorRegisterCallback);
    expect_value(__wrap_SYS_register_command_cb, user, NULL);
#endif
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_ERRNO);

    // Exec test target
    ret = SysAppDcmdInitialize(s_sys_client);

    // Check return and global value
    assert_int_equal(ret, kRetFailed);
    assert_int_equal(s_sys_client, expect_client);

    return;
}
/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdInitialize_ErrorRegisterDirectCommandWriteSensorRegisterCallback(
    void **state)
{
    RetCode ret;
    struct SYS_client *expect_client = (struct SYS_client *)0x98765432;

    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "reboot");
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandUnimplementedCallback);
    expect_any(__wrap_SYS_register_command_cb, user);
#else
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandRebootCallback);
    expect_value(__wrap_SYS_register_command_cb, user, NULL);
#endif
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "shutdown");
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandUnimplementedCallback);
    expect_any(__wrap_SYS_register_command_cb, user);
#else
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandShutdownCallback);
    expect_value(__wrap_SYS_register_command_cb, user, NULL);
#endif
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "factory_reset");
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandUnimplementedCallback);
    expect_any(__wrap_SYS_register_command_cb, user);
#else
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandFactoryResetCallback);
    expect_value(__wrap_SYS_register_command_cb, user, NULL);
#endif
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "direct_get_image");
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    expect_any(__wrap_SYS_register_command_cb, cb);
    expect_any(__wrap_SYS_register_command_cb, user);
#else
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandDirectGetImageCallback);
    expect_value(__wrap_SYS_register_command_cb, user, NULL);
#endif
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "read_sensor_register");
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandUnimplementedCallback);
    expect_any(__wrap_SYS_register_command_cb, user);
#else
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandReadSensorRegisterCallback);
    expect_value(__wrap_SYS_register_command_cb, user, NULL);
#endif
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_OK);

    expect_value(__wrap_SYS_register_command_cb, c, expect_client);
    expect_string(__wrap_SYS_register_command_cb, command, "write_sensor_register");
#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandUnimplementedCallback);
    expect_any(__wrap_SYS_register_command_cb, user);
#else
    expect_value(__wrap_SYS_register_command_cb, cb, DirectCommandWriteSensorRegisterCallback);
    expect_value(__wrap_SYS_register_command_cb, user, NULL);
#endif
    will_return(__wrap_SYS_register_command_cb, SYS_RESULT_ERRNO);

    // Exec test target
    ret = SysAppDcmdInitialize(expect_client);

    // Check return and global value
    assert_int_equal(ret, kRetFailed);
    assert_int_equal(s_sys_client, expect_client);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppDcmdFinalize()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdFinalize_FullySuccess(void **state)
{
    RetCode ret;

    // Exec test target
    ret = SysAppDcmdFinalize();

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppDcmdCheckSelfTerminate()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdCheckSelfTerminate_RebootRequested(void **state)
{
    bool ret;
    TerminationReason reason;

    s_terminate_request = RebootRequested;

    // Exec test target
    ret = SysAppDcmdCheckSelfTerminate(&reason);

    // Check return and global value
    assert_int_equal(reason, s_terminate_request);
    assert_true(ret);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdCheckSelfTerminate_FactoryResetRequested(void **state)
{
    bool ret;
    TerminationReason reason;

    s_terminate_request = FactoryResetRequested;

    // Exec test target
    ret = SysAppDcmdCheckSelfTerminate(&reason);

    // Check return and global value
    assert_int_equal(reason, s_terminate_request);
    assert_true(ret);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdCheckSelfTerminate_FactoryResetButtonRequested(void **state)
{
    bool ret;
    TerminationReason reason;

    s_terminate_request = FactoryResetButtonRequested;

    // Exec test target
    ret = SysAppDcmdCheckSelfTerminate(&reason);

    // Check return and global value
    assert_int_equal(reason, s_terminate_request);
    assert_true(ret);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdCheckSelfTerminate_UnDefined(void **state)
{
    bool ret;
    TerminationReason reason;

    s_terminate_request = UnDefined;

    // Exec test target
    ret = SysAppDcmdCheckSelfTerminate(&reason);

    // Check return and global value
    assert_int_equal(reason, s_terminate_request);
    assert_false(ret);

    return;
}
/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdCheckSelfTerminate_TerminationReasonNum(void **state)
{
    bool ret;
    TerminationReason reason;

    s_terminate_request = TerminationReasonNum;

    // Exec test target
    ret = SysAppDcmdCheckSelfTerminate(&reason);

    // Check return and global value
    assert_int_equal(reason, s_terminate_request);
    assert_true(ret);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppDcmdRebootCore()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdRebootCore_FullySuccess(void **state)
{
    s_terminate_request = FactoryResetButtonRequested;

    expect_function_call(__wrap_EsfPwrMgrPrepareReboot);
    will_return(__wrap_EsfPwrMgrPrepareReboot, kEsfPwrMgrOk);

    // Exec test target
    SysAppDcmdRebootCore();

    // Check global value
    assert_int_equal(s_terminate_request, UnDefined);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdRebootCore_ErrorEsfPwrMgrPrepareReboot(void **state)
{
    s_terminate_request = FactoryResetButtonRequested;

    expect_function_call(__wrap_EsfPwrMgrPrepareReboot);
    will_return(__wrap_EsfPwrMgrPrepareReboot, kEsfPwrMgrErrorInternal);

    // Exec test target
    SysAppDcmdRebootCore();

    // Check global value
    assert_int_equal(s_terminate_request, UnDefined);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppDcmdReboot()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdReboot_FullySuccess(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // Check UtilityLog function
    CheckDcmdRebootStartedUtilityLog();

    // Check SendDirectCommandResponseSync function
    SendDirectCommandResponseSync_FullSuccess(s_sys_client, cmd_id, req_id, DcOk, NULL, NULL);

    // Exec test target
    ret = SysAppDcmdReboot(cmd_id, req_id, param);

    // Check return and global value
    assert_int_equal(s_terminate_request, RebootRequested);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdReboot_MaxResponseLogStr(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    const char *string_expect =
        "ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss"
        "sssssssssssssssssssssssssssssssssssss";
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // Check UtilityLog function
    CheckDcmdRebootStartedUtilityLog();

    // Check CheckResponseLog function
    SendDirectCommandResponseSync_CheckResponseLog(s_sys_client, cmd_id, req_id, DcOk,
                                                   string_expect);

    // Exec test target
    ret = SysAppDcmdReboot(cmd_id, req_id, param);

    // Check return and global value
    assert_int_equal(s_terminate_request, RebootRequested);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdReboot_OverResponseLogStr(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    const char *string_expect =
        "ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss"
        "ssssssssssssssssssssssssssssssssssssss";
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // Check UtilityLog function
    CheckDcmdRebootStartedUtilityLog();

    // Check CheckResponseLog function
    SendDirectCommandResponseSync_CheckResponseLog(s_sys_client, cmd_id, req_id, DcOk,
                                                   string_expect);

    // Exec test target
    ret = SysAppDcmdReboot(cmd_id, req_id, param);

    // Check return and global value
    assert_int_equal(s_terminate_request, RebootRequested);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdReboot_ErrorEsfJsonOpen(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    const char *string_expect = "string_serialize_value";
    const char *string_expect_key = "res_info";
    int process_event_count = 5;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // Check UtilityLog function
    CheckDcmdRebootStartedUtilityLog();

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonHandleError);

    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, string_expect_key);
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, parent_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, NULL);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // Check response strdup
    will_return(mock_strdup, true);
    will_return(mock_strdup, true);
    expect_value(mock_strdup, __ptr, string_expect);

    // Check dcres_ctx malloc
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(DcResponseContext));

    expect_value(__wrap_SYS_set_response_cb, c, s_sys_client);
    expect_value(__wrap_SYS_set_response_cb, id, cmd_id);
    expect_string(__wrap_SYS_set_response_cb, response, string_expect);
    expect_value(__wrap_SYS_set_response_cb, status, SYS_RESPONSE_STATUS_OK);
    expect_value(__wrap_SYS_set_response_cb, cb, ResponseSendCompleteCallback);
    expect_not_value(__wrap_SYS_set_response_cb, user, NULL);
    will_return(__wrap_SYS_set_response_cb, SYS_RESULT_OK);
    will_return(__wrap_SYS_set_response_cb, process_event_count);

    for (int i = 0; i <= process_event_count; i++) {
        expect_value(__wrap_SYS_process_event, c, s_sys_client);
        expect_value(__wrap_SYS_process_event, ms, 0);
        will_return(__wrap_SYS_process_event, SYS_RESULT_OK);
    }

    // For free() of response
    will_return(mock_free, false); // Not check parameter

    // For free() of struct dcres_ctx
    will_return(mock_free, false); // Not check parameter

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppDcmdReboot(cmd_id, req_id, param);

    // Check return and global value
    assert_int_equal(s_terminate_request, RebootRequested);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdReboot_ErrorEsfJsonObjectInit(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    const char *string_expect = "string_serialize_value";
    const char *string_expect_key = "res_info";
    int process_event_count = 5;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // Check UtilityLog function
    CheckDcmdRebootStartedUtilityLog();

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonHandleError);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, string_expect_key);
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, parent_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, NULL);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // Check response strdup
    will_return(mock_strdup, true);
    will_return(mock_strdup, true);
    expect_value(mock_strdup, __ptr, string_expect);

    // Check dcres_ctx malloc
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(DcResponseContext));

    expect_value(__wrap_SYS_set_response_cb, c, s_sys_client);
    expect_value(__wrap_SYS_set_response_cb, id, cmd_id);
    expect_string(__wrap_SYS_set_response_cb, response, string_expect);
    expect_value(__wrap_SYS_set_response_cb, status, SYS_RESPONSE_STATUS_OK);
    expect_value(__wrap_SYS_set_response_cb, cb, ResponseSendCompleteCallback);
    expect_not_value(__wrap_SYS_set_response_cb, user, NULL);
    will_return(__wrap_SYS_set_response_cb, SYS_RESULT_OK);
    will_return(__wrap_SYS_set_response_cb, process_event_count);

    for (int i = 0; i <= process_event_count; i++) {
        expect_value(__wrap_SYS_process_event, c, s_sys_client);
        expect_value(__wrap_SYS_process_event, ms, 0);
        will_return(__wrap_SYS_process_event, SYS_RESULT_OK);
    }

    // For free() of response
    will_return(mock_free, false); // Not check parameter

    // For free() of struct dcres_ctx
    will_return(mock_free, false); // Not check parameter

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppDcmdReboot(cmd_id, req_id, param);

    // Check return and global value
    assert_int_equal(s_terminate_request, RebootRequested);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdReboot_ErrorSysAppCmnSetObjectValue(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    const char *string_expect = "string_serialize_value";
    const char *string_expect_key = "res_info";
    int process_event_count = 5;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // Check UtilityLog function
    CheckDcmdRebootStartedUtilityLog();

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, string_expect_key);
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetApiCallError);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, parent_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, NULL);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // Check response strdup
    will_return(mock_strdup, true);
    will_return(mock_strdup, true);
    expect_value(mock_strdup, __ptr, string_expect);

    // Check dcres_ctx malloc
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(DcResponseContext));

    expect_value(__wrap_SYS_set_response_cb, c, s_sys_client);
    expect_value(__wrap_SYS_set_response_cb, id, cmd_id);
    expect_string(__wrap_SYS_set_response_cb, response, string_expect);
    expect_value(__wrap_SYS_set_response_cb, status, SYS_RESPONSE_STATUS_OK);
    expect_value(__wrap_SYS_set_response_cb, cb, ResponseSendCompleteCallback);
    expect_not_value(__wrap_SYS_set_response_cb, user, NULL);
    will_return(__wrap_SYS_set_response_cb, SYS_RESULT_OK);
    will_return(__wrap_SYS_set_response_cb, process_event_count);

    for (int i = 0; i <= process_event_count; i++) {
        expect_value(__wrap_SYS_process_event, c, s_sys_client);
        expect_value(__wrap_SYS_process_event, ms, 0);
        will_return(__wrap_SYS_process_event, SYS_RESULT_OK);
    }

    // For free() of response
    will_return(mock_free, false); // Not check parameter

    // For free() of struct dcres_ctx
    will_return(mock_free, false); // Not check parameter

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppDcmdReboot(cmd_id, req_id, param);

    // Check return and global value
    assert_int_equal(s_terminate_request, RebootRequested);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdReboot_ErrorEsfJsonSerialize(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    const char *string_expect = "string_serialize_value";
    const char *string_expect_key = "res_info";
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // Check UtilityLog function
    CheckDcmdRebootStartedUtilityLog();

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, string_expect_key);
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, parent_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, NULL);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonInvalidArgument);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppDcmdReboot(cmd_id, req_id, param);

    // Check return and global value
    assert_int_equal(s_terminate_request, RebootRequested);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdReboot_ErrorEsfJsonSerializeNull(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    const char *string_expect = NULL;
    const char *string_expect_key = "res_info";
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // Check UtilityLog function
    CheckDcmdRebootStartedUtilityLog();

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, string_expect_key);
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, parent_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, NULL);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppDcmdReboot(cmd_id, req_id, param);

    // Check return and global value
    assert_int_equal(s_terminate_request, RebootRequested);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdReboot_ErrorStrdup(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    const char *string_expect = "string_serialize_value";
    const char *string_expect_key = "res_info";
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // Check UtilityLog function
    CheckDcmdRebootStartedUtilityLog();

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, string_expect_key);
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, parent_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, NULL);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // Check response strdup
    will_return(mock_strdup, true);
    will_return(mock_strdup, false);
    expect_value(mock_strdup, __ptr, string_expect);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppDcmdReboot(cmd_id, req_id, param);

    // Check return and global value
    assert_int_equal(s_terminate_request, RebootRequested);
    assert_int_equal(ret, kRetMemoryError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdReboot_ErrorMalloc(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    const char *string_expect = "string_serialize_value";
    const char *string_expect_key = "res_info";
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // Check UtilityLog function
    CheckDcmdRebootStartedUtilityLog();

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, string_expect_key);
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, parent_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, NULL);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // Check response strdup
    will_return(mock_strdup, true);
    will_return(mock_strdup, true);
    expect_value(mock_strdup, __ptr, string_expect);

    // Check dcres_ctx malloc
    will_return(mock_malloc, true);
    will_return(mock_malloc, false);
    expect_value(mock_malloc, __size, sizeof(DcResponseContext));

    // For free() of response
    will_return(mock_free, false); // Not check parameter

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppDcmdReboot(cmd_id, req_id, param);

    // Check return and global value
    assert_int_equal(s_terminate_request, RebootRequested);
    assert_int_equal(ret, kRetMemoryError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdReboot_ErrorSysSetResponseCb(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // Check UtilityLog function
    CheckDcmdRebootStartedUtilityLog();

    // Check SYS_set_response_cb Error case
    SendDirectCommandResponse_ErrorSysSetResponseCb(s_sys_client, cmd_id, req_id, DcOk, NULL, NULL);

    // Exec test target
    ret = SysAppDcmdReboot(cmd_id, req_id, param);

    // Check return and global value
    assert_int_equal(s_terminate_request, RebootRequested);
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdReboot_ErrorSysProcessEvent(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    const char *string_expect = "string_serialize_value";
    const char *string_expect_key = "res_info";
    int process_event_count = 1;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // Check UtilityLog function
    CheckDcmdRebootStartedUtilityLog();

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, string_expect_key);
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, parent_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, NULL);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // Check response strdup
    will_return(mock_strdup, true);
    will_return(mock_strdup, true);
    expect_value(mock_strdup, __ptr, string_expect);

    // Check dcres_ctx malloc
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(DcResponseContext));

    expect_value(__wrap_SYS_set_response_cb, c, s_sys_client);
    expect_value(__wrap_SYS_set_response_cb, id, cmd_id);
    expect_string(__wrap_SYS_set_response_cb, response, string_expect);
    expect_value(__wrap_SYS_set_response_cb, status, SYS_RESPONSE_STATUS_OK);
    expect_value(__wrap_SYS_set_response_cb, cb, ResponseSendCompleteCallback);
    expect_not_value(__wrap_SYS_set_response_cb, user, NULL);
    will_return(__wrap_SYS_set_response_cb, SYS_RESULT_OK);
    will_return(__wrap_SYS_set_response_cb, process_event_count);

    expect_value(__wrap_SYS_process_event, c, s_sys_client);
    expect_value(__wrap_SYS_process_event, ms, 0);
    will_return(__wrap_SYS_process_event, SYS_RESULT_SHOULD_EXIT);

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    ret = SysAppDcmdReboot(cmd_id, req_id, param);

    // Check return and global value
    assert_int_equal(s_terminate_request, RebootRequested);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdReboot_ErrorEsfJsonClose(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    const char *string_expect = "string_serialize_value";
    const char *string_expect_key = "res_info";
    int process_event_count = 5;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // Check UtilityLog function
    CheckDcmdRebootStartedUtilityLog();

    will_return(__wrap_EsfJsonOpen, handle_val);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, parent_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, string_expect_key);
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, parent_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, NULL);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 0);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "ok");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, handle_val);
    expect_value(__wrap_EsfJsonSerialize, value, parent_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // Check response strdup
    will_return(mock_strdup, true);
    will_return(mock_strdup, true);
    expect_value(mock_strdup, __ptr, string_expect);

    // Check dcres_ctx malloc
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    expect_value(mock_malloc, __size, sizeof(DcResponseContext));

    expect_value(__wrap_SYS_set_response_cb, c, s_sys_client);
    expect_value(__wrap_SYS_set_response_cb, id, cmd_id);
    expect_string(__wrap_SYS_set_response_cb, response, string_expect);
    expect_value(__wrap_SYS_set_response_cb, status, SYS_RESPONSE_STATUS_OK);
    expect_value(__wrap_SYS_set_response_cb, cb, ResponseSendCompleteCallback);
    expect_not_value(__wrap_SYS_set_response_cb, user, NULL);
    will_return(__wrap_SYS_set_response_cb, SYS_RESULT_OK);
    will_return(__wrap_SYS_set_response_cb, process_event_count);

    for (int i = 0; i <= process_event_count; i++) {
        expect_value(__wrap_SYS_process_event, c, s_sys_client);
        expect_value(__wrap_SYS_process_event, ms, 0);
        will_return(__wrap_SYS_process_event, SYS_RESULT_OK);
    }

    // For free() of response
    will_return(mock_free, false); // Not check parameter

    // For free() of struct dcres_ctx
    will_return(mock_free, false); // Not check parameter

    expect_value(__wrap_EsfJsonClose, handle, handle_val);
    will_return(__wrap_EsfJsonClose, kEsfJsonHandleError);

    // Exec test target
    ret = SysAppDcmdReboot(cmd_id, req_id, param);

    // Check return and global value
    assert_int_equal(s_terminate_request, RebootRequested);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppDcmdShutdown()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdShutdown_FullySuccess(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check SendDirectCommandResponseSync function
    SendDirectCommandResponseSync_FullSuccess(s_sys_client, cmd_id, req_id, DcUnimplemented, NULL,
                                              NULL);

    // Exec test target
    ret = SysAppDcmdShutdown(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdShutdown_ErrorSysSetResponseCb(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check SYS_set_response_cb Error case
    SendDirectCommandResponse_ErrorSysSetResponseCb(s_sys_client, cmd_id, req_id, DcUnimplemented,
                                                    NULL, NULL);

    // Exec test target
    ret = SysAppDcmdShutdown(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppDcmdFactoryResetCore()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdFactoryResetCore_FullySuccess(void **state)
{
    s_terminate_request = RebootRequested;

    expect_value(__wrap_EsfFwMgrStartFactoryReset, cause, kEsfFwMgrResetCauseCommand);
    will_return(__wrap_EsfFwMgrStartFactoryReset, kEsfFwMgrResultOk);

    // Exec test target
    SysAppDcmdFactoryResetCore();

    // Check global value
    assert_int_equal(s_terminate_request, UnDefined);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdFactoryResetCore_ErrorEsfFwMgrStartFactoryReset(void **state)
{
    s_terminate_request = RebootRequested;

    expect_value(__wrap_EsfFwMgrStartFactoryReset, cause, kEsfFwMgrResetCauseCommand);
    will_return(__wrap_EsfFwMgrStartFactoryReset, kEsfFwMgrResultInternal);

    // Exec test target
    SysAppDcmdFactoryResetCore();

    // Check global value
    assert_int_equal(s_terminate_request, UnDefined);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppDcmdFactoryReset()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdFactoryReset_FullySuccess(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // Check SendDirectCommandResponseSync function
    SendDirectCommandResponseSync_FullSuccess(s_sys_client, cmd_id, req_id, DcOk, NULL, NULL);

    // Check UtilityLog function
    CheckDcmdFactoryResetFromConsoleStartedUtilityLog();

    expect_function_call(__wrap_EVP_undeployModules);
    will_return(__wrap_EVP_undeployModules, 1);

    // Exec test target
    ret = SysAppDcmdFactoryReset(cmd_id, req_id, param);

    // Check return and global value
    assert_int_equal(s_terminate_request, FactoryResetRequested);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdFactoryReset_ErrorSysSetResponseCb(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // Check SYS_set_response_cb Error case
    SendDirectCommandResponse_ErrorSysSetResponseCb(s_sys_client, cmd_id, req_id, DcOk, NULL, NULL);

    // Check UtilityLog function
    CheckDcmdFactoryResetFromConsoleStartedUtilityLog();

    expect_function_call(__wrap_EVP_undeployModules);
    will_return(__wrap_EVP_undeployModules, 1);

    // Exec test target
    ret = SysAppDcmdFactoryReset(cmd_id, req_id, param);

    // Check return and global value
    assert_int_equal(s_terminate_request, FactoryResetRequested);
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdFactoryReset_ErrorEvpUndeployModules(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // Check SendDirectCommandResponseSync function
    SendDirectCommandResponseSync_FullSuccess(s_sys_client, cmd_id, req_id, DcOk, NULL, NULL);

    // Check UtilityLog function
    CheckDcmdFactoryResetFromConsoleStartedUtilityLog();

    expect_function_call(__wrap_EVP_undeployModules);
    will_return(__wrap_EVP_undeployModules, 0);

    // Exec test target
    ret = SysAppDcmdFactoryReset(cmd_id, req_id, param);

    // Check return and global value
    assert_int_equal(s_terminate_request, FactoryResetRequested);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppDcmdDirectGetImage()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorGetDirectGetImageParamsEsfJsonOpen(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_EsfJsonOpen);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);
    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorGetDirectGetImageParamsEsfJsonDeserialize(
    void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_EsfJsonDeserialize);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);
    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_GetDirectGetImageParamsNetworkIdMaxOver(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(
        param, GetDirectGetImageParams_SysAppCmnExtractStringValueNetworkIdMaxOver);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInvalidArgument,
                                               SetImageProperty, NULL);
    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_GetDirectGetImageParamsNetworkIdInvalidKey(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(
        param, GetDirectGetImageParams_SysAppCmnExtractStringValueNetworkIdInvalidKey);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInvalidArgument,
                                               SetImageProperty, NULL);
    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorGetOneFrameSysAppStateGetSensCordId(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_SysAppStateGetSensCordId);

    // Check UtilityLog function
    CheckDcmdDirectGetImageSensorErrorUtilityLog();

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);
    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorGetOneFrameSysAppStateGetSensCordStream(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_SysAppStateGetSensCordStream);

    // Check UtilityLog function
    CheckDcmdDirectGetImageSensorErrorUtilityLog();

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);
    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorGetOneFrameSenscordStreamSetPropertyAiModel(
    void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_SenscordStreamSetPropertyAiModel);

    // Check UtilityLog function
    CheckDcmdDirectGetImageSensorErrorUtilityLog();

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);
    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorGetOneFrameSenscordStreamSetPropertyInputData(
    void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_SenscordStreamSetPropertyInputData);

    // Check UtilityLog function
    CheckDcmdDirectGetImageSensorErrorUtilityLog();

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);
    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorGetOneFrameSenscordStreamSetPropertyImageProp(
    void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_SenscordStreamSetPropertyImageProp);

    // Check UtilityLog function
    CheckDcmdDirectGetImageSensorErrorUtilityLog();

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);
    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorGetOneFrameSenscordStreamStart(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_SenscordStreamStart);

    // Check UtilityLog function
    CheckDcmdDirectGetImageSensorErrorUtilityLog();

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);
    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorGetOneFrameSenscordStreamGetFrame(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_SenscordStreamGetFrame);

    // Check UtilityLog function
    CheckDcmdDirectGetImageSensorErrorUtilityLog();

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);
    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorGetOneFrameSenscordFrameGetChannelFromChannelId(
    void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_SenscordFrameGetChannelFromChannelId);

    // Check UtilityLog function
    CheckDcmdDirectGetImageSensorErrorUtilityLog();

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);
    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorGetOneFrameSenscordChannelGetRawData(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_SenscordChannelGetRawData);

    // Check UtilityLog function
    CheckDcmdDirectGetImageSensorErrorUtilityLog();

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);
    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_FullySuccess(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    EsfMemoryManagerHandle expect_b64_buf_handle = (EsfMemoryManagerHandle)0x13579000;
    EsfMemoryManagerHandle memmgr_handle_json = (EsfMemoryManagerHandle)0x98765432;
    uint32_t expect_b64_size = 4646;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_None);

    // Check EncodeToJpeg and EncodeToBase64 (with handle)
    Execute_EncodePhaseWithHandle(expect_b64_buf_handle, kJpegInputRgbPlanar_8, expect_b64_size);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccessHandle(cmd_id, DcOk, SetImagePropertyHandle,
                                                     (void *)(uintptr_t)expect_b64_buf_handle,
                                                     expect_b64_size, memmgr_handle_json);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx
    ExecSysProcessEventForMemoryFreeHandle(memmgr_handle_json);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorSysSetResponseCb(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    EsfMemoryManagerHandle expect_b64_buf_handle = (EsfMemoryManagerHandle)0x13579000;
    EsfMemoryManagerHandle memmgr_handle_json = (EsfMemoryManagerHandle)0x98765432;
    uint32_t expect_b64_size = 4646;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_None);

    // Check EncodeToJpeg and EncodeToBase64 (with handle)
    Execute_EncodePhaseWithHandle(expect_b64_buf_handle, kJpegInputRgbPlanar_8, expect_b64_size);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_ErrorSysSetResponseCbHandle(
        cmd_id, DcOk, SetImagePropertyHandle, (void *)(uintptr_t)expect_b64_buf_handle,
        expect_b64_size, memmgr_handle_json);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_GetDirectGetImageParamsNetworkIdNoKey(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    EsfMemoryManagerHandle expect_b64_buf_handle = (EsfMemoryManagerHandle)0x13579000;
    EsfMemoryManagerHandle memmgr_handle_json = (EsfMemoryManagerHandle)0x98765432;
    uint32_t expect_b64_size = 4646;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(
        param, GetDirectGetImageParams_SysAppCmnExtractStringValueNetworkIdNokey);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_SenscordStreamSetPropertyAiModelCheckDefault);

    // Check EncodeToJpeg and EncodeToBase64 (with handle)
    Execute_EncodePhaseWithHandle(expect_b64_buf_handle, kJpegInputRgbPlanar_8, expect_b64_size);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccessHandle(cmd_id, DcOk, SetImagePropertyHandle,
                                                     (void *)(uintptr_t)expect_b64_buf_handle,
                                                     expect_b64_size, memmgr_handle_json);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx
    ExecSysProcessEventForMemoryFreeHandle(memmgr_handle_json);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_GetDirectGetImageParamsNetworkIdNullStr(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    EsfMemoryManagerHandle expect_b64_buf_handle = (EsfMemoryManagerHandle)0x13579000;
    EsfMemoryManagerHandle memmgr_handle_json = (EsfMemoryManagerHandle)0x98765432;
    uint32_t expect_b64_size = 4646;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(
        param, GetDirectGetImageParams_SysAppCmnExtractStringValueNetworkIdNullStr);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_SenscordStreamSetPropertyAiModelCheckDefault);

    // Check EncodeToJpeg and EncodeToBase64 (with handle)
    Execute_EncodePhaseWithHandle(expect_b64_buf_handle, kJpegInputRgbPlanar_8, expect_b64_size);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccessHandle(cmd_id, DcOk, SetImagePropertyHandle,
                                                     (void *)(uintptr_t)expect_b64_buf_handle,
                                                     expect_b64_size, memmgr_handle_json);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx
    ExecSysProcessEventForMemoryFreeHandle(memmgr_handle_json);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_GetDirectGetImageParamsNetworkIdMax(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    EsfMemoryManagerHandle expect_b64_buf_handle = (EsfMemoryManagerHandle)0x13579000;
    EsfMemoryManagerHandle memmgr_handle_json = (EsfMemoryManagerHandle)0x98765432;
    uint32_t expect_b64_size = 4646;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(
        param, GetDirectGetImageParams_SysAppCmnExtractStringValueNetworkIdMax);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_SenscordStreamSetPropertyAiModelCheckMax);

    // Check EncodeToJpeg and EncodeToBase64 (with handle)
    Execute_EncodePhaseWithHandle(expect_b64_buf_handle, kJpegInputRgbPlanar_8, expect_b64_size);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccessHandle(cmd_id, DcOk, SetImagePropertyHandle,
                                                     (void *)(uintptr_t)expect_b64_buf_handle,
                                                     expect_b64_size, memmgr_handle_json);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx
    ExecSysProcessEventForMemoryFreeHandle(memmgr_handle_json);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorGetDirectGetImageParamsEsfJsonClose(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    EsfMemoryManagerHandle expect_b64_buf_handle = (EsfMemoryManagerHandle)0x13579000;
    EsfMemoryManagerHandle memmgr_handle_json = (EsfMemoryManagerHandle)0x98765432;
    uint32_t expect_b64_size = 4646;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_EsfJsonClose);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_None);

    // Check EncodeToJpeg and EncodeToBase64 (with handle)
    Execute_EncodePhaseWithHandle(expect_b64_buf_handle, kJpegInputRgbPlanar_8, expect_b64_size);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccessHandle(cmd_id, DcOk, SetImagePropertyHandle,
                                                     (void *)(uintptr_t)expect_b64_buf_handle,
                                                     expect_b64_size, memmgr_handle_json);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx
    ExecSysProcessEventForMemoryFreeHandle(memmgr_handle_json);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorGetOneFrameGetFormatOfImage(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    EsfMemoryManagerHandle expect_b64_buf_handle = (EsfMemoryManagerHandle)0x13579000;
    EsfMemoryManagerHandle memmgr_handle_json = (EsfMemoryManagerHandle)0x98765432;
    uint32_t expect_b64_size = 4646;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_GetFormatOfImage);

    // Check EncodeToJpeg and EncodeToBase64 (with handle)
    Execute_EncodePhaseWithHandle(expect_b64_buf_handle, kJpegInputGray_8, expect_b64_size);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccessHandle(cmd_id, DcOk, SetImagePropertyHandle,
                                                     (void *)(uintptr_t)expect_b64_buf_handle,
                                                     expect_b64_size, memmgr_handle_json);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx
    ExecSysProcessEventForMemoryFreeHandle(memmgr_handle_json);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorAllocateAndFopenMemoryManagerHandleForEncodeToJpeg(
    void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    EsfMemoryManagerHandle expect_jpeg_buf_handle = (EsfMemoryManagerHandle)0x24680000;

    const uint32_t jpeg_buf_size = DC_DIRECT_GET_IMAGE_MAX_SIZE * 3 / 4;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_None);

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_jpeg_buf_handle, jpeg_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_Allocate);

    // Check ReleaseOneFrame function
    Execute_ReleaseOneFrame(ReleaseOneFrame_None);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorEncodeToJpegEsfCodecJpegEncodeBuffSizeMaxOver(
    void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    EsfMemoryManagerHandle expect_jpeg_buf_handle = (EsfMemoryManagerHandle)0x24680000;
    EsfMemoryManagerHandle expect_b64_buf_handle = (EsfMemoryManagerHandle)0x13579000;
    EsfMemoryManagerHandle memmgr_handle_json = (EsfMemoryManagerHandle)0x98765432;

    int32_t expect_jpeg_size = (DC_DIRECT_GET_IMAGE_MAX_SIZE * 3 / 4) + 1; // OverSize
    int expect_quality = 80;
    uint32_t expect_b64_buf_size = 6464;
    const uint32_t jpeg_buf_size = DC_DIRECT_GET_IMAGE_MAX_SIZE * 3 / 4;
    uint32_t expect_b64_size = 4646;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_None);

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_jpeg_buf_handle, jpeg_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    // 1st jpeg size over
    // 2nd success
    for (int i = 0; i < 2; i++) {
        // Check EsfCodecJpegEncodeHandle function
        Execute_EsfCodecJpegEncodeHandle(expect_jpeg_buf_handle, kJpegInputRgbPlanar_8,
                                         expect_quality, expect_jpeg_size, JpegEncodeHandle_None);

        // Only 1st, reduce size and quality.
        // Because jpeg_size is not to equal to the expected value in next tests.
        if (i == 0) {
            expect_jpeg_size /= 2;
            expect_quality /= 2;
        }
    }

    expect_value(__wrap_EsfCodecBase64GetEncodeSize, in_size, expect_jpeg_size);
    will_return(__wrap_EsfCodecBase64GetEncodeSize, expect_b64_buf_size);

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_b64_buf_handle, expect_b64_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    // Check EsfCodecBase64EncodeHandle function
    Execute_EsfCodecBase64EncodeHandle(expect_jpeg_size, kEsfCodecBase64ResultSuccess,
                                       expect_jpeg_buf_handle, expect_b64_buf_handle,
                                       expect_b64_size);

    // FcloseAndFreeMemoryManagerHandle()
    FcloseAndFreeMemoryManagerHandleCommon(expect_jpeg_buf_handle,
                                           FcloseAndFreeMemoryManagerHandle_None);

    // Check ReleaseOneFrame function
    Execute_ReleaseOneFrame(ReleaseOneFrame_None);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccessHandle(cmd_id, DcOk, SetImagePropertyHandle,
                                                     (void *)(uintptr_t)expect_b64_buf_handle,
                                                     expect_b64_size, memmgr_handle_json);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx
    ExecSysProcessEventForMemoryFreeHandle(memmgr_handle_json);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_FullySuccessEncodeToJpegEsfCodecJpegEncodeBuffSizeMax(
    void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    EsfMemoryManagerHandle expect_jpeg_buf_handle = (EsfMemoryManagerHandle)0x24680000;
    EsfMemoryManagerHandle expect_b64_buf_handle = (EsfMemoryManagerHandle)0x13579000;
    EsfMemoryManagerHandle memmgr_handle_json = (EsfMemoryManagerHandle)0x98765432;

    int32_t expect_jpeg_size = (DC_DIRECT_GET_IMAGE_MAX_SIZE * 3 / 4); // MaxSize
    int expect_quality = 80;
    uint32_t expect_b64_buf_size = 6464;
    const uint32_t jpeg_buf_size = DC_DIRECT_GET_IMAGE_MAX_SIZE * 3 / 4;
    uint32_t expect_b64_size = 4646;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_None);

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_jpeg_buf_handle, jpeg_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    // Check EsfCodecJpegEncodeHandle function
    Execute_EsfCodecJpegEncodeHandle(expect_jpeg_buf_handle, kJpegInputRgbPlanar_8, expect_quality,
                                     expect_jpeg_size, JpegEncodeHandle_None);

    expect_value(__wrap_EsfCodecBase64GetEncodeSize, in_size, expect_jpeg_size);
    will_return(__wrap_EsfCodecBase64GetEncodeSize, expect_b64_buf_size);

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_b64_buf_handle, expect_b64_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    // Check EsfCodecBase64EncodeHandle function
    Execute_EsfCodecBase64EncodeHandle(expect_jpeg_size, kEsfCodecBase64ResultSuccess,
                                       expect_jpeg_buf_handle, expect_b64_buf_handle,
                                       expect_b64_size);

    // FcloseAndFreeMemoryManagerHandle()
    FcloseAndFreeMemoryManagerHandleCommon(expect_jpeg_buf_handle,
                                           FcloseAndFreeMemoryManagerHandle_None);

    // Check ReleaseOneFrame function
    Execute_ReleaseOneFrame(ReleaseOneFrame_None);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccessHandle(cmd_id, DcOk, SetImagePropertyHandle,
                                                     (void *)(uintptr_t)expect_b64_buf_handle,
                                                     expect_b64_size, memmgr_handle_json);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx
    ExecSysProcessEventForMemoryFreeHandle(memmgr_handle_json);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorEncodeToJpegEsfCodecJpegEncodeBufferFull(
    void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    EsfMemoryManagerHandle expect_jpeg_buf_handle = (EsfMemoryManagerHandle)0x24680000;
    EsfMemoryManagerHandle expect_b64_buf_handle = (EsfMemoryManagerHandle)0x13579000;
    EsfMemoryManagerHandle memmgr_handle_json = (EsfMemoryManagerHandle)0x98765432;

    int32_t expect_jpeg_size = 5566;
    int expect_quality = 80;
    uint32_t expect_b64_buf_size = 6464;
    const uint32_t jpeg_buf_size = DC_DIRECT_GET_IMAGE_MAX_SIZE * 3 / 4;
    uint32_t expect_b64_size = 4646;
    JpegEncodeHandleErrorFlag err_flag;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_None);

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_jpeg_buf_handle, jpeg_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    // 1st JpegOutput BufferFull Error
    // 2nd success
    for (int i = 0; i < 2; i++) {
        if (i == 0) {
            err_flag = JpegEncodeHandle_JpegOutputBufferFull;
        }
        else {
            err_flag = JpegEncodeHandle_None;
        }

        // Check EsfCodecJpegEncodeHandle function
        Execute_EsfCodecJpegEncodeHandle(expect_jpeg_buf_handle, kJpegInputRgbPlanar_8,
                                         expect_quality, expect_jpeg_size, err_flag);

        expect_quality /= 2;
    }

    expect_value(__wrap_EsfCodecBase64GetEncodeSize, in_size, expect_jpeg_size);
    will_return(__wrap_EsfCodecBase64GetEncodeSize, expect_b64_buf_size);

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_b64_buf_handle, expect_b64_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    // Check EsfCodecBase64EncodeHandle function
    Execute_EsfCodecBase64EncodeHandle(expect_jpeg_size, kEsfCodecBase64ResultSuccess,
                                       expect_jpeg_buf_handle, expect_b64_buf_handle,
                                       expect_b64_size);

    // FcloseAndFreeMemoryManagerHandle()
    FcloseAndFreeMemoryManagerHandleCommon(expect_jpeg_buf_handle,
                                           FcloseAndFreeMemoryManagerHandle_None);

    // Check ReleaseOneFrame function
    Execute_ReleaseOneFrame(ReleaseOneFrame_None);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccessHandle(cmd_id, DcOk, SetImagePropertyHandle,
                                                     (void *)(uintptr_t)expect_b64_buf_handle,
                                                     expect_b64_size, memmgr_handle_json);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx
    ExecSysProcessEventForMemoryFreeHandle(memmgr_handle_json);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorEncodeToJpegEsfCodecJpegEncodeRetryOver(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    EsfMemoryManagerHandle expect_jpeg_buf_handle = (EsfMemoryManagerHandle)0x24680000;

    int32_t expect_jpeg_size = (DC_DIRECT_GET_IMAGE_MAX_SIZE * 3 / 4) + 1; // OverSize
    int expect_quality = 80;
    const uint32_t jpeg_buf_size = DC_DIRECT_GET_IMAGE_MAX_SIZE * 3 / 4;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_None);

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_jpeg_buf_handle, jpeg_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    for (; expect_quality >= 0; expect_quality /= 2) {
        // Check EsfCodecJpegEncodeHandle function
        Execute_EsfCodecJpegEncodeHandle(expect_jpeg_buf_handle, kJpegInputRgbPlanar_8,
                                         expect_quality, expect_jpeg_size, JpegEncodeHandle_None);

        if (expect_quality == 0) {
            break;
        }
    }

    // Check ReleaseOneFrame function
    Execute_ReleaseOneFrame(ReleaseOneFrame_None);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorEncodeToJpegEsfCodecJpegEncodeOther(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    EsfMemoryManagerHandle expect_jpeg_buf_handle = (EsfMemoryManagerHandle)0x24680000;

    int32_t expect_jpeg_size = 5566;
    int expect_quality = 80;
    const uint32_t jpeg_buf_size = DC_DIRECT_GET_IMAGE_MAX_SIZE * 3 / 4;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_None);

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_jpeg_buf_handle, jpeg_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    // Check EsfCodecJpegEncodeHandle function
    Execute_EsfCodecJpegEncodeHandle(expect_jpeg_buf_handle, kJpegInputRgbPlanar_8, expect_quality,
                                     expect_jpeg_size, JpegEncodeHandle_JpegOutputOther);

    // Check ReleaseOneFrame function
    Execute_ReleaseOneFrame(ReleaseOneFrame_None);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_FullySuccessEncodeToJpegErrorEsfMemoryManagerFseek(
    void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    EsfMemoryManagerHandle expect_jpeg_buf_handle = (EsfMemoryManagerHandle)0x24680000;
    EsfMemoryManagerHandle expect_b64_buf_handle = (EsfMemoryManagerHandle)0x13579000;
    EsfMemoryManagerHandle memmgr_handle_json = (EsfMemoryManagerHandle)0x98765432;

    int32_t expect_jpeg_size = 5566;
    int expect_quality = 80;
    uint32_t expect_b64_buf_size = 6464;
    const uint32_t jpeg_buf_size = DC_DIRECT_GET_IMAGE_MAX_SIZE * 3 / 4;
    uint32_t expect_b64_size = 4646;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_None);

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_jpeg_buf_handle, jpeg_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    // Check EsfCodecJpegEncodeHandle function
    Execute_EsfCodecJpegEncodeHandle(expect_jpeg_buf_handle, kJpegInputRgbPlanar_8, expect_quality,
                                     expect_jpeg_size, JpegEncodeHandle_None);

    expect_value(__wrap_EsfCodecBase64GetEncodeSize, in_size, expect_jpeg_size);
    will_return(__wrap_EsfCodecBase64GetEncodeSize, expect_b64_buf_size);

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_b64_buf_handle, expect_b64_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    // Check EsfCodecBase64EncodeHandle function
    Execute_EsfCodecBase64EncodeHandle(expect_jpeg_size, kEsfCodecBase64ResultSuccess,
                                       expect_jpeg_buf_handle, expect_b64_buf_handle,
                                       expect_b64_size);

    // FcloseAndFreeMemoryManagerHandle()
    FcloseAndFreeMemoryManagerHandleCommon(expect_jpeg_buf_handle,
                                           FcloseAndFreeMemoryManagerHandle_None);

    // Check ReleaseOneFrame function
    Execute_ReleaseOneFrame(ReleaseOneFrame_None);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccessHandle(cmd_id, DcOk, SetImagePropertyHandle,
                                                     (void *)(uintptr_t)expect_b64_buf_handle,
                                                     expect_b64_size, memmgr_handle_json);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx
    ExecSysProcessEventForMemoryFreeHandle(memmgr_handle_json);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorAllocateAndFopenMemoryManagerHandleForEncodeToBase64(
    void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    EsfMemoryManagerHandle expect_jpeg_buf_handle = (EsfMemoryManagerHandle)0x24680000;
    EsfMemoryManagerHandle expect_b64_buf_handle = (EsfMemoryManagerHandle)0x13579000;

    int32_t expect_jpeg_size = 5566;
    int expect_quality = 80;
    uint32_t expect_b64_buf_size = 6464;
    const uint32_t jpeg_buf_size = DC_DIRECT_GET_IMAGE_MAX_SIZE * 3 / 4;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_None);

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_jpeg_buf_handle, jpeg_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    // Check EsfCodecJpegEncodeHandle function
    Execute_EsfCodecJpegEncodeHandle(expect_jpeg_buf_handle, kJpegInputRgbPlanar_8, expect_quality,
                                     expect_jpeg_size, JpegEncodeHandle_None);

    expect_value(__wrap_EsfCodecBase64GetEncodeSize, in_size, expect_jpeg_size);
    will_return(__wrap_EsfCodecBase64GetEncodeSize, expect_b64_buf_size);

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_b64_buf_handle, expect_b64_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_Allocate);

    // FcloseAndFreeMemoryManagerHandle()
    FcloseAndFreeMemoryManagerHandleCommon(expect_jpeg_buf_handle,
                                           FcloseAndFreeMemoryManagerHandle_None);

    // Check ReleaseOneFrame function
    Execute_ReleaseOneFrame(ReleaseOneFrame_None);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorEncodeToBase64EsfCodecBase64EncodeHandle(
    void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    EsfMemoryManagerHandle expect_jpeg_buf_handle = (EsfMemoryManagerHandle)0x24680000;
    EsfMemoryManagerHandle expect_b64_buf_handle = (EsfMemoryManagerHandle)0x13579000;

    int32_t expect_jpeg_size = 5566;
    int expect_quality = 80;
    uint32_t expect_b64_buf_size = 6464;
    const uint32_t jpeg_buf_size = DC_DIRECT_GET_IMAGE_MAX_SIZE * 3 / 4;
    uint32_t expect_b64_size = 4646;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_None);

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_jpeg_buf_handle, jpeg_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    // Check EsfCodecJpegEncodeHandle function
    Execute_EsfCodecJpegEncodeHandle(expect_jpeg_buf_handle, kJpegInputRgbPlanar_8, expect_quality,
                                     expect_jpeg_size, JpegEncodeHandle_None);

    expect_value(__wrap_EsfCodecBase64GetEncodeSize, in_size, expect_jpeg_size);
    will_return(__wrap_EsfCodecBase64GetEncodeSize, expect_b64_buf_size);

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_b64_buf_handle, expect_b64_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    // Check EsfCodecBase64EncodeHandle function
    Execute_EsfCodecBase64EncodeHandle(expect_jpeg_size, kEsfCodecBase64ResultInternalError,
                                       expect_jpeg_buf_handle, expect_b64_buf_handle,
                                       expect_b64_size);

    // FcloseAndFreeMemoryManagerHandle() for base64
    FcloseAndFreeMemoryManagerHandleCommon(expect_b64_buf_handle,
                                           FcloseAndFreeMemoryManagerHandle_None);

    // FcloseAndFreeMemoryManagerHandle() for jpeg
    FcloseAndFreeMemoryManagerHandleCommon(expect_jpeg_buf_handle,
                                           FcloseAndFreeMemoryManagerHandle_None);

    // Check ReleaseOneFrame function
    Execute_ReleaseOneFrame(ReleaseOneFrame_None);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_FullySuccessEncodeToBase64ErrorEsfMemoryManagerFseek(
    void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    EsfMemoryManagerHandle expect_jpeg_buf_handle = (EsfMemoryManagerHandle)0x24680000;
    EsfMemoryManagerHandle expect_b64_buf_handle = (EsfMemoryManagerHandle)0x13579000;
    EsfMemoryManagerHandle memmgr_handle_json = (EsfMemoryManagerHandle)0x98765432;

    int32_t expect_jpeg_size = 5566;
    int expect_quality = 80;
    uint32_t expect_b64_buf_size = 6464;
    const uint32_t jpeg_buf_size = DC_DIRECT_GET_IMAGE_MAX_SIZE * 3 / 4;
    uint32_t expect_b64_size = 4646;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_None);

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_jpeg_buf_handle, jpeg_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    // Check EsfCodecJpegEncodeHandle function
    Execute_EsfCodecJpegEncodeHandle(expect_jpeg_buf_handle, kJpegInputRgbPlanar_8, expect_quality,
                                     expect_jpeg_size, JpegEncodeHandle_None);

    expect_value(__wrap_EsfCodecBase64GetEncodeSize, in_size, expect_jpeg_size);
    will_return(__wrap_EsfCodecBase64GetEncodeSize, expect_b64_buf_size);

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_b64_buf_handle, expect_b64_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    // Check EsfCodecBase64EncodeHandle function
    Execute_EsfCodecBase64EncodeHandle(expect_jpeg_size, kEsfCodecBase64ResultSuccess,
                                       expect_jpeg_buf_handle, expect_b64_buf_handle,
                                       expect_b64_size);

    // FcloseAndFreeMemoryManagerHandle()
    FcloseAndFreeMemoryManagerHandleCommon(expect_jpeg_buf_handle,
                                           FcloseAndFreeMemoryManagerHandle_None);

    // Check ReleaseOneFrame function
    Execute_ReleaseOneFrame(ReleaseOneFrame_None);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccessHandle(cmd_id, DcOk, SetImagePropertyHandle,
                                                     (void *)(uintptr_t)expect_b64_buf_handle,
                                                     expect_b64_size, memmgr_handle_json);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx
    ExecSysProcessEventForMemoryFreeHandle(memmgr_handle_json);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorReleaseOneFrameSenscordStreamReleaseFrame(
    void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    EsfMemoryManagerHandle expect_jpeg_buf_handle = (EsfMemoryManagerHandle)0x24680000;
    EsfMemoryManagerHandle expect_b64_buf_handle = (EsfMemoryManagerHandle)0x13579000;

    int32_t expect_jpeg_size = 5566;
    int expect_quality = 80;
    uint32_t expect_b64_buf_size = 6464;
    const uint32_t jpeg_buf_size = DC_DIRECT_GET_IMAGE_MAX_SIZE * 3 / 4;
    uint32_t expect_b64_size = 4646;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_None);

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_jpeg_buf_handle, jpeg_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    // Check EsfCodecJpegEncodeHandle function
    Execute_EsfCodecJpegEncodeHandle(expect_jpeg_buf_handle, kJpegInputRgbPlanar_8, expect_quality,
                                     expect_jpeg_size, JpegEncodeHandle_None);

    expect_value(__wrap_EsfCodecBase64GetEncodeSize, in_size, expect_jpeg_size);
    will_return(__wrap_EsfCodecBase64GetEncodeSize, expect_b64_buf_size);

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_b64_buf_handle, expect_b64_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    // Check EsfCodecBase64EncodeHandle function
    Execute_EsfCodecBase64EncodeHandle(expect_jpeg_size, kEsfCodecBase64ResultSuccess,
                                       expect_jpeg_buf_handle, expect_b64_buf_handle,
                                       expect_b64_size);

    // FcloseAndFreeMemoryManagerHandle()
    FcloseAndFreeMemoryManagerHandleCommon(expect_jpeg_buf_handle,
                                           FcloseAndFreeMemoryManagerHandle_None);

    // Check ReleaseOneFrame function
    Execute_ReleaseOneFrame(ReleaseOneFrame_SenscordStreamReleaseFrame);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorReleaseOneFrameSenscordStreamStop(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    EsfMemoryManagerHandle expect_jpeg_buf_handle = (EsfMemoryManagerHandle)0x24680000;
    EsfMemoryManagerHandle expect_b64_buf_handle = (EsfMemoryManagerHandle)0x13579000;

    int32_t expect_jpeg_size = 5566;
    int expect_quality = 80;
    uint32_t expect_b64_buf_size = 6464;
    const uint32_t jpeg_buf_size = DC_DIRECT_GET_IMAGE_MAX_SIZE * 3 / 4;
    uint32_t expect_b64_size = 4646;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_None);

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_jpeg_buf_handle, jpeg_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    // Check EsfCodecJpegEncodeHAndle function
    Execute_EsfCodecJpegEncodeHandle(expect_jpeg_buf_handle, kJpegInputRgbPlanar_8, expect_quality,
                                     expect_jpeg_size, JpegEncodeHandle_None);

    expect_value(__wrap_EsfCodecBase64GetEncodeSize, in_size, expect_jpeg_size);
    will_return(__wrap_EsfCodecBase64GetEncodeSize, expect_b64_buf_size);

    // Check AllocateAndFopenMemoryManagerHandle()
    AllocateAndFopenMemoryManagerHandleCommon(expect_b64_buf_handle, expect_b64_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    // Check EsfCodecBase64EncodeHandle function
    Execute_EsfCodecBase64EncodeHandle(expect_jpeg_size, kEsfCodecBase64ResultSuccess,
                                       expect_jpeg_buf_handle, expect_b64_buf_handle,
                                       expect_b64_size);

    // FcloseAndFreeMemoryManagerHandle()
    FcloseAndFreeMemoryManagerHandleCommon(expect_jpeg_buf_handle,
                                           FcloseAndFreeMemoryManagerHandle_None);

    // Check ReleaseOneFrame function
    Execute_ReleaseOneFrame(ReleaseOneFrame_SenscordStreamStop);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorGetOneFrameEsfMemoryManagerGetHandleInfo(
    void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_EsfMemoryManagerGetHandleInfo);

    // Check UtilityLog function
    CheckDcmdDirectGetImageSensorErrorUtilityLog();

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);
    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_FullySuccessUseMallocBuffer(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    char *expect_b64_buf = "0x64646464";
    uint32_t expect_b64_size = 4646;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_EsfMemoryManagerGetHandleInfoOtherHeap);

    // Check EncodeToJpeg and EncodeToBase64 (with raw data)
    Execute_EncodePhaseWithRawData(expect_b64_buf, kJpegInputRgbPlanar_8, expect_b64_size,
                                   ExecEncodePhaseWithRawData_None);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcOk, SetImageProperty,
                                               expect_b64_buf);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorUseMallocBufferMallocJpeg(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    char *expect_b64_buf = "0x64646464";
    uint32_t expect_b64_size = 4646;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_EsfMemoryManagerGetHandleInfoOtherHeap);

    // Check EncodeToJpeg and EncodeToBase64 (with raw data)
    Execute_EncodePhaseWithRawData(expect_b64_buf, kJpegInputRgbPlanar_8, expect_b64_size,
                                   ExecEncodePhaseWithRawData_MallocJpegEncodeBuffer);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorUseMallocBufferMallocBase64(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    char *expect_b64_buf = "0x64646464";
    uint32_t expect_b64_size = 4646;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_EsfMemoryManagerGetHandleInfoOtherHeap);

    // Check EncodeToJpeg and EncodeToBase64 (with raw data)
    Execute_EncodePhaseWithRawData(expect_b64_buf, kJpegInputRgbPlanar_8, expect_b64_size,
                                   ExecEncodePhaseWithRawData_MallocBase64EncodeBuffer);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorUseMallocBufferEsfCodecJpegEncode(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    char *expect_b64_buf = "0x64646464";
    uint32_t expect_b64_size = 4646;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_EsfMemoryManagerGetHandleInfoOtherHeap);

    // Check EncodeToJpeg and EncodeToBase64 (with raw data)
    Execute_EncodePhaseWithRawData(expect_b64_buf, kJpegInputRgbPlanar_8, expect_b64_size,
                                   ExecEncodePhaseWithRawData_EsfCodecJpegEncode);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();
}

/*----------------------------------------------------------------------------*/
static void test_SysAppDcmdDirectGetImage_ErrorUseMallocBufferEsfCodecBase64Encode(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    char *expect_b64_buf = "0x64646464";
    uint32_t expect_b64_size = 4646;
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_EsfMemoryManagerGetHandleInfoOtherHeap);

    // Check EncodeToJpeg and EncodeToBase64 (with raw data)
    Execute_EncodePhaseWithRawData(expect_b64_buf, kJpegInputRgbPlanar_8, expect_b64_size,
                                   ExecEncodePhaseWithRawData_EsfCodecBase64Encode);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcInternal,
                                               SetImageProperty, NULL);

    // Exec test target
    ret = SysAppDcmdDirectGetImage(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();
}

/*----------------------------------------------------------------------------*/

//
// GetSensorRegisterArrayParam()
//

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterArrayParam_FullySuccessGetValueProperty(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 4, .info = NULL};
    bool is_get_value_property = true;
    uint32_t size;
    int i;

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }

    // mock oepration for GetSensorRegisterArrayParam()
    GetSensorRegisterArrayParamCommon(json_handle, json_val, sensor_register_param.num,
                                      is_get_value_property, GetSensorRegisterArrayParam_None);

    // Exec test target
    ret = GetSensorRegisterArrayParam(json_handle, json_val, &sensor_register_param,
                                      is_get_value_property);

    // Check return and output value
    assert_int_equal(ret, DcOk);
    for (i = 0; i < sensor_register_param.num; i++) {
        size = GetSensorRegisterArraySize(i);
        assert_int_equal(sensor_register_param.info[i].address, GetSensorRegisterArrayAddress(i));
        assert_int_equal(sensor_register_param.info[i].size, size);
        assert_int_equal(sensor_register_param.info[i].value, GetSensorRegisterArrayValue(size, i));
    }

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#if defined(CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500)
static void test_GetSensorRegisterArrayParam_FullySuccessNotGetValueProperty(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 4, .info = NULL};
    bool is_get_value_property = false;
    int i;

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }

    // mock oepration for GetSensorRegisterArrayParam()
    GetSensorRegisterArrayParamCommon(json_handle, json_val, sensor_register_param.num,
                                      is_get_value_property, GetSensorRegisterArrayParam_None);

    // Exec test target
    ret = GetSensorRegisterArrayParam(json_handle, json_val, &sensor_register_param,
                                      is_get_value_property);

    // Check return and output value
    assert_int_equal(ret, DcOk);
    for (i = 0; i < sensor_register_param.num; i++) {
        assert_int_equal(sensor_register_param.info[i].address, GetSensorRegisterArrayAddress(i));
        assert_int_equal(sensor_register_param.info[i].size, GetSensorRegisterArraySize(i));
    }

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterArrayParam_ErrorEsfJsonArrayGet(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 3, .info = NULL};
    bool is_get_value_property = true;

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }

    // mock oepration for GetSensorRegisterArrayParam()
    GetSensorRegisterArrayParamCommon(json_handle, json_val, sensor_register_param.num,
                                      is_get_value_property,
                                      GetSensorRegisterArrayParam_EsfJsonArrayGet);

    // Exec test target
    ret = GetSensorRegisterArrayParam(json_handle, json_val, &sensor_register_param,
                                      is_get_value_property);

    // Check return value
    assert_int_equal(ret, DcInternal);

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterArrayParam_ErrorSysAppCmnExtractRealNumberValueAddress(
    void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 3, .info = NULL};
    bool is_get_value_property = true;

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }

    // mock oepration for GetSensorRegisterArrayParam()
    GetSensorRegisterArrayParamCommon(
        json_handle, json_val, sensor_register_param.num, is_get_value_property,
        GetSensorRegisterArrayParam_SysAppCmnExtractRealNumberValueAddress);

    // Exec test target
    ret = GetSensorRegisterArrayParam(json_handle, json_val, &sensor_register_param,
                                      is_get_value_property);

    // Check return value
    assert_int_equal(ret, DcInvalidArgument);

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterArrayParam_ErrorSysAppCmnExtractNumberValueSize(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 3, .info = NULL};
    bool is_get_value_property = true;

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }

    // mock oepration for GetSensorRegisterArrayParam()
    GetSensorRegisterArrayParamCommon(json_handle, json_val, sensor_register_param.num,
                                      is_get_value_property,
                                      GetSensorRegisterArrayParam_SysAppCmnExtractNumberValueSize);

    // Exec test target
    ret = GetSensorRegisterArrayParam(json_handle, json_val, &sensor_register_param,
                                      is_get_value_property);

    // Check return value
    assert_int_equal(ret, DcInvalidArgument);

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterArrayParam_InvalidSizeProtertyValue(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 3, .info = NULL};
    bool is_get_value_property = true;

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }

    // mock oepration for GetSensorRegisterArrayParam()
    GetSensorRegisterArrayParamCommon(json_handle, json_val, sensor_register_param.num,
                                      is_get_value_property,
                                      GetSensorRegisterArrayParam_InvalidSizeProtertyValue);

    // Exec test target
    ret = GetSensorRegisterArrayParam(json_handle, json_val, &sensor_register_param,
                                      is_get_value_property);

    // Check return value
    assert_int_equal(ret, DcInvalidArgument);

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterArrayParam_ErrorSysAppCmnExtractRealNumberValueValue(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 3, .info = NULL};
    bool is_get_value_property = true;

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }

    // mock oepration for GetSensorRegisterArrayParam()
    GetSensorRegisterArrayParamCommon(
        json_handle, json_val, sensor_register_param.num, is_get_value_property,
        GetSensorRegisterArrayParam_SysAppCmnExtractRealNumberValueValue);

    // Exec test target
    ret = GetSensorRegisterArrayParam(json_handle, json_val, &sensor_register_param,
                                      is_get_value_property);

    // Check return value
    assert_int_equal(ret, DcInvalidArgument);

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterArrayParam_MaxOverValue1Byte(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 3, .info = NULL};
    bool is_get_value_property = true;

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }

    // mock oepration for GetSensorRegisterArrayParam()
    GetSensorRegisterArrayParamCommon(json_handle, json_val, sensor_register_param.num,
                                      is_get_value_property,
                                      GetSensorRegisterArrayParam_MaxOverValue1Byte);

    // Exec test target
    ret = GetSensorRegisterArrayParam(json_handle, json_val, &sensor_register_param,
                                      is_get_value_property);

    // Check return value
    assert_int_equal(ret, DcInvalidArgument);

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterArrayParam_MaxValue1Byte(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 3, .info = NULL};
    bool is_get_value_property = true;
    uint32_t size;
    int i;

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }

    // mock oepration for GetSensorRegisterArrayParam()
    GetSensorRegisterArrayParamCommon(json_handle, json_val, sensor_register_param.num,
                                      is_get_value_property,
                                      GetSensorRegisterArrayParam_MaxValue1Byte);

    // Exec test target
    ret = GetSensorRegisterArrayParam(json_handle, json_val, &sensor_register_param,
                                      is_get_value_property);

    // Check return and output value
    assert_int_equal(ret, DcOk);
    for (i = 0; i < sensor_register_param.num; i++) {
        size = GetSensorRegisterArraySize(i);
        assert_int_equal(sensor_register_param.info[i].address, GetSensorRegisterArrayAddress(i));
        assert_int_equal(sensor_register_param.info[i].size, size);
        if (size == 1) {
            assert_int_equal(sensor_register_param.info[i].value,
                             GetSensorRegisterArrayMaxValue(size));
        }
        else {
            assert_int_equal(sensor_register_param.info[i].value,
                             GetSensorRegisterArrayValue(size, i));
        }
    }

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterArrayParam_MaxOverValue2Byte(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 3, .info = NULL};
    bool is_get_value_property = true;

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }

    // mock oepration for GetSensorRegisterArrayParam()
    GetSensorRegisterArrayParamCommon(json_handle, json_val, sensor_register_param.num,
                                      is_get_value_property,
                                      GetSensorRegisterArrayParam_MaxOverValue2Byte);

    // Exec test target
    ret = GetSensorRegisterArrayParam(json_handle, json_val, &sensor_register_param,
                                      is_get_value_property);

    // Check return value
    assert_int_equal(ret, DcInvalidArgument);

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterArrayParam_MaxValue2Byte(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 3, .info = NULL};
    bool is_get_value_property = true;
    uint32_t size;
    int i;

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }

    // mock oepration for GetSensorRegisterArrayParam()
    GetSensorRegisterArrayParamCommon(json_handle, json_val, sensor_register_param.num,
                                      is_get_value_property,
                                      GetSensorRegisterArrayParam_MaxValue2Byte);

    // Exec test target
    ret = GetSensorRegisterArrayParam(json_handle, json_val, &sensor_register_param,
                                      is_get_value_property);

    // Check return and output value
    assert_int_equal(ret, DcOk);
    for (i = 0; i < sensor_register_param.num; i++) {
        size = GetSensorRegisterArraySize(i);
        assert_int_equal(sensor_register_param.info[i].address, GetSensorRegisterArrayAddress(i));
        assert_int_equal(sensor_register_param.info[i].size, size);
        if (size == 2) {
            assert_int_equal(sensor_register_param.info[i].value,
                             GetSensorRegisterArrayMaxValue(size));
        }
        else {
            assert_int_equal(sensor_register_param.info[i].value,
                             GetSensorRegisterArrayValue(size, i));
        }
    }

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterArrayParam_MaxOverValue4Byte(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 3, .info = NULL};
    bool is_get_value_property = true;

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }

    // mock oepration for GetSensorRegisterArrayParam()
    GetSensorRegisterArrayParamCommon(json_handle, json_val, sensor_register_param.num,
                                      is_get_value_property,
                                      GetSensorRegisterArrayParam_MaxOverValue4Byte);

    // Exec test target
    ret = GetSensorRegisterArrayParam(json_handle, json_val, &sensor_register_param,
                                      is_get_value_property);

    // Check return value
    assert_int_equal(ret, DcInvalidArgument);

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterArrayParam_MaxValue4Byte(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 3, .info = NULL};
    bool is_get_value_property = true;
    uint32_t size;
    int i;

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }

    // mock oepration for GetSensorRegisterArrayParam()
    GetSensorRegisterArrayParamCommon(json_handle, json_val, sensor_register_param.num,
                                      is_get_value_property,
                                      GetSensorRegisterArrayParam_MaxValue4Byte);

    // Exec test target
    ret = GetSensorRegisterArrayParam(json_handle, json_val, &sensor_register_param,
                                      is_get_value_property);

    // Check return and output value
    assert_int_equal(ret, DcOk);
    for (i = 0; i < sensor_register_param.num; i++) {
        size = GetSensorRegisterArraySize(i);
        assert_int_equal(sensor_register_param.info[i].address, GetSensorRegisterArrayAddress(i));
        assert_int_equal(sensor_register_param.info[i].size, size);
        if (size == 4) {
            assert_int_equal(sensor_register_param.info[i].value,
                             GetSensorRegisterArrayMaxValue(size));
        }
        else {
            assert_int_equal(sensor_register_param.info[i].value,
                             GetSensorRegisterArrayValue(size, i));
        }
    }

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/

//
// GetSensorRegisterParam()
//

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterParam_FullySuccessGetValueProperty(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};
    bool is_get_value_property = true;
    int32_t array_num = 3;
    uint32_t size;
    int i;

    // mock oepration for GetSensorRegisterParam()
    GetSensorRegisterParamCommon(json_handle, json_val, array_num, is_get_value_property,
                                 GetSensorRegisterParam_None);

    // Exec test target
    ret = GetSensorRegisterParam(json_handle, json_val, &sensor_register_param,
                                 is_get_value_property);

    // Check return and output value
    assert_int_equal(ret, DcOk);
    assert_int_equal(sensor_register_param.num, array_num);
    assert_non_null(sensor_register_param.info);
    for (i = 0; i < sensor_register_param.num; i++) {
        size = GetSensorRegisterArraySize(i);
        assert_int_equal(sensor_register_param.info[i].address, GetSensorRegisterArrayAddress(i));
        assert_int_equal(sensor_register_param.info[i].size, size);
        assert_int_equal(sensor_register_param.info[i].value, GetSensorRegisterArrayValue(size, i));
    }

    // Free memory allocated test target
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterParam_FullySuccessNotGetValueProperty(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};
    bool is_get_value_property = false;
    int32_t array_num = 3;
    uint32_t size;
    int i;

    // mock oepration for GetSensorRegisterParam()
    GetSensorRegisterParamCommon(json_handle, json_val, array_num, is_get_value_property,
                                 GetSensorRegisterParam_None);

    // Exec test target
    ret = GetSensorRegisterParam(json_handle, json_val, &sensor_register_param,
                                 is_get_value_property);

    // Check return and output value
    assert_int_equal(ret, DcOk);
    assert_int_equal(sensor_register_param.num, array_num);
    assert_non_null(sensor_register_param.info);
    for (i = 0; i < sensor_register_param.num; i++) {
        size = GetSensorRegisterArraySize(i);
        assert_int_equal(sensor_register_param.info[i].address, GetSensorRegisterArrayAddress(i));
        assert_int_equal(sensor_register_param.info[i].size, size);
    }

    // Free memory allocated test target
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterParam_ErrorEsfJsonObjectGet(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};
    bool is_get_value_property = false;
    int32_t array_num = 3;

    // mock oepration for GetSensorRegisterParam()
    GetSensorRegisterParamCommon(json_handle, json_val, array_num, is_get_value_property,
                                 GetSensorRegisterParam_EsfJsonObjectGet);

    // Exec test target
    ret = GetSensorRegisterParam(json_handle, json_val, &sensor_register_param,
                                 is_get_value_property);

    // Check return value
    assert_int_equal(ret, DcInvalidArgument);

    // Free memory allocated test target
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterParam_ErrorEsfJsonValueTypeGet(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};
    bool is_get_value_property = false;
    int32_t array_num = 3;

    // mock oepration for GetSensorRegisterParam()
    GetSensorRegisterParamCommon(json_handle, json_val, array_num, is_get_value_property,
                                 GetSensorRegisterParam_EsfJsonValueTypeGet);

    // Exec test target
    ret = GetSensorRegisterParam(json_handle, json_val, &sensor_register_param,
                                 is_get_value_property);

    // Check return value
    assert_int_equal(ret, DcInternal);

    // Free memory allocated test target
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterParam_InvalidTypeRegisterProperty(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};
    bool is_get_value_property = false;
    int32_t array_num = 3;

    // mock oepration for GetSensorRegisterParam()
    GetSensorRegisterParamCommon(json_handle, json_val, array_num, is_get_value_property,
                                 GetSensorRegisterParam_InvalidTypeRegisterProperty);

    // Exec test target
    ret = GetSensorRegisterParam(json_handle, json_val, &sensor_register_param,
                                 is_get_value_property);

    // Check return value
    assert_int_equal(ret, DcInvalidArgument);

    // Free memory allocated test target
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterParam_MinOverArrayNum(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};
    bool is_get_value_property = false;
    int32_t array_num = SENSOR_REGISTER_PARAM_REGISTER_ARRAY_NUM_MIN - 1;

    // mock oepration for GetSensorRegisterParam()
    GetSensorRegisterParamCommon(json_handle, json_val, array_num, is_get_value_property,
                                 GetSensorRegisterParam_None);

    // Exec test target
    ret = GetSensorRegisterParam(json_handle, json_val, &sensor_register_param,
                                 is_get_value_property);

    // Check return value
    assert_int_equal(ret, DcInvalidArgument);

    // Free memory allocated test target
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterParam_MinArrayNum(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};
    bool is_get_value_property = true;
    int32_t array_num = SENSOR_REGISTER_PARAM_REGISTER_ARRAY_NUM_MIN;
    uint32_t size;
    int i;

    // mock oepration for GetSensorRegisterParam()
    GetSensorRegisterParamCommon(json_handle, json_val, array_num, is_get_value_property,
                                 GetSensorRegisterParam_None);

    // Exec test target
    ret = GetSensorRegisterParam(json_handle, json_val, &sensor_register_param,
                                 is_get_value_property);

    // Check return and output value
    assert_int_equal(ret, DcOk);
    assert_int_equal(sensor_register_param.num, array_num);
    assert_non_null(sensor_register_param.info);
    for (i = 0; i < sensor_register_param.num; i++) {
        size = GetSensorRegisterArraySize(i);
        assert_int_equal(sensor_register_param.info[i].address, GetSensorRegisterArrayAddress(i));
        assert_int_equal(sensor_register_param.info[i].size, size);
        assert_int_equal(sensor_register_param.info[i].value, GetSensorRegisterArrayValue(size, i));
    }

    // Free memory allocated test target
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterParam_MaxArrayNum(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};
    bool is_get_value_property = true;
    int32_t array_num = SENSOR_REGISTER_PARAM_REGISTER_ARRAY_NUM_MAX;
    uint32_t size;
    int i;

    // mock oepration for GetSensorRegisterParam()
    GetSensorRegisterParamCommon(json_handle, json_val, array_num, is_get_value_property,
                                 GetSensorRegisterParam_None);

    // Exec test target
    ret = GetSensorRegisterParam(json_handle, json_val, &sensor_register_param,
                                 is_get_value_property);

    // Check return and output value
    assert_int_equal(ret, DcOk);
    assert_int_equal(sensor_register_param.num, array_num);
    assert_non_null(sensor_register_param.info);
    for (i = 0; i < sensor_register_param.num; i++) {
        size = GetSensorRegisterArraySize(i);
        assert_int_equal(sensor_register_param.info[i].address, GetSensorRegisterArrayAddress(i));
        assert_int_equal(sensor_register_param.info[i].size, size);
        assert_int_equal(sensor_register_param.info[i].value, GetSensorRegisterArrayValue(size, i));
    }

    // Free memory allocated test target
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterParam_MaxOverArrayNum(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};
    bool is_get_value_property = false;
    int32_t array_num = SENSOR_REGISTER_PARAM_REGISTER_ARRAY_NUM_MAX + 1;

    // mock oepration for GetSensorRegisterParam()
    GetSensorRegisterParamCommon(json_handle, json_val, array_num, is_get_value_property,
                                 GetSensorRegisterParam_None);

    // Exec test target
    ret = GetSensorRegisterParam(json_handle, json_val, &sensor_register_param,
                                 is_get_value_property);

    // Check return value
    assert_int_equal(ret, DcInvalidArgument);

    // Free memory allocated test target
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterParam_ErrorMalloc(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};
    bool is_get_value_property = false;
    int32_t array_num = 3;

    // mock oepration for GetSensorRegisterParam()
    GetSensorRegisterParamCommon(json_handle, json_val, array_num, is_get_value_property,
                                 GetSensorRegisterParam_Malloc);

    // Exec test target
    ret = GetSensorRegisterParam(json_handle, json_val, &sensor_register_param,
                                 is_get_value_property);

    // Check return value
    assert_int_equal(ret, DcInternal);

    // Free memory allocated test target
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetSensorRegisterParam_ErrorGetSensorRegisterArrayParam(void **state)
{
    DcResult ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};
    bool is_get_value_property = false;
    int32_t array_num = 3;

    // mock oepration for GetSensorRegisterParam()
    GetSensorRegisterParamCommon(json_handle, json_val, array_num, is_get_value_property,
                                 GetSensorRegisterParam_GetSensorRegisterArrayParam);

    // Exec test target
    ret = GetSensorRegisterParam(json_handle, json_val, &sensor_register_param,
                                 is_get_value_property);

    // Check return value
    assert_int_equal(ret, DcInvalidArgument);

    // Free memory allocated test target
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/

//
// GetReadSensorRegisterParam()
//

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetReadSensorRegisterParam_FullySuccess(void **state)
{
    DcResult ret;
    const char *param = "test GetReadSensorRegisterParam";
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};
    int i;

    // mock oepration for GetReadSensorRegisterParam()
    GetReadSensorRegisterParamCommon(param, GetReadSensorRegisterParam_None);

    // Exec test target
    ret = GetReadSensorRegisterParam(param, &sensor_register_param);

    // Check return and output value
    assert_int_equal(ret, DcOk);
    assert_int_equal(sensor_register_param.num, SENSOR_REGISTER_COMMON_ARRAY_NUM);
    assert_non_null(sensor_register_param.info);
    for (i = 0; i < sensor_register_param.num; i++) {
        assert_int_equal(sensor_register_param.info[i].address, GetSensorRegisterArrayAddress(i));
        assert_int_equal(sensor_register_param.info[i].size, GetSensorRegisterArraySize(i));
    }

    // Free memory allocated test target
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetReadSensorRegisterParam_ErrorEsfJsonOpen(void **state)
{
    DcResult ret;
    const char *param = "test GetReadSensorRegisterParam";
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};

    // mock oepration for GetReadSensorRegisterParam()
    GetReadSensorRegisterParamCommon(param, GetReadSensorRegisterParam_EsfJsonOpen);

    // Exec test target
    ret = GetReadSensorRegisterParam(param, &sensor_register_param);

    // Check return value
    assert_int_equal(ret, DcInternal);

    // Free memory allocated test target
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetReadSensorRegisterParam_ErrorEsfJsonDeserialize(void **state)
{
    DcResult ret;
    const char *param = "test GetReadSensorRegisterParam";
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};

    // mock oepration for GetReadSensorRegisterParam()
    GetReadSensorRegisterParamCommon(param, GetReadSensorRegisterParam_EsfJsonDeserialize);

    // Exec test target
    ret = GetReadSensorRegisterParam(param, &sensor_register_param);

    // Check return value
    assert_int_equal(ret, DcInternal);

    // Free memory allocated test target
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetReadSensorRegisterParam_ErrorGetSensorRegisterParam(void **state)
{
    DcResult ret;
    const char *param = "test GetReadSensorRegisterParam";
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};

    // mock oepration for GetReadSensorRegisterParam()
    GetReadSensorRegisterParamCommon(param, GetReadSensorRegisterParam_GetSensorRegisterParam);

    // Exec test target
    ret = GetReadSensorRegisterParam(param, &sensor_register_param);

    // Check return value
    assert_int_equal(ret, DcInvalidArgument);

    // Free memory allocated test target
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetReadSensorRegisterParam_ErrorEsfJsonClose(void **state)
{
    DcResult ret;
    const char *param = "test GetReadSensorRegisterParam";
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};
    int i;

    // mock oepration for GetReadSensorRegisterParam()
    GetReadSensorRegisterParamCommon(param, GetReadSensorRegisterParam_EsfJsonClose);

    // Exec test target
    ret = GetReadSensorRegisterParam(param, &sensor_register_param);

    // Check return and output value
    assert_int_equal(ret, DcOk);
    assert_int_equal(sensor_register_param.num, SENSOR_REGISTER_COMMON_ARRAY_NUM);
    assert_non_null(sensor_register_param.info);
    for (i = 0; i < sensor_register_param.num; i++) {
        assert_int_equal(sensor_register_param.info[i].address, GetSensorRegisterArrayAddress(i));
        assert_int_equal(sensor_register_param.info[i].size, GetSensorRegisterArraySize(i));
    }

    // Free memory allocated test target
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/

//
// GetWriteSensorRegisterParam()
//

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetWriteSensorRegisterParam_FullySuccess(void **state)
{
    DcResult ret;
    const char *param = "test GetWriteSensorRegisterParam";
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};
    uint32_t size;
    int i;

    // mock oepration for GetWriteSensorRegisterParam()
    GetWriteSensorRegisterParamCommon(param, GetWriteSensorRegisterParam_None);

    // Exec test target
    ret = GetWriteSensorRegisterParam(param, &sensor_register_param);

    // Check return and output value
    assert_int_equal(ret, DcOk);
    assert_int_equal(sensor_register_param.num, SENSOR_REGISTER_COMMON_ARRAY_NUM);
    assert_non_null(sensor_register_param.info);
    for (i = 0; i < sensor_register_param.num; i++) {
        size = GetSensorRegisterArraySize(i);
        assert_int_equal(sensor_register_param.info[i].address, GetSensorRegisterArrayAddress(i));
        assert_int_equal(sensor_register_param.info[i].size, size);
        assert_int_equal(sensor_register_param.info[i].value, GetSensorRegisterArrayValue(size, i));
    }

    // Free memory allocated test target
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetWriteSensorRegisterParam_ErrorEsfJsonOpen(void **state)
{
    DcResult ret;
    const char *param = "test GetWriteSensorRegisterParam";
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};

    // mock oepration for GetWriteSensorRegisterParam()
    GetWriteSensorRegisterParamCommon(param, GetWriteSensorRegisterParam_EsfJsonOpen);

    // Exec test target
    ret = GetWriteSensorRegisterParam(param, &sensor_register_param);

    // Check return value
    assert_int_equal(ret, DcInternal);

    // Free memory allocated test target
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetWriteSensorRegisterParam_ErrorEsfJsonDeserialize(void **state)
{
    DcResult ret;
    const char *param = "test GetWriteSensorRegisterParam";
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};

    // mock oepration for GetWriteSensorRegisterParam()
    GetWriteSensorRegisterParamCommon(param, GetWriteSensorRegisterParam_EsfJsonDeserialize);

    // Exec test target
    ret = GetWriteSensorRegisterParam(param, &sensor_register_param);

    // Check return value
    assert_int_equal(ret, DcInternal);

    // Free memory allocated test target
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetWriteSensorRegisterParam_ErrorGetSensorRegisterParam(void **state)
{
    DcResult ret;
    const char *param = "test GetWriteSensorRegisterParam";
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};

    // mock oepration for GetWriteSensorRegisterParam()
    GetWriteSensorRegisterParamCommon(param, GetWriteSensorRegisterParam_GetSensorRegisterParam);

    // Exec test target
    ret = GetWriteSensorRegisterParam(param, &sensor_register_param);

    // Check return value
    assert_int_equal(ret, DcInvalidArgument);

    // Free memory allocated test target
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_GetWriteSensorRegisterParam_ErrorEsfJsonClose(void **state)
{
    DcResult ret;
    const char *param = "test GetWriteSensorRegisterParam";
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};
    uint32_t size;
    int i;

    // mock oepration for GetWriteSensorRegisterParam()
    GetWriteSensorRegisterParamCommon(param, GetWriteSensorRegisterParam_EsfJsonClose);

    // Exec test target
    ret = GetWriteSensorRegisterParam(param, &sensor_register_param);

    // Check return and output value
    assert_int_equal(ret, DcOk);
    assert_int_equal(sensor_register_param.num, SENSOR_REGISTER_COMMON_ARRAY_NUM);
    assert_non_null(sensor_register_param.info);
    for (i = 0; i < sensor_register_param.num; i++) {
        size = GetSensorRegisterArraySize(i);
        assert_int_equal(sensor_register_param.info[i].address, GetSensorRegisterArrayAddress(i));
        assert_int_equal(sensor_register_param.info[i].size, size);
        assert_int_equal(sensor_register_param.info[i].value, GetSensorRegisterArrayValue(size, i));
    }

    // Free memory allocated test target
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/

//
// ExecReadSensorRegister8bit()
//

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecReadSensorRegister8bit_FullySuccess(void **state)
{
    RetCode ret;
    SensorRegisterInfo sensor_register_info = {.address = 0x78945612, .value = 0};

    // mock oepration for ExecReadSensorRegister8bits()
    ExecReadSensorRegister8bitCommon(&sensor_register_info, 0, ExecReadSensorRegister8bit_None);

    // Exec test target
    ret = ExecReadSensorRegister8bit(READ_SENSOR_REGISTER_COMMON_SENSCORD_STREAM,
                                     &sensor_register_info);

    // Check return and output value
    assert_int_equal(ret, kRetOk);
    assert_int_equal(sensor_register_info.value, GetSensorRegisterArrayValue(1, 0));

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecReadSensorRegister8bit_ErrorSenscordStreamGetProperty(void **state)
{
    RetCode ret;
    SensorRegisterInfo sensor_register_info = {.address = 0x78945612, .value = 0};

    // mock oepration for ExecReadSensorRegister8bits()
    ExecReadSensorRegister8bitCommon(&sensor_register_info, 0,
                                     ExecReadSensorRegister8bit_GetProperty);

    // Exec test target
    ret = ExecReadSensorRegister8bit(READ_SENSOR_REGISTER_COMMON_SENSCORD_STREAM,
                                     &sensor_register_info);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}
#endif

/*----------------------------------------------------------------------------*/

//
// ExecReadSensorRegister16bit()
//

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecReadSensorRegister16bit_FullySuccess(void **state)
{
    RetCode ret;
    SensorRegisterInfo sensor_register_info = {.address = 0x78945612, .value = 0};

    // mock oepration for ExecReadSensorRegister16bits()
    ExecReadSensorRegister16bitCommon(&sensor_register_info, 0, ExecReadSensorRegister16bit_None);

    // Exec test target
    ret = ExecReadSensorRegister16bit(READ_SENSOR_REGISTER_COMMON_SENSCORD_STREAM,
                                      &sensor_register_info);

    // Check return and output value
    assert_int_equal(ret, kRetOk);
    assert_int_equal(sensor_register_info.value, GetSensorRegisterArrayValue(2, 0));

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecReadSensorRegister16bit_ErrorSenscordStreamGetProperty(void **state)
{
    RetCode ret;
    SensorRegisterInfo sensor_register_info = {.address = 0x78945612, .value = 0};

    // mock oepration for ExecReadSensorRegister16bits()
    ExecReadSensorRegister16bitCommon(&sensor_register_info, 0,
                                      ExecReadSensorRegister16bit_GetProperty);

    // Exec test target
    ret = ExecReadSensorRegister16bit(READ_SENSOR_REGISTER_COMMON_SENSCORD_STREAM,
                                      &sensor_register_info);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}
#endif

/*----------------------------------------------------------------------------*/

//
// ExecReadSensorRegister32bit()
//

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecReadSensorRegister32bit_FullySuccess(void **state)
{
    RetCode ret;
    SensorRegisterInfo sensor_register_info = {.address = 0x78945612, .value = 0};

    // mock oepration for ExecReadSensorRegister32bits()
    ExecReadSensorRegister32bitCommon(&sensor_register_info, 0, ExecReadSensorRegister32bit_None);

    // Exec test target
    ret = ExecReadSensorRegister32bit(READ_SENSOR_REGISTER_COMMON_SENSCORD_STREAM,
                                      &sensor_register_info);

    // Check return and output value
    assert_int_equal(ret, kRetOk);
    assert_int_equal(sensor_register_info.value, GetSensorRegisterArrayValue(4, 0));

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecReadSensorRegister32bit_ErrorSenscordStreamGetProperty(void **state)
{
    RetCode ret;
    SensorRegisterInfo sensor_register_info = {.address = 0x78945612, .value = 0};

    // mock oepration for ExecReadSensorRegister32bits()
    ExecReadSensorRegister32bitCommon(&sensor_register_info, 0,
                                      ExecReadSensorRegister32bit_GetProperty);

    // Exec test target
    ret = ExecReadSensorRegister32bit(READ_SENSOR_REGISTER_COMMON_SENSCORD_STREAM,
                                      &sensor_register_info);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}
#endif

/*----------------------------------------------------------------------------*/

//
// ExecReadSensorRegister()
//

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecReadSensorRegister_FullySuccess(void **state)
{
    DcResult ret;
    SensorRegisterParam sensor_register_param = {.num = SENSOR_REGISTER_COMMON_ARRAY_NUM,
                                                 .info = NULL};
    int i;

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }
    SetCommonParamExecReadSensorRegister(&sensor_register_param);

    // mock oepration for ExecReadSensorRegister()
    ExecReadSensorRegisterCommon(&sensor_register_param, ExecReadSensorRegister_None);

    // Exec test target
    ret = ExecReadSensorRegister(&sensor_register_param);

    // Check return and output value
    assert_int_equal(ret, DcOk);
    for (i = 0; i < sensor_register_param.num; i++) {
        assert_int_equal(sensor_register_param.info[i].value,
                         GetSensorRegisterArrayValue(GetSensorRegisterArraySize(i), i));
    }

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecReadSensorRegister_ErrorSysAppStateGetSensCordStream(void **state)
{
    DcResult ret;
    SensorRegisterParam sensor_register_param = {.num = SENSOR_REGISTER_COMMON_ARRAY_NUM,
                                                 .info = NULL};

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }
    SetCommonParamExecReadSensorRegister(&sensor_register_param);

    // mock oepration for ExecReadSensorRegister()
    ExecReadSensorRegisterCommon(&sensor_register_param,
                                 ExecReadSensorRegister_SysAppStateGetSensCordStream);

    // Exec test target
    ret = ExecReadSensorRegister(&sensor_register_param);

    // Check return and output value
    assert_int_equal(ret, DcInternal);

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecReadSensorRegister_ErrorExecReadSensorRegister8bit(void **state)
{
    DcResult ret;
    SensorRegisterParam sensor_register_param = {.num = SENSOR_REGISTER_COMMON_ARRAY_NUM,
                                                 .info = NULL};

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }
    SetCommonParamExecReadSensorRegister(&sensor_register_param);

    // mock oepration for ExecReadSensorRegister()
    ExecReadSensorRegisterCommon(&sensor_register_param,
                                 ExecReadSensorRegister_ExecReadSensorRegister8bit);

    // Exec test target
    ret = ExecReadSensorRegister(&sensor_register_param);

    // Check return and output value
    assert_int_equal(ret, DcInternal);

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecReadSensorRegister_ErrorExecReadSensorRegister16bit(void **state)
{
    DcResult ret;
    SensorRegisterParam sensor_register_param = {.num = SENSOR_REGISTER_COMMON_ARRAY_NUM,
                                                 .info = NULL};

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }
    SetCommonParamExecReadSensorRegister(&sensor_register_param);

    // mock oepration for ExecReadSensorRegister()
    ExecReadSensorRegisterCommon(&sensor_register_param,
                                 ExecReadSensorRegister_ExecReadSensorRegister16bit);

    // Exec test target
    ret = ExecReadSensorRegister(&sensor_register_param);

    // Check return and output value
    assert_int_equal(ret, DcInternal);

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecReadSensorRegister_ErrorExecReadSensorRegister32bit(void **state)
{
    DcResult ret;
    SensorRegisterParam sensor_register_param = {.num = SENSOR_REGISTER_COMMON_ARRAY_NUM,
                                                 .info = NULL};

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }
    SetCommonParamExecReadSensorRegister(&sensor_register_param);

    // mock oepration for ExecReadSensorRegister()
    ExecReadSensorRegisterCommon(&sensor_register_param,
                                 ExecReadSensorRegister_ExecReadSensorRegister32bit);

    // Exec test target
    ret = ExecReadSensorRegister(&sensor_register_param);

    // Check return and output value
    assert_int_equal(ret, DcInternal);

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecReadSensorRegister_InvalidSize(void **state)
{
    DcResult ret;
    SensorRegisterParam sensor_register_param = {.num = 1, .info = NULL};

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }

    sensor_register_param.info[0].address = GetSensorRegisterArrayAddress(0);
    sensor_register_param.info[0].size = 3;

    // mock oepration for ExecReadSensorRegister()
    ExecReadSensorRegisterCommon(&sensor_register_param, ExecReadSensorRegister_None);

    // Exec test target
    ret = ExecReadSensorRegister(&sensor_register_param);

    // Check return and output value
    assert_int_equal(ret, DcOk);
    assert_int_equal(sensor_register_param.info[0].value, GetSensorRegisterArrayValue(4, 0));

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/

//
// ExecWriteSensorRegister8bit()
//

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecWriteSensorRegister8bit_FullySuccess(void **state)
{
    SensorRegisterInfo sensor_register_info = {.address = 999, .value = 255};
    RetCode ret;

    // mock oepration for ExecWriteSensorRegister
    ExecWriteSensorRegisterEachBit(sensor_register_info.address, sensor_register_info.value,
                                   ExecWriteSensorRegisterBit_8bit,
                                   ExecWriteSensorRegisterEachBit_None);

    // Exec test target
    ret = ExecWriteSensorRegister8bit(WRITE_SENSOR_REGISTER_COMMON_SENSCORD_STREAM,
                                      &sensor_register_info);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecWriteSensorRegister8bit_ErrorSenscordStreamSetProperty(void **state)
{
    SensorRegisterInfo sensor_register_info = {.address = 999, .value = 255};
    RetCode ret;

    // mock oepration for ExecWriteSensorRegister
    ExecWriteSensorRegisterEachBit(sensor_register_info.address, sensor_register_info.value,
                                   ExecWriteSensorRegisterBit_8bit,
                                   ExecWriteSensorRegisterEachBit_SetProperty);

    // Exec test target
    ret = ExecWriteSensorRegister8bit(WRITE_SENSOR_REGISTER_COMMON_SENSCORD_STREAM,
                                      &sensor_register_info);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------------*/

//
// ExecWriteSensorRegister16bit()
//

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecWriteSensorRegister16bit_FullySuccess(void **state)
{
    SensorRegisterInfo sensor_register_info = {.address = 999, .value = 65535};
    RetCode ret;

    // mock oepration for ExecWriteSensorRegister
    ExecWriteSensorRegisterEachBit(sensor_register_info.address, sensor_register_info.value,
                                   ExecWriteSensorRegisterBit_16bit,
                                   ExecWriteSensorRegisterEachBit_None);

    // Exec test target
    ret = ExecWriteSensorRegister16bit(WRITE_SENSOR_REGISTER_COMMON_SENSCORD_STREAM,
                                       &sensor_register_info);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecWriteSensorRegister16bit_ErrorSenscordStreamSetProperty(void **state)
{
    SensorRegisterInfo sensor_register_info = {.address = 999, .value = 65535};
    RetCode ret;

    // mock oepration for ExecWriteSensorRegister
    ExecWriteSensorRegisterEachBit(sensor_register_info.address, sensor_register_info.value,
                                   ExecWriteSensorRegisterBit_16bit,
                                   ExecWriteSensorRegisterEachBit_SetProperty);

    // Exec test target
    ret = ExecWriteSensorRegister16bit(WRITE_SENSOR_REGISTER_COMMON_SENSCORD_STREAM,
                                       &sensor_register_info);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------------*/

//
// ExecWriteSensorRegister32bit()
//

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecWriteSensorRegister32bit_FullySuccess(void **state)
{
    SensorRegisterInfo sensor_register_info = {.address = 999, .value = 4294967295};
    RetCode ret;

    // mock oepration for ExecWriteSensorRegister
    ExecWriteSensorRegisterEachBit(sensor_register_info.address, sensor_register_info.value,
                                   ExecWriteSensorRegisterBit_32bit,
                                   ExecWriteSensorRegisterEachBit_None);

    // Exec test target
    ret = ExecWriteSensorRegister32bit(WRITE_SENSOR_REGISTER_COMMON_SENSCORD_STREAM,
                                       &sensor_register_info);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecWriteSensorRegister32bit_ErrorSenscordStreamSetProperty(void **state)
{
    SensorRegisterInfo sensor_register_info = {.address = 999, .value = 4294967295};
    RetCode ret;

    // mock oepration for ExecWriteSensorRegister
    ExecWriteSensorRegisterEachBit(sensor_register_info.address, sensor_register_info.value,
                                   ExecWriteSensorRegisterBit_32bit,
                                   ExecWriteSensorRegisterEachBit_SetProperty);

    // Exec test target
    ret = ExecWriteSensorRegister32bit(WRITE_SENSOR_REGISTER_COMMON_SENSCORD_STREAM,
                                       &sensor_register_info);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------------*/

//
// ExecWriteSensorRegister()
//

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecWriteSensorRegister_FullySuccess(void **state)
{
    SensorRegisterParam sensor_register_param = {.num = SENSOR_REGISTER_COMMON_ARRAY_NUM,
                                                 .info = NULL};
    DcResult ret;

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }
    SetCommonParamExecWriteSensorRegister(&sensor_register_param);

    // mock oepration for ExecWriteSensorRegister()
    ExecWriteSensorRegisterCommon(&sensor_register_param, ExecWriteSensorRegister_None);

    // Exec test target
    ret = ExecWriteSensorRegister(&sensor_register_param);

    // Check return value
    assert_int_equal(ret, DcOk);

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecWriteSensorRegister_ErrorSysAppStateGetSensCordStream(void **state)
{
    SensorRegisterParam sensor_register_param = {.num = SENSOR_REGISTER_COMMON_ARRAY_NUM,
                                                 .info = NULL};
    DcResult ret;

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }
    SetCommonParamExecWriteSensorRegister(&sensor_register_param);

    // mock oepration for ExecWriteSensorRegister()
    ExecWriteSensorRegisterCommon(&sensor_register_param,
                                  ExecWriteSensorRegister_SysAppStateGetSensCordStream);

    // Exec test target
    ret = ExecWriteSensorRegister(&sensor_register_param);

    // Check return value
    assert_int_equal(ret, DcInternal);

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecWriteSensorRegister_ErrorExecWriteSensorRegister8bit(void **state)
{
    SensorRegisterParam sensor_register_param = {.num = SENSOR_REGISTER_COMMON_ARRAY_NUM,
                                                 .info = NULL};
    DcResult ret;

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }
    SetCommonParamExecWriteSensorRegister(&sensor_register_param);

    // mock oepration for ExecWriteSensorRegister()
    ExecWriteSensorRegisterCommon(&sensor_register_param,
                                  ExecWriteSensorRegister_ExecWriteSensorRegister8bit);

    // Exec test target
    ret = ExecWriteSensorRegister(&sensor_register_param);

    // Check return value
    assert_int_equal(ret, DcInternal);

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecWriteSensorRegister_ErrorExecWriteSensorRegister16bit(void **state)
{
    SensorRegisterParam sensor_register_param = {.num = SENSOR_REGISTER_COMMON_ARRAY_NUM,
                                                 .info = NULL};
    DcResult ret;

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }
    SetCommonParamExecWriteSensorRegister(&sensor_register_param);

    // mock oepration for ExecWriteSensorRegister()
    ExecWriteSensorRegisterCommon(&sensor_register_param,
                                  ExecWriteSensorRegister_ExecWriteSensorRegister16bit);

    // Exec test target
    ret = ExecWriteSensorRegister(&sensor_register_param);

    // Check return value
    assert_int_equal(ret, DcInternal);

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecWriteSensorRegister_ErrorExecWriteSensorRegister32bit(void **state)
{
    SensorRegisterParam sensor_register_param = {.num = SENSOR_REGISTER_COMMON_ARRAY_NUM,
                                                 .info = NULL};
    DcResult ret;

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }
    SetCommonParamExecWriteSensorRegister(&sensor_register_param);

    // mock oepration for ExecWriteSensorRegister()
    ExecWriteSensorRegisterCommon(&sensor_register_param,
                                  ExecWriteSensorRegister_ExecWriteSensorRegister32bit);

    // Exec test target
    ret = ExecWriteSensorRegister(&sensor_register_param);

    // Check return value
    assert_int_equal(ret, DcInternal);

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_ExecWriteSensorRegister_InvalidSize(void **state)
{
    SensorRegisterParam sensor_register_param = {.num = 1, .info = NULL};
    DcResult ret;

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }

    sensor_register_param.info[0].address = GetSensorRegisterArrayAddress(0);
    sensor_register_param.info[0].size = 3;
    sensor_register_param.info[0].value = GetSensorRegisterArrayValue(4, 0);

    // mock oepration for ExecWriteSensorRegister()
    ExecWriteSensorRegisterCommon(&sensor_register_param, ExecWriteSensorRegister_None);

    // Exec test target
    ret = ExecWriteSensorRegister(&sensor_register_param);

    // Check return value
    assert_int_equal(ret, DcOk);

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------------*/

//
// MakeJsonRegisterParams()
//

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_MakeJsonRegisterParams(void **state)
{
    RetCode ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x97538642;
    EsfJsonValue parent_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 1, .info = NULL};

    // Prepare test target argument
    sensor_register_param.info = malloc(sizeof(SensorRegisterInfo) * sensor_register_param.num);
    if (sensor_register_param.info == NULL) {
        assert_non_null(sensor_register_param.info);
        goto exit;
    }
    for (int i = 0; i < sensor_register_param.num; i++) {
        sensor_register_param.info[i].address = GetSensorRegisterArrayAddress(i);
        sensor_register_param.info[i].size = GetSensorRegisterArraySize(i);
        sensor_register_param.info[i].value =
            GetSensorRegisterArrayValue(sensor_register_param.info[i].size, i);
    }

    // mock oepration for MakeJsonRegisterParams()
    MakeJsonRegisterParamsCommon(json_handle, parent_val, &sensor_register_param);

    // Exec test target
    ret = MakeJsonRegisterParams(json_handle, parent_val, 0, (void *)&sensor_register_param);

    // Check return value
    assert_int_equal(ret, kRetOk);

exit:
    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/

//
// SetRegisterProperty()
//

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_SetRegisterProperty_FullySuccess(void **state)
{
    RetCode ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x97538642;
    EsfJsonValue parent_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 1, .info = NULL};

    // For SysAppCmnSetArrayValue();
    expect_value(__wrap_SysAppCmnSetArrayValue, handle, json_handle);
    expect_value(__wrap_SysAppCmnSetArrayValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetArrayValue, key, "register");
    expect_value(__wrap_SysAppCmnSetArrayValue, array_num, sensor_register_param.num);
    expect_value(__wrap_SysAppCmnSetArrayValue, make_json, MakeJsonRegisterParams);
    expect_value(__wrap_SysAppCmnSetArrayValue, ctx, (void *)&sensor_register_param);
    will_return(__wrap_SysAppCmnSetArrayValue, false);
    will_return(__wrap_SysAppCmnSetArrayValue, kRetOk);

    // Exec test target
    ret = SetRegisterProperty(json_handle, parent_val, (void *)&sensor_register_param, 0);

    // Check return and output value
    assert_int_equal(ret, kRetOk);
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_SetRegisterProperty_ErrorSysAppCmnSetArrayValue(void **state)
{
    RetCode ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x97538642;
    EsfJsonValue parent_val = 1357;
    SensorRegisterParam sensor_register_param = {.num = 1, .info = NULL};

    // For SysAppCmnSetArrayValue();
    expect_value(__wrap_SysAppCmnSetArrayValue, handle, json_handle);
    expect_value(__wrap_SysAppCmnSetArrayValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetArrayValue, key, "register");
    expect_value(__wrap_SysAppCmnSetArrayValue, array_num, sensor_register_param.num);
    expect_value(__wrap_SysAppCmnSetArrayValue, make_json, MakeJsonRegisterParams);
    expect_value(__wrap_SysAppCmnSetArrayValue, ctx, (void *)&sensor_register_param);
    will_return(__wrap_SysAppCmnSetArrayValue, false);
    will_return(__wrap_SysAppCmnSetArrayValue, kRetFailed);

    // Exec test target
    ret = SetRegisterProperty(json_handle, parent_val, (void *)&sensor_register_param, 0);

    // Check return and output value
    assert_int_equal(ret, kRetFailed);
}
#endif

/*----------------------------------------------------------------------------*/

//
// SysAppDcmdReadSensorRegister()
//

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_SysAppDcmdReadSensorRegister_FullySuccess(void **state)
{
    RetCode ret;
    SYS_response_id cmd_id = 9876;
    const char *req_id = "No.1234";
    const char *param = "test SysAppDcmdReadSensorRegister";

    // mock oepration for SysAppDcmdReadSensorRegister()
    if (SysAppDcmdReadSensorRegisterCommon(cmd_id, req_id, param,
                                           SysAppDcmdReadSensorRegister_None) == false) {
        goto exit;
    }

    // Exec test target
    ret = SysAppDcmdReadSensorRegister(cmd_id, req_id, param);

    // Check return and output value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

exit:
    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_SysAppDcmdReadSensorRegister_ErrorGetReadSensorRegisterParamInvalidParam(
    void **state)
{
    RetCode ret;
    SYS_response_id cmd_id = 9876;
    const char *req_id = "No.1234";
    const char *param = "test SysAppDcmdReadSensorRegister";

    // mock oepration for SysAppDcmdReadSensorRegister()
    if (SysAppDcmdReadSensorRegisterCommon(
            cmd_id, req_id, param,
            SysAppDcmdReadSensorRegister_GetReadSensorRegisterParamInvalidParam) == false) {
        goto exit;
    }

    // Exec test target
    ret = SysAppDcmdReadSensorRegister(cmd_id, req_id, param);

    // Check return and output value
    assert_int_equal(ret, kRetFailed);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

exit:
    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_SysAppDcmdReadSensorRegister_ErrorGetReadSensorRegisterParamOther(void **state)
{
    RetCode ret;
    SYS_response_id cmd_id = 9876;
    const char *req_id = "No.1234";
    const char *param = "test SysAppDcmdReadSensorRegister";

    // mock oepration for SysAppDcmdReadSensorRegister()
    if (SysAppDcmdReadSensorRegisterCommon(
            cmd_id, req_id, param, SysAppDcmdReadSensorRegister_GetReadSensorRegisterParamOther) ==
        false) {
        goto exit;
    }

    // Exec test target
    ret = SysAppDcmdReadSensorRegister(cmd_id, req_id, param);

    // Check return and output value
    assert_int_equal(ret, kRetFailed);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

exit:
    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_SysAppDcmdReadSensorRegister_ErrorExecReadSensorRegister(void **state)
{
    RetCode ret;
    SYS_response_id cmd_id = 9876;
    const char *req_id = "No.1234";
    const char *param = "test SysAppDcmdReadSensorRegister";

    // mock oepration for SysAppDcmdReadSensorRegister()
    if (SysAppDcmdReadSensorRegisterCommon(
            cmd_id, req_id, param, SysAppDcmdReadSensorRegister_ExecReadSensorRegister) == false) {
        goto exit;
    }

    // Exec test target
    ret = SysAppDcmdReadSensorRegister(cmd_id, req_id, param);

    // Check return and output value
    assert_int_equal(ret, kRetFailed);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

exit:
    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_SysAppDcmdReadSensorRegister_ErrorSendDirectCommandResponseAsync(void **state)
{
    RetCode ret;
    SYS_response_id cmd_id = 9876;
    const char *req_id = "No.1234";
    const char *param = "test SysAppDcmdReadSensorRegister";

    // mock oepration for SysAppDcmdReadSensorRegister()
    if (SysAppDcmdReadSensorRegisterCommon(
            cmd_id, req_id, param, SysAppDcmdReadSensorRegister_SendDirectCommandResponseAsync) ==
        false) {
        goto exit;
    }

    // Exec test target
    ret = SysAppDcmdReadSensorRegister(cmd_id, req_id, param);

    // Check return and output value
    assert_int_equal(ret, kRetFailed);

exit:
    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
static void test_SysAppDcmdReadSensorRegister_FullySuccess(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcUnimplemented, NULL,
                                               NULL);

    // Exec test target
    ret = SysAppDcmdReadSensorRegister(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
static void test_SysAppDcmdReadSensorRegister_ErrorSysSetResponseCb(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check SYS_set_response_cb Error case
    SendDirectCommandResponse_ErrorSysSetResponseCb(s_sys_client, cmd_id, req_id, DcUnimplemented,
                                                    NULL, NULL);

    // Exec test target
    ret = SysAppDcmdReadSensorRegister(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}
#endif

/*----------------------------------------------------------------------------*/

//
// SysAppDcmdWriteSensorRegister()
//

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_SysAppDcmdWriteSensorRegister_FullySuccess(void **state)
{
    RetCode ret;
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    // mock oepration for SysAppDcmdWriteSensorRegister()
    if (SysAppDcmdWriteSensorRegisterCommon(cmd_id, req_id, param,
                                            SysAppDcmdWriteSensorRegister_None) == false) {
        goto exit;
    }

    // Exec test target
    ret = SysAppDcmdWriteSensorRegister(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

exit:
    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_SysAppDcmdWriteSensorRegister_ErrorGetWriteSensorRegisterInvalidParam(void **state)
{
    RetCode ret;
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    // mock oepration for SysAppDcmdWriteSensorRegister()
    if (SysAppDcmdWriteSensorRegisterCommon(
            cmd_id, req_id, param,
            SysAppDcmdWriteSensorRegister_GetWriteSensorRegisterParamInvalidParam) == false) {
        goto exit;
    }

    // Exec test target
    ret = SysAppDcmdWriteSensorRegister(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

exit:
    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_SysAppDcmdWriteSensorRegister_ErrorGetWriteSensorRegisterParamOther(void **state)
{
    RetCode ret;
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    // mock oepration for SysAppDcmdWriteSensorRegister()
    if (SysAppDcmdWriteSensorRegisterCommon(
            cmd_id, req_id, param,
            SysAppDcmdWriteSensorRegister_GetWriteSensorRegisterParamOther) == false) {
        goto exit;
    }

    // Exec test target
    ret = SysAppDcmdWriteSensorRegister(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

exit:
    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_SysAppDcmdWriteSensorRegister_ErrorExecWriteSensorRegister(void **state)
{
    RetCode ret;
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    // mock oepration for SysAppDcmdWriteSensorRegister()
    if (SysAppDcmdWriteSensorRegisterCommon(
            cmd_id, req_id, param, SysAppDcmdWriteSensorRegister_ExecWriteSensorRegister) ==
        false) {
        goto exit;
    }

    // Exec test target
    ret = SysAppDcmdWriteSensorRegister(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

exit:
    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
static void test_SysAppDcmdWriteSensorRegister_ErrorSendDirectCommandResponseAsync(void **state)
{
    RetCode ret;
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    // mock oepration for SysAppDcmdWriteSensorRegister()
    if (SysAppDcmdWriteSensorRegisterCommon(
            cmd_id, req_id, param, SysAppDcmdWriteSensorRegister_SendDirectCommandResponseAsync) ==
        false) {
        goto exit;
    }

    // Exec test target
    ret = SysAppDcmdWriteSensorRegister(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetFailed);

exit:
    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
static void test_SysAppDcmdWriteSensorRegister_FullySuccess(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcUnimplemented, NULL,
                                               NULL);

    // Exec test target
    ret = SysAppDcmdWriteSensorRegister(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
static void test_SysAppDcmdWriteSensorRegister_ErrorSysSetResponseCb(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    RetCode ret;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Check SYS_set_response_cb Error case
    SendDirectCommandResponse_ErrorSysSetResponseCb(s_sys_client, cmd_id, req_id, DcUnimplemented,
                                                    NULL, NULL);

    // Exec test target
    ret = SysAppDcmdWriteSensorRegister(cmd_id, req_id, param);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}
#endif

/*----------------------------------------------------------------------------*/

//
// DirectCommandRebootCallback()
//

/*----------------------------------------------------------------------------*/
static void test_DirectCommandRebootCallback_FullySuccess(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    bool expect_btn_fc_request = false;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // set SysAppBtnCheckFactoryResetRequest() return value
    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, expect_btn_fc_request);

    // Check UtilityLog function
    CheckDcmdRebootStartedUtilityLog();

    // Check SendDirectCommandResponseSync function
    SendDirectCommandResponseSync_FullSuccess(s_sys_client, cmd_id, req_id, DcOk, NULL, NULL);

    // Exec test target
    DirectCommandRebootCallback(s_sys_client, cmd_id, param, NULL);

    // Check global value
    assert_int_equal(s_terminate_request, RebootRequested);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_DirectCommandRebootCallback_ErrorParamsNull(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    bool expect_btn_fc_request = false;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // set SysAppBtnCheckFactoryResetRequest() return value
    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, expect_btn_fc_request);

    // Check UtilityLog function
    CheckDcmdRebootStartedUtilityLog();

    // Check SendDirectCommandResponseSync function
    SendDirectCommandResponseSync_FullSuccess(s_sys_client, cmd_id, req_id, DcOk, NULL, NULL);

    // Exec test target
    DirectCommandRebootCallback(s_sys_client, cmd_id, NULL, NULL);

    // Check global value
    assert_int_equal(s_terminate_request, RebootRequested);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_DirectCommandRebootCallback_ErrorCheckDirectCommandExecutableFactoryResetRequested(
    void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = FactoryResetRequested;

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcUnavailable, NULL,
                                               NULL);

    // Exec test target
    DirectCommandRebootCallback(s_sys_client, cmd_id, param, NULL);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void
    test_DirectCommandRebootCallback_ErrorCheckDirectCommandExecutableBtnFactoryResetRequested(
        void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    bool expect_btn_fc_request = true;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // set SysAppBtnCheckFactoryResetRequest() return value
    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, expect_btn_fc_request);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcUnavailable, NULL,
                                               NULL);

    // Exec test target
    DirectCommandRebootCallback(s_sys_client, cmd_id, param, NULL);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_DirectCommandRebootCallback_ErrorCheckDirectCommandExecutableRebootRequested(
    void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    bool expect_btn_fc_request = false;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = RebootRequested;

    // set SysAppBtnCheckFactoryResetRequest() return value
    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, expect_btn_fc_request);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcUnavailable, NULL,
                                               NULL);

    // Exec test target
    DirectCommandRebootCallback(s_sys_client, cmd_id, param, NULL);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/

//
// DirectCommandShutdownCallback()
//

/*----------------------------------------------------------------------------*/
static void test_DirectCommandShutdownCallback_FullySuccess(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    bool expect_btn_fc_request = false;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // set SysAppBtnCheckFactoryResetRequest() return value
    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, expect_btn_fc_request);

    // Check SendDirectCommandResponseSync function
    SendDirectCommandResponseSync_FullSuccess(s_sys_client, cmd_id, req_id, DcUnimplemented, NULL,
                                              NULL);

    // Exec test target
    DirectCommandShutdownCallback(s_sys_client, cmd_id, param, NULL);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_DirectCommandShutdownCallback_ErrorParamsNull(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    bool expect_btn_fc_request = false;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // set SysAppBtnCheckFactoryResetRequest() return value
    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, expect_btn_fc_request);

    // Check SendDirectCommandResponseSync function
    SendDirectCommandResponseSync_FullSuccess(s_sys_client, cmd_id, req_id, DcUnimplemented, NULL,
                                              NULL);

    // Exec test target
    DirectCommandShutdownCallback(s_sys_client, cmd_id, NULL, NULL);

    return;
}

/*----------------------------------------------------------------------------*/
static void
    test_DirectCommandShutdownCallback_ErrorCheckDirectCommandExecutableFactoryResetRequested(
        void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = FactoryResetRequested;

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcUnavailable, NULL,
                                               NULL);

    // Exec test target
    DirectCommandShutdownCallback(s_sys_client, cmd_id, param, NULL);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/

//
// DirectCommandFactoryResetCallback()
//

/*----------------------------------------------------------------------------*/
static void test_DirectCommandFactoryResetCallback_FullySuccess(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    bool expect_btn_fc_request = false;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // set SysAppBtnCheckFactoryResetRequest() return value
    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, expect_btn_fc_request);

    // Check SendDirectCommandResponseSync function
    SendDirectCommandResponseSync_FullSuccess(s_sys_client, cmd_id, req_id, DcOk, NULL, NULL);

    // Check UtilityLog function
    CheckDcmdFactoryResetFromConsoleStartedUtilityLog();

    expect_function_call(__wrap_EVP_undeployModules);
    will_return(__wrap_EVP_undeployModules, 1);

    // Exec test target
    DirectCommandFactoryResetCallback(s_sys_client, cmd_id, param, NULL);

    // Check global value
    assert_int_equal(s_terminate_request, FactoryResetRequested);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_DirectCommandFactoryResetCallback_ErrorParamsNull(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    bool expect_btn_fc_request = false;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // set SysAppBtnCheckFactoryResetRequest() return value
    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, expect_btn_fc_request);

    // Check SendDirectCommandResponseSync function
    SendDirectCommandResponseSync_FullSuccess(s_sys_client, cmd_id, req_id, DcOk, NULL, NULL);

    // Check UtilityLog function
    CheckDcmdFactoryResetFromConsoleStartedUtilityLog();

    expect_function_call(__wrap_EVP_undeployModules);
    will_return(__wrap_EVP_undeployModules, 1);

    // Exec test target
    DirectCommandFactoryResetCallback(s_sys_client, cmd_id, NULL, NULL);

    // Check global value
    assert_int_equal(s_terminate_request, FactoryResetRequested);

    return;
}

/*----------------------------------------------------------------------------*/
static void
    test_DirectCommandFactoryResetCallback_ErrorCheckDirectCommandExecutableFactoryResetRequested(
        void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = FactoryResetRequested;

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcUnavailable, NULL,
                                               NULL);

    // Exec test target
    DirectCommandFactoryResetCallback(s_sys_client, cmd_id, param, NULL);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/

//
// DirectCommandDirectGetImageCallback()
//

/*----------------------------------------------------------------------------*/
static void
    test_DirectCommandDirectGetImageCallback_ErrorCheckDirectCommandExecutableFactoryResetRequested(
        void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = FactoryResetRequested;

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcUnavailable, NULL,
                                               NULL);

    // Exec test target
    DirectCommandDirectGetImageCallback(s_sys_client, cmd_id, param, NULL);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_DirectCommandDirectGetImageCallback_FullySuccess(void **state)
{
    bool expect_btn_fc_request = false;

    SYS_response_id cmd_id = 777;
    const char *param = "test_param_string";

    EsfMemoryManagerHandle expect_b64_buf_handle = (EsfMemoryManagerHandle)0x13579000;
    EsfMemoryManagerHandle memmgr_handle_json = (EsfMemoryManagerHandle)0x98765432;
    uint32_t expect_b64_size = 4646;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // set SysAppBtnCheckFactoryResetRequest() return value
    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, expect_btn_fc_request);

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(param, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_None);

    // Check EncodeToJpeg and EncodeToBase64 (with handle)
    Execute_EncodePhaseWithHandle(expect_b64_buf_handle, kJpegInputRgbPlanar_8, expect_b64_size);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccessHandle(cmd_id, DcOk, SetImagePropertyHandle,
                                                     (void *)(uintptr_t)expect_b64_buf_handle,
                                                     expect_b64_size, memmgr_handle_json);

    // Exec test target
    DirectCommandDirectGetImageCallback(s_sys_client, cmd_id, param, NULL);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx
    ExecSysProcessEventForMemoryFreeHandle(memmgr_handle_json);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_DirectCommandDirectGetImageCallback_ErrorParamsNull(void **state)
{
    bool expect_btn_fc_request = false;

    SYS_response_id cmd_id = 777;

    EsfMemoryManagerHandle expect_b64_buf_handle = (EsfMemoryManagerHandle)0x13579000;
    EsfMemoryManagerHandle memmgr_handle_json = (EsfMemoryManagerHandle)0x98765432;
    uint32_t expect_b64_size = 4646;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // set SysAppBtnCheckFactoryResetRequest() return value
    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, expect_btn_fc_request);

    // Check UtilityLog function
    CheckDcmdDirectGetImageRequestStartedUtilityLog();

    // Check GetDirectGetImageParams function
    Execute_GetDirectGetImageParams(NULL, GetDirectGetImageParams_None);

    // Check GetOneFrame function
    Execute_GetOneFrame(GetOneFrame_None);

    // Check EncodeToJpeg and EncodeToBase64 (with handle)
    Execute_EncodePhaseWithHandle(expect_b64_buf_handle, kJpegInputRgbPlanar_8, expect_b64_size);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccessHandle(cmd_id, DcOk, SetImagePropertyHandle,
                                                     (void *)(uintptr_t)expect_b64_buf_handle,
                                                     expect_b64_size, memmgr_handle_json);

    // Exec test target
    DirectCommandDirectGetImageCallback(s_sys_client, cmd_id, NULL, NULL);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx
    ExecSysProcessEventForMemoryFreeHandle(memmgr_handle_json);

    return;
}

/*----------------------------------------------------------------------------*/

//
// DirectCommandReadSensorRegisterCallback()
//

/*----------------------------------------------------------------------------*/
static void test_DirectCommandReadSensorRegisterCallback_FullySuccess(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    bool expect_btn_fc_request = false;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // set SysAppBtnCheckFactoryResetRequest() return value
    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, expect_btn_fc_request);

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
    // mock oepration for SysAppDcmdReadSensorRegister()
    if (SysAppDcmdReadSensorRegisterCommon(cmd_id, req_id, param,
                                           SysAppDcmdReadSensorRegister_None) == false) {
        return;
    }
#else
    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcUnimplemented, NULL,
                                               NULL);
#endif

    // Exec test target
    DirectCommandReadSensorRegisterCallback(s_sys_client, cmd_id, param, NULL);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_DirectCommandReadSensorRegisterCallback_ErrorParamsNull(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    bool expect_btn_fc_request = false;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // set SysAppBtnCheckFactoryResetRequest() return value
    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, expect_btn_fc_request);

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
    // mock oepration for SysAppDcmdReadSensorRegister()
    if (SysAppDcmdReadSensorRegisterCommon(cmd_id, req_id, NULL,
                                           SysAppDcmdReadSensorRegister_None) == false) {
        return;
    }
#else
    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcUnimplemented, NULL,
                                               NULL);
#endif

    // Exec test target
    DirectCommandReadSensorRegisterCallback(s_sys_client, cmd_id, NULL, NULL);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void
    test_DirectCommandReadSensorRegisterCallback_ErrorCheckDirectCommandExecutableFactoryResetRequested(
        void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = FactoryResetRequested;

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcUnavailable, NULL,
                                               NULL);

    // Exec test target
    DirectCommandReadSensorRegisterCallback(s_sys_client, cmd_id, param, NULL);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/

//
// DirectCommandWriteSensorRegisterCallback()
//

/*----------------------------------------------------------------------------*/
static void test_DirectCommandWriteSensorRegisterCallback_FullySuccess(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    bool expect_btn_fc_request = false;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // set SysAppBtnCheckFactoryResetRequest() return value
    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, expect_btn_fc_request);

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
    // mock oepration for SysAppDcmdWriteSensorRegister()
    if (SysAppDcmdWriteSensorRegisterCommon(cmd_id, req_id, param,
                                            SysAppDcmdWriteSensorRegister_None) == false) {
        return;
    }
#else
    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcUnimplemented, NULL,
                                               NULL);
#endif

    // Exec test target
    DirectCommandWriteSensorRegisterCallback(s_sys_client, cmd_id, param, NULL);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_DirectCommandWriteSensorRegisterCallback_ErrorParamsNull(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    bool expect_btn_fc_request = false;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = UnDefined;

    // set SysAppBtnCheckFactoryResetRequest() return value
    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, expect_btn_fc_request);

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
    // mock oepration for SysAppDcmdWriteSensorRegister()
    if (SysAppDcmdWriteSensorRegisterCommon(cmd_id, req_id, NULL,
                                            SysAppDcmdWriteSensorRegister_None) == false) {
        return;
    }
#else
    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcUnimplemented, NULL,
                                               NULL);
#endif

    // Exec test target
    DirectCommandWriteSensorRegisterCallback(s_sys_client, cmd_id, NULL, NULL);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void
    test_DirectCommandWriteSensorRegisterCallback_ErrorCheckDirectCommandExecutableFactoryResetRequested(
        void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request = FactoryResetRequested;

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcUnavailable, NULL,
                                               NULL);

    // Exec test target
    DirectCommandWriteSensorRegisterCallback(s_sys_client, cmd_id, param, NULL);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/

//
// ResponseSendCompleteCallback()
//

/*----------------------------------------------------------------------------*/
static void test_ResponseSendCompleteCallback_FullySuccess(void **state)
{
    bool send_complete = false;
    DcResponseContext *dcres_ctx = NULL;
    dcres_ctx = (DcResponseContext *)malloc(sizeof(DcResponseContext));
    dcres_ctx->cmd_id = 777;
    dcres_ctx->response = strdup("Response_DC_Test");
    dcres_ctx->status_code = 0;
    dcres_ctx->retry_count = 0;
    dcres_ctx->send_complete = &send_complete;

    s_sys_client = (struct SYS_client *)0x98765432;

    // For free() of ctx->response
    will_return(mock_free, true);
    expect_value(mock_free, __ptr, dcres_ctx->response);

    // For free() of ctx
    will_return(mock_free, true);
    expect_value(mock_free, __ptr, dcres_ctx);

    // Exec test target
    ResponseSendCompleteCallback(s_sys_client, SYS_REASON_FINISHED, (void *)dcres_ctx);

    // Check output argument
    assert_true(send_complete);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ResponseSendCompleteCallback_ErrorContextNull(void **state)
{
    DcResponseContext *dcres_ctx = NULL;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Exec test target
    ResponseSendCompleteCallback(s_sys_client, SYS_REASON_FINISHED, (void *)dcres_ctx);

    return;
}

/*----------------------------------------------------------------------------*/

//
// ResponseSendCompleteCallbackHandle()
//

/*----------------------------------------------------------------------------*/
static void test_ResponseSendCompleteCallbackHandle_FullySuccess(void **state)
{
    bool send_complete = false;
    DcResponseContext *dcres_ctx = NULL;
    dcres_ctx = (DcResponseContext *)malloc(sizeof(DcResponseContext));
    dcres_ctx->cmd_id = 777;
    dcres_ctx->response = (void *)0x12345678;
    dcres_ctx->status_code = 0;
    dcres_ctx->retry_count = 0;
    dcres_ctx->send_complete = &send_complete;

    s_sys_client = (struct SYS_client *)0x98765432;

    // For FcloseAndFreeMemoryManagerHandle()
    FcloseAndFreeMemoryManagerHandleCommon((EsfMemoryManagerHandle)(uintptr_t)dcres_ctx->response,
                                           FcloseAndFreeMemoryManagerHandle_None);

    // For free() of ctx
    will_return(mock_free, true);
    expect_value(mock_free, __ptr, dcres_ctx);

    // Exec test target
    ResponseSendCompleteCallbackHandle(s_sys_client, SYS_REASON_FINISHED, (void *)dcres_ctx);

    // Check output argument
    assert_true(send_complete);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ResponseSendCompleteCallbackHandle_ErrorContextNull(void **state)
{
    DcResponseContext *dcres_ctx = NULL;

    s_sys_client = (struct SYS_client *)0x98765432;

    // Exec test target
    ResponseSendCompleteCallbackHandle(s_sys_client, SYS_REASON_FINISHED, (void *)dcres_ctx);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ResponseSendCompleteCallbackHandle_ErrorEsfMemoryManagerFclose(void **state)
{
    bool send_complete = false;
    DcResponseContext *dcres_ctx = NULL;
    dcres_ctx = (DcResponseContext *)malloc(sizeof(DcResponseContext));
    dcres_ctx->cmd_id = 777;
    dcres_ctx->response = (void *)0x12345678;
    dcres_ctx->status_code = 0;
    dcres_ctx->retry_count = 0;
    dcres_ctx->send_complete = &send_complete;

    s_sys_client = (struct SYS_client *)0x98765432;

    // For FcloseAndFreeMemoryManagerHandle()
    FcloseAndFreeMemoryManagerHandleCommon((EsfMemoryManagerHandle)(uintptr_t)dcres_ctx->response,
                                           FcloseAndFreeMemoryManagerHandle_Fclose);

    // For free() of ctx
    will_return(mock_free, true);
    expect_value(mock_free, __ptr, dcres_ctx);

    // Exec test target
    ResponseSendCompleteCallbackHandle(s_sys_client, SYS_REASON_FINISHED, (void *)dcres_ctx);

    // Check output argument
    assert_true(send_complete);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ResponseSendCompleteCallbackHandle_ErrorEsfMemoryManagerFree(void **state)
{
    bool send_complete = false;
    DcResponseContext *dcres_ctx = NULL;
    dcres_ctx = (DcResponseContext *)malloc(sizeof(DcResponseContext));
    dcres_ctx->cmd_id = 777;
    dcres_ctx->response = (void *)0x12345678;
    dcres_ctx->status_code = 0;
    dcres_ctx->retry_count = 0;
    dcres_ctx->send_complete = &send_complete;

    s_sys_client = (struct SYS_client *)0x98765432;

    // For FcloseAndFreeMemoryManagerHandle()
    FcloseAndFreeMemoryManagerHandleCommon((EsfMemoryManagerHandle)(uintptr_t)dcres_ctx->response,
                                           FcloseAndFreeMemoryManagerHandle_Free);

    // For free() of ctx
    will_return(mock_free, true);
    expect_value(mock_free, __ptr, dcres_ctx);

    // Exec test target
    ResponseSendCompleteCallbackHandle(s_sys_client, SYS_REASON_FINISHED, (void *)dcres_ctx);

    // Check output argument
    assert_true(send_complete);

    return;
}

/*----------------------------------------------------------------------------*/

//
// MakeJsonResInfo()
//

/*----------------------------------------------------------------------------*/
static void test_MakeJsonResInfo_FullySuccess(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    ResInfoContext ctx = {
        .res_id = "Test_Res_Id", .code = 13, .detail_msg = "MakeJsonResInfo_detail_msg"};
    RetCode ret;

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, handle_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, parent_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, NULL);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, ctx.code);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, ctx.detail_msg);
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    // Exec test target
    ret = MakeJsonResInfo(handle_val, parent_val, (void *)&ctx);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SetImageProperty()
//

/*----------------------------------------------------------------------------*/
static void test_SetImageProperty_FullySuccess(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_SetImageProperty";
    size_t param_size = 0;
    RetCode ret;

    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "image");
    expect_string(__wrap_SysAppCmnSetStringValue, string, string_expect);
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // Exec test target
    ret = SetImageProperty(handle_val, parent_val, (void *)string_expect, param_size);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetImageProperty_ErrorParamNull(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = NULL;
    size_t param_size = 0;
    RetCode ret;

    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "image");
    expect_string(__wrap_SysAppCmnSetStringValue, string, "");
    will_return(__wrap_SysAppCmnSetStringValue, kRetOk);

    // Exec test target
    ret = SetImageProperty(handle_val, parent_val, (void *)string_expect, param_size);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetImageProperty_ErrorSysAppCmnSetStringValue(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    const char *string_expect = "string_SetImageProperty";
    size_t param_size = 0;
    RetCode ret;

    expect_value(__wrap_SysAppCmnSetStringValue, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValue, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValue, key, "image");
    expect_string(__wrap_SysAppCmnSetStringValue, string, string_expect);
    will_return(__wrap_SysAppCmnSetStringValue, kRetMemoryError);

    // Exec test target
    ret = SetImageProperty(handle_val, parent_val, (void *)string_expect, param_size);

    // Check return value
    assert_int_equal(ret, kRetMemoryError);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SetImagePropertyHandle()
//

/*----------------------------------------------------------------------------*/
static void test_SetImagePropertyHandle_FullySuccess(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfMemoryManagerHandle expect_mm_handle = (EsfMemoryManagerHandle)0x24680000;
    size_t param_size = 99;
    RetCode ret;

    expect_value(__wrap_SysAppCmnSetStringValueHandle, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValueHandle, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValueHandle, key, "image");
    expect_value(__wrap_SysAppCmnSetStringValueHandle, mm_handle, expect_mm_handle);
    expect_value(__wrap_SysAppCmnSetStringValueHandle, size,
                 param_size - 1); // // "-1" means exclude null char
    will_return(__wrap_SysAppCmnSetStringValueHandle, kRetOk);

    // Exec test target
    ret = SetImagePropertyHandle(handle_val, parent_val, (void *)(uintptr_t)expect_mm_handle,
                                 param_size);

    // Check return value
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetImagePropertyHandle_ErrorParamNull(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfMemoryManagerHandle expect_mm_handle = (EsfMemoryManagerHandle)(uintptr_t)NULL;
    size_t param_size = 99;
    RetCode ret;

    // Exec test target
    ret = SetImagePropertyHandle(handle_val, parent_val, (void *)(uintptr_t)expect_mm_handle,
                                 param_size);

    // Check return value
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SetImagePropertyHandle_ErrorSysAppCmnSetStringValueHandle(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfMemoryManagerHandle expect_mm_handle = (EsfMemoryManagerHandle)(uintptr_t)0x24680000;
    size_t param_size = 99;
    RetCode ret;

    expect_value(__wrap_SysAppCmnSetStringValueHandle, handle, handle_val);
    expect_value(__wrap_SysAppCmnSetStringValueHandle, parent, parent_val);
    expect_string(__wrap_SysAppCmnSetStringValueHandle, key, "image");
    expect_value(__wrap_SysAppCmnSetStringValueHandle, mm_handle, expect_mm_handle);
    expect_value(__wrap_SysAppCmnSetStringValueHandle, size,
                 param_size - 1); // // "-1" means exclude null char
    will_return(__wrap_SysAppCmnSetStringValueHandle, kRetApiCallError);

    // Exec test target
    ret = SetImagePropertyHandle(handle_val, parent_val, (void *)(uintptr_t)expect_mm_handle,
                                 param_size);

    // Check return value
    assert_int_equal(ret, kRetApiCallError);

    return;
}

/*----------------------------------------------------------------------------*/

//
// Response2CodeAndDetailmsg()
//

/*----------------------------------------------------------------------------*/
static void test_Response2CodeAndDetailmsg_Ok(void **state)
{
    ResInfoContext ctx = {0};
    DcResult input_res = DcOk;
    int expect_code = 0;
    const char *expect_detail_msg = "ok";

    // Exec test target
    Response2CodeAndDetailmsg(input_res, &(ctx.code), ctx.detail_msg, sizeof(ctx.detail_msg));

    // Check output argument
    assert_int_equal(ctx.code, expect_code);
    assert_string_equal(ctx.detail_msg, expect_detail_msg);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_Response2CodeAndDetailmsg_Unknown(void **state)
{
    ResInfoContext ctx = {0};
    DcResult input_res = DcUnknown;
    int expect_code = 2;
    const char *expect_detail_msg = "unknown";

    // Exec test target
    Response2CodeAndDetailmsg(input_res, &(ctx.code), ctx.detail_msg, sizeof(ctx.detail_msg));

    // Check output argument
    assert_int_equal(ctx.code, expect_code);
    assert_string_equal(ctx.detail_msg, expect_detail_msg);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_Response2CodeAndDetailmsg_InvalidArgument(void **state)
{
    ResInfoContext ctx = {0};
    DcResult input_res = DcInvalidArgument;
    int expect_code = 3;
    const char *expect_detail_msg = "invalid_argument";

    // Exec test target
    Response2CodeAndDetailmsg(input_res, &(ctx.code), ctx.detail_msg, sizeof(ctx.detail_msg));

    // Check output argument
    assert_int_equal(ctx.code, expect_code);
    assert_string_equal(ctx.detail_msg, expect_detail_msg);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_Response2CodeAndDetailmsg_ResourceExhausted(void **state)
{
    ResInfoContext ctx = {0};
    DcResult input_res = DcResourceExhausted;
    int expect_code = 8;
    const char *expect_detail_msg = "resource_exhausted";

    // Exec test target
    Response2CodeAndDetailmsg(input_res, &(ctx.code), ctx.detail_msg, sizeof(ctx.detail_msg));

    // Check output argument
    assert_int_equal(ctx.code, expect_code);
    assert_string_equal(ctx.detail_msg, expect_detail_msg);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_Response2CodeAndDetailmsg_FailedPrecondition(void **state)
{
    ResInfoContext ctx = {0};
    DcResult input_res = DcFailedPreCondition;
    int expect_code = 9;
    const char *expect_detail_msg = "failed_precondition";

    // Exec test target
    Response2CodeAndDetailmsg(input_res, &(ctx.code), ctx.detail_msg, sizeof(ctx.detail_msg));

    // Check output argument
    assert_int_equal(ctx.code, expect_code);
    assert_string_equal(ctx.detail_msg, expect_detail_msg);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_Response2CodeAndDetailmsg_Aborted(void **state)
{
    ResInfoContext ctx = {0};
    DcResult input_res = DcAborted;
    int expect_code = 10;
    const char *expect_detail_msg = "aborted";

    // Exec test target
    Response2CodeAndDetailmsg(input_res, &(ctx.code), ctx.detail_msg, sizeof(ctx.detail_msg));

    // Check output argument
    assert_int_equal(ctx.code, expect_code);
    assert_string_equal(ctx.detail_msg, expect_detail_msg);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_Response2CodeAndDetailmsg_Unimplemented(void **state)
{
    ResInfoContext ctx = {0};
    DcResult input_res = DcUnimplemented;
    int expect_code = 12;
    const char *expect_detail_msg = "unimplemented";

    // Exec test target
    Response2CodeAndDetailmsg(input_res, &(ctx.code), ctx.detail_msg, sizeof(ctx.detail_msg));

    // Check output argument
    assert_int_equal(ctx.code, expect_code);
    assert_string_equal(ctx.detail_msg, expect_detail_msg);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_Response2CodeAndDetailmsg_Internal(void **state)
{
    ResInfoContext ctx = {0};
    DcResult input_res = DcInternal;
    int expect_code = 13;
    const char *expect_detail_msg = "internal";

    // Exec test target
    Response2CodeAndDetailmsg(input_res, &(ctx.code), ctx.detail_msg, sizeof(ctx.detail_msg));

    // Check output argument
    assert_int_equal(ctx.code, expect_code);
    assert_string_equal(ctx.detail_msg, expect_detail_msg);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_Response2CodeAndDetailmsg_Unavailable(void **state)
{
    ResInfoContext ctx = {0};
    DcResult input_res = DcUnavailable;
    int expect_code = 14;
    const char *expect_detail_msg = "unavailable";

    // Exec test target
    Response2CodeAndDetailmsg(input_res, &(ctx.code), ctx.detail_msg, sizeof(ctx.detail_msg));

    // Check output argument
    assert_int_equal(ctx.code, expect_code);
    assert_string_equal(ctx.detail_msg, expect_detail_msg);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_Response2CodeAndDetailmsg_Unauthenticated(void **state)
{
    ResInfoContext ctx = {0};
    DcResult input_res = DcUnauthenticated;
    int expect_code = 16;
    const char *expect_detail_msg = "unauthenticated";

    // Exec test target
    Response2CodeAndDetailmsg(input_res, &(ctx.code), ctx.detail_msg, sizeof(ctx.detail_msg));

    // Check output argument
    assert_int_equal(ctx.code, expect_code);
    assert_string_equal(ctx.detail_msg, expect_detail_msg);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_Response2CodeAndDetailmsg_Default(void **state)
{
    ResInfoContext ctx = {0};
    DcResult input_res = DcResultNum;
    int expect_code = 2;
    const char *expect_detail_msg = "unknown";

    // Exec test target
    Response2CodeAndDetailmsg(input_res, &(ctx.code), ctx.detail_msg, sizeof(ctx.detail_msg));

    // Check output argument
    assert_int_equal(ctx.code, expect_code);
    assert_string_equal(ctx.detail_msg, expect_detail_msg);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_Response2CodeAndDetailmsg_CheckLengthOk(void **state)
{
#define TEST_ARRAY_MAX_NUMBER 20

    ResInfoContext ctx = {0};
    DcResult input_res = DcOk;
    int expect_code = 0;
    const char *expect_detail_msg = "ok";
    char buff_name[TEST_ARRAY_MAX_NUMBER];
    int check_str_length = 2;

    // Initialize buff_name and expect_buff_name
    memset(buff_name, 'Z', sizeof(buff_name));
    memset(ctx.detail_msg, 'Z', sizeof(buff_name));

    // Generate expect_buff_name
    // Copy expect_detail_msg -> snprintf
    memcpy(buff_name, expect_detail_msg, check_str_length - 1);

    // Add Null
    buff_name[check_str_length - 1] = '\0';

    // Exec test target
    Response2CodeAndDetailmsg(input_res, &(ctx.code), ctx.detail_msg, check_str_length);

    // Check output argument
    assert_int_equal(ctx.code, expect_code);
    assert_memory_equal(ctx.detail_msg, buff_name, sizeof(buff_name));

    return;
}

/*----------------------------------------------------------------------------*/
static void test_Response2CodeAndDetailmsg_CheckLengthUnknown(void **state)
{
#define TEST_ARRAY_MAX_NUMBER 20

    ResInfoContext ctx = {0};
    DcResult input_res = DcUnknown;
    int expect_code = 2;
    const char *expect_detail_msg = "unknown";
    char buff_name[TEST_ARRAY_MAX_NUMBER];
    int check_str_length = 2;

    // Initialize buff_name and ctx.detail_msg
    memset(buff_name, 'Z', sizeof(buff_name));
    memset(ctx.detail_msg, 'Z', sizeof(buff_name));

    // Generate expect_buff_name
    // Copy expect_detail_msg -> snprintf
    memcpy(buff_name, expect_detail_msg, check_str_length - 1);

    // Add Null
    buff_name[check_str_length - 1] = '\0';

    // Exec test target
    Response2CodeAndDetailmsg(input_res, &(ctx.code), ctx.detail_msg, check_str_length);

    // Check output argument
    assert_int_equal(ctx.code, expect_code);
    assert_memory_equal(ctx.detail_msg, buff_name, sizeof(buff_name));

    return;
}

/*----------------------------------------------------------------------------*/
static void test_Response2CodeAndDetailmsg_CheckLengthInvalidArgument(void **state)
{
#define TEST_ARRAY_MAX_NUMBER 20

    ResInfoContext ctx = {0};
    DcResult input_res = DcInvalidArgument;
    int expect_code = 3;
    const char *expect_detail_msg = "invalid_argument";
    char buff_name[TEST_ARRAY_MAX_NUMBER];
    int check_str_length = 2;

    // Initialize buff_name and ctx.detail_msg
    memset(buff_name, 'Z', sizeof(buff_name));
    memset(ctx.detail_msg, 'Z', sizeof(buff_name));

    // Generate expect_buff_name
    // Copy expect_detail_msg -> snprintf
    memcpy(buff_name, expect_detail_msg, check_str_length - 1);

    // Add Null
    buff_name[check_str_length - 1] = '\0';

    // Exec test target
    Response2CodeAndDetailmsg(input_res, &(ctx.code), ctx.detail_msg, check_str_length);

    // Check output argument
    assert_int_equal(ctx.code, expect_code);
    assert_memory_equal(ctx.detail_msg, buff_name, sizeof(buff_name));

    return;
}

/*----------------------------------------------------------------------------*/
static void test_Response2CodeAndDetailmsg_CheckLengthResourceExhausted(void **state)
{
#define TEST_ARRAY_MAX_NUMBER 20

    ResInfoContext ctx = {0};
    DcResult input_res = DcResourceExhausted;
    int expect_code = 8;
    const char *expect_detail_msg = "resource_exhausted";
    char buff_name[TEST_ARRAY_MAX_NUMBER];
    int check_str_length = 2;

    // Initialize buff_name and ctx.detail_msg
    memset(buff_name, 'Z', sizeof(buff_name));
    memset(ctx.detail_msg, 'Z', sizeof(buff_name));

    // Generate expect_buff_name
    // Copy expect_detail_msg -> snprintf
    memcpy(buff_name, expect_detail_msg, check_str_length - 1);

    // Add Null
    buff_name[check_str_length - 1] = '\0';

    // Exec test target
    Response2CodeAndDetailmsg(input_res, &(ctx.code), ctx.detail_msg, check_str_length);

    // Check output argument
    assert_int_equal(ctx.code, expect_code);
    assert_memory_equal(ctx.detail_msg, buff_name, sizeof(buff_name));

    return;
}

/*----------------------------------------------------------------------------*/
static void test_Response2CodeAndDetailmsg_CheckLengthFailedPrecondition(void **state)
{
#define TEST_ARRAY_MAX_NUMBER 20

    ResInfoContext ctx = {0};
    DcResult input_res = DcFailedPreCondition;
    int expect_code = 9;
    const char *expect_detail_msg = "failed_precondition";
    char buff_name[TEST_ARRAY_MAX_NUMBER];
    int check_str_length = 2;

    // Initialize buff_name and ctx.detail_msg
    memset(buff_name, 'Z', sizeof(buff_name));
    memset(ctx.detail_msg, 'Z', sizeof(buff_name));

    // Generate expect_buff_name
    // Copy expect_detail_msg -> snprintf
    memcpy(buff_name, expect_detail_msg, check_str_length - 1);

    // Add Null
    buff_name[check_str_length - 1] = '\0';

    // Exec test target
    Response2CodeAndDetailmsg(input_res, &(ctx.code), ctx.detail_msg, check_str_length);

    // Check output argument
    assert_int_equal(ctx.code, expect_code);
    assert_memory_equal(ctx.detail_msg, buff_name, sizeof(buff_name));

    return;
}

/*----------------------------------------------------------------------------*/
static void test_Response2CodeAndDetailmsg_CheckLengthAborted(void **state)
{
#define TEST_ARRAY_MAX_NUMBER 20

    ResInfoContext ctx = {0};
    DcResult input_res = DcAborted;
    int expect_code = 10;
    const char *expect_detail_msg = "aborted";
    char buff_name[TEST_ARRAY_MAX_NUMBER];
    int check_str_length = 2;

    // Initialize buff_name and ctx.detail_msg
    memset(buff_name, 'Z', sizeof(buff_name));
    memset(ctx.detail_msg, 'Z', sizeof(buff_name));

    // Generate expect_buff_name
    // Copy expect_detail_msg -> snprintf
    memcpy(buff_name, expect_detail_msg, check_str_length - 1);

    // Add Null
    buff_name[check_str_length - 1] = '\0';

    // Exec test target
    Response2CodeAndDetailmsg(input_res, &(ctx.code), ctx.detail_msg, check_str_length);

    // Check output argument
    assert_int_equal(ctx.code, expect_code);
    assert_memory_equal(ctx.detail_msg, buff_name, sizeof(buff_name));

    return;
}

/*----------------------------------------------------------------------------*/
static void test_Response2CodeAndDetailmsg_CheckLengthUnimplemented(void **state)
{
#define TEST_ARRAY_MAX_NUMBER 20

    ResInfoContext ctx = {0};
    DcResult input_res = DcUnimplemented;
    int expect_code = 12;
    const char *expect_detail_msg = "unimplemented";
    char buff_name[TEST_ARRAY_MAX_NUMBER];
    int check_str_length = 2;

    // Initialize buff_name and ctx.detail_msg
    memset(buff_name, 'Z', sizeof(buff_name));
    memset(ctx.detail_msg, 'Z', sizeof(buff_name));

    // Generate expect_buff_name
    // Copy expect_detail_msg -> snprintf
    memcpy(buff_name, expect_detail_msg, check_str_length - 1);

    // Add Null
    buff_name[check_str_length - 1] = '\0';

    // Exec test target
    Response2CodeAndDetailmsg(input_res, &(ctx.code), ctx.detail_msg, check_str_length);

    // Check output argument
    assert_int_equal(ctx.code, expect_code);
    assert_memory_equal(ctx.detail_msg, buff_name, sizeof(buff_name));

    return;
}

/*----------------------------------------------------------------------------*/
static void test_Response2CodeAndDetailmsg_CheckLengthInternal(void **state)
{
#define TEST_ARRAY_MAX_NUMBER 20

    ResInfoContext ctx = {0};
    DcResult input_res = DcInternal;
    int expect_code = 13;
    const char *expect_detail_msg = "internal";
    char buff_name[TEST_ARRAY_MAX_NUMBER];
    int check_str_length = 2;

    // Initialize buff_name and ctx.detail_msg
    memset(buff_name, 'Z', sizeof(buff_name));
    memset(ctx.detail_msg, 'Z', sizeof(buff_name));

    // Generate expect_buff_name
    // Copy expect_detail_msg -> snprintf
    memcpy(buff_name, expect_detail_msg, check_str_length - 1);

    // Add Null
    buff_name[check_str_length - 1] = '\0';

    // Exec test target
    Response2CodeAndDetailmsg(input_res, &(ctx.code), ctx.detail_msg, check_str_length);

    // Check output argument
    assert_int_equal(ctx.code, expect_code);
    assert_memory_equal(ctx.detail_msg, buff_name, sizeof(buff_name));

    return;
}

/*----------------------------------------------------------------------------*/
static void test_Response2CodeAndDetailmsg_CheckLengthUnavailable(void **state)
{
#define TEST_ARRAY_MAX_NUMBER 20

    ResInfoContext ctx = {0};
    DcResult input_res = DcUnavailable;
    int expect_code = 14;
    const char *expect_detail_msg = "unavailable";
    char buff_name[TEST_ARRAY_MAX_NUMBER];
    int check_str_length = 2;

    // Initialize buff_name and ctx.detail_msg
    memset(buff_name, 'Z', sizeof(buff_name));
    memset(ctx.detail_msg, 'Z', sizeof(buff_name));

    // Generate expect_buff_name
    // Copy expect_detail_msg -> snprintf
    memcpy(buff_name, expect_detail_msg, check_str_length - 1);

    // Add Null
    buff_name[check_str_length - 1] = '\0';

    // Exec test target
    Response2CodeAndDetailmsg(input_res, &(ctx.code), ctx.detail_msg, check_str_length);

    // Check output argument
    assert_int_equal(ctx.code, expect_code);
    assert_memory_equal(ctx.detail_msg, buff_name, sizeof(buff_name));

    return;
}

/*----------------------------------------------------------------------------*/
static void test_Response2CodeAndDetailmsg_CheckLengthUnauthenticated(void **state)
{
#define TEST_ARRAY_MAX_NUMBER 20

    ResInfoContext ctx = {0};
    DcResult input_res = DcUnauthenticated;
    int expect_code = 16;
    const char *expect_detail_msg = "unauthenticated";
    char buff_name[TEST_ARRAY_MAX_NUMBER];
    int check_str_length = 2;

    // Initialize buff_name and ctx.detail_msg
    memset(buff_name, 'Z', sizeof(buff_name));
    memset(ctx.detail_msg, 'Z', sizeof(buff_name));

    // Generate expect_buff_name
    // Copy expect_detail_msg -> snprintf
    memcpy(buff_name, expect_detail_msg, check_str_length - 1);

    // Add Null
    buff_name[check_str_length - 1] = '\0';

    // Exec test target
    Response2CodeAndDetailmsg(input_res, &(ctx.code), ctx.detail_msg, check_str_length);

    // Check output argument
    assert_int_equal(ctx.code, expect_code);
    assert_memory_equal(ctx.detail_msg, buff_name, sizeof(buff_name));

    return;
}

/*----------------------------------------------------------------------------*/
static void test_Response2CodeAndDetailmsg_CheckLengthDefault(void **state)
{
#define TEST_ARRAY_MAX_NUMBER 20

    ResInfoContext ctx = {0};
    DcResult input_res = DcResultNum;
    int expect_code = 2;
    const char *expect_detail_msg = "unknown";
    char buff_name[TEST_ARRAY_MAX_NUMBER];
    int check_str_length = 2;

    // Initialize buff_name and ctx.detail_msg
    memset(buff_name, 'Z', sizeof(buff_name));
    memset(ctx.detail_msg, 'Z', sizeof(buff_name));

    // Generate expect_buff_name
    // Copy expect_detail_msg -> snprintf
    memcpy(buff_name, expect_detail_msg, check_str_length - 1);

    // Add Null
    buff_name[check_str_length - 1] = '\0';

    // Exec test target
    Response2CodeAndDetailmsg(input_res, &(ctx.code), ctx.detail_msg, check_str_length);

    // Check output argument
    assert_int_equal(ctx.code, expect_code);
    assert_memory_equal(ctx.detail_msg, buff_name, sizeof(buff_name));

    return;
}

/*----------------------------------------------------------------------------*/

//
// SendDirectCommandResponse()
//

/*----------------------------------------------------------------------------*/
static void test_SendDirectCommandResponse_FullySuccessHandle(void **state)
{
    RetCode ret;
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    DcResult dc_result = DcOk;
    EsfMemoryManagerHandle memmgr_handle_json = (EsfMemoryManagerHandle)0x98765432;
    EsfMemoryManagerHandle memmgr_handle_additional_param = (EsfMemoryManagerHandle)0x10293847;

    s_sys_client = (struct SYS_client *)0x78945612;

    // Check SendDirectCommandResponse
    SendDirectCommandResponseAsync_FullSuccessHandle(
        cmd_id, dc_result, NULL, (void *)(uintptr_t)memmgr_handle_additional_param, 0,
        memmgr_handle_json);

    // Exec test target
    ret = SendDirectCommandResponse(s_sys_client, cmd_id, req_id, dc_result, NULL,
                                    (void *)(uintptr_t)memmgr_handle_additional_param, 0, true,
                                    false);

    // Check return value
    assert_int_equal(ret, kRetOk);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx
    ExecSysProcessEventForMemoryFreeHandle(memmgr_handle_json);
}

/*----------------------------------------------------------------------------*/
static void test_SendDirectCommandResponse_ErrorEsfMemoryManagerAllocate(void **state)
{
    RetCode ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    DcResult dc_result = DcOk;
    size_t json_buf_size = 2468;
    EsfMemoryManagerHandle memmgr_handle_json = (EsfMemoryManagerHandle)0x98765432;
    EsfMemoryManagerHandle memmgr_handle_additional_param = (EsfMemoryManagerHandle)0x10293847;

    s_sys_client = (struct SYS_client *)0x78945612;

    // mock operation
    will_return(__wrap_EsfJsonOpen, json_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectInit, handle, json_handle);
    will_return(__wrap_EsfJsonObjectInit, json_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, json_handle);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, json_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, json_handle);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, json_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, NULL);

    Response2CodeAndDetailmsgForTest(dc_result);

    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerializeSizeGet, handle, json_handle);
    expect_value(__wrap_EsfJsonSerializeSizeGet, value, json_val);
    will_return(__wrap_EsfJsonSerializeSizeGet,
                json_buf_size - 1); // "-1" means terminate null string

    AllocateAndFopenMemoryManagerHandleCommon(memmgr_handle_json, json_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_Allocate);

    expect_value(__wrap_EsfJsonClose, handle, json_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    FcloseAndFreeMemoryManagerHandleCommon(memmgr_handle_additional_param,
                                           FcloseAndFreeMemoryManagerHandle_None);

    // Exec test target
    ret = SendDirectCommandResponse(s_sys_client, cmd_id, req_id, dc_result, NULL,
                                    (void *)(uintptr_t)memmgr_handle_additional_param, 0, true,
                                    false);

    // Check return value
    assert_int_equal(ret, kRetFailed);
}

/*----------------------------------------------------------------------------*/
static void test_SendDirectCommandResponse_ErrorEsfJsonSerializeHandle(void **state)
{
    RetCode ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    DcResult dc_result = DcOk;
    size_t json_buf_size = 2468;
    size_t json_serialize_size = 3579;
    EsfMemoryManagerHandle memmgr_handle_json = (EsfMemoryManagerHandle)0x98765432;
    EsfMemoryManagerHandle memmgr_handle_additional_param = (EsfMemoryManagerHandle)0x10293847;

    s_sys_client = (struct SYS_client *)0x78945612;

    // mock operation
    will_return(__wrap_EsfJsonOpen, json_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectInit, handle, json_handle);
    will_return(__wrap_EsfJsonObjectInit, json_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, json_handle);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, json_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, json_handle);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, json_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, NULL);

    Response2CodeAndDetailmsgForTest(dc_result);

    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerializeSizeGet, handle, json_handle);
    expect_value(__wrap_EsfJsonSerializeSizeGet, value, json_val);
    will_return(__wrap_EsfJsonSerializeSizeGet,
                json_buf_size - 1); // "-1" means terminate null string

    AllocateAndFopenMemoryManagerHandleCommon(memmgr_handle_json, json_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    expect_value(__wrap_EsfJsonSerializeHandle, handle, json_handle);
    expect_value(__wrap_EsfJsonSerializeHandle, value, json_val);
    expect_value(__wrap_EsfJsonSerializeHandle, mem_handle, memmgr_handle_json);
    will_return(__wrap_EsfJsonSerializeHandle, json_serialize_size);
    will_return(__wrap_EsfJsonSerializeHandle, kEsfJsonInternalError);

    FcloseAndFreeMemoryManagerHandleCommon(memmgr_handle_json,
                                           FcloseAndFreeMemoryManagerHandle_None);

    expect_value(__wrap_EsfJsonClose, handle, json_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    FcloseAndFreeMemoryManagerHandleCommon(memmgr_handle_additional_param,
                                           FcloseAndFreeMemoryManagerHandle_None);

    // Exec test target
    ret = SendDirectCommandResponse(s_sys_client, cmd_id, req_id, dc_result, NULL,
                                    (void *)(uintptr_t)memmgr_handle_additional_param, 0, true,
                                    false);

    // Check return value
    assert_int_equal(ret, kRetFailed);
}

/*----------------------------------------------------------------------------*/
static void test_SendDirectCommandResponse_InvalidHandleEsfMemoryManagerAllocate(void **state)
{
    RetCode ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    DcResult dc_result = DcOk;
    size_t json_buf_size = 2468;
    size_t json_serialize_size = 3579;
    EsfMemoryManagerHandle memmgr_handle_json = (EsfMemoryManagerHandle)0;
    EsfMemoryManagerHandle memmgr_handle_additional_param = (EsfMemoryManagerHandle)0x10293847;

    s_sys_client = (struct SYS_client *)0x98765432;

    // mock operation
    will_return(__wrap_EsfJsonOpen, json_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectInit, handle, json_handle);
    will_return(__wrap_EsfJsonObjectInit, json_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, json_handle);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, json_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, json_handle);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, json_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, NULL);

    Response2CodeAndDetailmsgForTest(dc_result);

    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerializeSizeGet, handle, json_handle);
    expect_value(__wrap_EsfJsonSerializeSizeGet, value, json_val);
    will_return(__wrap_EsfJsonSerializeSizeGet,
                json_buf_size - 1); // "-1" means terminate null string

    AllocateAndFopenMemoryManagerHandleCommon(memmgr_handle_json, json_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    expect_value(__wrap_EsfJsonSerializeHandle, handle, json_handle);
    expect_value(__wrap_EsfJsonSerializeHandle, value, json_val);
    expect_value(__wrap_EsfJsonSerializeHandle, mem_handle, memmgr_handle_json);
    will_return(__wrap_EsfJsonSerializeHandle, json_serialize_size);
    will_return(__wrap_EsfJsonSerializeHandle, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonClose, handle, json_handle);
    FcloseAndFreeMemoryManagerHandleCommon(memmgr_handle_json,
                                           FcloseAndFreeMemoryManagerHandle_None);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    FcloseAndFreeMemoryManagerHandleCommon(memmgr_handle_additional_param,
                                           FcloseAndFreeMemoryManagerHandle_None);

    // Exec test target
    ret = SendDirectCommandResponse(s_sys_client, cmd_id, req_id, dc_result, NULL,
                                    (void *)(uintptr_t)memmgr_handle_additional_param, 0, true,
                                    false);

    // Check return value
    assert_int_equal(ret, kRetFailed);
}

/*----------------------------------------------------------------------------*/
static void test_SendDirectCommandResponse_ErrorSendDirectCommandResponseCore(void **state)
{
    RetCode ret;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    DcResult dc_result = DcOk;
    size_t json_buf_size = 2468;
    size_t json_serialize_size = 3579;
    EsfMemoryManagerHandle memmgr_handle_json = (EsfMemoryManagerHandle)0x98765432;
    EsfMemoryManagerHandle memmgr_handle_additional_param = (EsfMemoryManagerHandle)0x10293847;

    s_sys_client = (struct SYS_client *)0x78945612;

    // mock operation
    will_return(__wrap_EsfJsonOpen, json_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectInit, handle, json_handle);
    will_return(__wrap_EsfJsonObjectInit, json_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, json_handle);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, json_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, json_handle);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, json_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, NULL);

    Response2CodeAndDetailmsgForTest(dc_result);

    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerializeSizeGet, handle, json_handle);
    expect_value(__wrap_EsfJsonSerializeSizeGet, value, json_val);
    will_return(__wrap_EsfJsonSerializeSizeGet,
                json_buf_size - 1); // "-1" means terminate null string

    AllocateAndFopenMemoryManagerHandleCommon(memmgr_handle_json, json_buf_size,
                                              AllocateAndFopenMemoryManagerHandle_None);

    expect_value(__wrap_EsfJsonSerializeHandle, handle, json_handle);
    expect_value(__wrap_EsfJsonSerializeHandle, value, json_val);
    expect_value(__wrap_EsfJsonSerializeHandle, mem_handle, memmgr_handle_json);
    will_return(__wrap_EsfJsonSerializeHandle, json_serialize_size);
    will_return(__wrap_EsfJsonSerializeHandle, kEsfJsonSuccess);

    will_return(mock_malloc, true);
    will_return(mock_malloc, false);
    expect_value(mock_malloc, __size, sizeof(DcResponseContext));

    FcloseAndFreeMemoryManagerHandleCommon(memmgr_handle_json,
                                           FcloseAndFreeMemoryManagerHandle_None);

    expect_value(__wrap_EsfJsonClose, handle, json_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    FcloseAndFreeMemoryManagerHandleCommon(memmgr_handle_additional_param,
                                           FcloseAndFreeMemoryManagerHandle_None);

    // Exec test target
    ret = SendDirectCommandResponse(s_sys_client, cmd_id, req_id, dc_result, NULL,
                                    (void *)(uintptr_t)memmgr_handle_additional_param, 0, true,
                                    false);

    // Check return value
    assert_int_equal(ret, kRetMemoryError);
}

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
/*----------------------------------------------------------------------------*/
static void test_DirectCommandUnimplementedCallback_FullySuccess(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    bool expect_btn_fc_request = false;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request =
        UnDefined; // Set to normal state so CheckDirectCommandExecutable returns true

    // set SysAppBtnCheckFactoryResetRequest() return value
    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, expect_btn_fc_request);

    // Check SendDirectCommandResponseAsync function
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcUnimplemented, NULL,
                                               NULL);

    // Exec test target
    DirectCommandUnimplementedCallback(s_sys_client, cmd_id, param, NULL);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_DirectCommandUnimplementedCallback_paramsNull(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = NULL;
    bool expect_btn_fc_request = false;

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request =
        UnDefined; // Set to normal state so CheckDirectCommandExecutable returns true

    // set SysAppBtnCheckFactoryResetRequest() return value
    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, expect_btn_fc_request);

    // Check SendDirectCommandResponseAsync
    SendDirectCommandResponseAsync_FullSuccess(s_sys_client, cmd_id, req_id, DcUnimplemented, NULL,
                                               NULL);

    // Exec test target
    DirectCommandUnimplementedCallback(s_sys_client, cmd_id, param, NULL);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_DirectCommandUnimplementedCallback_DirectCommandCallbackCommonFailure(void **state)
{
    SYS_response_id cmd_id = 777;
    const char *req_id = "No.4680";
    const char *param = "test_param_string";
    bool expect_btn_fc_request = true; // Set to make CheckDirectCommandExecutable return false

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request =
        FactoryResetRequested; // Set to error state so CheckDirectCommandExecutable returns false

    // Check SendDirectCommandResponseAsync
    SendDirectCommandResponseAsync_FullSuccess(
        s_sys_client, cmd_id, req_id,
        DcUnavailable, // DirectCommandCallbackCommon sends DcUnavailable when busy
        NULL, NULL);

    // Exec test target
    DirectCommandUnimplementedCallback(s_sys_client, cmd_id, param, NULL);

    // Exec SYS_process_event() to free allocate memory for dcres_ctx and dcres_ctx->response
    ExecSysProcessEventForMemoryFree();

    // Reset s_terminate_request after test
    s_terminate_request = UnDefined;

    return;
}

/*----------------------------------------------------------------------------*/
static void test_DirectCommandUnimplementedCallback_SendDirectCommandResponseAsyncError(
    void **state)
{
    SYS_response_id cmd_id = 777;
    const char *param = "test_param_string";
    bool expect_btn_fc_request = false;
    EsfJsonHandle json_handle = (EsfJsonHandle)0x12345678;
    EsfJsonValue json_val = 1357;
    size_t json_buf_size = 2468;
    size_t json_serialize_size = 3579;
    const char *string_expect = "string_serialize_value";

    s_sys_client = (struct SYS_client *)0x98765432;
    s_terminate_request =
        UnDefined; // Set to normal state so CheckDirectCommandExecutable returns true

    // set SysAppBtnCheckFactoryResetRequest() return value
    will_return(__wrap_SysAppBtnCheckFactoryResetRequest, expect_btn_fc_request);

    // Mock operations to reach SYS_set_response_cb and make it fail
    will_return(__wrap_EsfJsonOpen, json_handle);
    will_return(__wrap_EsfJsonOpen, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectInit, handle, json_handle);
    will_return(__wrap_EsfJsonObjectInit, json_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(__wrap_SysAppCmnSetObjectValue, handle, json_handle);
    expect_value(__wrap_SysAppCmnSetObjectValue, parent, json_val);
    expect_string(__wrap_SysAppCmnSetObjectValue, key, "res_info");
    expect_value(__wrap_SysAppCmnSetObjectValue, make_json, MakeJsonResInfo);
    expect_not_value(__wrap_SysAppCmnSetObjectValue, ctx, NULL);
    will_return(__wrap_SysAppCmnSetObjectValue, true);
    will_return(__wrap_SysAppCmnSetObjectValue, kRetOk);

    expect_value(__wrap_SysAppCmnMakeJsonResInfo, handle, json_handle);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, root, json_val);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, res_id, NULL);
    expect_value(__wrap_SysAppCmnMakeJsonResInfo, code, 12);
    expect_string(__wrap_SysAppCmnMakeJsonResInfo, detail_msg, "unimplemented");
    will_return(__wrap_SysAppCmnMakeJsonResInfo, kRetOk);

    expect_value(__wrap_EsfJsonSerialize, handle, json_handle);
    expect_value(__wrap_EsfJsonSerialize, value, json_val);
    will_return(__wrap_EsfJsonSerialize, string_expect);
    will_return(__wrap_EsfJsonSerialize, kEsfJsonSuccess);

    // Setup strdup to succeed without parameter check
    will_return(mock_strdup, false); // Disable parameter check
    will_return(mock_strdup, true);  // Return string for strdup

    // Setup malloc to succeed
    will_return(mock_malloc, true); // Enable parameter check
    will_return(mock_malloc, true); // Return success for malloc
    expect_value(mock_malloc, __size, sizeof(DcResponseContext));

    // Make SYS_set_response_cb fail to trigger the error handling
    expect_value(__wrap_SYS_set_response_cb, c, s_sys_client);
    expect_value(__wrap_SYS_set_response_cb, id, cmd_id);
    expect_string(__wrap_SYS_set_response_cb, response, string_expect);
    expect_value(__wrap_SYS_set_response_cb, status, SYS_RESPONSE_STATUS_OK);
    expect_value(__wrap_SYS_set_response_cb, cb, ResponseSendCompleteCallback);
    expect_not_value(__wrap_SYS_set_response_cb, user, NULL);
    will_return(__wrap_SYS_set_response_cb, SYS_RESULT_ERRNO); // Make it fail

    // For free() of response after error
    will_return(mock_free, false);

    // For free() of dcres_ctx after error
    will_return(mock_free, false);

    expect_value(__wrap_EsfJsonClose, handle, json_handle);
    will_return(__wrap_EsfJsonClose, kEsfJsonSuccess);

    // Exec test target
    DirectCommandUnimplementedCallback(s_sys_client, cmd_id, param, NULL);

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
        cmocka_unit_test(test_SysAppDcmd_InitialValueOfGlobalVariable),

        // SysAppDcmdInitialize
        cmocka_unit_test(test_SysAppDcmdInitialize_FullySuccess),
        cmocka_unit_test(test_SysAppDcmdInitialize_ErrorEvpHandleNull),
        cmocka_unit_test(test_SysAppDcmdInitialize_ErrorRegisterDirectCommandRebootCallback),
        cmocka_unit_test(test_SysAppDcmdInitialize_ErrorRegisterDirectCommandShutdownCallback),
        cmocka_unit_test(test_SysAppDcmdInitialize_ErrorRegisterDirectCommandFactoryResetCallback),
        cmocka_unit_test(
            test_SysAppDcmdInitialize_ErrorRegisterDirectCommandDirectGetImageCallback),
        cmocka_unit_test(
            test_SysAppDcmdInitialize_ErrorRegisterDirectCommandReadSensorRegisterCallback),
        cmocka_unit_test(
            test_SysAppDcmdInitialize_ErrorRegisterDirectCommandWriteSensorRegisterCallback),

        // SysAppDcmdFinalize
        cmocka_unit_test(test_SysAppDcmdFinalize_FullySuccess),

        // SysAppDcmdCheckSelfTerminate
        cmocka_unit_test(test_SysAppDcmdCheckSelfTerminate_RebootRequested),
        cmocka_unit_test(test_SysAppDcmdCheckSelfTerminate_FactoryResetRequested),
        cmocka_unit_test(test_SysAppDcmdCheckSelfTerminate_FactoryResetButtonRequested),
        cmocka_unit_test(test_SysAppDcmdCheckSelfTerminate_UnDefined),
        cmocka_unit_test(test_SysAppDcmdCheckSelfTerminate_TerminationReasonNum),

        // SysAppDcmdRebootCore
        cmocka_unit_test(test_SysAppDcmdRebootCore_FullySuccess),
        cmocka_unit_test(test_SysAppDcmdRebootCore_ErrorEsfPwrMgrPrepareReboot),

        // SysAppDcmdReboot
        cmocka_unit_test(test_SysAppDcmdReboot_FullySuccess),
        cmocka_unit_test(test_SysAppDcmdReboot_MaxResponseLogStr),
        cmocka_unit_test(test_SysAppDcmdReboot_OverResponseLogStr),
        cmocka_unit_test(test_SysAppDcmdReboot_ErrorEsfJsonOpen),
        cmocka_unit_test(test_SysAppDcmdReboot_ErrorEsfJsonObjectInit),
        cmocka_unit_test(test_SysAppDcmdReboot_ErrorSysAppCmnSetObjectValue),
        cmocka_unit_test(test_SysAppDcmdReboot_ErrorEsfJsonSerialize),
        cmocka_unit_test(test_SysAppDcmdReboot_ErrorEsfJsonSerializeNull),
        cmocka_unit_test(test_SysAppDcmdReboot_ErrorStrdup),
        cmocka_unit_test(test_SysAppDcmdReboot_ErrorMalloc),
        cmocka_unit_test(test_SysAppDcmdReboot_ErrorSysSetResponseCb),
        cmocka_unit_test(test_SysAppDcmdReboot_ErrorSysProcessEvent),
        cmocka_unit_test(test_SysAppDcmdReboot_ErrorEsfJsonClose),

        // SysAppDcmdShutdown
        cmocka_unit_test(test_SysAppDcmdShutdown_FullySuccess),
        cmocka_unit_test(test_SysAppDcmdShutdown_ErrorSysSetResponseCb),

        // SysAppDcmdFactoryResetCore
        cmocka_unit_test(test_SysAppDcmdFactoryResetCore_FullySuccess),
        cmocka_unit_test(test_SysAppDcmdFactoryResetCore_ErrorEsfFwMgrStartFactoryReset),

        // SysAppDcmdFactoryReset
        cmocka_unit_test(test_SysAppDcmdFactoryReset_FullySuccess),
        cmocka_unit_test(test_SysAppDcmdFactoryReset_ErrorSysSetResponseCb),
        cmocka_unit_test(test_SysAppDcmdFactoryReset_ErrorEvpUndeployModules),

        // SysAppDcmdDirectGetImage
        cmocka_unit_test(test_SysAppDcmdDirectGetImage_FullySuccess),
        cmocka_unit_test(test_SysAppDcmdDirectGetImage_ErrorSysSetResponseCb),
        cmocka_unit_test(test_SysAppDcmdDirectGetImage_ErrorGetDirectGetImageParamsEsfJsonOpen),
        cmocka_unit_test(
            test_SysAppDcmdDirectGetImage_ErrorGetDirectGetImageParamsEsfJsonDeserialize),
        cmocka_unit_test(test_SysAppDcmdDirectGetImage_GetDirectGetImageParamsNetworkIdNoKey),
        cmocka_unit_test(test_SysAppDcmdDirectGetImage_GetDirectGetImageParamsNetworkIdNullStr),
        cmocka_unit_test(test_SysAppDcmdDirectGetImage_GetDirectGetImageParamsNetworkIdMaxOver),
        cmocka_unit_test(test_SysAppDcmdDirectGetImage_GetDirectGetImageParamsNetworkIdMax),
        cmocka_unit_test(test_SysAppDcmdDirectGetImage_GetDirectGetImageParamsNetworkIdInvalidKey),
        cmocka_unit_test(test_SysAppDcmdDirectGetImage_ErrorGetDirectGetImageParamsEsfJsonClose),
        cmocka_unit_test(test_SysAppDcmdDirectGetImage_ErrorGetOneFrameSysAppStateGetSensCordId),
        cmocka_unit_test(
            test_SysAppDcmdDirectGetImage_ErrorGetOneFrameSysAppStateGetSensCordStream),
        cmocka_unit_test(
            test_SysAppDcmdDirectGetImage_ErrorGetOneFrameSenscordStreamSetPropertyAiModel),
        cmocka_unit_test(
            test_SysAppDcmdDirectGetImage_ErrorGetOneFrameSenscordStreamSetPropertyInputData),
        cmocka_unit_test(
            test_SysAppDcmdDirectGetImage_ErrorGetOneFrameSenscordStreamSetPropertyImageProp),
        cmocka_unit_test(test_SysAppDcmdDirectGetImage_ErrorGetOneFrameGetFormatOfImage),
        cmocka_unit_test(test_SysAppDcmdDirectGetImage_ErrorGetOneFrameSenscordStreamStart),
        cmocka_unit_test(test_SysAppDcmdDirectGetImage_ErrorGetOneFrameSenscordStreamGetFrame),
        cmocka_unit_test(
            test_SysAppDcmdDirectGetImage_ErrorGetOneFrameSenscordFrameGetChannelFromChannelId),
        cmocka_unit_test(test_SysAppDcmdDirectGetImage_ErrorGetOneFrameSenscordChannelGetRawData),
        cmocka_unit_test(
            test_SysAppDcmdDirectGetImage_ErrorAllocateAndFopenMemoryManagerHandleForEncodeToJpeg),
        cmocka_unit_test(
            test_SysAppDcmdDirectGetImage_ErrorEncodeToJpegEsfCodecJpegEncodeBuffSizeMaxOver),
        cmocka_unit_test(
            test_SysAppDcmdDirectGetImage_FullySuccessEncodeToJpegEsfCodecJpegEncodeBuffSizeMax),
        cmocka_unit_test(
            test_SysAppDcmdDirectGetImage_ErrorEncodeToJpegEsfCodecJpegEncodeBufferFull),
        cmocka_unit_test(
            test_SysAppDcmdDirectGetImage_ErrorEncodeToJpegEsfCodecJpegEncodeRetryOver),
        cmocka_unit_test(test_SysAppDcmdDirectGetImage_ErrorEncodeToJpegEsfCodecJpegEncodeOther),
        cmocka_unit_test(
            test_SysAppDcmdDirectGetImage_FullySuccessEncodeToJpegErrorEsfMemoryManagerFseek),
        cmocka_unit_test(
            test_SysAppDcmdDirectGetImage_ErrorAllocateAndFopenMemoryManagerHandleForEncodeToBase64),
        cmocka_unit_test(
            test_SysAppDcmdDirectGetImage_ErrorEncodeToBase64EsfCodecBase64EncodeHandle),
        cmocka_unit_test(
            test_SysAppDcmdDirectGetImage_FullySuccessEncodeToBase64ErrorEsfMemoryManagerFseek),
        cmocka_unit_test(
            test_SysAppDcmdDirectGetImage_ErrorReleaseOneFrameSenscordStreamReleaseFrame),
        cmocka_unit_test(test_SysAppDcmdDirectGetImage_ErrorReleaseOneFrameSenscordStreamStop),
        cmocka_unit_test(
            test_SysAppDcmdDirectGetImage_ErrorGetOneFrameEsfMemoryManagerGetHandleInfo),
        cmocka_unit_test(test_SysAppDcmdDirectGetImage_FullySuccessUseMallocBuffer),
        cmocka_unit_test(test_SysAppDcmdDirectGetImage_ErrorUseMallocBufferMallocJpeg),
        cmocka_unit_test(test_SysAppDcmdDirectGetImage_ErrorUseMallocBufferMallocBase64),
        cmocka_unit_test(test_SysAppDcmdDirectGetImage_ErrorUseMallocBufferEsfCodecJpegEncode),
        cmocka_unit_test(test_SysAppDcmdDirectGetImage_ErrorUseMallocBufferEsfCodecBase64Encode),

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
        // GetSensorRegisterArrayParam
        cmocka_unit_test(test_GetSensorRegisterArrayParam_FullySuccessGetValueProperty),
        cmocka_unit_test(test_GetSensorRegisterArrayParam_FullySuccessNotGetValueProperty),
        cmocka_unit_test(test_GetSensorRegisterArrayParam_ErrorEsfJsonArrayGet),
        cmocka_unit_test(
            test_GetSensorRegisterArrayParam_ErrorSysAppCmnExtractRealNumberValueAddress),
        cmocka_unit_test(test_GetSensorRegisterArrayParam_ErrorSysAppCmnExtractNumberValueSize),
        cmocka_unit_test(test_GetSensorRegisterArrayParam_InvalidSizeProtertyValue),
        cmocka_unit_test(
            test_GetSensorRegisterArrayParam_ErrorSysAppCmnExtractRealNumberValueValue),
        cmocka_unit_test(test_GetSensorRegisterArrayParam_MaxOverValue1Byte),
        cmocka_unit_test(test_GetSensorRegisterArrayParam_MaxValue1Byte),
        cmocka_unit_test(test_GetSensorRegisterArrayParam_MaxOverValue2Byte),
        cmocka_unit_test(test_GetSensorRegisterArrayParam_MaxValue2Byte),
        cmocka_unit_test(test_GetSensorRegisterArrayParam_MaxOverValue4Byte),
        cmocka_unit_test(test_GetSensorRegisterArrayParam_MaxValue4Byte),

        // GetSensorRegisterParam
        cmocka_unit_test(test_GetSensorRegisterParam_FullySuccessGetValueProperty),
        cmocka_unit_test(test_GetSensorRegisterParam_FullySuccessNotGetValueProperty),
        cmocka_unit_test(test_GetSensorRegisterParam_ErrorEsfJsonObjectGet),
        cmocka_unit_test(test_GetSensorRegisterParam_ErrorEsfJsonValueTypeGet),
        cmocka_unit_test(test_GetSensorRegisterParam_InvalidTypeRegisterProperty),
        cmocka_unit_test(test_GetSensorRegisterParam_MinOverArrayNum),
        cmocka_unit_test(test_GetSensorRegisterParam_MinArrayNum),
        cmocka_unit_test(test_GetSensorRegisterParam_MaxArrayNum),
        cmocka_unit_test(test_GetSensorRegisterParam_MaxOverArrayNum),
        cmocka_unit_test(test_GetSensorRegisterParam_ErrorMalloc),
        cmocka_unit_test(test_GetSensorRegisterParam_ErrorGetSensorRegisterArrayParam),

        // GetReadSensorRegisterParam
        cmocka_unit_test(test_GetReadSensorRegisterParam_FullySuccess),
        cmocka_unit_test(test_GetReadSensorRegisterParam_ErrorEsfJsonOpen),
        cmocka_unit_test(test_GetReadSensorRegisterParam_ErrorEsfJsonDeserialize),
        cmocka_unit_test(test_GetReadSensorRegisterParam_ErrorGetSensorRegisterParam),
        cmocka_unit_test(test_GetReadSensorRegisterParam_ErrorEsfJsonClose),

        // GetWriteSensorRegisterParam
        cmocka_unit_test(test_GetWriteSensorRegisterParam_FullySuccess),
        cmocka_unit_test(test_GetWriteSensorRegisterParam_ErrorEsfJsonOpen),
        cmocka_unit_test(test_GetWriteSensorRegisterParam_ErrorEsfJsonDeserialize),
        cmocka_unit_test(test_GetWriteSensorRegisterParam_ErrorGetSensorRegisterParam),
        cmocka_unit_test(test_GetWriteSensorRegisterParam_ErrorEsfJsonClose),

        // ExecReadSensorRegister8bit
        cmocka_unit_test(test_ExecReadSensorRegister8bit_FullySuccess),
        cmocka_unit_test(test_ExecReadSensorRegister8bit_ErrorSenscordStreamGetProperty),

        // ExecReadSensorRegister16bit
        cmocka_unit_test(test_ExecReadSensorRegister16bit_FullySuccess),
        cmocka_unit_test(test_ExecReadSensorRegister16bit_ErrorSenscordStreamGetProperty),

        // ExecReadSensorRegister32bit
        cmocka_unit_test(test_ExecReadSensorRegister32bit_FullySuccess),
        cmocka_unit_test(test_ExecReadSensorRegister32bit_ErrorSenscordStreamGetProperty),

        // ExecReadSensorRegister
        cmocka_unit_test(test_ExecReadSensorRegister_FullySuccess),
        cmocka_unit_test(test_ExecReadSensorRegister_ErrorSysAppStateGetSensCordStream),
        cmocka_unit_test(test_ExecReadSensorRegister_ErrorExecReadSensorRegister8bit),
        cmocka_unit_test(test_ExecReadSensorRegister_ErrorExecReadSensorRegister16bit),
        cmocka_unit_test(test_ExecReadSensorRegister_ErrorExecReadSensorRegister32bit),
        cmocka_unit_test(test_ExecReadSensorRegister_InvalidSize),

        // ExecWriteSensorRegister8bit
        cmocka_unit_test(test_ExecWriteSensorRegister8bit_FullySuccess),
        cmocka_unit_test(test_ExecWriteSensorRegister8bit_ErrorSenscordStreamSetProperty),

        // ExecWriteSensorRegister16bit
        cmocka_unit_test(test_ExecWriteSensorRegister16bit_FullySuccess),
        cmocka_unit_test(test_ExecWriteSensorRegister16bit_ErrorSenscordStreamSetProperty),

        // ExecWriteSensorRegister32bit
        cmocka_unit_test(test_ExecWriteSensorRegister32bit_FullySuccess),
        cmocka_unit_test(test_ExecWriteSensorRegister32bit_ErrorSenscordStreamSetProperty),

        // ExecWriteSensorRegister
        cmocka_unit_test(test_ExecWriteSensorRegister_FullySuccess),
        cmocka_unit_test(test_ExecWriteSensorRegister_ErrorSysAppStateGetSensCordStream),
        cmocka_unit_test(test_ExecWriteSensorRegister_ErrorExecWriteSensorRegister8bit),
        cmocka_unit_test(test_ExecWriteSensorRegister_ErrorExecWriteSensorRegister16bit),
        cmocka_unit_test(test_ExecWriteSensorRegister_ErrorExecWriteSensorRegister32bit),
        cmocka_unit_test(test_ExecWriteSensorRegister_InvalidSize),

        // MakeJsonRegisterParams
        cmocka_unit_test(test_MakeJsonRegisterParams),

        // SetRegisterProperty
        cmocka_unit_test(test_SetRegisterProperty_FullySuccess),
        cmocka_unit_test(test_SetRegisterProperty_ErrorSysAppCmnSetArrayValue),

        // SysAppDcmdReadSensorRegister
        cmocka_unit_test(test_SysAppDcmdReadSensorRegister_FullySuccess),
        cmocka_unit_test(
            test_SysAppDcmdReadSensorRegister_ErrorGetReadSensorRegisterParamInvalidParam),
        cmocka_unit_test(test_SysAppDcmdReadSensorRegister_ErrorGetReadSensorRegisterParamOther),
        cmocka_unit_test(test_SysAppDcmdReadSensorRegister_ErrorExecReadSensorRegister),
        cmocka_unit_test(test_SysAppDcmdReadSensorRegister_ErrorSendDirectCommandResponseAsync),

        // SysAppDcmdWriteSensorRegister
        cmocka_unit_test(test_SysAppDcmdWriteSensorRegister_FullySuccess),
        cmocka_unit_test(
            test_SysAppDcmdWriteSensorRegister_ErrorGetWriteSensorRegisterInvalidParam),
        cmocka_unit_test(test_SysAppDcmdWriteSensorRegister_ErrorGetWriteSensorRegisterParamOther),
        cmocka_unit_test(test_SysAppDcmdWriteSensorRegister_ErrorExecWriteSensorRegister),
        cmocka_unit_test(test_SysAppDcmdWriteSensorRegister_ErrorSendDirectCommandResponseAsync),

#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
        // SysAppDcmdReadSensorRegister
        cmocka_unit_test(test_SysAppDcmdReadSensorRegister_FullySuccess),
        cmocka_unit_test(test_SysAppDcmdReadSensorRegister_ErrorSysSetResponseCb),

        // SysAppDcmdWriteSensorRegister
        cmocka_unit_test(test_SysAppDcmdWriteSensorRegister_FullySuccess),
        cmocka_unit_test(test_SysAppDcmdWriteSensorRegister_ErrorSysSetResponseCb),
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP

        // DirectCommandRebootCallback
        cmocka_unit_test(test_DirectCommandRebootCallback_FullySuccess),
        cmocka_unit_test(test_DirectCommandRebootCallback_ErrorParamsNull),
        cmocka_unit_test(
            test_DirectCommandRebootCallback_ErrorCheckDirectCommandExecutableFactoryResetRequested),
        cmocka_unit_test(
            test_DirectCommandRebootCallback_ErrorCheckDirectCommandExecutableBtnFactoryResetRequested),
        cmocka_unit_test(
            test_DirectCommandRebootCallback_ErrorCheckDirectCommandExecutableRebootRequested),

        // DirectCommandShutdownCallback
        cmocka_unit_test(test_DirectCommandShutdownCallback_FullySuccess),
        cmocka_unit_test(test_DirectCommandShutdownCallback_ErrorParamsNull),
        cmocka_unit_test(
            test_DirectCommandShutdownCallback_ErrorCheckDirectCommandExecutableFactoryResetRequested),

        // DirectCommandFactoryResetCallback
        cmocka_unit_test(test_DirectCommandFactoryResetCallback_FullySuccess),
        cmocka_unit_test(test_DirectCommandFactoryResetCallback_ErrorParamsNull),
        cmocka_unit_test(
            test_DirectCommandFactoryResetCallback_ErrorCheckDirectCommandExecutableFactoryResetRequested),

        // DirectCommandDirectGetImageCallback
        cmocka_unit_test(test_DirectCommandDirectGetImageCallback_FullySuccess),
        cmocka_unit_test(test_DirectCommandDirectGetImageCallback_ErrorParamsNull),
        cmocka_unit_test(
            test_DirectCommandDirectGetImageCallback_ErrorCheckDirectCommandExecutableFactoryResetRequested),

        // DirectCommandReadSensorRegisterCallback
        cmocka_unit_test(test_DirectCommandReadSensorRegisterCallback_FullySuccess),
        cmocka_unit_test(test_DirectCommandReadSensorRegisterCallback_ErrorParamsNull),
        cmocka_unit_test(
            test_DirectCommandReadSensorRegisterCallback_ErrorCheckDirectCommandExecutableFactoryResetRequested),

        // DirectCommandWriteSensorRegisterCallback
        cmocka_unit_test(test_DirectCommandWriteSensorRegisterCallback_FullySuccess),
        cmocka_unit_test(test_DirectCommandWriteSensorRegisterCallback_ErrorParamsNull),
        cmocka_unit_test(
            test_DirectCommandWriteSensorRegisterCallback_ErrorCheckDirectCommandExecutableFactoryResetRequested),

        // ResponseSendCompleteCallback
        cmocka_unit_test(test_ResponseSendCompleteCallback_FullySuccess),
        cmocka_unit_test(test_ResponseSendCompleteCallback_ErrorContextNull),

        // ResponseSendCompleteCallbackHandle
        cmocka_unit_test(test_ResponseSendCompleteCallbackHandle_FullySuccess),
        cmocka_unit_test(test_ResponseSendCompleteCallbackHandle_ErrorContextNull),
        cmocka_unit_test(test_ResponseSendCompleteCallbackHandle_ErrorEsfMemoryManagerFclose),
        cmocka_unit_test(test_ResponseSendCompleteCallbackHandle_ErrorEsfMemoryManagerFree),

        // MakeJsonResInfo
        cmocka_unit_test(test_MakeJsonResInfo_FullySuccess),

        // SetImageProperty
        cmocka_unit_test(test_SetImageProperty_FullySuccess),
        cmocka_unit_test(test_SetImageProperty_ErrorParamNull),
        cmocka_unit_test(test_SetImageProperty_ErrorSysAppCmnSetStringValue),

        // SetImagePropertyHandle
        cmocka_unit_test(test_SetImagePropertyHandle_FullySuccess),
        cmocka_unit_test(test_SetImagePropertyHandle_ErrorParamNull),
        cmocka_unit_test(test_SetImagePropertyHandle_ErrorSysAppCmnSetStringValueHandle),

        // Response2CodeAndDetailmsg
        cmocka_unit_test(test_Response2CodeAndDetailmsg_Ok),
        cmocka_unit_test(test_Response2CodeAndDetailmsg_Unknown),
        cmocka_unit_test(test_Response2CodeAndDetailmsg_InvalidArgument),
        cmocka_unit_test(test_Response2CodeAndDetailmsg_ResourceExhausted),
        cmocka_unit_test(test_Response2CodeAndDetailmsg_FailedPrecondition),
        cmocka_unit_test(test_Response2CodeAndDetailmsg_Aborted),
        cmocka_unit_test(test_Response2CodeAndDetailmsg_Unimplemented),
        cmocka_unit_test(test_Response2CodeAndDetailmsg_Internal),
        cmocka_unit_test(test_Response2CodeAndDetailmsg_Unavailable),
        cmocka_unit_test(test_Response2CodeAndDetailmsg_Unauthenticated),
        cmocka_unit_test(test_Response2CodeAndDetailmsg_Default),
        cmocka_unit_test(test_Response2CodeAndDetailmsg_CheckLengthOk),
        cmocka_unit_test(test_Response2CodeAndDetailmsg_CheckLengthUnknown),
        cmocka_unit_test(test_Response2CodeAndDetailmsg_CheckLengthInvalidArgument),
        cmocka_unit_test(test_Response2CodeAndDetailmsg_CheckLengthResourceExhausted),
        cmocka_unit_test(test_Response2CodeAndDetailmsg_CheckLengthFailedPrecondition),
        cmocka_unit_test(test_Response2CodeAndDetailmsg_CheckLengthAborted),
        cmocka_unit_test(test_Response2CodeAndDetailmsg_CheckLengthUnimplemented),
        cmocka_unit_test(test_Response2CodeAndDetailmsg_CheckLengthInternal),
        cmocka_unit_test(test_Response2CodeAndDetailmsg_CheckLengthUnavailable),
        cmocka_unit_test(test_Response2CodeAndDetailmsg_CheckLengthUnauthenticated),
        cmocka_unit_test(test_Response2CodeAndDetailmsg_CheckLengthDefault),

        // SendDirectCommandResponse
        cmocka_unit_test(test_SendDirectCommandResponse_FullySuccessHandle),
        cmocka_unit_test(test_SendDirectCommandResponse_ErrorEsfMemoryManagerAllocate),
        cmocka_unit_test(test_SendDirectCommandResponse_ErrorEsfJsonSerializeHandle),
        cmocka_unit_test(test_SendDirectCommandResponse_InvalidHandleEsfMemoryManagerAllocate),
        cmocka_unit_test(test_SendDirectCommandResponse_ErrorSendDirectCommandResponseCore),

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
        // DirectCommandUnimplementedCallback
        cmocka_unit_test(test_DirectCommandUnimplementedCallback_FullySuccess),
        cmocka_unit_test(test_DirectCommandUnimplementedCallback_paramsNull),
        cmocka_unit_test(
            test_DirectCommandUnimplementedCallback_DirectCommandCallbackCommonFailure),
        cmocka_unit_test(
            test_DirectCommandUnimplementedCallback_SendDirectCommandResponseAsyncError),
#endif // !CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
    };

    return (((cmocka_run_group_tests(tests, NULL, NULL)) == 0) ? 0 : 1);
}
