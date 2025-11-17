/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

#if defined(__NuttX__)
#include <nuttx/config.h>
#endif

#include "sdk_backdoor.h"

#include "senscord/c_api/senscord_c_api.h"
#include "senscord/inference_stream/c_api/property_c_types.h"
#include "firmware_manager.h"
#include "memory_manager.h"
#include "power_manager.h"
#include "json/include/json.h"
#include "json/include/json_handle.h"
#include "jpeg/include/jpeg.h"
#include "base64/include/base64.h"

#include "system_app_common.h"
#include "system_app_log.h"
#include "system_app_direct_command.h"
#include "system_app_direct_command_private.h"
#include "system_app_state.h"
#include "system_app_led.h"
#include "system_app_button.h"
#include "system_app_util.h"

//
// Macros.
//

#define DISABLE_REQ_INFO // Disable parsing of req_info and remove res_id from responses

#define SENSOR_REGISTER_ARRAY_MIN (1)
#define SENSOR_REGISTER_ARRAY_MAX (32)

#define SENSOR_REGISTER_ID_IMX500 (0x00000000)

//
// File private structure and enum.
//

typedef union {
    EsfMemoryManagerHandle handle; // for lheap
    void *raw;                     // for malloc
} encode_buf_t;

typedef union {
    EsfCodecJpegInfo handle;  // for lheap
    EsfCodecJpegEncParam raw; // for malloc
} jpeg_encode_param_t;

//
// File static variables.
//

STATIC struct SYS_client *s_sys_client = NULL;
STATIC TerminationReason s_terminate_request = UnDefined;

//
// File static private functions.
//

/*----------------------------------------------------------------------*/
static RetCode AllocateAndFopenMemoryManagerHandle(size_t buf_size,
                                                   EsfMemoryManagerHandle *buf_handle)
{
    RetCode ret = kRetOk;
    EsfMemoryManagerResult esfmm_ret = kEsfMemoryManagerResultSuccess;

    esfmm_ret = EsfMemoryManagerAllocate(kEsfMemoryManagerTargetLargeHeap, NULL, buf_size,
                                         buf_handle);

    if (esfmm_ret != kEsfMemoryManagerResultSuccess) {
        SYSAPP_ERR("EsfMemoryManagerAllocate(buf_size %zu, buf_handle %p)", buf_size, buf_handle);
        return kRetFailed;
    }

    return ret;
}

/*----------------------------------------------------------------------*/
static RetCode FcloseAndFreeMemoryManagerHandle(EsfMemoryManagerHandle buf_handle)
{
    RetCode ret = kRetOk;
    EsfMemoryManagerResult esfmm_ret = kEsfMemoryManagerResultSuccess;

    esfmm_ret = EsfMemoryManagerFree(buf_handle, NULL);

    if (esfmm_ret != kEsfMemoryManagerResultSuccess) {
        SYSAPP_WARN("EsfMemoryManagerFree(buf_handle %d)", buf_handle);
        ret = kRetFailed;
    }

    return ret;
}

/*----------------------------------------------------------------------*/
STATIC void ResponseSendCompleteCallback(struct SYS_client *client, enum SYS_callback_reason reason,
                                         void *context)
{
    if (context == NULL) {
        SYSAPP_ERR("ResponseSendCompleteCallback(%d, %p)", reason, context);
        return;
    }

    DcResponseContext *ctx = (DcResponseContext *)context;

    *(ctx->send_complete) = true;

    free(ctx->response);
    free(ctx);
}

/*----------------------------------------------------------------------*/
STATIC void ResponseSendCompleteCallbackHandle(struct SYS_client *client,
                                               enum SYS_callback_reason reason, void *context)
{
    if (context == NULL) {
        SYSAPP_ERR("ResponseSendCompleteCallbackHandle(%d, %p)", reason, context);
        return;
    }

    DcResponseContext *ctx = (DcResponseContext *)context;

    *(ctx->send_complete) = true;

    FcloseAndFreeMemoryManagerHandle((EsfMemoryManagerHandle)(uintptr_t)ctx->response);
    free(ctx);
}

/*----------------------------------------------------------------------*/
static RetCode SendDirectCommandResponseCore(struct SYS_client *evp_handle, SYS_response_id cmd_id,
                                             const char *response, SYS_response_cb response_cb,
                                             bool is_sync)
{
    RetCode ret = kRetOk;
    enum SYS_result sys_ret = SYS_RESULT_OK;
    DcResponseContext *dcres_ctx = NULL;
    bool send_complete = false;

    // Set context parameter to give send-complete-callback.

    dcres_ctx = (DcResponseContext *)malloc(sizeof(DcResponseContext));

    if (dcres_ctx == NULL) {
        return kRetMemoryError;
    }

    dcres_ctx->cmd_id = cmd_id;
    dcres_ctx->response = (void *)response;
    dcres_ctx->status_code = 0;
    dcres_ctx->retry_count = 0;
    dcres_ctx->send_complete = &send_complete;

    // Send direct command response.

    SYSAPP_INFO("Send command response: cmd_id %ju", cmd_id);

    sys_ret = SYS_set_response_cb(evp_handle, cmd_id, response, SYS_RESPONSE_STATUS_OK, response_cb,
                                  dcres_ctx);

    if (sys_ret != SYS_RESULT_OK) {
        SYSAPP_ERR("SYS_set_response_cb() ret %d", sys_ret);
        ret = kRetFailed;
        goto evp_api_failed;
    }

    // If sync is specified, call SYS_process_event() until send complete.
    // When call SYS_process_event(), ResponseSendCompleteCallback() is called internally.
    // ResponseSendCompleteCallback() notifies send completion to send_complete flag.

    if (is_sync) {
        while (true) {
            sys_ret = SYS_process_event(s_sys_client, 0);
            if (sys_ret == SYS_RESULT_SHOULD_EXIT) {
                break;
            }

            if (send_complete) {
                break;
            }

            SYSAPP_INFO("Wait...");
            usleep(100);
        }
    }

    return ret;

    //
    // Error handle.
    //

evp_api_failed:

    free(dcres_ctx);

    return ret;
}

/*----------------------------------------------------------------------*/
STATIC RetCode MakeJsonResInfo(EsfJsonHandle handle, EsfJsonValue root, void *ctx)
{
    RetCode ret = kRetOk;

    ResInfoContext *res_info = (ResInfoContext *)ctx;

    ret = SysAppCmnMakeJsonResInfo(handle, root,
#ifdef DISABLE_REQ_INFO
                                   NULL,
#else
                                   res_info->res_id,
#endif
                                   res_info->code, res_info->detail_msg);

    return ret;
}

/*----------------------------------------------------------------------*/
STATIC void Response2CodeAndDetailmsg(DcResult res, int *code, char *desc, uint32_t desc_len)
{
    switch (res) {
        case DcOk:
            *code = RESULT_CODE_OK;
            snprintf(desc, desc_len, "%s", "ok");
            break;

        case DcUnknown:
            *code = RESULT_CODE_UNKNOWN;
            snprintf(desc, desc_len, "%s", "unknown");
            break;

        case DcInvalidArgument:
            *code = RESULT_CODE_INVALID_ARGUMENT;
            snprintf(desc, desc_len, "%s", "invalid_argument");
            break;

        case DcResourceExhausted:
            *code = RESULT_CODE_RESOURCE_EXHAUSTED;
            snprintf(desc, desc_len, "%s", "resource_exhausted");
            break;

        case DcFailedPreCondition:
            *code = RESULT_CODE_FAILED_PRECONDITION;
            snprintf(desc, desc_len, "%s", "failed_precondition");
            break;

        case DcAborted:
            *code = RESULT_CODE_ABORTED;
            snprintf(desc, desc_len, "%s", "aborted");
            break;

        case DcUnimplemented:
            *code = RESULT_CODE_UNIMPLEMENTED;
            snprintf(desc, desc_len, "%s", "unimplemented");
            break;

        case DcInternal:
            *code = RESULT_CODE_INTERNAL;
            snprintf(desc, desc_len, "%s", "internal");
            break;

        case DcUnavailable:
            *code = RESULT_CODE_UNAVAILABLE;
            snprintf(desc, desc_len, "%s", "unavailable");
            break;

        case DcUnauthenticated:
            *code = RESULT_CODE_UNAUTHENTICATED;
            snprintf(desc, desc_len, "%s", "unauthenticated");
            break;

        default:
            *code = RESULT_CODE_UNKNOWN;
            snprintf(desc, desc_len, "%s", "unknown");
            SYSAPP_WARN("Unknown response code, res %d. -> res %d desc %s", res, *code, desc);
            break;
    }
}

/*----------------------------------------------------------------------*/
STATIC RetCode SendDirectCommandResponse(
    struct SYS_client *evp_handle, SYS_response_id cmd_id, const char *req_id, DcResult dc_result,
    RetCode (*additional)(EsfJsonHandle, EsfJsonValue, void *, size_t), void *additional_param,
    size_t additional_param_size, bool is_additional_param_file_io, bool is_sync)
{
    RetCode ret = kRetOk;
    EsfJsonErrorCode esfj_ret = kEsfJsonSuccess;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;

    // Set res_info parameter.

    esfj_ret = EsfJsonOpen(&esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonOpen(%p) ret %d", &esfj_handle, esfj_ret);
    }

    esfj_ret = EsfJsonObjectInit(esfj_handle, &val);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectInit(%p) ret %d", esfj_handle, esfj_ret);
    }

    ResInfoContext ctx = {0};
    snprintf(ctx.res_id, sizeof(ctx.res_id), "%s", req_id);
    Response2CodeAndDetailmsg(dc_result, &(ctx.code), ctx.detail_msg, sizeof(ctx.detail_msg));

    ret = SysAppCmnSetObjectValue(esfj_handle, val, "res_info", MakeJsonResInfo, &ctx);

    // Set additional(e.g. "image") info if needed.

    if (additional != NULL) {
        additional(esfj_handle, val, additional_param, additional_param_size);
    }

    // Serialize json string and send it.

    if (is_additional_param_file_io != true) {
        // Case normal heap.
        // Copy serialized string to heap.
        // This memory will be freed when response send complete.

        const char *response_org = NULL;
        esfj_ret = EsfJsonSerialize(esfj_handle, val, &response_org);

        if ((esfj_ret == kEsfJsonSuccess) && (response_org != NULL)) {
            char *response = strdup(response_org);

            if (response != NULL) {
                ret = SendDirectCommandResponseCore(evp_handle, cmd_id, response,
                                                    ResponseSendCompleteCallback, is_sync);

                if (ret != kRetOk) {
                    SYSAPP_ERR("SendDirectCommandResponseCore() ret %d", ret);
                    free(response);
                }
            }
            else {
                SYSAPP_ERR("Response allocate failed");
                ret = kRetMemoryError;
            }
        }
    }
    else {
        // Case Large heap (Handle).
        // Allocate from MemoryManager with Handle-handle and serialize Json to it.
        // This Handle-handle is still valid even after closing Json-handle, and freed when response send complete.

        EsfMemoryManagerHandle json_buf_handle = 0;
        size_t json_buf_size = EsfJsonSerializeSizeGet(esfj_handle, val) + 1 /*Size of null char.*/;

        ret = AllocateAndFopenMemoryManagerHandle(json_buf_size, &json_buf_handle);

        if (ret == kRetOk) {
            esfj_ret = EsfJsonSerializeHandle(esfj_handle, val, json_buf_handle, &json_buf_size);

            if ((esfj_ret == kEsfJsonSuccess) && (json_buf_handle != 0)) {
                ret = SendDirectCommandResponseCore(evp_handle, cmd_id,
                                                    (void *)(uintptr_t)json_buf_handle,
                                                    ResponseSendCompleteCallbackHandle, is_sync);

                if (ret != kRetOk) {
                    SYSAPP_ERR("SendDirectCommandResponseCore() ret %d", ret);
                    FcloseAndFreeMemoryManagerHandle(json_buf_handle);
                }
            }
            else {
                SYSAPP_ERR("EsfJsonSerializeHandle() ret %d, json_buf_handle %d", ret,
                           json_buf_handle);
                FcloseAndFreeMemoryManagerHandle(json_buf_handle);
                ret = kRetFailed;
            }
        }
        else {
            ret = kRetFailed;
        }
    }

    // Clean up.

    esfj_ret = EsfJsonClose(esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_WARN("EsfJsonClose(%p) ret %d", esfj_handle, esfj_ret);
    }

    // Free additional_param.

    if (is_additional_param_file_io == true) {
        FcloseAndFreeMemoryManagerHandle((EsfMemoryManagerHandle)(uintptr_t)additional_param);
    }

    return ret;
}

/*----------------------------------------------------------------------*/
static RetCode SendDirectCommandResponseSync(
    struct SYS_client *evp_handle, SYS_response_id cmd_id, const char *req_id, DcResult dc_result,
    RetCode (*additional)(EsfJsonHandle, EsfJsonValue, void *, size_t), void *additional_param,
    size_t additional_param_size, bool is_additional_param_file_io)
{
    return SendDirectCommandResponse(evp_handle, cmd_id, req_id, dc_result, additional,
                                     additional_param, additional_param_size,
                                     is_additional_param_file_io, true);
}

/*----------------------------------------------------------------------*/
static RetCode SendDirectCommandResponseAsync(
    struct SYS_client *evp_handle, SYS_response_id cmd_id, const char *req_id, DcResult dc_result,
    RetCode (*additional)(EsfJsonHandle, EsfJsonValue, void *, size_t), void *additional_param,
    size_t additional_param_size, bool is_additional_param_file_io)
{
    return SendDirectCommandResponse(evp_handle, cmd_id, req_id, dc_result, additional,
                                     additional_param, additional_param_size,
                                     is_additional_param_file_io, false);
}

/*----------------------------------------------------------------------*/
#ifdef DISABLE_REQ_INFO
static RetCode GetReqId(const char *, char *, uint32_t)
{
    return kRetOk;
}
#else
static RetCode GetReqId(const char *param, char *req_id_buf, uint32_t buf_len)
{
    RetCode ret = kRetOk;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;

    // Open ESF(Json) and create JsonValue from param.

    EsfJsonErrorCode esfj_ret = EsfJsonOpen(&esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonOpen(%p) ret %d", esfj_handle, esfj_ret);
        return kRetFailed;
    }

    esfj_ret = EsfJsonDeserialize(esfj_handle, param, &val);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonDeserialize(%p) ret %d", esfj_handle, esfj_ret);
        ret = kRetFailed;
        goto clean_up_exit;
    }

    // Get req_id.

    const char *req_id_ptr = NULL;
    ret = SysAppCmnGetReqId(esfj_handle, val, &req_id_ptr);

    if (ret == kRetOk) {
        if (strlen(req_id_ptr) <= CFG_RES_ID_LEN) {
            // Copy req_id to output.

            snprintf(req_id_buf, buf_len, "%s", req_id_ptr);
        }
        else {
            ret = kRetFailed;
        }
    }

clean_up_exit:

    // Clean up.

    esfj_ret = EsfJsonClose(esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonClose(%p) ret %d", esfj_handle, esfj_ret);
    }

    return ret;
}
#endif

/*----------------------------------------------------------------------*/
static DcResult GetDirectGetImageParams(const char *param, DirectGetImageParam *out)
{
    DcResult ret = DcOk;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;

    // Open handle and set config parameters.

    EsfJsonErrorCode esfj_ret = EsfJsonOpen(&esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonOpen(%p) ret %d", &esfj_handle, esfj_ret);
        return DcInternal;
    }

    esfj_ret = EsfJsonDeserialize(esfj_handle, param, &val);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonDeserialize(%p) ret %d", esfj_handle, esfj_ret);
        ret = DcInternal;
        goto direct_get_image_param_exit;
    }

    // Get sensor_name property.

#if 0 // sensor name is ignored
  const char* sensor_name = NULL;
  int extret = SysAppCmnExtractStringValue(esfj_handle, val, "sensor_name", &sensor_name);

  if (extret >= 0) {
    if ((extret >= 1) && (strlen(sensor_name) <= DC_SENSOR_NAME_LEN)) {
      snprintf(out->sensor_name, sizeof(out->sensor_name), "%s", sensor_name);
    } else {
      SYSAPP_ERR("Invalid sensor_name");
      ret = DcInvalidArgument;
    }
  } else {
    out->sensor_name[0] = '\0'; // Means "not specified".
  }
#else
    const char *sensor_name = "sensor_chip";
    snprintf(out->sensor_name, sizeof(out->sensor_name), "%s", sensor_name);
    int extret;
#endif

    // Get network_id property.

    const char *network_id = NULL;
    extret = SysAppCmnExtractStringValue(esfj_handle, val, "network_id", &network_id);

    if (extret >= 0) {
        if ((extret >= 1) && (strnlen(network_id, DC_NETWORK_ID_LEN + 1) <= DC_NETWORK_ID_LEN)) {
            if (strncmp(network_id, "", DC_NETWORK_ID_LEN) == 0) {
                snprintf(out->network_id, sizeof(out->network_id), "%s",
                         CONFIG_EXTERNAL_SYSTEMAPP_DEFAULT_NETWORK_ID);
            }
            else {
                snprintf(out->network_id, sizeof(out->network_id), "%s", network_id);
            }
        }
        else {
            SYSAPP_ERR("Invalid network_id %s", network_id);
            ret = DcInvalidArgument;
        }
    }
    else {
        snprintf(out->network_id, sizeof(out->network_id), "%s",
                 CONFIG_EXTERNAL_SYSTEMAPP_DEFAULT_NETWORK_ID);
    }
    SYSAPP_INFO("direct_get_image network_id (%s)", out->network_id);

direct_get_image_param_exit:

    // Close handle.

    esfj_ret = EsfJsonClose(esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonClose(%p)", esfj_handle);
    }

    return ret;
}

/*----------------------------------------------------------------------*/
static RetCode GetFormatOfImage(char *scord_format, EsfCodecJpegInputFormat *jpg_format)
{
    const struct {
        const char *scord_format;
        EsfCodecJpegInputFormat jpg_format;
    } formats[] = {{SENSCORD_PIXEL_FORMAT_RGB8_PLANAR, kJpegInputRgbPlanar_8},
                   {SENSCORD_PIXEL_FORMAT_GREY, kJpegInputGray_8},
                   {SENSCORD_PIXEL_FORMAT_RGB24, kJpegInputRgbPacked_8},
                   {NULL, 0}},
      *cp = formats;

    while (cp->scord_format != NULL) {
        if (strcmp(cp->scord_format, scord_format) == 0) {
            *jpg_format = cp->jpg_format;
            return kRetOk;
        }
        cp++;
    }

    return kRetNotFound;
}

/*----------------------------------------------------------------------*/
static RetCode GetOneFrame(DirectGetImageParam *dgi, FrameInfo *out)
{
    RetCode ret = kRetOk;

    // Get handle of SensCord.

    ret = SysAppStateGetSensCordId(&out->sccore);

    if (ret != kRetOk) {
        SYSAPP_ERR("SysAppStateGetSensCordId ret=%d", ret);
        goto open_stream_failed;
    }

    ret = SysAppStateGetSensCordStream(&out->scstream);

    if (ret != kRetOk) {
        SYSAPP_ERR("SysAppStateGetSensCordStream ret=%d", ret);
        goto open_stream_failed;
    }

    // Load AI model.

    struct senscord_ai_model_bundle_id_property_t ai_model;

    snprintf(ai_model.ai_model_bundle_id, sizeof(ai_model.ai_model_bundle_id), "%s",
             dgi->network_id);

    int32_t sc_ret = senscord_stream_set_property(out->scstream,
                                                  SENSCORD_AI_MODEL_BUNDLE_ID_PROPERTY_KEY,
                                                  (const void *)&ai_model, sizeof(ai_model));

    if (sc_ret < 0) {
        SYSAPP_ERR("senscord_stream_set_property(AIMODEL) ret=%d", sc_ret);
        ret = kRetFailed;
        goto set_ai_model_property_failed;
    }

    // Set input data type.

    struct senscord_input_data_type_property_t input_data = {
        .count = 1,
        .channels[0] = 0x00000001 // 0x1:Inference input image
    };

    sc_ret = senscord_stream_set_property(out->scstream, SENSCORD_INPUT_DATA_TYPE_PROPERTY_KEY,
                                          (const void *)&input_data, sizeof(input_data));

    if (sc_ret < 0) {
        SYSAPP_ERR("senscord_stream_set_property(INPUT_DATA_TYPE) ret=%d", sc_ret);
        ret = kRetFailed;
        goto set_input_data_property_failed;
    }

    // Start stream.

    sc_ret = senscord_stream_start(out->scstream);

    if (sc_ret < 0) {
        SYSAPP_ERR("senscord_stream_start() ret %d", sc_ret);
        ret = kRetFailed;
        goto start_stream_failed;
    }

    // Get a frame.

    sc_ret = senscord_stream_get_frame(out->scstream, &out->scframe, -1);

    if (sc_ret < 0) {
        SYSAPP_ERR("senscord_stream_get_frame() ret %d", sc_ret);
        ret = kRetFailed;
        goto get_frame_failed;
    }

    // Get channel_id.

    senscord_channel_t channel = 0;

    sc_ret = senscord_frame_get_channel_from_channel_id(out->scframe,
                                                        0x00000001, /*T.B.D Inference image*/
                                                        &channel);

    if (sc_ret < 0) {
        SYSAPP_ERR("senscord_frame_get_channel_from_channel_id() ret %d", sc_ret);
        ret = kRetFailed;
        goto get_channel_failed;
    }

    // Get frame size.

    struct senscord_image_property_t img_prop = {0};

    sc_ret = senscord_stream_get_property(out->scstream, SENSCORD_IMAGE_PROPERTY_KEY,
                                          (void *)&img_prop, sizeof(img_prop));

    if (sc_ret < 0) {
        SYSAPP_ERR("ssenscord_stream_get_property() ret=%d", sc_ret);
        ret = kRetFailed;
        goto get_image_property_failed;
    }

    // Check the format of the acquired image data and convert it to JPEG format.

    if (GetFormatOfImage(img_prop.pixel_format, &out->format) != kRetOk) {
        SYSAPP_ERR("Unsupported format:%s", img_prop.pixel_format);

        // If no corresponding format is available, the grayscale setting will be used.

        out->format = kJpegInputGray_8;
    }

    out->width = img_prop.width;
    out->height = img_prop.height;
    out->stride = img_prop.stride_bytes;
    SYSAPP_INFO("w %d h %d s %d f %s", out->width, out->height, out->stride, img_prop.pixel_format);

    // Get raw_data.

    struct senscord_raw_data_t raw_data = {};

    sc_ret = senscord_channel_get_raw_data(channel, &raw_data);

    if (sc_ret < 0) {
        SYSAPP_ERR("senscord_channel_get_raw_data() ret %d", sc_ret);
        ret = kRetFailed;
        goto get_raw_data_failed;
    }

    out->size = (uint32_t)raw_data.size;
    out->time_stamp = (uint64_t)raw_data.timestamp;
    out->handle = (EsfMemoryManagerHandle)(uintptr_t)raw_data.address;

    EsfMemoryManagerHandleInfo handle_info;
    EsfMemoryManagerResult esfmm_ret = EsfMemoryManagerGetHandleInfo(out->handle, &handle_info);
    if (esfmm_ret != kEsfMemoryManagerResultSuccess) {
        SYSAPP_ERR("EsfMemoryManagerGetHandleInfo() ret %d", esfmm_ret);
        ret = kRetFailed;
        goto get_handle_info_failed;
    }

    if (handle_info.target_area == kEsfMemoryManagerTargetOtherHeap) {
        // raw_data.address represents malloc buffer.
        out->addr = raw_data.address;
        out->handle = 0; // invalidate
    }
    else {
        // raw_data.address represents memory manager's handle.
        out->addr = NULL;
    }

    return kRetOk;

    //
    // Error handling.
    //

get_handle_info_failed:
get_raw_data_failed:
get_channel_failed:

    senscord_stream_release_frame(out->scstream, out->scframe);

get_frame_failed:

    senscord_stream_stop(out->scstream);

start_stream_failed:
get_image_property_failed:
set_input_data_property_failed:
set_ai_model_property_failed:
open_stream_failed:

    return ret;
}

/*----------------------------------------------------------------------*/
static RetCode ReleaseOneFrame(FrameInfo *frame)
{
    RetCode ret = kRetOk;

    // Release a frame.

    int32_t sc_ret = senscord_stream_release_frame(frame->scstream, frame->scframe);

    if (sc_ret < 0) {
        SYSAPP_WARN("senscord_stream_release_frame() ret %d", sc_ret);
        ret = kRetFailed;
    }

    // Stop stream.

    sc_ret = senscord_stream_stop(frame->scstream);

    if (sc_ret < 0) {
        SYSAPP_WARN("senscord_stream_stop() ret %d", sc_ret);
        ret = kRetFailed;
    }

    return ret;
}

/*----------------------------------------------------------------------*/
static RetCode AllocateEncodeBuffer(encode_buf_t *buf, size_t buf_size, bool use_handle)
{
    RetCode ret = kRetOk;

    if (use_handle) {
        ret = AllocateAndFopenMemoryManagerHandle(buf_size, &buf->handle);
    }
    else {
        buf->raw = malloc(buf_size);
        if (buf->raw == NULL) {
            ret = kRetFailed;
        }
    }

    return ret;
}

/*----------------------------------------------------------------------*/
static RetCode FreeEncodeBuffer(encode_buf_t *buf, bool use_handle)
{
    RetCode ret = kRetOk;

    if (use_handle) {
        ret = FcloseAndFreeMemoryManagerHandle(buf->handle);
    }
    else {
        free(buf->raw);
    }

    return ret;
}

/*----------------------------------------------------------------------*/
static void SetupJpegEncParam(jpeg_encode_param_t *param, encode_buf_t *buf, uint32_t buf_size,
                              FrameInfo *frame, bool use_handle)
{
    const int32_t quality = 80; /*T.B.D.*/

    if (use_handle) {
        param->handle.input_fmt = frame->format;
        param->handle.width = frame->width;
        param->handle.height = frame->height;
        param->handle.stride = frame->stride;
        param->handle.quality = quality;
    }
    else {
        param->raw.input_fmt = frame->format;
        param->raw.width = frame->width;
        param->raw.height = frame->height;
        param->raw.stride = frame->stride;
        param->raw.quality = quality;

        param->raw.input_adr_handle = (uintptr_t)frame->addr;
        param->raw.out_buf.output_adr_handle = (uintptr_t)buf->raw;
        param->raw.out_buf.output_buf_size = buf_size;
    }
}

/*----------------------------------------------------------------------*/
static RetCode EncodeToJpeg(FrameInfo *frame, encode_buf_t *jpeg_out_buf,
                            uint32_t jpeg_out_buf_size, uint32_t *jpeg_out_size, bool use_handle)
{
    RetCode ret = kRetOk;
    EsfCodecJpegError esfj_ret = kJpegSuccess;

    jpeg_encode_param_t enc_param = {0};
    int32_t jpeg_size = 0;
    int32_t *quality = use_handle ? &enc_param.handle.quality : &enc_param.raw.quality;

    SetupJpegEncParam(&enc_param, jpeg_out_buf, jpeg_out_buf_size, frame, use_handle);

    while (1) {
        // Execute jpeg encode.

        if (use_handle) {
            esfj_ret = EsfCodecJpegEncodeHandle(frame->handle, jpeg_out_buf->handle,
                                                &enc_param.handle, &jpeg_size);
        }
        else {
            esfj_ret = EsfCodecJpegEncode(&enc_param.raw, &jpeg_size);
        }
        if (esfj_ret == kJpegSuccess) {
            // Check jpeg size, and determine retry or not.

            if (jpeg_size <= (int32_t)jpeg_out_buf_size) {
                ret = kRetOk;
                break;
            }
        }
        else if (esfj_ret == kJpegOutputBufferFullError) {
            // Jpeg size exceeds buffer size, retry.
        }
        else {
            // Other error, return fail.

            ret = kRetFailed;
            break;
        }

        // Retry jpeg encode to reduce the size.

        SYSAPP_INFO("Too large jpeg. %d byte. ret %d", jpeg_size, esfj_ret);

        if (*quality > 0) {
            *quality /= 2;
            continue;
        }
        else {
            ret = kRetFailed;
            break;
        }
    }

    // Set encoded jpeg size.

    if (ret == kRetOk) {
        *jpeg_out_size = jpeg_size;
    }
    else {
        *jpeg_out_size = 0;
    }

    return ret;
}

/*----------------------------------------------------------------------*/
static RetCode EncodeToBase64(encode_buf_t *in_buf, const uint32_t in_size, encode_buf_t *out_buf,
                              const uint32_t out_buf_size, size_t *out_size, bool use_handle)
{
    RetCode ret = kRetOk;
    EsfCodecBase64ResultEnum esfb_ret = kEsfCodecBase64ResultSuccess;

    // Encode to base64.

    *out_size = out_buf_size;

    if (use_handle) {
        esfb_ret = EsfCodecBase64EncodeHandle(in_buf->handle, in_size, out_buf->handle, out_size);
    }
    else {
        esfb_ret = EsfCodecBase64Encode(in_buf->raw, in_size, out_buf->raw, out_size);
    }

    if (esfb_ret != kEsfCodecBase64ResultSuccess) {
        SYSAPP_ERR("EsfCodecBase64Encode%s() ret %d", use_handle ? "Handle" : "", esfb_ret);
        ret = kRetFailed;
        *out_size = 0;
    }

    return ret;
}

/*----------------------------------------------------------------------*/
STATIC RetCode SetImageProperty(EsfJsonHandle handle, EsfJsonValue val, void *param,
                                size_t param_size)
{
    (void)param_size;
    RetCode ret = kRetOk;
    const char *image_b64 = (param != NULL) ? param : "";

    ret = SysAppCmnSetStringValue(handle, val, "image", image_b64);

    if (ret != kRetOk) {
        SYSAPP_WARN("Set image body failed. %d", ret);
    }

    return ret;
}

/*----------------------------------------------------------------------*/
STATIC RetCode SetImagePropertyHandle(EsfJsonHandle handle, EsfJsonValue val, void *param,
                                      size_t param_size)
{
    RetCode ret = kRetOk;
    EsfMemoryManagerHandle mm_handle = (EsfMemoryManagerHandle)(uintptr_t)param;

    if (mm_handle != 0) {
        ret = SysAppCmnSetStringValueHandle(handle, val, "image", mm_handle,
                                            param_size - 1 /*Exclude null char*/);

        if (ret != kRetOk) {
            SYSAPP_WARN("Set image body failed. %d", ret);
        }
    }
    else {
        ret = kRetFailed;
    }

    return ret;
}

/*----------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
STATIC DcResult GetSensorRegisterArrayParam(EsfJsonHandle esfj_handle, EsfJsonValue val,
                                            SensorRegisterParam *sensor_register_param,
                                            bool is_get_value_property)
{
    DcResult dc_ret = DcOk;
    EsfJsonErrorCode esfj_ret;
    EsfJsonValue cval;
    int idx;
    int extret;
    double temp_double;
    uint32_t max_val = 0;

    for (idx = 0; idx < sensor_register_param->num; idx++) {
        esfj_ret = EsfJsonArrayGet(esfj_handle, val, idx, &cval);

        if (esfj_ret != kEsfJsonSuccess) {
            SYSAPP_ERR("EsfJsonArrayGet() ret %d idx %d", esfj_ret, idx);
            dc_ret = DcInternal;
            break;
        }

        // Get address property.

        extret = SysAppCmnExtractRealNumberValue(esfj_handle, cval, "address", &temp_double);

        if (extret < 1) {
            SYSAPP_ERR("Invalid address idx %d", idx);
            dc_ret = DcInvalidArgument;
            break;
        }

        sensor_register_param->info[idx].address = (uint64_t)temp_double;

        // Get size property.

        extret = SysAppCmnExtractNumberValue(esfj_handle, cval, "size",
                                             (int *)&sensor_register_param->info[idx].size);

        if (extret < 1) {
            SYSAPP_ERR("Invalid size idx %d", idx);
            dc_ret = DcInvalidArgument;
            break;
        }
        else {
            if (sensor_register_param->info[idx].size == RegiSize1Byte) {
                max_val = 0xFF;
            }
            else if (sensor_register_param->info[idx].size == RegiSize2Byte) {
                max_val = 0xFFFF;
            }
            else if (sensor_register_param->info[idx].size == RegiSize4Byte) {
                max_val = 0xFFFFFFFF;
            }
            else {
                SYSAPP_ERR("Undefinition value size %d idx %d",
                           sensor_register_param->info[idx].size, idx);
                dc_ret = DcInvalidArgument;
                break;
            }
        }

        // Get value property.

        if (is_get_value_property) {
            extret = SysAppCmnExtractRealNumberValue(esfj_handle, cval, "value", &temp_double);

            if (extret < 1) {
                SYSAPP_ERR("Invalid value idx %d", idx);
                dc_ret = DcInvalidArgument;
                break;
            }
            else if ((uint64_t)temp_double > max_val) {
                SYSAPP_ERR("Range over value %lld idx %d", (uint64_t)temp_double, idx);
                dc_ret = DcInvalidArgument;
                break;
            }

            sensor_register_param->info[idx].value = (uint32_t)temp_double;
        }
    }

    return dc_ret;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
STATIC DcResult GetSensorRegisterParam(EsfJsonHandle esfj_handle, EsfJsonValue val,
                                       SensorRegisterParam *sensor_register_param,
                                       bool is_get_value_property)
{
    DcResult dc_ret = DcOk;
    EsfJsonValue cval = ESF_JSON_VALUE_INVALID;
    EsfJsonErrorCode esfj_ret;
    EsfJsonValueType val_type;

    // Get register object.

    esfj_ret = EsfJsonObjectGet(esfj_handle, val, "register", &cval);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("Not found register");
        dc_ret = DcInvalidArgument;
        goto exit;
    }

    // Check type.

    esfj_ret = EsfJsonValueTypeGet(esfj_handle, cval, &val_type);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonValueTypeGet() ret %d", esfj_ret);
        dc_ret = DcInternal;
        goto exit;
    }
    else if (val_type != kEsfJsonValueTypeArray) {
        SYSAPP_ERR("Invalid type register");
        dc_ret = DcInvalidArgument;
        goto exit;
    }

    // Get and check array num.

    sensor_register_param->num = EsfJsonArrayCount(esfj_handle, cval);

    if ((sensor_register_param->num < SENSOR_REGISTER_ARRAY_MIN) ||
        (SENSOR_REGISTER_ARRAY_MAX < sensor_register_param->num)) {
        SYSAPP_ERR("Array num over register %d", sensor_register_param->num);
        dc_ret = DcInvalidArgument;
        goto exit;
    }

    // Allocate for saving array data.

    sensor_register_param->info =
        (SensorRegisterInfo *)malloc(sizeof(SensorRegisterInfo) * sensor_register_param->num);

    if (sensor_register_param->info == NULL) {
        SYSAPP_ERR("malloc");
        dc_ret = DcInternal;
        goto exit;
    }

    // Get array value.

    dc_ret = GetSensorRegisterArrayParam(esfj_handle, cval, sensor_register_param,
                                         is_get_value_property);

exit:

    return dc_ret;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
STATIC DcResult GetReadSensorRegisterParam(const char *param,
                                           SensorRegisterParam *sensor_register_param)
{
    DcResult dc_ret = DcOk;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;

    // Open ESF(Json) and create JsonValue from param.

    EsfJsonErrorCode esfj_ret = EsfJsonOpen(&esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonOpen() ret %d", esfj_ret);
        return DcInternal;
    }

    esfj_ret = EsfJsonDeserialize(esfj_handle, param, &val);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonDeserialize() ret %d", esfj_ret);
        dc_ret = DcInternal;
        goto read_sensor_register_param_exit;
    }

    // Get register property.

    dc_ret = GetSensorRegisterParam(esfj_handle, val, sensor_register_param, false);

read_sensor_register_param_exit:

    // Close handle.

    esfj_ret = EsfJsonClose(esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonClose() ret %d", esfj_ret);
    }

    return dc_ret;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
STATIC DcResult GetWriteSensorRegisterParam(const char *param,
                                            SensorRegisterParam *sensor_register_param)
{
    DcResult dc_ret = DcOk;
    EsfJsonHandle esfj_handle = ESF_JSON_HANDLE_INITIALIZER;
    EsfJsonValue val = ESF_JSON_VALUE_INVALID;

    // Open ESF(Json) and create JsonValue from param.

    EsfJsonErrorCode esfj_ret = EsfJsonOpen(&esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonOpen() ret %d", esfj_ret);
        return DcInternal;
    }

    esfj_ret = EsfJsonDeserialize(esfj_handle, param, &val);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonDeserialize() ret %d", esfj_ret);
        dc_ret = DcInternal;
        goto write_sensor_register_param_exit;
    }

    // Get register property.
    dc_ret = GetSensorRegisterParam(esfj_handle, val, sensor_register_param, true);

write_sensor_register_param_exit:

    // Close handle.

    esfj_ret = EsfJsonClose(esfj_handle);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonClose() ret %d", esfj_ret);
    }

    return dc_ret;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
STATIC RetCode ExecReadSensorRegister8bit(senscord_stream_t scstream,
                                          SensorRegisterInfo *sensor_register_info)
{
    RetCode ret = kRetOk;
    struct senscord_register_access_8_property_t sc_data;
    int32_t sc_ret;

    sc_data.id = SENSOR_REGISTER_ID_IMX500;
    sc_data.address = sensor_register_info->address;

    sc_ret = senscord_stream_get_property(scstream, SENSCORD_REGISTER_ACCESS_8_PROPERTY_KEY,
                                          &sc_data, sizeof(sc_data));

    if (sc_ret < 0) {
        SYSAPP_ERR("senscord_stream_get_property(Register, 8bit) ret=%d", sc_ret);
        ret = kRetFailed;
        goto exit;
    }

    sensor_register_info->value = sc_data.data;

exit:
    return ret;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
STATIC RetCode ExecReadSensorRegister16bit(senscord_stream_t scstream,
                                           SensorRegisterInfo *sensor_register_info)
{
    RetCode ret = kRetOk;
    struct senscord_register_access_16_property_t sc_data;
    int32_t sc_ret;

    sc_data.id = SENSOR_REGISTER_ID_IMX500;
    sc_data.address = sensor_register_info->address;

    sc_ret = senscord_stream_get_property(scstream, SENSCORD_REGISTER_ACCESS_16_PROPERTY_KEY,
                                          &sc_data, sizeof(sc_data));

    if (sc_ret < 0) {
        SYSAPP_ERR("senscord_stream_get_property(Register, 16bit) ret=%d", sc_ret);
        ret = kRetFailed;
        goto exit;
    }

    sensor_register_info->value = sc_data.data;

exit:
    return ret;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
STATIC RetCode ExecReadSensorRegister32bit(senscord_stream_t scstream,
                                           SensorRegisterInfo *sensor_register_info)
{
    RetCode ret = kRetOk;
    struct senscord_register_access_32_property_t sc_data;
    int32_t sc_ret;

    sc_data.id = SENSOR_REGISTER_ID_IMX500;
    sc_data.address = sensor_register_info->address;

    sc_ret = senscord_stream_get_property(scstream, SENSCORD_REGISTER_ACCESS_32_PROPERTY_KEY,
                                          &sc_data, sizeof(sc_data));

    if (sc_ret < 0) {
        SYSAPP_ERR("senscord_stream_get_property(Register, 32bit) ret=%d", sc_ret);
        ret = kRetFailed;
        goto exit;
    }

    sensor_register_info->value = sc_data.data;

exit:
    return ret;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
STATIC DcResult ExecReadSensorRegister(SensorRegisterParam *sensor_register_param)
{
    DcResult dc_ret = DcOk;
    int idx;
    RetCode ret = kRetOk;
    senscord_stream_t scstream;

    // Get handle of SensCord.

    ret = SysAppStateGetSensCordStream((void *)&scstream);

    if (ret != kRetOk) {
        SYSAPP_ERR("SysAppStateGetSensCordStream ret=%d", ret);
        dc_ret = DcInternal;
        goto exit;
    }

    // Get sensor register.

    for (idx = 0; idx < sensor_register_param->num; idx++) {
        switch (sensor_register_param->info[idx].size) {
            case RegiSize1Byte:
                ret = ExecReadSensorRegister8bit(scstream, &sensor_register_param->info[idx]);
                break;
            case RegiSize2Byte:
                ret = ExecReadSensorRegister16bit(scstream, &sensor_register_param->info[idx]);
                break;
            case RegiSize4Byte:
            default:
                ret = ExecReadSensorRegister32bit(scstream, &sensor_register_param->info[idx]);
                break;
        }

        if (ret != kRetOk) {
            dc_ret = DcInternal;
            goto exit;
        }
    }

exit:
    return dc_ret;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
STATIC RetCode ExecWriteSensorRegister8bit(senscord_stream_t scstream,
                                           SensorRegisterInfo *sensor_register_info)
{
    RetCode ret = kRetOk;
    struct senscord_register_access_8_property_t sc_data;
    int32_t sc_ret;

    sc_data.id = SENSOR_REGISTER_ID_IMX500;
    sc_data.address = sensor_register_info->address;
    sc_data.data = sensor_register_info->value;

    sc_ret = senscord_stream_set_property(scstream, SENSCORD_REGISTER_ACCESS_8_PROPERTY_KEY,
                                          &sc_data, sizeof(sc_data));

    if (sc_ret < 0) {
        SYSAPP_ERR("senscord_stream_set_property(Register, 8bit) ret=%d", sc_ret);
        ret = kRetFailed;
        goto exit;
    }

exit:
    return ret;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
STATIC RetCode ExecWriteSensorRegister16bit(senscord_stream_t scstream,
                                            SensorRegisterInfo *sensor_register_info)
{
    RetCode ret = kRetOk;
    struct senscord_register_access_16_property_t sc_data;
    int32_t sc_ret;

    sc_data.id = SENSOR_REGISTER_ID_IMX500;
    sc_data.address = sensor_register_info->address;
    sc_data.data = sensor_register_info->value;

    sc_ret = senscord_stream_set_property(scstream, SENSCORD_REGISTER_ACCESS_16_PROPERTY_KEY,
                                          &sc_data, sizeof(sc_data));

    if (sc_ret < 0) {
        SYSAPP_ERR("senscord_stream_set_property(Register, 16bit) ret=%d", sc_ret);
        ret = kRetFailed;
        goto exit;
    }

exit:
    return ret;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
STATIC RetCode ExecWriteSensorRegister32bit(senscord_stream_t scstream,
                                            SensorRegisterInfo *sensor_register_info)
{
    RetCode ret = kRetOk;
    struct senscord_register_access_32_property_t sc_data;
    int32_t sc_ret;

    sc_data.id = SENSOR_REGISTER_ID_IMX500;
    sc_data.address = sensor_register_info->address;
    sc_data.data = sensor_register_info->value;

    sc_ret = senscord_stream_set_property(scstream, SENSCORD_REGISTER_ACCESS_32_PROPERTY_KEY,
                                          &sc_data, sizeof(sc_data));

    if (sc_ret < 0) {
        SYSAPP_ERR("senscord_stream_set_property(Register, 32bit) ret=%d", sc_ret);
        ret = kRetFailed;
        goto exit;
    }

exit:
    return ret;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
STATIC DcResult ExecWriteSensorRegister(SensorRegisterParam *sensor_register_param)
{
    DcResult dc_ret = DcOk;
    int idx;
    RetCode ret = kRetOk;
    senscord_stream_t scstream;

    // Get handle of SensCord.

    ret = SysAppStateGetSensCordStream((void *)&scstream);

    if (ret != kRetOk) {
        SYSAPP_ERR("SysAppStateGetSensCordStream ret=%d", ret);
        dc_ret = DcInternal;
        goto exit;
    }

    // Get sensor register.

    for (idx = 0; idx < sensor_register_param->num; idx++) {
        switch (sensor_register_param->info[idx].size) {
            case RegiSize1Byte:
                ret = ExecWriteSensorRegister8bit(scstream, &sensor_register_param->info[idx]);
                break;
            case RegiSize2Byte:
                ret = ExecWriteSensorRegister16bit(scstream, &sensor_register_param->info[idx]);
                break;
            case RegiSize4Byte:
            default:
                ret = ExecWriteSensorRegister32bit(scstream, &sensor_register_param->info[idx]);
                break;
        }

        if (ret != kRetOk) {
            dc_ret = DcInternal;
            goto exit;
        }
    }

exit:
    return dc_ret;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
STATIC RetCode MakeJsonRegisterParams(EsfJsonHandle handle, EsfJsonValue root, uint32_t no,
                                      void *ctx)
{
    SensorRegisterParam *sensor_register_param = (SensorRegisterParam *)ctx;

    // Set address.
    SysAppCmnSetRealNumberValue(handle, root, "address", sensor_register_param->info[no].address);

    // Set size.
    SysAppCmnSetNumberValue(handle, root, "size", sensor_register_param->info[no].size);

    // Set value.
    SysAppCmnSetRealNumberValue(handle, root, "value", sensor_register_param->info[no].value);

    return kRetOk;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------*/
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
STATIC RetCode SetRegisterProperty(EsfJsonHandle handle, EsfJsonValue val, void *param,
                                   size_t param_size)
{
    (void)param_size;
    RetCode ret = kRetOk;
    SensorRegisterParam *sensor_register_param = (SensorRegisterParam *)param;

    ret = SysAppCmnSetArrayValue(handle, val, "register", sensor_register_param->num,
                                 MakeJsonRegisterParams, param);

    if (ret != kRetOk) {
        SYSAPP_WARN("Set register body failed. %d", ret);
    }

    return ret;
}
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

/*----------------------------------------------------------------------*/
static bool CheckDirectCommandExecutable(void)
{
    // Check direct command execution state.

    // Check factory reset state.

    if (s_terminate_request == FactoryResetRequested) {
        SYSAPP_INFO("Factory reset is working by DirectCommand.");
        return false;
    }

    if (SysAppBtnCheckFactoryResetRequest() == true) {
        SYSAPP_INFO("Factory reset is working by button.");
        return false;
    }

    // Check deploying state.

    // Check rebooting state.

    if (s_terminate_request == RebootRequested) {
        SYSAPP_INFO("Reboot is working by DirectCommand.");
        return false;
    }

    // Check operation mode.

    // Check  config mode.

    return true;
}

/*----------------------------------------------------------------------*/
static RetCode DirectCommandCallbackCommon(SYS_response_id cmd_id, const char *params,
                                           char *req_id_buf, uint32_t buf_len)
{
    // Get req_info.

    GetReqId(params, req_id_buf, buf_len);

    // Check executable or not.

    if (CheckDirectCommandExecutable() != true) {
        RetCode ret = SendDirectCommandResponseAsync(
            s_sys_client, cmd_id, req_id_buf, DcUnavailable, NULL, NULL, 0 /*Don't care*/, false);
        if (ret != kRetOk) {
            SYSAPP_ERR("Send response failed ret %d", ret);
        }
        return kRetBusy;
    }

    return kRetOk;
}
/*----------------------------------------------------------------------*/
STATIC void DirectCommandRebootCallback(struct SYS_client *client, SYS_response_id cmd_id,
                                        const char *params, void *user_context)
{
    if ((params == NULL)) {
        SYSAPP_ERR("DirectCommandRebootCallback(%d, %p, %p)", (int)cmd_id, params, user_context);
    }
    SYSAPP_INFO("DirectCommand callback (cmd_id %ju, %s)", cmd_id, "reboot");
    SYSAPP_DBG("Params %s", params);
    // Execute all command common process
    char req_id[CFG_RES_ID_LEN + 1] = "0";
    if (DirectCommandCallbackCommon(cmd_id, params, req_id, sizeof(req_id)) != kRetOk) {
        return;
    }

    // Execute direct commands.

    SysAppDcmdReboot(cmd_id, req_id, params);
}
/*----------------------------------------------------------------------*/
STATIC void DirectCommandShutdownCallback(struct SYS_client *client, SYS_response_id cmd_id,
                                          const char *params, void *user_context)
{
    if ((params == NULL)) {
        SYSAPP_ERR("DirectCommandShutdownCallback(%d, %p, %p)", (int)cmd_id, params, user_context);
    }
    SYSAPP_INFO("DirectCommand callback (cmd_id %ju, %s)", cmd_id, "shutdown");
    SYSAPP_DBG("Params %s", params);
    // Execute all command common process
    char req_id[CFG_RES_ID_LEN + 1] = "0";
    if (DirectCommandCallbackCommon(cmd_id, params, req_id, sizeof(req_id)) != kRetOk) {
        return;
    }
    // Execute direct commands.
    SysAppDcmdShutdown(cmd_id, req_id, params);
}
/*----------------------------------------------------------------------*/
STATIC void DirectCommandFactoryResetCallback(struct SYS_client *client, SYS_response_id cmd_id,
                                              const char *params, void *user_context)
{
    if ((params == NULL)) {
        SYSAPP_ERR("DirectCommandFactoryResetCallback(%d, %p, %p)", (int)cmd_id, params,
                   user_context);
    }
    SYSAPP_INFO("DirectCommand callback (cmd_id %ju, %s)", cmd_id, "factory_reset");
    SYSAPP_DBG("Params %s", params);
    // Execute all command common process
    char req_id[CFG_RES_ID_LEN + 1] = "0";
    if (DirectCommandCallbackCommon(cmd_id, params, req_id, sizeof(req_id)) != kRetOk) {
        return;
    }
    // Execute direct commands.
    SysAppDcmdFactoryReset(cmd_id, req_id, params);
}
/*----------------------------------------------------------------------*/
STATIC void DirectCommandDirectGetImageCallback(struct SYS_client *client, SYS_response_id cmd_id,
                                                const char *params, void *user_context)
{
    if ((params == NULL)) {
        SYSAPP_ERR("DirectCommandDirectGetImageCallback(%d, %p, %p)", (int)cmd_id, params,
                   user_context);
    }
    SYSAPP_INFO("DirectCommand callback (cmd_id %ju, %s)", cmd_id, "direct_get_image");
    SYSAPP_DBG("Params %s", params);
    // Execute all command common process
    char req_id[CFG_RES_ID_LEN + 1] = "0";
    if (DirectCommandCallbackCommon(cmd_id, params, req_id, sizeof(req_id)) != kRetOk) {
        return;
    }
    // Execute direct commands.
    SysAppDcmdDirectGetImage(cmd_id, req_id, params);
}
/*----------------------------------------------------------------------*/
STATIC void DirectCommandReadSensorRegisterCallback(struct SYS_client *client,
                                                    SYS_response_id cmd_id, const char *params,
                                                    void *user_context)
{
    if ((params == NULL)) {
        SYSAPP_ERR("DirectCommandReadSensorRegisterCallback(%d, %p, %p)", (int)cmd_id, params,
                   user_context);
    }
    SYSAPP_INFO("DirectCommand callback (cmd_id %ju, %s)", cmd_id, "read_sensor_register");
    SYSAPP_DBG("Params %s", params);
    // Execute all command common process
    char req_id[CFG_RES_ID_LEN + 1] = "0";
    if (DirectCommandCallbackCommon(cmd_id, params, req_id, sizeof(req_id)) != kRetOk) {
        return;
    }

    // Execute direct commands.
    SysAppDcmdReadSensorRegister(cmd_id, req_id, params);
}
/*----------------------------------------------------------------------*/
STATIC void DirectCommandWriteSensorRegisterCallback(struct SYS_client *client,
                                                     SYS_response_id cmd_id, const char *params,
                                                     void *user_context)
{
    if ((params == NULL)) {
        SYSAPP_ERR("DirectCommandWriteSensorRegisterCallback(%d, %p, %p)", (int)cmd_id, params,
                   user_context);
    }
    SYSAPP_INFO("DirectCommand callback (cmd_id %ju, %s)", cmd_id, "write_sensor_register");
    SYSAPP_DBG("Params %s", params);
    // Execute all command common process
    char req_id[CFG_RES_ID_LEN + 1] = "0";
    if (DirectCommandCallbackCommon(cmd_id, params, req_id, sizeof(req_id)) != kRetOk) {
        return;
    }
    // Execute direct commands.
    SysAppDcmdWriteSensorRegister(cmd_id, req_id, params);
}

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
/*----------------------------------------------------------------------*/
STATIC void DirectCommandUnimplementedCallback(struct SYS_client *client, SYS_response_id cmd_id,
                                               const char *params, void *user_context)
{
    if (params == NULL) {
        SYSAPP_ERR("DirectCommandUnimplementedCallback(%ju, %p, %p)", cmd_id, params, user_context);
    }
    SYSAPP_INFO("DirectCommand callback (cmd_id %ju, %s)", cmd_id, (const char *)user_context);
    SYSAPP_DBG("Params %s", params);
    // Execute all command common process
    char req_id[CFG_RES_ID_LEN + 1] = "0";
    if (DirectCommandCallbackCommon(cmd_id, params, req_id, sizeof(req_id)) != kRetOk) {
        return;
    }

    // Send "unimplemented" error response
    RetCode ret = SendDirectCommandResponseAsync(s_sys_client, cmd_id, req_id, DcUnimplemented,
                                                 NULL, NULL, 0 /*Don't care*/, false);
    if (ret != kRetOk) {
        SYSAPP_ERR("Send response failed ret %d", ret);
    }
}

/*----------------------------------------------------------------------*/
STATIC bool IsUnimplementedMethod(const char *method)
{
    static const char *unimplemented_methods[] = {
        "shutdown",
        "factory_reset",
        "read_sensor_register",
        "write_sensor_register",
    };

    bool ret = false;

    for (size_t i = 0; i < ARRAY_SIZE(unimplemented_methods); i++) {
        if (strcmp(method, unimplemented_methods[i]) == 0) {
            ret = true;
            break;
        }
    }

    return ret;
}
#endif // !CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION

/*----------------------------------------------------------------------*/
static RetCode RegisterDirectCommandCallback(void)
{
    static const struct {
        const char *method;
        SYS_command_cb cb;
    } table[] = {
        {.method = "reboot", .cb = DirectCommandRebootCallback},
        {.method = "shutdown", .cb = DirectCommandShutdownCallback},
        {.method = "factory_reset", .cb = DirectCommandFactoryResetCallback},
        {.method = "direct_get_image", .cb = DirectCommandDirectGetImageCallback},
        {.method = "read_sensor_register", .cb = DirectCommandReadSensorRegisterCallback},
        {.method = "write_sensor_register", .cb = DirectCommandWriteSensorRegisterCallback},
    };

    RetCode ret = kRetOk;
    enum SYS_result sys_ret;
    SYS_command_cb cb;
    void *user_context;

    for (size_t i = 0; i < ARRAY_SIZE(table); i++) {
        cb = table[i].cb;
        user_context = NULL;

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
        if (IsUnimplementedMethod(table[i].method)) {
            cb = DirectCommandUnimplementedCallback;
            user_context = (void *)table[i].method;
        }
#endif // !CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION

        sys_ret = SYS_register_command_cb(s_sys_client, table[i].method, cb, user_context);
        if (sys_ret != SYS_RESULT_OK) {
            SYSAPP_CRIT("SYS_register_command_cb(%p, %s, %p, %p) ret %d", s_sys_client,
                        table[i].method, cb, user_context, sys_ret);

            ret = kRetFailed;
            break;
        }
    }

    return ret;
}

//
// Public functions.
//

/*----------------------------------------------------------------------*/
RetCode SysAppDcmdInitialize(struct SYS_client *sys_client)
{
    SYSAPP_INFO("Initialize DirectCommand block.");
    RetCode ret = kRetOk;

    // Check and save sys_client.

    if (sys_client == NULL) {
        SYSAPP_CRIT("sys_client is NULL.");
        return kRetFailed;
    }

    s_sys_client = sys_client;

    // Register direct command callback.

    if (RegisterDirectCommandCallback() != kRetOk) {
        ret = kRetFailed;
        goto evp_set_rpc_callback_error;
    }

#if 0 /*T.B.D EsfPwrMgrStart_always_fails*/
  // Initialise SSF(PowerManager).

  EsfPwrMgrError esfpm_ret = EsfPwrMgrStart();

  if (esfpm_ret != kEsfPwrMgrOk) {
    SYSAPP_ERR("EsfPwrMgrStart() ret %d", esfpm_ret);
    ret = kRetFailed;
    goto ssfpw_start_error;
  }
#endif

    //const char paramstr[] = "{\"req_info\":{\"req_id\":\"reboot_hoge_id\"}}";
    //DirectCommandCallback(0, "reboot", paramstr, NULL);

    //const char paramstr[] = "{\"req_info\":{\"req_id\":\"shutdown_hoge_id\"}}";
    //DirectCommandCallback(0, "shutdown", paramstr, NULL);

    //const char paramstr[] = "{\"req_info\":{\"req_id\":\"factory_reset_hoge_id\"}}";
    //DirectCommandCallback(0, "factory_reset", paramstr, NULL);

    return ret;

    //
    // Error handling.
    //

#if 0 /*T.B.D EsfPwrMgrStart_always_fails*/
ssfpw_start_error:
#endif

evp_set_rpc_callback_error:

    return ret;
}

/*----------------------------------------------------------------------*/
RetCode SysAppDcmdFinalize(void)
{
    SYSAPP_INFO("Finalize DirectCommand block.");

    RetCode ret = kRetOk;

#if 0 /*T.B.D EsfPwrMgrStart_always_fails*/
  EsfPwrMgrError esfpm_ret = EsfPwrMgrStop();

  if (esfpm_ret != kEsfPwrMgrOk) {
    SYSAPP_ERR("EsfPwrMgrStop() ret %d", esfpm_ret);
    ret = kRetFailed;
  }
#endif

    return ret;
}

/*----------------------------------------------------------------------*/
bool SysAppDcmdCheckSelfTerminate(TerminationReason *reason)
{
    *reason = s_terminate_request;

    return (s_terminate_request != UnDefined) ? true : false;
}

/*----------------------------------------------------------------------*/
void SysAppDcmdRebootCore(void)
{
    SYSAPP_INFO("Execute reboot!");

    s_terminate_request = UnDefined;

    // Execute reboot.(API name is prepare, but execute.)

    EsfPwrMgrError esfpm_ret = EsfPwrMgrPrepareReboot();

    if (esfpm_ret != kEsfPwrMgrOk) {
        SYSAPP_ERR("EsfPwrMgrPrepareReboot() ret %d", esfpm_ret);
    }
}

/*----------------------------------------------------------------------*/
RetCode SysAppDcmdReboot(SYS_response_id cmd_id, const char *req_id, const char *param)
{
    (void)param;
    RetCode ret = kRetOk;

    SYSAPP_ELOG_INFO(SYSAPP_EVT_REBOOT_STARTED);

    // Before reboot, send command response and wait response of it.

    ret = SendDirectCommandResponseSync(s_sys_client, cmd_id, req_id, DcOk, NULL, NULL,
                                        0 /*Don't care*/, false);

    if (ret != kRetOk) {
        SYSAPP_WARN("SendDirectCommandResponseSync() ret %d", ret);
    }

    // Request reboot.
    // Reboot will be executed after.

    s_terminate_request = RebootRequested;

    return ret;
}

/*----------------------------------------------------------------------*/
RetCode SysAppDcmdShutdown(SYS_response_id cmd_id, const char *req_id, const char *param)
{
    (void)param;
    RetCode ret = kRetOk;

    // Before shutdown, send command response and wait response of it.

    ret = SendDirectCommandResponseSync(s_sys_client, cmd_id, req_id, DcUnimplemented, NULL, NULL,
                                        0 /*Don't care*/, false);

    if (ret != kRetOk) {
        SYSAPP_WARN("SendDirectCommandResponseSync() ret %d", ret);
    }

    return ret;
}

/*----------------------------------------------------------------------*/
void SysAppDcmdFactoryResetCore(void)
{
    SYSAPP_INFO("Execute factory reset!");

    s_terminate_request = UnDefined;

    // Start factory reset, this API will execute reboot afeter factory reset process.

    EsfFwMgrResult esffm_ret = EsfFwMgrStartFactoryReset(kEsfFwMgrResetCauseCommand);

    if (esffm_ret != kEsfFwMgrResultOk) {
        SYSAPP_ERR("EsfFwMgrStartFactoryReset() ret %d", esffm_ret);
    }
}

/*----------------------------------------------------------------------*/
RetCode SysAppDcmdFactoryReset(SYS_response_id cmd_id, const char *req_id, const char *param)
{
    (void)param;
    RetCode ret = kRetOk;

    // Before factory reset, send command response and wait response of it.

    DcResult dc_result = DcOk;

    ret = SendDirectCommandResponseSync(s_sys_client, cmd_id, req_id, dc_result, NULL, NULL,
                                        0 /*Don't care*/, false);

    if (ret != kRetOk) {
        SYSAPP_WARN("SendDirectCommandResponseSync() ret %d", ret);
    }

    // Execute factory reset.

    {
        SYSAPP_ELOG_INFO(SYSAPP_EVT_FACTORY_RESET_FROM_CONSOLE_STARTED);

        // Force undeploy modules.

        int evp_ret = EVP_undeployModules();

        if (evp_ret != 1) {
            SYSAPP_WARN("EVP_undeployModules() ret %d", evp_ret);
        }

        // Request shutdown.
        // Shutdown will be executed after.

        s_terminate_request = FactoryResetRequested;
    }

    return ret;
}

/*----------------------------------------------------------------------*/
RetCode SysAppDcmdDirectGetImage(SYS_response_id cmd_id, const char *req_id, const char *param)
{
    RetCode ret = kRetOk;
    size_t b64_size = 0;

    SYSAPP_ELOG_INFO(SYSAPP_EVT_DIRECT_GET_IMAGE_REQUEST_STARTED);

    // Parse and get properties.

    DirectGetImageParam dgiparam = {0};

    DcResult dc_ret = GetDirectGetImageParams(param, &dgiparam);

    if (dc_ret != DcOk) {
        SYSAPP_ERR("Get param failed ret %d", dc_ret);
        goto get_param_failed;
    }

    // Get a frame.

    FrameInfo frame = {0};

    ret = GetOneFrame(&dgiparam, &frame);

    if (ret != kRetOk) {
        SYSAPP_ELOG_ERR(SYSAPP_EVT_FAILED_TO_DIRET_GET_IMAGE_SENOR_ERROR);
        SYSAPP_ERR("Get one frame failed ret %d", ret);
        dc_ret = DcInternal;
        goto get_one_frame_failed;
    }

    // Encode a frame to jpeg that will be encoded to base64.

    uint32_t jpeg_size = 0;
    const uint32_t jpeg_buf_size = DC_DIRECT_GET_IMAGE_MAX_SIZE * 3 / 4;
    encode_buf_t jpeg_buf = {0};
    bool use_handle = (frame.handle != 0);

    ret = AllocateEncodeBuffer(&jpeg_buf, jpeg_buf_size, use_handle);

    if (ret == kRetOk) {
        ret = EncodeToJpeg(&frame, &jpeg_buf, jpeg_buf_size, &jpeg_size, use_handle);
        if (ret != kRetOk) {
            SYSAPP_ERR("Jpeg encode failed ret %d", ret);
            dc_ret = DcInternal;
            goto jpeg_encode_failed;
        }
    }
    else {
        dc_ret = DcInternal;
        goto jpeg_encode_failed;
    }

    // Encode jpeg to base64. The size of base64 will be 4/3 of jpeg.

    const uint32_t b64_buf_size = EsfCodecBase64GetEncodeSize(jpeg_size);
    encode_buf_t b64_buf = {0};

    ret = AllocateEncodeBuffer(&b64_buf, b64_buf_size, use_handle);

    if (ret == kRetOk) {
        ret = EncodeToBase64(&jpeg_buf, jpeg_size, &b64_buf, b64_buf_size,
                             &b64_size /* This size is including null char.*/, use_handle);
        if (ret != kRetOk) {
            SYSAPP_ERR("Base64 encode failed ret %d", ret);
            FreeEncodeBuffer(&b64_buf, use_handle);
            dc_ret = DcInternal;
            goto base64_encode_failed;
        }
    }
    else {
        dc_ret = DcInternal;
        goto base64_encode_failed;
    }

base64_encode_failed:

    // Free jpeg buffer.

    FreeEncodeBuffer(&jpeg_buf, use_handle);

jpeg_encode_failed:

    // Release a frame.

    ret = ReleaseOneFrame(&frame);

    if (ret != kRetOk) {
        SYSAPP_ERR("Release one frame failed ret %d", ret);
        dc_ret = DcInternal;
    }

get_one_frame_failed:
get_param_failed:

    // Send response.

    RetCode (*additional)(EsfJsonHandle, EsfJsonValue, void *, size_t);
    void *additional_param;
    size_t additional_param_size;
    bool is_additional_param_file_io;
    if (dc_ret == DcOk) {
        if (use_handle) {
            additional = SetImagePropertyHandle;
            additional_param = (void *)(uintptr_t)b64_buf.handle;
        }
        else {
            additional = SetImageProperty;
            additional_param = b64_buf.raw;
        }
        additional_param_size = b64_size;
        is_additional_param_file_io = use_handle;
    }
    else {
        additional = SetImageProperty;
        additional_param = NULL;
        additional_param_size = 0;
        is_additional_param_file_io = false;
    }

    ret = SendDirectCommandResponseAsync(s_sys_client, cmd_id, req_id, dc_ret, additional,
                                         additional_param, additional_param_size,
                                         is_additional_param_file_io);

    if (ret != kRetOk) {
        SYSAPP_ERR("Send response failed ret %d", ret);
    }

    return ret;
}

/*----------------------------------------------------------------------*/
RetCode SysAppDcmdReadSensorRegister(SYS_response_id cmd_id, const char *req_id, const char *param)
{
    RetCode ret = kRetOk;

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
    DcResult dc_ret;
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};

    // Parse and get properties.

    dc_ret = GetReadSensorRegisterParam(param, &sensor_register_param);

    if (dc_ret != DcOk) {
        SYSAPP_ERR("Get param failed ret %d", dc_ret);
        sensor_register_param.num = 0;
        ret = kRetFailed;
        goto exit;
    }

    // Read register value.

    dc_ret = ExecReadSensorRegister(&sensor_register_param);

    if (dc_ret != DcOk) {
        SYSAPP_ERR("Read register value failed ret %d", dc_ret);
        sensor_register_param.num = 0;
        ret = kRetFailed;
        goto exit;
    }

exit:

    // Send response.

    RetCode ret_send = SendDirectCommandResponseAsync(s_sys_client, cmd_id, req_id, dc_ret,
                                                      SetRegisterProperty, &sensor_register_param,
                                                      0 /*Don't care*/, false);
    if (ret_send != kRetOk) {
        SYSAPP_ERR("Send response failed ret %d", ret_send);
        ret = kRetFailed;
    }

    // Free memory.

    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP

    // SystemApp not support this command, but it's defined on DTDL, so, always return "unimplemented".

    (void)param;
    ret = SendDirectCommandResponseAsync(s_sys_client, cmd_id, req_id, DcUnimplemented, NULL, NULL,
                                         0 /*Don't care*/, false);

    if (ret != kRetOk) {
        SYSAPP_WARN("SendDirectCommandResponseAsync() ret %d", ret);
    }

#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP

    return ret;
}

/*----------------------------------------------------------------------*/
RetCode SysAppDcmdWriteSensorRegister(SYS_response_id cmd_id, const char *req_id, const char *param)
{
    RetCode ret = kRetOk;

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
    DcResult dc_ret;
    SensorRegisterParam sensor_register_param = {.num = 0, .info = NULL};

    // Parse and get properties.

    dc_ret = GetWriteSensorRegisterParam(param, &sensor_register_param);

    if (dc_ret != DcOk) {
        SYSAPP_ERR("Get param failed ret %d", dc_ret);
        ret = kRetFailed;
        goto exit;
    }

    // Write register value.

    dc_ret = ExecWriteSensorRegister(&sensor_register_param);

    if (dc_ret != DcOk) {
        SYSAPP_ERR("Write register value failed ret %d", dc_ret);
        ret = kRetFailed;
        goto exit;
    }

exit:

    // Send response.

    RetCode ret_send = SendDirectCommandResponseAsync(s_sys_client, cmd_id, req_id, dc_ret, NULL,
                                                      NULL, 0 /*Don't care*/, false);
    if (ret_send != kRetOk) {
        SYSAPP_ERR("Send response failed ret %d", ret_send);
        ret = kRetFailed;
    }

    // Free memory.

    if (sensor_register_param.info != NULL) {
        free(sensor_register_param.info);
    }

#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP

    // SystemApp not support this command, but it's defined on DTDL, so, always return "unimplemented".

    (void)param;
    ret = SendDirectCommandResponseAsync(s_sys_client, cmd_id, req_id, DcUnimplemented, NULL, NULL,
                                         0 /*Don't care*/, false);

    if (ret != kRetOk) {
        SYSAPP_WARN("SendDirectCommandResponseAsync() ret %d", ret);
    }

#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP

    return ret;
}
