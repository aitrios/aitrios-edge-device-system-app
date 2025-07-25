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

#include "sensor_main.h"
#include "senscord/c_api/senscord_c_api.h"
#include "senscord/inference_stream/c_api/property_c_types.h"
#include "led_manager.h"
#include "power_manager.h"
#include "system_manager.h"
#include "utility_log.h"

#if defined(__NuttX__)
#include <nuttx/config.h>
#endif

#include "initial_setting_app_main.h"
#include "initial_setting_app_ps.h"
#include "initial_setting_app_qrcode.h"
#include "initial_setting_app_qr_decode.h"
#include "initial_setting_app_timer.h"
#include "system_app_common.h"

extern bool InitializeApp(struct senscord_image_property_t* img_prop);
extern void FinalizeApp(void);
extern void SetLedStatusForQrCodeMode(void);
extern void UnsetLedStatusOfWaitingInputToConnectConsole(void);
extern void SetLedStatusForQrCodeError(void);
extern void UnsetLedStatusForQrCodeError(void);
extern void QrModeTimerCallback(void);
extern bool IsQrModeTimeout(void);

extern senscord_core_t s_core;
extern senscord_stream_t s_stream;

extern bool s_senscord_core_init_success;
extern bool s_senscord_open_success;
extern bool s_senscord_start_success;

extern uint8_t* sp_qrcode_payload_buff;

extern bool s_qr_mode_timeout_reboot_request;

#if defined(INITIAL_SETTING_APP_UT) && defined(__NuttX__)
int initial_setting_app_main_for_test(int argc, char* argv[]);
#endif // INITIAL_SETTING_APP_UT

/*----------------------------------------------------------------------------*/
//
// For SensCord API
//
/*----------------------------------------------------------------------------*/
static void GetSensCordStringProperty(int32_t ret)
{
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
    struct senscord_info_string_property_t sensor_id = {0};
    sensor_id.category = SENSCORD_INFO_STRING_SENSOR_ID;
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
    struct senscord_info_string_property_t aiisp = {0};
    aiisp.category = SENSCORD_INFO_STRING_AIISP_DEVICE_ID;
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP

    expect_value(__wrap_senscord_stream_get_property, stream, s_stream);
    expect_string(__wrap_senscord_stream_get_property, property_key,
                  SENSCORD_INFO_STRING_PROPERTY_KEY);
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
    expect_value(__wrap_senscord_stream_get_property, value_size, sizeof(sensor_id));
    will_return(__wrap_senscord_stream_get_property, &sensor_id);
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
    expect_value(__wrap_senscord_stream_get_property, value_size, sizeof(aiisp));
    will_return(__wrap_senscord_stream_get_property, &aiisp);
#endif // CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
    will_return(__wrap_senscord_stream_get_property, ret);
}

/*----------------------------------------------------------------------------*/
static void SetSensCordAIModelProperty(int32_t ret)
{
    struct senscord_ai_model_bundle_id_property_t ai_model_bundle_id = {};
    expect_value(__wrap_senscord_stream_set_property, stream, s_stream);
    expect_string(__wrap_senscord_stream_set_property, property_key,
                  SENSCORD_AI_MODEL_BUNDLE_ID_PROPERTY_KEY);
    expect_memory(__wrap_senscord_stream_set_property, ai_model->ai_model_bundle_id,
                  AIMODEL_ID_FOR_QRCODE,
                  strlen(AIMODEL_ID_FOR_QRCODE)); // for mock function
    expect_value(__wrap_senscord_stream_set_property, value_size, sizeof(ai_model_bundle_id));
    will_return(__wrap_senscord_stream_set_property, ret);
}

/*----------------------------------------------------------------------------*/
static void SetSensCordInputDataProperty(int32_t ret)
{
    struct senscord_input_data_type_property_t input_data = {};
    expect_value(__wrap_senscord_stream_set_property, stream, s_stream);
    expect_string(__wrap_senscord_stream_set_property, property_key,
                  SENSCORD_INPUT_DATA_TYPE_PROPERTY_KEY);
    expect_value(__wrap_senscord_stream_set_property, input_data->count, 1);
    expect_value(__wrap_senscord_stream_set_property, input_data->channels[0], 0x1);
    expect_value(__wrap_senscord_stream_set_property, value_size, sizeof(input_data));
    will_return(__wrap_senscord_stream_set_property, ret);
}

/*----------------------------------------------------------------------------*/
static void GetSensCordGetProperty(struct senscord_image_property_t** expected_img_prop,
                                   int32_t ret)
{
    expect_value(__wrap_senscord_stream_get_property, stream, s_stream);
    expect_string(__wrap_senscord_stream_get_property, property_key, SENSCORD_IMAGE_PROPERTY_KEY);
    expect_value(__wrap_senscord_stream_get_property, value_size,
                 sizeof(struct senscord_image_property_t));
    will_return(__wrap_senscord_stream_get_property, *expected_img_prop);
    will_return(__wrap_senscord_stream_get_property, ret);
}

/*----------------------------------------------------------------------------*/
static void SensCordCoreInit(int32_t ret)
{
    expect_value(__wrap_senscord_core_init, core, &s_core);
    will_return(__wrap_senscord_core_init, ret);
}

/*----------------------------------------------------------------------------*/
static void SensCordCoreOpenStream(int32_t ret)
{
    expect_value(__wrap_senscord_core_open_stream, core, s_core);
    expect_string(__wrap_senscord_core_open_stream, stream_key, "inference_stream");
    expect_value(__wrap_senscord_core_open_stream, stream, &s_stream);
    will_return(__wrap_senscord_core_open_stream, ret);
}

/*----------------------------------------------------------------------------*/
static void SensCordStreamStart(int32_t ret)
{
    expect_value(__wrap_senscord_stream_start, stream, s_stream);
    will_return(__wrap_senscord_stream_start, ret);
}

/*----------------------------------------------------------------------------*/
static void SensCordGetFrame(int32_t ret)
{
    expect_value(__wrap_senscord_stream_get_frame, stream, s_stream);
    expect_value(__wrap_senscord_stream_get_frame, timeout_msec, -1);
    will_return(__wrap_senscord_stream_get_frame, 0); // dummy frame
    will_return(__wrap_senscord_stream_get_frame, ret);
}

/*----------------------------------------------------------------------------*/
static void SensCordGetChannelId(senscord_frame_t frame, uint32_t channel_id, int32_t ret)
{
    expect_value(__wrap_senscord_frame_get_channel_from_channel_id, frame, frame);
    expect_value(__wrap_senscord_frame_get_channel_from_channel_id, channel_id, channel_id);
    will_return(__wrap_senscord_frame_get_channel_from_channel_id, 0); // dummy channel
    will_return(__wrap_senscord_frame_get_channel_from_channel_id, ret);
}

/*----------------------------------------------------------------------------*/
static void SensCordStreamStop(int32_t ret)
{
    expect_value(__wrap_senscord_stream_stop, stream, s_stream);
    will_return(__wrap_senscord_stream_stop, ret);
}

/*----------------------------------------------------------------------------*/
static void SensCordCoreCloseStream(int32_t ret)
{
    expect_value(__wrap_senscord_core_close_stream, core, s_core);
    expect_value(__wrap_senscord_core_close_stream, stream, s_stream);
    will_return(__wrap_senscord_core_close_stream, ret);
}

/*----------------------------------------------------------------------------*/
static void SensCordCoreExit(int32_t ret)
{
    expect_value(__wrap_senscord_core_exit, core, s_core);
    will_return(__wrap_senscord_core_exit, ret);
}

/*----------------------------------------------------------------------------*/
static void SensCordStreamReleaseFrame(senscord_frame_t frame, int32_t ret)
{
    expect_value(__wrap_senscord_stream_release_frame, stream, s_stream);
    expect_value(__wrap_senscord_stream_release_frame, frame, frame);
    will_return(__wrap_senscord_stream_release_frame, ret);
}

/*----------------------------------------------------------------------------*/
//
// Common
//
/*----------------------------------------------------------------------------*/
static void CallMainforTest(int expected_result)
{
    char* argv[] = {"ISA_main", "arg1"}; // dummy value
#if defined(__NuttX__)
    int result = initial_setting_app_main_for_test(2, argv);
#else
    int result = initial_setting_app_main();
#endif
    assert_int_equal(result, expected_result);
}

/*----------------------------------------------------------------------------*/
static void SetLedStatusForQrCodeMode_Success()
{
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsole);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);
}

/*----------------------------------------------------------------------------*/
static void SetLedStatusForQrCodeError_Success()
{
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusErrorInvalidQRCode);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);
}

/*----------------------------------------------------------------------------*/
static void UnsetLedStatusForQrCodeError_Success()
{
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusErrorInvalidQRCode);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);
}

/*----------------------------------------------------------------------------*/
static void NotPSMode_Success()
{
    int32_t qr_mode_tmo = 0;
    expect_memory(__wrap_EsfSystemManagerGetQrModeTimeoutValue, data, &qr_mode_tmo,
                  sizeof(int32_t));
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, 0);
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    expect_value(__wrap_IsaRunProvisioningService, is_debug_mode, false);
    will_return(__wrap_IsaRunProvisioningService, kIsaPsSuccess); // Not PS Mode
}

/*----------------------------------------------------------------------------*/
static void MapMemory_Success(struct senscord_raw_data_t* raw_data, char* map_address)
{
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 1);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size,
                 (EsfMemoryManagerHandle)(uintptr_t)raw_data->size);
    will_return(__wrap_IsaLargeHeapAlloc, map_address); // ok, dummy ptr

    expect_value(__wrap_EsfMemoryManagerFopen, handle,
                 (EsfMemoryManagerHandle)(uintptr_t)raw_data->address);
    will_return(__wrap_EsfMemoryManagerFopen, kEsfMemoryManagerResultSuccess);

    expect_value(__wrap_EsfMemoryManagerFread, handle,
                 (EsfMemoryManagerHandle)(uintptr_t)raw_data->address);
    expect_value(__wrap_EsfMemoryManagerFread, buff, map_address);
    expect_value(__wrap_EsfMemoryManagerFread, size, raw_data->size);
    expect_any(__wrap_EsfMemoryManagerFread, rsize);
    will_return(__wrap_EsfMemoryManagerFread, kEsfMemoryManagerResultSuccess);

    expect_value(__wrap_EsfMemoryManagerFclose, handle,
                 (EsfMemoryManagerHandle)(uintptr_t)raw_data->address);
    will_return(__wrap_EsfMemoryManagerFclose, kEsfMemoryManagerResultSuccess);

#endif
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_MEMORY_MAP
    expect_value(__wrap_EsfMemoryManagerMap, handle, raw_data->address);
    expect_value(__wrap_EsfMemoryManagerMap, exec_env, NULL);
    expect_value(__wrap_EsfMemoryManagerMap, size, raw_data->size);
    will_return(__wrap_EsfMemoryManagerMap, map_address); // ok, dummy ptr
    will_return(__wrap_EsfMemoryManagerMap, kEsfMemoryManagerResultSuccess);
#endif
}

/*----------------------------------------------------------------------------*/
static void UnmapMemory_Success(char* map_address)
{
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
    expect_value(__wrap_IsaLargeHeapFree, memory_address, map_address);
#endif
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_MEMORY_MAP
    expect_value(__wrap_EsfMemoryManagerUnmap, handle, map_address);
    expect_value(__wrap_EsfMemoryManagerUnmap, address, NULL);
    will_return(__wrap_EsfMemoryManagerUnmap, kEsfMemoryManagerResultSuccess);
#endif
}

/*----------------------------------------------------------------------------*/
static void InitializeApp_Success(struct senscord_image_property_t* expected_img_prop)
{
    expect_value(mock_malloc, __size, QRCODE_PAYLOAD_MAX_SIZE);
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    will_return(__wrap_IsaQrcodeInit, kIsaQrcode_Success);
    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // senscord_core_init
    SensCordCoreInit(0);

    // senscord_core_open_stream
    SensCordCoreOpenStream(0);

    // senscord_stream_set_property(ai_model)
    SetSensCordAIModelProperty(0);

    // senscord_stream_set_property(input_data)
    SetSensCordInputDataProperty(0);

#ifdef CONFIG_EXTERNAL_ISAPP_ENABLE_QR_QUALITY_OPTIMIZATION
    expect_value(__wrap_SetupCameraExposureAndMetering, s_stream, s_stream);
#endif // CONFIG_EXTERNAL_ISAPP_ENABLE_QR_QUALITY_OPTIMIZATION

    // senscord_stream_start
    SensCordStreamStart(0);

    // senscord_stream_get_property
    GetSensCordGetProperty(&expected_img_prop, 0);
}

/*----------------------------------------------------------------------------*/
static void FinalizeApp_Success()
{
    will_return(__wrap_EsfSensorExit, kEsfSensorOk); // SsfSensorExit
    will_return(__wrap_IsaQrcodeExit, kIsaQrcode_Success);

    // free static pointer
    expect_any(mock_free, __ptr);
    will_return(mock_free, true);
    assert_null(sp_qrcode_payload_buff);

    // finish senscord
    SensCordStreamStop(0);
    SensCordCoreCloseStream(0);
    SensCordCoreExit(0);
}

/*----------------------------------------------------------------------------*/
// Normal termination process in case ret_main == -1
static void TerminationProcessAborted()
{
    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    will_return(__wrap_IsaBtnCheckFactoryResetRequest, true);

    // Disable WaitingForInputsToConnectConsole.
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsole);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // Disable WaitingForInputsToConnectConsoleGrobalProvisioner.
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    will_return(__wrap_IsaBtnExecuteFactoryResetCore, kRetOk);
    will_return(__wrap_IsaTimerFinalize, kRetOk);
    will_return(__wrap_IsaBtnFinalize, kRetOk);
}

/*----------------------------------------------------------------------------*/
static void* AllocateGrayBuff(size_t height, size_t width)
{
    void* ptr = malloc(height * width);
    return ptr;
}

/*----------------------------------------------------------------------------*/
static void CleanupQRPayloadBuff()
{
    if (sp_qrcode_payload_buff != NULL) {
        free(sp_qrcode_payload_buff);
        sp_qrcode_payload_buff = NULL;
    }
}

/*----------------------------------------------------------------------------*/
static int setup(void** state)
{
    // initialize static variable
    s_core = 0;
    s_stream = 0;

    s_senscord_core_init_success = false;
    s_senscord_open_success = false;
    s_senscord_start_success = false;

    sp_qrcode_payload_buff = NULL;

    s_qr_mode_timeout_reboot_request = false;

    return 0;
}

/*----------------------------------------------------------------------------*/
static int teardown(void** state)
{
    // free heap memory
    CleanupQRPayloadBuff();
    assert_null(sp_qrcode_payload_buff);

    return 0;
}

/*----------------------------------------------------------------------------*/

//
// SetLedStatusForQrCodeMode()
//

/*----------------------------------------------------------------------------*/
static void test_SetLedStatusForQrCodeMode_Failed(void** state)
{
    // SetLedStatusForQrCodeMode() Failed
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsole);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerInternalError);

    SetLedStatusForQrCodeMode();
}

/*----------------------------------------------------------------------------*/
static void test_SetLedStatusForQrCodeMode_fully_success(void** state)
{
    SetLedStatusForQrCodeMode_Success();
    SetLedStatusForQrCodeMode();
}

/*----------------------------------------------------------------------------*/

//
// UnsetLedStatusOfWaitingInputToConnectConsole()
//

/*----------------------------------------------------------------------------*/
static void test_UnsetLedStatusOfWaitingInputToConnectConsole_fully_success(void** state)
{
    // Disable WaitingForInputsToConnectConsole.
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsole);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // Disable WaitingForInputsToConnectConsoleGrobalProvisioner.
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    UnsetLedStatusOfWaitingInputToConnectConsole();
}

/*----------------------------------------------------------------------------*/
static void test_UnsetLedStatusOfWaitingInputToConnectConsole_unset_qr_failed(void** state)
{
    // Disable WaitingForInputsToConnectConsole.
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsole);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerInternalError); // error

    // Disable WaitingForInputsToConnectConsoleGrobalProvisioner.
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    UnsetLedStatusOfWaitingInputToConnectConsole();
}

/*----------------------------------------------------------------------------*/
static void test_UnsetLedStatusOfWaitingInputToConnectConsole_unset_ps_failed(void** state)
{
    // Disable WaitingForInputsToConnectConsole.
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsole);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // Disable WaitingForInputsToConnectConsoleGrobalProvisioner.
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerInternalError); // error

    UnsetLedStatusOfWaitingInputToConnectConsole();
}

/*----------------------------------------------------------------------------*/
//
// SetLedStatusForQrCodeError()
//
/*----------------------------------------------------------------------------*/
static void test_SetLedStatusForQrCodeError_fully_success(void** state)
{
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusErrorInvalidQRCode);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    SetLedStatusForQrCodeError();
}

/*----------------------------------------------------------------------------*/
static void test_SetLedStatusForQrCodeError_EsfLedManagerSetStatus_failed(void** state)
{
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusErrorInvalidQRCode);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerInternalError); // failed

    SetLedStatusForQrCodeError();
}

/*----------------------------------------------------------------------------*/
//
// UnsetLedStatusForQrCodeError()
//
/*----------------------------------------------------------------------------*/
static void test_UnsetLedStatusForQrCodeError_fully_Success()
{
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusErrorInvalidQRCode);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    UnsetLedStatusForQrCodeError();
}

/*----------------------------------------------------------------------------*/
static void test_UnsetLedStatusForQrCodeError_EsfLedManagerSetStatus_failed()
{
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusErrorInvalidQRCode);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerInternalError); // failed

    UnsetLedStatusForQrCodeError();
}

/*----------------------------------------------------------------------------*/

//
// initial_setting_app_main_for_test()
//

/*----------------------------------------------------------------------------*/
static void test_main_BtnAborted(void** state)
{
    will_return(__wrap_IsaBtnInitialize, kRetFailed);
    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    expect_function_call(__wrap_EsfPwrMgrPrepareReboot);
    will_return(__wrap_EsfPwrMgrPrepareReboot, kEsfPwrMgrOk);

    will_return(__wrap_IsaTimerFinalize, kRetOk);
    will_return(__wrap_IsaBtnFinalize, kRetOk);

    CallMainforTest(0);
}

/*----------------------------------------------------------------------------*/
static void test_main_BtnAborted_SetQrModeTimeoutValue_Failed()
{
    will_return(__wrap_IsaBtnInitialize, kRetFailed);
    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultParamError);

    expect_function_call(__wrap_EsfPwrMgrPrepareReboot);
    will_return(__wrap_EsfPwrMgrPrepareReboot, kEsfPwrMgrOk);

    will_return(__wrap_IsaTimerFinalize, kRetOk);
    will_return(__wrap_IsaBtnFinalize, kRetOk);

    CallMainforTest(0);
}

/*----------------------------------------------------------------------------*/
static void test_main_BtnAborted_EsfPwrMgrPrepareReboot_Failed()
{
    will_return(__wrap_IsaBtnInitialize, kRetFailed);
    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    expect_function_call(__wrap_EsfPwrMgrPrepareReboot);
    will_return(__wrap_EsfPwrMgrPrepareReboot, kEsfPwrMgrErrorInvalidArgument);

    will_return(__wrap_IsaTimerFinalize, kRetOk);
    will_return(__wrap_IsaBtnFinalize, kRetOk);

    CallMainforTest(0);
}

/*----------------------------------------------------------------------------*/
static void test_main_TimerAborted(void** state)
{
#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetFailed);

    TerminationProcessAborted();

    CallMainforTest(-1);
}

/*----------------------------------------------------------------------------*/
static void test_main_TimerAborted_WaitFactoryReset(void** state)
{
#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetFailed);

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    will_return(__wrap_IsaBtnCheckFactoryResetRequest, false); // haven't received FactoryReset
    will_return(__wrap_IsaBtnCheckFactoryResetRequest, true);  // received FactoryReset

    // Disable WaitingForInputsToConnectConsole.
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsole);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // Disable WaitingForInputsToConnectConsoleGrobalProvisioner.
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    will_return(__wrap_IsaBtnExecuteFactoryResetCore, kRetOk);
    will_return(__wrap_IsaTimerFinalize, kRetOk);
    will_return(__wrap_IsaBtnFinalize, kRetOk);

    CallMainforTest(-1);
}

/*----------------------------------------------------------------------------*/
static void test_main_TimeoutValue_Failed_PSAborted(void** state)
{
#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    int32_t qr_mode_tmo = 0;
    expect_memory(__wrap_EsfSystemManagerGetQrModeTimeoutValue, data, &qr_mode_tmo,
                  sizeof(int32_t));
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, 0);
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, kEsfSystemManagerResultInternalError);
    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultInternalError);
    expect_value(__wrap_IsaRunProvisioningService, is_debug_mode, false);
    will_return(__wrap_IsaRunProvisioningService, kIsaPsFailed);

    TerminationProcessAborted();

    CallMainforTest(-1);
}

/*----------------------------------------------------------------------------*/
static void test_main_PSCompleted(void** state)
{
#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    int32_t qr_mode_tmo = 0;
    expect_memory(__wrap_EsfSystemManagerGetQrModeTimeoutValue, data, &qr_mode_tmo,
                  sizeof(int32_t));
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, ISAPP_PS_MODE_FORCE_ENTRY);
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    expect_value(__wrap_IsaRunProvisioningService, is_debug_mode, true);
    will_return(__wrap_IsaRunProvisioningService, kIsaPsReboot);

    CallMainforTest(0);
}

/*----------------------------------------------------------------------------*/
static void test_main_PSCompleted_FR(void** state)
{
#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    int32_t qr_mode_tmo = 0;
    expect_memory(__wrap_EsfSystemManagerGetQrModeTimeoutValue, data, &qr_mode_tmo,
                  sizeof(int32_t));
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, ISAPP_PS_MODE_FORCE_ENTRY);
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    expect_value(__wrap_IsaRunProvisioningService, is_debug_mode, true);
    will_return(__wrap_IsaRunProvisioningService, kIsaPsFactoryReset);

    CallMainforTest(0);
}

/*----------------------------------------------------------------------------*/
static void test_main_PSSuccess_InitializeApp_malloc_failed(void** state)
{
#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    int32_t qr_mode_tmo = 0;
    expect_memory(__wrap_EsfSystemManagerGetQrModeTimeoutValue, data, &qr_mode_tmo,
                  sizeof(int32_t));
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, ISAPP_PS_MODE_FORCE_ENTRY);
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    expect_value(__wrap_IsaRunProvisioningService, is_debug_mode, true);
    will_return(__wrap_IsaRunProvisioningService, kIsaPsSuccess);

    // InitializeApp (malloc failed)
    expect_value(mock_malloc, __size, QRCODE_PAYLOAD_MAX_SIZE);
    will_return(mock_malloc, true);
    will_return(mock_malloc, false);

    // FinalizeApp
    will_return(__wrap_EsfSensorExit, kEsfSensorOk); // SsfSensorExit
    will_return(__wrap_IsaQrcodeExit, kIsaQrcode_Success);

    TerminationProcessAborted();

    CallMainforTest(-1);
}

/*----------------------------------------------------------------------------*/
static void test_main_QRmode_with_tmo_InitializeApp_malloc_failed(void** state)
{
#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    int32_t qr_mode_tmo = 0;
    expect_memory(__wrap_EsfSystemManagerGetQrModeTimeoutValue, data, &qr_mode_tmo,
                  sizeof(int32_t));
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, 1); // > 0
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    expect_value(__wrap_IsaTimerStart, time, 1);
    expect_value(__wrap_IsaTimerStart, notify_cb, QrModeTimerCallback);
    will_return(__wrap_IsaTimerStart, kRetOk);
    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    // InitializeApp (malloc failed)
    expect_value(mock_malloc, __size, QRCODE_PAYLOAD_MAX_SIZE);
    will_return(mock_malloc, true);
    will_return(mock_malloc, false);

    // FinalizeApp
    will_return(__wrap_EsfSensorExit, kEsfSensorOk); // SsfSensorExit
    will_return(__wrap_IsaQrcodeExit, kIsaQrcode_Success);

    TerminationProcessAborted();

    CallMainforTest(-1);
}

/*----------------------------------------------------------------------------*/
static void test_main_QRmode_with_minus_tmo_InitializeApp_malloc_failed(void** state)
{
#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    int32_t qr_mode_tmo = 0;
    expect_memory(__wrap_EsfSystemManagerGetQrModeTimeoutValue, data, &qr_mode_tmo,
                  sizeof(int32_t));
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, -1); // < 0
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    // InitializeApp (malloc failed)
    expect_value(mock_malloc, __size, QRCODE_PAYLOAD_MAX_SIZE);
    will_return(mock_malloc, true);
    will_return(mock_malloc, false);

    // FinalizeApp
    will_return(__wrap_EsfSensorExit, kEsfSensorOk); // SsfSensorExit
    will_return(__wrap_IsaQrcodeExit, kIsaQrcode_Success);

    TerminationProcessAborted();

    CallMainforTest(-1);
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_senscord_stream_get_property_ULog_gray_alloc_failed(void** state)
{
#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    struct senscord_image_property_t img_prop = {0};
    InitializeApp_Success(&img_prop);

    GetSensCordStringProperty(-1);                                             // fail
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusFailed); // fail

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, NULL); // fail

    // FinalizeApp
    FinalizeApp_Success();

    TerminationProcessAborted();

    CallMainforTest(-1);
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_senscord_stream_get_property_gray_alloc_failed(void** state)
{
#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    struct senscord_image_property_t img_prop = {0};
    InitializeApp_Success(&img_prop);

    GetSensCordStringProperty(-1);                                         // fail
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk); // ok

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, NULL); // fail

    FinalizeApp_Success();

    TerminationProcessAborted();

    CallMainforTest(-1);
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_ULog_gray_alloc_failed(void** state)
{
#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    struct senscord_image_property_t img_prop = {0};
    InitializeApp_Success(&img_prop);

    GetSensCordStringProperty(0);                                              // ok
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusFailed); // fail

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, NULL); // fail

    // FinalizeApp
    FinalizeApp_Success();

    TerminationProcessAborted();

    CallMainforTest(-1);
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_gray_alloc_failed(void** state)
{
#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    struct senscord_image_property_t img_prop = {0};
    InitializeApp_Success(&img_prop);

    GetSensCordStringProperty(0);                                          // ok
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk); // ok

    // heap alloc (failed)
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, NULL); // fail

    FinalizeApp_Success();

    TerminationProcessAborted();

    CallMainforTest(-1);
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_senscord_stream_get_frame_failed(void** state)
{
#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    struct senscord_image_property_t img_prop = {0};
    InitializeApp_Success(&img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678); // ok, dummy ptr

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame (failed)
    SensCordGetFrame(-1); // fail
    will_return(__wrap_senscord_get_last_error_cause, 0);

    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    FinalizeApp_Success();

    TerminationProcessAborted();

    CallMainforTest(-1);
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_senscord_frame_get_channel_failed(void** state)
{
#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    struct senscord_image_property_t img_prop = {0};
    InitializeApp_Success(&img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0); // ok

    // senscord_frame_get_channel_from_channel_id
    senscord_frame_t frame = 0;
    SensCordGetChannelId(frame, 0x1, -1); // fail
    will_return(__wrap_senscord_get_last_error_cause, 0);

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, 0);

    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    FinalizeApp_Success();

    TerminationProcessAborted();

    CallMainforTest(-1);
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_senscord_channel_get_raw_data_failed(void** state)
{
#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    struct senscord_image_property_t img_prop = {0};
    InitializeApp_Success(&img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    senscord_frame_t frame = 0;
    SensCordGetChannelId(frame, 0x1, 0); // ok

    // senscord_channel_get_raw_data
    senscord_channel_t channel = 0;
    struct senscord_raw_data_t raw_data = {};
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, -1); // fail
    will_return(__wrap_senscord_get_last_error_cause, 0);

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, 0);

    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    FinalizeApp_Success();

    TerminationProcessAborted();

    CallMainforTest(-1);
}

#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
/*----------------------------------------------------------------------------*/
static void test_main_NotPS_IsaLargeHeapAlloc_pool1_failed(void** state)
{
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = 0,
        .stride_bytes = QRCODE_IMAGE_WIDTH}; // invalid width

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    EsfMemoryManagerHandle mem_mng_handle = 0x11223344; // dummy
    struct senscord_raw_data_t dummy_raw_data = {.address = (void*)(uintptr_t)mem_mng_handle,
                                                 .size = 123456,
                                                 .type = "dummy_raw_data_type",
                                                 .timestamp = 202501090500}; // dummy

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc (pool_no = 0)
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &dummy_raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // call MemoryManager using expected img_prop (T5)

    // heap alloc (pool_no = 1)
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 1);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size,
                 (EsfMemoryManagerHandle)dummy_raw_data.size);
    will_return(__wrap_IsaLargeHeapAlloc, NULL); // ng

    SensCordStreamReleaseFrame(frame, 0);

    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678); // free pool_no = 0

    FinalizeApp_Success();

    TerminationProcessAborted();

    CallMainforTest(-1);
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_EsfMemoryManagerFopen_failed(void** state)
{
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = 0,
        .stride_bytes = QRCODE_IMAGE_WIDTH}; // invalid width

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    EsfMemoryManagerHandle mem_mng_handle = 0x11223344; // dummy
    struct senscord_raw_data_t dummy_raw_data = {.address = (void*)(uintptr_t)mem_mng_handle,
                                                 .size = 123456,
                                                 .type = "dummy_raw_data_type",
                                                 .timestamp = 202501090500}; // dummy

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc (pool_no = 0)
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &dummy_raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // heap alloc (pool_no = 1)
    char* dummy_map_address = "0x87654321"; // dummy ptr
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 1);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size,
                 (EsfMemoryManagerHandle)dummy_raw_data.size);
    will_return(__wrap_IsaLargeHeapAlloc, dummy_map_address);

    expect_value(__wrap_EsfMemoryManagerFopen, handle,
                 (EsfMemoryManagerHandle)(uintptr_t)dummy_raw_data.address);
    will_return(__wrap_EsfMemoryManagerFopen, kEsfMemoryManagerResultParamError); // fail

    SensCordStreamReleaseFrame(frame, 0);

    // heap free (pool_no = 1)
    expect_value(__wrap_IsaLargeHeapFree, memory_address, dummy_map_address);
    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    FinalizeApp_Success();

    TerminationProcessAborted();

    CallMainforTest(-1);
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_EsfMemoryManagerFread_failed(void** state)
{
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = 0,
        .stride_bytes = QRCODE_IMAGE_WIDTH}; // invalid width

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    EsfMemoryManagerHandle mem_mng_handle = 0x11223344; // dummy
    struct senscord_raw_data_t dummy_raw_data = {.address = (void*)(uintptr_t)mem_mng_handle,
                                                 .size = 123456,
                                                 .type = "dummy_raw_data_type",
                                                 .timestamp = 202501090500}; // dummy

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc (pool_no = 0)
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &dummy_raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // heap alloc (pool_no = 1)
    char* dummy_map_address = "0x87654321"; // dummy ptr
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 1);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size,
                 (EsfMemoryManagerHandle)dummy_raw_data.size);
    will_return(__wrap_IsaLargeHeapAlloc, dummy_map_address);

    expect_value(__wrap_EsfMemoryManagerFopen, handle,
                 (EsfMemoryManagerHandle)(uintptr_t)dummy_raw_data.address);
    will_return(__wrap_EsfMemoryManagerFopen, kEsfMemoryManagerResultSuccess); // ok

    expect_value(__wrap_EsfMemoryManagerFread, handle,
                 (EsfMemoryManagerHandle)(uintptr_t)dummy_raw_data.address);
    expect_value(__wrap_EsfMemoryManagerFread, buff, dummy_map_address);
    expect_value(__wrap_EsfMemoryManagerFread, size, dummy_raw_data.size);
    expect_any(__wrap_EsfMemoryManagerFread, rsize);
    will_return(__wrap_EsfMemoryManagerFread, kEsfMemoryManagerResultParamError); // fail

    SensCordStreamReleaseFrame(frame, 0);

    // heap free (pool_no = 1)
    expect_value(__wrap_IsaLargeHeapFree, memory_address, dummy_map_address);
    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    expect_value(__wrap_EsfMemoryManagerFclose, handle,
                 (EsfMemoryManagerHandle)(uintptr_t)dummy_raw_data.address);
    will_return(__wrap_EsfMemoryManagerFclose, kEsfMemoryManagerResultSuccess);

    FinalizeApp_Success();

    TerminationProcessAborted();

    CallMainforTest(-1);
}

#endif
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_MEMORY_MAP
/*----------------------------------------------------------------------------*/
static void test_main_NotPS_invalid_height_map_alloc_failed(void** state)
{
    // define expected img_prop
    struct senscord_image_property_t expected_img_prop = {
        .height = 0,
        .width = QRCODE_IMAGE_WIDTH,
        .stride_bytes = QRCODE_IMAGE_WIDTH}; // invalid height

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    EsfMemoryManagerHandle mem_mng_handle = 0x11223344; // dummy
    struct senscord_raw_data_t dummy_raw_data = {.address = (void*)(uintptr_t)mem_mng_handle,
                                                 .size = 123456,
                                                 .type = "dummy_raw_data_type",
                                                 .timestamp = 202501090500}; // dummy

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &dummy_raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0); // ok

    // call MemoryManager using expected img_prop (T5)
    char* dummy_map_address = "0x87654321"; // dummy
    expect_value(__wrap_EsfMemoryManagerMap, handle, dummy_raw_data.address);
    expect_value(__wrap_EsfMemoryManagerMap, exec_env, NULL);
    expect_value(__wrap_EsfMemoryManagerMap, size, dummy_raw_data.size);
    will_return(__wrap_EsfMemoryManagerMap, dummy_map_address);
    will_return(__wrap_EsfMemoryManagerMap, kEsfMemoryManagerResultMapError); // fail

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, 0);

    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    FinalizeApp_Success();

    TerminationProcessAborted();

    CallMainforTest(-1);
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_invalid_width_map_alloc_failed(void** state)
{
    // define expected img_prop
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = 0,
        .stride_bytes = QRCODE_IMAGE_WIDTH}; // invalid width

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    EsfMemoryManagerHandle mem_mng_handle = 0x11223344; // dummy
    struct senscord_raw_data_t dummy_raw_data = {.address = (void*)(uintptr_t)mem_mng_handle,
                                                 .size = 123456,
                                                 .type = "dummy_raw_data_type",
                                                 .timestamp = 202501090500}; // dummy

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &dummy_raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // call MemoryManager using expected img_prop (T5)
    char* dummy_map_address = "0x87654321";
    expect_value(__wrap_EsfMemoryManagerMap, handle, dummy_raw_data.address);
    expect_value(__wrap_EsfMemoryManagerMap, exec_env, NULL);
    expect_value(__wrap_EsfMemoryManagerMap, size, dummy_raw_data.size);
    will_return(__wrap_EsfMemoryManagerMap, dummy_map_address);
    will_return(__wrap_EsfMemoryManagerMap, kEsfMemoryManagerResultMapError); // fail

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, 0);

    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    FinalizeApp_Success();

    TerminationProcessAborted();

    CallMainforTest(-1);
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_invalid_stride_map_alloc_failed(void** state)
{
    // define expected img_prop
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = QRCODE_IMAGE_WIDTH,
        .stride_bytes = 0,
        .pixel_format = SENSCORD_PIXEL_FORMAT_RGB24}; // invalid stride_bytes (strncmp return 0)

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    EsfMemoryManagerHandle mem_mng_handle = 0x11223344; // dummy
    struct senscord_raw_data_t dummy_raw_data = {.address = (void*)(uintptr_t)mem_mng_handle,
                                                 .size = 123456,
                                                 .type = "dummy_raw_data_type",
                                                 .timestamp = 202501090500}; // dummy

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &dummy_raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // call MemoryManager using expected img_prop (T5)
    char* dummy_map_address = "0x87654321";
    expect_value(__wrap_EsfMemoryManagerMap, handle, dummy_raw_data.address);
    expect_value(__wrap_EsfMemoryManagerMap, exec_env, NULL);
    expect_value(__wrap_EsfMemoryManagerMap, size, dummy_raw_data.size);
    will_return(__wrap_EsfMemoryManagerMap, dummy_map_address);
    will_return(__wrap_EsfMemoryManagerMap, kEsfMemoryManagerResultMapError); // fail

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, 0);

    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    FinalizeApp_Success();

    TerminationProcessAborted();

    CallMainforTest(-1);
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_invalid_pixel_format_map_alloc_failed(void** state)
{
    // define expected img_prop
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = QRCODE_IMAGE_WIDTH,
        .stride_bytes = 0,
        .pixel_format =
            SENSCORD_PIXEL_FORMAT_BGR24}; // invalid stride_bytes (strncmp return positive value)

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    EsfMemoryManagerHandle mem_mng_handle = 0x11223344; // dummy
    struct senscord_raw_data_t dummy_raw_data = {.address = (void*)(uintptr_t)mem_mng_handle,
                                                 .size = 123456,
                                                 .type = "dummy_raw_data_type",
                                                 .timestamp = 202501090500}; // dummy

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &dummy_raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // call MemoryManager using expected img_prop (T5)
    char* dummy_map_address = "0x87654321";
    expect_value(__wrap_EsfMemoryManagerMap, handle, dummy_raw_data.address);
    expect_value(__wrap_EsfMemoryManagerMap, exec_env, NULL);
    expect_value(__wrap_EsfMemoryManagerMap, size, dummy_raw_data.size);
    will_return(__wrap_EsfMemoryManagerMap, dummy_map_address);
    will_return(__wrap_EsfMemoryManagerMap, kEsfMemoryManagerResultMapError); // fail

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, 0);

    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    FinalizeApp_Success();

    TerminationProcessAborted();

    CallMainforTest(-1);
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_map_alloc_failed(void** state)
{
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = QRCODE_IMAGE_WIDTH,
        .stride_bytes = QRCODE_IMAGE_WIDTH,
        .pixel_format = SENSCORD_PIXEL_FORMAT_RGB24}; // valid

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    EsfMemoryManagerHandle mem_mng_handle = 0x11223344; // dummy
    struct senscord_raw_data_t dummy_raw_data = {.address = (void*)(uintptr_t)mem_mng_handle,
                                                 .size = 123456,
                                                 .type = "dummy_raw_data_type",
                                                 .timestamp = 202501090500}; // dummy

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &dummy_raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // call MemoryManager using expected img_prop (T5)
    char* dummy_map_address = "0x87654321";
    expect_value(__wrap_EsfMemoryManagerMap, handle, dummy_raw_data.address);
    expect_value(__wrap_EsfMemoryManagerMap, exec_env, NULL);
    expect_value(__wrap_EsfMemoryManagerMap, size, dummy_raw_data.size);
    will_return(__wrap_EsfMemoryManagerMap, dummy_map_address);
    will_return(__wrap_EsfMemoryManagerMap, kEsfMemoryManagerResultMapError); // fail

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, 0);

    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    FinalizeApp_Success();

    TerminationProcessAborted();

    CallMainforTest(-1);
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_GrayScale_Unmap_failed(void** state)
{
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = QRCODE_IMAGE_WIDTH,
        .stride_bytes = QRCODE_IMAGE_WIDTH,
        .pixel_format = SENSCORD_PIXEL_FORMAT_GREY}; // valid (qr)

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    EsfMemoryManagerHandle mem_mng_handle = 0x11223344; // dummy
    struct senscord_raw_data_t dummy_raw_data = {.address = (void*)(uintptr_t)mem_mng_handle,
                                                 .size = 123456,
                                                 .type = "dummy_raw_data_type",
                                                 .timestamp = 202501090500}; // dummy

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &dummy_raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // call MemoryManager using expected img_prop (T5)
    char* dummy_map_address = "0x87654321";                // dummy ptr
    MapMemory_Success(&dummy_raw_data, dummy_map_address); // ok

    // confirm IsaCodecQrInputParam parameter
    uint8_t* output_buf = (uint8_t*)malloc(QRCODE_PAYLOAD_MAX_SIZE);
    if (output_buf == NULL) {
        goto exit;
    }
    memset(output_buf, 0, QRCODE_PAYLOAD_MAX_SIZE);

    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->input_adr_handle,
                 (uint64_t)dummy_map_address);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->width, QRCODE_IMAGE_WIDTH);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->height, QRCODE_IMAGE_HEIGHT);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->stride, QRCODE_IMAGE_WIDTH);
    expect_memory(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_adr_handle,
                  (uint64_t)output_buf, sizeof(output_buf));
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_max_size,
                 QRCODE_PAYLOAD_MAX_SIZE);
    will_return(__wrap_IsaCodecQrDecodeQrCode, 1); // dummy size (>0)
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrOutputNumeric);
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrSuccess);

    expect_value(__wrap_EsfMemoryManagerUnmap, handle, dummy_raw_data.address);
    expect_value(__wrap_EsfMemoryManagerUnmap, address, NULL);
    will_return(__wrap_EsfMemoryManagerUnmap, kEsfMemoryManagerResultMapError); // fail

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, 0);

    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    FinalizeApp_Success();

    TerminationProcessAborted();

    CallMainforTest(-1);

    if (output_buf != NULL) {
        free(output_buf);
        output_buf = NULL;
    }
exit:
    return;
}
#endif

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_GrayScale_success(void** state)
{
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = QRCODE_IMAGE_WIDTH,
        .stride_bytes = QRCODE_IMAGE_WIDTH,
        .pixel_format = SENSCORD_PIXEL_FORMAT_GREY}; // valid (qr)

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    EsfMemoryManagerHandle mem_mng_handle = 0x11223344; // dummy
    struct senscord_raw_data_t dummy_raw_data = {.address = (void*)(uintptr_t)mem_mng_handle,
                                                 .size = 123456,
                                                 .type = "dummy_raw_data_type",
                                                 .timestamp = 202501090500}; // dummy

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &dummy_raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // call MemoryManager using expected img_prop (T5)
    char* dummy_map_address = "0x87654321";                // dummy ptr
    MapMemory_Success(&dummy_raw_data, dummy_map_address); // ok

    // confirm IsaCodecQrInputParam parameter
    uint8_t* output_buf = (uint8_t*)malloc(QRCODE_PAYLOAD_MAX_SIZE);
    if (output_buf == NULL) {
        goto exit;
    }
    memset(output_buf, 0, QRCODE_PAYLOAD_MAX_SIZE);

    int32_t dummy_out_size = 1; // dummy size (>0)
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->input_adr_handle,
                 (uint64_t)dummy_map_address); // GrayScale
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->width, QRCODE_IMAGE_WIDTH);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->height, QRCODE_IMAGE_HEIGHT);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->stride, QRCODE_IMAGE_WIDTH);
    expect_memory(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_adr_handle,
                  (uint64_t)output_buf, sizeof(output_buf));
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_max_size,
                 QRCODE_PAYLOAD_MAX_SIZE);
    will_return(__wrap_IsaCodecQrDecodeQrCode, dummy_out_size);
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrOutputNumeric); // dummy type
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrSuccess);       // ok

#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
    UnmapMemory_Success(dummy_map_address);
#endif
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_MEMORY_MAP
    UnmapMemory_Success(dummy_raw_data.address);
#endif

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, 0);

    // decode QR payload
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk); // ok
    expect_string(__wrap_IsaQrcodeDecodePayload, payload, (uint8_t*)output_buf);
    expect_value(__wrap_IsaQrcodeDecodePayload, payload_size, dummy_out_size);
    will_return(__wrap_IsaQrcodeDecodePayload, kIsaQrcodeDecode_AllRecognized);
    will_return(__wrap_IsaQrcodeDecodePayload, 1); // dummy
    will_return(__wrap_IsaQrcodeDecodePayload, kIsaQrcode_Success);
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsole);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);
    will_return(__wrap_IsaWriteQrcodePayloadToFlash, kIsaQrcode_Success);

    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    FinalizeApp_Success();

    // termination process (ret = 0)
    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    expect_function_call(__wrap_EsfPwrMgrPrepareReboot);
    will_return(__wrap_EsfPwrMgrPrepareReboot, kEsfPwrMgrOk);
    will_return(__wrap_IsaTimerFinalize, kRetOk);
    will_return(__wrap_IsaBtnFinalize, kRetOk);

    CallMainforTest(0);

    if (output_buf != NULL) {
        free(output_buf);
        output_buf = NULL;
    }
exit:
    return;
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_GrayScale_width_not_equal_stride(void** state)
{
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = QRCODE_IMAGE_WIDTH,
        .stride_bytes = QRCODE_IMAGE_WIDTH - 1,      // not equal to width
        .pixel_format = SENSCORD_PIXEL_FORMAT_GREY}; // valid (qr)

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    struct senscord_raw_data_t raw_data = {.size = QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT,
                                           .type = "raw_data_type",
                                           .timestamp = 202501290900};

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    unsigned char* gray_buff = AllocateGrayBuff(QRCODE_IMAGE_WIDTH, QRCODE_IMAGE_HEIGHT);
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, gray_buff); // for ConvertfromGrayToGray()

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // call MemoryManager using expected img_prop (T5)
    char* map_address = malloc(raw_data.size); // for ConvertfromGrayToGray()
    MapMemory_Success(&raw_data, map_address); // ok

    // confirm IsaCodecQrInputParam parameter
    uint8_t* output_buf = (uint8_t*)malloc(QRCODE_PAYLOAD_MAX_SIZE);
    if (output_buf == NULL) {
        goto exit;
    }
    memset(output_buf, 0, QRCODE_PAYLOAD_MAX_SIZE);

    int32_t dummy_out_size = 1; // dummy size (>0)
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->input_adr_handle,
                 (uint64_t)(uintptr_t)gray_buff); // GrayScale
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->width, expected_img_prop.width);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->height, expected_img_prop.height);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->stride,
                 QRCODE_IMAGE_WIDTH); // fix value same as width
    expect_memory(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_adr_handle,
                  (uint64_t)output_buf, sizeof(output_buf));
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_max_size,
                 QRCODE_PAYLOAD_MAX_SIZE);
    will_return(__wrap_IsaCodecQrDecodeQrCode, dummy_out_size);
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrOutputNumeric); // dummy type
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrSuccess);       // ok

#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
    UnmapMemory_Success(map_address);
#endif
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_MEMORY_MAP
    UnmapMemory_Success(raw_data.address);
#endif

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, 0);

    // decode QR payload
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk); // ok
    expect_string(__wrap_IsaQrcodeDecodePayload, payload, (uint8_t*)output_buf);
    expect_value(__wrap_IsaQrcodeDecodePayload, payload_size, dummy_out_size);
    will_return(__wrap_IsaQrcodeDecodePayload, kIsaQrcodeDecode_AllRecognized);
    will_return(__wrap_IsaQrcodeDecodePayload, 1); // dummy
    will_return(__wrap_IsaQrcodeDecodePayload, kIsaQrcode_Success);
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsole);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);
    will_return(__wrap_IsaWriteQrcodePayloadToFlash, kIsaQrcode_Success);

    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, gray_buff);

    FinalizeApp_Success();

    // termination process (ret = 0)
    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    expect_function_call(__wrap_EsfPwrMgrPrepareReboot);
    will_return(__wrap_EsfPwrMgrPrepareReboot, kEsfPwrMgrOk);
    will_return(__wrap_IsaTimerFinalize, kRetOk);
    will_return(__wrap_IsaBtnFinalize, kRetOk);

    CallMainforTest(0);

    if (output_buf != NULL) {
        free(output_buf);
        output_buf = NULL;
    }
exit:
    return;
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_GrayScale_FactoryResetRequested(void** state)
{
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = QRCODE_IMAGE_WIDTH,
        .stride_bytes = QRCODE_IMAGE_WIDTH,
        .pixel_format = SENSCORD_PIXEL_FORMAT_GREY}; // valid (qr)

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    EsfMemoryManagerHandle mem_mng_handle = 0x11223344; // dummy
    struct senscord_raw_data_t dummy_raw_data = {.address = (void*)(uintptr_t)mem_mng_handle,
                                                 .size = 123456,
                                                 .type = "dummy_raw_data_type",
                                                 .timestamp = 202501090500}; // dummy

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &dummy_raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // call MemoryManager using expected img_prop (T5)
    char* dummy_map_address = "0x87654321";                // dummy ptr
    MapMemory_Success(&dummy_raw_data, dummy_map_address); // ok

    // confirm IsaCodecQrInputParam parameter
    uint8_t* output_buf = (uint8_t*)malloc(QRCODE_PAYLOAD_MAX_SIZE);
    if (output_buf == NULL) {
        goto exit;
    }
    memset(output_buf, 0, QRCODE_PAYLOAD_MAX_SIZE);

    int32_t dummy_out_size = 1; // dummy size (>0)
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->input_adr_handle,
                 (uint64_t)dummy_map_address); // GrayScale
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->width, QRCODE_IMAGE_WIDTH);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->height, QRCODE_IMAGE_HEIGHT);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->stride, QRCODE_IMAGE_WIDTH);
    expect_memory(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_adr_handle,
                  (uint64_t)output_buf, sizeof(output_buf));
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_max_size,
                 QRCODE_PAYLOAD_MAX_SIZE);
    will_return(__wrap_IsaCodecQrDecodeQrCode, dummy_out_size);
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrOutputNumeric); // dummy type
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrSuccess);       // ok

#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
    UnmapMemory_Success(dummy_map_address);
#endif
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_MEMORY_MAP
    UnmapMemory_Success(dummy_raw_data.address);
#endif

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, 0);

    // decode QR payload
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk); // ok
    expect_string(__wrap_IsaQrcodeDecodePayload, payload, (uint8_t*)output_buf);
    expect_value(__wrap_IsaQrcodeDecodePayload, payload_size, dummy_out_size);
    will_return(__wrap_IsaQrcodeDecodePayload, kIsaQrcodeDecode_Invalid);
    will_return(__wrap_IsaQrcodeDecodePayload, 1); // dummy
    will_return(__wrap_IsaQrcodeDecodePayload, kIsaQrcode_Success);

    SetLedStatusForQrCodeError_Success();
    UnsetLedStatusForQrCodeError_Success();

    will_return(__wrap_IsaBtnCheckFactoryResetRequest, true); // FactoryReset requested

    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    FinalizeApp_Success();

    // termination process (ret = 1)
    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    // Disable WaitingForInputsToConnectConsole.
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsole);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // Disable WaitingForInputsToConnectConsoleGrobalProvisioner.
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    will_return(__wrap_IsaBtnExecuteFactoryResetCore, kRetOk);
    will_return(__wrap_IsaTimerFinalize, kRetOk);
    will_return(__wrap_IsaBtnFinalize, kRetOk);

    CallMainforTest(1);

    if (output_buf != NULL) {
        free(output_buf);
        output_buf = NULL;
    }
exit:
    return;
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_GrayScale_RebootRequested(void** state)
{
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = QRCODE_IMAGE_WIDTH,
        .stride_bytes = QRCODE_IMAGE_WIDTH,
        .pixel_format = SENSCORD_PIXEL_FORMAT_GREY}; // valid (qr)

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    EsfMemoryManagerHandle mem_mng_handle = 0x11223344; // dummy
    struct senscord_raw_data_t dummy_raw_data = {.address = (void*)(uintptr_t)mem_mng_handle,
                                                 .size = 123456,
                                                 .type = "dummy_raw_data_type",
                                                 .timestamp = 202501090500}; // dummy

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    // to be called QrModeTimerCallback() instead of NotPSMode_Success()
    int32_t qr_mode_tmo = 0;
    expect_memory(__wrap_EsfSystemManagerGetQrModeTimeoutValue, data, &qr_mode_tmo,
                  sizeof(int32_t));
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, 1); // > 0
    will_return(__wrap_EsfSystemManagerGetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    expect_value(__wrap_IsaTimerStart, time, 1);
    expect_value(__wrap_IsaTimerStart, notify_cb, QrModeTimerCallback);
    will_return(__wrap_IsaTimerStart, kRetOk);
    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &dummy_raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // call MemoryManager using expected img_prop (T5)
    char* dummy_map_address = "0x87654321";                // dummy ptr
    MapMemory_Success(&dummy_raw_data, dummy_map_address); // ok

    // confirm IsaCodecQrInputParam parameter
    uint8_t* output_buf = (uint8_t*)malloc(QRCODE_PAYLOAD_MAX_SIZE);
    if (output_buf == NULL) {
        goto exit;
    }
    memset(output_buf, 0, QRCODE_PAYLOAD_MAX_SIZE);

    int32_t dummy_out_size = 1; // dummy size (>0)
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->input_adr_handle,
                 (uint64_t)dummy_map_address); // GrayScale
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->width, QRCODE_IMAGE_WIDTH);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->height, QRCODE_IMAGE_HEIGHT);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->stride, QRCODE_IMAGE_WIDTH);
    expect_memory(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_adr_handle,
                  (uint64_t)output_buf, sizeof(output_buf));
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_max_size,
                 QRCODE_PAYLOAD_MAX_SIZE);
    will_return(__wrap_IsaCodecQrDecodeQrCode, dummy_out_size);
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrOutputNumeric); // dummy type
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrSuccess);       // ok

#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
    UnmapMemory_Success(dummy_map_address);
#endif
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_MEMORY_MAP
    UnmapMemory_Success(dummy_raw_data.address);
#endif

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, 0);

    // decode QR payload
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);
    expect_string(__wrap_IsaQrcodeDecodePayload, payload, (uint8_t*)output_buf);
    expect_value(__wrap_IsaQrcodeDecodePayload, payload_size, dummy_out_size);
    will_return(__wrap_IsaQrcodeDecodePayload, kIsaQrcodeDecode_Invalid);
    will_return(__wrap_IsaQrcodeDecodePayload, 1); // dummy
    will_return(__wrap_IsaQrcodeDecodePayload, kIsaQrcode_Success);

    SetLedStatusForQrCodeError_Success();
    UnsetLedStatusForQrCodeError_Success();

    will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);

    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    FinalizeApp_Success();

    // termination process (ret = 0)
    expect_function_call(__wrap_EsfPwrMgrPrepareReboot);
    will_return(__wrap_EsfPwrMgrPrepareReboot, kEsfPwrMgrOk);
    will_return(__wrap_IsaTimerFinalize, kRetOk);
    will_return(__wrap_IsaBtnFinalize, kRetOk);

    QrModeTimerCallback();                                    // simulate callback called
    assert_int_equal(s_qr_mode_timeout_reboot_request, true); // reboot requested
    CallMainforTest(0);

    if (output_buf != NULL) {
        free(output_buf);
        output_buf = NULL;
    }
exit:
    return;
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_GrayScale_IsaQrcodeDecodePayload_next_get_frame_failed(void** state)
{
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = QRCODE_IMAGE_WIDTH,
        .stride_bytes = QRCODE_IMAGE_WIDTH,
        .pixel_format = SENSCORD_PIXEL_FORMAT_GREY}; // valid (qr)

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    EsfMemoryManagerHandle mem_mng_handle = 0x11223344; // dummy
    struct senscord_raw_data_t dummy_raw_data = {.address = (void*)(uintptr_t)mem_mng_handle,
                                                 .size = 123456,
                                                 .type = "dummy_raw_data_type",
                                                 .timestamp = 202501090500}; // dummy

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &dummy_raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // call MemoryManager using expected img_prop (T5)
    char* dummy_map_address = "0x87654321";                // dummy ptr
    MapMemory_Success(&dummy_raw_data, dummy_map_address); // ok

    // confirm IsaCodecQrInputParam parameter
    uint8_t* output_buf = (uint8_t*)malloc(QRCODE_PAYLOAD_MAX_SIZE);
    if (output_buf == NULL) {
        goto exit;
    }
    memset(output_buf, 0, QRCODE_PAYLOAD_MAX_SIZE);

    int32_t dummy_out_size = 1; // dummy size (>0)
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->input_adr_handle,
                 (uint64_t)dummy_map_address); // GrayScale
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->width, QRCODE_IMAGE_WIDTH);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->height, QRCODE_IMAGE_HEIGHT);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->stride, QRCODE_IMAGE_WIDTH);
    expect_memory(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_adr_handle,
                  (uint64_t)output_buf, sizeof(output_buf));
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_max_size,
                 QRCODE_PAYLOAD_MAX_SIZE);
    will_return(__wrap_IsaCodecQrDecodeQrCode, dummy_out_size);
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrOutputNumeric);
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrSuccess);

#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
    UnmapMemory_Success(dummy_map_address);
#endif
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_MEMORY_MAP
    UnmapMemory_Success(dummy_raw_data.address);
#endif

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, 0);

    // decode QR payload
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);
    expect_string(__wrap_IsaQrcodeDecodePayload, payload, (uint8_t*)output_buf);
    expect_value(__wrap_IsaQrcodeDecodePayload, payload_size, dummy_out_size);
    will_return(__wrap_IsaQrcodeDecodePayload, kIsaQrcodeDecode_Invalid);
    will_return(__wrap_IsaQrcodeDecodePayload, 1);
    will_return(__wrap_IsaQrcodeDecodePayload, kIsaQrcode_Failed); // fail

    SetLedStatusForQrCodeError_Success();
    UnsetLedStatusForQrCodeError_Success();

    // get next frame
    will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);
    assert_int_equal(s_qr_mode_timeout_reboot_request, false);

    // senscord_stream_get_frame (failed)
    SensCordGetFrame(-1); // fail
    will_return(__wrap_senscord_get_last_error_cause, 0);

    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    FinalizeApp_Success();

    TerminationProcessAborted();

    CallMainforTest(-1);

    if (output_buf != NULL) {
        free(output_buf);
        output_buf = NULL;
    }
exit:
    return;
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_GrayScale_IsaWriteQrcodePayloadToFlash_failed(void** state)
{
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = QRCODE_IMAGE_WIDTH,
        .stride_bytes = QRCODE_IMAGE_WIDTH,
        .pixel_format = SENSCORD_PIXEL_FORMAT_GREY}; // valid (qr)

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    EsfMemoryManagerHandle mem_mng_handle = 0x11223344; // dummy
    struct senscord_raw_data_t dummy_raw_data = {.address = (void*)(uintptr_t)mem_mng_handle,
                                                 .size = 123456,
                                                 .type = "dummy_raw_data_type",
                                                 .timestamp = 202501090500}; // dummy

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &dummy_raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // call MemoryManager using expected img_prop (T5)
    char* dummy_map_address = "0x87654321";                // dummy ptr
    MapMemory_Success(&dummy_raw_data, dummy_map_address); // ok

    // confirm IsaCodecQrInputParam parameter
    uint8_t* output_buf = (uint8_t*)malloc(QRCODE_PAYLOAD_MAX_SIZE);
    if (output_buf == NULL) {
        goto exit;
    }
    memset(output_buf, 0, QRCODE_PAYLOAD_MAX_SIZE);

    int32_t dummy_out_size = 1; // dummy size (>0)
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->input_adr_handle,
                 (uint64_t)dummy_map_address); // GrayScale
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->width, QRCODE_IMAGE_WIDTH);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->height, QRCODE_IMAGE_HEIGHT);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->stride, QRCODE_IMAGE_WIDTH);
    expect_memory(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_adr_handle,
                  (uint64_t)output_buf, sizeof(output_buf));
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_max_size,
                 QRCODE_PAYLOAD_MAX_SIZE);
    will_return(__wrap_IsaCodecQrDecodeQrCode, dummy_out_size);
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrOutputNumeric);
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrSuccess);

#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
    UnmapMemory_Success(dummy_map_address);
#endif
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_MEMORY_MAP
    UnmapMemory_Success(dummy_raw_data.address);
#endif

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, 0);

    // decode QR payload
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);
    expect_string(__wrap_IsaQrcodeDecodePayload, payload, (uint8_t*)output_buf);
    expect_value(__wrap_IsaQrcodeDecodePayload, payload_size, dummy_out_size);
    will_return(__wrap_IsaQrcodeDecodePayload, kIsaQrcodeDecode_AllRecognized);
    will_return(__wrap_IsaQrcodeDecodePayload, 1);
    will_return(__wrap_IsaQrcodeDecodePayload, kIsaQrcode_Success);
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsole);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);
    will_return(__wrap_IsaWriteQrcodePayloadToFlash, kIsaQrcode_Failed); // fail

    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    FinalizeApp_Success();

    // termination process (ret = 0)
    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    expect_function_call(__wrap_EsfPwrMgrPrepareReboot);
    will_return(__wrap_EsfPwrMgrPrepareReboot, kEsfPwrMgrOk);
    will_return(__wrap_IsaTimerFinalize, kRetOk);
    will_return(__wrap_IsaBtnFinalize, kRetOk);

    CallMainforTest(0);

    if (output_buf != NULL) {
        free(output_buf);
        output_buf = NULL;
    }
exit:
    return;
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_GrayScale_PartRecognized_next_get_frame_failed(void** state)
{
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = QRCODE_IMAGE_WIDTH,
        .stride_bytes = QRCODE_IMAGE_WIDTH,
        .pixel_format = SENSCORD_PIXEL_FORMAT_GREY}; // valid (qr)

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    EsfMemoryManagerHandle mem_mng_handle = 0x11223344; // dummy
    struct senscord_raw_data_t dummy_raw_data = {.address = (void*)(uintptr_t)mem_mng_handle,
                                                 .size = 123456,
                                                 .type = "dummy_raw_data_type",
                                                 .timestamp = 202501090500}; // dummy

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &dummy_raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // call MemoryManager using expected img_prop (T5)
    char* dummy_map_address = "0x87654321";                // dummy ptr
    MapMemory_Success(&dummy_raw_data, dummy_map_address); // ok

    // confirm IsaCodecQrInputParam parameter
    uint8_t* output_buf = (uint8_t*)malloc(QRCODE_PAYLOAD_MAX_SIZE);
    if (output_buf == NULL) {
        goto exit;
    }
    memset(output_buf, 0, QRCODE_PAYLOAD_MAX_SIZE);

    int32_t dummy_out_size = 1; // dummy size (>0)
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->input_adr_handle,
                 (uint64_t)dummy_map_address); // GrayScale
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->width, QRCODE_IMAGE_WIDTH);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->height, QRCODE_IMAGE_HEIGHT);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->stride, QRCODE_IMAGE_WIDTH);
    expect_memory(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_adr_handle,
                  (uint64_t)output_buf, sizeof(output_buf));
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_max_size,
                 QRCODE_PAYLOAD_MAX_SIZE);
    will_return(__wrap_IsaCodecQrDecodeQrCode, dummy_out_size);
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrOutputNumeric);
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrSuccess);

#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
    UnmapMemory_Success(dummy_map_address);
#endif
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_MEMORY_MAP
    UnmapMemory_Success(dummy_raw_data.address);
#endif

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, 0);

    // decode QR payload
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);
    expect_string(__wrap_IsaQrcodeDecodePayload, payload, (uint8_t*)output_buf);
    expect_value(__wrap_IsaQrcodeDecodePayload, payload_size, dummy_out_size);
    will_return(__wrap_IsaQrcodeDecodePayload, kIsaQrcodeDecode_PartRecognized);
    will_return(__wrap_IsaQrcodeDecodePayload, 1);
    will_return(__wrap_IsaQrcodeDecodePayload, kIsaQrcode_Success);

    // get next frame
    will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);
    assert_int_equal(s_qr_mode_timeout_reboot_request, false);

    // senscord_stream_get_frame (failed)
    SensCordGetFrame(-1); // fail
    will_return(__wrap_senscord_get_last_error_cause, 0);

    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    FinalizeApp_Success();

    TerminationProcessAborted();

    CallMainforTest(-1);

    if (output_buf != NULL) {
        free(output_buf);
        output_buf = NULL;
    }
exit:
    return;
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_GrayScale_InvalidQR_next_get_frame_failed(void** state)
{
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = QRCODE_IMAGE_WIDTH,
        .stride_bytes = QRCODE_IMAGE_WIDTH,
        .pixel_format = SENSCORD_PIXEL_FORMAT_GREY}; // valid (qr)

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    EsfMemoryManagerHandle mem_mng_handle = 0x11223344; // dummy
    struct senscord_raw_data_t dummy_raw_data = {.address = (void*)(uintptr_t)mem_mng_handle,
                                                 .size = 123456,
                                                 .type = "dummy_raw_data_type",
                                                 .timestamp = 202501090500}; // dummy

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &dummy_raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // call MemoryManager using expected img_prop (T5)
    char* dummy_map_address = "0x87654321";                // dummy ptr
    MapMemory_Success(&dummy_raw_data, dummy_map_address); // ok

    // confirm IsaCodecQrInputParam parameter
    uint8_t* output_buf = (uint8_t*)malloc(QRCODE_PAYLOAD_MAX_SIZE);
    if (output_buf == NULL) {
        goto exit;
    }
    memset(output_buf, 0, QRCODE_PAYLOAD_MAX_SIZE);

    int32_t dummy_out_size = 1; // dummy size (>0)
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->input_adr_handle,
                 (uint64_t)dummy_map_address); // GrayScale
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->width, QRCODE_IMAGE_WIDTH);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->height, QRCODE_IMAGE_HEIGHT);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->stride, QRCODE_IMAGE_WIDTH);
    expect_memory(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_adr_handle,
                  (uint64_t)output_buf, sizeof(output_buf));
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_max_size,
                 QRCODE_PAYLOAD_MAX_SIZE);
    will_return(__wrap_IsaCodecQrDecodeQrCode, dummy_out_size);
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrOutputNumeric);
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrSuccess);

#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
    UnmapMemory_Success(dummy_map_address);
#endif
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_MEMORY_MAP
    UnmapMemory_Success(dummy_raw_data.address);
#endif

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, 0);

    // decode QR payload
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);
    expect_string(__wrap_IsaQrcodeDecodePayload, payload, (uint8_t*)output_buf);
    expect_value(__wrap_IsaQrcodeDecodePayload, payload_size, dummy_out_size);
    will_return(__wrap_IsaQrcodeDecodePayload, kIsaQrcodeDecode_Invalid); // invalid
    will_return(__wrap_IsaQrcodeDecodePayload, 1);                        // dummy
    will_return(__wrap_IsaQrcodeDecodePayload, kIsaQrcode_Success);

    SetLedStatusForQrCodeError_Success();
    UnsetLedStatusForQrCodeError_Success();

    // get next frame
    will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);
    assert_int_equal(s_qr_mode_timeout_reboot_request, false);

    // senscord_stream_get_frame (failed)
    SensCordGetFrame(-1); // fail
    will_return(__wrap_senscord_get_last_error_cause, 0);

    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    FinalizeApp_Success();

    TerminationProcessAborted();

    CallMainforTest(-1);

    if (output_buf != NULL) {
        free(output_buf);
        output_buf = NULL;
    }
exit:
    return;
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_GrayScale_qr_data_malloc_failure(void** state)
{
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = QRCODE_IMAGE_WIDTH,
        .stride_bytes = QRCODE_IMAGE_WIDTH,
        .pixel_format = SENSCORD_PIXEL_FORMAT_GREY}; // valid (qr)

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    EsfMemoryManagerHandle mem_mng_handle = 0x11223344; // dummy
    struct senscord_raw_data_t dummy_raw_data = {.address = (void*)(uintptr_t)mem_mng_handle,
                                                 .size = 123456,
                                                 .type = "dummy_raw_data_type",
                                                 .timestamp = 202501090500}; // dummy

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &dummy_raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // call MemoryManager using expected img_prop (T5)
    char* dummy_map_address = "0x87654321";                // dummy ptr
    MapMemory_Success(&dummy_raw_data, dummy_map_address); // ok

    // confirm IsaCodecQrInputParam parameter
    uint8_t* output_buf = (uint8_t*)malloc(QRCODE_PAYLOAD_MAX_SIZE);
    if (output_buf == NULL) {
        goto exit;
    }
    memset(output_buf, 0, QRCODE_PAYLOAD_MAX_SIZE);

    int32_t dummy_out_size = 1; // dummy size (>0)
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->input_adr_handle,
                 (uint64_t)dummy_map_address); // GrayScale
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->width, QRCODE_IMAGE_WIDTH);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->height, QRCODE_IMAGE_HEIGHT);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->stride, QRCODE_IMAGE_WIDTH);
    expect_memory(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_adr_handle,
                  (uint64_t)output_buf, sizeof(output_buf));
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_max_size,
                 QRCODE_PAYLOAD_MAX_SIZE);
    will_return(__wrap_IsaCodecQrDecodeQrCode, dummy_out_size);
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrOutputNumeric);
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrSuccess);

#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
    UnmapMemory_Success(dummy_map_address);
#endif
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_MEMORY_MAP
    UnmapMemory_Success(dummy_raw_data.address);
#endif

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, 0);

    // decode QR payload
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);
    expect_string(__wrap_IsaQrcodeDecodePayload, payload, (uint8_t*)output_buf);
    expect_value(__wrap_IsaQrcodeDecodePayload, payload_size, dummy_out_size);
    will_return(__wrap_IsaQrcodeDecodePayload, kIsaQrcodeDecode_ResultNum); // qr_data malloc failed

    will_return(__wrap_IsaQrcodeDecodePayload, 1); // dummy
    will_return(__wrap_IsaQrcodeDecodePayload, kIsaQrcode_Success);

    // get next frame
    will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);
    assert_int_equal(s_qr_mode_timeout_reboot_request, false);

    // senscord_stream_get_frame (failed)
    SensCordGetFrame(-1); // fail
    will_return(__wrap_senscord_get_last_error_cause, 0);

    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    FinalizeApp_Success();

    TerminationProcessAborted();

    CallMainforTest(-1);

    if (output_buf != NULL) {
        free(output_buf);
        output_buf = NULL;
    }
exit:
    return;
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_GrayScale_QrDecode_failed(void** state)
{
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = QRCODE_IMAGE_WIDTH,
        .stride_bytes = QRCODE_IMAGE_WIDTH,
        .pixel_format = SENSCORD_PIXEL_FORMAT_GREY}; // valid (qr)

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    EsfMemoryManagerHandle mem_mng_handle = 0x11223344; // dummy
    struct senscord_raw_data_t dummy_raw_data = {.address = (void*)(uintptr_t)mem_mng_handle,
                                                 .size = 123456,
                                                 .type = "dummy_raw_data_type",
                                                 .timestamp = 202501090500}; // dummy

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &dummy_raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // call MemoryManager using expected img_prop (T5)
    char* dummy_map_address = "0x87654321";                // dummy ptr
    MapMemory_Success(&dummy_raw_data, dummy_map_address); // ok

    // confirm IsaCodecQrInputParam parameter
    uint8_t* output_buf = (uint8_t*)malloc(QRCODE_PAYLOAD_MAX_SIZE);
    if (output_buf == NULL) {
        goto exit;
    }
    memset(output_buf, 0, QRCODE_PAYLOAD_MAX_SIZE);

    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->input_adr_handle,
                 (uint64_t)dummy_map_address);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->width, QRCODE_IMAGE_WIDTH);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->height, QRCODE_IMAGE_HEIGHT);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->stride, QRCODE_IMAGE_WIDTH);
    expect_memory(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_adr_handle,
                  (uint64_t)output_buf, sizeof(output_buf));
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_max_size,
                 QRCODE_PAYLOAD_MAX_SIZE);
    will_return(__wrap_IsaCodecQrDecodeQrCode, 1); // dummy size (>0)
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrOutputNumeric);
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrParamError); // fail

#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
    UnmapMemory_Success(dummy_map_address);
#endif
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_MEMORY_MAP
    UnmapMemory_Success(dummy_raw_data.address);
#endif

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, 0);

    // skip decode because decode failed

    will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);
    s_qr_mode_timeout_reboot_request = true; // simulate timeout
    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    // FinalizeApp
    FinalizeApp_Success();

    // termination process (ret = 0)
    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    expect_function_call(__wrap_EsfPwrMgrPrepareReboot);
    will_return(__wrap_EsfPwrMgrPrepareReboot, kEsfPwrMgrOk);
    will_return(__wrap_IsaTimerFinalize, kRetOk);
    will_return(__wrap_IsaBtnFinalize, kRetOk);

    CallMainforTest(0); // Reboot requested

    if (output_buf != NULL) {
        free(output_buf);
        output_buf = NULL;
    }
exit:
    return;
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_GrayScale_OutSize_zero(void** state)
{
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = QRCODE_IMAGE_WIDTH,
        .stride_bytes = QRCODE_IMAGE_WIDTH,
        .pixel_format = SENSCORD_PIXEL_FORMAT_GREY}; // valid (qr)

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    EsfMemoryManagerHandle mem_mng_handle = 0x11223344; // dummy
    struct senscord_raw_data_t dummy_raw_data = {.address = (void*)(uintptr_t)mem_mng_handle,
                                                 .size = 123456,
                                                 .type = "dummy_raw_data_type",
                                                 .timestamp = 202501090500}; // dummy

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &dummy_raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // call MemoryManager using expected img_prop (T5)
    char* dummy_map_address = "0x87654321";                // dummy ptr
    MapMemory_Success(&dummy_raw_data, dummy_map_address); // ok

    // confirm IsaCodecQrInputParam parameter
    uint8_t* output_buf = (uint8_t*)malloc(QRCODE_PAYLOAD_MAX_SIZE);
    if (output_buf == NULL) {
        goto exit;
    }
    memset(output_buf, 0, QRCODE_PAYLOAD_MAX_SIZE);

    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->input_adr_handle,
                 (uint64_t)dummy_map_address);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->width, QRCODE_IMAGE_WIDTH);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->height, QRCODE_IMAGE_HEIGHT);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->stride, QRCODE_IMAGE_WIDTH);
    expect_memory(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_adr_handle,
                  (uint64_t)output_buf, sizeof(output_buf));
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_max_size,
                 QRCODE_PAYLOAD_MAX_SIZE);
    will_return(__wrap_IsaCodecQrDecodeQrCode, 0); // zero
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrOutputNumeric);
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrSuccess);

#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
    UnmapMemory_Success(dummy_map_address);
#endif
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_MEMORY_MAP
    UnmapMemory_Success(dummy_raw_data.address);
#endif

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, 0);

    // skip decode because out_size == 0

    will_return(__wrap_IsaBtnCheckFactoryResetRequest, false);
    s_qr_mode_timeout_reboot_request = true; // simulate timeout
    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    // FinalizeApp
    FinalizeApp_Success();

    // termination process (ret = 0)
    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    expect_function_call(__wrap_EsfPwrMgrPrepareReboot);
    will_return(__wrap_EsfPwrMgrPrepareReboot, kEsfPwrMgrOk);
    will_return(__wrap_IsaTimerFinalize, kRetOk);
    will_return(__wrap_IsaBtnFinalize, kRetOk);

    CallMainforTest(0); // Reboot requested

    if (output_buf != NULL) {
        free(output_buf);
        output_buf = NULL;
    }
exit:
    return;
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_GrayScale_senscord_stream_release_frame_failed(void** state)
{
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = QRCODE_IMAGE_WIDTH,
        .stride_bytes = QRCODE_IMAGE_WIDTH,
        .pixel_format = SENSCORD_PIXEL_FORMAT_GREY}; // valid (qr)

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    EsfMemoryManagerHandle mem_mng_handle = 0x11223344; // dummy
    struct senscord_raw_data_t dummy_raw_data = {.address = (void*)(uintptr_t)mem_mng_handle,
                                                 .size = 123456,
                                                 .type = "dummy_raw_data_type",
                                                 .timestamp = 202501090500}; // dummy

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &dummy_raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // call MemoryManager using expected img_prop (T5)
    char* dummy_map_address = "0x87654321";                // dummy ptr
    MapMemory_Success(&dummy_raw_data, dummy_map_address); // ok

    // confirm IsaCodecQrInputParam parameter
    uint8_t* output_buf = (uint8_t*)malloc(QRCODE_PAYLOAD_MAX_SIZE);
    if (output_buf == NULL) {
        goto exit;
    }
    memset(output_buf, 0, QRCODE_PAYLOAD_MAX_SIZE);

    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->input_adr_handle,
                 (uint64_t)dummy_map_address);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->width, QRCODE_IMAGE_WIDTH);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->height, QRCODE_IMAGE_HEIGHT);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->stride, QRCODE_IMAGE_WIDTH);
    expect_memory(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_adr_handle,
                  (uint64_t)output_buf, sizeof(output_buf));
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_max_size,
                 QRCODE_PAYLOAD_MAX_SIZE);
    will_return(__wrap_IsaCodecQrDecodeQrCode, 1); // dummy size (>0)
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrOutputNumeric);
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrSuccess);

#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
    UnmapMemory_Success(dummy_map_address);
#endif
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_MEMORY_MAP
    UnmapMemory_Success(dummy_raw_data.address);
#endif

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, -1); // fail
    will_return(__wrap_senscord_get_last_error_cause, 0);

    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    FinalizeApp_Success();

    TerminationProcessAborted();

    CallMainforTest(-1);

    if (output_buf != NULL) {
        free(output_buf);
        output_buf = NULL;
    }
exit:
    return;
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_RGB_success(void** state)
{
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = QRCODE_IMAGE_WIDTH,
        .stride_bytes = QRCODE_IMAGE_WIDTH,
        .pixel_format = SENSCORD_PIXEL_FORMAT_RGB24}; // valid (RGB)

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    struct senscord_raw_data_t raw_data = {.size = QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT,
                                           .type = "raw_data_type",
                                           .timestamp = 202501290900};

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    unsigned char* gray_buff = AllocateGrayBuff(QRCODE_IMAGE_WIDTH, QRCODE_IMAGE_HEIGHT);
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, gray_buff); // ConvertfromRGB24ToGray()

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // call MemoryManager using expected img_prop (T5)
    char* map_address = malloc(raw_data.size); // for ConvertfromRGB24ToGray()
    MapMemory_Success(&raw_data, map_address); // ok

    // confirm IsaCodecQrInputParam parameter
    uint8_t* output_buf = (uint8_t*)malloc(QRCODE_PAYLOAD_MAX_SIZE);
    if (output_buf == NULL) {
        goto exit;
    }
    memset(output_buf, 0, QRCODE_PAYLOAD_MAX_SIZE);

    int32_t dummy_out_size = 1; // dummy size (>0)
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->input_adr_handle,
                 (uint64_t)(uintptr_t)gray_buff); // GrayScale
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->width, expected_img_prop.width);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->height, expected_img_prop.height);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->stride, expected_img_prop.stride_bytes * 3);
    expect_memory(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_adr_handle,
                  (uint64_t)output_buf, sizeof(output_buf));
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_max_size,
                 QRCODE_PAYLOAD_MAX_SIZE);
    will_return(__wrap_IsaCodecQrDecodeQrCode, dummy_out_size);
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrOutputNumeric); // dummy type
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrSuccess);       // ok

#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
    UnmapMemory_Success(map_address);
#endif
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_MEMORY_MAP
    UnmapMemory_Success(raw_data.address);
#endif

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, 0);

    // decode QR payload
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk); // ok
    expect_string(__wrap_IsaQrcodeDecodePayload, payload, (uint8_t*)output_buf);
    expect_value(__wrap_IsaQrcodeDecodePayload, payload_size, dummy_out_size);
    will_return(__wrap_IsaQrcodeDecodePayload, kIsaQrcodeDecode_AllRecognized);
    will_return(__wrap_IsaQrcodeDecodePayload, 1); // dummy
    will_return(__wrap_IsaQrcodeDecodePayload, kIsaQrcode_Success);
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsole);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);
    will_return(__wrap_IsaWriteQrcodePayloadToFlash, kIsaQrcode_Success);

    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, gray_buff);

    FinalizeApp_Success();

    // termination process (ret = 0)
    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    expect_function_call(__wrap_EsfPwrMgrPrepareReboot);
    will_return(__wrap_EsfPwrMgrPrepareReboot, kEsfPwrMgrOk);
    will_return(__wrap_IsaTimerFinalize, kRetOk);
    will_return(__wrap_IsaBtnFinalize, kRetOk);

    CallMainforTest(0);

    if (output_buf != NULL) {
        free(output_buf);
        output_buf = NULL;
    }
exit:
    return;
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_RGBPlanar_success(void** state)
{
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = QRCODE_IMAGE_WIDTH,
        .stride_bytes = QRCODE_IMAGE_WIDTH,
        .pixel_format = SENSCORD_PIXEL_FORMAT_RGB8_PLANAR}; // valid (qr)

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    struct senscord_raw_data_t raw_data = {.size = QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT,
                                           .type = "raw_data_type",
                                           .timestamp = 202501290900};

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    unsigned char* gray_buff = AllocateGrayBuff(QRCODE_IMAGE_WIDTH, QRCODE_IMAGE_HEIGHT);
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, gray_buff); // TODO: ConvertfromRGB8PlanarToGray()

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // call MemoryManager using expected img_prop (T5)
    char* map_address = malloc(raw_data.size); // for ConvertfromRGB8PlanarToGray()
    MapMemory_Success(&raw_data, map_address); // ok

    // confirm IsaCodecQrInputParam parameter
    uint8_t* output_buf = (uint8_t*)malloc(QRCODE_PAYLOAD_MAX_SIZE);
    if (output_buf == NULL) {
        goto exit;
    }
    memset(output_buf, 0, QRCODE_PAYLOAD_MAX_SIZE);

    int32_t dummy_out_size = 1; // dummy size (>0)
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->input_adr_handle,
                 (uint64_t)(uintptr_t)gray_buff); // GrayScale
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->width, QRCODE_IMAGE_WIDTH);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->height, QRCODE_IMAGE_HEIGHT);
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->stride, QRCODE_IMAGE_WIDTH);
    expect_memory(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_adr_handle,
                  (uint64_t)output_buf, sizeof(output_buf));
    expect_value(__wrap_IsaCodecQrDecodeQrCode, input->out_buf.output_max_size,
                 QRCODE_PAYLOAD_MAX_SIZE);
    will_return(__wrap_IsaCodecQrDecodeQrCode, dummy_out_size);
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrOutputNumeric); // dummy type
    will_return(__wrap_IsaCodecQrDecodeQrCode, kDecodeQrSuccess);       // ok

#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
    UnmapMemory_Success(map_address);
#endif
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_MEMORY_MAP
    UnmapMemory_Success(raw_data.address);
#endif

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, 0);

    // decode QR payload
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk); // ok
    expect_string(__wrap_IsaQrcodeDecodePayload, payload, (uint8_t*)output_buf);
    expect_value(__wrap_IsaQrcodeDecodePayload, payload_size, dummy_out_size);
    will_return(__wrap_IsaQrcodeDecodePayload, kIsaQrcodeDecode_AllRecognized);
    will_return(__wrap_IsaQrcodeDecodePayload, 1); // dummy
    will_return(__wrap_IsaQrcodeDecodePayload, kIsaQrcode_Success);
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsole);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);
    will_return(__wrap_IsaWriteQrcodePayloadToFlash, kIsaQrcode_Success);

    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, gray_buff);

    FinalizeApp_Success();

    // termination process (ret = 0)
    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);
    expect_function_call(__wrap_EsfPwrMgrPrepareReboot);
    will_return(__wrap_EsfPwrMgrPrepareReboot, kEsfPwrMgrOk);
    will_return(__wrap_IsaTimerFinalize, kRetOk);
    will_return(__wrap_IsaBtnFinalize, kRetOk);

    CallMainforTest(0);

    if (output_buf != NULL) {
        free(output_buf);
        output_buf = NULL;
    }
exit:
    return;
}

/*----------------------------------------------------------------------------*/
static void test_main_NotPS_invalid_pixel_format(void** state)
{
    // define expected img_prop
    struct senscord_image_property_t expected_img_prop = {
        .height = QRCODE_IMAGE_HEIGHT,
        .width = QRCODE_IMAGE_WIDTH,
        .stride_bytes = QRCODE_IMAGE_WIDTH,
        .pixel_format =
            SENSCORD_PIXEL_FORMAT_BGR24}; // invalid stride_bytes (strncmp return positive value)

    senscord_frame_t frame = 0;
    senscord_channel_t channel = 0;
    EsfMemoryManagerHandle mem_mng_handle = 0x11223344; // dummy
    struct senscord_raw_data_t dummy_raw_data = {.address = (void*)(uintptr_t)mem_mng_handle,
                                                 .size = 123456,
                                                 .type = "dummy_raw_data_type",
                                                 .timestamp = 202501090500}; // dummy

#if defined(__NuttX__)
    will_return(__wrap_IsaBtnInitialize, kRetOk);
#endif
    will_return(__wrap_IsaTimerInitialize, kRetOk);

    NotPSMode_Success();

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, 0);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    InitializeApp_Success(&expected_img_prop);

    GetSensCordStringProperty(0);
    will_return(__wrap_UtilityLogForcedOutputToUart, kUtilityLogStatusOk);

    // heap alloc
    expect_value(__wrap_IsaLargeHeapAlloc, pool_no, 0);
    expect_value(__wrap_IsaLargeHeapAlloc, request_size, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
    will_return(__wrap_IsaLargeHeapAlloc, (void*)0x12345678);

    SetLedStatusForQrCodeMode_Success();

    // senscord_stream_get_frame
    SensCordGetFrame(0);

    // senscord_frame_get_channel_from_channel_id
    SensCordGetChannelId(frame, 0x1, 0);

    // senscord_channel_get_raw_data (T5)
    expect_value(__wrap_senscord_channel_get_raw_data, channel, channel);
    will_return(__wrap_senscord_channel_get_raw_data, &dummy_raw_data);
    will_return(__wrap_senscord_channel_get_raw_data, 0);

    // call MemoryManager using expected img_prop (T5)
    char* dummy_map_address = "0x87654321";                // dummy ptr
    MapMemory_Success(&dummy_raw_data, dummy_map_address); // ok

    will_return(__wrap_senscord_get_last_error_cause, 0);

    // senscord_stream_release_frame
    SensCordStreamReleaseFrame(frame, 0);

#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
    UnmapMemory_Success(dummy_map_address);
#endif

    // heap free
    expect_value(__wrap_IsaLargeHeapFree, memory_address, (void*)0x12345678);

    // FinalizeApp
    FinalizeApp_Success();

    TerminationProcessAborted();

    CallMainforTest(-1);
}

/*----------------------------------------------------------------------------*/

//
// InitializeApp()
//

/*----------------------------------------------------------------------------*/
static void test_InitializeApp_malloc_failed(void** state)
{
    expect_value(mock_malloc, __size, QRCODE_PAYLOAD_MAX_SIZE);
    will_return(mock_malloc, true);
    will_return(mock_malloc, false); // fail

    struct senscord_image_property_t img_prop = {0};
    InitializeApp(&img_prop);
}

/*----------------------------------------------------------------------------*/
static void test_InitializeApp_IsaQrcodeInit_failed(void** state)
{
    expect_value(mock_malloc, __size, QRCODE_PAYLOAD_MAX_SIZE);
    will_return(mock_malloc, true);
    will_return(mock_malloc, true); // success
    will_return(__wrap_IsaQrcodeInit, kIsaQrcode_Failed);

    struct senscord_image_property_t img_prop = {0};
    InitializeApp(&img_prop);
}

/*----------------------------------------------------------------------------*/
static void test_InitializeApp_SsfSensorInit_failed(void** state)
{
    expect_value(mock_malloc, __size, QRCODE_PAYLOAD_MAX_SIZE);
    will_return(mock_malloc, true);
    will_return(mock_malloc, true); // success
    will_return(__wrap_IsaQrcodeInit, kIsaQrcode_Success);
    will_return(__wrap_EsfSensorInit, kEsfSensorFail); // fail

    struct senscord_image_property_t img_prop = {0};
    InitializeApp(&img_prop);
}

/*----------------------------------------------------------------------------*/
static void test_InitializeApp_senscord_core_init_failed(void** state)
{
    expect_value(mock_malloc, __size, QRCODE_PAYLOAD_MAX_SIZE);
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    will_return(__wrap_IsaQrcodeInit, kIsaQrcode_Success);
    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // senscord_core_init
    SensCordCoreInit(-1); // fail
    will_return(__wrap_senscord_get_last_error_cause, 0);

    struct senscord_image_property_t img_prop = {0};
    InitializeApp(&img_prop);
}

/*----------------------------------------------------------------------------*/
static void test_InitializeApp_senscord_core_open_stream_failed(void** state)
{
    expect_value(mock_malloc, __size, QRCODE_PAYLOAD_MAX_SIZE);
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    will_return(__wrap_IsaQrcodeInit, kIsaQrcode_Success);
    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    SensCordCoreInit(0);

    SensCordCoreOpenStream(-1); // fail
    will_return(__wrap_senscord_get_last_error_cause, 0);

    struct senscord_image_property_t img_prop = {0};
    InitializeApp(&img_prop);
}

/*----------------------------------------------------------------------------*/
static void test_InitializeApp_senscord_stream_set_property_aimodel_failed(void** state)
{
    expect_value(mock_malloc, __size, QRCODE_PAYLOAD_MAX_SIZE);
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    will_return(__wrap_IsaQrcodeInit, kIsaQrcode_Success);
    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    SensCordCoreInit(0);
    SensCordCoreOpenStream(0);

    // senscord_stream_set_property(ai_model)
    SetSensCordAIModelProperty(-1); // fail
    will_return(__wrap_senscord_get_last_error_cause, 0);

    struct senscord_image_property_t img_prop = {0};
    InitializeApp(&img_prop);
}

/*----------------------------------------------------------------------------*/
static void test_InitializeApp_senscord_stream_set_property_inputdata_failed(void** state)
{
    expect_value(mock_malloc, __size, QRCODE_PAYLOAD_MAX_SIZE);
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    will_return(__wrap_IsaQrcodeInit, kIsaQrcode_Success);
    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    // senscord_core_init
    SensCordCoreInit(0);
    SensCordCoreOpenStream(0);
    SetSensCordAIModelProperty(0);

    // senscord_stream_set_property(input_data)
    SetSensCordInputDataProperty(-1); // fail
    will_return(__wrap_senscord_get_last_error_cause, 0);

    struct senscord_image_property_t img_prop = {0};
    InitializeApp(&img_prop);
}

/*----------------------------------------------------------------------------*/
static void test_InitializeApp_senscord_stream_start_failed(void** state)
{
    expect_value(mock_malloc, __size, QRCODE_PAYLOAD_MAX_SIZE);
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    will_return(__wrap_IsaQrcodeInit, kIsaQrcode_Success);
    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    SensCordCoreInit(0);
    SensCordCoreOpenStream(0);
    SetSensCordAIModelProperty(0);
    SetSensCordInputDataProperty(0); // ok

#ifdef CONFIG_EXTERNAL_ISAPP_ENABLE_QR_QUALITY_OPTIMIZATION
    expect_value(__wrap_SetupCameraExposureAndMetering, s_stream, s_stream);
#endif // CONFIG_EXTERNAL_ISAPP_ENABLE_QR_QUALITY_OPTIMIZATION

    // senscord_stream_start
    SensCordStreamStart(-1); // fail
    will_return(__wrap_senscord_get_last_error_cause, 0);

    struct senscord_image_property_t img_prop = {0};
    InitializeApp(&img_prop);
}

/*----------------------------------------------------------------------------*/
static void test_InitializeApp_senscord_stream_get_property_failed(void** state)
{
    expect_value(mock_malloc, __size, QRCODE_PAYLOAD_MAX_SIZE);
    will_return(mock_malloc, true);
    will_return(mock_malloc, true);
    will_return(__wrap_IsaQrcodeInit, kIsaQrcode_Success);
    will_return(__wrap_EsfSensorInit, kEsfSensorOk);

    SensCordCoreInit(0);
    SensCordCoreOpenStream(0);
    SetSensCordAIModelProperty(0);
    SetSensCordInputDataProperty(0);

#ifdef CONFIG_EXTERNAL_ISAPP_ENABLE_QR_QUALITY_OPTIMIZATION
    expect_value(__wrap_SetupCameraExposureAndMetering, s_stream, s_stream);
#endif // CONFIG_EXTERNAL_ISAPP_ENABLE_QR_QUALITY_OPTIMIZATION

    // senscord_stream_start
    SensCordStreamStart(0);

    // senscord_stream_get_property
    struct senscord_image_property_t img_prop = {0};
    expect_value(__wrap_senscord_stream_get_property, stream, s_stream);
    expect_string(__wrap_senscord_stream_get_property, property_key, SENSCORD_IMAGE_PROPERTY_KEY);
    expect_value(__wrap_senscord_stream_get_property, value_size, sizeof(img_prop));
    will_return(__wrap_senscord_stream_get_property, &img_prop);
    will_return(__wrap_senscord_stream_get_property, -1);
    will_return(__wrap_senscord_get_last_error_cause, 0);

    InitializeApp(&img_prop);
}

/*----------------------------------------------------------------------------*/

//
// FinalizeApp()
//

/*----------------------------------------------------------------------------*/
static void test_FinalizeApp_fully_success(void** state)
{
    s_senscord_core_init_success = true;
    s_senscord_open_success = true;
    s_senscord_start_success = true;

    SensCordStreamStop(0);
    SensCordCoreCloseStream(0);
    SensCordCoreExit(0);
    will_return(__wrap_EsfSensorExit, kEsfSensorOk); // SsfSensorExit
    will_return(__wrap_IsaQrcodeExit, kIsaQrcode_Success);

    FinalizeApp();

    assert_null(sp_qrcode_payload_buff);
    assert_int_equal(s_senscord_start_success, false);
    assert_int_equal(s_senscord_open_success, false);
    assert_int_equal(s_senscord_core_init_success, false);
}

/*----------------------------------------------------------------------------*/
static void test_FinalizeApp_senscord_stream_stop_failed(void** state)
{
    s_senscord_start_success = true;

    SensCordStreamStop(-1);
    will_return(__wrap_senscord_get_last_error_cause, 0);
    will_return(__wrap_EsfSensorExit, kEsfSensorOk); // SsfSensorExit
    will_return(__wrap_IsaQrcodeExit, kIsaQrcode_Success);

    FinalizeApp();
    assert_int_equal(s_senscord_start_success, false);
}

/*----------------------------------------------------------------------------*/
static void test_FinalizeApp_senscord_core_close_failed(void** state)
{
    s_senscord_open_success = true;

    SensCordCoreCloseStream(-1);
    will_return(__wrap_senscord_get_last_error_cause, 0);
    will_return(__wrap_EsfSensorExit, kEsfSensorOk); // SsfSensorExit
    will_return(__wrap_IsaQrcodeExit, kIsaQrcode_Success);

    FinalizeApp();
    assert_int_equal(s_senscord_open_success, false);
}

/*----------------------------------------------------------------------------*/
static void test_FinalizeApp_senscord_core_exit_failed(void** state)
{
    s_senscord_core_init_success = true;

    SensCordCoreExit(-1); // fail
    will_return(__wrap_senscord_get_last_error_cause, 0);
    will_return(__wrap_EsfSensorExit, kEsfSensorOk); // SsfSensorExit
    will_return(__wrap_IsaQrcodeExit, kIsaQrcode_Success);

    FinalizeApp();
    assert_int_equal(s_senscord_core_init_success, false);
}

/*----------------------------------------------------------------------------*/
static void test_FinalizeApp_SsfSensorExit_failed(void** state)
{
    will_return(__wrap_EsfSensorExit, kEsfSensorFail); // SsfSensorExit fail
    will_return(__wrap_IsaQrcodeExit, kIsaQrcode_Success);

    FinalizeApp();
}

/*----------------------------------------------------------------------------*/
static void test_FinalizeApp_IsaQrcodeExit_failed(void** state)
{
    will_return(__wrap_EsfSensorExit, kEsfSensorOk);      // SsfSensorExit
    will_return(__wrap_IsaQrcodeExit, kIsaQrcode_Failed); // fail

    FinalizeApp();
}

/*----------------------------------------------------------------------------*/

//
// main()
//

/*----------------------------------------------------------------------------*/
int main(void)
{
    const struct CMUnitTest tests[] = {
        // SetLedStatusForQrCodeMode()
        cmocka_unit_test(test_SetLedStatusForQrCodeMode_fully_success),
        cmocka_unit_test(test_SetLedStatusForQrCodeMode_Failed),
        // UnsetLedStatusOfWaitingInputToConnectConsole()
        cmocka_unit_test(test_UnsetLedStatusOfWaitingInputToConnectConsole_fully_success),
        cmocka_unit_test(test_UnsetLedStatusOfWaitingInputToConnectConsole_unset_qr_failed),
        cmocka_unit_test(test_UnsetLedStatusOfWaitingInputToConnectConsole_unset_ps_failed),
        // SetLedStatusForQrCodeError()
        cmocka_unit_test(test_SetLedStatusForQrCodeError_fully_success),
        cmocka_unit_test(test_SetLedStatusForQrCodeError_EsfLedManagerSetStatus_failed),
        // test_UnsetLedStatusForQrCodeError()
        cmocka_unit_test(test_UnsetLedStatusForQrCodeError_fully_Success),
        cmocka_unit_test(test_UnsetLedStatusForQrCodeError_EsfLedManagerSetStatus_failed),
    // main()
#if defined(__NuttX__)
        cmocka_unit_test(test_main_BtnAborted),
        cmocka_unit_test(test_main_BtnAborted_SetQrModeTimeoutValue_Failed),
        cmocka_unit_test(test_main_BtnAborted_EsfPwrMgrPrepareReboot_Failed),
#endif
        cmocka_unit_test(test_main_TimerAborted),
        cmocka_unit_test(test_main_TimerAborted_WaitFactoryReset),
        cmocka_unit_test(test_main_TimeoutValue_Failed_PSAborted),
        cmocka_unit_test(test_main_PSCompleted),
        cmocka_unit_test(test_main_PSCompleted_FR),
        cmocka_unit_test(test_main_PSSuccess_InitializeApp_malloc_failed),
        cmocka_unit_test(test_main_QRmode_with_tmo_InitializeApp_malloc_failed),
        cmocka_unit_test(test_main_QRmode_with_minus_tmo_InitializeApp_malloc_failed),
        cmocka_unit_test_setup_teardown(
            test_main_NotPS_senscord_stream_get_property_ULog_gray_alloc_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_main_NotPS_senscord_stream_get_property_gray_alloc_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(test_main_NotPS_ULog_gray_alloc_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(test_main_NotPS_gray_alloc_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(test_main_NotPS_senscord_stream_get_frame_failed, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_main_NotPS_senscord_frame_get_channel_failed, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_main_NotPS_senscord_channel_get_raw_data_failed, setup,
                                        teardown),
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
        cmocka_unit_test_setup_teardown(test_main_NotPS_IsaLargeHeapAlloc_pool1_failed, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_main_NotPS_EsfMemoryManagerFopen_failed, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_main_NotPS_EsfMemoryManagerFread_failed, setup,
                                        teardown),
#endif
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_MEMORY_MAP
        cmocka_unit_test_setup_teardown(test_main_NotPS_invalid_height_map_alloc_failed, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_main_NotPS_invalid_width_map_alloc_failed, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_main_NotPS_invalid_stride_map_alloc_failed, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_main_NotPS_invalid_pixel_format_map_alloc_failed,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_main_NotPS_map_alloc_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(test_main_NotPS_GrayScale_Unmap_failed, setup, teardown),
#endif
        cmocka_unit_test_setup_teardown(test_main_NotPS_GrayScale_success, setup, teardown),
        cmocka_unit_test_setup_teardown(test_main_NotPS_GrayScale_width_not_equal_stride, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_main_NotPS_GrayScale_FactoryResetRequested, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_main_NotPS_GrayScale_RebootRequested, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_main_NotPS_GrayScale_IsaQrcodeDecodePayload_next_get_frame_failed, setup,
            teardown),
        cmocka_unit_test_setup_teardown(
            test_main_NotPS_GrayScale_IsaWriteQrcodePayloadToFlash_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_main_NotPS_GrayScale_PartRecognized_next_get_frame_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(test_main_NotPS_GrayScale_InvalidQR_next_get_frame_failed,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_main_NotPS_GrayScale_qr_data_malloc_failure, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_main_NotPS_GrayScale_QrDecode_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(test_main_NotPS_GrayScale_OutSize_zero, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_main_NotPS_GrayScale_senscord_stream_release_frame_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(test_main_NotPS_RGB_success, setup, teardown),
        cmocka_unit_test_setup_teardown(test_main_NotPS_RGBPlanar_success, setup, teardown),
        cmocka_unit_test_setup_teardown(test_main_NotPS_invalid_pixel_format, setup, teardown),
        // InitializeApp()
        cmocka_unit_test(test_InitializeApp_malloc_failed),
        cmocka_unit_test_setup_teardown(test_InitializeApp_IsaQrcodeInit_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(test_InitializeApp_SsfSensorInit_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(test_InitializeApp_senscord_core_init_failed, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_InitializeApp_senscord_core_open_stream_failed, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(
            test_InitializeApp_senscord_stream_set_property_aimodel_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_InitializeApp_senscord_stream_set_property_inputdata_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(test_InitializeApp_senscord_stream_start_failed, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_InitializeApp_senscord_stream_get_property_failed,
                                        setup, teardown),
        // FinalizeApp()
        cmocka_unit_test_setup_teardown(test_FinalizeApp_fully_success, setup, NULL),
        cmocka_unit_test_setup_teardown(test_FinalizeApp_senscord_stream_stop_failed, setup, NULL),
        cmocka_unit_test_setup_teardown(test_FinalizeApp_senscord_core_close_failed, setup, NULL),
        cmocka_unit_test_setup_teardown(test_FinalizeApp_senscord_core_exit_failed, setup, NULL),
        cmocka_unit_test_setup_teardown(test_FinalizeApp_SsfSensorExit_failed, setup, NULL),
        cmocka_unit_test_setup_teardown(test_FinalizeApp_IsaQrcodeExit_failed, setup, NULL),
    };

    return (((cmocka_run_group_tests(tests, NULL, NULL)) == 0) ? 0 : 1);
}
