/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <stdio.h>

#if defined(__linux__)
#include <unistd.h>
#include <pthread.h>
#endif

#include "sensor_main.h"
#include "senscord/c_api/senscord_c_api.h"
#include "senscord/inference_stream/c_api/property_c_types.h"
#include "memory_manager.h"
#include "parameter_storage_manager.h"
#include "power_manager.h"
#include "led_manager.h"
#include "utility_log.h"
#include "utility_log_module_id.h"
#include "system_manager.h"
#include "clock_manager.h"
#include "clock_manager_setting.h"
#include "network_manager.h"
#include "firmware_manager.h"

#include "initial_setting_app_main.h"
#include "initial_setting_app_button.h"
#include "initial_setting_app_timer.h"
#include "initial_setting_app_log.h"
#include "initial_setting_app_qr_decode.h"
#include "initial_setting_app_qr_decode_internal.h"
#include "initial_setting_app_qrcode.h"
#include "initial_setting_app_ps.h"
#include "initial_setting_app_util.h"

#ifdef INITIAL_SETTING_APP_UT
#include <unistd.h>
#endif // INITIAL_SETTING_APP_UT

static void PrintSensCordError(void);
STATIC bool InitializeApp(struct senscord_image_property_t *img_prop);
STATIC void FinalizeApp(void);
STATIC void SetLedStatusForQrCodeMode(void);
STATIC void UnsetLedStatusOfWaitingInputToConnectConsole(void);
STATIC void SetLedStatusForQrCodeError(void);
STATIC void UnsetLedStatusForQrCodeError(void);
STATIC void QrModeTimerCallback(void);
STATIC bool IsQrModeTimeout(void);
static unsigned char RGBToY(int r, int g, int b);
static void ConvertfromGrayToGray(unsigned char *gray_addtrss, unsigned char *rgb_addtrss,
                                  int32_t height, int32_t width, int32_t stride);
static void ConvertfromRGB24ToGray(unsigned char *gray_addtrss, unsigned char *rgb_addtrss,
                                   int32_t height, int32_t width, int32_t stride);
static void ConvertfromRGB8PlanarToGray(unsigned char *gray_address, unsigned char *rgb_address,
                                        int32_t height, int32_t width, int32_t stride);

STATIC senscord_core_t s_core = 0;
STATIC senscord_stream_t s_stream = 0;

STATIC bool s_senscord_core_init_success = false;
STATIC bool s_senscord_open_success = false;
STATIC bool s_senscord_start_success = false;

STATIC uint8_t *sp_qrcode_payload_buff = NULL;

STATIC bool s_qr_mode_timeout_reboot_request = false;

/****************************************************************************
 * main
 ****************************************************************************/
#if defined(INITIAL_SETTING_APP_UT) && defined(__NuttX__) // INITIAL_SETTING_APP_UT
int initial_setting_app_main_for_test(int argc, FAR char *argv[])
{
#elif !defined(__NuttX__) // INITIAL_SETTING_APP_UT
int initial_setting_app_main()
{
#else                     /* INITIAL_SETTING_APP_UT or !__NuttX__ */
int main(int argc, FAR char *argv[])
{
#endif                    // INITIAL_SETTING_APP_UT
    int ret_main = -1; // -1:Wait for factory reset button to be pressed, 0:reboot, 1:factory_reset
    bool init_success = false;
    bool write_flash_error = false;
    unsigned char *gray_buff = NULL;
    struct senscord_image_property_t img_prop = {0};

    // Button Setup.

    RetCode ret = IsaBtnInitialize();

    if (ret != kRetOk) {
        ISA_CRIT("IsaBtnInitialize() ret %d", ret);

        /* If button initialization fail,
     * button will not be used for hooks and will need to be restarted. */

        ret_main = 0; // reboot
        goto btn_aborted;
    }

    // Timer initialize.

    ret = IsaTimerInitialize();

    if (ret != kRetOk) {
        ISA_CRIT("IsaTimerInitialize() ret %d", ret);
        goto timer_aborted;
    }

#ifdef ISAPP_DO_PREPROCESS_SC

    /* Senscord Init() */

    SsfSensorErrCode ret_sensor = SsfSensorInit();

    if (ret_sensor != kSsfSensorOk) {
        ISA_CRIT("SsfSensorInit() failed : ret=%d", ret_sensor);
        goto sensor_init_aborted;
    }

#endif // ISAPP_DO_PREPROCESS_SC

    // Determine QR mode or not.

    int32_t qr_mode_tmo = 0;

    EsfSystemManagerResult res = EsfSystemManagerGetQrModeTimeoutValue(&qr_mode_tmo);

    if (res != kEsfSystemManagerResultOk) {
        ISA_ERR("EsfSystemManagerGetQrModeTimeoutValue:%d", res);
        qr_mode_tmo = 0;
    }

    /* Clear the debug mode settings to prevent PS from starting in debug mode again. */

    EsfSystemManagerSetQrModeTimeoutValue(0);

    if ((qr_mode_tmo == 0) || (qr_mode_tmo == ISAPP_PS_MODE_FORCE_ENTRY)) {
        /* Run the Provisioning Service */

        IsaPsErrorCode ercd = IsaRunProvisioningService((qr_mode_tmo != 0));

        if (ercd == kIsaPsReboot) {
            // IsaRunProvisioningService will complete successfully
            // and the reboot process will be executed, so you can exit main at this point.

            return 0;
        }
        else if (ercd == kIsaPsFactoryReset) {
            // IsaRunProvisioningService will complete successfully
            // and the factory reset process will be executed, so you can exit main at this point.

            return 0;
        }
        else if (ercd == kIsaPsSwitchToQrMode) {
            // Switch to QR mode without timeout.
        }
        else if (ercd != kIsaPsSuccess) {
            // If an error occurs in IsaRunProvisioningService,
            // the system will wait until the factory reset button is pressed.

            ISA_CRIT("IsaRunProvisioningService:%d", ercd);
            goto ps_aborted;
        }
    }
    else {
        /* Run QR mode with or without timeout. */

        if (qr_mode_tmo > 0) {
            IsaTimerStart(qr_mode_tmo, QrModeTimerCallback);
        }
    }

    /* Initialize */

    init_success = InitializeApp(&img_prop);

    if (!init_success) {
        ISA_CRIT("InitializeApp");
        goto sensor_init_aborted;
    }

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
    {
        /* Get sensor string info */

        struct senscord_info_string_property_t sensor_id = {0};

        sensor_id.category = SENSCORD_INFO_STRING_SENSOR_ID;

        int32_t ret_senscord = senscord_stream_get_property(
            s_stream, SENSCORD_INFO_STRING_PROPERTY_KEY, (void *)&sensor_id, sizeof(sensor_id));
        if (ret_senscord < 0) {
            ISA_ERR("senscord_stream_get_property ret %d", ret_senscord);

            /* Forced Output Log */

            UtilityLogStatus ulog_ret = UtilityLogForcedOutputToUart("SENSOR_ID: Error\n");
            if (ulog_ret != kUtilityLogStatusOk) {
                ISA_ERR("ERROR! UtilityLogForcedOutputToUart() ret %d\n", ulog_ret);
            }
        }
        else {
            /* Forced Output Log */

            UtilityLogStatus ulog_ret = UtilityLogForcedOutputToUart("SENSOR_ID: %s\n",
                                                                     sensor_id.info);
            if (ulog_ret != kUtilityLogStatusOk) {
                ISA_ERR("ERROR! UtilityLogForcedOutputToUart() ret %d\n", ulog_ret);
            }
        }
    }
#endif
#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
    {
        /* Get sensor string info */

        struct senscord_info_string_property_t aiisp = {0};

        aiisp.category = SENSCORD_INFO_STRING_AIISP_DEVICE_ID;

        int32_t ret_senscord = senscord_stream_get_property(
            s_stream, SENSCORD_INFO_STRING_PROPERTY_KEY, (void *)&aiisp, sizeof(aiisp));
        if (ret_senscord < 0) {
            ISA_ERR("senscord_stream_get_property ret %d", ret_senscord);

            /* Forced Output Log */

            UtilityLogStatus ulog_ret = UtilityLogForcedOutputToUart("AIISP_DEVICE_ID : Error\n");
            if (ulog_ret != kUtilityLogStatusOk) {
                ISA_ERR("ERROR! UtilityLogForcedOutputToUart() ret %d\n", ulog_ret);
            }
        }
        else {
            /* Forced Output Log */

            UtilityLogStatus ulog_ret = UtilityLogForcedOutputToUart("AIISP_DEVICE_ID: %s\n",
                                                                     aiisp.info);
            if (ulog_ret != kUtilityLogStatusOk) {
                ISA_ERR("ERROR! UtilityLogForcedOutputToUart() ret %d\n", ulog_ret);
            }
        }
    }
#endif

    gray_buff = IsaLargeHeapAlloc(0, QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);

    if (gray_buff == NULL) {
        ISA_CRIT("IsaLargeHeapAlloc() error size %d", QRCODE_IMAGE_WIDTH * QRCODE_IMAGE_HEIGHT);
        goto malloc_failed;
    }

    // Set LED status when entering QR code mode.

    SetLedStatusForQrCodeMode();

    while (1) {
        int32_t ret_senscord = -1;
        senscord_frame_t frame = 0;
        senscord_channel_t channel = 0;
        struct senscord_raw_data_t raw_data = {};

        /* Get frame */

        ret_senscord = senscord_stream_get_frame(s_stream, &frame, -1);

        if (ret_senscord < 0) {
            ISA_CRIT("senscord_stream_get_frame : ret=%d", ret_senscord);
            PrintSensCordError();
            break;
        }

        /* Get channel_id */

        ret_senscord = senscord_frame_get_channel_from_channel_id(frame,
                                                                  0x1, // 0x1:Inference input image
                                                                  &channel);

        if (ret_senscord < 0) {
            ISA_CRIT("senscord_frame_get_channel_from_channel_id : ret=%d", ret_senscord);
            PrintSensCordError();
            senscord_stream_release_frame(s_stream, frame);
            break;
        }

        /* Get raw_data */

        ret_senscord = senscord_channel_get_raw_data(channel, &raw_data);

        if (ret_senscord < 0) {
            ISA_CRIT("senscord_channel_get_raw_data : ret=%d", ret_senscord);
            PrintSensCordError();
            senscord_stream_release_frame(s_stream, frame);
            break;
        }

        ISA_DBG("raw_data.address:%p", raw_data.address);
        ISA_DBG("raw_data.size:%zu", raw_data.size);
        ISA_DBG("raw_data.timestamp:%llu", raw_data.timestamp);
        ISA_DBG("raw_data.type:%s", raw_data.type);
        ISA_DBG("img_prop.width:%u", img_prop.width);
        ISA_DBG("img_prop.height:%u", img_prop.height);
        ISA_DBG("img_prop.stride_bytes:%u", img_prop.stride_bytes);
        ISA_DBG("img_prop.pixel_format:%s", img_prop.pixel_format);

        uint32_t raw_height = img_prop.height;
        uint32_t raw_width = img_prop.width;
        uint32_t raw_stride = img_prop.stride_bytes;

        if (raw_height <= 0) {
            raw_height = QRCODE_IMAGE_HEIGHT;
            ISA_ERR("Invalid img_prop.height! Use default valude %u", raw_height);
        }
        if (raw_width <= 0) {
            raw_width = QRCODE_IMAGE_WIDTH;
            ISA_ERR("Invalid img_prop.width! Use default valude %u", raw_width);
        }
        if (raw_stride <= 0) {
            raw_stride = QRCODE_IMAGE_WIDTH;
            if (strncmp(img_prop.pixel_format, SENSCORD_PIXEL_FORMAT_RGB24,
                        SENSCORD_PIXEL_FORMAT_LENGTH + 1) == 0) {
                raw_stride *= 3;
            }
            ISA_ERR("Invalid img_prop.storide_bites! Use default valude %u", raw_stride);
        }
        ISA_DBG("Result of height/width/stride : %u / %u / %u", raw_height, raw_width, raw_stride);

        EsfMemoryManagerResult esfmm_ret = kEsfMemoryManagerResultSuccess;

        uint64_t *map_address;

#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO

        /* Allocate memory & read */

        map_address = IsaLargeHeapAlloc(1, (EsfMemoryManagerHandle)(uintptr_t)raw_data.size);

        if (map_address == NULL) {
            ISA_CRIT("IsaLargeHeapAlloc(1, %u) failed", raw_data.size);
            senscord_stream_release_frame(s_stream, frame);
            break;
        }

        esfmm_ret = EsfMemoryManagerFopen((EsfMemoryManagerHandle)(uintptr_t)raw_data.address);

        if (esfmm_ret != kEsfMemoryManagerResultSuccess) {
            ISA_CRIT("EsfMemoryManagerFopen() ret %d", esfmm_ret);
            senscord_stream_release_frame(s_stream, frame);
            IsaLargeHeapFree(map_address);
            break;
        }

        size_t rsize;
        esfmm_ret = EsfMemoryManagerFread((EsfMemoryManagerHandle)(uintptr_t)raw_data.address,
                                          map_address, raw_data.size, &rsize);

        if (esfmm_ret != kEsfMemoryManagerResultSuccess) {
            ISA_CRIT("EsfMemoryManagerFread() ret %d", esfmm_ret);
            senscord_stream_release_frame(s_stream, frame);
            IsaLargeHeapFree(map_address);
            EsfMemoryManagerFclose((EsfMemoryManagerHandle)(uintptr_t)raw_data.address);
            break;
        }

        EsfMemoryManagerFclose((EsfMemoryManagerHandle)(uintptr_t)raw_data.address);

#else // Use #else for build: CONFIG_EXTERNAL_LARGE_HEAP_MEMORY_MAP

        EsfMemoryManagerHandleInfo handle_info = {0};

        esfmm_ret = EsfMemoryManagerGetHandleInfo(
            (EsfMemoryManagerHandle)(uintptr_t)raw_data.address, &handle_info);

        if (esfmm_ret != kEsfMemoryManagerResultSuccess) {
            ISA_CRIT("EsfMemoryManagerGetHandleInfo : ret=%d", esfmm_ret);
            senscord_stream_release_frame(s_stream, frame);
            break;
        }

        if (handle_info.target_area == kEsfMemoryManagerTargetOtherHeap) {
            // raw_data.address represents malloc buffer.
            map_address = (uint64_t *)raw_data.address;
        }
        else {
            /* Map memory */
            esfmm_ret = EsfMemoryManagerMap((EsfMemoryManagerHandle)(uintptr_t)raw_data.address,
                                            NULL, raw_data.size, (void *)&map_address);

            if (esfmm_ret != kEsfMemoryManagerResultSuccess) {
                ISA_CRIT("EsfMemoryManagerMap : ret=%d", esfmm_ret);
                senscord_stream_release_frame(s_stream, frame);
                break;
            }
        }
#endif

        unsigned char *gray_address = NULL;

        if (strncmp(img_prop.pixel_format, SENSCORD_PIXEL_FORMAT_GREY,
                    SENSCORD_PIXEL_FORMAT_LENGTH + 1) == 0) {
            // GRAY

            ISA_INFO("GrayScale Image.");
            if (raw_width == raw_stride) {
                /* None padding data */
                gray_address = (unsigned char *)map_address;
            }
            else {
                /* Remove padding data */

                ISA_INFO("Remove padding from GrayScale.");
                gray_address = gray_buff;
                ConvertfromGrayToGray(gray_address, (unsigned char *)map_address, raw_height,
                                      raw_width, raw_stride);
                raw_stride = raw_width;
            }
        }
        else if (strncmp(img_prop.pixel_format, SENSCORD_PIXEL_FORMAT_RGB24,
                         SENSCORD_PIXEL_FORMAT_LENGTH + 1) == 0) {
            // RGB

            ISA_INFO("Convert from RGB(Packed pixel) to Y.");
            gray_address = gray_buff;
            ConvertfromRGB24ToGray(gray_address, (unsigned char *)map_address, raw_height,
                                   raw_width, raw_stride);
            raw_stride = raw_width * 3;
        }
        else if (strncmp(img_prop.pixel_format, SENSCORD_PIXEL_FORMAT_RGB8_PLANAR,
                         SENSCORD_PIXEL_FORMAT_LENGTH + 1) == 0) {
            // RGB PLANAR

            ISA_INFO("Convert from RGB(PLAN) to Y.");
            gray_address = gray_buff;
            ConvertfromRGB8PlanarToGray(gray_address, (unsigned char *)map_address, raw_height,
                                        raw_width, raw_stride);
            raw_stride = raw_width;
        }
        else {
            // Other

            ISA_CRIT("pixel format does not exist, format=%s", img_prop.pixel_format);
            PrintSensCordError();
            senscord_stream_release_frame(s_stream, frame);
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
            IsaLargeHeapFree(map_address);
#endif
            break;
        }

        /* Decode QR Code */

        IsaCodecQrInputParam input = {};
        IsaCodecQrOutputInfo output = {};

        memset(sp_qrcode_payload_buff, 0, QRCODE_PAYLOAD_MAX_SIZE);

        input.input_adr_handle = (uint64_t)(uintptr_t)gray_address;
        input.width = raw_width;
        input.height = raw_height;
        input.stride = raw_stride;
        input.out_buf.output_adr_handle = (uint64_t)(uintptr_t)sp_qrcode_payload_buff;
        input.out_buf.output_max_size = QRCODE_PAYLOAD_MAX_SIZE;

        IsaCodecQrError ret_ssfqr = IsaCodecQrDecodeQrCode(&input, &output);

#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO

        /* Deallocate memory buffer. */

        IsaLargeHeapFree(map_address);

#endif
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_MEMORY_MAP

        /* Unmap memory */

        if (handle_info.target_area != kEsfMemoryManagerTargetOtherHeap) {
            esfmm_ret = EsfMemoryManagerUnmap((EsfMemoryManagerHandle)(uintptr_t)raw_data.address,
                                              NULL);

            if (esfmm_ret != kEsfMemoryManagerResultSuccess) {
                ISA_CRIT("EsfMemoryManagerUnmap : ret=%d", esfmm_ret);
                senscord_stream_release_frame(s_stream, frame);
                break;
            }
        }

#endif

        /* Release frame as soon as no longer needed */

        ret_senscord = senscord_stream_release_frame(s_stream, frame);

        if (ret_senscord < 0) {
            ISA_CRIT("senscord_stream_release_frame : ret=%d", ret_senscord);
            PrintSensCordError();
            break;
        }

        if ((ret_ssfqr == kDecodeQrSuccess) && (output.output_size != 0)) {
            /* Decode QR Code payload */

            UtilityLogForcedOutputToUart("QR Code Payload: [%s] sz:%d\n",
                                         (uint8_t *)(uintptr_t)input.out_buf.output_adr_handle,
                                         output.output_size);

            IsaQrcodeErrorCode ret_qrcode = kIsaQrcode_Failed;
            IsaQrcodeDecodeResult result = kIsaQrcodeDecode_Invalid;
            uint8_t qr_count = 0; /* Currently not used */

            /* Note : Payload length w/o terminator. */

            ret_qrcode =
                IsaQrcodeDecodePayload((uint8_t *)(uintptr_t)input.out_buf.output_adr_handle,
                                       output.output_size, &result, &qr_count);

            if (ret_qrcode != kIsaQrcode_Success) {
                ISA_ERR("IsaQrcodeDecodePayload() failed : ret=%d", ret_qrcode);
            }

            if (result == kIsaQrcodeDecode_AllRecognized) {
                ISA_INFO("Fully detected QR Code");

                UnsetLedStatusOfWaitingInputToConnectConsole();

                /* Write data obtained from QrCode to Flash */

                ret_qrcode = IsaWriteQrcodePayloadToFlash();

                if (ret_qrcode != kIsaQrcode_Success) {
                    ISA_ERR("IsaWriteQrcodePayloadToFlash() failed : ret=%d", ret_qrcode);
                    write_flash_error = true;
                }

                ret_main = 0;
                break;
            }
            else if (result == kIsaQrcodeDecode_PartRecognized) {
                ISA_INFO("Partially detected QR Code");
            }
            else if (result == kIsaQrcodeDecode_Invalid) {
                ISA_ERR("Invalid QR Code");
                IsaClearMultiQRParam();

                SetLedStatusForQrCodeError();

                /* Wait 5sec to notify QR Code error */

                sleep(5);

                UnsetLedStatusForQrCodeError();
            }
        }
        else {
            ISA_DBG("Not detect QR Code");
        }

        // Check factory reset request.

        if (IsaBtnCheckFactoryResetRequest()) {
            ISA_INFO("FactoryReset was requested.");
            ret_main = 1;
            break;
        }

        if (IsQrModeTimeout()) {
            ISA_INFO("Reboot was requested.");
            ret_main = 0;
            break;
        }
    }

    if (gray_buff != NULL) {
        IsaLargeHeapFree(gray_buff);
        gray_buff = NULL;
    }

sensor_init_aborted:
malloc_failed:
    /* Finalize */

    FinalizeApp();

btn_aborted:
timer_aborted:
ps_aborted:
    /* Clear Qr mode timeout value */

    uint32_t clear_qr_mode_tmo = 0;
    if (write_flash_error) {
        // If an error occurs while writing to flash,
        // set the QR mode timeout value to -1 to enter QR mode on the next boot.
        clear_qr_mode_tmo = -1;
    }

    EsfSystemManagerResult esfss_ret = EsfSystemManagerSetQrModeTimeoutValue(clear_qr_mode_tmo);

    if (esfss_ret != kEsfSystemManagerResultOk) {
        ISA_ERR("EsfSystemManagerSetQrModeTimeoutValue() ret %d", esfss_ret);
    }

    /* Reboot if all processes are successful */

    if (ret_main == 0) { // Reboot.
        ISA_INFO("Execute reboot!");

        EsfPwrMgrError ret_pm = kEsfPwrMgrOk;

        // Stop Keep Alive of WDT

        ISA_INFO("Stop Keep Alive of WDT");
        EsfPwrMgrWdtTerminate();

        ret_pm = EsfPwrMgrPrepareReboot();

        if (ret_pm != kEsfPwrMgrOk) {
            ISA_ERR("EsfPwrMgrPrepareReboot failed : ret=%d", ret_pm);
        }
    }
    else if (ret_main == 1) { // Factory reset.
        UnsetLedStatusOfWaitingInputToConnectConsole();
        IsaBtnExecuteFactoryResetCore();
    }
    else {
        // If this application terminates due to an error, etc.,
        // it will wait for a factory reboot request via the button.
        ISA_CRIT(
            "Unknown reason for InitialSettingApp termination. Waiting for factory "
            "reset request. ret_main=%d",
            ret_main);

        for (;;) {
            ISA_INFO("Check factory reset request.");

            if (IsaBtnCheckFactoryResetRequest()) {
                ISA_INFO("FactoryReset was requested.");
                UnsetLedStatusOfWaitingInputToConnectConsole();
                IsaBtnExecuteFactoryResetCore();
                break;
            }

            sleep(1);
        }
    }

    IsaTimerFinalize();

    IsaBtnFinalize();

    return ret_main;
}

static void PrintSensCordError(void)
{
    enum senscord_error_cause_t cause = senscord_get_last_error_cause();

    ISA_DBG("cause  : %d\n", cause);
}

STATIC bool InitializeApp(struct senscord_image_property_t *img_prop)
{
    bool ret = false;
    int32_t ret_senscord = -1;
    IsaQrcodeErrorCode ret_qrcode = kIsaQrcode_Failed;
    const char ISA_STREAM_KEY[] = "inference_stream";

    do {
        /* Malloc for decoding Qrcode */

        sp_qrcode_payload_buff = (uint8_t *)malloc(QRCODE_PAYLOAD_MAX_SIZE);

        if (sp_qrcode_payload_buff == NULL) {
            ISA_CRIT("malloc() failed\n");
            break;
        }

        memset(sp_qrcode_payload_buff, 0, QRCODE_PAYLOAD_MAX_SIZE);

        /* InitialSettingApp Qrcode Init */

        ret_qrcode = IsaQrcodeInit();

        if (ret_qrcode != kIsaQrcode_Success) {
            ISA_CRIT("IsaQrcodeInit() failed : ret=%d\n", ret_qrcode);
            break;
        }

        /* Senscord Core Init */

        ret_senscord = senscord_core_init(&s_core);

        if (ret_senscord < 0) {
            ISA_CRIT("senscord_core_init failed : ret=%d", ret_senscord);
            PrintSensCordError();
            break;
        }
        else {
            s_senscord_core_init_success = true;
        }

        /* Senscord Stream Open */

        ret_senscord = senscord_core_open_stream(s_core, ISA_STREAM_KEY, &s_stream);

        if (ret_senscord < 0) {
            ISA_CRIT("senscord_core_open_stream failed : ret=%d", ret_senscord);
            PrintSensCordError();
            break;
        }
        else {
            s_senscord_open_success = true;
        }

        /* Senscord Load AiModel for QrCode */

        struct senscord_ai_model_bundle_id_property_t ai_model_bundle_id = {};

        snprintf(ai_model_bundle_id.ai_model_bundle_id,
                 sizeof(ai_model_bundle_id.ai_model_bundle_id), "%s", AIMODEL_ID_FOR_QRCODE);

        ret_senscord = senscord_stream_set_property(
            s_stream, SENSCORD_AI_MODEL_BUNDLE_ID_PROPERTY_KEY, (const void *)&ai_model_bundle_id,
            sizeof(ai_model_bundle_id));

        if (ret_senscord < 0) {
            ISA_CRIT("senscord_stream_set_property(AIMODEL) failed : ret=%d", ret_senscord);
            PrintSensCordError();
            break;
        }

        /* Set Input Data Type Property */

        struct senscord_input_data_type_property_t input_data = {};
        input_data.count = 1;
        input_data.channels[0] = 0x1; // 0x1:Inference input image

        ret_senscord = senscord_stream_set_property(s_stream, SENSCORD_INPUT_DATA_TYPE_PROPERTY_KEY,
                                                    (const void *)&input_data, sizeof(input_data));

        if (ret_senscord < 0) {
            ISA_CRIT("senscord_stream_set_property(INPUT_DATA_TYPE) failed : ret=%d", ret_senscord);
            PrintSensCordError();
            break;
        }

#ifdef CONFIG_EXTERNAL_ISAPP_ENABLE_QR_QUALITY_OPTIMIZATION
        SetupCameraExposureAndMetering(s_stream);
#endif

        /* Senscord Stream Start */

        ret_senscord = senscord_stream_start(s_stream);

        if (ret_senscord < 0) {
            ISA_CRIT("senscord_stream_start failed : ret=%d", ret_senscord);
            PrintSensCordError();
            break;
        }
        else {
            s_senscord_start_success = true;
        }

        // Get frame information.

        ret_senscord = senscord_stream_get_property(s_stream, SENSCORD_IMAGE_PROPERTY_KEY,
                                                    (void *)img_prop,
                                                    sizeof(struct senscord_image_property_t));

        if (ret_senscord < 0) {
            ISA_CRIT("senscord_stream_get_property(SENSCORD_IMAGE_PROPERTY_KEY) failed : ret=%d",
                     ret_senscord);
            PrintSensCordError();
            break;
        }

        ret = true;
    } while (0);

    return ret;
}

STATIC void FinalizeApp(void)
{
    int32_t ret_senscord = -1;
    SsfSensorErrCode ret_sensor = kSsfSensorFail;
    IsaQrcodeErrorCode ret_qrcode = kIsaQrcode_Failed;

    /* Senscord Stream Stop */

    if (s_senscord_start_success) {
        ret_senscord = senscord_stream_stop(s_stream);

        if (ret_senscord < 0) {
            ISA_ERR("senscord_stream_stop failed : ret=%d", ret_senscord);
            PrintSensCordError();
        }

        s_senscord_start_success = false;
    }

    /* Senscord Stream Close */

    if (s_senscord_open_success) {
        ret_senscord = senscord_core_close_stream(s_core, s_stream);

        if (ret_senscord < 0) {
            ISA_ERR("senscord_core_close_stream failed : ret=%d", ret_senscord);
            PrintSensCordError();
        }

        s_senscord_open_success = false;
    }

    /* Senscord Core Exit */

    if (s_senscord_core_init_success) {
        ret_senscord = senscord_core_exit(s_core);

        if (ret_senscord < 0) {
            ISA_ERR("senscord_core_exit failed : ret=%d", ret_senscord);
            PrintSensCordError();
        }

        s_senscord_core_init_success = false;
    }

#ifdef ISAPP_DO_PREPROCESS_SC

    /* Senscord Exit */

    ret_sensor = SsfSensorExit();

    if (ret_sensor != kSsfSensorOk) {
        ISA_ERR("SsfSensorExit failed : ret=%d", ret_sensor);
    }

#endif // ISAPP_DO_PREPROCESS_SC

    /* InitialSettingApp Qrcode Exit */

    ret_qrcode = IsaQrcodeExit();

    if (ret_qrcode != kIsaQrcode_Success) {
        ISA_ERR("IsaQrcodeExit failed : ret=%d", ret_qrcode);
    }

    /* Free */

    if (sp_qrcode_payload_buff != NULL) {
        free(sp_qrcode_payload_buff);
        sp_qrcode_payload_buff = NULL;
    }
}

STATIC void SetLedStatusForQrCodeMode(void)
{
    // Set LED status when entering QR code mode.

    EsfLedManagerResult ret_ledmgr = kEsfLedManagerInternalError;
    EsfLedManagerLedStatusInfo status;

    status.led = kEsfLedManagerTargetLedPower;
    status.enabled = true;
    status.status = kEsfLedManagerLedStatusWaitingForInputsToConnectConsole;

    ret_ledmgr = EsfLedManagerSetStatus(&status);

    if (ret_ledmgr != kEsfLedManagerSuccess) {
        ISA_ERR("EsfLedManagerSetStatus failed : ret=%d", ret_ledmgr);
    }
}

STATIC void UnsetLedStatusOfWaitingInputToConnectConsole(void)
{
    //
    // Unset WaintgForinputToConnectConsole{GlobalProvisioner}
    // Even if current status is both QR or PS.
    //

    // Unset QR mode led status.

    EsfLedManagerResult ret_ledmgr = kEsfLedManagerInternalError;
    EsfLedManagerLedStatusInfo status;

    status.led = kEsfLedManagerTargetLedPower;
    status.enabled = false;
    status.status = kEsfLedManagerLedStatusWaitingForInputsToConnectConsole;

    ret_ledmgr = EsfLedManagerSetStatus(&status);

    if (ret_ledmgr != kEsfLedManagerSuccess) {
        ISA_ERR("EsfLedManagerSetStatus failed : ret=%d", ret_ledmgr);
    }

    // Unset PS mode led status.

    status.status = kEsfLedManagerLedStatusWaitingForInputsToConnectConsoleGlobalProvisioner;

    ret_ledmgr = EsfLedManagerSetStatus(&status);

    if (ret_ledmgr != kEsfLedManagerSuccess) {
        ISA_ERR("EsfLedManagerSetStatus failed : ret=%d", ret_ledmgr);
    }
}

STATIC void SetLedStatusForQrCodeError(void)
{
    // Set LED status when QR code is invalid.

    EsfLedManagerResult ret_ledmgr = kEsfLedManagerInternalError;
    EsfLedManagerLedStatusInfo status;

    status.led = kEsfLedManagerTargetLedPower;
    status.enabled = true;
    status.status = kEsfLedManagerLedStatusErrorInvalidQRCode;

    ret_ledmgr = EsfLedManagerSetStatus(&status);

    if (ret_ledmgr != kEsfLedManagerSuccess) {
        ISA_ERR("EsfLedManagerSetStatus failed : ret=%d", ret_ledmgr);
    }
}

STATIC void UnsetLedStatusForQrCodeError(void)
{
    // Unset LED status when QR code is invalid.

    EsfLedManagerResult ret_ledmgr = kEsfLedManagerInternalError;
    EsfLedManagerLedStatusInfo status;

    status.led = kEsfLedManagerTargetLedPower;
    status.enabled = false;
    status.status = kEsfLedManagerLedStatusErrorInvalidQRCode;

    ret_ledmgr = EsfLedManagerSetStatus(&status);

    if (ret_ledmgr != kEsfLedManagerSuccess) {
        ISA_ERR("EsfLedManagerSetStatus failed : ret=%d", ret_ledmgr);
    }
}

STATIC void QrModeTimerCallback(void)
{
    ISA_INFO("QrModeTimerCallback");

    s_qr_mode_timeout_reboot_request = true;
}

STATIC bool IsQrModeTimeout(void)
{
    return s_qr_mode_timeout_reboot_request;
}

static unsigned char RGBToY(int r, int g, int b)
{
    return (unsigned char)((299 * r + 587 * g + 114 * b) / 1000);
}

static void ConvertfromGrayToGray(unsigned char *dst_address, unsigned char *src_address,
                                  int32_t height, int32_t width, int32_t stride)
{
    // Convert from GrayScale to GrayScale.

    for (uint32_t y = 0U; y < (uint32_t)height; y++) {
        for (uint32_t x = 0U; x < (uint32_t)width; x++) {
            dst_address[x] = src_address[x];
        }
        dst_address += width;
        src_address += stride;
    }
}

static void ConvertfromRGB24ToGray(unsigned char *gray_address, unsigned char *rgb_address,
                                   int32_t height, int32_t width, int32_t stride)
{
    // Convert from RGB to Y.

    for (uint32_t y = 0U; y < (uint32_t)height; y++) {
        for (uint32_t x = 0U; x < (uint32_t)width; x++) {
            gray_address[x] = RGBToY(rgb_address[x * 3], rgb_address[x * 3 + 1],
                                     rgb_address[x * 3 + 2]);
        }
        gray_address += width;
        rgb_address += stride;
    }
}

static void ConvertfromRGB8PlanarToGray(unsigned char *gray_address, unsigned char *rgb_address,
                                        int32_t height, int32_t width, int32_t stride)
{
    // Convert from RGB_PLANAR to Y.

    uint32_t plan_size = height * stride;

    for (uint32_t y = 0U; y < (uint32_t)height; y++) {
        uint8_t *r_plan = rgb_address;
        uint8_t *g_plan = r_plan + plan_size;
        uint8_t *b_plan = g_plan + plan_size;
        for (uint32_t x = 0U; x < (uint32_t)width; x++) {
            gray_address[x] = RGBToY(r_plan[x], g_plan[x], b_plan[x]);
        }
        gray_address += width;
        rgb_address += stride;
    }
}
