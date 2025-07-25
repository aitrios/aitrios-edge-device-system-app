/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#include "initial_setting_app_qr_decode.h" // for IsaCodecQrInputParam, kDecodeQrSuccess

#include <stdint.h> // for uint8_t, uintptr_t, uint64_t
#include <stdio.h>  // for NULL
#include <stdlib.h> // for free

#if defined(__NuttX__)
#include <nuttx/config.h>
#endif

#ifdef CONFIG_ZXING_CPP_PORTING
#include "zxing-cpp/src/wrappers/c/zxing-c.h"
#endif
#ifdef CONFIG_EXTERNAL_QUIRC
#include "quirc/lib/quirc.h" // for quirc_destroy, quirc_code, qui...
#endif

#include "initial_setting_app_qr_decode_internal.h" // for IsaCodecQrCreateInstance, IsaC...

#include "initial_setting_app_log.h"
#include "initial_setting_app_util.h"

/****************************************************************************
 * Pre-processor definitions
 ****************************************************************************/

IsaCodecQrError IsaCodecQrDecodeQrCode(const IsaCodecQrInputParam *input,
                                       IsaCodecQrOutputInfo *output)
{
    // Parameter check.
    if ((input == (IsaCodecQrInputParam *)NULL) || (output == (IsaCodecQrOutputInfo *)NULL)) {
        ISA_ERR("IsaQrDecodeQrCode(%p, %p)", input, output);
        return kDecodeQrParamError;
    }
    IsaCodecQrError result = kDecodeQrSuccess;

#ifdef CONFIG_ZXING_CPP_PORTING
    uint8_t *image = (uint8_t *)(uintptr_t)input->input_adr_handle;

    const IsaCodecQrOutputBuf *out_buf = &(input->out_buf);

    // Set input image.

    zxing_ImageView *zx_iv =
        zxing_ImageView_new(image,                 // Input image data
                            input->width,          // Input image width pix
                            input->height,         // Input image height pix
                            zxing_ImageFormat_Lum, // Input image format
                            0,  // Input row stride, 0 means use default value intenallry.
                            0); // Input pix strime, 0 means use default value intenallry.

    if (zx_iv == NULL) {
        ISA_ERR("zxing_ImageView_new failed");
        result = kDecodeQrOssInternalError;
        goto zx_image_viewer_create_failed;
    }

    // Set decode hints.

    zxing_DecodeHints *zx_hints = zxing_DecodeHints_new();

    if (zx_hints == NULL) {
        ISA_ERR("zxing_DecodeHints_new failed");
        result = kDecodeQrOssInternalError;
        goto zx_decode_hints_create_failed;
    }

    zxing_BarcodeFormats zx_formats = zxing_BarcodeFormat_QRCode;

    zxing_DecodeHints_setTextMode(zx_hints, zxing_TextMode_HRI);
    zxing_DecodeHints_setEanAddOnSymbol(zx_hints, zxing_EanAddOnSymbol_Ignore);
    zxing_DecodeHints_setFormats(zx_hints, zx_formats);
    zxing_DecodeHints_setReturnErrors(zx_hints, true);

    // Decode.

    zxing_Result *zx_result = zxing_ReadBarcode(zx_iv, zx_hints);

    if (zx_result != NULL) {
        if (zxing_Result_isValid(zx_result)) {
            // Check payload size.

            int zx_bytes_len = 0;
            uint8_t *zx_bytes = zxing_Result_bytes(zx_result,
                                                   &zx_bytes_len); // Using malloc() internally.
            free(zx_bytes);

            if (zx_bytes_len >= out_buf->output_max_size) {
                ISA_ERR("Payload size over, payload[%d] buf[%d]", zx_bytes_len,
                        out_buf->output_max_size);
                result = kDecodeQrOutputSizeOver;
                zxing_Result_delete(zx_result);
                goto output_size_over;
            }

            // Set output info.

            char *zx_result_txt = zxing_Result_text(zx_result); // Using malloc() internally.
            snprintf((char *)(uintptr_t)out_buf->output_adr_handle, out_buf->output_max_size, "%s",
                     zx_result_txt);
            output->output_size = zx_bytes_len;
            output->output_type = kDecodeQrOutputAlphanumeric; /*Will not use after.*/

            ISA_INFO("Text       : %s", zx_result_txt);
            ISA_INFO("Bytes len  : %d", zx_bytes_len);
            free(zx_result_txt);
        }
        else {
            ISA_INFO("Invalid QR code");
        }

        ISA_INFO("Rotation   : %d", zxing_Result_orientation(zx_result));
        ISA_INFO("Inverted   : %d", zxing_Result_isInverted(zx_result));
        ISA_INFO("Mirrored   : %d", zxing_Result_isMirrored(zx_result));

        zxing_Result_delete(zx_result);
    }
    else {
        ISA_INFO("QR code was not detected.");
    }

output_size_over:

    zxing_DecodeHints_delete(zx_hints);

zx_decode_hints_create_failed:

    zxing_ImageView_delete(zx_iv);

zx_image_viewer_create_failed:

    return result;
#endif // CONFIG_ZXING_CPP_PORTING
#ifdef CONFIG_EXTERNAL_QUIRC
    uint8_t *image = (uint8_t *)(uintptr_t)input->input_adr_handle;
    struct quirc *instance = IsaCodecQrCreateInstance(input->width, input->height);
    if (instance == (struct quirc *)NULL) {
        ISA_ERR("IsaCodecQrCreateInstance");
        return kDecodeQrOssInternalError;
    }

    struct quirc_code *qr_code_info = (struct quirc_code *)calloc(1, sizeof(*qr_code_info));
    if (qr_code_info == (struct quirc_code *)NULL) {
        ISA_ERR("calloc(qr_code_info)");
        quirc_destroy(instance);
        return kDecodeQrOtherError;
    }

    result = IsaCodecQrDetect((uint64_t)(uintptr_t)image, qr_code_info, instance);
    quirc_destroy(instance);
    if (result != kDecodeQrSuccess) {
        ISA_ERR("IsaCodecQrDetect(%d)", result);
        free(qr_code_info);
        return result;
    }

    struct quirc_data *qr_code_data = (struct quirc_data *)calloc(1, sizeof(*qr_code_data));
    if (qr_code_data == (struct quirc_data *)NULL) {
        ISA_ERR("calloc(qr_code_data)");
        free(qr_code_info);
        return kDecodeQrOtherError;
    }

    result = IsaCodecQrDecodeQrCodeInfo(qr_code_info, qr_code_data);
    free(qr_code_info);
    if (result != kDecodeQrSuccess) {
        ISA_ERR("IsaCodecQrDecodeQrCodeInfo(%d)", result);
        free(qr_code_data);
        return result;
    }

    result = IsaCodecQrStoreDecodingResult(&(input->out_buf), qr_code_data, output);
    free(qr_code_data);
    if (result != kDecodeQrSuccess) {
        ISA_ERR("IsaCodecQrStoreDecodingResult(%d)", result);
        return result;
    }

    return kDecodeQrSuccess;
#endif // CONFIG_EXTERNAL_QUIRC

    return result;
}
