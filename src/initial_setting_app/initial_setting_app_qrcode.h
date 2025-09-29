/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#ifndef _INITIAL_SETTING_APP_QRCODE_H_
#define _INITIAL_SETTING_APP_QRCODE_H_

#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    kIsaQrcode_Success = 0,     // Success.
    kIsaQrcode_InvalidArgument, // Argument error.
    kIsaQrcode_Failed,          // Failed.

    kIsaQrcode_ErrcodeNum
} IsaQrcodeErrorCode;

typedef enum {
    kIsaQrcodeDecode_AllRecognized = 0,
    kIsaQrcodeDecode_PartRecognized,
    kIsaQrcodeDecode_Invalid,

    kIsaQrcodeDecode_ResultNum
} IsaQrcodeDecodeResult;

IsaQrcodeErrorCode IsaQrcodeInit(void);

IsaQrcodeErrorCode IsaQrcodeDecodePayload(uint8_t* payload, int32_t payload_size,
                                          IsaQrcodeDecodeResult* result, uint8_t* qr_count);

IsaQrcodeErrorCode IsaWriteQrcodePayloadToFlash(void);

void IsaClearMultiQRParam(void);

IsaQrcodeErrorCode IsaQrcodeExit(void);

#define MULTI_QR_NUM_MAX (8)

// Enable if preprocessing is need itself
#define ISAPP_DO_PREPROCESS_DS // DeviceSetting
#define ISAPP_DO_PREPROCESS_SC // SensCord
#define ISAPP_DO_PREPROCESS_PM // PowerManager

#ifdef __cplusplus
}
#endif

#endif // _INITIAL_SETTING_APP_QRCODE_H_
