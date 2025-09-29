/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

// Define the external public API for QR code.

#ifndef INITIAL_SETTING_APP_QR_DECODE_H_
#define INITIAL_SETTING_APP_QR_DECODE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

// This code defines an enumeration type for the result of executing an API.
typedef enum {
    kDecodeQrSuccess,          // No errors.
    kDecodeQrParamError,       // Parameter Error.
    kDecodeQrOssInternalError, // Internal Error in OSS.
    kDecodeQrDetectCountError, // Detection Count Error.
    kDecodeQrNotDetectError,   // Undetectable error.
    kDecodeQrDecodeError,      // Decode Error.
    kDecodeQrOutputSizeOver,   // Payload size over.
    kDecodeQrOtherError        // Other Errors.
} IsaCodecQrError;

// The definition of the data type of the decoded result.
typedef enum {
    kDecodeQrOutputNumeric,      // Numerical value.
    kDecodeQrOutputAlphanumeric, // Alphanumeric.
    kDecodeQrOutputBinary,       // Binary.
    kDecodeQrOutputKanji         // Kanji.
} IsaCodecQrOutputType;

// The decoded result output destination information.
typedef struct {
    // The address of the beginning of the output destination for decoding
    // results.
    uint64_t output_adr_handle;

    // The maximum size of the decoded output result.
    int32_t output_max_size;
} IsaCodecQrOutputBuf;

// Input data information.
typedef struct {
    // The address of the first input data.
    uint64_t input_adr_handle;

    // The width of the image in pixels.
    int32_t width;

    // The height of the image in pixels.
    int32_t height;

    // The stride (in bytes) of the input image.
    int32_t stride;

    // Decoding result output destination information
    IsaCodecQrOutputBuf out_buf;
} IsaCodecQrInputParam;

// Decoded information from the QR code.
typedef struct {
    int32_t output_size;              // Decoded result payload size.
    IsaCodecQrOutputType output_type; // Output data type.
} IsaCodecQrOutputInfo;

// """Detect and decode QR codes from grayscale images.

// Detect and decode QR code from 8-bit grayscale image.
// Allocate output memory in the calling function and set the upper limit of the
// output size to IsaCodecQrOutputInfo. For non-grayscale images, convert them
// to grayscale using another module before calling this API.

// Args:
//     input (const IsaCodecQrInputParam *): Input grayscale image
//       information. NULL assignment not allowed.
//     output (IsaCodecQrOutputInfo *): Decoded result information. NULL
//       assignment not allowed.

// Returns:
//     IsaCodecQrError: The code returns one of the values IsaCodecQrError
//     depending on the execution result.

// Raises:
//     kDecodeQrParamError: When the argument is NULL, or an unsupported feature is
//       selected.
//     kDecodeQrOssInternalError: In the event of an error occurring within OSS.
//     kDecodeQrDetectCountError: When there are multiple QR codes inside an image.
//     kDecodeQrDecodeError: If QR code decoding is not possible.
//     kDecodeQrOutputSizeOver: After decoding, the size is exceeded.
//     kDecodeQrOtherError: Other Errors.

// Note:
// """
IsaCodecQrError IsaCodecQrDecodeQrCode(const IsaCodecQrInputParam *input,
                                       IsaCodecQrOutputInfo *output);

#ifdef __cplusplus
}
#endif

#endif // INITIAL_SETTING_APP_QR_DECODE_H_
