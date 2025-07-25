/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

// Define the internal API for QR code.

#ifndef INITIAL_SETTING_APP_QR_DECODE_INTERNAL_H_
#define INITIAL_SETTING_APP_QR_DECODE_INTERNAL_H_

#include <stdint.h>
#include <stdlib.h>

#if defined(__NuttX__)
#include <nuttx/config.h>
#endif

#ifdef CONFIG_EXTERNAL_QUIRC
#include "quirc/lib/quirc.h"
#endif // CONFIG_EXTERNAL_QUIRC

#include "initial_setting_app_qr_decode.h"

void *IsaLargeHeapAlloc(uint32_t pool_no, size_t request_size);
void IsaLargeHeapFree(void *memory_address);

#ifdef CONFIG_EXTERNAL_QUIRC
// """Create an instance for QR code processing.

// The function will perform the following operations:
//   If either width or height is 0 or less, it will return NULL as an
//   abnormality.
//   Call quirc_new() to create an instance and return NULL if its return value
//   is NULL.
//   Input the instance, width, and height into quirc_resize(). If the return
//   value of quirc_resize() is negative, destroy the instance with
//   quirc_destroy() and return NULL as an abnormality.
//   Return the instance.
// It can be called concurrently.
// Multiple threads can call it.
// Multiple tasks can call it.
// The function does not block internally.

// Args:
//     width (int32_t): The width of the image in pixels.
//       Entering values less than or equal to zero is prohibited.

//     height (int32_t): The height of the image in pixels.
//       Entering values less than or equal to zero is prohibited.

// Returns:
//     struct quirc *: Instance pointer for QR code processing.
// """
struct quirc *IsaCodecQrCreateInstance(int32_t width, int32_t height);

// """Detect and return QR code information from input image.

// This function performs the following processes:
//   If instance or qr_code_info is NULL, or image_addr is 0, it returns NULL as
//   an abnormality. Call quirc_begin() to get the buffer and its size. Copy the
//   input image into the buffer. Call quirc_end() to detect QR codes. Call
//   quirc_count() to get the number of detected QR codes. If the detection
//   count is 0 or less, return kDecodeQrNotDetectError. If the detection count is 2
//   or more, return kDecodeQrDetectCountError. If the detection count is 1, call
//   quirc_extract() with index = 0 to get QR code information. Set QR code
//   information in qr_code_info and return kDecodeQrSuccess.
// It can be called concurrently.
// Multiple threads can call it.
// Multiple tasks can call it.
// The function does not block internally.

// Args:
//     image_addr (uint64_t): The address of the input image. Input of values
//       below zero is prohibited.
//     qr_code_info (struct quirc_code *): This is a
//       pointer to the QR code information.NULL assignment not allowed.
//     instance (struct quirc *): Instance pointer for QR code processing. NULL
//       assignment not allowed.

// Returns:
//     IsaCodecQrError: The code returns one of the values IsaCodecQrError
//     depending on the execution result.

// Raises:
//     kDecodeQrSuccess: On normal termination, it returns.
//     kDecodeQrDetectCountError: If multiple QR codes are detected, it returns.
//     kDecodeQrNotDetectError: If multiple QR codes are detected, return.
//     kDecodeQrParamError: If the argument's instance or qr_code_info is NULL, or
//       image_addr is 0, it returns.
// """
IsaCodecQrError IsaCodecQrDetect(uint64_t image_addr,
                                 struct quirc_code *qr_code_info,
                                 struct quirc *instance);

// """This function decodes QR code information and returns the decoded result.

// This function performs the following processes:
//   If qr_code_info or qrc_code_data is NULL, return kDecodeQrParamError as an
//   abnormality. Call quirc_decode() to get the decoding result. If the return
//   value of quirc_decode() is not zero, return kDecodeQrDecodeError, otherwise
//   return kDecodeQrSuccess.
// It can be called concurrently.
// Multiple threads can call it.
// Multiple tasks can call it.
// The function does not block internally.

// Args:
//     qr_code_info (const struct quirc_code *): This is a pointer to the QR
//       code information. NULL assignment not allowed.
//     qr_code_data (struct quirc_data *): The result pointer of QR code
//       decoding. NULL assignment not allowed.

// Returns:
//     IsaCodecQrError: The code returns one of the values IsaCodecQrError
//     depending on the execution result.

// Raises:
//     kDecodeQrSuccess: On normal termination, it returns.
//     kDecodeQrDecodeError: Return if the return value of quirc_decode() is not zero.
//     kDecodeQrParamError: If the argument qr_code_info or qr_code_data is NULL, it
//       returns.
// """
IsaCodecQrError IsaCodecQrDecodeQrCodeInfo(
    const struct quirc_code *qr_code_info, struct quirc_data *qr_code_data);

// """The decoded result is stored in the output buffer specified by the upper
// App.

// This function performs the following processes:
//   If output_buffer_info, qr_code_data, or output_result_info is NULL, or if
//   output_buffer_info->output_adr_handle is 0, return kDecodeQrParamError as an
//   abnormality. If output_buffer_info->output_max_size <
//   qr_code_data->payload_len, return kDecodeQrOutputSizeOver as an abnormality.
//   Store qr_code_data->data_type in output_result_info->output_type. Convert
//   qr_code_data->data_type QUIRC_DATA_TYPE_NUMERIC to kDecodeQrOutputNumeric,
//   QUIRC_DATA_TYPE_ALPHA to kDecodeQrOutputAlphanumeric, QUIRC_DATA_TYPE_BYTE to
//   kDecodeQrOutputBinary, and QUIRC_DATA_TYPE_KANJI to kDecodeQrOutputKanji. If none
//   apply, return kDecodeQrParamError as an abnormality. Copy qr_code_data->payload
//   to output_buffer_info->output_adr_handle in byte for
//   qr_code_data->payload_len. Store qr_code_data->payload_len in
//   output_result_info->output_size. Return kDecodeQrSuccess.
// It can be called concurrently.
// Multiple threads can call it.
// Multiple tasks can call it.
// The function does not block internally.

// Args:
//     output_buffer_info (const IsaCodecQrOutputBuf *): This is a pointer to
//       the buffer information for the output of the QR code decoding result.
//       NULL assignment not allowed.
//     qr_code_data (struct quirc_data *): The result pointer of QR code
//       decoding. NULL assignment not allowed.
//     output_result_info (IsaCodecQrOutputInfo *): This is a pointer to the
//       information of the result of QR code decoding. NULL assignment not
//       allowed.

// Returns:
//     IsaCodecQrError: The code returns one of the values IsaCodecQrError
//     depending on the execution result.

// Raises:
//     kDecodeQrSuccess: On normal termination, it returns.
//     kDecodeQrOutputSizeOver: If the decoded result does not fit in the output
//       buffer (output_buffer_info->output_max_size <
//       qr_code_data->payload_len), it returns.
//     kDecodeQrParamError: If the argument's output_buffer_info, qr_code_data, or
//       output_result_info is NULL, it returns. If the argument's
//       output_buffer_info->output_adr_handle is 0, it returns. If the
//       argument's qr_code_data->data_type is undefined, it returns.
// """
IsaCodecQrError IsaCodecQrStoreDecodingResult(
    const IsaCodecQrOutputBuf *output_buffer_info,
    const struct quirc_data *qr_code_data,
    IsaCodecQrOutputInfo *output_result_info);
#endif // CONFIG_EXTERNAL_QUIRC

#endif  // INITIAL_SETTING_APP_QR_DECODE_INTERNAL_H_
