/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#ifndef WAMR_APP_NATIVE_EXPORT_ESF_CODEC_JPEG_JPEG_EXPORT_API_H_
#define WAMR_APP_NATIVE_EXPORT_ESF_CODEC_JPEG_JPEG_EXPORT_API_H_

#include "wasm_export.h"
#include "jpeg.h"

EsfCodecJpegError EsfCodecJpegEncode_wasm(wasm_exec_env_t exec_env,
                                          uint32_t enc_param_offset,
                                          uint32_t jpeg_size_offset);
#endif  // WAMR_APP_NATIVE_EXPORT_ESF_CODEC_JPEG_JPEG_EXPORT_API_H_
