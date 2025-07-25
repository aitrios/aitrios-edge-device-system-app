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

#include "jpeg.h"

/*----------------------------------------------------------------------------*/
EsfCodecJpegError __wrap_EsfCodecJpegEncode(const EsfCodecJpegEncParam *enc_param,
                                            int32_t *jpeg_size)
{
    check_expected(enc_param->input_adr_handle);
    check_expected(enc_param->out_buf.output_adr_handle);
    check_expected(enc_param->out_buf.output_buf_size);
    check_expected(enc_param->input_fmt);
    check_expected(enc_param->width);
    check_expected(enc_param->height);
    check_expected(enc_param->stride);
    check_expected(enc_param->quality);
    *jpeg_size = mock_type(int32_t);
    return mock_type(EsfCodecJpegError);
}

/*----------------------------------------------------------------------------*/
EsfCodecJpegError __wrap_EsfCodecJpegEncodeFileIo(EsfMemoryManagerHandle input_file_handle,
                                                  EsfMemoryManagerHandle output_file_handle,
                                                  const EsfCodecJpegInfo *info, int32_t *jpeg_size)
{
    check_expected(input_file_handle);
    check_expected(output_file_handle);
    check_expected(info->input_fmt);
    check_expected(info->width);
    check_expected(info->height);
    check_expected(info->stride);
    check_expected(info->quality);
    *jpeg_size = mock_type(int32_t);
    return mock_type(EsfCodecJpegError);
}

/*----------------------------------------------------------------------------*/
EsfCodecJpegError __wrap_EsfCodecJpegEncodeHandle(EsfMemoryManagerHandle input_file_handle,
                                                  EsfMemoryManagerHandle output_file_handle,
                                                  const EsfCodecJpegInfo *info, int32_t *jpeg_size)
{
    check_expected(input_file_handle);
    check_expected(output_file_handle);
    check_expected(info->input_fmt);
    check_expected(info->width);
    check_expected(info->height);
    check_expected(info->stride);
    check_expected(info->quality);
    *jpeg_size = mock_type(int32_t);
    return mock_type(EsfCodecJpegError);
}

/*----------------------------------------------------------------------------*/
