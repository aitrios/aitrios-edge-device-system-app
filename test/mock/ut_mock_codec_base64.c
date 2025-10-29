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

#include <string.h>
#include "base64/include/base64.h"
#include "base64/include/base64_fileio.h"

/*----------------------------------------------------------------------------*/
EsfCodecBase64ResultEnum __wrap_EsfCodecBase64Encode(const uint8_t *in, size_t in_size, char *out,
                                                     size_t *out_size)
{
    char *out_tmp = mock_type(char *);

    check_expected(in);
    check_expected(in_size);
    memcpy(out, out_tmp, strlen(out_tmp) + 1);
    *out_size = mock_type(size_t);

    return mock_type(EsfCodecBase64ResultEnum);
}

/*----------------------------------------------------------------------------*/
EsfCodecBase64ResultEnum __wrap_EsfCodecBase64Decode(const char *in, size_t in_size, uint8_t *out,
                                                     size_t *out_size)
{
    check_expected_ptr(in);
    check_expected(in_size);

    if (mock_type(bool) == true) {
        const uint8_t *ret_out = mock_type(const uint8_t *);
        size_t ret_out_size = mock_type(size_t);
        memcpy(out, ret_out, ret_out_size);
        *out_size = ret_out_size;
    }

    return mock_type(EsfCodecBase64ResultEnum);
}

/*----------------------------------------------------------------------------*/
size_t __wrap_EsfCodecBase64GetEncodeSize(size_t in_size)
{
    check_expected(in_size);
    return mock_type(size_t);
}

/*----------------------------------------------------------------------------*/
size_t __wrap_EsfCodecBase64GetDecodeSize(size_t in_size)
{
    check_expected(in_size);
    return mock_type(size_t);
}

/*----------------------------------------------------------------------------*/
EsfCodecBase64ResultEnum __wrap_EsfCodecBase64EncodeHandle(EsfMemoryManagerHandle in_handle,
                                                           size_t in_size,
                                                           EsfMemoryManagerHandle out_handle,
                                                           size_t *out_size)
{
    check_expected(in_handle);
    check_expected(in_size);
    check_expected(out_handle);
    *out_size = mock_type(size_t);
    return mock_type(EsfCodecBase64ResultEnum);
}
