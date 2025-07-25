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

#include "initial_setting_app_qr_decode.h"

/*----------------------------------------------------------------------------*/
IsaCodecQrError __wrap_IsaCodecQrDecodeQrCode(const IsaCodecQrInputParam *input,
                                              IsaCodecQrOutputInfo *output)
{
    check_expected(input->input_adr_handle);
    check_expected(input->width);
    check_expected(input->height);
    check_expected(input->stride);
    check_expected(input->out_buf.output_adr_handle);
    check_expected(input->out_buf.output_max_size);

    output->output_size = mock_type(int32_t);
    output->output_type = mock_type(IsaCodecQrOutputType);
    return mock_type(IsaCodecQrError);
}

/*----------------------------------------------------------------------------*/
