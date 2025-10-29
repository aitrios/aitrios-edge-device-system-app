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

#include "initial_setting_app_qrcode.h"

/*----------------------------------------------------------------------------*/
IsaQrcodeErrorCode __wrap_IsaQrcodeInit(void)
{
    return mock_type(IsaQrcodeErrorCode);
}

/*----------------------------------------------------------------------------*/
IsaQrcodeErrorCode __wrap_IsaQrcodeDecodePayload(uint8_t *payload, int32_t payload_size,
                                                 IsaQrcodeDecodeResult *result, uint8_t *qr_count)
{
    check_expected_ptr(payload);
    check_expected(payload_size);
    *result = mock_type(IsaQrcodeDecodeResult);
    *qr_count = mock_type(uint8_t);
    return mock_type(IsaQrcodeErrorCode);
}

/*----------------------------------------------------------------------------*/
IsaQrcodeErrorCode __wrap_IsaWriteQrcodePayloadToFlash(void)
{
    return mock_type(IsaQrcodeErrorCode);
}

/*----------------------------------------------------------------------------*/
void __wrap_IsaClearMultiQRParam(void)
{
    return;
}

/*----------------------------------------------------------------------------*/
IsaQrcodeErrorCode __wrap_IsaQrcodeExit(void)
{
    return mock_type(IsaQrcodeErrorCode);
}

/*----------------------------------------------------------------------------*/
