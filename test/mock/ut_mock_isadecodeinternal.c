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
#include "quirc.h"
#include "initial_setting_app_qr_decode.h"

/*----------------------------------------------------------------------------*/
struct quirc *__wrap_IsaCodecQrCreateInstance(int32_t width, int32_t height)
{
    check_expected(width);
    check_expected(height);

    return mock_type(struct quirc *);
}

/*----------------------------------------------------------------------------*/
IsaCodecQrError __wrap_IsaCodecQrDetect(uint64_t image_addr, struct quirc_code *qr_code_info,
                                        struct quirc *instance)
{
    check_expected(image_addr);
    check_expected_ptr(instance);

    *qr_code_info = *(mock_type(struct quirc_code *));

    return mock_type(IsaCodecQrError);
}

/*----------------------------------------------------------------------------*/
IsaCodecQrError __wrap_IsaCodecQrDecodeQrCodeInfo(const struct quirc_code *qr_code_info,
                                                  struct quirc_data *qr_code_data)
{
    int i;

    for (i = 0; i < sizeof(qr_code_info->corners) / sizeof(struct quirc_point); i++) {
        check_expected(qr_code_info->corners[i].x);
        check_expected(qr_code_info->corners[i].y);
    }
    check_expected(qr_code_info->size);
    check_expected_ptr(qr_code_info->cell_bitmap);

    *qr_code_data = *(mock_type(struct quirc_data *));

    return mock_type(IsaCodecQrError);
}

/*----------------------------------------------------------------------------*/
IsaCodecQrError __wrap_IsaCodecQrStoreDecodingResult(const IsaCodecQrOutputBuf *output_buffer_info,
                                                     const struct quirc_data *qr_code_data,
                                                     IsaCodecQrOutputInfo *output_result_info)
{
    check_expected(output_buffer_info->output_adr_handle);
    check_expected(output_buffer_info->output_max_size);
    check_expected(qr_code_data->version);
    check_expected(qr_code_data->ecc_level);
    check_expected(qr_code_data->mask);
    check_expected(qr_code_data->data_type);
    check_expected_ptr(qr_code_data->payload);
    check_expected(qr_code_data->payload_len);
    check_expected(qr_code_data->eci);

    output_result_info->output_size = mock_type(int32_t);
    output_result_info->output_type = mock_type(IsaCodecQrOutputType);

    memcpy((uint8_t *)output_buffer_info->output_adr_handle, mock_type(uint8_t *),
           output_result_info->output_size);

    return mock_type(IsaCodecQrError);
}

/*----------------------------------------------------------------------------*/
void *__wrap_IsaLargeHeapAlloc(uint32_t pool_no, size_t request_size)
{
    check_expected(pool_no);
    check_expected(request_size);
    return mock_type(void *);
}

/*----------------------------------------------------------------------------*/
void __wrap_IsaLargeHeapFree(void *memory_address)
{
    check_expected_ptr(memory_address);
}
