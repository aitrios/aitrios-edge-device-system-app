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

#include <stdlib.h>
#include <string.h>
#if defined(__NuttX__)
#include <nuttx/config.h>
#endif
#include "quirc/lib/quirc.h"
#include "zxing-cpp/src/wrappers/c/zxing-c.h"
#include "initial_setting_app_qr_decode.h"

/*----------------------------------------------------------------------------*/

//
// Common
//

/*----------------------------------------------------------------------------*/
static void SetInputParam(IsaCodecQrInputParam* input, uint8_t** input_image, uint8_t** output_buf)
{
    input->width = 640;
    input->height = 480;
    input->stride = input->width + 16;

    *input_image = malloc(input->width * input->stride);
    if (*input_image == NULL) {
        assert_non_null(*input_image);
        goto exit;
    }
    input->input_adr_handle = (uint64_t)*input_image;

    input->out_buf.output_max_size = input->width * input->height;

    *output_buf = malloc(input->out_buf.output_max_size);
    if (*output_buf == NULL) {
        assert_non_null(*output_buf);
        goto exit;
    }
    memset(*output_buf, 0xFF, input->out_buf.output_max_size);
    input->out_buf.output_adr_handle = (uint64_t)*output_buf;

exit:
    return;
}

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_EXTERNAL_QUIRC
static void CreateQuircCode(struct quirc_code* code)
{
    int i;

    code->corners[0].x = 0x12;
    code->corners[0].y = 0x34;
    code->corners[1].x = 0x56;
    code->corners[1].y = 0x78;
    code->corners[2].x = 0x90;
    code->corners[2].y = 0x21;
    code->corners[3].x = 0x43;
    code->corners[3].y = 0x65;

    code->size = 0x87;

    for (i = 0; i < sizeof(code->cell_bitmap); i++) {
        code->cell_bitmap[i] = i % 128;
    }

    return;
}
#endif // CONFIG_EXTERNAL_QUIRC

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_EXTERNAL_QUIRC
static void CreateQuircData(struct quirc_data* data, int payload_len)
{
    int i, j;

    data->version = 0x13;
    data->ecc_level = 0x57;
    data->mask = 0x24;
    data->data_type = QUIRC_DATA_TYPE_BYTE;

    for (i = (sizeof(data->payload) - 1), j = 0; i <= 0; i--, j++) {
        data->payload[i] = j % 128;
    }

    data->payload_len = payload_len;
    data->eci = 0x76;

    return;
}
#endif // CONFIG_EXTERNAL_QUIRC

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_EXTERNAL_QUIRC
static void CreateExpectOutputData(uint8_t* data, int payload_len)
{
    int i;

    for (i = 0; i < payload_len; i++) {
        data[i] = (i * 2) % 128;
    }

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_EXTERNAL_QUIRC
static void CheckCalloc(size_t __nmemb, size_t __size)
{
    will_return(mock_calloc, true); // Check parameter
    will_return(mock_calloc, true); // Return allocated address

    expect_value(mock_calloc, __nmemb, __nmemb);
    expect_value(mock_calloc, __size, __size);

    return;
}
#endif

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_EXTERNAL_QUIRC
static void ForIsaCodecQrCreateInstance(struct quirc* quirc_instance, IsaCodecQrInputParam* input)
{
    will_return(__wrap_IsaCodecQrCreateInstance, quirc_instance);

    expect_value(__wrap_IsaCodecQrCreateInstance, width, input->width);
    expect_value(__wrap_IsaCodecQrCreateInstance, height, input->height);

    return;
}
#endif // CONFIG_EXTERNAL_QUIRC

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_EXTERNAL_QUIRC
static void ForIsaCodecQrDetect(struct quirc_code* qr_code_info, IsaCodecQrError result,
                                uint64_t image_addr, struct quirc* quirc_instance)
{
    will_return(__wrap_IsaCodecQrDetect, qr_code_info);
    will_return(__wrap_IsaCodecQrDetect, result);

    expect_value(__wrap_IsaCodecQrDetect, image_addr, image_addr);
    expect_value(__wrap_IsaCodecQrDetect, instance, quirc_instance);

    return;
}
#endif // CONFIG_EXTERNAL_QUIRC

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_EXTERNAL_QUIRC
static void ForIsaCodecQrDecodeQrCodeInfo(struct quirc_data* qr_code_data, IsaCodecQrError result,
                                          struct quirc_code* qr_code_info)
{
    int i;

    will_return(__wrap_IsaCodecQrDecodeQrCodeInfo, qr_code_data);
    will_return(__wrap_IsaCodecQrDecodeQrCodeInfo, result);

    for (i = 0; i < sizeof(qr_code_info->corners) / sizeof(struct quirc_point); i++) {
        expect_value(__wrap_IsaCodecQrDecodeQrCodeInfo, qr_code_info->corners[i].x,
                     qr_code_info->corners[i].x);
        expect_value(__wrap_IsaCodecQrDecodeQrCodeInfo, qr_code_info->corners[i].y,
                     qr_code_info->corners[i].y);
    }
    expect_value(__wrap_IsaCodecQrDecodeQrCodeInfo, qr_code_info->size, qr_code_info->size);
    expect_memory(__wrap_IsaCodecQrDecodeQrCodeInfo, qr_code_info->cell_bitmap,
                  qr_code_info->cell_bitmap, sizeof(qr_code_info->cell_bitmap));

    return;
}
#endif // CONFIG_EXTERNAL_QUIRC

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_EXTERNAL_QUIRC
static void ForIsaCodecQrStoreDecodingResult(int payload_len, IsaCodecQrOutputType data_type,
                                             uint8_t* output_data, IsaCodecQrError result,
                                             IsaCodecQrInputParam* input,
                                             struct quirc_data* qr_code_data)
{
    will_return(__wrap_IsaCodecQrStoreDecodingResult, payload_len);
    will_return(__wrap_IsaCodecQrStoreDecodingResult, data_type);
    will_return(__wrap_IsaCodecQrStoreDecodingResult, output_data);
    will_return(__wrap_IsaCodecQrStoreDecodingResult, result);

    expect_value(__wrap_IsaCodecQrStoreDecodingResult, output_buffer_info->output_adr_handle,
                 input->out_buf.output_adr_handle);
    expect_value(__wrap_IsaCodecQrStoreDecodingResult, output_buffer_info->output_max_size,
                 input->out_buf.output_max_size);
    expect_value(__wrap_IsaCodecQrStoreDecodingResult, qr_code_data->version,
                 qr_code_data->version);
    expect_value(__wrap_IsaCodecQrStoreDecodingResult, qr_code_data->ecc_level,
                 qr_code_data->ecc_level);
    expect_value(__wrap_IsaCodecQrStoreDecodingResult, qr_code_data->mask, qr_code_data->mask);
    expect_value(__wrap_IsaCodecQrStoreDecodingResult, qr_code_data->data_type,
                 qr_code_data->data_type);
    expect_memory(__wrap_IsaCodecQrStoreDecodingResult, qr_code_data->payload,
                  qr_code_data->payload, payload_len);
    expect_value(__wrap_IsaCodecQrStoreDecodingResult, qr_code_data->payload_len,
                 qr_code_data->payload_len);
    expect_value(__wrap_IsaCodecQrStoreDecodingResult, qr_code_data->eci, qr_code_data->eci);

    return;
}
#endif // CONFIG_EXTERNAL_QUIRC

/*----------------------------------------------------------------------------*/

//
// IsaCodecQrDecodeQrCode()
//

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDecodeQrCode_FullySuccess(void** state)
{
    IsaCodecQrError ret;
    IsaCodecQrInputParam input;
    IsaCodecQrOutputInfo output;
    uint8_t* input_image = NULL;
    uint8_t* output_data = NULL;

#ifdef CONFIG_ZXING_CPP_PORTING

    zxing_ImageView zx_iv;
    zxing_DecodeHints zx_hints;
    zxing_Result zx_result;
    uint8_t* zx_bytes = malloc(11);
    uint8_t* zx_result_text = malloc(11);

    // Set test target argument
    SetInputParam(&input, &input_image, &output_data);

    // For zxing_ImageView_new()
    will_return(__wrap_zxing_ImageView_new, &zx_iv);

    // For zxing_DecodeHints_new()
    will_return(__wrap_zxing_DecodeHints_new, &zx_hints);

    // For zxing_ReadBarcode()
    will_return(__wrap_zxing_ReadBarcode, &zx_result);

    // For zxing_Result_isValid()
    will_return(__wrap_zxing_Result_isValid, true);

    // For zxing_Result_bytes()
    will_return(__wrap_zxing_Result_bytes, 10);
    will_return(__wrap_zxing_Result_bytes, zx_bytes);

    // For free()
    will_return(mock_free, false); // Not check parameter

    // For zxing_Result_text()
    will_return(__wrap_zxing_Result_text, zx_result_text);
    will_return(mock_free, false); // Not check parameter

    // For zxing_Result_orientation()
    will_return(__wrap_zxing_Result_orientation, 0);

    // For zxing_Result_isInverted()
    will_return(__wrap_zxing_Result_isInverted, false);

    // For zxing_Result_isMirrored()
    will_return(__wrap_zxing_Result_isMirrored, false);

    // For zxing_Result_delete()
    //will_return(__wrap_zxing_Result_delete, 0);

    // For zxing_DecodeHints_delete();
    //will_return(__wrap_zxing_DecodeHints_delete, 0);

    // For zxing_ImageView_delete()
    //will_return(__wrap_zxing_ImageView_delete, 0);

    // Exec test target
    ret = IsaCodecQrDecodeQrCode((const IsaCodecQrInputParam*)&input, &output);

    // Check return value
    assert_int_equal(ret, kDecodeQrSuccess);

#endif // CONFIG_ZXING_CPP_PORTING

#ifdef CONFIG_EXTERNAL_QUIRC

    uint8_t* output_init_data = NULL;
    uint8_t* output_expect_data = NULL;
    int32_t quirc_instance;
    struct quirc_code* qr_code_info = NULL;
    struct quirc_data* qr_code_data = NULL;
    int payload_len;
    IsaCodecQrOutputType data_type = kDecodeQrOutputBinary;

    // Set test target argument
    SetInputParam(&input, &input_image, &output_data);
    if ((input_image == NULL) || (output_data == NULL)) {
        goto exit;
    }

    output_init_data = malloc(input.out_buf.output_max_size);
    if (output_init_data == NULL) {
        assert_non_null(output_init_data);
        goto exit;
    }
    memcpy(output_init_data, output_data, input.out_buf.output_max_size);

    // For IsaCodecQrCreateInstance()
    ForIsaCodecQrCreateInstance((struct quirc*)&quirc_instance, &input);

    // For calloc() of struct quirc_code
    CheckCalloc(1, sizeof(struct quirc_code));

    // For IsaCodecQrDetect()
    qr_code_info = malloc(sizeof(struct quirc_code));
    if (qr_code_info == NULL) {
        assert_non_null(qr_code_info);
        goto exit;
    }
    CreateQuircCode(qr_code_info);
    ForIsaCodecQrDetect(qr_code_info, kDecodeQrSuccess, input.input_adr_handle,
                        (struct quirc*)&quirc_instance);

    // For quirc_destroy()
    expect_value(__wrap_quirc_destroy, q, (struct quirc*)&quirc_instance);

    // For calloc() of struct quirc_data
    CheckCalloc(1, sizeof(struct quirc_data));

    // For IsaCodecQrDecodeQrCodeInfo()
    qr_code_data = malloc(sizeof(struct quirc_data));
    if (qr_code_data == NULL) {
        assert_non_null(qr_code_data);
        goto exit;
    }
    payload_len = sizeof(qr_code_data->payload) - 5;
    CreateQuircData(qr_code_data, payload_len);
    ForIsaCodecQrDecodeQrCodeInfo(qr_code_data, kDecodeQrSuccess, qr_code_info);

    // For free() of struct quirc_code
    will_return(mock_free, false); // Not check parameter

    // For IsaCodecQrStoreDecodingResult()
    output_expect_data = malloc(payload_len);
    if (output_expect_data == NULL) {
        assert_non_null(output_expect_data);
        goto exit;
    }
    CreateExpectOutputData(output_expect_data, payload_len);
    ForIsaCodecQrStoreDecodingResult(payload_len, data_type, output_expect_data, kDecodeQrSuccess,
                                     &input, qr_code_data);

    // For free() of struct quirc_data
    will_return(mock_free, false); // Not check parameter

    // Exec test target
    ret = IsaCodecQrDecodeQrCode((const IsaCodecQrInputParam*)&input, &output);

    // Check return and output value
    assert_int_equal(ret, kDecodeQrSuccess);
    assert_int_equal(output.output_size, payload_len);
    assert_int_equal(output.output_type, data_type);
    assert_memory_equal((uint8_t*)input.out_buf.output_adr_handle, output_expect_data,
                        output.output_size);
    assert_memory_equal((uint8_t*)input.out_buf.output_adr_handle + output.output_size,
                        output_init_data, input.out_buf.output_max_size - output.output_size);

exit:
    if (output_expect_data != NULL) {
        free(output_expect_data);
    }

    if (qr_code_data != NULL) {
        free(qr_code_data);
    }

    if (qr_code_info != NULL) {
        free(qr_code_info);
    }

    if (output_init_data != NULL) {
        free(output_init_data);
    }

    if (output_data != NULL) {
        free(output_data);
    }

    if (input_image != NULL) {
        free(input_image);
    }

#endif // CONFIG_EXTERNAL_QUIRC

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDecodeQrCode_InputNull(void** state)
{
    IsaCodecQrError ret;
    IsaCodecQrOutputInfo output;

    // Exec test target
    ret = IsaCodecQrDecodeQrCode(NULL, &output);

    // Check return value
    assert_int_equal(ret, kDecodeQrParamError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDecodeQrCode_OutputNull(void** state)
{
    IsaCodecQrError ret;
    IsaCodecQrInputParam input;
    uint8_t* input_image = NULL;
    uint8_t* output_data = NULL;

    // Set test target argument
    SetInputParam(&input, &input_image, &output_data);
    if ((input_image == NULL) || (output_data == NULL)) {
        goto exit;
    }

    // Exec test target
    ret = IsaCodecQrDecodeQrCode((const IsaCodecQrInputParam*)&input, NULL);

    // Check return value
    assert_int_equal(ret, kDecodeQrParamError);

exit:
    if (output_data != NULL) {
        free(output_data);
    }

    if (input_image != NULL) {
        free(input_image);
    }

    return;
}

#ifdef CONFIG_ZXING_CPP_PORTING
/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDecodeQrCode_Error_zxing_ImageView_new(void** state)
{
    IsaCodecQrError ret;
    IsaCodecQrInputParam input;
    IsaCodecQrOutputInfo output;
    uint8_t* input_image = NULL;
    uint8_t* output_data = NULL;

    // Set test target argument
    SetInputParam(&input, &input_image, &output_data);

    // For zxing_ImageView_new()
    will_return(__wrap_zxing_ImageView_new, NULL);

    // Exec test target
    ret = IsaCodecQrDecodeQrCode((const IsaCodecQrInputParam*)&input, &output);

    // Check return value
    assert_int_equal(ret, kDecodeQrOssInternalError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDecodeQrCode_Error_zxing_DecodeHints_new(void** state)
{
    IsaCodecQrError ret;
    IsaCodecQrInputParam input;
    IsaCodecQrOutputInfo output;
    uint8_t* input_image = NULL;
    uint8_t* output_data = NULL;
    zxing_ImageView zx_iv;

    // Set test target argument
    SetInputParam(&input, &input_image, &output_data);

    // For zxing_ImageView_new()
    will_return(__wrap_zxing_ImageView_new, &zx_iv);

    // For zxing_DecodeHints_new()
    will_return(__wrap_zxing_DecodeHints_new, NULL);

    // For zxing_ImageView_delete()
    //will_return(__wrap_zxing_ImageView_delete, 0);

    // Exec test target
    ret = IsaCodecQrDecodeQrCode((const IsaCodecQrInputParam*)&input, &output);

    // Check return value
    assert_int_equal(ret, kDecodeQrOssInternalError);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDecodeQrCode_NotDetect_zxing_ReadBarcode(void** state)
{
    IsaCodecQrError ret;
    IsaCodecQrInputParam input;
    IsaCodecQrOutputInfo output;
    uint8_t* input_image = NULL;
    uint8_t* output_data = NULL;
    zxing_ImageView zx_iv;
    zxing_DecodeHints zx_hints;

    // Set test target argument
    SetInputParam(&input, &input_image, &output_data);

    // For zxing_ImageView_new()
    will_return(__wrap_zxing_ImageView_new, &zx_iv);

    // For zxing_DecodeHints_new()
    will_return(__wrap_zxing_DecodeHints_new, &zx_hints);

    // For zxing_ReadBarcode()
    will_return(__wrap_zxing_ReadBarcode, NULL);

    // For zxing_DecodeHints_delete();
    //will_return(__wrap_zxing_DecodeHints_delete, 0);

    // For zxing_ImageView_delete()
    //will_return(__wrap_zxing_ImageView_delete, 0);

    // Exec test target
    ret = IsaCodecQrDecodeQrCode((const IsaCodecQrInputParam*)&input, &output);

    // Check return value
    assert_int_equal(ret, kDecodeQrSuccess);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDecodeQrCode_Error_InvalidQRCode(void** state)
{
    IsaCodecQrError ret;
    IsaCodecQrInputParam input;
    IsaCodecQrOutputInfo output;
    uint8_t* input_image = NULL;
    uint8_t* output_data = NULL;
    zxing_ImageView zx_iv;
    zxing_DecodeHints zx_hints;
    zxing_Result zx_result;

    // Set test target argument
    SetInputParam(&input, &input_image, &output_data);

    // For zxing_ImageView_new()
    will_return(__wrap_zxing_ImageView_new, &zx_iv);

    // For zxing_DecodeHints_new()
    will_return(__wrap_zxing_DecodeHints_new, &zx_hints);

    // For zxing_ReadBarcode()
    will_return(__wrap_zxing_ReadBarcode, &zx_result);

    // For zxing_Result_isValid()
    will_return(__wrap_zxing_Result_isValid, false);

    // For zxing_Result_orientation()
    will_return(__wrap_zxing_Result_orientation, 0);

    // For zxing_Result_isInverted()
    will_return(__wrap_zxing_Result_isInverted, false);

    // For zxing_Result_isMirrored()
    will_return(__wrap_zxing_Result_isMirrored, false);

    // For zxing_Result_delete()
    //will_return(__wrap_zxing_Result_delete, 0);

    // For zxing_DecodeHints_delete();
    //will_return(__wrap_zxing_DecodeHints_delete, 0);

    // For zxing_ImageView_delete()
    //will_return(__wrap_zxing_ImageView_delete, 0);

    // Exec test target
    ret = IsaCodecQrDecodeQrCode((const IsaCodecQrInputParam*)&input, &output);

    // Check return value
    assert_int_equal(ret, kDecodeQrSuccess);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDecodeQrCode_Error_PayloadSizeOver(void** state)
{
    IsaCodecQrError ret;
    IsaCodecQrInputParam input;
    IsaCodecQrOutputInfo output;
    uint8_t* input_image = NULL;
    uint8_t* output_data = NULL;
    zxing_ImageView zx_iv;
    zxing_DecodeHints zx_hints;
    zxing_Result zx_result;
    uint8_t* zx_bytes = malloc(11);

    // Set test target argument
    SetInputParam(&input, &input_image, &output_data);

    // For zxing_ImageView_new()
    will_return(__wrap_zxing_ImageView_new, &zx_iv);

    // For zxing_DecodeHints_new()
    will_return(__wrap_zxing_DecodeHints_new, &zx_hints);

    // For zxing_ReadBarcode()
    will_return(__wrap_zxing_ReadBarcode, &zx_result);

    // For zxing_Result_isValid()
    will_return(__wrap_zxing_Result_isValid, true);

    // For zxing_Result_bytes()
    will_return(__wrap_zxing_Result_bytes, 0x7fffffff);
    will_return(__wrap_zxing_Result_bytes, zx_bytes);

    // For free()
    will_return(mock_free, false); // Not check parameter

    // For zxing_DecodeHints_delete();
    //will_return(__wrap_zxing_DecodeHints_delete, 0);

    // For zxing_ImageView_delete()
    //will_return(__wrap_zxing_ImageView_delete, 0);

    // Exec test target
    ret = IsaCodecQrDecodeQrCode((const IsaCodecQrInputParam*)&input, &output);

    // Check return value
    assert_int_equal(ret, kDecodeQrOutputSizeOver);
}
#endif // CONFIG_ZXING_CPP_PORTING

#ifdef CONFIG_EXTERNAL_QUIRC
/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDecodeQrCode_ErrorIsaCodecQrCreateInstance(void** state)
{
    IsaCodecQrError ret;
    IsaCodecQrInputParam input;
    IsaCodecQrOutputInfo output;
    uint8_t* input_image = NULL;
    uint8_t* output_data = NULL;

    // Set test target argument
    SetInputParam(&input, &input_image, &output_data);
    if ((input_image == NULL) || (output_data == NULL)) {
        goto exit;
    }

    // For IsaCodecQrCreateInstance()
    ForIsaCodecQrCreateInstance(NULL, &input);

    // Exec test target
    ret = IsaCodecQrDecodeQrCode((const IsaCodecQrInputParam*)&input, &output);

    // Check return value
    assert_int_equal(ret, kDecodeQrOssInternalError);

exit:
    if (output_data != NULL) {
        free(output_data);
    }

    if (input_image != NULL) {
        free(input_image);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDecodeQrCode_ErrorCalloc1st(void** state)
{
    IsaCodecQrError ret;
    IsaCodecQrInputParam input;
    IsaCodecQrOutputInfo output;
    uint8_t* input_image = NULL;
    uint8_t* output_data = NULL;
    int32_t quirc_instance;

    // Set test target argument
    SetInputParam(&input, &input_image, &output_data);
    if ((input_image == NULL) || (output_data == NULL)) {
        goto exit;
    }

    // For IsaCodecQrCreateInstance()
    ForIsaCodecQrCreateInstance((struct quirc*)&quirc_instance, &input);

    // For calloc() of struct quirc_code
    will_return(mock_calloc, true);  // Check parameter
    will_return(mock_calloc, false); // Return NULL

    expect_value(mock_calloc, __nmemb, 1);
    expect_value(mock_calloc, __size, sizeof(struct quirc_code));

    // For quirc_destroy()
    expect_value(__wrap_quirc_destroy, q, (struct quirc*)&quirc_instance);

    // Exec test target
    ret = IsaCodecQrDecodeQrCode((const IsaCodecQrInputParam*)&input, &output);

    // Check return value
    assert_int_equal(ret, kDecodeQrOtherError);

exit:
    if (output_data != NULL) {
        free(output_data);
    }

    if (input_image != NULL) {
        free(input_image);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDecodeQrCode_ErrorIsaCodecQrDetect(void** state)
{
    IsaCodecQrError ret;
    IsaCodecQrInputParam input;
    IsaCodecQrOutputInfo output;
    uint8_t* input_image = NULL;
    uint8_t* output_data = NULL;
    int32_t quirc_instance;
    struct quirc_code* qr_code_info = NULL;

    // Set test target argument
    SetInputParam(&input, &input_image, &output_data);
    if ((input_image == NULL) || (output_data == NULL)) {
        goto exit;
    }

    // For IsaCodecQrCreateInstance()
    ForIsaCodecQrCreateInstance((struct quirc*)&quirc_instance, &input);

    // For calloc() of struct quirc_code
    CheckCalloc(1, sizeof(struct quirc_code));

    // For IsaCodecQrDetect()
    qr_code_info = malloc(sizeof(struct quirc_code));
    if (qr_code_info == NULL) {
        assert_non_null(qr_code_info);
        goto exit;
    }
    CreateQuircCode(qr_code_info);
    ForIsaCodecQrDetect(qr_code_info, kDecodeQrDecodeError, input.input_adr_handle,
                        (struct quirc*)&quirc_instance);

    // For quirc_destroy()
    expect_value(__wrap_quirc_destroy, q, (struct quirc*)&quirc_instance);

    // For free() of struct quirc_code
    will_return(mock_free, false); // Not check parameter

    // Exec test target
    ret = IsaCodecQrDecodeQrCode((const IsaCodecQrInputParam*)&input, &output);

    // Check return value
    assert_int_equal(ret, kDecodeQrDecodeError);

exit:
    if (qr_code_info != NULL) {
        free(qr_code_info);
    }

    if (output_data != NULL) {
        free(output_data);
    }

    if (input_image != NULL) {
        free(input_image);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDecodeQrCode_ErrorCalloc2nd(void** state)
{
    IsaCodecQrError ret;
    IsaCodecQrInputParam input;
    IsaCodecQrOutputInfo output;
    uint8_t* input_image = NULL;
    uint8_t* output_data = NULL;
    int32_t quirc_instance;
    struct quirc_code* qr_code_info = NULL;

    // Set test target argument
    SetInputParam(&input, &input_image, &output_data);
    if ((input_image == NULL) || (output_data == NULL)) {
        goto exit;
    }

    // For IsaCodecQrCreateInstance()
    ForIsaCodecQrCreateInstance((struct quirc*)&quirc_instance, &input);

    // For calloc() of struct quirc_code
    CheckCalloc(1, sizeof(struct quirc_code));

    // For IsaCodecQrDetect()
    qr_code_info = malloc(sizeof(struct quirc_code));
    if (qr_code_info == NULL) {
        assert_non_null(qr_code_info);
        goto exit;
    }
    CreateQuircCode(qr_code_info);
    ForIsaCodecQrDetect(qr_code_info, kDecodeQrSuccess, input.input_adr_handle,
                        (struct quirc*)&quirc_instance);

    // For quirc_destroy()
    expect_value(__wrap_quirc_destroy, q, (struct quirc*)&quirc_instance);

    // For calloc() of struct quirc_code
    will_return(mock_calloc, true);  // Check parameter
    will_return(mock_calloc, false); // Return NULL

    expect_value(mock_calloc, __nmemb, 1);
    expect_value(mock_calloc, __size, sizeof(struct quirc_data));

    // For free() of struct quirc_code
    will_return(mock_free, false); // Not check parameter

    // Exec test target
    ret = IsaCodecQrDecodeQrCode((const IsaCodecQrInputParam*)&input, &output);

    // Check return value
    assert_int_equal(ret, kDecodeQrOtherError);

exit:
    if (qr_code_info != NULL) {
        free(qr_code_info);
    }

    if (output_data != NULL) {
        free(output_data);
    }

    if (input_image != NULL) {
        free(input_image);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDecodeQrCode_ErrorIsaCodecQrDecodeQrCodeInfo(void** state)
{
    IsaCodecQrError ret;
    IsaCodecQrInputParam input;
    IsaCodecQrOutputInfo output;
    uint8_t* input_image = NULL;
    uint8_t* output_data = NULL;
    int32_t quirc_instance;
    struct quirc_code* qr_code_info = NULL;
    struct quirc_data* qr_code_data = NULL;
    int payload_len;

    // Set test target argument
    SetInputParam(&input, &input_image, &output_data);
    if ((input_image == NULL) || (output_data == NULL)) {
        goto exit;
    }

    // For IsaCodecQrCreateInstance()
    ForIsaCodecQrCreateInstance((struct quirc*)&quirc_instance, &input);

    // For calloc() of struct quirc_code
    CheckCalloc(1, sizeof(struct quirc_code));

    // For IsaCodecQrDetect()
    qr_code_info = malloc(sizeof(struct quirc_code));
    if (qr_code_info == NULL) {
        assert_non_null(qr_code_info);
        goto exit;
    }
    CreateQuircCode(qr_code_info);
    ForIsaCodecQrDetect(qr_code_info, kDecodeQrSuccess, input.input_adr_handle,
                        (struct quirc*)&quirc_instance);

    // For quirc_destroy()
    expect_value(__wrap_quirc_destroy, q, (struct quirc*)&quirc_instance);

    // For calloc() of struct quirc_code
    CheckCalloc(1, sizeof(struct quirc_data));

    // For IsaCodecQrDecodeQrCodeInfo()
    qr_code_data = malloc(sizeof(struct quirc_data));
    if (qr_code_data == NULL) {
        assert_non_null(qr_code_data);
        goto exit;
    }
    payload_len = sizeof(qr_code_data->payload) - 5;
    CreateQuircData(qr_code_data, payload_len);
    ForIsaCodecQrDecodeQrCodeInfo(qr_code_data, kDecodeQrDecodeError, qr_code_info);

    // For free() of struct quirc_code
    will_return(mock_free, false); // Not check parameter

    // For free() of struct quirc_data
    will_return(mock_free, false); // Not check parameter

    // Exec test target
    ret = IsaCodecQrDecodeQrCode((const IsaCodecQrInputParam*)&input, &output);

    // Check return value
    assert_int_equal(ret, kDecodeQrDecodeError);

exit:
    if (qr_code_data != NULL) {
        free(qr_code_data);
    }

    if (qr_code_info != NULL) {
        free(qr_code_info);
    }

    if (output_data != NULL) {
        free(output_data);
    }

    if (input_image != NULL) {
        free(input_image);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDecodeQrCode_ErrorIsaCodecQrStoreDecodingResult(void** state)
{
    IsaCodecQrError ret;
    IsaCodecQrInputParam input;
    IsaCodecQrOutputInfo output;
    uint8_t* input_image = NULL;
    uint8_t* output_data = NULL;
    uint8_t* output_expect_data = NULL;
    int32_t quirc_instance;
    struct quirc_code* qr_code_info = NULL;
    struct quirc_data* qr_code_data = NULL;
    int payload_len;
    IsaCodecQrOutputType data_type = kDecodeQrOutputBinary;

    // Set test target argument
    SetInputParam(&input, &input_image, &output_data);
    if ((input_image == NULL) || (output_data == NULL)) {
        goto exit;
    }

    // For IsaCodecQrCreateInstance()
    ForIsaCodecQrCreateInstance((struct quirc*)&quirc_instance, &input);

    // For calloc() of struct quirc_code
    CheckCalloc(1, sizeof(struct quirc_code));

    // For IsaCodecQrDetect()
    qr_code_info = malloc(sizeof(struct quirc_code));
    if (qr_code_info == NULL) {
        assert_non_null(qr_code_info);
        goto exit;
    }
    CreateQuircCode(qr_code_info);
    ForIsaCodecQrDetect(qr_code_info, kDecodeQrSuccess, input.input_adr_handle,
                        (struct quirc*)&quirc_instance);

    // For quirc_destroy()
    expect_value(__wrap_quirc_destroy, q, (struct quirc*)&quirc_instance);

    // For calloc() of struct quirc_code
    CheckCalloc(1, sizeof(struct quirc_data));

    // For IsaCodecQrDecodeQrCodeInfo()
    qr_code_data = malloc(sizeof(struct quirc_data));
    if (qr_code_data == NULL) {
        assert_non_null(qr_code_data);
        goto exit;
    }
    payload_len = sizeof(qr_code_data->payload) - 5;
    CreateQuircData(qr_code_data, payload_len);
    ForIsaCodecQrDecodeQrCodeInfo(qr_code_data, kDecodeQrSuccess, qr_code_info);

    // For free() of struct quirc_code
    will_return(mock_free, false); // Not check parameter

    // For IsaCodecQrStoreDecodingResult()
    output_expect_data = malloc(payload_len);
    if (output_expect_data == NULL) {
        assert_non_null(output_expect_data);
        goto exit;
    }
    CreateExpectOutputData(output_expect_data, payload_len);
    ForIsaCodecQrStoreDecodingResult(payload_len, data_type, output_expect_data,
                                     kDecodeQrDecodeError, &input, qr_code_data);

    // For free() of struct quirc_data
    will_return(mock_free, false); // Not check parameter

    // Exec test target
    ret = IsaCodecQrDecodeQrCode((const IsaCodecQrInputParam*)&input, &output);

    // Check return value
    assert_int_equal(ret, kDecodeQrDecodeError);

exit:
    if (output_expect_data != NULL) {
        free(output_expect_data);
    }

    if (qr_code_data != NULL) {
        free(qr_code_data);
    }

    if (qr_code_info != NULL) {
        free(qr_code_info);
    }

    if (output_data != NULL) {
        free(output_data);
    }

    if (input_image != NULL) {
        free(input_image);
    }

    return;
}
#endif // CONFIG_EXTERNAL_QUIRC

/*----------------------------------------------------------------------------*/

//
// main()
//

/*----------------------------------------------------------------------------*/
int main(void)
{
    const struct CMUnitTest tests[] = {
        // IsaCodecQrDecodeQrCode()
        cmocka_unit_test(test_IsaCodecQrDecodeQrCode_FullySuccess),
        cmocka_unit_test(test_IsaCodecQrDecodeQrCode_InputNull),
        cmocka_unit_test(test_IsaCodecQrDecodeQrCode_OutputNull),
#ifdef CONFIG_ZXING_CPP_PORTING // use zxing library for QR decode.
        cmocka_unit_test(test_IsaCodecQrDecodeQrCode_Error_zxing_ImageView_new),
        cmocka_unit_test(test_IsaCodecQrDecodeQrCode_Error_zxing_DecodeHints_new),
        cmocka_unit_test(test_IsaCodecQrDecodeQrCode_NotDetect_zxing_ReadBarcode),
        cmocka_unit_test(test_IsaCodecQrDecodeQrCode_Error_InvalidQRCode),
        cmocka_unit_test(test_IsaCodecQrDecodeQrCode_Error_PayloadSizeOver),
#endif                       // CONFIG_ZXING_CPP_PORTING
#ifdef CONFIG_EXTERNAL_QUIRC // use QUIRC library for QR decode.
        cmocka_unit_test(test_IsaCodecQrDecodeQrCode_ErrorIsaCodecQrCreateInstance),
        cmocka_unit_test(test_IsaCodecQrDecodeQrCode_ErrorCalloc1st),
        cmocka_unit_test(test_IsaCodecQrDecodeQrCode_ErrorIsaCodecQrDetect),
        cmocka_unit_test(test_IsaCodecQrDecodeQrCode_ErrorCalloc2nd),
        cmocka_unit_test(test_IsaCodecQrDecodeQrCode_ErrorIsaCodecQrDecodeQrCodeInfo),
        cmocka_unit_test(test_IsaCodecQrDecodeQrCode_ErrorIsaCodecQrStoreDecodingResult),
#endif // CONFIG_EXTERNAL_QUIRC
    };

    return (((cmocka_run_group_tests(tests, NULL, NULL)) == 0) ? 0 : 1);
}
