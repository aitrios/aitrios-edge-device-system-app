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
#include <stdbool.h>
#include <string.h>
#if defined(__NuttX__)
#include <nuttx/config.h>
#endif
#include "memory_manager.h"
#include "initial_setting_app_qr_decode_internal.h"
#include "initial_setting_app_qr_decode_internal_private.h"

#ifdef CONFIG_EXTERNAL_QUIRC
extern uint8_t *g_linear_pool_address;
extern uint8_t g_pool_used[2];
#endif //CONFIG_EXTERNAL_QUIRC

#ifdef CONFIG_EXTERNAL_QUIRC
/*----------------------------------------------------------------------------*/

//
// Common
//

/*----------------------------------------------------------------------------*/
static uint8_t GetCommonImageData(int index_width)
{
    return index_width % 128;
}

/*----------------------------------------------------------------------------*/
static uint8_t *CreateNotPaddingImage(int32_t width, int32_t height, size_t *size)
{
    uint8_t *not_padding_image;
    int index_width, index_height;

    *size = width * height;

    not_padding_image = malloc(*size);
    if (not_padding_image == NULL) {
        assert_non_null(not_padding_image);
        goto exit;
    }

    for (index_height = 0; index_height < height; index_height++) {
        for (index_width = 0; index_width < width; index_width++) {
            not_padding_image[(index_height * width) + index_width] =
                GetCommonImageData(index_width);
        }
    }

exit:
    return not_padding_image;
}

/*----------------------------------------------------------------------------*/
static void CreateQuircCode(struct quirc_code *code)
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

/*----------------------------------------------------------------------------*/
static void CreateQuircData(struct quirc_data *data, int data_type, int payload_len)
{
    int i, j;

    data->version = 0x13;
    data->ecc_level = 0x57;
    data->mask = 0x24;
    data->data_type = data_type;

    for (i = (sizeof(data->payload) - 1), j = 0; i <= 0; i--, j++) {
        data->payload[i] = j % 128;
    }

    data->payload_len = payload_len;
    data->eci = 0x76;

    return;
}
#endif // CONFIG_EXTERNAL_QUIRC

/*----------------------------------------------------------------------------*/

//
// Initial value check for static global variable
//

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_EXTERNAL_QUIRC
static void test_IsaQrDecodeInternalInitialValueOfGlobalVariable(void **state)
{
    assert_null(g_linear_pool_address);
    assert_int_equal(g_pool_used[0], 0);
    assert_int_equal(g_pool_used[1], 0);

    return;
}
#endif // #ifdef CONFIG_EXTERNAL_QUIRC

/*----------------------------------------------------------------------------*/

//
// IsaLargeHeapAlloc()
//

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_EXTERNAL_QUIRC
static void test_IsaLargeHeapAlloc_FullySuccessPool0(void **state)
{
    void *ret;
    uint32_t pool_no = 0;
    uint32_t request_size = 1234;
    EsfMemoryManagerAppMemory mem_addr;

    // Set global variable
    g_linear_pool_address = NULL;
    memset(g_pool_used, 0xFF, sizeof(g_pool_used));

    // For EsfMemoryManagerWasmAllocate()
    will_return(__wrap_EsfMemoryManagerWasmAllocate, &mem_addr);
    expect_value(__wrap_EsfMemoryManagerWasmAllocate, usage,
                 kEsfMemoryManagerWasmAllocForLinearMemory);
    expect_value(__wrap_EsfMemoryManagerWasmAllocate, size, LINEAR_POOL_SIZE);

    // Exec test target
    ret = IsaLargeHeapAlloc(pool_no, request_size);

    // Check output
    assert_ptr_equal(ret, &mem_addr);
    assert_ptr_equal(g_linear_pool_address, (void *)&mem_addr);
    assert_int_equal(g_pool_used[0], 1);
    assert_int_equal(g_pool_used[1], 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaLargeHeapAlloc_FullySuccessPool1(void **state)
{
    void *ret;
    uint32_t pool_no = 1;
    uint32_t request_size = 1234;
    EsfMemoryManagerAppMemory mem_addr;

    // Set global variable
    g_linear_pool_address = NULL;
    memset(g_pool_used, 0xFF, sizeof(g_pool_used));

    // For EsfMemoryManagerWasmAllocate()
    will_return(__wrap_EsfMemoryManagerWasmAllocate, &mem_addr);
    expect_value(__wrap_EsfMemoryManagerWasmAllocate, usage,
                 kEsfMemoryManagerWasmAllocForLinearMemory);
    expect_value(__wrap_EsfMemoryManagerWasmAllocate, size, LINEAR_POOL_SIZE);

    // Exec test target
    ret = IsaLargeHeapAlloc(pool_no, request_size);

    // Check output
    assert_ptr_equal(ret, (uint8_t *)&mem_addr + POOL_0_SIZE);
    assert_ptr_equal(g_linear_pool_address, &mem_addr);
    assert_int_equal(g_pool_used[0], 0);
    assert_int_equal(g_pool_used[1], 1);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaLargeHeapAlloc_FullySuccessAlreadyAlloc(void **state)
{
    void *ret;
    uint32_t pool_no = 0;
    uint32_t request_size = 1234;
    EsfMemoryManagerAppMemory mem_addr;

    // Set global variable
    g_linear_pool_address = (uint8_t *)&mem_addr;
    g_pool_used[0] = 0;
    g_pool_used[1] = 0xFF;

    // Exec test target
    ret = IsaLargeHeapAlloc(pool_no, request_size);

    // Check output
    assert_ptr_equal(ret, &mem_addr);
    assert_ptr_equal(g_linear_pool_address, (void *)&mem_addr);
    assert_int_equal(g_pool_used[0], 1);
    assert_int_equal(g_pool_used[1], 0xFF);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaLargeHeapAlloc_ErrorMaxOverPoolNo(void **state)
{
    void *ret;
    uint32_t pool_no = 2;
    uint32_t request_size = 1234;
    EsfMemoryManagerAppMemory mem_addr;

    // Set global variable
    g_linear_pool_address = NULL;
    memset(g_pool_used, 0xFF, sizeof(g_pool_used));

    // For EsfMemoryManagerWasmAllocate()
    will_return(__wrap_EsfMemoryManagerWasmAllocate, &mem_addr);
    expect_value(__wrap_EsfMemoryManagerWasmAllocate, usage,
                 kEsfMemoryManagerWasmAllocForLinearMemory);
    expect_value(__wrap_EsfMemoryManagerWasmAllocate, size, LINEAR_POOL_SIZE);

    // Exec test target
    ret = IsaLargeHeapAlloc(pool_no, request_size);

    // Check output
    assert_null(ret);
    assert_ptr_equal(g_linear_pool_address, (void *)&mem_addr);
    assert_int_equal(g_pool_used[0], 0);
    assert_int_equal(g_pool_used[1], 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaLargeHeapAlloc_ErrorAlreadyGetPool0(void **state)
{
    void *ret;
    uint32_t pool_no = 0;
    uint32_t request_size = 1234;
    EsfMemoryManagerAppMemory mem_addr;

    // Set global variable
    g_linear_pool_address = (uint8_t *)&mem_addr;
    g_pool_used[0] = 1;
    g_pool_used[1] = 0;

    // Exec test target
    ret = IsaLargeHeapAlloc(pool_no, request_size);

    // Check output
    assert_null(ret);
    assert_ptr_equal(g_linear_pool_address, (void *)&mem_addr);
    assert_int_equal(g_pool_used[0], 1);
    assert_int_equal(g_pool_used[1], 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaLargeHeapAlloc_ErrorAlreadyGetPool1(void **state)
{
    void *ret;
    uint32_t pool_no = 1;
    uint32_t request_size = 1234;
    EsfMemoryManagerAppMemory mem_addr;

    // Set global variable
    g_linear_pool_address = (uint8_t *)&mem_addr;
    g_pool_used[0] = 0;
    g_pool_used[1] = 1;

    // Exec test target
    ret = IsaLargeHeapAlloc(pool_no, request_size);

    // Check output
    assert_null(ret);
    assert_ptr_equal(g_linear_pool_address, (void *)&mem_addr);
    assert_int_equal(g_pool_used[0], 0);
    assert_int_equal(g_pool_used[1], 1);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaLargeHeapAlloc_ErrorMaxOverReqeustSizePool0(void **state)
{
    void *ret;
    uint32_t pool_no = 0;
    uint32_t request_size = POOL_0_SIZE + 1;
    EsfMemoryManagerAppMemory mem_addr;

    // Set global variable
    g_linear_pool_address = NULL;
    memset(g_pool_used, 0xFF, sizeof(g_pool_used));

    // For EsfMemoryManagerWasmAllocate()
    will_return(__wrap_EsfMemoryManagerWasmAllocate, &mem_addr);
    expect_value(__wrap_EsfMemoryManagerWasmAllocate, usage,
                 kEsfMemoryManagerWasmAllocForLinearMemory);
    expect_value(__wrap_EsfMemoryManagerWasmAllocate, size, LINEAR_POOL_SIZE);

    // Exec test target
    ret = IsaLargeHeapAlloc(pool_no, request_size);

    // Check output
    assert_null(ret);
    assert_ptr_equal(g_linear_pool_address, (void *)&mem_addr);
    assert_int_equal(g_pool_used[0], 0);
    assert_int_equal(g_pool_used[1], 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaLargeHeapAlloc_FullySuccessMaxReqeustSizePool0(void **state)
{
    void *ret;
    uint32_t pool_no = 0;
    uint32_t request_size = POOL_0_SIZE;
    EsfMemoryManagerAppMemory mem_addr;

    // Set global variable
    g_linear_pool_address = NULL;
    memset(g_pool_used, 0xFF, sizeof(g_pool_used));

    // For EsfMemoryManagerWasmAllocate()
    will_return(__wrap_EsfMemoryManagerWasmAllocate, &mem_addr);
    expect_value(__wrap_EsfMemoryManagerWasmAllocate, usage,
                 kEsfMemoryManagerWasmAllocForLinearMemory);
    expect_value(__wrap_EsfMemoryManagerWasmAllocate, size, LINEAR_POOL_SIZE);

    // Exec test target
    ret = IsaLargeHeapAlloc(pool_no, request_size);

    // Check output
    assert_ptr_equal(ret, &mem_addr);
    assert_ptr_equal(g_linear_pool_address, (void *)&mem_addr);
    assert_int_equal(g_pool_used[0], 1);
    assert_int_equal(g_pool_used[1], 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaLargeHeapAlloc_ErrorMaxOverReqeustSizePool1(void **state)
{
    void *ret;
    uint32_t pool_no = 1;
    uint32_t request_size = POOL_1_SIZE + 1;
    EsfMemoryManagerAppMemory mem_addr;

    // Set global variable
    g_linear_pool_address = NULL;
    memset(g_pool_used, 0xFF, sizeof(g_pool_used));

    // For EsfMemoryManagerWasmAllocate()
    will_return(__wrap_EsfMemoryManagerWasmAllocate, &mem_addr);
    expect_value(__wrap_EsfMemoryManagerWasmAllocate, usage,
                 kEsfMemoryManagerWasmAllocForLinearMemory);
    expect_value(__wrap_EsfMemoryManagerWasmAllocate, size, LINEAR_POOL_SIZE);

    // Exec test target
    ret = IsaLargeHeapAlloc(pool_no, request_size);

    // Check output
    assert_null(ret);
    assert_ptr_equal(g_linear_pool_address, (void *)&mem_addr);
    assert_int_equal(g_pool_used[0], 0);
    assert_int_equal(g_pool_used[1], 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaLargeHeapAlloc_FullySuccessMaxReqeustSizePool1(void **state)
{
    void *ret;
    uint32_t pool_no = 1;
    uint32_t request_size = POOL_1_SIZE;
    EsfMemoryManagerAppMemory mem_addr;

    // Set global variable
    g_linear_pool_address = NULL;
    memset(g_pool_used, 0xFF, sizeof(g_pool_used));

    // For EsfMemoryManagerWasmAllocate()
    will_return(__wrap_EsfMemoryManagerWasmAllocate, &mem_addr);
    expect_value(__wrap_EsfMemoryManagerWasmAllocate, usage,
                 kEsfMemoryManagerWasmAllocForLinearMemory);
    expect_value(__wrap_EsfMemoryManagerWasmAllocate, size, LINEAR_POOL_SIZE);

    // Exec test target
    ret = IsaLargeHeapAlloc(pool_no, request_size);

    // Check output
    assert_ptr_equal(ret, (uint8_t *)&mem_addr + POOL_0_SIZE);
    assert_ptr_equal(g_linear_pool_address, &mem_addr);
    assert_int_equal(g_pool_used[0], 0);
    assert_int_equal(g_pool_used[1], 1);

    return;
}
#endif // CONFIG_EXTERNAL_QUIRC

#ifdef CONFIG_ZXING_CPP_PORTING
/*----------------------------------------------------------------------------*/
static void test_IsaLargeHeapAlloc_FullySuccess(void **state)
{
    void *ret = NULL;
    size_t size = 1234;

    // For malloc()
    will_return(mock_malloc, true); // Check parameter
    will_return(mock_malloc, true); // Return allocated address
    expect_value(mock_malloc, __size, size);

    // Exec test target
    ret = IsaLargeHeapAlloc(0, size);

    // Check return value
    assert_non_null(ret);

    if (ret != NULL) {
        free(ret);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaLargeHeapAlloc_ErrorMalloc(void **state)
{
    void *ret = NULL;
    size_t size = 1234;

    // For malloc()
    will_return(mock_malloc, true);  // Check parameter
    will_return(mock_malloc, false); // Return NULL
    expect_value(mock_malloc, __size, size);

    // Exec test target
    ret = IsaLargeHeapAlloc(0, size);

    // Check return value
    assert_null(ret);

    if (ret != NULL) {
        free(ret);
    }

    return;
}
#endif // CONFIG_ZXING_CPP_PORTING

/*----------------------------------------------------------------------------*/

//
// IsaLargeHeapFree()
//

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_EXTERNAL_QUIRC
static void test_IsaLargeHeapFree_Pool0NotExecFree(void **state)
{
    void *memory_address;

    // Set global variable
    g_linear_pool_address = (uint8_t *)0x12345678;
    memset(g_pool_used, 0xFF, sizeof(g_pool_used));

    // Set test target argument
    memory_address = (void *)g_linear_pool_address;

    // Exec test target
    IsaLargeHeapFree(memory_address);

    // Check output
    assert_int_equal(g_pool_used[0], 0);
    assert_int_equal(g_pool_used[1], 0xFF);
}

/*----------------------------------------------------------------------------*/
static void test_IsaLargeHeapFree_Pool1NotExecFree(void **state)
{
    void *memory_address;

    // Set global variable
    g_linear_pool_address = (uint8_t *)0x12345678;
    memset(g_pool_used, 0xFF, sizeof(g_pool_used));

    // Set test target argument
    memory_address = (void *)(g_linear_pool_address + POOL_0_SIZE);

    // Exec test target
    IsaLargeHeapFree(memory_address);

    // Check output
    assert_int_equal(g_pool_used[0], 0xFF);
    assert_int_equal(g_pool_used[1], 0);
}

/*----------------------------------------------------------------------------*/
static void test_IsaLargeHeapFree_Pool0ExecFree(void **state)
{
    void *memory_address;

    // Set global variable
    g_linear_pool_address = (uint8_t *)0x12345678;
    g_pool_used[0] = 1;
    g_pool_used[1] = 0;

    // Set test target argument
    memory_address = (void *)g_linear_pool_address;

    // For EsfMemoryManagerWasmFree()
    expect_value(__wrap_EsfMemoryManagerWasmFree, usage, kEsfMemoryManagerWasmAllocForLinearMemory);
    expect_value(__wrap_EsfMemoryManagerWasmFree, memory, g_linear_pool_address);

    // Exec test target
    IsaLargeHeapFree(memory_address);

    // Check output
    assert_int_equal(g_pool_used[0], 0);
    assert_int_equal(g_pool_used[1], 0);
}

/*----------------------------------------------------------------------------*/
static void test_IsaLargeHeapFree_Pool1ExecFree(void **state)
{
    void *memory_address;

    // Set global variable
    g_linear_pool_address = (uint8_t *)0x12345678;
    g_pool_used[0] = 0;
    g_pool_used[1] = 1;

    // Set test target argument
    memory_address = (void *)(g_linear_pool_address + POOL_0_SIZE);

    // For EsfMemoryManagerWasmFree()
    expect_value(__wrap_EsfMemoryManagerWasmFree, usage, kEsfMemoryManagerWasmAllocForLinearMemory);
    expect_value(__wrap_EsfMemoryManagerWasmFree, memory, g_linear_pool_address);

    // Exec test target
    IsaLargeHeapFree(memory_address);

    // Check output
    assert_int_equal(g_pool_used[0], 0);
    assert_int_equal(g_pool_used[1], 0);
}

/*----------------------------------------------------------------------------*/
static void test_IsaLargeHeapFree_NotAllocateMemory(void **state)
{
    void *memory_address;

    // Set global variable
    g_linear_pool_address = NULL;
    g_pool_used[0] = 1;
    g_pool_used[1] = 0;

    // Set test target argument
    memory_address = (void *)g_linear_pool_address;

    // Exec test target
    IsaLargeHeapFree(memory_address);

    // Check output
    assert_int_equal(g_pool_used[0], 0);
    assert_int_equal(g_pool_used[1], 0);
}

/*----------------------------------------------------------------------------*/
static void test_IsaLargeHeapFree_UnknownAddress(void **state)
{
    void *memory_address;

    // Set global variable
    g_linear_pool_address = (uint8_t *)0x12345678;
    memset(g_pool_used, 0xFF, sizeof(g_pool_used));

    // Set test target argument
    memory_address = (void *)g_linear_pool_address + 1;

    // Exec test target
    IsaLargeHeapFree(memory_address);

    // Check output
    assert_int_equal(g_pool_used[0], 0xFF);
    assert_int_equal(g_pool_used[1], 0xFF);
}
#endif // CONFIG_EXTERNAL_QUIRC

/*----------------------------------------------------------------------------*/
#ifdef CONFIG_ZXING_CPP_PORTING
static void test_IsaLargeHeapFree(void **state)
{
    void *test_buff;

    // Allocate for test target argument
    test_buff = malloc(1024);
    if (test_buff == NULL) {
        assert_non_null(test_buff);
        goto exit;
    }

    // For free()
    will_return(mock_free, true); // Check parameter
    expect_value(mock_free, __ptr, test_buff);

    // Exec test target
    IsaLargeHeapFree(test_buff);

exit:
    return;
}
#endif // CONFIG_ZXING_CPP_PORTING

#ifdef CONFIG_EXTERNAL_QUIRC
/*----------------------------------------------------------------------------*/

//
// IsaCodecQrCreateInstance()
//

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrCreateInstance_FullySuccessCore(int32_t width, int32_t height)
{
    int32_t quirc_instance;
    struct quirc *ret;

    // For quirc_new()
    will_return(__wrap_quirc_new, (struct quirc *)&quirc_instance);

    // For quirc_resize()
    expect_value(__wrap_quirc_resize, q, (struct quirc *)&quirc_instance);
    expect_value(__wrap_quirc_resize, w, width);
    expect_value(__wrap_quirc_resize, h, height);
    will_return(__wrap_quirc_resize, 0);

    // Exec test target
    ret = IsaCodecQrCreateInstance(width, height);

    // Check return value
    assert_ptr_equal((struct quirc *)&quirc_instance, ret);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrCreateInstance_FullySuccess(void **state)
{
    int32_t width = 680;
    int32_t height = 480;

    test_IsaCodecQrCreateInstance_FullySuccessCore(width, height);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrCreateInstance_WidthMinOver(void **state)
{
    int32_t width = 0;
    int32_t height = 480;
    struct quirc *ret;

    // Exec test target
    ret = IsaCodecQrCreateInstance(width, height);

    // Check return value
    assert_null(ret);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrCreateInstance_WidthMin(void **state)
{
    int32_t width = 1;
    int32_t height = 480;

    test_IsaCodecQrCreateInstance_FullySuccessCore(width, height);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrCreateInstance_HeightMinOver(void **state)
{
    int32_t width = 640;
    int32_t height = 0;
    struct quirc *ret;

    // Exec test target
    ret = IsaCodecQrCreateInstance(width, height);

    // Check return value
    assert_null(ret);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrCreateInstance_HeightMin(void **state)
{
    int32_t width = 680;
    int32_t height = 1;

    test_IsaCodecQrCreateInstance_FullySuccessCore(width, height);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrCreateInstance_ErrorQuircNew(void **state)
{
    int32_t width = 680;
    int32_t height = 480;
    struct quirc *ret;

    // For quirc_new()
    will_return(__wrap_quirc_new, NULL);

    // Exec test target
    ret = IsaCodecQrCreateInstance(width, height);

    // Check return value
    assert_null(ret);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrCreateInstance_ErrorQuircrResize(void **state)
{
    int32_t width = 680;
    int32_t height = 480;
    int32_t quirc_instance;
    struct quirc *ret;

    // For quirc_new()
    will_return(__wrap_quirc_new, (struct quirc *)&quirc_instance);

    // For quirc_resize()
    expect_value(__wrap_quirc_resize, q, (struct quirc *)&quirc_instance);
    expect_value(__wrap_quirc_resize, w, width);
    expect_value(__wrap_quirc_resize, h, height);
    will_return(__wrap_quirc_resize, -1);

    // For quirc_destroy()
    expect_value(__wrap_quirc_destroy, q, (struct quirc *)&quirc_instance);

    // Exec test target
    ret = IsaCodecQrCreateInstance(width, height);

    // Check return value
    assert_null(ret);

    return;
}
#endif // CONFIG_EXTERNAL_QUIRC

#ifdef CONFIG_EXTERNAL_QUIRC
/*----------------------------------------------------------------------------*/

//
// IsaCodecQrDetect()
//

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDetect_FullySuccess(void **state)
{
    int32_t width = 680;
    int32_t height = 480;
    int32_t quirc_instance;
    IsaCodecQrError ret;
    struct quirc_code *out_qr_code_info = NULL;
    struct quirc_code *expected_qr_code_info = NULL;
    uint8_t *image_data = NULL;
    uint8_t *quirc_begin_ret = NULL;
    size_t image_data_size;

    // For quirc_begin()
    expect_value(__wrap_quirc_begin, q, (struct quirc *)&quirc_instance);
    expect_not_value(__wrap_quirc_begin, w, NULL);
    expect_not_value(__wrap_quirc_begin, h, NULL);

    quirc_begin_ret = malloc(width * height);
    if (quirc_begin_ret == NULL) {
        assert_non_null(quirc_begin_ret);
        goto exit;
    }
    will_return(__wrap_quirc_begin, quirc_begin_ret);

    // For quirc_end()
    expect_value(__wrap_quirc_end, q, (struct quirc *)&quirc_instance);

    // For quirc_count()
    expect_value(__wrap_quirc_count, q, (struct quirc *)&quirc_instance);
    will_return(__wrap_quirc_count, 1);

    // For quirc_extract()
    expect_value(__wrap_quirc_extract, q, (struct quirc *)&quirc_instance);
    expect_value(__wrap_quirc_extract, index, 0);

    expected_qr_code_info = malloc(sizeof(struct quirc_code));
    if (expected_qr_code_info == NULL) {
        assert_non_null(expected_qr_code_info);
        goto exit;
    }
    CreateQuircCode(expected_qr_code_info);
    will_return(__wrap_quirc_extract, expected_qr_code_info);

    // For test target argument
    image_data = CreateNotPaddingImage(width, height, &image_data_size);
    if (image_data == NULL) {
        goto exit;
    }

    out_qr_code_info = malloc(sizeof(struct quirc_code));
    if (out_qr_code_info == NULL) {
        assert_non_null(out_qr_code_info);
        goto exit;
    }

    // Exec test target
    ret = IsaCodecQrDetect((uint64_t)image_data, out_qr_code_info, (struct quirc *)&quirc_instance);

    // Check return value and output argument
    assert_int_equal(ret, kDecodeQrSuccess);
    assert_memory_equal(out_qr_code_info, expected_qr_code_info, sizeof(struct quirc_code));

exit:
    if (out_qr_code_info != NULL) {
        free(out_qr_code_info);
    }

    if (image_data != NULL) {
        free(image_data);
    }

    if (expected_qr_code_info != NULL) {
        free(expected_qr_code_info);
    }

    if (quirc_begin_ret != NULL) {
        free(quirc_begin_ret);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDetect_InstanceNull(void **state)
{
    int32_t width = 680;
    int32_t height = 480;
    IsaCodecQrError ret;
    struct quirc_code *out_qr_code_info = NULL;
    uint8_t *image_data = NULL;
    size_t image_data_size;

    // For test target argument
    image_data = CreateNotPaddingImage(width, height, &image_data_size);
    if (image_data == NULL) {
        goto exit;
    }

    out_qr_code_info = malloc(sizeof(struct quirc_code));
    if (out_qr_code_info == NULL) {
        assert_non_null(out_qr_code_info);
        goto exit;
    }

    // Exec test target
    ret = IsaCodecQrDetect((uint64_t)image_data, out_qr_code_info, NULL);

    // Check return value
    assert_int_equal(ret, kDecodeQrParamError);

exit:
    if (out_qr_code_info != NULL) {
        free(out_qr_code_info);
    }

    if (image_data != NULL) {
        free(image_data);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDetect_ImageAddrNull(void **state)
{
    int32_t quirc_instance;
    IsaCodecQrError ret;
    struct quirc_code *out_qr_code_info = NULL;

    // For test target argument
    out_qr_code_info = malloc(sizeof(struct quirc_code));
    if (out_qr_code_info == NULL) {
        assert_non_null(out_qr_code_info);
        goto exit;
    }

    // Exec test target
    ret = IsaCodecQrDetect(0, out_qr_code_info, (struct quirc *)&quirc_instance);

    // Check return value
    assert_int_equal(ret, kDecodeQrParamError);

exit:
    if (out_qr_code_info != NULL) {
        free(out_qr_code_info);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDetect_QrCodeInfoNull(void **state)
{
    int32_t width = 680;
    int32_t height = 480;
    int32_t quirc_instance;
    IsaCodecQrError ret;
    uint8_t *image_data = NULL;
    size_t image_data_size;

    // For test target argument
    image_data = CreateNotPaddingImage(width, height, &image_data_size);
    if (image_data == NULL) {
        goto exit;
    }

    // Exec test target
    ret = IsaCodecQrDetect((uint64_t)image_data, NULL, (struct quirc *)&quirc_instance);

    // Check return value
    assert_int_equal(ret, kDecodeQrParamError);

exit:
    if (image_data != NULL) {
        free(image_data);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDetect_QrCountZero(void **state)
{
    int32_t width = 680;
    int32_t height = 480;
    int32_t quirc_instance;
    IsaCodecQrError ret;
    struct quirc_code *out_qr_code_info = NULL;
    uint8_t *image_data = NULL;
    uint8_t *quirc_begin_ret = NULL;
    size_t image_data_size;

    // For quirc_begin()
    expect_value(__wrap_quirc_begin, q, (struct quirc *)&quirc_instance);
    expect_not_value(__wrap_quirc_begin, w, NULL);
    expect_not_value(__wrap_quirc_begin, h, NULL);

    quirc_begin_ret = malloc(width * height);
    if (quirc_begin_ret == NULL) {
        assert_non_null(quirc_begin_ret);
        goto exit;
    }
    will_return(__wrap_quirc_begin, quirc_begin_ret);

    // For quirc_end()
    expect_value(__wrap_quirc_end, q, (struct quirc *)&quirc_instance);

    // For quirc_count()
    expect_value(__wrap_quirc_count, q, (struct quirc *)&quirc_instance);
    will_return(__wrap_quirc_count, 0);

    // For test target argument
    image_data = CreateNotPaddingImage(width, height, &image_data_size);
    if (image_data == NULL) {
        goto exit;
    }

    out_qr_code_info = malloc(sizeof(struct quirc_code));
    if (out_qr_code_info == NULL) {
        assert_non_null(out_qr_code_info);
        goto exit;
    }

    // Exec test target
    ret = IsaCodecQrDetect((uint64_t)image_data, out_qr_code_info, (struct quirc *)&quirc_instance);

    // Check return value
    assert_int_equal(ret, kDecodeQrNotDetectError);

exit:
    if (out_qr_code_info != NULL) {
        free(out_qr_code_info);
    }

    if (image_data != NULL) {
        free(image_data);
    }

    if (quirc_begin_ret != NULL) {
        free(quirc_begin_ret);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDetect_QrCountTwo(void **state)
{
    int32_t width = 680;
    int32_t height = 480;
    int32_t quirc_instance;
    IsaCodecQrError ret;
    struct quirc_code *out_qr_code_info = NULL;
    uint8_t *image_data = NULL;
    uint8_t *quirc_begin_ret = NULL;
    size_t image_data_size;

    // For quirc_begin()
    expect_value(__wrap_quirc_begin, q, (struct quirc *)&quirc_instance);
    expect_not_value(__wrap_quirc_begin, w, NULL);
    expect_not_value(__wrap_quirc_begin, h, NULL);

    quirc_begin_ret = malloc(width * height);
    if (quirc_begin_ret == NULL) {
        assert_non_null(quirc_begin_ret);
        goto exit;
    }
    will_return(__wrap_quirc_begin, quirc_begin_ret);

    // For quirc_end()
    expect_value(__wrap_quirc_end, q, (struct quirc *)&quirc_instance);

    // For quirc_count()
    expect_value(__wrap_quirc_count, q, (struct quirc *)&quirc_instance);
    will_return(__wrap_quirc_count, 2);

    // For test target argument
    image_data = CreateNotPaddingImage(width, height, &image_data_size);
    if (image_data == NULL) {
        goto exit;
    }

    out_qr_code_info = malloc(sizeof(struct quirc_code));
    if (out_qr_code_info == NULL) {
        assert_non_null(out_qr_code_info);
        goto exit;
    }

    // Exec test target
    ret = IsaCodecQrDetect((uint64_t)image_data, out_qr_code_info, (struct quirc *)&quirc_instance);

    // Check return value and output argument
    assert_int_equal(ret, kDecodeQrDetectCountError);

exit:
    if (out_qr_code_info != NULL) {
        free(out_qr_code_info);
    }

    if (image_data != NULL) {
        free(image_data);
    }

    if (quirc_begin_ret != NULL) {
        free(quirc_begin_ret);
    }

    return;
}
#endif // CONFIG_EXTERNAL_QUIRC

#ifdef CONFIG_EXTERNAL_QUIRC
/*----------------------------------------------------------------------------*/

//
// IsaCodecQrDecodeQrCodeInfo()
//

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDecodeQrCodeInfo_FullySuccess(void **state)
{
    IsaCodecQrError ret;
    struct quirc_code *qr_code_info = NULL;
    struct quirc_data *out_qr_code_data = NULL;
    struct quirc_data *expected_qr_code_data = NULL;

    // For quirc_decode()
    qr_code_info = malloc(sizeof(struct quirc_code));
    if (qr_code_info == NULL) {
        assert_non_null(qr_code_info);
        goto exit;
    }
    CreateQuircCode(qr_code_info);
    expect_memory(__wrap_quirc_decode, code, qr_code_info, sizeof(struct quirc_code));

    expected_qr_code_data = malloc(sizeof(struct quirc_data));
    if (expected_qr_code_data == NULL) {
        assert_non_null(expected_qr_code_data);
        goto exit;
    }
    CreateQuircData(expected_qr_code_data, QUIRC_DATA_TYPE_BYTE,
                    sizeof(expected_qr_code_data->payload));
    will_return(__wrap_quirc_decode, expected_qr_code_data);

    will_return(__wrap_quirc_decode, QUIRC_SUCCESS);

    // For test target argument
    out_qr_code_data = malloc(sizeof(struct quirc_data));
    if (out_qr_code_data == NULL) {
        assert_non_null(out_qr_code_data);
        goto exit;
    }

    // Exec test target
    ret = IsaCodecQrDecodeQrCodeInfo(qr_code_info, out_qr_code_data);

    // Check return value and output argument
    assert_int_equal(ret, kDecodeQrSuccess);
    assert_memory_equal(out_qr_code_data, expected_qr_code_data, sizeof(struct quirc_data));

exit:
    if (out_qr_code_data != NULL) {
        free(out_qr_code_data);
    }

    if (expected_qr_code_data != NULL) {
        free(expected_qr_code_data);
    }

    if (qr_code_info != NULL) {
        free(qr_code_info);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDecodeQrCodeInfo_QrCodeInfoNull(void **state)
{
    IsaCodecQrError ret;
    struct quirc_data *out_qr_code_data = NULL;

    // For test target argument
    out_qr_code_data = malloc(sizeof(struct quirc_data));
    if (out_qr_code_data == NULL) {
        assert_non_null(out_qr_code_data);
        goto exit;
    }

    // Exec test target
    ret = IsaCodecQrDecodeQrCodeInfo(NULL, out_qr_code_data);

    // Check return value
    assert_int_equal(ret, kDecodeQrParamError);

exit:
    if (out_qr_code_data != NULL) {
        free(out_qr_code_data);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDecodeQrCodeInfo_QrCodeDataNull(void **state)
{
    IsaCodecQrError ret;
    struct quirc_code *qr_code_info = NULL;

    // For test target argument
    qr_code_info = malloc(sizeof(struct quirc_code));
    if (qr_code_info == NULL) {
        assert_non_null(qr_code_info);
        goto exit;
    }
    CreateQuircCode(qr_code_info);

    // Exec test target
    ret = IsaCodecQrDecodeQrCodeInfo(qr_code_info, NULL);

    // Check return value
    assert_int_equal(ret, kDecodeQrParamError);

exit:
    if (qr_code_info != NULL) {
        free(qr_code_info);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrDecodeQrCodeInfo_ErrorQuircDecode(void **state)
{
    IsaCodecQrError ret;
    struct quirc_code *qr_code_info = NULL;
    struct quirc_data *out_qr_code_data = NULL;
    struct quirc_data *expected_qr_code_data = NULL;

    // For quirc_decode()
    qr_code_info = malloc(sizeof(struct quirc_code));
    if (qr_code_info == NULL) {
        assert_non_null(qr_code_info);
        goto exit;
    }
    CreateQuircCode(qr_code_info);
    expect_memory(__wrap_quirc_decode, code, qr_code_info, sizeof(struct quirc_code));

    expected_qr_code_data = malloc(sizeof(struct quirc_data));
    if (expected_qr_code_data == NULL) {
        assert_non_null(expected_qr_code_data);
        goto exit;
    }
    CreateQuircData(expected_qr_code_data, QUIRC_DATA_TYPE_BYTE,
                    sizeof(expected_qr_code_data->payload));
    will_return(__wrap_quirc_decode, expected_qr_code_data);

    // For test target argument
    will_return(__wrap_quirc_decode, QUIRC_ERROR_INVALID_GRID_SIZE);

    out_qr_code_data = malloc(sizeof(struct quirc_data));
    if (out_qr_code_data == NULL) {
        assert_non_null(out_qr_code_data);
        goto exit;
    }

    // Exec test target
    ret = IsaCodecQrDecodeQrCodeInfo(qr_code_info, out_qr_code_data);

    // Check return value and output argument
    assert_int_equal(ret, kDecodeQrDecodeError);

exit:
    if (out_qr_code_data != NULL) {
        free(out_qr_code_data);
    }

    if (expected_qr_code_data != NULL) {
        free(expected_qr_code_data);
    }

    if (qr_code_info != NULL) {
        free(qr_code_info);
    }

    return;
}
#endif // CONFIG_EXTERNAL_QUIRC

#ifdef CONFIG_EXTERNAL_QUIRC
/*----------------------------------------------------------------------------*/

//
// IsaCodecQrStoreDecodingResult()
//

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrStoreDecodingResult_FullySuccessCore(IsaCodecQrOutputType data_type)
{
    IsaCodecQrError ret;
    IsaCodecQrOutputBuf output_buffer_info;
    struct quirc_data *qr_code_data = NULL;
    IsaCodecQrOutputInfo output_result_info;
    int payload_size = 1234;
    int32_t output_buf_size = 2 * 1024;
    void *out_output_buf = NULL;
    void *init_val_output_buf = NULL;
    int quirc_data_type;

    // For test target argument
    out_output_buf = malloc(output_buf_size);
    if (out_output_buf == NULL) {
        assert_non_null(out_output_buf);
        goto exit;
    }
    memset(out_output_buf, 0xFF, output_buf_size);
    output_buffer_info.output_adr_handle = (uint64_t)out_output_buf;
    output_buffer_info.output_max_size = output_buf_size;

    qr_code_data = malloc(sizeof(struct quirc_data));
    if (qr_code_data == NULL) {
        assert_non_null(qr_code_data);
        goto exit;
    }
    switch (data_type) {
        case kDecodeQrOutputNumeric:
            quirc_data_type = QUIRC_DATA_TYPE_NUMERIC;
            break;
        case kDecodeQrOutputAlphanumeric:
            quirc_data_type = QUIRC_DATA_TYPE_ALPHA;
            break;
        case kDecodeQrOutputBinary:
            quirc_data_type = QUIRC_DATA_TYPE_BYTE;
            break;
        case kDecodeQrOutputKanji:
            quirc_data_type = QUIRC_DATA_TYPE_KANJI;
            break;
        default:
            assert_in_range(quirc_data_type, kDecodeQrOutputNumeric, kDecodeQrOutputKanji);
            goto exit;
    }
    CreateQuircData(qr_code_data, quirc_data_type, payload_size);

    // Create expected value
    init_val_output_buf = malloc(output_buf_size);
    if (init_val_output_buf == NULL) {
        assert_non_null(init_val_output_buf);
        goto exit;
    }
    memset(init_val_output_buf, 0xFF, output_buf_size);

    // Exec test target
    ret = IsaCodecQrStoreDecodingResult(&output_buffer_info, qr_code_data, &output_result_info);

    // Check return value and output argument
    assert_int_equal(ret, kDecodeQrSuccess);
    assert_memory_equal(output_buffer_info.output_adr_handle, qr_code_data->payload, payload_size);
    assert_memory_equal(output_buffer_info.output_adr_handle + payload_size, init_val_output_buf,
                        output_buf_size - payload_size);
    assert_int_equal(output_result_info.output_size, payload_size);
    assert_int_equal(output_result_info.output_type, data_type);

exit:
    if (out_output_buf != NULL) {
        free(out_output_buf);
    }

    if (qr_code_data != NULL) {
        free(qr_code_data);
    }

    if (init_val_output_buf != NULL) {
        free(init_val_output_buf);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrStoreDecodingResult_FullySuccessNumeric(void **state)
{
    test_IsaCodecQrStoreDecodingResult_FullySuccessCore(kDecodeQrOutputNumeric);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrStoreDecodingResult_FullySuccessAlpha(void **state)
{
    test_IsaCodecQrStoreDecodingResult_FullySuccessCore(kDecodeQrOutputAlphanumeric);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrStoreDecodingResult_FullySuccessByte(void **state)
{
    test_IsaCodecQrStoreDecodingResult_FullySuccessCore(kDecodeQrOutputBinary);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrStoreDecodingResult_FullySuccessKanji(void **state)
{
    test_IsaCodecQrStoreDecodingResult_FullySuccessCore(kDecodeQrOutputKanji);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrStoreDecodingResult_OutputBufferInfoNull(void **state)
{
    IsaCodecQrError ret;
    struct quirc_data *qr_code_data = NULL;
    IsaCodecQrOutputInfo output_result_info;
    int payload_size = 1234;

    // For test target argument
    qr_code_data = malloc(sizeof(struct quirc_data));
    if (qr_code_data == NULL) {
        assert_non_null(qr_code_data);
        goto exit;
    }
    CreateQuircData(qr_code_data, QUIRC_DATA_TYPE_NUMERIC, payload_size);

    // Exec test target
    ret = IsaCodecQrStoreDecodingResult(NULL, qr_code_data, &output_result_info);

    // Check return value
    assert_int_equal(ret, kDecodeQrParamError);

exit:
    if (qr_code_data != NULL) {
        free(qr_code_data);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrStoreDecodingResult_OutputBufferAddrNull(void **state)
{
    IsaCodecQrError ret;
    IsaCodecQrOutputBuf output_buffer_info;
    struct quirc_data *qr_code_data = NULL;
    IsaCodecQrOutputInfo output_result_info;
    int payload_size = 1234;
    int32_t output_buf_size = 2 * 1024;

    // For test target argument
    output_buffer_info.output_adr_handle = (uint64_t)NULL;
    output_buffer_info.output_max_size = output_buf_size;

    qr_code_data = malloc(sizeof(struct quirc_data));
    if (qr_code_data == NULL) {
        assert_non_null(qr_code_data);
        goto exit;
    }
    CreateQuircData(qr_code_data, QUIRC_DATA_TYPE_NUMERIC, payload_size);

    // Exec test target
    ret = IsaCodecQrStoreDecodingResult(&output_buffer_info, qr_code_data, &output_result_info);

    // Check return value and output argument
    assert_int_equal(ret, kDecodeQrParamError);

exit:
    if (qr_code_data != NULL) {
        free(qr_code_data);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrStoreDecodingResult_QrCodeDataNull(void **state)
{
    IsaCodecQrError ret;
    IsaCodecQrOutputBuf output_buffer_info;
    IsaCodecQrOutputInfo output_result_info;
    int32_t output_buf_size = 2 * 1024;
    void *out_output_buf = NULL;

    // For test target argument
    out_output_buf = malloc(output_buf_size);
    if (out_output_buf == NULL) {
        assert_non_null(out_output_buf);
        goto exit;
    }
    memset(out_output_buf, 0xFF, output_buf_size);
    output_buffer_info.output_adr_handle = (uint64_t)out_output_buf;
    output_buffer_info.output_max_size = output_buf_size;

    // Exec test target
    ret = IsaCodecQrStoreDecodingResult(&output_buffer_info, NULL, &output_result_info);

    // Check return value and output argument
    assert_int_equal(ret, kDecodeQrParamError);

exit:
    if (out_output_buf != NULL) {
        free(out_output_buf);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrStoreDecodingResult_OutputResultInfoNull(void **state)
{
    IsaCodecQrError ret;
    IsaCodecQrOutputBuf output_buffer_info;
    struct quirc_data *qr_code_data = NULL;
    int payload_size = 1234;
    int32_t output_buf_size = 2 * 1024;
    void *out_output_buf = NULL;

    // For test target argument
    out_output_buf = malloc(output_buf_size);
    if (out_output_buf == NULL) {
        assert_non_null(out_output_buf);
        goto exit;
    }
    memset(out_output_buf, 0xFF, output_buf_size);
    output_buffer_info.output_adr_handle = (uint64_t)out_output_buf;
    output_buffer_info.output_max_size = output_buf_size;

    qr_code_data = malloc(sizeof(struct quirc_data));
    if (qr_code_data == NULL) {
        assert_non_null(qr_code_data);
        goto exit;
    }
    CreateQuircData(qr_code_data, QUIRC_DATA_TYPE_NUMERIC, payload_size);

    // Exec test target
    ret = IsaCodecQrStoreDecodingResult(&output_buffer_info, qr_code_data, NULL);

    // Check return value and output argument
    assert_int_equal(ret, kDecodeQrParamError);

exit:
    if (out_output_buf != NULL) {
        free(out_output_buf);
    }

    if (qr_code_data != NULL) {
        free(qr_code_data);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrStoreDecodingResult_OutputBufferSmall(void **state)
{
    IsaCodecQrError ret;
    IsaCodecQrOutputBuf output_buffer_info;
    struct quirc_data *qr_code_data = NULL;
    IsaCodecQrOutputInfo output_result_info;
    int payload_size = 1234;
    int32_t output_buf_size = payload_size - 1;
    void *out_output_buf = NULL;

    // For test target argument
    out_output_buf = malloc(output_buf_size);
    if (out_output_buf == NULL) {
        assert_non_null(out_output_buf);
        goto exit;
    }
    memset(out_output_buf, 0xFF, output_buf_size);
    output_buffer_info.output_adr_handle = (uint64_t)out_output_buf;
    output_buffer_info.output_max_size = output_buf_size;

    qr_code_data = malloc(sizeof(struct quirc_data));
    if (qr_code_data == NULL) {
        assert_non_null(qr_code_data);
        goto exit;
    }
    CreateQuircData(qr_code_data, QUIRC_DATA_TYPE_NUMERIC, payload_size);

    // Exec test target
    ret = IsaCodecQrStoreDecodingResult(&output_buffer_info, qr_code_data, &output_result_info);

    // Check return value and output argument
    assert_int_equal(ret, kDecodeQrOutputSizeOver);

exit:
    if (out_output_buf != NULL) {
        free(out_output_buf);
    }

    if (qr_code_data != NULL) {
        free(qr_code_data);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrStoreDecodingResult_OutputBufferEqual(void **state)
{
    IsaCodecQrError ret;
    IsaCodecQrOutputBuf output_buffer_info;
    struct quirc_data *qr_code_data = NULL;
    IsaCodecQrOutputInfo output_result_info;
    int payload_size = 1234;
    int32_t output_buf_size = payload_size;
    void *out_output_buf = NULL;

    // For test target argument
    out_output_buf = malloc(output_buf_size);
    if (out_output_buf == NULL) {
        assert_non_null(out_output_buf);
        goto exit;
    }
    memset(out_output_buf, 0xFF, output_buf_size);
    output_buffer_info.output_adr_handle = (uint64_t)out_output_buf;
    output_buffer_info.output_max_size = output_buf_size;

    qr_code_data = malloc(sizeof(struct quirc_data));
    if (qr_code_data == NULL) {
        assert_non_null(qr_code_data);
        goto exit;
    }
    CreateQuircData(qr_code_data, QUIRC_DATA_TYPE_NUMERIC, payload_size);

    // Exec test target
    ret = IsaCodecQrStoreDecodingResult(&output_buffer_info, qr_code_data, &output_result_info);

    // Check return value and output argument
    assert_int_equal(ret, kDecodeQrSuccess);
    assert_memory_equal(output_buffer_info.output_adr_handle, qr_code_data->payload, payload_size);

exit:
    if (out_output_buf != NULL) {
        free(out_output_buf);
    }

    if (qr_code_data != NULL) {
        free(qr_code_data);
    }

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaCodecQrStoreDecodingResult_DataTypeUnknown(void **state)
{
    IsaCodecQrError ret;
    IsaCodecQrOutputBuf output_buffer_info;
    struct quirc_data *qr_code_data = NULL;
    IsaCodecQrOutputInfo output_result_info;
    int payload_size = 1234;
    int32_t output_buf_size = 2 * 1024;
    void *out_output_buf = NULL;

    // For test target argument
    out_output_buf = malloc(output_buf_size);
    if (out_output_buf == NULL) {
        assert_non_null(out_output_buf);
        goto exit;
    }
    memset(out_output_buf, 0xFF, output_buf_size);
    output_buffer_info.output_adr_handle = (uint64_t)out_output_buf;
    output_buffer_info.output_max_size = output_buf_size;

    qr_code_data = malloc(sizeof(struct quirc_data));
    if (qr_code_data == NULL) {
        assert_non_null(qr_code_data);
        goto exit;
    }
    CreateQuircData(qr_code_data, 16, payload_size);

    // Exec test target
    ret = IsaCodecQrStoreDecodingResult(&output_buffer_info, qr_code_data, &output_result_info);

    // Check return value and output argument
    assert_int_equal(ret, kDecodeQrParamError);

exit:
    if (out_output_buf != NULL) {
        free(out_output_buf);
    }

    if (qr_code_data != NULL) {
        free(qr_code_data);
    }

    return;
}
#endif // CONFCONFIG_EXTERNAL_QUIRC

/*----------------------------------------------------------------------------*/

//
// main()
//

/*----------------------------------------------------------------------------*/
int main(void)
{
    const struct CMUnitTest tests[] = {
    // Initial value check for static global variable
#ifdef CONFIG_EXTERNAL_QUIRC
        cmocka_unit_test(test_IsaQrDecodeInternalInitialValueOfGlobalVariable),
#endif // CONFIG_EXTERNAL_QUIRC

    // IsaLargeHeapAlloc()
#ifdef CONFIG_EXTERNAL_QUIRC
        cmocka_unit_test(test_IsaLargeHeapAlloc_FullySuccessPool0),
        cmocka_unit_test(test_IsaLargeHeapAlloc_FullySuccessPool1),
        cmocka_unit_test(test_IsaLargeHeapAlloc_FullySuccessAlreadyAlloc),
        cmocka_unit_test(test_IsaLargeHeapAlloc_ErrorMaxOverPoolNo),
        cmocka_unit_test(test_IsaLargeHeapAlloc_ErrorAlreadyGetPool0),
        cmocka_unit_test(test_IsaLargeHeapAlloc_ErrorAlreadyGetPool1),
        cmocka_unit_test(test_IsaLargeHeapAlloc_ErrorMaxOverReqeustSizePool0),
        cmocka_unit_test(test_IsaLargeHeapAlloc_FullySuccessMaxReqeustSizePool0),
        cmocka_unit_test(test_IsaLargeHeapAlloc_ErrorMaxOverReqeustSizePool1),
        cmocka_unit_test(test_IsaLargeHeapAlloc_FullySuccessMaxReqeustSizePool1),
#endif // CONFIG_EXTERNAL_QUIRC
#ifdef CONFIG_ZXING_CPP_PORTING
        cmocka_unit_test(test_IsaLargeHeapAlloc_FullySuccess),
        cmocka_unit_test(test_IsaLargeHeapAlloc_ErrorMalloc),
#endif // CONFIG_ZXING_CPP_PORTING

    // IsaLargeHeapFree()
#ifdef CONFIG_EXTERNAL_QUIRC
        cmocka_unit_test(test_IsaLargeHeapFree_Pool0NotExecFree),
        cmocka_unit_test(test_IsaLargeHeapFree_Pool1NotExecFree),
        cmocka_unit_test(test_IsaLargeHeapFree_Pool0ExecFree),
        cmocka_unit_test(test_IsaLargeHeapFree_Pool1ExecFree),
        cmocka_unit_test(test_IsaLargeHeapFree_NotAllocateMemory),
        cmocka_unit_test(test_IsaLargeHeapFree_UnknownAddress),
#endif // CONFIG_EXTERNAL_QUIRC
#ifdef CONFIG_ZXING_CPP_PORTING
        cmocka_unit_test(test_IsaLargeHeapFree),
#endif // CONFIG_ZXING_CPP_PORTING

#ifdef CONFIG_EXTERNAL_QUIRC
        // IsaCodecQrCreateInstance()
        cmocka_unit_test(test_IsaCodecQrCreateInstance_FullySuccess),
        cmocka_unit_test(test_IsaCodecQrCreateInstance_WidthMinOver),
        cmocka_unit_test(test_IsaCodecQrCreateInstance_WidthMin),
        cmocka_unit_test(test_IsaCodecQrCreateInstance_HeightMinOver),
        cmocka_unit_test(test_IsaCodecQrCreateInstance_HeightMin),
        cmocka_unit_test(test_IsaCodecQrCreateInstance_ErrorQuircNew),
        cmocka_unit_test(test_IsaCodecQrCreateInstance_ErrorQuircrResize),

        // IsaCodecQrDetect
        cmocka_unit_test(test_IsaCodecQrDetect_FullySuccess),
        cmocka_unit_test(test_IsaCodecQrDetect_InstanceNull),
        cmocka_unit_test(test_IsaCodecQrDetect_ImageAddrNull),
        cmocka_unit_test(test_IsaCodecQrDetect_QrCodeInfoNull),
        cmocka_unit_test(test_IsaCodecQrDetect_QrCountZero),
        cmocka_unit_test(test_IsaCodecQrDetect_QrCountTwo),

        // IsaCodecQrDecodeQrCodeInfo
        cmocka_unit_test(test_IsaCodecQrDecodeQrCodeInfo_FullySuccess),
        cmocka_unit_test(test_IsaCodecQrDecodeQrCodeInfo_QrCodeInfoNull),
        cmocka_unit_test(test_IsaCodecQrDecodeQrCodeInfo_QrCodeDataNull),
        cmocka_unit_test(test_IsaCodecQrDecodeQrCodeInfo_ErrorQuircDecode),

        // IsaCodecQrStoreDecodingResult
        cmocka_unit_test(test_IsaCodecQrStoreDecodingResult_FullySuccessNumeric),
        cmocka_unit_test(test_IsaCodecQrStoreDecodingResult_FullySuccessAlpha),
        cmocka_unit_test(test_IsaCodecQrStoreDecodingResult_FullySuccessByte),
        cmocka_unit_test(test_IsaCodecQrStoreDecodingResult_FullySuccessKanji),
        cmocka_unit_test(test_IsaCodecQrStoreDecodingResult_OutputBufferInfoNull),
        cmocka_unit_test(test_IsaCodecQrStoreDecodingResult_OutputBufferAddrNull),
        cmocka_unit_test(test_IsaCodecQrStoreDecodingResult_QrCodeDataNull),
        cmocka_unit_test(test_IsaCodecQrStoreDecodingResult_OutputResultInfoNull),
        cmocka_unit_test(test_IsaCodecQrStoreDecodingResult_OutputBufferSmall),
        cmocka_unit_test(test_IsaCodecQrStoreDecodingResult_OutputBufferEqual),
        cmocka_unit_test(test_IsaCodecQrStoreDecodingResult_DataTypeUnknown),
#endif // CONFIG_EXTERNAL_QUIRC
    };

    return (((cmocka_run_group_tests(tests, NULL, NULL)) == 0) ? 0 : 1);
}
