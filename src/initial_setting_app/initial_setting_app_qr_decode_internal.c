/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#include "initial_setting_app_qr_decode_internal.h"         // for IsaCodecQrCreateInstance, IsaC...
#include "initial_setting_app_qr_decode_internal_private.h" // for private define of this file

#include <inttypes.h> // for uint8_t, int32_t, uint64_t
#include <stdio.h>    // for NULL
#include <string.h>   // for memcpy

#if defined(__NuttX__)
#include <nuttx/config.h>
#endif

#ifdef CONFIG_EXTERNAL_QUIRC
#include "quirc/lib/quirc.h" // for quirc_data, quirc_begin, quirc...
#endif

#include "initial_setting_app_qr_decode.h" // for IsaCodecQrOutputInfo, kDecodeQrParamE...
#include "initial_setting_app_util.h"      // for Common definitions

#include "initial_setting_app_log.h"
#include "memory_manager.h" // for EsfMemoryManagerWasmAlloc/Free, kEsfMemoryManager...

/****************************************************************************
 * Large heap memory allocate / free.
 ****************************************************************************/
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
uint8_t *g_linear_pool_address = NULL;
uint8_t g_pool_used[2] = {0, 0};
#endif

void *IsaLargeHeapAlloc(uint32_t pool_no, size_t request_size)
{
    ISA_DBG("IsaLargeHeapAlloc(pool_no:%u, req_size:%zu)", pool_no, request_size);
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
    if (g_linear_pool_address == NULL) {
        g_linear_pool_address = (void *)EsfMemoryManagerWasmAllocate(
            kEsfMemoryManagerWasmAllocForLinearMemory, LINEAR_POOL_SIZE);
        g_pool_used[0] = 0;
        g_pool_used[1] = 0;
    }
    if ((pool_no < 2) && (g_pool_used[pool_no] != 0)) {
        ISA_ERR("IsaLargeHeapAlloc(pool_no:%u,...) Pool already used.", pool_no);
        return NULL;
    }
    if (pool_no == 0) {
        if (request_size <= POOL_0_SIZE) {
            g_pool_used[0] = 1;
            return (void *)g_linear_pool_address;
        }
    }
    else if (pool_no == 1) {
        if (request_size <= POOL_1_SIZE) {
            g_pool_used[1] = 1;
            return (void *)(g_linear_pool_address + POOL_0_SIZE);
        }
    }
    else {
        /* Pool number is out of range, memory cannot obtain and NULL return */
    }
    ISA_ERR("IsaLargeHeapAlloc(pool_no:%u, req_size:%zu) No memory space.", pool_no, request_size);
    return NULL;
#else /* T5 */
    return malloc(request_size);
#endif
}

void IsaLargeHeapFree(void *memory_address)
{
    ISA_DBG("IsaLargeHeapFree(%p)", memory_address);
#ifdef CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
    if (memory_address == g_linear_pool_address) { /* pool_no : 0 */
        g_pool_used[0] = 0;
    }
    else if (memory_address == (g_linear_pool_address + POOL_0_SIZE)) { /* pool_no : 1 */
        g_pool_used[1] = 0;
    }
    else {
        ISA_ERR("IsaLargeHeapFree(%p) Unknown address.", memory_address);
    }
    if ((g_pool_used[0] == 0) && (g_pool_used[1] == 0)) {
        if (g_linear_pool_address != NULL) {
            EsfMemoryManagerWasmFree(kEsfMemoryManagerWasmAllocForLinearMemory,
                                     g_linear_pool_address);
        }
    }
#else /* T5 */
    return free(memory_address);
#endif
}

#ifdef CONFIG_EXTERNAL_QUIRC
struct quirc *IsaCodecQrCreateInstance(int32_t width, int32_t height)
{
    // Parameter check.
    if ((width <= 0) || (height <= 0)) {
        ISA_ERR("IsaCodecQrCreateInstance(%d, %d)", width, height);
        return (struct quirc *)NULL;
    }

    // Instantiate a quirc object
    struct quirc *instance = quirc_new();
    if (instance == (struct quirc *)NULL) {
        ISA_ERR("quirc_new");
        return (struct quirc *)NULL;
    }

    if (quirc_resize(instance, width, height) < 0) {
        ISA_ERR("quirc_resize");
        quirc_destroy(instance);
        return (struct quirc *)NULL;
    }

    return instance;
}

IsaCodecQrError IsaCodecQrDetect(uint64_t image_addr, struct quirc_code *qr_code_info,
                                 struct quirc *instance)
{
    // Parameter check.
    if ((instance == (struct quirc *)NULL) || (image_addr == 0U) ||
        (qr_code_info == (struct quirc_code *)NULL)) {
        ISA_ERR("IsaCodecQrDetect(%" PRIx64 ", %p, %p)", image_addr, qr_code_info, instance);
        return kDecodeQrParamError;
    }

    {
        int width = 0;
        int height = 0;
        uint8_t *image_buffer = quirc_begin(instance, &width, &height);
        memcpy(image_buffer, (uint8_t *)(uintptr_t)image_addr, width * height);
        quirc_end(instance);
    }

    {
        int num_codes = quirc_count(instance);
        if (num_codes <= 0) {
            ISA_ERR("quirc_count(%d)", num_codes);
            return kDecodeQrNotDetectError;
        }
        else if (num_codes >= 2) { // Multiple QR code detection is not supported.
            ISA_ERR("quirc_count(%d)", num_codes);
            return kDecodeQrDetectCountError;
        }
    }

    // The index is specified as zero since the detection of one QR code is
    // confirmed.
    quirc_extract(instance, 0, qr_code_info);

    return kDecodeQrSuccess;
}

IsaCodecQrError IsaCodecQrDecodeQrCodeInfo(const struct quirc_code *qr_code_info,
                                           struct quirc_data *qr_code_data)
{
    // Parameter check.
    if ((qr_code_info == (struct quirc_code *)NULL) ||
        (qr_code_data == (struct quirc_data *)NULL)) {
        ISA_ERR("IsaCodecQrDecodeQrCodeInfo(%p, %p)", qr_code_info, qr_code_data);
        return kDecodeQrParamError;
    }

    quirc_decode_error_t error = quirc_decode(qr_code_info, qr_code_data);
    if (error != QUIRC_SUCCESS) {
        ISA_ERR("quirc_decode(%d)", error);
        return kDecodeQrDecodeError;
    }

    return kDecodeQrSuccess;
}

IsaCodecQrError IsaCodecQrStoreDecodingResult(const IsaCodecQrOutputBuf *output_buffer_info,
                                              const struct quirc_data *qr_code_data,
                                              IsaCodecQrOutputInfo *output_result_info)
{
    // Parameter check.
    if ((output_buffer_info == (IsaCodecQrOutputBuf *)NULL) ||
        (output_buffer_info->output_adr_handle == 0U) ||
        (qr_code_data == (struct quirc_data *)NULL) ||
        (output_result_info == (IsaCodecQrOutputInfo *)NULL)) {
        ISA_ERR("IsaCodecQrStoreDecodingResult(%p, %p, %p)", output_buffer_info, qr_code_data,
                output_result_info);
        return kDecodeQrParamError;
    }

    // Size check.
    if (output_buffer_info->output_max_size < qr_code_data->payload_len) {
        ISA_ERR("output_max_size = %d, payload_len = %d", output_buffer_info->output_max_size,
                qr_code_data->payload_len);
        return kDecodeQrOutputSizeOver;
    }

    switch (qr_code_data->data_type) {
        case QUIRC_DATA_TYPE_NUMERIC:
            output_result_info->output_type = kDecodeQrOutputNumeric;
            break;
        case QUIRC_DATA_TYPE_ALPHA:
            output_result_info->output_type = kDecodeQrOutputAlphanumeric;
            break;
        case QUIRC_DATA_TYPE_BYTE:
            output_result_info->output_type = kDecodeQrOutputBinary;
            break;
        case QUIRC_DATA_TYPE_KANJI:
            output_result_info->output_type = kDecodeQrOutputKanji;
            break;
        default:
            ISA_ERR("data_type = %d", qr_code_data->data_type);
            return kDecodeQrParamError;
    }

    memcpy((uint8_t *)(uintptr_t)output_buffer_info->output_adr_handle, qr_code_data->payload,
           qr_code_data->payload_len);
    output_result_info->output_size = qr_code_data->payload_len;

    return kDecodeQrSuccess;
}
#endif // CONFIG_EXTERNAL_QUIRC
