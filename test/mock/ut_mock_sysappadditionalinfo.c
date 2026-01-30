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
#include <string.h>
#include <cmocka.h>

#include "evp/sdk_sys.h"
#include "system_app_additional_info.h"

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppAdditionalInfoCollect(StAdditionalInfoParams *info)
{
    check_expected_ptr(info);

    // Populate mock data for testing
    info->item_count = 6;

    strncpy(info->items[0].key, "edc_version", sizeof(info->items[0].key) - 1);
    strncpy(info->items[0].value, "1.0.0", sizeof(info->items[0].value) - 1);

    strncpy(info->items[1].key, "kernel_version", sizeof(info->items[1].key) - 1);
    strncpy(info->items[1].value, "5.10.0", sizeof(info->items[1].value) - 1);

    strncpy(info->items[2].key, "senscord_version", sizeof(info->items[2].key) - 1);
    strncpy(info->items[2].value, "2.0.0", sizeof(info->items[2].value) - 1);

    strncpy(info->items[3].key, "libcamera_version", sizeof(info->items[3].key) - 1);
    strncpy(info->items[3].value, "0.0.1", sizeof(info->items[3].value) - 1);

    strncpy(info->items[4].key, "imx500_firmware_version", sizeof(info->items[4].key) - 1);
    strncpy(info->items[4].value, "1.5.0", sizeof(info->items[4].value) - 1);

    strncpy(info->items[5].key, "imx500_tools_version", sizeof(info->items[5].key) - 1);
    strncpy(info->items[5].value, "1.2.0", sizeof(info->items[5].value) - 1);

    return mock_type(RetCode);
}
