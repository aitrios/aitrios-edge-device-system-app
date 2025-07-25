/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#ifndef SENSCORD_C_API_SENSCORD_C_API_UTILS_H_
#define SENSCORD_C_API_SENSCORD_C_API_UTILS_H_

#include <stddef.h>
#include <stdint.h>

#include "senscord/config.h"
#include "senscord/c_api/senscord_c_types.h"
#include "senscord/c_api/rawdata_c_types.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

/* =============================================================
 * Property Utility APIs
 * ============================================================= */
/**
 * @brief Set the channel id to property key.
 *
 * If "made_key == NULL" and "length != NULL",
 * the required buffer size is stored in "length".
 *
 * @param[in] key  Property key.
 * @param[in] channel_id  Channel ID
 * @param[out] made_key  Property key + Channel ID
 * @param[in,out] length  [in] made_key buffer size.
 *                        [out] made_key length.
 * @return 0 is success or minus is failed.
 */
int32_t senscord_property_key_set_channel_id(
    const char* key,
    uint32_t channel_id,
    char* made_key,
    uint32_t* length);

#ifdef __cplusplus
}  // extern "C"
#endif  /* __cplusplus */

#endif  /* SENSCORD_C_API_SENSCORD_C_API_UTILS_H_ */
