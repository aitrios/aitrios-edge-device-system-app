/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#ifndef SENSCORD_C_API_SENSCORD_C_API_ENVIRONMENT_H_
#define SENSCORD_C_API_SENSCORD_C_API_ENVIRONMENT_H_

#include <stddef.h>
#include <stdint.h>

#include "senscord/config.h"
#include "senscord/c_api/senscord_c_types.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

/* =============================================================
 * Environment APIs
 * ============================================================= */
/**
 * @brief Set the file search paths.
 *
 * Use instead of SENSCORD_FILE_PATH.
 *
 * @param[in] paths  The same format as SENSCORD_FILE_PATH.
 * @return 0 is success or minus is failed (error code).
 */
int32_t senscord_set_file_search_path(
    const char* paths);

/**
 * @brief Get the file search paths.
 *
 * If "buffer == NULL" and "length != NULL",
 * the required buffer size is stored in "length".
 *
 * @param[out] buffer  Location to store the path string.
 * @param[in,out] length  [in] Buffer size.
 *                        [out] String length. (not including '\0')
 * @return 0 is success or minus is failed (error code).
 */
int32_t senscord_get_file_search_path(
    char* buffer, uint32_t* length);

#ifdef __cplusplus
}  // extern "C"
#endif  /* __cplusplus */

#endif  /* SENSCORD_C_API_SENSCORD_C_API_ENVIRONMENT_H_ */
