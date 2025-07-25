/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#ifndef SENSCORD_C_API_SENSCORD_C_API_STATUS_H_
#define SENSCORD_C_API_SENSCORD_C_API_STATUS_H_

#include <stddef.h>
#include <stdint.h>

#include "senscord/config.h"
#include "senscord/c_api/senscord_c_types.h"
#include "senscord/error_types.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

/* =============================================================
 * Status APIs
 * ============================================================= */
/**
 * @brief Gets the level of the last error that occurred.
 * @return Error level.
 */
enum senscord_error_level_t senscord_get_last_error_level(void);

/**
 * @brief Gets the cause of the last error that occurred.
 * @return Error cause.
 */
enum senscord_error_cause_t senscord_get_last_error_cause(void);

/**
 * @brief Type of error parameter.
 */
enum senscord_status_param_t {
  /** Error message. */
  SENSCORD_STATUS_PARAM_MESSAGE,
  /** Where the error occurred. */
  SENSCORD_STATUS_PARAM_BLOCK,
  /** Trace information. */
  SENSCORD_STATUS_PARAM_TRACE,
};

/**
 * @brief Gets the parameters of the last error that occurred.
 * @param[in] param  The type of parameter to get.
 * @param[out] buffer  Location to store the parameter string.
 * @param[in,out] length  [in] Buffer size.
 *                        [out] String length. (not including '\0')
 * @return 0 is success or minus is failed.
 */
int32_t senscord_get_last_error_string(
    enum senscord_status_param_t param,
    char* buffer,
    uint32_t* length);

/**
 * @brief Error status.
 */
struct senscord_status_t {
  /** Level of error. */
  enum senscord_error_level_t level;
  /** Cause of error. */
  enum senscord_error_cause_t cause;
  /** Error message. */
  const char* message;
  /** Where the error occurred. */
  const char* block;
  /** Trace information. */
  const char* trace;
};

/**
 * @brief Get information on the last error that occurred.
 * @return Error status.
 */
struct senscord_status_t senscord_get_last_error(void);

#ifdef __cplusplus
}  // extern "C"
#endif  /* __cplusplus */

#endif  /* SENSCORD_C_API_SENSCORD_C_API_STATUS_H_ */
