/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#ifndef SENSCORD_C_API_SENSCORD_C_API_CORE_H_
#define SENSCORD_C_API_SENSCORD_C_API_CORE_H_

#include <stddef.h>
#include <stdint.h>

#include "senscord/config.h"
#include "senscord/c_api/senscord_c_types.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

/* =============================================================
 * Core APIs
 * ============================================================= */
/**
 * @brief Initialize Core, called at once.
 * @param[out] core  Core handle.
 * @return 0 is success or minus is failed (error code).
 * @see Core::Init
 */
int32_t senscord_core_init(
    senscord_core_t* core);

/**
 * @brief Initialize Core with configuration.
 * @param[out] core    Core handle.
 * @param[in]  config  Config handle.
 * @return 0 is success or minus is failed (error code).
 * @see Core::Init
 */
int32_t senscord_core_init_with_config(
    senscord_core_t* core,
    senscord_config_t config);

/**
 * @brief Finalize Core and close all opened streams.
 * @param[in] core  Core handle.
 * @return 0 is success or minus is failed (error code).
 * @see Core::Exit
 */
int32_t senscord_core_exit(
    senscord_core_t core);

/**
 * @brief Get count of supported streams list.
 * @param[in]  core   Core handle.
 * @param[out] count  Count of supported streams list.
 * @return 0 is success or minus is failed (error code).
 * @see Core::GetStreamList
 */
int32_t senscord_core_get_stream_count(
    senscord_core_t core,
    uint32_t* count);

/**
 * @brief Get supported stream information.
 * @param[in]  core         Core handle.
 * @param[in]  index        Index of supported streams list.
 *                          (min=0, max=count-1)
 * @param[out] stream_info  Location of stream information.
 * @return 0 is success or minus is failed (error code).
 * @see Core::GetStreamList
 */
int32_t senscord_core_get_stream_info(
    senscord_core_t core,
    uint32_t index,
    struct senscord_stream_type_info_t* stream_info);

/**
 * @brief Get supported stream information.
 * @param[in]  core       Core handle.
 * @param[in]  index      Index of supported streams list.
 *                        (min=0, max=count-1)
 * @param[in]  param      The type of parameter to get.
 * @param[out] buffer     Location to store the parameter string.
 * @param[in,out] length  [in] Buffer size.
 *                        [out] String length. (not including '\0')
 * @return 0 is success or minus is failed (error code).
 * @see Core::GetStreamList
 */
int32_t senscord_core_get_stream_info_string(
    senscord_core_t core,
    uint32_t index,
    enum senscord_stream_info_param_t param,
    char* buffer,
    uint32_t* length);

/**
 * @brief Get count of opened stream.
 * @param[in]  core        Core handle.
 * @param[in]  stream_key  Stream key.
 * @param[out] count       Count of opened stream.
 * @return 0 is success or minus is failed (error code).
 * @see Core::GetOpenedStreamCount
 */
int32_t senscord_core_get_opened_stream_count(
    senscord_core_t core,
    const char* stream_key,
    uint32_t* count);

/**
 * @brief Get the version of this core library.
 * @param[in]  core     Core handle.
 * @param[out] version  The version of this core library.
 * @return 0 is success or minus is failed (error code).
 * @see Core::GetVersion
 */
int32_t senscord_core_get_version(
    senscord_core_t core,
    struct senscord_version_t* version);

/**
 * @brief Open the new stream from key.
 * @param[in]  core        Core handle.
 * @param[in]  stream_key  The key of the stream to open.
 * @param[out] stream      The new stream handle.
 * @return 0 is success or minus is failed (error code).
 * @see Core::OpenStream
 */
int32_t senscord_core_open_stream(
    senscord_core_t core,
    const char* stream_key,
    senscord_stream_t* stream);

/**
 * @brief Open the new stream from key and specified config.
 * @param[in]  core        Core handle.
 * @param[in]  stream_key  The key of the stream to open.
 * @param[in]  setting     Config to open stream.
 * @param[out] stream      The new stream handle.
 * @return 0 is success or minus is failed (error code).
 * @see Core::OpenStream
 */
int32_t senscord_core_open_stream_with_setting(
    senscord_core_t core,
    const char* stream_key,
    const struct senscord_open_stream_setting_t* setting,
    senscord_stream_t* stream);

/**
 * @brief Close the opened stream.
 * @param[in] core    Core handle.
 * @param[in] stream  The opened stream handle.
 * @return 0 is success or minus is failed (error code).
 * @see Core::CloseStream
 */
int32_t senscord_core_close_stream(
    senscord_core_t core,
    senscord_stream_t stream);

#ifdef __cplusplus
}  // extern "C"
#endif  /* __cplusplus */

#endif  /* SENSCORD_C_API_SENSCORD_C_API_CORE_H_ */
