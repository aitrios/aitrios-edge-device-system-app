/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#ifndef SENSCORD_C_API_SENSCORD_C_API_CONFIG_H_
#define SENSCORD_C_API_SENSCORD_C_API_CONFIG_H_

#include <stddef.h>
#include <stdint.h>

#include "senscord/config.h"
#include "senscord/c_api/senscord_c_types.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

/* =============================================================
 * Configuration APIs
 * ============================================================= */
/**
 * @brief Creates the config.
 * @param[out] config  Config handle.
 * @return 0 is success or minus is failed (error code).
 */
int32_t senscord_config_create(
    senscord_config_t* config);

/**
 * @brief Deletes the config.
 * @param[in] config  Config handle.
 * @return 0 is success or minus is failed (error code).
 */
int32_t senscord_config_destroy(
    senscord_config_t config);

/**
 * @brief Adds a stream.
 * @param[in] config         Config handle.
 * @param[in] stream_key     Stream key.
 * @param[in] instance_name  Component instance name.
 * @param[in] stream_type    Stream type.
 * @param[in] port_id        Port id.
 * @return 0 is success or minus is failed (error code).
 */
int32_t senscord_config_add_stream(
    senscord_config_t config,
    const char* stream_key,
    const char* instance_name,
    const char* stream_type,
    int32_t port_id);

/**
 * @brief Sets the buffering mode of the stream.
 * @param[in] config      Config handle.
 * @param[in] stream_key  Stream key.
 * @param[in] buffering   Buffering setting.
 * @param[in] num         Buffering frame number.
 * @param[in] format      Buffering format.
 * @return 0 is success or minus is failed (error code).
 */
int32_t senscord_config_set_stream_buffering(
    senscord_config_t config,
    const char* stream_key,
    enum senscord_buffering_t buffering,
    int32_t num,
    enum senscord_buffering_format_t format);

/**
 * @brief Adds a stream argument.
 * @param[in] config          Config handle.
 * @param[in] stream_key      Stream key.
 * @param[in] argument_name   Argument name.
 * @param[in] argument_value  Argument value.
 * @return 0 is success or minus is failed (error code).
 */
int32_t senscord_config_add_stream_argument(
    senscord_config_t config,
    const char* stream_key,
    const char* argument_name,
    const char* argument_value);

/**
 * @brief Adds an instance.
 * @param[in] config          Config handle.
 * @param[in] instance_name   Component instance name.
 * @param[in] component_name  Component library name.
 * @return 0 is success or minus is failed (error code).
 */
int32_t senscord_config_add_instance(
    senscord_config_t config,
    const char* instance_name,
    const char* component_name);

/**
 * @brief Adds an instance argument.
 * @param[in] config          Config handle.
 * @param[in] instance_name   Component instance name.
 * @param[in] argument_name   Argument name.
 * @param[in] argument_value  Argument value.
 * @return 0 is success or minus is failed (error code).
 */
int32_t senscord_config_add_instance_argument(
    senscord_config_t config,
    const char* instance_name,
    const char* argument_name,
    const char* argument_value);

/**
 * @brief Adds an instance allocator.
 * @param[in] config          Config handle.
 * @param[in] instance_name   Component instance name.
 * @param[in] allocator_key   Allocator key.
 * @param[in] allocator_name  Allocator name.
 * @return 0 is success or minus is failed (error code).
 */
int32_t senscord_config_add_instance_allocator(
    senscord_config_t config,
    const char* instance_name,
    const char* allocator_key,
    const char* allocator_name);

/**
 * @brief Adds an allocator.
 * @param[in] config         Config handle.
 * @param[in] allocator_key  Allocator key.
 * @param[in] type           Allocator type.
 * @param[in] cacheable      Cacheable or not.
 * @return 0 is success or minus is failed (error code).
 */
int32_t senscord_config_add_allocator(
    senscord_config_t config,
    const char* allocator_key,
    const char* type,
    int32_t cacheable);

/**
 * @brief Adds an allocator argument.
 * @param[in] config          Config handle.
 * @param[in] allocator_key   Allocator key.
 * @param[in] argument_name   Argument name.
 * @param[in] argument_value  Argument value.
 * @return 0 is success or minus is failed (error code).
 */
int32_t senscord_config_add_allocator_argument(
    senscord_config_t config,
    const char* allocator_key,
    const char* argument_name,
    const char* argument_value);

/**
 * @brief Adds a converter.
 * @param[in] config  Config handle.
 * @param[in] converter_name   Converter name.
 * @param[in] enable_property  Enable Property conversion.
 * @param[in] enable_rawdata   Enable RawData conversion.
 * @return 0 is success or minus is failed (error code).
 */
int32_t senscord_config_add_converter(
    senscord_config_t config,
    const char* converter_name,
    int32_t enable_property,
    int32_t enable_rawdata);

#ifdef __cplusplus
}  // extern "C"
#endif  /* __cplusplus */

#endif  /* SENSCORD_C_API_SENSCORD_C_API_CONFIG_H_ */
