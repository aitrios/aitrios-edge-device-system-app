/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#ifndef SENSCORD_C_API_SENSCORD_C_API_EVENT_ARGUMENT_H_
#define SENSCORD_C_API_SENSCORD_C_API_EVENT_ARGUMENT_H_

#include <stddef.h>
#include <stdint.h>

#include "senscord/config.h"
#include "senscord/c_api/senscord_c_types.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

/* =============================================================
 * Event argument APIs
 * ============================================================= */
/**
 * @brief Gets the int8_t value of the specified key.
 * @param[in] args  Event argument handle.
 * @param[in] key  Argument key.
 * @param[out] value  Location to store the value.
 * @return 0 is success or minus is failed.
 */
int32_t senscord_event_argument_getvalue_int8(
    senscord_event_argument_t args, const char* key,
    int8_t* value);

/**
 * @brief Gets the int16_t value of the specified key.
 * @param[in] args  Event argument handle.
 * @param[in] key  Argument key.
 * @param[out] value  Location to store the value.
 * @return 0 is success or minus is failed.
 */
int32_t senscord_event_argument_getvalue_int16(
    senscord_event_argument_t args, const char* key,
    int16_t* value);

/**
 * @brief Gets the int32_t value of the specified key.
 * @param[in] args  Event argument handle.
 * @param[in] key  Argument key.
 * @param[out] value  Location to store the value.
 * @return 0 is success or minus is failed.
 */
int32_t senscord_event_argument_getvalue_int32(
    senscord_event_argument_t args, const char* key,
    int32_t* value);

/**
 * @brief Gets the int64_t value of the specified key.
 * @param[in] args  Event argument handle.
 * @param[in] key  Argument key.
 * @param[out] value  Location to store the value.
 * @return 0 is success or minus is failed.
 */
int32_t senscord_event_argument_getvalue_int64(
    senscord_event_argument_t args, const char* key,
    int64_t* value);

/**
 * @brief Gets the uint8_t value of the specified key.
 * @param[in] args  Event argument handle.
 * @param[in] key  Argument key.
 * @param[out] value  Location to store the value.
 * @return 0 is success or minus is failed.
 */
int32_t senscord_event_argument_getvalue_uint8(
    senscord_event_argument_t args, const char* key,
    uint8_t* value);

/**
 * @brief Gets the uint16_t value of the specified key.
 * @param[in] args  Event argument handle.
 * @param[in] key  Argument key.
 * @param[out] value  Location to store the value.
 * @return 0 is success or minus is failed.
 */
int32_t senscord_event_argument_getvalue_uint16(
    senscord_event_argument_t args, const char* key,
    uint16_t* value);

/**
 * @brief Gets the uint32_t value of the specified key.
 * @param[in] args  Event argument handle.
 * @param[in] key  Argument key.
 * @param[out] value  Location to store the value.
 * @return 0 is success or minus is failed.
 */
int32_t senscord_event_argument_getvalue_uint32(
    senscord_event_argument_t args, const char* key,
    uint32_t* value);

/**
 * @brief Gets the uint64_t value of the specified key.
 * @param[in] args  Event argument handle.
 * @param[in] key  Argument key.
 * @param[out] value  Location to store the value.
 * @return 0 is success or minus is failed.
 */
int32_t senscord_event_argument_getvalue_uint64(
    senscord_event_argument_t args, const char* key,
    uint64_t* value);

/**
 * @brief Gets the float value of the specified key.
 * @param[in] args  Event argument handle.
 * @param[in] key  Argument key.
 * @param[out] value  Location to store the value.
 * @return 0 is success or minus is failed.
 */
int32_t senscord_event_argument_getvalue_float(
    senscord_event_argument_t args, const char* key,
    float* value);

/**
 * @brief Gets the double value of the specified key.
 * @param[in] args  Event argument handle.
 * @param[in] key  Argument key.
 * @param[out] value  Location to store the value.
 * @return 0 is success or minus is failed.
 */
int32_t senscord_event_argument_getvalue_double(
    senscord_event_argument_t args, const char* key,
    double* value);

/**
 * @brief Gets the string of the specified key.
 *
 * If "buffer == NULL" and "length != NULL",
 * the required buffer size is stored in "length".
 *
 * @param[in] args  Event argument handle.
 * @param[in] key  Argument key.
 * @param[out] buffer  Location to store the string.
 * @param[in,out] length  [in] Buffer size.
 *                        [out] String length. (not including '\0')
 * @return 0 is success or minus is failed.
 */
int32_t senscord_event_argument_getvalue_string(
    senscord_event_argument_t args, const char* key,
    char* buffer, uint32_t* length);

/**
 * @brief Gets the binary array of the specified key.
 *
 * If "buffer == NULL" and "length != NULL",
 * the required buffer size is stored in "length".
 *
 * @param[in] args  Event argument handle.
 * @param[in] key  Argument key.
 * @param[out] buffer  Location to store the binary array.
 * @param[in,out] length  [in] Buffer size.
 *                        [out] Length of binary array.
 * @return 0 is success or minus is failed.
 */
int32_t senscord_event_argument_getvalue_binary(
    senscord_event_argument_t args, const char* key,
    void* buffer, uint32_t* length);

/**
 * @brief Gets the serialized binary array of the specified key.
 *
 * If "buffer == NULL" and "length != NULL",
 * the required buffer size is stored in "length".
 *
 * @param[in] args  Event argument handle.
 * @param[in] key  Argument key.
 * @param[out] buffer  Location to store the binary array.
 * @param[in,out] length  [in] Buffer size.
 *                        [out] Length of binary array.
 * @return 0 is success or minus is failed.
 */
int32_t senscord_event_argument_get_serialized_binary(
    senscord_event_argument_t args, const char* key,
    void* buffer, uint32_t* length);

/**
 * @brief Get the number of elements.
 * @param[in] args  Event argument handle.
 * @param[out] count  Location to store the number of elements.
 * @return 0 is success or minus is failed.
 */
int32_t senscord_event_argument_get_element_count(
    senscord_event_argument_t args, uint32_t* count);

/**
 * @brief Gets the key at the specified index.
 * @param[in] args  Event argument handle.
 * @param[in] index  Index (0 to elements-1)
 * @param[out] buffer  Location to store the string.
 * @param[in,out] length  [in] Buffer size.
 *                        [out] String length. (not including '\0')
 * @return 0 is success or minus is failed.
 */
int32_t senscord_event_argument_get_key_string(
    senscord_event_argument_t args, uint32_t index,
    char* buffer, uint32_t* length);

/**
 * @brief Gets the key at the specified index.
 * @param[in] args  Event argument handle.
 * @param[in] index  Index (0 to elements-1)
 * @return String pointer. Returns NULL if invalid.
 */
const char* senscord_event_argument_get_key(
    senscord_event_argument_t args, uint32_t index);

#ifdef __cplusplus
}  // extern "C"
#endif  /* __cplusplus */

#endif  /* SENSCORD_C_API_SENSCORD_C_API_EVENT_ARGUMENT_H_ */
