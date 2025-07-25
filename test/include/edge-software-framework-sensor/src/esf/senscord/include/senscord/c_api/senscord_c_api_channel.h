/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#ifndef SENSCORD_C_API_SENSCORD_C_API_CHANNEL_H_
#define SENSCORD_C_API_SENSCORD_C_API_CHANNEL_H_

#include <stddef.h>
#include <stdint.h>

#include "senscord/config.h"
#include "senscord/c_api/senscord_c_types.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

/* =============================================================
 * Channel APIs
 * ============================================================= */
/**
 * @brief Get the channel ID.
 * @param[in]  channel     Channel handle.
 * @param[out] channel_id  Channel ID.
 * @return 0 is success or minus is failed (error code).
 * @see Channel::GetChannelId
 */
int32_t senscord_channel_get_channel_id(
    senscord_channel_t channel,
    uint32_t* channel_id);

/**
 * @brief Get the raw data.
 * @param[in]  channel   Channel handle.
 * @param[out] raw_data  Raw data.
 * @return 0 is success or minus is failed (error code).
 * @see Channel::GetRawData
 */
int32_t senscord_channel_get_raw_data(
    senscord_channel_t channel,
    struct senscord_raw_data_t* raw_data);

/**
 * @brief Convert the raw data.
 * @param[in]  channel         Channel handle.
 * @param[out] output_rawdata  Pointer to the structure of the rawdata.
 * @param[out] output_size     Size of rawdata structure.
 * @return 0 is success or minus is failed (error code).
 */
int32_t senscord_channel_convert_rawdata(
    senscord_channel_t channel,
    void* output_rawdata,
    size_t output_size);

/**
 * @brief Get the property related to this channel.
 * @param[in]  channel       Channel handle.
 * @param[in]  property_key  Key of property to get.
 * @param[out] value         Pointer to the structure of the property.
 * @param[in]  value_size    Size of property structure.
 * @return 0 is success or minus is failed (error code).
 * @see Channel::GetProperty
 */
int32_t senscord_channel_get_property(
    senscord_channel_t channel,
    const char* property_key,
    void* value,
    size_t value_size);

/**
 * @brief Get the serialized property related to this raw data.
 * @param[in]  channel       Channel handle.
 * @param[in]  property_key  Key of property to get.
 * @param[out] buffer        Buffer that stores output property values.
 * @param[in]  buffer_size   Buffer size.
 * @param[out] output_size   Size of output property. (optional)
 * @return 0 is success or minus is failed (error code).
 * @see Channel::GetProperty
 */
int32_t senscord_channel_get_serialized_property(
    senscord_channel_t channel,
    const char* property_key,
    void* buffer,
    size_t buffer_size,
    size_t* output_size);

/**
 * @brief Get the count of stored property key on this channel.
 * @param[in]  channel  Channel handle.
 * @param[out] count    Count of stored property key.
 * @return 0 is success or minus is failed (error code).
 * @see Channel::GetPropertyList
 */
int32_t senscord_channel_get_property_count(
    senscord_channel_t channel,
    uint32_t* count);

/**
 * @brief Get the stored property key on this channel.
 * @param[in]  channel       Channel handle.
 * @param[in]  index         Index of stored property key list.
 *                           (min=0, max=count-1)
 * @param[out] property_key  Location of property key.
 * @return 0 is success or minus is failed (error code).
 * @see Channel::GetPropertyList
 */
int32_t senscord_channel_get_property_key(
    senscord_channel_t channel,
    uint32_t index,
    const char** property_key);

/**
 * @brief Get the stored property key on this channel.
 * @param[in]  channel    Channel handle.
 * @param[in]  index      Index of stored property key list.
 *                        (min=0, max=count-1)
 * @param[out] buffer     Location to store the property key string.
 * @param[in,out] length  [in] Buffer size.
 *                        [out] String length. (not including '\0')
 * @return 0 is success or minus is failed (error code).
 * @see Channel::GetPropertyList
 */
int32_t senscord_channel_get_property_key_string(
    senscord_channel_t channel,
    uint32_t index,
    char* buffer,
    uint32_t* length);

/**
 * @brief Get the count of updated property key on this channel.
 * @param[in]  channel  Channel handle.
 * @param[out] count    Count of updated property key.
 * @return 0 is success or minus is failed (error code).
 * @see Channel::GetUpdatedPropertyList
 */
int32_t senscord_channel_get_updated_property_count(
    senscord_channel_t channel,
    uint32_t* count);

/**
 * @brief Get the updated property key on this channel.
 * @param[in]  channel       Channel handle.
 * @param[in]  index         Index of updated property key list.
 *                           (min=0, max=count-1)
 * @param[out] property_key  Location of property key.
 * @return 0 is success or minus is failed (error code).
 * @see Channel::GetUpdatedPropertyList
 */
int32_t senscord_channel_get_updated_property_key(
    senscord_channel_t channel,
    uint32_t index,
    const char** property_key);

/**
 * @brief Get the updated property key on this channel.
 * @param[in]  channel    Channel handle.
 * @param[in]  index      Index of updated property key list.
 *                        (min=0, max=count-1)
 * @param[out] buffer     Location to store the property key string.
 * @param[in,out] length  [in] Buffer size.
 *                        [out] String length. (not including '\0')
 * @return 0 is success or minus is failed (error code).
 * @see Channel::GetUpdatedPropertyList
 */
int32_t senscord_channel_get_updated_property_key_string(
    senscord_channel_t channel,
    uint32_t index,
    char* buffer,
    uint32_t* length);

#ifdef __cplusplus
}  // extern "C"
#endif  /* __cplusplus */

#endif  /* SENSCORD_C_API_SENSCORD_C_API_CHANNEL_H_ */
