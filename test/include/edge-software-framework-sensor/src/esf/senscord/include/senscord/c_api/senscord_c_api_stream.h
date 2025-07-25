/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#ifndef SENSCORD_C_API_SENSCORD_C_API_STREAM_H_
#define SENSCORD_C_API_SENSCORD_C_API_STREAM_H_

#include <stddef.h>
#include <stdint.h>

#include "senscord/config.h"
#include "senscord/c_api/senscord_c_types.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

/* =============================================================
 * Stream APIs
 * ============================================================= */
/**
 * @brief Start stream.
 * @param[in] stream  Stream handle.
 * @return 0 is success or minus is failed (error code).
 * @see Stream::Start
 */
int32_t senscord_stream_start(
    senscord_stream_t stream);

/**
 * @brief Stop stream.
 * @param[in] stream  Stream handle.
 * @return 0 is success or minus is failed (error code).
 * @see Stream::Stop
 */
int32_t senscord_stream_stop(
    senscord_stream_t stream);

/**
 * @brief Get the received frame.
 * @param[in]  stream        Stream handle.
 * @param[out] frame         Location of received frame.
 * @param[in]  timeout_msec  Time of wait msec if no received.
 *                           0 is polling, minus is forever.
 * @return 0 is success or minus is failed (error code).
 * @see Stream::GetFrame
 * @see SENSCORD_TIMEOUT_POLLING, SENSCORD_TIMEOUT_FOREVER
 */
int32_t senscord_stream_get_frame(
    senscord_stream_t stream,
    senscord_frame_t* frame,
    int32_t timeout_msec);

/**
 * @brief Release the gotten frame.
 * @param[in] stream  Stream handle.
 * @param[in] frame   Received frame by senscord_stream_get_frame().
 * @return 0 is success or minus is failed (error code).
 * @see Stream::ReleaseFrame
 */
int32_t senscord_stream_release_frame(
    senscord_stream_t stream,
    senscord_frame_t frame);

/**
 * @brief Release the gotten frame.
 *
 * Use this function if you do not refer to the raw data of the channel.
 *
 * @param[in] stream  Stream handle.
 * @param[in] frame   Received frame by senscord_stream_get_frame().
 * @return 0 is success or minus is failed (error code).
 * @see Stream::ReleaseFrameUnused
 */
int32_t senscord_stream_release_frame_unused(
    senscord_stream_t stream,
    senscord_frame_t frame);

/**
 * @brief Clear frames have not gotten.
 * @param[in]  stream        Stream handle.
 * @param[out] frame_number  Number of cleared frames. (optional)
 * @return 0 is success or minus is failed (error code).
 * @see Stream::ClearFrames
 */
int32_t senscord_stream_clear_frames(
    senscord_stream_t stream,
    int32_t* frame_number);

/**
 * @brief Get the property.
 * @param[in]  stream        Stream handle.
 * @param[in]  property_key  Key of property to get.
 * @param[in,out] value      Pointer to the structure of the property.
 * @param[in]  value_size    Size of property structure.
 * @return 0 is success or minus is failed (error code).
 * @see Stream::GetProperty
 */
int32_t senscord_stream_get_property(
    senscord_stream_t stream,
    const char* property_key,
    void* value,
    size_t value_size);

/**
 * @brief Set the property with key.
 * @param[in] stream        Stream handle.
 * @param[in] property_key  Key of property to set.
 * @param[in] value         Pointer to the structure of the property.
 * @param[in] value_size    Size of property structure.
 * @return 0 is success or minus is failed (error code).
 * @see Stream::SetProperty
 */
int32_t senscord_stream_set_property(
    senscord_stream_t stream,
    const char* property_key,
    const void* value,
    size_t value_size);

/**
 * @brief Get the serialized property.
 * @param[in]  stream        Stream handle.
 * @param[in]  property_key  Key of property to get.
 * @param[in,out] buffer     Buffer that stores output property values.
 * @param[in]  buffer_size   Buffer size.
 * @param[out] output_size   Size of output property. (optional)
 * @return 0 is success or minus is failed (error code).
 * @see Stream::GetProperty
 */
int32_t senscord_stream_get_serialized_property(
    senscord_stream_t stream,
    const char* property_key,
    void* buffer,
    size_t buffer_size,
    size_t* output_size);

/**
 * @brief Set the serialized property with key.
 * @param[in] stream        Stream handle.
 * @param[in] property_key  Key of property to set.
 * @param[in] buffer        Buffer that contains input property values.
 * @param[in] buffer_size   Buffer size.
 * @return 0 is success or minus is failed (error code).
 * @see Stream::SetProperty
 */
int32_t senscord_stream_set_serialized_property(
    senscord_stream_t stream,
    const char* property_key,
    const void* buffer,
    size_t buffer_size);

/**
 * @brief Get the user data property.
 * @param[in]  stream       Stream handle.
 * @param[out] buffer       Buffer that stores output property values.
 * @param[in]  buffer_size  Buffer size.
 * @return 0 is success or minus is failed (error code).
 * @see Stream::GetProperty
 */
int32_t senscord_stream_get_userdata_property(
    senscord_stream_t stream,
    void* buffer,
    size_t buffer_size);

/**
 * @brief Set the user data property.
 * @param[in] stream       Stream handle.
 * @param[in] buffer       Buffer that contains input property values.
 * @param[in] buffer_size  Buffer size.
 * @return 0 is success or minus is failed (error code).
 * @see Stream::SetProperty
 */
int32_t senscord_stream_set_userdata_property(
    senscord_stream_t stream,
    const void* buffer,
    size_t buffer_size);

/**
 * @brief Get the count of supported property key on this stream.
 * @param[in]  stream  Stream handle.
 * @param[out] count   Count of supported property key.
 * @return 0 is success or minus is failed (error code).
 * @see Stream::GetPropertyList
 */
int32_t senscord_stream_get_property_count(
    senscord_stream_t stream,
    uint32_t* count);

/**
 * @brief Get the supported property key on this stream.
 * @param[in]  stream        Stream handle.
 * @param[in]  index         Index of supported property key list.
 *                           (min=0, max=count-1)
 * @param[out] property_key  Location of property key.
 * @return 0 is success or minus is failed (error code).
 * @see Stream::GetPropertyList
 */
int32_t senscord_stream_get_property_key(
    senscord_stream_t stream,
    uint32_t index,
    const char** property_key);

/**
 * @brief Get the supported property key on this stream.
 * @param[in]  stream     Stream handle.
 * @param[in]  index      Index of supported property key list.
 *                        (min=0, max=count-1)
 * @param[out] buffer     Location to store the property key string.
 * @param[in,out] length  [in] Buffer size.
 *                        [out] String length. (not including '\0')
 * @return 0 is success or minus is failed (error code).
 * @see Stream::GetPropertyList
 */
int32_t senscord_stream_get_property_key_string(
    senscord_stream_t stream,
    uint32_t index,
    char* buffer,
    uint32_t* length);

/**
 * @brief Lock to access properties.
 * @param[in] stream        Stream handle.
 * @param[in] timeout_msec  Time of wait msec if locked already.
 *                          0 is polling, minus is forever.
 * @return 0 is success or minus is failed (error code).
 * @see Stream::LockProperty
 * @see SENSCORD_TIMEOUT_POLLING, SENSCORD_TIMEOUT_FOREVER
 */
int32_t senscord_stream_lock_property(
    senscord_stream_t stream,
    int32_t timeout_msec);

/**
 * @brief Lock to access properties (specify key).
 * @param[in] stream         Stream handle.
 * @param[in] keys           Property keys for lock targets.
 * @param[in] count          Count of property keys.
 * @param[in] timeout_msec   Time of wait msec if locked already.
 *                           0 is polling, minus is forever.
 * @param[out] lock_resource Locked properties resource.
 * @return 0 is success or minus is failed (error code).
 * @see Stream::LockProperty
 * @see SENSCORD_TIMEOUT_POLLING, SENSCORD_TIMEOUT_FOREVER
 */
int32_t senscord_stream_lock_property_with_key(
    senscord_stream_t stream,
    const char* keys[],
    uint32_t count,
    int32_t timeout_msec,
    senscord_property_lock_resource_t* lock_resource);

/**
 * @brief Unlock to access properties.
 * @param[in] stream  Stream handle.
 * @return 0 is success or minus is failed (error code).
 * @see Stream::UnlockProperty
 */
int32_t senscord_stream_unlock_property(
    senscord_stream_t stream);

/**
 * @brief Unlock to access properties (specify resource).
 * @param[in] stream        Stream handle.
 * @param[in] lock_resource Locked properties resource.
 * @return 0 is success or minus is failed (error code).
 * @see Stream::UnlockProperty
 */
int32_t senscord_stream_unlock_property_by_resource(
    senscord_stream_t stream,
    senscord_property_lock_resource_t lock_resource);

/**
 * @brief Register the callback for frame reached.
 * @param[in] stream        Stream handle.
 * @param[in] callback      Function pointer.
 * @param[in] private_data  Private data for callback.
 * @return 0 is success or minus is failed (error code).
 * @see Stream::RegisterFrameCallback
 */
int32_t senscord_stream_register_frame_callback(
    senscord_stream_t stream,
    const senscord_frame_received_callback callback,
    void* private_data);

/**
 * @brief Unregister the callback for frame reached.
 * @param[in] stream  Stream handle.
 * @return 0 is success or minus is failed (error code).
 * @see Stream::UnregisterFrameCallback
 */
int32_t senscord_stream_unregister_frame_callback(
    senscord_stream_t stream);

/**
 * @deprecated
 * @brief Register the callback for event receiving.
 * @param[in] stream        Stream handle.
 * @param[in] event_type    Event type to receive.
 * @param[in] callback      Function pointer.
 * @param[in] private_data  Private data for callback.
 * @return 0 is success or minus is failed (error code).
 * @see Stream::RegisterEventCallback
 */
int32_t senscord_stream_register_event_callback(
    senscord_stream_t stream,
    const char* event_type,
    const senscord_event_received_callback callback,
    void* private_data);

/**
 * @brief Register the callback for event receiving.
 * @param[in] stream        Stream handle.
 * @param[in] event_type    Event type to receive.
 * @param[in] callback      Function pointer.
 * @param[in] private_data  Private data for callback.
 * @return 0 is success or minus is failed (error code).
 * @see Stream::RegisterEventCallback
 */
int32_t senscord_stream_register_event_callback2(
    senscord_stream_t stream,
    const char* event_type,
    const senscord_event_received_callback2 callback,
    void* private_data);

/**
 * @brief Unregister the event callback.
 * @param[in] stream      Stream handle.
 * @param[in] event_type  Event type to receive.
 * @return 0 is success or minus is failed (error code).
 * @see Stream::UnregisterEventCallback
 */
int32_t senscord_stream_unregister_event_callback(
    senscord_stream_t stream,
    const char* event_type);

#ifdef __cplusplus
}  // extern "C"
#endif  /* __cplusplus */

#endif  /* SENSCORD_C_API_SENSCORD_C_API_STREAM_H_ */
