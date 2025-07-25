/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#ifndef SENSCORD_C_API_SENSCORD_C_API_FRAME_H_
#define SENSCORD_C_API_SENSCORD_C_API_FRAME_H_

#include <stddef.h>
#include <stdint.h>

#include "senscord/config.h"
#include "senscord/c_api/senscord_c_types.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

/* =============================================================
 * Frame APIs
 * ============================================================= */
/**
 * @brief Get the sequential number of frame.
 * @param[in]  frame         Frame handle.
 * @param[out] frame_number  The number of this frame.
 * @return 0 is success or minus is failed (error code).
 * @see Frame::GetSequenceNumber
 */
int32_t senscord_frame_get_sequence_number(
    senscord_frame_t frame,
    uint64_t* frame_number);

/**
 * @brief Get type of frame.
 * @param[in]  frame  Frame handle.
 * @param[out] type   Type of frame.
 * @return 0 is success or minus is failed (error code).
 * @see Frame::GetType
 */
int32_t senscord_frame_get_type(
    senscord_frame_t frame,
    const char** type);

/**
 * @brief Get channel count.
 * @param[in]  frame          Frame handle.
 * @param[out] channel_count  Location of channel count.
 * @return 0 is success or minus is failed (error code).
 * @see Frame::GetChannelList
 */
int32_t senscord_frame_get_channel_count(
    senscord_frame_t frame,
    uint32_t* channel_count);

/**
 * @brief Get channel data.
 * @param[in]  frame    Frame handle.
 * @param[in]  index    Index of channel list. (min=0, max=count-1)
 * @param[out] channel  Channel handle.
 * @return 0 is success or minus is failed (error code).
 * @see Frame::GetChannelList
 */
int32_t senscord_frame_get_channel(
    senscord_frame_t frame,
    uint32_t index,
    senscord_channel_t* channel);

/**
 * @brief Get channel data from channel id.
 * @param[in]  frame       Frame handle.
 * @param[in]  channel_id  Channel ID to get.
 * @param[out] channel     Channel handle.
 * @return 0 is success or minus is failed (error code).
 * @see Frame::GetChannel
 */
int32_t senscord_frame_get_channel_from_channel_id(
    senscord_frame_t frame,
    uint32_t channel_id,
    senscord_channel_t* channel);

/**
 * @brief Get the user data.
 * @param[in]  frame      Frame handle.
 * @param[out] user_data  User data.
 * @return 0 is success or minus is failed (error code).
 * @see Frame::GetUserData
 */
int32_t senscord_frame_get_user_data(
    senscord_frame_t frame,
    struct senscord_user_data_t* user_data);

#ifdef __cplusplus
}  // extern "C"
#endif  /* __cplusplus */

#endif  /* SENSCORD_C_API_SENSCORD_C_API_FRAME_H_ */
