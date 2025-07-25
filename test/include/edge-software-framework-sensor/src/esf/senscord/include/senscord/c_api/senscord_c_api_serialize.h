/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#ifndef SENSCORD_C_API_SENSCORD_C_API_SERIALIZE_H_
#define SENSCORD_C_API_SENSCORD_C_API_SERIALIZE_H_

#include <stddef.h>
#include <stdint.h>

#include "senscord/config.h"

#ifdef SENSCORD_SERIALIZE

#include "senscord/c_api/senscord_c_types.h"
#include "senscord/c_api/property_c_types.h"
#include "senscord/c_api/rawdata_c_types.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

/* =============================================================
 * Serialize/Deserialize APIs
 * ============================================================= */
/**
 * @brief Deserialize raw data.
 * (AccelerationData, AngularVelocityData, MagneticFieldData)
 *
 * To release, you need to call the
 * senscord_release_vector3_data() function.
 *
 * @param[in]  raw_data           Raw data.
 * @param[in]  raw_data_size      Raw data size.
 * @param[out] deserialized_data  Deserialized vector3 data.
 * @return 0 is success or minus is failed (error code).
 * @see senscord_release_vector3_data
 */
int32_t senscord_deserialize_vector3_data(
    const void* raw_data, size_t raw_data_size,
    struct senscord_vector3f_t** deserialized_data);

/**
 * @brief Release Vector3 data.
 * @param[in] data  Vector3 data.
 */
void senscord_release_vector3_data(
    struct senscord_vector3f_t* data);

/**
 * @brief Deserialize raw data. (RotationData)
 *
 * To release, you need to call the
 * senscord_release_rotation_data() function.
 *
 * @param[in]  raw_data           Raw data.
 * @param[in]  raw_data_size      Raw data size.
 * @param[out] deserialized_data  Deserialized rotation data.
 * @return 0 is success or minus is failed (error code).
 * @see senscord_release_rotation_data
 */
int32_t senscord_deserialize_rotation_data(
    const void* raw_data, size_t raw_data_size,
    struct senscord_rotation_data_t** deserialized_data);

/**
 * @brief Release rotation data.
 * @param[in] data  Rotation data.
 */
void senscord_release_rotation_data(
    struct senscord_rotation_data_t* data);

/**
 * @brief Deserialize raw data. (PoseQuaternionData)
 *
 * To release, you need to call the
 * senscord_release_pose_quaternion_data() function.
 *
 * @param[in]  raw_data           Raw data.
 * @param[in]  raw_data_size      Raw data size.
 * @param[out] deserialized_data  Deserialized pose data.
 * @return 0 is success or minus is failed (error code).
 * @see senscord_release_pose_quaternion_data
 */
int32_t senscord_deserialize_pose_quaternion_data(
    const void* raw_data, size_t raw_data_size,
    struct senscord_pose_quaternion_data_t** deserialized_data);

/**
 * @brief Release Pose(quaternion) data.
 * @param[in] data  Pose data.
 */
void senscord_release_pose_quaternion_data(
    struct senscord_pose_quaternion_data_t* data);

/**
 * @brief Deserialize raw data. (PoseData)
 *
 * To release, you need to call the
 * senscord_release_pose_data() function.
 *
 * @param[in]  raw_data           Raw data.
 * @param[in]  raw_data_size      Raw data size.
 * @param[out] deserialized_data  Deserialized pose data.
 * @return 0 is success or minus is failed (error code).
 * @see senscord_release_pose_data
 * @deprecated will be replaced by senscord_deserialize_pose_quaternion_data
 */
int32_t senscord_deserialize_pose_data(
    const void* raw_data, size_t raw_data_size,
    struct senscord_pose_data_t** deserialized_data);

/**
 * @brief Release Pose data.
 * @param[in] data  Pose data.
 * @deprecated will be replaced by senscord_release_pose_quaternion_data
 */
void senscord_release_pose_data(struct senscord_pose_data_t* data);

/**
 * @brief Deserialize raw data. (PoseMatrixData)
 *
 * To release, you need to call the
 * senscord_release_pose_matrix_data() function.
 *
 * @param[in]  raw_data           Raw data.
 * @param[in]  raw_data_size      Raw data size.
 * @param[out] deserialized_data  Deserialized pose data.
 * @return 0 is success or minus is failed (error code).
 * @see senscord_release_pose_matrix_data
 */
int32_t senscord_deserialize_pose_matrix_data(
    const void* raw_data, size_t raw_data_size,
    struct senscord_pose_matrix_data_t** deserialized_data);

/**
 * @brief Release Pose(rotation matrix) data.
 * @param[in] data  Pose data.
 */
void senscord_release_pose_matrix_data(
    struct senscord_pose_matrix_data_t* data);

/**
 * @brief Deserialize raw data. (object_detection_data)
 *
 * To release, you need to call the
 * senscord_release_object_detection_data() function.
 *
 * @param[in]  raw_data           Raw data.
 * @param[in]  raw_data_size      Raw data size.
 * @param[out] deserialized_data  Deserialized Object Detection data.
 * @return 0 is success or minus is failed (error code).
 * @see senscord_release_object_detection_data
 */
int32_t senscord_deserialize_object_detection_data(
    const void* raw_data, size_t raw_data_size,
    struct senscord_object_detection_data_t** deserialized_data);

/**
 * @brief Release object_detection_data.
 * @param[in] data  Object Detection Data.
 */
void senscord_release_object_detection_data(
    struct senscord_object_detection_data_t* data);

/**
 * @brief Deserialize raw data. (key_point_data)
 *
 * To release, you need to call the
 * senscord_release_key_point_data() function.
 *
 * @param[in]  raw_data           Raw data.
 * @param[in]  raw_data_size      Raw data size.
 * @param[out] deserialized_data  Deserialized Key Point data.
 * @return 0 is success or minus is failed (error code).
 * @see senscord_release_key_point_data
 */
int32_t senscord_deserialize_key_point_data(
    const void* raw_data, size_t raw_data_size,
    struct senscord_key_point_data_t** deserialized_data);

/**
 * @brief Release key_point_data.
 * @param[in] data  Key Point Data.
 */
void senscord_release_key_point_data(
    struct senscord_key_point_data_t* data);

/**
 * @brief Deserialize raw data. (object_tracking_data)
 *
 * To release, you need to call the
 * senscord_release_object_tracking_data() function.
 *
 * @param[in]  raw_data           Raw data.
 * @param[in]  raw_data_size      Raw data size.
 * @param[out] deserialized_data  Deserialized Object Tracking data.
 * @return 0 is success or minus is failed (error code).
 * @see senscord_release_object_tracking_data
 */
int32_t senscord_deserialize_object_tracking_data(
    const void* raw_data, size_t raw_data_size,
    struct senscord_object_tracking_data_t** deserialized_data);

/**
 * @brief Release object_tracking_data.
 * @param[in] data  Object Tracking Data.
 */
void senscord_release_object_tracking_data(
    struct senscord_object_tracking_data_t* data);

#ifdef __cplusplus
}  // extern "C"
#endif  /* __cplusplus */

#endif  /* SENSCORD_SERIALIZE */
#endif  /* SENSCORD_C_API_SENSCORD_C_API_SERIALIZE_H_ */
