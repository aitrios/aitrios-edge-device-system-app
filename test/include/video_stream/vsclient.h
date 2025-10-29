/*
 * SPDX-FileCopyrightText: 2025 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef VSCLIENT_H
#define VSCLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "wire_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

// Return codes for all library functions
typedef enum {
    VSCLIENT_SUCCESS = 0,
    VSCLIENT_ERROR_CONNECTION_FAILED = -1,
    VSCLIENT_ERROR_ALREADY_CONNECTED = -2,
    VSCLIENT_ERROR_NOT_CONNECTED = -3,
    VSCLIENT_ERROR_SEND_FAILED = -4,
    VSCLIENT_ERROR_RECEIVE_FAILED = -5,
    VSCLIENT_ERROR_INVALID_PARAMETER = -6,
    VSCLIENT_ERROR_SERVER_ERROR = -7,
    VSCLIENT_ERROR_INVALID_RESPONSE = -8,
    VSCLIENT_ERROR_TIMEOUT = -9,
    VSCLIENT_ERROR_INVALID_STATE = -10,
    VSCLIENT_ERROR_INVALID_COMMAND = -11,
    VSCLIENT_ERROR_SYSTEM_ERROR = -12,
    VSCLIENT_ERROR_SERVER_NOT_AVAILABLE = -13,
    VSCLIENT_ERROR_PROTOCOL_ERROR = -14,
    VSCLIENT_ERROR_UNKNOWN = -99
} vsclient_result_t;

// Stream status
typedef enum { VSCLIENT_STREAM_STOPPED = 0, VSCLIENT_STREAM_STARTED = 1 } vsclient_stream_status_t;

// Use wire protocol types directly to avoid duplication
typedef wire_operating_mode_t vsclient_operating_mode_t;

// Client-specific constants for operating modes
#define VSCLIENT_MODE_STREAM_ONLY WIRE_MODE_STREAM_ONLY
#define VSCLIENT_MODE_RECORD_ONLY WIRE_MODE_RECORD_ONLY
#define VSCLIENT_MODE_STREAM_AND_RECORD WIRE_MODE_STREAM_AND_RECORD

// Use wire protocol types directly with client-friendly names
#define vsclient_nfs_config_t wire_nfs_config_t
#define vsclient_rtp_config_t wire_rtp_config_t
#define vsclient_rtsp_config_t wire_rtsp_config_t
#define vsclient_server_status_t wire_server_status_t

// Opaque client handle
typedef struct vsclient_handle vsclient_handle_t;

// Connection Management Functions (DEPRECATED - Use oneshot API instead)
/**
 * @brief Connect to video streaming server
 * @note DEPRECATED: Use oneshot API functions for better reliability and automatic connection management
 */
vsclient_result_t vsclient_connect(const char *socket_path, vsclient_handle_t **handle);

/**
 * @brief Disconnect from video streaming server
 * @note DEPRECATED: Use oneshot API functions for automatic connection management
 */
vsclient_result_t vsclient_disconnect(vsclient_handle_t *handle);

/**
 * @brief Check if client is connected
 * @note DEPRECATED: Use oneshot API functions instead
 */
bool vsclient_is_connected(const vsclient_handle_t *handle);

// Stream Control Functions (DEPRECATED - Use oneshot API instead)
/**
 * @brief Start video streaming
 * @note DEPRECATED: Use vsclient_oneshot_start_stream() instead
 */
vsclient_result_t vsclient_start_stream(vsclient_handle_t *handle);

/**
 * @brief Stop video streaming
 * @note DEPRECATED: Use vsclient_oneshot_stop_stream() instead
 */
vsclient_result_t vsclient_stop_stream(vsclient_handle_t *handle);

// RTP Configuration Functions (DEPRECATED - Use oneshot API instead)
/**
 * @brief Set video format
 * @note DEPRECATED: Use vsclient_oneshot_set_video_format() instead
 */
vsclient_result_t vsclient_set_video_format(vsclient_handle_t *handle, uint32_t width,
                                            uint32_t height, uint32_t framerate);

/**
 * @brief Set RTP clock rate
 * @note DEPRECATED: Use vsclient_oneshot_set_rtp_clock_rate() instead
 */
vsclient_result_t vsclient_set_rtp_clock_rate(vsclient_handle_t *handle, uint32_t clock_rate);

/**
 * @brief Set RTP payload type
 * @note DEPRECATED: Use vsclient_oneshot_set_rtp_payload_type() instead
 */
vsclient_result_t vsclient_set_rtp_payload_type(vsclient_handle_t *handle, uint32_t payload_type);

/**
 * @brief Set RTP channel
 * @note DEPRECATED: Use vsclient_oneshot_set_rtp_channel() instead
 */
vsclient_result_t vsclient_set_rtp_channel(vsclient_handle_t *handle, uint32_t channel);

/**
 * @brief Set RTP jitter buffer size
 * @note DEPRECATED: Use vsclient_oneshot_set_rtp_jitter_buffer_size() instead
 */
vsclient_result_t vsclient_set_rtp_jitter_buffer_size(vsclient_handle_t *handle, uint32_t size);

/**
 * @brief Set RTP packetization interval
 * @note DEPRECATED: Use vsclient_oneshot_set_rtp_packetization_interval() instead
 */
vsclient_result_t vsclient_set_rtp_packetization_interval(vsclient_handle_t *handle,
                                                          uint32_t interval);

/**
 * @brief Set RTP multicast mode
 * @note DEPRECATED: Use vsclient_oneshot_set_rtp_multicast_mode() instead
 */
vsclient_result_t vsclient_set_rtp_multicast_mode(vsclient_handle_t *handle, bool multicast);

/**
 * @brief Set RTP configuration
 * @note DEPRECATED: Use vsclient_oneshot_set_rtp_config() instead
 */
vsclient_result_t vsclient_set_rtp_config(vsclient_handle_t *handle,
                                          const vsclient_rtp_config_t *config);

/**
 * @brief Set RTP destination
 * @note DEPRECATED: Use vsclient_oneshot_set_rtp_destination() instead
 */
vsclient_result_t vsclient_set_rtp_destination(vsclient_handle_t *handle, const char *destination,
                                               uint32_t port);

/**
 * @brief Reset RTP sequence
 * @note DEPRECATED: Use vsclient_oneshot_reset_rtp_sequence() instead
 */
vsclient_result_t vsclient_reset_rtp_sequence(vsclient_handle_t *handle);

// NFS Configuration Functions - Consolidated Protocol (DEPRECATED - Use oneshot API instead)
/**
 * @brief Set NFS configuration
 * @note DEPRECATED: Use vsclient_oneshot_set_nfs_config() instead
 */
vsclient_result_t vsclient_set_nfs_config(vsclient_handle_t *handle,
                                          const vsclient_nfs_config_t *config);

// Operating Mode Configuration Functions (DEPRECATED - Use oneshot API instead)
/**
 * @brief Set operating mode
 * @note DEPRECATED: Use vsclient_oneshot_set_operating_mode() instead
 */
vsclient_result_t vsclient_set_operating_mode(vsclient_handle_t *handle,
                                              vsclient_operating_mode_t mode);

// Status Query Functions (DEPRECATED - Use oneshot API instead)
/**
 * @brief Get stream status
 * @note DEPRECATED: Use vsclient_oneshot_get_stream_status() instead
 */
vsclient_result_t vsclient_get_stream_status(vsclient_handle_t *handle,
                                             vsclient_stream_status_t *status);

/**
 * @brief Get operating mode
 * @note DEPRECATED: Use vsclient_oneshot_get_operating_mode() instead
 */
vsclient_result_t vsclient_get_operating_mode(vsclient_handle_t *handle,
                                              vsclient_operating_mode_t *mode);

/**
 * @brief Get RTP configuration
 * @note DEPRECATED: Use vsclient_oneshot_get_rtp_config() instead
 */
vsclient_result_t vsclient_get_rtp_config(vsclient_handle_t *handle, vsclient_rtp_config_t *config);

/**
 * @brief Get NFS configuration
 * @note DEPRECATED: Use vsclient_oneshot_get_nfs_config() instead
 */
vsclient_result_t vsclient_get_nfs_config(vsclient_handle_t *handle, vsclient_nfs_config_t *config);

/**
 * @brief Get server status
 * @note DEPRECATED: Use vsclient_oneshot_get_server_status() instead
 */
vsclient_result_t vsclient_get_server_status(vsclient_handle_t *handle,
                                             vsclient_server_status_t *status);

// RTSP Configuration Functions (DEPRECATED - Use oneshot API instead)
/**
 * @brief Set RTSP server configuration
 * @note DEPRECATED: Use vsclient_oneshot_set_rtsp_server_config() instead
 */
vsclient_result_t vsclient_set_rtsp_server_config(vsclient_handle_t *handle, const char *server_ip,
                                                  uint16_t server_port, const char *stream_name,
                                                  uint8_t max_clients);

/**
 * @brief Set RTSP authentication configuration
 * @note DEPRECATED: Use vsclient_oneshot_set_rtsp_auth_config() instead
 */
vsclient_result_t vsclient_set_rtsp_auth_config(vsclient_handle_t *handle, const char *username,
                                                const char *password, bool enable_auth);

/**
 * @brief Get RTSP configuration
 * @note DEPRECATED: Use vsclient_oneshot_get_rtsp_config() instead
 */
vsclient_result_t vsclient_get_rtsp_config(vsclient_handle_t *handle,
                                           vsclient_rtsp_config_t *config);

// Local Mount Point Functions (DEPRECATED - Use oneshot API instead)
/**
 * @brief Set local mount point
 * @note DEPRECATED: Use vsclient_oneshot_set_local_mount_point() instead
 */
vsclient_result_t vsclient_set_local_mount_point(vsclient_handle_t *handle,
                                                 const char *mount_point);

/**
 * @brief Get local mount point
 * @note DEPRECATED: Use vsclient_oneshot_get_local_mount_point() instead
 */
vsclient_result_t vsclient_get_local_mount_point(vsclient_handle_t *handle, char *mount_point,
                                                 size_t buffer_size);

// Error Handling Functions
const char *vsclient_get_error_string(vsclient_result_t result);
vsclient_result_t vsclient_get_last_error(vsclient_handle_t *handle, char *buffer,
                                          size_t buffer_size);
vsclient_result_t wire_responste_to_vsclient_result(wire_response_code_t code);

// ============================================================================
// NEW ONESHOT API - Recommended for all new code
// ============================================================================
// These functions automatically handle connection management (connect → request → disconnect)
// and provide better reliability, thread safety, and error handling.
//
// Timeout behavior:
// - Functions without _timeout suffix: Wait forever (blocking)
// - Functions with _timeout suffix accept custom timeout parameter:
//   * timeout_seconds = -1: Wait forever (blocking until response received)
//   * timeout_seconds =  0: Non-blocking (return immediately if would block)
//   * timeout_seconds >  0: Wait for specified number of seconds
//   * Other values: Return VSCLIENT_ERROR_INVALID_PARAMETER

// Stream Control Functions (Oneshot API)
vsclient_result_t vsclient_oneshot_start_stream(const char *socket_path);
vsclient_result_t vsclient_oneshot_start_stream_timeout(const char *socket_path,
                                                        int timeout_seconds);
vsclient_result_t vsclient_oneshot_stop_stream(const char *socket_path);
vsclient_result_t vsclient_oneshot_stop_stream_timeout(const char *socket_path,
                                                       int timeout_seconds);

// Operating Mode Configuration (Oneshot API)
vsclient_result_t vsclient_oneshot_set_operating_mode(const char *socket_path,
                                                      vsclient_operating_mode_t mode);
vsclient_result_t vsclient_oneshot_set_operating_mode_timeout(const char *socket_path,
                                                              vsclient_operating_mode_t mode,
                                                              int timeout_seconds);

// RTP Configuration Functions (Oneshot API)
vsclient_result_t vsclient_oneshot_set_rtp_destination(const char *socket_path,
                                                       const char *destination, uint32_t port);
vsclient_result_t vsclient_oneshot_set_rtp_destination_timeout(const char *socket_path,
                                                               const char *destination,
                                                               uint32_t port, int timeout_seconds);
vsclient_result_t vsclient_oneshot_set_video_format(const char *socket_path, uint32_t width,
                                                    uint32_t height, uint32_t framerate);
vsclient_result_t vsclient_oneshot_set_video_format_timeout(const char *socket_path, uint32_t width,
                                                            uint32_t height, uint32_t framerate,
                                                            int timeout_seconds);
vsclient_result_t vsclient_oneshot_set_rtp_config(const char *socket_path,
                                                  const vsclient_rtp_config_t *config);
vsclient_result_t vsclient_oneshot_set_rtp_config_timeout(const char *socket_path,
                                                          const vsclient_rtp_config_t *config,
                                                          int timeout_seconds);
vsclient_result_t vsclient_oneshot_set_rtp_clock_rate(const char *socket_path, uint32_t clock_rate);
vsclient_result_t vsclient_oneshot_set_rtp_clock_rate_timeout(const char *socket_path,
                                                              uint32_t clock_rate,
                                                              int timeout_seconds);
vsclient_result_t vsclient_oneshot_set_rtp_payload_type(const char *socket_path,
                                                        uint32_t payload_type);
vsclient_result_t vsclient_oneshot_set_rtp_payload_type_timeout(const char *socket_path,
                                                                uint32_t payload_type,
                                                                int timeout_seconds);
vsclient_result_t vsclient_oneshot_set_rtp_channel(const char *socket_path, uint32_t channel);
vsclient_result_t vsclient_oneshot_set_rtp_channel_timeout(const char *socket_path,
                                                           uint32_t channel, int timeout_seconds);
vsclient_result_t vsclient_oneshot_set_rtp_jitter_buffer_size(const char *socket_path,
                                                              uint32_t size);
vsclient_result_t vsclient_oneshot_set_rtp_jitter_buffer_size_timeout(const char *socket_path,
                                                                      uint32_t size,
                                                                      int timeout_seconds);
vsclient_result_t vsclient_oneshot_set_rtp_packetization_interval(const char *socket_path,
                                                                  uint32_t interval);
vsclient_result_t vsclient_oneshot_set_rtp_packetization_interval_timeout(const char *socket_path,
                                                                          uint32_t interval,
                                                                          int timeout_seconds);
vsclient_result_t vsclient_oneshot_set_rtp_multicast_mode(const char *socket_path, bool multicast);
vsclient_result_t vsclient_oneshot_set_rtp_multicast_mode_timeout(const char *socket_path,
                                                                  bool multicast,
                                                                  int timeout_seconds);
vsclient_result_t vsclient_oneshot_reset_rtp_sequence(const char *socket_path);
vsclient_result_t vsclient_oneshot_reset_rtp_sequence_timeout(const char *socket_path,
                                                              int timeout_seconds);

// NFS Configuration Functions (Oneshot API)
vsclient_result_t vsclient_oneshot_set_nfs_config(const char *socket_path,
                                                  const vsclient_nfs_config_t *config);
vsclient_result_t vsclient_oneshot_set_nfs_config_timeout(const char *socket_path,
                                                          const vsclient_nfs_config_t *config,
                                                          int timeout_seconds);

// RTSP Configuration Functions (Oneshot API)
vsclient_result_t vsclient_oneshot_set_rtsp_server_config(const char *socket_path,
                                                          const char *server_ip,
                                                          uint16_t server_port,
                                                          const char *stream_name,
                                                          uint8_t max_clients);
vsclient_result_t vsclient_oneshot_set_rtsp_server_config_timeout(
    const char *socket_path, const char *server_ip, uint16_t server_port, const char *stream_name,
    uint8_t max_clients, int timeout_seconds);
vsclient_result_t vsclient_oneshot_set_rtsp_auth_config(const char *socket_path,
                                                        const char *username, const char *password,
                                                        bool enable_auth);
vsclient_result_t vsclient_oneshot_set_rtsp_auth_config_timeout(const char *socket_path,
                                                                const char *username,
                                                                const char *password,
                                                                bool enable_auth,
                                                                int timeout_seconds);
vsclient_result_t vsclient_oneshot_get_rtsp_config(const char *socket_path,
                                                   vsclient_rtsp_config_t *config);
vsclient_result_t vsclient_oneshot_get_rtsp_config_timeout(const char *socket_path,
                                                           vsclient_rtsp_config_t *config,
                                                           int timeout_seconds);

// Local Mount Point Functions (Oneshot API)
vsclient_result_t vsclient_oneshot_set_local_mount_point(const char *socket_path,
                                                         const char *mount_point);
vsclient_result_t vsclient_oneshot_set_local_mount_point_timeout(const char *socket_path,
                                                                 const char *mount_point,
                                                                 int timeout_seconds);
vsclient_result_t vsclient_oneshot_get_local_mount_point(const char *socket_path, char *mount_point,
                                                         size_t buffer_size);
vsclient_result_t vsclient_oneshot_get_local_mount_point_timeout(const char *socket_path,
                                                                 char *mount_point,
                                                                 size_t buffer_size,
                                                                 int timeout_seconds);

// Status Query Functions (Oneshot API)
vsclient_result_t vsclient_oneshot_get_server_status(const char *socket_path,
                                                     vsclient_server_status_t *status);
vsclient_result_t vsclient_oneshot_get_server_status_timeout(const char *socket_path,
                                                             vsclient_server_status_t *status,
                                                             int timeout_seconds);
vsclient_result_t vsclient_oneshot_get_operating_mode(const char *socket_path,
                                                      vsclient_operating_mode_t *mode);
vsclient_result_t vsclient_oneshot_get_operating_mode_timeout(const char *socket_path,
                                                              vsclient_operating_mode_t *mode,
                                                              int timeout_seconds);
vsclient_result_t vsclient_oneshot_get_stream_status(const char *socket_path,
                                                     vsclient_stream_status_t *status);
vsclient_result_t vsclient_oneshot_get_stream_status_timeout(const char *socket_path,
                                                             vsclient_stream_status_t *status,
                                                             int timeout_seconds);
vsclient_result_t vsclient_oneshot_get_rtp_config(const char *socket_path,
                                                  vsclient_rtp_config_t *config);
vsclient_result_t vsclient_oneshot_get_rtp_config_timeout(const char *socket_path,
                                                          vsclient_rtp_config_t *config,
                                                          int timeout_seconds);
vsclient_result_t vsclient_oneshot_get_nfs_config(const char *socket_path,
                                                  vsclient_nfs_config_t *config);
vsclient_result_t vsclient_oneshot_get_nfs_config_timeout(const char *socket_path,
                                                          vsclient_nfs_config_t *config,
                                                          int timeout_seconds);

#ifdef __cplusplus
}
#endif

#endif // VSCLIENT_H
