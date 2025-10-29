/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _SYSTEM_APP_VSC_MANAGER_H_
#define _SYSTEM_APP_VSC_MANAGER_H_

#include "system_app_common.h"
#include <string.h>
#include "vsclient.h"

#ifdef __cplusplus
extern "C" {
#endif

// Constants

// Default stream name for RTSP streaming
static const char *DEFAULT_STREAM_NAME = "cam";

//
// Configuration parameter structures
//

typedef struct {
    char server_ip[CFGST_STREAMING_RTSP_SERVER_IP_LEN + 1];
    char stream_name[CFGST_STREAMING_RTSP_STREAM_NAME_LEN + 1];
    char user_name[CFGST_STREAMING_RTSP_USER_NAME_LEN + 1];
    char password[CFGST_STREAMING_RTSP_PASSWORD_LEN + 1];
    bool is_rtsp_server_running;
} CfgStRtspConfigParam;

typedef struct {
    char server_ip[CFGST_STREAMING_NFS_SERVER_IP_LEN + 1];
    char mount_path[CFGST_STREAMING_NFS_MOUNT_PATH_LEN + 1];
    int nfs_version;
    bool use_tcp;
    int max_record_time;
    char record_filename[CFGST_STREAMING_NFS_RECORD_FILENAME_LEN + 1];
    char file_recording_time[CFGST_STREAMING_NFS_FILE_RECORDING_TIME_LEN + 1];
} CfgStNfsConfigParam;

typedef struct {
    char id[CFG_RES_ID_LEN + 1];
    int process_state;
    int operating_mode;
    CfgStRtspConfigParam rtsp_config;
    CfgStNfsConfigParam nfs_config;
    CfgStUpdateInfo update;
} CfgStStreamingSettingsParam;

//
// VSC Manager Public API
//

/**
 * @brief Initialize VSC Manager with socket path
 * @param socket_path Path to VSC server socket
 * @return kRetOk on success, kRetFailed on failure
 */
RetCode SysAppVscManagerInitialize(const char *socket_path);

/**
 * @brief Finalize VSC Manager and cleanup resources
 * @return kRetOk on success, kRetFailed on failure
 */
RetCode SysAppVscManagerFinalize(void);

//
// VSC Operation Wrapper Functions (Thread-Safe)
//

/**
 * @brief Configure RTSP server settings
 * @param server_ip RTSP server IP address
 * @param stream_name RTSP stream name
 * @return vsclient_result_t result code
 */
vsclient_result_t SysAppVscConfigureRtspServer(const char *server_ip, const char *stream_name);

/**
 * @brief Configure RTSP authentication
 * @param user_name RTSP authentication username
 * @param password RTSP authentication password
 * @return vsclient_result_t result code
 */
vsclient_result_t SysAppVscConfigureRtspAuth(const char *user_name, const char *password);

/**
 * @brief Configure NFS recording settings
 * @param server_ip NFS server IP address
 * @param mount_path NFS mount path
 * @param nfs_version NFS protocol version (3 or 4)
 * @param use_tcp Use TCP protocol (true) or UDP (false)
 * @param record_time Maximum recording time in minutes
 * @return vsclient_result_t result code
 */
vsclient_result_t SysAppVscConfigureNfs(const char *server_ip, const char *mount_path,
                                        int nfs_version, bool use_tcp, int record_time);

/**
 * @brief Set VSC operating mode
 * @param mode Operating mode (StreamOnly, RecordOnly, StreamRecord)
 * @return vsclient_result_t result code
 */
vsclient_result_t SysAppVscSetMode(int mode);

/**
 * @brief Start video streaming
 * @return vsclient_result_t result code
 */
vsclient_result_t SysAppVscStartStream(void);

/**
 * @brief Stop video streaming
 * @return vsclient_result_t result code
 */
vsclient_result_t SysAppVscStopStream(void);

/**
 * @brief Get current server status
 * @param status Pointer to status structure to fill
 * @return vsclient_result_t result code
 */
vsclient_result_t SysAppVscGetServerStatus(vsclient_server_status_t *status);

//
// VSC Error Handling Utilities
//

/**
 * @brief Get VSC error string description
 * @param error VSC error code
 * @return Error string description
 */
const char *SysAppVscGetErrorString(vsclient_result_t error);

/**
 * @brief Map VSC error to SystemApp response code
 * @param vsc_error VSC error code
 * @return SystemApp response code
 */
int SysAppVscMapErrorToResponseCode(vsclient_result_t vsc_error);

/**
 * @brief Format VSC error detail message
 * @param vsc_error VSC error code
 * @param context Error context description
 * @param detail_msg Buffer to store detail message
 * @param detail_msg_size Size of detail message buffer
 */
void SysAppVscFormatErrorDetail(vsclient_result_t vsc_error, const char *context, char *detail_msg,
                                size_t detail_msg_size);

/**
 * @brief Unified VSC error handling function
 * 
 * This function provides unified VSC error handling for both state.c and configuration.c
 * 
 * @param vsc_error VSC error code
 * @param context Error context description
 * @param topic State topic for error flag setting
 */
void SysAppVscHandleCreateError(vsclient_result_t vsc_error, const char *context, uint32_t topic);

//
// VSC Error Information Management APIs
//

/**
 * @brief Check if VSC error information is available
 * @return true if VSC error exists, false otherwise
 */
bool SysAppVscManagerHasError(void);

/**
 * @brief Get VSC error response code for API response
 * @return Mapped response code (0 for success, non-zero for error)
 */
int SysAppVscManagerGetErrorResponseCode(void);

/**
 * @brief Get VSC error detailed message
 * @return Pointer to detailed error message string
 */
const char *SysAppVscManagerGetErrorMessage(void);

/**
 * @brief Clear VSC error information
 */
void SysAppVscManagerClearError(void);

#ifdef __cplusplus
}
#endif

#endif // _SYSTEM_APP_VSC_MANAGER_H_
