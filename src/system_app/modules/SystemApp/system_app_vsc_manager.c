/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "system_app_common.h"
#include "system_app_vsc_manager.h"
#include "system_app_log.h"
#include "system_app_util.h"
#include "system_app_state.h"
#include <time.h>

//
// Constants
//

#define VSC_RTSP_PORT 8554     // RTSP default port
#define VSC_RTSP_MAX_CLIENTS 4 // RTSP default max clients
#define VSC_TIMEOUT_SEC 30     // VSC operation timeout in seconds

//
// Private VSC Manager Structure
//

// VSC Error Information

typedef struct {
    bool has_vsc_error;         // Whether a VSC error has occurred
    bool is_critical;           // Whether the error is critical
    int mapped_response_code;   // Mapped response code
    char detailed_message[256]; // Detailed error message
} error_info_t;

typedef struct {
    char socket_path[256];   // Socket path for connection
    bool is_initialized;     // Initialization status
    pthread_mutex_t mutex;   // Thread safety mutex
    error_info_t error_info; // VSC error information
} VscManager;

//
// Static Variables
//

static VscManager s_vsc_manager = {0};

//
// Private Functions
//

//
// Public API Implementation
//

/*----------------------------------------------------------------------*/
RetCode SysAppVscManagerInitialize(const char *socket_path)
{
    if (!socket_path || strlen(socket_path) == 0) {
        SYSAPP_ERR("VSC Manager: Invalid socket path");
        return kRetFailed;
    }

    // Initialize mutex for thread safety

    int mutex_ret = pthread_mutex_init(&s_vsc_manager.mutex, NULL);

    if (mutex_ret != 0) {
        SYSAPP_ERR("VSC Manager: Failed to initialize mutex: %d", mutex_ret);
        return kRetFailed;
    }

    pthread_mutex_lock(&s_vsc_manager.mutex);

    // Store socket path

    strncpy(s_vsc_manager.socket_path, socket_path, sizeof(s_vsc_manager.socket_path) - 1);
    s_vsc_manager.socket_path[sizeof(s_vsc_manager.socket_path) - 1] = '\0';

    // Initialize error information

    s_vsc_manager.error_info.has_vsc_error = false;
    s_vsc_manager.error_info.is_critical = false;
    s_vsc_manager.error_info.mapped_response_code = 0;
    s_vsc_manager.error_info.detailed_message[0] = '\0';
    s_vsc_manager.is_initialized = true;

    pthread_mutex_unlock(&s_vsc_manager.mutex);

    SYSAPP_INFO("VSC Manager: Initialized with socket path: %s", s_vsc_manager.socket_path);

    return kRetOk; // Always return success for initialization
}

/*----------------------------------------------------------------------*/
RetCode SysAppVscManagerFinalize(void)
{
    if (!s_vsc_manager.is_initialized) {
        SYSAPP_WARN("VSC Manager: Already finalized or not initialized");
        return kRetOk;
    }

    pthread_mutex_lock(&s_vsc_manager.mutex);

    // Reset state
    s_vsc_manager.is_initialized = false;
    memset(s_vsc_manager.socket_path, 0, sizeof(s_vsc_manager.socket_path));

    pthread_mutex_unlock(&s_vsc_manager.mutex);

    // Destroy mutex
    pthread_mutex_destroy(&s_vsc_manager.mutex);

    SYSAPP_INFO("VSC Manager: Finalized successfully");

    return kRetOk;
}

//
// VSC Operation Wrapper Functions
//

/*----------------------------------------------------------------------*/
vsclient_result_t SysAppVscConfigureRtspServer(const char *server_ip, const char *stream_name)
{
    vsclient_result_t result = vsclient_oneshot_set_rtsp_server_config_timeout(
        s_vsc_manager.socket_path, server_ip, VSC_RTSP_PORT, stream_name, VSC_RTSP_MAX_CLIENTS,
        VSC_TIMEOUT_SEC);

    if (result == VSCLIENT_SUCCESS) {
        SYSAPP_INFO("VSC Manager: RTSP server configured successfully: %s:%d/%s (max %d clients)",
                    server_ip, VSC_RTSP_PORT, stream_name, VSC_RTSP_MAX_CLIENTS);
    }
    else {
        SYSAPP_ERR("VSC Manager: RTSP server configuration failed: %s",
                   vsclient_get_error_string(result));
    }

    return result;
}

/*----------------------------------------------------------------------*/
vsclient_result_t SysAppVscConfigureRtspAuth(const char *user_name, const char *password)
{
    // Enable authentication if both username and password are provided and non-empty

    bool enable_auth =
        (user_name != NULL && strlen(user_name) > 0 && password != NULL && strlen(password) > 0);

    vsclient_result_t result = vsclient_oneshot_set_rtsp_auth_config_timeout(
        s_vsc_manager.socket_path, user_name, password, enable_auth, VSC_TIMEOUT_SEC);

    if (result == VSCLIENT_SUCCESS) {
        if (enable_auth) {
            SYSAPP_INFO("VSC Manager: RTSP authentication enabled for user: %s", user_name);
        }
        else {
            SYSAPP_INFO("VSC Manager: RTSP authentication disabled (empty credentials)");
        }
    }
    else {
        SYSAPP_ERR("VSC Manager: RTSP authentication configuration failed: %s",
                   vsclient_get_error_string(result));
    }

    return result;
}

/*----------------------------------------------------------------------*/
vsclient_result_t SysAppVscConfigureNfs(const char *server_ip, const char *mount_path,
                                        int nfs_version, bool use_tcp, int record_time)
{
    // Create complete NFS config structure

    vsclient_nfs_config_t nfs_config = {0};

    // Basic NFS settings

    strncpy(nfs_config.server_ip, server_ip, sizeof(nfs_config.server_ip) - 1);
    nfs_config.server_ip[sizeof(nfs_config.server_ip) - 1] = '\0';

    strncpy(nfs_config.mount_point, mount_path, sizeof(nfs_config.mount_point) - 1);
    nfs_config.mount_point[sizeof(nfs_config.mount_point) - 1] = '\0';

    nfs_config.nfs_version = (uint32_t)nfs_version;
    nfs_config.use_tcp = use_tcp ? 1 : 0;
    nfs_config.file_duration_minutes = (uint32_t)record_time;

    vsclient_result_t result = vsclient_oneshot_set_nfs_config_timeout(
        s_vsc_manager.socket_path, &nfs_config, VSC_TIMEOUT_SEC);

    if (result == VSCLIENT_SUCCESS) {
        SYSAPP_INFO("VSC Manager: NFS configured successfully: %s:%s (v%d, %s, max_record_time:%d)",
                    server_ip, mount_path, nfs_version, use_tcp ? "tcp" : "udp", record_time);
    }
    else {
        SYSAPP_ERR("VSC Manager: NFS configuration failed: %s", vsclient_get_error_string(result));
    }

    return result;
}

/*----------------------------------------------------------------------*/
vsclient_result_t SysAppVscSetMode(int mode)
{
    vsclient_result_t result = vsclient_oneshot_set_operating_mode_timeout(
        s_vsc_manager.socket_path, (vsclient_operating_mode_t)mode, VSC_TIMEOUT_SEC);

    if (result == VSCLIENT_SUCCESS) {
        SYSAPP_INFO("VSC Manager: Operating mode set successfully: %d", mode);
    }
    else {
        SYSAPP_ERR("VSC Manager: Mode setting failed: %s", vsclient_get_error_string(result));
    }

    return result;
}

/*----------------------------------------------------------------------*/
vsclient_result_t SysAppVscStartStream(void)
{
    vsclient_result_t result = vsclient_oneshot_start_stream_timeout(s_vsc_manager.socket_path,
                                                                     VSC_TIMEOUT_SEC);

    if (result == VSCLIENT_SUCCESS) {
        SYSAPP_INFO("VSC Manager: Stream started successfully");
    }
    else {
        SYSAPP_ERR("VSC Manager: Stream start failed: %s", vsclient_get_error_string(result));
    }

    return result;
}

/*----------------------------------------------------------------------*/
vsclient_result_t SysAppVscStopStream(void)
{
    vsclient_result_t result = vsclient_oneshot_stop_stream_timeout(s_vsc_manager.socket_path,
                                                                    VSC_TIMEOUT_SEC);

    if (result == VSCLIENT_SUCCESS) {
        SYSAPP_INFO("VSC Manager: Stream stopped successfully");
    }
    else {
        SYSAPP_ERR("VSC Manager: Stream stop failed: %s", vsclient_get_error_string(result));
    }

    return result;
}

/*----------------------------------------------------------------------*/
vsclient_result_t SysAppVscGetServerStatus(vsclient_server_status_t *status)
{
    if (!status) {
        SYSAPP_ERR("VSC Manager: Invalid status pointer");
        return VSCLIENT_ERROR_INVALID_PARAMETER;
    }

    vsclient_result_t result = vsclient_oneshot_get_server_status_timeout(s_vsc_manager.socket_path,
                                                                          status, VSC_TIMEOUT_SEC);

    if (result == VSCLIENT_SUCCESS) {
        SYSAPP_DBG("VSC Manager: Server status retrieved successfully");
    }
    else {
        SYSAPP_ERR("VSC Manager: Status query failed: %s", vsclient_get_error_string(result));
    }

    return result;
}

//
// VSC Error Handling Utilities
//

/*----------------------------------------------------------------------*/
const char *SysAppVscGetErrorString(vsclient_result_t error)
{
    return vsclient_get_error_string(error);
}

/*----------------------------------------------------------------------*/
int SysAppVscMapErrorToResponseCode(vsclient_result_t vsc_error)
{
    switch (vsc_error) {
        case VSCLIENT_SUCCESS:
            return RESULT_CODE_OK;
        case VSCLIENT_ERROR_INVALID_PARAMETER:
            return RESULT_CODE_INVALID_ARGUMENT;
        case VSCLIENT_ERROR_CONNECTION_FAILED:
        case VSCLIENT_ERROR_NOT_CONNECTED:
        case VSCLIENT_ERROR_SERVER_NOT_AVAILABLE:
            return RESULT_CODE_UNAVAILABLE; // unavailable (transient network condition)
        case VSCLIENT_ERROR_ALREADY_CONNECTED:
            return RESULT_CODE_ALREADY_EXISTS;
        case VSCLIENT_ERROR_SEND_FAILED:
        case VSCLIENT_ERROR_RECEIVE_FAILED:
        case VSCLIENT_ERROR_INVALID_RESPONSE:
        case VSCLIENT_ERROR_INVALID_COMMAND:
        case VSCLIENT_ERROR_PROTOCOL_ERROR:
        case VSCLIENT_ERROR_SERVER_ERROR:
        case VSCLIENT_ERROR_TIMEOUT:
            return RESULT_CODE_INTERNAL;
        case VSCLIENT_ERROR_INVALID_STATE:
            return RESULT_CODE_FAILED_PRECONDITION;
        case VSCLIENT_ERROR_SYSTEM_ERROR:
            return RESULT_CODE_RESOURCE_EXHAUSTED;
        case VSCLIENT_ERROR_UNKNOWN:
        default:
            return RESULT_CODE_UNKNOWN;
    }
}

/*----------------------------------------------------------------------*/
void SysAppVscFormatErrorDetail(vsclient_result_t vsc_error, const char *context, char *detail_msg,
                                size_t detail_msg_size)
{
    if (!detail_msg || detail_msg_size == 0) {
        return;
    }

    const char *error_str = SysAppVscGetErrorString(vsc_error);

    switch (vsc_error) {
        case VSCLIENT_ERROR_INVALID_PARAMETER:
            snprintf(detail_msg, detail_msg_size, "Invalid parameter in %s (VSC error: %s)",
                     context, error_str);
            break;
        case VSCLIENT_ERROR_CONNECTION_FAILED:
            snprintf(detail_msg, detail_msg_size, "Connection failed during %s (VSC error: %s)",
                     context, error_str);
            break;
        case VSCLIENT_ERROR_ALREADY_CONNECTED:
            snprintf(detail_msg, detail_msg_size, "Already connected during %s (VSC error: %s)",
                     context, error_str);
            break;
        case VSCLIENT_ERROR_NOT_CONNECTED:
            snprintf(detail_msg, detail_msg_size, "Not connected during %s (VSC error: %s)",
                     context, error_str);
            break;
        case VSCLIENT_ERROR_SEND_FAILED:
            snprintf(detail_msg, detail_msg_size, "Send failed during %s (VSC error: %s)", context,
                     error_str);
            break;
        case VSCLIENT_ERROR_RECEIVE_FAILED:
            snprintf(detail_msg, detail_msg_size, "Receive failed during %s (VSC error: %s)",
                     context, error_str);
            break;
        case VSCLIENT_ERROR_INVALID_RESPONSE:
            snprintf(detail_msg, detail_msg_size, "Invalid response in %s (VSC error: %s)", context,
                     error_str);
            break;
        case VSCLIENT_ERROR_INVALID_COMMAND:
            snprintf(detail_msg, detail_msg_size, "Invalid command in %s (VSC error: %s)", context,
                     error_str);
            break;
        case VSCLIENT_ERROR_PROTOCOL_ERROR:
            snprintf(detail_msg, detail_msg_size, "Protocol error in %s (VSC error: %s)", context,
                     error_str);
            break;
        case VSCLIENT_ERROR_SERVER_ERROR:
            snprintf(detail_msg, detail_msg_size, "Server error during %s (VSC error: %s)", context,
                     error_str);
            break;
        case VSCLIENT_ERROR_TIMEOUT:
            snprintf(detail_msg, detail_msg_size, "Timeout occurred in %s (VSC error: %s)", context,
                     error_str);
            break;
        case VSCLIENT_ERROR_INVALID_STATE:
            snprintf(detail_msg, detail_msg_size, "Invalid state during %s (VSC error: %s)",
                     context, error_str);
            break;
        case VSCLIENT_ERROR_SYSTEM_ERROR:
            snprintf(detail_msg, detail_msg_size, "System error during %s (VSC error: %s)", context,
                     error_str);
            break;
        case VSCLIENT_ERROR_SERVER_NOT_AVAILABLE:
            snprintf(detail_msg, detail_msg_size, "Server not available during %s (VSC error: %s)",
                     context, error_str);
            break;
        case VSCLIENT_ERROR_UNKNOWN:
            snprintf(detail_msg, detail_msg_size, "Unknown error in %s (VSC error: %s)", context,
                     error_str);
            break;
        default:
            snprintf(detail_msg, detail_msg_size, "Undefined error in %s (VSC error: %s, code: %d)",
                     context, error_str, vsc_error);
            break;
    }
}

/*----------------------------------------------------------------------*/
void SysAppVscHandleCreateError(vsclient_result_t vsc_error, const char *context, uint32_t topic)
{
    // Common VSC error processing (mapping + detailed message generation)

    int response_code = SysAppVscMapErrorToResponseCode(vsc_error);
    char detail_msg[256] = "";

    SysAppVscFormatErrorDetail(vsc_error, context, detail_msg, sizeof(detail_msg));

    // Save detailed information

    pthread_mutex_lock(&s_vsc_manager.mutex);

    s_vsc_manager.error_info.is_critical = context != NULL && strstr(context, "status") == NULL;

    if (!s_vsc_manager.error_info.has_vsc_error || s_vsc_manager.error_info.is_critical) {
        s_vsc_manager.error_info.has_vsc_error = true;
        s_vsc_manager.error_info.mapped_response_code = response_code;

        if (detail_msg != NULL) {
            strncpy(s_vsc_manager.error_info.detailed_message, detail_msg,
                    sizeof(s_vsc_manager.error_info.detailed_message) - 1);
            s_vsc_manager.error_info
                .detailed_message[sizeof(s_vsc_manager.error_info.detailed_message) - 1] = '\0';
        }
        else {
            s_vsc_manager.error_info.detailed_message[0] = '\0';
        }
    }

    pthread_mutex_unlock(&s_vsc_manager.mutex);

    SYSAPP_ERR("VSC error code %d -> Response code %d, Detail: %s", vsc_error, response_code,
               detail_msg);
}

//
// VSC Error Information Management APIs
//

/*----------------------------------------------------------------------*/
bool SysAppVscManagerHasError(void)
{
    if (!s_vsc_manager.is_initialized) {
        return false;
    }

    pthread_mutex_lock(&s_vsc_manager.mutex);

    bool has_error = s_vsc_manager.error_info.has_vsc_error;

    pthread_mutex_unlock(&s_vsc_manager.mutex);

    return has_error;
}

/*----------------------------------------------------------------------*/
int SysAppVscManagerGetErrorResponseCode(void)
{
    if (!s_vsc_manager.is_initialized) {
        return 0;
    }

    pthread_mutex_lock(&s_vsc_manager.mutex);

    int response_code =
        s_vsc_manager.error_info.has_vsc_error ? s_vsc_manager.error_info.mapped_response_code : 0;

    pthread_mutex_unlock(&s_vsc_manager.mutex);

    return response_code;
}

/*----------------------------------------------------------------------*/
const char *SysAppVscManagerGetErrorMessage(void)
{
    if (!s_vsc_manager.is_initialized) {
        return "";
    }

    pthread_mutex_lock(&s_vsc_manager.mutex);

    const char *message =
        s_vsc_manager.error_info.has_vsc_error ? s_vsc_manager.error_info.detailed_message : "";

    pthread_mutex_unlock(&s_vsc_manager.mutex);

    return message;
}

/*----------------------------------------------------------------------*/
void SysAppVscManagerClearError(void)
{
    if (!s_vsc_manager.is_initialized) {
        return;
    }

    pthread_mutex_lock(&s_vsc_manager.mutex);

    // Clear VSC error information

    s_vsc_manager.error_info.has_vsc_error = false;
    s_vsc_manager.error_info.is_critical = false;
    s_vsc_manager.error_info.mapped_response_code = 0;
    s_vsc_manager.error_info.detailed_message[0] = '\0';

    pthread_mutex_unlock(&s_vsc_manager.mutex);

    SYSAPP_DBG("VSC Manager: Error information cleared");
}
