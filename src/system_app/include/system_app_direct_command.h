/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _SYSTEM_APP_DIRECT_COMMAND_H_
#define _SYSTEM_APP_DIRECT_COMMAND_H_

#if defined(__NuttX__)
#include <nuttx/config.h>
#endif

#include "evp/sdk_sys.h"
#include "system_app_common.h"

// String length for DirectCommand.

#define DC_SENSOR_NAME_LEN (32)
#define DC_NETWORK_ID_LEN (32)

// Camera image size.

#define DC_CAMERA_IMAGE_H_SIZE (4056)
#define DC_CAMERA_IMAGE_V_SIZE (3040)

// Default network for direct_get_image.

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
#define DC_DIRECT_GET_IMAGE_NETWORK_ID "99999999999999999999999999999999"
#else // Use #else for build: CONFIG_APP_EXTERNAL_SENSOR_IMX500_LIB
#define DC_DIRECT_GET_IMAGE_NETWORK_ID "999997"
#endif

// Max size of direct_get_image image size.

#define DC_DIRECT_GET_IMAGE_MAX_SIZE (120 * 1000)

// DirectCommand return code.

typedef enum {
    DcOk = 0,
    DcUnknown,
    DcInvalidArgument,
    DcResourceExhausted,
    DcFailedPreCodition,
    DcAborted,
    DcUnimplemented,
    DcInternal,
    DcUnavailable,
    DcUnauthenticated,

    DcResultNum
} DcResult;

//
// Public functions declaration.
//

RetCode SysAppDcmdInitialize(struct SYS_client* evp_client);
RetCode SysAppDcmdFinalize(void);
bool SysAppDcmdCheckSelfTerminate(TerminationReason* reason);
void SysAppDcmdRebootCore(void);       // This API can be called after SysAppDcmdFinalize().
void SysAppDcmdFactoryResetCore(void); // This API can be called after SysAppDcmdFinalize().
RetCode SysAppDcmdReboot(SYS_response_id cmd_id, const char* req_id, const char* param);
RetCode SysAppDcmdShutdown(SYS_response_id cmd_id, const char* req_id, const char* param);
RetCode SysAppDcmdFactoryReset(SYS_response_id cmd_id, const char* req_id, const char* param);
RetCode SysAppDcmdDirectGetImage(SYS_response_id cmd_id, const char* req_id, const char* param);
RetCode SysAppDcmdReadSensorRegister(SYS_response_id cmd_id, const char* req_id, const char* param);
RetCode SysAppDcmdWriteSensorRegister(SYS_response_id cmd_id, const char* req_id,
                                      const char* param);

#endif // _SYSTEM_APP_DIRECT_COMMAND_H_
