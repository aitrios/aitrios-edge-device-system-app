/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _SYSTEM_APP_LOG_H_
#define _SYSTEM_APP_LOG_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef SYSTEM_APP_UT
#include <string.h>
#endif  // SYSTEM_APP_UT

#include "utility_log.h"
#include "utility_log_module_id.h"
#include "log_manager.h"

#include "system_app_common.h"

/*----------------------------------------------------------------------------*/
/* Macros                                                                     */
/*----------------------------------------------------------------------------*/

#define ULOG_MODULE_ID MODULE_ID_SYSTEM

#if !defined(__FILE_NAME__)
  #define __FILE_NAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

#if 1 /* Use MACROs of UtiltyLog.*/
/* for DLog */

#define SYSAPP_CRIT(fmt, ...) WRITE_DLOG_CRITICAL(ULOG_MODULE_ID, "%s %d [CRT]" fmt, __FILE_NAME__, __LINE__,##__VA_ARGS__)
#define SYSAPP_ERR(fmt, ...) WRITE_DLOG_ERROR(ULOG_MODULE_ID, "%s %d [ERR] " fmt, __FILE_NAME__, __LINE__,##__VA_ARGS__)
#define SYSAPP_WARN(fmt, ...) WRITE_DLOG_WARN(ULOG_MODULE_ID, "%s %d [WAR] " fmt, __FILE_NAME__, __LINE__,##__VA_ARGS__)
#define SYSAPP_INFO(fmt, ...) WRITE_DLOG_INFO(ULOG_MODULE_ID, "%s %d [INF] " fmt, __FILE_NAME__, __LINE__,##__VA_ARGS__)
#define SYSAPP_DBG(fmt, ...) WRITE_DLOG_DEBUG(ULOG_MODULE_ID, "%s %d [DBG] " fmt, __FILE_NAME__, __LINE__,##__VA_ARGS__)
#define SYSAPP_TRC(fmt, ...) WRITE_DLOG_TRACE(ULOG_MODULE_ID, "%s %d [TRC] " fmt, __FILE_NAME__, __LINE__,##__VA_ARGS__)

/* for ELog */

#define SYSAPP_EVT_SENSOR_APPROACHING_HIGH_TEMP (0x4010)
#define SYSAPP_EVT_SENSOR_EXCEEDED_HIGH_TEMP (0x4020)
#define SYSAPP_EVT_SENSOR_APPROACHING_LOW_TEMP (0x4110)
#define SYSAPP_EVT_SENSOR_EXCEEDED_LOW_TEMP (0x4120)
#define SYSAPP_EVT_OTA_STARTED (0xb000)
#define SYSAPP_EVT_REBOOT_STARTED (0xb001)
#define SYSAPP_EVT_FACTORY_RESET_FROM_CONSOLE_STARTED (0xb002)
#define SYSAPP_EVT_FACTORY_RESET_FROM_PUSHKEY_STARTED (0xb003)
#define SYSAPP_EVT_DIRECT_GET_IMAGE_REQUEST_STARTED (0xb004)
#define SYSAPP_EVT_FAILED_TO_RETRIEVE_TEMP (0xb0b0)
#define SYSAPP_EVT_FAILED_TO_DIRET_GET_IMAGE_SENOR_ERROR (0xb0b1)
#define SYSAPP_EVT_FAILED_TO_DOWNLOAD_FILE (0xb0b2)
#define SYSAPP_EVT_OTA_FAILED (0xb0b3)

#define SYSAPP_ELOG_CRIT(event_id) WRITE_ELOG_CRITICAL(ULOG_MODULE_ID, event_id)
#define SYSAPP_ELOG_ERR(event_id) WRITE_ELOG_ERROR(ULOG_MODULE_ID, event_id)
#define SYSAPP_ELOG_WARN(event_id) WRITE_ELOG_WARN(ULOG_MODULE_ID, event_id)
#define SYSAPP_ELOG_INFO(event_id) WRITE_ELOG_INFO(ULOG_MODULE_ID, event_id)
#define SYSAPP_ELOG_DBG(event_id) WRITE_ELOG_DEBUG(ULOG_MODULE_ID, event_id)
#define SYSAPP_ELOG_TRC(event_id) WRITE_ELOG_TRACE(ULOG_MODULE_ID, event_id)
#else
/* for DLog */
  #if 1
#include "stdio.h"

#define SYSAPP_CRIT(fmt, ...) printf("%s %d [CRT] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define SYSAPP_ERR(fmt, ...) printf("%s %d [ERR] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define SYSAPP_WARN(fmt, ...) printf("%s %d [WAR] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define SYSAPP_INFO(fmt, ...) printf("%s %d [INF] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define SYSAPP_DBG(fmt, ...) printf("%s %d [DBG] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define SYSAPP_TRC(fmt, ...) printf("%s %d [TRC] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
  #else
#include <syslog.h>

#define SYSAPP_CRIT(fmt, ...) syslog(LOG_ERR, "%s %d [CRT] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define SYSAPP_ERR(fmt, ...) syslog(LOG_ERR, "%s %d [ERR] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define SYSAPP_WARN(fmt, ...) syslog(LOG_WARNING, "%s %d [WAR] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define SYSAPP_INFO(fmt, ...) syslog(LOG_INFO, "%s %d [INF] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define SYSAPP_DBG(fmt, ...) syslog(LOG_DEBUG, "%s %d [DBG] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define SYSAPP_TRC(fmt, ...) syslog(LOG_DEBUG, "%s %d [TRC] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
  #endif
#endif

/*----------------------------------------------------------------------------*/
/* Public functions                                                           */
/*----------------------------------------------------------------------------*/
//int SysAppLogConvertExternalLevel(EsfLogManagerDlogLevel esflevel);
//int SysAppLogConvertInternalLevel(CfgStLogLevel level);

RetCode SysAppLogGetParameterNumber(CfgStLogFilter filter,
                                    SystemSettingsProperty prop,
                                    int *ret_value);
RetCode SysAppLogGetParameterString(CfgStLogFilter filter,
                                    SystemSettingsProperty prop,
                                    char *ret_value,
                                    size_t buff_size);
RetCode SysAppLogSetParameterNumber(CfgStLogFilter filter,
                                    SystemSettingsProperty prop,
                                    int set_value);
RetCode SysAppLogSetParameterString(CfgStLogFilter filter,
                                    SystemSettingsProperty prop,
                                    const char *set_value,
                                    size_t buff_size);


/*----------------------------------------------------------------------------*/
/* Globals                                                                    */
/*----------------------------------------------------------------------------*/

#ifdef __cplusplus
}
#endif

#endif // _SYSTEM_APP_LED_H_
