/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _INITIAL_SETTING_APP_LOG_H_
#define _INITIAL_SETTING_APP_LOG_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef SYSTEM_APP_UT
#include <string.h>
#endif // SYSTEM_APP_UT

#include "utility_log.h"
#include "utility_log_module_id.h"

/*----------------------------------------------------------------------------*/
/* Macros                                                                     */
/*----------------------------------------------------------------------------*/

#if !defined(__FILE_NAME__)
#define __FILE_NAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

#if 1 /* Use MACROs of UtiltyLog.*/
/* for DLog */

#define ISA_CRIT(fmt, ...) \
    WRITE_DLOG_CRITICAL(MODULE_ID_SYSTEM, "%s %d [CRT]" fmt, __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define ISA_ERR(fmt, ...) \
    WRITE_DLOG_ERROR(MODULE_ID_SYSTEM, "%s %d [ERR] " fmt, __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define ISA_WARN(fmt, ...) \
    WRITE_DLOG_WARN(MODULE_ID_SYSTEM, "%s %d [WAR] " fmt, __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define ISA_INFO(fmt, ...) \
    WRITE_DLOG_INFO(MODULE_ID_SYSTEM, "%s %d [INF] " fmt, __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define ISA_DBG(fmt, ...) \
    WRITE_DLOG_DEBUG(MODULE_ID_SYSTEM, "%s %d [DBG] " fmt, __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define ISA_TRC(fmt, ...) \
    WRITE_DLOG_TRACE(MODULE_ID_SYSTEM, "%s %d [TRC] " fmt, __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#else
/* for DLog */
#if 1
#include "stdio.h"

#define ISA_CRIT(fmt, ...) printf("%s %d [CRT] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define ISA_ERR(fmt, ...) printf("%s %d [ERR] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define ISA_WARN(fmt, ...) printf("%s %d [WAR] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define ISA_INFO(fmt, ...) printf("%s %d [INF] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define ISA_DBG(fmt, ...) printf("%s %d [DBG] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define ISA_TRC(fmt, ...) printf("%s %d [TRC] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#else
#include <syslog.h>

#define ISA_CRIT(fmt, ...) \
    syslog(LOG_ERR, "%s %d [CRT] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define ISA_ERR(fmt, ...) \
    syslog(LOG_ERR, "%s %d [ERR] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define ISA_WARN(fmt, ...) \
    syslog(LOG_WARNING, "%s %d [WAR] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define ISA_INFO(fmt, ...) \
    syslog(LOG_INFO, "%s %d [INF] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define ISA_DBG(fmt, ...) \
    syslog(LOG_DEBUG, "%s %d [DBG] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define ISA_TRC(fmt, ...) \
    syslog(LOG_DEBUG, "%s %d [TRC] " fmt "\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#endif
#endif

/*----------------------------------------------------------------------------*/
/* Public functions                                                           */
/*----------------------------------------------------------------------------*/

#ifdef __cplusplus
}
#endif

#endif // _INITIAL_SETTING__APP_LED_H_
