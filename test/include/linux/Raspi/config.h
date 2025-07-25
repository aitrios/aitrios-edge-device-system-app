/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
/* linux_config.h -- Configuration file for Linux platform */

#ifndef __INCLUDE_LINUX_CONFIG_H
#define __INCLUDE_LINUX_CONFIG_H

/* General Definitions ***********************************/
#define CONFIG_HOST_LINUX 1
#define CONFIG_EXTERNAL_SYSTEMAPP 1
#define CONFIG_EXTERNAL_SYSTEMAPP_STACKSIZE 4096
#define CONFIG_EXTERNAL_ISAPP_STACKSIZE 4096
#define CONFIG_EXTERNAL_LARGE_HEAP_MEMORY_MAP 1
#define CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500 1
#define CONFIG_EXTERNAL_SYSTEMAPP_SCHEMA "dtmi:com:sony_semicon:aitrios:sss:edge:system:t3p;2"

/* Debugging Options */
#define CONFIG_DEBUG_FEATURES 1
#define CONFIG_DEBUG_ERROR 1
#define CONFIG_DEBUG_WARN 1
#define CONFIG_DEBUG_INFO 1

#define CONFIG_UTILITY_TIMER_THREAD_PRIORITY 120
#define CONFIG_EXTERNAL_FIRMWARE_MANAGER_AI_MODEL_SLOT_NUM 4
#define CONFIG_EXTERNAL_FIRMWARE_MANAGER_MAX_MEMORY_SIZE 1048576

#endif /* __INCLUDE_LINUX_CONFIG_H */
