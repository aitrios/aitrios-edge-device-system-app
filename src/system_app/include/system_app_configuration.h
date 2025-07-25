/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _SYSTEM_APP_CONFIGURATION_H_
#define _SYSTEM_APP_CONFIGURATION_H_

#include "system_app_common.h"

//
// Public functions declaration.
//

RetCode SysAppCfgInitialize(struct SYS_client* evp_client);
RetCode SysAppCfgFinalize(void);
RetCode SysAppCfgSystemSettings(const char* param);
RetCode SysAppCfgNetworkSettings(const char* param);
RetCode SysAppCfgPeriodicSetting(const char* param);
RetCode SysAppCfgWirelessSetting(const char* param);
RetCode SysAppCfgEndpointSettings(const char* param);

#endif //_SYSTEM_APP_CONFIGURATION_H_

