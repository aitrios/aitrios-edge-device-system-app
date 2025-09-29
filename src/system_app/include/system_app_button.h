/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _SYSTEM_APP_BUTTON_H_
#define _SYSTEM_APP_BUTTON_H_

#include "system_app_common.h"

RetCode SysAppBtnInitialize(void);
RetCode SysAppBtnFinalize(void);
bool SysAppBtnCheckRebootRequest(void);
bool SysAppBtnCheckFactoryResetRequest(void);
RetCode SysAppBtnExecuteFactoryResetCore(void); // This API can be called after SysAppBtnFinalize().

#endif // _SYSTEM_APP_BUTTON_H_
