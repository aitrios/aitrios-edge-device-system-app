/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _INITIAL_SETTING_APP_BUTTON_H_
#define _INITIAL_SETTING_APP_BUTTON_H_

#include "system_app_common.h"

RetCode IsaBtnInitialize(void);
RetCode IsaBtnFinalize(void);
bool IsaBtnCheckRebootRequest(void);
bool IsaBtnCheckFactoryResetRequest(void);
RetCode IsaBtnExecuteRebootCore(void);
RetCode IsaBtnExecuteFactoryResetCore(void); // This API can be called after SysAppBtnFinalize().

#endif // _SYSTEM_APP_BUTTON_H_

