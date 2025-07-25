/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _INITIAL_SETTING_APP_TIMER_H_
#define _INITIAL_SETTING_APP_TIMER_H_

#include "system_app_common.h"

//
// Public type declaration.
//

typedef void (*IsaTimerCallback)(void);

//
// Public functions declaration.
//

RetCode IsaTimerInitialize(void);
RetCode IsaTimerFinalize(void);
RetCode IsaTimerStart(uint32_t time, IsaTimerCallback notify_cb);
RetCode IsaTimerStop(void);

#endif // _INITIAL_SETTING_APP_TIMER_H_

