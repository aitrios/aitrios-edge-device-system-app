/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _INITIAL_SETTING_APP_TIMER_PRIVATE_H_
#define _INITIAL_SETTING_APP_TIMER_PRIVATE_H_

#include "utility_timer.h"

typedef struct {
    UtilityTimerHandle handle;
    bool is_working;
    IsaTimerCallback cb;
} IsaTimerContext;

#endif // _INITIAL_SETTING_APP_TIMER_PRIVATE_H_
