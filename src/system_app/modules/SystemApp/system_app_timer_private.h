/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _SYSTEM_APP_TIMER_PRIVATE_H_
#define _SYSTEM_APP_TIMER_PRIVATE_H_

#include "utility_timer.h"

typedef struct {
    UtilityTimerHandle handle;
    bool is_working;
    TimerCallback cb;
} TimerContext;

#endif // _SYSTEM_APP_TIMER_PRIVATE_H_
