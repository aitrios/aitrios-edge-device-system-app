/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _SYSTEM_APP_TIMER_H_
#define _SYSTEM_APP_TIMER_H_

#include "system_app_common.h"

//
// Public type declaration.
//

typedef enum {
  SensorTempIntervalTimer = 0,
  HoursMeterIntervalTimer,

  TimerTypeNum
} TimerType;

typedef void (*TimerCallback)(void);

//
// Public functions declaration.
//

RetCode SysAppTimerInitialize(void);
RetCode SysAppTimerFinalize(void);
RetCode SysAppTimerStartTimer(TimerType type, uint32_t time, TimerCallback notify_cb);
RetCode SysAppTimerUpdateTimer(TimerType type, uint32_t time);
RetCode SysAppTimerStopTimer(TimerType type);

#endif // _SYSTEM_APP_TIMER_H_
