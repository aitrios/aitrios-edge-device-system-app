/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#ifndef _UT_MOCK_CLOCK_MANAGER_H_
#define _UT_MOCK_CLOCK_MANAGER_H_

typedef enum {
  kClockManagerExecCbIsaBtn = 0,    // Exec cb in IsaBtn
  kClockManagerExecCbCM,            // Exec cb in ClockManager
  kClockManagerExecCbNothing,       // Disable exec cb

  kClockManagerExecCbNum
} ClockManagerExecCb;

#endif  // _UT_MOCK_CLOCK_MANAGER_H_
