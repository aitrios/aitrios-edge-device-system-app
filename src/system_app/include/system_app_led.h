/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _SYSTEM_APP_LED_H_
#define _SYSTEM_APP_LED_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "led_manager.h"

#include "system_app_common.h"

typedef enum {
    LedTypePower = kEsfLedManagerTargetLedPower,
    LedTypeWiFi = kEsfLedManagerTargetLedWifi,
    LedTypeService = kEsfLedManagerTargetLedService,
    LedTypeNum = kEsfLedManagerTargetLedNum
} LedType;

// An enumerated type that defines the state of the Application.
typedef enum LedAppStatus {
    LedAppStatusForceOff = kEsfLedManagerLedStatusForcedOff,
    LedAppStatusAbleToAcceptInput = kEsfLedManagerLedStatusAbleToAcceptInputs,
    LedAppStatusUnableToAcceptInput = kEsfLedManagerLedStatusUnableToAcceptInputs,
    LedAppStatusWaitingForInputToConnect = kEsfLedManagerLedStatusWaitingForInputsToConnectConsole,
    LedAppStatusErrorDownloadFailed = kEsfLedManagerLedStatusErrorDownloadFailed,
    LedAppStatusErrorUpdateMemoryAllocateFailed =
        kEsfLedManagerLedStatusErrorUpdateMemoryAllocateFailed,
    LedAppStatusErrorDataFlashFailed = kEsfLedManagerLedStatusErrorDataFlashFailed,
    LedAppStatusNum = kEsfLedManagerLedStatusNum
} LedAppStatus;

// Public functions

void SysAppLedSetAppStatus(LedType type, LedAppStatus app_state);
void SysAppLedUnsetAppStatus(LedType type, LedAppStatus app_state);
RetCode SysAppLedSetEnable(bool led_enable);
RetCode SysAppLedGetEnable(bool* led_enable);

#ifdef __cplusplus
}
#endif

#endif // _SYSTEM_APP_LED_H_
