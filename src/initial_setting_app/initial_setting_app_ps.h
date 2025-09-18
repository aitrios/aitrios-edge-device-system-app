/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#ifndef _INITIAL_SETTING_APP_PS_H_
#define _INITIAL_SETTING_APP_PS_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    kIsaPsSuccess = 0,     // Success.
    kIsaPsInvalidArgument, // Argument error.
    kIsaPsFailed,          // Failed.
    kIsaPsReboot,          // Reboot.
    kIsaPsDoesntRun,       // PS mode doesnt run.
    kIsaPsFactoryReset,    // FactoryReset.
    kIsaPsSwitchToQrMode,  // Switch to QR mode.
    kIsaPsErrcodeNum
} IsaPsErrorCode;

// Enable if preprocessing is need itself

#define ISAPP_DO_PREPROCESS_DS // DeviceSetting
#define ISAPP_DO_PREPROCESS_PM // PowerManager
#define ISAPP_DO_PREPROCESS_LM // LedManager

// Force PS mode

#define ISAPP_PS_MODE_FORCE_ENTRY (0x77777777)

// Public functions

IsaPsErrorCode IsaRunProvisioningService(bool is_debug_mode);

#ifdef __cplusplus
}
#endif

#endif // _INITIAL_SETTING_APP_PS_H_
