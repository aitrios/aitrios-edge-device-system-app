/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <stdio.h>

#include "sdk_backdoor.h"

#include "evp/sdk_sys.h"
#include "power_manager.h"
#include "button_manager.h"
#include "firmware_manager.h"
#include "system_manager.h"

#include "system_app_common.h"
#include "system_app_direct_command.h"
#include "system_app_state.h"
#include "system_app_led.h"
#include "system_app_log.h"
#include "system_app_util.h"

//
// Macros.
//

//
// File private structure.
//

//
// File private structure.
//

//
// File static variables.
//

STATIC EsfButtonManagerHandle s_esfbm_handle = NULL;
STATIC bool s_reboot_requested = false;
STATIC bool s_factory_reset_requested = false;

//
// File static private functions.
//

/*----------------------------------------------------------------------------*/
STATIC void ButtonPressedCallback(void *user_data)
{
    SYSAPP_INFO("Button pressed. %p", user_data);
}

/*----------------------------------------------------------------------------*/
STATIC void ButtonReleased5to29Callback(void *user_data)
{
    SYSAPP_INFO("Button released after 5sec to 29 sec. %p", user_data);

    // Request reboot to transit to QR mode.

    s_reboot_requested = true;

    // In this case, QR mode will be timed out with 180 sec..

    EsfSystemManagerResult esfsm_ret = EsfSystemManagerSetQrModeTimeoutValue(180);

    if (esfsm_ret != kEsfSystemManagerResultOk) {
        SYSAPP_ERR("EsfSystemManagerGetQrModeTimeoutValue:%d", esfsm_ret);
    }
}

/*----------------------------------------------------------------------------*/
STATIC void ButtonReleasedOver30Callback(void *user_data)
{
    SYSAPP_INFO("Button released after more than 30 sec. %p", user_data);

    // Is factory reset already working?

    if (s_factory_reset_requested) {
        SYSAPP_INFO("Factory reset is already working by button.");
        return;
    }

    TerminationReason reason = UnDefined;
    SysAppDcmdCheckSelfTerminate(&reason);

    if (reason == FactoryResetRequested) {
        SYSAPP_INFO("Factory reset is already working by DirectCommand.");
        return;
    }

    if (reason == RebootRequested) {
        SYSAPP_INFO("Reboot is already working by DirectCommand.");
        return;
    }

    // Request factory reset.

    {
        SYSAPP_ELOG_INFO(SYSAPP_EVT_FACTORY_RESET_FROM_PUSHKEY_STARTED);

        // Force undeploy modules.

        int evp_ret = EVP_undeployModules();

        if (evp_ret != 1) {
            SYSAPP_WARN("EVP_undeployModules() ret %d", evp_ret);
        }

        // Request factory reset.
        // Factory reset will be executed after.

        s_factory_reset_requested = true;
    }
}

/*----------------------------------------------------------------------------*/
STATIC void SetLedStatusForButtonLongPressed5(void)
{
    // Set LED status when button is long pressed for 5 seconds.

    EsfLedManagerResult ret_ledmgr = kEsfLedManagerInternalError;
    EsfLedManagerLedStatusInfo status;

    status.led = kEsfLedManagerTargetLedPower;
    status.enabled = false;

    // Unset all statuses except for ForcedOff.

    for (EsfLedManagerLedStatus led_status = kEsfLedManagerLedStatusAbleToAcceptInputs;
         led_status < kEsfLedManagerLedStatusNum; led_status++) {
        status.status = led_status;

        ret_ledmgr = EsfLedManagerSetStatus(&status);

        if (ret_ledmgr != kEsfLedManagerSuccess) {
            SYSAPP_ERR("EsfLedManagerSetStatus failed : ret=%d, led_status=%d", ret_ledmgr,
                       led_status);
        }
    }

    // Set status to QR code mode.

    status.enabled = true;
    status.status = kEsfLedManagerLedStatusWaitingForInputsToConnectConsole;

    ret_ledmgr = EsfLedManagerSetStatus(&status);

    if (ret_ledmgr != kEsfLedManagerSuccess) {
        SYSAPP_ERR("EsfLedManagerSetStatus failed : ret=%d", ret_ledmgr);
    }
}

/*----------------------------------------------------------------------------*/
STATIC void SetLedStatusForButtonLongPressed30(void)
{
    // Set LED status when button is long pressed for 30 seconds.

    EsfLedManagerResult ret_ledmgr = kEsfLedManagerInternalError;
    EsfLedManagerLedStatusInfo status;

    // Unset status of QR code mode.

    status.led = kEsfLedManagerTargetLedPower;
    status.enabled = false;
    status.status = kEsfLedManagerLedStatusWaitingForInputsToConnectConsole;

    ret_ledmgr = EsfLedManagerSetStatus(&status);

    if (ret_ledmgr != kEsfLedManagerSuccess) {
        SYSAPP_ERR("EsfLedManagerSetStatus failed : ret=%d", ret_ledmgr);
    }

    // Set status to factory reset.

    status.enabled = true;
    status.status = kEsfLedManagerLedStatusUnableToAcceptInputs;

    ret_ledmgr = EsfLedManagerSetStatus(&status);

    if (ret_ledmgr != kEsfLedManagerSuccess) {
        SYSAPP_ERR("EsfLedManagerSetStatus failed : ret=%d", ret_ledmgr);
    }
}

/*----------------------------------------------------------------------------*/
STATIC void ButtonLongPressed5Callback(void *user_data)
{
    SYSAPP_INFO("Button pressed 5sec. %p", user_data);

    SetLedStatusForButtonLongPressed5();
}

/*----------------------------------------------------------------------------*/
STATIC void ButtonLongPressed30Callback(void *user_data)
{
    SYSAPP_INFO("Button pressed 30sec. %p", user_data);

    SetLedStatusForButtonLongPressed30();
}

//
// Public functions.
//

/*----------------------------------------------------------------------------*/
RetCode SysAppBtnInitialize(void)
{
    SYSAPP_INFO("Initialize Button block.");

    RetCode ret = kRetOk;
    EsfButtonManagerStatus esfbm_ret = kEsfButtonManagerStatusOk;

    // Open ButtonManager and get handle.

    esfbm_ret = EsfButtonManagerOpen(&s_esfbm_handle);

    if (esfbm_ret != kEsfButtonManagerStatusOk) {
        SYSAPP_CRIT("EsfButtonManagerOpen() ret %d", esfbm_ret);
        ret = kRetFailed;
        goto bm_open_failed;
    }

    // Register button pressed callback.

    esfbm_ret = EsfButtonManagerRegisterPressedCallback(0 /*button_id, accept only 0.*/,
                                                        ButtonPressedCallback,
                                                        NULL /*T.B.D user_data*/, s_esfbm_handle);

    if (esfbm_ret != kEsfButtonManagerStatusOk) {
        SYSAPP_CRIT("EsfButtonManagerRegisterPressedCallback() ret %d", esfbm_ret);
        ret = kRetFailed;
        goto bm_register_pressed_cb_failed;
    }

    // Register button released (between 5sec and 29sec) callback.

    esfbm_ret = EsfButtonManagerRegisterReleasedCallback(0 /*button_id, accept only 0.*/, 5, 29,
                                                         ButtonReleased5to29Callback,
                                                         NULL /*T.B.D user_data*/, s_esfbm_handle);

    if (esfbm_ret != kEsfButtonManagerStatusOk) {
        SYSAPP_CRIT("EsfButtonManagerRegisterReleasedCallback(5-29sec) ret %d", esfbm_ret);
        ret = kRetFailed;
        goto bm_register_released_5_29_cb_failed;
    }

    // Register button released (over 30sec) callback.

    esfbm_ret = EsfButtonManagerRegisterReleasedCallback(0 /*button_id, accept only 0.*/, 30, 0,
                                                         ButtonReleasedOver30Callback,
                                                         NULL /*T.B.D user_data*/, s_esfbm_handle);

    if (esfbm_ret != kEsfButtonManagerStatusOk) {
        SYSAPP_CRIT("EsfButtonManagerRegisterReleasedCallback(30sec) ret %d", esfbm_ret);
        ret = kRetFailed;
        goto bm_register_released_30_cb_failed;
    }

    // Register button long pressed 5sec callback.

    esfbm_ret = EsfButtonManagerRegisterLongPressedCallback(
        0 /*button_id, accept only 0.*/, 5, ButtonLongPressed5Callback, NULL /*T.B.D user_data*/,
        s_esfbm_handle);

    if (esfbm_ret != kEsfButtonManagerStatusOk) {
        SYSAPP_CRIT("EsfButtonManagerRegisterLongPressedCallback(5sec) ret %d", esfbm_ret);
        ret = kRetFailed;
        goto bm_register_long_pressed_5_cb_failed;
    }

    // Register button long pressed 30sec callback.

    esfbm_ret = EsfButtonManagerRegisterLongPressedCallback(
        0 /*button_id, accept only 0.*/, 30, ButtonLongPressed30Callback, NULL /*T.B.D user_data*/,
        s_esfbm_handle);

    if (esfbm_ret != kEsfButtonManagerStatusOk) {
        SYSAPP_CRIT("EsfButtonManagerRegisterLongPressedCallback(30sec) ret %d", esfbm_ret);
        ret = kRetFailed;
        goto bm_register_long_pressed_30_cb_failed;
    }

    // Activate registered callbacks.

    esfbm_ret = EsfButtonManagerEnableNotificationCallback(s_esfbm_handle);

    if (esfbm_ret != kEsfButtonManagerStatusOk) {
        SYSAPP_CRIT("EsfButtonManagerEnableNotificationCallback() ret %d", esfbm_ret);
        ret = kRetFailed;
        goto bm_register_enable_cb_failed;
    }

    // Update LED status.

    SysAppLedSetAppStatus(LedTypePower, LedAppStatusAbleToAcceptInput);

    return ret;

    //
    // From here, error handling.
    //

bm_register_enable_cb_failed:
bm_register_long_pressed_30_cb_failed:

    EsfButtonManagerUnregisterLongPressedCallback(0 /*button_id, accept only 0.*/, s_esfbm_handle);

bm_register_long_pressed_5_cb_failed:
bm_register_released_30_cb_failed:

    EsfButtonManagerUnregisterReleasedCallback(0 /*button_id, accept only 0.*/, s_esfbm_handle);

bm_register_released_5_29_cb_failed:

    EsfButtonManagerUnregisterPressedCallback(0 /*button_id, accept only 0.*/, s_esfbm_handle);

bm_register_pressed_cb_failed:

    EsfButtonManagerClose(s_esfbm_handle);

bm_open_failed:

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppBtnFinalize(void)
{
    SYSAPP_INFO("Finalize Button block.");

    RetCode ret = kRetOk;
    EsfButtonManagerStatus esfbm_ret = kEsfButtonManagerStatusOk;

    // Update LED status. (Cancel lighting patterns with high priority)

    SysAppLedUnsetAppStatus(LedTypePower, LedAppStatusAbleToAcceptInput);
    SysAppLedSetAppStatus(LedTypePower, LedAppStatusUnableToAcceptInput);

    // Deactivate registered callback.

    esfbm_ret = EsfButtonManagerDisableNotificationCallback(s_esfbm_handle);

    if (esfbm_ret != kEsfButtonManagerStatusOk) {
        SYSAPP_WARN("EsfButtonManagerDisableNotificationCallback() ret %d", esfbm_ret);
        ret = kRetFailed;
    }

    // Unregister long pressed callback.

    esfbm_ret = EsfButtonManagerUnregisterLongPressedCallback(0 /*button_id, accept only 0.*/,
                                                              s_esfbm_handle);

    if (esfbm_ret != kEsfButtonManagerStatusOk) {
        SYSAPP_WARN("EsfButtonManagerUnregisterLongPressedCallback() ret %d", esfbm_ret);
        ret = kRetFailed;
    }

    // Unregister released callback.

    esfbm_ret = EsfButtonManagerUnregisterReleasedCallback(0 /*button_id, accept only 0.*/,
                                                           s_esfbm_handle);

    if (esfbm_ret != kEsfButtonManagerStatusOk) {
        SYSAPP_WARN("EsfButtonManagerUnregisterReleasedCallback() ret %d", esfbm_ret);
        ret = kRetFailed;
    }

    // Unregister pressed callback.

    esfbm_ret = EsfButtonManagerUnregisterPressedCallback(0 /*button_id, accept only 0.*/,
                                                          s_esfbm_handle);

    if (esfbm_ret != kEsfButtonManagerStatusOk) {
        SYSAPP_WARN("EsfButtonManagerUnregisterPressedCallback() ret %d", esfbm_ret);
        ret = kRetFailed;
    }

    // Close ButtonManager.

    esfbm_ret = EsfButtonManagerClose(s_esfbm_handle);

    if (esfbm_ret != kEsfButtonManagerStatusOk) {
        SYSAPP_WARN("EsfButtonManagerClose() ret %d", esfbm_ret);
        ret = kRetFailed;
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
bool SysAppBtnCheckRebootRequest(void)
{
    return s_reboot_requested;
}

/*----------------------------------------------------------------------------*/
bool SysAppBtnCheckFactoryResetRequest(void)
{
    return s_factory_reset_requested;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppBtnExecuteFactoryResetCore(void)
{
    SYSAPP_INFO("Execute factory reset!");

    RetCode ret = kRetOk;

    s_factory_reset_requested = false;

    // Start factory reset, this API will execute reboot afeter factory reset process.

    EsfFwMgrResult esffm_ret = EsfFwMgrStartFactoryReset(kEsfFwMgrResetCauseButton);

    if (esffm_ret != kEsfFwMgrResultOk) {
        SYSAPP_ERR("EsfFwMgrStartFactoryReset() ret %d", esffm_ret);
        ret = kRetFailed;
    }

    return ret;
}
