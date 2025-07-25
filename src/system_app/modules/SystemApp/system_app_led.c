/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "led_manager.h"
//#include "evp/agent.h" // T.B.D.
#include "evp/sdk_sys.h"
#include "system_app_common.h"
#include "system_app_log.h"
#include "system_app_led.h"
#include "system_app_util.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

//
// Macros.
//

/*----------------------------------------------------------------------*/
void SysAppLedSetAppStatus(LedType type, LedAppStatus app_state)
{
    EsfLedManagerResult ret_ledmanager = kEsfLedManagerInternalError;
    EsfLedManagerLedStatusInfo status;

    SYSAPP_DBG("Set App Status:%d", app_state);
    status.led = (EsfLedManagerTargetLed)type;
    status.status = (EsfLedManagerLedStatus)app_state;
    status.enabled = true;

    ret_ledmanager = EsfLedManagerSetStatus(&status);

    if (ret_ledmanager != kEsfLedManagerSuccess) {
        SYSAPP_ERR("EsfLedManagerSetStatus(app_state) failed : ret=%d", ret_ledmanager);
    }
}

/*----------------------------------------------------------------------*/
void SysAppLedUnsetAppStatus(LedType type, LedAppStatus app_state)
{
    EsfLedManagerResult ret_ledmanager = kEsfLedManagerInternalError;
    EsfLedManagerLedStatusInfo status;

    SYSAPP_DBG("Unset App Status:%d", app_state);
    status.led = (EsfLedManagerTargetLed)type;
    status.status = (EsfLedManagerLedStatus)app_state;
    status.enabled = false;

    ret_ledmanager = EsfLedManagerSetStatus(&status);

    if (ret_ledmanager != kEsfLedManagerSuccess) {
        SYSAPP_ERR("EsfLedManagerSetStatus(app_state) failed : ret=%d", ret_ledmanager);
    }
}

/*----------------------------------------------------------------------*/
RetCode SysAppLedSetEnable(bool led_enable)
{
    RetCode ret = kRetOk;
    EsfLedManagerResult esflm_ret = kEsfLedManagerSuccess;
    EsfLedManagerLedStatusInfo status;

    // Set LED force on/off.

    status.status = kEsfLedManagerLedStatusForcedOff;
    status.enabled = !led_enable;

    // Set to all LEDs.

    for (EsfLedManagerTargetLed type = kEsfLedManagerTargetLedPower;
         type < kEsfLedManagerTargetLedNum; type++) {
        status.led = type;

        esflm_ret = EsfLedManagerSetStatus(&status);

        if (esflm_ret != kEsfLedManagerSuccess) {
            SYSAPP_ERR("EsfLedManagerSetStatus() failed %d", esflm_ret);
            ret = kRetFailed;
        }
    }

    return ret;
}

/*----------------------------------------------------------------------*/
RetCode SysAppLedGetEnable(bool* led_enable)
{
    RetCode ret = kRetOk;
    EsfLedManagerResult esflm_ret = kEsfLedManagerSuccess;
    EsfLedManagerLedStatusInfo status;
    bool esf_led_force_off = true;
    bool esf_led_force_off_prev = true;

    // Get LED force on/off info.

    status.status = kEsfLedManagerLedStatusForcedOff;

    // Get info from all LEDs.

    for (EsfLedManagerTargetLed type = kEsfLedManagerTargetLedPower;
         type < kEsfLedManagerTargetLedNum; type++) {
        status.led = type;

        esflm_ret = EsfLedManagerGetStatus(&status);

        if (esflm_ret != kEsfLedManagerSuccess) {
            SYSAPP_ERR("EsfLedManagerSetStatus() failed %d", esflm_ret);
            ret = kRetFailed;
            break;
        }
        else {
            //
            // If all LEDs are force off, led_enable will be DISABLE.
            // If one of LEDs is not force off, led_enable will be ENABLE.
            //

            esf_led_force_off &= status.enabled;

            // Check all LEDs setting are same? (Should be same!).

            if (type > kEsfLedManagerTargetLedPower) {
                if (esf_led_force_off_prev != status.enabled) {
                    ret = kRetFailed;
                }
            }

            esf_led_force_off_prev = status.enabled;
        }
    }

    // Set output value.(Force LED off means LED disable.)

    *led_enable = !esf_led_force_off;

    return ret;
}
