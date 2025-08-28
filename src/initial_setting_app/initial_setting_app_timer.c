/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#if defined(__NuttX__)
#include <nuttx/config.h>
#endif

#include <stdio.h>
#include "utility_timer.h"

#include "system_app_common.h"
#include "initial_setting_app_timer.h"
#include "initial_setting_app_timer_private.h"
#include "initial_setting_app_util.h"
#include "initial_setting_app_log.h"

//
// Macros.
//

#define ISA_TIMER_THREAD_STACK_SIZE (6 * 1024)

//
// File private structure.
//

//
// File private structure.
//

//
// File static variables.
//

STATIC IsaTimerContext s_qr_mode_timer_ctx;

//
// File static private functions.
//

/*----------------------------------------------------------------------------*/
STATIC void QrModeTimerCallback(void* timer_cb_params)
{
    ISA_INFO("QrModeTimerCallback() param %p", timer_cb_params);

    if (s_qr_mode_timer_ctx.cb != NULL) {
        s_qr_mode_timer_ctx.cb();
    }

    return;
}

//
// Public functions.
//

/*----------------------------------------------------------------------*/
RetCode IsaTimerInitialize(void)
{
    ISA_INFO("Initialize Timer block.");

    RetCode ret = kRetOk;
    UtilityTimerErrCode utim_ret = kUtilityTimerOk;

    // Initialize internal value.

    s_qr_mode_timer_ctx.handle = (UtilityTimerHandle)NULL;
    s_qr_mode_timer_ctx.is_working = false;
    s_qr_mode_timer_ctx.cb = NULL;

    // Create timer for qr mode.

    utim_ret = UtilityTimerCreateEx(QrModeTimerCallback, NULL, CONFIG_UTILITY_TIMER_THREAD_PRIORITY,
                                    ISA_TIMER_THREAD_STACK_SIZE, &s_qr_mode_timer_ctx.handle);

    if (utim_ret != kUtilityTimerOk) {
        ISA_CRIT("UtilityTimerCreateEx(QR) ret %u", utim_ret);
        ret = kRetFailed;
        goto qr_mode_timer_create_failed;
    }

    return ret;

    //
    // Error handling.
    //

qr_mode_timer_create_failed:

    return ret;
}

/*----------------------------------------------------------------------*/
RetCode IsaTimerFinalize(void)
{
    ISA_INFO("Finalize Timer block.");

    RetCode ret = kRetOk;
    UtilityTimerErrCode utim_ret = kUtilityTimerOk;

    // Delete timer for sensor tempterture.

    utim_ret = UtilityTimerDelete(s_qr_mode_timer_ctx.handle);

    if (utim_ret != kUtilityTimerOk) {
        ISA_WARN("UtilityTimerDelete(sensor_temp) ret %u", utim_ret);
        ret = kRetFailed;
    }

    return ret;
}

/*----------------------------------------------------------------------*/
RetCode IsaTimerStart(uint32_t time, IsaTimerCallback notify_cb)
{
    ISA_INFO("Start timer time %u", time);

    RetCode ret = kRetOk;
    UtilityTimerErrCode utim_ret = kUtilityTimerOk;
    IsaTimerContext* timer_ctx = &s_qr_mode_timer_ctx;

    // If specified timer is working, have to stop it.

    if (timer_ctx->is_working == true) {
        utim_ret = UtilityTimerStop(timer_ctx->handle);

        if (utim_ret != kUtilityTimerOk) {
            ISA_ERR("UtilityTimerStop() ret %u", utim_ret);
            return kRetFailed;
        }
    }

    // Start timer.

    struct timespec interval = {.tv_sec = (time_t)time, .tv_nsec = 0};

    utim_ret = UtilityTimerStart(timer_ctx->handle, &interval, kUtilityTimerRepeat);

    if (utim_ret != kUtilityTimerOk) {
        ISA_ERR("UtilityTimerStart() ret %u", utim_ret);
        ret = kRetFailed;
    }
    else {
        timer_ctx->is_working = true;

        if (notify_cb != NULL) {
            timer_ctx->cb = notify_cb;
        }
    }

    return ret;
}

/*----------------------------------------------------------------------*/
RetCode IsaTimerStop(void)
{
    ISA_INFO("Stop timer");

    RetCode ret = kRetOk;
    UtilityTimerErrCode utim_ret = kUtilityTimerOk;
    IsaTimerContext* timer_ctx = &s_qr_mode_timer_ctx;

    // Check specified timer is working?

    if (timer_ctx->is_working != true) {
        ISA_INFO("timer is already stopped.");
        return kRetFailed;
    }

    // Stop timer.

    utim_ret = UtilityTimerStop(timer_ctx->handle);

    if (utim_ret != kUtilityTimerOk) {
        ISA_ERR("UtilityTimerStop() ret %u", utim_ret);
        ret = kRetFailed;
    }
    else {
        timer_ctx->is_working = false;
        timer_ctx->cb = NULL;
    }

    return ret;
}
