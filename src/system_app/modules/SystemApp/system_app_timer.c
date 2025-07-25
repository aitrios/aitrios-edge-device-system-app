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
#include "system_app_timer.h"
#include "system_app_timer_private.h"
#include "system_app_common.h"
#include "system_app_log.h"
#include "system_app_util.h"

//
// Macros.
//

#define SA_TIMER_THREAD_STACK_SIZE (6 * 1024)

//
// File private structure.
//

//
// File private structure.
//

//
// File static variables.
//

STATIC TimerContext s_sensortemp_timer_ctx;
STATIC TimerContext s_hoursmeter_timer_ctx;

//
// File static private functions.
//

/*----------------------------------------------------------------------*/
STATIC void SensorTempTimerCallback(void* timer_cb_params)
{
    SYSAPP_INFO("SensorTempTimerCallback() param %p", timer_cb_params);

    if (s_sensortemp_timer_ctx.cb != NULL) {
        s_sensortemp_timer_ctx.cb();
    }

    return;
}

/*----------------------------------------------------------------------*/
STATIC void HoursMeterTimerCallback(void* timer_cb_params)
{
    SYSAPP_INFO("HoursMeterTimerCallback() param %p", timer_cb_params);

    if (s_hoursmeter_timer_ctx.cb != NULL) {
        s_hoursmeter_timer_ctx.cb();
    }

    return;
}

/*----------------------------------------------------------------------*/
static TimerContext* GetTimerContext(TimerType type)
{
    // Get timer context from type.

    if (type == SensorTempIntervalTimer) {
        return &s_sensortemp_timer_ctx;
    }
    else if (type == HoursMeterIntervalTimer) {
        return &s_hoursmeter_timer_ctx;
    }
    else {
        return NULL;
    }
}

//
// Public functions.
//

/*----------------------------------------------------------------------*/
RetCode SysAppTimerInitialize(void)
{
    SYSAPP_INFO("Initialize Timer block.");

    RetCode ret = kRetOk;
    UtilityTimerErrCode utim_ret = kUtilityTimerOk;

    // Initialize internal value.

    s_sensortemp_timer_ctx.handle = (UtilityTimerHandle)NULL;
    s_sensortemp_timer_ctx.is_working = false;
    s_sensortemp_timer_ctx.cb = NULL;

    s_hoursmeter_timer_ctx.handle = (UtilityTimerHandle)NULL;
    s_hoursmeter_timer_ctx.is_working = false;
    s_hoursmeter_timer_ctx.cb = NULL;

    // Create timer for sensor temperature.

    utim_ret = UtilityTimerCreateEx(SensorTempTimerCallback, NULL,
                                    CONFIG_UTILITY_TIMER_THREAD_PRIORITY,
                                    SA_TIMER_THREAD_STACK_SIZE, &s_sensortemp_timer_ctx.handle);

    if (utim_ret != kUtilityTimerOk) {
        SYSAPP_ERR("UtilityTimerCreateEx(sensor_temp) ret %d", utim_ret);
        ret = kRetFailed;
        goto sensor_temp_timer_create_failed;
    }

    // Create timer for sensor temperature.

    utim_ret = UtilityTimerCreateEx(HoursMeterTimerCallback, NULL,
                                    CONFIG_UTILITY_TIMER_THREAD_PRIORITY,
                                    SA_TIMER_THREAD_STACK_SIZE, &s_hoursmeter_timer_ctx.handle);

    if (utim_ret != kUtilityTimerOk) {
        SYSAPP_ERR("UtilityTimerCreateEx(hours_meter) ret %d", utim_ret);
        ret = kRetFailed;
        goto hours_meter_timer_create_failed;
    }

    return ret;

    //
    // Error handling.
    //

hours_meter_timer_create_failed:

    UtilityTimerDelete(s_sensortemp_timer_ctx.handle);

sensor_temp_timer_create_failed:

    return ret;
}

/*----------------------------------------------------------------------*/
RetCode SysAppTimerFinalize(void)
{
    SYSAPP_INFO("Finalize Timer block.");

    RetCode ret = kRetOk;
    UtilityTimerErrCode utim_ret = kUtilityTimerOk;

    // Delete timer for sensor tempterture.

    utim_ret = UtilityTimerDelete(s_sensortemp_timer_ctx.handle);

    if (utim_ret != kUtilityTimerOk) {
        SYSAPP_WARN("UtilityTimerDelete(sensor_temp) ret %d", utim_ret);
        ret = kRetFailed;
    }

    // Delete timer for hours meter.

    utim_ret = UtilityTimerDelete(s_hoursmeter_timer_ctx.handle);

    if (utim_ret != kUtilityTimerOk) {
        SYSAPP_WARN("UtilityTimerDelete(hours_meter) ret %d", utim_ret);
        ret = kRetFailed;
    }

    return ret;
}

/*----------------------------------------------------------------------*/
RetCode SysAppTimerStartTimer(TimerType type, uint32_t time, TimerCallback notify_cb)
{
    SYSAPP_INFO("Start timer type %d time %d", type, time);

    RetCode ret = kRetOk;
    UtilityTimerErrCode utim_ret = kUtilityTimerOk;
    TimerContext* timer_ctx = NULL;

    // Get timer context which is according to timer type.

    timer_ctx = GetTimerContext(type);

    if (timer_ctx == NULL) {
        SYSAPP_ERR("Invalid timer type %d", type);
        return kRetFailed;
    }

    // If specified timer is working, have to stop it.

    if (timer_ctx->is_working == true) {
        utim_ret = UtilityTimerStop(timer_ctx->handle);

        if (utim_ret != kUtilityTimerOk) {
            SYSAPP_ERR("UtilityTimerStop() ret %d", utim_ret);
            return kRetFailed;
        }
    }

    // Start timer.

    struct timespec interval = {.tv_sec = (time_t)time, .tv_nsec = 0};

    utim_ret = UtilityTimerStart(timer_ctx->handle, &interval, kUtilityTimerRepeat);

    if (utim_ret != kUtilityTimerOk) {
        SYSAPP_ERR("UtilityTimerStart() ret %d", utim_ret);
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
RetCode SysAppTimerUpdateTimer(TimerType type, uint32_t time)
{
    return SysAppTimerStartTimer(type, time, NULL);
}

/*----------------------------------------------------------------------*/
RetCode SysAppTimerStopTimer(TimerType type)
{
    SYSAPP_INFO("Stop timer type %d", type);

    RetCode ret = kRetOk;
    UtilityTimerErrCode utim_ret = kUtilityTimerOk;
    TimerContext* timer_ctx = NULL;

    // Get timer context which is according to timer type.

    timer_ctx = GetTimerContext(type);

    if (timer_ctx == NULL) {
        SYSAPP_ERR("Invalid timer type %d", type);
        return kRetFailed;
    }

    // Check specified timer is working?

    if (timer_ctx->is_working != true) {
        SYSAPP_INFO("timer type %d is already stopped.", type);
        return kRetFailed;
    }

    // Stop timer.

    utim_ret = UtilityTimerStop(timer_ctx->handle);

    if (utim_ret != kUtilityTimerOk) {
        SYSAPP_ERR("UtilityTimerStop() ret %d", utim_ret);
        ret = kRetFailed;
    }
    else {
        timer_ctx->is_working = false;
        timer_ctx->cb = NULL;
    }

    return ret;
}
