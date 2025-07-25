/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#if defined(__NuttX__)
#include <nuttx/config.h>
#endif
#include "system_app_timer.h"
#include "system_app_timer_private.h"

extern TimerContext s_sensortemp_timer_ctx;
extern TimerContext s_hoursmeter_timer_ctx;

extern void SensorTempTimerCallback(void *timer_cb_params);
extern void HoursMeterTimerCallback(void *timer_cb_params);

#define UT_SA_TIMER_THREAD_STACK_SIZE (6 * 1024)

/*----------------------------------------------------------------------------*/

//
// Registerd Callback
//

/*----------------------------------------------------------------------------*/
static void SensorTempIntervalCallback(void)
{
    function_called();

    return;
}

/*----------------------------------------------------------------------------*/
static void HoursMeterIntervalCallback(void)
{
    function_called();

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppTimerInitialize()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppTimerInitialize_FullySuccess(void **state)
{
    UtilityTimerHandle timer_handle_sensor_temp = (UtilityTimerHandle)0x12345678;
    UtilityTimerHandle timer_handle_hours_meter = (UtilityTimerHandle)0x98765432;
    RetCode ret;

    expect_value(__wrap_UtilityTimerCreateEx, callback, SensorTempTimerCallback);
    expect_value(__wrap_UtilityTimerCreateEx, cb_params, NULL);
    expect_value(__wrap_UtilityTimerCreateEx, priority, CONFIG_UTILITY_TIMER_THREAD_PRIORITY);
    expect_value(__wrap_UtilityTimerCreateEx, stacksize, UT_SA_TIMER_THREAD_STACK_SIZE);
    will_return(__wrap_UtilityTimerCreateEx, timer_handle_sensor_temp);
    will_return(__wrap_UtilityTimerCreateEx, kUtilityTimerOk);

    expect_value(__wrap_UtilityTimerCreateEx, callback, HoursMeterTimerCallback);
    expect_value(__wrap_UtilityTimerCreateEx, cb_params, NULL);
    expect_value(__wrap_UtilityTimerCreateEx, priority, CONFIG_UTILITY_TIMER_THREAD_PRIORITY);
    expect_value(__wrap_UtilityTimerCreateEx, stacksize, UT_SA_TIMER_THREAD_STACK_SIZE);
    will_return(__wrap_UtilityTimerCreateEx, timer_handle_hours_meter);
    will_return(__wrap_UtilityTimerCreateEx, kUtilityTimerOk);

    ret = SysAppTimerInitialize();

    assert_int_equal(ret, kRetOk);

    assert_int_equal(s_sensortemp_timer_ctx.handle, timer_handle_sensor_temp);
    assert_false(s_sensortemp_timer_ctx.is_working);
    assert_null(s_sensortemp_timer_ctx.cb);

    assert_int_equal(s_hoursmeter_timer_ctx.handle, timer_handle_hours_meter);
    assert_false(s_hoursmeter_timer_ctx.is_working);
    assert_null(s_hoursmeter_timer_ctx.cb);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppTimerInitialize_ErrorUtilityTimerCreateExForSensorTemp(void **state)
{
    UtilityTimerHandle timer_handle_sensor_temp = (UtilityTimerHandle)0x12345678;
    // UtilityTimerHandle timer_handle_hours_meter = (UtilityTimerHandle)0x98765432;
    RetCode ret;

    expect_value(__wrap_UtilityTimerCreateEx, callback, SensorTempTimerCallback);
    expect_value(__wrap_UtilityTimerCreateEx, cb_params, NULL);
    expect_value(__wrap_UtilityTimerCreateEx, priority, CONFIG_UTILITY_TIMER_THREAD_PRIORITY);
    expect_value(__wrap_UtilityTimerCreateEx, stacksize, UT_SA_TIMER_THREAD_STACK_SIZE);
    will_return(__wrap_UtilityTimerCreateEx, timer_handle_sensor_temp);
    will_return(__wrap_UtilityTimerCreateEx, kUtilityTimerErrInternal);

    ret = SysAppTimerInitialize();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppTimerInitialize_ErrorUtilityTimerCreateExForHoursMeter(void **state)
{
    UtilityTimerHandle timer_handle_sensor_temp = (UtilityTimerHandle)0x12345678;
    UtilityTimerHandle timer_handle_hours_meter = (UtilityTimerHandle)0x98765432;
    RetCode ret;

    expect_value(__wrap_UtilityTimerCreateEx, callback, SensorTempTimerCallback);
    expect_value(__wrap_UtilityTimerCreateEx, cb_params, NULL);
    expect_value(__wrap_UtilityTimerCreateEx, priority, CONFIG_UTILITY_TIMER_THREAD_PRIORITY);
    expect_value(__wrap_UtilityTimerCreateEx, stacksize, UT_SA_TIMER_THREAD_STACK_SIZE);
    will_return(__wrap_UtilityTimerCreateEx, timer_handle_sensor_temp);
    will_return(__wrap_UtilityTimerCreateEx, kUtilityTimerOk);

    expect_value(__wrap_UtilityTimerCreateEx, callback, HoursMeterTimerCallback);
    expect_value(__wrap_UtilityTimerCreateEx, cb_params, NULL);
    expect_value(__wrap_UtilityTimerCreateEx, priority, CONFIG_UTILITY_TIMER_THREAD_PRIORITY);
    expect_value(__wrap_UtilityTimerCreateEx, stacksize, UT_SA_TIMER_THREAD_STACK_SIZE);
    will_return(__wrap_UtilityTimerCreateEx, timer_handle_hours_meter);
    will_return(__wrap_UtilityTimerCreateEx, kUtilityTimerErrInternal);

    expect_value(__wrap_UtilityTimerDelete, utility_timer_handle, timer_handle_sensor_temp);
    will_return(__wrap_UtilityTimerDelete, kUtilityTimerOk);

    ret = SysAppTimerInitialize();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppTimerFinalize()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppTimerFinalize_FullySuccess(void **state)
{
    RetCode ret;

    s_sensortemp_timer_ctx.handle = (UtilityTimerHandle)0x98765432;
    s_hoursmeter_timer_ctx.handle = (UtilityTimerHandle)0x12345678;

    expect_value(__wrap_UtilityTimerDelete, utility_timer_handle, s_sensortemp_timer_ctx.handle);
    will_return(__wrap_UtilityTimerDelete, kUtilityTimerOk);

    expect_value(__wrap_UtilityTimerDelete, utility_timer_handle, s_hoursmeter_timer_ctx.handle);
    will_return(__wrap_UtilityTimerDelete, kUtilityTimerOk);

    ret = SysAppTimerFinalize();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppTimerFinalize_ErrorUtilityTimerDeleteForSensorTemp(void **state)
{
    RetCode ret;

    s_sensortemp_timer_ctx.handle = (UtilityTimerHandle)0x98765432;
    s_hoursmeter_timer_ctx.handle = (UtilityTimerHandle)0x12345678;

    expect_value(__wrap_UtilityTimerDelete, utility_timer_handle, s_sensortemp_timer_ctx.handle);
    will_return(__wrap_UtilityTimerDelete, kUtilityTimerErrInternal);

    expect_value(__wrap_UtilityTimerDelete, utility_timer_handle, s_hoursmeter_timer_ctx.handle);
    will_return(__wrap_UtilityTimerDelete, kUtilityTimerOk);

    ret = SysAppTimerFinalize();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppTimerFinalize_ErrorUtilityTimerDeleteForHoursMeter(void **state)
{
    RetCode ret;

    s_sensortemp_timer_ctx.handle = (UtilityTimerHandle)0x98765432;
    s_hoursmeter_timer_ctx.handle = (UtilityTimerHandle)0x12345678;

    expect_value(__wrap_UtilityTimerDelete, utility_timer_handle, s_sensortemp_timer_ctx.handle);
    will_return(__wrap_UtilityTimerDelete, kUtilityTimerOk);

    expect_value(__wrap_UtilityTimerDelete, utility_timer_handle, s_hoursmeter_timer_ctx.handle);
    will_return(__wrap_UtilityTimerDelete, kUtilityTimerErrInternal);

    ret = SysAppTimerFinalize();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppTimerStartTimer()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppTimerStartTimer_FullySuccessSensorTemp(void **state)
{
    uint32_t time = 100;
    RetCode ret;

    s_sensortemp_timer_ctx.handle = (UtilityTimerHandle)0x13572468;
    s_sensortemp_timer_ctx.is_working = false;
    s_sensortemp_timer_ctx.cb = NULL;

    s_hoursmeter_timer_ctx.handle = (UtilityTimerHandle)0x97538642;
    s_hoursmeter_timer_ctx.is_working = false;
    s_hoursmeter_timer_ctx.cb = NULL;

    expect_value(__wrap_UtilityTimerStart, utility_timer_handle, s_sensortemp_timer_ctx.handle);
    expect_value(__wrap_UtilityTimerStart, interval_ts->tv_sec, time);
    expect_value(__wrap_UtilityTimerStart, interval_ts->tv_nsec, 0);
    expect_value(__wrap_UtilityTimerStart, utility_timer_repeat_type, kUtilityTimerRepeat);
    will_return(__wrap_UtilityTimerStart, kUtilityTimerOk);

    ret = SysAppTimerStartTimer(SensorTempIntervalTimer, time, SensorTempIntervalCallback);

    assert_int_equal(ret, kRetOk);

    assert_true(s_sensortemp_timer_ctx.is_working);
    assert_ptr_equal(s_sensortemp_timer_ctx.cb, SensorTempIntervalCallback);

    assert_false(s_hoursmeter_timer_ctx.is_working);
    assert_null(s_hoursmeter_timer_ctx.cb);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppTimerStartTimer_FullySuccessHoursMeter(void **state)
{
    uint32_t time = 200;
    RetCode ret;

    s_sensortemp_timer_ctx.handle = (UtilityTimerHandle)0x13572468;
    s_sensortemp_timer_ctx.is_working = false;
    s_sensortemp_timer_ctx.cb = NULL;

    s_hoursmeter_timer_ctx.handle = (UtilityTimerHandle)0x97538642;
    s_hoursmeter_timer_ctx.is_working = false;
    s_hoursmeter_timer_ctx.cb = NULL;

    expect_value(__wrap_UtilityTimerStart, utility_timer_handle, s_hoursmeter_timer_ctx.handle);
    expect_value(__wrap_UtilityTimerStart, interval_ts->tv_sec, time);
    expect_value(__wrap_UtilityTimerStart, interval_ts->tv_nsec, 0);
    expect_value(__wrap_UtilityTimerStart, utility_timer_repeat_type, kUtilityTimerRepeat);
    will_return(__wrap_UtilityTimerStart, kUtilityTimerOk);

    ret = SysAppTimerStartTimer(HoursMeterIntervalTimer, time, HoursMeterIntervalCallback);

    assert_int_equal(ret, kRetOk);

    assert_false(s_sensortemp_timer_ctx.is_working);
    assert_null(s_sensortemp_timer_ctx.cb);

    assert_true(s_hoursmeter_timer_ctx.is_working);
    assert_ptr_equal(s_hoursmeter_timer_ctx.cb, HoursMeterIntervalCallback);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppTimerStartTimer_FullySuccessNotRegisterCb(void **state)
{
    uint32_t time = 100;
    RetCode ret;

    s_sensortemp_timer_ctx.handle = (UtilityTimerHandle)0x13572468;
    s_sensortemp_timer_ctx.is_working = false;
    s_sensortemp_timer_ctx.cb = SensorTempIntervalCallback;

    s_hoursmeter_timer_ctx.handle = (UtilityTimerHandle)0x97538642;
    s_hoursmeter_timer_ctx.is_working = false;
    s_hoursmeter_timer_ctx.cb = HoursMeterIntervalCallback;

    expect_value(__wrap_UtilityTimerStart, utility_timer_handle, s_sensortemp_timer_ctx.handle);
    expect_value(__wrap_UtilityTimerStart, interval_ts->tv_sec, time);
    expect_value(__wrap_UtilityTimerStart, interval_ts->tv_nsec, 0);
    expect_value(__wrap_UtilityTimerStart, utility_timer_repeat_type, kUtilityTimerRepeat);
    will_return(__wrap_UtilityTimerStart, kUtilityTimerOk);

    ret = SysAppTimerStartTimer(SensorTempIntervalTimer, time, NULL);

    assert_int_equal(ret, kRetOk);

    assert_true(s_sensortemp_timer_ctx.is_working);
    assert_ptr_equal(s_sensortemp_timer_ctx.cb, SensorTempIntervalCallback);

    assert_false(s_hoursmeter_timer_ctx.is_working);
    assert_ptr_equal(s_hoursmeter_timer_ctx.cb, HoursMeterIntervalCallback);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppTimerStartTimer_FullySuccessAlreadyWorking(void **state)
{
    uint32_t time = 100;
    RetCode ret;

    s_sensortemp_timer_ctx.handle = (UtilityTimerHandle)0x13572468;
    s_sensortemp_timer_ctx.is_working = true;
    s_sensortemp_timer_ctx.cb = NULL;

    s_hoursmeter_timer_ctx.handle = (UtilityTimerHandle)0x97538642;
    s_hoursmeter_timer_ctx.is_working = false;
    s_hoursmeter_timer_ctx.cb = NULL;

    expect_value(__wrap_UtilityTimerStop, utility_timer_handle, s_sensortemp_timer_ctx.handle);
    will_return(__wrap_UtilityTimerStop, kUtilityTimerOk);

    expect_value(__wrap_UtilityTimerStart, utility_timer_handle, s_sensortemp_timer_ctx.handle);
    expect_value(__wrap_UtilityTimerStart, interval_ts->tv_sec, time);
    expect_value(__wrap_UtilityTimerStart, interval_ts->tv_nsec, 0);
    expect_value(__wrap_UtilityTimerStart, utility_timer_repeat_type, kUtilityTimerRepeat);
    will_return(__wrap_UtilityTimerStart, kUtilityTimerOk);

    ret = SysAppTimerStartTimer(SensorTempIntervalTimer, time, SensorTempIntervalCallback);

    assert_int_equal(ret, kRetOk);

    assert_true(s_sensortemp_timer_ctx.is_working);
    assert_ptr_equal(s_sensortemp_timer_ctx.cb, SensorTempIntervalCallback);

    assert_false(s_hoursmeter_timer_ctx.is_working);
    assert_null(s_hoursmeter_timer_ctx.cb);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppTimerStartTimer_InvalidType(void **state)
{
    uint32_t time = 100;
    RetCode ret;

    s_sensortemp_timer_ctx.handle = (UtilityTimerHandle)0x13572468;
    s_sensortemp_timer_ctx.is_working = false;
    s_sensortemp_timer_ctx.cb = NULL;

    s_hoursmeter_timer_ctx.handle = (UtilityTimerHandle)0x97538642;
    s_hoursmeter_timer_ctx.is_working = false;
    s_hoursmeter_timer_ctx.cb = NULL;

    ret = SysAppTimerStartTimer(TimerTypeNum, time, SensorTempIntervalCallback);

    assert_int_equal(ret, kRetFailed);

    assert_false(s_sensortemp_timer_ctx.is_working);
    assert_null(s_sensortemp_timer_ctx.cb);

    assert_false(s_hoursmeter_timer_ctx.is_working);
    assert_null(s_hoursmeter_timer_ctx.cb);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppTimerStartTimer_ErrorUtilityTimerStop(void **state)
{
    uint32_t time = 100;
    RetCode ret;

    s_sensortemp_timer_ctx.handle = (UtilityTimerHandle)0x13572468;
    s_sensortemp_timer_ctx.is_working = true;
    s_sensortemp_timer_ctx.cb = NULL;

    s_hoursmeter_timer_ctx.handle = (UtilityTimerHandle)0x97538642;
    s_hoursmeter_timer_ctx.is_working = false;
    s_hoursmeter_timer_ctx.cb = NULL;

    expect_value(__wrap_UtilityTimerStop, utility_timer_handle, s_sensortemp_timer_ctx.handle);
    will_return(__wrap_UtilityTimerStop, kUtilityTimerErrInternal);

    ret = SysAppTimerStartTimer(SensorTempIntervalTimer, time, SensorTempIntervalCallback);

    assert_int_equal(ret, kRetFailed);

    assert_true(s_sensortemp_timer_ctx.is_working);
    assert_null(s_sensortemp_timer_ctx.cb);

    assert_false(s_hoursmeter_timer_ctx.is_working);
    assert_null(s_hoursmeter_timer_ctx.cb);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppTimerStartTimer_ErrorUtilityTimerStart(void **state)
{
    uint32_t time = 100;
    RetCode ret;

    s_sensortemp_timer_ctx.handle = (UtilityTimerHandle)0x13572468;
    s_sensortemp_timer_ctx.is_working = false;
    s_sensortemp_timer_ctx.cb = NULL;

    s_hoursmeter_timer_ctx.handle = (UtilityTimerHandle)0x97538642;
    s_hoursmeter_timer_ctx.is_working = false;
    s_hoursmeter_timer_ctx.cb = NULL;

    expect_value(__wrap_UtilityTimerStart, utility_timer_handle, s_sensortemp_timer_ctx.handle);
    expect_value(__wrap_UtilityTimerStart, interval_ts->tv_sec, time);
    expect_value(__wrap_UtilityTimerStart, interval_ts->tv_nsec, 0);
    expect_value(__wrap_UtilityTimerStart, utility_timer_repeat_type, kUtilityTimerRepeat);
    will_return(__wrap_UtilityTimerStart, kUtilityTimerErrInternal);

    ret = SysAppTimerStartTimer(SensorTempIntervalTimer, time, SensorTempIntervalCallback);

    assert_int_equal(ret, kRetFailed);

    assert_false(s_sensortemp_timer_ctx.is_working);
    assert_null(s_sensortemp_timer_ctx.cb);

    assert_false(s_hoursmeter_timer_ctx.is_working);
    assert_null(s_hoursmeter_timer_ctx.cb);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppTimerUpdateTimer()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppTimerUpdateTimer(void **state)
{
    uint32_t time = 300;
    RetCode ret;

    s_sensortemp_timer_ctx.handle = (UtilityTimerHandle)0x13572468;
    s_sensortemp_timer_ctx.is_working = false;
    s_sensortemp_timer_ctx.cb = SensorTempIntervalCallback;

    s_hoursmeter_timer_ctx.handle = (UtilityTimerHandle)0x97538642;
    s_hoursmeter_timer_ctx.is_working = false;
    s_hoursmeter_timer_ctx.cb = HoursMeterIntervalCallback;

    expect_value(__wrap_UtilityTimerStart, utility_timer_handle, s_hoursmeter_timer_ctx.handle);
    expect_value(__wrap_UtilityTimerStart, interval_ts->tv_sec, time);
    expect_value(__wrap_UtilityTimerStart, interval_ts->tv_nsec, 0);
    expect_value(__wrap_UtilityTimerStart, utility_timer_repeat_type, kUtilityTimerRepeat);
    will_return(__wrap_UtilityTimerStart, kUtilityTimerOk);

    ret = SysAppTimerUpdateTimer(HoursMeterIntervalTimer, time);

    assert_int_equal(ret, kRetOk);

    assert_false(s_sensortemp_timer_ctx.is_working);
    assert_ptr_equal(s_sensortemp_timer_ctx.cb, SensorTempIntervalCallback);

    assert_true(s_hoursmeter_timer_ctx.is_working);
    assert_ptr_equal(s_hoursmeter_timer_ctx.cb, HoursMeterIntervalCallback);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppTimerStopTimer()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppTimerStopTimer_FullySuccessSensorTemp(void **state)
{
    RetCode ret;

    s_sensortemp_timer_ctx.handle = (UtilityTimerHandle)0x13572468;
    s_sensortemp_timer_ctx.is_working = true;
    s_sensortemp_timer_ctx.cb = SensorTempIntervalCallback;

    s_hoursmeter_timer_ctx.handle = (UtilityTimerHandle)0x97538642;
    s_hoursmeter_timer_ctx.is_working = false;
    s_hoursmeter_timer_ctx.cb = HoursMeterIntervalCallback;

    expect_value(__wrap_UtilityTimerStop, utility_timer_handle, s_sensortemp_timer_ctx.handle);
    will_return(__wrap_UtilityTimerStop, kUtilityTimerOk);

    ret = SysAppTimerStopTimer(SensorTempIntervalTimer);

    assert_int_equal(ret, kRetOk);

    assert_false(s_sensortemp_timer_ctx.is_working);
    assert_null(s_sensortemp_timer_ctx.cb);

    assert_false(s_hoursmeter_timer_ctx.is_working);
    assert_ptr_equal(s_hoursmeter_timer_ctx.cb, HoursMeterIntervalCallback);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppTimerStopTimer_FullySuccessHoursMeter(void **state)
{
    RetCode ret;

    s_sensortemp_timer_ctx.handle = (UtilityTimerHandle)0x13572468;
    s_sensortemp_timer_ctx.is_working = false;
    s_sensortemp_timer_ctx.cb = SensorTempIntervalCallback;

    s_hoursmeter_timer_ctx.handle = (UtilityTimerHandle)0x97538642;
    s_hoursmeter_timer_ctx.is_working = true;
    s_hoursmeter_timer_ctx.cb = HoursMeterIntervalCallback;

    expect_value(__wrap_UtilityTimerStop, utility_timer_handle, s_hoursmeter_timer_ctx.handle);
    will_return(__wrap_UtilityTimerStop, kUtilityTimerOk);

    ret = SysAppTimerStopTimer(HoursMeterIntervalTimer);

    assert_int_equal(ret, kRetOk);

    assert_false(s_sensortemp_timer_ctx.is_working);
    assert_ptr_equal(s_sensortemp_timer_ctx.cb, SensorTempIntervalCallback);

    assert_false(s_hoursmeter_timer_ctx.is_working);
    assert_null(s_hoursmeter_timer_ctx.cb);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppTimerStopTimer_InvalidType(void **state)
{
    RetCode ret;

    s_sensortemp_timer_ctx.handle = (UtilityTimerHandle)0x13572468;
    s_sensortemp_timer_ctx.is_working = true;
    s_sensortemp_timer_ctx.cb = SensorTempIntervalCallback;

    s_hoursmeter_timer_ctx.handle = (UtilityTimerHandle)0x97538642;
    s_hoursmeter_timer_ctx.is_working = true;
    s_hoursmeter_timer_ctx.cb = HoursMeterIntervalCallback;

    ret = SysAppTimerStopTimer(TimerTypeNum);

    assert_int_equal(ret, kRetFailed);

    assert_true(s_sensortemp_timer_ctx.is_working);
    assert_ptr_equal(s_sensortemp_timer_ctx.cb, SensorTempIntervalCallback);

    assert_true(s_hoursmeter_timer_ctx.is_working);
    assert_ptr_equal(s_hoursmeter_timer_ctx.cb, HoursMeterIntervalCallback);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppTimerStopTimer_NotWorking(void **state)
{
    RetCode ret;

    s_sensortemp_timer_ctx.handle = (UtilityTimerHandle)0x13572468;
    s_sensortemp_timer_ctx.is_working = false;
    s_sensortemp_timer_ctx.cb = SensorTempIntervalCallback;

    s_hoursmeter_timer_ctx.handle = (UtilityTimerHandle)0x97538642;
    s_hoursmeter_timer_ctx.is_working = false;
    s_hoursmeter_timer_ctx.cb = HoursMeterIntervalCallback;

    ret = SysAppTimerStopTimer(SensorTempIntervalTimer);

    assert_int_equal(ret, kRetFailed);

    assert_false(s_sensortemp_timer_ctx.is_working);
    assert_ptr_equal(s_sensortemp_timer_ctx.cb, SensorTempIntervalCallback);

    assert_false(s_hoursmeter_timer_ctx.is_working);
    assert_ptr_equal(s_hoursmeter_timer_ctx.cb, HoursMeterIntervalCallback);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppTimerStopTimer_ErrorUtilityTimerStop(void **state)
{
    RetCode ret;

    s_sensortemp_timer_ctx.handle = (UtilityTimerHandle)0x13572468;
    s_sensortemp_timer_ctx.is_working = true;
    s_sensortemp_timer_ctx.cb = SensorTempIntervalCallback;

    s_hoursmeter_timer_ctx.handle = (UtilityTimerHandle)0x97538642;
    s_hoursmeter_timer_ctx.is_working = true;
    s_hoursmeter_timer_ctx.cb = HoursMeterIntervalCallback;

    expect_value(__wrap_UtilityTimerStop, utility_timer_handle, s_sensortemp_timer_ctx.handle);
    will_return(__wrap_UtilityTimerStop, kUtilityTimerErrInternal);

    ret = SysAppTimerStopTimer(SensorTempIntervalTimer);

    assert_int_equal(ret, kRetFailed);

    assert_true(s_sensortemp_timer_ctx.is_working);
    assert_ptr_equal(s_sensortemp_timer_ctx.cb, SensorTempIntervalCallback);

    assert_true(s_hoursmeter_timer_ctx.is_working);
    assert_ptr_equal(s_hoursmeter_timer_ctx.cb, HoursMeterIntervalCallback);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SensorTempTimerCallback()
//

/*----------------------------------------------------------------------------*/
static void test_SensorTempTimerCallback_RegisteredCallback(void **state)
{
    s_sensortemp_timer_ctx.cb = SensorTempIntervalCallback;
    s_hoursmeter_timer_ctx.cb = HoursMeterIntervalCallback;

    expect_function_call(SensorTempIntervalCallback);

    SensorTempTimerCallback(NULL);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SensorTempTimerCallback_NotRegisteredCallback(void **state)
{
    s_sensortemp_timer_ctx.cb = NULL;
    s_hoursmeter_timer_ctx.cb = HoursMeterIntervalCallback;

    SensorTempTimerCallback(NULL);

    return;
}

/*----------------------------------------------------------------------------*/

//
// HoursMeterTimerCallback()
//

/*----------------------------------------------------------------------------*/
static void test_HoursMeterTimerCallback_RegisteredCallback(void **state)
{
    s_sensortemp_timer_ctx.cb = SensorTempIntervalCallback;
    s_hoursmeter_timer_ctx.cb = HoursMeterIntervalCallback;

    expect_function_call(HoursMeterIntervalCallback);

    HoursMeterTimerCallback(NULL);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_HoursMeterTimerCallback_NotRegisteredCallback(void **state)
{
    s_sensortemp_timer_ctx.cb = SensorTempIntervalCallback;
    s_hoursmeter_timer_ctx.cb = NULL;

    HoursMeterTimerCallback(NULL);

    return;
}

/*----------------------------------------------------------------------------*/

//
// main()
//

/*----------------------------------------------------------------------------*/
int main(void)
{
    const struct CMUnitTest tests[] = {
        // SysAppTimerInitialize()
        cmocka_unit_test(test_SysAppTimerInitialize_FullySuccess),
        cmocka_unit_test(test_SysAppTimerInitialize_ErrorUtilityTimerCreateExForSensorTemp),
        cmocka_unit_test(test_SysAppTimerInitialize_ErrorUtilityTimerCreateExForHoursMeter),

        // SysAppTimerFinalize()
        cmocka_unit_test(test_SysAppTimerFinalize_FullySuccess),
        cmocka_unit_test(test_SysAppTimerFinalize_ErrorUtilityTimerDeleteForSensorTemp),
        cmocka_unit_test(test_SysAppTimerFinalize_ErrorUtilityTimerDeleteForHoursMeter),

        // SysAppTimerStartTimer()
        cmocka_unit_test(test_SysAppTimerStartTimer_FullySuccessSensorTemp),
        cmocka_unit_test(test_SysAppTimerStartTimer_FullySuccessHoursMeter),
        cmocka_unit_test(test_SysAppTimerStartTimer_FullySuccessNotRegisterCb),
        cmocka_unit_test(test_SysAppTimerStartTimer_FullySuccessAlreadyWorking),
        cmocka_unit_test(test_SysAppTimerStartTimer_InvalidType),
        cmocka_unit_test(test_SysAppTimerStartTimer_ErrorUtilityTimerStop),
        cmocka_unit_test(test_SysAppTimerStartTimer_ErrorUtilityTimerStart),

        // SysAppTimerUpdateTimer()
        cmocka_unit_test(test_SysAppTimerUpdateTimer),

        // SysAppTimerStopTimer()
        cmocka_unit_test(test_SysAppTimerStopTimer_FullySuccessSensorTemp),
        cmocka_unit_test(test_SysAppTimerStopTimer_FullySuccessHoursMeter),
        cmocka_unit_test(test_SysAppTimerStopTimer_InvalidType),
        cmocka_unit_test(test_SysAppTimerStopTimer_NotWorking),
        cmocka_unit_test(test_SysAppTimerStopTimer_ErrorUtilityTimerStop),

        // SensorTempTimerCallback()
        cmocka_unit_test(test_SensorTempTimerCallback_RegisteredCallback),
        cmocka_unit_test(test_SensorTempTimerCallback_NotRegisteredCallback),

        // HoursMeterTimerCallback()
        cmocka_unit_test(test_HoursMeterTimerCallback_RegisteredCallback),
        cmocka_unit_test(test_HoursMeterTimerCallback_NotRegisteredCallback),
    };

    return (((cmocka_run_group_tests(tests, NULL, NULL)) == 0) ? 0 : 1);
}
