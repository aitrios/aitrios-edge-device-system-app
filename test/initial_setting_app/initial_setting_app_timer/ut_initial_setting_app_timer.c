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

#include "initial_setting_app_timer.h"
#include "initial_setting_app_timer_private.h"

extern IsaTimerContext s_qr_mode_timer_ctx;

extern void QrModeTimerCallback(void *timer_cb_params);

#define UT_ISA_TIMER_THREAD_STACK_SIZE (6 * 1024)

/*----------------------------------------------------------------------------*/

//
// Registerd Callback
//

/*----------------------------------------------------------------------------*/
static void TimerCallback(void)
{
    function_called();

    return;
}

/*----------------------------------------------------------------------------*/

//
// IsaTimerInitialize()
//

/*----------------------------------------------------------------------------*/
static void test_IsaTimerInitialize_FullySuccess(void **state)
{
    UtilityTimerHandle timer_handle = (UtilityTimerHandle)0x12345678;
    RetCode ret;

    expect_value(__wrap_UtilityTimerCreateEx, callback, QrModeTimerCallback);
    expect_value(__wrap_UtilityTimerCreateEx, cb_params, NULL);
    expect_value(__wrap_UtilityTimerCreateEx, priority, CONFIG_UTILITY_TIMER_THREAD_PRIORITY);
    expect_value(__wrap_UtilityTimerCreateEx, stacksize, UT_ISA_TIMER_THREAD_STACK_SIZE);
    will_return(__wrap_UtilityTimerCreateEx, timer_handle);
    will_return(__wrap_UtilityTimerCreateEx, kUtilityTimerOk);

    ret = IsaTimerInitialize();

    assert_int_equal(ret, kRetOk);

    assert_int_equal(s_qr_mode_timer_ctx.handle, timer_handle);
    assert_false(s_qr_mode_timer_ctx.is_working);
    assert_null(s_qr_mode_timer_ctx.cb);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaTimerInitialize_ErrorUtilityTimerCreateEx(void **state)
{
    UtilityTimerHandle timer_handle = (UtilityTimerHandle)0x12345678;
    RetCode ret;

    expect_value(__wrap_UtilityTimerCreateEx, callback, QrModeTimerCallback);
    expect_value(__wrap_UtilityTimerCreateEx, cb_params, NULL);
    expect_value(__wrap_UtilityTimerCreateEx, priority, CONFIG_UTILITY_TIMER_THREAD_PRIORITY);
    expect_value(__wrap_UtilityTimerCreateEx, stacksize, UT_ISA_TIMER_THREAD_STACK_SIZE);
    will_return(__wrap_UtilityTimerCreateEx, timer_handle);
    will_return(__wrap_UtilityTimerCreateEx, kUtilityTimerErrInternal);

    ret = IsaTimerInitialize();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/

//
// IsaTimerFinalize()
//

/*----------------------------------------------------------------------------*/
static void test_IsaTimerFinalize_FullySuccess(void **state)
{
    RetCode ret;

    s_qr_mode_timer_ctx.handle = (UtilityTimerHandle)0x98765432;

    expect_value(__wrap_UtilityTimerDelete, utility_timer_handle, s_qr_mode_timer_ctx.handle);
    will_return(__wrap_UtilityTimerDelete, kUtilityTimerOk);

    ret = IsaTimerFinalize();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaTimerFinalize_ErrorUtilityTimerDelete(void **state)
{
    RetCode ret;

    s_qr_mode_timer_ctx.handle = (UtilityTimerHandle)0x98765432;

    expect_value(__wrap_UtilityTimerDelete, utility_timer_handle, s_qr_mode_timer_ctx.handle);
    will_return(__wrap_UtilityTimerDelete, kUtilityTimerErrInternal);

    ret = IsaTimerFinalize();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/

//
// IsaTimerStart()
//

/*----------------------------------------------------------------------------*/
static void test_IsaTimerStart_FullySuccessRegisterCb(void **state)
{
    uint32_t time = 100;
    RetCode ret;

    s_qr_mode_timer_ctx.handle = (UtilityTimerHandle)0x13572468;
    s_qr_mode_timer_ctx.is_working = false;
    s_qr_mode_timer_ctx.cb = NULL;

    expect_value(__wrap_UtilityTimerStart, utility_timer_handle, s_qr_mode_timer_ctx.handle);
    expect_value(__wrap_UtilityTimerStart, interval_ts->tv_sec, time);
    expect_value(__wrap_UtilityTimerStart, interval_ts->tv_nsec, 0);
    expect_value(__wrap_UtilityTimerStart, utility_timer_repeat_type, kUtilityTimerRepeat);
    will_return(__wrap_UtilityTimerStart, kUtilityTimerOk);

    ret = IsaTimerStart(time, TimerCallback);

    assert_int_equal(ret, kRetOk);

    assert_true(s_qr_mode_timer_ctx.is_working);
    assert_ptr_equal(s_qr_mode_timer_ctx.cb, TimerCallback);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaTimerStart_FullySuccessNotRegisterCb(void **state)
{
    uint32_t time = 100;
    RetCode ret;

    s_qr_mode_timer_ctx.handle = (UtilityTimerHandle)0x13572468;
    s_qr_mode_timer_ctx.is_working = false;
    s_qr_mode_timer_ctx.cb = TimerCallback;

    expect_value(__wrap_UtilityTimerStart, utility_timer_handle, s_qr_mode_timer_ctx.handle);
    expect_value(__wrap_UtilityTimerStart, interval_ts->tv_sec, time);
    expect_value(__wrap_UtilityTimerStart, interval_ts->tv_nsec, 0);
    expect_value(__wrap_UtilityTimerStart, utility_timer_repeat_type, kUtilityTimerRepeat);
    will_return(__wrap_UtilityTimerStart, kUtilityTimerOk);

    ret = IsaTimerStart(time, NULL);

    assert_int_equal(ret, kRetOk);

    assert_true(s_qr_mode_timer_ctx.is_working);
    assert_ptr_equal(s_qr_mode_timer_ctx.cb, TimerCallback);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaTimerStart_FullySuccessAlreadyWorking(void **state)
{
    uint32_t time = 100;
    RetCode ret;

    s_qr_mode_timer_ctx.handle = (UtilityTimerHandle)0x13572468;
    s_qr_mode_timer_ctx.is_working = true;
    s_qr_mode_timer_ctx.cb = NULL;

    expect_value(__wrap_UtilityTimerStop, utility_timer_handle, s_qr_mode_timer_ctx.handle);
    will_return(__wrap_UtilityTimerStop, kUtilityTimerOk);

    expect_value(__wrap_UtilityTimerStart, utility_timer_handle, s_qr_mode_timer_ctx.handle);
    expect_value(__wrap_UtilityTimerStart, interval_ts->tv_sec, time);
    expect_value(__wrap_UtilityTimerStart, interval_ts->tv_nsec, 0);
    expect_value(__wrap_UtilityTimerStart, utility_timer_repeat_type, kUtilityTimerRepeat);
    will_return(__wrap_UtilityTimerStart, kUtilityTimerOk);

    ret = IsaTimerStart(time, TimerCallback);

    assert_int_equal(ret, kRetOk);

    assert_true(s_qr_mode_timer_ctx.is_working);
    assert_ptr_equal(s_qr_mode_timer_ctx.cb, TimerCallback);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaTimerStart_FullySuccessErrorUtilityTimerStop(void **state)
{
    uint32_t time = 100;
    RetCode ret;

    s_qr_mode_timer_ctx.handle = (UtilityTimerHandle)0x13572468;
    s_qr_mode_timer_ctx.is_working = true;
    s_qr_mode_timer_ctx.cb = NULL;

    expect_value(__wrap_UtilityTimerStop, utility_timer_handle, s_qr_mode_timer_ctx.handle);
    will_return(__wrap_UtilityTimerStop, kUtilityTimerErrInternal);

    ret = IsaTimerStart(time, TimerCallback);

    assert_int_equal(ret, kRetFailed);

    assert_true(s_qr_mode_timer_ctx.is_working);
    assert_null(s_qr_mode_timer_ctx.cb);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaTimerStart_FullySuccessErrorUtilityTimerStart(void **state)
{
    uint32_t time = 100;
    RetCode ret;

    s_qr_mode_timer_ctx.handle = (UtilityTimerHandle)0x13572468;
    s_qr_mode_timer_ctx.is_working = false;
    s_qr_mode_timer_ctx.cb = NULL;

    expect_value(__wrap_UtilityTimerStart, utility_timer_handle, s_qr_mode_timer_ctx.handle);
    expect_value(__wrap_UtilityTimerStart, interval_ts->tv_sec, time);
    expect_value(__wrap_UtilityTimerStart, interval_ts->tv_nsec, 0);
    expect_value(__wrap_UtilityTimerStart, utility_timer_repeat_type, kUtilityTimerRepeat);
    will_return(__wrap_UtilityTimerStart, kUtilityTimerErrInternal);

    ret = IsaTimerStart(time, TimerCallback);

    assert_int_equal(ret, kRetFailed);

    assert_false(s_qr_mode_timer_ctx.is_working);
    assert_null(s_qr_mode_timer_ctx.cb);

    return;
}

/*----------------------------------------------------------------------------*/

//
// IsaTimerStop()
//

/*----------------------------------------------------------------------------*/
static void test_IsaTimerStop_FullySuccess(void **state)
{
    RetCode ret;

    s_qr_mode_timer_ctx.handle = (UtilityTimerHandle)0x13572468;
    s_qr_mode_timer_ctx.is_working = true;
    s_qr_mode_timer_ctx.cb = TimerCallback;

    expect_value(__wrap_UtilityTimerStop, utility_timer_handle, s_qr_mode_timer_ctx.handle);
    will_return(__wrap_UtilityTimerStop, kUtilityTimerOk);

    ret = IsaTimerStop();

    assert_int_equal(ret, kRetOk);

    assert_false(s_qr_mode_timer_ctx.is_working);
    assert_null(s_qr_mode_timer_ctx.cb);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaTimerStop_NotWorking(void **state)
{
    RetCode ret;

    s_qr_mode_timer_ctx.handle = (UtilityTimerHandle)0x13572468;
    s_qr_mode_timer_ctx.is_working = false;
    s_qr_mode_timer_ctx.cb = TimerCallback;

    ret = IsaTimerStop();

    assert_int_equal(ret, kRetFailed);

    assert_false(s_qr_mode_timer_ctx.is_working);
    assert_ptr_equal(s_qr_mode_timer_ctx.cb, TimerCallback);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaTimerStop_ErrorUtilityTimerStop(void **state)
{
    RetCode ret;

    s_qr_mode_timer_ctx.handle = (UtilityTimerHandle)0x13572468;
    s_qr_mode_timer_ctx.is_working = true;
    s_qr_mode_timer_ctx.cb = TimerCallback;

    expect_value(__wrap_UtilityTimerStop, utility_timer_handle, s_qr_mode_timer_ctx.handle);
    will_return(__wrap_UtilityTimerStop, kUtilityTimerErrInternal);

    ret = IsaTimerStop();

    assert_int_equal(ret, kRetFailed);

    assert_true(s_qr_mode_timer_ctx.is_working);
    assert_ptr_equal(s_qr_mode_timer_ctx.cb, TimerCallback);

    return;
}

/*----------------------------------------------------------------------------*/

//
// QrModeTimerCallback()
//

/*----------------------------------------------------------------------------*/
static void test_QrModeTimerCallback_RegisteredCallback(void **state)
{
    s_qr_mode_timer_ctx.cb = TimerCallback;

    expect_function_call(TimerCallback);

    QrModeTimerCallback(NULL);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_QrModeTimerCallback_NotRegisteredCallback(void **state)
{
    s_qr_mode_timer_ctx.cb = NULL;

    QrModeTimerCallback(NULL);

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
        // IsaTimerInitialize()
        cmocka_unit_test(test_IsaTimerInitialize_FullySuccess),
        cmocka_unit_test(test_IsaTimerInitialize_ErrorUtilityTimerCreateEx),

        // IsaTimerFinalize()
        cmocka_unit_test(test_IsaTimerFinalize_FullySuccess),
        cmocka_unit_test(test_IsaTimerFinalize_ErrorUtilityTimerDelete),

        // IsaTimerStart()
        cmocka_unit_test(test_IsaTimerStart_FullySuccessRegisterCb),
        cmocka_unit_test(test_IsaTimerStart_FullySuccessNotRegisterCb),
        cmocka_unit_test(test_IsaTimerStart_FullySuccessNotRegisterCb),
        cmocka_unit_test(test_IsaTimerStart_FullySuccessAlreadyWorking),
        cmocka_unit_test(test_IsaTimerStart_FullySuccessErrorUtilityTimerStop),
        cmocka_unit_test(test_IsaTimerStart_FullySuccessErrorUtilityTimerStart),

        // IsaTimerStop()
        cmocka_unit_test(test_IsaTimerStop_FullySuccess),
        cmocka_unit_test(test_IsaTimerStop_NotWorking),
        cmocka_unit_test(test_IsaTimerStop_ErrorUtilityTimerStop),

        // QrModeTimerCallback()
        cmocka_unit_test(test_QrModeTimerCallback_RegisteredCallback),
        cmocka_unit_test(test_QrModeTimerCallback_NotRegisteredCallback),
    };

    return (((cmocka_run_group_tests(tests, NULL, NULL)) == 0) ? 0 : 1);
}
