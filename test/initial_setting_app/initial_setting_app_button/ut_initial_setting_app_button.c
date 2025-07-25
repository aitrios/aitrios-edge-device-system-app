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

#include "button_manager.h"
#include "firmware_manager.h"
#include "system_manager.h"
#include "initial_setting_app_button.h"
#include "system_app_led.h"

extern EsfButtonManagerHandle s_esfbm_handle;
extern bool s_reboot_requested;
extern bool s_factory_reset_requested;

extern void ButtonPressedCallback(void *user_data);
extern void ButtonReleased5to29Callback(void *user_data);
extern void ButtonReleasedOver30Callback(void *user_data);
extern void ButtonLongPressed5Callback(void *user_data);
extern void ButtonLongPressed30Callback(void *user_data);

/*----------------------------------------------------------------------------*/

//
// Initial value check for static global variable
//

/*----------------------------------------------------------------------------*/
static void test_IsaBtn_InitialValueOfGlobalVariable(void **state)
{
    assert_null(s_esfbm_handle);
    assert_false(s_factory_reset_requested);
    assert_false(s_reboot_requested);

    return;
}

/*----------------------------------------------------------------------------*/

//
// IsaBtnInitialize()
//

/*----------------------------------------------------------------------------*/
static void test_IsaBtnInitialize_FullySuccess(void **state)
{
    EsfButtonManagerHandle handle_val = (EsfButtonManagerHandle)0x12345678;
    RetCode ret;

    will_return(__wrap_EsfButtonManagerOpen, handle_val);
    will_return(__wrap_EsfButtonManagerOpen, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, callback, ButtonPressedCallback);
    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, min_second, 5);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, max_second, 29);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, callback,
                 ButtonReleased5to29Callback);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterReleasedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, min_second, 30);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, max_second, 0);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, callback,
                 ButtonReleasedOver30Callback);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterReleasedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, second, 5);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, callback,
                 ButtonLongPressed5Callback);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterLongPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, second, 30);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, callback,
                 ButtonLongPressed30Callback);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterLongPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerEnableNotificationCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerEnableNotificationCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusAbleToAcceptInput);

    ret = IsaBtnInitialize();

    assert_int_equal(ret, kRetOk);
    assert_ptr_equal(handle_val, s_esfbm_handle);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaBtnInitialize_ErrorEsfButtonManagerOpen(void **state)
{
    EsfButtonManagerHandle handle_val = (EsfButtonManagerHandle)0x12345678;
    RetCode ret;

    will_return(__wrap_EsfButtonManagerOpen, handle_val);
    will_return(__wrap_EsfButtonManagerOpen, kEsfButtonManagerStatusInternalError);

    ret = IsaBtnInitialize();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaBtnInitialize_ErrorEsfButtonManagerRegisterPressedCallback(void **state)
{
    EsfButtonManagerHandle handle_val = (EsfButtonManagerHandle)0x12345678;
    RetCode ret;

    will_return(__wrap_EsfButtonManagerOpen, handle_val);
    will_return(__wrap_EsfButtonManagerOpen, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, callback, ButtonPressedCallback);
    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterPressedCallback,
                kEsfButtonManagerStatusInternalError);

    expect_value(__wrap_EsfButtonManagerClose, handle, handle_val);
    will_return(__wrap_EsfButtonManagerClose, kEsfButtonManagerStatusOk);

    ret = IsaBtnInitialize();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaBtnInitialize_ErrorEsfButtonManagerRegisterReleasedCallbackFor5to29(
    void **state)
{
    EsfButtonManagerHandle handle_val = (EsfButtonManagerHandle)0x12345678;
    RetCode ret;

    will_return(__wrap_EsfButtonManagerOpen, handle_val);
    will_return(__wrap_EsfButtonManagerOpen, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, callback, ButtonPressedCallback);
    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, min_second, 5);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, max_second, 29);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, callback,
                 ButtonReleased5to29Callback);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterReleasedCallback,
                kEsfButtonManagerStatusInternalError);

    expect_value(__wrap_EsfButtonManagerUnregisterPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterPressedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerUnregisterPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerClose, handle, handle_val);
    will_return(__wrap_EsfButtonManagerClose, kEsfButtonManagerStatusOk);

    ret = IsaBtnInitialize();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaBtnInitialize_ErrorEsfButtonManagerRegisterReleasedCallbackFor30Over(
    void **state)
{
    EsfButtonManagerHandle handle_val = (EsfButtonManagerHandle)0x12345678;
    RetCode ret;

    will_return(__wrap_EsfButtonManagerOpen, handle_val);
    will_return(__wrap_EsfButtonManagerOpen, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, callback, ButtonPressedCallback);
    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, min_second, 5);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, max_second, 29);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, callback,
                 ButtonReleased5to29Callback);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterReleasedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, min_second, 30);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, max_second, 0);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, callback,
                 ButtonReleasedOver30Callback);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterReleasedCallback,
                kEsfButtonManagerStatusInternalError);

    expect_value(__wrap_EsfButtonManagerUnregisterReleasedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterReleasedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerUnregisterReleasedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerUnregisterPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterPressedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerUnregisterPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerClose, handle, handle_val);
    will_return(__wrap_EsfButtonManagerClose, kEsfButtonManagerStatusOk);

    ret = IsaBtnInitialize();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaBtnInitialize_ErrorEsfButtonManagerRegisterLongPressedCallbackFor5(void **state)
{
    EsfButtonManagerHandle handle_val = (EsfButtonManagerHandle)0x12345678;
    RetCode ret;

    will_return(__wrap_EsfButtonManagerOpen, handle_val);
    will_return(__wrap_EsfButtonManagerOpen, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, callback, ButtonPressedCallback);
    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, min_second, 5);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, max_second, 29);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, callback,
                 ButtonReleased5to29Callback);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterReleasedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, min_second, 30);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, max_second, 0);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, callback,
                 ButtonReleasedOver30Callback);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterReleasedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, second, 5);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, callback,
                 ButtonLongPressed5Callback);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterLongPressedCallback,
                kEsfButtonManagerStatusInternalError);

    expect_value(__wrap_EsfButtonManagerUnregisterReleasedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterReleasedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerUnregisterReleasedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerUnregisterPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterPressedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerUnregisterPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerClose, handle, handle_val);
    will_return(__wrap_EsfButtonManagerClose, kEsfButtonManagerStatusOk);

    ret = IsaBtnInitialize();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaBtnInitialize_ErrorEsfButtonManagerRegisterLongPressedCallbackFor30(
    void **state)
{
    EsfButtonManagerHandle handle_val = (EsfButtonManagerHandle)0x12345678;
    RetCode ret;

    will_return(__wrap_EsfButtonManagerOpen, handle_val);
    will_return(__wrap_EsfButtonManagerOpen, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, callback, ButtonPressedCallback);
    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, min_second, 5);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, max_second, 29);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, callback,
                 ButtonReleased5to29Callback);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterReleasedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, min_second, 30);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, max_second, 0);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, callback,
                 ButtonReleasedOver30Callback);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterReleasedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, second, 5);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, callback,
                 ButtonLongPressed5Callback);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterLongPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, second, 30);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, callback,
                 ButtonLongPressed30Callback);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterLongPressedCallback,
                kEsfButtonManagerStatusInternalError);

    expect_value(__wrap_EsfButtonManagerUnregisterLongPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterLongPressedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerUnregisterLongPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerUnregisterReleasedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterReleasedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerUnregisterReleasedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerUnregisterPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterPressedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerUnregisterPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerClose, handle, handle_val);
    will_return(__wrap_EsfButtonManagerClose, kEsfButtonManagerStatusOk);

    ret = IsaBtnInitialize();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaBtnInitialize_ErrorEsfButtonManagerEnableNotificationCallback(void **state)
{
    EsfButtonManagerHandle handle_val = (EsfButtonManagerHandle)0x12345678;
    RetCode ret;

    will_return(__wrap_EsfButtonManagerOpen, handle_val);
    will_return(__wrap_EsfButtonManagerOpen, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, callback, ButtonPressedCallback);
    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterPressedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, min_second, 5);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, max_second, 29);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, callback,
                 ButtonReleased5to29Callback);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterReleasedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, min_second, 30);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, max_second, 0);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, callback,
                 ButtonReleasedOver30Callback);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterReleasedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterReleasedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, second, 5);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, callback,
                 ButtonLongPressed5Callback);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterLongPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, second, 30);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, callback,
                 ButtonLongPressed30Callback);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, user_data, NULL);
    expect_value(__wrap_EsfButtonManagerRegisterLongPressedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerRegisterLongPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerEnableNotificationCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerEnableNotificationCallback,
                kEsfButtonManagerStatusInternalError);

    expect_value(__wrap_EsfButtonManagerUnregisterLongPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterLongPressedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerUnregisterLongPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerUnregisterReleasedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterReleasedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerUnregisterReleasedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerUnregisterPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterPressedCallback, handle, handle_val);
    will_return(__wrap_EsfButtonManagerUnregisterPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerClose, handle, handle_val);
    will_return(__wrap_EsfButtonManagerClose, kEsfButtonManagerStatusOk);

    ret = IsaBtnInitialize();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/

//
// IsaBtnFinalize()
//

/*----------------------------------------------------------------------------*/
static void test_IsaBtnFinalize_FullySuccess(void **state)
{
    RetCode ret;

    s_esfbm_handle = (EsfButtonManagerHandle)0x98765432;

    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusAbleToAcceptInput);
    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusUnableToAcceptInput);

    expect_value(__wrap_EsfButtonManagerDisableNotificationCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerDisableNotificationCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerUnregisterLongPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterLongPressedCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerUnregisterLongPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerUnregisterReleasedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterReleasedCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerUnregisterReleasedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerUnregisterPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterPressedCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerUnregisterPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerClose, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerClose, kEsfButtonManagerStatusOk);

    ret = IsaBtnFinalize();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaBtnFinalize_ErrorEsfButtonManagerDisableNotificationCallback(void **state)
{
    RetCode ret;

    s_esfbm_handle = (EsfButtonManagerHandle)0x98765432;

    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusAbleToAcceptInput);
    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusUnableToAcceptInput);

    expect_value(__wrap_EsfButtonManagerDisableNotificationCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerDisableNotificationCallback,
                kEsfButtonManagerStatusInternalError);

    expect_value(__wrap_EsfButtonManagerUnregisterLongPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterLongPressedCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerUnregisterLongPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerUnregisterReleasedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterReleasedCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerUnregisterReleasedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerUnregisterPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterPressedCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerUnregisterPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerClose, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerClose, kEsfButtonManagerStatusOk);

    ret = IsaBtnFinalize();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaBtnFinalize_ErrorEsfButtonManagerUnregisterLongPressedCallback(void **state)
{
    RetCode ret;

    s_esfbm_handle = (EsfButtonManagerHandle)0x98765432;

    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusAbleToAcceptInput);
    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusUnableToAcceptInput);

    expect_value(__wrap_EsfButtonManagerDisableNotificationCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerDisableNotificationCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerUnregisterLongPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterLongPressedCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerUnregisterLongPressedCallback,
                kEsfButtonManagerStatusInternalError);

    expect_value(__wrap_EsfButtonManagerUnregisterReleasedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterReleasedCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerUnregisterReleasedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerUnregisterPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterPressedCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerUnregisterPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerClose, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerClose, kEsfButtonManagerStatusOk);

    ret = IsaBtnFinalize();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaBtnFinalize_ErrorEsfButtonManagerUnregisterReleasedCallback(void **state)
{
    RetCode ret;

    s_esfbm_handle = (EsfButtonManagerHandle)0x98765432;

    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusAbleToAcceptInput);
    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusUnableToAcceptInput);

    expect_value(__wrap_EsfButtonManagerDisableNotificationCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerDisableNotificationCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerUnregisterLongPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterLongPressedCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerUnregisterLongPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerUnregisterReleasedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterReleasedCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerUnregisterReleasedCallback,
                kEsfButtonManagerStatusInternalError);

    expect_value(__wrap_EsfButtonManagerUnregisterPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterPressedCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerUnregisterPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerClose, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerClose, kEsfButtonManagerStatusOk);

    ret = IsaBtnFinalize();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaBtnFinalize_ErrorEsfButtonManagerUnregisterPressedCallback(void **state)
{
    RetCode ret;

    s_esfbm_handle = (EsfButtonManagerHandle)0x98765432;

    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusAbleToAcceptInput);
    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusUnableToAcceptInput);

    expect_value(__wrap_EsfButtonManagerDisableNotificationCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerDisableNotificationCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerUnregisterLongPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterLongPressedCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerUnregisterLongPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerUnregisterReleasedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterReleasedCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerUnregisterReleasedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerUnregisterPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterPressedCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerUnregisterPressedCallback,
                kEsfButtonManagerStatusInternalError);

    expect_value(__wrap_EsfButtonManagerClose, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerClose, kEsfButtonManagerStatusOk);

    ret = IsaBtnFinalize();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaBtnFinalize_ErrorEsfButtonManagerClose(void **state)
{
    RetCode ret;

    s_esfbm_handle = (EsfButtonManagerHandle)0x98765432;

    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusAbleToAcceptInput);
    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusUnableToAcceptInput);

    expect_value(__wrap_EsfButtonManagerDisableNotificationCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerDisableNotificationCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerUnregisterLongPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterLongPressedCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerUnregisterLongPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerUnregisterReleasedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterReleasedCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerUnregisterReleasedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerUnregisterPressedCallback, button_id, 0);
    expect_value(__wrap_EsfButtonManagerUnregisterPressedCallback, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerUnregisterPressedCallback, kEsfButtonManagerStatusOk);

    expect_value(__wrap_EsfButtonManagerClose, handle, s_esfbm_handle);
    will_return(__wrap_EsfButtonManagerClose, kEsfButtonManagerStatusInternalError);

    ret = IsaBtnFinalize();

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/

//
// IsaBtnCheckRebootRequest()
//

/*----------------------------------------------------------------------------*/
static void test_IsaBtnCheckRebootRequest(void **state)
{
    bool ret;

    s_reboot_requested = true;
    ret = IsaBtnCheckRebootRequest();

    assert_int_equal(ret, s_reboot_requested);

    return;
}

/*----------------------------------------------------------------------------*/

//
// IsaBtnCheckFactoryResetRequest()
//

/*----------------------------------------------------------------------------*/
static void test_IsaBtnCheckFactoryResetRequest(void **state)
{
    bool ret;

    s_factory_reset_requested = true;
    ret = IsaBtnCheckFactoryResetRequest();

    assert_int_equal(ret, s_factory_reset_requested);

    return;
}

/*----------------------------------------------------------------------------*/

//
// IsaBtnExecuteRebootCore()
//

/*----------------------------------------------------------------------------*/
static void test_IsaBtnExecuteRebootCore(void **state)
{
    bool ret;

    s_reboot_requested = true;

    expect_function_call(__wrap_EsfPwrMgrExecuteReboot);

    ret = IsaBtnExecuteRebootCore();

    assert_int_equal(ret, kRetOk);
    assert_false(s_reboot_requested);

    return;
}

/*----------------------------------------------------------------------------*/

//
// IsaBtnExecuteFactoryResetCore()
//

/*----------------------------------------------------------------------------*/
static void test_IsaBtnExecuteFactoryResetCore_FullySuccess(void **state)
{
    RetCode ret;

    s_factory_reset_requested = true;

    expect_value(__wrap_EsfFwMgrStartFactoryReset, cause, kEsfFwMgrResetCauseButton);
    will_return(__wrap_EsfFwMgrStartFactoryReset, kEsfFwMgrResultOk);

    ret = IsaBtnExecuteFactoryResetCore();

    assert_int_equal(ret, kRetOk);
    assert_false(s_factory_reset_requested);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaBtnExecuteFactoryResetCore_ErrorEsfFwMgrStartFactoryReset(void **state)
{
    RetCode ret;

    s_factory_reset_requested = true;

    expect_value(__wrap_EsfFwMgrStartFactoryReset, cause, kEsfFwMgrResetCauseButton);
    will_return(__wrap_EsfFwMgrStartFactoryReset, kEsfFwMgrResultInternal);

    ret = IsaBtnExecuteFactoryResetCore();

    assert_int_equal(ret, kRetFailed);
    assert_false(s_factory_reset_requested);

    return;
}

/*----------------------------------------------------------------------------*/

//
// ButtonPressedCallback()
//

/*----------------------------------------------------------------------------*/
static void test_ButtonPressedCallback(void **state)
{
    ButtonPressedCallback(NULL);
    return;
}

/*----------------------------------------------------------------------------*/

//
// ButtonReleased5to29Callback()
//

/*----------------------------------------------------------------------------*/
static void test_ButtonReleased5to29Callback_FullySuccess(void **state)
{
    s_reboot_requested = false;

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, -1);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultOk);

    ButtonReleased5to29Callback(NULL);

    assert_true(s_reboot_requested);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ButtonReleased5to29Callback_ErrorEsfSystemManagerSetQrModeTimeoutValue(
    void **state)
{
    s_reboot_requested = false;

    expect_value(__wrap_EsfSystemManagerSetQrModeTimeoutValue, data, -1);
    will_return(__wrap_EsfSystemManagerSetQrModeTimeoutValue, kEsfSystemManagerResultInternalError);

    ButtonReleased5to29Callback(NULL);

    assert_true(s_reboot_requested);

    return;
}

/*----------------------------------------------------------------------------*/

//
// ButtonReleasedOver30Callback()
//

/*----------------------------------------------------------------------------*/
static void test_ButtonReleasedOver30Callback_ExecFactoryReset(void **state)
{
    s_factory_reset_requested = false;

    expect_function_call(__wrap_EVP_undeployModules);
    will_return(__wrap_EVP_undeployModules, 1);

    ButtonReleasedOver30Callback(NULL);

    assert_true(s_factory_reset_requested);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ButtonReleasedOver30Callback_AlreadyButtonFcWorking(void **state)
{
    s_factory_reset_requested = true;

    ButtonReleasedOver30Callback(NULL);

    assert_true(s_factory_reset_requested);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_ButtonReleasedOver30Callback_ErrorEvpUndeployModules(void **state)
{
    s_factory_reset_requested = false;

    expect_function_call(__wrap_EVP_undeployModules);
    will_return(__wrap_EVP_undeployModules, 0);

    ButtonReleasedOver30Callback(NULL);

    assert_true(s_factory_reset_requested);

    return;
}

/*----------------------------------------------------------------------------*/

//
// ButtonLongPressed5Callback()
//

/*----------------------------------------------------------------------------*/
static void test_ButtonLongPressed5Callback_FullySuccess(void **state)
{
    for (int i = kEsfLedManagerLedStatusAbleToAcceptInputs; i < kEsfLedManagerLedStatusNum; i++) {
        expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
        expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
        expect_value(__wrap_EsfLedManagerSetStatus, status->status, i);
        will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);
    }
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsole);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    ButtonLongPressed5Callback(NULL);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_ButtonLongPressed5Callback_ErrorEsfLedManagerSetStatus_UnsetFail(void **state)
{
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusAbleToAcceptInputs);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerInternalError);
    for (int i = kEsfLedManagerLedStatusAbleToAcceptInputs + 1; i < kEsfLedManagerLedStatusNum;
         i++) {
        expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
        expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
        expect_value(__wrap_EsfLedManagerSetStatus, status->status, i);
        will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);
    }
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsole);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    ButtonLongPressed5Callback(NULL);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_ButtonLongPressed5Callback_ErrorEsfLedManagerSetStatus_QrModeOnFail(void **state)
{
    for (int i = kEsfLedManagerLedStatusAbleToAcceptInputs; i < kEsfLedManagerLedStatusNum; i++) {
        expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
        expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
        expect_value(__wrap_EsfLedManagerSetStatus, status->status, i);
        will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);
    }
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsole);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerInternalError);

    ButtonLongPressed5Callback(NULL);
    return;
}

/*----------------------------------------------------------------------------*/

//
// test_ButtonLongPressed30Callback()
//

/*----------------------------------------------------------------------------*/
static void test_ButtonLongPressed30Callback_FullySuccess(void **state)
{
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsole);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusUnableToAcceptInputs);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);
    ButtonLongPressed30Callback(NULL);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_ButtonLongPressed30Callback_ErrorEsfLedManagerSetStatus_UnsetFail(void **state)
{
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsole);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerInternalError);

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusUnableToAcceptInputs);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    ButtonLongPressed30Callback(NULL);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_ButtonLongPressed30Callback_ErrorEsfLedManagerSetStatus_FactoryResetModeOnFail(
    void **state)
{
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsole);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusUnableToAcceptInputs);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerInternalError);

    ButtonLongPressed30Callback(NULL);
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
        // Initial value check for static global variable
        cmocka_unit_test(test_IsaBtn_InitialValueOfGlobalVariable),

        // IsaBtnInitialize()
        cmocka_unit_test(test_IsaBtnInitialize_FullySuccess),
        cmocka_unit_test(test_IsaBtnInitialize_ErrorEsfButtonManagerOpen),
        cmocka_unit_test(test_IsaBtnInitialize_ErrorEsfButtonManagerRegisterPressedCallback),
        cmocka_unit_test(
            test_IsaBtnInitialize_ErrorEsfButtonManagerRegisterReleasedCallbackFor5to29),
        cmocka_unit_test(
            test_IsaBtnInitialize_ErrorEsfButtonManagerRegisterReleasedCallbackFor30Over),
        cmocka_unit_test(
            test_IsaBtnInitialize_ErrorEsfButtonManagerRegisterLongPressedCallbackFor5),
        cmocka_unit_test(
            test_IsaBtnInitialize_ErrorEsfButtonManagerRegisterLongPressedCallbackFor30),
        cmocka_unit_test(test_IsaBtnInitialize_ErrorEsfButtonManagerEnableNotificationCallback),

        // IsaBtnFinalize()
        cmocka_unit_test(test_IsaBtnFinalize_FullySuccess),
        cmocka_unit_test(test_IsaBtnFinalize_ErrorEsfButtonManagerDisableNotificationCallback),
        cmocka_unit_test(test_IsaBtnFinalize_ErrorEsfButtonManagerUnregisterLongPressedCallback),
        cmocka_unit_test(test_IsaBtnFinalize_ErrorEsfButtonManagerUnregisterReleasedCallback),
        cmocka_unit_test(test_IsaBtnFinalize_ErrorEsfButtonManagerUnregisterPressedCallback),
        cmocka_unit_test(test_IsaBtnFinalize_ErrorEsfButtonManagerClose),

        // IsaBtnCheckRebootRequest()
        cmocka_unit_test(test_IsaBtnCheckRebootRequest),

        // IsaBtnCheckFactoryResetRequest()
        cmocka_unit_test(test_IsaBtnCheckFactoryResetRequest),

        // IsaBtnExecuteRebootCore()
        cmocka_unit_test(test_IsaBtnExecuteRebootCore),

        // IsaBtnExecuteFactoryResetCore()
        cmocka_unit_test(test_IsaBtnExecuteFactoryResetCore_FullySuccess),
        cmocka_unit_test(test_IsaBtnExecuteFactoryResetCore_ErrorEsfFwMgrStartFactoryReset),

        // ButtonPressedCallback()
        cmocka_unit_test(test_ButtonPressedCallback),

        // ButtonReleased5to29Callback()
        cmocka_unit_test(test_ButtonReleased5to29Callback_FullySuccess),
        cmocka_unit_test(
            test_ButtonReleased5to29Callback_ErrorEsfSystemManagerSetQrModeTimeoutValue),

        // ButtonReleasedOver30Callback()
        cmocka_unit_test(test_ButtonReleasedOver30Callback_ExecFactoryReset),
        cmocka_unit_test(test_ButtonReleasedOver30Callback_AlreadyButtonFcWorking),
        cmocka_unit_test(test_ButtonReleasedOver30Callback_ErrorEvpUndeployModules),

        // ButtonLongPressed5Callback()
        cmocka_unit_test(test_ButtonLongPressed5Callback_FullySuccess),
        cmocka_unit_test(test_ButtonLongPressed5Callback_ErrorEsfLedManagerSetStatus_UnsetFail),
        cmocka_unit_test(test_ButtonLongPressed5Callback_ErrorEsfLedManagerSetStatus_QrModeOnFail),

        // ButtonLongPressed30Callback()
        cmocka_unit_test(test_ButtonLongPressed30Callback_FullySuccess),
        cmocka_unit_test(test_ButtonLongPressed30Callback_ErrorEsfLedManagerSetStatus_UnsetFail),
        cmocka_unit_test(
            test_ButtonLongPressed30Callback_ErrorEsfLedManagerSetStatus_FactoryResetModeOnFail),
    };

    return (((cmocka_run_group_tests(tests, NULL, NULL)) == 0) ? 0 : 1);
}
