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

/*----------------------------------------------------------------------------*/
EsfButtonManagerStatus __wrap_EsfButtonManagerOpen(EsfButtonManagerHandle *handle)
{
    *handle = mock_type(EsfButtonManagerHandle);

    return mock_type(EsfButtonManagerStatus);
}

/*----------------------------------------------------------------------------*/
EsfButtonManagerStatus __wrap_EsfButtonManagerClose(EsfButtonManagerHandle handle)
{
    check_expected(handle);

    return mock_type(EsfButtonManagerStatus);
}

/*----------------------------------------------------------------------------*/
EsfButtonManagerStatus __wrap_EsfButtonManagerRegisterPressedCallback(
    uint32_t button_id, const EsfButtonManagerCallback callback, void *user_data,
    EsfButtonManagerHandle handle)
{
    check_expected(button_id);
    check_expected_ptr(callback);
    check_expected_ptr(user_data);
    check_expected(handle);

    return mock_type(EsfButtonManagerStatus);
}

/*----------------------------------------------------------------------------*/
EsfButtonManagerStatus __wrap_EsfButtonManagerRegisterReleasedCallback(
    uint32_t button_id, int32_t min_second, int32_t max_second,
    const EsfButtonManagerCallback callback, void *user_data, EsfButtonManagerHandle handle)
{
    check_expected(button_id);
    check_expected(min_second);
    check_expected(max_second);
    check_expected_ptr(callback);
    check_expected_ptr(user_data);
    check_expected(handle);

    return mock_type(EsfButtonManagerStatus);
}

/*----------------------------------------------------------------------------*/
EsfButtonManagerStatus __wrap_EsfButtonManagerRegisterLongPressedCallback(
    uint32_t button_id, int32_t second, const EsfButtonManagerCallback callback, void *user_data,
    EsfButtonManagerHandle handle)
{
    check_expected(button_id);
    check_expected(second);
    check_expected_ptr(callback);
    check_expected_ptr(user_data);
    check_expected(handle);

    return mock_type(EsfButtonManagerStatus);
}

/*----------------------------------------------------------------------------*/
EsfButtonManagerStatus __wrap_EsfButtonManagerUnregisterPressedCallback(
    uint32_t button_id, EsfButtonManagerHandle handle)
{
    check_expected(button_id);
    check_expected(handle);

    return mock_type(EsfButtonManagerStatus);
}

/*----------------------------------------------------------------------------*/
EsfButtonManagerStatus __wrap_EsfButtonManagerUnregisterReleasedCallback(
    uint32_t button_id, EsfButtonManagerHandle handle)
{
    check_expected(button_id);
    check_expected(handle);

    return mock_type(EsfButtonManagerStatus);
}

/*----------------------------------------------------------------------------*/
EsfButtonManagerStatus __wrap_EsfButtonManagerUnregisterLongPressedCallback(
    uint32_t button_id, EsfButtonManagerHandle handle)
{
    check_expected(button_id);
    check_expected(handle);

    return mock_type(EsfButtonManagerStatus);
}

/*----------------------------------------------------------------------------*/
EsfButtonManagerStatus __wrap_EsfButtonManagerEnableNotificationCallback(
    EsfButtonManagerHandle handle)
{
    check_expected(handle);

    return mock_type(EsfButtonManagerStatus);
}

/*----------------------------------------------------------------------------*/
EsfButtonManagerStatus __wrap_EsfButtonManagerDisableNotificationCallback(
    EsfButtonManagerHandle handle)
{
    check_expected(handle);

    return mock_type(EsfButtonManagerStatus);
}

/*----------------------------------------------------------------------------*/
