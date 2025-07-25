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

#include "system_app_led.h"

/*----------------------------------------------------------------------------*/

//
// SysAppLedSetAppStatus()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppLedSetAppStatus_FullySuccess(void **state)
{
    LedType type = LedTypeWiFi;
    LedAppStatus app_state = LedAppStatusWaitingForInputToConnect;

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedWifi);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsole);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    SysAppLedSetAppStatus(type, app_state);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLedUnsetAppStatus_FullySuccess(void **state)
{
    LedType type = LedTypeWiFi;
    LedAppStatus app_state = LedAppStatusWaitingForInputToConnect;

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedWifi);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status,
                 kEsfLedManagerLedStatusWaitingForInputsToConnectConsole);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    SysAppLedUnsetAppStatus(type, app_state);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLedSetAppStatus_EsfError(void **state)
{
    LedType type = LedTypePower;
    LedAppStatus app_state = LedAppStatusForceOff;

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerInternalError);

    SysAppLedSetAppStatus(type, app_state);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLedUnsetAppStatus_EsfError(void **state)
{
    LedType type = LedTypePower;
    LedAppStatus app_state = LedAppStatusForceOff;

    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerInternalError);

    SysAppLedUnsetAppStatus(type, app_state);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppLedSetEnable()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppLedSetEnable_TrueFullySuccess(void **state)
{
    bool led_enable = true;

    // Loop 1
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // Loop 2
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedWifi);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // Loop 3
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedService);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    RetCode ret = SysAppLedSetEnable(led_enable);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLedSetEnable_FalseFullySuccess(void **state)
{
    bool led_enable = false;

    // Loop 1
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // Loop 2
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedWifi);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // Loop 3
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedService);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, true);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    RetCode ret = SysAppLedSetEnable(led_enable);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLedSetEnable_EsfError(void **state)
{
    bool led_enable = true;

    // Loop 1
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerInternalError);

    // Loop 2
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedWifi);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    // Loop 3
    expect_value(__wrap_EsfLedManagerSetStatus, status->led, kEsfLedManagerTargetLedService);
    expect_value(__wrap_EsfLedManagerSetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    expect_value(__wrap_EsfLedManagerSetStatus, status->enabled, false);
    will_return(__wrap_EsfLedManagerSetStatus, kEsfLedManagerSuccess);

    RetCode ret = SysAppLedSetEnable(led_enable);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppLedGetEnable()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppLedGetEnable_FullySuccess(void **state)
{
    bool led_value = true;

    // Loop 1
    expect_value(__wrap_EsfLedManagerGetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerGetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    will_return(__wrap_EsfLedManagerGetStatus, true);
    will_return(__wrap_EsfLedManagerGetStatus, kEsfLedManagerSuccess);

    // Loop 2
    expect_value(__wrap_EsfLedManagerGetStatus, status->led, kEsfLedManagerTargetLedWifi);
    expect_value(__wrap_EsfLedManagerGetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    will_return(__wrap_EsfLedManagerGetStatus, true);
    will_return(__wrap_EsfLedManagerGetStatus, kEsfLedManagerSuccess);

    // Loop 3
    expect_value(__wrap_EsfLedManagerGetStatus, status->led, kEsfLedManagerTargetLedService);
    expect_value(__wrap_EsfLedManagerGetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    will_return(__wrap_EsfLedManagerGetStatus, true);
    will_return(__wrap_EsfLedManagerGetStatus, kEsfLedManagerSuccess);

    RetCode ret = SysAppLedGetEnable(&led_value);
    assert_false(led_value);
    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLedGetEnable_EsfError(void **state)
{
    bool led_value = true;

    // Loop 1
    expect_value(__wrap_EsfLedManagerGetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerGetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    will_return(__wrap_EsfLedManagerGetStatus, true);
    will_return(__wrap_EsfLedManagerGetStatus, kEsfLedManagerInternalError);

    RetCode ret = SysAppLedGetEnable(&led_value);
    assert_false(led_value);
    assert_int_equal(ret, kRetFailed);

    return;
}
/*----------------------------------------------------------------------------*/
static void test_SysAppLedGetEnable_PowerSameError(void **state)
{
    bool led_value = true;

    // Loop 1
    expect_value(__wrap_EsfLedManagerGetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerGetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    will_return(__wrap_EsfLedManagerGetStatus, false);
    will_return(__wrap_EsfLedManagerGetStatus, kEsfLedManagerSuccess);

    // Loop 2
    expect_value(__wrap_EsfLedManagerGetStatus, status->led, kEsfLedManagerTargetLedWifi);
    expect_value(__wrap_EsfLedManagerGetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    will_return(__wrap_EsfLedManagerGetStatus, true);
    will_return(__wrap_EsfLedManagerGetStatus, kEsfLedManagerSuccess);

    // Loop 3
    expect_value(__wrap_EsfLedManagerGetStatus, status->led, kEsfLedManagerTargetLedService);
    expect_value(__wrap_EsfLedManagerGetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    will_return(__wrap_EsfLedManagerGetStatus, true);
    will_return(__wrap_EsfLedManagerGetStatus, kEsfLedManagerSuccess);

    RetCode ret = SysAppLedGetEnable(&led_value);
    assert_true(led_value);
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLedGetEnable_WiFiSameError(void **state)
{
    bool led_value = true;

    // Loop 1
    expect_value(__wrap_EsfLedManagerGetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerGetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    will_return(__wrap_EsfLedManagerGetStatus, true);
    will_return(__wrap_EsfLedManagerGetStatus, kEsfLedManagerSuccess);

    // Loop 2
    expect_value(__wrap_EsfLedManagerGetStatus, status->led, kEsfLedManagerTargetLedWifi);
    expect_value(__wrap_EsfLedManagerGetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    will_return(__wrap_EsfLedManagerGetStatus, false);
    will_return(__wrap_EsfLedManagerGetStatus, kEsfLedManagerSuccess);

    // Loop 3
    expect_value(__wrap_EsfLedManagerGetStatus, status->led, kEsfLedManagerTargetLedService);
    expect_value(__wrap_EsfLedManagerGetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    will_return(__wrap_EsfLedManagerGetStatus,
                false); // To test only when Target Led WiFi return kRetFailed.
    will_return(__wrap_EsfLedManagerGetStatus, kEsfLedManagerSuccess);

    RetCode ret = SysAppLedGetEnable(&led_value);
    assert_true(led_value);
    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppLedGetEnable_ServiceSameError(void **state)
{
    bool led_value = true;

    // Loop 1
    expect_value(__wrap_EsfLedManagerGetStatus, status->led, kEsfLedManagerTargetLedPower);
    expect_value(__wrap_EsfLedManagerGetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    will_return(__wrap_EsfLedManagerGetStatus, true);
    will_return(__wrap_EsfLedManagerGetStatus, kEsfLedManagerSuccess);

    // Loop 2
    expect_value(__wrap_EsfLedManagerGetStatus, status->led, kEsfLedManagerTargetLedWifi);
    expect_value(__wrap_EsfLedManagerGetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    will_return(__wrap_EsfLedManagerGetStatus, true);
    will_return(__wrap_EsfLedManagerGetStatus, kEsfLedManagerSuccess);

    // Loop 3
    expect_value(__wrap_EsfLedManagerGetStatus, status->led, kEsfLedManagerTargetLedService);
    expect_value(__wrap_EsfLedManagerGetStatus, status->status, kEsfLedManagerLedStatusForcedOff);
    will_return(__wrap_EsfLedManagerGetStatus, false);
    will_return(__wrap_EsfLedManagerGetStatus, kEsfLedManagerSuccess);

    RetCode ret = SysAppLedGetEnable(&led_value);
    assert_true(led_value);
    assert_int_equal(ret, kRetFailed);

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
        // SysAppLedSetAppStatus()
        cmocka_unit_test(test_SysAppLedSetAppStatus_FullySuccess),
        cmocka_unit_test(test_SysAppLedSetAppStatus_EsfError),

        // SysAppLedUnsetAppStatus()
        cmocka_unit_test(test_SysAppLedUnsetAppStatus_FullySuccess),
        cmocka_unit_test(test_SysAppLedUnsetAppStatus_EsfError),

        // SysAppLedSetEnable()
        cmocka_unit_test(test_SysAppLedSetEnable_TrueFullySuccess),
        cmocka_unit_test(test_SysAppLedSetEnable_FalseFullySuccess),
        cmocka_unit_test(test_SysAppLedSetEnable_EsfError),

        // SysAppLedGetEnable()
        cmocka_unit_test(test_SysAppLedGetEnable_FullySuccess),
        cmocka_unit_test(test_SysAppLedGetEnable_EsfError),
        cmocka_unit_test(test_SysAppLedGetEnable_PowerSameError),
        cmocka_unit_test(test_SysAppLedGetEnable_WiFiSameError),
        cmocka_unit_test(test_SysAppLedGetEnable_ServiceSameError),
    };

    return (((cmocka_run_group_tests(tests, NULL, NULL)) == 0) ? 0 : 1);
}
