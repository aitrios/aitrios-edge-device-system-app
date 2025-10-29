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

#include "led_manager.h"

/*----------------------------------------------------------------------------*/
EsfLedManagerResult __wrap_EsfLedManagerGetStatus(EsfLedManagerLedStatusInfo *status)
{
    check_expected(status->led);
    check_expected(status->status);
    status->enabled = mock_type(bool);
    return mock_type(EsfLedManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfLedManagerResult __wrap_EsfLedManagerInit(void)
{
    return mock_type(EsfLedManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfLedManagerResult __wrap_EsfLedManagerDeinit(void)
{
    return mock_type(EsfLedManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfLedManagerResult __wrap_EsfLedManagerSetStatus(const EsfLedManagerLedStatusInfo *status)
{
    check_expected(status->led);
    check_expected(status->status);
    check_expected(status->enabled);
    return mock_type(EsfLedManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfLedManagerResult __wrap_EsfLedManagerSetLightingPersistence(EsfLedManagerTargetLed led,
                                                               bool is_enable)
{
    return mock_type(EsfLedManagerResult);
}

/*----------------------------------------------------------------------------*/
