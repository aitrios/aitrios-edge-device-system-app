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

#include "sensor_main.h"
#include "sensor_ai_lib/sensor_ai_lib_state.h"

/*----------------------------------------------------------------------------*/
SsfSensorErrCode __wrap_SsfSensorInit(void)
{
    return mock_type(SsfSensorErrCode);
}

/*----------------------------------------------------------------------------*/
SsfSensorErrCode __wrap_SsfSensorExit(void)
{
    return mock_type(SsfSensorErrCode);
}

/*----------------------------------------------------------------------------*/
void __wrap_EsfSensorPowerOFF(void)
{
}

/*----------------------------------------------------------------------------*/
EsfSensorErrCode __wrap_EsfSensorInit(void)
{
    return mock_type(EsfSensorErrCode);
}

/*----------------------------------------------------------------------------*/
EsfSensorErrCode __wrap_EsfSensorExit(void)
{
    return mock_type(EsfSensorErrCode);
}

/*----------------------------------------------------------------------------*/
EsfSensorErrCode __wrap_EsfSensorUtilitySetupFiles(void)
{
    return mock_type(EsfSensorErrCode);
}

/*----------------------------------------------------------------------------*/
SsfSensorLibState __wrap_SsfSensorLibGetState(void)
{
    return mock_type(SsfSensorLibState);
}
