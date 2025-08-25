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

#include "power_manager.h"

/*----------------------------------------------------------------------------*/
EsfPwrMgrError __wrap_EsfPwrMgrStart(void)
{
    return mock_type(EsfPwrMgrError);
}

/*----------------------------------------------------------------------------*/
EsfPwrMgrError __wrap_EsfPwrMgrStop(void)
{
    return mock_type(EsfPwrMgrError);
}

/*----------------------------------------------------------------------------*/
EsfPwrMgrError __wrap_EsfPwrMgrPrepareReboot(void)
{
    function_called();

    return mock_type(EsfPwrMgrError);
}

/*----------------------------------------------------------------------------*/
void __wrap_EsfPwrMgrExecuteReboot(void)
{
    function_called();
}

/*----------------------------------------------------------------------------*/
EsfPwrMgrError __wrap_EsfPwrMgrPrepareShutdown(void)
{
    return mock_type(EsfPwrMgrError);
}

/*----------------------------------------------------------------------------*/
void __wrap_EsfPwrMgrExecuteShutdown(void)
{
}

/*----------------------------------------------------------------------------*/
EsfPwrMgrError __wrap_EsfPwrMgrGetVoltage(int32_t *voltage)
{
    *voltage = 5;
    return mock_type(EsfPwrMgrError);
}

/*----------------------------------------------------------------------------*/
EsfPwrMgrError __wrap_EsfPwrMgrHoursMeterGetValue(int32_t *hours)
{
    *hours = mock_type(int32_t);
    return mock_type(EsfPwrMgrError);
}

/*----------------------------------------------------------------------------*/
EsfPwrMgrError __wrap_EsfPwrMgrGetSupplyType(EsfPwrMgrSupplyType *supply_type)
{
    *supply_type = mock_type(EsfPwrMgrSupplyType);
    return mock_type(EsfPwrMgrError);
}

/*----------------------------------------------------------------------------*/
void __wrap_EsfPwrMgrWdtTerminate(void)
{
}

/*----------------------------------------------------------------------------*/
EsfPwrMgrError __wrap_EsfPwrMgrSwWdtStart(uint8_t id)
{
    check_expected(id);
    return mock_type(EsfPwrMgrError);
}

/*----------------------------------------------------------------------------*/
EsfPwrMgrError __wrap_EsfPwrMgrSwWdtStop(uint8_t id)
{
    check_expected(id);
    return mock_type(EsfPwrMgrError);
}

/*----------------------------------------------------------------------------*/
EsfPwrMgrError __wrap_EsfPwrMgrSwWdtKeepalive(uint8_t id)
{
    check_expected(id);
    return mock_type(EsfPwrMgrError);
}
