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

#include "system_app_common.h"
#include "system_app_deploy.h"

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppDeployGetFirmwareState(char **state, uint32_t *p_size)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppDeployGetAiModelState(char **state, uint32_t *p_size)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppDeployGetSensorCalibrationParamState(char **state, uint32_t *p_size)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppDeployInitialize(void)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
bool __wrap_SysAppDeployCheckResetRequest(bool *is_downgrade)
{
    *is_downgrade = mock_type(bool);
    return mock_type(bool);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppDeployFinalize(void)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppDeploy(const char *topic, const char *config, size_t len)
{
    check_expected_ptr(topic);
    check_expected_ptr(config);
    check_expected(len);

    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppDeployFreeState(char *state)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
void __wrap_SysAppDeployFactoryReset(void)
{
}

/*----------------------------------------------------------------------------*/
bool __wrap_SysAppDeployGetCancel(void)
{
    return mock_type(bool);
}
