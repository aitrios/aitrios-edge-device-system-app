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

#include "system_app_direct_command.h"

/*----------------------------------------------------------------------------*/
bool __wrap_SysAppDcmdCheckSelfTerminate(TerminationReason *reason)
{
    *reason = mock_type(TerminationReason);

    return mock_type(bool);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppDcmdInitialize(struct SYS_client *sys_client)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppDcmdFinalize(void)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
void __wrap_SysAppDcmdRebootCore(void)
{
    return;
}

/*----------------------------------------------------------------------------*/
void __wrap_SysAppDcmdFactoryResetCore(void)
{
    return;
}

/*----------------------------------------------------------------------------*/
