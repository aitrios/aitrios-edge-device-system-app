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

#include "evp/sdk_sys.h"
#include "system_app_configuration.h"

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppCfgInitialize(struct SYS_client* sys_client)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppCfgFinalize(void)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
