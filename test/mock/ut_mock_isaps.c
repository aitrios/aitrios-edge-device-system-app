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

#include "initial_setting_app_ps.h"

/*----------------------------------------------------------------------------*/
IsaPsErrorCode __wrap_IsaRunProvisioningService(bool is_debug_mode)
{
    check_expected(is_debug_mode);
    return mock_type(IsaPsErrorCode);
}

/*----------------------------------------------------------------------------*/
