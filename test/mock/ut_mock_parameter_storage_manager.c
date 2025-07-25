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

#include "parameter_storage_manager.h"

/*----------------------------------------------------------------------------*/
EsfParameterStorageManagerStatus __wrap_EsfParameterStorageManagerInit(void)
{
    return mock_type(EsfParameterStorageManagerStatus);
}

/*----------------------------------------------------------------------------*/
EsfParameterStorageManagerStatus __wrap_EsfParameterStorageManagerDeinit(void)
{
    return mock_type(EsfParameterStorageManagerStatus);
}

/*----------------------------------------------------------------------------*/
