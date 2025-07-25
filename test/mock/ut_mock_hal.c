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

#include "hal_driver.h"
#include "hal_i2c.h"
#include "hal_ioexp.h"

/*----------------------------------------------------------------------------*/
HalErrCode __wrap_HalDriverInitialize(void)
{
    return mock_type(HalErrCode);
}

/*----------------------------------------------------------------------------*/
HalErrCode __wrap_HalDriverFinalize(void)
{
    return mock_type(HalErrCode);
}

/*----------------------------------------------------------------------------*/
HalErrCode __wrap_HalI2cInitialize(void)
{
    return mock_type(HalErrCode);
}

/*----------------------------------------------------------------------------*/
HalErrCode __wrap_HalI2cFinalize(void)
{
    return mock_type(HalErrCode);
}

/*----------------------------------------------------------------------------*/
HalErrCode __wrap_HalIoexpInitialize(void)
{
    return mock_type(HalErrCode);
}

/*----------------------------------------------------------------------------*/
HalErrCode __wrap_HalIoexpFinalize(void)
{
    return mock_type(HalErrCode);
}

/*----------------------------------------------------------------------------*/
