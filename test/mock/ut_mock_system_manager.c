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

#include <stdio.h>
#include "system_manager.h"

/*----------------------------------------------------------------------------*/
EsfSystemManagerResult __wrap_EsfSystemManagerGetDeviceManifest(char *data, size_t *data_size)
{
    *data_size = snprintf(data, *data_size, "%s", mock_type(const char *));
    return mock_type(EsfSystemManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfSystemManagerResult __wrap_EsfSystemManagerSetProjectId(const char *data, size_t data_size)
{
    check_expected_ptr(data);
    check_expected(data_size);
    return mock_type(EsfSystemManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfSystemManagerResult __wrap_EsfSystemManagerSetRegisterToken(const char *data, size_t data_size)
{
    check_expected_ptr(data);
    check_expected(data_size);
    return mock_type(EsfSystemManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfSystemManagerResult __wrap_EsfSystemManagerGetEvpHubUrl(char *data, size_t *data_size)
{
    *data_size = snprintf(data, *data_size, "%s", mock_type(const char *));
    return mock_type(EsfSystemManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfSystemManagerResult __wrap_EsfSystemManagerGetEvpHubPort(char *data, size_t *data_size)
{
    *data_size = snprintf(data, *data_size, "%s", mock_type(const char *));
    return mock_type(EsfSystemManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfSystemManagerResult __wrap_EsfSystemManagerSetEvpHubUrl(const char *data, size_t data_size)
{
    check_expected_ptr(data);
    check_expected(data_size);
    return mock_type(EsfSystemManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfSystemManagerResult __wrap_EsfSystemManagerSetEvpHubPort(const char *data, size_t data_size)
{
    check_expected_ptr(data);
    check_expected(data_size);
    return mock_type(EsfSystemManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfSystemManagerResult __wrap_EsfSystemManagerSetEvpTls(EsfSystemManagerEvpTlsValue data)
{
    check_expected(data);
    return mock_type(EsfSystemManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfSystemManagerResult __wrap_EsfSystemManagerGetQrModeTimeoutValue(int32_t *data)
{
    check_expected_ptr(data);
    *data = mock_type(int32_t);
    return mock_type(EsfSystemManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfSystemManagerResult __wrap_EsfSystemManagerSetQrModeTimeoutValue(int32_t data)
{
    check_expected(data);

    return mock_type(EsfSystemManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfSystemManagerResult __wrap_EsfSystemManagerGetProjectId(char *data, size_t *data_size)
{
    *data_size = snprintf(data, *data_size, "%s", mock_type(const char *));
    return mock_type(EsfSystemManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfSystemManagerResult __wrap_EsfSystemManagerGetRegisterToken(char *data, size_t *data_size)
{
    *data_size = snprintf(data, *data_size, "%s", mock_type(const char *));
    return mock_type(EsfSystemManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfSystemManagerResult __wrap_EsfSystemManagerGetHwInfo(EsfSystemManagerHwInfo *data)
{
    snprintf(data->serial_number, ESF_SYSTEM_MANAGER_HWINFO_PRODUCT_SERIAL_NUMBER_MAX_SIZE, "%s",
             mock_type(const char *));
    return mock_type(EsfSystemManagerResult);
}

/*----------------------------------------------------------------------------*/
