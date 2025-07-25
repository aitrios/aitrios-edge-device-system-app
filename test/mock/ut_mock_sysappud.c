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
#include "system_app_ud_main.h"

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppUdInitialize(struct SYS_client *iot_client_ud)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppUdFinalize(void)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
size_t __wrap_SysAppUdGetImageSize(char *uri, int *http_status)
{
    *http_status = mock_type(int);
    return mock_type(size_t);
}

/*----------------------------------------------------------------------------*/
ssize_t __wrap_SysAppUdGetImageData(char *request_url, size_t offset, size_t size,
                                    SysAppUdDownloadCb cb, void *usr_param, int *http_status)
{
    *http_status = mock_type(int);
    return mock_type(ssize_t);
}

/*----------------------------------------------------------------------------*/
void __wrap_SysAppUdRequestToStopDownload(void)
{
    function_called();
}

/*----------------------------------------------------------------------------*/
bool __wrap_SysAppUdIsThisRequestToStopForDownload(void)
{
    return mock_type(bool);
}

/*----------------------------------------------------------------------------*/
void __wrap_SysAppUdCancelDownloadStopRequest(void)
{
}

/*----------------------------------------------------------------------------*/
void __wrap_SysAppUdWaitForDownloadToStop(void)
{
    function_called();
}
