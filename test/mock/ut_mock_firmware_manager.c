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

#include <string.h>
#include "firmware_manager.h"

/*----------------------------------------------------------------------------*/
EsfFwMgrResult __wrap_EsfFwMgrGetFactoryResetFlag(bool* factory_reset_flag)
{
    *factory_reset_flag = mock_type(bool);
    return mock_type(EsfFwMgrResult);
}

/*----------------------------------------------------------------------------*/
EsfFwMgrResult __wrap_EsfFwMgrGetInfo(EsfFwMgrGetInfoData* data)
{
    memcpy(data->response, mock_type(EsfFwMgrGetInfoResponse*),
           sizeof(EsfFwMgrGetInfoResponse) * data->in_length);
    data->out_length = data->in_length;
    return mock_type(EsfFwMgrResult);
}

/*----------------------------------------------------------------------------*/
EsfFwMgrResult __wrap_EsfFwMgrInit(void)
{
    return mock_type(EsfFwMgrResult);
}

/*----------------------------------------------------------------------------*/
EsfFwMgrResult __wrap_EsfFwMgrDeinit(void)
{
    return mock_type(EsfFwMgrResult);
}

/*----------------------------------------------------------------------------*/
EsfFwMgrResult __wrap_EsfFwMgrSetFactoryResetFlag(bool factory_reset_flag)
{
    return mock_type(EsfFwMgrResult);
}

/*----------------------------------------------------------------------------*/
EsfFwMgrResult __wrap_EsfFwMgrOpen(const EsfFwMgrOpenRequest* request,
                                   const EsfFwMgrPrepareWriteRequest* prepare_write,
                                   EsfFwMgrOpenResponse* response)
{
    response->handle = mock_type(EsfFwMgrHandle);
    response->prepare_write.memory_size = mock_type(int32_t);
    response->prepare_write.writable_size = mock_type(int32_t);

    return mock_type(EsfFwMgrResult);
}

/*----------------------------------------------------------------------------*/
EsfFwMgrResult __wrap_EsfFwMgrWrite(EsfFwMgrHandle handle, const EsfFwMgrWriteRequest* request)
{
    return mock_type(EsfFwMgrResult);
}

/*----------------------------------------------------------------------------*/
EsfFwMgrResult __wrap_EsfFwMgrClose(EsfFwMgrHandle handle)
{
    return mock_type(EsfFwMgrResult);
}

/*----------------------------------------------------------------------------*/
EsfFwMgrResult __wrap_EsfFwMgrErase(EsfFwMgrHandle handle)
{
    return mock_type(EsfFwMgrResult);
}

/*----------------------------------------------------------------------------*/
EsfFwMgrResult __wrap_EsfFwMgrPostProcess(EsfFwMgrHandle handle)
{
    return mock_type(EsfFwMgrResult);
}

/*----------------------------------------------------------------------------*/
EsfFwMgrResult __wrap_EsfFwMgrCopyToInternalBuffer(
    EsfFwMgrHandle handle, const EsfFwMgrCopyToInternalBufferRequest* request)
{
    check_expected(handle);
    check_expected(request->offset);
    check_expected(request->size);
    check_expected_ptr(request->data);
    return mock_type(EsfFwMgrResult);
}

/*----------------------------------------------------------------------------*/
EsfFwMgrResult __wrap_EsfFwMgrStartFactoryReset(EsfFwMgrFactoryResetCause cause)
{
    check_expected(cause);

    return mock_type(EsfFwMgrResult);
}

/*----------------------------------------------------------------------------*/
EsfFwMgrResult __wrap_EsfFwMgrGetBinaryHeaderInfo(EsfFwMgrHandle handle,
                                                  EsfFwMgrBinaryHeaderInfo* info)
{
    info->sw_arch_version = mock_type(EsfFwMgrSwArchVersion);
    return mock_type(EsfFwMgrResult);
}

/*----------------------------------------------------------------------------*/
