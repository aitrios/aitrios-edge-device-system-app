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

#include "memory_manager.h"

/*----------------------------------------------------------------------------*/
EsfMemoryManagerResult __wrap_EsfMemoryManagerInitialize(int32_t app_mem_blocks)
{
    return mock_type(EsfMemoryManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfMemoryManagerResult __wrap_EsfMemoryManagerFinalize(void)
{
    return mock_type(EsfMemoryManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfMemoryManagerResult __wrap_EsfMemoryManagerMap(EsfMemoryManagerHandle handle,
                                                  const wasm_exec_env_t *exec_env, int32_t size,
                                                  void **address)
{
    check_expected(handle);
    check_expected_ptr(exec_env);
    check_expected(size);
    *address = mock_type(void *);
    return mock_type(EsfMemoryManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfMemoryManagerResult __wrap_EsfMemoryManagerUnmap(EsfMemoryManagerHandle handle, void **address)
{
    check_expected(handle);
    check_expected_ptr(address);
    return mock_type(EsfMemoryManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfMemoryManagerResult __wrap_EsfMemoryManagerAllocate(EsfMemoryManagerTargetArea target_area,
                                                       const wasm_exec_env_t *exec_env,
                                                       int32_t size, EsfMemoryManagerHandle *handle)
{
    check_expected(target_area);
    check_expected_ptr(exec_env);
    check_expected(size);

    *handle = mock_type(EsfMemoryManagerHandle);

    return mock_type(EsfMemoryManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfMemoryManagerResult __wrap_EsfMemoryManagerFree(EsfMemoryManagerHandle handle,
                                                   const wasm_exec_env_t *exec_env)
{
    check_expected(handle);
    check_expected_ptr(exec_env);
    return mock_type(EsfMemoryManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfMemoryManagerResult __wrap_EsfMemoryManagerFopen(EsfMemoryManagerHandle handle)
{
    check_expected(handle);
    return mock_type(EsfMemoryManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfMemoryManagerResult __wrap_EsfMemoryManagerFclose(EsfMemoryManagerHandle handle)
{
    check_expected(handle);
    return mock_type(EsfMemoryManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfMemoryManagerResult __wrap_EsfMemoryManagerFseek(EsfMemoryManagerHandle handle, off_t offset,
                                                    int whence, off_t *result_offset)
{
    check_expected(handle);
    check_expected(offset);
    check_expected(whence);
    *result_offset = mock_type(off_t);
    return mock_type(EsfMemoryManagerResult);
}

/*----------------------------------------------------------------------------*/
EsfMemoryManagerResult __wrap_EsfMemoryManagerFread(EsfMemoryManagerHandle handle, const void *buff,
                                                    size_t size, size_t *rsize)
{
    check_expected(handle);
    check_expected_ptr(buff);
    check_expected(size);
    check_expected_ptr(rsize);
    return mock_type(EsfMemoryManagerResult);
}
/*----------------------------------------------------------------------------*/
EsfMemoryManagerAppMemory __wrap_EsfMemoryManagerWasmAllocate(EsfMemoryManagerWasmMemoryUsage usage,
                                                              int32_t size)
{
    check_expected(usage);
    check_expected(size);

    return mock_type(EsfMemoryManagerAppMemory);
}
/*----------------------------------------------------------------------------*/
void __wrap_EsfMemoryManagerWasmFree(EsfMemoryManagerWasmMemoryUsage usage,
                                     EsfMemoryManagerAppMemory memory)
{
    check_expected(usage);
    check_expected(memory);
}
/*----------------------------------------------------------------------------*/
EsfMemoryManagerResult __wrap_EsfMemoryManagerGetHandleInfo(uint32_t handle,
                                                            EsfMemoryManagerHandleInfo *info)
{
    check_expected(handle);
    info->target_area = mock_type(EsfMemoryManagerTargetArea);
    return mock_type(EsfMemoryManagerResult);
}
