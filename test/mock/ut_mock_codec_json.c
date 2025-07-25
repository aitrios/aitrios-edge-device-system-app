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

#include <float.h>
#include "ut_mock_codec_json.h"
#include "json/include/json.h"
#include "json/include/json_fileio.h"

static double real_get_value = 0;
static bool is_set_real_get_value = false;

static double real_init_expect_value = 0;
static bool is_set_real_init_expect_value = false;

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonOpen(EsfJsonHandle* handle)
{
    *handle = mock_type(EsfJsonHandle);

    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonClose(EsfJsonHandle handle)
{
    check_expected(handle);

    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonObjectInit(EsfJsonHandle handle, EsfJsonValue* value)
{
    check_expected(handle);

    *value = mock_type(EsfJsonValue);

    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonSerialize(EsfJsonHandle handle, EsfJsonValue value, const char** str)
{
    check_expected(handle);
    check_expected(value);
    *str = mock_type(const char*);
    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonObjectGet(EsfJsonHandle handle, EsfJsonValue parent, const char* key,
                                         EsfJsonValue* value)
{
    check_expected(handle);
    check_expected(parent);
    check_expected_ptr(key);

    *value = mock_type(EsfJsonValue);

    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonValueTypeGet(EsfJsonHandle handle, EsfJsonValue value,
                                            EsfJsonValueType* type)
{
    check_expected(handle);
    check_expected(value);

    *type = mock_type(EsfJsonValueType);

    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonStringGet(EsfJsonHandle handle, EsfJsonValue value, const char** str)
{
    check_expected(handle);
    check_expected(value);

    *str = mock_type(const char*);

    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonIntegerGet(EsfJsonHandle handle, EsfJsonValue value, int32_t* num)
{
    check_expected(handle);
    check_expected(value);

    *num = mock_type(int32_t);

    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
void SetEsfJsonRealGetValue(double value)
{
    real_get_value = value;
    is_set_real_get_value = true;
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonRealGet(EsfJsonHandle handle, EsfJsonValue value, double* num)
{
    check_expected(handle);
    check_expected(value);

    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    //   The number type supports will_return() is only integer.
    //   That is, not support floating decimal point.
    //   Therefore receive value with SetEsfJsonRealGetValue() instead of mock_type().
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    // *num = mock_type(double);

    if (is_set_real_get_value == true) {
        *num = real_get_value;
        is_set_real_get_value = false;
    }
    else {
        assert_true(is_set_real_get_value);
    }

    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonBooleanGet(EsfJsonHandle handle, EsfJsonValue value, bool* boolean)
{
    check_expected(handle);
    check_expected(value);

    *boolean = mock_type(bool);

    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonStringInit(EsfJsonHandle handle, const char* str,
                                          EsfJsonValue* value)
{
    check_expected(handle);
    check_expected_ptr(str);

    *value = mock_type(EsfJsonValue);

    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonObjectSet(EsfJsonHandle handle, EsfJsonValue parent, const char* key,
                                         EsfJsonValue value)
{
    check_expected(handle);
    check_expected(parent);
    check_expected_ptr(key);
    check_expected(value);

    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonIntegerInit(EsfJsonHandle handle, int32_t num, EsfJsonValue* value)
{
    check_expected(handle);
    check_expected(num);

    *value = mock_type(EsfJsonValue);

    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
void SetEsfJsonRealInitExpectValue(double value)
{
    real_init_expect_value = value;
    is_set_real_init_expect_value = true;
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonRealInit(EsfJsonHandle handle, double num, EsfJsonValue* value)
{
    check_expected(handle);

    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    //   cmocka API expect_XXX() to set expect number value only supports integer.
    //   That is, not support floating decimal point.
    //   Therefore receive expect value with SetEsfJsonRealInitExpectValue(),
    //   and check with cmocka assert API instead of check_expected().
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    // check_expected(num);

    if (is_set_real_init_expect_value == true) {
#ifdef assert_double_equal
        assert_double_equal(real_init_expect_value, num, DBL_EPSILON);
#else
        // I actually want to use "assert_double_equal()",
        // but it doesn't exist, so I use "assert_float_equal()".
        assert_float_equal(real_init_expect_value, num, FLT_EPSILON);
#endif
        is_set_real_init_expect_value = false;
    }
    else {
        assert_true(is_set_real_init_expect_value);
    }

    *value = mock_type(EsfJsonValue);

    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonBooleanInit(EsfJsonHandle handle, bool boolean, EsfJsonValue* value)
{
    check_expected(handle);
    check_expected(boolean);

    *value = mock_type(EsfJsonValue);

    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonArrayInit(EsfJsonHandle handle, EsfJsonValue* value)
{
    check_expected(handle);

    *value = mock_type(EsfJsonValue);

    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonArrayAppend(EsfJsonHandle handle, EsfJsonValue parent,
                                           EsfJsonValue value)
{
    check_expected(handle);
    check_expected(parent);
    check_expected(value);

    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonDeserialize(EsfJsonHandle handle, const char* str,
                                           EsfJsonValue* value)
{
    check_expected(handle);
    check_expected_ptr(str);
    *value = mock_type(EsfJsonValue);
    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
int32_t __wrap_EsfJsonArrayCount(EsfJsonHandle handle, EsfJsonValue parent)
{
    check_expected(handle);
    check_expected(parent);
    return mock_type(int32_t);
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonArrayGet(EsfJsonHandle handle, EsfJsonValue parent, int32_t index,
                                        EsfJsonValue* value)
{
    check_expected(handle);
    check_expected(parent);
    check_expected(index);
    *value = mock_type(EsfJsonValue);
    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonSerializeFree(EsfJsonHandle handle)
{
    check_expected(handle);
    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
size_t __wrap_EsfJsonSerializeSizeGet(EsfJsonHandle handle, EsfJsonValue value)
{
    check_expected(handle);
    check_expected(value);
    return mock_type(size_t);
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonSerializeFileIO(EsfJsonHandle handle, EsfJsonValue value,
                                               EsfMemoryManagerHandle mem_handle, size_t* mem_size)
{
    check_expected(handle);
    check_expected(value);
    check_expected(mem_handle);

    *mem_size = mock_type(size_t);

    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonSerializeHandle(EsfJsonHandle handle, EsfJsonValue value,
                                               EsfMemoryManagerHandle mem_handle, size_t* mem_size)
{
    check_expected(handle);
    check_expected(value);
    check_expected(mem_handle);

    *mem_size = mock_type(size_t);

    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonStringInitFileIO(EsfJsonHandle handle,
                                                EsfMemoryManagerHandle mem_handle, size_t mem_size,
                                                EsfJsonValue* value)
{
    check_expected(handle);
    check_expected(mem_handle);
    check_expected(mem_size);

    *value = mock_type(EsfJsonValue);

    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
EsfJsonErrorCode __wrap_EsfJsonStringInitHandle(EsfJsonHandle handle,
                                                EsfMemoryManagerHandle mem_handle, size_t mem_size,
                                                EsfJsonValue* value)
{
    check_expected(handle);
    check_expected(mem_handle);
    check_expected(mem_size);

    *value = mock_type(EsfJsonValue);

    return mock_type(EsfJsonErrorCode);
}

/*----------------------------------------------------------------------------*/
