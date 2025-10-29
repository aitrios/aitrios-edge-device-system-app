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

#include <float.h>
#include "system_app_common.h"
#include "ut_mock_sysappcmn.h"

#define EXTRACT_REAL_NUMBER_GET_VAL_MAX_NUM \
    (32 * 2) // "32" means max array number of read/write_sensor_register \
             // "2" means execute number of SetSysAppCmnExtractRealNumberValue() per one array
#define SET_REAL_NUMBER_SET_VAL_MAX_NUM EXTRACT_REAL_NUMBER_GET_VAL_MAX_NUM

static double extract_real_number_get_val[EXTRACT_REAL_NUMBER_GET_VAL_MAX_NUM] = {0};
static uint32_t extract_real_number_get_val_num = 0;

static double set_real_number_set_val[SET_REAL_NUMBER_SET_VAL_MAX_NUM] = {0};
static uint32_t set_real_number_set_val_num = 0;

/*----------------------------------------------------------------------------*/
int __wrap_SysAppCmnExtractStringValue(EsfJsonHandle handle, EsfJsonValue parent_val,
                                       const char *jsonkey, const char **string)
{
    check_expected(handle);
    check_expected(parent_val);
    check_expected_ptr(jsonkey);
    *string = mock_type(const char *);
    return mock_type(int);
}

/*----------------------------------------------------------------------------*/
int __wrap_SysAppCmnExtractNumberValue(EsfJsonHandle handle, EsfJsonValue parent_val,
                                       const char *jsonkey, int *number)
{
    check_expected(handle);
    check_expected(parent_val);
    check_expected_ptr(jsonkey);
    *number = mock_type(int);
    return mock_type(int);
}

/*----------------------------------------------------------------------------*/
void SetSysAppCmnExtractRealNumberValue(double value)
{
    if (extract_real_number_get_val_num < EXTRACT_REAL_NUMBER_GET_VAL_MAX_NUM) {
        extract_real_number_get_val[extract_real_number_get_val_num] = value;
        extract_real_number_get_val_num++;
    }
    else {
        assert_int_not_equal(extract_real_number_get_val_num, EXTRACT_REAL_NUMBER_GET_VAL_MAX_NUM);
    }

    return;
}

/*----------------------------------------------------------------------------*/
int __wrap_SysAppCmnExtractRealNumberValue(EsfJsonHandle handle, EsfJsonValue parent_val,
                                           const char *jsonkey, double *number)
{
    check_expected(handle);
    check_expected(parent_val);
    check_expected_ptr(jsonkey);

    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    //   The number type supports will_return() is only integer.
    //   That is, not support floating decimal point.
    //   Therefore receive value with SetSysAppCmnExtractRealNumberValue() instead of mock_type().
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    // *number = mock_type(double);

    if (extract_real_number_get_val_num != 0) {
        *number = extract_real_number_get_val[0];
        extract_real_number_get_val_num--;

        for (int i = 0; i < extract_real_number_get_val_num; i++) {
            extract_real_number_get_val[i] = extract_real_number_get_val[i + 1];
        }
    }
    else {
        assert_int_not_equal(extract_real_number_get_val_num, 0);
    }

    return mock_type(int);
}

/*----------------------------------------------------------------------------*/
int __wrap_SysAppCmnExtractBooleanValue(EsfJsonHandle handle, EsfJsonValue parent_val,
                                        const char *jsonkey, bool *boolean)
{
    check_expected(handle);
    check_expected(parent_val);
    check_expected_ptr(jsonkey);
    *boolean = mock_type(bool);
    return mock_type(int);
}

/*----------------------------------------------------------------------------*/
int __wrap_SysAppCmnExtractObjectValue(EsfJsonHandle handle, EsfJsonValue parent_val,
                                       const char *jsonkey, EsfJsonValue *object)
{
    return mock_type(int);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppCmnGetReqId(EsfJsonHandle handle, EsfJsonValue parent_val, const char **req_id)
{
    check_expected(handle);
    check_expected(parent_val);
    *req_id = mock_type(const char *);
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppCmnSetStringValue(EsfJsonHandle handle, EsfJsonValue parent, const char *key,
                                       const char *string)
{
    check_expected(handle);
    check_expected(parent);
    check_expected_ptr(key);
    check_expected_ptr(string);
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppCmnSetNumberValue(EsfJsonHandle handle, EsfJsonValue parent, const char *key,
                                       int number)
{
    check_expected(handle);
    check_expected(parent);
    check_expected_ptr(key);
    check_expected(number);
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
void SetSysAppCmnSetRealNumberValue(double value)
{
    if (set_real_number_set_val_num < SET_REAL_NUMBER_SET_VAL_MAX_NUM) {
        set_real_number_set_val[set_real_number_set_val_num] = value;
        set_real_number_set_val_num++;
    }
    else {
        assert_int_not_equal(set_real_number_set_val_num, SET_REAL_NUMBER_SET_VAL_MAX_NUM);
    }

    return;
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppCmnSetRealNumberValue(EsfJsonHandle handle, EsfJsonValue parent,
                                           const char *key, double number)
{
    check_expected(handle);
    check_expected(parent);
    check_expected_ptr(key);

    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    //   cmocka API expect_XXX() to set expect number value only supports integer.
    //   That is, not support floating decimal point.
    //   Therefore receive expect value with SetSysAppCmnSetRealNumberValue(),
    //   and check with cmocka assert API instead of check_expected().
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    // check_expected(number);

    if (set_real_number_set_val_num != 0) {
#ifdef assert_double_equal
        assert_double_equal(set_real_number_set_val[0], number, DBL_EPSILON);
#else
        // I actually want to use "assert_double_equal()",
        // but it doesn't exist, so I use "assert_float_equal()".
        assert_float_equal(set_real_number_set_val[0], number, FLT_EPSILON);
#endif
        set_real_number_set_val_num--;

        for (int i = 0; i < set_real_number_set_val_num; i++) {
            set_real_number_set_val[i] = set_real_number_set_val[i + 1];
        }
    }
    else {
        assert_int_not_equal(set_real_number_set_val_num, 0);
    }

    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppCmnSetBooleanValue(EsfJsonHandle handle, EsfJsonValue parent, const char *key,
                                        bool boolean)
{
    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppCmnSetObjectValue(EsfJsonHandle handle, EsfJsonValue parent, const char *key,
                                       RetCode (*make_json)(EsfJsonHandle, EsfJsonValue, void *),
                                       void *ctx)
{
    bool exec_cb_flag;

    check_expected(handle);
    check_expected(parent);
    check_expected_ptr(key);
    check_expected_ptr(make_json);
    check_expected_ptr(ctx);

    exec_cb_flag = mock_type(bool);

    if (make_json != NULL) {
        if (exec_cb_flag) {
            make_json(handle, parent, ctx);
        }
    }

    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppCmnSetArrayValue(
    EsfJsonHandle handle, EsfJsonValue parent, const char *key, uint32_t array_num,
    RetCode (*make_json)(EsfJsonHandle, EsfJsonValue, uint32_t, void *), void *ctx)
{
#if defined(SYSTEM_APP_DIRECT_COMMAND)
    check_expected(handle);
    check_expected(parent);
    check_expected_ptr(key);
    check_expected(array_num);
    check_expected_ptr(make_json);
    check_expected_ptr(ctx);

    if (make_json != NULL) {
        if (mock_type(bool) == true) {
            for (int i = 0; i < array_num; i++) {
                make_json(handle, parent, i, ctx);
            }
        }
    }
#endif

    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppCmnMakeJsonResInfo(EsfJsonHandle handle, EsfJsonValue root, const char *res_id,
                                        int code, const char *detail_msg)
{
    check_expected(handle);
    check_expected(root);
    check_expected_ptr(res_id);
    check_expected(code);
    check_expected_ptr(detail_msg);

    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppCmnSetStringValueFileIO(EsfJsonHandle handle, EsfJsonValue parent,
                                             const char *key, EsfMemoryManagerHandle mm_handle,
                                             size_t size)
{
    check_expected(handle);
    check_expected(parent);
    check_expected_ptr(key);
    check_expected(mm_handle);
    check_expected(size);

    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
RetCode __wrap_SysAppCmnSetStringValueHandle(EsfJsonHandle handle, EsfJsonValue parent,
                                             const char *key, EsfMemoryManagerHandle mm_handle,
                                             size_t size)
{
    check_expected(handle);
    check_expected(parent);
    check_expected_ptr(key);
    check_expected(mm_handle);
    check_expected(size);

    return mock_type(RetCode);
}
