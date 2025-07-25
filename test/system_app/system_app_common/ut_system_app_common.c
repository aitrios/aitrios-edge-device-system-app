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

#include <stdlib.h>
#include <float.h>
#include "ut_mock_codec_json.h"
#include "system_app_common.h"

/*----------------------------------------------------------------------------*/

//
// SysAppCmnExtractStringValue()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractStringValue_FullySuccess(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    const char *string_expect = "string_value";
    const char *string_out = NULL;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, child_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeString);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonStringGet, handle, handle_val);
    expect_value(__wrap_EsfJsonStringGet, value, child_val);
    will_return(__wrap_EsfJsonStringGet, string_expect);
    will_return(__wrap_EsfJsonStringGet, kEsfJsonSuccess);

    ret = SysAppCmnExtractStringValue(handle_val, parent_val, jsonkey, &string_out);

    assert_int_equal(ret, 1);
    assert_ptr_equal(string_expect, string_out);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractStringValue_ErrorEsfJsonObjectGet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    // const char *string_expect = "string_value";
    const char *string_out = NULL;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonInternalError);

    ret = SysAppCmnExtractStringValue(handle_val, parent_val, jsonkey, &string_out);

    assert_int_equal(ret, -1);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractStringValue_ErrorEsfJsonValueTypeGet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    // const char *string_expect = "string_value";
    const char *string_out = NULL;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, child_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeString);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonInternalError);

    ret = SysAppCmnExtractStringValue(handle_val, parent_val, jsonkey, &string_out);

    assert_int_equal(ret, 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractStringValue_OtherTypeEsfJsonValueTypeGet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    // const char *string_expect = "string_value";
    const char *string_out = NULL;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, child_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeNumber);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    ret = SysAppCmnExtractStringValue(handle_val, parent_val, jsonkey, &string_out);

    assert_int_equal(ret, 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractStringValue_ErrorEsfJsonStringGet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    const char *string_expect = "string_value";
    const char *string_out = NULL;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, child_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeString);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonStringGet, handle, handle_val);
    expect_value(__wrap_EsfJsonStringGet, value, child_val);
    will_return(__wrap_EsfJsonStringGet, string_expect);
    will_return(__wrap_EsfJsonStringGet, kEsfJsonInternalError);

    ret = SysAppCmnExtractStringValue(handle_val, parent_val, jsonkey, &string_out);

    assert_int_equal(ret, 0);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCmnExtractNumberValue()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractNumberValue_FullySuccess(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    int number_expect = 9876;
    int number_out;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, child_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeNumber);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonIntegerGet, handle, handle_val);
    expect_value(__wrap_EsfJsonIntegerGet, value, child_val);
    will_return(__wrap_EsfJsonIntegerGet, number_expect);
    will_return(__wrap_EsfJsonIntegerGet, kEsfJsonSuccess);

    ret = SysAppCmnExtractNumberValue(handle_val, parent_val, jsonkey, &number_out);

    assert_int_equal(ret, 1);
    assert_int_equal(number_expect, number_out);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractNumberValue_ErrorEsfJsonObjectGet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    //int number_expect = 9876;
    int number_out;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonInternalError);

    ret = SysAppCmnExtractNumberValue(handle_val, parent_val, jsonkey, &number_out);

    assert_int_equal(ret, -1);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractNumberValue_ErrorEsfJsonValueTypeGet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    //int number_expect = 9876;
    int number_out;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, child_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeNumber);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonInternalError);

    ret = SysAppCmnExtractNumberValue(handle_val, parent_val, jsonkey, &number_out);

    assert_int_equal(ret, 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractNumberValue_OtherTypeEsfJsonValueTypeGet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    //int number_expect = 9876;
    int number_out;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, child_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeString);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    ret = SysAppCmnExtractNumberValue(handle_val, parent_val, jsonkey, &number_out);

    assert_int_equal(ret, 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractNumberValue_ErrorEsfJsonIntegerGet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    int number_expect = 9876;
    int number_out;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, child_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeNumber);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonIntegerGet, handle, handle_val);
    expect_value(__wrap_EsfJsonIntegerGet, value, child_val);
    will_return(__wrap_EsfJsonIntegerGet, number_expect);
    will_return(__wrap_EsfJsonIntegerGet, kEsfJsonInternalError);

    ret = SysAppCmnExtractNumberValue(handle_val, parent_val, jsonkey, &number_out);

    assert_int_equal(ret, 0);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCmnExtractRealNumberValue()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractRealNumberValue_FullySuccess(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    double number_expect = 9876.5432;
    double number_out;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, child_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeNumber);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonRealGet, handle, handle_val);
    expect_value(__wrap_EsfJsonRealGet, value, child_val);

    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    //   The number type supports will_return() is only integer.
    //   That is, not support floating decimal point.
    //   Therefore set value with SetEsfJsonRealGetValue() instead of will_return().
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    // will_return(__wrap_EsfJsonRealGet, number_expect);
    SetEsfJsonRealGetValue(number_expect);

    will_return(__wrap_EsfJsonRealGet, kEsfJsonSuccess);

    ret = SysAppCmnExtractRealNumberValue(handle_val, parent_val, jsonkey, &number_out);

    assert_int_equal(ret, 1);

#ifdef assert_double_equal
    assert_double_equal(number_expect, number_out, DBL_EPSILON);
#else
    // I actually want to use "assert_double_equal()",
    // but it doesn't exist, so I use "assert_float_equal()".
    assert_float_equal(number_expect, number_out, FLT_EPSILON);
#endif

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractRealNumberValue_ErrorEsfJsonObjectGet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    //double number_expect = 9876.5432;
    double number_out;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonInternalError);

    ret = SysAppCmnExtractRealNumberValue(handle_val, parent_val, jsonkey, &number_out);

    assert_int_equal(ret, -1);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractRealNumberValue_ErrorEsfJsonValueTypeGet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    //double number_expect = 9876.5432;
    double number_out;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, child_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeNumber);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonInternalError);

    ret = SysAppCmnExtractRealNumberValue(handle_val, parent_val, jsonkey, &number_out);

    assert_int_equal(ret, 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractRealNumberValue_OtherTypeEsfJsonValueTypeGet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    //double number_expect = 9876.5432;
    double number_out;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, child_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeString);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    ret = SysAppCmnExtractRealNumberValue(handle_val, parent_val, jsonkey, &number_out);

    assert_int_equal(ret, 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractRealNumberValue_ErrorEsfJsonRealGet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    double number_expect = 9876.5432;
    double number_out;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, child_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeNumber);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonRealGet, handle, handle_val);
    expect_value(__wrap_EsfJsonRealGet, value, child_val);

    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    //   The number type supports will_return() is only integer.
    //   That is, not support floating decimal point.
    //   Therefore set value with SetEsfJsonRealGetValue() instead of will_return().
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    // will_return(__wrap_EsfJsonRealGet, number_expect);
    SetEsfJsonRealGetValue(number_expect);

    will_return(__wrap_EsfJsonRealGet, kEsfJsonInternalError);

    ret = SysAppCmnExtractRealNumberValue(handle_val, parent_val, jsonkey, &number_out);

    assert_int_equal(ret, 0);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCmnExtractBooleanValue()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractBooleanValue_FullySuccess(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    bool bool_expect = true;
    bool bool_out;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, child_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeBoolean);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonBooleanGet, handle, handle_val);
    expect_value(__wrap_EsfJsonBooleanGet, value, child_val);
    will_return(__wrap_EsfJsonBooleanGet, bool_expect);
    will_return(__wrap_EsfJsonBooleanGet, kEsfJsonSuccess);

    ret = SysAppCmnExtractBooleanValue(handle_val, parent_val, jsonkey, &bool_out);

    assert_int_equal(ret, 1);
    assert_int_equal(bool_expect, bool_out);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractBooleanValue_ErrorEsfJsonObjectGet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    // bool bool_expect = true;
    bool bool_out;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonInternalError);

    ret = SysAppCmnExtractBooleanValue(handle_val, parent_val, jsonkey, &bool_out);

    assert_int_equal(ret, -1);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractBooleanValue_ErrorEsfJsonValueTypeGet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    // bool bool_expect = true;
    bool bool_out;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, child_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeBoolean);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonInternalError);

    ret = SysAppCmnExtractBooleanValue(handle_val, parent_val, jsonkey, &bool_out);

    assert_int_equal(ret, 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractBooleanValue_OtherTypeEsfJsonValueTypeGet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    // bool bool_expect = true;
    bool bool_out;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, child_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeNumber);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    ret = SysAppCmnExtractBooleanValue(handle_val, parent_val, jsonkey, &bool_out);

    assert_int_equal(ret, 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractBooleanValue_ErrorEsfJsonBooleanGet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    bool bool_expect = true;
    bool bool_out;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, child_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeBoolean);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonBooleanGet, handle, handle_val);
    expect_value(__wrap_EsfJsonBooleanGet, value, child_val);
    will_return(__wrap_EsfJsonBooleanGet, bool_expect);
    will_return(__wrap_EsfJsonBooleanGet, kEsfJsonInternalError);

    ret = SysAppCmnExtractBooleanValue(handle_val, parent_val, jsonkey, &bool_out);

    assert_int_equal(ret, 0);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCmnExtractObjectValue()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractObjectValue_FullySuccess(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    EsfJsonValue jsonval_out;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, child_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeObject);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    ret = SysAppCmnExtractObjectValue(handle_val, parent_val, jsonkey, &jsonval_out);

    assert_int_equal(ret, 1);
    assert_int_equal(child_val, jsonval_out);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractObjectValue_ErrorEsfJsonObjectGet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    EsfJsonValue jsonval_out;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonInternalError);

    ret = SysAppCmnExtractObjectValue(handle_val, parent_val, jsonkey, &jsonval_out);

    assert_int_equal(ret, -1);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractObjectValue_ErrorEsfJsonValueTypeGet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    EsfJsonValue jsonval_out;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, child_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeObject);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonInternalError);

    ret = SysAppCmnExtractObjectValue(handle_val, parent_val, jsonkey, &jsonval_out);

    assert_int_equal(ret, 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnExtractObjectValue_OtherTypeEsfJsonValueTypeGet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    EsfJsonValue jsonval_out;
    int ret;

    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, jsonkey);
    will_return(__wrap_EsfJsonObjectGet, child_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, child_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeString);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    ret = SysAppCmnExtractObjectValue(handle_val, parent_val, jsonkey, &jsonval_out);

    assert_int_equal(ret, 0);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCmnGetReqId()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnGetReqId_FullySuccess(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue req_info_val = 2468;
    EsfJsonValue req_id_val = 3579;
    const char *req_id_expect = "No.4680";
    const char *req_id_out = NULL;
    RetCode ret;

    // for SysAppCmnExtractObjectValue()
    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, "req_info");
    will_return(__wrap_EsfJsonObjectGet, req_info_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, req_info_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeObject);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // for SysAppCmnExtractStringValue()
    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, req_info_val);
    expect_string(__wrap_EsfJsonObjectGet, key, "req_id");
    will_return(__wrap_EsfJsonObjectGet, req_id_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, req_id_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeString);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonStringGet, handle, handle_val);
    expect_value(__wrap_EsfJsonStringGet, value, req_id_val);
    will_return(__wrap_EsfJsonStringGet, req_id_expect);
    will_return(__wrap_EsfJsonStringGet, kEsfJsonSuccess);

    ret = SysAppCmnGetReqId(handle_val, parent_val, &req_id_out);

    assert_int_equal(ret, kRetOk);
    assert_ptr_equal(req_id_expect, req_id_out);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnGetReqId_NotFoundReqInfo(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue req_info_val = 2468;
    // EsfJsonValue req_id_val = 3579;
    // const char *req_id_expect = "No.4680";
    const char *req_id_out = NULL;
    RetCode ret;

    // for SysAppCmnExtractObjectValue()
    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, "req_info");
    will_return(__wrap_EsfJsonObjectGet, req_info_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonInternalError);

    ret = SysAppCmnGetReqId(handle_val, parent_val, &req_id_out);

    assert_int_equal(ret, kRetNotFound);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnGetReqId_OtherTypeReqInfo(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue req_info_val = 2468;
    // EsfJsonValue req_id_val = 3579;
    // const char *req_id_expect = "No.4680";
    const char *req_id_out = NULL;
    RetCode ret;

    // for SysAppCmnExtractObjectValue()
    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, "req_info");
    will_return(__wrap_EsfJsonObjectGet, req_info_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, req_info_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeString);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    ret = SysAppCmnGetReqId(handle_val, parent_val, &req_id_out);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnGetReqId_NotFoundReqId(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue req_info_val = 2468;
    EsfJsonValue req_id_val = 3579;
    // const char *req_id_expect = "No.4680";
    const char *req_id_out = NULL;
    RetCode ret;

    // for SysAppCmnExtractObjectValue()
    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, "req_info");
    will_return(__wrap_EsfJsonObjectGet, req_info_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, req_info_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeObject);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // for SysAppCmnExtractStringValue()
    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, req_info_val);
    expect_string(__wrap_EsfJsonObjectGet, key, "req_id");
    will_return(__wrap_EsfJsonObjectGet, req_id_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonInternalError);

    ret = SysAppCmnGetReqId(handle_val, parent_val, &req_id_out);

    assert_int_equal(ret, kRetNotFound);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnGetReqId_OtherTypeReqId(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue req_info_val = 2468;
    EsfJsonValue req_id_val = 3579;
    // const char *req_id_expect = "No.4680";
    const char *req_id_out = NULL;
    RetCode ret;

    // for SysAppCmnExtractObjectValue()
    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectGet, key, "req_info");
    will_return(__wrap_EsfJsonObjectGet, req_info_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, req_info_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeObject);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    // for SysAppCmnExtractStringValue()
    expect_value(__wrap_EsfJsonObjectGet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectGet, parent, req_info_val);
    expect_string(__wrap_EsfJsonObjectGet, key, "req_id");
    will_return(__wrap_EsfJsonObjectGet, req_id_val);
    will_return(__wrap_EsfJsonObjectGet, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonValueTypeGet, handle, handle_val);
    expect_value(__wrap_EsfJsonValueTypeGet, value, req_id_val);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonValueTypeNumber);
    will_return(__wrap_EsfJsonValueTypeGet, kEsfJsonSuccess);

    ret = SysAppCmnGetReqId(handle_val, parent_val, &req_id_out);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCmnSetStringValue()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetStringValue_FullySuccess(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    const char *string = "string_value";
    RetCode ret;

    expect_value(__wrap_EsfJsonStringInit, handle, handle_val);
    expect_string(__wrap_EsfJsonStringInit, str, string);
    will_return(__wrap_EsfJsonStringInit, child_val);
    will_return(__wrap_EsfJsonStringInit, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, jsonkey);
    expect_value(__wrap_EsfJsonObjectSet, value, child_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonSuccess);

    ret = SysAppCmnSetStringValue(handle_val, parent_val, jsonkey, string);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetStringValue_ErrorEsfJsonStringInit(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    const char *string = "string_value";
    RetCode ret;

    expect_value(__wrap_EsfJsonStringInit, handle, handle_val);
    expect_string(__wrap_EsfJsonStringInit, str, string);
    will_return(__wrap_EsfJsonStringInit, child_val);
    will_return(__wrap_EsfJsonStringInit, kEsfJsonInternalError);

    ret = SysAppCmnSetStringValue(handle_val, parent_val, jsonkey, string);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetStringValue_ErrorEsfJsonObjectSet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    const char *string = "string_value";
    RetCode ret;

    expect_value(__wrap_EsfJsonStringInit, handle, handle_val);
    expect_string(__wrap_EsfJsonStringInit, str, string);
    will_return(__wrap_EsfJsonStringInit, child_val);
    will_return(__wrap_EsfJsonStringInit, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, jsonkey);
    expect_value(__wrap_EsfJsonObjectSet, value, child_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonInternalError);

    ret = SysAppCmnSetStringValue(handle_val, parent_val, jsonkey, string);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCmnSetStringValueHandle()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetStringValueHandle_FullySuccess(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfMemoryManagerHandle mem_mgr_handle = (EsfMemoryManagerHandle)0x98765432;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    size_t size = 3579;
    RetCode ret;

    expect_value(__wrap_EsfJsonStringInitHandle, handle, handle_val);
    expect_value(__wrap_EsfJsonStringInitHandle, mem_handle, mem_mgr_handle);
    expect_value(__wrap_EsfJsonStringInitHandle, mem_size, size);
    will_return(__wrap_EsfJsonStringInitHandle, child_val);
    will_return(__wrap_EsfJsonStringInitHandle, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, jsonkey);
    expect_value(__wrap_EsfJsonObjectSet, value, child_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonSuccess);

    ret = SysAppCmnSetStringValueHandle(handle_val, parent_val, jsonkey, mem_mgr_handle, size);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetStringValueHandle_ErrorEsfJsonStringInitFileIO(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfMemoryManagerHandle mem_mgr_handle = (EsfMemoryManagerHandle)0x98765432;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    size_t size = 3579;
    RetCode ret;

    expect_value(__wrap_EsfJsonStringInitHandle, handle, handle_val);
    expect_value(__wrap_EsfJsonStringInitHandle, mem_handle, mem_mgr_handle);
    expect_value(__wrap_EsfJsonStringInitHandle, mem_size, size);
    will_return(__wrap_EsfJsonStringInitHandle, child_val);
    will_return(__wrap_EsfJsonStringInitHandle, kEsfJsonInternalError);

    ret = SysAppCmnSetStringValueHandle(handle_val, parent_val, jsonkey, mem_mgr_handle, size);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetStringValueHandle_ErrorEsfJsonObjectSet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfMemoryManagerHandle mem_mgr_handle = (EsfMemoryManagerHandle)0x98765432;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    size_t size = 3579;
    RetCode ret;

    expect_value(__wrap_EsfJsonStringInitHandle, handle, handle_val);
    expect_value(__wrap_EsfJsonStringInitHandle, mem_handle, mem_mgr_handle);
    expect_value(__wrap_EsfJsonStringInitHandle, mem_size, size);
    will_return(__wrap_EsfJsonStringInitHandle, child_val);
    will_return(__wrap_EsfJsonStringInitHandle, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, jsonkey);
    expect_value(__wrap_EsfJsonObjectSet, value, child_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonInternalError);

    ret = SysAppCmnSetStringValueHandle(handle_val, parent_val, jsonkey, mem_mgr_handle, size);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCmnSetNumberValue()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetNumberValue_FullySuccess(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    int number = 3579;
    RetCode ret;

    expect_value(__wrap_EsfJsonIntegerInit, handle, handle_val);
    expect_value(__wrap_EsfJsonIntegerInit, num, number);
    will_return(__wrap_EsfJsonIntegerInit, child_val);
    will_return(__wrap_EsfJsonIntegerInit, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, jsonkey);
    expect_value(__wrap_EsfJsonObjectSet, value, child_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonSuccess);

    ret = SysAppCmnSetNumberValue(handle_val, parent_val, jsonkey, number);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetNumberValue_ErrorEsfJsonIntegerInit(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    int number = 3579;
    RetCode ret;

    expect_value(__wrap_EsfJsonIntegerInit, handle, handle_val);
    expect_value(__wrap_EsfJsonIntegerInit, num, number);
    will_return(__wrap_EsfJsonIntegerInit, child_val);
    will_return(__wrap_EsfJsonIntegerInit, kEsfJsonInternalError);

    ret = SysAppCmnSetNumberValue(handle_val, parent_val, jsonkey, number);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetNumberValue_ErrorEsfJsonObjectSet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    int number = 3579;
    RetCode ret;

    expect_value(__wrap_EsfJsonIntegerInit, handle, handle_val);
    expect_value(__wrap_EsfJsonIntegerInit, num, number);
    will_return(__wrap_EsfJsonIntegerInit, child_val);
    will_return(__wrap_EsfJsonIntegerInit, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, jsonkey);
    expect_value(__wrap_EsfJsonObjectSet, value, child_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonInternalError);

    ret = SysAppCmnSetNumberValue(handle_val, parent_val, jsonkey, number);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCmnSetRealNumberValue()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetRealNumberValue_FullySuccess(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    double number = 3579.2468;
    RetCode ret;

    expect_value(__wrap_EsfJsonRealInit, handle, handle_val);

    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    //   cmocka API expect_XXX() to set expect number value only supports integer.
    //   That is, not support floating decimal point.
    //   Therefore set expect value with SetEsfJsonRealInitExpectValue().
    //   So then, mock will check parameter SetEsfJsonRealInitExpectValue() value.
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    //expect_value(__wrap_EsfJsonRealInit, num, number);
    SetEsfJsonRealInitExpectValue(number);

    will_return(__wrap_EsfJsonRealInit, child_val);
    will_return(__wrap_EsfJsonRealInit, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, jsonkey);
    expect_value(__wrap_EsfJsonObjectSet, value, child_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonSuccess);

    ret = SysAppCmnSetRealNumberValue(handle_val, parent_val, jsonkey, number);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetRealNumberValue_ErrorEsfJsonRealInit(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    double number = 3579.2468;
    RetCode ret;

    expect_value(__wrap_EsfJsonRealInit, handle, handle_val);

    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    //   cmocka API expect_XXX() to set expect number value only supports integer.
    //   That is, not support floating decimal point.
    //   Therefore set expect value with SetEsfJsonRealInitExpectValue().
    //   So then, mock will check parameter SetEsfJsonRealInitExpectValue() value.
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    //expect_value(__wrap_EsfJsonRealInit, num, number);
    SetEsfJsonRealInitExpectValue(number);

    will_return(__wrap_EsfJsonRealInit, child_val);
    will_return(__wrap_EsfJsonRealInit, kEsfJsonInternalError);

    ret = SysAppCmnSetRealNumberValue(handle_val, parent_val, jsonkey, number);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetRealNumberValue_ErrorEsfJsonObjectSet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    double number = 3579.2468;
    RetCode ret;

    expect_value(__wrap_EsfJsonRealInit, handle, handle_val);

    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    //   cmocka API expect_XXX() to set expect number value only supports integer.
    //   That is, not support floating decimal point.
    //   Therefore set expect value with SetEsfJsonRealInitExpectValue().
    //   So then, mock will check parameter SetEsfJsonRealInitExpectValue() value.
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    //expect_value(__wrap_EsfJsonRealInit, num, number);
    SetEsfJsonRealInitExpectValue(number);

    will_return(__wrap_EsfJsonRealInit, child_val);
    will_return(__wrap_EsfJsonRealInit, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, jsonkey);
    expect_value(__wrap_EsfJsonObjectSet, value, child_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonInternalError);

    ret = SysAppCmnSetRealNumberValue(handle_val, parent_val, jsonkey, number);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCmnSetBooleanValue()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetBooleanValue_FullySuccess(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    bool bool_val = true;
    RetCode ret;

    expect_value(__wrap_EsfJsonBooleanInit, handle, handle_val);
    expect_value(__wrap_EsfJsonBooleanInit, boolean, bool_val);
    will_return(__wrap_EsfJsonBooleanInit, child_val);
    will_return(__wrap_EsfJsonBooleanInit, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, jsonkey);
    expect_value(__wrap_EsfJsonObjectSet, value, child_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonSuccess);

    ret = SysAppCmnSetBooleanValue(handle_val, parent_val, jsonkey, bool_val);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetBooleanValue_ErrorEsfJsonBooleanInit(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    bool bool_val = true;
    RetCode ret;

    expect_value(__wrap_EsfJsonBooleanInit, handle, handle_val);
    expect_value(__wrap_EsfJsonBooleanInit, boolean, bool_val);
    will_return(__wrap_EsfJsonBooleanInit, child_val);
    will_return(__wrap_EsfJsonBooleanInit, kEsfJsonInternalError);

    ret = SysAppCmnSetBooleanValue(handle_val, parent_val, jsonkey, bool_val);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetBooleanValue_ErrorEsfJsonObjectSet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    bool bool_val = true;
    RetCode ret;

    expect_value(__wrap_EsfJsonBooleanInit, handle, handle_val);
    expect_value(__wrap_EsfJsonBooleanInit, boolean, bool_val);
    will_return(__wrap_EsfJsonBooleanInit, child_val);
    will_return(__wrap_EsfJsonBooleanInit, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, jsonkey);
    expect_value(__wrap_EsfJsonObjectSet, value, child_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonInternalError);

    ret = SysAppCmnSetBooleanValue(handle_val, parent_val, jsonkey, bool_val);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCmnSetObjectValue()
//

/*----------------------------------------------------------------------------*/
static RetCode test_SysAppCmnSetObjectValueCallback(EsfJsonHandle handle, EsfJsonValue value,
                                                    void *user_data)
{
    check_expected(handle);
    check_expected(value);
    check_expected_ptr(user_data);

    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetObjectValue_FullySuccess(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    int user_data = 0x98765432;

    RetCode ret;

    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(test_SysAppCmnSetObjectValueCallback, handle, handle_val);
    expect_value(test_SysAppCmnSetObjectValueCallback, value, child_val);
    expect_value(test_SysAppCmnSetObjectValueCallback, user_data, &user_data);
    will_return(test_SysAppCmnSetObjectValueCallback, kRetOk);

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, jsonkey);
    expect_value(__wrap_EsfJsonObjectSet, value, child_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonSuccess);

    ret = SysAppCmnSetObjectValue(handle_val, parent_val, jsonkey,
                                  test_SysAppCmnSetObjectValueCallback, (void *)&user_data);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetObjectValue_ErrorEsfJsonObjectInit(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    int user_data = 0x98765432;

    RetCode ret;

    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonInternalError);

    ret = SysAppCmnSetObjectValue(handle_val, parent_val, jsonkey,
                                  test_SysAppCmnSetObjectValueCallback, (void *)&user_data);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetObjectValue_ErrorEsfJsonObjectSet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue child_val = 2468;
    const char *jsonkey = "proterty_name";
    int user_data = 0x98765432;

    RetCode ret;

    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, child_val);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(test_SysAppCmnSetObjectValueCallback, handle, handle_val);
    expect_value(test_SysAppCmnSetObjectValueCallback, value, child_val);
    expect_value(test_SysAppCmnSetObjectValueCallback, user_data, &user_data);
    will_return(test_SysAppCmnSetObjectValueCallback, kRetOk);

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, jsonkey);
    expect_value(__wrap_EsfJsonObjectSet, value, child_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonInternalError);

    ret = SysAppCmnSetObjectValue(handle_val, parent_val, jsonkey,
                                  test_SysAppCmnSetObjectValueCallback, (void *)&user_data);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCmnSetArrayValue()
//

/*----------------------------------------------------------------------------*/
static RetCode test_SysAppCmnSetArrayValueCallback(EsfJsonHandle handle, EsfJsonValue value,
                                                   uint32_t idx, void *user_data)
{
    check_expected(handle);
    check_expected(value);
    check_expected(idx);
    check_expected_ptr(user_data);

    return mock_type(RetCode);
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetArrayValue_FullySuccess(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue array_val = 2468;
    EsfJsonValue object_val_1 = 3579;
    EsfJsonValue object_val_2 = 4680;
    const char *jsonkey = "proterty_name";
    int user_data = 0x98765432;
    RetCode ret;

    expect_value(__wrap_EsfJsonArrayInit, handle, handle_val);
    will_return(__wrap_EsfJsonArrayInit, array_val);
    will_return(__wrap_EsfJsonArrayInit, kEsfJsonSuccess);

    // loop 1st
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, object_val_1);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(test_SysAppCmnSetArrayValueCallback, handle, handle_val);
    expect_value(test_SysAppCmnSetArrayValueCallback, value, object_val_1);
    expect_value(test_SysAppCmnSetArrayValueCallback, idx, 0);
    expect_value(test_SysAppCmnSetArrayValueCallback, user_data, &user_data);
    will_return(test_SysAppCmnSetArrayValueCallback, kRetOk);

    expect_value(__wrap_EsfJsonArrayAppend, handle, handle_val);
    expect_value(__wrap_EsfJsonArrayAppend, parent, array_val);
    expect_value(__wrap_EsfJsonArrayAppend, value, object_val_1);
    will_return(__wrap_EsfJsonArrayAppend, kEsfJsonSuccess);
    // ========

    // loop 2nd
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, object_val_2);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(test_SysAppCmnSetArrayValueCallback, handle, handle_val);
    expect_value(test_SysAppCmnSetArrayValueCallback, value, object_val_2);
    expect_value(test_SysAppCmnSetArrayValueCallback, idx, 1);
    expect_value(test_SysAppCmnSetArrayValueCallback, user_data, &user_data);
    will_return(test_SysAppCmnSetArrayValueCallback, kRetOk);

    expect_value(__wrap_EsfJsonArrayAppend, handle, handle_val);
    expect_value(__wrap_EsfJsonArrayAppend, parent, array_val);
    expect_value(__wrap_EsfJsonArrayAppend, value, object_val_2);
    will_return(__wrap_EsfJsonArrayAppend, kEsfJsonSuccess);
    // ========

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, jsonkey);
    expect_value(__wrap_EsfJsonObjectSet, value, array_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonSuccess);

    ret = SysAppCmnSetArrayValue(handle_val, parent_val, jsonkey, 2,
                                 test_SysAppCmnSetArrayValueCallback, &user_data);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetArrayValue_ErrorEsfJsonArrayInit(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue array_val = 2468;
    // EsfJsonValue object_val_1 = 3579;
    // EsfJsonValue object_val_2 = 4680;
    const char *jsonkey = "proterty_name";
    int user_data = 0x98765432;
    RetCode ret;

    expect_value(__wrap_EsfJsonArrayInit, handle, handle_val);
    will_return(__wrap_EsfJsonArrayInit, array_val);
    will_return(__wrap_EsfJsonArrayInit, kEsfJsonInternalError);

    ret = SysAppCmnSetArrayValue(handle_val, parent_val, jsonkey, 2,
                                 test_SysAppCmnSetArrayValueCallback, &user_data);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetArrayValue_ErrorEsfJsonObjectInit(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue array_val = 2468;
    EsfJsonValue object_val_1 = 3579;
    // EsfJsonValue object_val_2 = 4680;
    const char *jsonkey = "proterty_name";
    int user_data = 0x98765432;
    RetCode ret;

    expect_value(__wrap_EsfJsonArrayInit, handle, handle_val);
    will_return(__wrap_EsfJsonArrayInit, array_val);
    will_return(__wrap_EsfJsonArrayInit, kEsfJsonSuccess);

    // loop 1st
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, object_val_1);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonInternalError);
    // ========

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, jsonkey);
    expect_value(__wrap_EsfJsonObjectSet, value, array_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonSuccess);

    ret = SysAppCmnSetArrayValue(handle_val, parent_val, jsonkey, 2,
                                 test_SysAppCmnSetArrayValueCallback, &user_data);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetArrayValue_MakeJsonCbNotFound(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue array_val = 2468;
    EsfJsonValue object_val_1 = 3579;
    EsfJsonValue object_val_2 = 4680;
    const char *jsonkey = "proterty_name";
    int user_data = 0x98765432;
    RetCode ret;

    expect_value(__wrap_EsfJsonArrayInit, handle, handle_val);
    will_return(__wrap_EsfJsonArrayInit, array_val);
    will_return(__wrap_EsfJsonArrayInit, kEsfJsonSuccess);

    // loop 1st
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, object_val_1);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(test_SysAppCmnSetArrayValueCallback, handle, handle_val);
    expect_value(test_SysAppCmnSetArrayValueCallback, value, object_val_1);
    expect_value(test_SysAppCmnSetArrayValueCallback, idx, 0);
    expect_value(test_SysAppCmnSetArrayValueCallback, user_data, &user_data);
    will_return(test_SysAppCmnSetArrayValueCallback, kRetNotFound);

    // expect_value(__wrap_EsfJsonArrayAppend, handle, handle_val);
    // expect_value(__wrap_EsfJsonArrayAppend, parent, array_val);
    // expect_value(__wrap_EsfJsonArrayAppend, value, object_val_2);
    // will_return(__wrap_EsfJsonArrayAppend, kEsfJsonSuccess);
    // ========

    // loop 2nd
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, object_val_2);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(test_SysAppCmnSetArrayValueCallback, handle, handle_val);
    expect_value(test_SysAppCmnSetArrayValueCallback, value, object_val_2);
    expect_value(test_SysAppCmnSetArrayValueCallback, idx, 1);
    expect_value(test_SysAppCmnSetArrayValueCallback, user_data, &user_data);
    will_return(test_SysAppCmnSetArrayValueCallback, kRetOk);

    expect_value(__wrap_EsfJsonArrayAppend, handle, handle_val);
    expect_value(__wrap_EsfJsonArrayAppend, parent, array_val);
    expect_value(__wrap_EsfJsonArrayAppend, value, object_val_2);
    will_return(__wrap_EsfJsonArrayAppend, kEsfJsonSuccess);
    // ========

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, jsonkey);
    expect_value(__wrap_EsfJsonObjectSet, value, array_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonSuccess);

    ret = SysAppCmnSetArrayValue(handle_val, parent_val, jsonkey, 2,
                                 test_SysAppCmnSetArrayValueCallback, &user_data);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetArrayValue_ErrorEsfJsonArrayAppend(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue array_val = 2468;
    EsfJsonValue object_val_1 = 3579;
    // EsfJsonValue object_val_2 = 4680;
    const char *jsonkey = "proterty_name";
    int user_data = 0x98765432;
    RetCode ret;

    expect_value(__wrap_EsfJsonArrayInit, handle, handle_val);
    will_return(__wrap_EsfJsonArrayInit, array_val);
    will_return(__wrap_EsfJsonArrayInit, kEsfJsonSuccess);

    // loop 1st
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, object_val_1);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(test_SysAppCmnSetArrayValueCallback, handle, handle_val);
    expect_value(test_SysAppCmnSetArrayValueCallback, value, object_val_1);
    expect_value(test_SysAppCmnSetArrayValueCallback, idx, 0);
    expect_value(test_SysAppCmnSetArrayValueCallback, user_data, &user_data);
    will_return(test_SysAppCmnSetArrayValueCallback, kRetOk);

    expect_value(__wrap_EsfJsonArrayAppend, handle, handle_val);
    expect_value(__wrap_EsfJsonArrayAppend, parent, array_val);
    expect_value(__wrap_EsfJsonArrayAppend, value, object_val_1);
    will_return(__wrap_EsfJsonArrayAppend, kEsfJsonInternalError);
    // ========

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, jsonkey);
    expect_value(__wrap_EsfJsonObjectSet, value, array_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonSuccess);

    ret = SysAppCmnSetArrayValue(handle_val, parent_val, jsonkey, 2,
                                 test_SysAppCmnSetArrayValueCallback, &user_data);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnSetArrayValue_ErrorEsfJsonObjectSet(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue array_val = 2468;
    EsfJsonValue object_val_1 = 3579;
    EsfJsonValue object_val_2 = 4680;
    const char *jsonkey = "proterty_name";
    int user_data = 0x98765432;
    RetCode ret;

    expect_value(__wrap_EsfJsonArrayInit, handle, handle_val);
    will_return(__wrap_EsfJsonArrayInit, array_val);
    will_return(__wrap_EsfJsonArrayInit, kEsfJsonSuccess);

    // loop 1st
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, object_val_1);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(test_SysAppCmnSetArrayValueCallback, handle, handle_val);
    expect_value(test_SysAppCmnSetArrayValueCallback, value, object_val_1);
    expect_value(test_SysAppCmnSetArrayValueCallback, idx, 0);
    expect_value(test_SysAppCmnSetArrayValueCallback, user_data, &user_data);
    will_return(test_SysAppCmnSetArrayValueCallback, kRetOk);

    expect_value(__wrap_EsfJsonArrayAppend, handle, handle_val);
    expect_value(__wrap_EsfJsonArrayAppend, parent, array_val);
    expect_value(__wrap_EsfJsonArrayAppend, value, object_val_1);
    will_return(__wrap_EsfJsonArrayAppend, kEsfJsonSuccess);
    // ========

    // loop 2nd
    expect_value(__wrap_EsfJsonObjectInit, handle, handle_val);
    will_return(__wrap_EsfJsonObjectInit, object_val_2);
    will_return(__wrap_EsfJsonObjectInit, kEsfJsonSuccess);

    expect_value(test_SysAppCmnSetArrayValueCallback, handle, handle_val);
    expect_value(test_SysAppCmnSetArrayValueCallback, value, object_val_2);
    expect_value(test_SysAppCmnSetArrayValueCallback, idx, 1);
    expect_value(test_SysAppCmnSetArrayValueCallback, user_data, &user_data);
    will_return(test_SysAppCmnSetArrayValueCallback, kRetOk);

    expect_value(__wrap_EsfJsonArrayAppend, handle, handle_val);
    expect_value(__wrap_EsfJsonArrayAppend, parent, array_val);
    expect_value(__wrap_EsfJsonArrayAppend, value, object_val_2);
    will_return(__wrap_EsfJsonArrayAppend, kEsfJsonSuccess);
    // ========

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, jsonkey);
    expect_value(__wrap_EsfJsonObjectSet, value, array_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonInternalError);

    ret = SysAppCmnSetArrayValue(handle_val, parent_val, jsonkey, 2,
                                 test_SysAppCmnSetArrayValueCallback, &user_data);

    assert_int_equal(ret, kRetFailed);

    return;
}

/*----------------------------------------------------------------------------*/

//
// SysAppCmnMakeJsonResInfo()
//

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnMakeJsonResInfo_FullySuccessResIdNotNull(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    EsfJsonValue res_id_val = 2468;
    EsfJsonValue code_val = 3579;
    EsfJsonValue detail_msg_val = 4680;
    const char *res_id = "No.4680";
    int code = 3;
    const char *detail_msg = "invalid_argument";
    RetCode ret;

    // SysAppCmnSetStringValue() for res_id
    expect_value(__wrap_EsfJsonStringInit, handle, handle_val);
    expect_string(__wrap_EsfJsonStringInit, str, res_id);
    will_return(__wrap_EsfJsonStringInit, res_id_val);
    will_return(__wrap_EsfJsonStringInit, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, "res_id");
    expect_value(__wrap_EsfJsonObjectSet, value, res_id_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonSuccess);

    // SysAppCmnSetNumberValue() for code
    expect_value(__wrap_EsfJsonIntegerInit, handle, handle_val);
    expect_value(__wrap_EsfJsonIntegerInit, num, code);
    will_return(__wrap_EsfJsonIntegerInit, code_val);
    will_return(__wrap_EsfJsonIntegerInit, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, "code");
    expect_value(__wrap_EsfJsonObjectSet, value, code_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonSuccess);

    // SysAppCmnSetStringValue() for detail_msg
    expect_value(__wrap_EsfJsonStringInit, handle, handle_val);
    expect_string(__wrap_EsfJsonStringInit, str, detail_msg);
    will_return(__wrap_EsfJsonStringInit, detail_msg_val);
    will_return(__wrap_EsfJsonStringInit, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, "detail_msg");
    expect_value(__wrap_EsfJsonObjectSet, value, detail_msg_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonSuccess);

    ret = SysAppCmnMakeJsonResInfo(handle_val, parent_val, res_id, code, detail_msg);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppCmnMakeJsonResInfo_FullySuccessResIdNull(void **state)
{
    EsfJsonHandle handle_val = (EsfJsonHandle)0x12345678;
    EsfJsonValue parent_val = 1357;
    // EsfJsonValue res_id_val = 2468;
    EsfJsonValue code_val = 3579;
    EsfJsonValue detail_msg_val = 4680;
    // const char* res_id = "No.4680";
    int code = 3;
    const char *detail_msg = "invalid_argument";
    RetCode ret;

    // SysAppCmnSetStringValue() for res_id
    // Not process

    // SysAppCmnSetNumberValue() for code
    expect_value(__wrap_EsfJsonIntegerInit, handle, handle_val);
    expect_value(__wrap_EsfJsonIntegerInit, num, code);
    will_return(__wrap_EsfJsonIntegerInit, code_val);
    will_return(__wrap_EsfJsonIntegerInit, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, "code");
    expect_value(__wrap_EsfJsonObjectSet, value, code_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonSuccess);

    // SysAppCmnSetStringValue() for detail_msg
    expect_value(__wrap_EsfJsonStringInit, handle, handle_val);
    expect_string(__wrap_EsfJsonStringInit, str, detail_msg);
    will_return(__wrap_EsfJsonStringInit, detail_msg_val);
    will_return(__wrap_EsfJsonStringInit, kEsfJsonSuccess);

    expect_value(__wrap_EsfJsonObjectSet, handle, handle_val);
    expect_value(__wrap_EsfJsonObjectSet, parent, parent_val);
    expect_string(__wrap_EsfJsonObjectSet, key, "detail_msg");
    expect_value(__wrap_EsfJsonObjectSet, value, detail_msg_val);
    will_return(__wrap_EsfJsonObjectSet, kEsfJsonSuccess);

    ret = SysAppCmnMakeJsonResInfo(handle_val, parent_val, NULL, code, detail_msg);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/

//
// main()
//

/*----------------------------------------------------------------------------*/
int main(void)
{
    const struct CMUnitTest tests[] = {
        // SysAppCmnExtractStringValue()
        cmocka_unit_test(test_SysAppCmnExtractStringValue_FullySuccess),
        cmocka_unit_test(test_SysAppCmnExtractStringValue_ErrorEsfJsonObjectGet),
        cmocka_unit_test(test_SysAppCmnExtractStringValue_ErrorEsfJsonValueTypeGet),
        cmocka_unit_test(test_SysAppCmnExtractStringValue_OtherTypeEsfJsonValueTypeGet),
        cmocka_unit_test(test_SysAppCmnExtractStringValue_ErrorEsfJsonStringGet),

        // SysAppCmnExtractNumberValue()
        cmocka_unit_test(test_SysAppCmnExtractNumberValue_FullySuccess),
        cmocka_unit_test(test_SysAppCmnExtractNumberValue_ErrorEsfJsonObjectGet),
        cmocka_unit_test(test_SysAppCmnExtractNumberValue_ErrorEsfJsonValueTypeGet),
        cmocka_unit_test(test_SysAppCmnExtractNumberValue_OtherTypeEsfJsonValueTypeGet),
        cmocka_unit_test(test_SysAppCmnExtractNumberValue_ErrorEsfJsonIntegerGet),

        // SysAppCmnExtractRealNumberValue()
        cmocka_unit_test(test_SysAppCmnExtractRealNumberValue_FullySuccess),
        cmocka_unit_test(test_SysAppCmnExtractRealNumberValue_ErrorEsfJsonObjectGet),
        cmocka_unit_test(test_SysAppCmnExtractRealNumberValue_ErrorEsfJsonValueTypeGet),
        cmocka_unit_test(test_SysAppCmnExtractRealNumberValue_OtherTypeEsfJsonValueTypeGet),
        cmocka_unit_test(test_SysAppCmnExtractRealNumberValue_ErrorEsfJsonRealGet),

        // SysAppCmnExtractBooleanValue()
        cmocka_unit_test(test_SysAppCmnExtractBooleanValue_FullySuccess),
        cmocka_unit_test(test_SysAppCmnExtractBooleanValue_ErrorEsfJsonObjectGet),
        cmocka_unit_test(test_SysAppCmnExtractBooleanValue_ErrorEsfJsonValueTypeGet),
        cmocka_unit_test(test_SysAppCmnExtractBooleanValue_OtherTypeEsfJsonValueTypeGet),
        cmocka_unit_test(test_SysAppCmnExtractBooleanValue_ErrorEsfJsonBooleanGet),

        // SysAppCmnExtractObjectValue()
        cmocka_unit_test(test_SysAppCmnExtractObjectValue_FullySuccess),
        cmocka_unit_test(test_SysAppCmnExtractObjectValue_ErrorEsfJsonObjectGet),
        cmocka_unit_test(test_SysAppCmnExtractObjectValue_ErrorEsfJsonValueTypeGet),
        cmocka_unit_test(test_SysAppCmnExtractObjectValue_OtherTypeEsfJsonValueTypeGet),

        // SysAppCmnGetReqId()
        cmocka_unit_test(test_SysAppCmnGetReqId_FullySuccess),
        cmocka_unit_test(test_SysAppCmnGetReqId_NotFoundReqInfo),
        cmocka_unit_test(test_SysAppCmnGetReqId_OtherTypeReqInfo),
        cmocka_unit_test(test_SysAppCmnGetReqId_NotFoundReqId),
        cmocka_unit_test(test_SysAppCmnGetReqId_OtherTypeReqId),

        // SysAppCmnSetStringValue()
        cmocka_unit_test(test_SysAppCmnSetStringValue_FullySuccess),
        cmocka_unit_test(test_SysAppCmnSetStringValue_ErrorEsfJsonStringInit),
        cmocka_unit_test(test_SysAppCmnSetStringValue_ErrorEsfJsonObjectSet),

        // SysAppCmnSetStringValueHandle()
        cmocka_unit_test(test_SysAppCmnSetStringValueHandle_FullySuccess),
        cmocka_unit_test(test_SysAppCmnSetStringValueHandle_ErrorEsfJsonStringInitFileIO),
        cmocka_unit_test(test_SysAppCmnSetStringValueHandle_ErrorEsfJsonObjectSet),

        // SysAppCmnSetNumberValue()
        cmocka_unit_test(test_SysAppCmnSetNumberValue_FullySuccess),
        cmocka_unit_test(test_SysAppCmnSetNumberValue_ErrorEsfJsonIntegerInit),
        cmocka_unit_test(test_SysAppCmnSetNumberValue_ErrorEsfJsonObjectSet),

        // SysAppCmnSetRealNumberValue()
        cmocka_unit_test(test_SysAppCmnSetRealNumberValue_FullySuccess),
        cmocka_unit_test(test_SysAppCmnSetRealNumberValue_ErrorEsfJsonRealInit),
        cmocka_unit_test(test_SysAppCmnSetRealNumberValue_ErrorEsfJsonObjectSet),

        // SysAppCmnSetBooleanValue()
        cmocka_unit_test(test_SysAppCmnSetBooleanValue_FullySuccess),
        cmocka_unit_test(test_SysAppCmnSetBooleanValue_ErrorEsfJsonBooleanInit),
        cmocka_unit_test(test_SysAppCmnSetBooleanValue_ErrorEsfJsonObjectSet),

        // SysAppCmnSetObjectValue()
        cmocka_unit_test(test_SysAppCmnSetObjectValue_FullySuccess),
        cmocka_unit_test(test_SysAppCmnSetObjectValue_ErrorEsfJsonObjectInit),
        cmocka_unit_test(test_SysAppCmnSetObjectValue_ErrorEsfJsonObjectSet),

        // SysAppCmnSetArrayValue()
        cmocka_unit_test(test_SysAppCmnSetArrayValue_FullySuccess),
        cmocka_unit_test(test_SysAppCmnSetArrayValue_ErrorEsfJsonArrayInit),
        cmocka_unit_test(test_SysAppCmnSetArrayValue_ErrorEsfJsonObjectInit),
        cmocka_unit_test(test_SysAppCmnSetArrayValue_MakeJsonCbNotFound),
        cmocka_unit_test(test_SysAppCmnSetArrayValue_ErrorEsfJsonArrayAppend),
        cmocka_unit_test(test_SysAppCmnSetArrayValue_ErrorEsfJsonObjectSet),

        // SysAppCmnMakeJsonResInfo()
        cmocka_unit_test(test_SysAppCmnMakeJsonResInfo_FullySuccessResIdNotNull),
        cmocka_unit_test(test_SysAppCmnMakeJsonResInfo_FullySuccessResIdNull),
    };

    return (((cmocka_run_group_tests(tests, NULL, NULL)) == 0) ? 0 : 1);
}
