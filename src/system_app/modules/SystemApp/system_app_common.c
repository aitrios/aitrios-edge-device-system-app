/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <stdio.h>
#include "memory_manager.h"
#include "json/include/json.h"
#include "json/include/json_handle.h"
#include "system_app_common.h"
#include "system_app_log.h"
#include "system_app_util.h"

//
// Macros.
//

//
// File private structure.
//

//
// File private structure.
//

//
// File static variables.
//

//
// File static private functions.
//

//
// Public functions.
//

/*----------------------------------------------------------------------*/
int SysAppCmnExtractStringValue(EsfJsonHandle handle, EsfJsonValue parent_val, const char *jsonkey,
                                const char **string)
{
    // -1 : A value which matches to jsokey is not found.
    // 0  : A value which matches to jsokey is found but it is not valid.
    // 1  : A value which matches to jsokey is found.

    int ret = -1;
    EsfJsonValue cval;

    EsfJsonErrorCode esfj_ret = EsfJsonObjectGet(handle, parent_val, jsonkey, &cval);

    if (esfj_ret == kEsfJsonSuccess) {
        EsfJsonValueType val_type;

        esfj_ret = EsfJsonValueTypeGet(handle, cval, &val_type);
        ret = 0;

        if ((val_type == kEsfJsonValueTypeString) && (esfj_ret == kEsfJsonSuccess)) {
            esfj_ret = EsfJsonStringGet(handle, cval, string);

            if (esfj_ret == kEsfJsonSuccess) {
                ret = 1;
            }
        }
    }

    return ret;
}

/*----------------------------------------------------------------------*/
int SysAppCmnExtractNumberValue(EsfJsonHandle handle, EsfJsonValue parent_val, const char *jsonkey,
                                int *number)
{
    // -1 : A value which matches to jsokey is not found.
    // 0  : A value which matches to jsokey is found but it is not valid.
    // 1  : A value which matches to jsokey is found.

    int ret = -1;
    EsfJsonValue cval;

    EsfJsonErrorCode esfj_ret = EsfJsonObjectGet(handle, parent_val, jsonkey, &cval);

    if (esfj_ret == kEsfJsonSuccess) {
        EsfJsonValueType val_type;

        esfj_ret = EsfJsonValueTypeGet(handle, cval, &val_type);
        ret = 0;

        if ((val_type == kEsfJsonValueTypeNumber) && (esfj_ret == kEsfJsonSuccess)) {
            esfj_ret = EsfJsonIntegerGet(handle, cval, number);

            if (esfj_ret == kEsfJsonSuccess) {
                ret = 1;
            }
        }
    }

    return ret;
}

/*----------------------------------------------------------------------*/
int SysAppCmnExtractRealNumberValue(EsfJsonHandle handle, EsfJsonValue parent_val,
                                    const char *jsonkey, double *number)
{
    // -1 : A value which matches to jsokey is not found.
    // 0  : A value which matches to jsokey is found but it is not valid.
    // 1  : A value which matches to jsokey is found.

    int ret = -1;
    EsfJsonValue cval;

    EsfJsonErrorCode esfj_ret = EsfJsonObjectGet(handle, parent_val, jsonkey, &cval);

    if (esfj_ret == kEsfJsonSuccess) {
        EsfJsonValueType val_type;

        esfj_ret = EsfJsonValueTypeGet(handle, cval, &val_type);
        ret = 0;

        if ((val_type == kEsfJsonValueTypeNumber) && (esfj_ret == kEsfJsonSuccess)) {
            esfj_ret = EsfJsonRealGet(handle, cval, number);

            if (esfj_ret == kEsfJsonSuccess) {
                ret = 1;
            }
        }
    }

    return ret;
}

/*----------------------------------------------------------------------*/
int SysAppCmnExtractBooleanValue(EsfJsonHandle handle, EsfJsonValue parent_val, const char *jsonkey,
                                 bool *boolean)
{
    // -1 : A value which matches to jsokey is not found.
    // 0  : A value which matches to jsokey is found but it is not valid.
    // 1  : A value which matches to jsokey is found.

    int ret = -1;
    EsfJsonValue cval;

    EsfJsonErrorCode esfj_ret = EsfJsonObjectGet(handle, parent_val, jsonkey, &cval);

    if (esfj_ret == kEsfJsonSuccess) {
        EsfJsonValueType val_type;

        esfj_ret = EsfJsonValueTypeGet(handle, cval, &val_type);
        ret = 0;

        if ((val_type == kEsfJsonValueTypeBoolean) && (esfj_ret == kEsfJsonSuccess)) {
            esfj_ret = EsfJsonBooleanGet(handle, cval, boolean);

            if (esfj_ret == kEsfJsonSuccess) {
                ret = 1;
            }
        }
    }

    return ret;
}

/*----------------------------------------------------------------------*/
int SysAppCmnExtractObjectValue(EsfJsonHandle handle, EsfJsonValue parent_val, const char *jsonkey,
                                EsfJsonValue *object)
{
    // -1 : A value which matches to jsokey is not found.
    // 0  : A value which matches to jsokey is found but it is not valid.
    // 1  : A value which matches to jsokey is found.

    int ret = -1;
    EsfJsonValue cval;

    EsfJsonErrorCode esfj_ret = EsfJsonObjectGet(handle, parent_val, jsonkey, &cval);

    if (esfj_ret == kEsfJsonSuccess) {
        EsfJsonValueType val_type;

        esfj_ret = EsfJsonValueTypeGet(handle, cval, &val_type);
        ret = 0;

        if ((val_type == kEsfJsonValueTypeObject) && (esfj_ret == kEsfJsonSuccess)) {
            *object = cval;
            ret = 1;
        }
    }

    return ret;
}

/*----------------------------------------------------------------------*/
RetCode SysAppCmnGetReqId(EsfJsonHandle handle, EsfJsonValue parent_val, const char **req_id)
{
    RetCode ret = kRetNotFound;
    EsfJsonValue req_info_val;

    int extret = SysAppCmnExtractObjectValue(handle, parent_val, "req_info", &req_info_val);

    if (extret >= 0) {
        if (extret >= 1) {
            extret = SysAppCmnExtractStringValue(handle, req_info_val, "req_id", req_id);

            if (extret >= 0) {
                if (extret >= 1) {
                    ret = kRetOk;
                }
                else {
                    SYSAPP_WARN("Invalid req_id");
                    ret = kRetFailed;
                }
            }
        }
        else {
            SYSAPP_WARN("Invalid req_info");
            ret = kRetFailed;
        }
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppCmnMakeJsonResInfo(EsfJsonHandle handle, EsfJsonValue root, const char *res_id,
                                 int code, const char *detail_msg)
{
    RetCode ret = kRetOk;

    // Set res_id.

    if (res_id) {
        SysAppCmnSetStringValue(handle, root, "res_id", res_id);
    }

    // Set code.

    SysAppCmnSetNumberValue(handle, root, "code", code);

    // Set detail_msg.

    SysAppCmnSetStringValue(handle, root, "detail_msg", detail_msg);

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppCmnSetStringValue(EsfJsonHandle handle, EsfJsonValue parent, const char *key,
                                const char *string)
{
    RetCode ret = kRetOk;
    EsfJsonErrorCode esfj_ret = kEsfJsonSuccess;
    EsfJsonValue cval = ESF_JSON_VALUE_INVALID;

    // Create StringValue from "string" argument,
    // and set StringValue to parent Object with "key".

    esfj_ret = EsfJsonStringInit(handle, string, &cval);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonStringInit(%p, %s, %p) ret %d", handle, string, &cval, esfj_ret);
        return kRetFailed;
    }

    esfj_ret = EsfJsonObjectSet(handle, parent, key, cval);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectSet(%p, %d, %s, %d) ret %d", handle, parent, key, cval, esfj_ret);
        ret = kRetFailed;
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppCmnSetStringValueHandle(EsfJsonHandle handle, EsfJsonValue parent, const char *key,
                                      EsfMemoryManagerHandle mm_handle, size_t size)
{
    RetCode ret = kRetOk;
    EsfJsonErrorCode esfj_ret = kEsfJsonSuccess;
    EsfJsonValue cval = ESF_JSON_VALUE_INVALID;

    // Create StringValue from "mm_handle" argument,
    // and set StringValue to parent Object with "key".

    esfj_ret = EsfJsonStringInitHandle(handle, mm_handle, size, &cval);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonStringInit(%p, %d, %p) ret %d", handle, mm_handle, &cval, esfj_ret);
        return kRetFailed;
    }

    esfj_ret = EsfJsonObjectSet(handle, parent, key, cval);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectSet(%p, %d, %s, %d) ret %d", handle, parent, key, cval, esfj_ret);
        ret = kRetFailed;
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppCmnSetNumberValue(EsfJsonHandle handle, EsfJsonValue parent, const char *key,
                                int number)
{
    RetCode ret = kRetOk;
    EsfJsonErrorCode esfj_ret = kEsfJsonSuccess;
    EsfJsonValue cval = ESF_JSON_VALUE_INVALID;

    // Create NumberValue from "number" argument,
    // and set NumberValue to parent Object with "key".

    esfj_ret = EsfJsonIntegerInit(handle, number, &cval);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonIntegerInit(%p, %d, %p) ret %d", handle, number, &cval, esfj_ret);
        return kRetFailed;
    }

    esfj_ret = EsfJsonObjectSet(handle, parent, key, cval);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectSet(%p, %d, %s, %d) ret %d", handle, parent, key, cval, esfj_ret);
        ret = kRetFailed;
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppCmnSetRealNumberValue(EsfJsonHandle handle, EsfJsonValue parent, const char *key,
                                    double number)
{
    RetCode ret = kRetOk;
    EsfJsonErrorCode esfj_ret = kEsfJsonSuccess;
    EsfJsonValue cval = ESF_JSON_VALUE_INVALID;

    // Create RealNumberValue from "number" argument,
    // and set RealNumberValue to parent Object with "key".

    esfj_ret = EsfJsonRealInit(handle, number, &cval);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonRealInit(%p, %f, %p) ret %d", handle, number, &cval, esfj_ret);
        return kRetFailed;
    }

    esfj_ret = EsfJsonObjectSet(handle, parent, key, cval);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectSet(%p, %d, %s, %d) ret %d", handle, parent, key, cval, esfj_ret);
        ret = kRetFailed;
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppCmnSetBooleanValue(EsfJsonHandle handle, EsfJsonValue parent, const char *key,
                                 bool boolean)
{
    RetCode ret = kRetOk;
    EsfJsonErrorCode esfj_ret = kEsfJsonSuccess;
    EsfJsonValue cval = ESF_JSON_VALUE_INVALID;

    // Create BooleanValue from "string" argument,
    // and set NumberValue to parent Object with "key".

    esfj_ret = EsfJsonBooleanInit(handle, boolean, &cval);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonBooleanInit(%p, %d, %p) ret %d", handle, boolean, &cval, esfj_ret);
        return kRetFailed;
    }

    esfj_ret = EsfJsonObjectSet(handle, parent, key, cval);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectSet(%p, %d, %s, %d) ret %d", handle, parent, key, cval, esfj_ret);
        ret = kRetFailed;
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppCmnSetObjectValue(EsfJsonHandle handle, EsfJsonValue parent, const char *key,
                                RetCode (*make_json)(EsfJsonHandle, EsfJsonValue, void *),
                                void *ctx)
{
    RetCode ret = kRetOk;
    EsfJsonErrorCode esfj_ret = kEsfJsonSuccess;
    EsfJsonValue cval = ESF_JSON_VALUE_INVALID;

    // Create ObjectValue by "make_json" function,
    // and set StringValue to parent Object with "key".

    esfj_ret = EsfJsonObjectInit(handle, &cval);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectInit(%p, %p) ret %d", handle, &cval, esfj_ret);
        return kRetFailed;
    }

    make_json(handle, cval, ctx);

    esfj_ret = EsfJsonObjectSet(handle, parent, key, cval);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectSet(%p, %d, %s, %d) ret %d", handle, parent, key, cval, esfj_ret);
        ret = kRetFailed;
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppCmnSetArrayValue(EsfJsonHandle handle, EsfJsonValue parent, const char *key,
                               uint32_t array_num,
                               RetCode (*make_json)(EsfJsonHandle, EsfJsonValue, uint32_t, void *),
                               void *ctx)
{
    RetCode ret = kRetOk;
    EsfJsonErrorCode esfj_ret = kEsfJsonSuccess;
    EsfJsonValue carr;

    // Create ArrayValue and fill elements by "make_json" function,
    // and set StringValue to parent Object with "key".

    esfj_ret = EsfJsonArrayInit(handle, &carr);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonArrayInit(%p, %p) ret %d", handle, &carr, esfj_ret);
        return kRetFailed;
    }

    for (uint32_t idx = 0; idx < array_num; idx++) {
        EsfJsonValue cval;

        esfj_ret = EsfJsonObjectInit(handle, &cval);

        if (esfj_ret != kEsfJsonSuccess) {
            SYSAPP_ERR("EsfJsonObjectInit(%p, %p) ret %d", handle, &cval, esfj_ret);
            ret = kRetFailed;
            break;
        }

        if (make_json(handle, cval, idx, ctx) == kRetNotFound) {
            continue;
        }

        esfj_ret = EsfJsonArrayAppend(handle, carr, cval);

        if (esfj_ret != kEsfJsonSuccess) {
            SYSAPP_ERR("EsfJsonArrayAppend(%p, %d, %d) ret %d", handle, carr, cval, esfj_ret);
            ret = kRetFailed;
            break;
        }
    }

    esfj_ret = EsfJsonObjectSet(handle, parent, key, carr);

    if (esfj_ret != kEsfJsonSuccess) {
        SYSAPP_ERR("EsfJsonObjectSet(%p, %d, %s, %d) ret %d", handle, parent, key, carr, esfj_ret);
        ret = kRetFailed;
    }

    return ret;
}
