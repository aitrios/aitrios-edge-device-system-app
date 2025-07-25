/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#include "system_app_log.h"
#include "system_app_common.h"
#include "system_app_util.h"

/*----------------------------------------------------------------------------*/
STATIC EsfLogManagerSettingBlockType EncodeFiltertToBlockType(CfgStLogFilter filter)
{
    EsfLogManagerSettingBlockType block;

    switch (filter) {
        case AllLog:
            block = kEsfLogManagerBlockTypeAll;
            break;
        case MainFwLog:
            block = kEsfLogManagerBlockTypeSysApp;
            break;
        case SensorLog:
            block = kEsfLogManagerBlockTypeSensor;
            break;
        case CompanionFwLog:
            block = kEsfLogManagerBlockTypeAiisp;
            break;
        case CompanionAppLog:
            block = kEsfLogManagerBlockTypeVicapp;
            break;
        default:
            // If conversion is not possible, returns the maximum unused number.
            block = kEsfLogManagerBlockTypeNum;
            break;
    }
    return block;
}

/*----------------------------------------------------------------------------*/
static CfgStLogLevel DecodeDLogLevel(EsfLogManagerDlogLevel esflevel)
{
    CfgStLogLevel level;

    switch (esflevel) {
        case kEsfLogManagerDlogLevelCritical: // Critical
            level = CriticalLv;
            break;
        case kEsfLogManagerDlogLevelError: // Error
            level = ErrorLv;
            break;
        case kEsfLogManagerDlogLevelWarn: // Warning
            level = WarningLv;
            break;
        case kEsfLogManagerDlogLevelInfo: // Info
            level = InfoLv;
            break;
        case kEsfLogManagerDlogLevelDebug: // Debug
            level = DebugLv;
            break;
        case kEsfLogManagerDlogLevelTrace: // Trace
            level = VerboseLv;
            break;
        default:
            // If conversion is not possible, returns the maximum unused number.
            level = LogLevelNum;
    }
    return level;
}

/*----------------------------------------------------------------------------*/
static EsfLogManagerDlogLevel EncodeDLogLevel(CfgStLogLevel level)
{
    EsfLogManagerDlogLevel esflevel;

    switch (level) {
        case CriticalLv:
            esflevel = kEsfLogManagerDlogLevelCritical;
            break;
        case ErrorLv:
            esflevel = kEsfLogManagerDlogLevelError;
            break;
        case WarningLv:
            esflevel = kEsfLogManagerDlogLevelWarn;
            break;
        case InfoLv:
            esflevel = kEsfLogManagerDlogLevelInfo;
            break;
        case DebugLv:
            esflevel = kEsfLogManagerDlogLevelDebug;
            break;
        case VerboseLv:
            esflevel = kEsfLogManagerDlogLevelTrace;
            break;
        default:
            // If conversion is not possible, returns the maximum unused number.
            esflevel = kEsfLogManagerDlogLevelNum;
    }
    return esflevel;
}

/*----------------------------------------------------------------------------*/
static CfgStLogDestination DecodeDLogDestination(EsfLogManagerDlogDest esfDest)
{
    CfgStLogDestination destination;

    switch (esfDest) {
        case kEsfLogManagerDlogDestUart: // UART
            destination = DestUart;
            break;
        case kEsfLogManagerDlogDestStore: // CLOUD
            destination = DestCloudStorage;
            break;
        case kEsfLogManagerDlogDestBoth: //T.B.D BOTH
        default:
            // If conversion is not possible, returns the maximum unused number.
            destination = LogDestinationNum;
    }
    return destination;
}

/*----------------------------------------------------------------------------*/
static EsfLogManagerDlogDest EncodeDLogDestination(CfgStLogDestination destination)
{
    EsfLogManagerDlogDest esfDest;

    switch (destination) {
        case DestUart:
            esfDest = kEsfLogManagerDlogDestUart;
            break;
        case DestCloudStorage:
            esfDest = kEsfLogManagerDlogDestStore;
            break;
        default:
            // If conversion is not possible, returns the maximum unused number.
            esfDest = kEsfLogManagerDlogDestNum;
    }
    return esfDest;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppLogGetParameterNumber(CfgStLogFilter filter, SystemSettingsProperty prop,
                                    int *ret_value)
{
    RetCode result = kRetOk;
    EsfLogManagerStatus esflog_ret = kEsfLogManagerStatusOk;
    EsfLogManagerSettingBlockType block;
    EsfLogManagerParameterValue value = {0};

    if ((filter >= MainFwLog) && (filter < LogFilterNum)) {
        /* Convert filter to block_type */
        block = EncodeFiltertToBlockType(filter);
        esflog_ret = EsfLogManagerGetParameter(block, &value);

        if (esflog_ret == kEsfLogManagerStatusOk) {
            if (prop == LogLevel) {
                *ret_value = (int)DecodeDLogLevel(value.dlog_level);
                SYSAPP_DBG("SysAppLogGetParameterNumber(f:%d, p:LogLevel) v=%d", filter,
                           *ret_value);
            }
            else if (prop == LogDestination) {
                *ret_value = (int)DecodeDLogDestination(value.dlog_dest);
                SYSAPP_DBG("SysAppLogGetParameterNumber(f:%d, p:LogDest) v=%d", filter, *ret_value);
            }
            else {
                SYSAPP_ERR("SysAppLogGetParameterNumber(f:%d, p:%d, v:%d)", filter, prop,
                           *ret_value);
                result = kRetApiCallError;
            }
        }
        else {
            SYSAPP_ERR("EsfLogManagerGetParameter(b:%d) %d", block, esflog_ret);
            result = kRetFailed;
        }
    }
    else {
        SYSAPP_ERR("SysAppLogGetParameterNumber(f:%d, p:%d, v:%d)", filter, prop, *ret_value);
        result = kRetApiCallError;
    }

    return result;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppLogGetParameterString(CfgStLogFilter filter, SystemSettingsProperty prop,
                                    char *ret_value, size_t buff_size)
{
    RetCode result = kRetOk;
    EsfLogManagerStatus esflog_ret = kEsfLogManagerStatusOk;
    EsfLogManagerSettingBlockType block;
    EsfLogManagerParameterValue value = {0};

    if ((filter >= MainFwLog) && (filter < LogFilterNum)) {
        /* Convert filter to block_type */
        block = EncodeFiltertToBlockType(filter);
        esflog_ret = EsfLogManagerGetParameter(block, &value);

        if (esflog_ret == kEsfLogManagerStatusOk) {
            if (prop == LogStorageName) {
                snprintf(ret_value, buff_size, "%s", &(value.storage_name[0]));
                SYSAPP_DBG("SysAppLogGetParameterString(f:%d, p:StrName) v=%s", filter, ret_value);
            }
            else if (prop == LogPath) {
                snprintf(ret_value, buff_size, "%s", &(value.storage_path[0]));
                SYSAPP_DBG("SysAppLogGetParameterString(f:%d, p:StrPath) v=%s", filter, ret_value);
            }
            else {
                SYSAPP_ERR("SysAppLogGetParameterString(f:%d, p:%d, v:%s)", filter, prop,
                           ret_value);
                result = kRetApiCallError;
            }
        }
        else {
            SYSAPP_ERR("EsfLogManagerGetParameter() %d", esflog_ret);
            result = kRetFailed;
        }
    }
    else {
        SYSAPP_ERR("SysAppLogGetParameterString(f:%d, p:%d, v:%s)", filter, prop, ret_value);
        result = kRetApiCallError;
    }

    return result;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppLogSetParameterNumber(CfgStLogFilter filter, SystemSettingsProperty prop,
                                    int set_value)
{
    RetCode result = kRetOk;
    EsfLogManagerStatus esflog_ret = kEsfLogManagerStatusOk;
    EsfLogManagerSettingBlockType block;
    EsfLogManagerParameterValue value = {0};
    EsfLogManagerParameterMask mask = {0};

    if ((filter >= MainFwLog) && (filter < LogFilterNum)) {
        /* Convert filter to block_type */
        block = EncodeFiltertToBlockType(filter);

        if (prop == LogLevel) {
            mask.dlog_level = 1;
            value.dlog_level = EncodeDLogLevel((CfgStLogLevel)set_value);
        }
        else if (prop == LogDestination) {
            mask.dlog_dest = 1;
            value.dlog_dest = EncodeDLogDestination((CfgStLogDestination)set_value);
        }
        else {
            SYSAPP_ERR("SysAppLogSetParameterNumber(f:%d, p:%d, v=%d)", filter, prop, set_value);
            result = kRetApiCallError;
            return result;
        }

        esflog_ret = EsfLogManagerSetParameter(block, value, mask);
        if (esflog_ret != kEsfLogManagerStatusOk) {
            SYSAPP_ERR("EsfLogManagerSetParameter() %d", esflog_ret);
            if (esflog_ret == kEsfLogManagerStatusParamError) {
                result = kRetParamError;
            }
            else {
                result = kRetFailed;
            }
        }
    }
    else {
        SYSAPP_ERR("SysAppLogSetParameterNumber(f:%d, p:%d, v=%d)", filter, prop, set_value);
        result = kRetApiCallError;
    }

    return result;
}

/*----------------------------------------------------------------------------*/
RetCode SysAppLogSetParameterString(CfgStLogFilter filter, SystemSettingsProperty prop,
                                    const char *set_value, size_t buff_size)
{
    RetCode result = kRetOk;
    EsfLogManagerStatus esflog_ret = kEsfLogManagerStatusOk;
    EsfLogManagerSettingBlockType block;
    EsfLogManagerParameterValue value = {0};
    EsfLogManagerParameterMask mask = {0};

    if ((filter >= MainFwLog) && (filter < LogFilterNum)) {
        /* Convert filter to block_type */
        block = EncodeFiltertToBlockType(filter);

        if (prop == LogStorageName) {
            mask.storage_name = 1;
            snprintf(value.storage_name, sizeof(value.storage_name), "%s", set_value);
            SYSAPP_DBG("SysAppLogSetParameterString(f:%d, p:StrName, v:%s) bsz:%zu", filter,
                       set_value, buff_size);
        }
        else if (prop == LogPath) {
            mask.storage_path = 1;
            snprintf(value.storage_path, sizeof(value.storage_path), "%s", set_value);
            SYSAPP_DBG("SysAppLogSetParameterString(f:%d, p:StrPath, v=%s) bsz:%zu", filter,
                       set_value, buff_size);
        }
        else {
            SYSAPP_ERR("SysAppLogSetParameterString(f:%d, p:%d, s:%s)", filter, prop, set_value);
            result = kRetApiCallError;
            return result;
        }

        esflog_ret = EsfLogManagerSetParameter(block, value, mask);
        if (esflog_ret != kEsfLogManagerStatusOk) {
            SYSAPP_ERR("EsfLogManagerSetParameter() %d", esflog_ret);
            if (esflog_ret == kEsfLogManagerStatusParamError) {
                result = kRetParamError;
            }
            else {
                result = kRetFailed;
            }
        }
    }
    else {
        SYSAPP_ERR("SysAppLogSetParameterString(f:%d, p:%d, s:%s)", filter, prop, set_value);
        result = kRetApiCallError;
    }

    return result;
}
